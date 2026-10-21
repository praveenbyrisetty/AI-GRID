"""
AI-GRID Generic MCP Protocol Client (v4.0)

Real MCP client using the official MCP Python SDK.
Connects to any MCP-compliant server via stdio or SSE transport
and performs protocol-level operations:
    1. Initialize connection (protocol handshake)
    2. List tools (tools/list)
    3. Inspect tool schemas (input validation schemas)
    4. Call tools with controlled inputs
    5. Handle errors, timeouts, and malformed responses
    6. Log all protocol messages for audit trail

This replaces the previous LocalSoilAIMCPServer which bypassed the protocol
and called Python functions directly.
"""

import asyncio
import json
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("aigrid.mcp_client")


@dataclass
class MCPToolSchema:
    """Parsed tool information from MCP server discovery."""
    name: str
    description: str
    input_schema: Dict[str, Any] = field(default_factory=dict)
    raw: Any = None


@dataclass
class MCPCallResult:
    """Result of a single MCP tool call."""
    tool_name: str
    arguments: Dict[str, Any]
    success: bool
    data: Any = None
    error: Optional[str] = None
    duration_ms: float = 0.0
    raw_response: Any = None


@dataclass
class MCPProtocolLog:
    """A single logged protocol message for audit trail."""
    timestamp: str
    direction: str  # "SENT" or "RECEIVED"
    method: str
    data: Any = None
    status: str = "OK"


class MCPClient:
    """
    Generic MCP protocol client.

    Connects to MCP servers via stdio transport using the official SDK.
    Falls back to a direct-invocation mode for demo/test environments
    where the MCP SDK may not be available.
    """

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self.protocol_logs: List[MCPProtocolLog] = []
        self._session = None
        self._streams = None
        self._connected = False
        self._sdk_available = False

        # Check MCP SDK availability
        try:
            from mcp import ClientSession  # noqa: F401
            from mcp.client.stdio import stdio_client  # noqa: F401
            self._sdk_available = True
        except ImportError:
            logger.warning(
                "MCP Python SDK not installed. Install via: pip install mcp. "
                "Falling back to direct-invocation mode for demo servers."
            )
            self._sdk_available = False

    def _log_protocol(self, direction: str, method: str, data: Any = None, status: str = "OK"):
        self.protocol_logs.append(MCPProtocolLog(
            timestamp=datetime.now().isoformat(),
            direction=direction,
            method=method,
            data=data,
            status=status,
        ))

    @asynccontextmanager
    async def session(self, command: str, args: List[str], env: Optional[Dict[str, str]] = None):
        """
        Async context manager providing a clean, leak-free connection session.
        Guarantees task group entering and exiting within the same task scope.
        """
        if not self._sdk_available:
            raise RuntimeError("MCP Python SDK not installed.")

        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        cmd_args = list(args)
        if (command == sys.executable or "python" in os.path.basename(command).lower()) and "-u" not in cmd_args:
            cmd_args.insert(0, "-u")

        run_env = {"PYTHONUNBUFFERED": "1", **os.environ}
        if env:
            run_env.update(env)

        params = StdioServerParameters(command=command, args=cmd_args, env=run_env)
        self._log_protocol("SENT", "connect_stdio", {"command": command, "args": cmd_args})

        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await asyncio.wait_for(session.initialize(), timeout=self.timeout)
                self._session = session
                self._connected = True
                self._log_protocol("RECEIVED", "initialize", {"status": "connected"}, "SUCCESS")
                logger.info("MCP connection established via stdio")
                try:
                    yield self
                finally:
                    self._connected = False
                    self._session = None
                    self._log_protocol("SYSTEM", "disconnect", None, "OK")

    async def connect_stdio(self, command: str, args: List[str], env: Optional[Dict[str, str]] = None) -> bool:
        """
        Connect to an MCP server via stdio transport.

        Args:
            command: The command to launch the server (e.g., "python")
            args: Command arguments (e.g., ["demo_servers/good_server.py"])
            env: Optional environment variables

        Returns:
            True if connection was successful, False otherwise.
        """
        if not self._sdk_available:
            logger.error("Cannot connect via stdio: MCP SDK not installed.")
            self._log_protocol("SYSTEM", "connect_stdio", {"error": "MCP SDK not installed"}, "ERROR")
            return False

        try:
            from mcp import ClientSession
            from mcp.client.stdio import StdioServerParameters, stdio_client

            cmd_args = list(args)
            if (command == sys.executable or "python" in os.path.basename(command).lower()) and "-u" not in cmd_args:
                cmd_args.insert(0, "-u")

            run_env = {"PYTHONUNBUFFERED": "1", **os.environ}
            if env:
                run_env.update(env)

            self._log_protocol("SENT", "connect_stdio", {"command": command, "args": cmd_args})

            params = StdioServerParameters(command=command, args=cmd_args, env=run_env)

            self._stdio_cm = stdio_client(params)
            self._streams = await self._stdio_cm.__aenter__()

            read_stream, write_stream = self._streams
            self._session_cm = ClientSession(read_stream, write_stream)
            self._session = await self._session_cm.__aenter__()

            # Initialize the session (protocol handshake)
            await asyncio.wait_for(self._session.initialize(), timeout=self.timeout)

            self._connected = True
            self._log_protocol("RECEIVED", "initialize", {"status": "connected"}, "SUCCESS")
            logger.info("MCP connection established via stdio")
            return True

        except asyncio.TimeoutError:
            self._log_protocol("SYSTEM", "connect_stdio", {"error": "Connection timeout"}, "TIMEOUT")
            logger.error(f"MCP connection timed out after {self.timeout}s")
            return False
        except Exception as e:
            self._log_protocol("SYSTEM", "connect_stdio", {"error": str(e)}, "ERROR")
            logger.error(f"MCP connection failed: {e}")
            return False

    async def disconnect(self):
        """Disconnect from the MCP server and clean up resources."""
        try:
            if self._session and hasattr(self, '_session_cm'):
                await self._session_cm.__aexit__(None, None, None)
            if self._streams and hasattr(self, '_stdio_cm'):
                await self._stdio_cm.__aexit__(None, None, None)
        except Exception as e:
            logger.warning(f"Error during disconnect: {e}")
        finally:
            self._session = None
            self._streams = None
            self._connected = False
            self._log_protocol("SYSTEM", "disconnect", None, "OK")

    async def list_tools(self) -> List[MCPToolSchema]:
        """
        Discover all tools exposed by the connected MCP server.

        Returns:
            List of MCPToolSchema objects with name, description, and input schema.
        """
        if not self._connected or not self._session:
            self._log_protocol("SYSTEM", "list_tools", {"error": "Not connected"}, "ERROR")
            return []

        try:
            self._log_protocol("SENT", "tools/list", None)
            response = await asyncio.wait_for(
                self._session.list_tools(), timeout=self.timeout
            )

            tools = []
            for tool in response.tools:
                schema_dict = (
                    tool.input_schema
                    if hasattr(tool, "input_schema")
                    else getattr(tool, "inputSchema", {})
                )
                if not isinstance(schema_dict, dict) and hasattr(schema_dict, "model_dump"):
                    schema_dict = schema_dict.model_dump()

                schema = MCPToolSchema(
                    name=tool.name,
                    description=tool.description or "",
                    input_schema=schema_dict or {},
                    raw=tool,
                )
                tools.append(schema)

            self._log_protocol(
                "RECEIVED", "tools/list",
                {"tool_count": len(tools), "names": [t.name for t in tools]},
                "SUCCESS",
            )
            return tools

        except asyncio.TimeoutError:
            self._log_protocol("SYSTEM", "list_tools", {"error": "Timeout"}, "TIMEOUT")
            return []
        except Exception as e:
            self._log_protocol("SYSTEM", "list_tools", {"error": str(e)}, "ERROR")
            return []

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> MCPCallResult:
        """
        Call a specific tool on the connected MCP server.

        Args:
            name: The tool name to invoke.
            arguments: Dictionary of arguments to pass.

        Returns:
            MCPCallResult with success status, data, timing, and raw response.
        """
        if not self._connected or not self._session:
            return MCPCallResult(
                tool_name=name,
                arguments=arguments,
                success=False,
                error="Not connected to MCP server",
            )

        start_time = time.monotonic()
        self._log_protocol("SENT", f"tools/call:{name}", {"arguments": arguments})

        try:
            response = await asyncio.wait_for(
                self._session.call_tool(name, arguments=arguments),
                timeout=self.timeout,
            )
            elapsed = (time.monotonic() - start_time) * 1000

            # Parse response content
            data = self._parse_call_result(response)

            result = MCPCallResult(
                tool_name=name,
                arguments=arguments,
                success=True,
                data=data,
                duration_ms=round(elapsed, 1),
                raw_response=response,
            )

            self._log_protocol(
                "RECEIVED", f"tools/call:{name}",
                {"success": True, "duration_ms": result.duration_ms},
                "SUCCESS",
            )
            return result

        except asyncio.TimeoutError:
            elapsed = (time.monotonic() - start_time) * 1000
            self._log_protocol("SYSTEM", f"tools/call:{name}", {"error": "Timeout"}, "TIMEOUT")
            return MCPCallResult(
                tool_name=name,
                arguments=arguments,
                success=False,
                error=f"Tool call timed out after {self.timeout}s",
                duration_ms=round(elapsed, 1),
            )
        except Exception as e:
            elapsed = (time.monotonic() - start_time) * 1000
            self._log_protocol("SYSTEM", f"tools/call:{name}", {"error": str(e)}, "ERROR")
            return MCPCallResult(
                tool_name=name,
                arguments=arguments,
                success=False,
                error=str(e),
                duration_ms=round(elapsed, 1),
            )

    def _parse_call_result(self, response: Any) -> Any:
        """Parse MCP CallToolResult into a Python dict."""
        try:
            # MCP SDK returns CallToolResult with .content list
            if hasattr(response, 'content'):
                for content_item in response.content:
                    if hasattr(content_item, 'text'):
                        try:
                            return json.loads(content_item.text)
                        except json.JSONDecodeError:
                            return {"text": content_item.text}
                    elif hasattr(content_item, 'data'):
                        return content_item.data
            # Fallback
            if isinstance(response, dict):
                return response
            return {"raw": str(response)}
        except Exception:
            return {"raw": str(response)}

    def get_protocol_logs(self) -> List[Dict[str, Any]]:
        """Return all protocol logs as serializable dicts."""
        return [
            {
                "timestamp": log.timestamp,
                "direction": log.direction,
                "method": log.method,
                "data": log.data,
                "status": log.status,
            }
            for log in self.protocol_logs
        ]


class DirectInvocationClient:
    """
    Fallback client for when the MCP SDK is not installed.
    Directly imports and calls demo server tool functions.

    This is ONLY for demonstration and testing when the full MCP SDK
    cannot be installed. It does NOT use the MCP protocol and is clearly
    labeled as a non-protocol fallback.
    """

    def __init__(self, server_module_path: str = None):
        self.protocol_logs: List[MCPProtocolLog] = []
        self._tools = {}
        self._module = None
        self._module_path = server_module_path

    def _log_protocol(self, direction: str, method: str, data: Any = None, status: str = "OK"):
        self.protocol_logs.append(MCPProtocolLog(
            timestamp=datetime.now().isoformat(),
            direction=direction,
            method=method,
            data=data,
            status=status,
        ))

    async def connect_direct(self, tool_functions: Dict[str, callable]) -> bool:
        """
        Register tool functions directly (no protocol, no transport).

        Args:
            tool_functions: Dict mapping tool name to callable function.

        Returns:
            True (always succeeds for direct invocation).
        """
        self._tools = tool_functions
        self._log_protocol("SYSTEM", "direct_connect",
                           {"mode": "DIRECT_INVOCATION (no MCP protocol)",
                            "tools": list(tool_functions.keys())},
                           "WARNING")
        return True

    async def list_tools(self) -> List[MCPToolSchema]:
        """List registered tool functions."""
        tools = []
        for name, fn in self._tools.items():
            tools.append(MCPToolSchema(
                name=name,
                description=fn.__doc__ or "No description available",
                input_schema={},
            ))
        self._log_protocol("SENT", "tools/list (DIRECT)", {"tool_count": len(tools)})
        return tools

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> MCPCallResult:
        """Call a registered tool function directly."""
        if name not in self._tools:
            return MCPCallResult(
                tool_name=name, arguments=arguments, success=False,
                error=f"Tool '{name}' not registered",
            )

        start_time = time.monotonic()
        self._log_protocol("SENT", f"tools/call:{name} (DIRECT)", {"arguments": arguments})

        try:
            fn = self._tools[name]
            result = fn(**arguments) if arguments else fn()
            elapsed = (time.monotonic() - start_time) * 1000

            if not isinstance(result, dict):
                try:
                    result = json.loads(str(result))
                except (json.JSONDecodeError, TypeError):
                    result = {"result": str(result)}

            self._log_protocol("RECEIVED", f"tools/call:{name} (DIRECT)",
                               {"success": True, "duration_ms": round(elapsed, 1)}, "SUCCESS")

            return MCPCallResult(
                tool_name=name, arguments=arguments, success=True,
                data=result, duration_ms=round(elapsed, 1),
            )
        except Exception as e:
            elapsed = (time.monotonic() - start_time) * 1000
            self._log_protocol("SYSTEM", f"tools/call:{name} (DIRECT)",
                               {"error": str(e)}, "ERROR")
            return MCPCallResult(
                tool_name=name, arguments=arguments, success=False,
                error=str(e), duration_ms=round(elapsed, 1),
            )

    async def disconnect(self):
        """No-op for direct invocation."""
        self._tools = {}

    def get_protocol_logs(self) -> List[Dict[str, Any]]:
        return [
            {
                "timestamp": log.timestamp,
                "direction": log.direction,
                "method": log.method,
                "data": log.data,
                "status": log.status,
            }
            for log in self.protocol_logs
        ]
