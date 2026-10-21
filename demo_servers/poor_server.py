"""
AI-GRID Demo MCP Server: POOR Security Profile

A deliberately insecure MCP server for testing AI-GRID's detection capabilities:
- No metadata endpoint
- No input validation
- No output clamping
- No encryption declarations
- No human oversight
- Accepts and processes any input without guardrails

WARNING: This server is intentionally insecure for demonstration purposes.
Launch: python demo_servers/poor_server.py
"""

import json
import sys

try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as MCPServer
    except ImportError:
        print("ERROR: MCP SDK not installed. Install via: pip install mcp", file=sys.stderr)
        sys.exit(1)


mcp = MCPServer("Uncertified-Predictor-v0.1")


@mcp.tool()
def raw_predict(input_value: float = 0.0) -> str:
    """Basic prediction endpoint. No validation or safety controls."""
    # No input validation — accepts any value including negatives
    result = input_value * 0.9 + 25.0
    return json.dumps({
        "status": "SUCCESS",
        "prediction": "Class_1",
        "recommended_value": result,
        # No clamping, no confidence, no explanations
    })


if __name__ == "__main__":
    mcp.run(transport="stdio")
