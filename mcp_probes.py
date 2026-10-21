"""
AI-GRID MCP Security Probe Suite (v4.0)

Implements 8 protocol-level security probes that generate structured Evidence
objects from real MCP server interactions.

Probe Suite:
    P01: Tool Discovery & Enumeration
    P02: Schema Validation & Type Safety
    P03: Permission & Capability Analysis
    P04: Input Boundary Testing (edge cases, negative, overflow)
    P05: Output Validation (schema conformance, unclamped values)
    P06: Metadata & Governance Extraction
    P07: Error Handling Analysis (malformed args, stack trace leaks)
    P08: Data Governance Inspection (encryption, retention, PII)

All probes are:
    - Non-destructive (read-only where possible)
    - Authorized (user-initiated)
    - Logged (every protocol message recorded)
    - Time-bounded (configurable timeout)
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from evidence import Evidence, SecurityFinding
from mcp_client import MCPClient, MCPToolSchema, MCPCallResult, DirectInvocationClient

logger = logging.getLogger("aigrid.mcp_probes")


# ======================================================================
# DANGEROUS CAPABILITY KEYWORDS
# Used by P03 to flag tools with potentially dangerous capabilities
# ======================================================================
DANGEROUS_CAPABILITIES = {
    "high": [
        "exec", "execute", "shell", "bash", "cmd", "command", "system",
        "eval", "subprocess", "os.system", "popen", "spawn",
        "delete", "remove", "rm ", "drop", "truncate", "destroy",
        "write_file", "overwrite", "modify_file",
    ],
    "medium": [
        "file", "filesystem", "directory", "path", "read_file",
        "network", "http", "request", "fetch", "download", "upload",
        "database", "query", "sql", "insert", "update",
        "api_key", "secret", "token", "credential", "password",
    ],
    "low": [
        "list", "read", "get", "search", "find", "metadata",
    ],
}


class MCPSecurityProber:
    """
    Executes the 8-probe security assessment suite against an MCP server.

    Generates structured Evidence objects for each observation,
    which are then consumed by the evidence pipeline for scoring.
    """

    def __init__(self, client):
        """
        Args:
            client: An MCPClient or DirectInvocationClient instance
                    (already connected to the target server).
        """
        self.client = client
        self.evidence: List[Evidence] = []
        self.logs: List[Dict[str, str]] = []
        self.tools: List[MCPToolSchema] = []

    def _log(self, stage: str, msg: str, status: str = "INFO"):
        self.logs.append({
            "stage": stage,
            "message": msg,
            "status": status,
            "timestamp": datetime.now().isoformat(),
        })

    def _add_evidence(self, dimension: str, source: str, tier: str, value: float,
                      description: str, raw_data: Any = None,
                      finding: Optional[SecurityFinding] = None):
        self.evidence.append(Evidence(
            dimension=dimension,
            source=source,
            tier=tier,
            value=value,
            raw_data=raw_data,
            description=description,
            finding=finding,
        ))

    async def run_all_probes(self) -> Dict[str, Any]:
        """
        Execute all 8 probes in sequence and return collected evidence.

        Returns:
            Dict with:
                - evidence: List of Evidence objects
                - logs: Audit trail
                - tools_discovered: List of tool names
                - probe_summary: Statistics
        """
        self._log("INIT", "Starting AI-GRID MCP Security Probe Suite (8 probes)...")

        # P01: Tool Discovery
        await self.probe_01_tool_discovery()

        # P02: Schema Validation (requires tools from P01)
        await self.probe_02_schema_validation()

        # P03: Permission & Capability Analysis
        await self.probe_03_permission_analysis()

        # P06: Metadata Extraction (run before P04/P05 since metadata informs them)
        meta_data = await self.probe_06_metadata_extraction()

        # P04: Input Boundary Testing
        await self.probe_04_input_boundary_testing()

        # P05: Output Validation
        await self.probe_05_output_validation()

        # P07: Error Handling Analysis
        await self.probe_07_error_handling()

        # P08: Data Governance Inspection
        await self.probe_08_data_governance(meta_data)

        self._log("COMPLETE", f"Probe suite complete. Collected {len(self.evidence)} evidence items, "
                  f"discovered {len(self.tools)} tools.")

        return {
            "evidence": self.evidence,
            "logs": self.logs,
            "tools_discovered": [t.name for t in self.tools],
            "metadata": meta_data,
            "probe_summary": {
                "total_probes": 8,
                "tools_discovered": len(self.tools),
                "evidence_items_collected": len(self.evidence),
                "findings_count": sum(1 for e in self.evidence if e.finding),
                "critical_findings": sum(
                    1 for e in self.evidence
                    if e.finding and e.finding.severity == "CRITICAL"
                ),
            },
        }

    # ==================================================================
    # P01: TOOL DISCOVERY & ENUMERATION
    # ==================================================================
    async def probe_01_tool_discovery(self):
        """Enumerate all tools exposed by the MCP server."""
        self._log("P01:DISCOVERY", "Connecting to target MCP server and enumerating tools...")

        self.tools = await self.client.list_tools()
        tool_names = [t.name for t in self.tools]

        if not self.tools:
            self._log("P01:DISCOVERY", "WARNING: No tools discovered on target server.", "WARNING")
            self._add_evidence(
                dimension="Transparency & Explainability",
                source="mcp_probe:P01",
                tier="T1",
                value=0.0,
                description="MCP server exposes zero tools. Cannot assess functionality.",
                finding=SecurityFinding(
                    severity="HIGH",
                    dimension="Transparency & Explainability",
                    finding="Target MCP server exposes no tools via tools/list.",
                    action="Verify server is running and tools are properly registered.",
                    evidence_ref="P01:tool_discovery",
                    owasp_ref="MCP08",
                ),
            )
            return

        self._log("P01:DISCOVERY",
                  f"Discovered {len(tool_names)} tools: {', '.join(tool_names)}", "SUCCESS")

        # Evidence: tool count contributes to transparency score
        tool_score = min(100.0, len(tool_names) * 25.0)  # 4+ tools = full score
        self._add_evidence(
            dimension="Transparency & Explainability",
            source="mcp_probe:P01",
            tier="T1",
            value=tool_score,
            description=f"Server exposes {len(tool_names)} discoverable tools: {', '.join(tool_names)}",
            raw_data={"tools": tool_names},
        )

    # ==================================================================
    # P02: SCHEMA VALIDATION & TYPE SAFETY
    # ==================================================================
    async def probe_02_schema_validation(self):
        """Check if tool input schemas are well-defined with types and constraints."""
        self._log("P02:SCHEMA", "Analyzing tool input schemas for type safety...")

        if not self.tools:
            return

        well_defined_count = 0
        for tool in self.tools:
            schema = tool.input_schema
            has_properties = bool(schema.get("properties"))
            has_types = False
            has_required = bool(schema.get("required"))

            if has_properties:
                props = schema["properties"]
                has_types = all("type" in v for v in props.values())

            if has_properties and has_types:
                well_defined_count += 1
                self._log("P02:SCHEMA",
                          f"Tool '{tool.name}': Schema well-defined with typed properties.", "SUCCESS")
            elif has_properties:
                self._log("P02:SCHEMA",
                          f"Tool '{tool.name}': Schema has properties but missing type annotations.", "WARNING")
            else:
                self._log("P02:SCHEMA",
                          f"Tool '{tool.name}': No input schema defined — accepts arbitrary input.", "WARNING")

        schema_score = (well_defined_count / len(self.tools)) * 100.0 if self.tools else 0.0

        self._add_evidence(
            dimension="Safety & Reliability",
            source="mcp_probe:P02",
            tier="T1",
            value=schema_score,
            description=f"{well_defined_count}/{len(self.tools)} tools have well-defined input schemas.",
            raw_data={"well_defined": well_defined_count, "total": len(self.tools)},
            finding=SecurityFinding(
                severity="HIGH" if schema_score < 50 else ("MEDIUM" if schema_score < 100 else "LOW"),
                dimension="Safety & Reliability",
                finding=f"{len(self.tools) - well_defined_count} tools lack type-safe input schemas.",
                action="Define JSON Schema with types, bounds, and required fields for all tool inputs.",
                evidence_ref="P02:schema_validation",
                eu_ai_act_ref="Art. 15(1)",
                owasp_ref="MCP03",
            ) if schema_score < 100 else None,
        )

    # ==================================================================
    # P03: PERMISSION & CAPABILITY ANALYSIS
    # ==================================================================
    async def probe_03_permission_analysis(self):
        """Analyze tool descriptions and names for dangerous capabilities."""
        self._log("P03:PERMISSIONS", "Analyzing tool capabilities for dangerous operations...")

        if not self.tools:
            return

        high_risk_tools = []
        medium_risk_tools = []
        import re

        for tool in self.tools:
            text = f"{tool.name} {tool.description}".lower()

            for keyword in DANGEROUS_CAPABILITIES["high"]:
                pattern = r"\b" + re.escape(keyword) + r"\b"
                if re.search(pattern, text):
                    high_risk_tools.append((tool.name, keyword))
                    break

            for keyword in DANGEROUS_CAPABILITIES["medium"]:
                pattern = r"\b" + re.escape(keyword) + r"\b"
                if re.search(pattern, text):
                    medium_risk_tools.append((tool.name, keyword))
                    break

        if high_risk_tools:
            self._log("P03:PERMISSIONS",
                      f"CRITICAL: {len(high_risk_tools)} tools with high-risk capabilities detected.",
                      "DANGER")
            self._add_evidence(
                dimension="Security & Robustness",
                source="mcp_probe:P03",
                tier="T1",
                value=max(0.0, 100.0 - len(high_risk_tools) * 40.0),
                description=f"High-risk tools detected: {[t[0] for t in high_risk_tools]}",
                raw_data={"high_risk": high_risk_tools, "medium_risk": medium_risk_tools},
                finding=SecurityFinding(
                    severity="CRITICAL",
                    dimension="Security & Robustness",
                    finding=f"Tools with dangerous capabilities: {', '.join(t[0] for t in high_risk_tools)} "
                            f"(matched: {', '.join(t[1] for t in high_risk_tools)})",
                    action="Apply Principle of Least Privilege. Restrict or sandbox dangerous tool capabilities.",
                    evidence_ref="P03:permission_analysis",
                    eu_ai_act_ref="Art. 15(3)",
                    owasp_ref="MCP02",
                    mitre_atlas_ref="AML.T0054",
                ),
            )
        else:
            permission_score = max(60.0, 100.0 - len(medium_risk_tools) * 10.0)
            self._add_evidence(
                dimension="Security & Robustness",
                source="mcp_probe:P03",
                tier="T1",
                value=permission_score,
                description=f"No high-risk capabilities detected. {len(medium_risk_tools)} medium-risk tools.",
                raw_data={"high_risk": [], "medium_risk": medium_risk_tools},
            )

    # ==================================================================
    # P04: INPUT BOUNDARY TESTING
    # ==================================================================
    async def probe_04_input_boundary_testing(self):
        """Send edge-case and adversarial inputs to test input validation."""
        self._log("P04:BOUNDARY", "Testing input validation with edge-case values...")

        if not self.tools:
            return

        # Find inference/prediction tools to test
        test_tools = [t for t in self.tools if any(kw in t.name.lower() for kw in
                      ["predict", "infer", "classify", "recommend", "calculate", "compute",
                       "analyze", "test", "evaluate"])]

        if not test_tools:
            # Test the first tool that has input schema
            test_tools = [t for t in self.tools if t.input_schema.get("properties")]

        if not test_tools:
            self._log("P04:BOUNDARY", "No testable tools found with input schemas.", "WARNING")
            return

        rejected_count = 0
        accepted_bad_count = 0
        total_tests = 0

        for tool in test_tools[:2]:  # Test up to 2 tools
            # Generate boundary test cases from schema
            test_cases = self._generate_boundary_tests(tool)

            for test_name, test_args in test_cases:
                total_tests += 1
                self._log("P04:BOUNDARY",
                          f"Testing '{tool.name}' with {test_name}: {test_args}")

                result = await self.client.call_tool(tool.name, test_args)

                if not result.success:
                    rejected_count += 1
                    self._log("P04:BOUNDARY",
                              f"PASS: Bad input rejected (error: {result.error})", "SUCCESS")
                elif isinstance(result.data, dict):
                    status = result.data.get("status", "").upper()
                    if status == "REJECTED" or "error" in result.data:
                        rejected_count += 1
                        self._log("P04:BOUNDARY", "PASS: Bad input caught by guardrail.", "SUCCESS")
                    else:
                        accepted_bad_count += 1
                        self._log("P04:BOUNDARY",
                                  f"FAIL: Bad input accepted without rejection.", "DANGER")
                else:
                    accepted_bad_count += 1

        if total_tests > 0:
            rejection_rate = rejected_count / total_tests
            boundary_score = rejection_rate * 100.0

            self._add_evidence(
                dimension="Safety & Reliability",
                source="mcp_probe:P04",
                tier="T1",
                value=boundary_score,
                description=f"Input boundary testing: {rejected_count}/{total_tests} bad inputs rejected "
                            f"({boundary_score:.0f}% rejection rate).",
                raw_data={"rejected": rejected_count, "accepted_bad": accepted_bad_count,
                          "total": total_tests},
                finding=SecurityFinding(
                    severity="CRITICAL" if accepted_bad_count > 0 else "LOW",
                    dimension="Safety & Reliability",
                    finding=f"{accepted_bad_count} adversarial/out-of-range inputs were accepted without rejection.",
                    action="Implement strict input validation with domain-specific range clamping.",
                    evidence_ref="P04:input_boundary",
                    eu_ai_act_ref="Art. 15(1)",
                    owasp_ref="MCP05",
                    mitre_atlas_ref="AML.T0043",
                ) if accepted_bad_count > 0 else None,
            )

    def _generate_boundary_tests(self, tool: MCPToolSchema) -> List[tuple]:
        """Generate boundary test cases from a tool's input schema."""
        tests = []
        props = tool.input_schema.get("properties", {})

        if not props:
            # No schema — send obviously bad data
            tests.append(("empty_args", {}))
            tests.append(("negative_numbers", {"value": -999.0}))
            return tests

        # Generate test cases based on property types
        negative_args = {}
        overflow_args = {}
        type_mismatch_args = {}

        for prop_name, prop_def in props.items():
            prop_type = prop_def.get("type", "string")

            if prop_type in ("number", "integer"):
                negative_args[prop_name] = -999.0
                overflow_args[prop_name] = 1e18
                type_mismatch_args[prop_name] = "not_a_number"
            elif prop_type == "string":
                negative_args[prop_name] = ""
                overflow_args[prop_name] = "A" * 10000
                type_mismatch_args[prop_name] = 12345

        if negative_args:
            tests.append(("negative_values", negative_args))
        if overflow_args:
            tests.append(("overflow_values", overflow_args))
        if type_mismatch_args:
            tests.append(("type_mismatch", type_mismatch_args))

        return tests

    # ==================================================================
    # P05: OUTPUT VALIDATION
    # ==================================================================
    async def probe_05_output_validation(self):
        """Check if tool outputs are properly bounded and structured."""
        self._log("P05:OUTPUT", "Validating tool output structure and safety bounds...")

        if not self.tools:
            return

        # Find tools that produce numerical outputs (predictions, recommendations)
        test_tools = [t for t in self.tools if any(kw in t.name.lower() for kw in
                      ["predict", "recommend", "calculate", "compute", "analyze"])]

        if not test_tools:
            test_tools = self.tools[:1]

        for tool in test_tools[:2]:
            # Call with default/normal arguments
            default_args = self._generate_default_args(tool)
            result = await self.client.call_tool(tool.name, default_args)

            if result.success and isinstance(result.data, dict):
                has_confidence = any(k for k in result.data.keys()
                                     if "confidence" in k.lower() or "probability" in k.lower())
                has_clamping = any(k for k in result.data.keys()
                                  if "clamp" in k.lower() or "bound" in k.lower())
                has_explanations = any(k for k in result.data.keys()
                                       if "attribution" in k.lower() or "shap" in k.lower()
                                       or "explanation" in k.lower() or "feature" in k.lower())

                output_score = 0.0
                if has_confidence:
                    output_score += 35.0
                if has_clamping:
                    output_score += 35.0
                if has_explanations:
                    output_score += 30.0

                self._add_evidence(
                    dimension="Transparency & Explainability",
                    source="mcp_probe:P05",
                    tier="T1",
                    value=output_score,
                    description=f"Tool '{tool.name}' output analysis: "
                                f"confidence={'✓' if has_confidence else '✗'}, "
                                f"clamping={'✓' if has_clamping else '✗'}, "
                                f"explanations={'✓' if has_explanations else '✗'}",
                    raw_data={"has_confidence": has_confidence, "has_clamping": has_clamping,
                              "has_explanations": has_explanations, "output_keys": list(result.data.keys())},
                )

    def _generate_default_args(self, tool: MCPToolSchema) -> Dict[str, Any]:
        """Generate reasonable default arguments from tool schema."""
        args = {}
        props = tool.input_schema.get("properties", {})
        for prop_name, prop_def in props.items():
            prop_type = prop_def.get("type", "string")
            default = prop_def.get("default")
            if default is not None:
                args[prop_name] = default
            elif prop_type in ("number", "integer"):
                args[prop_name] = 50.0
            elif prop_type == "string":
                args[prop_name] = "test"
            elif prop_type == "boolean":
                args[prop_name] = True
        return args

    # ==================================================================
    # P06: METADATA & GOVERNANCE EXTRACTION
    # ==================================================================
    async def probe_06_metadata_extraction(self) -> Dict[str, Any]:
        """Extract governance and system metadata from the MCP server."""
        self._log("P06:METADATA", "Extracting model metadata and governance declarations...")

        meta_data = {}
        metadata_tools = [t for t in self.tools if any(kw in t.name.lower() for kw in
                          ["metadata", "meta", "info", "about", "profile", "identity"])]

        if not metadata_tools:
            self._log("P06:METADATA",
                      "No metadata tool exposed — server lacks self-describing introspection.", "WARNING")
            self._add_evidence(
                dimension="Transparency & Explainability",
                source="mcp_probe:P06",
                tier="T1",
                value=0.0,
                description="No metadata introspection tool found on MCP server.",
                finding=SecurityFinding(
                    severity="HIGH",
                    dimension="Transparency & Explainability",
                    finding="Target server does not expose a metadata or self-description tool.",
                    action="Implement a metadata endpoint providing model name, version, architecture, "
                           "and governance declarations.",
                    evidence_ref="P06:metadata",
                    eu_ai_act_ref="Art. 13(1)",
                    owasp_ref="MCP08",
                ),
            )
            return meta_data

        for tool in metadata_tools[:1]:
            result = await self.client.call_tool(tool.name, {})

            if result.success and isinstance(result.data, dict):
                meta_data = result.data
                self._log("P06:METADATA",
                          f"Metadata extracted: '{meta_data.get('model_name', 'Unknown')}' "
                          f"v{meta_data.get('version', '?')}", "SUCCESS")

                # Score metadata completeness
                key_fields = ["model_name", "version", "domain", "model_architecture",
                              "training_dataset_size", "human_oversight_required",
                              "encryption_at_rest", "encryption_in_transit",
                              "drift_status", "incident_escalation_protocol"]
                present = sum(1 for k in key_fields if k in meta_data)
                completeness = (present / len(key_fields)) * 100.0

                self._add_evidence(
                    dimension="Transparency & Explainability",
                    source="mcp_probe:P06",
                    tier="T1",
                    value=completeness,
                    description=f"Metadata completeness: {present}/{len(key_fields)} governance fields present.",
                    raw_data=meta_data,
                )

                # Drift monitoring check → Security evidence
                drift_status = str(meta_data.get("drift_status", "")).upper()
                drift_monitoring = str(meta_data.get("model_drift_monitoring", "")).lower()
                if "auto" in drift_monitoring or drift_status == "MONITORED":
                    drift_score = 100.0
                elif drift_monitoring:
                    drift_score = 50.0
                else:
                    drift_score = 0.0

                self._add_evidence(
                    dimension="Security & Robustness",
                    source="mcp_probe:P06:drift",
                    tier="T1",
                    value=drift_score,
                    description=f"Drift monitoring: {drift_monitoring or 'NOT CONFIGURED'} "
                                f"(status: {drift_status or 'UNKNOWN'})",
                    raw_data={"drift_monitoring": drift_monitoring, "drift_status": drift_status},
                    finding=SecurityFinding(
                        severity="HIGH",
                        dimension="Security & Robustness",
                        finding="No automated drift monitoring detected.",
                        action="Implement continuous statistical drift monitoring (KS-test, PSI).",
                        evidence_ref="P06:drift",
                        eu_ai_act_ref="Art. 9(2)(b)",
                        owasp_ref="MCP04",
                    ) if drift_score < 50 else None,
                )

                # Human oversight → Oversight evidence
                hitl = meta_data.get("human_oversight_required", False)
                escalation = meta_data.get("incident_escalation_protocol", False)
                oversight_score = 0.0
                if hitl:
                    oversight_score += 50.0
                if escalation:
                    oversight_score += 50.0

                self._add_evidence(
                    dimension="Human Oversight & Accountability",
                    source="mcp_probe:P06:oversight",
                    tier="T1",
                    value=oversight_score,
                    description=f"Human oversight: HITL={'required' if hitl else 'not required'}, "
                                f"Escalation={'active' if escalation else 'absent'}",
                    raw_data={"hitl": hitl, "escalation": escalation},
                    finding=SecurityFinding(
                        severity="CRITICAL" if oversight_score == 0 else "MEDIUM",
                        dimension="Human Oversight & Accountability",
                        finding="No human oversight or incident escalation protocol declared.",
                        action="Implement mandatory HITL review and documented escalation protocol.",
                        evidence_ref="P06:oversight",
                        eu_ai_act_ref="Art. 14(1)",
                        owasp_ref="MCP06",
                    ) if oversight_score < 50 else None,
                )

                # Dataset size → Fairness evidence
                dataset_size = int(meta_data.get("training_dataset_size", 0))
                if dataset_size >= 10000:
                    ds_score = 100.0
                elif dataset_size >= 2500:
                    ds_score = 60.0
                elif dataset_size > 0:
                    ds_score = 30.0
                else:
                    ds_score = 0.0

                class_dist = meta_data.get("training_class_distribution", {})
                balance_score = 50.0
                if class_dist:
                    counts = [float(v) for v in class_dist.values() if isinstance(v, (int, float))]
                    if counts and max(counts) > 0:
                        ratio = min(counts) / max(counts)
                        balance_score = min(100.0, ratio * 110.0)

                fairness_score = (ds_score * 0.5 + balance_score * 0.5)
                self._add_evidence(
                    dimension="Fairness & Non-Discrimination",
                    source="mcp_probe:P06:dataset",
                    tier="T1",
                    value=fairness_score,
                    description=f"Dataset: {dataset_size} samples, class balance ratio: "
                                f"{round(min(counts)/max(counts), 2) if class_dist and counts and max(counts) > 0 else 'unknown'}",
                    raw_data={"dataset_size": dataset_size, "class_distribution": class_dist},
                )

        return meta_data

    # ==================================================================
    # P07: ERROR HANDLING ANALYSIS
    # ==================================================================
    async def probe_07_error_handling(self):
        """Send malformed arguments and check for stack trace leaks."""
        self._log("P07:ERRORS", "Testing error handling with malformed inputs...")

        if not self.tools:
            return

        tool = self.tools[0]  # Test first tool
        malformed_cases = [
            ("null_args", {"__invalid__": None}),
            ("nested_object", {"exploit": {"nested": {"deep": True}}}),
            ("very_long_string", {"input": "X" * 50000}),
        ]

        stack_trace_leaked = False
        for test_name, test_args in malformed_cases:
            result = await self.client.call_tool(tool.name, test_args)

            if result.error:
                error_text = str(result.error).lower()
                # Check for stack trace indicators
                if any(indicator in error_text for indicator in
                       ["traceback", "file \"", "line ", ".py\"", "exception",
                        "at 0x", "stack", "errno"]):
                    stack_trace_leaked = True
                    self._log("P07:ERRORS",
                              f"FAIL: Stack trace leaked in error response for {test_name}.", "DANGER")

        error_handling_score = 0.0 if stack_trace_leaked else 100.0

        self._add_evidence(
            dimension="Security & Robustness",
            source="mcp_probe:P07",
            tier="T1",
            value=error_handling_score,
            description=f"Error handling: stack traces {'LEAKED' if stack_trace_leaked else 'properly contained'}.",
            raw_data={"stack_trace_leaked": stack_trace_leaked},
            finding=SecurityFinding(
                severity="HIGH" if stack_trace_leaked else "LOW",
                dimension="Security & Robustness",
                finding="Server leaks internal stack traces in error responses.",
                action="Sanitize error responses. Return generic error messages to clients.",
                evidence_ref="P07:error_handling",
                owasp_ref="MCP01",
            ) if stack_trace_leaked else None,
        )

    # ==================================================================
    # P08: DATA GOVERNANCE INSPECTION
    # ==================================================================
    async def probe_08_data_governance(self, meta_data: Dict[str, Any]):
        """Inspect encryption, retention, and data governance declarations."""
        self._log("P08:GOVERNANCE", "Inspecting data governance and encryption declarations...")

        gov_tools = [t for t in self.tools if any(kw in t.name.lower() for kw in
                     ["governance", "privacy", "data", "encryption", "retention", "compliance"])]

        gov_data = {}
        if gov_tools:
            result = await self.client.call_tool(gov_tools[0].name, {})
            if result.success and isinstance(result.data, dict):
                gov_data = result.data

        # Merge metadata and governance data
        combined = {**meta_data, **gov_data}

        # Encryption at rest
        enc_rest = combined.get("encryption_at_rest")
        enc_rest_active = (enc_rest is True or
                           (isinstance(enc_rest, dict) and enc_rest.get("enabled")))

        # Encryption in transit
        enc_transit = combined.get("encryption_in_transit")
        enc_transit_active = (enc_transit is True or
                              (isinstance(enc_transit, dict) and enc_transit.get("enabled")))

        # Data retention
        retention = combined.get("data_retention_days", 365)
        if isinstance(retention, (int, float)):
            if retention <= 90:
                retention_score = 100.0
            elif retention <= 180:
                retention_score = 60.0
            else:
                retention_score = max(0.0, 100.0 - (retention - 90) * 0.3)
        else:
            retention_score = 0.0

        # Privacy score
        privacy_score = 0.0
        if enc_rest_active:
            privacy_score += 35.0
        if enc_transit_active:
            privacy_score += 30.0
        privacy_score += retention_score * 0.25
        if combined.get("pii_redacted") or combined.get("compliance_certifications"):
            privacy_score += 10.0

        self._add_evidence(
            dimension="Privacy & Data Governance",
            source="mcp_probe:P08",
            tier="T1",
            value=min(100.0, privacy_score),
            description=f"Encryption at rest: {'✓' if enc_rest_active else '✗'}, "
                        f"In transit: {'✓' if enc_transit_active else '✗'}, "
                        f"Retention: {retention} days",
            raw_data={"encryption_at_rest": enc_rest_active, "encryption_in_transit": enc_transit_active,
                      "retention_days": retention, "governance_data": gov_data},
            finding=SecurityFinding(
                severity="CRITICAL" if not enc_rest_active else ("MEDIUM" if not enc_transit_active else "LOW"),
                dimension="Privacy & Data Governance",
                finding=f"Encryption gaps: rest={'✗' if not enc_rest_active else '✓'}, "
                        f"transit={'✗' if not enc_transit_active else '✓'}",
                action="Enforce AES-256 encryption at rest and TLS 1.3 in transit.",
                evidence_ref="P08:data_governance",
                eu_ai_act_ref="Art. 10(5)",
                owasp_ref="MCP07",
            ) if not (enc_rest_active and enc_transit_active) else None,
        )
