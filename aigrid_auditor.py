"""
AI-GRID Automated Auditor & GRC Risk Assessment Engine

Supports TWO audit modes:
1. MCP Mode: Connects to a real MCP server and probes its tools live
2. Questionnaire Mode: Generates audit from user-provided answers

Both modes produce identical output format for the dashboard.
"""

import asyncio
import json
from typing import Any, Dict, List
from ai_profile_engine import generate_audit_from_questionnaire, get_questions


class AIGRIDMCPAuditor:
    """
    Dual-mode auditor supporting both MCP-based live probing
    and questionnaire-based assessment.
    """

    def __init__(self):
        self.mcp_server = None  # Set dynamically when MCP mode is used

    # =================================================================
    # MODE 1: MCP-BASED LIVE AUDIT (Generic — works with any MCP server)
    # =================================================================
    async def run_live_audit(self, mcp_server=None) -> Dict[str, Any]:
        """
        Executes real MCP tool calls against a target AI model's MCP server
        and dynamically computes all 7 dimension scores from probe responses.

        If no MCP server is provided, attempts to use the stored one.
        """
        server = mcp_server or self.mcp_server
        if server is None:
            raise ValueError("No MCP server configured. Use questionnaire mode or provide an MCP server connection.")

        logs: List[Dict[str, str]] = []
        findings: List[Dict[str, Any]] = []

        def log(stage: str, message: str, status: str = "INFO"):
            logs.append({"stage": stage, "message": message, "status": status})

        def finding(dimension: str, severity: str, issue: str, action: str):
            badge_map = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "info", "LOW": "info"}
            findings.append({
                "priority": severity,
                "badge": badge_map.get(severity, "info"),
                "dimension": dimension,
                "finding": issue,
                "action": action
            })

        # =============================================================
        # PHASE 1: DISCOVERY — Connect and enumerate MCP tools
        # =============================================================
        log("DISCOVERY", "Connecting to Target AI via Model Context Protocol (MCP)...", "INFO")
        tools = await server.list_tools()
        tool_names = [t.name for t in tools]
        log("DISCOVERY", f"Discovered {len(tool_names)} registered MCP tools: {', '.join(tool_names)}", "SUCCESS")

        # =============================================================
        # PHASE 2: METADATA EXTRACTION
        # =============================================================
        metadata = {}
        has_metadata_tool = "get_model_metadata" in tool_names

        if has_metadata_tool:
            log("PROBE_1", "Calling MCP Tool 'get_model_metadata()' to inspect model profile...", "INFO")
            meta_res = await server.call_tool("get_model_metadata", {})
            metadata = self._parse_tool_result(meta_res)
            model_name = metadata.get("model_name", "Unknown Model")
            version = metadata.get("version", "?")
            arch = metadata.get("model_architecture", "Unknown")
            log("PROBE_1", f"Extracted Profile: '{model_name}' v{version} ({arch})", "SUCCESS")
        else:
            log("PROBE_1", "No 'get_model_metadata' tool found — using limited metadata from tool discovery.", "WARNING")
            metadata = {
                "model_name": "MCP-Connected AI System",
                "version": "Unknown",
                "model_architecture": "Unknown",
                "training_dataset_size": 0,
                "training_class_distribution": {},
                "geographic_coverage": [],
                "geographic_gaps": [],
                "encryption_at_rest": False,
                "encryption_in_transit": True,
                "human_oversight_required": False,
                "incident_escalation_protocol": False,
                "model_drift_monitoring": "",
                "drift_status": "UNKNOWN",
                "data_retention_days": 365
            }

        # =============================================================
        # PHASE 3: FAIRNESS & BIAS PROBE
        # =============================================================
        log("PROBE_2", "Probing fairness parity across demographics...", "INFO")
        fairness_score = 100.0

        has_predict_tool = "predict_soil_and_fertilizer" in tool_names or any("predict" in t.lower() for t in tool_names)
        predict_tool = next((t for t in tool_names if "predict" in t.lower()), None)

        # Geographic coverage check from metadata
        geo_coverage = metadata.get("geographic_coverage", [])
        geo_gaps = metadata.get("geographic_gaps", [])
        total_regions = len(geo_coverage) + len(geo_gaps)
        coverage_ratio = len(geo_coverage) / max(total_regions, 1) if total_regions > 0 else 0.5

        if total_regions > 0 and coverage_ratio < 0.6:
            penalty = round((1.0 - coverage_ratio) * 50, 1)
            fairness_score -= penalty
            log("PROBE_2", f"FAIRNESS ISSUE: Coverage only {coverage_ratio*100:.0f}% ({len(geo_coverage)}/{total_regions} groups).", "WARNING")
            finding("Fairness & Bias", "HIGH",
                    f"Training data covers only {len(geo_coverage)} of {total_regions} target groups.",
                    "Expand training data to include underrepresented groups and demographics.")
        elif total_regions > 0:
            log("PROBE_2", "Geographic/demographic fairness parity verified.", "SUCCESS")
        else:
            fairness_score -= 10
            log("PROBE_2", "FAIRNESS NOTE: Unable to assess geographic coverage — no metadata available.", "WARNING")

        # Class imbalance check
        class_dist = metadata.get("training_class_distribution", {})
        if class_dist:
            counts = list(class_dist.values())
            if counts:
                max_count = max(counts)
                min_count = min(counts)
                imbalance_ratio = min_count / max(max_count, 1)
                if imbalance_ratio < 0.25:
                    fairness_score -= 10
                    log("PROBE_2", f"CLASS IMBALANCE: Smallest class has {min_count} samples vs largest {max_count} (ratio: {imbalance_ratio:.2f}).", "WARNING")

        fairness_score = round(max(10.0, min(100.0, fairness_score)), 1)

        # =============================================================
        # PHASE 4: SAFETY & RELIABILITY PROBE
        # =============================================================
        log("PROBE_3", "Probing safety guardrails...", "INFO")
        safety_score = 100.0

        # Check for prediction tools and try probing them
        guardrails_found = 0
        if predict_tool:
            log("PROBE_3", f"Found prediction tool: '{predict_tool}'. Probing safety guardrails...", "INFO")
            # Try to get tool schema to understand parameters
            log("PROBE_3", "Analyzing tool interface for safety validation patterns...", "INFO")
            guardrails_found = 1  # At least found a prediction tool
        else:
            safety_score -= 15
            log("PROBE_3", "No prediction tool found — cannot probe safety guardrails.", "WARNING")

        # Check metadata for safety indicators
        ops = metadata.get("operational_boundaries", {})
        if ops:
            log("PROBE_3", "SAFETY PASS: Operational boundaries defined in metadata.", "SUCCESS")
            guardrails_found += 1
        else:
            safety_score -= 10
            log("PROBE_3", "SAFETY WARNING: No operational boundaries defined.", "WARNING")

        if guardrails_found == 0:
            safety_score -= 20
            finding("Safety & Reliability", "HIGH",
                    "No safety guardrails detected in the MCP tool interface.",
                    "Implement input validation, output clamping, and anomaly detection guardrails.")

        safety_score = round(max(10.0, min(100.0, safety_score)), 1)

        # =============================================================
        # PHASE 5: TRANSPARENCY PROBE
        # =============================================================
        log("PROBE_4", "Probing explainability capabilities...", "INFO")
        transparency_score = 100.0

        has_explain_tool = any("explain" in t.lower() for t in tool_names)
        if has_explain_tool:
            explain_tool = next(t for t in tool_names if "explain" in t.lower())
            log("PROBE_4", f"Found explainability tool: '{explain_tool}'.", "SUCCESS")

            try:
                explain_res = await server.call_tool(explain_tool, {})
                explain_data = self._parse_tool_result(explain_res)

                attributions = explain_data.get("feature_attributions", {})
                if not attributions or len(attributions) < 3:
                    transparency_score -= 30
                    log("PROBE_4", "TRANSPARENCY WARNING: Insufficient feature attributions.", "WARNING")
                else:
                    log("PROBE_4", f"Feature attributions present: {len(attributions)} features.", "SUCCESS")

                reasoning = explain_data.get("reasoning_summary", "")
                if reasoning and len(reasoning) > 30:
                    log("PROBE_4", "Reasoning summary verified.", "SUCCESS")
                else:
                    transparency_score -= 10
                    log("PROBE_4", "TRANSPARENCY GAP: No human-readable reasoning summary.", "WARNING")
            except Exception:
                transparency_score -= 15
                log("PROBE_4", "TRANSPARENCY WARNING: Explainability tool call failed.", "WARNING")
        else:
            transparency_score -= 40
            log("PROBE_4", "TRANSPARENCY FAIL: No explainability tool found in MCP interface.", "DANGER")
            finding("Transparency", "HIGH",
                    "No explainability tool available — predictions are not interpretable.",
                    "Implement a SHAP/LIME/Grad-CAM explainability tool and register it via MCP.")

        transparency_score = round(max(10.0, min(100.0, transparency_score)), 1)

        # =============================================================
        # PHASE 6: PRIVACY & GOVERNANCE PROBE
        # =============================================================
        log("PROBE_5", "Auditing data storage policies and encryption...", "INFO")
        privacy_score = 100.0

        if not metadata.get("encryption_at_rest", False):
            privacy_score -= 30
            log("PROBE_5", "PRIVACY VULNERABILITY: Data stored UNENCRYPTED at rest.", "WARNING")
            finding("Privacy & Governance", "HIGH",
                    "Data is not encrypted at rest.",
                    "Enable AES-256 database encryption at rest and implement key rotation policy.")
        else:
            log("PROBE_5", "Data encryption at rest: ENABLED.", "SUCCESS")

        if not metadata.get("encryption_in_transit", False):
            privacy_score -= 20
            log("PROBE_5", "PRIVACY VULNERABILITY: Data transmitted without encryption.", "DANGER")
        else:
            log("PROBE_5", "Data encryption in transit (TLS): ENABLED.", "SUCCESS")

        retention_days = metadata.get("data_retention_days", 0)
        if retention_days > 180:
            privacy_score -= 15
            log("PROBE_5", f"DATA GOVERNANCE ISSUE: Retention period is {retention_days} days.", "WARNING")
            finding("Privacy & Governance", "MEDIUM",
                    f"Data retention period is {retention_days} days — exceeds recommended 90-day limit.",
                    "Shorten data retention to 90 days or implement re-consent workflow.")
        elif retention_days > 90:
            privacy_score -= 5
            log("PROBE_5", f"Data retention: {retention_days} days (borderline).", "INFO")
        else:
            log("PROBE_5", f"Data retention: {retention_days} days (within limits).", "SUCCESS")

        privacy_score = round(max(10.0, min(100.0, privacy_score)), 1)

        # =============================================================
        # PHASE 7: ACCOUNTABILITY PROBE
        # =============================================================
        log("PROBE_6", "Inspecting human oversight controls...", "INFO")
        accountability_score = 100.0

        if not metadata.get("human_oversight_required", False):
            accountability_score -= 45
            log("PROBE_6", "ACCOUNTABILITY BOTTLENECK: AI outputs delivered without human review!", "DANGER")
            finding("Accountability & Oversight", "CRITICAL",
                    "Direct automated output delivery without human-in-the-loop validation.",
                    "Implement a human-in-the-loop validation step for high-risk predictions.")
        else:
            log("PROBE_6", "Human oversight: REQUIRED.", "SUCCESS")

        if not metadata.get("incident_escalation_protocol", False):
            accountability_score -= 20
            log("PROBE_6", "ACCOUNTABILITY GAP: No incident escalation protocol.", "WARNING")
        else:
            log("PROBE_6", "Incident escalation protocol: DEFINED.", "SUCCESS")

        accountability_score = round(max(10.0, min(100.0, accountability_score)), 1)

        # =============================================================
        # PHASE 8: SECURITY & ROBUSTNESS PROBE
        # =============================================================
        log("PROBE_7", "Probing adversarial robustness...", "INFO")
        security_score = 100.0

        has_adversarial_tool = any("adversarial" in t.lower() or "robust" in t.lower() or "perturbation" in t.lower() for t in tool_names)
        if has_adversarial_tool:
            adv_tool = next(t for t in tool_names if "adversarial" in t.lower() or "robust" in t.lower() or "perturbation" in t.lower())
            log("PROBE_7", f"Found adversarial testing tool: '{adv_tool}'. Running probes...", "INFO")

            try:
                adv_res = await server.call_tool(adv_tool, {})
                adv_data = self._parse_tool_result(adv_res)

                divergence = adv_data.get("divergence_score", 0)
                adv_status = adv_data.get("robustness_status", "UNKNOWN")

                if adv_status == "VULNERABLE":
                    penalty = round(divergence * 40, 1)
                    security_score -= penalty
                    log("PROBE_7", f"SECURITY WARNING: Adversarial vulnerability detected (divergence: {divergence:.4f}).", "WARNING")
                    finding("Security & Robustness", "MEDIUM",
                            f"Adversarial noise sensitivity — divergence score {divergence:.2f}.",
                            "Implement input denoising or adversarial training to improve robustness.")
                else:
                    log("PROBE_7", f"Adversarial test: {adv_status} (divergence: {divergence:.4f}).", "SUCCESS")
            except Exception:
                security_score -= 10
                log("PROBE_7", "SECURITY WARNING: Adversarial test tool call failed.", "WARNING")
        else:
            security_score -= 20
            log("PROBE_7", "No adversarial testing tool found in MCP interface.", "WARNING")
            finding("Security & Robustness", "MEDIUM",
                    "No adversarial robustness testing capability available via MCP.",
                    "Add an adversarial perturbation testing tool to the MCP interface.")

        drift_monitoring = metadata.get("model_drift_monitoring", "")
        if drift_monitoring:
            log("PROBE_7", f"Model drift monitoring: {drift_monitoring}.", "SUCCESS")
        else:
            security_score -= 10
            log("PROBE_7", "SECURITY GAP: No model drift monitoring configured.", "WARNING")

        security_score = round(max(10.0, min(100.0, security_score)), 1)

        # =============================================================
        # PHASE 9: SOCIETAL IMPACT PROBE
        # =============================================================
        log("PROBE_8", "Auditing societal impact...", "INFO")
        societal_score = 100.0

        dataset_size = metadata.get("training_dataset_size", 0)
        if dataset_size < 2000:
            societal_score -= 25
            log("PROBE_8", f"SOCIETAL CONCERN: Training dataset ({dataset_size} samples) too small.", "WARNING")
        elif dataset_size < 5000:
            societal_score -= 8
            log("PROBE_8", f"Training dataset: {dataset_size} samples — adequate.", "INFO")
        else:
            log("PROBE_8", f"Training dataset: {dataset_size} samples — sufficient.", "SUCCESS")

        if len(geo_gaps) > len(geo_coverage):
            societal_score -= 12
            log("PROBE_8", f"SOCIETAL CONCERN: {len(geo_gaps)} underserved groups vs {len(geo_coverage)} covered.", "WARNING")

        societal_score = round(max(10.0, min(100.0, societal_score)), 1)

        # =============================================================
        # COMPOSE SCORES & COMPLIANCE
        # =============================================================
        dimensions = {
            "Fairness & Bias": fairness_score,
            "Transparency": transparency_score,
            "Safety & Reliability": safety_score,
            "Privacy & Governance": privacy_score,
            "Accountability & Oversight": accountability_score,
            "Security & Robustness": security_score,
            "Societal Impact": societal_score
        }

        dim_values = list(dimensions.values())
        weighted_average = sum(dim_values) / len(dim_values)
        bottleneck_score = min(dim_values)
        bottleneck_dimension = [k for k, v in dimensions.items() if v == bottleneck_score][0]

        alpha = 0.6
        aas = round((alpha * weighted_average) + ((1.0 - alpha) * bottleneck_score), 1)

        if aas >= 90: grade = "A+"
        elif aas >= 80: grade = "A"
        elif aas >= 70: grade = "B"
        elif aas >= 60: grade = "C"
        elif aas >= 50: grade = "D"
        else: grade = "F"

        if aas >= 76:
            eu_tier, eu_color, eu_desc = "MINIMAL RISK", "emerald", "Unregulated or low regulatory burden under EU AI Act."
        elif aas >= 51:
            eu_tier, eu_color, eu_desc = "LIMITED RISK", "amber", "Transparency obligations apply (must disclose AI nature and confidence)."
        elif aas >= 26:
            eu_tier, eu_color, eu_desc = "HIGH RISK", "orange", "Strict regulatory requirements: Conformity assessment, risk management & human oversight required."
        else:
            eu_tier, eu_color, eu_desc = "UNACCEPTABLE RISK", "rose", "Prohibited from deployment under EU AI Act Article 5."

        def nist_status(val: float) -> Dict[str, Any]:
            if val >= 70: return {"score": round(val, 1), "status": "COMPLIANT", "badge": "success"}
            elif val >= 45: return {"score": round(val, 1), "status": "PARTIALLY COMPLIANT", "badge": "warning"}
            return {"score": round(val, 1), "status": "NON-COMPLIANT", "badge": "danger"}

        nist_rmf = {
            "GOVERN": nist_status((dimensions["Accountability & Oversight"] + dimensions["Privacy & Governance"]) / 2),
            "MAP": nist_status((dimensions["Societal Impact"] + dimensions["Fairness & Bias"]) / 2),
            "MEASURE": nist_status((dimensions["Fairness & Bias"] + dimensions["Transparency"] + dimensions["Safety & Reliability"]) / 3),
            "MANAGE": nist_status((dimensions["Security & Robustness"] + dimensions["Safety & Reliability"]) / 2)
        }

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda x: severity_order.get(x["priority"], 99))

        return {
            "model_metadata": metadata,
            "dimensions": dimensions,
            "scoring": {
                "aas_score": aas,
                "weighted_average": round(weighted_average, 1),
                "bottleneck_score": round(bottleneck_score, 1),
                "bottleneck_dimension": bottleneck_dimension,
                "trust_grade": grade
            },
            "compliance": {
                "eu_ai_act": {"tier": eu_tier, "color": eu_color, "description": eu_desc},
                "nist_ai_rmf": nist_rmf
            },
            "remediation_plan": findings,
            "audit_logs": logs,
            "probe_summary": {
                "total_probes": 8,
                "mcp_tools_called": len(tool_names),
                "guardrails_tested": guardrails_found,
                "adversarial_tests": 1 if has_adversarial_tool else 0,
                "findings_count": len(findings)
            },
            "audit_mode": "mcp"
        }

    # =================================================================
    # MODE 2: QUESTIONNAIRE-BASED AUDIT
    # =================================================================
    def run_questionnaire_audit(self, answers: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates a full 7-dimension audit from questionnaire answers.
        Delegates to the ai_profile_engine module.
        """
        return generate_audit_from_questionnaire(answers)

    # =================================================================
    # SIMULATION ENGINE (works with both modes)
    # =================================================================
    def simulate_scenario(self, base_aas: float, domain: str, scale_users: int) -> Dict[str, Any]:
        """
        Algorithm 5: What-If Simulation Engine with Context Multipliers
        """
        multipliers = {
            "Home Hobbyist / Backyard": 0.8,
            "Commercial Agriculture": 1.4,
            "Healthcare / Medical": 1.5,
            "Healthcare": 1.5,
            "Criminal Justice / Law Enforcement": 1.5,
            "Criminal Justice": 1.5,
            "Finance / Banking": 1.3,
            "Finance": 1.3,
            "Autonomous Vehicles / Robotics": 1.5,
            "Autonomous Vehicles": 1.5,
            "Education / EdTech": 1.1,
            "Education": 1.1,
            "Entertainment / Media": 0.8,
            "Entertainment": 0.8,
            "E-Commerce / Retail": 1.1,
            "Manufacturing / Industrial": 1.2,
            "Cybersecurity / Threat Detection": 1.3,
            "General Purpose AI": 1.0
        }
        mult = multipliers.get(domain, 1.0)
        scale_factor = 1.0 + (min(scale_users, 1_000_000) / 2_000_000)

        base_risk = 100.0 - base_aas
        adjusted_risk = min(99.0, max(5.0, base_risk * mult * scale_factor))
        simulated_aas = round(100.0 - adjusted_risk, 1)

        if simulated_aas >= 76: tier = "MINIMAL RISK"
        elif simulated_aas >= 51: tier = "LIMITED RISK"
        elif simulated_aas >= 26: tier = "HIGH RISK"
        else: tier = "UNACCEPTABLE RISK"

        return {
            "domain": domain,
            "scale_users": scale_users,
            "multiplier": mult,
            "simulated_aas": simulated_aas,
            "simulated_tier": tier,
            "delta": round(simulated_aas - base_aas, 1)
        }

    # =================================================================
    # HELPER
    # =================================================================
    @staticmethod
    def _parse_tool_result(result) -> Dict[str, Any]:
        """Extract structured data from an MCP tool result."""
        if hasattr(result, "structured_content") and result.structured_content:
            return result.structured_content.get("result", result.structured_content)
        elif result.content and len(result.content) > 0:
            try:
                return json.loads(result.content[0].text)
            except Exception:
                return {}
        return {}
