"""
AI-GRID Automated Protocol Auditor & GRC Risk Engine (v4.0)

Implements Dual-Mode Trust Auditing with real MCP protocol probing:

1. Automated MCP Protocol Probing (Evidence Tier T1, weight 1.0):
   - Connects to target MCP server via stdio transport using the official MCP SDK
   - Executes 8 security probes (tool discovery, schema validation, boundary testing, etc.)
   - Generates structured Evidence objects with provenance tracking
   
2. Structured Questionnaire Assessment (Evidence Tier T3, weight 0.6):
   - 30 research-grounded items mapped to 6 dimensions
   - Evidence-weighted scoring (T3 weight = 0.6)

3. Attestation Discrepancy Analysis (Comparative Engine):
   - Computes ADI = mean(S_self(d) - S_probe(d)) to quantify self-reporting bias

DISCLAIMER: This assessment does not constitute legal certification.
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from evidence import (
    Evidence,
    SecurityFinding,
    DIMENSIONS_LIST,
    TIER_WEIGHTS,
    aggregate_dimension_scores,
    compute_aas,
)
from ai_profile_engine import (
    generate_audit_from_questionnaire,
    get_questions,
    compute_aas_and_bottleneck,
    DOMAIN_LABELS,
)
from compliance_engines import (
    compute_fairness_metrics,
    analyze_risk_cohorts,
    solve_remediation_priority,
    evaluate_eu_ai_act_compliance,
    evaluate_nist_ai_rmf,
    map_owasp_and_atlas,
    scan_ai_vulnerabilities,
    generate_google_model_card,
)

logger = logging.getLogger("aigrid.auditor")

# Base directory for demo servers
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEMO_SERVERS_DIR = os.path.join(BASE_DIR, "demo_servers")

# Demo server profile mapping
DEMO_SERVER_PROFILES = {
    "good": os.path.join(DEMO_SERVERS_DIR, "good_server.py"),
    "moderate": os.path.join(DEMO_SERVERS_DIR, "moderate_server.py"),
    "poor": os.path.join(DEMO_SERVERS_DIR, "poor_server.py"),
}


class AIGRIDMCPAuditor:
    """
    Dual-mode auditor evaluating AI trust across 6 dimensions
    via real MCP protocol probing and self-attested questionnaire analysis.
    """

    def __init__(self):
        self.last_probe_results: Dict[str, Any] = {}

    # =================================================================
    # MODE 1: MCP-BASED AUTOMATED PROBE AUDIT (Evidence Tier T1)
    # Uses real MCP protocol via official SDK
    # =================================================================
    async def run_live_audit(
        self,
        profile: str = "good",
        mcp_command: Optional[str] = None,
        mcp_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Executes real protocol-level MCP tool probing against target AI agent.

        Args:
            profile: Demo server profile ("good", "moderate", "poor").
                     Used when mcp_command is not provided.
            mcp_command: Custom command to launch the MCP server (e.g., "python").
            mcp_args: Arguments for the server command (e.g., ["my_server.py"]).

        Returns:
            Complete audit payload with evidence-weighted dimension scores.
        """
        logs: List[Dict[str, str]] = []

        def log(stage: str, msg: str, st: str = "INFO"):
            logs.append({"stage": stage, "message": msg, "status": st})

        log("INIT", "AI-GRID MCP Protocol Auditor v4.0 starting...")
        log("INIT", "Evidence collection mode: T1 (Automated Runtime Observation, weight=1.0)")

        # Determine MCP server target
        if mcp_command and mcp_args:
            server_command = mcp_command
            server_args = mcp_args
            log("TARGET", f"Custom MCP server: {mcp_command} {' '.join(mcp_args)}")
        else:
            server_script = DEMO_SERVER_PROFILES.get(profile)
            if not server_script or not os.path.exists(server_script):
                log("TARGET", f"Demo server script not found for profile '{profile}'", "ERROR")
                return self._build_error_payload(
                    f"Demo server script not found for profile '{profile}'. "
                    f"Expected at: {server_script}",
                    logs,
                )
            server_command = sys.executable  # Use the current Python interpreter
            server_args = [server_script]
            log("TARGET", f"Demo MCP server profile: {profile} ({server_script})")

        # Try to connect via real MCP SDK
        use_sdk = True
        evidence_items = []
        tools_discovered = []
        meta_data = {}

        try:
            from mcp_client import MCPClient
            from mcp_probes import MCPSecurityProber

            client = MCPClient(timeout=30.0)
            async with client.session(server_command, server_args) as session_client:
                log("CONNECTION", "Connected to target MCP server via stdio transport (official MCP SDK).", "SUCCESS")
                prober = MCPSecurityProber(session_client)
                probe_results = await prober.run_all_probes()

                evidence_items = probe_results["evidence"]
                probe_logs = probe_results["logs"]
                tools_discovered = probe_results["tools_discovered"]
                meta_data = probe_results.get("metadata", {})

                logs.extend(probe_logs)
                log("PROBES", f"Completed 8 security probes. Collected {len(evidence_items)} evidence items.", "SUCCESS")

        except Exception as e:
            logger.warning(f"MCP SDK connection/probing failed: {e}. Attempting fallback.")
            log("CONNECTION", f"MCP SDK error: {e}. Falling back to direct invocation.", "WARNING")
            use_sdk = False

        # Fallback: direct invocation (strictly for demo servers, NEVER for custom targets)
        if not use_sdk:
            if mcp_command:
                log("CONNECTION", f"Failed to connect to custom MCP target '{server_command}' via MCP protocol.", "ERROR")
                return self._build_error_payload(
                    f"Live MCP protocol connection to '{server_command}' failed. "
                    "Simulated fallbacks are disabled for live targets to guarantee test integrity.",
                    logs,
                )
            log("CONNECTION", "Using DIRECT INVOCATION demo benchmark fallback (not live wire MCP protocol).", "WARNING")
            log("INTEGRITY", "NOTICE: This benchmark run executed via simulated in-process calls.", "WARNING")
            fallback_client = await self._create_fallback_client(profile)
            if not fallback_client:
                return self._build_error_payload(
                    "Failed to connect to demo MCP server via both SDK and fallback.",
                    logs,
                )
            try:
                from mcp_probes import MCPSecurityProber
                prober = MCPSecurityProber(fallback_client)
                probe_results = await prober.run_all_probes()

                evidence_items = probe_results["evidence"]
                probe_logs = probe_results["logs"]
                tools_discovered = probe_results["tools_discovered"]
                meta_data = probe_results.get("metadata", {})

                logs.extend(probe_logs)
                log("PROBES", f"Completed 8 security probes (fallback mode). Collected {len(evidence_items)} evidence items.", "SUCCESS")
            except Exception as e:
                log("PROBES", f"Fallback probe execution error: {e}", "ERROR")
                return self._build_error_payload(f"Probe execution failed: {e}", logs)

        # Aggregate evidence into dimension scores
        dimension_results = aggregate_dimension_scores(evidence_items)
        dimensions = {name: r.score for name, r in dimension_results.items()}

        # Compute AAS
        scoring = compute_aas(dimension_results, alpha=0.6)
        log("SCORING", f"AAS: {scoring['aas_score']}/100 (Grade: {scoring['trust_grade']}) | "
            f"Confidence: {scoring['overall_confidence']:.1%} | "
            f"Bottleneck: '{scoring['bottleneck_dimension']}' ({scoring['bottleneck_score']})",
            "SUCCESS")

        # Extract security findings from evidence
        findings = [
            e.finding.to_dict() for e in evidence_items
            if e.finding is not None
        ]
        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda x: sev_order.get(x.get("priority", "LOW"), 99))

        # Regulatory evaluation
        eu_comp = evaluate_eu_ai_act_compliance(
            domain=meta_data.get("domain", "Agriculture / Environmental"),
            autonomy_level="semi_autonomous" if meta_data.get("human_oversight_required") else "fully_autonomous",
            dimensions=dimensions,
        )
        nist_comp = evaluate_nist_ai_rmf(dimensions=dimensions)
        threat_cross = map_owasp_and_atlas(findings=findings, dimensions=dimensions)

        fairness_metrics = compute_fairness_metrics(
            metadata=meta_data,
            fairness_score=dimensions.get("Fairness & Non-Discrimination", 50.0),
        )
        risk_cohorts = analyze_risk_cohorts(
            dimensions=dimensions, findings=findings, metadata=meta_data,
        )
        remediation = solve_remediation_priority(
            current_aas=scoring["aas_score"], dimensions=dimensions,
            findings=findings, target_score=76.0,
        )
        vulnerability_scan = scan_ai_vulnerabilities(
            domain=meta_data.get("domain", "General Purpose AI"),
        )

        audit_payload = {
            "execution_mode": "DEMO_BENCHMARK" if (not mcp_command) else "LIVE_MCP_PROTOCOL",
            "is_demo": bool(not mcp_command),
            "protocol_verified": bool(use_sdk),
            "protocol_status": "OFFICIAL_MCP_SDK_STDIO_VERIFIED" if use_sdk else "SIMULATED_FALLBACK_NON_PROTOCOL",
            "model_metadata": {
                "model_name": meta_data.get("model_name", "MCP Target AI"),
                "version": meta_data.get("version", "Unknown"),
                "domain": meta_data.get("domain", "Unknown"),
                "model_architecture": meta_data.get("model_architecture", "Unknown"),
                "deployment_type": "mcp_agent",
                "execution_mode": "DEMO_BENCHMARK" if (not mcp_command) else "LIVE_MCP_PROTOCOL",
                "audit_mode_label": "Certified Demo Benchmark Audit" if (not mcp_command) else "Live Wire MCP Protocol Audit",
                "evidence_tier": "T1",
                "evidence_confidence_weight": 1.0,
                "mcp_tools_discovered": tools_discovered,
                "mcp_transport": "stdio (Official MCP Python SDK)" if use_sdk else "direct_invocation (simulated_fallback)",
                "simulated_fallback": not use_sdk,
                "audit_timestamp": datetime.now().isoformat(),
            },
            "dimensions": dimensions,
            "dimension_confidences": {
                name: r.confidence for name, r in dimension_results.items()
            },
            "scoring": scoring,
            "compliance": {
                "eu_ai_act": {
                    "tier": eu_comp["intended_purpose_classification"]["tier"],
                    "badge_color": eu_comp["intended_purpose_classification"]["badge_color"],
                    "legal_basis": eu_comp["intended_purpose_classification"]["legal_basis"],
                    "market_placement_permitted": eu_comp["intended_purpose_classification"]["market_placement_permitted"],
                    "conformity_assessment_required": eu_comp["intended_purpose_classification"]["conformity_assessment_required"],
                    "overall_status": eu_comp["article_level_conformance"]["overall_status"],
                    "conformant_articles": eu_comp["article_level_conformance"]["conformant_articles"],
                    "articles": eu_comp["article_level_conformance"]["articles"],
                    "disclaimer": "This assessment is indicative only and does not constitute legal certification.",
                },
                "nist_ai_rmf": nist_comp["functions"],
            },
            "threat_landscape": {
                "owasp_llm_top_10": threat_cross["owasp_llm_top_10"],
                "owasp_mcp_top_10": threat_cross["owasp_mcp_top_10"],
                "mitre_atlas_techniques": threat_cross["mitre_atlas_techniques"],
            },
            "remediation_plan": findings,
            "audit_logs": logs,
            "probe_summary": {
                "total_probes": 8,
                "mcp_tools_called": len(tools_discovered),
                "evidence_tier": "T1",
                "confidence_weight": 1.0,
                "evidence_items_collected": len(evidence_items),
                "findings_count": len(findings),
                "critical_findings": sum(1 for f in findings if f.get("priority") == "CRITICAL"),
                "overall_confidence": scoring.get("overall_confidence", 0.0),
            },
            "audit_mode": "mcp",
            "aif360": fairness_metrics,
            "cohort_analysis": risk_cohorts,
            "prescriptive_counterfactual": remediation,
            "vulnerability_scan": vulnerability_scan,
        }

        audit_payload["model_card"] = generate_google_model_card(audit_payload)
        self.last_probe_results = audit_payload
        return audit_payload

    async def _create_fallback_client(self, profile: str):
        """Create a direct-invocation fallback client for demo servers."""
        try:
            from mcp_client import DirectInvocationClient

            # Import demo server functions based on profile
            demo_tools = self._load_demo_tools(profile)
            if not demo_tools:
                return None

            client = DirectInvocationClient()
            await client.connect_direct(demo_tools)
            return client
        except Exception as e:
            logger.error(f"Fallback client creation failed: {e}")
            return None

    def _load_demo_tools(self, profile: str) -> Dict[str, callable]:
        """Load demo tool functions for fallback mode."""
        import importlib.util
        import json

        server_script = DEMO_SERVER_PROFILES.get(profile)
        if not server_script or not os.path.exists(server_script):
            return {}

        try:
            spec = importlib.util.spec_from_file_location(f"demo_{profile}", server_script)
            module = importlib.util.module_from_spec(spec)
            # We need to mock the mcp import for direct loading
            # Instead, define simple tool wrappers based on profile
            return self._get_profile_tools(profile)
        except Exception:
            return self._get_profile_tools(profile)

    def _get_profile_tools(self, profile: str) -> Dict[str, callable]:
        """Get tool functions for a specific demo profile."""
        import json

        if profile == "good":
            def get_model_metadata():
                return {
                    "model_name": "AgriTrust-SoilNet", "version": "2.1.0",
                    "domain": "Agriculture / Environmental",
                    "model_architecture": "XGBoost + MLP",
                    "training_dataset_size": 10000,
                    "training_class_distribution": {"Alluvial": 3200, "Black": 2800, "Red": 2200, "Laterite": 1800},
                    "encryption_at_rest": True, "encryption_in_transit": True,
                    "data_retention_days": 90, "human_oversight_required": True,
                    "incident_escalation_protocol": True,
                    "model_drift_monitoring": "Automated KS & PSI (Daily)",
                    "drift_status": "MONITORED",
                }

            def predict_soil_and_fertilizer(nitrogen=65.0, phosphorus=40.0, potassium=45.0, ph=6.8, moisture=35.0, temperature=26.5):
                if nitrogen < 0 or ph < 0 or ph > 14:
                    return {"status": "REJECTED", "error": "Input validation failure", "output_clamped": False}
                raw = round(nitrogen * 0.85 + phosphorus * 0.45 + (7.0 - ph) * 5.0, 1)
                clamped = raw > 150.0 or raw < 10.0
                final = max(10.0, min(150.0, raw))
                conf = 0.942 if 5.5 <= ph <= 7.5 else 0.810
                total = abs(nitrogen) + abs(phosphorus) + abs(potassium) + abs(ph*10) + abs(moisture)
                return {
                    "status": "SUCCESS", "predicted_soil_class": "Alluvial Clay Loam",
                    "classification_confidence": conf, "recommended_dosage_kg_ha": final,
                    "output_clamped": clamped, "human_review_required": conf < 0.85 or clamped,
                    "feature_attributions": {
                        "Nitrogen": round(abs(nitrogen)/max(total,1), 3),
                        "Phosphorus": round(abs(phosphorus)/max(total,1), 3),
                    },
                    "reasoning_summary": f"Soil pH {ph}, dosage {final} kg/ha",
                }

            def test_adversarial_perturbation(noise_level=0.05):
                noise = max(0.001, min(0.5, noise_level))
                div = round(noise * 0.428, 4)
                return {"noise_level_applied": noise, "divergence_score": div,
                        "robustness_status": "ROBUST" if div < 0.05 else "VULNERABLE"}

            def get_data_governance_record():
                return {
                    "encryption_at_rest": {"enabled": True, "algorithm": "AES-256-GCM"},
                    "encryption_in_transit": {"enabled": True, "protocol": "TLS 1.3"},
                    "data_retention_days": 90, "pii_redacted": True,
                    "compliance_certifications": ["ISO 27001"],
                }

            return {
                "get_model_metadata": get_model_metadata,
                "predict_soil_and_fertilizer": predict_soil_and_fertilizer,
                "test_adversarial_perturbation": test_adversarial_perturbation,
                "get_data_governance_record": get_data_governance_record,
            }

        elif profile == "moderate":
            def get_model_metadata():
                return {
                    "model_name": "AgriModel-Beta", "version": "0.9.1",
                    "domain": "Agriculture / Environmental", "model_architecture": "Random Forest",
                    "training_dataset_size": 3200,
                    "training_class_distribution": {"Alluvial": 2200, "Clay": 1000},
                    "encryption_at_rest": False, "encryption_in_transit": True,
                    "data_retention_days": 180, "human_oversight_required": False,
                    "incident_escalation_protocol": False,
                    "model_drift_monitoring": "Manual periodic review",
                    "drift_status": "UNMONITORED",
                }

            def predict_soil_and_fertilizer(nitrogen=65.0, phosphorus=40.0, ph=6.8):
                if nitrogen < 0 or ph < 0 or ph > 14:
                    return {"status": "REJECTED", "error": "Validation failed"}
                raw = nitrogen * 0.85 + phosphorus * 0.45
                return {
                    "status": "SUCCESS", "prediction": "Alluvial_Loam",
                    "recommended_nitrogen_kg_ha": raw, "output_clamped": False,
                    "classification_confidence": 0.78,
                    "feature_attributions": {"nitrogen": 0.50, "phosphorus": 0.50},
                }

            return {
                "get_model_metadata": get_model_metadata,
                "predict_soil_and_fertilizer": predict_soil_and_fertilizer,
            }

        else:  # poor
            def raw_predict(input_value=0.0):
                return {
                    "status": "SUCCESS", "prediction": "Class_1",
                    "recommended_value": input_value * 0.9 + 25.0,
                }

            return {"raw_predict": raw_predict}

    def _build_error_payload(self, error_msg: str, logs: List[Dict]) -> Dict[str, Any]:
        """Build a minimal error payload when audit fails."""
        return {
            "model_metadata": {
                "model_name": "Unknown", "version": "Unknown",
                "domain": "Unknown", "error": error_msg,
                "audit_timestamp": datetime.now().isoformat(),
            },
            "dimensions": {d: 0.0 for d in DIMENSIONS_LIST},
            "scoring": {"aas_score": 0.0, "trust_grade": "F", "error": error_msg},
            "audit_logs": logs,
            "audit_mode": "mcp",
            "error": error_msg,
        }

    # =================================================================
    # MODE 2: QUESTIONNAIRE-BASED AUDIT (Evidence Tier T3, weight 0.6)
    # =================================================================
    def run_questionnaire_audit(self, answers: Dict[str, Any]) -> Dict[str, Any]:
        """Executes audit from self-attested questionnaire responses."""
        return generate_audit_from_questionnaire(answers, evidence_tier="T3")

    # =================================================================
    # MODE 3: ATTESTATION DISCREPANCY COMPARATIVE ENGINE
    # Tests research hypothesis: Self-Report vs Probed Reality
    # =================================================================
    def compare_attestation_vs_probe(
        self,
        questionnaire_results: Dict[str, Any],
        probe_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Calculates the Attestation Discrepancy Index (ADI):
            Delta_d = Score_self(d) - Score_probe(d)
            ADI = mean(positive deltas)

        Quantifies the gap between self-attested governance claims
        and runtime protocol observations.
        """
        q_dims = questionnaire_results.get("dimensions", {})
        p_dims = probe_results.get("dimensions", {})

        deltas = {}
        total_overestimation = 0.0

        for d in DIMENSIONS_LIST:
            s_self = q_dims.get(d, 50.0)
            s_probe = p_dims.get(d, 50.0)
            diff = round(s_self - s_probe, 1)
            deltas[d] = {
                "self_attested": s_self,
                "automated_probe": s_probe,
                "delta": diff,
                "bias_direction": (
                    "OVERESTIMATED" if diff > 5.0
                    else ("UNDERESTIMATED" if diff < -5.0 else "ALIGNED")
                ),
            }
            if diff > 0:
                total_overestimation += diff

        adi = round(total_overestimation / len(DIMENSIONS_LIST), 1)

        return {
            "engine": "Attestation Discrepancy Comparative Engine",
            "research_hypothesis": (
                "Self-attested governance reports systematically overestimate "
                "trustworthy AI posture compared to runtime protocol probing."
            ),
            "attestation_discrepancy_index": adi,
            "significance": (
                "HIGH RISK OF SELF-REPORT BIAS" if adi > 15.0
                else ("MODERATE SKEW" if adi > 5.0 else "HIGH FIDELITY")
            ),
            "dimension_deltas": deltas,
            "recommendation": (
                "Require Tier 1 runtime evidence verification "
                "prior to conformity attestation submission."
            ),
            "disclaimer": (
                "ADI > 0 indicates self-attested scores exceed probe-derived scores. "
                "This does not necessarily indicate intentional misreporting."
            ),
        }

    # =================================================================
    # SCENARIO SIMULATION ENGINE
    # =================================================================
    def simulate_scenario(
        self, base_aas: float, domain: str, scale_users: int,
    ) -> Dict[str, Any]:
        """
        Estimates how systemic failure risk scales with deployment volume.

        DISCLAIMER: This is a simplified heuristic model, not a validated
        risk prediction. Results are illustrative estimates only.
        """
        failure_prob_base = max(0.001, (100.0 - base_aas) / 1000.0)
        expected_incidents = int(failure_prob_base * scale_users)
        liability_multiplier = 250 if domain.lower() in ("healthcare", "finance") else 50
        projected_liability_usd = expected_incidents * liability_multiplier

        return {
            "base_aas": base_aas,
            "domain": domain,
            "scale_users": scale_users,
            "estimated_failure_rate_pct": round(failure_prob_base * 100, 3),
            "projected_annual_incidents": expected_incidents,
            "projected_financial_liability_usd": projected_liability_usd,
            "mitigation_savings_usd": int(projected_liability_usd * 0.72),
            "disclaimer": (
                "These projections are heuristic estimates based on a simplified "
                "model. They are not validated predictions and should not be used "
                "for financial planning or regulatory submissions."
            ),
        }
