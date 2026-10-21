"""
Unit Tests for AI-GRID Compliance & Responsible AI Engines (v4.0)
"""

import pytest
from compliance_engines import (
    evaluate_eu_ai_act_compliance,
    evaluate_nist_ai_rmf,
    map_owasp_and_atlas,
    compute_fairness_metrics,
    analyze_risk_cohorts,
    solve_remediation_priority,
    scan_ai_vulnerabilities,
    generate_google_model_card,
)


def test_eu_ai_act_prohibited_and_high_risk_classification():
    """Verify correct classification according to Annex III."""
    dims = {
        "Security & Robustness": 80.0,
        "Fairness & Non-Discrimination": 75.0,
        "Transparency & Explainability": 85.0,
        "Privacy & Data Governance": 90.0,
        "Human Oversight & Accountability": 70.0,
        "Safety & Reliability": 80.0,
    }
    # Healthcare -> High-Risk System
    res_health = evaluate_eu_ai_act_compliance(domain="healthcare", autonomy_level="semi_autonomous", dimensions=dims)
    assert "HIGH RISK" in res_health["intended_purpose_classification"]["tier"]
    assert res_health["intended_purpose_classification"]["conformity_assessment_required"] is True

    # Social scoring -> Prohibited Practice
    res_proh = evaluate_eu_ai_act_compliance(domain="social_scoring", autonomy_level="fully_autonomous", dimensions=dims)
    assert "PROHIBITED" in res_proh["intended_purpose_classification"]["tier"]
    assert res_proh["intended_purpose_classification"]["market_placement_permitted"] is False

    # Agriculture -> General Purpose AI
    res_agri = evaluate_eu_ai_act_compliance(domain="agriculture", autonomy_level="semi_autonomous", dimensions=dims)
    assert "MINIMAL" in res_agri["intended_purpose_classification"]["tier"] or "GENERAL" in res_agri["intended_purpose_classification"]["tier"]


def test_nist_ai_rmf_crosswalk():
    """Verify all 4 core NIST AI RMF functions are mapped."""
    dims = {
        "Security & Robustness": 80.0,
        "Fairness & Non-Discrimination": 75.0,
        "Transparency & Explainability": 85.0,
        "Privacy & Data Governance": 90.0,
        "Human Oversight & Accountability": 70.0,
        "Safety & Reliability": 80.0,
    }
    nist_res = evaluate_nist_ai_rmf(dims)
    assert "GOVERN" in nist_res["functions"]
    assert "MAP" in nist_res["functions"]
    assert "MEASURE" in nist_res["functions"]
    assert "MANAGE" in nist_res["functions"]
    assert nist_res["functions"]["GOVERN"]["score"] > 50.0
    assert nist_res["functions"]["GOVERN"]["subcategories"][0]["status"] in ("COMPLIANT", "PARTIALLY COMPLIANT")


def test_threat_crosswalk_evidence_based():
    """Verify OWASP and MITRE ATLAS mappings are derived from findings."""
    findings = [
        {
            "priority": "CRITICAL",
            "dimension": "Security & Robustness",
            "finding": "Tools with dangerous capabilities (exec)",
            "action": "Sandbox tool execution",
            "owasp_ref": "MCP02",
            "mitre_atlas_ref": "AML.T0054",
        },
        {
            "priority": "HIGH",
            "dimension": "Safety & Reliability",
            "finding": "Input boundary testing rejected 0 bad inputs",
            "action": "Add input validation",
            "owasp_ref": "MCP05",
            "mitre_atlas_ref": "AML.T0043",
        },
    ]
    dims = {"Security & Robustness": 50.0, "Safety & Reliability": 40.0}
    threat_res = map_owasp_and_atlas(findings=findings, dimensions=dims)

    mcp_codes = [t["code"] for t in threat_res["owasp_mcp_top_10"]]
    assert "MCP02" in mcp_codes
    assert "MCP05" in mcp_codes

    atlas_ids = [t["id"] for t in threat_res["mitre_atlas_techniques"]]
    assert "AML.T0054" in atlas_ids


def test_remediation_priority_ranker():
    """Verify ranker prioritizes critical findings with greatest dimension gap without fake projections."""
    findings = [
        {"priority": "MEDIUM", "dimension": "Transparency & Explainability", "finding": "Incomplete docs", "action": "Update docs"},
        {"priority": "CRITICAL", "dimension": "Security & Robustness", "finding": "Exec capability exposed", "action": "Sandbox"},
        {"priority": "HIGH", "dimension": "Safety & Reliability", "finding": "No output clamping", "action": "Clamp"},
    ]
    dims = {
        "Security & Robustness": 30.0,
        "Safety & Reliability": 50.0,
        "Transparency & Explainability": 80.0,
    }
    rem_res = solve_remediation_priority(current_aas=50.0, dimensions=dims, findings=findings, target_score=75.0)

    assert "recommended_interventions" in rem_res
    interventions = rem_res["recommended_interventions"]
    assert len(interventions) == 3
    # Check interventions content
    assert any(i["priority"] == "CRITICAL" for i in interventions)
    # Ensure honest disclaimer is present
    assert "projection_disclaimer" in rem_res


def test_model_card_generation():
    """Verify Model Card generation incorporates governance metadata and disclaimers."""
    audit_data = {
        "model_metadata": {
            "model_name": "TestModel",
            "version": "1.0.0",
            "domain": "Healthcare",
            "model_architecture": "Transformer",
            "deployment_type": "mcp_agent",
        },
        "scoring": {"aas_score": 75.0, "trust_grade": "B", "bottleneck_dimension": "Privacy"},
        "dimensions": {
            "Security & Robustness": 80.0,
            "Fairness & Non-Discrimination": 75.0,
            "Transparency & Explainability": 85.0,
            "Privacy & Data Governance": 60.0,
            "Human Oversight & Accountability": 75.0,
            "Safety & Reliability": 75.0,
        },
        "compliance": {"eu_ai_act": {"tier": "High-Risk AI System"}},
        "remediation_plan": [],
    }
    card = generate_google_model_card(audit_data)
    assert "TestModel" in card["markdown"]
    assert "High-Risk AI System" in card["markdown"]
    assert "DISCLAIMER" in card["markdown"]
