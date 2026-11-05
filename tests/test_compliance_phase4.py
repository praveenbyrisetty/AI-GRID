"""
Tests for Phase 4: Elimination of Fabricated Numbers & Sanitize Compliance.
Validates rigorous mathematical and regulatory compliance without external dataset dependencies.
"""

from compliance_engines import (
    evaluate_eu_ai_act_compliance,
    compute_fairness_metrics,
    solve_remediation_priority,
    generate_google_model_card,
    evaluate_nist_ai_rmf,
)


def test_unknown_domain_is_unclassified_never_minimal_risk():
    """
    BUG: Unknown domain was previously classified as 'MINIMAL RISK (Unregulated)'.
    Under EU AI Act, unclassified or unknown domains must be UNCLASSIFIED.
    """
    res = evaluate_eu_ai_act_compliance(
        domain="unknown",
        autonomy_level="semi_autonomous",
        dimensions={"Security & Robustness": 80.0},
    )
    tier = res["intended_purpose_classification"]["tier"]
    assert "MINIMAL" not in tier, f"Unknown domain should not be MINIMAL RISK, got {tier}"
    assert tier == "UNCLASSIFIED"


def test_fairness_not_fabricated_without_csv_and_eod_not_085_spd():
    """
    When no predictions CSV is provided, target model metrics are not fabricated,
    and the engine honestly returns NO_EVALUATION_DATASET_PROVIDED.
    """
    res = compute_fairness_metrics(answers={}, fairness_score=75.0)
    assert res["evaluated"] is False
    assert res["status"] == "NO_EVALUATION_DATASET_PROVIDED"
    assert res["pre_mitigation"] is None


def test_remediation_priority_ranked_by_severity_no_fake_gains():
    """
    BUG: solve_remediation_priority previously added fake projected_dimension_gain (12, 8, 4)
    and computed fake projected_aas.
    """
    findings = [
        {"priority": "CRITICAL", "finding": "Boundary bypass", "action": "Add bounds check", "dimension": "Safety & Reliability"},
        {"priority": "LOW", "finding": "Minor typo in schema", "action": "Fix typo", "dimension": "Transparency & Explainability"},
    ]
    res = solve_remediation_priority(current_aas=60.0, dimensions={"Safety & Reliability": 40.0}, findings=findings)
    interventions = res["recommended_interventions"]
    assert len(interventions) >= 2
    # First intervention must be the CRITICAL one
    assert interventions[0]["priority"] == "CRITICAL"
    # Must not show fabricated guaranteed score gains
    for item in interventions:
        assert "projected_dimension_gain" not in item or item.get("projected_dimension_gain") is None


def test_model_card_has_no_certified_or_verified_hitl():
    """
    BUG: Model cards previously claimed 'Certified', 'verified human-in-the-loop',
    and 'certified tolerances'.
    """
    audit_payload = {
        "model_metadata": {"model_name": "TestModel", "version": "1.0", "domain": "Healthcare"},
        "scoring": {"aas_score": 80.0, "trust_grade": "A"},
        "dimensions": {"Safety & Reliability": 80.0},
        "compliance": {"eu_ai_act": {"tier": "HIGH RISK (Annex III)"}},
        "remediation_plan": [],
    }
    card = generate_google_model_card(audit_payload)
    md = card["markdown"]
    assert "verified human-in-the-loop" not in md.lower()
    assert "certified tolerances" not in md.lower()
    assert "certified demo" not in md.lower()


def test_nist_ai_rmf_playbook_official_subcategories_and_ai_100_1():
    """
    Verifies that NIST evaluation references NIST AI 100-1 (not SP 1270)
    and uses verified Playbook subcategory IDs.
    """
    res = evaluate_nist_ai_rmf({"Security & Robustness": 80.0})
    engine_name = res["engine"]
    assert "SP 1270" not in engine_name, f"Should reference NIST AI 100-1, got {engine_name}"
    assert "100-1" in engine_name
    govern = res["functions"]["GOVERN"]["subcategories"]
    sub_ids = [s["id"] for s in govern]
    assert "GOVERN 1.1" in sub_ids
    assert "GOVERN 1.2" in sub_ids
