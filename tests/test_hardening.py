"""v5.1 hardening tests: catalog completeness, coverage, gap isolation, grade caps, severity, parameters."""
import pytest

import ai_profile_engine as eng
from ai_profile_engine import (
    QUESTIONS, DIMENSIONS_LIST, assess_coverage, calculate_dimension_scores,
    compute_aas_and_bottleneck, generate_audit_from_questionnaire, resolve_dimension_weights,
)

Q = [q for q in QUESTIONS if not q.get("is_identity")]


def best_answers(domain="other"):
    a = {"model_name": "t", "domain": domain}
    for q in Q:
        a[q["id"]] = max(q["options"], key=lambda o: o["score"])["value"]
    return a


def worst_answers(domain="other"):
    a = {"model_name": "t", "domain": domain}
    for q in Q:
        a[q["id"]] = min(q["options"], key=lambda o: o["score"])["value"]
    return a


def test_every_question_has_complete_grc_mapping():
    for q in Q:
        for k in ("eu_ai_act_ref", "nist_rmf_ref", "governance_action", "owner_role", "evidence_expected"):
            assert q.get(k), f"{q['id']} missing {k}"
        assert q["eu_ai_act_ref"].startswith(("Art.", "Annex")), q["id"]
    assert len(Q) == 35
    assert len({q["id"] for q in Q}) == 35


def test_five_questions_per_dimension():
    for d in DIMENSIONS_LIST:
        assert sum(1 for q in Q if q["dimension"] == d) == 5


def test_findings_use_governance_wording_not_engineering():
    out = generate_audit_from_questionnaire(worst_answers())
    assert out["remediation_plan"]
    for f in out["remediation_plan"]:
        assert "engineering control" not in f["action"].lower()
        assert f["required_governance_action"] and f["owner_role"] and f["evidence_expected"]


def test_unanswered_questions_are_gaps_not_compliance():
    a = best_answers()
    for qid in ("q21_human_oversight", "q10_fairness_audit"):
        del a[qid]
    a["q20_governance_policy"] = "not_a_real_option"
    cov = assess_coverage(a)
    assert cov["total_questions"] == 35 and cov["answered_questions"] == 32
    assert {g["id"] for g in cov["unanswered_questions"]} == {"q21_human_oversight", "q10_fairness_audit"}
    assert cov["invalid_answers"][0]["id"] == "q20_governance_policy"
    out = generate_audit_from_questionnaire(a)
    assert out["audit_summary"]["total_questions"] == 35
    assert out["audit_summary"]["answered_questions"] == 32
    assert len(out["assessment_gaps"]) == 3


def test_coverage_and_assurance_levels():
    a = best_answers()
    assert assess_coverage(a)["assurance_level"] == "SELF_ASSESSED"
    ev = [{"item_id": "q10_fairness_audit", "verified_score": 1.0, "claim_supported": True}]
    cov = assess_coverage(a, ev)
    assert cov["verified_questions"] == 1 and cov["assurance_level"] == "PARTIALLY_VERIFIED"
    assert cov["max_attainable_verified_coverage_pct"] == round(100 * 5 / 35, 1)
    all5 = [{"item_id": i, "verified_score": 1.0, "claim_supported": True} for i in eng.VERIFIABLE_QUESTION_IDS]
    assert assess_coverage(a, all5)["assurance_level"] == "VERIFIED_WITHIN_VERIFIABLE_SCOPE"


def test_attestation_gap_zero_when_verifier_agrees_with_mixed_answers():
    """Gap must reflect verifier disagreement only, not the effect of weighting."""
    a = best_answers()
    a["q6_demographic_coverage"] = "partial" if any(o["value"] == "partial" for q in Q if q["id"] == "q6_demographic_coverage" for o in q["options"]) else a["q6_demographic_coverage"]
    # make the fairness dimension mixed
    q7 = next(q for q in Q if q["id"] == "q7_class_balance")
    a["q7_class_balance"] = min(q7["options"], key=lambda o: o["score"])["value"]
    ev = [{"item_id": "q10_fairness_audit", "verified_score": 1.0, "claim_supported": True}]
    _, _, _, gap = calculate_dimension_scores(a, verified_evidence=ev)
    assert gap["composite_gap"] == 0.0
    assert gap["dimensions"]["Fairness & Non-Discrimination"]["gap"] == 0.0


def test_attestation_gap_positive_when_claim_refuted():
    a = best_answers()
    ev = [{"item_id": "q10_fairness_audit", "verified_score": 0.0, "claim_supported": False}]
    _, _, _, gap = calculate_dimension_scores(a, verified_evidence=ev)
    assert gap["dimensions"]["Fairness & Non-Discrimination"]["gap"] > 0
    assert gap["composite_gap"] > 0


def test_grade_cap_on_refuted_claim_keeps_numeric_aas():
    a = best_answers()
    ev = [{"item_id": "q10_fairness_audit", "verified_score": 0.0, "claim_supported": False}]
    out = generate_audit_from_questionnaire(a, verified_evidence=ev)
    sc = out["scoring"]
    assert sc["aas_score"] >= 80
    assert sc["uncapped_grade"] in ("A", "A+")
    assert sc["trust_grade"] == "C"
    assert sc["grade_caps_applied"]


def test_no_cap_when_nothing_refuted_and_no_critical():
    out = generate_audit_from_questionnaire(best_answers())
    assert out["scoring"]["trust_grade"] == "A+"
    assert out["scoring"]["grade_caps_applied"] == []


def test_high_risk_domain_escalates_severity():
    a = worst_answers("healthcare")
    b = worst_answers("agriculture")
    hi = {f["question_id"]: f for f in generate_audit_from_questionnaire(a)["remediation_plan"]}
    lo = {f["question_id"]: f for f in generate_audit_from_questionnaire(b)["remediation_plan"]}
    fairness = "q10_fairness_audit"
    assert lo[fairness]["priority"] == "HIGH"
    assert hi[fairness]["priority"] == "CRITICAL"
    assert hi[fairness]["priority_base"] == "HIGH"


def test_alpha_is_validated_and_applied():
    with pytest.raises(ValueError):
        generate_audit_from_questionnaire(best_answers(), alpha=1.5)
    d = {k: 100.0 for k in DIMENSIONS_LIST}
    d["Fairness & Non-Discrimination"] = 40.0
    lo = compute_aas_and_bottleneck(d, alpha=0.2)["aas_score"]
    hi = compute_aas_and_bottleneck(d, alpha=0.8)["aas_score"]
    assert lo < hi


def test_dimension_weights_change_mean_but_not_bottleneck():
    d = {k: 100.0 for k in DIMENSIONS_LIST}
    d["Fairness & Non-Discrimination"] = 50.0
    eq = compute_aas_and_bottleneck(d)
    w = resolve_dimension_weights("domain", "finance")
    fw = compute_aas_and_bottleneck(d, dimension_weights=w)
    assert eq["bottleneck_score"] == fw["bottleneck_score"] == 50.0
    assert fw["weighted_average"] < eq["weighted_average"]
    assert resolve_dimension_weights("equal") is None
    with pytest.raises(ValueError):
        resolve_dimension_weights({"Fairness & Non-Discrimination": -1})


def test_t2_documentary_evidence_weight_between_t1_and_t3():
    a = best_answers()
    a["q7_class_balance"] = min(next(q for q in Q if q["id"] == "q7_class_balance")["options"], key=lambda o: o["score"])["value"]
    base, _, _, _ = calculate_dimension_scores(a)
    ref, _, _, _ = calculate_dimension_scores(a, evidence_refs={"q7_class_balance": "Dataset report v3"})
    # the weak answer carries more weight with a document reference, so the dimension score drops
    assert ref["Fairness & Non-Discrimination"] < base["Fairness & Non-Discrimination"]


def test_api_rejects_bad_parameters_and_accepts_good_ones():
    import server
    c = server.app.test_client()
    body = {"answers": best_answers()}
    assert c.post("/api/audit/questionnaire", json={**body, "alpha": 2}).status_code == 400
    assert c.post("/api/audit/questionnaire", json={**body, "weight_profile": "nonsense"}).status_code == 400
    assert c.post("/api/audit/questionnaire", json={**body, "evidence_refs": []}).status_code == 400
    ok = c.post("/api/audit/questionnaire", json={**body, "alpha": 0.5, "weight_profile": "domain"})
    assert ok.status_code == 200
    assert ok.get_json()["data"]["scoring_parameters"]["alpha"] == 0.5
