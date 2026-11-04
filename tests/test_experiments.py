"""
Research Validation Tests: Experiment 1 (Multi-Risk Profiling) & Experiment 2 (Sensitivity Analysis)
"""

import pytest
from aigrid_auditor import AIGRIDAuditor
from ai_profile_engine import get_questions, compute_aas_and_bottleneck


def test_experiment_1_questionnaire_governance_profiling():
    """
    Validates Hypothesis H1:
    Structured self-attestation accurately reflects the presence or absence of
    governance controls across 6 trust dimensions, with bottleneck penalization
    preventing compensatory masking of weak dimensions.
    """
    auditor = AIGRIDAuditor()

    # Profile A: High-compliance attestation (all optimal options)
    high_answers = {
        q["id"]: q["options"][0]["value"]
        for q in get_questions()
        if not q.get("is_identity") and q.get("options")
    }
    high_answers["model_name"] = "CompliantDiagnosticAI"
    high_answers["domain"] = "healthcare"
    high_answers["q22_autonomy_level"] = "human_in_loop"

    q_audit = auditor.run_questionnaire_audit(high_answers)
    self_aas = q_audit["scoring"]["aas_score"]
    assert self_aas >= 85.0
    assert q_audit["scoring"]["trust_grade"] in ("A", "A+")
    assert "HIGH RISK" in q_audit["compliance"]["eu_ai_act"]["tier"]

    # Profile B: System with severe safety defect (Q3 = None)
    low_safety_answers = dict(high_answers)
    # Set safety answers to lowest options
    for q in get_questions():
        if q.get("dimension") == "Safety & Reliability" and q.get("options"):
            low_safety_answers[q["id"]] = q["options"][-1]["value"]

    low_safety_audit = auditor.run_questionnaire_audit(low_safety_answers)
    low_aas = low_safety_audit["scoring"]["aas_score"]
    assert low_aas < self_aas
    # Bottleneck penalization ensures low safety severely drags down overall AAS
    assert low_safety_audit["scoring"]["bottleneck_score"] < low_safety_audit["scoring"]["weighted_average"]
    assert low_safety_audit["scoring"]["aas_score"] < low_safety_audit["scoring"]["weighted_average"]


def test_experiment_2_alpha_sensitivity():
    """
    Validates Experiment 2:
    AAS monotonic sensitivity to alpha parameter in [0.1, 0.9].
    When bottleneck is severely lower than mean, lower alpha penalizes more heavily.
    """
    dimensions = {
        "Security & Robustness": 90.0,
        "Fairness & Non-Discrimination": 90.0,
        "Transparency & Explainability": 90.0,
        "Privacy & Data Governance": 90.0,
        "Human Oversight & Accountability": 90.0,
        "Safety & Reliability": 20.0,  # Critical bottleneck
    }
    res = compute_aas_and_bottleneck(dimensions, alpha=0.6)
    curve = res["sensitivity_curve"]
    assert len(curve) == 9

    # Check alpha values range from 0.1 to 0.9
    alphas = [c["alpha"] for c in curve]
    scores = [c["score"] for c in curve]
    assert alphas == [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]

    # Because bottleneck (20) is lower than mean (78.33), score MUST strictly increase as alpha increases
    for i in range(len(scores) - 1):
        assert scores[i] <= scores[i + 1]

    # Score at alpha=0.1 (bottleneck heavy) should be much lower than alpha=0.9 (mean heavy)
    assert scores[0] < scores[-1]
    assert scores[0] < 30.0
    assert scores[-1] > 70.0
