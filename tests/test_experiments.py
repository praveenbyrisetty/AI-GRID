"""
Research Validation Tests: Experiment 1 (ADI) & Experiment 2 (Sensitivity Analysis)
"""

import pytest
from aigrid_auditor import AIGRIDMCPAuditor
from ai_profile_engine import get_questions, compute_aas_and_bottleneck


@pytest.mark.asyncio
async def test_experiment_1_attestation_discrepancy_divergence():
    """
    Validates Hypothesis H1:
    Automated MCP protocol probing reveals weaknesses that self-attested responses miss,
    producing a statistically positive Attestation Discrepancy Index (ADI > 0).
    """
    auditor = AIGRIDMCPAuditor()

    # Self-attested answers with all optimal responses (self-serving bias)
    high_answers = {
        q["id"]: q["options"][0]["value"]
        for q in get_questions()
        if not q.get("is_identity") and q.get("options")
    }
    q_audit = auditor.run_questionnaire_audit(high_answers)
    self_aas = q_audit["scoring"]["aas_score"]
    assert self_aas >= 90.0

    # Probe against poor and moderate demo profiles
    poor_audit = await auditor.run_live_audit(profile="poor")
    poor_aas = poor_audit["scoring"]["aas_score"]

    comparison_poor = auditor.compare_attestation_vs_probe(q_audit, poor_audit)
    adi_poor = comparison_poor["attestation_discrepancy_index"]

    # ADI must be positive, demonstrating self-report overestimation
    assert adi_poor > 15.0
    assert comparison_poor["significance"] == "HIGH RISK OF SELF-REPORT BIAS"

    # Test against moderate profile
    mod_audit = await auditor.run_live_audit(profile="moderate")
    comparison_mod = auditor.compare_attestation_vs_probe(q_audit, mod_audit)
    adi_mod = comparison_mod["attestation_discrepancy_index"]
    assert adi_mod > 5.0


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
