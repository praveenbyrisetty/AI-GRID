"""
Unit & Integration Tests for AI-GRID Evidence Model & Scoring Engine (v4.0)
"""

import pytest
from evidence import (
    Evidence,
    SecurityFinding,
    DimensionResult,
    compute_weighted_dimension_score,
    aggregate_dimension_scores,
    compute_aas,
    DIMENSIONS_LIST,
    TIER_WEIGHTS,
)


def test_evidence_weighting():
    """Verify evidence tier weights are strictly enforced (T1=1.0, T2=0.8, T3=0.6)."""
    assert TIER_WEIGHTS["T1"] == 1.0
    assert TIER_WEIGHTS["T2"] == 0.8
    assert TIER_WEIGHTS["T3"] == 0.6

    e1 = Evidence(dimension="Safety & Reliability", source="probe:P04", tier="T1", value=90.0)
    assert e1.weight() == 1.0

    e3 = Evidence(dimension="Safety & Reliability", source="q:q1", tier="T3", value=90.0)
    assert e3.weight() == 0.6


def test_compute_weighted_dimension_score():
    """Verify weighted dimension score discounts low-tier evidence correctly."""
    # Two T1 observations at 80 and 60 -> weighted avg = 70.0
    items_t1 = [
        Evidence(dimension="Safety & Reliability", source="probe:1", tier="T1", value=80.0),
        Evidence(dimension="Safety & Reliability", source="probe:2", tier="T1", value=60.0),
    ]
    score, conf = compute_weighted_dimension_score(items_t1)
    assert score == 70.0
    assert conf > 0.5

    # One T3 (0.6 weight) at 100, one T1 (1.0 weight) at 50
    # Expected: (100 * 0.6 + 50 * 1.0) / (0.6 + 1.0) = 110 / 1.6 = 68.75 -> 68.8
    mixed_items = [
        Evidence(dimension="Safety & Reliability", source="q:1", tier="T3", value=100.0),
        Evidence(dimension="Safety & Reliability", source="probe:1", tier="T1", value=50.0),
    ]
    mixed_score, mixed_conf = compute_weighted_dimension_score(mixed_items)
    assert mixed_score == 68.8


def test_missing_evidence_handling():
    """Verify that dimensions with zero evidence default safely to 50.0 score and 0.0 confidence."""
    empty_items = []
    score, conf = compute_weighted_dimension_score(empty_items)
    assert score == 50.0
    assert conf == 0.0


def test_aggregate_dimension_scores_and_missing_evidence_flag():
    """Verify all 6 dimensions are populated, and unevidenced dimensions are flagged."""
    # Only provide evidence for 4 dimensions; leave Privacy and Fairness empty
    partial_evidence = [
        Evidence(dimension="Security & Robustness", source="p:p03", tier="T1", value=95.0),
        Evidence(dimension="Transparency & Explainability", source="p:p01", tier="T1", value=100.0),
        Evidence(dimension="Human Oversight & Accountability", source="p:p06", tier="T1", value=75.0),
        Evidence(dimension="Safety & Reliability", source="p:p04", tier="T1", value=40.0),
    ]
    results = aggregate_dimension_scores(partial_evidence)
    assert len(results) == 6

    # Evidenced dimension
    assert results["Security & Robustness"].status == "SUFFICIENT"
    assert results["Security & Robustness"].evidence_count == 1
    assert results["Security & Robustness"].confidence > 0.2

    # Unevidenced dimensions
    assert results["Privacy & Data Governance"].status == "INSUFFICIENT_EVIDENCE"
    assert results["Privacy & Data Governance"].evidence_count == 0
    assert results["Privacy & Data Governance"].confidence == 0.0

    assert results["Fairness & Non-Discrimination"].status == "INSUFFICIENT_EVIDENCE"
    assert results["Fairness & Non-Discrimination"].evidence_count == 0


def test_compute_aas_bottleneck_penalty():
    """Verify AAS applies bottleneck penalty: AAS = alpha*mean + (1-alpha)*min."""
    evidence = [
        Evidence(dimension="Security & Robustness", source="p:p03", tier="T1", value=90.0),
        Evidence(dimension="Fairness & Non-Discrimination", source="p:p01", tier="T1", value=90.0),
        Evidence(dimension="Transparency & Explainability", source="p:p01", tier="T1", value=90.0),
        Evidence(dimension="Privacy & Data Governance", source="p:p08", tier="T1", value=90.0),
        Evidence(dimension="Human Oversight & Accountability", source="p:p06", tier="T1", value=90.0),
        Evidence(dimension="Safety & Reliability", source="p:p04", tier="T1", value=20.0),  # Bottleneck
    ]
    results = aggregate_dimension_scores(evidence)
    aas_res = compute_aas(results, alpha=0.6)

    # Mean = (90*5 + 20) / 6 = 470 / 6 = 78.333
    # Bottleneck = 20.0
    # Expected AAS = 0.6 * 78.333 + 0.4 * 20.0 = 47.0 + 8.0 = 55.0
    assert aas_res["bottleneck_score"] == 20.0
    assert aas_res["bottleneck_dimension"] == "Safety & Reliability"
    assert aas_res["aas_score"] == 55.0
    assert aas_res["trust_grade"] == "D"
    assert len(aas_res["sensitivity_curve"]) == 9
    assert aas_res["is_fully_evidenced"] is True
    assert aas_res["evidence_sufficiency_pct"] == 100.0


def test_compute_aas_with_missing_evidence_impact():
    """Verify AAS reports missing evidence dimensions and reduced sufficiency percentage."""
    partial_evidence = [
        Evidence(dimension="Security & Robustness", source="p:p03", tier="T1", value=80.0),
        Evidence(dimension="Safety & Reliability", source="p:p04", tier="T1", value=70.0),
    ]
    results = aggregate_dimension_scores(partial_evidence)
    aas_res = compute_aas(results, alpha=0.6)

    assert aas_res["is_fully_evidenced"] is False
    assert len(aas_res["missing_evidence_dimensions"]) == 4
    assert "Privacy & Data Governance" in aas_res["missing_evidence_dimensions"]
    assert aas_res["evidence_sufficiency_pct"] == round(100.0 * 2 / 6, 1)
