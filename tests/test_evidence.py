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


def test_aggregate_dimension_scores():
    """Verify all 6 dimensions are populated with scores and confidence."""
    evidence = [
        Evidence(dimension="Security & Robustness", source="p:p03", tier="T1", value=95.0),
        Evidence(dimension="Fairness & Non-Discrimination", source="q:q5", tier="T3", value=80.0),
        Evidence(dimension="Transparency & Explainability", source="p:p01", tier="T1", value=100.0),
        Evidence(dimension="Privacy & Data Governance", source="p:p08", tier="T1", value=85.0),
        Evidence(dimension="Human Oversight & Accountability", source="p:p06", tier="T1", value=75.0),
        Evidence(dimension="Safety & Reliability", source="p:p04", tier="T1", value=40.0),
    ]
    results = aggregate_dimension_scores(evidence)
    assert len(results) == 6
    for dim_name in DIMENSIONS_LIST:
        assert dim_name in results
        assert isinstance(results[dim_name], DimensionResult)
        assert 0.0 <= results[dim_name].score <= 100.0


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
