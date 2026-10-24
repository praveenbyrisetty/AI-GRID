"""
AI-GRID Evidence Model & Scoring Engine (v4.0)

Normalizes all assessment observations — from technical audit observations (T1),
schema/metadata declarations (T2), and structured questionnaire responses (T3) —
into structured Evidence objects with full provenance tracking.

Implements the evidence-weighted dimension scoring formula:
    score_d = Σ(e.value × tier_weight[e.tier]) / Σ(tier_weight[e.tier])
    confidence_d = 1 - 1 / (1 + Σ tier_weights)
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from config import (
    TIER_WEIGHTS,
    ALPHA_DEFAULT,
    MIN_DIMENSIONS_FOR_AAS,
    MIN_EVIDENCE_FOR_SUFFICIENCY,
    SUFFICIENCY_CONFIDENCE_THRESHOLD,
    DIMENSIONS_LIST,
    GRADE_THRESHOLDS,
)


@dataclass
class Evidence:
    """
    A single structured assessment observation with provenance metadata.

    Attributes:
        dimension:  Which of the 6 trust dimensions this evidence relates to.
        source:     Where this evidence came from (e.g., "mcp_probe:P04", "questionnaire:q1").
        tier:       Evidence confidence tier — "T1" (runtime), "T2" (metadata), "T3" (self-attested).
        value:      Normalized score contribution (0.0 to 100.0), or None if inconclusive.
        raw_data:   The original observation data (tool response, answer text, etc.).
        description: Human-readable description of what was observed.
        timestamp:  When this evidence was collected.
        finding:    Optional security finding generated from this evidence.
    """
    dimension: str
    source: str
    tier: str
    value: Optional[float] = None
    raw_data: Any = None
    description: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    finding: Optional["SecurityFinding"] = None

    def weight(self) -> float:
        return TIER_WEIGHTS.get(self.tier, 0.6)


@dataclass
class SecurityFinding:
    """
    A concrete security or governance finding generated from evidence.

    Attributes:
        severity:       CRITICAL | HIGH | MEDIUM | LOW
        dimension:      Trust dimension this finding impacts.
        finding:        What was observed (the problem).
        action:         Recommended remediation action.
        evidence_ref:   Reference to the Evidence source.
        eu_ai_act_ref:  Relevant EU AI Act article (if applicable).
        owasp_ref:      Relevant OWASP LLM/MCP code (if applicable).
        mitre_atlas_ref: Relevant MITRE ATLAS technique ID (if applicable).
    """
    severity: str
    dimension: str
    finding: str
    action: str
    evidence_ref: str = ""
    eu_ai_act_ref: str = ""
    owasp_ref: str = ""
    mitre_atlas_ref: str = ""

    def to_dict(self) -> Dict[str, Any]:
        badge_map = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "info", "LOW": "info"}
        return {
            "priority": self.severity,
            "badge": badge_map.get(self.severity, "info"),
            "dimension": self.dimension,
            "finding": self.finding,
            "action": self.action,
            "evidence_ref": self.evidence_ref,
            "eu_ai_act_ref": self.eu_ai_act_ref,
            "owasp_ref": self.owasp_ref,
            "mitre_atlas_ref": self.mitre_atlas_ref,
        }


@dataclass
class DimensionResult:
    """
    Aggregated result for a single trust dimension after evidence weighting.
    """
    name: str
    score: Optional[float]
    confidence: float
    evidence_count: int
    tier_breakdown: Dict[str, int]
    status: str = "SUFFICIENT"  # "SUFFICIENT" | "INSUFFICIENT_EVIDENCE"


def compute_weighted_dimension_score(
    evidence_items: List[Evidence],
) -> Tuple[Optional[float], float]:
    """
    Computes evidence-weighted score and confidence for a dimension.

    score = Σ(item.value × tier_weight[item.tier]) / Σ(tier_weight[item.tier])
    confidence = 1 - (1 / (1 + n_effective))   where n_effective = Σ tier_weights

    Returns:
        (score, confidence) tuple.
        - score: 0-100 weighted dimension score, or None if no valid evidence.
        - confidence: 0-1 indicating how trustworthy this score is.
    """
    valid_items = [e for e in evidence_items if e.value is not None]
    if not valid_items:
        return (None, 0.0)

    weighted_sum = 0.0
    weight_total = 0.0

    for e in valid_items:
        w = TIER_WEIGHTS.get(e.tier, 0.6)
        weighted_sum += e.value * w
        weight_total += w

    if weight_total == 0:
        return (None, 0.0)

    score = weighted_sum / weight_total
    confidence = 1.0 - (1.0 / (1.0 + weight_total))

    return (round(max(0.0, min(100.0, score)), 1), round(confidence, 3))


def aggregate_dimension_scores(
    all_evidence: List[Evidence],
) -> Dict[str, DimensionResult]:
    """
    Groups evidence by dimension and computes weighted scores for all 6 dimensions.
    A dimension with no evidence gets score=None, confidence=0.0, and status='INSUFFICIENT_EVIDENCE'.
    A dimension requires >= 2 evidence items and confidence >= 0.20 to be marked 'SUFFICIENT'.

    Returns:
        Dict mapping dimension name to DimensionResult.
    """
    # Group by dimension
    dim_evidence: Dict[str, List[Evidence]] = {d: [] for d in DIMENSIONS_LIST}
    for e in all_evidence:
        if e.dimension in dim_evidence:
            dim_evidence[e.dimension].append(e)

    results = {}
    for dim_name in DIMENSIONS_LIST:
        items = dim_evidence[dim_name]
        score, confidence = compute_weighted_dimension_score(items)

        tier_counts: Dict[str, int] = {}
        for e in items:
            tier_counts[e.tier] = tier_counts.get(e.tier, 0) + 1

        evidence_status = (
            "SUFFICIENT"
            if (len(items) >= MIN_EVIDENCE_FOR_SUFFICIENCY and confidence >= SUFFICIENCY_CONFIDENCE_THRESHOLD)
            else "INSUFFICIENT_EVIDENCE"
        )
        results[dim_name] = DimensionResult(
            name=dim_name,
            score=score,
            confidence=confidence,
            evidence_count=len(items),
            tier_breakdown=tier_counts,
            status=evidence_status,
        )

    return results


def compute_aas(
    dimension_results: Dict[str, DimensionResult],
    alpha: float = ALPHA_DEFAULT,
) -> Dict[str, Any]:
    """
    Computes the Assurance Adequacy Score (AAS) with bottleneck penalty:
        AAS = α × mean(S) + (1-α) × min(S)
    using a bottleneck-penalised aggregate.

    Rules:
        - Dimensions without evidence (score is None) NEVER enter mean or min.
        - Withhold AAS (aas_score = None, status = 'INSUFFICIENT_EVIDENCE')
          if fewer than 4 of 6 dimensions have evidence.

    Returns:
        Dictionary containing AAS, breakdown, confidence, sensitivity curve, and status.
    """
    valid_results = [r for r in dimension_results.values() if r.score is not None]
    valid_scores = [r.score for r in valid_results]
    confidences = [r.confidence for r in valid_results]
    missing_evidence_dims = [
        r.name for r in dimension_results.values() if r.score is None
    ]
    sufficiency_pct = round(
        100.0 * len(valid_scores) / max(len(dimension_results), 1),
        1,
    )

    # Withhold AAS if fewer than MIN_DIMENSIONS_FOR_AAS dimensions have evidence
    if len(valid_scores) < MIN_DIMENSIONS_FOR_AAS:
        avg_score = round(sum(valid_scores) / len(valid_scores), 1) if valid_scores else None
        min_score = min(valid_scores) if valid_scores else None
        btn_dim = next((r.name for r in valid_results if r.score == min_score), None) if valid_scores else None
        return {
            "aas_score": None,
            "weighted_average": avg_score,
            "bottleneck_score": min_score,
            "bottleneck_dimension": btn_dim,
            "trust_grade": "INSUFFICIENT_EVIDENCE",
            "alpha_parameter": alpha,
            "overall_confidence": round(sum(confidences) / len(confidences), 3) if confidences else 0.0,
            "missing_evidence_dimensions": missing_evidence_dims,
            "evidence_sufficiency_pct": sufficiency_pct,
            "is_fully_evidenced": len(missing_evidence_dims) == 0,
            "sensitivity_curve": [],
            "dimension_confidences": {
                name: round(r.confidence, 3) for name, r in dimension_results.items()
            },
            "status": "INSUFFICIENT_EVIDENCE",
            "message": f"AAS withheld: only {len(valid_scores)}/6 dimensions have evidence (minimum {MIN_DIMENSIONS_FOR_AAS} required).",
        }

    weighted_average = sum(valid_scores) / len(valid_scores)
    bottleneck_score = min(valid_scores)
    overall_confidence = sum(confidences) / len(confidences) if confidences else 0.0

    # Identify bottleneck dimension from evidenced dimensions
    bottleneck_dimension = next(r.name for r in valid_results if r.score == bottleneck_score)

    aas = round((alpha * weighted_average) + ((1.0 - alpha) * bottleneck_score), 1)

    # Grade assignment based on heuristic boundaries
    if aas >= GRADE_THRESHOLDS["A+"]:
        grade = "A+"
    elif aas >= GRADE_THRESHOLDS["A"]:
        grade = "A"
    elif aas >= GRADE_THRESHOLDS["B"]:
        grade = "B"
    elif aas >= GRADE_THRESHOLDS["C"]:
        grade = "C"
    elif aas >= GRADE_THRESHOLDS["D"]:
        grade = "D"
    else:
        grade = "F"

    # Sensitivity curve across α ∈ [0.1 .. 0.9]
    sensitivity_curve = []
    for a_val in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
        score_at_a = round(
            (a_val * weighted_average) + ((1.0 - a_val) * bottleneck_score), 1
        )
        sensitivity_curve.append({
            "alpha": round(a_val, 1),
            "score": score_at_a,
            "interpretation": (
                "High Bottleneck Penalty" if a_val <= 0.3
                else ("Balanced (bottleneck-penalised aggregate)" if a_val <= 0.7 else "Mean-Dominant")
            ),
        })

    return {
        "aas_score": aas,
        "weighted_average": round(weighted_average, 1),
        "bottleneck_score": round(bottleneck_score, 1),
        "bottleneck_dimension": bottleneck_dimension,
        "trust_grade": grade,
        "alpha_parameter": alpha,
        "overall_confidence": round(overall_confidence, 3),
        "missing_evidence_dimensions": missing_evidence_dims,
        "evidence_sufficiency_pct": sufficiency_pct,
        "is_fully_evidenced": len(missing_evidence_dims) == 0,
        "sensitivity_curve": sensitivity_curve,
        "dimension_confidences": {
            name: round(r.confidence, 3) for name, r in dimension_results.items()
        },
        "status": "COMPUTED",
    }
