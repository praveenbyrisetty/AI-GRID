"""
AI-GRID Configuration & Trust Framework Parameters (v4.0)

All weights and thresholds in this file represent heuristic parameters established for
the multi-dimensional trust assessment framework.
Basis: Heuristic, not calibrated against empirical loss functions.
"""

from typing import Dict, List

# Heuristic weights for evidence tiers (T1 = Runtime Observation, T2 = Schema Introspection, T3 = Self-Declared)
# Note: In the questionnaire-first control plane, all active assessments are currently Tier T3 (self-attested, weight = 0.60).
# Tier T1/T2 weights are preserved for future automated artifact integrations.
TIER_WEIGHTS: Dict[str, float] = {
    "T1": 1.0,  # heuristic, not calibrated
    "T2": 0.8,  # heuristic, not calibrated
    "T3": 0.6,  # heuristic, not calibrated
}

# Default bottleneck penalty parameter for Assurance Adequacy Score (AAS)
# AAS = α × mean(S) + (1-α) × min(S)
# Basis: α = 0.6 balances average system trustworthiness with penalty for critical vulnerability bottlenecks.
ALPHA_DEFAULT: float = 0.6  # heuristic, not calibrated

# Minimum number of evidenced dimensions (out of 7) required to compute a valid overall AAS.
# If fewer than 4 dimensions have evidence, AAS is withheld to prevent misleading assurance.
MIN_DIMENSIONS_FOR_AAS: int = 4  # heuristic, not calibrated

# Minimum number of independent evidence items required to mark a dimension as "SUFFICIENT"
MIN_EVIDENCE_FOR_SUFFICIENCY: int = 2  # heuristic, not calibrated

# Minimum confidence threshold for sufficiency
SUFFICIENCY_CONFIDENCE_THRESHOLD: float = 0.20  # heuristic, not calibrated

# The 7 core trust dimensions of AI-GRID
DIMENSIONS_LIST: List[str] = [
    "Security & Robustness",
    "Safety & Reliability",
    "Fairness & Non-Discrimination",
    "Transparency & Explainability",
    "Privacy & Data Governance",
    "Human Oversight & Agency",
    "Accountability & Governance",
]

# Heuristic grade boundaries for Trust Grade assignment
GRADE_THRESHOLDS: Dict[str, float] = {
    "A+": 90.0,  # heuristic, not calibrated
    "A": 80.0,   # heuristic, not calibrated
    "B": 70.0,   # heuristic, not calibrated
    "C": 60.0,   # heuristic, not calibrated
    "D": 50.0,   # heuristic, not calibrated
}

# API Rate limiting and execution timeouts
AUDIT_RATE_LIMIT_PER_MINUTE: int = 30
AUDIT_SUBPROCESS_TIMEOUT_SECONDS: int = 45
