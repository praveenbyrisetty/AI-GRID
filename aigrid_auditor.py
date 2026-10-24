"""
AI-GRID Master Audit Orchestrator (v4.0)

Orchestrates multi-dimensional trustworthy AI governance audits based on
research-grounded structured questionnaires (Tier T3 self-attestation)
grounded in QB4AIRA, EU AI Act Regulation (EU) 2024/1689, NIST AI 100-1,
and the 6 Trust Dimensions.
"""

import logging
from typing import Any, Dict, Optional

from config import DIMENSIONS_LIST, ALPHA_DEFAULT
from ai_profile_engine import (
    get_questions,
    generate_audit_from_questionnaire,
    compute_aas_and_bottleneck,
)

logger = logging.getLogger("aigrid.auditor")


class AIGRIDAuditor:
    """
    Core auditing engine orchestrating questionnaire-based AI governance,
    evidence-weighted dimension aggregation, and regulatory compliance evaluations.
    """

    def __init__(self):
        self.last_results: Optional[Dict[str, Any]] = None

    def run_questionnaire_audit(self, answers: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes an audit from structured questionnaire responses (Tier T3).
        """
        results = generate_audit_from_questionnaire(answers, evidence_tier="T3")
        self.last_results = results
        return results

    def get_questions(self):
        """Retrieve question bank."""
        return get_questions()


# Backward compatibility alias
AIGRIDMCPAuditor = AIGRIDAuditor
