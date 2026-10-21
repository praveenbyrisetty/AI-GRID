"""
Backward-compatibility wrapper for compliance_engines.py.
Redirects legacy RAI engine calls to the unified compliance_engines module.
"""

from compliance_engines import (
    load_german_credit_baseline,
    compute_fairness_metrics,
    compute_aif360_fairness,
    load_clinical_safety_benchmark,
    analyze_risk_cohorts,
    solve_remediation_priority,
    solve_prescriptive_counterfactual,
    evaluate_eu_ai_act_compliance,
    evaluate_nist_ai_rmf,
    map_owasp_and_atlas,
    scan_ai_vulnerabilities,
    generate_google_model_card,
    get_dataset_catalog,
)

__all__ = [
    "load_german_credit_baseline",
    "compute_fairness_metrics",
    "compute_aif360_fairness",
    "load_clinical_safety_benchmark",
    "analyze_risk_cohorts",
    "solve_remediation_priority",
    "solve_prescriptive_counterfactual",
    "evaluate_eu_ai_act_compliance",
    "evaluate_nist_ai_rmf",
    "map_owasp_and_atlas",
    "scan_ai_vulnerabilities",
    "generate_google_model_card",
    "get_dataset_catalog",
]
