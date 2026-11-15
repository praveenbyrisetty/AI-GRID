"""
AI-GRID Governance Catalog (v5.1)

One entry per questionnaire item. Each entry carries:
  eu_ai_act_ref   - the EU AI Act (Regulation (EU) 2024/1689) provision the control supports
  nist_rmf_ref    - the NIST AI RMF 1.0 subcategory the control supports
  governance_action - the GRC deliverable that closes a gap on this item
  owner_role      - the organisational role accountable for that deliverable
  evidence_expected - what an auditor would ask to see
  ref_note        - why the reference differs from the pre-5.1 mapping (if it does)

The catalog is merged into QUESTIONS at import time (see ai_profile_engine.py), so
the question bank stays the single source of truth for scoring while this file is the
single source of truth for GRC mapping and remediation wording.

VERIFICATION STATUS (see docs/MAPPING_VERIFICATION.md):
  * Art. 15 paragraph numbers and NIST GOVERN 1.5/1.6/1.7, 2.3, MEASURE 2.4/2.6/2.7/2.8/2.10/2.11,
    MAP 4.1 were checked against published texts.
  * The remaining paragraph/letter references (Arts. 9, 10, 12, 13, 14, 17, 26, 72, 73 and the other
    NIST subcategories) follow the Official Journal / NIST AI 100-1 wording as understood by the
    author and MUST be re-checked against the primary texts before publication.
"""

from typing import Dict

GOVERNANCE_CATALOG: Dict[str, Dict[str, str]] = {
    # ------------------------------------------------------------------ Security & Robustness
    "q1_adversarial_tested": {
        "eu_ai_act_ref": "Art. 15(5)", "nist_rmf_ref": "MEASURE 2.7",
        "governance_action": "Adopt an adversarial-robustness testing policy and record test results and risk acceptance decisions before each release",
        "owner_role": "AI Risk Manager",
        "evidence_expected": "Approved testing policy, test reports covering adversarial examples, signed risk-acceptance record",
        "ref_note": "Adversarial examples are named in Art. 15(5); Art. 15(4) concerns errors, faults and redundancy.",
    },
    "q2_drift_monitoring": {
        "eu_ai_act_ref": "Art. 72(1); Art. 9(2)(c)", "nist_rmf_ref": "MEASURE 2.4",
        "governance_action": "Define drift thresholds, a review cadence and an owner, and document the response when thresholds are breached",
        "owner_role": "Model Owner / AI Risk Manager",
        "evidence_expected": "Monitoring plan, threshold definitions, dated review minutes, breach-response records",
        "ref_note": "Drift monitoring is post-market monitoring (Art. 72) feeding the risk system (Art. 9(2)(c)); NIST MEASURE 2.4 covers production monitoring.",
    },
    "q3_sbom_tracking": {
        "eu_ai_act_ref": "Art. 15(5); Annex IV(2)(a)", "nist_rmf_ref": "GOVERN 1.6; MAP 4.1",
        "governance_action": "Establish and maintain a machine-readable AI-BOM (CycloneDX/SPDX) covering model weights, training-data provenance and libraries, with a named owner",
        "owner_role": "AI Governance Lead / Security Lead",
        "evidence_expected": "Current AI-BOM file, version history, hashes for weights and datasets, third-party component list",
        "ref_note": "Was Art. 15(2) (Commission benchmarks) and GOVERN 1.7 (decommissioning). Inventory is GOVERN 1.6; component and third-party risk is MAP 4.1.",
    },
    "q4_red_teaming": {
        "eu_ai_act_ref": "Art. 15(5)", "nist_rmf_ref": "MEASURE 2.7",
        "governance_action": "Commission independent red-team or penetration testing on a defined schedule and track findings to closure",
        "owner_role": "Chief Information Security Officer",
        "evidence_expected": "Independent test report, scope and rules of engagement, remediation tracker with closure dates",
        "ref_note": "Was Art. 15(4); attack resilience is Art. 15(5).",
    },
    "q5_api_auth_ratelimit": {
        "eu_ai_act_ref": "Art. 15(5)", "nist_rmf_ref": "MEASURE 2.7",
        "governance_action": "Approve an access-control standard for inference and tool endpoints (authentication, authorisation, rate limits) and review access periodically",
        "owner_role": "Security Lead",
        "evidence_expected": "Access-control standard, endpoint inventory, periodic access review records",
        "ref_note": "Was Art. 15(3) (declared accuracy) and MANAGE 2.4 (deactivation). Resilience against unauthorised third parties is Art. 15(5).",
    },
    # ------------------------------------------------------------------ Fairness & Non-Discrimination
    "q6_demographic_coverage": {
        "eu_ai_act_ref": "Art. 10(3); Art. 10(2)(f)", "nist_rmf_ref": "MAP 2.3",
        "governance_action": "Define the target population and document how well the training data represents it, with an accepted coverage threshold",
        "owner_role": "Data Governance Lead",
        "evidence_expected": "Target-population definition, representativeness analysis, sign-off on coverage threshold",
        "ref_note": "Representativeness is Art. 10(3); MAP 2.3 covers data representativeness in TEVV considerations.",
    },
    "q7_class_balance": {
        "eu_ai_act_ref": "Art. 10(3)", "nist_rmf_ref": "MEASURE 2.11",
        "governance_action": "Document class and group balance of training data and the mitigation chosen where imbalance exists",
        "owner_role": "Data Governance Lead",
        "evidence_expected": "Dataset composition report, mitigation decision record",
        "ref_note": "",
    },
    "q8_coverage_gaps": {
        "eu_ai_act_ref": "Art. 10(2)(h)", "nist_rmf_ref": "MAP 2.2",
        "governance_action": "Maintain a register of known data gaps and shortcomings, the residual risk of each and the planned treatment",
        "owner_role": "Data Governance Lead",
        "evidence_expected": "Data-gap register with owners and dates, residual-risk acceptance",
        "ref_note": "Was Art. 10(2)(g) (bias mitigation measures); identifying data gaps is Art. 10(2)(h).",
    },
    "q9_dataset_size": {
        "eu_ai_act_ref": "Art. 10(3)", "nist_rmf_ref": "MAP 2.3",
        "governance_action": "Justify that training-data volume is sufficient for the intended purpose and record the justification",
        "owner_role": "Model Owner",
        "evidence_expected": "Sufficiency analysis, validation results on held-out data",
        "ref_note": "Was MAP 3.2 (costs of errors).",
    },
    "q10_fairness_audit": {
        "eu_ai_act_ref": "Art. 10(2)(f)-(g)", "nist_rmf_ref": "MEASURE 2.11",
        "governance_action": "Commission a documented bias examination using agreed fairness metrics and record the remediation decision",
        "owner_role": "Compliance Officer",
        "evidence_expected": "Fairness audit report (e.g. DIR, SPD, EOD), threshold rationale, signed remediation decision",
        "ref_note": "",
    },
    # ------------------------------------------------------------------ Transparency & Explainability
    "q11_xai_engine": {
        "eu_ai_act_ref": "Art. 13(1)", "nist_rmf_ref": "MEASURE 2.9",
        "governance_action": "Adopt an explainability requirement for the system and document which explanation methods are provided to deployers",
        "owner_role": "Model Owner",
        "evidence_expected": "Explainability requirement, description of explanation method, deployer documentation",
        "ref_note": "Was MAP 1.5 (risk tolerance); explaining and interpreting the model is MEASURE 2.9.",
    },
    "q12_attribution_count": {
        "eu_ai_act_ref": "Art. 13(3)(b)(iv)", "nist_rmf_ref": "MEASURE 2.9",
        "governance_action": "Specify the minimum feature-attribution information exposed per prediction and document it in the instructions for use",
        "owner_role": "Model Owner",
        "evidence_expected": "Attribution specification, instructions-for-use extract, sample outputs",
        "ref_note": "Was MEASURE 2.6 (safety).",
    },
    "q13_reasoning_summaries": {
        "eu_ai_act_ref": "Art. 13(3)(b)(iv); Art. 13(3)(d)", "nist_rmf_ref": "MEASURE 2.9",
        "governance_action": "Require plain-language reasoning summaries for decisions and approve their wording with a domain expert",
        "owner_role": "Product Owner",
        "evidence_expected": "Summary template, expert review record, sample outputs",
        "ref_note": "Was MAP 1.5.",
    },
    "q14_model_card_doc": {
        "eu_ai_act_ref": "Art. 11; Art. 13(2)", "nist_rmf_ref": "MAP 2.2",
        "governance_action": "Publish and version-control a model/system card covering intended use, limits, data and evaluation",
        "owner_role": "AI Governance Lead",
        "evidence_expected": "Current model card with version history and approval",
        "ref_note": "Was GOVERN 1.5 (periodic review). Documenting knowledge limits is MAP 2.2.",
    },
    "q15_uncertainty_scores": {
        "eu_ai_act_ref": "Art. 13(3)(b)(ii)", "nist_rmf_ref": "MEASURE 2.5",
        "governance_action": "Require calibrated confidence outputs, declare accuracy metrics in the instructions for use and review calibration periodically",
        "owner_role": "Model Owner",
        "evidence_expected": "Calibration report, declared metrics, review records",
        "ref_note": "Was MEASURE 2.6.",
    },
    # ------------------------------------------------------------------ Privacy & Data Governance
    "q16_encryption_rest": {
        "eu_ai_act_ref": "Art. 15(5); GDPR Art. 32", "nist_rmf_ref": "MEASURE 2.10",
        "governance_action": "Adopt an encryption-at-rest standard for training data, caches and logs and verify compliance periodically",
        "owner_role": "Security Lead / Data Protection Officer",
        "evidence_expected": "Encryption standard, configuration attestations, review records",
        "ref_note": "Was Art. 10(5) (special-category data for bias detection) and GOVERN 1.2.",
    },
    "q17_encryption_transit": {
        "eu_ai_act_ref": "Art. 15(5); GDPR Art. 32", "nist_rmf_ref": "MEASURE 2.10",
        "governance_action": "Adopt a transport-security standard (minimum TLS version, certificate management) for all network boundaries",
        "owner_role": "Security Lead",
        "evidence_expected": "Transport-security standard, TLS scan results, certificate inventory",
        "ref_note": "Was Art. 15(3) (declared accuracy) and GOVERN 1.2.",
    },
    "q18_data_retention": {
        "eu_ai_act_ref": "Art. 10(5)(e); GDPR Art. 5(1)(e)", "nist_rmf_ref": "MEASURE 2.10",
        "governance_action": "Approve a data-retention and purge schedule with an owner and evidence that purging runs",
        "owner_role": "Data Protection Officer",
        "evidence_expected": "Retention schedule, purge job logs, exception approvals",
        "ref_note": "Was GOVERN 1.2.",
    },
    "q19_pii_handling": {
        "eu_ai_act_ref": "Art. 10(5); GDPR Art. 5(1)(c), 25", "nist_rmf_ref": "MEASURE 2.10",
        "governance_action": "Define PII handling rules (detect, redact, anonymise) and verify them through periodic sampling",
        "owner_role": "Data Protection Officer",
        "evidence_expected": "PII handling policy, data-protection impact assessment, sampling results",
        "ref_note": "Was MAP 1.6.",
    },
    "q20_governance_policy": {
        "eu_ai_act_ref": "Art. 10(2)", "nist_rmf_ref": "GOVERN 1.1",
        "governance_action": "Approve an AI data governance policy with named roles and review dates",
        "owner_role": "AI Governance Lead",
        "evidence_expected": "Signed policy, role assignments, review log",
        "ref_note": "",
    },
    # ------------------------------------------------------------------ Human Oversight & Agency
    "q21_human_oversight": {
        "eu_ai_act_ref": "Art. 14(1); Art. 14(4)(d)", "nist_rmf_ref": "GOVERN 3.2",
        "governance_action": "Approve a human-in-the-loop policy defining which decisions require human approval before actuation",
        "owner_role": "AI Governance Lead",
        "evidence_expected": "Signed oversight policy, decision-class register, approval workflow evidence",
        "ref_note": "Was GOVERN 1.4. Defining human-AI oversight roles is GOVERN 3.2.",
    },
    "q22_autonomy_level": {
        "eu_ai_act_ref": "Art. 14(3)", "nist_rmf_ref": "GOVERN 3.2",
        "governance_action": "Classify the system's autonomy level and set oversight measures proportionate to it",
        "owner_role": "AI Governance Lead",
        "evidence_expected": "Autonomy classification record, proportionality rationale",
        "ref_note": "Art. 14(3) links oversight measures to risk, autonomy and context of use.",
    },
    "q24_kill_switch": {
        "eu_ai_act_ref": "Art. 14(4)(e)", "nist_rmf_ref": "MANAGE 2.4",
        "governance_action": "Define who may stop or deactivate the system, under what conditions, and test the procedure on a schedule",
        "owner_role": "Operations Lead",
        "evidence_expected": "Stop/deactivation procedure, authorised-operator list, test records",
        "ref_note": "Was GOVERN 1.4. Deactivation mechanisms are MANAGE 2.4.",
    },
    "q24b_operator_training": {
        "eu_ai_act_ref": "Art. 26(2); Art. 14(4)(a)", "nist_rmf_ref": "GOVERN 2.2",
        "governance_action": "Require and record training for every person assigned to oversee the system",
        "owner_role": "Training / HR Lead",
        "evidence_expected": "Training curriculum, attendance and competency records, authority assignment",
        "ref_note": "Was Art. 14(2). Competence of assigned overseers is a deployer duty under Art. 26(2).",
    },
    "q24c_override_capability": {
        "eu_ai_act_ref": "Art. 14(4)(d)", "nist_rmf_ref": "MANAGE 4.1",
        "governance_action": "Document how operators can override or reverse an AI decision and how overrides are logged and reviewed",
        "owner_role": "Operations Lead",
        "evidence_expected": "Override procedure, override log, periodic review of overrides",
        "ref_note": "Was Art. 14(4)(a) (understanding capacities) and GOVERN 1.4.",
    },
    # ------------------------------------------------------------------ Accountability & Governance
    "q23_incident_escalation": {
        "eu_ai_act_ref": "Art. 73; Art. 17(1)(i)", "nist_rmf_ref": "MANAGE 4.3",
        "governance_action": "Adopt an incident escalation and serious-incident reporting procedure with named responsibilities and time limits",
        "owner_role": "Compliance Officer",
        "evidence_expected": "Incident procedure, escalation contacts, incident register, reporting records",
        "ref_note": "Was Art. 9(9) (vulnerable groups). Serious-incident reporting is Art. 73.",
    },
    "q25_decision_logging": {
        "eu_ai_act_ref": "Art. 12(1)", "nist_rmf_ref": "MEASURE 2.4",
        "governance_action": "Define a logging and log-retention standard that makes decisions traceable and protects logs from alteration",
        "owner_role": "Security Lead / Compliance Officer",
        "evidence_expected": "Logging standard, retention schedule, integrity check results",
        "ref_note": "Was MEASURE 2.5.",
    },
    "q25b_technical_dossier": {
        "eu_ai_act_ref": "Art. 11; Annex IV", "nist_rmf_ref": "GOVERN 4.2",
        "governance_action": "Compile and maintain technical documentation to Annex IV with version control and an owner",
        "owner_role": "AI Governance Lead",
        "evidence_expected": "Annex IV dossier, change history, approval record",
        "ref_note": "Was GOVERN 1.5 (periodic review of the risk process).",
    },
    "q25c_post_market_monitoring": {
        "eu_ai_act_ref": "Art. 72", "nist_rmf_ref": "MANAGE 4.1",
        "governance_action": "Approve a post-market monitoring plan covering data sources, review frequency and escalation",
        "owner_role": "Compliance Officer",
        "evidence_expected": "Monitoring plan, periodic monitoring reports, corrective-action log",
        "ref_note": "Was MANAGE 4.3.",
    },
    "q25d_governance_charter": {
        "eu_ai_act_ref": "Art. 17(1)(m); Art. 9(1)", "nist_rmf_ref": "GOVERN 2.3",
        "governance_action": "Issue an executive AI governance charter naming accountable owners and their responsibilities",
        "owner_role": "Executive Sponsor (e.g. Chief AI Officer)",
        "evidence_expected": "Signed charter, accountability matrix, board or executive minutes",
        "ref_note": "Was GOVERN 1.1. Executive responsibility is GOVERN 2.3; an accountability framework is Art. 17(1)(m).",
    },
    # ------------------------------------------------------------------ Safety & Reliability
    "q26_input_validation": {
        "eu_ai_act_ref": "Art. 15(4)", "nist_rmf_ref": "MEASURE 2.7",
        "governance_action": "Set input-validation requirements and require evidence of rejection testing before release",
        "owner_role": "Engineering Lead / Quality Assurance",
        "evidence_expected": "Validation requirement, test results for malformed and out-of-range inputs",
        "ref_note": "Art. 15(4) covers resilience to errors, faults and inconsistencies.",
    },
    "q27_guardrail_count": {
        "eu_ai_act_ref": "Art. 9(5)", "nist_rmf_ref": "MANAGE 1.3",
        "governance_action": "Document the safety guardrails in place, the risks each mitigates and the residual risk accepted",
        "owner_role": "AI Risk Manager",
        "evidence_expected": "Guardrail register, risk-to-control mapping, residual-risk sign-off",
        "ref_note": "Was Art. 9(2)(a) (risk identification) and MANAGE 2.2.",
    },
    "q28_output_clamping": {
        "eu_ai_act_ref": "Art. 15(4)", "nist_rmf_ref": "MEASURE 2.6",
        "governance_action": "Define safe output limits and fail-safe behaviour and require evidence that limits are enforced",
        "owner_role": "Safety Officer",
        "evidence_expected": "Safe-limit specification, fail-safe test results",
        "ref_note": "Was Art. 15(1) and MANAGE 2.2.",
    },
    "q29_contextual_advisory": {
        "eu_ai_act_ref": "Art. 13(3)(b)(iii)", "nist_rmf_ref": "MAP 2.2",
        "governance_action": "Document known conditions that raise risk and how the system warns users when they occur",
        "owner_role": "Product Owner",
        "evidence_expected": "Known-limitations list, advisory text, examples of advisories in use",
        "ref_note": "Was Art. 13(3)(d) and MANAGE 2.3.",
    },
    "q30_failure_mode_testing": {
        "eu_ai_act_ref": "Art. 15(1); Art. 9(6)", "nist_rmf_ref": "MEASURE 2.6",
        "governance_action": "Maintain a catalogue of failure modes and edge cases and require a passing regression suite before release",
        "owner_role": "Quality Assurance Lead",
        "evidence_expected": "Failure-mode catalogue, regression results, release gate records",
        "ref_note": "Was MEASURE 2.8 (transparency and accountability risks). Safety evaluation is MEASURE 2.6.",
    },
}


def merge_into_questions(questions: list) -> int:
    """Merge catalog fields into question dicts in place. Returns number merged."""
    merged = 0
    for q in questions:
        entry = GOVERNANCE_CATALOG.get(q.get("id"))
        if not entry:
            continue
        q["eu_ai_act_ref"] = entry["eu_ai_act_ref"]
        q["nist_rmf_ref"] = entry["nist_rmf_ref"]
        q["governance_action"] = entry["governance_action"]
        q["owner_role"] = entry["owner_role"]
        q["evidence_expected"] = entry["evidence_expected"]
        q["ref_note"] = entry.get("ref_note", "")
        merged += 1
    return merged
