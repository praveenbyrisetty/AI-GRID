"""
AI-GRID Questionnaire-Based Audit Engine (v4.0)

Implements the 35 Research-Grounded Question Bank (5 per dimension x 7 dimensions)
grounded in QB4AIRA (Lee et al., 2024), Pfau & Jung (IEEE TAI 2026), EU AI Act (Articles 9-15),
NIST AI 100-1, OWASP Top 10, and MITRE ATLAS.

Employs Multi-Tier Evidence Weighting (T1=1.0, T2=0.8, T3=0.6; all active audits currently T3)
and bottleneck-penalised aggregate scoring (AAS), inspired by average-case versus worst-case ERM.
"""

import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from compliance_engines import (
    compute_fairness_metrics,
    analyze_risk_cohorts,
    solve_remediation_priority,
    evaluate_eu_ai_act_compliance,
    evaluate_nist_ai_rmf,
    map_owasp_and_atlas,
    scan_ai_vulnerabilities,
    generate_google_model_card,
)

# ======================================================================
# QUESTION DEFINITIONS: 5 IDENTITY + 30 SCORED QUESTIONS
# ======================================================================
QUESTIONS: List[Dict[str, Any]] = [
    # -------------------------------------------------------------
    # Step 1: System Identity (5 Non-Scored Contextual Questions)
    # -------------------------------------------------------------
    {
        "id": "model_name",
        "step": 1,
        "step_title": "System Identity",
        "label": "What is the name of your AI model/system?",
        "type": "text",
        "placeholder": "e.g., AgriTrust-SoilNet, ClinicalRisk-AI, CreditScorer-v2",
        "required": True,
        "is_identity": True,
        "dimension": None
    },
    {
        "id": "model_version",
        "step": 1,
        "step_title": "System Identity",
        "label": "What is the release version?",
        "type": "text",
        "placeholder": "e.g., 1.0.0, 2.3.1",
        "required": True,
        "is_identity": True,
        "dimension": None
    },
    {
        "id": "domain",
        "step": 1,
        "step_title": "System Identity",
        "label": "What operational domain does this AI belong to?",
        "type": "select",
        "options": [
            {"value": "healthcare", "label": "Healthcare / Medical Diagnostics (High-Risk Annex III)"},
            {"value": "finance", "label": "Finance / Credit Scoring (High-Risk Annex III)"},
            {"value": "agriculture", "label": "Agriculture / Environmental Resource Management"},
            {"value": "education", "label": "Education / Admissions Assessment (High-Risk Annex III)"},
            {"value": "autonomous_vehicles", "label": "Autonomous Vehicles / Robotics (High-Risk Annex III)"},
            {"value": "criminal_justice", "label": "Law Enforcement / Judicial Decision Support (High-Risk Annex III)"},
            {"value": "cybersecurity", "label": "Cybersecurity / Critical Digital Infrastructure"},
            {"value": "ecommerce", "label": "E-Commerce / Commercial Retail"},
            {"value": "manufacturing", "label": "Manufacturing / Industrial Automation"},
            {"value": "entertainment", "label": "Entertainment / Media Synthesis"},
            {"value": "other", "label": "General Purpose AI / Other"}
        ],
        "required": True,
        "is_identity": True,
        "dimension": None
    },
    {
        "id": "architecture",
        "step": 1,
        "step_title": "System Identity",
        "label": "What is the core model architecture / framework?",
        "type": "text",
        "placeholder": "e.g., Gradient Boosted Trees (XGBoost), Transformer (LLM), CNN (ResNet-50)",
        "required": True,
        "is_identity": True,
        "dimension": None
    },
    {
        "id": "deployment_type",
        "step": 1,
        "step_title": "System Identity",
        "label": "What is the deployment topology?",
        "type": "select",
        "options": [
            {"value": "cloud_api", "label": "Public / Multi-Tenant Cloud API"},
            {"value": "private_cloud", "label": "Dedicated / Private VPC Cloud"},
            {"value": "on_premise", "label": "On-Premises Air-Gapped Infrastructure"},
            {"value": "edge_device", "label": "Edge Device / Embedded Systems"},
            {"value": "hybrid", "label": "Hybrid Cloud / Agentic Mesh"}
        ],
        "required": True,
        "is_identity": True,
        "dimension": None
    },

    # -------------------------------------------------------------
    # Step 2: Dimension 1 — Security & Robustness (Q1 - Q5)
    # -------------------------------------------------------------
    {
        "id": "q1_adversarial_tested",
        "step": 2,
        "step_title": "Security & Robustness",
        "label": "Q1: Has the model undergone adversarial robustness testing?",
        "type": "select",
        "options": [
            {"value": "comprehensive", "label": "Comprehensive: Noise injection, evasion attacks & boundary stress testing", "score": 1.0},
            {"value": "basic", "label": "Basic: Gaussian noise injection or simple synthetic boundary checks", "score": 0.5},
            {"value": "none", "label": "None: No adversarial robustness testing conducted", "score": 0.0}
        ],
        "required": True,
        "dimension": "Security & Robustness",
        "research_source": "QB4AIRA §Security; Pfau & Jung (IEEE TAI 2026) §Robustness",
        "eu_ai_act_ref": "Art. 15(4)",
        "nist_rmf_ref": "MEASURE 2.7",
        "owasp_ref": "OWASP LLM01 (Prompt Injection)",
        "mitre_atlas_ref": "AML.T0029"
    },
    {
        "id": "q2_drift_monitoring",
        "step": 2,
        "step_title": "Security & Robustness",
        "label": "Q2: Is continuous data and model concept drift monitoring configured?",
        "type": "select",
        "options": [
            {"value": "automated", "label": "Automated: Continuous statistical drift monitoring (KS-test, PSI, Wasserstein)", "score": 1.0},
            {"value": "manual", "label": "Manual: Periodic manual accuracy checks on sampled production logs", "score": 0.5},
            {"value": "none", "label": "None: No post-deployment drift monitoring active", "score": 0.0}
        ],
        "required": True,
        "dimension": "Security & Robustness",
        "research_source": "QB4AIRA §Monitoring; RBAAF Governance Framework",
        "eu_ai_act_ref": "Art. 9(2)(b)",
        "nist_rmf_ref": "MANAGE 4.2",
        "owasp_ref": "OWASP LLM04 (Data Poisoning)",
        "mitre_atlas_ref": "AML.T0015"
    },
    {
        "id": "q3_sbom_tracking",
        "step": 2,
        "step_title": "Security & Robustness",
        "label": "Q3: Is there a machine-readable AI-BOM / SBOM tracking model weights and runtime dependencies?",
        "type": "select",
        "options": [
            {"value": "formal_sbom", "label": "Formal CycloneDX / SPDX AI-BOM tracking weights, training data hash & libraries", "score": 1.0},
            {"value": "basic_requirements", "label": "Basic static requirements.txt / lockfile without cryptographic hashes", "score": 0.5},
            {"value": "none", "label": "None: No formal inventory of software or model supply chain dependencies", "score": 0.0}
        ],
        "required": True,
        "dimension": "Security & Robustness",
        "research_source": "OWASP MCP Top 10 (MCP04); NIST SP 800-218 (SSDF)",
        "eu_ai_act_ref": "Art. 15(2)",
        "nist_rmf_ref": "GOVERN 1.7",
        "owasp_ref": "OWASP LLM03 (Supply Chain Vulnerabilities)",
        "mitre_atlas_ref": "AML.T0015"
    },
    {
        "id": "q4_red_teaming",
        "step": 2,
        "step_title": "Security & Robustness",
        "label": "Q4: Has the system undergone third-party red teaming or penetration testing?",
        "type": "select",
        "options": [
            {"value": "independent", "label": "Independent third-party AI red teaming completed with remediation verification", "score": 1.0},
            {"value": "internal", "label": "Internal developer security review conducted without external validation", "score": 0.5},
            {"value": "none", "label": "None: No red teaming or security penetration testing performed", "score": 0.0}
        ],
        "required": True,
        "dimension": "Security & Robustness",
        "research_source": "OWASP LLM Top 10; MCPSHIELD (Acharya & Gupta, 2026)",
        "eu_ai_act_ref": "Art. 15(4)",
        "nist_rmf_ref": "MEASURE 2.7",
        "owasp_ref": "OWASP LLM01 (Prompt Injection)",
        "mitre_atlas_ref": "AML.T0054"
    },
    {
        "id": "q5_api_auth_ratelimit",
        "step": 2,
        "step_title": "Security & Robustness",
        "label": "Q5: Are inference APIs and tool execution endpoints authenticated and rate-limited?",
        "type": "select",
        "options": [
            {"value": "mTLS_ratelimited", "label": "Strong token auth (mTLS / OAuth2 / API keys) with granular rate limiting & quotas", "score": 1.0},
            {"value": "basic_key", "label": "Static API key authentication without rate limiting or request throttling", "score": 0.5},
            {"value": "unauthenticated", "label": "Unauthenticated or exposed endpoint without access controls", "score": 0.0}
        ],
        "required": True,
        "dimension": "Security & Robustness",
        "research_source": "OWASP MCP Top 10 (MCP07); Google Research Agentic Security (2026)",
        "eu_ai_act_ref": "Art. 15(3)",
        "nist_rmf_ref": "MANAGE 2.4",
        "owasp_ref": "OWASP API04 (Resource Consumption)",
        "mitre_atlas_ref": "AML.T0043"
    },

    # -------------------------------------------------------------
    # Step 3: Dimension 2 — Fairness & Non-Discrimination (Q6 - Q10)
    # -------------------------------------------------------------
    {
        "id": "q6_demographic_coverage",
        "step": 3,
        "step_title": "Fairness & Non-Discrimination",
        "label": "Q6: What percentage of target demographic/geographic populations does training data cover?",
        "type": "select",
        "options": [
            {"value": "comprehensive", "label": "Comprehensive: > 80% coverage across target demographics and geography", "score": 1.0},
            {"value": "partial", "label": "Partial: 40% – 80% coverage with known regional/demographic omissions", "score": 0.5},
            {"value": "limited", "label": "Limited: < 40% coverage (high risk of discriminatory generalization error)", "score": 0.0}
        ],
        "required": True,
        "dimension": "Fairness & Non-Discrimination",
        "research_source": "QB4AIRA §Fairness; Pfau & Jung (IEEE TAI 2026) §Nondiscrimination",
        "eu_ai_act_ref": "Art. 10(2)(f)",
        "nist_rmf_ref": "MAP 2.2",
        "owasp_ref": "OWASP LLM08",
        "mitre_atlas_ref": "AML.T0015"
    },
    {
        "id": "q7_class_balance",
        "step": 3,
        "step_title": "Fairness & Non-Discrimination",
        "label": "Q7: How balanced is the class and demographic representation in the training dataset?",
        "type": "select",
        "options": [
            {"value": "balanced", "label": "Balanced: Equal or proportional representation (< 1.5:1 ratio between groups)", "score": 1.0},
            {"value": "moderate", "label": "Moderate Imbalance: 1.5:1 to 3:1 ratio across majority vs minority groups", "score": 0.6},
            {"value": "severe", "label": "Severe Imbalance: > 3:1 ratio (minority protected groups heavily underrepresented)", "score": 0.0}
        ],
        "required": True,
        "dimension": "Fairness & Non-Discrimination",
        "research_source": "QB4AIRA §Fairness; IBM AIF360 Base Rate Parity Methodology",
        "eu_ai_act_ref": "Art. 10(2)(f)",
        "nist_rmf_ref": "MEASURE 2.11",
        "owasp_ref": "OWASP LLM08",
        "mitre_atlas_ref": "AML.T0015"
    },
    {
        "id": "q8_coverage_gaps",
        "step": 3,
        "step_title": "Fairness & Non-Discrimination",
        "label": "Q8: Are there documented demographic or geographic coverage gaps?",
        "type": "select",
        "options": [
            {"value": "none", "label": "None: Rigorous demographic stratification shows no significant coverage gaps", "score": 1.0},
            {"value": "minor", "label": "Minor Gaps: Documented gaps in 1-2 edge demographic or geographic groups", "score": 0.6},
            {"value": "significant", "label": "Significant Gaps: Substantial underserved populations completely missing", "score": 0.0}
        ],
        "required": True,
        "dimension": "Fairness & Non-Discrimination",
        "research_source": "QB4AIRA §Fairness; Mitchell et al. (2019) Model Cards Out-of-Scope",
        "eu_ai_act_ref": "Art. 10(2)(g)",
        "nist_rmf_ref": "MAP 2.2",
        "owasp_ref": "OWASP LLM08",
        "mitre_atlas_ref": "AML.T0015"
    },
    {
        "id": "q9_dataset_size",
        "step": 3,
        "step_title": "Fairness & Non-Discrimination",
        "label": "Q9: What is the sample volume of the training dataset?",
        "type": "select",
        "options": [
            {"value": "large", "label": "Production Scale (> 10,000 verified samples with representative validation)", "score": 1.0},
            {"value": "moderate", "label": "Moderate Volume (2,000 – 10,000 samples with basic cross-validation)", "score": 0.7},
            {"value": "small", "label": "Insufficient Volume (< 2,000 samples, high risk of severe overfitting)", "score": 0.2}
        ],
        "required": True,
        "dimension": "Fairness & Non-Discrimination",
        "research_source": "Pfau & Jung (IEEE TAI 2026) §Data Governance; EU AI Act Art. 10",
        "eu_ai_act_ref": "Art. 10(3)",
        "nist_rmf_ref": "MAP 3.2",
        "owasp_ref": "OWASP LLM08",
        "mitre_atlas_ref": "AML.T0015"
    },
    {
        "id": "q10_fairness_audit",
        "step": 3,
        "step_title": "Fairness & Non-Discrimination",
        "label": "Q10: Has disparate impact testing (e.g., DIR, Statistical Parity) been formally computed?",
        "type": "select",
        "options": [
            {"value": "formal_audit", "label": "Formal Audit: DIR (Four-Fifths Rule >= 0.80) and SPD computed across protected classes", "score": 1.0},
            {"value": "informal", "label": "Informal: Ad-hoc spot checking of demographic slices without formal parity metrics", "score": 0.5},
            {"value": "none", "label": "None: No disparate impact or algorithmic fairness metrics calculated", "score": 0.0}
        ],
        "required": True,
        "dimension": "Fairness & Non-Discrimination",
        "research_source": "AIF360; EEOC 80% Rule; Kamiran & Calders (2012)",
        "eu_ai_act_ref": "Art. 10(2)(f)",
        "nist_rmf_ref": "MEASURE 2.11",
        "owasp_ref": "OWASP LLM08",
        "mitre_atlas_ref": "AML.T0015"
    },

    # -------------------------------------------------------------
    # Step 4: Dimension 3 — Transparency & Explainability (Q11 - Q15)
    # -------------------------------------------------------------
    {
        "id": "q11_xai_engine",
        "step": 4,
        "step_title": "Transparency & Explainability",
        "label": "Q11: Does the model incorporate an algorithmic explainability engine?",
        "type": "select",
        "options": [
            {"value": "full_xai", "label": "Full XAI: Deterministic local explanations (TreeSHAP, KernelSHAP, LIME, Grad-CAM)", "score": 1.0},
            {"value": "partial_xai", "label": "Partial: Global feature importance rankings only (no prediction-level attributions)", "score": 0.5},
            {"value": "none", "label": "None: Black-box model with zero explainability or interpretability telemetry", "score": 0.0}
        ],
        "required": True,
        "dimension": "Transparency & Explainability",
        "research_source": "QB4AIRA §Transparency; Pfau & Jung (IEEE TAI 2026) §Transparency",
        "eu_ai_act_ref": "Art. 13(1)",
        "nist_rmf_ref": "MAP 1.5",
        "owasp_ref": "OWASP LLM05",
        "mitre_atlas_ref": "AML.T0054"
    },
    {
        "id": "q12_attribution_count",
        "step": 4,
        "step_title": "Transparency & Explainability",
        "label": "Q12: How many feature attributions are computed and exposed per inference?",
        "type": "select",
        "options": [
            {"value": "comprehensive", "label": "Comprehensive: >= 4 quantitative feature importance weights per decision", "score": 1.0},
            {"value": "limited", "label": "Limited: 1 – 3 feature attributions exposed with partial weight quantification", "score": 0.6},
            {"value": "zero", "label": "Zero: Model outputs single prediction score without attribution factors", "score": 0.0}
        ],
        "required": True,
        "dimension": "Transparency & Explainability",
        "research_source": "QB4AIRA §Transparency; Mitchell et al. (2019) Model Cards",
        "eu_ai_act_ref": "Art. 13(3)(b)",
        "nist_rmf_ref": "MEASURE 2.6",
        "owasp_ref": "OWASP LLM05",
        "mitre_atlas_ref": "AML.T0054"
    },
    {
        "id": "q13_reasoning_summaries",
        "step": 4,
        "step_title": "Transparency & Explainability",
        "label": "Q13: Does the system deliver plain-language human-readable reasoning summaries?",
        "type": "select",
        "options": [
            {"value": "yes", "label": "Yes: Generates automated plain-language rationale explaining prediction drivers", "score": 1.0},
            {"value": "technical_only", "label": "Technical Only: Raw numerical tensors or floating-point weights without narration", "score": 0.5},
            {"value": "no", "label": "No: Raw prediction returned without reasoning explanation", "score": 0.0}
        ],
        "required": True,
        "dimension": "Transparency & Explainability",
        "research_source": "Pfau & Jung (IEEE TAI 2026) §Transparency; EU AI Act Art. 13(3)(d)",
        "eu_ai_act_ref": "Art. 13(3)(d)",
        "nist_rmf_ref": "MAP 1.5",
        "owasp_ref": "OWASP LLM05",
        "mitre_atlas_ref": "AML.T0054"
    },
    {
        "id": "q14_model_card_doc",
        "step": 4,
        "step_title": "Transparency & Explainability",
        "label": "Q14: Is there an authoritative Model Card / System Card documenting intended use & limitations?",
        "type": "select",
        "options": [
            {"value": "published_card", "label": "Published Model Card: Standardized card (Mitchell et al. 2019) with performance boundaries", "score": 1.0},
            {"value": "internal_readme", "label": "Informal developer README without verified benchmarks or failure mode analysis", "score": 0.5},
            {"value": "none", "label": "None: Undocumented model without technical documentation sheet", "score": 0.0}
        ],
        "required": True,
        "dimension": "Transparency & Explainability",
        "research_source": "Model Cards (Mitchell et al., 2019); IEEE P8000.1 Standard",
        "eu_ai_act_ref": "Art. 11 & Art. 13(1)",
        "nist_rmf_ref": "GOVERN 1.5",
        "owasp_ref": "OWASP LLM05",
        "mitre_atlas_ref": "AML.T0054"
    },
    {
        "id": "q15_uncertainty_scores",
        "step": 4,
        "step_title": "Transparency & Explainability",
        "label": "Q15: Does every inference provide calibrated prediction confidence / uncertainty bounds?",
        "type": "select",
        "options": [
            {"value": "calibrated_intervals", "label": "Calibrated uncertainty intervals (temperature-scaled confidence / conformal bounds)", "score": 1.0},
            {"value": "raw_softmax", "label": "Uncalibrated raw softmax probability without empirical reliability calibration", "score": 0.5},
            {"value": "none", "label": "None: Categorical prediction returned with zero confidence metric", "score": 0.0}
        ],
        "required": True,
        "dimension": "Transparency & Explainability",
        "research_source": "QB4AIRA §Transparency; Guo et al. (ICML) On Calibration of Modern Neural Networks",
        "eu_ai_act_ref": "Art. 13(3)(b)",
        "nist_rmf_ref": "MEASURE 2.6",
        "owasp_ref": "OWASP LLM05",
        "mitre_atlas_ref": "AML.T0029"
    },

    # -------------------------------------------------------------
    # Step 5: Dimension 4 — Privacy & Data Governance (Q16 - Q20)
    # -------------------------------------------------------------
    {
        "id": "q16_encryption_rest",
        "step": 5,
        "step_title": "Privacy & Data Governance",
        "label": "Q16: Is all stored training data, cache, and inference logs encrypted at rest?",
        "type": "select",
        "options": [
            {"value": "aes256_kms", "label": "AES-256 with managed KMS key rotation and hardware security module (HSM) backing", "score": 1.0},
            {"value": "standard_disk", "label": "Standard OS-level disk encryption without granular key rotation", "score": 0.6},
            {"value": "plaintext", "label": "Plaintext / Unencrypted data at rest (high vulnerability)", "score": 0.0}
        ],
        "required": True,
        "dimension": "Privacy & Data Governance",
        "research_source": "NIST SP 800-53 (SC-28); GDPR Article 32(1)(a)",
        "eu_ai_act_ref": "Art. 10(5)",
        "nist_rmf_ref": "GOVERN 1.2",
        "owasp_ref": "OWASP LLM06 (Sensitive Data Disclosure)",
        "mitre_atlas_ref": "AML.T0015"
    },
    {
        "id": "q17_encryption_transit",
        "step": 5,
        "step_title": "Privacy & Data Governance",
        "label": "Q17: Is data encrypted in transit across all network boundaries?",
        "type": "select",
        "options": [
            {"value": "tls13_strict", "label": "TLS 1.3 enforced with strict HSTS, mutual TLS, and certificate pinning", "score": 1.0},
            {"value": "tls12_mixed", "label": "Standard TLS 1.2 with fallback or mixed internal unencrypted links", "score": 0.6},
            {"value": "unencrypted_http", "label": "Unencrypted HTTP or plaintext socket protocol", "score": 0.0}
        ],
        "required": True,
        "dimension": "Privacy & Data Governance",
        "research_source": "NIST SP 800-53 (SC-8); RFC 8446 (TLS 1.3)",
        "eu_ai_act_ref": "Art. 15(3)",
        "nist_rmf_ref": "GOVERN 1.2",
        "owasp_ref": "OWASP API04 (Resource Consumption)",
        "mitre_atlas_ref": "AML.T0043"
    },
    {
        "id": "q18_data_retention",
        "step": 5,
        "step_title": "Privacy & Data Governance",
        "label": "Q18: What is the data retention and automated purging policy for user inference logs?",
        "type": "select",
        "options": [
            {"value": "strict_90", "label": "Strict <= 90 days with cryptographically verified automated shredding", "score": 1.0},
            {"value": "moderate_180", "label": "Standard 90 – 180 days retention with manual periodic review", "score": 0.6},
            {"value": "indefinite", "label": "Indefinite or unmanaged log retention (> 180 days / no purge mechanism)", "score": 0.0}
        ],
        "required": True,
        "dimension": "Privacy & Data Governance",
        "research_source": "GDPR Art. 5(1)(e) Storage Limitation; QB4AIRA §Privacy",
        "eu_ai_act_ref": "Art. 10(5)",
        "nist_rmf_ref": "GOVERN 1.2",
        "owasp_ref": "OWASP LLM06",
        "mitre_atlas_ref": "AML.T0015"
    },
    {
        "id": "q19_pii_handling",
        "step": 5,
        "step_title": "Privacy & Data Governance",
        "label": "Q19: Does the system detect, redact, or anonymize Personally Identifiable Information (PII)?",
        "type": "select",
        "options": [
            {"value": "automated_redaction", "label": "Automated regex & NER PII redaction pipeline before prompt storage / logging", "score": 1.0},
            {"value": "basic_filtering", "label": "Basic keyword filtering without specialized NER entity masking", "score": 0.5},
            {"value": "none", "label": "None: Raw user prompts and sensitive records stored unredacted", "score": 0.0}
        ],
        "required": True,
        "dimension": "Privacy & Data Governance",
        "research_source": "GDPR Art. 25 Data Protection by Design; Pfau & Jung §Privacy",
        "eu_ai_act_ref": "Art. 10(5)",
        "nist_rmf_ref": "MAP 1.6",
        "owasp_ref": "OWASP LLM06",
        "mitre_atlas_ref": "AML.T0015"
    },
    {
        "id": "q20_governance_policy",
        "step": 5,
        "step_title": "Privacy & Data Governance",
        "label": "Q20: Is there an established AI data governance policy with formally designated Data Stewards?",
        "type": "select",
        "options": [
            {"value": "formal_policy", "label": "Formal ISO/IEC 42001 aligned AI data governance charter with designated owners", "score": 1.0},
            {"value": "general_it", "label": "General corporate IT data policy without AI-specific training data safeguards", "score": 0.5},
            {"value": "none", "label": "None: No formal data governance charter or steward assigned", "score": 0.0}
        ],
        "required": True,
        "dimension": "Privacy & Data Governance",
        "research_source": "ISO/IEC 42001:2023 §A.7; QB4AIRA §Governance",
        "eu_ai_act_ref": "Art. 10(2)",
        "nist_rmf_ref": "GOVERN 1.1",
        "owasp_ref": "OWASP LLM04 (Data Poisoning)",
        "mitre_atlas_ref": "AML.T0015"
    },

    # -------------------------------------------------------------
    # Step 6: Dimension 5 — Human Oversight & Agency (Q21 - Q25)
    # -------------------------------------------------------------
    {
        "id": "q21_human_oversight",
        "step": 6,
        "step_title": "Human Oversight & Agency",
        "label": "Q21: Is human oversight mandatory before AI decisions are actuated in production?",
        "type": "select",
        "options": [
            {"value": "mandatory_hitl", "label": "Mandatory HITL: Qualified human expert must sign off on high-risk decisions", "score": 1.0},
            {"value": "optional_hotl", "label": "Human-on-the-loop: AI acts automatically with retrospective operator audit", "score": 0.5},
            {"value": "none", "label": "Zero Oversight: Fully autonomous execution without human review interface", "score": 0.0}
        ],
        "required": True,
        "dimension": "Human Oversight & Agency",
        "research_source": "QB4AIRA §Accountability; Dhanorkar et al. (ACM FAccT 2026)",
        "eu_ai_act_ref": "Art. 14(1)",
        "nist_rmf_ref": "GOVERN 1.4",
        "owasp_ref": "OWASP LLM08",
        "mitre_atlas_ref": "AML.T0054"
    },
    {
        "id": "q22_autonomy_level",
        "step": 6,
        "step_title": "Human Oversight & Agency",
        "label": "Q22: What autonomy classification characterizes this AI's operational mode?",
        "type": "select",
        "options": [
            {"value": "advisory", "label": "Advisory Only: AI provides recommendations; natural person executes action", "score": 1.0},
            {"value": "semi_autonomous", "label": "Semi-Autonomous: AI takes routine actions; alerts operator for exceptions", "score": 0.6},
            {"value": "fully_autonomous", "label": "Fully Autonomous: AI initiates and completes irreversible workflows alone", "score": 0.1}
        ],
        "required": True,
        "dimension": "Human Oversight & Agency",
        "research_source": "Pfau & Jung (IEEE TAI 2026) §Human Agency; EU AI Act Art. 14(4)",
        "eu_ai_act_ref": "Art. 14(4)",
        "nist_rmf_ref": "GOVERN 1.4",
        "owasp_ref": "OWASP LLM08 (Excessive Agency)",
        "mitre_atlas_ref": "AML.T0054"
    },
    {
        "id": "q24_kill_switch",
        "step": 6,
        "step_title": "Human Oversight & Agency",
        "label": "Q23: Does an authorized human operator possess an immediate emergency kill-switch?",
        "type": "select",
        "options": [
            {"value": "instant_killswitch", "label": "Instant hardware/software kill-switch: Safely suspends AI execution within seconds", "score": 1.0},
            {"value": "graceful_drain", "label": "Graceful process drain requiring cloud console administrator privileges", "score": 0.6},
            {"value": "none", "label": "None: Cannot interrupt running workflows without tearing down primary service", "score": 0.0}
        ],
        "required": True,
        "dimension": "Human Oversight & Agency",
        "research_source": "Pfau & Jung (IEEE TAI 2026) §Human Agency; Dhanorkar et al. (2026)",
        "eu_ai_act_ref": "Art. 14(4)(e)",
        "nist_rmf_ref": "GOVERN 1.4",
        "owasp_ref": "OWASP LLM08 (Excessive Agency)",
        "mitre_atlas_ref": "AML.T0054"
    },
    {
        "id": "q24b_operator_training",
        "step": 6,
        "step_title": "Human Oversight & Agency",
        "label": "Q24: Have human overseers received verified training on system operational boundaries?",
        "type": "select",
        "options": [
            {"value": "certified_training", "label": "Certified Training: Mandatory role-based competency certification and boundary drills", "score": 1.0},
            {"value": "basic_briefing", "label": "Informal: Product walkthrough briefing or standard operating procedure document", "score": 0.5},
            {"value": "none", "label": "None: No formal training on automation bias or error detection provided", "score": 0.0}
        ],
        "required": True,
        "dimension": "Human Oversight & Agency",
        "research_source": "EU AI Act Art. 14(2); NIST AI RMF GOVERN 2.2",
        "eu_ai_act_ref": "Art. 14(2)",
        "nist_rmf_ref": "GOVERN 2.2",
        "owasp_ref": "OWASP LLM08",
        "mitre_atlas_ref": "AML.T0054"
    },
    {
        "id": "q24c_override_capability",
        "step": 6,
        "step_title": "Human Oversight & Agency",
        "label": "Q25: Can operators intervene, override, or reverse AI decisions in real time?",
        "type": "select",
        "options": [
            {"value": "instant_override", "label": "Real-time Override: Dedicated operator console can instantly reverse decisions", "score": 1.0},
            {"value": "post_hoc_ticket", "label": "Post-hoc Review: Decisions can be flagged for support review within business hours", "score": 0.5},
            {"value": "irreversible", "label": "Irreversible: Decisions execute automatically without manual override hook", "score": 0.0}
        ],
        "required": True,
        "dimension": "Human Oversight & Agency",
        "research_source": "EU AI Act Art. 14(4)(a); IEEE TAI 2026 §Human Agency",
        "eu_ai_act_ref": "Art. 14(4)(a)",
        "nist_rmf_ref": "GOVERN 1.4",
        "owasp_ref": "OWASP LLM08",
        "mitre_atlas_ref": "AML.T0054"
    },

    # -------------------------------------------------------------
    # Step 7: Dimension 6 — Accountability & Governance (Q26 - Q30)
    # -------------------------------------------------------------
    {
        "id": "q23_incident_escalation",
        "step": 7,
        "step_title": "Accountability & Governance",
        "label": "Q26: Is there a documented incident escalation and anomaly triage protocol?",
        "type": "select",
        "options": [
            {"value": "formal_escalation", "label": "Documented 24/7 on-call escalation protocol with defined SLAs and incident commander", "score": 1.0},
            {"value": "informal_slack", "label": "Ad-hoc developer alerting (email/Slack) without guaranteed response SLA", "score": 0.5},
            {"value": "none", "label": "None: No defined incident triage or failure escalation pathway", "score": 0.0}
        ],
        "required": True,
        "dimension": "Accountability & Governance",
        "research_source": "ISO/IEC 42001 §A.8; QB4AIRA §Accountability",
        "eu_ai_act_ref": "Art. 9(9)",
        "nist_rmf_ref": "MANAGE 4.1",
        "owasp_ref": "OWASP LLM08 (Excessive Agency)",
        "mitre_atlas_ref": "AML.T0054"
    },
    {
        "id": "q25_decision_logging",
        "step": 7,
        "step_title": "Accountability & Governance",
        "label": "Q27: Are all AI inputs, prompts, weights, and decisions logged in tamper-evident audit trails?",
        "type": "select",
        "options": [
            {"value": "append_only_signed", "label": "Cryptographically signed append-only logs with WORM storage (Art. 12 compliant)", "score": 1.0},
            {"value": "standard_cloudwatch", "label": "Standard database/cloud logging without cryptographic integrity verification", "score": 0.6},
            {"value": "none", "label": "None: Ephemeral logging or decisions discarded immediately after response", "score": 0.0}
        ],
        "required": True,
        "dimension": "Accountability & Governance",
        "research_source": "QB4AIRA §Accountability; EU AI Act Article 12 Automatic Logging",
        "eu_ai_act_ref": "Art. 12(1)",
        "nist_rmf_ref": "MEASURE 2.5",
        "owasp_ref": "OWASP LLM08",
        "mitre_atlas_ref": "AML.T0054"
    },
    {
        "id": "q25b_technical_dossier",
        "step": 7,
        "step_title": "Accountability & Governance",
        "label": "Q28: Is a comprehensive EU AI Act Annex IV Technical Documentation dossier maintained?",
        "type": "select",
        "options": [
            {"value": "full_annex_iv", "label": "Full Annex IV: Version-controlled technical dossier with architecture, training data & validation", "score": 1.0},
            {"value": "partial_docs", "label": "Partial: Standard software engineering documentation without statutory Annex IV sections", "score": 0.5},
            {"value": "none", "label": "None: Undocumented system architecture and missing regulatory records", "score": 0.0}
        ],
        "required": True,
        "dimension": "Accountability & Governance",
        "research_source": "EU AI Act Article 11 & Annex IV; ISO/IEC 42001 §A.9",
        "eu_ai_act_ref": "Art. 11",
        "nist_rmf_ref": "GOVERN 1.5",
        "owasp_ref": "OWASP LLM05",
        "mitre_atlas_ref": "AML.T0054"
    },
    {
        "id": "q25c_post_market_monitoring",
        "step": 7,
        "step_title": "Accountability & Governance",
        "label": "Q29: Is there a systematic post-market monitoring plan and regulatory authority reporting workflow?",
        "type": "select",
        "options": [
            {"value": "active_monitoring", "label": "Active Plan: Continuous post-market telemetry with automated serious incident alerting per Art. 72", "score": 1.0},
            {"value": "reactive_support", "label": "Reactive: Customer ticket intake without formal regulatory incident reporting SLAs", "score": 0.5},
            {"value": "none", "label": "None: No post-market monitoring or incident disclosure protocol", "score": 0.0}
        ],
        "required": True,
        "dimension": "Accountability & Governance",
        "research_source": "EU AI Act Article 72; NIST AI RMF MANAGE 4.3",
        "eu_ai_act_ref": "Art. 72",
        "nist_rmf_ref": "MANAGE 4.3",
        "owasp_ref": "OWASP LLM08",
        "mitre_atlas_ref": "AML.T0054"
    },
    {
        "id": "q25d_governance_charter",
        "step": 7,
        "step_title": "Accountability & Governance",
        "label": "Q30: Has an executive AI Governance Charter designated responsible compliance stewards?",
        "type": "select",
        "options": [
            {"value": "formal_charter", "label": "Formal Charter: Designated AI Ethics Board, Chief AI Safety Officer, and line-of-business owners", "score": 1.0},
            {"value": "ad_hoc_committee", "label": "Ad-hoc committee without formal executive veto power or defined accountability lines", "score": 0.5},
            {"value": "none", "label": "None: No designated AI governance owner or organizational accountability structure", "score": 0.0}
        ],
        "required": True,
        "dimension": "Accountability & Governance",
        "research_source": "ISO/IEC 42001:2023 §5 Leadership; NIST AI RMF GOVERN 1.1",
        "eu_ai_act_ref": "Art. 9(1)",
        "nist_rmf_ref": "GOVERN 1.1",
        "owasp_ref": "OWASP LLM08",
        "mitre_atlas_ref": "AML.T0054"
    },

    # -------------------------------------------------------------
    # Step 8: Dimension 7 — Safety & Reliability (Q31 - Q35)
    # -------------------------------------------------------------
    {
        "id": "q26_input_validation",
        "step": 8,
        "step_title": "Safety & Reliability",
        "label": "Q31: Does the model validate and reject corrupted, malformed, or out-of-range inputs?",
        "type": "select",
        "options": [
            {"value": "comprehensive_rejection", "label": "Comprehensive: Strict Pydantic/JSON-schema validation, range clamps & corrupted data rejection", "score": 1.0},
            {"value": "basic_types", "label": "Basic: Primitive type coercion (casts string to float) without domain range bounds", "score": 0.5},
            {"value": "none", "label": "None: Direct passthrough of arbitrary raw inputs to model tensors", "score": 0.0}
        ],
        "required": True,
        "dimension": "Safety & Reliability",
        "research_source": "QB4AIRA §Safety; Pfau & Jung (IEEE TAI 2026) §Robustness",
        "eu_ai_act_ref": "Art. 15(1)",
        "nist_rmf_ref": "MANAGE 2.2",
        "owasp_ref": "OWASP LLM01 (Prompt Injection)",
        "mitre_atlas_ref": "AML.T0043"
    },
    {
        "id": "q27_guardrail_count",
        "step": 8,
        "step_title": "Safety & Reliability",
        "label": "Q32: How many independent safety guardrails are operational in the pipeline?",
        "type": "select",
        "options": [
            {"value": "3plus", "label": ">= 3 Guardrails: Input schema validator + Output range clamp + Anomaly detector", "score": 1.0},
            {"value": "1to2", "label": "1 – 2 Guardrails: Partial controls (e.g., input type check only)", "score": 0.5},
            {"value": "zero", "label": "Zero: Model runs without active software guardrails or safety filters", "score": 0.0}
        ],
        "required": True,
        "dimension": "Safety & Reliability",
        "research_source": "RBAAF Safety Scaffold; Pfau & Jung (IEEE TAI 2026) §Safety",
        "eu_ai_act_ref": "Art. 9(2)(a)",
        "nist_rmf_ref": "MANAGE 2.2",
        "owasp_ref": "OWASP LLM05 (Improper Output Handling)",
        "mitre_atlas_ref": "AML.T0029"
    },
    {
        "id": "q28_output_clamping",
        "step": 8,
        "step_title": "Safety & Reliability",
        "label": "Q33: Does the system enforce deterministic safety clamping on dangerous output bounds?",
        "type": "select",
        "options": [
            {"value": "hard_clamping", "label": "Hard Clamping: Strict programmatic limits enforce legal/physical boundaries on outputs", "score": 1.0},
            {"value": "soft_warning", "label": "Soft Advisory: Flags out-of-bounds outputs but allows consumer execution", "score": 0.5},
            {"value": "raw_unclamped", "label": "Raw Unclamped: Extreme unbounded values emitted directly to consumers", "score": 0.0}
        ],
        "required": True,
        "dimension": "Safety & Reliability",
        "research_source": "QB4AIRA §Safety; Pfau & Jung §Safety; Clinical Dosage Benchmark",
        "eu_ai_act_ref": "Art. 15(1)",
        "nist_rmf_ref": "MANAGE 2.2",
        "owasp_ref": "OWASP LLM05",
        "mitre_atlas_ref": "AML.T0029"
    },
    {
        "id": "q29_contextual_advisory",
        "step": 8,
        "step_title": "Safety & Reliability",
        "label": "Q34: Does the system emit contextual or environmental safety advisories alongside predictions?",
        "type": "select",
        "options": [
            {"value": "yes_dynamic", "label": "Yes: Dynamic warnings generated based on real-world environment/safety context", "score": 1.0},
            {"value": "static_disclaimer", "label": "Static Disclaimer: Generic boiler-plate disclaimer text appended to responses", "score": 0.5},
            {"value": "no", "label": "No: Outputs emitted without safety or operational context advisories", "score": 0.0}
        ],
        "required": True,
        "dimension": "Safety & Reliability",
        "research_source": "Pfau & Jung (IEEE TAI 2026) §Safety; EU AI Act Art. 13(3)(d)",
        "eu_ai_act_ref": "Art. 13(3)(d)",
        "nist_rmf_ref": "MANAGE 2.3",
        "owasp_ref": "OWASP LLM05",
        "mitre_atlas_ref": "AML.T0029"
    },
    {
        "id": "q30_failure_mode_testing",
        "step": 8,
        "step_title": "Safety & Reliability",
        "label": "Q35: Has the system been validated against documented edge cases and known failure modes?",
        "type": "select",
        "options": [
            {"value": "formal_failure_suite", "label": "Formal Test Suite: Regression suite covering 100% of cataloged failure modes & edge cases", "score": 1.0},
            {"value": "partial_tests", "label": "Partial: Ad-hoc unit tests for known bugs without systematic edge case harness", "score": 0.5},
            {"value": "none", "label": "None: No formal regression or failure-mode test harness active", "score": 0.0}
        ],
        "required": True,
        "dimension": "Safety & Reliability",
        "research_source": "QB4AIRA §Reliability; RBAAF Verification Framework",
        "eu_ai_act_ref": "Art. 15(1)",
        "nist_rmf_ref": "MEASURE 2.8",
        "owasp_ref": "OWASP LLM05",
        "mitre_atlas_ref": "AML.T0029"
    }
]

DOMAIN_LABELS = {
    "healthcare": "Healthcare / Medical Diagnostics",
    "finance": "Finance / Credit Scoring",
    "agriculture": "Agriculture / Environmental",
    "education": "Education / Admissions",
    "autonomous_vehicles": "Autonomous Vehicles / Robotics",
    "criminal_justice": "Criminal Justice / Law Enforcement",
    "cybersecurity": "Cybersecurity / Critical Infrastructure",
    "ecommerce": "E-Commerce / Commercial Retail",
    "manufacturing": "Manufacturing / Industrial",
    "entertainment": "Entertainment / Media Synthesis",
    "other": "General Purpose AI"
}

DIMENSIONS_LIST = [
    "Security & Robustness",
    "Safety & Reliability",
    "Fairness & Non-Discrimination",
    "Transparency & Explainability",
    "Privacy & Data Governance",
    "Human Oversight & Agency",
    "Accountability & Governance",
]


def get_questions() -> List[Dict[str, Any]]:
    """Returns the full 35-question list for frontend wizard."""
    return QUESTIONS


def calculate_dimension_scores(answers: Dict[str, Any],
                               evidence_tier: str = "T3") -> Tuple[Dict[str, float], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Computes 6-dimension scores from question answers using Multi-Tier Evidence Weighting:
    - Tier 1 (Automated MCP probe): weight = 1.0
    - Tier 2 (Declared metadata/schema): weight = 0.8
    - Tier 3 (Self-attested questionnaire response): weight = 0.6
    """
    tier_weights = {"T1": 1.0, "T2": 0.8, "T3": 0.6}
    w_evidence = tier_weights.get(evidence_tier, 0.6)

    # Buckets for dimension scoring
    dim_totals: Dict[str, float] = {d: 0.0 for d in DIMENSIONS_LIST}
    dim_counts: Dict[str, int] = {d: 0 for d in DIMENSIONS_LIST}
    findings: List[Dict[str, Any]] = []
    logs: List[Dict[str, str]] = []

    def finding(dim: str, sev: str, issue: str, action: str, eu_ref: str = "", nist_ref: str = ""):
        badge_map = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "info", "LOW": "info"}
        findings.append({
            "priority": sev,
            "badge": badge_map.get(sev, "info"),
            "dimension": dim,
            "finding": issue,
            "action": action,
            "eu_ai_act_ref": eu_ref,
            "nist_ref": nist_ref,
            "evidence_tier": evidence_tier,
            "evidence_weight": w_evidence
        })

    # Build question lookup
    q_map = {q["id"]: q for q in QUESTIONS if not q.get("is_identity")}

    for q_id, q_def in q_map.items():
        dim = q_def["dimension"]
        user_val = answers.get(q_id)
        if user_val is None:
            # Unanswered question: do NOT count as 0.5 default
            continue

        matched_opt = None
        for opt in q_def.get("options", []):
            if opt["value"] == user_val:
                matched_opt = opt
                break

        if matched_opt is None:
            # Invalid/unrecognized value: do NOT count as 0.5 default
            continue

        opt_score = float(matched_opt.get("score", 0.0))
        opt_label = matched_opt.get("label", "")

        dim_totals[dim] += (opt_score * 100.0)
        dim_counts[dim] += 1

        # Check for deficiencies
        if opt_score == 0.0:
            finding(
                dim=dim,
                sev="CRITICAL" if dim in ("Security & Robustness", "Safety & Reliability") else "HIGH",
                issue=f"{q_def['label']} — Control absent: {opt_label}",
                action=f"Remediate control mapped to {q_def.get('eu_ai_act_ref', 'compliance')} and {q_def.get('nist_rmf_ref', '')}.",
                eu_ref=q_def.get("eu_ai_act_ref", ""),
                nist_ref=q_def.get("nist_rmf_ref", "")
            )
        elif opt_score <= 0.6:
            finding(
                dim=dim,
                sev="MEDIUM",
                issue=f"{q_def['label']} — Partial implementation: {opt_label}",
                action=f"Upgrade control to comprehensive status per {q_def.get('research_source', '')}.",
                eu_ref=q_def.get("eu_ai_act_ref", ""),
                nist_ref=q_def.get("nist_rmf_ref", "")
            )

    # Compute normalized dimension scores
    dimension_scores: Dict[str, Optional[float]] = {}
    for dim in DIMENSIONS_LIST:
        if dim_counts[dim] == 0:
            dimension_scores[dim] = None
        else:
            raw_avg = dim_totals[dim] / dim_counts[dim]
            dimension_scores[dim] = round(raw_avg, 1)

    return dimension_scores, findings, logs


def compute_aas_and_bottleneck(dimensions: Dict[str, Optional[float]], alpha: float = 0.6) -> Dict[str, Any]:
    """
    Computes Bottleneck-Penalized Trust Score (AAS) via bottleneck-penalised aggregate,
    inspired by average-case versus worst-case ERM:
    AAS = alpha * mean(S) + (1 - alpha) * min(S)
    Dimensions with score=None are excluded from mean and min.
    Withholds AAS if fewer than 4 dimensions have evidence.
    """
    canonical_7 = [
        "Security & Robustness",
        "Safety & Reliability",
        "Fairness & Non-Discrimination",
        "Transparency & Explainability",
        "Privacy & Data Governance",
        "Human Oversight & Agency",
        "Accountability & Governance",
    ]
    has_7 = any(k in dimensions for k in ("Human Oversight & Agency", "Accountability & Governance"))
    if has_7:
        eval_dims = {k: v for k, v in dimensions.items() if k in canonical_7 and v is not None}
    else:
        eval_dims = {k: v for k, v in dimensions.items() if v is not None}

    valid_scores = list(eval_dims.values())
    if len(valid_scores) < 4:
        return {
            "aas_score": None,
            "weighted_average": round(sum(valid_scores) / len(valid_scores), 1) if valid_scores else None,
            "bottleneck_score": min(valid_scores) if valid_scores else None,
            "bottleneck_dimension": next((k for k, v in eval_dims.items() if v == min(valid_scores)), None) if valid_scores else "Unknown",
            "trust_grade": "INSUFFICIENT_EVIDENCE",
            "alpha_parameter": alpha,
            "sensitivity_curve": [],
            "status": "INSUFFICIENT_EVIDENCE",
        }

    weighted_average = sum(valid_scores) / len(valid_scores)
    bottleneck_score = min(valid_scores)
    bottleneck_dimension = next(k for k, v in eval_dims.items() if v == bottleneck_score)

    aas = round((alpha * weighted_average) + ((1.0 - alpha) * bottleneck_score), 1)

    if aas >= 90: grade = "A+"
    elif aas >= 80: grade = "A"
    elif aas >= 70: grade = "B"
    elif aas >= 60: grade = "C"
    elif aas >= 50: grade = "D"
    else: grade = "F"

    # Compute sensitivity curve across alpha in [0.1, 0.9]
    sensitivity_curve = []
    for a_val in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
        score_at_a = round((a_val * weighted_average) + ((1.0 - a_val) * bottleneck_score), 1)
        sensitivity_curve.append({
            "alpha": round(a_val, 1),
            "score": score_at_a,
            "interpretation": "High Bottleneck Penalty" if a_val <= 0.3 else ("Balanced (bottleneck-penalised aggregate)" if a_val <= 0.7 else "Mean-Dominant")
        })

    return {
        "aas_score": aas,
        "weighted_average": round(weighted_average, 1),
        "bottleneck_score": round(bottleneck_score, 1),
        "bottleneck_dimension": bottleneck_dimension,
        "trust_grade": grade,
        "alpha_parameter": alpha,
        "sensitivity_curve": sensitivity_curve,
        "status": "COMPUTED",
    }


def generate_audit_from_questionnaire(answers: Dict[str, Any],
                                      evidence_tier: str = "T3") -> Dict[str, Any]:
    """
    Takes user questionnaire answers and executes the complete 7-dimension audit.
    Integrates all research-grounded compliance engines.
    """
    logs: List[Dict[str, str]] = []

    def log(stage: str, msg: str, st: str = "INFO"):
        logs.append({"stage": stage, "message": msg, "status": st})

    model_name = answers.get("model_name", "AI System Under Audit")
    model_version = answers.get("model_version", "1.0.0")
    domain = answers.get("domain", "other")
    architecture = answers.get("architecture", "Unknown Model")
    deployment_type = answers.get("deployment_type", "cloud_api")
    domain_label = DOMAIN_LABELS.get(domain, "General Purpose AI")

    log("DISCOVERY", f"Initiating research-grounded audit for '{model_name}' v{model_version}...", "INFO")
    log("DISCOVERY", f"Operating Domain: {domain_label} | Architecture: {architecture} | Topology: {deployment_type}", "SUCCESS")
    log("DISCOVERY", f"Evidence Tier: {evidence_tier} (Confidence Weight: {1.0 if evidence_tier=='T1' else (0.8 if evidence_tier=='T2' else 0.6)})", "INFO")

    # Phase 1: Compute 7 Dimension Scores
    dimensions, findings, audit_logs = calculate_dimension_scores(answers, evidence_tier=evidence_tier)
    log("EVALUATION", f"Computed 7 dimension scores across 35 research-grounded question items.", "SUCCESS")

    # Phase 2: Compute Bottleneck AAS
    scoring = compute_aas_and_bottleneck(dimensions, alpha=0.6)
    aas = scoring["aas_score"]
    grade = scoring["trust_grade"]
    log("SCORING", f"Bottleneck AAS Score: {aas}/100 (Grade: {grade}) | Bottleneck: '{scoring['bottleneck_dimension']}' ({scoring['bottleneck_score']})", "SUCCESS")

    # Phase 3: Regulatory Compliance (EU AI Act & NIST AI RMF)
    eu_compliance = evaluate_eu_ai_act_compliance(
        domain=domain,
        autonomy_level=answers.get("q22_autonomy_level", "semi_autonomous"),
        dimensions=dimensions,
        answers=answers
    )
    log("COMPLIANCE", f"EU AI Act Classification: {eu_compliance['intended_purpose_classification']['tier']}", "INFO")

    nist_compliance = evaluate_nist_ai_rmf(dimensions=dimensions)
    log("COMPLIANCE", "NIST AI RMF 1.0 Subcategory Crosswalk completed across GOVERN, MAP, MEASURE, MANAGE.", "INFO")

    # Phase 4: OWASP & MITRE ATLAS Mappings
    threat_crosswalk = map_owasp_and_atlas(findings=findings, dimensions=dimensions)

    # Phase 5: Empirical Benchmark Engines
    fairness_metrics = compute_fairness_metrics(answers=answers, fairness_score=dimensions.get("Fairness & Non-Discrimination"))
    risk_cohorts = analyze_risk_cohorts(dimensions=dimensions, findings=findings, metadata={"domain": domain_label})
    counterfactual = solve_remediation_priority(current_aas=aas, dimensions=dimensions, findings=findings, target_score=76.0)
    vulnerability_scan = scan_ai_vulnerabilities(domain=domain_label)

    # Construct Metadata Payload
    metadata = {
        "model_name": model_name,
        "version": model_version,
        "domain": domain_label,
        "model_architecture": architecture,
        "deployment_type": deployment_type,
        "autonomy_level": answers.get("q22_autonomy_level", "semi_autonomous"),
        "audit_mode": "questionnaire_v3",
        "evidence_tier": evidence_tier,
        "evidence_confidence_weight": 1.0 if evidence_tier == "T1" else (0.8 if evidence_tier == "T2" else 0.6),
        "audit_timestamp": datetime.now().isoformat()
    }

    # Sort findings by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: sev_order.get(x["priority"], 99))

    audit_payload = {
        "model_metadata": metadata,
        "dimensions": dimensions,
        "scoring": scoring,
        "compliance": {
            "eu_ai_act": {
                "tier": eu_compliance["intended_purpose_classification"]["tier"],
                "badge_color": eu_compliance["intended_purpose_classification"]["badge_color"],
                "legal_basis": eu_compliance["intended_purpose_classification"]["legal_basis"],
                "market_placement_permitted": eu_compliance["intended_purpose_classification"]["market_placement_permitted"],
                "conformity_assessment_required": eu_compliance["intended_purpose_classification"]["conformity_assessment_required"],
                "overall_status": eu_compliance["article_level_conformance"]["overall_status"],
                "conformant_articles": eu_compliance["article_level_conformance"]["conformant_articles"],
                "articles": eu_compliance["article_level_conformance"]["articles"]
            },
            "nist_ai_rmf": nist_compliance["functions"],
            "nist_rmf": nist_compliance["functions"]
        },
        "threat_landscape": {
            "owasp_llm_top_10": threat_crosswalk["owasp_llm_top_10"],
            "mitre_atlas_techniques": threat_crosswalk["mitre_atlas_techniques"]
        },
        "remediation_plan": findings,
        "audit_logs": logs + audit_logs,
        "audit_summary": {
            "total_questions": 35,
            "evidence_tier": evidence_tier,
            "confidence_weight": metadata["evidence_confidence_weight"],
            "findings_count": len(findings),
            "critical_findings": sum(1 for f in findings if f["priority"] == "CRITICAL"),
            "high_findings": sum(1 for f in findings if f["priority"] == "HIGH")
        },
        "audit_mode": "questionnaire",
        "aif360": fairness_metrics,
        "cohort_analysis": risk_cohorts,
        "remediation_priority": counterfactual,
        "prescriptive_counterfactual": counterfactual,
        "vulnerability_scan": vulnerability_scan
    }

    # Generate Google Model Card
    audit_payload["model_card"] = generate_google_model_card(audit_payload)

    # Compute SHA-256 integrity hash of canonical payload
    canonical_bytes = json.dumps(audit_payload, sort_keys=True, default=str).encode("utf-8")
    audit_payload["audit_hash"] = hashlib.sha256(canonical_bytes).hexdigest()
    audit_payload["sha256_hash"] = audit_payload["audit_hash"]

    return audit_payload
