"""
AI-GRID Questionnaire-Based Audit Engine (v4.0)

Implements the 35 Research-Grounded Question Bank (5 per dimension x 7 dimensions)
grounded in QB4AIRA (Lee et al., 2024), ISO/IEC 42001, EU AI Act (Articles 9-15),
NIST AI 100-1, OWASP Top 10, and MITRE ATLAS.

Employs Multi-Tier Evidence Weighting (T1=1.0, T2=0.8, T3=0.6; all active audits currently T3)
and bottleneck-penalised aggregate scoring (AAS), inspired by average-case versus worst-case ERM.
"""

from dataclasses import dataclass, field
import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from compliance_engines import (
    compute_fairness_metrics,
    solve_remediation_priority,
    evaluate_eu_ai_act_compliance,
    evaluate_nist_ai_rmf,
    map_owasp_and_atlas,
    generate_google_model_card,
)
from config import (
    TIER_WEIGHTS,
    MIN_EVIDENCE_FOR_SUFFICIENCY,
    SUFFICIENCY_CONFIDENCE_THRESHOLD,
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
            {"value": "healthcare", "label": "Healthcare / Medical Diagnostics (High Risk - Healthcare)"},
            {"value": "finance", "label": "Finance / Credit Scoring (High Risk - Financial Services)"},
            {"value": "agriculture", "label": "Agriculture / Environmental Resource Management"},
            {"value": "education", "label": "Education / Admissions Assessment (High Risk - Education)"},
            {"value": "autonomous_vehicles", "label": "Autonomous Vehicles / Robotics (High Risk - Transport & Robotics)"},
            {"value": "criminal_justice", "label": "Law Enforcement / Judicial Decision Support (High Risk - Justice)"},
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
        "research_source": "QB4AIRA §Security; NIST AI 100-1 MEASURE 2.7",
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
        "research_source": "QB4AIRA §Monitoring; ISO/IEC 42001:2023",
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
        "research_source": "NIST SP 800-218 (SSDF); OWASP LLM Top 10 (LLM03)",
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
        "research_source": "OWASP LLM Top 10; MITRE ATLAS",
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
        "research_source": "OWASP API Security Top 10 (API4)",
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
        "research_source": "QB4AIRA §Fairness; NIST AI 100-1 MEASURE 2.11; Kamiran & Calders (2012)",
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
        "research_source": "EU AI Act Art. 10; NIST AI 100-1 MAP 1.1; ISO/IEC 42001",
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
        "research_source": "QB4AIRA §Transparency; NIST AI 100-1 MAP 1.5; ISO/IEC 42001",
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
        "research_source": "EU AI Act Art. 13(3)(d); NIST AI 100-1 MAP 1.5",
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
        "research_source": "GDPR Art. 25 Data Protection by Design; NIST AI 100-1 GOVERN 1.2",
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
        "research_source": "QB4AIRA §Accountability; Mitchell et al. (2019) Model Cards",
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
        "research_source": "EU AI Act Art. 14(4); NIST AI 100-1 GOVERN 1.4",
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
        "research_source": "EU AI Act Art. 14(4)(e); NIST AI 100-1 GOVERN 1.4",
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
        "research_source": "QB4AIRA §Safety; NIST AI 100-1 MANAGE 2.2",
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
        "research_source": "EU AI Act Article 9; NIST AI 100-1 MANAGE 2.4",
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
        "research_source": "QB4AIRA §Safety; NIST AI 100-1 MANAGE 2.2; Clinical Dosage Benchmark",
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
        "research_source": "EU AI Act Art. 13(3)(d); NIST AI 100-1 MANAGE 2.3",
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
        "research_source": "QB4AIRA §Reliability; NIST AI 100-1",
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


# =====================================================================
# v5.1 SCORING PARAMETERS (all are DESIGN PARAMETERS, not empirically derived)
# Justification and sensitivity analysis: docs/METHODOLOGY.md, scripts/reproduce_results.py
# =====================================================================
from governance_catalog import merge_into_questions as _merge_catalog

_merge_catalog(QUESTIONS)   # corrected EU/NIST refs + governance action, owner, evidence per question

# Evidence tiers (weight of an item in its dimension average):
#   T1 = machine-verified by an AI-GRID verifier module (score replaced by measured result)
#   T2 = documentary evidence reference supplied for the answer, not machine-verified
#   T3 = self-attested questionnaire answer
EVIDENCE_TIER_WEIGHTS = {"T1": 1.0, "T2": 0.8, "T3": 0.6}
DEFAULT_ALPHA = 0.6                      # AAS = alpha * mean + (1 - alpha) * min
ILLUSTRATIVE_TARGET_AAS = 76.0           # heuristic benchmark threshold used by the remediation ranker
VERIFIABLE_QUESTION_IDS = (              # questions that currently have a verifier module
    "q1_adversarial_tested", "q3_sbom_tracking", "q10_fairness_audit",
    "q17_encryption_transit", "q25_decision_logging",
)

# Illustrative domain weight profiles (relative importance of each dimension). Equal weighting is the
# neutral default. These profiles are design assumptions reflecting the Annex III use-case context and
# should be replaced by expert-elicited weights (e.g. AHP) in future work.
DOMAIN_WEIGHT_PROFILES: Dict[str, Dict[str, float]] = {
    "healthcare": {"Safety & Reliability": 1.5, "Human Oversight & Agency": 1.5, "Privacy & Data Governance": 1.25},
    "finance": {"Fairness & Non-Discrimination": 1.5, "Transparency & Explainability": 1.5,
                "Accountability & Governance": 1.25, "Privacy & Data Governance": 1.25},
    "criminal_justice": {"Fairness & Non-Discrimination": 1.5, "Human Oversight & Agency": 1.5,
                         "Transparency & Explainability": 1.5, "Accountability & Governance": 1.25},
    "autonomous_vehicles": {"Safety & Reliability": 1.75, "Security & Robustness": 1.5, "Human Oversight & Agency": 1.25},
    "education": {"Fairness & Non-Discrimination": 1.5, "Transparency & Explainability": 1.25, "Privacy & Data Governance": 1.25},
    "cybersecurity": {"Security & Robustness": 1.75},
    "biometrics": {"Privacy & Data Governance": 1.5, "Fairness & Non-Discrimination": 1.5, "Accountability & Governance": 1.25},
}

GRADE_ORDER = ["F", "D", "C", "B", "A", "A+"]
GRADE_CAP_NO_REFUTED_CLAIM = "C"     # a verifier refuted a claimed answer
GRADE_CAP_NO_CRITICAL_GAP = "C"      # at least one CRITICAL finding is open


def resolve_dimension_weights(profile: Any, domain: str = "") -> Optional[Dict[str, float]]:
    """'equal' / None -> None (equal weights); 'domain' -> illustrative profile for the domain;
    dict -> custom weights (validated, missing dimensions default to 1.0)."""
    if profile in (None, "", "equal"):
        return None
    if profile == "domain":
        d = (domain or "").lower().replace(" / ", "_").replace(" ", "_").strip()
        key = next((k for k in DOMAIN_WEIGHT_PROFILES if k in d), None)
        if key is None:
            return None
        return {dim: float(DOMAIN_WEIGHT_PROFILES[key].get(dim, 1.0)) for dim in DIMENSIONS_LIST}
    if isinstance(profile, dict):
        out = {}
        for dim in DIMENSIONS_LIST:
            w = float(profile.get(dim, 1.0))
            if w <= 0:
                raise ValueError(f"dimension weight for '{dim}' must be > 0")
            out[dim] = w
        return out
    raise ValueError("weight_profile must be 'equal', 'domain' or a {dimension: weight} object")


def _q_map() -> Dict[str, Dict[str, Any]]:
    return {q["id"]: q for q in QUESTIONS if not q.get("is_identity")}


def assess_coverage(
    answers: Dict[str, Any],
    verified_evidence: Optional[List[Dict[str, Any]]] = None,
    evidence_refs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """How much of the score rests on verified evidence, and what was not assessed.
    An unanswered question is reported as a gap and is never treated as compliant."""
    q_map = _q_map()
    v_ids = {v["item_id"] for v in (verified_evidence or []) if isinstance(v, dict) and v.get("item_id") in q_map}
    refs = {k for k, v in (evidence_refs or {}).items() if k in q_map and str(v).strip()}
    answered, invalid, unanswered = [], [], []
    per_dim = {d: {"questions": 0, "answered": 0, "verified": 0, "documented": 0} for d in DIMENSIONS_LIST}
    for qid, q in q_map.items():
        per_dim[q["dimension"]]["questions"] += 1
        val = answers.get(qid)
        valid_values = {o["value"] for o in q.get("options", [])}
        if val is None:
            unanswered.append({"id": qid, "dimension": q["dimension"], "question": q["label"],
                               "eu_ai_act_ref": q.get("eu_ai_act_ref", ""), "nist_ref": q.get("nist_rmf_ref", ""),
                               "reason": "not answered"})
        elif val not in valid_values:
            invalid.append({"id": qid, "dimension": q["dimension"], "value": str(val),
                            "reason": "value is not one of the defined options"})
        else:
            answered.append(qid)
            per_dim[q["dimension"]]["answered"] += 1
            if qid in v_ids:
                per_dim[q["dimension"]]["verified"] += 1
            elif qid in refs:
                per_dim[q["dimension"]]["documented"] += 1
    verified_n = sum(1 for qid in answered if qid in v_ids)
    documented_n = sum(1 for qid in answered if qid not in v_ids and qid in refs)
    verifiable = [qid for qid in VERIFIABLE_QUESTION_IDS if qid in q_map]
    n_ans = len(answered)
    if verified_n == 0:
        level = "SELF_ASSESSED"
    elif verified_n >= len(verifiable):
        level = "VERIFIED_WITHIN_VERIFIABLE_SCOPE"
    else:
        level = "PARTIALLY_VERIFIED"
    return {
        "total_questions": len(q_map),
        "answered_questions": n_ans,
        "unanswered_questions": unanswered,
        "invalid_answers": invalid,
        "verified_questions": verified_n,
        "documented_questions": documented_n,
        "self_attested_questions": n_ans - verified_n - documented_n,
        "verifiable_questions": len(verifiable),
        "verified_coverage_pct": round(100.0 * verified_n / n_ans, 1) if n_ans else 0.0,
        "verifiable_scope_coverage_pct": round(100.0 * verified_n / len(verifiable), 1) if verifiable else 0.0,
        "max_attainable_verified_coverage_pct": round(100.0 * len(verifiable) / len(q_map), 1) if q_map else 0.0,
        "assurance_level": level,
        "by_dimension": per_dim,
        "note": "Only questions with a verifier module can reach Tier T1. The remainder of the score rests on self-attestation or documentary evidence.",
    }


def calculate_dimension_scores(
    answers: Dict[str, Any],
    evidence_tier: str = "T3",
    verified_evidence: Optional[List[Dict[str, Any]]] = None,
    evidence_refs: Optional[Dict[str, Any]] = None,
    tier_weights: Optional[Dict[str, float]] = None,
    alpha: float = DEFAULT_ALPHA,
    dimension_weights: Optional[Dict[str, float]] = None,
) -> Tuple[Dict[str, Optional[float]], List[Dict[str, Any]], List[Dict[str, str]], Dict[str, Any]]:
    """
    Computes 7 dimension scores using multi-tier evidence weighting:
    - T1 verified item: score replaced by the verifier's measured result, weight tier_weights['T1']
    - T2 documented item: claimed answer plus a document reference, weight tier_weights['T2']
    - T3 self-attested item: claimed answer, weight tier_weights['T3']

    Attestation gap: the claimed score uses the SAME item weights as the verified score and differs only
    where a verifier overrode an answer, so the gap measures verifier disagreement, not weighting effects.
    """
    tw = dict(EVIDENCE_TIER_WEIGHTS)
    tw.update(tier_weights or {})
    default_w = tw.get(evidence_tier, tw["T3"])
    refs = {k: v for k, v in (evidence_refs or {}).items() if str(v).strip()}

    v_map: Dict[str, Dict[str, Any]] = {}
    if verified_evidence:
        for v in verified_evidence:
            if isinstance(v, dict) and "item_id" in v:
                v_map[v["item_id"]] = v

    findings: List[Dict[str, Any]] = []
    logs: List[Dict[str, str]] = []

    def finding(q_def: Dict[str, Any], dim: str, sev: str, issue: str, action: str,
                tier: str, weight: float, verification_criteria: str):
        badge_map = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "info", "LOW": "info"}
        findings.append({
            "priority": sev,
            "badge": badge_map.get(sev, "info"),
            "dimension": dim,
            "question_id": q_def["id"],
            "finding": issue,
            "action": action,
            "required_governance_action": q_def.get("governance_action", ""),
            "owner_role": q_def.get("owner_role", ""),
            "evidence_expected": q_def.get("evidence_expected", ""),
            "eu_ai_act_ref": q_def.get("eu_ai_act_ref", ""),
            "nist_ref": q_def.get("nist_rmf_ref", ""),
            "evidence_tier": tier,
            "evidence_weight": weight,
            "verification_criteria": verification_criteria,
            "severity_basis": "control gap and dimension",
        })

    dim_effective: Dict[str, List[Tuple[float, float]]] = {d: [] for d in DIMENSIONS_LIST}
    dim_claimed: Dict[str, List[Tuple[float, float]]] = {d: [] for d in DIMENSIONS_LIST}

    for q_id, q_def in _q_map().items():
        dim = q_def["dimension"]
        user_val = answers.get(q_id)
        if user_val is None:
            continue
        matched_opt = next((o for o in q_def.get("options", []) if o["value"] == user_val), None)
        if matched_opt is None:
            continue

        claimed_score = float(matched_opt.get("score", 0.0))

        if q_id in v_map:
            v_item = v_map[q_id]
            eff_score = float(v_item.get("verified_score", 0.0))
            eff_tier, eff_weight = "T1", tw["T1"]
            logs.append({
                "timestamp": datetime.now().isoformat(),
                "event": "VERIFIED_EVIDENCE_APPLIED",
                "message": f"Verified evidence override for {q_id}: claimed={claimed_score:.2f}, verified={eff_score:.2f} (Tier T1, weight {eff_weight})."
            })
        elif q_id in refs:
            eff_score, eff_tier, eff_weight = claimed_score, "T2", tw["T2"]
        else:
            eff_score, eff_tier, eff_weight = claimed_score, evidence_tier, default_w

        dim_effective[dim].append((eff_score, eff_weight))
        dim_claimed[dim].append((claimed_score, eff_weight))

        best_opts = [o for o in q_def.get("options", []) if float(o.get("score", 0)) >= 1.0]
        best_label = best_opts[0]["label"] if best_opts else "full implementation"
        q_label_short = q_def["label"].split(": ", 1)[-1] if ": " in q_def["label"] else q_def["label"]
        gov = q_def.get("governance_action") or f"Close the gap on: {q_label_short}"
        eu_ref = q_def.get("eu_ai_act_ref", "")
        nist_ref = q_def.get("nist_rmf_ref", "")
        ref_txt = f"[{eu_ref} | NIST {nist_ref}]"
        cite = q_def.get("research_source", "EU AI Act & NIST AI RMF")

        if eff_score == 0.0:
            finding(q_def, dim,
                    "CRITICAL" if dim in ("Security & Robustness", "Safety & Reliability") else "HIGH",
                    f"{q_def['label']} — Control absent: {matched_opt.get('label', '')}",
                    f"{gov}. {ref_txt}",
                    eff_tier, eff_weight,
                    f"Obtain the evidence listed for '{q_label_short}': {q_def.get('evidence_expected', best_label)}. Citation: {cite}.")
        elif eff_score <= 0.6:
            finding(q_def, dim, "MEDIUM",
                    f"{q_def['label']} — Partial implementation: {matched_opt.get('label', '')}",
                    f"Move from partial to full — {gov}. Target state: {best_label}. {ref_txt}",
                    eff_tier, eff_weight,
                    f"Verify transition of '{q_label_short}' to: {best_label}. Evidence: {q_def.get('evidence_expected', '')}. Citation: {cite}.")

    def wavg(items: List[Tuple[float, float]]) -> Optional[float]:
        w_total = sum(w for _, w in items)
        return round(100.0 * sum(s * w for s, w in items) / w_total, 1) if w_total > 0 else None

    dimension_scores: Dict[str, Optional[float]] = {}
    claimed_scores: Dict[str, Optional[float]] = {}
    attestation_gap: Dict[str, Any] = {"dimensions": {}, "composite_gap": 0.0}

    for dim in DIMENSIONS_LIST:
        items, c_items = dim_effective[dim], dim_claimed[dim]
        if not items:
            dimension_scores[dim] = None
            claimed_scores[dim] = None
            continue
        dim_score, c_score = wavg(items), wavg(c_items)
        dimension_scores[dim] = dim_score
        claimed_scores[dim] = c_score
        gap = round(c_score - dim_score, 1) if (c_score is not None and dim_score is not None) else 0.0
        attestation_gap["dimensions"][dim] = {
            "claimed_score": c_score,
            "verified_score": dim_score,
            "gap": gap,
            "verified_count": sum(1 for q_id, q in _q_map().items()
                                  if q["dimension"] == dim and q_id in v_map and answers.get(q_id) is not None),
        }

    c_aas = compute_aas_and_bottleneck(claimed_scores, alpha=alpha, dimension_weights=dimension_weights).get("aas_score")
    v_aas = compute_aas_and_bottleneck(dimension_scores, alpha=alpha, dimension_weights=dimension_weights).get("aas_score")
    if c_aas is not None and v_aas is not None:
        attestation_gap["composite_gap"] = round(c_aas - v_aas, 1)
        attestation_gap["claimed_aas"] = c_aas
        attestation_gap["verified_aas"] = v_aas
    else:
        attestation_gap["composite_gap"] = 0.0

    return dimension_scores, findings, logs, attestation_gap


def escalate_for_high_risk(findings: List[Dict[str, Any]], regulatory_tier: str) -> None:
    """For HIGH RISK systems the mapped Art. 9-15/17/72/73 requirements are binding, so every open gap
    is raised one severity level (CRITICAL stays CRITICAL). The base severity is kept for transparency."""
    if regulatory_tier != "HIGH RISK":
        return
    up = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL"}
    badge_map = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "info", "LOW": "info"}
    for f in findings:
        if f["priority"] in up:
            f["priority_base"] = f["priority"]
            f["priority"] = up[f["priority"]]
            f["badge"] = badge_map[f["priority"]]
            f["severity_basis"] = "escalated one level: mapped obligation is binding for high-risk systems"


def apply_grade_caps(
    scoring: Dict[str, Any],
    findings: List[Dict[str, Any]],
    verified_evidence: Optional[List[Dict[str, Any]]],
) -> Dict[str, Any]:
    """Caps the displayed grade so a high average cannot hide an integrity problem or an open critical gap.
    The numeric AAS is never changed. Returns the list of caps applied."""
    grade = scoring.get("trust_grade")
    scoring["uncapped_grade"] = grade
    scoring["grade_caps_applied"] = []
    if grade not in GRADE_ORDER:
        return scoring
    caps = []
    if any(isinstance(v, dict) and v.get("claim_supported") is False for v in (verified_evidence or [])):
        caps.append((GRADE_CAP_NO_REFUTED_CLAIM, "a claimed answer was refuted by verified evidence"))
    if any(f.get("priority") == "CRITICAL" for f in findings):
        caps.append((GRADE_CAP_NO_CRITICAL_GAP, "at least one CRITICAL finding is open"))
    for cap, reason in caps:
        if GRADE_ORDER.index(grade) > GRADE_ORDER.index(cap):
            grade = cap
        scoring["grade_caps_applied"].append({"cap": cap, "reason": reason})
    scoring["trust_grade"] = grade
    return scoring


def compute_aas_and_bottleneck(
    dimensions: Dict[str, Optional[float]],
    alpha: float = DEFAULT_ALPHA,
    dimension_weights: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Bottleneck-penalised trust score:
        AAS = alpha * weighted_mean(S) + (1 - alpha) * min(S)
    weighted_mean uses dimension_weights when given (default: equal weights).
    Dimensions with score=None are excluded. AAS is withheld if fewer than 4 dimensions have data.
    """
    canonical_7 = list(DIMENSIONS_LIST)
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

    if dimension_weights:
        w = {k: float(dimension_weights.get(k, 1.0)) for k in eval_dims}
        weighted_average = sum(eval_dims[k] * w[k] for k in eval_dims) / sum(w.values())
    else:
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
        "dimension_weights": dict(dimension_weights) if dimension_weights else "equal",
        "sensitivity_curve": sensitivity_curve,
        "status": "COMPUTED",
    }


@dataclass
class Evidence:
    """
    A single structured assessment observation with provenance metadata.
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
    status: str = "SUFFICIENT"  # 'SUFFICIENT' | 'INSUFFICIENT_EVIDENCE'


def compute_weighted_dimension_score(
    evidence_items: List[Evidence],
) -> Tuple[Optional[float], float]:
    """
    Computes evidence-weighted score and confidence for a dimension.
    score = Σ(item.value × tier_weight[item.tier]) / Σ(tier_weight[item.tier])
    confidence = 1 - (1 / (1 + n_effective))   where n_effective = Σ tier_weights
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
    Groups evidence by dimension and computes weighted scores for all 7 dimensions.
    """
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



def generate_audit_from_questionnaire(
    answers: Dict[str, Any],
    evidence_tier: str = "T3",
    verified_evidence: Optional[List[Dict[str, Any]]] = None,
    alpha: float = DEFAULT_ALPHA,
    weight_profile: Any = "equal",
    evidence_refs: Optional[Dict[str, Any]] = None,
    tier_weights: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Takes user questionnaire answers and executes the complete 7-dimension audit.
    Integrates all research-grounded compliance engines.

    alpha          bottleneck blend in [0, 1] (default 0.6)
    weight_profile 'equal' (default), 'domain' (illustrative Annex III profile) or {dimension: weight}
    evidence_refs  {question_id: document reference} -> those answers count as Tier T2
    tier_weights   optional override of the T1/T2/T3 weights (used by sensitivity analysis)
    """
    if not isinstance(alpha, (int, float)) or not (0.0 <= float(alpha) <= 1.0):
        raise ValueError("alpha must be a number between 0 and 1")
    alpha = float(alpha)
    logs: List[Dict[str, str]] = []

    def log(stage: str, msg: str, st: str = "INFO"):
        logs.append({"stage": stage, "message": msg, "status": st})

    model_name = answers.get("model_name", "AI System Under Audit")
    model_version = answers.get("model_version", "1.0.0")
    domain = answers.get("domain", "other")
    architecture = answers.get("architecture", "Unknown Model")
    deployment_type = answers.get("deployment_type", "cloud_api")
    domain_label = DOMAIN_LABELS.get(domain, "General Purpose AI")

    tw = dict(EVIDENCE_TIER_WEIGHTS)
    tw.update(tier_weights or {})
    dim_weights = resolve_dimension_weights(weight_profile, domain)

    log("DISCOVERY", f"Initiating research-grounded audit for '{model_name}' v{model_version}...", "INFO")
    log("DISCOVERY", f"Operating Domain: {domain_label} | Architecture: {architecture} | Topology: {deployment_type}", "SUCCESS")
    log("DISCOVERY", f"Default evidence tier for unverified answers: {evidence_tier} (weight {tw.get(evidence_tier, tw['T3'])}); alpha={alpha}; dimension weights: {'equal' if not dim_weights else 'domain profile'}", "INFO")

    coverage = assess_coverage(answers, verified_evidence, evidence_refs)
    n_total, n_answered = coverage["total_questions"], coverage["answered_questions"]

    # Phase 1: Compute 7 Dimension Scores
    dimensions, findings, audit_logs, attestation_gap = calculate_dimension_scores(
        answers, evidence_tier=evidence_tier, verified_evidence=verified_evidence,
        evidence_refs=evidence_refs, tier_weights=tw, alpha=alpha, dimension_weights=dim_weights)
    log("EVALUATION", f"Computed dimension scores from {n_answered} of {n_total} question items "
                      f"({coverage['verified_questions']} verified, {coverage['documented_questions']} documented, "
                      f"{coverage['self_attested_questions']} self-attested).", "SUCCESS")
    if coverage["unanswered_questions"] or coverage["invalid_answers"]:
        log("EVALUATION", f"{len(coverage['unanswered_questions'])} question(s) unanswered and "
                          f"{len(coverage['invalid_answers'])} invalid answer(s): reported as assessment gaps, NOT treated as compliant.", "WARNING")

    # Phase 2: Compute Bottleneck AAS
    scoring = compute_aas_and_bottleneck(dimensions, alpha=alpha, dimension_weights=dim_weights)
    aas = scoring["aas_score"]

    # Phase 3: Regulatory Compliance (EU AI Act & NIST AI RMF)
    eu_compliance = evaluate_eu_ai_act_compliance(
        domain=domain,
        autonomy_level=answers.get("q22_autonomy_level", "semi_autonomous"),
        dimensions=dimensions,
        answers=answers
    )
    reg_tier = eu_compliance["intended_purpose_classification"]["tier"]
    log("COMPLIANCE", f"EU AI Act Classification: {reg_tier}", "INFO")

    # Severity follows the legal obligation: binding for HIGH RISK systems -> escalate one level
    escalate_for_high_risk(findings, reg_tier)
    apply_grade_caps(scoring, findings, verified_evidence)
    grade = scoring["trust_grade"]
    log("SCORING", f"Bottleneck AAS Score: {aas}/100 (Grade: {grade}"
                   f"{' - capped from ' + str(scoring['uncapped_grade']) if scoring['uncapped_grade'] != grade else ''}) | "
                   f"Bottleneck: '{scoring['bottleneck_dimension']}' ({scoring['bottleneck_score']})", "SUCCESS")

    nist_compliance = evaluate_nist_ai_rmf(dimensions=dimensions)
    log("COMPLIANCE", "NIST AI RMF 1.0 Subcategory Crosswalk completed across GOVERN, MAP, MEASURE, MANAGE.", "INFO")

    # Phase 4: OWASP & MITRE ATLAS Mappings
    threat_crosswalk = map_owasp_and_atlas(findings=findings, dimensions=dimensions)

    # Phase 5: Empirical Benchmark Engines
    fairness_metrics = compute_fairness_metrics(answers=answers, fairness_score=dimensions.get("Fairness & Non-Discrimination"))
    counterfactual = solve_remediation_priority(current_aas=aas, dimensions=dimensions, findings=findings,
                                                target_score=ILLUSTRATIVE_TARGET_AAS)

    metadata = {
        "model_name": model_name,
        "version": model_version,
        "domain": domain_label,
        "model_architecture": architecture,
        "deployment_type": deployment_type,
        "autonomy_level": answers.get("q22_autonomy_level", "semi_autonomous"),
        "audit_mode": "questionnaire_v5.1",
        "evidence_tier": evidence_tier,
        "evidence_confidence_weight": tw.get(evidence_tier, tw["T3"]),
        "audit_timestamp": datetime.now().isoformat()
    }

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: sev_order.get(x["priority"], 99))

    audit_payload = {
        "model_metadata": metadata,
        "dimensions": dimensions,
        "scoring": scoring,
        "scoring_parameters": {
            "alpha": alpha,
            "tier_weights": tw,
            "dimension_weights": dim_weights if dim_weights else "equal",
            "illustrative_target_aas": ILLUSTRATIVE_TARGET_AAS,
            "note": "All scoring parameters are documented design choices; see docs/METHODOLOGY.md for justification and sensitivity analysis.",
        },
        "evidence_coverage": coverage,
        "assessment_gaps": coverage["unanswered_questions"] + coverage["invalid_answers"],
        "compliance": {
            "eu_ai_act": {
                "tier": reg_tier,
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
            "total_questions": n_total,
            "answered_questions": n_answered,
            "unanswered_questions": len(coverage["unanswered_questions"]),
            "evidence_tier": evidence_tier,
            "confidence_weight": metadata["evidence_confidence_weight"],
            "assurance_level": coverage["assurance_level"],
            "findings_count": len(findings),
            "critical_findings": sum(1 for f in findings if f["priority"] == "CRITICAL"),
            "high_findings": sum(1 for f in findings if f["priority"] == "HIGH")
        },
        "audit_mode": "questionnaire",
        "aif360": fairness_metrics,
        "remediation_priority": counterfactual,
        "verified_evidence": verified_evidence or [],
        "attestation_gap": attestation_gap
    }

    audit_payload["model_card"] = generate_google_model_card(audit_payload)

    canonical_bytes = json.dumps(audit_payload, sort_keys=True, default=str).encode("utf-8")
    audit_payload["audit_hash"] = hashlib.sha256(canonical_bytes).hexdigest()
    audit_payload["sha256_hash"] = audit_payload["audit_hash"]

    return audit_payload
