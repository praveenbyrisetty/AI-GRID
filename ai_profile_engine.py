"""
AI-GRID Questionnaire-Based Audit Engine

Generates a complete 7-dimension trust audit from user-provided
questionnaire answers. Produces the same output format as the
MCP-based live audit so the dashboard works identically.
"""

from datetime import datetime
from typing import Any, Dict, List


# ======================================================================
# QUESTION DEFINITIONS
# Each question maps to one or more trust dimensions
# ======================================================================
QUESTIONS = [
    # --- Step 1: Model Identity ---
    {
        "id": "model_name",
        "step": 1,
        "step_title": "Model Identity",
        "label": "What is the name of your AI model/system?",
        "type": "text",
        "placeholder": "e.g., Customer Churn Predictor, Medical Imaging Classifier",
        "required": True,
        "dimension": None
    },
    {
        "id": "model_version",
        "step": 1,
        "step_title": "Model Identity",
        "label": "What is the current version?",
        "type": "text",
        "placeholder": "e.g., 1.0.0, 2.3.1",
        "required": True,
        "dimension": None
    },
    {
        "id": "domain",
        "step": 1,
        "step_title": "Model Identity",
        "label": "What domain does this AI operate in?",
        "type": "select",
        "options": [
            {"value": "healthcare", "label": "Healthcare / Medical"},
            {"value": "finance", "label": "Finance / Banking"},
            {"value": "agriculture", "label": "Agriculture / Environmental"},
            {"value": "education", "label": "Education / EdTech"},
            {"value": "autonomous_vehicles", "label": "Autonomous Vehicles / Robotics"},
            {"value": "criminal_justice", "label": "Criminal Justice / Law Enforcement"},
            {"value": "entertainment", "label": "Entertainment / Media"},
            {"value": "ecommerce", "label": "E-Commerce / Retail"},
            {"value": "manufacturing", "label": "Manufacturing / Industrial"},
            {"value": "cybersecurity", "label": "Cybersecurity / Threat Detection"},
            {"value": "other", "label": "Other"}
        ],
        "required": True,
        "dimension": None
    },
    {
        "id": "architecture",
        "step": 1,
        "step_title": "Model Identity",
        "label": "What is the model architecture?",
        "type": "text",
        "placeholder": "e.g., Transformer (GPT-4), CNN (ResNet-50), Random Forest, LSTM",
        "required": True,
        "dimension": None
    },
    {
        "id": "autonomy_level",
        "step": 1,
        "step_title": "Model Identity",
        "label": "What is the autonomy level of this AI?",
        "type": "select",
        "options": [
            {"value": "advisory", "label": "Advisory Only (human makes final decision)"},
            {"value": "semi_autonomous", "label": "Semi-Autonomous (AI acts, human can override)"},
            {"value": "fully_autonomous", "label": "Fully Autonomous (AI acts independently)"}
        ],
        "required": True,
        "dimension": "Accountability & Oversight"
    },

    # --- Step 2: Training Data ---
    {
        "id": "dataset_size",
        "step": 2,
        "step_title": "Training Data",
        "label": "How large is the training dataset? (number of samples)",
        "type": "number",
        "placeholder": "e.g., 10000",
        "required": True,
        "dimension": "Societal Impact"
    },
    {
        "id": "num_classes",
        "step": 2,
        "step_title": "Training Data",
        "label": "How many output classes/categories does the model have?",
        "type": "number",
        "placeholder": "e.g., 5",
        "required": True,
        "dimension": None
    },
    {
        "id": "class_balance",
        "step": 2,
        "step_title": "Training Data",
        "label": "How balanced is the class distribution in training data?",
        "type": "select",
        "options": [
            {"value": "balanced", "label": "Well-Balanced (all classes have similar sample counts)"},
            {"value": "moderate", "label": "Moderately Imbalanced (2:1 to 5:1 ratio)"},
            {"value": "severe", "label": "Severely Imbalanced (>5:1 ratio between classes)"}
        ],
        "required": True,
        "dimension": "Fairness & Bias"
    },
    {
        "id": "geographic_coverage",
        "step": 2,
        "step_title": "Training Data",
        "label": "What percentage of target demographics/regions does the training data cover?",
        "type": "select",
        "options": [
            {"value": "full", "label": "Full Coverage (>80% of target population represented)"},
            {"value": "partial", "label": "Partial Coverage (40%-80% represented)"},
            {"value": "limited", "label": "Limited Coverage (<40% represented)"}
        ],
        "required": True,
        "dimension": "Fairness & Bias"
    },
    {
        "id": "known_gaps",
        "step": 2,
        "step_title": "Training Data",
        "label": "Are there known demographic or geographic gaps in training data?",
        "type": "select",
        "options": [
            {"value": "none", "label": "No known gaps"},
            {"value": "minor", "label": "Minor gaps (1-2 underrepresented groups)"},
            {"value": "significant", "label": "Significant gaps (3+ underrepresented groups)"}
        ],
        "required": True,
        "dimension": "Fairness & Bias"
    },

    # --- Step 3: Safety & Reliability ---
    {
        "id": "input_validation",
        "step": 3,
        "step_title": "Safety & Reliability",
        "label": "Does the model validate and reject corrupted/malformed inputs?",
        "type": "select",
        "options": [
            {"value": "comprehensive", "label": "Yes — comprehensive input validation (quality, range, format checks)"},
            {"value": "basic", "label": "Partial — basic range/type checking only"},
            {"value": "none", "label": "No — model always attempts prediction on any input"}
        ],
        "required": True,
        "dimension": "Safety & Reliability"
    },
    {
        "id": "guardrail_count",
        "step": 3,
        "step_title": "Safety & Reliability",
        "label": "How many safety guardrails are implemented?",
        "type": "select",
        "options": [
            {"value": "3plus", "label": "3 or more guardrails (input validation, output clamping, anomaly detection, etc.)"},
            {"value": "1to2", "label": "1-2 guardrails"},
            {"value": "0", "label": "No guardrails implemented"}
        ],
        "required": True,
        "dimension": "Safety & Reliability"
    },
    {
        "id": "output_safety",
        "step": 3,
        "step_title": "Safety & Reliability",
        "label": "Does the model clamp or limit dangerous outputs (e.g., dosage limits, financial caps)?",
        "type": "select",
        "options": [
            {"value": "yes", "label": "Yes — outputs are clamped to safe ranges"},
            {"value": "partial", "label": "Partial — some outputs are limited"},
            {"value": "no", "label": "No — raw model outputs are returned directly"}
        ],
        "required": True,
        "dimension": "Safety & Reliability"
    },
    {
        "id": "env_advisory",
        "step": 3,
        "step_title": "Safety & Reliability",
        "label": "Does the system provide environmental or contextual safety advisories with predictions?",
        "type": "select",
        "options": [
            {"value": "yes", "label": "Yes — contextual safety warnings are included"},
            {"value": "no", "label": "No — predictions are returned without safety context"}
        ],
        "required": True,
        "dimension": "Societal Impact"
    },

    # --- Step 4: Transparency & Explainability ---
    {
        "id": "explainability_engine",
        "step": 4,
        "step_title": "Transparency & Explainability",
        "label": "Does the model have an explainability engine (SHAP, LIME, Grad-CAM, etc.)?",
        "type": "select",
        "options": [
            {"value": "full", "label": "Yes — full XAI engine (SHAP/LIME/Grad-CAM with feature attributions)"},
            {"value": "partial", "label": "Partial — feature importance list only (no local attributions)"},
            {"value": "none", "label": "No — model is a black box"}
        ],
        "required": True,
        "dimension": "Transparency"
    },
    {
        "id": "attribution_count",
        "step": 4,
        "step_title": "Transparency & Explainability",
        "label": "How many feature attributions are provided per prediction?",
        "type": "select",
        "options": [
            {"value": "4plus", "label": "4 or more features with importance scores"},
            {"value": "1to3", "label": "1-3 features"},
            {"value": "0", "label": "No feature attributions provided"}
        ],
        "required": True,
        "dimension": "Transparency"
    },
    {
        "id": "human_readable_reasoning",
        "step": 4,
        "step_title": "Transparency & Explainability",
        "label": "Does the model provide human-readable reasoning summaries?",
        "type": "select",
        "options": [
            {"value": "yes", "label": "Yes — natural language explanation of predictions"},
            {"value": "no", "label": "No — only raw scores/labels are returned"}
        ],
        "required": True,
        "dimension": "Transparency"
    },

    # --- Step 5: Privacy & Security ---
    {
        "id": "encryption_rest",
        "step": 5,
        "step_title": "Privacy & Security",
        "label": "Is stored data encrypted at rest?",
        "type": "select",
        "options": [
            {"value": "yes", "label": "Yes — AES-256 or equivalent encryption at rest"},
            {"value": "no", "label": "No — data is stored unencrypted"}
        ],
        "required": True,
        "dimension": "Privacy & Governance"
    },
    {
        "id": "encryption_transit",
        "step": 5,
        "step_title": "Privacy & Security",
        "label": "Is data encrypted in transit (TLS/HTTPS)?",
        "type": "select",
        "options": [
            {"value": "yes", "label": "Yes — TLS 1.2+ / HTTPS enforced"},
            {"value": "no", "label": "No — unencrypted transmission"}
        ],
        "required": True,
        "dimension": "Privacy & Governance"
    },
    {
        "id": "data_retention",
        "step": 5,
        "step_title": "Privacy & Security",
        "label": "What is the data retention period?",
        "type": "select",
        "options": [
            {"value": "short", "label": "Short (≤90 days)"},
            {"value": "medium", "label": "Medium (91-180 days)"},
            {"value": "long", "label": "Long (>180 days or indefinite)"}
        ],
        "required": True,
        "dimension": "Privacy & Governance"
    },
    {
        "id": "adversarial_tested",
        "step": 5,
        "step_title": "Privacy & Security",
        "label": "Has the model been tested against adversarial attacks (noise injection, prompt injection, etc.)?",
        "type": "select",
        "options": [
            {"value": "comprehensive", "label": "Yes — comprehensive adversarial testing performed"},
            {"value": "basic", "label": "Basic — limited adversarial testing done"},
            {"value": "none", "label": "No — no adversarial testing performed"}
        ],
        "required": True,
        "dimension": "Security & Robustness"
    },
    {
        "id": "drift_monitoring",
        "step": 5,
        "step_title": "Privacy & Security",
        "label": "Is model drift monitoring configured?",
        "type": "select",
        "options": [
            {"value": "yes", "label": "Yes — automated drift detection (KS-test, PSI, etc.)"},
            {"value": "manual", "label": "Manual — periodic manual review only"},
            {"value": "none", "label": "No — no drift monitoring"}
        ],
        "required": True,
        "dimension": "Security & Robustness"
    },

    # --- Step 6: Accountability & Societal Impact ---
    {
        "id": "human_oversight",
        "step": 6,
        "step_title": "Accountability & Impact",
        "label": "Is human oversight/review required before the AI's output is acted upon?",
        "type": "select",
        "options": [
            {"value": "mandatory", "label": "Yes — human-in-the-loop validation is mandatory"},
            {"value": "optional", "label": "Optional — human can review but isn't required"},
            {"value": "none", "label": "No — AI outputs are acted upon directly without human review"}
        ],
        "required": True,
        "dimension": "Accountability & Oversight"
    },
    {
        "id": "incident_escalation",
        "step": 6,
        "step_title": "Accountability & Impact",
        "label": "Is there a defined incident escalation protocol?",
        "type": "select",
        "options": [
            {"value": "yes", "label": "Yes — documented escalation procedures exist"},
            {"value": "no", "label": "No — no incident response protocol defined"}
        ],
        "required": True,
        "dimension": "Accountability & Oversight"
    },
    {
        "id": "societal_risk",
        "step": 6,
        "step_title": "Accountability & Impact",
        "label": "What is the potential societal risk if the model produces incorrect results?",
        "type": "select",
        "options": [
            {"value": "low", "label": "Low (inconvenience, minor financial impact)"},
            {"value": "medium", "label": "Medium (significant financial or operational impact)"},
            {"value": "high", "label": "High (physical harm, legal liability, or systemic discrimination)"}
        ],
        "required": True,
        "dimension": "Societal Impact"
    }
]


# ======================================================================
# DOMAIN LABELS (for display)
# ======================================================================
DOMAIN_LABELS = {
    "healthcare": "Healthcare / Medical",
    "finance": "Finance / Banking",
    "agriculture": "Agriculture / Environmental",
    "education": "Education / EdTech",
    "autonomous_vehicles": "Autonomous Vehicles / Robotics",
    "criminal_justice": "Criminal Justice / Law Enforcement",
    "entertainment": "Entertainment / Media",
    "ecommerce": "E-Commerce / Retail",
    "manufacturing": "Manufacturing / Industrial",
    "cybersecurity": "Cybersecurity / Threat Detection",
    "other": "General Purpose AI"
}


def get_questions() -> List[Dict[str, Any]]:
    """Returns the full question list for the frontend wizard."""
    return QUESTIONS


def generate_audit_from_questionnaire(answers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Takes user questionnaire answers and generates the full 7-dimension
    audit output. Produces the same data shape as AIGRIDMCPAuditor.run_live_audit().
    """
    logs: List[Dict[str, str]] = []
    findings: List[Dict[str, Any]] = []

    def log(stage: str, message: str, status: str = "INFO"):
        logs.append({"stage": stage, "message": message, "status": status})

    def finding(dimension: str, severity: str, issue: str, action: str):
        badge_map = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "info", "LOW": "info"}
        findings.append({
            "priority": severity,
            "badge": badge_map.get(severity, "info"),
            "dimension": dimension,
            "finding": issue,
            "action": action
        })

    # Extract answers with defaults
    model_name = answers.get("model_name", "Unnamed AI Model")
    model_version = answers.get("model_version", "1.0.0")
    domain = answers.get("domain", "other")
    architecture = answers.get("architecture", "Unknown Architecture")
    autonomy_level = answers.get("autonomy_level", "semi_autonomous")
    dataset_size = int(answers.get("dataset_size", 1000))
    num_classes = int(answers.get("num_classes", 2))
    class_balance = answers.get("class_balance", "moderate")
    geographic_coverage = answers.get("geographic_coverage", "partial")
    known_gaps = answers.get("known_gaps", "minor")
    input_validation = answers.get("input_validation", "basic")
    guardrail_count = answers.get("guardrail_count", "1to2")
    output_safety = answers.get("output_safety", "partial")
    env_advisory = answers.get("env_advisory", "no")
    explainability_engine = answers.get("explainability_engine", "partial")
    attribution_count = answers.get("attribution_count", "1to3")
    human_readable = answers.get("human_readable_reasoning", "no")
    encryption_rest = answers.get("encryption_rest", "no")
    encryption_transit = answers.get("encryption_transit", "yes")
    data_retention = answers.get("data_retention", "medium")
    adversarial_tested = answers.get("adversarial_tested", "none")
    drift_monitoring = answers.get("drift_monitoring", "none")
    human_oversight = answers.get("human_oversight", "none")
    incident_escalation = answers.get("incident_escalation", "no")
    societal_risk = answers.get("societal_risk", "medium")

    domain_label = DOMAIN_LABELS.get(domain, "General Purpose AI")

    # =============================================================
    # PHASE 1: DISCOVERY
    # =============================================================
    log("DISCOVERY", f"Analyzing questionnaire responses for AI system: '{model_name}'...", "INFO")
    log("DISCOVERY", f"Domain: {domain_label} | Architecture: {architecture} | Version: {model_version}", "SUCCESS")
    log("DISCOVERY", f"Audit mode: Questionnaire-Based Assessment (no MCP connection)", "INFO")

    # =============================================================
    # PHASE 2: METADATA CONSTRUCTION
    # =============================================================
    log("PROFILE", f"Constructing system profile from {len(answers)} questionnaire responses...", "INFO")

    metadata = {
        "model_name": model_name,
        "version": model_version,
        "model_hash": "questionnaire-based",
        "framework": architecture,
        "model_architecture": architecture,
        "training_dataset_size": dataset_size,
        "training_class_distribution": {f"Class_{i+1}": dataset_size // max(num_classes, 1) for i in range(num_classes)},
        "supported_classes": [f"Class_{i+1}" for i in range(num_classes)],
        "geographic_coverage": ["Covered Regions"] if geographic_coverage != "limited" else [],
        "geographic_gaps": {
            "none": [],
            "minor": ["Gap Region 1", "Gap Region 2"],
            "significant": ["Gap Region 1", "Gap Region 2", "Gap Region 3", "Gap Region 4"]
        }.get(known_gaps, []),
        "input_specifications": {
            "validation_level": input_validation,
            "guardrail_count": guardrail_count
        },
        "operational_boundaries": {"defined": input_validation != "none"},
        "data_retention_days": {"short": 90, "medium": 150, "long": 365}.get(data_retention, 150),
        "encryption_at_rest": encryption_rest == "yes",
        "encryption_in_transit": encryption_transit == "yes",
        "human_oversight_required": human_oversight == "mandatory",
        "incident_escalation_protocol": incident_escalation == "yes",
        "model_drift_monitoring": {
            "yes": "Automated drift detection (KS-test / PSI)",
            "manual": "Manual periodic review",
            "none": ""
        }.get(drift_monitoring, ""),
        "drift_status": "MONITORED" if drift_monitoring in ("yes", "manual") else "UNMONITORED",
        "domain": domain_label,
        "autonomy_level": autonomy_level,
        "audit_mode": "questionnaire",
        "audit_timestamp": datetime.now().isoformat()
    }

    log("PROFILE", f"Profile constructed: '{model_name}' v{model_version} ({architecture})", "SUCCESS")

    # =============================================================
    # PHASE 3: FAIRNESS & BIAS SCORING
    # =============================================================
    log("FAIRNESS", "Evaluating fairness & bias based on training data characteristics...", "INFO")
    fairness_score = 100.0

    # Geographic/demographic coverage
    coverage_penalties = {"full": 0, "partial": 20, "limited": 40}
    cov_penalty = coverage_penalties.get(geographic_coverage, 20)
    if cov_penalty > 0:
        fairness_score -= cov_penalty
        cov_label = {"partial": "40-80%", "limited": "<40%"}.get(geographic_coverage, "")
        log("FAIRNESS", f"FAIRNESS ISSUE: Demographic/geographic coverage is {cov_label}. High disparity risk for underrepresented groups.", "WARNING")
        finding("Fairness & Bias",
                "HIGH" if cov_penalty >= 30 else "MEDIUM",
                f"Training data covers only {cov_label} of target demographics/regions.",
                "Expand training data collection to include underrepresented demographics and geographic regions.")
    else:
        log("FAIRNESS", "Geographic/demographic coverage is comprehensive (>80%).", "SUCCESS")

    # Class imbalance
    balance_penalties = {"balanced": 0, "moderate": 8, "severe": 18}
    bal_penalty = balance_penalties.get(class_balance, 8)
    if bal_penalty > 0:
        fairness_score -= bal_penalty
        log("FAIRNESS", f"CLASS IMBALANCE: Training data has {'moderate' if class_balance == 'moderate' else 'severe'} class imbalance.", "WARNING")
        if class_balance == "severe":
            finding("Fairness & Bias", "HIGH",
                    "Severe class imbalance (>5:1 ratio) in training data.",
                    "Apply SMOTE oversampling, class weighting, or collect additional minority class samples.")
    else:
        log("FAIRNESS", "Class distribution is well-balanced across all categories.", "SUCCESS")

    # Known gaps
    gap_penalties = {"none": 0, "minor": 5, "significant": 12}
    gap_penalty = gap_penalties.get(known_gaps, 5)
    if gap_penalty > 0:
        fairness_score -= gap_penalty
        gap_count = 2 if known_gaps == "minor" else 4
        log("FAIRNESS", f"COVERAGE GAPS: {gap_count} known underrepresented groups identified.", "WARNING")

    fairness_score = round(max(10.0, min(100.0, fairness_score)), 1)

    # =============================================================
    # PHASE 4: SAFETY & RELIABILITY SCORING
    # =============================================================
    log("SAFETY", "Evaluating safety guardrails and reliability controls...", "INFO")
    safety_score = 100.0

    # Input validation
    validation_penalties = {"comprehensive": 0, "basic": 15, "none": 30}
    val_penalty = validation_penalties.get(input_validation, 15)
    if val_penalty > 0:
        safety_score -= val_penalty
        if input_validation == "none":
            log("SAFETY", "SAFETY FAIL: No input validation — model processes any input without rejection.", "DANGER")
            finding("Safety & Reliability", "CRITICAL",
                    "Model accepts all inputs without validation — corrupted/malicious data can cause incorrect outputs.",
                    "Implement comprehensive input validation: quality checks, range validators, format validation.")
        else:
            log("SAFETY", "SAFETY WARNING: Only basic input validation (range/type checking). Missing quality and anomaly detection.", "WARNING")
    else:
        log("SAFETY", "SAFETY PASS: Comprehensive input validation with quality, range, and format checks.", "SUCCESS")

    # Guardrail count
    guardrail_penalties = {"3plus": 0, "1to2": 10, "0": 30}
    guard_penalty = guardrail_penalties.get(guardrail_count, 10)
    if guard_penalty > 0:
        safety_score -= guard_penalty
        if guardrail_count == "0":
            log("SAFETY", "SAFETY FAIL: Zero safety guardrails implemented!", "DANGER")
            finding("Safety & Reliability", "CRITICAL",
                    "No safety guardrails are in place to prevent harmful outputs.",
                    "Implement at least 3 guardrails: input validation, output clamping, and anomaly detection.")
        else:
            log("SAFETY", "SAFETY WARNING: Only 1-2 guardrails. Recommend adding anomaly detection and output clamping.", "WARNING")
    else:
        log("SAFETY", "SAFETY PASS: 3+ guardrails active (input validation, output clamping, anomaly detection).", "SUCCESS")

    # Output safety clamping
    output_penalties = {"yes": 0, "partial": 8, "no": 18}
    out_penalty = output_penalties.get(output_safety, 8)
    if out_penalty > 0:
        safety_score -= out_penalty
        if output_safety == "no":
            log("SAFETY", "SAFETY WARNING: Raw model outputs returned without safety clamping.", "WARNING")
            finding("Safety & Reliability", "HIGH",
                    "Model outputs are not clamped to safe ranges — risk of dangerous recommendations.",
                    "Implement output safety bounds to prevent extreme/harmful predictions.")
        else:
            log("SAFETY", "SAFETY NOTE: Partial output clamping — some outputs lack safety bounds.", "INFO")
    else:
        log("SAFETY", "SAFETY PASS: Output clamping enforces safe ranges on all predictions.", "SUCCESS")

    safety_score = round(max(10.0, min(100.0, safety_score)), 1)

    # =============================================================
    # PHASE 5: TRANSPARENCY & EXPLAINABILITY SCORING
    # =============================================================
    log("TRANSPARENCY", "Evaluating explainability and transparency capabilities...", "INFO")
    transparency_score = 100.0

    # Explainability engine
    xai_penalties = {"full": 0, "partial": 20, "none": 45}
    xai_penalty = xai_penalties.get(explainability_engine, 20)
    if xai_penalty > 0:
        transparency_score -= xai_penalty
        if explainability_engine == "none":
            log("TRANSPARENCY", "TRANSPARENCY FAIL: Model is a complete black box — no explainability engine.", "DANGER")
            finding("Transparency", "CRITICAL",
                    "No explainability engine implemented — predictions cannot be interpreted or audited.",
                    "Implement TreeSHAP, LIME, or Grad-CAM to provide local feature attributions per prediction.")
        else:
            log("TRANSPARENCY", "TRANSPARENCY WARNING: Only basic feature importance — no local attributions per prediction.", "WARNING")
    else:
        log("TRANSPARENCY", f"TRANSPARENCY PASS: Full XAI engine active with feature attributions.", "SUCCESS")

    # Attribution count
    attr_penalties = {"4plus": 0, "1to3": 10, "0": 30}
    attr_penalty = attr_penalties.get(attribution_count, 10)
    if attr_penalty > 0:
        transparency_score -= attr_penalty
        if attribution_count == "0":
            log("TRANSPARENCY", "TRANSPARENCY FAIL: No feature attributions provided for predictions.", "DANGER")
        else:
            log("TRANSPARENCY", "TRANSPARENCY NOTE: Limited feature attributions (1-3 features). Recommend 4+ for full interpretability.", "WARNING")
    else:
        log("TRANSPARENCY", "Feature attributions: 4+ features with importance scores per prediction.", "SUCCESS")

    # Human-readable reasoning
    if human_readable != "yes":
        transparency_score -= 10
        log("TRANSPARENCY", "TRANSPARENCY GAP: No human-readable reasoning summaries provided with predictions.", "WARNING")
    else:
        log("TRANSPARENCY", "Human-readable reasoning summaries: PRESENT.", "SUCCESS")

    transparency_score = round(max(10.0, min(100.0, transparency_score)), 1)

    # =============================================================
    # PHASE 6: PRIVACY & DATA GOVERNANCE SCORING
    # =============================================================
    log("PRIVACY", "Auditing data storage policies, encryption, and retention...", "INFO")
    privacy_score = 100.0

    # Encryption at rest
    if encryption_rest != "yes":
        privacy_score -= 30
        log("PRIVACY", "PRIVACY VULNERABILITY: Data stored UNENCRYPTED at rest.", "WARNING")
        finding("Privacy & Governance", "HIGH",
                "Stored data (training data, user inputs, model outputs) is not encrypted at rest.",
                "Enable AES-256 encryption at rest and implement key rotation policy.")
    else:
        log("PRIVACY", "Data encryption at rest: ENABLED.", "SUCCESS")

    # Encryption in transit
    if encryption_transit != "yes":
        privacy_score -= 20
        log("PRIVACY", "PRIVACY VULNERABILITY: Data transmitted without encryption (no TLS).", "DANGER")
        finding("Privacy & Governance", "CRITICAL",
                "Data is transmitted without encryption — vulnerable to interception.",
                "Enforce TLS 1.2+ for all data in transit. Implement HTTPS everywhere.")
    else:
        log("PRIVACY", "Data encryption in transit (TLS): ENABLED.", "SUCCESS")

    # Data retention
    retention_penalties = {"short": 0, "medium": 5, "long": 15}
    ret_penalty = retention_penalties.get(data_retention, 5)
    retention_days = {"short": 90, "medium": 150, "long": 365}.get(data_retention, 150)
    if ret_penalty > 0:
        privacy_score -= ret_penalty
        if data_retention == "long":
            log("PRIVACY", f"DATA GOVERNANCE ISSUE: Retention period is {retention_days} days — exceeds recommended 90-day limit.", "WARNING")
            finding("Privacy & Governance", "MEDIUM",
                    f"Data retention period is {retention_days} days — exceeds recommended 90-day maximum.",
                    "Shorten data retention to 90 days or implement explicit user re-consent workflow.")
        else:
            log("PRIVACY", f"Data retention: {retention_days} days (borderline — consider reducing).", "INFO")
    else:
        log("PRIVACY", f"Data retention: {retention_days} days (within recommended limits).", "SUCCESS")

    privacy_score = round(max(10.0, min(100.0, privacy_score)), 1)

    # =============================================================
    # PHASE 7: ACCOUNTABILITY & HUMAN OVERSIGHT SCORING
    # =============================================================
    log("ACCOUNTABILITY", "Inspecting human-in-the-loop controls and escalation protocols...", "INFO")
    accountability_score = 100.0

    # Human oversight
    oversight_penalties = {"mandatory": 0, "optional": 20, "none": 45}
    oversight_penalty = oversight_penalties.get(human_oversight, 20)
    if oversight_penalty > 0:
        accountability_score -= oversight_penalty
        if human_oversight == "none":
            log("ACCOUNTABILITY", "ACCOUNTABILITY BOTTLENECK: AI outputs are acted upon directly without any human review!", "DANGER")
            finding("Accountability & Oversight", "CRITICAL",
                    "Direct automated output delivery without human-in-the-loop validation.",
                    "Implement mandatory human review for high-risk predictions before they are acted upon.")
        else:
            log("ACCOUNTABILITY", "ACCOUNTABILITY WARNING: Human oversight is optional — not mandatory for high-risk outputs.", "WARNING")
            finding("Accountability & Oversight", "MEDIUM",
                    "Human oversight is available but not mandatory for high-risk predictions.",
                    "Make human review mandatory for outputs exceeding defined risk thresholds.")
    else:
        log("ACCOUNTABILITY", "Human oversight: MANDATORY — human-in-the-loop validation required.", "SUCCESS")

    # Incident escalation
    if incident_escalation != "yes":
        accountability_score -= 20
        log("ACCOUNTABILITY", "ACCOUNTABILITY GAP: No incident escalation protocol defined.", "WARNING")
        finding("Accountability & Oversight", "HIGH",
                "No documented incident response or escalation protocol exists.",
                "Define and document incident escalation procedures with clear ownership and response times.")
    else:
        log("ACCOUNTABILITY", "Incident escalation protocol: DEFINED.", "SUCCESS")

    # Autonomy level impact
    if autonomy_level == "fully_autonomous" and human_oversight != "mandatory":
        accountability_score -= 10
        log("ACCOUNTABILITY", "ACCOUNTABILITY CONCERN: Fully autonomous system without mandatory human oversight.", "WARNING")

    accountability_score = round(max(10.0, min(100.0, accountability_score)), 1)

    # =============================================================
    # PHASE 8: SECURITY & ROBUSTNESS SCORING
    # =============================================================
    log("SECURITY", "Evaluating adversarial robustness and security posture...", "INFO")
    security_score = 100.0

    # Adversarial testing
    adv_penalties = {"comprehensive": 0, "basic": 15, "none": 30}
    adv_penalty = adv_penalties.get(adversarial_tested, 15)
    if adv_penalty > 0:
        security_score -= adv_penalty
        if adversarial_tested == "none":
            log("SECURITY", "SECURITY WARNING: No adversarial robustness testing has been performed.", "WARNING")
            finding("Security & Robustness", "HIGH",
                    "Model has not been tested against adversarial attacks (noise injection, evasion, prompt injection).",
                    "Conduct comprehensive adversarial testing: Gaussian noise injection, FGSM attacks, boundary probing.")
        else:
            log("SECURITY", "SECURITY NOTE: Only basic adversarial testing performed. Recommend comprehensive testing.", "WARNING")
    else:
        log("SECURITY", "SECURITY PASS: Comprehensive adversarial robustness testing completed.", "SUCCESS")

    # Drift monitoring
    drift_penalties = {"yes": 0, "manual": 5, "none": 15}
    drift_penalty = drift_penalties.get(drift_monitoring, 5)
    if drift_penalty > 0:
        security_score -= drift_penalty
        if drift_monitoring == "none":
            log("SECURITY", "SECURITY GAP: No model drift monitoring configured.", "WARNING")
            finding("Security & Robustness", "MEDIUM",
                    "No model drift monitoring — model may silently degrade over time.",
                    "Implement automated drift detection using KS-test, PSI, or similar statistical methods.")
        else:
            log("SECURITY", f"Model drift monitoring: Manual periodic review (consider automating).", "INFO")
    else:
        log("SECURITY", f"Model drift monitoring: Automated ({metadata.get('model_drift_monitoring', 'Active')}).", "SUCCESS")

    security_score = round(max(10.0, min(100.0, security_score)), 1)

    # =============================================================
    # PHASE 9: SOCIETAL & ENVIRONMENTAL IMPACT SCORING
    # =============================================================
    log("SOCIETAL", "Auditing societal impact and environmental considerations...", "INFO")
    societal_score = 100.0

    # Environmental advisory
    if env_advisory != "yes":
        societal_score -= 15
        log("SOCIETAL", "SOCIETAL GAP: No environmental or contextual safety advisories in predictions.", "WARNING")
    else:
        log("SOCIETAL", "SOCIETAL PASS: Environmental/contextual safety advisories integrated into predictions.", "SUCCESS")

    # Dataset size adequacy
    if dataset_size < 2000:
        societal_score -= 25
        log("SOCIETAL", f"SOCIETAL CONCERN: Training dataset ({dataset_size} samples) may be too small for reliable deployment.", "WARNING")
        finding("Societal Impact", "HIGH",
                f"Training dataset of {dataset_size} samples may be insufficient for production deployment.",
                f"Expand training dataset to at least 5,000 samples for reliable predictions.")
    elif dataset_size < 5000:
        societal_score -= 8
        log("SOCIETAL", f"Training dataset: {dataset_size} samples — adequate but would benefit from expansion.", "INFO")
    else:
        log("SOCIETAL", f"Training dataset: {dataset_size:,} samples — sufficient for deployment.", "SUCCESS")

    # Coverage gaps vs coverage (societal exclusion risk)
    geo_gaps = metadata.get("geographic_gaps", [])
    geo_coverage = metadata.get("geographic_coverage", [])
    if len(geo_gaps) > len(geo_coverage):
        societal_score -= 12
        log("SOCIETAL", f"SOCIETAL CONCERN: {len(geo_gaps)} underserved groups vs {len(geo_coverage)} covered — risk of excluding vulnerable populations.", "WARNING")

    # Societal risk level
    if societal_risk == "high":
        societal_score -= 10
        log("SOCIETAL", "HIGH SOCIETAL RISK: Incorrect predictions could cause physical harm, legal liability, or discrimination.", "WARNING")
        finding("Societal Impact", "HIGH",
                "High potential societal harm from incorrect model outputs (physical harm, legal liability, or discrimination).",
                "Implement mandatory human review, additional safety checks, and comprehensive monitoring for high-risk predictions.")
    elif societal_risk == "medium":
        societal_score -= 3
        log("SOCIETAL", "MODERATE SOCIETAL RISK: Incorrect predictions could cause significant financial or operational impact.", "INFO")

    societal_score = round(max(10.0, min(100.0, societal_score)), 1)

    # =============================================================
    # COMPOSE 7 DIMENSION SCORES
    # =============================================================
    dimensions = {
        "Fairness & Bias": fairness_score,
        "Transparency": transparency_score,
        "Safety & Reliability": safety_score,
        "Privacy & Governance": privacy_score,
        "Accountability & Oversight": accountability_score,
        "Security & Robustness": security_score,
        "Societal Impact": societal_score
    }

    # =============================================================
    # ALGORITHM 2: BOTTLENECK COMPOSITE TRUST SCORE (AAS)
    # =============================================================
    dim_values = list(dimensions.values())
    weighted_average = sum(dim_values) / len(dim_values)
    bottleneck_score = min(dim_values)
    bottleneck_dimension = [k for k, v in dimensions.items() if v == bottleneck_score][0]

    alpha = 0.6
    aas = round((alpha * weighted_average) + ((1.0 - alpha) * bottleneck_score), 1)

    # Letter Grade
    if aas >= 90:
        grade = "A+"
    elif aas >= 80:
        grade = "A"
    elif aas >= 70:
        grade = "B"
    elif aas >= 60:
        grade = "C"
    elif aas >= 50:
        grade = "D"
    else:
        grade = "F"

    # =============================================================
    # ALGORITHM 3: EU AI ACT RISK CLASSIFICATION
    # =============================================================
    if aas >= 76:
        eu_tier = "MINIMAL RISK"
        eu_color = "emerald"
        eu_desc = "Unregulated or low regulatory burden under EU AI Act."
    elif aas >= 51:
        eu_tier = "LIMITED RISK"
        eu_color = "amber"
        eu_desc = "Transparency obligations apply (must disclose AI nature and confidence)."
    elif aas >= 26:
        eu_tier = "HIGH RISK"
        eu_color = "orange"
        eu_desc = "Strict regulatory requirements: Conformity assessment, risk management & human oversight required."
    else:
        eu_tier = "UNACCEPTABLE RISK"
        eu_color = "rose"
        eu_desc = "Prohibited from deployment under EU AI Act Article 5."

    # =============================================================
    # ALGORITHM 4: NIST AI RMF 4-FUNCTION MAPPING
    # =============================================================
    def nist_status(val: float) -> Dict[str, Any]:
        if val >= 70:
            return {"score": round(val, 1), "status": "COMPLIANT", "badge": "success"}
        elif val >= 45:
            return {"score": round(val, 1), "status": "PARTIALLY COMPLIANT", "badge": "warning"}
        return {"score": round(val, 1), "status": "NON-COMPLIANT", "badge": "danger"}

    nist_rmf = {
        "GOVERN": nist_status((dimensions["Accountability & Oversight"] + dimensions["Privacy & Governance"]) / 2),
        "MAP": nist_status((dimensions["Societal Impact"] + dimensions["Fairness & Bias"]) / 2),
        "MEASURE": nist_status((dimensions["Fairness & Bias"] + dimensions["Transparency"] + dimensions["Safety & Reliability"]) / 3),
        "MANAGE": nist_status((dimensions["Security & Robustness"] + dimensions["Safety & Reliability"]) / 2)
    }

    # Sort findings by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["priority"], 99))

    log("COMPLETE", f"Questionnaire-based audit complete. AAS: {aas}/100 (Grade: {grade})", "SUCCESS")

    return {
        "model_metadata": metadata,
        "dimensions": dimensions,
        "scoring": {
            "aas_score": aas,
            "weighted_average": round(weighted_average, 1),
            "bottleneck_score": round(bottleneck_score, 1),
            "bottleneck_dimension": bottleneck_dimension,
            "trust_grade": grade
        },
        "compliance": {
            "eu_ai_act": {
                "tier": eu_tier,
                "color": eu_color,
                "description": eu_desc
            },
            "nist_ai_rmf": nist_rmf
        },
        "remediation_plan": findings,
        "audit_logs": logs,
        "probe_summary": {
            "total_probes": 7,
            "mcp_tools_called": 0,
            "guardrails_tested": 3 if guardrail_count == "3plus" else (2 if guardrail_count == "1to2" else 0),
            "adversarial_tests": 1 if adversarial_tested != "none" else 0,
            "findings_count": len(findings)
        },
        "audit_mode": "questionnaire"
    }
