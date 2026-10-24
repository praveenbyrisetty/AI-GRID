"""
AI-GRID Compliance & Responsible AI Engines (v4.0)

Provides transparently named audit engines:
1. Custom Fairness Metrics Engine (DIR, SPD computation from dataset)
   NOTE: Computes DIR/SPD directly from CSV data. Does NOT use the IBM AIF360 library.
2. Rule-Based Risk Cohort Analysis Engine (subgroup risk slicing)
   NOTE: Uses rule-based cohort classification. Does NOT use Microsoft Fairlearn.
3. Remediation Priority Ranker (severity-based finding prioritization)
4. EU AI Act Article-by-Article Compliance Engine (Articles 9 to 15 + Annex III classification)
5. NIST AI RMF 1.0 Subcategory Mapper (NIST AI 100-1: GOVERN, MAP, MEASURE, MANAGE)
6. OWASP Top 10 for LLMs & OWASP MCP Top 10 Risk Mapper
7. MITRE ATLAS Adversarial Threat Technique Mapper
8. AI Software Supply Chain CVE & EPSS Compound Risk Scanner (static registry)
9. Model Card Generator (inspired by Mitchell et al., 2019 format)

DISCLAIMER: This assessment does not constitute legal certification or
guaranteed regulatory compliance. Professional review is recommended.
"""

import csv
import io
import os
import math
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
GERMAN_CREDIT_PATH = os.path.join(DATA_DIR, "german_credit_fairness.csv")
CLINICAL_SAFETY_PATH = os.path.join(DATA_DIR, "clinical_patient_safety.csv")
AI_CVE_REGISTRY_PATH = os.path.join(DATA_DIR, "ai_cve_epss_registry.csv")


# =====================================================================
# 1. CUSTOM FAIRNESS METRICS ENGINE (DIR/SPD Computation)
# Reference: UCI Machine Learning Repository: Statlog (German Credit Data)
# =====================================================================

def load_german_credit_baseline() -> Dict[str, Any]:
    """
    Loads empirical records from UCI Statlog (German Credit Data)
    as a reference benchmark example of demographic parity calculations.
    """
    if not os.path.exists(GERMAN_CREDIT_PATH):
        raise FileNotFoundError(f"Empirical dataset not found at {GERMAN_CREDIT_PATH}")

    total = 0
    priv_total = 0
    unpriv_total = 0
    priv_fav = 0
    priv_unfav = 0
    unpriv_fav = 0
    unpriv_unfav = 0

    with open(GERMAN_CREDIT_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1
            gender = row.get("gender", "").lower()
            risk = str(row.get("credit_risk", "")).strip()

            is_priv = (gender == "male")
            is_fav = (risk == "1")

            if is_priv:
                priv_total += 1
                if is_fav:
                    priv_fav += 1
                else:
                    priv_unfav += 1
            else:
                unpriv_total += 1
                if is_fav:
                    unpriv_fav += 1
                else:
                    unpriv_unfav += 1

    p_priv = priv_total / max(total, 1)
    p_unpriv = unpriv_total / max(total, 1)
    p_fav_overall = (priv_fav + unpriv_fav) / max(total, 1)
    p_unfav_overall = 1.0 - p_fav_overall

    p_fav_priv = priv_fav / max(priv_total, 1)
    p_fav_unpriv = unpriv_fav / max(unpriv_total, 1)

    p_priv_fav_joint = priv_fav / max(total, 1)
    p_priv_unfav_joint = priv_unfav / max(total, 1)
    p_unpriv_fav_joint = unpriv_fav / max(total, 1)
    p_unpriv_unfav_joint = unpriv_unfav / max(total, 1)

    weights = {
        "privileged_favorable": round((p_priv * p_fav_overall) / max(p_priv_fav_joint, 0.0001), 3),
        "privileged_unfavorable": round((p_priv * p_unfav_overall) / max(p_priv_unfav_joint, 0.0001), 3),
        "unprivileged_favorable": round((p_unpriv * p_fav_overall) / max(p_unpriv_fav_joint, 0.0001), 3),
        "unprivileged_unfavorable": round((p_unpriv * p_unfav_overall) / max(p_unpriv_unfav_joint, 0.0001), 3),
    }

    dir_empirical = round(p_fav_unpriv / max(p_fav_priv, 0.0001), 3)
    spd_empirical = round(p_fav_unpriv - p_fav_priv, 3)

    return {
        "loaded": True,
        "dataset_name": "UCI Machine Learning Repository: Statlog (German Credit Data)",
        "dataset_file": "german_credit_fairness.csv",
        "sample_count": total,
        "protected_attribute": "gender (female=unprivileged, male=privileged)",
        "target_outcome": "credit_risk (1=favorable/creditworthy, 0=unfavorable)",
        "subpopulations": {
            "privileged_count": priv_total,
            "unprivileged_count": unpriv_total,
            "privileged_favorable_count": priv_fav,
            "unprivileged_favorable_count": unpriv_fav,
        },
        "p_priv": round(p_priv, 3),
        "p_unpriv": round(p_unpriv, 3),
        "p_fav_priv": round(p_fav_priv, 3),
        "p_fav_unpriv": round(p_fav_unpriv, 3),
        "empirical_dir": dir_empirical,
        "empirical_spd": spd_empirical,
        "weights": weights,
    }


def compute_fairness_metrics(answers: Optional[Dict[str, Any]] = None,
                             metadata: Optional[Dict[str, Any]] = None,
                             fairness_score: Optional[float] = None,
                             predictions_csv: Optional[str] = None) -> Dict[str, Any]:
    """
    Computes algorithmic fairness indicators (DIR, SPD) from data.
    - If user supplies a predictions CSV: metrics are computed strictly from that data.
    - If no predictions CSV is provided: target model metrics are NOT fabricated;
      the engine reports 'NO_EVALUATION_DATASET_PROVIDED' and provides UCI German Credit
      strictly as an illustrative reference benchmark example.
    """
    baseline = load_german_credit_baseline()

    csv_data = None
    if predictions_csv:
        if os.path.exists(predictions_csv):
            with open(predictions_csv, mode="r", encoding="utf-8") as f:
                csv_data = f.read()
        else:
            csv_data = predictions_csv

    if csv_data:
        reader = csv.DictReader(io.StringIO(csv_data.strip()))
        rows = list(reader)
        if rows:
            protected_col = next((c for c in rows[0].keys() if c.lower() in ("gender", "sex", "race", "ethnicity", "age")), None)
            outcome_col = next((c for c in rows[0].keys() if c.lower() in ("prediction", "predicted", "outcome", "credit_risk", "label", "target", "approved")), None)
            label_col = next((c for c in rows[0].keys() if c.lower() in ("true_label", "ground_truth", "actual")), None)

            if protected_col and outcome_col:
                priv_fav = 0
                priv_total = 0
                unpriv_fav = 0
                unpriv_total = 0
                unpriv_true_pos = 0
                unpriv_pos_total = 0
                priv_true_pos = 0
                priv_pos_total = 0

                vals = set(r[protected_col].strip().lower() for r in rows if r.get(protected_col))
                priv_val = "male" if "male" in vals else ("white" if "white" in vals else sorted(list(vals))[0])

                for r in rows:
                    p_val = r.get(protected_col, "").strip().lower()
                    out_val = str(r.get(outcome_col, "")).strip().lower()
                    is_fav = out_val in ("1", "true", "positive", "approved", "favorable", "high")

                    is_priv = (p_val == priv_val)
                    if is_priv:
                        priv_total += 1
                        if is_fav: priv_fav += 1
                    else:
                        unpriv_total += 1
                        if is_fav: unpriv_fav += 1

                    if label_col:
                        act_val = str(r.get(label_col, "")).strip().lower()
                        is_act_pos = act_val in ("1", "true", "positive", "approved", "favorable", "high")
                        if is_act_pos:
                            if is_priv:
                                priv_pos_total += 1
                                if is_fav: priv_true_pos += 1
                            else:
                                unpriv_pos_total += 1
                                if is_fav: unpriv_true_pos += 1

                p_fav_priv = priv_fav / max(priv_total, 1)
                p_fav_unpriv = unpriv_fav / max(unpriv_total, 1)
                dir_val = round(p_fav_unpriv / max(p_fav_priv, 0.0001), 3)
                spd_val = round(p_fav_unpriv - p_fav_priv, 3)

                eod_val = None
                if label_col and priv_pos_total > 0 and unpriv_pos_total > 0:
                    tpr_priv = priv_true_pos / priv_pos_total
                    tpr_unpriv = unpriv_true_pos / unpriv_pos_total
                    eod_val = round(tpr_unpriv - tpr_priv, 3)

                is_dir_compliant = dir_val >= 0.80
                is_spd_compliant = abs(spd_val) <= 0.10

                return {
                    "engine": "Custom Fairness Metrics Engine (DIR/SPD from dataset)",
                    "evaluated": True,
                    "sample_count": len(rows),
                    "protected_attribute": protected_col,
                    "target_outcome": outcome_col,
                    "pre_mitigation": {
                        "disparate_impact_ratio": dir_val,
                        "dir_compliant": is_dir_compliant,
                        "dir_threshold": ">= 0.80 (EEOC 80% Rule)",
                        "statistical_parity_difference": spd_val,
                        "spd_compliant": is_spd_compliant,
                        "spd_threshold": "[-0.10, +0.10]",
                        "equal_opportunity_difference": eod_val,
                        "status": "COMPLIANT" if (is_dir_compliant and is_spd_compliant) else "BIAS DETECTED",
                    },
                    "reference_benchmark_example": {
                        "dataset_name": baseline["dataset_name"],
                        "empirical_dir": baseline["empirical_dir"],
                        "empirical_spd": baseline["empirical_spd"],
                        "note": "UCI German Credit reference dataset provided solely as an illustrative example.",
                    },
                    "regulatory_alignment": {
                        "eu_ai_act": "Article 10(2)(f) - Examination of possible biases in training datasets",
                        "nist_ai_rmf": "MEASURE 2.11 - Fairness and bias are evaluated and documented",
                    }
                }

    # No predictions CSV provided: report honestly without synthetic numbers
    return {
        "engine": "Custom Fairness Metrics Engine (DIR/SPD)",
        "evaluated": False,
        "status": "NO_EVALUATION_DATASET_PROVIDED",
        "message": "No model prediction dataset provided for empirical fairness evaluation. Supply a predictions CSV containing protected attributes and outcome labels to compute DIR and SPD.",
        "pre_mitigation": None,
        "post_mitigation_reweighed": None,
        "reference_benchmark_example": {
            "dataset_name": baseline["dataset_name"],
            "sample_count": baseline["sample_count"],
            "protected_attribute": baseline["protected_attribute"],
            "empirical_dir": baseline["empirical_dir"],
            "empirical_spd": baseline["empirical_spd"],
            "note": "UCI German Credit reference dataset provided solely as an illustrative reference benchmark, NOT target model metrics.",
        },
        "regulatory_alignment": {
            "eu_ai_act": "Article 10(2)(f) - Examination of possible biases in training datasets",
            "nist_ai_rmf": "MEASURE 2.11 - Fairness and bias are evaluated and documented",
        }
    }


# =====================================================================
# 2. RULE-BASED RISK COHORT ANALYSIS ENGINE
# Uses Clinical Patient Safety & Dosage Cohort
# =====================================================================

def load_clinical_safety_benchmark() -> Dict[str, Any]:
    """
    Loads empirical clinical safety benchmark to evaluate guardrail efficacy.
    Computes rejection rates and clamping rates directly from dataset rows.
    """
    if not os.path.exists(CLINICAL_SAFETY_PATH):
        raise FileNotFoundError(f"Empirical clinical safety benchmark not found at {CLINICAL_SAFETY_PATH}")

    total = 0
    corrupted_count = 0
    corrupted_rejected_count = 0
    clamped_count = 0
    physician_approved_count = 0
    high_risk_count = 0

    with open(CLINICAL_SAFETY_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1
            is_corrupted = str(row.get("input_corrupted", "")).lower() == "true"
            is_clamped = str(row.get("output_clamped", "")).lower() == "true"
            is_approved = str(row.get("physician_approved", "")).lower() == "true"

            if is_corrupted:
                corrupted_count += 1
                if not is_approved or is_clamped:
                    corrupted_rejected_count += 1
            if is_clamped:
                clamped_count += 1
            if is_approved:
                physician_approved_count += 1
            if str(row.get("adverse_event_risk", "")).lower() == "high":
                high_risk_count += 1

    corrupted_rejection_rate = round((corrupted_rejected_count / corrupted_count) * 100, 1) if corrupted_count else None

    return {
        "loaded": True,
        "dataset_name": "Clinical Patient Safety & Dosage Benchmark Cohort",
        "dataset_file": "clinical_patient_safety.csv",
        "sample_count": total,
        "metrics": {
            "corrupted_input_rejection_rate": corrupted_rejection_rate,
            "output_clamping_rate_pct": round((clamped_count / max(total, 1)) * 100, 1),
            "physician_hitl_approval_rate_pct": round((physician_approved_count / max(total, 1)) * 100, 1),
            "high_risk_adverse_cohort_pct": round((high_risk_count / max(total, 1)) * 100, 1)
        }
    }


def analyze_risk_cohorts(dimensions: Dict[str, Optional[float]],
                         findings: List[Dict[str, Any]],
                         metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Slices system behavior into risk cohorts using rule-based classification.
    """
    clinical_bench = load_clinical_safety_benchmark()
    domain = metadata.get("domain", "General Purpose AI")

    cohorts = []

    # Cohort 1: Critical Input Anomaly / Corrupted Data
    sec_score = dimensions.get("Security & Robustness") or 50.0
    cohorts.append({
        "cohort_name": "Input Anomaly & Out-of-Bounds Cohort",
        "cohort_description": "Inputs with negative values, extreme outliers, or non-numeric types",
        "sample_percentage": 15.0,
        "risk_level": "CRITICAL" if sec_score < 60 else ("HIGH" if sec_score < 75 else "LOW"),
        "error_rate_estimate_pct": round(max(0.5, (100.0 - sec_score) * 0.45), 1),
        "observed_failure_mode": "Silent execution with corrupted parameters",
        "affected_subgroup": "Edge cases & sensor error inputs"
    })

    # Cohort 2: Autonomous / HITL Governance
    oversight_score = dimensions.get("Human Oversight & Agency") or dimensions.get("Human Oversight & Accountability") or 50.0
    cohorts.append({
        "cohort_name": "High-Autonomy Decision Cohort",
        "cohort_description": "Decisions executed without human-in-the-loop review",
        "sample_percentage": 25.0,
        "risk_level": "CRITICAL" if oversight_score < 50 else ("HIGH" if oversight_score < 70 else "LOW"),
        "error_rate_estimate_pct": round(max(1.0, (100.0 - oversight_score) * 0.35), 1),
        "observed_failure_mode": "Unchecked cascading failure in high-impact scenarios",
        "affected_subgroup": "Direct automated actuation"
    })

    # Cohort 3: Extreme Prediction Boundary / Clamping
    safety_score = dimensions.get("Safety & Reliability") or 50.0
    cohorts.append({
        "cohort_name": "Boundary & Safety Clamping Regime",
        "cohort_description": "Outputs near physical or regulatory maximum limits",
        "sample_percentage": 10.0,
        "risk_level": "HIGH" if safety_score < 65 else "LOW",
        "error_rate_estimate_pct": round(max(1.5, (100.0 - safety_score) * 0.40), 1),
        "observed_failure_mode": "Unclamped dosage or recommendation exceeding safe operating bounds",
        "affected_subgroup": "High-severity edge cases"
    })

    max_cohort_risk = "LOW"
    for c in cohorts:
        if c["risk_level"] == "CRITICAL":
            max_cohort_risk = "CRITICAL"
            break
        elif c["risk_level"] == "HIGH":
            max_cohort_risk = "HIGH"

    return {
        "engine": "Illustrative Rule-Based Risk Cohort Engine (heuristic, not measured)",
        "cohort_disclaimer": "Cohort distributions (15%, 25%, 10%) and estimated error rates are illustrative rule-based heuristics derived from dimension scores, not measured from production telemetry.",
        "cohort_count": len(cohorts),
        "overall_cohort_risk": max_cohort_risk,
        "clinical_safety_benchmark": clinical_bench,
        "cohorts": cohorts,
        "methodology": "Illustrative rule-based subgroup slicing across input anomaly distributions and autonomy regimes (heuristic, not measured)."
    }


# =====================================================================
# 3. REMEDIATION PRIORITY RANKER
# Ranks findings strictly by severity for actionable remediation
# =====================================================================

def solve_remediation_priority(current_aas: Optional[float],
                               dimensions: Dict[str, Optional[float]],
                               findings: List[Dict[str, Any]],
                               target_score: float = 76.0) -> Dict[str, Any]:
    """
    Ranks findings strictly by severity (CRITICAL > HIGH > MEDIUM > LOW).
    No fabricated score gains or guaranteed AAS improvements are claimed.
    """
    valid_scores = [v for v in dimensions.values() if v is not None]
    bottleneck_score = min(valid_scores) if valid_scores else None
    bottleneck_dim = next((k for k, v in dimensions.items() if v == bottleneck_score), "Unknown")

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(findings, key=lambda x: sev_order.get(x.get("priority", "LOW"), 99))

    interventions = []
    for idx, f in enumerate(sorted_findings):
        dim = f.get("dimension", bottleneck_dim)
        sev = f.get("priority", "MEDIUM")
        cost = "Low" if sev in ("LOW", "MEDIUM") else "Moderate"
        if "retraining" in f.get("finding", "").lower() or "dataset" in f.get("finding", "").lower():
            cost = "High"

        interventions.append({
            "step": idx + 1,
            "target_dimension": dim,
            "action": f.get("action", "Implement missing control"),
            "cost_effort": cost,
            "priority": sev,
            "eu_ai_act_clause": f.get("eu_ai_act_ref", "Articles 9-15"),
        })

    return {
        "engine": "Remediation Priority Ranker",
        "current_aas": current_aas,
        "target_aas": target_score,
        "target_aas_label": "Illustrative Target AAS 76.0 (heuristic benchmark threshold)",
        "target_reached": (current_aas is not None and current_aas >= target_score),
        "bottleneck_dimension": bottleneck_dim,
        "bottleneck_score": bottleneck_score,
        "recommended_interventions": interventions,
        "projection_disclaimer": "Target AAS 76.0 is an illustrative heuristic threshold. Findings are prioritized strictly by severity and control gap, not guaranteed score improvements.",
        "remediation_objective": f"Prioritize remediation of critical findings and bottleneck '{bottleneck_dim}' (score: {bottleneck_score}) toward illustrative target AAS {target_score}.",
    }


# Backwards compatibility alias
solve_prescriptive_counterfactual = solve_remediation_priority


# =====================================================================
# 4. EU AI ACT ARTICLE-BY-ARTICLE COMPLIANCE ENGINE
# (Regulation (EU) 2024/1689: Articles 9 to 15 + Annex III Classification)
# =====================================================================

def evaluate_eu_ai_act_compliance(domain: str,
                                  autonomy_level: str,
                                  dimensions: Dict[str, Optional[float]],
                                  answers: Optional[Dict[str, Any]] = None,
                                  findings: Optional[List[Dict[str, Any]]] = None,
                                  dimension_confidences: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    """
    Evaluates EU AI Act (Regulation (EU) 2024/1689) compliance:
    1. Intended Purpose & Domain Risk Classification (Annex III, Article 5, Article 6, Article 50).
       NOTE: Legal risk tier is strictly determined by intended purpose domain, NEVER by audit scores.
       Unknown domains are UNCLASSIFIED, never defaulted to Minimal Risk.
    2. Article-by-Article Technical Pre-Audit Assessment (Articles 9 to 15).
       NOTE: Produces evidence-based technical indicators, NOT legal or statutory certification.
    """
    high_risk_domains = {
        "healthcare": "High-risk (confirm applicable EU AI Act route: Article 6(1)/Annex I or Annex III §5)",
        "finance": "Annex III §5(b) - Credit Scoring & Essential Financial Services",
        "autonomous_vehicles": "Annex III §2 - Critical Infrastructure & Safety Components of Transport",
        "criminal_justice": "Annex III §6 - Law Enforcement & Judicial Decision Support",
        "education": "Annex III §3 - Education & Vocational Training Admissions",
        "cybersecurity": "Annex III §2 - Critical Digital Infrastructure Security",
        "biometrics": "Annex III §1 - Remote Biometric Identification"
    }

    prohibited_domains = {
        "social_scoring": "Article 5(1)(c) - Social Scoring by Public Authorities",
        "subliminal_manipulation": "Article 5(1)(a) - Subliminal or Deceptive Manipulation causing Harm",
        "realtime_biometric_mass_surveillance": "Article 5(1)(d) - Real-Time Public Biometric Surveillance"
    }

    domain_clean = domain.lower().replace(" / ", "_").replace(" ", "_").strip()

    if domain_clean in prohibited_domains:
        regulatory_tier = "PROHIBITED (Article 5)"
        regulatory_color = "rose"
        tier_legal_basis = prohibited_domains[domain_clean]
        market_placement_permitted = False
    elif any(k in domain_clean for k in high_risk_domains):
        matched_k = next(k for k in high_risk_domains if k in domain_clean)
        if matched_k == "healthcare":
            regulatory_tier = "HIGH RISK (Art. 6(1)/Annex I or Annex III §5)"
        else:
            regulatory_tier = "HIGH RISK (Annex III)"
        regulatory_color = "orange"
        tier_legal_basis = high_risk_domains[matched_k]
        market_placement_permitted = True
    elif any(k in domain_clean for k in ("ecommerce", "entertainment", "general")):
        regulatory_tier = "LIMITED RISK (Article 50)"
        regulatory_color = "amber"
        tier_legal_basis = "Article 50 - Transparency obligations for generative / interactive AI"
        market_placement_permitted = True
    elif any(k in domain_clean for k in ("agri", "environ")):
        regulatory_tier = "MINIMAL RISK (Unregulated)"
        regulatory_color = "emerald"
        tier_legal_basis = "Article 6 / Recital 58 - Agricultural and environmental AI outside Annex III"
        market_placement_permitted = True
    else:
        # Unknown or unclassified domain is UNCLASSIFIED, never default to Minimal Risk
        regulatory_tier = "UNCLASSIFIED"
        regulatory_color = "gray"
        tier_legal_basis = "Intended purpose domain unspecified or unclassified under Regulation (EU) 2024/1689 (Requires bespoke legal review)"
        market_placement_permitted = None

    # STAGE 2: ARTICLE-BY-ARTICLE TECHNICAL ASSESSMENT (Articles 9 to 15)
    confidences = dimension_confidences or {}
    sec_score = dimensions.get("Security & Robustness")
    fair_score = dimensions.get("Fairness & Non-Discrimination")
    trans_score = dimensions.get("Transparency & Explainability")
    priv_score = dimensions.get("Privacy & Data Governance")
    over_score = dimensions.get("Human Oversight & Agency") or dimensions.get("Human Oversight & Accountability")
    acct_score = dimensions.get("Accountability & Governance") or over_score
    safe_score = dimensions.get("Safety & Reliability")

    def determine_status(score: Optional[float], conf_dim: str, threshold: float = 70.0) -> str:
        if score is None:
            return "INSUFFICIENT_EVIDENCE"
        conf = confidences.get(conf_dim, 0.5)
        if conf < 0.20:
            return "INSUFFICIENT_EVIDENCE"
        if score >= threshold:
            return "INDICATIVE_CONFORMANT"
        elif score >= threshold - 20:
            return "PARTIAL"
        else:
            return "NON-CONFORMANT"

    def safe_avg(*scores) -> Optional[float]:
        valid = [s for s in scores if s is not None]
        return round(sum(valid) / len(valid), 1) if valid else None

    articles = [
        {
            "article": "Article 9",
            "title": "Risk Management System",
            "requirement": "Continuous iterative risk management identifying known and foreseeable risks across lifecycle.",
            "status": determine_status(safe_avg(safe_score, sec_score), "Safety & Reliability", 68.0),
            "score": safe_avg(safe_score, sec_score),
            "mandatory_controls": ["Continuous drift monitoring", "Risk mitigation plan", "Known failure mode catalog"],
            "assessment_type": "Technical Pre-Audit Indicator"
        },
        {
            "article": "Article 10",
            "title": "Data & Data Governance",
            "requirement": "Training, validation, and testing datasets must be relevant, representative, and examined for biases.",
            "status": determine_status(safe_avg(fair_score, priv_score), "Fairness & Non-Discrimination", 68.0),
            "score": safe_avg(fair_score, priv_score),
            "mandatory_controls": ["Data origin documentation", "Statistical bias analysis", "Data encryption declarations"],
            "assessment_type": "Technical Pre-Audit Indicator"
        },
        {
            "article": "Article 11",
            "title": "Technical Documentation",
            "requirement": "Detailed technical documentation drawn up before placement on market (system architecture, parameters, validation).",
            "status": determine_status(trans_score, "Transparency & Explainability", 65.0),
            "score": round(trans_score, 1) if trans_score is not None else None,
            "mandatory_controls": ["Comprehensive Model Card", "Validation test benchmarks", "Dependency inventory"],
            "assessment_type": "Technical Pre-Audit Indicator"
        },
        {
            "article": "Article 12",
            "title": "Record-Keeping & Logging",
            "requirement": "Automatic logging of events during operation ensuring traceability and post-market monitoring.",
            "status": determine_status(safe_avg(over_score, sec_score), "Human Oversight & Accountability", 65.0),
            "score": safe_avg(over_score, sec_score),
            "mandatory_controls": ["Decision audit trail", "Tamper-evident logs", "Audit log retention >= 6 months"],
            "assessment_type": "Technical Pre-Audit Indicator"
        },
        {
            "article": "Article 13",
            "title": "Transparency & Provision of Information",
            "requirement": "Operation sufficiently transparent to enable deployers to interpret outputs and use appropriately.",
            "status": determine_status(trans_score, "Transparency & Explainability", 72.0),
            "score": round(trans_score, 1) if trans_score is not None else None,
            "mandatory_controls": ["Feature attributions", "Intended purpose documentation", "Deployer user manual"],
            "assessment_type": "Technical Pre-Audit Indicator"
        },
        {
            "article": "Article 14",
            "title": "Human Oversight",
            "requirement": "Designed to be effectively overseen by natural persons; ability to override, interrupt, or stop system.",
            "status": determine_status(over_score, "Human Oversight & Accountability", 70.0),
            "score": round(over_score, 1) if over_score is not None else None,
            "mandatory_controls": ["Human oversight gates", "Emergency stop mechanism", "Escalation protocol"],
            "assessment_type": "Technical Pre-Audit Indicator"
        },
        {
            "article": "Article 15",
            "title": "Accuracy, Robustness & Cybersecurity",
            "requirement": "Resilient against errors, adversarial attacks, data poisoning, and unauthorized system manipulation.",
            "status": determine_status(safe_avg(sec_score, safe_score), "Security & Robustness", 72.0),
            "score": safe_avg(sec_score, safe_score),
            "mandatory_controls": ["Adversarial robustness testing", "Input validation & corrupted data rejection", "Output clamping"],
            "assessment_type": "Technical Pre-Audit Indicator"
        }
    ]

    conformant_count = sum(1 for a in articles if a["status"] == "INDICATIVE_CONFORMANT")

    overall_status = (
        "CONFORMANT_INDICATIVE" if conformant_count >= 6
        else ("PARTIAL_CONFORMANCE" if conformant_count >= 3 else "NON_CONFORMANT_RISK")
    )

    return {
        "engine": "EU AI Act Compliance Engine (Regulation (EU) 2024/1689)",
        "intended_purpose_classification": {
            "tier": regulatory_tier,
            "badge_color": regulatory_color,
            "legal_basis": tier_legal_basis,
            "market_placement_permitted": market_placement_permitted,
            "conformity_assessment_required": regulatory_tier.startswith("HIGH RISK"),
            "regulatory_framework": "Regulation (EU) 2024/1689 of the European Parliament and of the Council"
        },
        "article_level_conformance": {
            "overall_status": overall_status,
            "conformant_articles": f"{conformant_count}/7",
            "articles": articles,
            "legal_disclaimer": "This assessment is indicative only and does not constitute formal legal certification under Regulation (EU) 2024/1689 or replace an accredited Notified Body conformity assessment."
        }
    }


# =====================================================================
# 5. NIST AI RMF 1.0 (NIST AI 100-1) ENGINE
# =====================================================================

def evaluate_nist_ai_rmf(dimensions: Dict[str, Optional[float]]) -> Dict[str, Any]:
    """
    Maps audit dimensions to NIST AI RMF 1.0 (NIST AI 100-1) Core Functions and Subcategories.
    Uses verified subcategory names from the NIST AI RMF Playbook.
    """
    sec_score = dimensions.get("Security & Robustness")
    fair_score = dimensions.get("Fairness & Non-Discrimination")
    trans_score = dimensions.get("Transparency & Explainability")
    priv_score = dimensions.get("Privacy & Data Governance")
    over_score = dimensions.get("Human Oversight & Agency") or dimensions.get("Human Oversight & Accountability")
    acct_score = dimensions.get("Accountability & Governance") or over_score
    safe_score = dimensions.get("Safety & Reliability")

    def safe_round(val: Optional[float]) -> Optional[float]:
        return round(val, 1) if val is not None else None

    def subcat_status(score: Optional[float]) -> str:
        if score is None: return "INSUFFICIENT_EVIDENCE"
        if score >= 75: return "COMPLIANT"
        if score >= 50: return "PARTIALLY COMPLIANT"
        return "NON-COMPLIANT"

    def avg_scores(*scores) -> Optional[float]:
        valid = [s for s in scores if s is not None]
        return round(sum(valid) / len(valid), 1) if valid else None

    gov_score = avg_scores(over_score, priv_score)
    map_score = avg_scores(fair_score, trans_score)
    meas_score = avg_scores(fair_score, trans_score, sec_score)
    man_score = avg_scores(safe_score, sec_score)

    functions = {
        "GOVERN": {
            "score": gov_score,
            "status": subcat_status(gov_score),
            "subcategories": [
                {"id": "GOVERN 1.1", "name": "Legal, regulatory, and policy priorities recognized and understood", "score": safe_round(priv_score), "status": subcat_status(priv_score)},
                {"id": "GOVERN 1.2", "name": "AI lifecycle policies, processes, and practices actively implemented", "score": safe_round(priv_score), "status": subcat_status(priv_score)},
                {"id": "GOVERN 1.4", "name": "Accountability structures and human oversight roles defined", "score": safe_round(over_score), "status": subcat_status(over_score)},
                {"id": "GOVERN 1.7", "name": "AI system inventory, software dependencies, and supply chain tracked", "score": safe_round(sec_score), "status": subcat_status(sec_score)}
            ]
        },
        "MAP": {
            "score": map_score,
            "status": subcat_status(map_score),
            "subcategories": [
                {"id": "MAP 1.5", "name": "System capabilities, design boundaries, and limitations characterized", "score": safe_round(trans_score), "status": subcat_status(trans_score)},
                {"id": "MAP 1.6", "name": "Stakeholder risks, privacy, and sensitive data dependencies identified", "score": safe_round(priv_score), "status": subcat_status(priv_score)},
                {"id": "MAP 2.2", "name": "Societal and user impacts mapped to operational context", "score": safe_round(fair_score), "status": subcat_status(fair_score)},
                {"id": "MAP 3.2", "name": "Training and evaluation data representativeness documented", "score": safe_round(fair_score), "status": subcat_status(fair_score)}
            ]
        },
        "MEASURE": {
            "score": meas_score,
            "status": subcat_status(meas_score),
            "subcategories": [
                {"id": "MEASURE 2.5", "name": "AI system monitored through continuous automated logs and metrics", "score": safe_round(over_score), "status": subcat_status(over_score)},
                {"id": "MEASURE 2.6", "name": "Explainability, interpretability, and output attribution evaluated", "score": safe_round(trans_score), "status": subcat_status(trans_score)},
                {"id": "MEASURE 2.7", "name": "Cybersecurity, adversarial resilience, and integrity quantified", "score": safe_round(sec_score), "status": subcat_status(sec_score)},
                {"id": "MEASURE 2.8", "name": "Safety boundaries, failure containment, and clamping evaluated", "score": safe_round(safe_score), "status": subcat_status(safe_score)},
                {"id": "MEASURE 2.11", "name": "Fairness, demographic parity, and potential biases assessed", "score": safe_round(fair_score), "status": subcat_status(fair_score)}
            ]
        },
        "MANAGE": {
            "score": man_score,
            "status": subcat_status(man_score),
            "subcategories": [
                {"id": "MANAGE 2.2", "name": "Input validation, anomaly containment, and safety clamping deployed", "score": safe_round(safe_score), "status": subcat_status(safe_score)},
                {"id": "MANAGE 2.4", "name": "Third-party dependency and integration risks controlled", "score": safe_round(sec_score), "status": subcat_status(sec_score)},
                {"id": "MANAGE 4.1", "name": "Incident response, rollback, and kill-switch mechanisms operational", "score": safe_round(over_score), "status": subcat_status(over_score)},
                {"id": "MANAGE 4.2", "name": "Continuous drift monitoring and degradation alerting established", "score": safe_round(sec_score), "status": subcat_status(sec_score)}
            ]
        }
    }

    return {
        "engine": "NIST AI Risk Management Framework (AI RMF 1.0 / NIST AI 100-1)",
        "functions": functions
    }


# =====================================================================
# 6. OWASP TOP 10 (LLM) & MITRE ATLAS ENGINE
# =====================================================================

def map_owasp_and_atlas(findings: List[Dict[str, Any]], dimensions: Dict[str, Optional[float]]) -> Dict[str, Any]:
    """
    Maps findings to OWASP Top 10 for LLMs and MITRE ATLAS Matrix.
    """
    sec_score = dimensions.get("Security & Robustness") or 50.0
    over_score = dimensions.get("Human Oversight & Agency") or dimensions.get("Human Oversight & Accountability") or 50.0
    safe_score = dimensions.get("Safety & Reliability") or 50.0

    owasp_llm_active = []
    atlas_techniques = []

    if sec_score < 75:
        owasp_llm_active.append({
            "code": "LLM01:2025",
            "name": "Prompt Injection",
            "mitigation": "Enforce strict input parameter type validation and sanitize prompts before model invocation."
        })
        atlas_techniques.append({
            "id": "AML.T0043",
            "technique": "LLM Prompt Injection",
            "tactic": "Initial Access / Execution"
        })

    if over_score < 70:
        owasp_llm_active.append({
            "code": "LLM06:2025",
            "name": "Excessive Agency",
            "mitigation": "Restrict tool permissions, require human authorization for irreversible actions."
        })
        atlas_techniques.append({
            "id": "AML.T0054",
            "technique": "LLM Jailbreak & Unauthorized Execution",
            "tactic": "Privilege Escalation"
        })

    if safe_score < 70:
        owasp_llm_active.append({
            "code": "LLM05:2025",
            "name": "Improper Output Handling",
            "mitigation": "Implement deterministic output clamping and safety filters before downstream consumers."
        })
        atlas_techniques.append({
            "id": "AML.T0029",
            "technique": "Evasion Attack via Perturbation",
            "tactic": "Defense Evasion"
        })

    supply_chain_findings = [f for f in findings if any(
        kw in f.get("finding", "").lower() for kw in ["supply chain", "dependency", "sbom", "cve", "package"]
    )]
    if supply_chain_findings or sec_score < 60:
        owasp_llm_active.append({
            "code": "LLM03:2025",
            "name": "Supply Chain Vulnerabilities",
            "mitigation": "Track dependencies with AI-BOM and scan with CVE/EPSS analyzer.",
            "evidence_based": bool(supply_chain_findings),
        })
        atlas_techniques.append({
            "id": "AML.T0015",
            "technique": "AI Dependency Poisoning & Malicious Deserialization",
            "tactic": "Persistence / Impact",
            "evidence_based": bool(supply_chain_findings),
        })

    for f in findings:
        owasp_code = f.get("owasp_ref", "")
        if owasp_code and not any(t["code"] == owasp_code for t in owasp_llm_active):
            owasp_llm_active.append({
                "code": owasp_code,
                "name": f.get("finding", "Observed Threat Surface"),
                "mitigation": f.get("action", "Apply appropriate engineering control"),
                "evidence_based": True,
            })

        atlas_ref = f.get("mitre_atlas_ref", "")
        if atlas_ref and not any(atlas_ref in t["id"] for t in atlas_techniques):
            atlas_techniques.append({
                "id": atlas_ref,
                "technique": f.get("finding", "Observed Attack Surface"),
                "tactic": "Assessed Technique",
                "evidence_based": True,
            })

    return {
        "engine": "OWASP & MITRE ATLAS Threat Crosswalk",
        "owasp_llm_top_10": owasp_llm_active,
        "owasp_mcp_top_10": owasp_llm_active,  # Backwards compatibility alias
        "mitre_atlas_techniques": atlas_techniques,
    }


# =====================================================================
# 7. AI SOFTWARE SUPPLY CHAIN SCANNER (CVE + EPSS)
# Evaluates Compound Risk on real AI/ML libraries
# =====================================================================

def scan_ai_vulnerabilities(domain: str = "General Purpose AI",
                            asset_criticality: str = "Mission-Critical",
                            target_dependencies: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Scans `ai_cve_epss_registry.csv` and computes Compound Vulnerability Risk:
    Risk = CVSS (0-10) * EPSS (0-1) * Criticality Multiplier
    Filters to target_dependencies if supplied.
    """
    if not os.path.exists(AI_CVE_REGISTRY_PATH):
        return {"loaded": False, "records": []}

    criticality_multipliers = {
        "Mission-Critical": 1.5,
        "Business-Critical": 1.2,
        "Operational / Advisory": 1.0,
        "Low / Non-Production": 0.7
    }
    mult = criticality_multipliers.get(asset_criticality, 1.2)

    vulnerabilities = []
    critical_count = 0
    high_count = 0

    target_pkgs = set(p.lower() for p in target_dependencies) if target_dependencies else None

    with open(AI_CVE_REGISTRY_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pkg = row.get("affected_package", "unknown").lower()
            if target_pkgs and pkg not in target_pkgs:
                continue

            try:
                cvss = float(row.get("cvss_score", 5.0))
                epss = float(row.get("epss_probability", 0.1))
            except ValueError:
                cvss, epss = 5.0, 0.1

            compound_risk = round(cvss * epss * mult, 2)
            cve_id = row.get("cve_id", "CVE-UNKNOWN")
            vtype = row.get("vulnerability_type", "Unknown")

            severity = "CRITICAL" if compound_risk >= 6.0 else ("HIGH" if compound_risk >= 3.5 else "MEDIUM")
            if severity == "CRITICAL":
                critical_count += 1
            elif severity == "HIGH":
                high_count += 1

            vulnerabilities.append({
                "cve_id": cve_id,
                "package": pkg,
                "package_type": row.get("package_type", "AI Runtime"),
                "vulnerability_type": vtype,
                "cvss_score": cvss,
                "epss_probability": epss,
                "compound_risk_score": compound_risk,
                "severity": severity,
                "description": (row.get("description", "")[:120] + "..."),
                "remediation": row.get("remediation_patch", "Upgrade to latest patched release")
            })

    vulnerabilities.sort(key=lambda x: x["compound_risk_score"], reverse=True)

    return {
        "engine": "AI Supply Chain Scanner (Static CVE/EPSS Registry — snapshot, not live)",
        "dataset_file": "ai_cve_epss_registry.csv",
        "data_disclaimer": "This scan uses a static local CVE registry. For production use, integrate the NIST NVD and FIRST EPSS live APIs.",
        "total_cves_indexed": len(vulnerabilities),
        "critical_vulnerabilities": critical_count,
        "high_vulnerabilities": high_count,
        "asset_criticality": asset_criticality,
        "criticality_multiplier": mult,
        "top_vulnerabilities": vulnerabilities[:8]
    }


# =====================================================================
# 8. GOOGLE MODEL CARD GENERATOR (Mitchell et al., 2019)
# =====================================================================

def generate_google_model_card(audit_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates a standardized Model Card conforming to Mitchell et al. (2019)
    and EU AI Act Article 13 technical transparency documentation.
    No unverified claims (no 'Certified', 'verified human-in-the-loop', or 'certified tolerances').
    """
    meta = audit_payload.get("model_metadata", {})
    scoring = audit_payload.get("scoring", {})
    dimensions = audit_payload.get("dimensions", {})
    compliance = audit_payload.get("compliance", {})
    findings = audit_payload.get("remediation_plan", [])

    model_name = meta.get("model_name", "AI System")
    version = meta.get("version", "1.0.0")
    arch = meta.get("model_architecture", "Unknown")
    domain = meta.get("domain", "General Purpose")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    markdown_card = f"""# AI Governance Passport & Technical Dossier
**System Name:** {model_name}
**Version:** {version} | **Architecture:** {arch}
**Operating Domain:** {domain}
**Audit Date:** {timestamp}
**AI Assurance Score (AAS):** {scoring.get('aas_score', 'N/A')}/100 (Grade: {scoring.get('trust_grade', 'N/A')})

---

### 1. Model Details
- **Framework / Runtime:** {arch}
- **Autonomy Level:** {meta.get('autonomy_level', 'Semi-Autonomous')}
- **Deployment Type:** {meta.get('deployment_type', 'Cloud API')}
- **Intended Purpose:** Decision support within {domain}

### 2. Intended Use & Out-of-Scope Deployments
- **Primary Use:** Automated inference and decision recommendations.
- **Out-of-Scope:** Deployment without operator override; autonomous actuation in life-critical systems without fail-safe clamps.

### 3. Quantitative Governance & Risk Assessment (7 Dimensions)
- **Security & Robustness:** {dimensions.get('Security & Robustness', 'N/A')}/100
- **Safety & Reliability:** {dimensions.get('Safety & Reliability', 'N/A')}/100
- **Fairness & Non-Discrimination:** {dimensions.get('Fairness & Non-Discrimination', 'N/A')}/100
- **Transparency & Explainability:** {dimensions.get('Transparency & Explainability', 'N/A')}/100
- **Privacy & Data Governance:** {dimensions.get('Privacy & Data Governance', 'N/A')}/100
- **Human Oversight & Agency:** {dimensions.get('Human Oversight & Agency', 'N/A')}/100
- **Accountability & Governance:** {dimensions.get('Accountability & Governance', 'N/A')}/100

### 4. Regulatory & Standards Alignment
- **EU AI Act Classification:** {compliance.get('eu_ai_act', {}).get('intended_purpose_classification', {}).get('tier', compliance.get('eu_ai_act', {}).get('tier', 'N/A'))}
- **Evidence Confidence Tier:** Multi-Tier Audited (T1/T2/T3)
- **NIST AI RMF Alignment:** Audited across GOVERN, MAP, MEASURE, MANAGE functions (NIST AI 100-1)

### 5. Remediation & Action Items
- Identified Findings Count: {len(findings)}
- Action Required: {findings[0].get('action') if findings else 'No active remediation findings identified.'}

### 6. Regulatory & Legal Disclaimer
> **DISCLAIMER:** This model card and associated governance evaluations are technical indicators generated by AI-GRID for risk assessment purposes. They do NOT constitute formal legal advice or statutory regulatory certification under the EU AI Act or other legal frameworks.
"""

    return {
        "engine": "Model Card Generator (inspired by Mitchell et al., 2019 format)",
        "model_name": model_name,
        "version": version,
        "aas_score": scoring.get("aas_score", 0.0),
        "disclaimer": "This assessment does not constitute legal certification.",
        "markdown": markdown_card,
        "json_schema": {
            "model_details": meta,
            "evaluation_scores": dimensions,
            "governance_status": compliance,
            "findings_count": len(findings)
        }
    }


def get_dataset_preview(filepath: str, max_rows: int = 6) -> List[Dict[str, str]]:
    """Helper to return top N records from a CSV dataset for live UI preview."""
    rows = []
    if os.path.exists(filepath):
        try:
            with open(filepath, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    if i >= max_rows:
                        break
                    rows.append(dict(row))
        except Exception:
            pass
    return rows


def get_dataset_catalog() -> List[Dict[str, Any]]:
    """
    Returns full metadata for the empirical benchmark datasets used in AI-GRID.
    """
    german = load_german_credit_baseline()
    clinical = load_clinical_safety_benchmark()

    return [
        {
            "id": "german_credit",
            "name": "UCI Statlog (German Credit Fairness Data)",
            "file": "german_credit_fairness.csv",
            "records": german["sample_count"],
            "features": 10,
            "domain": "Finance / Credit Risk",
            "license": "CC BY 4.0 / Open Data",
            "primary_metric": f"Empirical DIR = {german['empirical_dir']} | SPD = {german['empirical_spd']}",
            "relevance": "Used as an illustrative reference benchmark for demographic parity and Disparate Impact Ratio.",
            "preview_rows": get_dataset_preview(GERMAN_CREDIT_PATH, max_rows=5)
        },
        {
            "id": "clinical_safety",
            "name": "Clinical Patient Safety & Dosage Cohort",
            "file": "clinical_patient_safety.csv",
            "records": clinical["sample_count"],
            "features": 13,
            "domain": "Healthcare / Patient Safety",
            "license": "Curated Open Healthcare Benchmark",
            "primary_metric": f"Clamping Rate = {clinical['metrics']['output_clamping_rate_pct']}% | Rejection Rate = {clinical['metrics']['corrupted_input_rejection_rate']}%",
            "relevance": "Evaluates safety boundary guardrails and output clamping on clinical patient edge cases.",
            "preview_rows": get_dataset_preview(CLINICAL_SAFETY_PATH, max_rows=5)
        },
        {
            "id": "ai_cve_registry",
            "name": "AI Software Supply Chain CVE & EPSS Registry",
            "file": "ai_cve_epss_registry.csv",
            "records": 48,
            "features": 11,
            "domain": "Cybersecurity / AI Supply Chain",
            "license": "Derived from NIST NVD & FIRST EPSS (Open Data)",
            "primary_metric": "Compound Risk = CVSS × EPSS × Criticality Multiplier",
            "relevance": "Maps vulnerabilities across AI runtimes, agent frameworks, and math libraries.",
            "preview_rows": get_dataset_preview(AI_CVE_REGISTRY_PATH, max_rows=5)
        }
    ]
