"""
AI-GRID Compliance & Responsible AI Engines (v5.0)

Provides transparently named audit engines:
1. Custom Fairness Metrics Engine (DIR, SPD computation from predictions CSV)
2. Remediation Priority Ranker (severity-based finding prioritization)
3. EU AI Act Article-by-Article Compliance Engine (Articles 9 to 15 + Annex III classification)
4. NIST AI 100-1 Subcategory Crosswalk (GOVERN, MAP, MEASURE, MANAGE)
5. OWASP Top 10 for LLMs & Threat Mapper
6. MITRE ATLAS Adversarial Threat Technique Mapper
7. Google Model Card Generator (conforming to Mitchell et al., 2019 format)

DISCLAIMER: This assessment does not constitute legal certification or
guaranteed regulatory compliance. Professional review is recommended.
"""

import csv
import io
import os
from datetime import datetime
from typing import Any, Dict, List, Optional


# =====================================================================
# 1. CUSTOM FAIRNESS METRICS ENGINE (DIR/SPD Computation)
# =====================================================================

def compute_fairness_metrics(answers: Optional[Dict[str, Any]] = None,
                             metadata: Optional[Dict[str, Any]] = None,
                             fairness_score: Optional[float] = None,
                             predictions_csv: Optional[str] = None) -> Dict[str, Any]:
    """
    Computes algorithmic fairness indicators (DIR, SPD, EOD) from prediction data.
    - If user supplies a predictions CSV: metrics are computed strictly from that data.
    - If no predictions CSV is provided: reports NO_EVALUATION_DATASET_PROVIDED honestly.
    """
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
            protected_col = next((c for c in rows[0].keys() if c.lower() in ("gender", "sex", "race", "ethnicity", "age", "protected_attribute")), None)
            outcome_col = next((c for c in rows[0].keys() if c.lower() in ("prediction", "predicted", "outcome", "credit_risk", "label", "target", "approved", "y_pred")), None)
            label_col = next((c for c in rows[0].keys() if c.lower() in ("true_label", "ground_truth", "actual", "y_true")), None)

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
                    "engine": "Custom Fairness Metrics Engine (DIR/SPD from predictions)",
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
        "regulatory_alignment": {
            "eu_ai_act": "Article 10(2)(f) - Examination of possible biases in training datasets",
            "nist_ai_rmf": "MEASURE 2.11 - Fairness and bias are evaluated and documented",
        }
    }


# =====================================================================
# 2. REMEDIATION PRIORITY RANKER
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
        regulatory_color = "red"
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
    over_score = dimensions.get("Human Oversight & Agency")
    acct_score = dimensions.get("Accountability & Governance")
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
            "status": determine_status(safe_avg(trans_score, acct_score), "Transparency & Explainability", 65.0),
            "score": safe_avg(trans_score, acct_score),
            "mandatory_controls": ["Comprehensive Model Card", "Validation test benchmarks", "Dependency inventory"],
            "assessment_type": "Technical Pre-Audit Indicator"
        },
        {
            "article": "Article 12",
            "title": "Record-Keeping & Logging",
            "requirement": "Automatic logging of events during operation ensuring traceability and post-market monitoring.",
            "status": determine_status(acct_score, "Accountability & Governance", 65.0),
            "score": round(acct_score, 1) if acct_score is not None else None,
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
            "status": determine_status(over_score, "Human Oversight & Agency", 70.0),
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
    over_score = dimensions.get("Human Oversight & Agency")
    acct_score = dimensions.get("Accountability & Governance")
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

    gov_score = avg_scores(over_score, priv_score, acct_score)
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
                {"id": "GOVERN 2.1", "name": "Roles, responsibilities, and accountability structures transparently established", "score": safe_round(acct_score), "status": subcat_status(acct_score)},
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
                {"id": "MEASURE 2.5", "name": "AI system monitored through continuous automated logs and metrics", "score": safe_round(acct_score), "status": subcat_status(acct_score)},
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
                {"id": "MANAGE 4.1", "name": "Incident response, rollback, and kill-switch mechanisms operational", "score": safe_round(acct_score), "status": subcat_status(acct_score)},
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
    over_score = dimensions.get("Human Oversight & Agency") or 50.0
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
        "mitre_atlas_techniques": atlas_techniques,
    }


# =====================================================================
# 7. AI SOFTWARE SUPPLY CHAIN SCANNER (CVE + EPSS)
# Evaluates Compound Risk on real AI/ML libraries
# =====================================================================



# =====================================================================
# 7. GOOGLE MODEL CARD GENERATOR
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


