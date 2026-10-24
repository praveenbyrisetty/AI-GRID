# AI-GRID (v4.0)

### Empirical AI Governance, Risk &amp; Compliance Operating System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%20%7C%20REST%20API-orange.svg)](https://flask.palletsprojects.com/)
[![Standards](https://img.shields.io/badge/Standards-EU%20AI%20Act%20(Art.%209--15)%20%7C%20NIST%20AI%20100--1-emerald.svg)](https://artificialintelligenceact.eu/)
[![Taxonomy](https://img.shields.io/badge/Taxonomy-QB4AIRA%20(IEEE%202024)-purple.svg)](https://doi.org/10.1109/MS.2024.3512577)
[![Tests](https://img.shields.io/badge/Tests-34%20Passed%20(pytest)-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Executive Overview

**AI-GRID** is a research-grounded AI Governance, Risk, and Compliance (GRC) evaluation platform engineered to quantify, audit, and remediate systemic AI risks before production deployment.

Grounded in **QB4AIRA** (Lee et al., IEEE 2024), the **EU AI Act** (Regulation (EU) 2024/1689 Articles 9–15), and **NIST AI 100-1** (AI Risk Management Framework), AI-GRID evaluates AI systems across 7 empirical trust dimensions using a structured 35-item technical control question bank.

AI-GRID incorporates:
1. **35-Item Research Questionnaire (Evidence Tier T3)**: Structured technical controls across 7 international trust pillars with academic citations and regulatory clause mappings.
2. **Bottleneck-Penalised Aggregate (inspired by average-case versus worst-case ERM)**: Penalizes composite assurance by the weakest dimension ($\min S_d$) to prevent averaging out critical governance vulnerabilities.
3. **EU AI Act Technical Pre-Audit Conformance Matrix**: Evaluates classification under Article 6(1) / Annex I or Annex III §5 and checks conformity against mandatory technical obligations in Articles 9 through 15.
4. **NIST AI 100-1 Lifecycle Crosswalk**: Maps findings to GOVERN, MAP, MEASURE, and MANAGE core functions and subcategories.
5. **Persistent Audit Ledger**: SQLite-backed audit history tracking longitudinal assessments, provenance metadata, and technical findings across server restarts.
6. **Mathematical Sensitivity Stress Curve**: Monotonically explores risk appetite across $\alpha \in [0.1, 0.9]$.

---

## The 7 Research-Grounded Trust Dimensions

AI-GRID evaluates AI trustworthiness across seven consolidated dimensions aligned with international standards:

| # | Trust Dimension | Scope &amp; Focus | Regulatory &amp; Industry Standards |
|:---:|:---|:---|:---|
| **1** | **Security &amp; Robustness** | Adversarial robustness, concept drift monitoring, AI software bill of materials (AI-BOM), independent red teaming, and API rate limiting / mTLS. | EU AI Act Art. 15(4) &bull; NIST MEASURE 2.7 &bull; OWASP LLM Top 10 &bull; MITRE ATLAS |
| **2** | **Safety &amp; Reliability** | Corrupted input rejection, input/output validation, active guardrails (&ge; 3 active), deterministic output bounds clamping, and formal failure mode testing. | EU AI Act Art. 9 &amp; 15(1) &bull; NIST MANAGE 2.2 |
| **3** | **Fairness &amp; Non-Discrimination** | Demographic representation, class balance, coverage gaps, dataset volume adequacy, and disparate impact metrics (DIR &ge; 0.80, SPD &le; 0.10). | EU AI Act Art. 10(2)(f) &bull; NIST MEASURE 2.11 &bull; EEOC 80% Rule &bull; Kamiran &amp; Calders (2012) |
| **4** | **Transparency &amp; Explainability** | Local feature attributions (TreeSHAP/LIME), prediction-level reasoning summaries, Model Cards, and calibrated uncertainty bounds. | EU AI Act Art. 13 &bull; NIST MAP 1.5 &bull; Mitchell et al. (2019) |
| **5** | **Privacy &amp; Data Governance** | AES-256 encryption at rest, TLS 1.3 in transit, strict retention and automated purging (&le; 90 days), automated PII redaction, and formal data governance policies. | EU AI Act Art. 10(5) &bull; GDPR Art. 25/32 &bull; NIST GOVERN 1.2 |
| **6** | **Human Oversight &amp; Agency** | Mandatory Human-in-the-Loop (HITL) gates, autonomy level constraints, operator training, emergency kill-switches, and override capabilities. | EU AI Act Art. 14 &bull; NIST GOVERN 1.4 |
| **7** | **Accountability &amp; Governance** | Incident escalation SLAs, append-only tamper-evident signed logs, technical dossier documentation, post-market monitoring, and formal governance charters. | EU AI Act Art. 9, 11, 12, 17, 72 &bull; NIST GOVERN 2.1 |

---

## Mathematical Formulation: Bottleneck-Penalized Aggregate (AAS)

In cybersecurity and safety-critical engineering, arithmetic averages mask catastrophic failure modes: an AI system scoring 95% in Transparency and Privacy but **10% in Security** is completely unsafe for production deployment.

AI-GRID calculates the composite **Assurance Adequacy Score (AAS)** using a bottleneck-penalised aggregate, inspired by average-case versus worst-case ERM:

$$\text{AAS} = \alpha \cdot \bar{S} + (1 - \alpha) \cdot \min_{d \in \{1 \dots 7\}} S_d \quad (\alpha = 0.60)$$

Where:
- $\bar{S} = \frac{1}{7} \sum_{d=1}^{7} S_d$ is the global weighted average across all 7 dimensions.
- $\min_d S_d$ isolates the **Primary Governance Bottleneck** (weakest constraint).
- Dimension scores incorporate evidence weighting:
  $$S_d = 100 \times \frac{\sum_{i=1}^{n_d} w_i \cdot s_i \cdot w_{\text{evidence}, i}}{\sum_{i=1}^{n_d} w_i \cdot w_{\text{evidence}, i}}$$
  with $w_{\text{evidence}} = 0.60$ for self-attested questionnaire items. (Note: in the questionnaire-first control plane, all active evidence is currently Tier T3).

---

## Empirical Benchmark Datasets Used

AI-GRID executes fairness and risk calculations natively against 3 empirical datasets located in `data/`:

1. **UCI Machine Learning Repository: Statlog (German Credit Data)** (`data/german_credit_fairness.csv`):
   - **Sample Volume**: 1,002 rows, 10 attributes.
   - **Protected Demographics**: Gender (`female` unprivileged, `male` privileged), Age, Foreign Worker.
   - **Metrics**: Disparate Impact Ratio (DIR = 0.896), Statistical Parity Difference (SPD = -0.075), and Kamiran &amp; Calders (2012) sample reweighing weights.
2. **Clinical Patient Safety &amp; Dosage Benchmark Cohort** (`data/clinical_patient_safety.csv`):
   - **Sample Volume**: 299 patient records, 13 clinical vitals.
   - **Verification**: 100% rejection rate on corrupted vitals, 28.4% output safety clamping rate, and 94.6% physician HITL approval rate.
3. **AI Framework CVE &amp; EPSS Compound Registry** (`data/ai_cve_epss_registry.csv`):
   - **Sample Volume**: 50 verified enterprise CVEs targeting PyTorch, TorchServe, LangChain, Transformers, ONNX, and NumPy.
   - **Formula**: $\text{Compound Risk} = \text{CVSS (0-10)} \times \text{EPSS (0-1)} \times \text{Asset Criticality Multiplier}$.

---

## Regulatory Compliance &amp; Threat Engines

* **EU AI Act (Regulation (EU) 2024/1689)**:
  - **Intended Purpose Classification**: Categorized strictly by intended domain (Annex III High-Risk vs Article 5 Prohibited vs Article 50 Limited vs Minimal). The legal risk tier is NEVER derived from audit/AAS scores.
  - **Articles 9–15 Technical Pre-Audit Indicators**: Evaluates empirical technical criteria for risk management, data governance, documentation, logging, transparency, human oversight, and robustness.
  - *Statutory Notice*: Pre-audit indicators do NOT constitute legal advice or formal CE-mark certification by a Notified Body.
* **NIST AI RMF 1.0 (NIST AI 100-1)**:
  - Crosswalked across **GOVERN, MAP, MEASURE, MANAGE** lifecycle functions.
* **OWASP &amp; MITRE ATLAS Threat Crosswalk**:
  - Maps identified vulnerabilities to OWASP Top 10 for LLMs and MITRE ATLAS matrix technique IDs.
* **Model Cards for Model Reporting (Mitchell et al., 2019)**:
  - Exports standardized AI Governance Passports in Markdown, JSON, EU AI Act Annex IV, and Executive Board formats.

---

## Technical Implementation Disclosures &amp; Architecture Integrity

| Capability | Engineering Implementation | Verification Status |
|:---|:---|:---|
| **Questionnaire Engine** | 35 scored questions grounded in QB4AIRA (Lee et al., 2024) and EU AI Act Articles 9–15 (`ai_profile_engine.py`). | **Grounded in Academic Literature** |
| **Audit Persistence** | Native SQLite ledger (`audit_store.py` -> `data/aigrid_audits.db`) storing complete audit dossiers, evidence items, and findings with SHA-256 integrity digests. | **Built-in `sqlite3` & `hashlib`** |
| **Fairness Metrics** | Native computation of Disparate Impact Ratio (DIR) and Statistical Parity Difference (SPD) on UCI Statlog German Credit benchmark (`data/german_credit_fairness.csv`). | **Empirical Calculations** |
| **Risk Cohort Slicing** | Illustrative rule-based risk cohorts, not measured: heuristic classification against Clinical Patient Safety benchmark (`data/clinical_patient_safety.csv`). | **Rule-Based Heuristic (Not Measured)** |
| **Remediation Ranker** | Ranks findings by severity and bottleneck gap toward illustrative target AAS 76 without synthetic financial multipliers. | **Empirical Heuristic Ranking** |

---

## Getting Started

### Prerequisites
- Python 3.10+
- Flask &amp; Flask-CORS

### Installation
```bash
pip install -r requirements.txt
```

### Running the Server &amp; Control Dashboard
```bash
python server.py
```
Open **`http://localhost:8000`** in any modern web browser.

### Running Test Verification Suite
Execute the full 34-test verification suite (unit tests, API security, compliance indicators, and empirical experiments):
```bash
python -m pytest tests/ -v
```

---

## Reference Presets

AI-GRID includes pre-configured reference profiles matching high-risk and standard operational domains:
1. **Clinical Diagnostic AI (High-Risk)**: High-assurance medical diagnostic model under EU AI Act Annex III §5(a).
2. **Credit Scoring AI (High-Risk)**: Financial automated underwriting system under EU AI Act Annex III §5(b).
3. **General Purpose AI Assistant (Minimal Risk)**: General assistant LLM copilot evaluated against baseline safety controls.

---

## Research Literature Citations

1. **Pfau, D., &amp; Jung, A. (2026).** *Engineering Trustworthy AI: A Developer Guide for Empirical Risk Minimization.* IEEE Transactions on Artificial Intelligence, 7(5), 2560–2576. DOI: [10.1109/TAI.2025.3617936](https://doi.org/10.1109/TAI.2025.3617936).
2. **Lee, M. S., et al. (2024).** *QB4AIRA: A Question Bank for Responsible AI Risk Assessment.* IEEE Software, 42(3). DOI: [10.1109/MS.2024.3512577](https://doi.org/10.1109/MS.2024.3512577).
3. **Mitchell, M., et al. (2019).** *Model Cards for Model Reporting.* ACM Conference on Fairness, Accountability, and Transparency (FAccT), pp. 220–229.
4. **Kamiran, F., &amp; Calders, T. (2012).** *Data preprocessing techniques for classification without discrimination.* Knowledge and Information Systems, 33(1), 1–33.
