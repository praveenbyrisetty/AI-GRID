# AI-GRID (v5.0.0)

### Empirical AI Governance, Risk &amp; Compliance Operating System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%20%7C%20REST%20API-orange.svg)](https://flask.palletsprojects.com/)
[![Standards](https://img.shields.io/badge/Standards-EU%20AI%20Act%20(Art.%209--15)%20%7C%20NIST%20AI%20100--1-emerald.svg)](https://artificialintelligenceact.eu/)
[![Taxonomy](https://img.shields.io/badge/Taxonomy-QB4AIRA%20(IEEE%202024)-purple.svg)](https://doi.org/10.1109/MS.2024.3512577)
[![Evidence Tiers](https://img.shields.io/badge/Evidence%20Tiers-T1%20Verified%20%7C%20T3%20Attested-blueviolet.svg)](#empirical-verification-modules-tier-t1)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Executive Overview

**AI-GRID** is a research-grounded AI Governance, Risk, and Compliance (GRC) evaluation platform engineered to quantify, audit, and remediate systemic AI risks before production deployment.

Grounded in **QB4AIRA** (Lee et al., IEEE 2024), the **EU AI Act** (Regulation (EU) 2024/1689 Articles 9–15), **NIST AI 100-1** (AI Risk Management Framework), and **ISO/IEC 42001**, AI-GRID evaluates AI systems across 7 empirical trust dimensions using a structured 35-item technical control question bank combined with empirical evidence verifiers.

AI-GRID incorporates:
1. **35-Item Technical Control Question Bank**: Structured technical controls across 7 international trust pillars with academic citations and regulatory clause mappings.
2. **Empirical Evidence Verifiers (Tier T1)**: Real-time verification modules for fairness disparity, CycloneDX SBOM dependencies via public OSV API, TLS security, cryptographic log chains, and perturbation accuracy drops.
3. **Attestation Gap Analysis**: Automatically measures and visualizes discrepancies between self-asserted claims ($S_{\text{claimed}}$) and verified evidence ($S_{\text{verified}}$).
4. **Bottleneck-Penalised Aggregate (AAS)**: Penalizes composite assurance by the weakest dimension ($\min S_d$) using a convex combination ($\alpha = 0.60$) to prevent averaging out critical governance vulnerabilities.
5. **EU AI Act Technical Pre-Audit Conformance Matrix**: Evaluates classification under Article 6(1) / Annex I or Annex III §5 and checks conformity against mandatory technical obligations in Articles 9 through 15 (with Article 12 wired to Accountability).
6. **NIST AI 100-1 Lifecycle Crosswalk**: Maps findings to GOVERN, MAP, MEASURE, and MANAGE core functions and subcategories.
7. **Persistent Audit Ledger**: SQLite-backed audit history tracking longitudinal assessments, provenance metadata, and technical findings across server restarts.

---

## The 7 Research-Grounded Trust Dimensions

AI-GRID evaluates AI trustworthiness across seven consolidated dimensions aligned with international standards:

| # | Trust Dimension | Scope &amp; Focus | Regulatory &amp; Industry Standards |
|:---:|:---|:---|:---|
| **1** | **Security &amp; Robustness** | Adversarial robustness, concept drift monitoring, AI software bill of materials (AI-BOM), independent red teaming, and API rate limiting. | EU AI Act Art. 15(4) &bull; NIST MEASURE 2.7 &bull; OWASP LLM Top 10 &bull; MITRE ATLAS |
| **2** | **Safety &amp; Reliability** | Corrupted input rejection, input/output validation, active guardrails (&ge; 3 active), deterministic output bounds clamping, and formal failure mode testing. | EU AI Act Art. 9 &amp; 15(1) &bull; NIST MANAGE 2.2 |
| **3** | **Fairness &amp; Non-Discrimination** | Demographic representation, class balance, coverage gaps, dataset volume adequacy, and disparate impact metrics (DIR &ge; 0.80, SPD &le; 0.10). | EU AI Act Art. 10(2)(f) &bull; NIST MEASURE 2.11 &bull; EEOC 80% Rule &bull; Kamiran &amp; Calders (2012) |
| **4** | **Transparency &amp; Explainability** | Local feature attributions (TreeSHAP/LIME), prediction-level reasoning summaries, Model Cards, and calibrated uncertainty bounds. | EU AI Act Art. 13 &bull; NIST MAP 1.5 &bull; Mitchell et al. (2019) |
| **5** | **Privacy &amp; Data Governance** | AES-256 encryption at rest, TLS 1.3 in transit, strict retention and automated purging (&le; 90 days), automated PII redaction, and formal data governance policies. | EU AI Act Art. 10(5) &bull; GDPR Art. 25/32 &bull; NIST GOVERN 1.2 |
| **6** | **Human Oversight &amp; Agency** | Mandatory Human-in-the-Loop (HITL) gates, autonomy level constraints, operator training, emergency kill-switches, and override capabilities. | EU AI Act Art. 14 &bull; NIST GOVERN 1.4 |
| **7** | **Accountability &amp; Governance** | Incident escalation SLAs, append-only tamper-evident signed logs, technical dossier documentation, post-market monitoring, and formal governance charters. | EU AI Act Art. 9, 11, 12, 17, 72 &bull; NIST GOVERN 2.1 |

---

## Empirical Verification Modules (Tier T1)

AI-GRID provides 5 automated, empirical verification endpoints (`POST /api/verify/<module>`) that replace subjective claims with verified measurements:

### 1. Fairness Audit (`/api/verify/fairness`)
Upload a predictions CSV with columns `protected_attribute`, `y_true`, and `y_pred`:
```csv
protected_attribute,y_true,y_pred
male,1,1
male,0,0
female,1,1
female,0,0
```
- **Metrics**: Computes Disparate Impact Ratio (DIR), Statistical Parity Difference (SPD), and Equal Opportunity Difference (EOD / TPR gap).
- **Thresholds**: DIR $\ge 0.80$ and $|\text{SPD}| \le 0.10 \to 1.0$; DIR $\ge 0.70$ and $|\text{SPD}| \le 0.15 \to 0.5$; else $0.0$.
- Replaces self-attested answer for `q10_fairness_audit`.

### 2. Dependencies &amp; AI-BOM Verification (`/api/verify/dependencies`)
Upload a CycloneDX JSON SBOM or plain `requirements.txt`:
```text
requests==2.31.0
click==8.1.7
pydantic==2.5.0
```
- **Method**: Queries the public OSV API (`POST https://api.osv.dev/v1/querybatch`, PyPI ecosystem, Python `urllib` only) with a 5-second timeout and up to 200 packages.
- **Thresholds**: Valid CycloneDX with no CVSS $\ge 7.0$ match $\to 1.0$; requirements-only manifest or high vulnerability match $\to 0.5$.
- **Offline / Failure Resilience**: If the OSV lookup is offline or unreachable, returns `"vulnerability lookup unavailable"` and preserves the claimed score without penalizing for network failure.
- Replaces self-attested answer for `q3_aibom_inventory`.

### 3. TLS Encryption &amp; Certificate Prober (`/api/verify/tls`)
Submit target host and port via JSON payload:
```json
{
  "host": "api.example.com",
  "port": 443
}
```
- **Method**: Probes target with Python `ssl` using a 5-second socket timeout (ports 443 and 8443 only).
- **SSRF Defense**: Strictly blocks loopback, private (RFC 1918), link-local, multicast, and cloud metadata (`169.254.169.254`) IP addresses.
- **Thresholds**: TLS 1.3 + valid non-expired certificate $\to 1.0$; TLS 1.2 + valid certificate $\to 0.6$; else $0.0$.
- Replaces self-attested answer for `q17_encryption_transit`.

### 4. Log Tamper-Evidence Audit (`/api/verify/log-integrity`)
Upload a JSONL audit log containing `prev_hash`, `data`, and `hash`:
```json
{"prev_hash": "GENESIS", "data": {"event": "inference_completed"}, "hash": "6b86b273..."}
```
- **Method**: Cryptographically validates SHA-256 hash chains from genesis block: $\text{hash}_k = \text{SHA256}(\text{prev\_hash}_k + \text{data}_k)$.
- **Thresholds**: Valid unbroken chain $\to 1.0$; broken link or altered entry $\to 0.0$.
- Replaces self-attested answer for `q27_tamper_evident_logs`.

### 5. Adversarial Robustness Evaluation (`/api/verify/robustness`)
Upload clean baseline predictions and perturbed evaluation predictions CSV:
```csv
clean_prediction,perturbed_prediction,ground_truth
1,1,1
0,0,0
1,0,1
```
- **Method**: Measures accuracy degradation: $\Delta \text{Acc} = \text{Acc}_{\text{clean}} - \text{Acc}_{\text{perturbed}}$.
- **Thresholds**: Degradation $\Delta \text{Acc} \le 0.05$ (&le; 5%) $\to 1.0$; $\Delta \text{Acc} \le 0.15$ (&le; 15%) $\to 0.5$; drop $> 15\% \to 0.0$.
- Replaces self-attested answer for `q1_adversarial_testing`.

---

## Mathematical Formulation: Bottleneck AAS &amp; Attestation Gap

AI-GRID calculates composite assurance using a bottleneck-penalised aggregate:

$$\text{AAS} = \alpha \cdot \bar{S} + (1 - \alpha) \cdot \min_{d \in \{1 \dots 7\}} S_d \quad (\alpha = 0.60)$$

Where:
- $\bar{S} = \frac{1}{7} \sum_{d=1}^{7} S_d$ is the global weighted average across all 7 dimensions.
- $\min_d S_d$ isolates the **Primary Governance Bottleneck**.
- Dimension scores incorporate evidence weighting:
  $$S_d = 100 \times \frac{\sum_{i=1}^{n_d} w_i \cdot s_i \cdot w_{\text{evidence}, i}}{\sum_{i=1}^{n_d} w_i \cdot w_{\text{evidence}, i}}$$
  where $w_{\text{evidence}} = 1.0$ for Tier T1 verified artifacts and $w_{\text{evidence}} = 0.6$ for Tier T3 self-attested items.

### Attestation Gap Formulation
The attestation discrepancy quantifies the difference between self-attested claims and verified empirical reality:

$$\Delta_d = S_{d, \text{claimed}} - S_{d, \text{verified}}$$
$$\Delta_{\text{AAS}} = \text{AAS}_{\text{claimed}} - \text{AAS}_{\text{verified}}$$

---

## Regulatory Compliance &amp; Threat Engines

* **EU AI Act (Regulation (EU) 2024/1689)**:
  - **Intended Purpose Classification**: Categorized strictly by intended domain (Annex III High-Risk vs Article 5 Prohibited vs Article 50 Limited vs Minimal). The legal risk tier is NEVER derived from audit/AAS scores.
  - **Articles 9–15 Technical Pre-Audit Indicators**: Evaluates empirical technical criteria for risk management (Art. 9), data governance (Art. 10), technical documentation (Art. 11 wired to mean(Transparency, Accountability)), record-keeping/logging (Art. 12 wired to Accountability), transparency (Art. 13), human oversight (Art. 14), and robustness/cybersecurity (Art. 15).
  - *Statutory Notice*: Pre-audit indicators do NOT constitute legal advice or formal CE-mark certification by a Notified Body.
* **NIST AI RMF 1.0 (NIST AI 100-1)**:
  - Crosswalked across **GOVERN, MAP, MEASURE, MANAGE** lifecycle functions. GOVERN 2.1, MEASURE 2.5, and MANAGE 4.1 are directly wired to the Accountability dimension.
* **OWASP &amp; MITRE ATLAS Threat Crosswalk**:
  - Maps identified vulnerabilities to OWASP Top 10 for LLMs and MITRE ATLAS matrix technique IDs.
* **Model Cards for Model Reporting (Mitchell et al., 2019)**:
  - Exports standardized AI Governance Passports in Markdown, JSON, EU AI Act Annex IV, and Executive Board formats.

---

## Technical Implementation Disclosures &amp; Architecture Integrity

| Capability | Engineering Implementation | Verification Status |
|:---|:---|:---|
| **Questionnaire Engine** | 35 scored questions grounded in QB4AIRA (Lee et al., 2024) and EU AI Act Articles 9–15 (`ai_profile_engine.py`). | **Grounded in Academic Literature** |
| **Evidence Verifiers** | 5 automated empirical verification modules checking fairness, dependencies (OSV API), TLS, hash chains, and robustness (`verifiers.py`). | **Empirically Verified (Tier T1)** |
| **Audit Persistence** | Native SQLite ledger (`audit_store.py` -> `instance/aigrid_audits.db`) storing complete audit dossiers, evidence items, and findings with SHA-256 integrity digests. | **Built-in `sqlite3` & `hashlib`** |
| **Remediation Ranker** | Ranks findings by severity and bottleneck gap toward illustrative target AAS 76 without synthetic financial multipliers. | **Empirical Heuristic Ranking** |

---

## Getting Started

> [!IMPORTANT]
> **Authentication & Deployment Security Notice**:
> AI-GRID operates **without authentication** and is designed specifically for local evaluation, research, and demonstration environments. **Do not enter sensitive, proprietary, or regulated patient/customer data on a public deployment.**

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

---

## Reference Presets

AI-GRID includes pre-configured reference profiles matching high-risk and standard operational domains:
1. **Clinical Diagnostic AI (High-Risk)**: High-assurance medical diagnostic model under EU AI Act Annex III §5(a).
2. **Credit Scoring AI (High-Risk)**: Financial automated underwriting system under EU AI Act Annex III §5(b).
3. **General Purpose AI Assistant (Minimal Risk)**: General assistant LLM copilot evaluated against baseline safety controls.

---

## Research Literature Citations

1. **National Institute of Standards and Technology (NIST) (2023).** *Artificial Intelligence Risk Management Framework (AI RMF 1.0).* NIST AI 100-1. DOI: [10.6028/NIST.AI.100-1](https://doi.org/10.6028/NIST.AI.100-1).
2. **Lee, M. S., et al. (2024).** *QB4AIRA: A Question Bank for Responsible AI Risk Assessment.* IEEE Software, 42(3). DOI: [10.1109/MS.2024.3512577](https://doi.org/10.1109/MS.2024.3512577).
3. **Mitchell, M., et al. (2019).** *Model Cards for Model Reporting.* ACM Conference on Fairness, Accountability, and Transparency (FAccT), pp. 220–229.
4. **Kamiran, F., &amp; Calders, T. (2012).** *Data preprocessing techniques for classification without discrimination.* Knowledge and Information Systems, 33(1), 1–33.
5. **International Organization for Standardization (2023).** *ISO/IEC 42001: Information technology — Artificial intelligence — Management system.* ISO.
