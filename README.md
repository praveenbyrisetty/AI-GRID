# AI-GRID (v4.0)

### Empirical Governance, Risk &amp; Assurance Framework for Autonomous &amp; Tool-Augmented AI

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%20%7C%20REST%20API-orange.svg)](https://flask.palletsprojects.com/)
[![Standards](https://img.shields.io/badge/Standards-EU%20AI%20Act%20(Art.%209--15)%20%7C%20NIST%20AI%20RMF-emerald.svg)](https://artificialintelligenceact.eu/)
[![Protocol](https://img.shields.io/badge/Protocol-Model%20Context%20Protocol%20(MCP)%202.x-purple.svg)](https://modelcontextprotocol.io/)
[![Tests](https://img.shields.io/badge/Tests-27%20Passed%20(pytest)-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Executive Overview

**AI-GRID** is a research-grounded, empirical AI Governance, Risk, and Assurance framework engineered for tool-augmented AI agents and autonomous systems communicating via the **Model Context Protocol (MCP)**.

Modern agentic systems execute external tools, query databases, invoke financial APIs, and write code. Hardening a single model is insufficient; trustworthiness must be quantified and verified at runtime boundaries.

AI-GRID resolves the core challenge of AI governance through a dual-mode evaluation framework:
1. **Structured Research Questionnaire (Evidence Tier T3, weight 0.60)**: 30 standardized evaluation items mapped across 6 research-grounded dimensions.
2. **Automated Runtime MCP Protocol Probing (Evidence Tier T1, weight 1.00)**: Introspects tool schemas, validates boundary clamping, injects adversarial perturbations, and verifies data encryption using the official MCP Python SDK.
3. **Attestation Discrepancy Analysis**: Quantifies self-reporting optimism bias by computing the divergence index ($\Delta = S_{\text{self}} - S_{\text{probe}}$) between developer attestation and probed reality.

---

## The 6 Research-Grounded Trust Dimensions

AI-GRID evaluates AI trustworthiness across six consolidated dimensions aligned with the EU AI Act technical obligations (Articles 9–15) and ISO/IEC 42001:

| # | Trust Dimension | Scope &amp; Focus | Regulatory &amp; Industry Standards |
|:---:|:---|:---|:---|
| **1** | **Security &amp; Robustness** | Adversarial robustness, concept drift monitoring, AI-BOM software supply chain inventory, red teaming, and API rate limiting. | EU AI Act Art. 15(4) &bull; NIST MEASURE 2.7 &bull; OWASP MCP01/07 &bull; MITRE ATLAS AML.T0029 |
| **2** | **Fairness &amp; Non-Discrimination** | Demographic representation, class balance, coverage gaps, dataset volume adequacy, and disparate impact metrics (DIR &ge; 0.80, SPD &le; 0.10). | EU AI Act Art. 10(2)(f) &bull; NIST MEASURE 2.11 &bull; EEOC 80% Rule &bull; Kamiran &amp; Calders (2012) |
| **3** | **Transparency &amp; Explainability** | Local feature attributions (TreeSHAP/LIME), prediction-level reasoning summaries, Model Cards, and calibrated uncertainty bounds. | EU AI Act Art. 13 &bull; NIST MAP 1.5 &bull; Mitchell et al. (2019) |
| **4** | **Privacy &amp; Data Governance** | AES-256 encryption at rest, TLS 1.3 in transit, strict retention and automated purging (&le; 90 days), PII detection/masking, and data steward governance policies. | EU AI Act Art. 10(5) &bull; GDPR Art. 25/32 &bull; NIST GOVERN 1.2 &bull; ISO/IEC 42001 &sect;A.7 |
| **5** | **Human Oversight &amp; Accountability** | Mandatory Human-in-the-Loop (HITL) gates, autonomy level constraints, 24/7 incident escalation SLAs, emergency kill-switches, and tamper-evident audit logging. | EU AI Act Art. 12 &amp; 14 &bull; NIST GOVERN 1.4 &bull; ACM FAccT (2026) |
| **6** | **Safety &amp; Reliability** | Corrupted input rejection, input/output schema validation, safety guardrails (&ge; 3 active), deterministic output bounds clamping, and known failure mode regression suites. | EU AI Act Art. 9 &amp; 15(1) &bull; NIST MANAGE 2.2 &bull; RBAAF Verification |

---

## Mathematical Formulation: Bottleneck Empirical Risk Minimization (AAS)

A simple arithmetic average is dangerous in cybersecurity: an AI system scoring 95% in Transparency and Privacy but **10% in Security** is completely unsafe to deploy.

AI-GRID implements the **Bottleneck-Penalized Empirical Risk Minimization formula**:

$$\text{AAS} = \alpha \cdot \bar{S} + (1 - \alpha) \cdot \min_{d \in \{1 \dots 6\}} S_d \quad (\alpha = 0.60)$$

Where:
- $\bar{S} = \frac{1}{6} \sum_{d=1}^{6} S_d$ is the global weighted average across all 6 dimensions.
- $\min_d S_d$ isolates the **Primary Governance Bottleneck** (weakest constraint).
- Dimension scores incorporate **Multi-Tier Evidence Confidence Weighting**:
  $$S_d = 100 \times \frac{\sum_{i=1}^{n_d} w_i \cdot s_i \cdot w_{\text{evidence}, i}}{\sum_{i=1}^{n_d} w_i \cdot w_{\text{evidence}, i}}$$
  with $w_{\text{evidence}} \in \{1.0 \text{ (T1 Automated Probe)}, 0.8 \text{ (T2 Schema)}, 0.6 \text{ (T3 Self-Report)}\}$.

---

## Empirical Benchmark Datasets Used

AI-GRID executes calculations natively against 3 empirical datasets located in `data/`:

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

## Regulatory Compliance & Threat Engines

* **EU AI Act (Regulation (EU) 2024/1689)**:
  - **Intended Purpose Classification**: Categorized strictly by intended domain (Annex III High-Risk vs Article 5 Prohibited vs Article 50 Limited vs Minimal). The legal risk tier is NEVER derived from audit/AAS scores.
  - **Articles 9–15 Technical Pre-Audit Indicators**: Evaluates empirical technical criteria for risk management, data governance, documentation, logging, transparency, human oversight, and robustness.
  - *Statutory Notice*: Pre-audit indicators do NOT constitute legal advice or formal CE-mark certification by a Notified Body.
* **NIST AI RMF 1.0 (NIST SP 1270)**:
  - Crosswalked across **GOVERN, MAP, MEASURE, MANAGE** lifecycle functions across all 6 dimensions.
* **OWASP &amp; MITRE ATLAS Threat Crosswalk**:
  - Maps identified vulnerabilities to OWASP Top 10 for LLMs, OWASP MCP Top 10, and MITRE ATLAS matrix technique IDs.
* **Model Cards for Model Reporting (Mitchell et al., 2019)**:
  - Exports technical governance passport in Markdown and JSON formats.

---

## Technical Implementation Disclosures & Architecture Integrity

AI-GRID upholds rigorous academic and scientific honesty regarding library usage:

| Capability | Engineering Implementation | Third-Party Library Claim Status |
|:---|:---|:---|
| **MCP Protocol Client** | Official Anthropic Model Context Protocol SDK (`mcp` package) via stdio JSON-RPC transport (`mcp_client.py`). | **Real MCP SDK Integration** |
| **8-Probe Security Suite** | Automated tool discovery, schema inspection, capability analysis, boundary testing, clamping check, metadata extraction, error leakage, and encryption check (`mcp_probes.py`). | **Native Protocol Prober** |
| **Audit Persistence** | Native SQLite ledger (`audit_store.py` -> `data/aigrid_audits.db`) storing complete audit dossiers, evidence items, and findings. | **Built-in `sqlite3`** |
| **Fairness Metrics** | Native computation of Disparate Impact Ratio (DIR) and Statistical Parity Difference (SPD) on UCI Statlog German Credit benchmark (`data/german_credit_fairness.csv`). | **Custom Formulas (Not IBM AIF360)** |
| **Risk Cohort Slicing** | Empirical rule-based classification against Clinical Patient Safety benchmark (`data/clinical_patient_safety.csv`). | **Custom Rule Engine (Not Fairlearn)** |
| **Remediation Ranker** | Ranks findings by severity and bottleneck gap without fabricated score multipliers. | **Empirical Heuristic Ranking** |

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
Open **`http://localhost:8000`** in any web browser.

### Running Test Verification Suite
Execute the full 27-test verification suite (unit tests, MCP protocol tests, security validation, compliance indicators, and empirical experiments):
```bash
python -m pytest tests/ -v
```

### Running Test MCP Demo Servers
AI-GRID includes 3 reproducible demo MCP servers in `demo_servers/` with varying security profiles:
```bash
# Profile: Good (High assurance, schema-validated, input guardrails, output clamped)
python demo_servers/good_server.py

# Profile: Moderate (Partial gaps, missing encryption & human oversight)
python demo_servers/moderate_server.py

# Profile: Poor (Insecure test target, missing validation, unclamped output)
python demo_servers/poor_server.py
```

---

## Research Literature Citations

1. **Pfau, D., &amp; Jung, A. (2026).** *Engineering Trustworthy AI: A Developer Guide for Empirical Risk Minimization.* IEEE Transactions on Artificial Intelligence, 7(5), 2560–2576. DOI: [10.1109/TAI.2025.3617936](https://doi.org/10.1109/TAI.2025.3617936).
2. **Lee, M. S., et al. (2024).** *QB4AIRA: A Question Bank for Responsible AI Risk Assessment.* IEEE Software, 42(3). DOI: [10.1109/MS.2024.3512577](https://doi.org/10.1109/MS.2024.3512577).
3. **Acharya, N., &amp; Gupta, G. K. (2026).** *A Formal Security Framework for MCP-Based AI Agents (MCPSHIELD).* arXiv:2604.05969.
4. **Dhanorkar, S., Passi, S., &amp; Vorvoreanu, M. (2026).** *Human Oversight of Agentic Systems in Practice.* ACM Conference on Fairness, Accountability, and Transparency (FAccT).
5. **Mitchell, M., et al. (2019).** *Model Cards for Model Reporting.* ACM Conference on Fairness, Accountability, and Transparency (FAccT), pp. 220–229.
6. **Kamiran, F., &amp; Calders, T. (2012).** *Data preprocessing techniques for classification without discrimination.* Knowledge and Information Systems, 33(1), 1–33.
