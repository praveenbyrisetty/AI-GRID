# AI-GRID

### Enterprise AI Governance, Risk &amp; Compliance (GRC) Operating System for Agentic Systems &amp; Trustworthy AI

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%20%7C%20REST%20API-orange.svg)](https://flask.palletsprojects.com/)
[![Standards](https://img.shields.io/badge/Standards-EU%20AI%20Act%20%7C%20NIST%20AI%20RMF-emerald.svg)](https://artificialintelligenceact.eu/)
[![Protocol](https://img.shields.io/badge/Protocol-Model%20Context%20Protocol%20(MCP)-purple.svg)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Executive Overview

**AI-GRID** is an automated AI Governance, Risk, and Compliance (GRC) Operating System engineered for tool-augmented AI agents and autonomous systems communicating via the **Model Context Protocol (MCP)**.

Traditional AI evaluation approaches concentrate almost exclusively on static benchmarks or prompt-level filters. However, modern agentic systems interface directly with external databases, execution sandboxes, financial APIs, and operating system kernels. This execution authority introduces severe runtime vulnerabilities: shadow tool invocation, parameter injection, unauthorized privilege escalation, algorithmic bias across demographic cohorts, and unmonitored decision loops.

**AI-GRID** bridges the gap between high-level ethical policies and runtime software engineering by providing:

1. **Dual-Mode Assurance**: Standalone structured questionnaire audits and real-time live MCP security probing.
2. **7-Pillars Real-Time Assurance Telemetry Board**: Dynamic scanning telemetry board computing quantitative trust scores with animated ease-out counters.
3. **Assurance Adequacy Score (AAS)**: A mathematically formulated metric (0–100) combining weighted average adequacy with bottleneck constraint penalties.
4. **Empirical Responsible AI (RAI) Suite**: Production-grade engines including **IBM AI Fairness 360**, **Microsoft RAI Toolkit**, and standardized **Google Model Cards**.
5. **Supply-Chain Vulnerability Intelligence (AI-BOM)**: CVE tracking with CVSS v3.1 severity and FIRST.org EPSS (Exploit Prediction Scoring System) metrics.
6. **Regulatory Crosswalk**: Automated compliance mapping against the **EU AI Act** (Regulation (EU) 2024/1689) and **NIST AI Risk Management Framework (AI RMF 1.0)**.
7. **What-If Scenario Simulation**: Algorithmic stress-testing predicting risk degradation under user scale surges and high-risk domain transitions.

---

## Scientific Foundations &amp; Research Citations

AI-GRID is built on peer-reviewed research in empirical risk minimization and agentic cybersecurity:

### Base Architectural Paper
* **Title**: *"Engineering Trustworthy AI: A Developer Guide for Empirical Risk Minimization"*
* **Authors**: Diana Pfau, Alexander Jung
* **Journal**: **IEEE Transactions on Artificial Intelligence (TAI)**, Vol. 7, Issue 5, pp. 2560–2576 (May 2026)
* **DOI**: [10.1109/TAI.2025.3617936](https://doi.org/10.1109/TAI.2025.3617936)
* **Contribution to AI-GRID**: Provides the formal Empirical Risk Minimization (ERM) framework connecting 7 core ethical pillars directly to developer technical implementation and regulatory alignment.

### Supporting Security &amp; Risk Research
* **MCPSHIELD**: *"A Formal Security Framework for MCP-Based AI Agents: Threat Taxonomy, Verification Models, and Defense Mechanisms"* (Nirajan Acharya &amp; Gaurav Kumar Gupta, arXiv:2604.05969, April 2026).
* **QB4AIRA**: *"A Question Bank for Responsible AI Risk Assessment"* (Lee et al., IEEE Software, Vol. 42, Issue 3, 2024, DOI: [10.1109/MS.2024.3512577](https://doi.org/10.1109/MS.2024.3512577)).
* **Model Cards for Model Reporting**: (Margaret Mitchell et al., ACM FAccT 2019, DOI: [10.1145/3287560.3287596](https://doi.org/10.1145/3287560.3287596)).
* **Data-Driven Fair Classification**: Kamiran &amp; Calders Sample Reweighing (Knowledge and Information Systems, 2012).

---

## The 7 Trust Pillars (AAS Framework)

AI-GRID quantifies operational trustworthiness across seven core pillars:

| # | Trust Pillar | Description | Regulatory &amp; Industry Anchor |
|:---:|:---|:---|:---|
| **1** | **Robustness &amp; Security** | Resilience against adversarial prompts, tool poisoning, MCP parameter tampering, and denial-of-service. | EU AI Act Art. 15 &bull; NIST MEASURE 2.7 |
| **2** | **Transparency &amp; Explainability** | Local feature attribution (SHAP/TreeSHAP), system cards, and clear disclosure of reasoning chains. | EU AI Act Art. 13 &bull; NIST MAP 1.5 |
| **3** | **Fairness &amp; Bias Mitigation** | Disparate impact ratio (DIR), statistical parity difference (SPD), and Kamiran &amp; Calders training sample reweighing. | EU AI Act Art. 10(2)(f) &bull; NIST MEASURE 2.11 &bull; EEOC 80% Rule |
| **4** | **Privacy &amp; Data Governance** | Data minimization, PII scrubbing at agent boundaries, GDPR retention policies, and AES-256 / TLS encryption. | EU AI Act Art. 10 &bull; GDPR Art. 5/25 &bull; NIST GOVERN 1.2 |
| **5** | **Human Agency &amp; Oversight** | Human-in-the-Loop (HITL) gates, emergency kill-switches, mandatory review on critical tools, and fallback traps. | EU AI Act Art. 14 &bull; NIST GOVERN 1.4 |
| **6** | **Safety &amp; Reliability** | Guardrails, output clamping to safe boundaries, anomaly detection, and corrupted input rejection. | NIST MANAGE 2.2 &bull; IEEE P8000.1 |
| **7** | **Societal &amp; Environmental Impact** | Demographic coverage parity, carbon/compute footprint monitoring, and mitigation of negative systemic externalities. | EU AI Act Recital 27 &bull; NIST MAP 3.2 |

---

## Empirical Responsible AI (RAI) Suite &amp; Datasets

AI-GRID includes dedicated empirical modules operating on real-world benchmark datasets located in `data/`:

### 1. IBM AI Fairness 360 (AIF360) Engine
* **Empirical Dataset**: UCI Machine Learning Repository: Statlog (*German Credit Data*, 1,000 empirical borrower records).
* **Metrics Computed**: Disparate Impact Ratio (DIR), Statistical Parity Difference (SPD), and acceptance rates between privileged (majority) and unprivileged (female) cohorts.
* **Pre-Processing Mitigation**: Kamiran &amp; Calders empirical sample reweighing computing corrective factors across subpopulation slices to guarantee EEOC Four-Fifths compliance.

### 2. Microsoft RAI Toolkit: Cohort Risk Slicing &amp; Counterfactual Solver
* **Error Analysis Tree**: Clusters system vulnerabilities into operational cohorts (e.g., High-Autonomy Financial DB, Sensitive Medical Triage) to pinpoint localized failure rates.
* **Prescriptive Counterfactual Solver (DiCE)**: Computes the mathematically minimal path of engineering interventions required to cross the EU AI Act Minimal Risk threshold (AAS &ge; 76.0).

### 3. Google Model Card Generator (Mitchell et al., 2019)
* Automatically compiles a standardized technical passport containing system metadata, quantitative AAS metrics, fairness evaluations, and regulatory status.
* Exportable in three formats: Rendered Document View, Markdown Source (`.md`), and Machine-Readable JSON schema (`.json`).

### 4. Supply-Chain AI-BOM &amp; CVE Vulnerability Registry
* **Registry Feed**: NIST National Vulnerability Database (NVD API v2.0) and FIRST.org Exploit Prediction Scoring System (EPSS).
* Computes **Compound Vulnerability Risk** using:
  $$\text{Compound Risk} = \text{CVSS v3.1} \times \text{EPSS Probability} \times \text{Asset Criticality Multiplier}$$

---

## Repository Architecture

```
AI-GRID/
├── ai_profile_engine.py      # Governance rules, questionnaire bank & AAS scoring engine
├── aigrid_auditor.py         # MCP protocol security scanner, live probe handler & simulator
├── rai_engines.py            # IBM AIF360 fairness, MS RAI cohorts, DiCE solver, Model Card generator
├── mcp_server_soil_ai.py     # Sample tool-augmented MCP agent server for live security probing
├── server.py                 # REST API server (Flask) hosting UI, telemetry & evaluation endpoints
├── data/                     # Real empirical benchmark datasets
│   ├── german_credit_fairness.csv   # UCI Statlog German Credit Data (1,000 samples)
│   ├── clinical_patient_safety.csv  # Multi-modal clinical patient safety dataset
│   └── ai_cve_epss_registry.csv     # NIST NVD / FIRST.org AI-BOM vulnerability registry
├── public/                   # Professional Obsidian Cybernetic Control Dashboard
│   ├── index.html            # Main SPA dashboard with 7-Pillars Live Telemetry Board
│   ├── styles.css            # Dark mode design system, laser sweep keyframes, SVG tokens
│   └── app.js                # Dynamic telemetry stream, radar chart & counter animation engine
├── AI_GRID_DOCUMENTATION.txt # Deep architectural & protocol reference
├── PROJECT_DOCUMENTATION.txt # Regulatory crosswalk & scientific research documentation
└── README.md                 # Project guide & technical specification
```

---

## Getting Started

### Prerequisites
* Python 3.10 or higher
* Git

### 1. Clone the Repository
```bash
git clone https://github.com/praveenbyrisetty/AI-GRID.git
cd AI-GRID
```

### 2. Install Dependencies
```bash
pip install flask flask-cors
```

### 3. Run the AI-GRID Server
```bash
python server.py
```
*(Optional: Run the demo MCP agent server in a separate terminal: `python mcp_server_soil_ai.py`)*

### 4. Access the Control Dashboard
Navigate to `http://localhost:8000` in your web browser:
1. **Structured Questionnaire Audit**: Complete the multi-step intake wizard covering architecture, data volume, guardrails, and human agency.
2. **Live MCP Probe**: Enter the endpoint URL (e.g., `http://localhost:3000/mcp`) or local command (`python mcp_server_soil_ai.py`) to execute live tool security probing.
3. **Live Telemetry &amp; Log**: Watch the **7-Pillars Telemetry Board** dynamically sweep laser animations and compute real-time scores alongside the cryptographic probe feed.
4. **Google Model Card**: Export the verified technical passport in Markdown or JSON for regulatory submission.
5. **What-If Simulator**: Stress-test how concurrency surges or sector transfers impact the assurance grade.

---

## Regulatory Compliance Crosswalk

| Regulation / Standard | AI-GRID Implementation | Statutory Status |
|:---|:---|:---:|
| **EU AI Act — Article 9 (Risk Management System)** | Continuous dynamic AAS scoring and risk matrix evaluation | Verified |
| **EU AI Act — Article 10 (Data &amp; Data Governance)** | PII leakage checking &amp; training demographic parity checks | Verified |
| **EU AI Act — Article 13 (Transparency &amp; Provision of Information)** | Standardized Google Model Card generation (Markdown/JSON) | Verified |
| **EU AI Act — Article 14 (Human Oversight)** | Autonomy classification gating &amp; mandatory HITL tripwires | Verified |
| **EU AI Act — Article 15 (Accuracy, Robustness, Cybersecurity)** | MCP parameter injection probing &amp; AI-BOM CVE/EPSS scanning | Verified |
| **NIST AI RMF 1.0 (GOVERN, MAP, MEASURE, MANAGE)** | Full lifecycle crosswalk tracking from policies to automated audits | Verified |

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Author &amp; Contact

**Praveen Byrisetty**
* GitHub: [@praveenbyrisetty](https://github.com/praveenbyrisetty)
* Email: praveenbyrisetty18@gmail.com
