# AI-GRID

### AI-Powered Governance, Risk & Compliance (GRC) Intelligence Dashboard for Agentic Systems & Trustworthy AI

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%20%7C%20REST%20API-orange.svg)](https://flask.palletsprojects.com/)
[![Standards](https://img.shields.io/badge/Standards-EU%20AI%20Act%20%7C%20NIST%20AI%20RMF-emerald.svg)](https://artificialintelligenceact.eu/)
[![Protocol](https://img.shields.io/badge/Protocol-Model%20Context%20Protocol%20(MCP)-purple.svg)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📌 Overview

**AI-GRID** is an automated security scanner, empirical trust evaluator, and regulatory compliance pre-audit engine engineered for tool-augmented AI agents and systems interacting via the **Model Context Protocol (MCP)**.

While legacy machine learning evaluation focuses primarily on static benchmark metrics or basic text generation guards, modern agentic systems interface directly with external APIs, enterprise databases, code executors, and physical actuators. This real-world execution capability introduces severe security vulnerabilities—such as shadow tool execution, prompt/parameter injection, privilege escalation, and unvetted autonomous action loops.

**AI-GRID** bridges the gap between high-level ethical principles and technical system implementation by providing:
1. **Dual Evaluation Modes**: Dynamic interactive risk profiling questionnaire & live MCP security probing.
2. **Quantitative Trust Scoring**: A rigorous **Assurance Adequacy Score (AAS)** computed across 7 holistic trust dimensions.
3. **Regulatory Crosswalk**: Automated compliance mapping against the **EU AI Act** (Regulation (EU) 2024/1689) and **NIST AI Risk Management Framework (AI RMF 1.0)**.
4. **What-If Risk Simulator**: Interactive stress-testing simulating user scale surges and domain-specific regulatory exposures.

---

## 🏛️ Scientific Foundations & Research Base

AI-GRID is built upon cutting-edge research in responsible AI and agentic security:

### 🏆 Base Research Paper
- **Title**: *"Engineering Trustworthy AI: A Developer Guide for Empirical Risk Minimization"*
- **Authors**: Diana Pfau, Alexander Jung
- **Journal**: **IEEE Transactions on Artificial Intelligence (TAI)**, Vol. 7, Issue 5, pp. 2560–2576 (May 2026)
- **DOI**: [10.1109/TAI.2025.3617936](https://doi.org/10.1109/TAI.2025.3617936)
- **Contribution to AI-GRID**: Provides the formal Empirical Risk Minimization (ERM) framework connecting 7 core ethical pillars directly to developer technical implementation and regulatory alignment.

### 🛡️ Core Supporting Security Research
- **MCPSHIELD**: *"A Formal Security Framework for MCP-Based AI Agents: Threat Taxonomy, Verification Models, and Defense Mechanisms"* (Nirajan Acharya & Gaurav Kumar Gupta, arXiv:2604.05969, April 2026).
- **QB4AIRA**: *"A Question Bank for Responsible AI Risk Assessment"* (Lee et al., IEEE Software, Vol. 42, Issue 3, 2024, DOI: [10.1109/MS.2024.3512577](https://doi.org/10.1109/MS.2024.3512577)).

---

## 🛡️ The 7 Trust Dimensions (AAS Framework)

AI-GRID quantifies trustworthiness across seven fundamental dimensions:

| Dimension | Description | Regulatory Anchor |
|:---|:---|:---|
| **1. Robustness & Security** | Resilience against adversarial prompts, tool poisoning, MCP parameter tampering, and denial-of-service. | EU AI Act Art. 15, NIST MEASURE 2.7 |
| **2. Transparency & Explainability** | Model explainability (SHAP, LIME, feature attribution), system cards, and clear disclosure of AI capabilities. | EU AI Act Art. 13, NIST MAP 1.5 |
| **3. Fairness & Bias Mitigation** | Disparate impact auditing, protected attribute protection, and demographic parity checks across tool calls. | EU AI Act Art. 10(2)(f), NIST MEASURE 2.11 |
| **4. Privacy & Data Governance** | Data minimization, PII scrubbing at agent boundaries, GDPR compliance, and secure context caching. | EU AI Act Art. 10, GDPR Art. 5/25 |
| **5. Human Agency & Oversight** | Human-in-the-Loop (HITL) kill switches, mandatory human approval for critical tool invocations, and escalation paths. | EU AI Act Art. 14, NIST GOVERN 1.4 |
| **6. Accountability & Traceability** | Immutable audit trails, cryptographic logging of tool inputs/outputs, and reproducibility verification. | EU AI Act Art. 12, NIST MANAGE 1.3 |
| **7. Societal & Environmental Well-being** | Compute footprint monitoring, alignment with ethical constraints, and mitigation of negative systemic externalities. | EU AI Act Recital 27, NIST MAP 3.2 |

---

## ⚡ Key Features

- **Dynamic Interactive Audit Wizard**: Multi-step risk evaluation capturing AI system domain, autonomy level, deployment scale, and safeguard maturity.
- **MCP Live Audit Engine**: Real-time probing of Model Context Protocol endpoints (SSE / STDIO) checking for unvalidated parameters, toxic tool descriptions, and shadow endpoints.
- **Assurance Adequacy Score (AAS)**: Mathematically formulated metric (0–100) providing executive-ready governance posture.
- **Regulatory Gap Analysis**: Pinpoints exact non-compliance risks under EU AI Act High-Risk requirements (Articles 9, 10, 13, 14, 15) and NIST AI RMF core functions (*GOVERN, MAP, MEASURE, MANAGE*).
- **What-If Scenario Simulation**: Dynamically tests how risk scores degrade as user concurrency climbs from 1,000 to 1,000,000+ or when deploying in regulated domains (Healthcare, FinTech, Critical Infrastructure).
- **Modern Glassmorphic UI**: High-fidelity dark mode dashboard with interactive charts, real-time gauges, and printable pre-audit compliance summaries.

---

## 📂 Project Architecture

```
AI-GRID/
├── ai_profile_engine.py      # Core governance rules, questionnaire bank & scoring formulas
├── aigrid_auditor.py         # MCP security auditor, live probe handler & simulation engine
├── server.py                 # REST API server (Flask) serving web UI & audit endpoints
├── public/                   # Modern Glassmorphic Web Dashboard
│   ├── index.html            # Main single-page application & wizard UI
│   ├── styles.css            # Dark mode design system, tokens & animations
│   └── app.js                # Dynamic dashboard logic, API integration & state management
├── AI_GRID_DOCUMENTATION.txt # Detailed architectural and protocol documentation
├── PROJECT_DOCUMENTATION.txt # Deep dive into regulatory crosswalk & research foundations
└── README.md                 # Project documentation and setup guide
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- Git

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

### 4. Open the Web Dashboard
Navigate to `http://localhost:8000` in your web browser.
- Select **Questionnaire Mode** to conduct an end-to-end 7-dimension governance assessment.
- Select **MCP Live Audit** to connect to an active Model Context Protocol server endpoint.
- Use the **What-If Simulator** to stress-test your system's risk posture under different deployment profiles.

---

## ⚖️ Regulatory Compliance Matrix

| Regulation / Standard | AI-GRID Implementation | Status |
|:---|:---|:---:|
| **EU AI Act — Article 9 (Risk Management)** | Continuous dynamic AAS scoring and risk matrix evaluation | ✅ Implemented |
| **EU AI Act — Article 10 (Data & Data Governance)** | PII leakage checking & training data bias assessment | ✅ Implemented |
| **EU AI Act — Article 13 (Transparency)** | Model cards, prompt-to-tool flow logging & system clarity index | ✅ Implemented |
| **EU AI Act — Article 14 (Human Oversight)** | Autonomy tier gating, HITL approval enforcement on critical tools | ✅ Implemented |
| **EU AI Act — Article 15 (Accuracy, Robustness, Cybersecurity)** | MCP parameter fuzzing, tool poisoning defense & MCPSHIELD checks | ✅ Implemented |
| **NIST AI RMF 1.0 (GOVERN, MAP, MEASURE, MANAGE)** | Full lifecycle tracking from organizational policies to automated audits | ✅ Implemented |

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author & Contact

**Praveen Byrisetty**
- GitHub: [@praveenbyrisetty](https://github.com/praveenbyrisetty)
- Email: praveenbyrisetty18@gmail.com
