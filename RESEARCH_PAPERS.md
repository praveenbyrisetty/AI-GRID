# 📚 Research Foundations & 2026 Literature Base

This document catalogs the verified scientific papers, IEEE publications, and technical literature underpinning the **AI-GRID** governance and security framework.

---

## 🏆 RECOMMENDED BASE PAPER (2026) — IEEE (Implementation Paper)

### **"Engineering Trustworthy AI: A Developer Guide for Empirical Risk Minimization"**

| Field | Details |
|:------|:--------|
| **Authors** | Diana Pfau, Alexander Jung |
| **Journal** | **IEEE Transactions on Artificial Intelligence (TAI)** — *Premier IEEE Journal* |
| **Volume/Pages** | Volume 7, Issue 5, pp. 2560–2576 |
| **Date** | **May 2026** |
| **DOI** | [10.1109/TAI.2025.3617936](https://doi.org/10.1109/TAI.2025.3617936) |
| **Publisher** | **IEEE** |
| **Paper Type** | ⚙️ **Implementation / Developer Guide** (NOT a survey) |

### Why This Is the Best 2026 Base Paper for AI-GRID

| AI-GRID Feature | How This Paper Supports It |
|:----------------|:---------------------------|
| **7-Dimension Trust Framework** | Maps **7 key trustworthy AI requirements** (Robustness, Safety, Transparency, Privacy, Governance, Human Agency, Nondiscrimination) directly to implementation design choices — this is the **exact same 7-pillar structure** as your AI-GRID |
| **Quantitative Scoring (AAS)** | Provides an **Empirical Risk Minimization (ERM)** mathematical framework for quantifying AI trustworthiness — directly parallels your AAS formula's weighted scoring |
| **EU AI Act Compliance** | Explicitly maps technical design choices to **EU AI Act legislative requirements and GDPR** — directly supports your regulatory compliance engine |
| **Implementation Focus** | Bridges the gap between **high-level ethics principles → concrete technical implementation** — this is exactly what your `ai_profile_engine.py` questionnaire logic does |
| **Human Oversight** | Emphasizes **"human agency and oversight"** to prevent uncontrolled AI decisions — directly maps to your Accountability & Oversight dimension |
| **Interdisciplinary Approach** | Requires collaboration between **developers, legal experts, and ethicists** for use-case-specific assessment — matches your dual-mode (Questionnaire + MCP Audit) design philosophy |

---

## 📖 15 SUPPORTING PAPERS (ALL 2026)

---

### Category 1: MCP & Agentic AI Security

#### Paper 1: MCPSHIELD — Formal Security Framework for MCP
| Field | Details |
|:------|:--------|
| **Title** | "A Formal Security Framework for MCP-Based AI Agents: Threat Taxonomy, Verification Models, and Defense Mechanisms" |
| **Authors** | Nirajan Acharya, Gaurav Kumar Gupta |
| **Source** | **arXiv:2604.05969** (April 7, 2026) |
| **Relevance** | 🎯 Introduces MCPSHIELD — 7 threat categories, 23 attack vectors across 4 attack surfaces from analysis of 177,000+ MCP tools. Proposes defense-in-depth architecture with 91% threat coverage. Directly maps to your MCP live audit mode. |

#### Paper 2: Agentic AI Framework for Intrusion Detection (AAIF)
| Field | Details |
|:------|:--------|
| **Title** | "The Agentic AI Framework (AAIF): A Policy-Enforced Architecture for Accountable and High-Performance Intrusion Detection" |
| **Authors** | Ibrahim Adabara, Bashir Olaniyi Sadiq, et al. |
| **Source** | **Frontiers in Artificial Intelligence**, Vol. 9, DOI: [10.3389/frai.2026.1755696](https://doi.org/10.3389/frai.2026.1755696) |
| **Relevance** | 🎯 Policy-enforced architecture using **declarative YAML-based governance** for AI agent auditability, aligned with **NIST AI RMF 2.0**. |

#### Paper 3: SoK — Systems Security for Agentic Computing
| Field | Details |
|:------|:--------|
| **Title** | "SoK: Systems Security Foundations for Agentic Computing" |
| **Authors** | Google Research team |
| **Source** | **Google Research / arXiv:2512.01295** |
| **Relevance** | 🎯 Argues that **hardening a single AI model is insufficient** — advocates end-to-end systems security for agent-tool interactions with 11 attack case studies. Directly supports AI-GRID's approach of probing the **MCP security boundary**. |

#### Paper 4: Agentic AI and Cybersecurity — Survey
| Field | Details |
|:------|:--------|
| **Title** | "A Survey of Agentic AI and Cybersecurity: Challenges, Opportunities and Use-case Prototypes" |
| **Source** | **arXiv:2601.05293** (January 2026) |
| **Relevance** | 🎯 Maps **agent collusion, memory poisoning, oversight evasion** threats — directly relevant to your Security & Robustness dimension and tool-poisoning detection. |

---

### Category 2: EU AI Act & Regulatory Compliance

#### Paper 5: EU AI Act Governance-to-Controls Framework
| Field | Details |
|:------|:--------|
| **Title** | "From the EU AI Act to Audit Practice: A Governance-to-Controls Framework for Quality Management and Evidence" |
| **Authors** | János Kálmán |
| **Source** | **MDPI Accounting and Auditing**, Vol. 2, Issue 3, DOI: [10.3390/accountaudit2030012](https://doi.org/10.3390/accountaudit2030012) |
| **Relevance** | 🎯 Provides a **traceable crosswalk** between EU AI Act requirements and audit controls with maturity models and documentation checklists (Articles 9, 10, 13, 14, 15). |

#### Paper 6: AI Agents Under EU Law — Compliance Architecture
| Field | Details |
|:------|:--------|
| **Title** | "AI Agents Under EU Law: A Compliance Architecture for AI Providers" |
| **Authors** | Luca Nannini et al. |
| **Source** | **arXiv Working Paper** (April 2026) |
| **Relevance** | 🎯 Proposes a **12-step compliance architecture** integrating EU AI Act + GDPR + Cyber Resilience Act + Data Act for autonomous agents. |

#### Paper 7: Automated Ontology-Based Regulatory Compliance
| Field | Details |
|:------|:--------|
| **Title** | "Automated Regulatory Compliance for AI Systems in the Security Domain: The Case of Dual-Use Deployment" |
| **Authors** | Giedrė Sabaliauskaitė, Richard Paskauskas, et al. |
| **Source** | **Open Research Europe**, Vol. 6, Article 83 (2026) |
| **Relevance** | 🎯 Uses **RDF/Turtle knowledge graphs and SPARQL-based semantic reasoning** for executable compliance modeling with SHACL validation. |

---

### Category 3: Fairness, Bias & Explainability

#### Paper 8: Trustworthy AI — Invariance Conflicts & Causality
| Field | Details |
|:------|:--------|
| **Title** | "Trustworthy AI Suffers from Invariance Conflicts and Causality is The Solution" |
| **Source** | **ICML 2026**, arXiv: [2605.02640](https://arxiv.org/abs/2605.02640) |
| **Relevance** | 🎯 Resolves **trade-offs between fairness, robustness, privacy, and explainability** using causal inference. |

#### Paper 9: Structural Concentration in AI Bias Research
| Field | Details |
|:------|:--------|
| **Title** | "Whose Fairness? Structural Concentration in AI Bias Research" |
| **Source** | **arXiv:2607.05574** (July 2026) |
| **Relevance** | 🎯 Analyzes concentration of fairness research across domains — justifies AI-GRID's multi-domain evaluation approach. |

#### Paper 10: Actionable AI Fairness Practices
| Field | Details |
|:------|:--------|
| **Title** | "Moving Beyond Principles: Identifying Actionable AI Fairness Practices" |
| **Authors** | Christoph Burtscher, Mateusz Dolata |
| **Source** | **ECIS 2026** (34th European Conference on Information Systems) |
| **Relevance** | 🎯 Operationalized frameworks across the AI lifecycle using a modular governance scaffold. |

---

### Category 4: Privacy, Data Governance & Human Oversight

#### Paper 11: Differential Privacy in Generative AI Agents
| Field | Details |
|:------|:--------|
| **Title** | "Differential Privacy in Generative AI Agents: Analysis and Optimal Tradeoffs" |
| **Source** | **arXiv:2603.17902** (March 2026) |
| **Relevance** | 🎯 Token-level and message-level differential privacy for AI agents with privacy leakage bounds. |

#### Paper 12: Human Oversight of Agentic Systems in Practice
| Field | Details |
|:------|:--------|
| **Title** | "Human Oversight of Agentic Systems in Practice" |
| **Authors** | Dhanorkar, Passi, Vorvoreanu |
| **Source** | **ACM FAccT 2026 / arXiv:2606.05391** |
| **Relevance** | 🎯 Identifies **4 forms of oversight**: a priori control, co-planning, real-time monitoring, post-hoc review. |

---

### Category 5: AI Risk Quantification & Scoring

#### Paper 13: MIRAI — Multi-Dimensional Integrity & Responsibility Index
| Field | Details |
|:------|:--------|
| **Title** | "Multi-Dimensional Model Integrity and Responsibility Assessment Index and Scoring Framework" |
| **Source** | **PMLR Vol. 318**, pp. 1175–1180 (Canadian AI 2026) |
| **Relevance** | 🎯 Unified framework measuring models across 5 dimensions aggregated into a single composite score. |

#### Paper 14: Prioritization of Risks from AI
| Field | Details |
|:------|:--------|
| **Title** | "Prioritization of Risks from Artificial Intelligence: A Delphi Study of 272 International Experts" |
| **Source** | **Patterns (Cell Press)**, DOI: [10.1016/j.patter.2026.101517](https://doi.org/10.1016/j.patter.2026.101517) |
| **Relevance** | 🎯 Risk prioritization methodology directly supporting AI-GRID's remediation roadmap ranking. |

#### Paper 15: Adversarial Robustness — AAJR for Agentic Systems
| Field | Details |
|:------|:--------|
| **Title** | "Adversarial-Aligned Jacobian Regularization: A Structural Theory for Agentic Robustness" |
| **Source** | **arXiv:2603.04378** (March 2026) |
| **Relevance** | 🎯 Structural robustness theory for decoupling stability from expressivity in agentic systems. |

---

## 📊 Paper-to-Dimension Mapping

| AI-GRID Dimension | 2026 Papers |
|:---|:---|
| **Fairness & Bias** | Paper 8 (ICML), Paper 9 (arXiv), Paper 10 (ECIS) |
| **Transparency & Explainability** | Paper 8 (ICML), Paper 13 (MIRAI) |
| **Safety & Reliability** | Base Paper (IEEE TAI), Paper 15 (AAJR) |
| **Privacy & Data Governance** | Paper 11 (Differential Privacy), Paper 6 (EU Law) |
| **Accountability & Oversight** | Paper 12 (ACM FAccT), Paper 5 (MDPI) |
| **Security & Robustness** | Paper 1 (MCPSHIELD), Paper 3 (Google SoK), Paper 4 (arXiv), Paper 15 (AAJR) |
| **Societal Impact** | Paper 14 (Patterns), Paper 9 (arXiv) |
| **MCP Agent Security** | Paper 1 (MCPSHIELD), Paper 3 (Google SoK), Paper 4 (arXiv) |
| **EU AI Act Compliance** | Paper 5 (MDPI), Paper 6 (arXiv), Paper 7 (ORE) |
| **NIST AI RMF** | Paper 2 (Frontiers AAIF), Base Paper (IEEE TAI) |
