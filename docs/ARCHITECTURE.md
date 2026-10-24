# AI-GRID Architecture & Technical Specification

## 1. System Overview

AI-GRID is a high-assurance AI Governance, Risk, and Compliance (GRC) evaluation control plane.
It provides structured, evidence-based technical assessments grounded in:
- **QB4AIRA Taxonomy** (Lee et al., IEEE Software 2024)
- **EU AI Act** (Regulation (EU) 2024/1689: Articles 9 to 15 & Annex III)
- **NIST AI 100-1** (AI Risk Management Framework 1.0)
- **ISO/IEC 42001** (Artificial Intelligence Management System)

```mermaid
graph TD
    User([User / Compliance Engineer]) -->|Submits 30 Technical Controls| API[/api/audit/questionnaire]
    Presets[(Reference Presets)] -->|Clinical / Financial / Assistant| API
    API --> Auth[API Key Auth & Rate Limiter]
    Auth --> Auditor[AIGRIDAuditor Orchestrator]
    Auditor --> ProfileEngine[AI Profile Engine]
    ProfileEngine --> CompEngines[Compliance & Scoring Engines]
    CompEngines --> Scoring[ERM Bottleneck Scoring AAS]
    CompEngines --> EUAIAct[EU AI Act Annex III & Art. 9-15]
    CompEngines --> NIST[NIST AI 100-1 Crosswalk]
    CompEngines --> Fairness[Fairness & Disparate Impact]
    CompEngines --> VulnScan[CVE / EPSS Registry Scanner]
    CompEngines --> ModelCard[ISO 42001 / Annex IV Dossier]
    Auditor --> SQLite[(SQLite AuditStore)]
    Auditor --> Response([Evaluated Governance Dossier])
    Response --> UI[Web Control Plane UI]
```

---

## 2. Mathematical Scoring Model: Bottleneck ERM

Composite assurance cannot rely on an arithmetic mean because strong pillars mask critical security or safety vulnerabilities.
AI-GRID computes the **Assurance Adequacy Score (AAS)** using a convex combination of the dimension mean $\bar{S}$ and the bottleneck minimum $\min(S)$:

$$\text{AAS}(\alpha) = \alpha \cdot \bar{S} + (1 - \alpha) \cdot \min_{d \in \{1 \dots 6\}} S_d$$

- **Default Parameter**: $\alpha = 0.60$ (Balances systemic maturity with single-point failure safeguarding).
- **Dimension Score Formulation**:
  $$S_d = 100 \times \frac{\sum_{i=1}^{n_d} w_i \cdot s_i \cdot w_{\text{evidence}, i}}{\sum_{i=1}^{n_d} w_i \cdot w_{\text{evidence}, i}}$$
  where $w_{\text{evidence}} = 0.60$ for self-attested questionnaire items.

---

## 3. Persistence Layer (`audit_store.py`)

All audits are persisted to a local SQLite database (`data/aigrid_audits.db`).

### Schema Definition:
- **`audits`**: Stores audit execution metadata, timestamps, model identity, AAS scores, trust grade, bottleneck dimension, and serialized JSON dossier.
- **`audit_evidence`**: Normalized structured evidence items with provenance tracking.
- **`audit_findings`**: Specific vulnerability findings with priority, regulatory references, and remediation actions.

---

## 4. Security Architecture

1. **API Key Authentication**: Write endpoints (`/api/audit/*`, `/api/audit/reset`) enforce `X-API-Key` validation.
2. **Rate Limiting**: Sliding window in-memory rate limiter per client identifier (`is_rate_limited`).
3. **Payload Sanitization & XSS Defense**: Strict HTML escaping on frontend rendering (`escapeHtml()`) for all dynamic messages, findings, and logs.
4. **No Arbitrary Subprocess Execution**: Removed all runtime subprocess and command execution mechanisms.
