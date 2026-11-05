# Changelog

All notable changes to the **AI-GRID** platform are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [5.0.0] - 2026-11-05

### Empirical Evidence Verification & Attestation Gap Engine (Phase 6)
- **Empirical Verifiers Module (`verifiers.py`)**: Added 5 dedicated verification modules with REST endpoints (`POST /api/verify/<module>`):
  - **Fairness (`/api/verify/fairness`)**: Computes Disparate Impact Ratio (DIR), Statistical Parity Difference (SPD), and Equal Opportunity Difference (EOD) on uploaded predictions CSVs to verify `q10_fairness_audit`.
  - **Dependencies (`/api/verify/dependencies`)**: Queries the public OSV API (`api.osv.dev`, PyPI ecosystem, `urllib` only) with a 5-second timeout and up to 200 packages to verify `q3_aibom_inventory`. Gracefully handles offline states by preserving claimed scores.
  - **TLS Prober (`/api/verify/tls`)**: Probes host and port (443/8443) for TLS 1.3/1.2 negotiation and certificate validity with 5-second socket timeout and strict SSRF defenses to verify `q17_encryption_transit`.
  - **Log Integrity (`/api/verify/log-integrity`)**: Cryptographically validates SHA-256 hash chains from genesis in uploaded JSONL logs to verify `q27_tamper_evident_logs`.
  - **Adversarial Robustness (`/api/verify/robustness`)**: Measures accuracy drop between baseline and perturbed prediction CSVs to verify `q1_adversarial_testing`.
- **Multi-Tier Evidence Weighting**: Upgraded dimension score computation in `ai_profile_engine.py` to weight Tier T1 verified artifacts at $w=1.0$ and Tier T3 self-attested items at $w=0.6$.
- **Attestation Gap Analysis**: Computed dimension-level ($\Delta_d = S_{d,\text{claimed}} - S_{d,\text{verified}}$) and composite AAS gaps ($\Delta_{\text{AAS}} = \text{AAS}_{\text{claimed}} - \text{AAS}_{\text{verified}}$) to expose and prevent governance over-claiming.
- **Verification UI**: Added dedicated "Evidence Verification (T1)" page (`#page-verify`) with card uploaders, real-time result inspector, active badge count, and integrated audit compiler.

### Complete Elimination of Datasets & Static Registries (Phases 1-3 Override)
- **Removed All Bundled Datasets**: Deleted `data/` folder from repository.
- **Removed Static Lookups**: Deleted all mock loaders, baseline functions, and path constants from `compliance_engines.py` and `server.py`.
- **Isolated SQLite Storage**: Migrated SQLite database location to `instance/aigrid_audits.db`.

### Regulatory Crosswalk Wiring Fixes (Phase 5)
- **EU AI Act Accountability Wiring**: Connected Article 12 (record-keeping/logging) directly to the Accountability & Governance score; wired Article 11 (technical documentation) to $\text{mean}(S_{\text{Transparency}}, S_{\text{Accountability}})$.
- **NIST AI RMF 1.0 Wiring**: Included `acct_score` in the composite GOVERN function average; wired GOVERN 2.1, MEASURE 2.5, and MANAGE 4.1 to `acct_score`.
- **Removed Deprecated Labels**: Eliminated legacy fallbacks to "Human Oversight & Accountability".

### Security & Deployment Modernization (Phase 4)
- **Unauthenticated Local/Demo Deployment**: Removed API key generation, cookie handling, session tokens, and client token storage in `public/app.js` and `server.py`.
- **Upload Constraints**: Enforced 2 MB maximum request size (`MAX_CONTENT_LENGTH`) and whitelisted file extensions (`.csv`, `.json`, `.txt`, `.jsonl`).
- **Data Leakage Mitigation**: Sanitized audit history endpoints (`/api/audit/history` and `/api/audit/<id>`) to return metadata summaries only, withholding stored raw questionnaire answers.

### Codebase Hygiene & Removal of Dead Code (Phase 3)
- **Removed Deprecated MCP Endpoints**: Purged 410 dead routes (`/api/audit/mcp`, `/api/audit/compare`), `AIGRIDMCPAuditor`, and `owasp_mcp_top_10` aliases.
- **Removed Dead Risk Cohort & Scan Artifacts**: Removed `solve_prescriptive_counterfactual`, `analyze_risk_cohorts()`, and `/api/security/cve-scan`.
- **Unified AAS Implementation**: Standardized composite scoring on `ai_profile_engine.compute_aas_and_bottleneck`, eliminating duplicate logic in `evidence.py`.
- **Scrubbed Unverified Citations**: Replaced speculative or unverified references across question bank with verified sources (Mitchell et al. 2019, NIST AI 100-1, ISO/IEC 42001, EU AI Act).

---

## [4.0.0] - 2026-10-23

### Architecture Evolution: Pure Questionnaire AI Governance Engine
- **Removed MCP Probing Engine**: Completely retired Model Context Protocol (MCP) runtime prober (`mcp_client.py`, `mcp_probes.py`, `demo_servers/`), removing external process spawning and protocol socket overhead.
- **Pure Questionnaire-Based Governance**: Re-centered AI-GRID exclusively around the 35-item technical control question bank (5 per dimension across 7 canonical trust dimensions) grounded in QB4AIRA (Lee et al., 2024), EU AI Act Regulation (EU) 2024/1689 Articles 9–15, and NIST AI 100-1.
- **Deprecated Endpoints**: Updated `/api/audit/mcp` and `/api/audit/compare` to return `410 Gone` with clear deprecation notices.

### Elimination of Synthetic Data & Invented Claims
- **Removed Fake Financial Liabilities**: Removed arbitrary USD liability calculations from the simulation engine.
- **Eliminated Offset Measurements**: Replaced attestation discrepancy calculations with true bottleneck constraint tracking ($\min_{d} S_d$).
- **Grounded Regulatory Claims**: Aligned EU AI Act classifications strictly with verified statutory criteria (confirming Article 6(1)/Annex I and Annex III §5 applicable routes).
- **Removed Unverified Citations**: Cleaned all unverified legal and standards claims across documentation and codebase.

### User Interface Redesign
- **Questionnaire Wizard as Primary Workflow**: Replaced dual-mode launchpad with a dedicated 8-step interactive assessment wizard (1 Identity + 7 Dimension steps).
- **Quick-Start Reference Presets**: Added one-click reference profiles for Healthcare Clinical Diagnostic AI (High-Risk; confirm Article 6(1)/Annex I or Annex III §5), Credit Scoring AI (High-Risk Annex III §5(b)), and General Purpose Assistant AI.
- **Audit Records & History Screen**: Added `#page-history` screen with persistent SQLite record inspection, allowing users to review and reload past governance assessments.
- **Mathematical Sensitivity Curve Screen**: Added `#page-simulation` screen displaying empirical monotonic sensitivity across $\alpha \in [0.1, 0.9]$ without synthetic financial projections.
- **Eliminated MCP Badges & Visuals**: Removed MCP status pills, connection cards, tool counts, and probe telemetry from all screens.

### Security & Reliability
- **Preserved XSS Sanitization**: Retained strict HTML escaping on all dynamic findings, logs, and telemetry.
- **Retained Rate Limiting & Authentication**: POST endpoints require client-level rate limiting.
- **Test Suite**: 34 unit and integration tests passing cleanly across compliance engines, scoring algorithms, API contracts, and security boundaries.

---

## [3.0.0] - 2026-10-20
### Initial Dual-Mode Prototype
- Introduced 6 trust dimensions and preliminary EU AI Act compliance engine.
