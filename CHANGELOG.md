# Changelog

All notable changes to the **AI-GRID** platform are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [5.1.0] - 2026-11-14

### Strengthening release (scoring integrity, GRC mapping, reproducibility)
- **GRC roadmap:** "Required Engineering Action" is now **Required Governance Action**. Every question carries a
  `governance_action`, `owner_role` and `evidence_expected` (`governance_catalog.py`); the roadmap UI shows owner and
  EU AI Act | NIST references.
- **Mapping corrections:** EU AI Act and NIST references corrected (e.g. SBOM Art. 15(2) -> Art. 15(5), GOVERN 1.7 -> GOVERN 1.6;
  incident escalation Art. 9(9) -> Art. 73). See `docs/MAPPING_VERIFICATION.md` for the full old-vs-new table and the
  verification status of each reference group.
- **Attestation gap fix:** claimed and effective scores now use the same item weights, so the gap isolates verifier
  disagreement (previously a weighting artefact could produce a non-zero gap with no disagreement).
- **Evidence coverage:** every audit reports verified / documented / self-attested counts, maximum attainable coverage and an
  assurance level. Unanswered or invalid answers are reported as `assessment_gaps` instead of silently skipped.
- **Tier T2 defined:** documentary evidence supplied through `evidence_refs` (weight 0.8).
- **Grade caps:** displayed grade is capped at C when a claim is refuted by verified evidence or a CRITICAL finding is open.
  The numeric AAS is unchanged.
- **Severity follows obligation:** open findings are escalated one level for HIGH RISK systems.
- **Parameters exposed and validated:** `alpha`, `weight_profile` (`equal`, `domain` or custom) and `evidence_refs` on
  `POST /api/audit/questionnaire`; the hard-coded question count (35) and status version are computed.
- **Reproducibility:** `scripts/reproduce_results.py` regenerates every reported number plus alpha, evidence-weight,
  dimension-weight, leave-one-question-out, verifier-ablation and fairness-threshold sensitivity (`results/`).
- **Docs:** `docs/METHODOLOGY.md`; corrected stale question IDs in README, ARCHITECTURE and CHANGELOG entries.
- **Tests:** 14 new tests (`tests/test_hardening.py`); total 69.

## [5.0.1] - 2026-11-05

### Architecture Polish & Evidence Model Consolidation
- **Consolidated Evidence Model into `ai_profile_engine.py`**: Removed legacy `evidence.py` containing half-deleted duplicate AAS logic. Migrated `Evidence`, `SecurityFinding`, `DimensionResult`, `compute_weighted_dimension_score`, and `aggregate_dimension_scores` into `ai_profile_engine.py`.
- **Single Canonical AAS Engine**: Preserved `ai_profile_engine.compute_aas_and_bottleneck` as the sole source of truth for composite AAS and bottleneck penalty computation.
- **Updated Test Imports**: Retargeted `tests/test_evidence.py` to import from `ai_profile_engine` and `config`.

### Static Code Hygiene & Linter Cleanliness
- **Zero-Warning Pyflakes Conformance**: Fixed all unused variables, unused globals, and unused imports across all root and test Python files:
  - Removed unused exception variables (`except Exception:`) across `server.py`.
  - Removed unnecessary `global last_audit_data` declarations where name was read-only in scope.
  - Removed unused `os` import in `verifiers.py` and unused `io` import in `tests/test_verifiers.py`.

### Regulatory Compliance & Crosswalk Verification
- **NIST AI RMF 1.0 Accountability Sensitivity**: Confirmed wiring of `Accountability & Governance` score (`acct_score`) to GOVERN 2.1, MEASURE 2.5, MANAGE 4.1, and the composite GOVERN function average.
- **New Unit Test**: Added `test_nist_govern_score_sensitive_to_accountability_score` in `tests/test_compliance.py` verifying that changing only the Accountability score directly modifies the NIST GOVERN score.

### Documentation & Standards Alignment
- **README Refinements**: Changed subtitle to "AI governance risk assessment framework with verified evidence".
- **Entity Normalization**: Replaced all literal `&amp;` and `&ge;` instances with literal `&` and `>=` characters.
- **Test Badge**: Added test-suite badge reflecting 55 passed verification tests.

---

## [5.0.0] - 2026-11-05

### Empirical Evidence Verification & Attestation Gap Engine (Phase 6)
- **Empirical Verifiers Module (`verifiers.py`)**: Added 5 dedicated verification modules with REST endpoints (`POST /api/verify/<module>`):
  - **Fairness (`/api/verify/fairness`)**: Computes Disparate Impact Ratio (DIR), Statistical Parity Difference (SPD), and Equal Opportunity Difference (EOD) on uploaded predictions CSVs to verify `q10_fairness_audit`.
  - **Dependencies (`/api/verify/dependencies`)**: Queries the public OSV API (`api.osv.dev`, PyPI ecosystem, `urllib` only) with a 5-second timeout and up to 200 packages to verify `q3_sbom_tracking`. Gracefully handles offline states by preserving claimed scores.
  - **TLS Prober (`/api/verify/tls`)**: Probes host and port (443/8443) for TLS 1.3/1.2 negotiation and certificate validity with 5-second socket timeout and strict SSRF defenses to verify `q17_encryption_transit`.
  - **Log Integrity (`/api/verify/log-integrity`)**: Cryptographically validates SHA-256 hash chains from genesis in uploaded JSONL logs to verify `q25_decision_logging`.
  - **Adversarial Robustness (`/api/verify/robustness`)**: Measures accuracy drop between baseline and perturbed prediction CSVs to verify `q1_adversarial_tested`.
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
