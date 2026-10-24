# Changelog

All notable changes to the **AI-GRID** platform are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [4.0.0] - 2026-10-23

### Architecture Evolution: Pure Questionnaire AI Governance Engine
- **Removed MCP Probing Engine**: Completely retired Model Context Protocol (MCP) runtime prober (`mcp_client.py`, `mcp_probes.py`, `demo_servers/`), removing external process spawning and protocol socket overhead.
- **Pure Questionnaire-Based Governance**: Re-centered AI-GRID exclusively around the 35-item technical control question bank (5 per dimension across 7 canonical trust dimensions) grounded in QB4AIRA (Lee et al., 2024), EU AI Act Regulation (EU) 2024/1689 Articles 9–15, and NIST AI 100-1.
- **Deprecated Endpoints**: Updated `/api/audit/mcp` and `/api/audit/compare` to return `410 Gone` with clear deprecation notices.

### Elimination of Synthetic Data & Invented Claims
- **Removed Fake Financial Liabilities**: Removed arbitrary USD liability calculations (`$5,000 * scale_users`) from the simulation engine.
- **Eliminated Offset Measurements**: Replaced attestation discrepancy calculations ($\Delta = S_{\text{self}} - S_{\text{probe}}$) with true bottleneck constraint tracking ($\min_{d} S_d$).
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
- **Retained Rate Limiting & Authentication**: POST endpoints require `X-API-Key` authentication and are rate-limited per client identifier.
- **Test Suite**: 34 unit and integration tests passing cleanly across compliance engines, scoring algorithms, API contracts, and security boundaries.

---

## [3.0.0] - 2026-10-20
### Initial Dual-Mode Prototype
- Introduced 6 trust dimensions and preliminary EU AI Act compliance engine.
