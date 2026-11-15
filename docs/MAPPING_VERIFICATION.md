# Mapping verification log (v5.1)

Every questionnaire item maps to one EU AI Act provision and one NIST AI RMF 1.0 subcategory. The pre-5.1 mapping
contained several references that do not match the provision they were meant to support. This file records what was
changed and how far each correction has been checked.

**34 of 35 items changed.** Rationale per item is stored in `governance_catalog.py` (`ref_note`).

## Verification status — read before citing

| Reference group | Status |
|---|---|
| EU AI Act Art. 15 paragraph numbers (15(1) accuracy/robustness/cybersecurity, 15(2) Commission benchmarks, 15(3) declared accuracy, 15(4) errors and fail-safe, 15(5) cybersecurity incl. data/model poisoning and adversarial examples) | Checked against published text of the Regulation |
| NIST AI RMF GOVERN 1.5, 1.6, 1.7, 2.3; MEASURE 2.4, 2.6, 2.7, 2.8, 2.10, 2.11; MAP 4.1; GOVERN 6.1/6.2 | Checked against NIST AI RMF 1.0 text as quoted by several secondary sources |
| EU AI Act Arts. 9, 10, 11, 12, 13, 14, 17, 26, 72, 73 and Annex IV paragraph/letter references | Entered from the author's reading of the Official Journal text — **verify each against Regulation (EU) 2024/1689 before publication** |
| Remaining NIST subcategories (MAP 2.2, MAP 2.3, MEASURE 2.5, MEASURE 2.9, GOVERN 2.2, GOVERN 3.2, GOVERN 4.2, MANAGE 1.3, MANAGE 2.4, MANAGE 4.1, MANAGE 4.3) | Entered from the author's reading of NIST AI 100-1 — **verify against the Core tables (Section 5)** |

Secondary sources are not a substitute for the primary texts. Treat this table as a to-do list for the final check.

## Old vs new mapping

| Question | EU (before) | EU (now) | NIST (before) | NIST (now) | Result |
|---|---|---|---|---|---|
| `q1_adversarial_tested` | Art. 15(4) | Art. 15(5) | MEASURE 2.7 | MEASURE 2.7 | changed |
| `q2_drift_monitoring` | Art. 9(2)(b) | Art. 72(1); Art. 9(2)(c) | MANAGE 4.2 | MEASURE 2.4 | changed |
| `q3_sbom_tracking` | Art. 15(2) | Art. 15(5); Annex IV(2)(a) | GOVERN 1.7 | GOVERN 1.6; MAP 4.1 | changed |
| `q4_red_teaming` | Art. 15(4) | Art. 15(5) | MEASURE 2.7 | MEASURE 2.7 | changed |
| `q5_api_auth_ratelimit` | Art. 15(3) | Art. 15(5) | MANAGE 2.4 | MEASURE 2.7 | changed |
| `q6_demographic_coverage` | Art. 10(2)(f) | Art. 10(3); Art. 10(2)(f) | MAP 2.2 | MAP 2.3 | changed |
| `q7_class_balance` | Art. 10(2)(f) | Art. 10(3) | MEASURE 2.11 | MEASURE 2.11 | changed |
| `q8_coverage_gaps` | Art. 10(2)(g) | Art. 10(2)(h) | MAP 2.2 | MAP 2.2 | changed |
| `q9_dataset_size` | Art. 10(3) | Art. 10(3) | MAP 3.2 | MAP 2.3 | changed |
| `q10_fairness_audit` | Art. 10(2)(f) | Art. 10(2)(f)-(g) | MEASURE 2.11 | MEASURE 2.11 | changed |
| `q11_xai_engine` | Art. 13(1) | Art. 13(1) | MAP 1.5 | MEASURE 2.9 | changed |
| `q12_attribution_count` | Art. 13(3)(b) | Art. 13(3)(b)(iv) | MEASURE 2.6 | MEASURE 2.9 | changed |
| `q13_reasoning_summaries` | Art. 13(3)(d) | Art. 13(3)(b)(iv); Art. 13(3)(d) | MAP 1.5 | MEASURE 2.9 | changed |
| `q14_model_card_doc` | Art. 11 & Art. 13(1) | Art. 11; Art. 13(2) | GOVERN 1.5 | MAP 2.2 | changed |
| `q15_uncertainty_scores` | Art. 13(3)(b) | Art. 13(3)(b)(ii) | MEASURE 2.6 | MEASURE 2.5 | changed |
| `q16_encryption_rest` | Art. 10(5) | Art. 15(5); GDPR Art. 32 | GOVERN 1.2 | MEASURE 2.10 | changed |
| `q17_encryption_transit` | Art. 15(3) | Art. 15(5); GDPR Art. 32 | GOVERN 1.2 | MEASURE 2.10 | changed |
| `q18_data_retention` | Art. 10(5) | Art. 10(5)(e); GDPR Art. 5(1)(e) | GOVERN 1.2 | MEASURE 2.10 | changed |
| `q19_pii_handling` | Art. 10(5) | Art. 10(5); GDPR Art. 5(1)(c), 25 | MAP 1.6 | MEASURE 2.10 | changed |
| `q20_governance_policy` | Art. 10(2) | Art. 10(2) | GOVERN 1.1 | GOVERN 1.1 | kept |
| `q21_human_oversight` | Art. 14(1) | Art. 14(1); Art. 14(4)(d) | GOVERN 1.4 | GOVERN 3.2 | changed |
| `q22_autonomy_level` | Art. 14(4) | Art. 14(3) | GOVERN 1.4 | GOVERN 3.2 | changed |
| `q24_kill_switch` | Art. 14(4)(e) | Art. 14(4)(e) | GOVERN 1.4 | MANAGE 2.4 | changed |
| `q24b_operator_training` | Art. 14(2) | Art. 26(2); Art. 14(4)(a) | GOVERN 2.2 | GOVERN 2.2 | changed |
| `q24c_override_capability` | Art. 14(4)(a) | Art. 14(4)(d) | GOVERN 1.4 | MANAGE 4.1 | changed |
| `q23_incident_escalation` | Art. 9(9) | Art. 73; Art. 17(1)(i) | MANAGE 4.1 | MANAGE 4.3 | changed |
| `q25_decision_logging` | Art. 12(1) | Art. 12(1) | MEASURE 2.5 | MEASURE 2.4 | changed |
| `q25b_technical_dossier` | Art. 11 | Art. 11; Annex IV | GOVERN 1.5 | GOVERN 4.2 | changed |
| `q25c_post_market_monitoring` | Art. 72 | Art. 72 | MANAGE 4.3 | MANAGE 4.1 | changed |
| `q25d_governance_charter` | Art. 9(1) | Art. 17(1)(m); Art. 9(1) | GOVERN 1.1 | GOVERN 2.3 | changed |
| `q26_input_validation` | Art. 15(1) | Art. 15(4) | MANAGE 2.2 | MEASURE 2.7 | changed |
| `q27_guardrail_count` | Art. 9(2)(a) | Art. 9(5) | MANAGE 2.2 | MANAGE 1.3 | changed |
| `q28_output_clamping` | Art. 15(1) | Art. 15(4) | MANAGE 2.2 | MEASURE 2.6 | changed |
| `q29_contextual_advisory` | Art. 13(3)(d) | Art. 13(3)(b)(iii) | MANAGE 2.3 | MAP 2.2 | changed |
| `q30_failure_mode_testing` | Art. 15(1) | Art. 15(1); Art. 9(6) | MEASURE 2.8 | MEASURE 2.6 | changed |

## Application dates

Several sources consulted state that the high-risk requirements (including Art. 15) apply from 2 December 2027 for Annex III systems and 2 August 2028 for Annex I systems, following the Digital Omnibus changes. Confirm the current dates on EUR-Lex before quoting them.
