# AI-GRID Test Data & Audit Specifications

This directory contains verified sample inputs and reference specifications to test AI-GRID's empirical verification modules and questionnaire auditing engine.

---

## 1. Empirical Verifier Sample Files

| File | Target Verifier | Item / Claim Verified | Format |
| :--- | :--- | :--- | :--- |
| [`1_fairness_dataset.txt`](./1_fairness_dataset.txt) | `POST /api/verify/fairness` | `q10_fairness_audit` | CSV text (`protected_attribute,y_true,y_pred`) |
| [`2_requirements_dependencies.txt`](./2_requirements_dependencies.txt) | `POST /api/verify/dependencies` | `q3_sbom_tracking` | Python `requirements.txt` manifest |
| [`3_tls_config.txt`](./3_tls_config.txt) | `POST /api/verify/tls` | `q17_encryption_transit` | JSON payload (`host`, `port`) |
| [`4_log_chain_sample.txt`](./4_log_chain_sample.txt) | `POST /api/verify/log-integrity` | `q25_decision_logging` | JSONL cryptographic hash chain |
| [`5_robustness_dataset.txt`](./5_robustness_dataset.txt) | `POST /api/verify/robustness` | `q1_adversarial_tested` | CSV text (`clean_prediction,perturbed_prediction,ground_truth`) |

---

## 2. Complete Questionnaire & Options Reference

| File | Description |
| :--- | :--- |
| [`all_questions_and_answers.txt`](./all_questions_and_answers.txt) | Complete 35-question reference guide detailing question IDs, prompts, trust dimensions, academic literature sources, EU AI Act / NIST AI 100-1 regulatory crosswalk mappings, all multiple-choice options with numerical score contributions, and a ready-to-use JSON API audit payload. |

---

## Quick Testing Examples (curl)

```bash
# 1. Test Fairness Verifier
curl -X POST http://localhost:8000/api/verify/fairness -F "file=@test_data/1_fairness_dataset.txt"

# 2. Test Dependencies / SBOM Verifier
curl -X POST http://localhost:8000/api/verify/dependencies -F "file=@test_data/2_requirements_dependencies.txt"

# 3. Test TLS Prober
curl -X POST http://localhost:8000/api/verify/tls -H "Content-Type: application/json" -d @test_data/3_tls_config.txt

# 4. Test Log Hash-Chain Integrity
curl -X POST http://localhost:8000/api/verify/log-integrity -F "file=@test_data/4_log_chain_sample.txt"

# 5. Test Robustness Accuracy Drop
curl -X POST http://localhost:8000/api/verify/robustness -F "file=@test_data/5_robustness_dataset.txt"
```

