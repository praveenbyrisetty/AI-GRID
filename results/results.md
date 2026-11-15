# AI-GRID reproduced results

Commit `31f8f82` · generated 2026-11-15T03:24:44+00:00

_Reference profiles and verifier datasets are designed/simulated, not real-world systems._

## 1. Reference profiles (alpha = 0.6, equal dimension weights)

| Profile | AAS | Mean | Bottleneck | Grade | Findings | Verified / answered |
|---|---|---|---|---|---|---|
| healthcare | 100.0 | 100.0 | 100.0 (Security & Robustness) | A+ | 0 (0 critical) | 0 / 35 |
| finance | 68.7 | 81.1 | 50.0 (Safety & Reliability) | C | 14 (0 critical) | 0 / 35 |
| assistant | 51.9 | 53.1 | 50.0 (Security & Robustness) | D | 34 (0 critical) | 0 / 35 |

## 2. alpha sensitivity (AAS)

| Profile | 0.1 | 0.2 | 0.3 | 0.4 | 0.5 | 0.6 | 0.7 | 0.8 | 0.9 |
|---|---|---|---|---|---|---|---|---|---|
| healthcare | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 |
| finance | 53.1 | 56.2 | 59.3 | 62.5 | 65.6 | 68.7 | 71.8 | 74.9 | 78.0 |
| assistant | 50.3 | 50.6 | 50.9 | 51.3 | 51.6 | 51.9 | 52.2 | 52.5 | 52.8 |

Profile ordering identical for every alpha: **True**

## 3. Evidence-weight (T3) sensitivity

With no verified evidence all items share one weight, so the T3 weight cancels out of every dimension average and AAS is invariant to it. The weight only matters when verified and unverified items are mixed.

AAS with one refuted fairness claim (verified evidence at weight 1.0) and the composite attestation gap:

| T3 weight | healthcare AAS / gap | finance AAS / gap | assistant AAS / gap |
|---|---|---|---|
| 0.4 | 81.3 / 18.7 | 62.5 / 6.7 | 44.8 / 8.6 |
| 0.5 | 83.8 / 16.2 | 64.2 / 4.9 | 46.3 / 6.9 |
| 0.6 | 85.7 / 14.3 | 65.5 / 3.5 | 47.5 / 5.6 |
| 0.7 | 87.2 / 12.8 | 66.5 / 2.4 | 48.4 / 4.6 |
| 0.8 | 88.4 / 11.6 | 66.7 / 2.1 | 49.1 / 3.8 |
| 1.0 | 90.3 / 9.7 | 67.0 / 1.7 | 50.2 / 2.5 |

## 4. Dimension-weight sensitivity

| Profile | Equal weights | Illustrative domain profile |
|---|---|---|
| healthcare | 100.0 | 100.0 |
| finance | 68.7 | 69.8 |
| assistant | 51.9 | 51.9 |

1000 random weightings (each weight uniform in [0.5, 2.0]): profile ordering preserved in **100.0%** of draws.
AAS range: healthcare 100.0–100.0; finance 64.5–73.6; assistant 51.2–52.6

## 5. Leave-one-question-out robustness

| Profile | Baseline AAS | Min | Max | Range |
|---|---|---|---|---|
| healthcare | 100.0 | 100.0 | 100.0 | 0.0 |
| finance | 68.7 | 68.0 | 69.2 | 1.2 |
| assistant | 51.9 | 51.6 | 52.1 | 0.5 |

## 6. Verifier ablation (every profile claims a formal fairness audit; simulated biased dataset refutes it)

| Profile | AAS off | AAS on | Fairness dim off→on | Grade off | Grade on (uncapped) | Gap |
|---|---|---|---|---|---|---|
| healthcare | 100.0 | 85.7 | 100.0→70.6 | A+ | C (A) | 14.3 |
| finance | 68.7 | 65.5 | 74.0→47.6 | C | C (C) | 3.5 |
| assistant | 52.7 | 47.5 | 68.0→42.4 | D | F (F) | 5.6 |

## 7. Fairness threshold sensitivity (verifier score 1.0 / 0.5 / 0.0)

Applies the verifier's tiered scoring rule with alternative cut-offs to synthetic selection rates.

| Dataset | DIR | SPD | current (DIR 0.80 and SPD 0.10 full; 0.70 and 0.15 partial) | stricter (0.90 and 0.05; 0.80 and 0.10) | looser (0.70 and 0.15; 0.60 and 0.20) |
|---|---|---|---|---|---|
| selection 80% vs 80% | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 |
| selection 80% vs 70% | 0.87 | -0.1 | 1.0 | 0.5 | 1.0 |
| selection 80% vs 60% | 0.75 | -0.2 | 0.0 | 0.0 | 0.5 |
| selection 80% vs 40% | 0.5 | -0.4 | 0.0 | 0.0 | 0.0 |
| selection 80% vs 20% | 0.25 | -0.6 | 0.0 | 0.0 | 0.0 |
