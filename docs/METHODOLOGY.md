# AI-GRID Methodology, Parameter Justification and Limitations (v5.1)

AI-GRID is a **screening and pre-audit framework**. It is not a certification, and its score has not been validated
against real-world audit outcomes. Every number below is either derived from a stated rule or is a documented design
choice. Where it is a design choice, the sensitivity analysis in `results/results.md` (regenerate with
`python scripts/reproduce_results.py`) shows how much the conclusions depend on it.

## 1. What is measured

Thirty-five closed-form questions, five in each of seven dimensions, are answered by the assessor. Each option has an
ordinal score (1.0 full, 0.5 partial, 0.0 none; one question uses 0.6 for a middle option). Five questions can be
replaced by a machine-measured result from a verifier module.

## 2. Selecting the dimensions and questions

**Dimensions.** The seven dimensions follow the structure of the EU's Trustworthy AI requirements as operationalised
in ALTAI, with two differences that must be stated in the paper: technical robustness and safety is split into
*Security & Robustness* and *Safety & Reliability*, and societal and environmental well-being is not covered because it
cannot be assessed from technical evidence. *Confirm the exact list of the EU requirements against the primary source.*

**Questions.** Candidate controls come from QB4AIRA (293 questions, which carry importance levels 1-3), the EU AI Act
(Arts. 9-15, 17, 26, 72, 73), NIST AI 100-1, and the supporting sources named in each question's `research_source`
field. The questions are *adapted* from these sources and rewritten as closed-form options; they are not QB4AIRA
questions verbatim. Selection criteria the 35 items are meant to satisfy:

1. the control maps to a specific EU AI Act provision and a NIST AI RMF subcategory (`governance_catalog.py`);
2. it can be answered from observable practice or evidence, not opinion;
3. it is not a duplicate of another item;
4. every dimension has the same number of items (five), so no dimension dominates through question count.

The count of five per dimension is a design choice, not a property of any standard. Leave-one-question-out
robustness (section 5 of `results/results.md`) shows how much a single question can move the AAS.
*Record the QB4AIRA question ID each item was adapted from (where applicable) to complete the traceability matrix.*

## 3. Scoring

For dimension *d*, with items *i*, score *s* and evidence weight *w*:

    S_d = 100 * sum(s_i * w_i) / sum(w_i)
    AAS = alpha * weighted_mean(S_d) + (1 - alpha) * min(S_d)

| Parameter | Value | Basis | Status |
|---|---|---|---|
| T1 weight | 1.0 | Measured by a verifier module; the answer score is replaced by the measured score | Design choice |
| T2 weight | 0.8 | Documentary evidence reference supplied with the answer (`evidence_refs`), not machine-verified | Design choice |
| T3 weight | 0.6 | Self-attested answer | Design choice |
| alpha | 0.6 | Weights the average over the weakest dimension 60:40 so one weak dimension lowers but does not dominate the score | Design choice |
| Dimension weights | equal | Neutral default. Optional illustrative domain profiles exist (`weight_profile: "domain"`) | Design choice |
| Target AAS | 76.0 | Heuristic threshold used only to rank remediation | Illustrative |

**Evidence weights.** Only the *ordering* T1 > T2 > T3 is a principled claim (measured evidence is stronger than
documents, which are stronger than assertion). The specific values 1.0/0.8/0.6 are not derived from data. A property
worth knowing: when no verified evidence is present all items share one weight, so the T3 weight cancels out of every
dimension average. The weight only matters when verified and unverified items are mixed, and in that case it changes the
size of the attestation gap (see section 3 of `results/results.md`).

**Alpha.** The bottleneck term is a conservative-governance choice: a system that fails badly in one dimension should
not look acceptable because it is strong elsewhere. The alpha sweep (section 2 of the results) reports AAS for alpha from
0.1 to 0.9 and whether the ordering of the reference profiles changes.

**Equal dimension weights.** Equal weights are the neutral default, and the importance of dimensions does differ between
applications. The optional domain profiles express this for the Annex III areas, for example higher weight on Safety and
Human Oversight in healthcare and on Fairness and Transparency in credit scoring. These profiles are *assumptions*;
expert-elicited weights (for example through AHP) are future work. The bottleneck term is unaffected by dimension
weights and continues to protect against a single weak dimension.

## 4. Evidence, coverage and the attestation gap

* **Evidence coverage** is reported in every audit (`evidence_coverage`): how many answered questions are verified,
  documented or self-attested, plus the maximum coverage attainable with the current modules.
* Only **5 of 35** questions (14.3%) have a verifier, so even a fully verified audit rests mostly on self-attestation.
  The report labels the result `SELF_ASSESSED`, `PARTIALLY_VERIFIED` or `VERIFIED_WITHIN_VERIFIABLE_SCOPE` accordingly.
* **Attestation gap** = claimed score minus effective score, where both use the *same* item weights, so the gap
  isolates verifier disagreement. (Before v5.1 the claimed score used an unweighted mean, which could produce a non-zero gap
  even when every verifier agreed with the answer. That has been corrected.)
* **Unanswered or invalid answers** are listed in `assessment_gaps` and are never treated as compliant.

## 5. Grade caps and severity

* The numeric AAS is never altered. The displayed grade is capped at **C** when (a) any verifier refuted a claimed
  answer, or (b) any CRITICAL finding is open. Both caps are reported in `scoring.grade_caps_applied`.
* For systems classified HIGH RISK under the domain rules, every open finding is escalated one severity level because
  the mapped Art. 9-15/17/72/73 requirements are binding for those systems. The base severity is kept in `priority_base`.
* Both rules are design choices and are testable in `tests/test_hardening.py`.

## 6. Verifier thresholds

| Verifier | Rule (full / partial) | Source of the numbers |
|---|---|---|
| Fairness | DIR >= 0.80 and abs(SPD) <= 0.10 / DIR >= 0.70 and abs(SPD) <= 0.15 | The 0.80 level follows the four-fifths rule used in US employment guidance; SPD 0.10 is a common convention in fairness toolkits; the partial band is a project choice. *Add the exact citations before publication.* |
| Robustness | accuracy drop <= 5% / <= 15% | Project choice; no standard prescribes these values |

Section 7 of `results/results.md` shows how the verifier score changes under stricter and looser cut-offs.

## 7. Limitations and threats to validity

1. **No ground truth.** There is no labelled data on which systems are trustworthy, so accuracy of the score cannot be measured.
2. **Designed profiles.** The reference profiles and verifier datasets are designed or simulated. The healthcare profile is a best-case ceiling (all items at the best option).
3. **Well-separated profiles.** The three reference profiles differ by large margins, so stability of their *ordering* under reweighting is a weak test. Real systems cluster more tightly.
4. **Self-report dominates.** 30 of 35 questions cannot be machine-verified.
5. **Gameable evidence.** A verifier checks only what it is given; a selective dataset can pass.
6. **Mapping accuracy.** EU AI Act and NIST references were corrected in v5.1 but several remain to be checked against primary texts (`docs/MAPPING_VERIFICATION.md`).
7. **No authentication or access control** on the demo server, and the audit hash makes tampering detectable only if the hash is stored separately (records are not hash-chained).
8. **Not a legal assessment.** Output is an indicative technical pre-audit.

## 8. Validation plan (future work)

* run the framework on real, publicly documented AI systems and datasets;
* inter-rater agreement: several assessors answer the questionnaire for the same system;
* expert review of question wording and mappings;
* expert-elicited dimension weights;
* hash-chained audit ledger and authenticated, signed evidence upload.
