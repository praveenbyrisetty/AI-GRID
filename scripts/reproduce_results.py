#!/usr/bin/env python3
"""
Regenerates every number used in the AI-GRID paper from the current code.

    python scripts/reproduce_results.py            # writes results/results.json and results/results.md

Sections
  1. Reference profiles (baseline AAS, grade, coverage)
  2. alpha sensitivity (0.1 .. 0.9)
  3. Evidence-weight sensitivity (T3 weight sweep, with and without verified evidence)
  4. Dimension-weight sensitivity (equal vs illustrative domain profile vs 1000 random weightings)
  5. Question-removal robustness (leave-one-question-out, 35 runs per profile)
  6. Verifier ablation (verifiers off vs on, claim refuted by simulated verifier evidence)
  7. Fairness threshold sensitivity (alternative DIR / SPD cut-offs on synthetic datasets)

IMPORTANT: the reference profiles and the verifier datasets below are DESIGNED / SIMULATED. Results show how the
scoring behaves; they are not validation against real-world AI systems.
"""
import copy
import json
import os
import random
import subprocess
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ai_profile_engine as eng  # noqa: E402
from verifiers import verify_fairness  # noqa: E402

Q = [q for q in eng.QUESTIONS if not q.get("is_identity")]
PRESETS = json.load(open(os.path.join(ROOT, "test_data", "reference_presets.json")))
ALPHAS = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
T3_WEIGHTS = [0.4, 0.5, 0.6, 0.7, 0.8, 1.0]


def commit():
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


def run(answers, **kw):
    return eng.generate_audit_from_questionnaire(copy.deepcopy(answers), **kw)


def aas(answers, **kw):
    return run(answers, **kw)["scoring"]["aas_score"]


def biased_fairness_evidence():
    """Simulated verifier outcome: biased predictions refute a 'formal audit' claim."""
    rows = ["protected_attribute,y_true,y_pred"]
    rows += ["male,1,1"] * 8 + ["male,0,0"] * 2
    rows += ["female,1,0"] * 6 + ["female,1,1"] * 2 + ["female,0,0"] * 2
    return verify_fairness("\n".join(rows), claimed_value="formal_audit")


def fair_fairness_evidence():
    rows = ["protected_attribute,y_true,y_pred"]
    rows += ["male,1,1"] * 8 + ["male,0,0"] * 2
    rows += ["female,1,1"] * 8 + ["female,0,0"] * 2
    return verify_fairness("\n".join(rows), claimed_value="formal_audit")


def ordering(d):
    return tuple(sorted(d, key=lambda k: -d[k]))


def main():
    out = {"generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "commit": commit(),
           "note": "Reference profiles and verifier datasets are designed/simulated, not real-world systems."}

    # 1 baseline ------------------------------------------------------------------------------
    base = {}
    for name, ans in PRESETS.items():
        r = run(ans)
        base[name] = {
            "aas": r["scoring"]["aas_score"], "mean": r["scoring"]["weighted_average"],
            "bottleneck": r["scoring"]["bottleneck_score"], "bottleneck_dimension": r["scoring"]["bottleneck_dimension"],
            "grade": r["scoring"]["trust_grade"], "uncapped_grade": r["scoring"]["uncapped_grade"],
            "findings": r["audit_summary"]["findings_count"], "critical": r["audit_summary"]["critical_findings"],
            "assurance": r["evidence_coverage"]["assurance_level"], "verified": r["evidence_coverage"]["verified_questions"],
            "answered": r["evidence_coverage"]["answered_questions"], "dimensions": r["dimensions"],
        }
    out["baseline"] = base

    # 2 alpha ---------------------------------------------------------------------------------
    alpha = {n: {str(a): aas(ans, alpha=a) for a in ALPHAS} for n, ans in PRESETS.items()}
    out["alpha_sweep"] = alpha
    out["alpha_ordering_stable"] = len({ordering({n: alpha[n][str(a)] for n in PRESETS}) for a in ALPHAS}) == 1

    # 3 evidence weights ----------------------------------------------------------------------
    ev_bad, ev_ok = biased_fairness_evidence(), fair_fairness_evidence()
    ew = {"without_verified_evidence": {}, "with_refuted_claim": {}, "with_confirmed_claim": {}}
    for w in T3_WEIGHTS:
        tw = {"T3": w}
        ew["without_verified_evidence"][str(w)] = {n: aas(a, tier_weights=tw) for n, a in PRESETS.items()}
        ew["with_refuted_claim"][str(w)] = {}
        ew["with_confirmed_claim"][str(w)] = {}
        for n, a in PRESETS.items():
            a2 = copy.deepcopy(a)
            a2["q10_fairness_audit"] = "formal_audit"          # every profile claims a formal audit
            rb = run(a2, tier_weights=tw, verified_evidence=[ev_bad])
            ro = run(a2, tier_weights=tw, verified_evidence=[ev_ok])
            ew["with_refuted_claim"][str(w)][n] = {"aas": rb["scoring"]["aas_score"], "gap": rb["attestation_gap"]["composite_gap"]}
            ew["with_confirmed_claim"][str(w)][n] = {"aas": ro["scoring"]["aas_score"], "gap": ro["attestation_gap"]["composite_gap"]}
    out["evidence_weight_sweep"] = ew
    out["evidence_weight_finding"] = ("With no verified evidence all items share one weight, so the T3 weight cancels out of every "
                                      "dimension average and AAS is invariant to it. The weight only matters when verified and "
                                      "unverified items are mixed.")

    # 4 dimension weights ---------------------------------------------------------------------
    dw = {}
    for n, a in PRESETS.items():
        dw[n] = {"equal": aas(a), "domain_profile": aas(a, weight_profile="domain")}
    rng = random.Random(2026)
    base_order = ordering({n: dw[n]["equal"] for n in PRESETS})
    keep, lows, highs = 0, {n: 100.0 for n in PRESETS}, {n: 0.0 for n in PRESETS}
    N = 1000
    for _ in range(N):
        wts = {d: rng.uniform(0.5, 2.0) for d in eng.DIMENSIONS_LIST}
        vals = {n: aas(a, weight_profile=wts) for n, a in PRESETS.items()}
        keep += ordering(vals) == base_order
        for n, v in vals.items():
            lows[n], highs[n] = min(lows[n], v), max(highs[n], v)
    dw["random_weightings"] = {"draws": N, "weight_range": [0.5, 2.0], "ordering_preserved_pct": round(100 * keep / N, 1),
                               "aas_min": lows, "aas_max": highs}
    out["dimension_weight_sensitivity"] = dw

    # 5 leave-one-question-out ----------------------------------------------------------------
    loo = {}
    for n, a in PRESETS.items():
        vals = []
        for q in Q:
            a2 = copy.deepcopy(a)
            a2.pop(q["id"], None)
            vals.append(aas(a2))
        loo[n] = {"baseline": base[n]["aas"], "min": min(vals), "max": max(vals), "range": round(max(vals) - min(vals), 1)}
    out["leave_one_question_out"] = loo

    # 6 verifier ablation ---------------------------------------------------------------------
    abl = {}
    for n, a in PRESETS.items():
        a2 = copy.deepcopy(a)
        a2["q10_fairness_audit"] = "formal_audit"
        off = run(a2)
        on = run(a2, verified_evidence=[ev_bad])
        abl[n] = {"aas_without_verifier": off["scoring"]["aas_score"], "grade_without_verifier": off["scoring"]["trust_grade"],
                  "aas_with_verifier": on["scoring"]["aas_score"], "grade_with_verifier": on["scoring"]["trust_grade"],
                  "uncapped_grade_with_verifier": on["scoring"]["uncapped_grade"],
                  "attestation_gap": on["attestation_gap"]["composite_gap"],
                  "fairness_dim_without": off["dimensions"]["Fairness & Non-Discrimination"],
                  "fairness_dim_with": on["dimensions"]["Fairness & Non-Discrimination"]}
    out["verifier_ablation"] = {"simulated_evidence": {k: ev_bad[k] for k in ("claim_supported", "verified_score")} | {"details": ev_bad.get("details")},
                                "profiles": abl}

    # 7 fairness thresholds -------------------------------------------------------------------
    def band(dir_v, spd_v, full, part):
        dir_v, spd_v = round(dir_v, 4), round(abs(spd_v), 4)
        if dir_v >= full[0] and spd_v <= full[1]:
            return 1.0
        if dir_v >= part[0] and spd_v <= part[1]:
            return 0.5
        return 0.0
    datasets = {"selection 80% vs 80%": (0.80, 0.80), "selection 80% vs 70%": (0.80, 0.70), "selection 80% vs 60%": (0.80, 0.60),
                "selection 80% vs 40%": (0.80, 0.40), "selection 80% vs 20%": (0.80, 0.20)}
    rules = {"current (DIR 0.80 and SPD 0.10 full; 0.70 and 0.15 partial)": ((0.80, 0.10), (0.70, 0.15)),
             "stricter (0.90 and 0.05; 0.80 and 0.10)": ((0.90, 0.05), (0.80, 0.10)),
             "looser (0.70 and 0.15; 0.60 and 0.20)": ((0.70, 0.15), (0.60, 0.20))}
    thr = {}
    for dn, (p_priv, p_unpriv) in datasets.items():
        dir_v, spd_v = p_unpriv / p_priv, p_unpriv - p_priv
        thr[dn] = {"DIR": round(dir_v, 2), "SPD": round(spd_v, 2),
                   **{rn: band(dir_v, spd_v, f, p) for rn, (f, p) in rules.items()}}
    out["fairness_threshold_sensitivity"] = {"note": "Applies the verifier's tiered scoring rule with alternative cut-offs to synthetic selection rates.",
                                              "rows": thr}

    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    json.dump(out, open(os.path.join(ROOT, "results", "results.json"), "w"), indent=2, default=str)
    open(os.path.join(ROOT, "results", "results.md"), "w").write(to_markdown(out))
    print(to_markdown(out))


def to_markdown(o):
    L = ["# AI-GRID reproduced results", "", f"Commit `{o['commit']}` · generated {o['generated_utc']}", "", f"_{o['note']}_", ""]
    L += ["## 1. Reference profiles (alpha = 0.6, equal dimension weights)", "",
          "| Profile | AAS | Mean | Bottleneck | Grade | Findings | Verified / answered |", "|---|---|---|---|---|---|---|"]
    for n, b in o["baseline"].items():
        L.append(f"| {n} | {b['aas']} | {b['mean']} | {b['bottleneck']} ({b['bottleneck_dimension']}) | {b['grade']} | {b['findings']} ({b['critical']} critical) | {b['verified']} / {b['answered']} |")
    L += ["", "## 2. alpha sensitivity (AAS)", "", "| Profile | " + " | ".join(str(a) for a in ALPHAS) + " |", "|---|" + "---|" * len(ALPHAS)]
    for n, d in o["alpha_sweep"].items():
        L.append(f"| {n} | " + " | ".join(str(d[str(a)]) for a in ALPHAS) + " |")
    L.append(f"\nProfile ordering identical for every alpha: **{o['alpha_ordering_stable']}**")
    L += ["", "## 3. Evidence-weight (T3) sensitivity", "", o["evidence_weight_finding"], "",
          "AAS with one refuted fairness claim (verified evidence at weight 1.0) and the composite attestation gap:", "",
          "| T3 weight | " + " | ".join(f"{n} AAS / gap" for n in o["baseline"]) + " |", "|---|" + "---|" * len(o["baseline"])]
    for w in T3_WEIGHTS:
        row = o["evidence_weight_sweep"]["with_refuted_claim"][str(w)]
        L.append(f"| {w} | " + " | ".join(f"{row[n]['aas']} / {row[n]['gap']}" for n in o["baseline"]) + " |")
    L += ["", "## 4. Dimension-weight sensitivity", "", "| Profile | Equal weights | Illustrative domain profile |", "|---|---|---|"]
    for n in o["baseline"]:
        d = o["dimension_weight_sensitivity"][n]
        L.append(f"| {n} | {d['equal']} | {d['domain_profile']} |")
    r = o["dimension_weight_sensitivity"]["random_weightings"]
    L.append(f"\n{r['draws']} random weightings (each weight uniform in {r['weight_range']}): profile ordering preserved in **{r['ordering_preserved_pct']}%** of draws.")
    L.append("AAS range: " + "; ".join(f"{n} {r['aas_min'][n]}–{r['aas_max'][n]}" for n in o["baseline"]))
    L += ["", "## 5. Leave-one-question-out robustness", "", "| Profile | Baseline AAS | Min | Max | Range |", "|---|---|---|---|---|"]
    for n, d in o["leave_one_question_out"].items():
        L.append(f"| {n} | {d['baseline']} | {d['min']} | {d['max']} | {d['range']} |")
    L += ["", "## 6. Verifier ablation (every profile claims a formal fairness audit; simulated biased dataset refutes it)", "",
          "| Profile | AAS off | AAS on | Fairness dim off→on | Grade off | Grade on (uncapped) | Gap |", "|---|---|---|---|---|---|---|"]
    for n, d in o["verifier_ablation"]["profiles"].items():
        L.append(f"| {n} | {d['aas_without_verifier']} | {d['aas_with_verifier']} | {d['fairness_dim_without']}→{d['fairness_dim_with']} | {d['grade_without_verifier']} | {d['grade_with_verifier']} ({d['uncapped_grade_with_verifier']}) | {d['attestation_gap']} |")
    L += ["", "## 7. Fairness threshold sensitivity (verifier score 1.0 / 0.5 / 0.0)", "", o["fairness_threshold_sensitivity"]["note"], ""]
    rows = o["fairness_threshold_sensitivity"]["rows"]
    rn = [k for k in next(iter(rows.values())) if k not in ("DIR", "SPD")]
    L += ["| Dataset | DIR | SPD | " + " | ".join(rn) + " |", "|---|---|---|" + "---|" * len(rn)]
    for dn, d in rows.items():
        L.append(f"| {dn} | {d['DIR']} | {d['SPD']} | " + " | ".join(str(d[k]) for k in rn) + " |")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
