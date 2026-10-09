"""M4 - the cross-spec summary behind docs/m4-realizable-attacks.md section 11.

    python scripts/03d_summarize_realizable.py

Reads the saved test-split cells (``artifacts/adversarial_real/test_spec{A,B,C}*/``)
and the per-run tables, and writes the tables that compare across specs,
knowledge tiers and floors - so every number in the M4 write-up can be rebuilt
without re-running an attack.

Writes artifacts/reports/table4d_tiers.{md,csv} and
artifacts/reports/realizable_levers.csv.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aad.evaluate import bootstrap_ci  # noqa: E402

ADV = ROOT / "artifacts" / "adversarial_real"
REP = ROOT / "artifacts" / "reports"
SPECS = ("A", "B", "C")
ENS_CELLS = [("feat_pgd_ens", "ens", "white", "feature space"),
             ("adaptive_feat", "ens", "white", "feature space, validator-aware"),
             ("prim_pgd_ens", "ens", "white", "physical knobs"),
             ("adaptive_prim", "ens", "white", "physical knobs, validator-aware"),
             ("greybox", "surr", "grey", "physical knobs, own surrogate models"),
             ("blackbox", "ens", "black", "physical knobs, allow/stop answers only")]


def load(spec: str, cell: str, tag: str = "") -> dict:
    d = np.load(ADV / f"test_spec{spec}{tag}" / f"{cell}.npz", allow_pickle=False)
    return {k: d[k] for k in d.files}


def fmt(rate, lo, hi):
    return f"{100 * rate:.2f} [{100 * lo:.1f}, {100 * hi:.1f}]"


def main() -> None:
    table4b = {s: pd.read_csv(REP / f"table4b_realizable_test_spec{s}.csv") for s in SPECS}
    rows, lines = [], []

    # ---- 1. headline: every ensemble-level attacker, three specs ---------------
    lines += ["# Table IV-d - realizable attacks across knowledge tiers and flow-age specs", "",
              "Test split, 6,300 source rows (900 per attack category), each detected by MLP, CNN and "
              "LSTM at their calibrated thresholds. Cell = **pass-and-evade %**: no model detects the "
              "row AND the real validator lets it through [95% bootstrap interval]. Spec A: padding + "
              "TTL only; B: + longer connections; C: + longer or fresh connections.", "",
              "## 1. Overall", "",
              "| attacker | tier | " + " | ".join(f"spec {s}" for s in SPECS) + " |",
              "| --- | --- | " + " | ".join("---:" for _ in SPECS) + " |"]
    for cell, model, tier, desc in ENS_CELLS:
        vals = []
        for s in SPECS:
            d = load(s, f"{cell}_{model}")
            win = d["evades_target"] & d["passes_validator"]
            r = bootstrap_ci(win)
            vals.append(fmt(*r))
            rows.append({"attack": cell, "tier": tier, "spec": s, "group": "ALL", "pass_and_evade_%": 100 * r[0],
                         "lo": 100 * r[1], "hi": 100 * r[2]})
        lines.append(f"| `{cell}` ({desc}) | {tier} | " + " | ".join(vals) + " |")

    # ---- 2. by window population --------------------------------------------------
    lines += ["", "## 2. By window population (pass-and-evade %)", "",
              "| attacker | " + " | ".join(f"{s}: 10-pkt | {s}: 100-pkt" for s in SPECS) + " |",
              "| --- | " + " | ".join("---: | ---:" for _ in SPECS) + " |"]
    for cell, model, _, _ in ENS_CELLS:
        cells = []
        for s in SPECS:
            t = table4b[s]
            for pop in ("pop:10-pkt", "pop:100-pkt"):
                v = t[(t.attack == cell) & (t.model == model) & (t.group == pop)]["pass_and_evade_%"]
                cells.append(f"{float(v.iloc[0]):.2f}")
        lines.append(f"| `{cell}` | " + " | ".join(cells) + " |")

    # ---- 3. by category, spec C ----------------------------------------------------
    cats = ["BruteForce", "Web", "Recon", "Spoofing", "DDoS", "DoS", "Mirai"]
    t = table4b["C"]
    lines += ["", "## 3. By category, spec C (pass-and-evade %)", "",
              "| attacker | " + " | ".join(cats) + " |", "| --- |" + " ---: |" * len(cats)]
    for cell, model, _, _ in ENS_CELLS:
        vals = [t[(t.attack == cell) & (t.model == model) & (t.group == c)]["pass_and_evade_%"] for c in cats]
        lines.append(f"| `{cell}` | " + " | ".join(f"{float(v.iloc[0]):.1f}" for v in vals) + " |")

    # ---- 4. single models: one model at a time vs all three ---------------------------
    lines += ["", "## 4. One model at a time (spec C): fooling one member is not fooling the ensemble", "",
              "| attack | target | pass-and-evade on its target | also evades all three |",
              "| --- | --- | ---: | ---: |"]
    for cell in ("feat_pgd", "prim_pgd"):
        for m in ("mlp", "cnn", "lstm"):
            r = t[(t.attack == cell) & (t.model == m) & (t.group == "ALL")].iloc[0]
            lines.append(f"| `{cell}` | {m} | {r['pass_and_evade_%']:.2f} | {r['evades_all3_%']:.2f} |")

    # ---- 5. the validator's share ---------------------------------------------------------
    lines += ["", "## 5. What the validator adds against realizable attacks (test, ensemble cells)", "",
              "`fooled models` = rows no model detects; `stopped by validator` = of those, rows the real "
              "validator rejects.", "",
              "| spec | attack | fooled models | stopped by validator | share stopped |",
              "| --- | --- | ---: | ---: | ---: |"]
    for s in SPECS:
        for cell, model in (("feat_pgd_ens", "ens"), ("prim_pgd_ens", "ens")):
            d = load(s, f"{cell}_{model}")
            fooled = d["evades_target"]
            stopped = fooled & ~d["passes_validator"]
            lines.append(f"| {s} | `{cell}` | {int(fooled.sum())} | {int(stopped.sum())} | "
                         f"{100 * stopped.sum() / max(fooled.sum(), 1):.1f}% |")

    # ---- 6. the levers: which actions do the winning rows use? --------------------------------
    lever_rows = []
    lines += ["", "## 6. Which physical actions the successful attacks use (spec C)", "",
              "Among pass-and-evade rows. `younger` = connections shortened (stretch < 0, fresh "
              "connections); `lifetime` = median factor on `flow_duration`.", "",
              "| attack | wins | younger connections | longer | padding | throttling | TTL changed | median lifetime |",
              "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for cell in ("prim_pgd_ens_ens", "adaptive_prim_ens", "greybox_surr", "blackbox_ens"):
        d = load("C", cell)
        win = d["evades_target"] & d["passes_validator"]
        th = d["theta"][win]
        r = {"attack": cell, "wins": int(win.sum()),
             "younger_%": 100 * np.mean(th[:, 3] < -1e-6), "longer_%": 100 * np.mean(th[:, 3] > 1e-6),
             "padding_%": 100 * np.mean(th[:, 0] > 1e-6), "throttling_%": 100 * np.mean(th[:, 2] > 1e-6),
             "ttl_%": 100 * np.mean(np.abs(th[:, 1]) > 1e-6),
             "median_lifetime": float(np.median(d["cost_lifetime_factor"][win]))}
        lever_rows.append(r)
        lines.append(f"| `{cell}` | {r['wins']} | {r['younger_%']:.1f}% | {r['longer_%']:.1f}% | "
                     f"{r['padding_%']:.1f}% | {r['throttling_%']:.1f}% | {r['ttl_%']:.1f}% | "
                     f"×{r['median_lifetime']:.2f} |")
    pd.DataFrame(lever_rows).to_csv(REP / "realizable_levers.csv", index=False)

    # ---- 7. cost of the successful attacks --------------------------------------------------
    lines += ["", "## 7. What success costs the attacker (spec C, medians over pass-and-evade rows)", "",
              "| attack | byte overhead | rate loss | TTL change | features changed |",
              "| --- | ---: | ---: | ---: | ---: |"]
    for cell, model, _, _ in ENS_CELLS:
        r = t[(t.attack == cell) & (t.model == model) & (t.group == "ALL")].iloc[0]
        lines.append(f"| `{cell}` | {r['med_byte_overhead_%']:.1f}% | {r['med_rate_loss_%']:.1f}% | "
                     f"{r['med_ttl_change']:.1f} | {r['med_features_changed']:.0f} |")

    # ---- 8. functional floor sweep for floods ---------------------------------------------------
    lines += ["", "## 8. Flood functional-floor sweep (spec C, pass-and-evade %)", "",
              "Floods must keep at least ρ of their original rate.", "",
              "| attack | category | ρ = 0.25 | ρ = 0.5 | ρ = 0.75 |", "| --- | --- | ---: | ---: | ---: |"]
    sweep = {0.25: pd.read_csv(REP / "table4b_realizable_test_specC_floor0.25.csv"), 0.5: t,
             0.75: pd.read_csv(REP / "table4b_realizable_test_specC_floor0.75.csv")}
    for cell, model in (("feat_pgd_ens", "ens"), ("prim_pgd_ens", "ens"), ("blackbox", "ens")):
        for c in ("DDoS", "DoS", "Mirai"):
            v = [float(sweep[rho][(sweep[rho].attack == cell) & (sweep[rho].model == model) &
                                  (sweep[rho].group == c)]["pass_and_evade_%"].iloc[0]) for rho in (0.25, 0.5, 0.75)]
            lines.append(f"| `{cell}` | {c} | " + " | ".join(f"{x:.2f}" for x in v) + " |")

    # ---- 9. Table IV-c across specs ------------------------------------------------------------
    lines += ["", "## 9. Phase-3 ART attacks projected onto realizable traffic (Table IV-c, PGD)", "",
              "| target | evasion before | after P, spec A | spec B | spec C |", "| --- | ---: | ---: | ---: | ---: |"]
    tc = {s: pd.read_csv(REP / f"table4c_projection_spec{s}.csv") for s in SPECS}
    for m in ("mlp", "cnn", "lstm"):
        r = {s: tc[s][(tc[s].attack == "pgd") & (tc[s].model == m)].iloc[0] for s in SPECS}
        lines.append(f"| {m} | {r['A']['evasion_before_%']:.2f} | " + " | ".join(
            f"{r[s]['evasion_after_projection_%']:.2f}" for s in SPECS) + " |")

    pd.DataFrame(rows).to_csv(REP / "table4d_tiers.csv", index=False)
    (REP / "table4d_tiers.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
