"""M4 step 4.2 - audit the realism spec against the data.

    python scripts/03a_audit_realism.py

``config/realism.yaml`` is a hypothesis about what the extractor computes and what
an attacker can move. Like the M3 rules, it is checked against the data before
anything relies on it: every relation and bound the projection P assumes is
measured on the TRAIN split (benign and attack rows, in raw units), and every
assumption gets a verdict.

Writes:
    artifacts/reports/realism_audit.md
    artifacts/reports/realism_audit.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aad.attacks.realizable.constraints import RealismSpec, Scaling  # noqa: E402
from aad.defense.validator import scaled_to_raw  # noqa: E402
from aad.evaluate import load_class_names  # noqa: E402


def rel(a, b):
    return np.abs(a - b) / (np.abs(b) + 1e-9)


def pct(x):
    return float(100.0 * np.mean(x))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--realism", default="config/realism.yaml")
    ap.add_argument("--reports-dir", default="artifacts/reports")
    ap.add_argument("--max-rows", type=int, default=400_000, help="stratified train subsample")
    args = ap.parse_args()

    data_dir = ROOT / args.data_dir
    sc = Scaling.load(data_dir / "transform.json")
    spec = RealismSpec.load(ROOT / args.realism, "A")
    names = list(sc.feature_names)
    idx = {n: i for i, n in enumerate(names)}
    _, cat_names = load_class_names(data_dir)

    d = np.load(data_dir / "train.npz")
    rng = np.random.default_rng(0)
    take = np.sort(rng.choice(len(d["y"]), size=min(args.max_rows, len(d["y"])), replace=False))
    X, ycat = d["X"][take], d["y_category"][take]
    raw = scaled_to_raw(X, sc.data_min, sc.data_range, sc.log1p_indices)
    col = lambda n: raw[:, idx[n]]  # noqa: E731
    cats = np.array([cat_names[int(c)] for c in ycat])
    groups = {"benign": cats == "Benign", "attack": cats != "Benign", "all": np.ones(len(cats), bool)}

    checks = []

    def check(name, assumption, values: dict, verdict: str, note: str = ""):
        checks.append({"check": name, "assumption": assumption, "verdict": verdict,
                       "note": note, **values})

    # -- classification coverage -------------------------------------------------
    unclassified = [n for n in names if n not in spec.classes]
    check("coverage", "every model feature has a realism class",
          {"features": len(names), "unclassified": len(unclassified)},
          "holds" if not unclassified else "FAILS", ", ".join(unclassified))

    # -- derived relations -----------------------------------------------------------
    if {"Srate", "Rate"} <= idx.keys():
        r = rel(col("Srate"), col("Rate"))
        check("Srate = Rate", "Srate is recomputed as Rate",
              {g: f"max rel. err {r[m].max():.2e}" for g, m in groups.items()},
              "holds" if r.max() < 1e-5 else "approximate")
    if {"Magnitue", "AVG"} <= idx.keys():
        r = rel(col("Magnitue") ** 2, 2 * col("AVG"))
        check("Magnitue² ≈ 2·AVG", "padding by p adds 2p to Magnitue² (sqrt_shift)",
              {g: f"median rel. err {np.median(r[m]):.2%}, p90 {np.quantile(r[m], 0.9):.2%}"
               for g, m in groups.items()},
              "holds" if np.median(r) < 0.01 else "approximate")
    if {"Tot sum", "AVG"} <= idx.keys():
        ratio = col("Tot sum") / np.maximum(col("AVG"), 1e-9)
        check("Tot sum ∝ AVG", "Tot sum scales with AVG at the row's own ratio (scale_with)",
              {g: f"Tot sum / AVG median {np.median(ratio[m]):.2f} (p10 {np.quantile(ratio[m], .1):.2f}, "
                  f"p90 {np.quantile(ratio[m], .9):.2f})" for g, m in groups.items()},
              "assumption", "the ratio is a per-row packet count; padding keeps it, so Tot sum moves with AVG")
    if {"Tot size", "AVG"} <= idx.keys():
        r = rel(col("Tot size"), col("AVG"))
        check("Tot size ≈ AVG", "both padded by the same amount (increase_only)",
              {g: f"median rel. err {np.median(r[m]):.2%}" for g, m in groups.items()},
              "approximate" if np.median(r) < 0.1 else "FAILS")

    # -- invariants P must keep ------------------------------------------------------------
    if {"Min", "AVG", "Max"} <= idx.keys():
        ok = (col("Min") <= col("AVG") * (1 + 1e-6)) & (col("AVG") <= col("Max") * (1 + 1e-6))
        check("Min ≤ AVG ≤ Max", "restored by P after the size clamps",
              {g: f"{pct(ok[m]):.4f}% of rows" for g, m in groups.items()},
              "holds" if ok.all() else "approximate")
    binary = [n for n in names if spec.classes[n] == "immutable" and
              np.isin(np.unique(np.round(col(n), 6)), [0.0, 1.0]).all()]
    check("binary columns", "flags and protocol indicators are 0/1 and immutable",
          {"all": f"{len(binary)} immutable columns are strictly 0/1"}, "holds", ", ".join(binary))

    # -- bounds ----------------------------------------------------------------------------
    if "Max" in idx:
        over = col("Max") > spec.size_cap
        check("size cap", f"packets are padded to at most {spec.size_cap:g} bytes",
              {g: f"{pct(over[m]):.2f}% of rows already exceed it (they keep their own Max as the cap)"
               for g, m in groups.items()}, "assumption")
    if "Duration" in idx:
        lo, hi = spec.free_bounds["Duration"]
        inside = (col("Duration") >= lo) & (col("Duration") <= hi)
        check("TTL range", f"Duration (mean TTL) lies in [{lo:g}, {hi:g}]",
              {g: f"{pct(inside[m]):.3f}% inside; min {col('Duration')[m].min():.2f}"
               for g, m in groups.items()}, "holds" if inside.mean() > 0.999 else "approximate")
    if "Rate" in idx:
        zero = col("Rate") <= 0
        check("Rate > 0", "throttling scales a positive rate",
              {g: f"{pct(zero[m]):.2f}% of rows have Rate 0 (throttling cannot move them)"
               for g, m in groups.items()}, "assumption")
    flow = [n for n in names if spec.classes[n] == "flow_age"]
    if flow:
        zeros = {n: pct(col(n)[groups["attack"]] == 0) for n in flow}
        check("flow-age zeros (spec B)", "stretching multiplies; a zero stays zero",
              {"attack": ", ".join(f"{n} {v:.1f}% zero" for n, v in zeros.items())}, "assumption")

    # -- what the representable range allows --------------------------------------------------
    hi_raw = scaled_to_raw(np.ones((1, len(names))), sc.data_min, sc.data_range, sc.log1p_indices)[0]
    head = {n: float(np.median(hi_raw[idx[n]] / np.maximum(col(n)[groups["attack"]], 1e-9)))
            for n in ("AVG", "Max", "Duration") if n in idx}
    check("representable headroom", "P clips to what the scaler represents (scaled 1.0)",
          {"attack": ", ".join(f"{n}: median row can grow {v:.1f}x" for n, v in head.items())},
          "assumption")

    reports = ROOT / args.reports_dir
    (reports / "realism_audit.json").write_text(json.dumps(
        {"rows": int(len(take)), "split": "train", "checks": checks}, indent=2), encoding="utf-8")
    lines = ["# Realism audit (M4 step 4.2)", "",
             f"Every relation and bound `config/realism.yaml` relies on, measured on {len(take):,} "
             "stratified-random TRAIN rows in raw units. *holds* = exact on the data; *approximate* = "
             "true up to the stated error; *assumption* = a modelling choice the data can only "
             "describe, to be confirmed by the extractor code (4.1) and at packet level (M7).", ""]
    for c in checks:
        lines.append(f"### {c['check']} — {c['verdict']}")
        lines.append("")
        lines.append(f"*{c['assumption']}*")
        lines.append("")
        for k in ("benign", "attack", "all", "features", "unclassified"):
            if k in c:
                lines.append(f"- {k}: {c[k]}")
        if c["note"]:
            lines.append(f"- note: {c['note']}")
        lines.append("")
    (reports / "realism_audit.md").write_text("\n".join(lines), encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # check names use ≈ and ≤
    for c in checks:
        print(f"{c['verdict']:<12} {c['check']}")


if __name__ == "__main__":
    main()
