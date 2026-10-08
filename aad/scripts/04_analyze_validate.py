"""Phase 4 (M3) - mine benign CICIoT2023 traffic into rules.json, then measure the validator.

    python scripts/04_analyze_validate.py                 # mine + evaluate
    python scripts/04_analyze_validate.py --fpr-budget 0.005

Writes:
    artifacts/rules.json                           the mined rule set (incl. pruned candidates)
    artifacts/reports/table5_validator.{csv,md}    catch-rate and FPR, separately
    artifacts/reports/validator_metrics.json       everything above, plus per-category detail

Discipline, unchanged from the IDS2018 run: mine on benign TRAIN, calibrate the
distribution thresholds on benign VAL, report on TEST. Catch-rate and FPR are
reported apart and never blended - a validator that catches 100% while
rejecting 3% of legitimate traffic is unusable, and one blended number would
hide that. Walkthrough and results: docs/m3-validator.md.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aad.defense.analyzer import calibrate_distribution, mine, save  # noqa: E402
from aad.defense.validator import FAMILIES, Validator  # noqa: E402
from aad.evaluate import load_class_names  # noqa: E402

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(message)s", datefmt="%H:%M:%S"
)
log = logging.getLogger("validate")

USABILITY_FPR = 0.03


def load_split(data_dir: Path, name: str):
    d = np.load(data_dir / f"{name}.npz")
    return (d["X"].astype(np.float32), d["y"].astype(np.int64),
            d["y_multiclass"].astype(np.int8), d["y_category"].astype(np.int8))


def row_for(label: str, kind: str, result, n: int) -> dict:
    row = {"set": label, "kind": kind, "n": n, "combined_%": round(100 * result.reject_rate, 3)}
    for family, rate in result.family_rates().items():
        row[f"{family}_%"] = round(100 * rate, 3)
    return row


def sole_family_rates(result) -> dict[str, float]:
    """Share of rows rejected by exactly one family, per family. This is the
    attribution that says which family *carries* the gate: a family whose
    catches are all also made by another family adds nothing on its own."""
    stack = np.stack([result.by_family[f] for f in FAMILIES])
    alone = stack.sum(axis=0) == 1
    return {f: float((stack[i] & alone).mean()) for i, f in enumerate(FAMILIES)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--adv-dir", default="artifacts/adversarial")
    ap.add_argument("--out", default="artifacts/rules.json")
    ap.add_argument("--reports-dir", default="artifacts/reports")
    ap.add_argument("--fpr-budget", type=float, default=0.01,
                    help="distribution family's false-positive budget on benign val, per group")
    ap.add_argument("--range-tolerance", type=float, default=0.01)
    ap.add_argument("--dependency-percentile", type=float, default=99.9)
    args = ap.parse_args()

    data_dir = ROOT / args.data_dir
    reports_dir = ROOT / args.reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)

    X_train, y_train, _, _ = load_split(data_dir, "train")
    X_val, y_val, _, _ = load_split(data_dir, "val")
    X_test, y_test, _, c_test = load_split(data_dir, "test")
    feature_names = json.loads((data_dir / "feature_names.json").read_text(encoding="utf-8"))
    _, category_names = load_class_names(data_dir)
    # Everything needed to map scaled rows back to raw units (MinMax + signed log1p).
    tr = json.loads((data_dir / "transform.json").read_text(encoding="utf-8"))
    assert tr["feature_names"] == feature_names, "transform.json disagrees with feature_names.json"

    # ---- mine on benign train, calibrate on benign val ---------------------------
    rules = mine(
        X_train[y_train == 0], feature_names,
        np.asarray(tr["minmax_data_min"]), np.asarray(tr["minmax_data_range"]),
        log1p_indices=tr["log1p_indices"],
        range_tolerance=args.range_tolerance,
        dependency_percentile=args.dependency_percentile,
    )
    rules = calibrate_distribution(rules, X_val[y_val == 0], fpr_budget=args.fpr_budget,
                                   X_train_benign_scaled=X_train[y_train == 0])
    save(rules, ROOT / args.out)
    validator = Validator(rules)

    # ---- false positives and clean-attack rejects, on rows the rules never saw ----
    benign_test, attack_test = X_test[y_test == 0], X_test[y_test == 1]
    fpr = validator.check(benign_test)
    rows = [row_for("clean benign (test)", "FPR", fpr, len(benign_test)),
            row_for("clean attack (test)", "reject", validator.check(attack_test), len(attack_test))]
    log.info("=" * 72)
    log.info("false-positive rate on %d unseen benign test rows: %.4f%%",
             len(benign_test), 100 * fpr.reject_rate)
    for family, rate in fpr.family_rates().items():
        log.info("    %-13s %.4f%%", family, 100 * rate)

    # Per protocol group (benign FPR) and per category (clean reject).
    groups = validator.groups(validator.to_raw(benign_test))
    group_rows = []
    for g, gname in enumerate(rules["distribution"]["groups"]):
        mask = groups == g
        if mask.any():
            res = validator.check(benign_test[mask])
            group_rows.append({"protocol group": gname, "benign test rows": int(mask.sum()),
                               "FPR_%": round(100 * res.reject_rate, 3),
                               **{f"{f}_%": round(100 * r, 3) for f, r in res.family_rates().items()}})
    cat_rows = []
    for c, cname in category_names.items():
        mask = c_test == c
        if mask.any():
            res = validator.check(X_test[mask])
            cat_rows.append({"category": cname, "test rows": int(mask.sum()),
                             "rejected_%": round(100 * res.reject_rate, 3),
                             **{f"{f}_%": round(100 * r, 3) for f, r in res.family_rates().items()}})

    # ---- catch rate, per adversarial artefact ---------------------------------------
    npz_files = sorted((ROOT / args.adv_dir).glob("*.npz"))
    if not npz_files:
        log.warning("no .npz in %s -- run scripts/03_generate_ae.py first", args.adv_dir)
    per_cell: list[dict] = []
    for path in npz_files:
        d = np.load(path, allow_pickle=False)
        meta = json.loads(str(d["meta"]))
        res = validator.check(d["X_adv"])
        # A raw catch rate partly measures maliciousness: real attack rows already
        # sit outside the benign envelope. What the gate adds as an AE detector is
        # what it rejects only after perturbation.
        base = validator.check(d["X_clean"])
        row = row_for(f"{meta['attack']} x {meta['model']}", "catch", res, len(d["X_adv"]))
        row["clean_orig_%"] = round(100 * base.reject_rate, 3)
        row["attributable_%"] = round(100 * float((res.reject & ~base.reject).mean()), 3)
        # End to end through gate 1: the row passes the validator AND the model it
        # was crafted against calls it benign. This is the attacker's real success.
        row["pass_and_evade_%"] = round(100 * float((~res.reject & (d["pred_adv"] == 0)).mean()), 3)
        row["evade_model_only_%"] = round(100 * float((d["pred_adv"] == 0).mean()), 3)
        row.update({f"sole_{f}_%": round(100 * r, 3) for f, r in sole_family_rates(res).items()})
        row["attack"], row["model"] = meta["attack"], meta["model"]
        per_cell.append(row)
        log.info("%-22s catch %.2f%% (clean originals %.2f%%, attributable %.2f%%)  [%s]",
                 path.stem, 100 * res.reject_rate, 100 * base.reject_rate, row["attributable_%"],
                 ", ".join(f"{k} {100*v:.1f}%" for k, v in res.family_rates().items()))

    main_cols = ["set", "kind", "n", "combined_%", *[f"{f}_%" for f in FAMILIES],
                 "clean_orig_%", "attributable_%", "evade_model_only_%", "pass_and_evade_%"]
    table = pd.DataFrame(rows + per_cell).reindex(columns=main_cols)
    table.to_csv(reports_dir / "table5_validator.csv", index=False)

    # ---- report ---------------------------------------------------------------------
    deps, pruned = rules["dependency"]["rules"], rules["dependency"]["excluded_loose"]
    d = rules["distribution"]
    md = [
        "# Table V - validator catch-rate and false-positive rate (CICIoT2023)",
        "",
        f"Rules mined from {rules['provenance']['n_rows']:,} **benign training** rows. "
        f"Distribution thresholds calibrated per protocol group on benign *validation* rows "
        f"at a {100*args.fpr_budget:.1f}% budget. Everything below is measured on **test**, "
        "which neither pass saw. Walkthrough: `docs/m3-validator.md`.",
        "",
        table.to_markdown(index=False),
        "",
        "## The mined rule set",
        "",
        f"- **integrality** ({len(rules['integrality']['columns'])} columns): "
        f"{', '.join(rules['integrality']['columns']) or 'none'}",
        f"- **dependency kept** ({len(deps)}): " + "; ".join(
            f"`{r['name']}` (tol {r['tolerance']:.0e})" for r in deps),
        f"- **dependency pruned as loose** ({len(pruned)}): " + "; ".join(
            f"`{r['name']}` (benign p99.9 residual "
            f"{r['benign_residual'][f'p{args.dependency_percentile}']:.3g})" for r in pruned),
        "- **distribution groups**: " + "; ".join(
            f"{g} ({n:,} train rows{', global profile' if fb else ''}, threshold {t:.3f} "
            f"from {src})"
            for g, n, fb, t, src in zip(d["groups"], d["train_rows"], d["uses_global_profile"],
                                        d["threshold"], d["calibration"]["threshold_source"])),
        "",
        "## False positives by protocol group (clean benign test)",
        "",
        pd.DataFrame(group_rows).to_markdown(index=False),
        "",
        "## Clean (unperturbed) test rows rejected, by category",
        "",
        "For attack categories this is not an error - those rows are real intrusions - but "
        "it is the `clean_orig` baseline every catch rate below has to be read against.",
        "",
        pd.DataFrame(cat_rows).to_markdown(index=False),
        "",
    ]
    if per_cell:
        cell_df = pd.DataFrame(per_cell)
        fam = pd.DataFrame({
            "family": FAMILIES,
            "mean catch_%": [round(cell_df[f"{f}_%"].mean(), 2) for f in FAMILIES],
            "mean sole_%": [round(cell_df[f"sole_{f}_%"].mean(), 2) for f in FAMILIES],
        })
        dominant = fam.sort_values("mean sole_%", ascending=False).iloc[0]["family"]
        md += [
            "## Which family carries the gate?",
            "",
            "`sole_%` = adversarial rows rejected by that family *and no other*. A family "
            "with a high catch but ~0 sole catches is redundant with the others.",
            "",
            fam.to_markdown(index=False),
            "",
            f"Mean across the {len(per_cell)} adversarial sets: combined catch "
            f"{cell_df['combined_%'].mean():.2f}%, attributable to perturbation "
            f"{cell_df['attributable_%'].mean():.2f}%. The family carrying the most "
            f"catches on its own is **{dominant}**.",
            "",
            "`evade_model_only_%` = adversarial rows the target model calls benign with no "
            "gate in front; `pass_and_evade_%` = rows that also pass the validator, i.e. "
            f"the attacker's real success through gate 1. Worst cell: "
            f"{cell_df.loc[cell_df['pass_and_evade_%'].idxmax(), 'set']} at "
            f"{cell_df['pass_and_evade_%'].max():.2f}%.",
            "",
        ]
    (reports_dir / "table5_validator.md").write_text("\n".join(md), encoding="utf-8")

    (reports_dir / "validator_metrics.json").write_text(json.dumps({
        "fpr_budget": args.fpr_budget,
        "range_tolerance": args.range_tolerance,
        "dependency_percentile": args.dependency_percentile,
        "integer_columns": rules["integrality"]["columns"],
        "integrality_excluded_unverifiable": rules["integrality"]["excluded_unverifiable"],
        "dependency_rules": [{"name": r["name"], "tolerance": r["tolerance"],
                              "benign_residual": r["benign_residual"]} for r in deps],
        "dependency_pruned": [{"name": r["name"], "reason": r["reason"],
                               "benign_residual": r["benign_residual"]} for r in pruned],
        "distribution": {k: d[k] for k in ("groups", "train_rows", "uses_global_profile",
                                           "threshold", "calibration")},
        "fpr_by_group": group_rows,
        "reject_by_category": cat_rows,
        "rows": rows + per_cell,
    }, indent=2), encoding="utf-8")

    print("\n" + table.to_string(index=False))
    if fpr.reject_rate > USABILITY_FPR:
        log.warning("FPR %.3f%% exceeds the %.0f%% usability line",
                    100 * fpr.reject_rate, 100 * USABILITY_FPR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
