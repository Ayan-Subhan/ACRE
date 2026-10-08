"""Phase 5 - train and honestly evaluate the adversarial discriminator.

    python scripts/05_train_discriminator.py                    # all protocols
    python scripts/05_train_discriminator.py --protocols random # the paper's number only
    python scripts/05_train_discriminator.py --extra-negatives 5000   # quick run

Writes:
    artifacts/discriminator/rf.joblib              the deployable forest
    artifacts/discriminator/dataset_meta.json      how the training set was assembled
    artifacts/reports/table6_discriminator.{csv,md}
    artifacts/reports/discriminator_metrics.json
    artifacts/reports/figures/fig5_discriminator.png

Three protocols are reported side by side and the difference between them is the
result. ``random`` reproduces the paper: train on all four attack families, test
on all four, expect ~100%. ``leave_one_attack_out`` and ``leave_one_model_out``
withhold a whole family from training and ask whether the forest generalises to
an adversary it has never seen -- which is the only version of the question a
deployed detector actually faces.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aad.defense.discriminator import (  # noqa: E402
    build_dataset,
    fit_and_score,
    load_cells,
    split_leave_one_out,
    split_random,
    top_importances,
)
from aad.plots import figure5_discriminator  # noqa: E402

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(message)s", datefmt="%H:%M:%S"
)
log = logging.getLogger("discriminator")


def row_for(protocol: str, held: str, m: dict) -> dict:
    """One line of Table VI. Positive class is adversarial, so recall is the
    catch rate and FPR is legitimate traffic wrongly quarantined."""
    return {
        "protocol": protocol,
        "held_out": held,
        "n_train": m["n_train"],
        "n_test": m["n_test"],
        "accuracy_%": round(100 * m["accuracy"], 3),
        "precision_%": round(100 * m["precision"], 3),
        "catch_%": round(100 * m["recall"], 3),
        "f1_%": round(100 * m["f1"], 3),
        "fpr_%": round(100 * m["fpr"], 3),
        "fn": m["fn"],
        "fp": m["fp"],
        "fit_s": m["fit_seconds"],
    }


def integrality_overlap(importances: list[dict], rules_path: Path, feature_names: list[str]) -> dict:
    """How much of the forest's attention sits on the validator's integer columns.

    If gate 2's most important features are the same count-like columns gate 1
    checks for whole-numberedness, the two gates are not independent and a single
    adaptive attacker defeats both. Reported rather than assumed.
    """
    if not rules_path.exists():
        return {}
    rules = json.loads(rules_path.read_text(encoding="utf-8"))
    integer_idx = set(rules.get("integrality", {}).get("indices", []))
    if not integer_idx:
        return {}
    hits = [f["feature"] for f in importances if f["index"] in integer_idx]
    return {
        "n_integer_columns": len(integer_idx),
        "top_k": len(importances),
        "top_k_that_are_integer_columns": len(hits),
        "which": hits,
        "mass_on_integer_columns": round(
            sum(f["gini_importance"] for f in importances if f["index"] in integer_idx), 4
        ),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(ROOT / "config" / "discriminator.yaml"))
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--adv-dir", default="artifacts/adversarial")
    ap.add_argument("--rules", default="artifacts/rules.json")
    ap.add_argument("--tag", default=None, help="suffix so variant runs do not collide")
    ap.add_argument("--protocols", nargs="+", default=None,
                    choices=["random", "leave_one_attack_out", "leave_one_model_out"])
    ap.add_argument("--extra-negatives", default=None,
                    help="override config; an integer, or 'auto' for a 1:1 clean/adversarial mix")
    ap.add_argument("--n-estimators", type=int, default=None, help="override, for a quick run")
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    seed = int(cfg["seed"])
    tag = f"_{args.tag}" if args.tag else ""
    rf_cfg = dict(cfg["random_forest"])
    if args.n_estimators:
        rf_cfg["n_estimators"] = args.n_estimators

    data_dir = ROOT / args.data_dir
    out_dir = ROOT / cfg["output"]["discriminator_dir"]
    reports_dir = ROOT / cfg["output"]["reports_dir"]
    figures_dir = ROOT / cfg["output"]["figures_dir"]
    for d in (out_dir, reports_dir, figures_dir):
        d.mkdir(parents=True, exist_ok=True)

    test = np.load(data_dir / "test.npz")
    X_pool, y_pool = test["X"].astype(np.float32), test["y"].astype(np.int64)
    feature_names = json.loads((data_dir / "feature_names.json").read_text(encoding="utf-8"))

    # ---- assemble ----------------------------------------------------------
    cells = load_cells(ROOT / args.adv_dir, tag or "")
    extra = args.extra_negatives if args.extra_negatives is not None else cfg["dataset"]["extra_negatives"]
    if isinstance(extra, str) and extra != "auto":
        extra = int(extra)
    ds = build_dataset(
        cells, X_pool, y_pool,
        extra_negatives=extra,
        stratify_extra=bool(cfg["dataset"]["stratify_extra"]),
        seed=seed,
    )

    test_size = float(cfg["protocols"]["random"]["test_size"])
    wanted = args.protocols or [
        p for p in ("random", "leave_one_attack_out", "leave_one_model_out")
        if cfg["protocols"].get(p)
    ]

    rows: list[dict] = []
    detail: dict[str, dict] = {}
    deployable = None
    importances: list[dict] = []

    # ---- protocol 1: the paper's number ------------------------------------
    if "random" in wanted:
        train, test_idx = split_random(ds, test_size, seed)
        clf, m, _ = fit_and_score(ds, train, test_idx, rf_cfg, seed)
        rows.append(row_for("random", "-", m))
        detail["random"] = {"-": m}
        deployable, importances = clf, top_importances(clf, feature_names)
        log.info("random          catch %.3f%%  FPR %.3f%%", 100 * m["recall"], 100 * m["fpr"])

    # ---- protocol 2: an unseen attack family -------------------------------
    if "leave_one_attack_out" in wanted:
        detail["leave_one_attack_out"] = {}
        for held in ds.attacks:
            train, test_idx = split_leave_one_out(ds, "attack", held, test_size, seed)
            _, m, _ = fit_and_score(ds, train, test_idx, rf_cfg, seed)
            rows.append(row_for("leave_one_attack_out", held, m))
            detail["leave_one_attack_out"][held] = m
            log.info("LOAO %-9s  catch %.3f%%  FPR %.3f%%", held, 100 * m["recall"], 100 * m["fpr"])

    # ---- protocol 3: an unseen target model --------------------------------
    if "leave_one_model_out" in wanted:
        detail["leave_one_model_out"] = {}
        for held in ds.models:
            train, test_idx = split_leave_one_out(ds, "model", held, test_size, seed)
            _, m, _ = fit_and_score(ds, train, test_idx, rf_cfg, seed)
            rows.append(row_for("leave_one_model_out", held, m))
            detail["leave_one_model_out"][held] = m
            log.info("LOMO %-9s  catch %.3f%%  FPR %.3f%%", held, 100 * m["recall"], 100 * m["fpr"])

    table = pd.DataFrame(rows)
    table.to_csv(reports_dir / f"table6_discriminator{tag}.csv", index=False)

    if deployable is not None:
        joblib.dump(deployable, out_dir / f"rf{tag}.joblib")
        log.info("saved %s", out_dir / f"rf{tag}.joblib")

    overlap = integrality_overlap(importances, ROOT / args.rules, feature_names) if importances else {}

    # ---- report ------------------------------------------------------------
    n_pos, n_neg = int(ds.y.sum()), int((ds.y == 0).sum())
    md = [
        "# Table VI - adversarial discriminator (Random Forest, Gini)",
        "",
        f"{len(ds):,} rows: {n_pos:,} adversarial and {n_neg:,} clean "
        f"({len(cells[0].idx):,} exact unperturbed twins of the positives, plus "
        f"{n_neg - len(cells[0].idx):,} further rows sampled from the same split). "
        f"{rf_cfg['n_estimators']} trees, `criterion={rf_cfg['criterion']}`, "
        f"`class_weight={rf_cfg['class_weight']}`, seed {seed}.",
        "",
        "**Positive class = adversarial.** `catch_%` is recall over perturbed rows; "
        "`fpr_%` is the fraction of legitimate traffic wrongly quarantined. As in phase 4 "
        "these are reported apart and never blended.",
        "",
        "Every split is **grouped on the source flow**, so a perturbed row and its clean "
        "twin can never land on opposite sides. Without that, the forest is tested on "
        "flows whose originals it memorised, and the number is meaningless.",
        "",
        table.to_markdown(index=False),
        "",
        "## Reading this",
        "",
        "- **random** trains on all four attack families and tests on all four. This is "
        "the protocol the paper reports, and it is the optimistic one: the adversary the "
        "forest meets at test time is the adversary it was trained on.",
        "- **leave_one_attack_out** withholds an entire family from training. The gap "
        "between it and `random` is the part of the paper's number that comes from having "
        "seen the attack before.",
        "- **leave_one_model_out** withholds every example crafted against one target "
        "model, testing whether a perturbation fingerprint transfers across the "
        "architecture it was built to fool.",
        "",
    ]

    if "leave_one_attack_out" in detail:
        rnd = detail.get("random", {}).get("-")
        worst = min(detail["leave_one_attack_out"].items(), key=lambda kv: kv[1]["recall"])
        md += [
            f"The weakest hold-out is **{worst[0]}** at {100 * worst[1]['recall']:.2f}% catch"
            + (f", against {100 * rnd['recall']:.2f}% when it is in the training set."
               if rnd else ".")
            + " That difference, not the headline, is what the discriminator is worth "
              "against an adversary who picks an attack you did not anticipate.",
            "",
        ]

    if importances:
        md += [
            "## What the forest actually looks at",
            "",
            "Gini importance, top 15.",
            "",
            pd.DataFrame(importances)[["feature", "gini_importance"]]
            .assign(gini_importance=lambda d: d["gini_importance"].round(5))
            .to_markdown(index=False),
            "",
        ]
        if overlap:
            md += [
                f"**{overlap['top_k_that_are_integer_columns']} of the top "
                f"{overlap['top_k']}** are columns phase 4's validator already checks for "
                f"whole-numberedness ({overlap['mass_on_integer_columns']:.3f} of the total "
                "importance mass). The two gates are therefore *not* independent: to the "
                "extent this overlap is large, the discriminator has rediscovered the "
                "validator's arithmetic rather than adding a second, separate obstacle -- "
                "and one adaptive attacker who rounds onto the integer lattice degrades "
                "both at once. Phase 7 should not treat their catch rates as multiplying.",
                "",
            ]

    (reports_dir / f"table6_discriminator{tag}.md").write_text("\n".join(md), encoding="utf-8")
    (reports_dir / f"discriminator_metrics{tag}.json").write_text(
        json.dumps({
            "seed": seed,
            "data_dir": args.data_dir,
            "random_forest": rf_cfg,
            "dataset": {
                "n_rows": len(ds),
                "n_adversarial": n_pos,
                "n_clean": n_neg,
                "n_twins": len(cells[0].idx),
                "n_groups": int(len(np.unique(ds.group))),
                "attacks": ds.attacks,
                "models": ds.models,
                "test_size": test_size,
            },
            "importances_top15": importances,
            "integrality_overlap": overlap,
            "results": detail,
        }, indent=2),
        encoding="utf-8",
    )
    (out_dir / f"dataset_meta{tag}.json").write_text(
        json.dumps({
            "source_row_indices_sha": int(cells[0].idx.sum()),
            "n_cells": len(cells),
            "cells": [f"{c.attack}x{c.model}" for c in cells],
            "extra_negatives": extra,
            "seed": seed,
        }, indent=2),
        encoding="utf-8",
    )

    try:
        figure5_discriminator(table, figures_dir / f"fig5_discriminator{tag}.png")
    except Exception as exc:  # noqa: BLE001 - a plotting bug must not lose the run
        log.error("figure failed (tables and model are safe): %s", exc)

    print("\n" + table.to_string(index=False))

    if "random" in detail and "leave_one_attack_out" in detail:
        rnd = detail["random"]["-"]["recall"]
        loo = min(m["recall"] for m in detail["leave_one_attack_out"].values())
        log.info("generalisation gap: %.2f pp between random and the worst hold-out",
                 100 * (rnd - loo))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
