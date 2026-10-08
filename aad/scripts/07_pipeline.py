"""Phase 7 - wire the three defences together and measure the whole thing.

    python scripts/07_pipeline.py                    # full run
    python scripts/07_pipeline.py --no-ablation      # end-to-end table only
    python scripts/07_pipeline.py --eids baseline    # un-hardened models behind the gates

Requires phases 4, 5 and 6: artifacts/rules.json, artifacts/discriminator/rf.joblib,
artifacts/models/{mlp,cnn,lstm}_eids.keras.

Writes:
    artifacts/reports/table9_pipeline.{csv,md}       end-to-end, per traffic class
    artifacts/reports/table10_ablation.csv           every subset of the three gates
    artifacts/reports/pipeline_metrics.json
    artifacts/reports/figures/fig7_pipeline.png

One correctness point governs the whole script. The phase-5 forest was trained on
rows drawn from `test.npz`, so measuring the pipeline on the full test split would
score the discriminator on its own training data. This run therefore rebuilds the
phase-5 dataset with the same seed, recovers which rows landed in its *training*
fold, and evaluates on everything else. That is why the row counts below are
smaller than the test split, and it is the difference between an end-to-end number
and a press release.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import yaml  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tensorflow import keras  # noqa: E402

from aad.defense.discriminator import build_dataset, load_cells, split_random  # noqa: E402
from aad.defense.pipeline import (  # noqa: E402
    ALLOWED,
    DISCRIMINATOR,
    EIDS,
    STAGES,
    VALIDATOR,
    Pipeline,
    ablate,
    marginal_contribution,
)
from aad.defense.validator import Validator  # noqa: E402
from aad.models.eids import or_ensemble  # noqa: E402
from aad.plots import figure7_pipeline  # noqa: E402

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(message)s", datefmt="%H:%M:%S"
)
log = logging.getLogger("pipeline")


def rows_the_discriminator_trained_on(cells, X_test, y_test, dcfg, seed) -> np.ndarray:
    """Original test-split indices that fed the phase-5 forest's training fold.

    Rebuilt rather than stored: ``build_dataset`` and ``split_random`` are both
    seeded, so this reproduces the exact fold phase 5 used. Everything returned
    here has to be excluded from the pipeline's evaluation or the discriminator
    is being graded on its own homework.
    """
    ds = build_dataset(
        cells, X_test, y_test,
        extra_negatives=dcfg["dataset"]["extra_negatives"],
        stratify_extra=bool(dcfg["dataset"]["stratify_extra"]),
        seed=seed,
    )
    train_idx, _ = split_random(ds, float(dcfg["protocols"]["random"]["test_size"]), seed)
    return np.unique(ds.group[train_idx])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--adv-dir", default="artifacts/adversarial")
    ap.add_argument("--rules", default="artifacts/rules.json")
    ap.add_argument("--forest", default="artifacts/discriminator/rf.joblib")
    ap.add_argument("--models-dir", default="artifacts/models")
    ap.add_argument("--discriminator-config", default=str(ROOT / "config" / "discriminator.yaml"))
    ap.add_argument("--eids", default="eids", choices=["eids", "baseline"],
                    help="which NIDS generation sits at the end of the pipeline")
    ap.add_argument("--members", nargs="+", default=["mlp", "cnn", "lstm"])
    ap.add_argument("--no-ablation", action="store_true")
    ap.add_argument("--reports-dir", default="artifacts/reports")
    args = ap.parse_args()

    dcfg = yaml.safe_load(Path(args.discriminator_config).read_text(encoding="utf-8"))
    seed = int(dcfg["seed"])
    data_dir = ROOT / args.data_dir
    reports_dir = ROOT / args.reports_dir
    figures_dir = reports_dir / "figures"
    for d in (reports_dir, figures_dir):
        d.mkdir(parents=True, exist_ok=True)

    test = np.load(data_dir / "test.npz")
    X_test, y_test = test["X"].astype(np.float32), test["y"].astype(np.int64)

    # ---- the three stages --------------------------------------------------
    validator = Validator.load(ROOT / args.rules)
    forest = joblib.load(ROOT / args.forest)
    suffix = "_eids" if args.eids == "eids" else ""
    models = {
        n: keras.models.load_model(ROOT / args.models_dir / f"{n}{suffix}.keras")
        for n in args.members
    }
    log.info("EIDS generation: %s (%s)", args.eids, ", ".join(args.members))

    def validator_fn(X):
        return validator.check(X).reject

    def discriminator_fn(X):
        return forest.predict(X) == 1

    def eids_fn(X):
        preds = {n: m.predict(X, batch_size=4096, verbose=0).argmax(1).astype(np.int8)
                 for n, m in models.items()}
        return or_ensemble(preds) == 1

    fns = {VALIDATOR: validator_fn, DISCRIMINATOR: discriminator_fn, EIDS: eids_fn}
    pipeline = Pipeline(**{f"{s}_fn": f for s, f in fns.items()})

    # ---- carve out the discriminator's training fold -----------------------
    cells = load_cells(ROOT / args.adv_dir)
    seen = rows_the_discriminator_trained_on(cells, X_test, y_test, dcfg, seed)
    unseen = np.ones(len(X_test), dtype=bool)
    unseen[seen] = False
    log.info(
        "excluding %d of %d test rows the phase-5 forest trained on; %d remain",
        len(seen), len(X_test), int(unseen.sum()),
    )

    benign = np.flatnonzero(unseen & (y_test == 0))
    attack = np.flatnonzero(unseen & (y_test == 1))

    # ---- end to end --------------------------------------------------------
    rows, detail = [], {}

    def record(label: str, kind: str, X: np.ndarray) -> None:
        v = pipeline.decide(X)
        counts = v.stage_counts()
        row = {
            "traffic": label, "kind": kind, "n": len(X),
            "stopped_%": round(100 * v.stop_rate, 3),
            **{f"by_{s}_%": round(100 * counts[s] / max(1, len(X)), 3) for s in STAGES},
            f"{ALLOWED}_%": round(100 * counts[ALLOWED] / max(1, len(X)), 3),
        }
        rows.append(row)
        detail[label] = {"n": len(X), "stop_rate": v.stop_rate, "stage_counts": counts}
        log.info("%-24s %-6s n=%-6d stopped %.3f%%  %s",
                 label, kind, len(X), 100 * v.stop_rate,
                 {s: counts[s] for s in STAGES})

    record("clean benign", "FPR", X_test[benign])
    record("clean attack", "detect", X_test[attack])

    adv_parts = []
    for cell in cells:
        keep = ~np.isin(cell.idx, seen)
        if not keep.any():
            continue
        X_adv = cell.X_adv[keep]
        adv_parts.append(X_adv)
        record(f"{cell.attack} x {cell.model}", "catch", X_adv)

    X_adv_all = np.concatenate(adv_parts) if adv_parts else np.empty((0, X_test.shape[1]), np.float32)
    table = pd.DataFrame(rows)
    table.to_csv(reports_dir / "table9_pipeline.csv", index=False)

    # ---- ablation ----------------------------------------------------------
    ablation_rows: list[dict] = []
    catch_by_subset: dict[tuple[str, ...], float] = {}
    fpr_by_subset: dict[tuple[str, ...], float] = {}

    if not args.no_ablation and len(X_adv_all):
        log.info("=" * 70)
        log.info("ablation over %d adversarial and %d benign rows", len(X_adv_all), len(benign))
        adv_results = dict(ablate(fns, X_adv_all))
        fpr_results = dict(ablate(fns, X_test[benign]))
        for subset, v in adv_results.items():
            catch_by_subset[subset] = v.stop_rate
            fpr_by_subset[subset] = fpr_results[subset].stop_rate
            ablation_rows.append({
                "stages": "+".join(subset),
                "n_stages": len(subset),
                "catch_%": round(100 * v.stop_rate, 3),
                "fpr_%": round(100 * fpr_results[subset].stop_rate, 3),
            })
            log.info("%-38s catch %.3f%%  FPR %.3f%%",
                     "+".join(subset), 100 * v.stop_rate, 100 * fpr_results[subset].stop_rate)

    ablation = pd.DataFrame(ablation_rows)
    if len(ablation):
        ablation = ablation.sort_values(["n_stages", "stages"]).reset_index(drop=True)
        ablation.to_csv(reports_dir / "table10_ablation.csv", index=False)

    marginal_catch = marginal_contribution(catch_by_subset)
    marginal_fpr = marginal_contribution(fpr_by_subset)

    # ---- report ------------------------------------------------------------
    md = [
        "# Tables IX & X - the AAD pipeline end to end",
        "",
        f"`validator -> discriminator -> EIDS ({args.eids})`, short-circuiting on the first "
        "stage that stops a flow. Per-stage columns are therefore *what each stage saw and "
        "stopped*, not what it would stop alone -- a row the validator rejects never reaches "
        "the forest.",
        "",
        f"**Evaluated on the {int(unseen.sum()):,} test rows the phase-5 forest never trained "
        f"on** ({len(seen):,} excluded). Phase 5 drew its clean negatives from `test.npz`, so "
        "scoring this pipeline on the full split would grade the discriminator on its own "
        "training data. The fold is rebuilt from the same seed rather than stored.",
        "",
        "## Table IX - end to end",
        "",
        table.to_markdown(index=False),
        "",
        "`clean benign` is the deployment cost: the share of legitimate traffic the pipeline "
        "drops. It stacks across stages, because a benign flow is lost if *any* stage stops "
        "it. `clean attack` and the twelve adversarial rows are the benefit. Read them "
        "together; neither is a result on its own.",
        "",
    ]

    if len(ablation):
        md += [
            "## Table X - ablation",
            "",
            "Every subset of the three gates, over all "
            f"{len(X_adv_all):,} pooled adversarial rows and {len(benign):,} benign rows.",
            "",
            ablation.to_markdown(index=False),
            "",
            "### What each stage actually adds",
            "",
            "| stage | catch lost if removed | FPR saved if removed |",
            "| --- | ---: | ---: |",
        ]
        for stage in STAGES:
            if stage in marginal_catch:
                md.append(
                    f"| {stage} | {100 * marginal_catch[stage]:+.3f} pp "
                    f"| {100 * marginal_fpr.get(stage, 0.0):+.3f} pp |"
                )
        md += [
            "",
            "Standalone rates over-credit a redundant gate -- two gates that each stop the "
            "same 100% both look essential alone and neither is. The drop from removing a "
            "stage is the only number that answers *would we notice if this were switched "
            "off*. Phases 4 and 5 predicted redundancy here: 9 of the forest's top 15 "
            "features are the validator's integrality columns.",
            "",
        ]

    (reports_dir / "table9_pipeline.md").write_text("\n".join(md), encoding="utf-8")
    (reports_dir / "pipeline_metrics.json").write_text(
        json.dumps({
            "seed": seed,
            "eids_generation": args.eids,
            "members": args.members,
            "n_test_rows": int(len(X_test)),
            "n_excluded_discriminator_train": int(len(seen)),
            "n_benign_evaluated": int(len(benign)),
            "n_attack_evaluated": int(len(attack)),
            "n_adversarial_evaluated": int(len(X_adv_all)),
            "per_traffic": detail,
            "ablation": ablation_rows,
            "marginal_catch": marginal_catch,
            "marginal_fpr": marginal_fpr,
        }, indent=2),
        encoding="utf-8",
    )

    try:
        figure7_pipeline(table, ablation, figures_dir / "fig7_pipeline.png")
    except Exception as exc:  # noqa: BLE001 - a plotting bug must not lose the run
        log.error("figure failed (tables are safe): %s", exc)

    print("\n== Table IX - end to end ==")
    print(table.to_string(index=False))
    if len(ablation):
        print("\n== Table X - ablation ==")
        print(ablation.to_string(index=False))
        print("\nmarginal catch (pp lost if removed):", {k: round(100 * v, 3) for k, v in marginal_catch.items()})
        print("marginal FPR   (pp saved if removed):", {k: round(100 * v, 3) for k, v in marginal_fpr.items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
