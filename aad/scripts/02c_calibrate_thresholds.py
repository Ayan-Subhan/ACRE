"""M4 step 4.0 (decision D2) - calibrate each baseline's decision threshold.

    python scripts/02c_calibrate_thresholds.py                 # 2% benign-FPR budget
    python scripts/02c_calibrate_thresholds.py --fpr 0.01

Argmax (P(attack) >= 0.5) is an accident of training, not an operating point.
Every gate in the AAD pipeline adds false alarms (validator 1%, IDS, then the
discriminator), so each IDS gets an explicit budget instead: the smallest
threshold whose false-positive rate on **validation** benign rows is at most
``--fpr``. Test rows are only used to report what that threshold delivers.

Writes:
    artifacts/models/thresholds.json      threshold per model + val/test metrics
    artifacts/reports/thresholds.md       the same as a table, next to argmax

Every M4+ attack judges evasion at these thresholds (docs/m4-plan.md, D2).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tensorflow import keras  # noqa: E402

import aad.models.base  # noqa: E402,F401  (portable .keras loading)
from aad.evaluate import (  # noqa: E402
    binary_metrics, load_class_names, per_category_recall, threshold_for_fpr,
)

log = logging.getLogger("02c")


def p_attack(model, X: np.ndarray) -> np.ndarray:
    return model.predict(X, batch_size=8192, verbose=0)[:, 1].astype(np.float64)


def summarise(y, ycat, p, t, cat_names) -> dict:
    pred = (p >= t).astype(np.int8)
    m = binary_metrics(y, pred)
    return {
        "balanced_accuracy": m["balanced_accuracy"],
        "fpr": m["fpr"],
        "recall": m["recall"],
        "per_category": {k: v["correct_rate"] for k, v in
                         per_category_recall(ycat, pred, cat_names).items()},
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--models-dir", default="artifacts/models")
    ap.add_argument("--reports-dir", default="artifacts/reports")
    ap.add_argument("--models", nargs="+", default=["mlp", "cnn", "lstm"])
    ap.add_argument("--fpr", type=float, default=0.02, help="benign FPR budget per model")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(message)s",
                        datefmt="%H:%M:%S")

    data_dir, models_dir = ROOT / args.data_dir, ROOT / args.models_dir
    reports_dir = ROOT / args.reports_dir
    _, cat_names = load_class_names(data_dir)
    val, test = (np.load(data_dir / f"{s}.npz") for s in ("val", "test"))
    feature_names = json.loads((data_dir / "feature_names.json").read_text(encoding="utf-8"))

    out = {"fpr_budget": args.fpr, "calibrated_on": "val", "rule": "attack iff P(attack) >= threshold",
           "feature_names": feature_names, "models": {}}
    preds_val, preds_test = {}, {}
    for name in args.models:
        model = keras.models.load_model(models_dir / f"{name}.keras", compile=False)
        if model.input_shape[-1] != len(feature_names):
            raise SystemExit(f"{name}.keras takes {model.input_shape[-1]} features, the data has "
                             f"{len(feature_names)}: retrain it first (02_train_baselines.py)")
        pv, pt = p_attack(model, val["X"]), p_attack(model, test["X"])
        t = threshold_for_fpr(pv[val["y"] == 0], args.fpr)
        preds_val[name], preds_test[name] = pv >= t, pt >= t
        out["models"][name] = {
            "threshold": t,
            "val": summarise(val["y"], val["y_category"], pv, t, cat_names),
            "test": summarise(test["y"], test["y_category"], pt, t, cat_names),
            "test_argmax": summarise(test["y"], test["y_category"], pt, 0.5, cat_names),
        }
        r = out["models"][name]
        log.info("%-4s threshold %.6f | val FPR %.3f%% | test FPR %.3f%% bal.acc %.3f%% "
                 "(argmax: FPR %.3f%% bal.acc %.3f%%)", name, t, 100 * r["val"]["fpr"],
                 100 * r["test"]["fpr"], 100 * r["test"]["balanced_accuracy"],
                 100 * r["test_argmax"]["fpr"], 100 * r["test_argmax"]["balanced_accuracy"])

    # The OR-ensemble fires if any member fires, so its FPR is the union of theirs.
    for split, preds, d in (("val", preds_val, val), ("test", preds_test, test)):
        any_ = np.any(np.stack(list(preds.values())), axis=0).astype(np.int8)
        m = binary_metrics(d["y"], any_)
        out[f"or_ensemble_{split}"] = {"members": list(preds), "fpr": m["fpr"],
                                       "balanced_accuracy": m["balanced_accuracy"]}
    log.info("OR-ensemble at member thresholds: test FPR %.3f%%, bal.acc %.3f%%",
             100 * out["or_ensemble_test"]["fpr"], 100 * out["or_ensemble_test"]["balanced_accuracy"])

    (models_dir / "thresholds.json").write_text(json.dumps(out, indent=2), encoding="utf-8")

    cats = [c for c in cat_names.values() if c != "Benign"]
    lines = [
        f"# Decision thresholds - {100 * args.fpr:g}% benign-FPR budget per model (D2)",
        "",
        "Calibrated on validation benign rows; test rows only measure the result. "
        "Rule: attack iff P(attack) >= threshold. Written by `scripts/02c_calibrate_thresholds.py`.",
        "",
        "| model | threshold | val FPR | test FPR | test bal. acc. | argmax test FPR | argmax bal. acc. |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, r in out["models"].items():
        lines.append(f"| {name} | {r['threshold']:.6f} | {100 * r['val']['fpr']:.3f}% | "
                     f"{100 * r['test']['fpr']:.3f}% | {100 * r['test']['balanced_accuracy']:.3f}% | "
                     f"{100 * r['test_argmax']['fpr']:.3f}% | "
                     f"{100 * r['test_argmax']['balanced_accuracy']:.3f}% |")
    e = out["or_ensemble_test"]
    lines += ["", f"OR-ensemble of {', '.join(e['members'])} at these thresholds: test FPR "
              f"{100 * e['fpr']:.3f}%, balanced accuracy {100 * e['balanced_accuracy']:.3f}%.", "",
              "Detection rate per category on test at the calibrated threshold (%):", "",
              "| model | " + " | ".join(cats) + " |", "| --- |" + " ---: |" * len(cats)]
    for name, r in out["models"].items():
        lines.append(f"| {name} | " + " | ".join(f"{100 * r['test']['per_category'][c]:.2f}"
                                                   for c in cats) + " |")
    (reports_dir / "thresholds.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    log.info("wrote %s and %s", models_dir / "thresholds.json", reports_dir / "thresholds.md")


if __name__ == "__main__":
    main()
