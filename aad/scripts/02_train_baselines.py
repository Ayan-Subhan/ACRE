"""Phase 2 (M2) - train the three clean baseline NIDS models on CICIoT2023.

    python scripts/02_train_baselines.py                    # all three (~1 h CPU)
    python scripts/02_train_baselines.py --models mlp       # just one
    python scripts/02_train_baselines.py --smoke            # 1 epoch on data/smoke, writes to data/smoke/
    python scripts/02_train_baselines.py --eval-only        # re-measure saved models, never retrain

Writes:
    artifacts/models/{mlp,cnn,lstm}.keras             the trained weights
    artifacts/models/{mlp,cnn,lstm}_history.json      per-epoch loss/metrics
    artifacts/models/{mlp,cnn,lstm}_test_probs.npz    test-set probabilities
    artifacts/reports/baseline_metrics.json           every metric, per class and per category
    artifacts/reports/table3_nids.{csv,md}            Table III + per-category + per-class tables
    artifacts/reports/per_category_recall.csv         8 categories x 3 models
    artifacts/reports/per_type_recall.csv             34 classes x 3 models

Acceptance (plan, M2): balanced accuracy >= 99% for every model, with per-category
recall stated. Walkthrough and results: docs/m2-baselines.md.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")  # mute TF's startup banner

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import yaml  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tensorflow import keras  # noqa: E402

from aad.evaluate import (  # noqa: E402
    HEADER,
    binary_metrics,
    format_row,
    load_class_names,
    per_category_recall,
    per_type_recall,
)
from aad.models import cnn as cnn_mod  # noqa: E402
from aad.models import lstm as lstm_mod  # noqa: E402
from aad.models import mlp as mlp_mod  # noqa: E402
from aad.models.base import build_callbacks, compile_model, set_seeds, summarise  # noqa: E402

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(message)s", datefmt="%H:%M:%S"
)
log = logging.getLogger("train")

BUILDERS = {"mlp": mlp_mod.build, "cnn": cnn_mod.build, "lstm": lstm_mod.build}

# Plan acceptance threshold for M2 (balanced accuracy on the clean test set).
TARGET_BALANCED_ACC = 0.99


def load_split(data_dir: Path, name: str) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    d = np.load(data_dir / f"{name}.npz")
    return (d["X"], d["y"].astype(np.int64), d["y_multiclass"].astype(np.int64),
            d["y_category"].astype(np.int64))


def group_table(results: dict, key: str) -> pd.DataFrame:
    """Rows = classes or categories, columns = support + one detection rate per model."""
    rows = []
    any_model = next(iter(results))
    for gname, stats in results[any_model][key].items():
        row = {"group": gname, "support": stats["support"]}
        for name, m in results.items():
            row[name.upper()] = round(m[key][gname]["correct_rate"] * 100, 3)
        rows.append(row)
    return pd.DataFrame(rows)


def one_hot(y: np.ndarray) -> np.ndarray:
    """2-unit softmax targets to pair with CategoricalCrossentropy."""
    return keras.utils.to_categorical(y, num_classes=2).astype(np.float32)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(ROOT / "config" / "models.yaml"))
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--models", nargs="+", default=["mlp", "cnn", "lstm"], choices=list(BUILDERS))
    ap.add_argument("--tag", default=None, help="suffix so variant runs do not overwrite each other")
    ap.add_argument("--epochs", type=int, default=None, help="override config, for a quick check")
    ap.add_argument("--eval-only", action="store_true",
                    help="re-measure the saved .keras files instead of training. Use when the "
                         "report has drifted from the weights on disk: retraining would fix the "
                         "report by invalidating every artefact built against those weights.")
    ap.add_argument("--class-weight", choices=["false", "binary", "category"], default=None,
                    help="override training.class_weight (combine with --tag for an experiment)")
    ap.add_argument("--smoke", action="store_true",
                    help="wiring check: data/smoke in, 1 epoch, models and reports written under "
                         "data/smoke/ so the real artefacts are never touched")
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    tcfg = cfg["training"]
    seed = int(cfg["seed"])
    tag = f"_{args.tag}" if args.tag else ""

    if args.smoke:
        args.data_dir = "data/smoke"
        args.epochs = args.epochs or 1
        models_dir = ROOT / "data/smoke/models"
        reports_dir = ROOT / "data/smoke/reports"
    else:
        models_dir = ROOT / cfg["output"]["models_dir"]
        reports_dir = ROOT / cfg["output"]["reports_dir"]
    data_dir = ROOT / args.data_dir
    models_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    X_train, y_train, _, y_train_cat = load_split(data_dir, "train")
    X_val, y_val, _, _ = load_split(data_dir, "val")
    X_test, y_test, y_test_multi, y_test_cat = load_split(data_dir, "test")
    n_features = X_train.shape[1]
    feature_names = json.loads((data_dir / "feature_names.json").read_text(encoding="utf-8"))
    assert len(feature_names) == n_features, "feature_names.json disagrees with train.npz"
    class_names, category_names = load_class_names(data_dir)

    log.info(
        "data %s | train %s  val %s  test %s | attack share %.3f%%",
        args.data_dir, X_train.shape, X_val.shape, X_test.shape, 100 * y_train.mean(),
    )

    Y_train, Y_val = one_hot(y_train), one_hot(y_val)

    # Weighting mode: config value, overridable from the CLI. true is read as "binary".
    mode = args.class_weight or tcfg["class_weight"]
    mode = {True: "binary", False: "false"}.get(mode, str(mode))
    class_weight, sample_weight = None, None
    if mode == "binary":
        n0, n1 = int((y_train == 0).sum()), int((y_train == 1).sum())
        class_weight = {0: len(y_train) / (2 * n0), 1: len(y_train) / (2 * n1)}
        log.info("class_weight binary: %s", class_weight)
    elif mode == "category":
        counts = np.bincount(y_train_cat)
        power = float(tcfg.get("class_weight_power", 1.0))
        per_cat = (len(y_train_cat) / (len(counts) * np.maximum(counts, 1))) ** power
        sample_weight = per_cat[y_train_cat].astype(np.float32)
        sample_weight /= sample_weight.mean()   # keep the loss scale comparable
        log.info("sample weights by category (power %.2f): %s", power,
                 {category_names[i]: round(float(per_cat[i] / per_cat.mean()), 3)
                  for i in range(len(counts))})

    epochs = args.epochs or int(tcfg["epochs"])
    results: dict[str, dict] = {}

    # Wall-clock training time is the one column an evaluation pass cannot
    # recompute, so it is carried forward from the run that produced the models.
    prior: dict = {}
    prior_path = reports_dir / f"baseline_metrics{tag}.json"
    if args.eval_only and prior_path.exists():
        prior = json.loads(prior_path.read_text(encoding="utf-8")).get("results", {})

    for name in args.models:
        log.info("=" * 70)
        model_path = models_dir / f"{name}{tag}.keras"

        if args.eval_only:
            if not model_path.exists():
                raise FileNotFoundError(
                    f"--eval-only needs {model_path}, which does not exist"
                )
            log.info("measuring %s from %s", name.upper(), model_path.name)
            model = keras.models.load_model(model_path)
            history = None
            # Epoch count is recoverable from what the training run wrote.
            hist_path = models_dir / f"{name}{tag}_history.json"
            epochs_run = (
                len(json.loads(hist_path.read_text(encoding="utf-8"))["loss"])
                if hist_path.exists() else None
            )
            train_seconds = prior.get(name, {}).get("train_seconds")
        else:
            log.info("training %s", name.upper())
            set_seeds(seed)

            model = BUILDERS[name](n_features=n_features, **cfg["models"][name])
            compile_model(model, tcfg["optimizer"], float(tcfg["learning_rate"]))
            log.info("\n%s", summarise(model))

            t0 = time.time()
            history = model.fit(
                X_train, Y_train,
                validation_data=(X_val, Y_val),
                epochs=epochs,
                batch_size=int(tcfg["batch_size"]),
                callbacks=build_callbacks(tcfg),
                class_weight=class_weight,
                sample_weight=sample_weight,
                verbose=2,
            )
            train_seconds = round(time.time() - t0, 1)
            epochs_run = len(history.history["loss"])

        prob = model.predict(X_test, batch_size=4096, verbose=0)
        y_pred = prob.argmax(axis=1)

        m = binary_metrics(y_test, y_pred, y_prob=prob)
        m["per_attack_type"] = per_type_recall(y_test_multi, y_pred, class_names)
        m["per_category"] = per_category_recall(y_test_cat, y_pred, category_names)
        m["train_seconds"] = train_seconds
        m["seconds_per_epoch"] = (round(train_seconds / epochs_run, 1)
                                  if train_seconds and epochs_run else None)
        m["epochs_run"] = epochs_run
        m["params"] = int(model.count_params())
        results[name] = m

        # An evaluation pass must never touch the weights it is measuring.
        if not args.eval_only:
            model.save(model_path)
            (models_dir / f"{name}{tag}_history.json").write_text(
                json.dumps({k: [float(v) for v in vals]
                            for k, vals in history.history.items()}, indent=2),
                encoding="utf-8",
            )
        np.savez_compressed(models_dir / f"{name}{tag}_test_probs.npz", prob=prob.astype(np.float32))

        log.info(
            "%s: acc %.4f%%  bal.acc %.4f%%  F1 %.4f%%  FPR %.4f%%  loss %.5f  (%ss, %s epochs)",
            name, m["accuracy"] * 100, m["balanced_accuracy"] * 100, m["f1"] * 100,
            m["fpr"] * 100, m["loss"],
            train_seconds if train_seconds is not None else "?",
            epochs_run if epochs_run is not None else "?",
        )

    # ---- Table III ---------------------------------------------------------
    rows = []
    for name, m in results.items():
        rows.append({
            "model": name.upper(),
            "accuracy_%": round(m["accuracy"] * 100, 4),
            "balanced_acc_%": round(m["balanced_accuracy"] * 100, 4),
            "precision_%": round(m["precision"] * 100, 4),
            "recall_%": round(m["recall"] * 100, 4),
            "f1_%": round(m["f1"] * 100, 4),
            "test_loss": round(m["loss"], 5),
            "fpr_%": round(m["fpr"] * 100, 4),
            "fn": m["fn"], "fp": m["fp"],
            "params": m["params"],
            "epochs": m["epochs_run"],
            "train_s": m["train_seconds"],
            "s_per_epoch": m["seconds_per_epoch"],
        })
    table = pd.DataFrame(rows)
    table.to_csv(reports_dir / f"table3_nids{tag}.csv", index=False)

    md = [
        "# Table III - NIDS accuracy and loss (clean test set)",
        "",
        f"Data: `{args.data_dir}` | test rows: {len(y_test):,} "
        f"({int(y_test.sum()):,} attack, {int((y_test == 0).sum()):,} benign)",
        f"Seed {seed}, batch {tcfg['batch_size']}, Adam lr={tcfg['learning_rate']}, "
        f"early stopping on val_loss (patience {tcfg['early_stopping']['patience']}), "
        f"weighting: {mode}. `fpr_%` = benign flows flagged "
        "as attack; `balanced_acc_%` = mean of benign and attack recall.",
        ""
        if not args.eval_only else
        "Measured with `--eval-only` from the saved `.keras` files, so these numbers "
        "describe the exact weights every later phase was built against. `train_s` is "
        "carried forward from the run that produced them.",
        "",
        table.to_markdown(index=False),
        "",
        "## Detection rate per category (%)",
        "",
        "For Benign, \"detection\" means correctly passed as benign (= 100 - FPR).",
        "",
    ]
    cat_table = group_table(results, "per_category").rename(columns={"group": "category"})
    type_table = group_table(results, "per_attack_type").rename(columns={"group": "class"})
    md += [cat_table.to_markdown(index=False), "",
           "## Detection rate per class (%)", "", type_table.to_markdown(index=False), ""]
    (reports_dir / f"table3_nids{tag}.md").write_text("\n".join(md), encoding="utf-8")
    cat_table.to_csv(reports_dir / f"per_category_recall{tag}.csv", index=False)
    type_table.to_csv(reports_dir / f"per_type_recall{tag}.csv", index=False)

    (reports_dir / f"baseline_metrics{tag}.json").write_text(
        json.dumps({"data_dir": args.data_dir, "seed": seed, "weighting": mode,
                    "class_weight": class_weight, "results": results}, indent=2),
        encoding="utf-8",
    )

    print("\n" + HEADER)
    print("-" * len(HEADER))
    for name, m in results.items():
        print(format_row(name.upper(), m))
    print("\nper-category detection rate (%):")
    print(cat_table.to_string(index=False))

    below = [n for n, m in results.items() if m["balanced_accuracy"] < TARGET_BALANCED_ACC]
    if below:
        log.warning("below the %.0f%% balanced-accuracy target: %s",
                    100 * TARGET_BALANCED_ACC, below)
    else:
        log.info("all models cleared the %.0f%% balanced-accuracy target", 100 * TARGET_BALANCED_ACC)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
