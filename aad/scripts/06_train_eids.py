"""Phase 6 - adversarially train the three NIDS and combine them with a logical OR.

    python scripts/03_generate_ae.py --split train --n-samples 10000 --attacks fgsm bim pgd
    python scripts/06_train_eids.py                     # train all three + both evaluations
    python scripts/06_train_eids.py --models mlp        # one model
    python scripts/06_train_eids.py --skip-training     # re-evaluate saved hardened models
    python scripts/06_train_eids.py --no-adaptive       # skip the re-attack (saves ~12 min)

Writes:
    artifacts/models/{mlp,cnn,lstm}_eids.keras
    artifacts/models/{name}_eids_history.json
    artifacts/reports/table7_eids_clean.{csv,md}       clean cost of hardening
    artifacts/reports/table8_eids_robustness.csv       transferred and adaptive
    artifacts/reports/eids_metrics.json
    artifacts/reports/figures/fig6_eids.png

The two robustness regimes are the reason this script is long. Replaying phase
3's saved examples against a hardened model measures resistance to a *stale*
adversary holding the old weights. A white-box attacker recomputes gradients
against whatever is deployed, which is what the adaptive pass does. Reporting
only the first is how adversarial training gets oversold.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import yaml  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tensorflow import keras  # noqa: E402

from aad.attacks.generate import build_attack, run_attack, select_attack_rows  # noqa: E402
from aad.attacks.wrappers import load_wrapped  # noqa: E402
from aad.defense.discriminator import load_cells  # noqa: E402
from aad.evaluate import binary_metrics, load_class_names, per_type_recall  # noqa: E402
from aad.models import cnn as cnn_mod  # noqa: E402
from aad.models import lstm as lstm_mod  # noqa: E402
from aad.models import mlp as mlp_mod  # noqa: E402
from aad.models.base import build_callbacks, compile_model, set_seeds  # noqa: E402
from aad.models.eids import (  # noqa: E402
    build_augmented,
    disagreement,
    or_ensemble,
    or_ensemble_prob,
    select_pool,
)
from aad.plots import figure6_eids  # noqa: E402

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(message)s", datefmt="%H:%M:%S"
)
log = logging.getLogger("eids")

BUILDERS = {"mlp": mlp_mod.build, "cnn": cnn_mod.build, "lstm": lstm_mod.build}
ENSEMBLE = "ENSEMBLE"


def one_hot(y: np.ndarray) -> np.ndarray:
    return keras.utils.to_categorical(y, num_classes=2).astype(np.float32)


def predict(model, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    prob = model.predict(X, batch_size=4096, verbose=0).astype(np.float32)
    return prob.argmax(axis=1).astype(np.int8), prob


def detection_rate(pred: np.ndarray) -> float:
    """Every row in an adversarial set is a true attack, so the detection rate is
    simply the share still called attack. ``1 - this`` is the evasion rate."""
    return float((pred == 1).mean()) if len(pred) else float("nan")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(ROOT / "config" / "eids.yaml"))
    ap.add_argument("--models-config", default=str(ROOT / "config" / "models.yaml"))
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--models", nargs="+", default=None, choices=list(BUILDERS))
    ap.add_argument("--tag", default="eids", help="suffix for the hardened models")
    ap.add_argument("--epochs", type=int, default=None, help="override, for a quick check")
    ap.add_argument("--force", action="store_true", help="retrain models that already exist")
    ap.add_argument("--skip-training", action="store_true",
                    help="evaluate saved hardened models without retraining")
    ap.add_argument("--no-adaptive", action="store_true", help="skip the re-attack pass")
    ap.add_argument("--adaptive-samples", type=int, default=None,
                    help="override the re-attack sample count, for a smoke test")
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    mcfg = yaml.safe_load(Path(args.models_config).read_text(encoding="utf-8"))
    tcfg = mcfg["training"]
    seed = int(cfg["seed"])
    tag = f"_{args.tag}"
    at = cfg["adversarial_training"]
    members = args.models or list(cfg["ensemble"]["members"])

    data_dir = ROOT / args.data_dir
    models_dir = ROOT / cfg["output"]["models_dir"]
    reports_dir = ROOT / cfg["output"]["reports_dir"]
    figures_dir = ROOT / cfg["output"]["figures_dir"]
    for d in (models_dir, reports_dir, figures_dir):
        d.mkdir(parents=True, exist_ok=True)

    def load(name: str):
        d = np.load(data_dir / f"{name}.npz")
        return d["X"].astype(np.float32), d["y"].astype(np.int64), d["y_multiclass"].astype(np.int8)

    X_train, y_train, _ = load("train")
    X_val, y_val, _ = load("val")
    X_test, y_test, y_test_multi = load("test")
    n_features = X_train.shape[1]
    class_names, _ = load_class_names(data_dir)
    Y_val = one_hot(y_val)

    # ---- the training-split examples ---------------------------------------
    train_cells = load_cells(ROOT / at["adv_dir"], "_train")
    log.info(
        "hold-out: %s never enters training; %s does",
        at["holdout_attacks"],
        sorted({c.attack for c in train_cells} - {a.lower() for a in at["holdout_attacks"]}),
    )

    # ---- harden ------------------------------------------------------------
    aug_meta: dict[str, dict] = {}
    train_seconds: dict[str, float] = {}
    for name in members:
        out_path = models_dir / f"{name}{tag}.keras"
        if args.skip_training or (out_path.exists() and not args.force):
            log.info("%-4s  using %s (--force to retrain)", name, out_path.name)
            continue

        pool = select_pool(train_cells, name, tuple(at["holdout_attacks"]), at["sources"])
        X_aug, y_aug, meta = build_augmented(
            X_train, y_train, pool, fraction=float(at["fraction"]), seed=seed
        )
        aug_meta[name] = meta

        log.info("=" * 70)
        log.info("adversarially training %s on %d rows", name.upper(), len(X_aug))
        set_seeds(seed)
        model = BUILDERS[name](n_features=n_features, **mcfg["models"][name])
        compile_model(model, tcfg["optimizer"], float(tcfg["learning_rate"]))

        t0 = time.time()
        history = model.fit(
            X_aug, one_hot(y_aug),
            # Validation stays clean. Early stopping on a mixed set would select
            # for robustness at the cost of the clean traffic that is 100% of
            # what the system sees in normal operation.
            validation_data=(X_val, Y_val),
            epochs=args.epochs or int(tcfg["epochs"]),
            batch_size=int(tcfg["batch_size"]),
            callbacks=build_callbacks(tcfg),
            verbose=2,
        )
        train_seconds[name] = round(time.time() - t0, 1)

        model.save(out_path)
        (models_dir / f"{name}{tag}_history.json").write_text(
            json.dumps({k: [float(v) for v in vals] for k, vals in history.history.items()},
                       indent=2),
            encoding="utf-8",
        )
        log.info("%s hardened in %.0fs -> %s", name, train_seconds[name], out_path.name)
        del X_aug, y_aug, model
        keras.backend.clear_session()

    # ---- load both generations ---------------------------------------------
    baseline = {n: keras.models.load_model(models_dir / f"{n}.keras") for n in members}
    hardened = {n: keras.models.load_model(models_dir / f"{n}{tag}.keras") for n in members}

    # ---- Table VII: what hardening costs on clean traffic ------------------
    clean_rows, clean_detail = [], {}
    member_pred: dict[str, dict[str, np.ndarray]] = {"baseline": {}, "eids": {}}
    member_prob: dict[str, dict[str, np.ndarray]] = {"baseline": {}, "eids": {}}

    for variant, models in (("baseline", baseline), ("eids", hardened)):
        for name in members:
            pred, prob = predict(models[name], X_test)
            member_pred[variant][name] = pred
            member_prob[variant][name] = prob
            m = binary_metrics(y_test, pred, y_prob=prob)
            m["per_attack_type"] = per_type_recall(y_test_multi, pred, class_names)
            clean_detail[f"{name}_{variant}"] = m
            clean_rows.append({"model": name.upper(), "variant": variant, **{
                "accuracy_%": round(100 * m["accuracy"], 4),
                "precision_%": round(100 * m["precision"], 4),
                "recall_%": round(100 * m["recall"], 4),
                "f1_%": round(100 * m["f1"], 4),
                "fpr_%": round(100 * m["fpr"], 4),
                "fn": m["fn"], "fp": m["fp"],
            }})

        pred = or_ensemble(member_pred[variant])
        prob = or_ensemble_prob(member_prob[variant])
        m = binary_metrics(y_test, pred, y_prob=prob)
        m["per_attack_type"] = per_type_recall(y_test_multi, pred, class_names)
        m["disagreement"] = disagreement(member_pred[variant], y_test)
        clean_detail[f"ensemble_{variant}"] = m
        clean_rows.append({"model": ENSEMBLE, "variant": variant, **{
            "accuracy_%": round(100 * m["accuracy"], 4),
            "precision_%": round(100 * m["precision"], 4),
            "recall_%": round(100 * m["recall"], 4),
            "f1_%": round(100 * m["f1"], 4),
            "fpr_%": round(100 * m["fpr"], 4),
            "fn": m["fn"], "fp": m["fp"],
        }})
        log.info("%-8s ensemble: acc %.4f%%  recall %.4f%%  FPR %.4f%%",
                 variant, 100 * m["accuracy"], 100 * m["recall"], 100 * m["fpr"])

    clean_table = pd.DataFrame(clean_rows)

    # ---- Table VIII, regime 1: phase 3's examples, replayed ----------------
    rob_rows = []
    test_cells = load_cells(ROOT / cfg["output"]["adversarial_dir"])
    for cell in test_cells:
        preds = {n: predict(hardened[n], cell.X_adv)[0] for n in members}
        row = {
            "regime": "transferred",
            "attack": cell.attack,
            "crafted_against": f"{cell.model} (baseline)",
            "n": len(cell.X_adv),
        }
        row.update({n.upper() + "_%": round(100 * detection_rate(p), 3) for n, p in preds.items()})
        row[ENSEMBLE + "_%"] = round(100 * detection_rate(or_ensemble(preds)), 3)
        row["baseline_%"] = round(100 * cell.meta["metrics"]["accuracy_adv"], 3)
        rob_rows.append(row)

    # ---- Table VIII, regime 2: re-attack what is actually deployed ---------
    adaptive_cfg = cfg["adaptive_evaluation"]
    if adaptive_cfg["enabled"] and not args.no_adaptive:
        acfg = yaml.safe_load((ROOT / "config" / "attacks.yaml").read_text(encoding="utf-8"))
        # Same seed as phase 3, so the adaptive numbers sit on the same rows as
        # Table IV and the two are directly comparable.
        n_adaptive = args.adaptive_samples or int(adaptive_cfg["n_samples"])
        idx = select_attack_rows(y_test, n_adaptive, int(acfg["seed"]))
        X_src, y_src = X_test[idx], y_test[idx]

        for name in members:
            _, classifier, logit_classifier = load_wrapped(models_dir, name, n_features, tag)
            for attack_name in adaptive_cfg["attacks"]:
                clf = logit_classifier if attack_name == "deepfool" else classifier
                attack = build_attack(
                    attack_name, clf, dict(acfg["attacks"][attack_name]), int(acfg["batch_size"])
                )
                X_adv, elapsed = run_attack(attack, X_src, y_src)
                preds = {n: predict(hardened[n], X_adv)[0] for n in members}
                row = {
                    "regime": "adaptive",
                    "attack": attack_name,
                    "crafted_against": f"{name} (hardened)",
                    "n": len(X_adv),
                }
                row.update({n.upper() + "_%": round(100 * detection_rate(p), 3)
                            for n, p in preds.items()})
                row[ENSEMBLE + "_%"] = round(100 * detection_rate(or_ensemble(preds)), 3)
                row["baseline_%"] = float("nan")
                rob_rows.append(row)
                log.info(
                    "adaptive %-8s vs %-4s(hardened): %s holds %.2f%%, ensemble %.2f%%  (%.0fs)",
                    attack_name, name, name, row[name.upper() + "_%"],
                    row[ENSEMBLE + "_%"], elapsed,
                )

    rob_table = pd.DataFrame(rob_rows)

    # ---- write -------------------------------------------------------------
    clean_table.to_csv(reports_dir / "table7_eids_clean.csv", index=False)
    rob_table.to_csv(reports_dir / "table8_eids_robustness.csv", index=False)

    # Per-class detection, for every member and both ensembles. Built from the
    # members actually run so a --models subset still produces a table.
    columns = [(f"{n}_{v}", f"{n.upper()} {v}") for n in members for v in ("baseline", "eids")]
    columns += [("ensemble_baseline", "OR baseline"), ("ensemble_eids", "OR hardened")]
    reference = clean_detail[columns[0][0]]["per_attack_type"]

    type_rows = []
    for tname in reference:
        row = {"class": tname, "support": reference[tname]["support"]}
        for key, label in columns:
            row[label] = round(100 * clean_detail[key]["per_attack_type"][tname]["correct_rate"], 3)
        type_rows.append(row)
    type_table = pd.DataFrame(type_rows)
    type_table.to_csv(reports_dir / "per_type_recall_eids.csv", index=False)

    md = [
        "# Tables VII & VIII - the EIDS",
        "",
        f"Hardened on {aug_meta.get(members[0], {}).get('n_clean', len(X_train)):,} clean "
        f"training rows plus adversarial examples from `{at['adv_dir']}`, labelled attack. "
        f"`{', '.join(at['holdout_attacks'])}` withheld from training entirely. Same builders, "
        f"seed {seed} and callbacks as phase 2, so any difference is attributable to the data.",
        "",
        "## Table VII - clean test set (the cost of hardening)",
        "",
        clean_table.to_markdown(index=False),
        "",
        "OR only ever adds detections, so ensemble recall cannot fall below its best member "
        "and ensemble FPR cannot fall below its worst. Read the two columns together.",
        "",
        "### Detection rate per attack type (%)",
        "",
        type_table.to_markdown(index=False),
        "",
        "The phase-2 LSTM detects 0% of the three web-attack classes and still reports "
        "99.8% accuracy, because those classes are 81 of 224,469 test rows. Whether OR "
        "recovers them is the row to read here.",
        "",
        "## Table VIII - robustness, two regimes",
        "",
        rob_table.to_markdown(index=False),
        "",
        "- **transferred** replays phase 3's saved examples -- built against the *baseline* "
        "weights -- at the hardened models. This is the number an attacker gets if they "
        "hold a stale copy of the model. `baseline_%` is what the original model scored on "
        "the same rows (Table IV), so the improvement is read across that pair.",
        "- **adaptive** regenerates each attack against the *hardened* weights, on the same "
        "5,000 source rows Table IV used. This is the white-box threat model the paper "
        "states, and it is the only regime that describes a current adversary.",
        "",
        "A large transferred number beside a small adaptive one is the expected result of "
        "static adversarial training, not a bug: the model learned the perturbations it was "
        "shown. Real robustness needs examples generated inside the training loop against "
        "the current weights (Madry et al.), which a fixed pool cannot provide. "
        f"`{', '.join(at['holdout_attacks'])}` was never trained on, so its row is the "
        "cleanest measure of generalisation to an unanticipated attack.",
        "",
    ]
    (reports_dir / "table7_eids_clean.md").write_text("\n".join(md), encoding="utf-8")

    (reports_dir / "eids_metrics.json").write_text(
        json.dumps({
            "seed": seed,
            "data_dir": args.data_dir,
            "adversarial_training": at,
            "augmentation": aug_meta,
            "train_seconds": train_seconds,
            "clean": clean_detail,
            "robustness": rob_rows,
        }, indent=2, default=float),
        encoding="utf-8",
    )

    try:
        figure6_eids(clean_table, rob_table, figures_dir / "fig6_eids.png")
    except Exception as exc:  # noqa: BLE001 - never lose a 1-hour run to a plotting bug
        log.error("figure failed (tables are safe): %s", exc)

    print("\n== Table VII - clean ==")
    print(clean_table.to_string(index=False))
    print("\n== Table VIII - robustness ==")
    print(rob_table.to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
