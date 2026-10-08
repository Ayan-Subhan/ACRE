"""Phase 2b (M2) - do the trained models lean on capture artefacts?

    python scripts/02b_feature_reliance.py                     # importance + ablation
    python scripts/02b_feature_reliance.py --no-ablation       # importance only (~3 min)

Motivation. The M1 leakage probe (docs/m1-data-pipeline.md, section 4) found that
``IAT`` alone separates attack from benign at 94% balanced accuracy and behaves
like a capture timestamp, and that ``Number``/``Weight`` (~100 distinct values)
reflect the extractor's packet-window size. A model that relies on them is
recognising *when/how the capture was made*, not *how the attack behaves*, and
would not transfer to new traffic. Two measurements, because each alone can mislead:

1. **Permutation importance** (every model). Shuffle one feature's column in a
   fixed, stratified test subsample, re-predict, and record the drop in balanced
   accuracy. Large drop = the model uses that feature. Correlated features share
   credit (shuffling one leaves its twin intact), so a small drop does not prove a
   feature is unused - hence measurement 2.

2. **Ablation retraining** (MLP: the fastest model, and the strongest on IDS2018).
   Retrain from scratch with the same seed/config but with the suspect columns
   removed, then compare clean test metrics with the full-feature MLP. If accuracy
   barely moves, the information is also available from behavioural features and
   the artefact columns are not load-bearing.

3. **Reference forest** (``--reference-forest``). A Random Forest on the same
   split, as a ceiling estimate: tree ensembles are the strongest known models on
   CICIoT2023's tabular features. If the forest also stalls on Recon/Spoofing/
   Web/BruteForce, the limit is the features, not the neural networks.

Writes artifacts/reports/feature_reliance.{json,md} and feature_importance.csv.
The ablated models are not saved: they are measurements, not deployable artefacts.
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

from sklearn.metrics import balanced_accuracy_score  # noqa: E402
from tensorflow import keras  # noqa: E402

from aad.evaluate import binary_metrics, load_class_names, per_category_recall  # noqa: E402
from aad.models import mlp as mlp_mod  # noqa: E402
from aad.models.base import build_callbacks, compile_model, set_seeds  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("reliance")

# The window-size encoding: Number (5.5 / 9.5 / 13.5) and Weight (38.5 / 141.6 /
# 244.6) move together and track the extractor's 10- vs 100-packet window, not
# attack behaviour (docs/ciciot2023-features.md). IAT, the third copy, is dropped
# at the scan since 2026-10-08; it is listed so older data can still be analysed.
ARTEFACT_SUSPECTS = ["IAT", "Number", "Weight"]
CORRELATED = 0.95  # |r| above which features are permuted together


def load(data_dir: Path, name: str):
    d = np.load(data_dir / f"{name}.npz")
    return d["X"], d["y"].astype(np.int64), d["y_multiclass"].astype(np.int64), d["y_category"].astype(np.int64)


def stratified_rows(y_multi: np.ndarray, n: int, seed: int) -> np.ndarray:
    """~n rows keeping each class's share, at least 1 per class. Fixed by seed."""
    rng = np.random.default_rng(seed)
    out = []
    for c in np.unique(y_multi):
        idx = np.flatnonzero(y_multi == c)
        k = max(1, int(round(n * len(idx) / len(y_multi))))
        out.append(rng.choice(idx, size=min(k, len(idx)), replace=False))
    return np.sort(np.concatenate(out))


def predict(model, X: np.ndarray) -> np.ndarray:
    return model.predict(X, batch_size=8192, verbose=0).argmax(axis=1)


def correlated_groups(X: np.ndarray, names: list[str], thr: float = CORRELATED) -> list[list[int]]:
    """Connected components of the |corr| > thr graph; singletons for the rest.

    Why: shuffling ONE of two near-identical columns creates rows where they
    disagree - combinations that never occur in real traffic - and the model's
    confusion on those impossible rows is then misread as reliance. This is
    exactly how IAT (r = 0.998 with Number) earned a 13-17 point "importance"
    while removing it cost 0.02 points. Permuting each correlated group with one
    shared row permutation keeps every row internally consistent.
    """
    with np.errstate(invalid="ignore", divide="ignore"):
        r = np.nan_to_num(np.corrcoef(X, rowvar=False))
    parent = list(range(len(names)))
    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            if abs(r[i, j]) > thr:
                parent[find(i)] = find(j)
    groups: dict[int, list[int]] = {}
    for i in range(len(names)):
        groups.setdefault(find(i), []).append(i)
    return sorted(groups.values())


def permutation_importance(model, X, y, names, repeats: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    base = balanced_accuracy_score(y, predict(model, X))
    rows = []
    for cols in correlated_groups(X, names):
        drops = []
        for _ in range(repeats):
            Xp = X.copy()
            perm = rng.permutation(len(Xp))
            Xp[:, cols] = Xp[perm][:, cols]
            drops.append(base - balanced_accuracy_score(y, predict(model, Xp)))
        rows.append({"feature": " + ".join(names[j] for j in cols), "n_columns": len(cols),
                     "drop_mean": float(np.mean(drops)), "drop_std": float(np.std(drops))})
    df = pd.DataFrame(rows).sort_values("drop_mean", ascending=False).reset_index(drop=True)
    df.attrs["baseline_balanced_acc"] = float(base)
    return df


def train_mlp(X_tr, y_tr, X_va, y_va, mcfg: dict, epochs: int | None) -> tuple[keras.Model, float, int]:
    """Exactly phase 2's MLP recipe (builder, seed, callbacks, class weights)."""
    tcfg = mcfg["training"]
    set_seeds(int(mcfg["seed"]))
    model = mlp_mod.build(n_features=X_tr.shape[1], **mcfg["models"]["mlp"])
    compile_model(model, tcfg["optimizer"], float(tcfg["learning_rate"]))
    cw = None
    if tcfg["class_weight"] in (True, "binary"):
        n0, n1 = int((y_tr == 0).sum()), int((y_tr == 1).sum())
        cw = {0: len(y_tr) / (2 * n0), 1: len(y_tr) / (2 * n1)}
    t0 = time.time()
    hist = model.fit(X_tr, keras.utils.to_categorical(y_tr, 2), validation_data=(
        X_va, keras.utils.to_categorical(y_va, 2)), epochs=epochs or int(tcfg["epochs"]),
        batch_size=int(tcfg["batch_size"]), callbacks=build_callbacks(tcfg),
        class_weight=cw, verbose=0)
    return model, round(time.time() - t0, 1), len(hist.history["loss"])


def summarise(model, X_te, y_te, c_te, cat_names) -> dict:
    prob = model.predict(X_te, batch_size=8192, verbose=0)
    pred = prob.argmax(axis=1)
    m = binary_metrics(y_te, pred, y_prob=prob)
    m["per_category"] = per_category_recall(c_te, pred, cat_names)
    return m


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--models-dir", default="artifacts/models")
    ap.add_argument("--reports-dir", default="artifacts/reports")
    ap.add_argument("--models-config", default=str(ROOT / "config" / "models.yaml"))
    ap.add_argument("--models", nargs="+", default=["mlp", "cnn", "lstm"])
    ap.add_argument("--n-rows", type=int, default=20_000, help="test subsample for permutation")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--no-ablation", action="store_true")
    ap.add_argument("--reference-forest", action="store_true",
                    help="also fit a Random Forest on the same split as a ceiling estimate")
    ap.add_argument("--forest-rows", type=int, default=600_000,
                    help="stratified train subsample for the forest (RAM/time)")
    ap.add_argument("--epochs", type=int, default=None, help="override, for a quick check")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    t0 = time.time()
    data_dir, models_dir = ROOT / args.data_dir, ROOT / args.models_dir
    reports_dir = ROOT / args.reports_dir
    names = json.loads((data_dir / "feature_names.json").read_text(encoding="utf-8"))
    _, cat_names = load_class_names(data_dir)
    mcfg = yaml.safe_load(Path(args.models_config).read_text(encoding="utf-8"))
    X_te, y_te, m_te, c_te = load(data_dir, "test")

    # ---- 1. permutation importance ------------------------------------------------
    sub = stratified_rows(m_te, args.n_rows, args.seed)
    imp_tables, result = {}, {"n_rows": int(len(sub)), "repeats": args.repeats,
                              "permutation": {}, "ablation": {}}
    for name in args.models:
        path = models_dir / f"{name}.keras"
        if not path.exists():
            log.warning("skipping %s: %s not found", name, path)
            continue
        model = keras.models.load_model(path)
        tt = time.time()
        df = permutation_importance(model, X_te[sub], y_te[sub], names, args.repeats, args.seed)
        imp_tables[name] = df
        result["permutation"][name] = {
            "baseline_balanced_acc": df.attrs["baseline_balanced_acc"],
            "top10": df.head(10).to_dict(orient="records"),
            "suspects": df[df["feature"].str.contains("|".join(ARTEFACT_SUSPECTS))]
                        .to_dict(orient="records"),
        }
        top = ", ".join(f"{r.feature} {100 * r.drop_mean:.2f}" for r in df.head(5).itertuples())
        log.info("permutation %s (%.0fs): top drops in balanced-acc points: %s",
                 name, time.time() - tt, top)
        keras.backend.clear_session()

    wide = None
    if imp_tables:
        wide = pd.concat({n.upper(): t.set_index("feature")["drop_mean"] * 100
                          for n, t in imp_tables.items()}, axis=1)
        wide["mean"] = wide.mean(axis=1)
        wide = wide.sort_values("mean", ascending=False).round(3)
        wide.to_csv(reports_dir / "feature_importance.csv")

    # ---- 2. ablation retraining (MLP) ----------------------------------------------
    abl_rows = []
    if not args.no_ablation:
        X_tr, y_tr, _, _ = load(data_dir, "train")
        X_va, y_va, _, _ = load(data_dir, "val")
        present = [s for s in ARTEFACT_SUSPECTS if s in names]
        variants = {f"all {len(names)} features": [],
                    f"without {', '.join(present)}": present}
        for label, drop in variants.items():
            keep = [j for j, n in enumerate(names) if n not in drop]
            baseline_path = models_dir / "mlp.keras"
            if not drop and baseline_path.exists():
                # The full-feature control IS the phase-2 MLP: same recipe, seed and
                # (CPU) hardware, so retraining it would only cost time.
                log.info("ablation: '%s' = the phase-2 baseline MLP (not retrained)", label)
                model = keras.models.load_model(baseline_path)
                bm = json.loads((reports_dir / "baseline_metrics.json").read_text(encoding="utf-8"))
                secs, ep = bm["results"]["mlp"]["train_seconds"], bm["results"]["mlp"]["epochs_run"]
            else:
                log.info("ablation: training MLP '%s' on %d features", label, len(keep))
                model, secs, ep = train_mlp(X_tr[:, keep], y_tr, X_va[:, keep], y_va, mcfg,
                                            args.epochs)
            m = summarise(model, X_te[:, keep], y_te, c_te, cat_names)
            result["ablation"][label] = {"dropped": drop, "train_seconds": secs, "epochs": ep, **m}
            abl_rows.append({
                "variant": label, "features": len(keep),
                "balanced_acc_%": round(100 * m["balanced_accuracy"], 4),
                "accuracy_%": round(100 * m["accuracy"], 4),
                "recall_%": round(100 * m["recall"], 4), "fpr_%": round(100 * m["fpr"], 4),
                **{f"{k}_%": round(100 * v["correct_rate"], 2) for k, v in m["per_category"].items()},
                "epochs": ep, "train_s": secs,
            })
            log.info("ablation '%s': bal.acc %.4f%%  FPR %.4f%%", label,
                     100 * m["balanced_accuracy"], 100 * m["fpr"])
            keras.backend.clear_session()

    # ---- 3. reference forest ----------------------------------------------------------
    forest_row = None
    if args.reference_forest:
        from sklearn.ensemble import RandomForestClassifier
        X_tr, y_tr, m_tr, _ = load(data_dir, "train")
        idx = stratified_rows(m_tr, args.forest_rows, args.seed)
        rf = RandomForestClassifier(n_estimators=200, max_features="sqrt", n_jobs=-1,
                                    class_weight="balanced", random_state=args.seed)
        tt = time.time()
        rf.fit(X_tr[idx], y_tr[idx])
        secs = round(time.time() - tt, 1)
        prob = rf.predict_proba(X_te)
        m = binary_metrics(y_te, prob.argmax(1), y_prob=prob)
        m["per_category"] = per_category_recall(c_te, prob.argmax(1), cat_names)
        result["reference_forest"] = {"train_rows": int(len(idx)), "fit_seconds": secs, **m}
        forest_row = {
            "model": f"RandomForest (200 trees, {len(idx):,} train rows)",
            "balanced_acc_%": round(100 * m["balanced_accuracy"], 4),
            "fpr_%": round(100 * m["fpr"], 4),
            **{f"{k}_%": round(100 * v["correct_rate"], 2) for k, v in m["per_category"].items()},
        }
        log.info("reference forest: bal.acc %.4f%%  FPR %.4f%%  (%.0fs)",
                 100 * m["balanced_accuracy"], 100 * m["fpr"], secs)
        del rf, X_tr

    # ---- write ------------------------------------------------------------------------
    result["elapsed_seconds"] = round(time.time() - t0, 1)
    (reports_dir / "feature_reliance.json").write_text(json.dumps(result, indent=2),
                                                       encoding="utf-8")
    md = ["# Feature reliance of the baseline models (phase 2b)", "",
          "Method and interpretation: `docs/m2-baselines.md`, section 'Do the models lean on "
          "capture artefacts?'.", ""]
    if wide is not None:
        md += [f"## Permutation importance - drop in balanced accuracy (percentage points), "
               f"{len(sub):,} stratified test rows, {args.repeats} repeats", "",
               "Baseline balanced accuracy on this subsample: " + ", ".join(
                   f"{n.upper()} {100 * r['baseline_balanced_acc']:.3f}%"
                   for n, r in result["permutation"].items()) + ".", "",
               wide.head(15).to_markdown(), "",
               "Artefact suspects: ", "",
               wide.loc[[i for i in wide.index
                         if any(s in i for s in ARTEFACT_SUSPECTS)]].to_markdown(), "",
               f"Features correlated above |r| = {CORRELATED} are permuted together and shown "
               "as one row (`A + B`): permuting one alone would create impossible rows.", ""]
    if abl_rows:
        md += ["## Ablation - MLP retrained without the suspect columns", "",
               pd.DataFrame(abl_rows).to_markdown(index=False), ""]
    if forest_row:
        md += ["## Reference forest - is the ceiling the features or the networks?", "",
               pd.DataFrame([forest_row]).to_markdown(index=False), ""]
    (reports_dir / "feature_reliance.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))
    log.info("done in %.0fs", time.time() - t0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
