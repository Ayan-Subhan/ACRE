"""Phase 1b (M1) - leakage probes that must be read before any model is trained.

    python scripts/01b_probe_leakage.py

High accuracy on an IDS dataset is easy to get for the wrong reason. Three
probes, each answering one "is the score real?" question:

 1. duplicates  How much of the full file is repeated rows, per class, and how
                many feature vectors carry more than one label? (Read from the
                ingest report: computed over all 46.7M rows in phase 1.)
 2. one-feature Can a depth-3 tree on ONE feature separate attack from benign?
                A feature that does it alone (>= 99% balanced accuracy) is either
                a genuine, trivially-detectable signature or an artefact of how
                the capture was made (e.g. a timestamp-like column, or a column
                fixed by the packet-window size). Either way it must be named in
                the write-up, and it is the first thing an adversary would target.
 3. overlap     How many test rows are byte-identical to a training row after
                scaling? Phase 1 deduplicated (features + label) on the raw
                float64 values, so same-label overlap should be ~0; any remaining
                overlap is conflicting rows or float32 rounding, and is reported.

Writes artifacts/reports/leakage_probe.{json,md}.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import balanced_accuracy_score
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aad.evaluate import load_class_names  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("probe")

SUSPECT = 0.99  # balanced accuracy at or above which a single feature is flagged


def load(data_dir: Path, name: str):
    d = np.load(data_dir / f"{name}.npz")
    return d["X"], d["y"].astype(np.int8), d["y_multiclass"].astype(np.int8), d["y_category"].astype(np.int8)


def stratified_subsample(y_multi: np.ndarray, n: int, seed: int) -> np.ndarray:
    """At most n rows, keeping each class's share (and at least 1 row per class)."""
    if len(y_multi) <= n:
        return np.arange(len(y_multi))
    rng = np.random.default_rng(seed)
    out = []
    for c in np.unique(y_multi):
        idx = np.flatnonzero(y_multi == c)
        take = max(1, int(round(n * len(idx) / len(y_multi))))
        out.append(rng.choice(idx, size=min(take, len(idx)), replace=False))
    return np.sort(np.concatenate(out))


def probe_single_feature(X_tr, y_tr, cat_tr, X_te, y_te, cat_te, names) -> pd.DataFrame:
    rows = []
    for j, name in enumerate(names):
        xtr, xte = X_tr[:, j:j + 1], X_te[:, j:j + 1]
        binary = DecisionTreeClassifier(max_depth=3, class_weight="balanced", random_state=0)
        binary.fit(xtr, y_tr)
        cat = DecisionTreeClassifier(max_depth=3, class_weight="balanced", random_state=0)
        cat.fit(xtr, cat_tr)
        rows.append({
            "feature": name,
            "binary_balanced_acc": balanced_accuracy_score(y_te, binary.predict(xte)),
            "category_balanced_acc": balanced_accuracy_score(cat_te, cat.predict(xte)),
            "n_distinct_train": int(len(np.unique(xtr))),
        })
    df = pd.DataFrame(rows).sort_values("binary_balanced_acc", ascending=False)
    df["suspect"] = df["binary_balanced_acc"] >= SUSPECT
    return df.reset_index(drop=True)


def row_hashes(X: np.ndarray) -> np.ndarray:
    return pd.util.hash_pandas_object(pd.DataFrame(X, copy=False), index=False).to_numpy()


def probe_overlap(X_tr, y_tr, X_te, y_te, m_te, class_names) -> dict:
    h_tr, h_te = row_hashes(X_tr), row_hashes(X_te)
    # label(s) each training hash was seen with: bit 0 = benign, bit 1 = attack
    seen = pd.Series(1 << y_tr.astype(np.int64)).groupby(h_tr).agg(np.bitwise_or.reduce)
    hit = pd.Series(h_te).map(seen).fillna(0).astype(np.int64).to_numpy()
    in_train = hit > 0
    same = in_train & ((hit >> y_te.astype(np.int64)) & 1).astype(bool)
    per_class = {}
    for c in np.unique(m_te[in_train]):
        mask = m_te == c
        per_class[class_names[int(c)]] = {
            "test_rows": int(mask.sum()),
            "in_train": int((in_train & mask).sum()),
            "in_train_same_binary_label": int((same & mask).sum()),
        }
    return {
        "test_rows": int(len(X_te)),
        "test_rows_identical_to_a_train_row": int(in_train.sum()),
        "of_which_same_binary_label": int(same.sum()),
        "of_which_other_label_only": int((in_train & ~same).sum()),
        "per_class": per_class,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--reports-dir", default="artifacts/reports")
    ap.add_argument("--max-train", type=int, default=300_000,
                    help="stratified subsample for the one-feature trees (speed)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    t0 = time.time()
    data_dir, reports_dir = ROOT / args.data_dir, ROOT / args.reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)
    names = json.loads((data_dir / "feature_names.json").read_text(encoding="utf-8"))
    class_names, category_names = load_class_names(data_dir)
    X_tr, y_tr, m_tr, c_tr = load(data_dir, "train")
    X_te, y_te, m_te, c_te = load(data_dir, "test")

    # ---- probe 1: duplicates (full file, from phase 1's ingest report) ----------
    meta = json.loads((reports_dir / "prepare_meta.json").read_text(encoding="utf-8"))
    ing = meta["ingest"]
    dup_rows = []
    for cname, v in ing["per_class"].items():
        dup_rows.append({
            "class": cname,
            "rows_in_file": v["rows"],
            "exact_duplicate_%": round(100 * v["exact_duplicates"] / max(1, v["rows"]), 2),
            "conflicting_rows": v["conflicting_rows"],
            "sampled": v["sampled"],
        })
    dup = pd.DataFrame(dup_rows).sort_values("exact_duplicate_%", ascending=False)
    log.info("probe 1: %d exact duplicate rows in the file (%.2f%%), %d conflicting vectors",
             ing["exact_duplicate_rows"], 100 * ing["exact_duplicate_rows"] / ing["rows_in_file"],
             ing["conflicting_feature_vectors"])

    # ---- probe 2: one-feature trees ---------------------------------------------
    sub = stratified_subsample(m_tr, args.max_train, args.seed)
    single = probe_single_feature(X_tr[sub], y_tr[sub], c_tr[sub], X_te, y_te, c_te, names)
    flagged = single.loc[single["suspect"], "feature"].tolist()
    log.info("probe 2: %d feature(s) alone reach >= %.0f%% balanced accuracy: %s",
             len(flagged), 100 * SUSPECT, flagged)

    # ---- probe 3: train/test overlap ------------------------------------------------
    overlap = probe_overlap(X_tr, y_tr, X_te, y_te, m_te, class_names)
    log.info("probe 3: %d of %d test rows are identical to a training row (%d same label)",
             overlap["test_rows_identical_to_a_train_row"], overlap["test_rows"],
             overlap["of_which_same_binary_label"])

    result = {
        "data_dir": args.data_dir,
        "suspect_threshold": SUSPECT,
        "duplicates": {
            "rows_in_file": ing["rows_in_file"],
            "exact_duplicate_rows": ing["exact_duplicate_rows"],
            "conflicting_feature_vectors": ing["conflicting_feature_vectors"],
            "per_class": dup.to_dict(orient="records"),
        },
        "single_feature": single.to_dict(orient="records"),
        "single_feature_flagged": flagged,
        "overlap": overlap,
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    (reports_dir / "leakage_probe.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    md = [
        "# Leakage probe (phase 1b)",
        "",
        "Read this before trusting any accuracy figure. Method and interpretation: "
        "`docs/m1-data-pipeline.md`, section 'Leakage probe'.",
        "",
        "## 1. Duplicates in the full file",
        "",
        f"{ing['exact_duplicate_rows']:,} of {ing['rows_in_file']:,} rows "
        f"({100 * ing['exact_duplicate_rows'] / ing['rows_in_file']:.2f}%) are exact repeats of an "
        f"earlier row with the same label, and were removed before sampling. "
        f"{ing['conflicting_feature_vectors']:,} distinct feature vectors occur under more than "
        "one label; they were kept, and they put a ceiling on achievable accuracy.",
        "",
        dup.to_markdown(index=False),
        "",
        f"## 2. What one feature alone can do (depth-3 tree, {len(sub):,} train rows, full test)",
        "",
        f"Flagged (binary balanced accuracy >= {100 * SUSPECT:.0f}%): "
        f"{', '.join(f'`{f}`' for f in flagged) if flagged else 'none'}.",
        "",
        single.round(4).to_markdown(index=False),
        "",
        "## 3. Train/test overlap after scaling",
        "",
        f"- test rows: {overlap['test_rows']:,}",
        f"- identical to some training row: {overlap['test_rows_identical_to_a_train_row']:,}",
        f"  - with the same binary label: {overlap['of_which_same_binary_label']:,}",
        f"  - only with a different label (conflicts): {overlap['of_which_other_label_only']:,}",
        "",
    ]
    if overlap["per_class"]:
        md += [pd.DataFrame.from_dict(overlap["per_class"], orient="index")
               .rename_axis("class").reset_index().to_markdown(index=False), ""]
    (reports_dir / "leakage_probe.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))
    log.info("done in %.0fs", time.time() - t0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
