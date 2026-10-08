"""Phase 1 (M1) - build the processed CICIoT2023 dataset for every later phase.

    python scripts/01_prepare.py --sample-frac 0.02   # smoke test -> data/smoke/
    python scripts/01_prepare.py                      # full run   -> data/processed/
    python scripts/01_prepare.py --rescan             # ignore the interim cache

Step by step (each step is logged, and docs/m1-data-pipeline.md explains why):

 1. ingest     two streaming passes over the 13.75 GB CSV (src/aad/data/loader.py):
               scan every row -> drop NaN/inf rows and exact duplicates -> keep at
               most cap_per_class distinct rows per class (benign kept whole).
               The result is cached in data/interim/ so later runs take seconds.
 2. labels     raw label -> name, 34-way code, binary target, 8-way category
 3. clean      second line of defence; must report zero rows dropped
 4. split      70/15/15 stratified on the 34-way label, seed 42
 5. constants  constant / near-constant columns found on train only, dropped everywhere
 6. log1p      signed log1p on heavy-tailed columns (chosen on train only)
 7. scale      MinMax to [0,1] fitted on train only; val/test clipped

Writes (to data/processed/, or data/smoke/ with --sample-frac):
    {train,val,test}.npz     X float32 in [0,1]; y (binary); y_multiclass; y_category
    feature_names.json       retained feature order - every later phase must match it
    classes.json             code -> name for the 34 classes and 8 categories
    transform.json           log1p columns + MinMax parameters (to invert to raw units)
    scaler.pkl               the fitted MinMaxScaler
and reports (to artifacts/reports/, or the smoke dir):
    class_stats.{csv,md}     Table I: full-data counts, duplicates, sampled, per split
    feature_stats.csv        per-feature tail statistics behind the log1p choice
    prepare_meta.json        the complete ledger of this run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import random
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aad.data.clean import clean_rows, find_constant_columns, normalise_labels  # noqa: E402
from aad.data.loader import duplicate_analysis, load_selected, scan, select_capped  # noqa: E402
from aad.data.split import (  # noqa: E402
    apply_log1p,
    fit_scaler,
    stratified_split,
    transform,
)
from aad.evaluate import CLASSES_FILE  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("prepare")

LABEL_COLS = ["label_name", "label_multiclass", "label_binary", "label_category"]


# --------------------------------------------------------------------------- #
# step 1 - ingest, with an interim cache
# --------------------------------------------------------------------------- #

def _fingerprint(csv: Path, cfg: dict) -> dict:
    """Everything that, if changed, makes the cached sample stale."""
    st = csv.stat()
    label_map_hash = hashlib.sha1(
        json.dumps(cfg["label_map"], sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {
        "csv": csv.name,
        "csv_bytes": st.st_size,
        "csv_mtime_ns": st.st_mtime_ns,
        "cap_per_class": int(cfg["sampling"]["cap_per_class"]),
        "keep_all": sorted(cfg["sampling"]["keep_all"]),
        "seed": int(cfg["seed"]),
        "label_map_sha1": label_map_hash,
        # Bump when the meaning of "duplicate" changes. v2 = float32 precision
        # (v1 used exact float64 equality and left IAT-jitter twins in).
        "dedup": "float32-v2",
    }


def ingest(cfg: dict, rescan: bool) -> tuple[pd.DataFrame, dict]:
    """Return the sampled rows (features + raw label) and the ingest report.

    The report describes the FULL file - row counts, NaN/inf, exact and
    conflicting duplicates per class - not just the sample, because those are
    properties of the dataset the write-up has to state.
    """
    raw_cfg, smp = cfg["raw"], cfg["sampling"]
    if len(raw_cfg["files"]) != 1:
        raise ValueError("the CICIoT2023 pipeline expects the single merged CSV")
    csv = ROOT / raw_cfg["dir"] / raw_cfg["files"][0]
    if not csv.exists():
        raise FileNotFoundError(f"expected the CICIoT2023 CSV at {csv} (see README 'Setup')")

    cache = ROOT / smp["cache_file"]
    sidecar = cache.with_suffix(".json")
    fp = _fingerprint(csv, cfg)

    if not rescan and cache.exists() and sidecar.exists():
        meta = json.loads(sidecar.read_text(encoding="utf-8"))
        if meta.get("fingerprint") == fp:
            log.info("step 1 ingest: cache hit %s (use --rescan to rebuild)", cache.name)
            df = pd.read_parquet(cache)
            df[cfg["label_column"]] = df[cfg["label_column"]].astype("category")
            return df, meta["report"]
        log.info("step 1 ingest: cache is stale (CSV, cap, seed or label map changed)")

    log.info("step 1 ingest: pass 1 - scanning %s (%.2f GB)", csv.name, fp["csv_bytes"] / 1e9)
    s = scan(csv, cfg["label_column"], cfg["label_map"], int(raw_cfg["block_size_mb"]))

    # Sanity checks against what the dataset is published to contain.
    if raw_cfg.get("expected_rows") and s.n_rows != int(raw_cfg["expected_rows"]):
        raise ValueError(
            f"{csv.name} has {s.n_rows:,} rows, expected {int(raw_cfg['expected_rows']):,}: "
            "the file is truncated or is a different release"
        )
    if raw_cfg.get("expected_feature_count") and \
            len(s.feature_columns) != int(raw_cfg["expected_feature_count"]):
        raise ValueError(f"{len(s.feature_columns)} feature columns, expected "
                         f"{raw_cfg['expected_feature_count']}")

    is_first, dup = duplicate_analysis(s)
    keep_all = {int(cfg["label_map"][k]["code"]) for k in smp["keep_all"]}
    positions, kept = select_capped(s, is_first, int(smp["cap_per_class"]), keep_all,
                                    int(cfg["seed"]))
    log.info("step 1 ingest: selected %d rows; pass 2 - loading them", len(positions))
    df = load_selected(csv, positions, cfg["label_column"], int(raw_cfg["block_size_mb"]))

    code_to_name = {int(e["code"]): e["name"] for e in cfg["label_map"].values()}
    report = {
        "csv": csv.name,
        "csv_bytes": fp["csv_bytes"],
        "rows_in_file": s.n_rows,
        "feature_columns": s.feature_columns,
        "scan_seconds": s.seconds,
        "raw_label_counts": s.raw_label_counts,
        "nan_cells_by_column": s.nan_by_column,
        "inf_cells_by_column": s.inf_by_column,
        "distinct_rows": dup["distinct_rows"],
        "exact_duplicate_rows": dup["exact_duplicate_rows"],
        "exact_duplicate_rows_float64": dup["exact_duplicate_rows_float64"],
        "conflicting_feature_vectors": dup["conflicting_feature_vectors"],
        "per_class": {
            code_to_name[c]: {**v, "sampled": kept.get(c, 0)}
            for c, v in dup["per_code"].items()
        },
        "rows_sampled": int(len(positions)),
    }

    cache.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(cache, index=False, compression="snappy")
    sidecar.write_text(json.dumps({"fingerprint": fp, "report": report}, indent=2),
                       encoding="utf-8")
    log.info("step 1 ingest: cached %d rows -> %s (%.0f MB)",
             len(df), cache.name, cache.stat().st_size / 1e6)
    return df, report


# --------------------------------------------------------------------------- #
# step 6 helper - which columns get the log1p
# --------------------------------------------------------------------------- #

def feature_tail_stats(train: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    """How badly MinMax would squash each column, measured on TRAIN only.

    ``p50_position`` = where the median row lands after MinMax scaling, i.e.
    (p50 - min) / (max - min). A value of 0.005 means the typical row sits in
    the bottom 0.5% of [0,1] because a handful of extreme rows set the max, so
    a perturbation of eps=0.1 would be ~20x the typical value. That is the
    quantity the log1p decision is made on. ``p99_position`` is the same for the
    99th percentile, reported for context.
    """
    rows = []
    for c in cols:
        v = train[c].to_numpy(dtype=np.float64)
        lo, hi = float(v.min()), float(v.max())
        p50, p99 = np.percentile(v, [50, 99])
        span = hi - lo
        rows.append({
            "feature": c,
            "min": lo, "p50": float(p50), "p99": float(p99), "max": hi,
            "span": span,
            "p50_position": float((p50 - lo) / span) if span > 0 else float("nan"),
            "p99_position": float((p99 - lo) / span) if span > 0 else float("nan"),
            "frac_zero": float((v == 0).mean()),
            "frac_integer": float((v == np.rint(v)).mean()),
            "n_negative": int((v < 0).sum()),
        })
    return pd.DataFrame(rows)


def resolve_log1p_columns(tcfg: dict, stats: pd.DataFrame) -> list[str]:
    """An explicit list from the config, or ``auto``: every column whose median
    sits below ``auto_p50_position`` of its MinMax range AND whose span exceeds
    ``auto_min_span`` (log1p of a column confined to [0, 10] changes little, and
    0/1 indicator columns must stay linear)."""
    spec = tcfg.get("log1p_columns", [])
    if spec != "auto":
        return list(spec)
    thr, min_span = float(tcfg["auto_p50_position"]), float(tcfg["auto_min_span"])
    pick = stats[(stats["p50_position"] < thr) & (stats["span"] > min_span)]
    return pick["feature"].tolist()


# --------------------------------------------------------------------------- #
# reports
# --------------------------------------------------------------------------- #

def build_class_table(parts: dict[str, pd.DataFrame], ingest_report: dict,
                      category_names: dict[int, str]) -> pd.DataFrame:
    """Table I: per class, the full-file picture and what was kept, per split."""
    all_df = pd.concat(parts.values(), ignore_index=True)
    full = ingest_report["per_class"]
    rows = []
    for code, group in all_df.groupby("label_multiclass", observed=True):
        name = str(group["label_name"].iloc[0])
        f = full.get(name, {})
        row = {
            "code": int(code),
            "class": name,
            "category": category_names[int(group["label_category"].iloc[0])],
            "rows_in_file": f.get("rows", 0),
            "exact_duplicates": f.get("exact_duplicates", 0),
            "conflicting": f.get("conflicting_rows", 0),
            "kept": len(group),
        }
        for split, part in parts.items():
            row[split] = int((part["label_multiclass"] == code).sum())
        rows.append(row)
    table = pd.DataFrame(rows).sort_values("code").reset_index(drop=True)
    totals = {"code": "", "class": "ALL", "category": "",
              **{c: int(table[c].sum()) for c in
                 ("rows_in_file", "exact_duplicates", "conflicting", "kept")},
              **{s: len(p) for s, p in parts.items()}}
    return pd.concat([table, pd.DataFrame([totals])], ignore_index=True)


def write_markdown_table(table: pd.DataFrame, path: Path, meta: dict) -> None:
    ing = meta["ingest"]
    lines = [
        "# Table I - CICIoT2023 as processed for this project",
        "",
        f"Source: `{ing['csv']}` ({ing['csv_bytes'] / 1e9:.2f} GB, {ing['rows_in_file']:,} rows).",
        f"Distinct rows at float32 (model) precision: {ing['distinct_rows']:,}; duplicates "
        f"removed: {ing['exact_duplicate_rows']:,} (of which exact float64 copies: "
        f"{ing.get('exact_duplicate_rows_float64', 'n/a'):,}; the rest differ only below "
        "float32 precision, almost always in `IAT`). Feature vectors that occur under more "
        f"than one label: {ing['conflicting_feature_vectors']:,}.",
        f"Sampling: every class deduplicated, then capped at {meta['cap_per_class']:,} rows "
        f"(seed {meta['seed']}); kept whole: {meta['keep_all']}.",
        f"Kept: {meta['rows_after_cleaning']:,} rows, {meta['n_features']} of "
        f"{meta['n_features_before_constant_drop']} features. Split {meta['split_ratios']}, "
        "stratified on the 34-way label.",
        "",
        "`rows_in_file`, `exact_duplicates` and `conflicting` describe the full file; "
        "`kept` onward describe this project's sample.",
        "",
        table.to_markdown(index=False),
        "",
        "## Cleaning ledger",
        "",
        f"- NaN cells in the file: {sum(ing['nan_cells_by_column'].values()):,} "
        f"{ing['nan_cells_by_column'] or ''}",
        f"- Infinite cells in the file: {sum(ing['inf_cells_by_column'].values()):,} "
        f"{ing['inf_cells_by_column'] or ''}",
        f"- Rows dropped by the post-sample clean pass (must be 0): NaN "
        f"{meta['clean'].get('rows_dropped_nan', 0)}, duplicate "
        f"{meta['clean'].get('rows_dropped_duplicate', 0)}",
        f"- Constant / near-constant columns dropped (fewer than {meta['min_non_mode_rows']} "
        f"train rows differ from the column's mode; train only): "
        f"{meta['constant_columns_non_mode_rows']}",
        f"- Signed-log1p columns: {meta['log1p_columns']}",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--config", default=str(ROOT / "config" / "data.yaml"))
    ap.add_argument("--sample-frac", type=float, default=None,
                    help="stratified subsample for a fast smoke test; writes to data/smoke/")
    ap.add_argument("--rescan", action="store_true",
                    help="ignore the interim cache and re-read the 13.75 GB CSV")
    args = ap.parse_args()

    t0 = time.time()
    cfg = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    seed = int(cfg["seed"])
    random.seed(seed)
    np.random.seed(seed)

    smoke = args.sample_frac is not None
    out_cfg = cfg["output"]
    processed_dir = ROOT / (out_cfg["smoke_dir"] if smoke else out_cfg["processed_dir"])
    reports_dir = processed_dir / "reports" if smoke else ROOT / out_cfg["reports_dir"]
    for d in (processed_dir, reports_dir):
        d.mkdir(parents=True, exist_ok=True)

    # ---- 1. ingest -------------------------------------------------------------
    df, ingest_report = ingest(cfg, args.rescan)

    # ---- 2. labels -------------------------------------------------------------
    categories = {k: int(v) for k, v in cfg["categories"].items()}
    df, label_counts = normalise_labels(df, cfg["label_column"], cfg["label_map"], categories)
    feature_cols = [c for c in df.columns if c not in LABEL_COLS]
    log.info("step 2 labels: %d classes, %d features", len(label_counts), len(feature_cols))

    # ---- 3. clean (defensive) --------------------------------------------------
    df, clean_report = clean_rows(
        df, feature_cols,
        replace_inf_with_nan=cfg["clean"]["replace_inf_with_nan"],
        drop_nan_rows=cfg["clean"]["drop_nan_rows"],
        drop_duplicates=cfg["clean"]["drop_duplicates"],
    )
    dropped = clean_report.get("rows_dropped_nan", 0) + clean_report.get("rows_dropped_duplicate", 0)
    if dropped:
        raise RuntimeError(
            f"the clean pass dropped {dropped} rows after sampling; the sampler is meant to "
            "exclude NaN/inf rows and duplicates already. Inspect loader.select_capped."
        )
    log.info("step 3 clean: 0 rows dropped (as expected - ingest already filtered)")

    if smoke:
        n_before = len(df)
        df = (
            df.groupby("label_multiclass", group_keys=False, observed=True)
            # floor of 20 so even the rarest class survives a 70/15/15 split
            .apply(lambda g: g.sample(min(len(g), max(20, int(len(g) * args.sample_frac))),
                                      random_state=seed))
            .reset_index(drop=True)
        )
        log.warning("SMOKE TEST: subsampled %d -> %d rows, writing to %s",
                    n_before, len(df), processed_dir)

    # ---- 4. split --------------------------------------------------------------
    parts = stratified_split(
        df, train=cfg["split"]["train"], val=cfg["split"]["val"], test=cfg["split"]["test"],
        stratify_col="label_multiclass", seed=seed,
    )
    del df
    log.info("step 4 split: %s", {k: len(v) for k, v in parts.items()})

    # ---- 5. constant / near-constant columns (train only) -----------------------
    constant_cols, non_mode_rows = find_constant_columns(
        parts["train"], feature_cols,
        min_non_mode_rows=int(cfg["clean"].get("min_non_mode_rows", 0)),
    )
    n_features_before = len(feature_cols)
    feature_cols = [c for c in feature_cols if c not in constant_cols]
    log.info("step 5 constants: dropped %s, %d features remain", constant_cols, len(feature_cols))

    # ---- 6. signed log1p (columns chosen on train only) ------------------------
    stats = feature_tail_stats(parts["train"], feature_cols)
    log1p_cols = resolve_log1p_columns(cfg["transform"], stats)
    stats["log1p"] = stats["feature"].isin(log1p_cols)
    for part in parts.values():
        apply_log1p(part, log1p_cols)
    log.info("step 6 log1p: %d column(s): %s", len(log1p_cols), log1p_cols)

    # ---- 7. scale --------------------------------------------------------------
    frange = tuple(cfg["scale"]["feature_range"])
    scaler = fit_scaler(parts["train"], feature_cols, frange)
    scale_stats = {}
    for name, part in parts.items():
        X, st = transform(part, feature_cols, scaler, cfg["scale"]["clip_transformed"], frange)
        scale_stats[name] = st
        y_bin = part["label_binary"].to_numpy(dtype=np.int8)
        y_multi = part["label_multiclass"].to_numpy(dtype=np.int8)
        y_cat = part["label_category"].to_numpy(dtype=np.int8)

        assert X.shape == (len(part), len(feature_cols)), f"{name} X shape mismatch"
        assert np.isfinite(X).all(), f"{name} contains non-finite values after scaling"
        assert X.min() >= frange[0] - 1e-6 and X.max() <= frange[1] + 1e-6, f"{name} out of range"

        np.savez_compressed(processed_dir / f"{name}.npz",
                            X=X, y=y_bin, y_multiclass=y_multi, y_category=y_cat)
        log.info("step 7 scale: %s.npz X%s  attack=%.2f%%  clipped=%.5f%%",
                 name, X.shape, 100 * y_bin.mean(), 100 * st["fraction_clipped"])

    # ---- artefacts every later phase reads -------------------------------------
    joblib.dump(scaler, processed_dir / "scaler.pkl")
    (processed_dir / "feature_names.json").write_text(json.dumps(feature_cols, indent=2),
                                                      encoding="utf-8")
    class_names = {int(e["code"]): e["name"] for e in cfg["label_map"].values()}
    category_names = {v: k for k, v in categories.items()}
    (processed_dir / CLASSES_FILE).write_text(json.dumps({
        "classes": {str(k): class_names[k] for k in sorted(class_names)},
        "categories": {str(k): category_names[k] for k in sorted(category_names)},
        "class_to_category": {str(int(e["code"])): categories[e["category"]]
                              for e in cfg["label_map"].values()},
        "binary": {"0": "benign", "1": "attack"},
    }, indent=2), encoding="utf-8")
    # Everything needed to map a scaled row back to raw units without sklearn:
    # raw = inverse_signed_log1p(X * data_range + data_min) on the log1p columns.
    (processed_dir / "transform.json").write_text(json.dumps({
        "feature_names": feature_cols,
        "log1p_columns": log1p_cols,
        "log1p_indices": [feature_cols.index(c) for c in log1p_cols],
        "minmax_data_min": scaler.data_min_.tolist(),
        "minmax_data_range": scaler.data_range_.tolist(),
        "feature_range": list(frange),
    }, indent=2), encoding="utf-8")

    # ---- reports ------------------------------------------------------------------
    meta = {
        "dataset": cfg.get("dataset"),
        "seed": seed,
        "ingest": ingest_report,
        "cap_per_class": int(cfg["sampling"]["cap_per_class"]),
        "keep_all": cfg["sampling"]["keep_all"],
        "rows_after_cleaning": sum(len(p) for p in parts.values()),
        "label_counts_kept": label_counts,
        "clean": clean_report,
        "n_features_before_constant_drop": n_features_before,
        "n_features": len(feature_cols),
        "constant_columns": constant_cols,
        "constant_columns_non_mode_rows": {c: non_mode_rows[c] for c in constant_cols},
        "min_non_mode_rows": int(cfg["clean"].get("min_non_mode_rows", 0)),
        "log1p_columns": log1p_cols,
        "split_ratios": f"{cfg['split']['train']}/{cfg['split']['val']}/{cfg['split']['test']}",
        "split_sizes": {k: len(v) for k, v in parts.items()},
        "attack_share": {k: float(v["label_binary"].mean()) for k, v in parts.items()},
        "scaling": {"feature_range": list(frange), "per_split": scale_stats},
        "sample_frac": args.sample_frac,
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    table = build_class_table(parts, ingest_report, category_names)
    table.to_csv(reports_dir / "class_stats.csv", index=False)
    write_markdown_table(table, reports_dir / "class_stats.md", meta)
    stats.to_csv(reports_dir / "feature_stats.csv", index=False)
    (reports_dir / "prepare_meta.json").write_text(json.dumps(meta, indent=2, default=str),
                                                   encoding="utf-8")

    print("\n" + table.to_string(index=False))
    print(f"\ndone in {meta['elapsed_seconds']}s -> {processed_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
