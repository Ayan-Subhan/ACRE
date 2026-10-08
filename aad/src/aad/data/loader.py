"""Streaming two-pass ingestion for the CICIoT2023 merged CSV.

The file is 13.75 GB / 46.7M rows -- larger than this machine's RAM once pandas
has parsed it -- and 97.6% of it is flood traffic. So it is never loaded whole.
Instead:

**Pass 1 - ``scan``.** Stream the file once with pyarrow (multi-threaded CSV
parsing, bounded memory) and keep only three small per-row arrays:

* the label code (int8, 47 MB),
* a 64-bit hash of the 46 feature values *at float32 precision* (uint64,
  373 MB) - the precision every model sees; see ``_hash_rows_model_precision``,
* a "bad" flag for rows holding NaN or +/-inf (bool, 47 MB).

That is enough to count every class, every NaN/inf cell, every exact duplicate
and every *conflicting* duplicate (identical features, different label) over
the **full** dataset, which is what the write-up needs to report.

**Selection - ``select_capped``.** Per class: drop bad rows, drop exact
duplicates (keeping the first occurrence), then draw ``cap`` rows uniformly at
random with a fixed seed. Classes listed in ``keep_all`` (benign) are taken
whole. Deduplicating *before* sampling matters: a flood class with 7.2M rows can
hold only a few hundred thousand distinct windows, and sampling first would
fill the cap with copies of the same row.

**Pass 2 - ``load_selected``.** Stream the file again and keep exactly the
selected row positions.

Hash collisions: two different rows sharing a 64-bit hash would be wrongly
treated as duplicates. With n = 46.7M rows the expected number of colliding
pairs is n^2 / 2^65 ~ 6e-5, i.e. negligible, and it is stated here rather than
assumed silently.
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pacsv

from .clean import slugify_label

log = logging.getLogger(__name__)

# Mixes the label code into the feature hash so that (features, label) pairs
# hash differently per label. Odd 64-bit constant (golden ratio), standard choice.
_LABEL_MIX = np.uint64(0x9E3779B97F4A7C15)


def read_header(path: Path) -> list[str]:
    """Column names from the first line, without parsing the file."""
    with open(path, "r", encoding="utf-8", newline="") as fh:
        line = fh.readline().strip()
    return [c.strip() for c in line.split(",")]


def _stream(path: Path, columns: list[str], label_column: str, block_size_mb: int):
    """A pyarrow streaming reader with every feature forced to float64.

    Forcing the types (rather than letting pyarrow infer from the first block)
    means a column whose first block happens to be all-integer cannot silently
    switch type in a later block and fail mid-file.
    """
    types = {c: pa.float64() for c in columns if c != label_column}
    types[label_column] = pa.string()
    return pacsv.open_csv(
        path,
        read_options=pacsv.ReadOptions(block_size=block_size_mb << 20, use_threads=True),
        convert_options=pacsv.ConvertOptions(column_types=types, strings_can_be_null=False),
    )


def _feature_matrix(batch: pa.RecordBatch, feature_idx: list[int]) -> np.ndarray:
    """(n, n_features) float64. Empty cells arrive as NaN."""
    X = np.column_stack([batch.column(i).to_numpy(zero_copy_only=False) for i in feature_idx])
    # -0.0 and 0.0 are the same value but hash differently; +0.0 normalises them.
    return X + 0.0


def _hash_rows(X: np.ndarray) -> np.ndarray:
    """One uint64 per row over all feature values (pandas' vectorised hasher)."""
    return pd.util.hash_pandas_object(pd.DataFrame(X, copy=False), index=False).to_numpy()


def _hash_rows_model_precision(X: np.ndarray) -> np.ndarray:
    """Row hash at float32 precision - the precision every model sees.

    Why not exact float64 equality: the first M1 run deduplicated on float64 and
    found only 34 duplicates in 46.7M rows, yet 2.8% of test rows were then
    byte-identical to a training row after scaling. Every such pair differed
    only in ``IAT`` (~8.3e7, where float32 resolves steps of ~8): the same
    window statistics with sub-precision jitter in one column. To a float32
    model they are one row, so they are duplicates, and leaving them in leaks
    copies across the train/test boundary.
    """
    return _hash_rows(X.astype(np.float32))


@dataclass
class ScanResult:
    """Everything pass 1 learns about the full file, in a few hundred MB."""

    path: str
    n_rows: int
    feature_columns: list[str]
    codes: np.ndarray            # int8 per row, label code from the label map
    feat_hash: np.ndarray        # uint64 per row, hash at float32 (model) precision
    bad: np.ndarray              # bool per row, any NaN or +/-inf feature
    exact_duplicates_float64: int  # duplicates under exact float64 equality, for the record
    raw_label_counts: dict[str, int]
    nan_by_column: dict[str, int]
    inf_by_column: dict[str, int]
    seconds: float
    extra: dict = field(default_factory=dict)


def scan(
    path: Path,
    label_column: str,
    label_map: dict[str, dict],
    block_size_mb: int = 64,
) -> ScanResult:
    """Pass 1: stream the whole file once and summarise every row.

    Raises if any label is missing from ``label_map``: an unmapped class would
    otherwise be silently dropped or mislabelled, and either changes every
    number downstream.
    """
    t0 = time.time()
    path = Path(path)
    header = read_header(path)
    if label_column not in header:
        raise ValueError(f"label column {label_column!r} not in header of {path.name}: {header}")
    feature_columns = [c for c in header if c != label_column]
    feature_idx = [header.index(c) for c in feature_columns]
    label_idx = header.index(label_column)
    slug_to_code = {slug: int(entry["code"]) for slug, entry in label_map.items()}

    codes_parts, hash_parts, hash64_parts, bad_parts = [], [], [], []
    raw_counts: Counter = Counter()
    unknown: set[str] = set()
    nan_cols = np.zeros(len(feature_columns), dtype=np.int64)
    inf_cols = np.zeros(len(feature_columns), dtype=np.int64)
    n_rows = 0
    next_log = 5_000_000

    for batch in _stream(path, header, label_column, block_size_mb):
        n = batch.num_rows
        if n == 0:
            continue

        # Labels: dictionary-encode the block so each distinct string is
        # slugified once, not once per row.
        enc = pc.dictionary_encode(batch.column(label_idx))
        names = enc.dictionary.to_pylist()
        lut = np.array([slug_to_code.get(slugify_label(s), -1) for s in names], dtype=np.int16)
        idx = enc.indices.to_numpy(zero_copy_only=False)
        for name, cnt in zip(names, np.bincount(idx, minlength=len(names))):
            raw_counts[name] += int(cnt)
        if (lut < 0).any():
            unknown.update(s for s, c in zip(names, lut) if c < 0)
        codes_parts.append(lut[idx].astype(np.int8))

        X = _feature_matrix(batch, feature_idx)
        nan_mask = np.isnan(X)
        inf_mask = np.isinf(X)
        nan_cols += nan_mask.sum(axis=0)
        inf_cols += inf_mask.sum(axis=0)
        bad_parts.append((nan_mask | inf_mask).any(axis=1))
        hash_parts.append(_hash_rows_model_precision(X))
        hash64_parts.append(_hash_rows(X))

        n_rows += n
        if n_rows >= next_log:
            log.info("  scanned %10d rows  (%.0fs)", n_rows, time.time() - t0)
            next_log += 5_000_000

    if unknown:
        raise ValueError(
            f"unmapped label(s) {sorted(unknown)}; add their slugs "
            f"{sorted(slugify_label(u) for u in unknown)} to config/data.yaml:label_map"
        )

    codes = np.concatenate(codes_parts)
    # Exact float64 duplicate count (features + label), kept only as a number.
    h64 = np.concatenate(hash64_parts) ^ (codes.astype(np.uint64) * _LABEL_MIX)
    exact64 = int(n_rows - len(np.unique(h64)))
    del h64, hash64_parts

    result = ScanResult(
        path=str(path),
        n_rows=n_rows,
        feature_columns=feature_columns,
        codes=codes,
        feat_hash=np.concatenate(hash_parts),
        bad=np.concatenate(bad_parts),
        exact_duplicates_float64=exact64,
        raw_label_counts=dict(sorted(raw_counts.items(), key=lambda kv: -kv[1])),
        nan_by_column={c: int(v) for c, v in zip(feature_columns, nan_cols) if v},
        inf_by_column={c: int(v) for c, v in zip(feature_columns, inf_cols) if v},
        seconds=round(time.time() - t0, 1),
    )
    log.info("scan: %d rows x %d features in %.0fs", n_rows, len(feature_columns), result.seconds)
    return result


def duplicate_analysis(s: ScanResult) -> tuple[np.ndarray, dict]:
    """Find the first occurrence of every distinct (features, label) row.

    Returns ``is_first`` (bool per row) and a report with, per class:

    * ``exact_duplicates`` - rows identical to an earlier row *with the same
      label*, at float32 precision (see ``_hash_rows_model_precision``).
      Harmless to drop, and they must be dropped: left in, copies of one flow
      land in both train and test and inflate every score.
    * ``conflicting_rows`` - distinct rows whose feature vector also occurs
      under a *different* label. No model can classify these correctly every
      time; they are kept (removing them would hide a property of the dataset)
      and reported, because they put a ceiling on achievable accuracy.
    """
    key = s.feat_hash ^ (s.codes.astype(np.uint64) * _LABEL_MIX)
    _, first_idx = np.unique(key, return_index=True)
    is_first = np.zeros(s.n_rows, dtype=bool)
    is_first[first_idx] = True

    # A feature hash that survives with more than one label = a conflict.
    fh_first = s.feat_hash[first_idx]
    _, inv, cnt = np.unique(fh_first, return_inverse=True, return_counts=True)
    conflicted = cnt[inv] > 1

    n_codes = int(s.codes.max()) + 1
    total = np.bincount(s.codes, minlength=n_codes)
    dupes = np.bincount(s.codes[~is_first], minlength=n_codes)
    conflicts = np.bincount(s.codes[first_idx][conflicted], minlength=n_codes)
    bad = np.bincount(s.codes[s.bad], minlength=n_codes)

    report = {
        "rows": int(s.n_rows),
        "distinct_rows": int(len(first_idx)),
        "exact_duplicate_rows": int(s.n_rows - len(first_idx)),
        "exact_duplicate_rows_float64": int(s.exact_duplicates_float64),
        "conflicting_feature_vectors": int((cnt > 1).sum()),
        "per_code": {
            int(c): {
                "rows": int(total[c]),
                "exact_duplicates": int(dupes[c]),
                "conflicting_rows": int(conflicts[c]),
                "nan_or_inf_rows": int(bad[c]),
            }
            for c in range(n_codes)
        },
    }
    return is_first, report


def select_capped(
    s: ScanResult,
    is_first: np.ndarray,
    cap: int,
    keep_all_codes: set[int],
    seed: int,
) -> tuple[np.ndarray, dict[int, int]]:
    """Choose which rows to keep: clean, distinct, at most ``cap`` per class.

    Returns sorted row positions (int64) and the number kept per class code.
    Uniform sampling without replacement, so the sample keeps each class's
    internal distribution; seeded, so the selection is identical across runs.
    """
    rng = np.random.default_rng(seed)
    eligible = is_first & ~s.bad
    order = np.argsort(s.codes, kind="stable")
    bounds = np.searchsorted(s.codes[order], np.arange(int(s.codes.max()) + 2))

    picks, kept = [], {}
    for code in range(len(bounds) - 1):
        rows = order[bounds[code]:bounds[code + 1]]
        rows = rows[eligible[rows]]
        if code not in keep_all_codes and len(rows) > cap:
            rows = rng.choice(rows, size=cap, replace=False)
        picks.append(rows)
        kept[code] = int(len(rows))

    positions = np.sort(np.concatenate(picks)).astype(np.int64)
    return positions, kept


def load_selected(
    path: Path,
    positions: np.ndarray,
    label_column: str,
    block_size_mb: int = 64,
) -> pd.DataFrame:
    """Pass 2: stream the file again and keep exactly ``positions`` (sorted).

    Features stay float64 here. They are only narrowed to float32 after
    scaling, because the duplicate analysis was done on the float64 values and
    narrowing earlier could merge rows that pass 1 counted as distinct.
    """
    t0 = time.time()
    header = read_header(path)
    frames: list[pd.DataFrame] = []
    offset = 0
    for batch in _stream(Path(path), header, label_column, block_size_mb):
        n = batch.num_rows
        lo, hi = np.searchsorted(positions, [offset, offset + n])
        if hi > lo:
            local = pa.array(positions[lo:hi] - offset, type=pa.int64())
            frames.append(batch.take(local).to_pandas())
        offset += n

    df = pd.concat(frames, ignore_index=True)
    if len(df) != len(positions):
        raise RuntimeError(
            f"pass 2 recovered {len(df)} rows but {len(positions)} were selected; the file "
            "changed between passes or row positions are misaligned"
        )
    df[label_column] = df[label_column].astype(str).str.strip().astype("category")
    log.info("pass 2: loaded %d selected rows in %.0fs", len(df), time.time() - t0)
    return df
