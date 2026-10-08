"""Stratified 70/15/15 split, signed-log1p transform and train-only MinMax scaling.

Order of operations in phase 1, and why:

1. split            - before anything is fitted, so val/test never inform a fit
2. constant drop    - decided on train only
3. signed log1p     - a fixed function, nothing fitted, so it cannot leak
4. MinMax           - fitted on train only, applied to all three splits

The inverse of 3+4 is needed later (the validator checks rules in raw units),
so ``inverse_signed_log1p`` lives here beside the forward transform.
"""

from __future__ import annotations

import logging

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler

log = logging.getLogger(__name__)


def stratified_split(
    df: pd.DataFrame,
    train: float,
    val: float,
    test: float,
    stratify_col: str,
    seed: int,
) -> dict[str, pd.DataFrame]:
    """Two-stage stratified split. Stratifying on the fine-grained label keeps
    the rarest class (e.g. ~1.2k Uploading_Attack rows) present, in proportion,
    in all three partitions."""
    total = train + val + test
    if abs(total - 1.0) > 1e-9:
        raise ValueError(f"split ratios must sum to 1.0, got {total}")

    strata = df[stratify_col]
    counts = strata.value_counts()
    # A three-way stratified split needs >=1 row in train and >=1 in each of
    # val/test, i.e. the held-out remainder must hold at least two rows.
    min_rows = int(np.ceil(2 / (val + test)))
    if counts.min() < min_rows:
        offenders = counts[counts < min_rows].to_dict()
        raise ValueError(
            f"a {train}/{val}/{test} split needs at least {min_rows} rows per class; "
            f"too few in: {offenders}. Merge the class, drop it, or stratify on the "
            "binary label instead."
        )

    df_train, df_rest = train_test_split(
        df, train_size=train, stratify=strata, random_state=seed, shuffle=True
    )
    # val vs test within the held-out remainder
    rel_val = val / (val + test)
    df_val, df_test = train_test_split(
        df_rest,
        train_size=rel_val,
        stratify=df_rest[stratify_col],
        random_state=seed,
        shuffle=True,
    )

    parts = {
        "train": df_train.reset_index(drop=True),
        "val": df_val.reset_index(drop=True),
        "test": df_test.reset_index(drop=True),
    }
    for name, part in parts.items():
        log.info("%s: %d rows (%.2f%%)", name, len(part), 100 * len(part) / len(df))
    return parts


def signed_log1p(x: np.ndarray) -> np.ndarray:
    """sign(x) * log(1 + |x|). Compresses heavy tails; monotone; defined for x < 0."""
    return np.sign(x) * np.log1p(np.abs(x))


def inverse_signed_log1p(y: np.ndarray) -> np.ndarray:
    """Exact inverse of ``signed_log1p``: sign(y) * (exp(|y|) - 1)."""
    return np.sign(y) * np.expm1(np.abs(y))


def apply_log1p(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    """Signed log1p on ``columns`` in place (float64). Unknown columns are an error:
    a typo in the config would otherwise silently leave a column untransformed."""
    missing = [c for c in columns if c not in df.columns]
    if missing:
        raise KeyError(f"log1p_columns not in the data: {missing}")
    for c in columns:
        df[c] = signed_log1p(df[c].to_numpy(dtype=np.float64))
    return df


def fit_scaler(
    train_df: pd.DataFrame, feature_cols: list[str], feature_range: tuple[float, float]
) -> MinMaxScaler:
    """Fit on train ONLY. Fitting on the full frame is the single most common
    source of inflated numbers in this literature."""
    scaler = MinMaxScaler(feature_range=feature_range)
    scaler.fit(train_df[feature_cols].to_numpy(dtype=np.float64, copy=False))
    return scaler


def transform(
    df: pd.DataFrame,
    feature_cols: list[str],
    scaler: MinMaxScaler,
    clip: bool,
    feature_range: tuple[float, float],
) -> tuple[np.ndarray, dict]:
    """Scale and optionally clip back into range.

    val/test can hold values beyond the train min/max, which would land outside
    [0,1]; ART's attacks are configured with ``clip_values=(0,1)`` and expect the
    input domain to honour that, so clip and report how much was clipped.
    """
    X = scaler.transform(df[feature_cols].to_numpy(dtype=np.float64, copy=False))
    lo, hi = feature_range
    out_of_range = int(((X < lo) | (X > hi)).sum())
    if clip:
        X = np.clip(X, lo, hi)
    stats = {
        "cells": int(X.size),
        "cells_out_of_range_before_clip": out_of_range,
        "fraction_clipped": (out_of_range / X.size) if X.size else 0.0,
    }
    return X.astype(np.float32), stats
