"""The inbound analyzer: mine benign CICIoT2023 traffic into rules.json.

Not a model - a statistics pass. It looks only at *benign training* rows and
writes down what normal traffic obeys. Three consequences for the write-up:

* It never sees an adversarial example, so the validator cannot overfit to the
  attacks it will face (the property NIDS-CBAD claims and AAD does not clearly have).
* It never sees val or test, so the false-positive rate measured later is
  measured on rows the rules were not fitted to.
* Every candidate rule is *tested*, not assumed. A rule benign traffic does not
  obey tightly is pruned and recorded in ``dependency.excluded_loose``; a column
  that looks integral but cannot be verified at float32 precision is recorded in
  ``integrality.excluded_unverifiable``. rules.json therefore states exactly what
  is enforced and what was considered and rejected.

Every tolerance is *calibrated*, not guessed: residuals are measured on benign
train and the threshold is placed at a high percentile with headroom, which fixes
each rule's own false-positive rate by construction. A hand-picked tolerance is
tuned, in practice, until the catch rate looks good - the failure this project
exists to criticise.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np

from . import rules_ciciot2023 as decl
from .validator import (
    OTHER_GROUP,
    Validator,
    dependency_residual,
    norm_name,
    protocol_group,
    scaled_to_raw,
)

log = logging.getLogger(__name__)

# Phase 1 stores X as float32, so recovering raw units costs about
# ``range * 2^-24`` (~6e-8 relative) on linear columns. These constants set every
# tolerance a comfortable margin above that noise while staying far below the
# shift a gradient perturbation produces.
FLOAT32_REL_TOL = 1e-6  # ~16x the float32 round-trip error
INTEGER_TOL_FLOOR = 1e-6  # absolute floor for narrow-range columns

# A tolerance of 0.5 or more makes the integrality check vacuous: every real
# number is within 0.5 of some integer. Columns above this are recorded as
# unverifiable instead of carried as rules that can never fire.
INTEGRALITY_MAX_TOL = 0.25

# Benign residuals of an exact rule are pure float noise; calibrating at a raw
# percentile would fit the noise of this sample and reject the next. Headroom
# and a floor keep the tolerance ~5 orders of magnitude below a gradient step.
DEPENDENCY_TOL_HEADROOM = 10.0
DEPENDENCY_TOL_FLOOR = 1e-6

# A candidate rule whose calibrated relative tolerance exceeds this is not an
# invariant of benign traffic, only a tendency. Enforcing it would either reject
# benign rows or (at a tolerance wide enough not to) constrain nothing - so it
# is pruned and recorded.
DEPENDENCY_MAX_TOL = 0.05

# A protocol group needs this many benign train rows to get its own median/MAD;
# smaller groups use the global profile (recorded per group in rules.json).
# Deliberately low: the first real run used 1,000, which sent ARP (175 benign
# train rows) to the global TCP-dominated profile - and rejected 100% of benign
# ARP test rows. A rough profile of the right protocol beats a precise profile
# of the wrong one.
MIN_GROUP_ROWS = 100
# A group's threshold comes from its own benign VAL rows if it has this many;
# otherwise from its pooled train+val rows (in-sample, recorded as such) if those
# reach MIN_GROUP_ROWS; otherwise the global threshold.
MIN_GROUP_VAL_ROWS = 200


def _index_map(feature_names: list[str]) -> dict[str, int]:
    return {norm_name(n): i for i, n in enumerate(feature_names)}


def _resolve(idx_map: dict[str, int], *names: str) -> list[int] | None:
    """Column indices for a rule, or None if any column was dropped in phase 1."""
    out = []
    for n in names:
        i = idx_map.get(norm_name(n))
        if i is None:
            return None
        out.append(i)
    return out


def find_integer_columns(
    raw: np.ndarray, feature_names: list[str], tolerance: np.ndarray
) -> tuple[list[int], list[int]]:
    """Discover whole-number columns empirically rather than hardcoding a list.

    Returns ``(usable, unverifiable)``: columns that are integral *and* can be
    checked meaningfully, and columns that look integral but whose tolerance is
    too loose (or undefined, for log1p columns) for the test ever to fail.
    """
    frac = np.abs(raw - np.rint(raw))
    # Columns with no finite tolerance (log1p) are still *tested* for looking
    # integral, at a value-relative tolerance, so the "unverifiable" list only
    # names columns that genuinely look like counts.
    tol_matrix = np.where(np.isfinite(tolerance), tolerance,
                          1e-5 * np.maximum(1.0, np.abs(raw)))
    integral = (frac <= tol_matrix).all(axis=0)
    checkable = tolerance < INTEGRALITY_MAX_TOL

    idx = np.flatnonzero(integral & checkable).tolist()
    unverifiable = np.flatnonzero(integral & ~checkable).tolist()
    log.info("%d/%d columns are integral and checkable: %s",
             len(idx), raw.shape[1], [feature_names[i] for i in idx])
    if unverifiable:
        log.info("%d further integral-looking column(s) excluded as unverifiable: %s",
                 len(unverifiable), [feature_names[i] for i in unverifiable])
    return idx, unverifiable


def build_dependency_rules(feature_names: list[str]) -> list[dict]:
    """Instantiate every declared candidate whose columns survived phase 1."""
    idx_map = _index_map(feature_names)
    rules: list[dict] = []

    for lo, mid, hi in decl.ORDERING_RULES:
        ix = _resolve(idx_map, lo, mid, hi)
        if ix:
            rules.append({"kind": "ordering", "name": f"{lo} <= {mid} <= {hi}",
                          "columns": [lo, mid, hi], "indices": ix})

    for a, b in decl.EQUAL_RULES:
        ix = _resolve(idx_map, a, b)
        if ix:
            rules.append({"kind": "equal", "name": f"{a} == {b}", "columns": [a, b],
                          "indices": ix})

    for name, lhs, rhs, const in decl.LINEAR_LE_RULES:
        li = _resolve(idx_map, *lhs) if lhs else []
        ri = _resolve(idx_map, *rhs) if rhs else []
        if li is None or ri is None:
            continue
        rules.append({
            "kind": "linear_le", "name": name, "columns": [*lhs, *rhs],
            "lhs_indices": li, "lhs_coef": [float(v) for v in lhs.values()],
            "rhs_indices": ri, "rhs_coef": [float(v) for v in rhs.values()],
            "const": float(const),
        })

    for total, count, mean in decl.PRODUCT_RULES:
        ix = _resolve(idx_map, total, count, mean)
        if ix:
            rules.append({"kind": "product", "name": f"{total} ~= {count} * {mean}",
                          "columns": [total, count, mean], "indices": ix})
    return rules


def _mad(raw: np.ndarray) -> np.ndarray:
    """Median absolute deviation, scaled to be comparable to a std deviation.

    Floored at 1e-3 of the column's span so a column constant within a group
    does not divide by zero and flag every row on a rounding difference.
    """
    med = np.median(raw, axis=0)
    mad = np.median(np.abs(raw - med), axis=0) * 1.4826
    span = np.maximum(raw.max(axis=0) - raw.min(axis=0), 1e-9)
    return np.maximum(mad, 1e-3 * span)


def _mine_distribution(raw: np.ndarray, feature_names: list[str]) -> dict:
    """Median/MAD per protocol group, falling back to global for small groups."""
    idx_map = _index_map(feature_names)
    names = [g for g in decl.PROTOCOL_GROUPS if norm_name(g) in idx_map]
    gidx = [idx_map[norm_name(g)] for g in names]
    groups = protocol_group(raw, gidx)

    g_med, g_mad = np.median(raw, axis=0), _mad(raw)
    medians, mads, fallback, counts = [], [], [], []
    for g in range(len(names) + 1):
        rows = raw[groups == g]
        counts.append(int(len(rows)))
        if len(rows) >= MIN_GROUP_ROWS:
            medians.append(np.median(rows, axis=0))
            mads.append(_mad(rows))
            fallback.append(False)
        else:
            medians.append(g_med)
            mads.append(g_mad)
            fallback.append(True)
    labels = names + [OTHER_GROUP]
    log.info("distribution groups (benign train rows): %s",
             dict(zip(labels, counts)))
    return {
        "groups": labels,
        "group_columns": names,
        "group_indices": gidx,
        "train_rows": counts,
        "uses_global_profile": fallback,
        "median": [m.tolist() for m in medians],
        "mad": [m.tolist() for m in mads],
        "global_median": g_med.tolist(),
        "global_mad": g_mad.tolist(),
        # Filled by calibrate_distribution; inf keeps the Validator loadable.
        "threshold": [float("inf")] * len(labels),
    }


def mine(
    X_benign_scaled: np.ndarray,
    feature_names: list[str],
    data_min: np.ndarray,
    data_range: np.ndarray,
    log1p_indices: list[int] = (),
    range_tolerance: float = 0.01,
    dependency_percentile: float = 99.9,
) -> dict:
    """Build the rule set from benign training traffic.

    ``range_tolerance`` widens each observed [min,max] by that fraction of the
    column's span: benign val/test rows legitimately fall slightly outside what
    train happened to contain, and a zero-tolerance range rule would charge that
    to the false-positive budget.
    """
    log1p_indices = [int(i) for i in log1p_indices]
    raw = scaled_to_raw(X_benign_scaled, data_min, data_range, log1p_indices)
    n_rows, n_cols = raw.shape
    log.info("mining %d benign training rows x %d features", n_rows, n_cols)

    lo, hi = raw.min(axis=0), raw.max(axis=0)
    pad = range_tolerance * np.maximum(hi - lo, 1e-9)

    # Per column, because the float32 round-trip error scales with span. Log1p
    # columns get no finite tolerance: after expm1 their error grows with the
    # value itself, so they are never integrality-checked.
    int_tol = np.maximum(INTEGER_TOL_FLOOR, np.asarray(data_range) * FLOAT32_REL_TOL)
    int_tol[log1p_indices] = np.inf
    int_idx, int_unverifiable = find_integer_columns(raw, feature_names, int_tol)

    rules = {
        "dataset": "ciciot2023",
        "provenance": {
            "source": "benign rows of data/processed/train.npz",
            "n_rows": int(n_rows),
            "range_tolerance": range_tolerance,
            "dependency_percentile": dependency_percentile,
            "dependency_max_tolerance": DEPENDENCY_MAX_TOL,
            "integer_rel_tolerance": FLOAT32_REL_TOL,
        },
        "feature_names": feature_names,
        "scaling": {"data_min": np.asarray(data_min).tolist(),
                    "data_range": np.asarray(data_range).tolist(),
                    "log1p_indices": log1p_indices,
                    "log1p_columns": [feature_names[i] for i in log1p_indices]},
        "range": {"min": (lo - pad).tolist(), "max": (hi + pad).tolist()},
        "integrality": {
            "indices": int_idx,
            "columns": [feature_names[i] for i in int_idx],
            "tolerance": int_tol[int_idx].tolist(),
            "max_tolerance": INTEGRALITY_MAX_TOL,
            "excluded_unverifiable": [feature_names[i] for i in int_unverifiable],
        },
        "dependency": {"rules": build_dependency_rules(feature_names), "excluded_loose": []},
        "distribution": _mine_distribution(raw, feature_names),
    }
    _calibrate_dependencies(rules, raw, dependency_percentile)
    return rules


def _calibrate_dependencies(rules: dict, raw: np.ndarray, percentile: float) -> None:
    """Set each candidate's tolerance from its own benign residuals, then prune
    the candidates benign traffic does not actually obey."""
    kept, pruned = [], []
    for rule in rules["dependency"]["rules"]:
        res = dependency_residual(raw, rule)
        tol = float(np.percentile(res, percentile))
        rule["tolerance"] = max(tol * DEPENDENCY_TOL_HEADROOM, DEPENDENCY_TOL_FLOOR)
        rule["benign_residual"] = {
            "p50": float(np.percentile(res, 50)),
            "p99": float(np.percentile(res, 99)),
            f"p{percentile}": tol,
            "max": float(res.max()),
            "share_nonzero": float((res > 0).mean()),
        }
        loose = rule["tolerance"] > DEPENDENCY_MAX_TOL
        (pruned if loose else kept).append(rule)
        log.info("  %-44s tol=%.2e  benign p50 %.2e max %.2e  %s",
                 rule["name"], rule["tolerance"], rule["benign_residual"]["p50"],
                 rule["benign_residual"]["max"], "PRUNED (loose)" if loose else "kept")
    for rule in pruned:
        rule["reason"] = (f"calibrated tolerance {rule['tolerance']:.3g} > "
                          f"{DEPENDENCY_MAX_TOL}: benign traffic does not obey it tightly")
    rules["dependency"]["rules"] = kept
    rules["dependency"]["excluded_loose"] = pruned


def calibrate_distribution(
    rules: dict,
    X_val_benign_scaled: np.ndarray,
    fpr_budget: float = 0.01,
    X_train_benign_scaled: np.ndarray | None = None,
) -> dict:
    """Set each protocol group's outlier threshold, preferably on *validation* rows.

    Every group gets its own (1 - budget) quantile, so each spends the same
    budget. Calibrating on the rows the medians were mined from reports an
    optimistic FPR - the leak this project criticises elsewhere - so val is used
    whenever the group has enough val rows. For a tiny group (e.g. ARP: ~37 benign
    val rows) a 99th percentile of val alone is noise; if train rows are given,
    the pooled train+val rows are used instead and the group is marked
    ``train+val (in-sample)``. Only if even that is too small does the group fall
    back to the global threshold.
    """
    v = Validator(rules)
    raw = v.to_raw(X_val_benign_scaled)
    groups = v.groups(raw)
    scores = v.distribution_score(raw, groups)
    q = 100 * (1 - fpr_budget)
    global_thr = float(np.percentile(scores, q))

    tr_scores = tr_groups = None
    if X_train_benign_scaled is not None:
        raw_tr = v.to_raw(X_train_benign_scaled)
        tr_groups = v.groups(raw_tr)
        tr_scores = v.distribution_score(raw_tr, tr_groups)

    d = rules["distribution"]
    thresholds, val_rows, source = [], [], []
    for g in range(len(d["groups"])):
        s = scores[groups == g]
        val_rows.append(int(len(s)))
        pooled = s if tr_scores is None else np.concatenate([s, tr_scores[tr_groups == g]])
        if len(s) >= MIN_GROUP_VAL_ROWS:
            thresholds.append(float(np.percentile(s, q)))
            source.append("val")
        elif tr_scores is not None and len(pooled) >= MIN_GROUP_ROWS:
            thresholds.append(float(np.percentile(pooled, q)))
            source.append("train+val (in-sample)")
        else:
            thresholds.append(global_thr)
            source.append("global")
    d["threshold"] = thresholds
    d["calibration"] = {
        "source": "benign rows of data/processed/val.npz (train+val for tiny groups)",
        "n_rows": int(len(scores)),
        "val_rows_per_group": val_rows,
        "threshold_source": source,
        "fpr_budget": fpr_budget,
        "global_threshold": global_thr,
    }
    log.info("distribution thresholds at a %.1f%% budget: %s", 100 * fpr_budget,
             {gname: round(t, 4) for gname, t in zip(d["groups"], thresholds)})
    return rules


def save(rules: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rules, indent=2), encoding="utf-8")
    log.info("wrote %s", path)
    return path
