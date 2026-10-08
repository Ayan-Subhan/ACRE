"""Gate 1: reject rows that are not valid CICIoT2023 packet windows.

The premise of the whole defense. A gradient attack perturbs a vector of
*statistics*, but those statistics were computed from real packets by one
extractor and are therefore not independent. Move them freely and you get a row
no capture could produce: a 0.4 SYN flag, an HTTP packet that is not TCP, a
minimum packet length above the mean, a Srate that is no longer the Rate. The
validator checks arithmetic and benign-traffic envelopes, not learned behaviour,
so it needs no adversarial training data and has nothing to overfit.

Four rule families, each answering a different question:

* **range**        - is every value inside what benign traffic ever showed?
* **integrality**  - are the columns benign traffic only ever fills with whole
                     numbers still whole? (On CICIoT2023: the 0/1 TCP flags and
                     protocol indicators - see docs/m3-validator.md.)
* **dependency**   - do the columns still agree with each other?
* **distribution** - is the row jointly plausible *for its protocol*, even if
                     each value is legal on its own?

This module owns the rule *definitions* and the residual arithmetic.
``analyzer.py`` imports the same functions to calibrate tolerances, and
``validator_soft.py`` mirrors them in TensorFlow, so mining, checking and the
adaptive attacker's differentiable copy can never drift apart.

The checks run in **raw units**, not in the scaled [0,1] model space. Phase 1
applied a signed log1p to 16 heavy-tailed columns and then MinMax to all of them;
``scaled_to_raw`` undoes both, with every parameter stored in rules.json, so the
validator is pure numpy with no sklearn dependency at inference time.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

log = logging.getLogger(__name__)

FAMILIES = ("range", "integrality", "dependency", "distribution")

# Ceiling on any single feature's z-score, so one near-constant column cannot
# dominate a row's outlier score. See Validator.distribution_score.
Z_CLIP = 50.0

# Index of the catch-all group for rows carrying none of the protocol indicators.
OTHER_GROUP = "other"


def norm_name(s: str) -> str:
    """'Protocol Type' -> 'protocoltype'. Absorbs header spacing/case drift."""
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


# --- unit conversion --------------------------------------------------------


def scaled_to_raw(
    X_scaled: np.ndarray, data_min: np.ndarray, data_range: np.ndarray, log1p_indices
) -> np.ndarray:
    """Undo phase 1: MinMax inverse, then the inverse signed log1p on its columns.

    Must stay identical to ``aad.data.split.inverse_signed_log1p`` (pinned by a
    test); it is re-implemented here only so this module does not import sklearn.
    """
    raw = np.asarray(X_scaled, dtype=np.float64) * data_range + data_min
    idx = np.asarray(log1p_indices, dtype=np.int64)
    if len(idx):
        y = raw[:, idx]
        raw[:, idx] = np.sign(y) * np.expm1(np.abs(y))
    return raw


# --- residual arithmetic (shared with analyzer.py, mirrored in validator_soft.py)


def _rel_residual(actual: np.ndarray, expected: np.ndarray) -> np.ndarray:
    """Scale-free disagreement. The +1 floor keeps it finite near zero, where
    most flag and indicator columns live."""
    return np.abs(actual - expected) / (np.abs(expected) + 1.0)


def ordering_residual(raw: np.ndarray, i_lo: int, i_mid: int, i_hi: int) -> np.ndarray:
    """How far min <= mean <= max is violated, relative to the max."""
    lo, mid, hi = raw[:, i_lo], raw[:, i_mid], raw[:, i_hi]
    return np.maximum(np.maximum(lo - mid, mid - hi), 0.0) / (np.abs(hi) + 1.0)


def product_residual(raw: np.ndarray, i_total: int, i_count: int, i_mean: int) -> np.ndarray:
    return _rel_residual(raw[:, i_total], raw[:, i_count] * raw[:, i_mean])


def equal_residual(raw: np.ndarray, i_a: int, i_b: int) -> np.ndarray:
    return _rel_residual(raw[:, i_a], raw[:, i_b])


def linear_le_residual(
    raw: np.ndarray, lhs_idx, lhs_coef, rhs_idx, rhs_coef, const: float
) -> np.ndarray:
    """How far sum(lhs) <= sum(rhs) + const is violated, relative to the bound."""
    lhs = raw[:, np.asarray(lhs_idx, dtype=np.int64)] @ np.asarray(lhs_coef, dtype=np.float64) \
        if len(lhs_idx) else np.zeros(len(raw))
    rhs = raw[:, np.asarray(rhs_idx, dtype=np.int64)] @ np.asarray(rhs_coef, dtype=np.float64) \
        if len(rhs_idx) else np.zeros(len(raw))
    bound = rhs + const
    return np.maximum(lhs - bound, 0.0) / (np.abs(bound) + 1.0)


def dependency_residual(raw: np.ndarray, rule: dict) -> np.ndarray:
    """One rule's residual on raw rows."""
    kind = rule["kind"]
    if kind == "ordering":
        return ordering_residual(raw, *rule["indices"])
    if kind == "product":
        return product_residual(raw, *rule["indices"])
    if kind == "equal":
        return equal_residual(raw, *rule["indices"])
    if kind == "linear_le":
        return linear_le_residual(raw, rule["lhs_indices"], rule["lhs_coef"],
                                  rule["rhs_indices"], rule["rhs_coef"], rule["const"])
    raise ValueError(f"unknown dependency rule kind {kind!r}")


def protocol_group(raw: np.ndarray, group_indices: list[int]) -> np.ndarray:
    """Group id per row: the first protocol indicator that is set, else 'other'.

    Indicators are 0/1 on CICIoT2023 and at most one transport is set per row (a
    dependency rule enforces it), so "first set" is unambiguous on real traffic.
    On a perturbed row with fractional indicators the largest one >= 0.5 wins.
    """
    n_groups = len(group_indices)
    if not n_groups:
        return np.zeros(len(raw), dtype=np.int64)
    block = raw[:, np.asarray(group_indices, dtype=np.int64)]
    best = block.argmax(axis=1)
    has = block.max(axis=1) >= 0.5
    return np.where(has, best, n_groups).astype(np.int64)


@dataclass
class ValidationResult:
    """Which rows were rejected, and by which family."""

    reject: np.ndarray
    by_family: dict[str, np.ndarray] = field(default_factory=dict)

    @property
    def reject_rate(self) -> float:
        return float(self.reject.mean()) if len(self.reject) else 0.0

    def family_rates(self) -> dict[str, float]:
        return {k: float(v.mean()) for k, v in self.by_family.items()}


class Validator:
    """Stateless, vectorised checker over a mined rules.json."""

    def __init__(self, rules: dict):
        self.rules = rules
        self.feature_names: list[str] = rules["feature_names"]
        self.n_features = len(self.feature_names)

        sc = rules["scaling"]
        self._data_min = np.asarray(sc["data_min"], dtype=np.float64)
        self._data_range = np.asarray(sc["data_range"], dtype=np.float64)
        self._log1p_idx = list(sc.get("log1p_indices", []))

        r = rules["range"]
        self._lo = np.asarray(r["min"], dtype=np.float64)
        self._hi = np.asarray(r["max"], dtype=np.float64)

        self._int_idx = np.asarray(rules["integrality"]["indices"], dtype=np.int64)
        # Per-column, not a single scalar. See check_integrality.
        self._int_tol = np.asarray(rules["integrality"]["tolerance"], dtype=np.float64)

        self._deps = rules["dependency"]["rules"]

        d = rules["distribution"]
        self._group_idx = list(d["group_indices"])
        self._median = np.asarray(d["median"], dtype=np.float64)       # (groups, features)
        self._mad = np.asarray(d["mad"], dtype=np.float64)
        self._threshold = np.asarray(d["threshold"], dtype=np.float64)  # (groups,)

    @classmethod
    def load(cls, path: Path) -> Validator:
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    # --- unit conversion ---------------------------------------------------

    def to_raw(self, X_scaled: np.ndarray) -> np.ndarray:
        return scaled_to_raw(X_scaled, self._data_min, self._data_range, self._log1p_idx)

    # --- the four families -------------------------------------------------

    def check_range(self, raw: np.ndarray) -> np.ndarray:
        return ((raw < self._lo) | (raw > self._hi)).any(axis=1)

    def check_integrality(self, raw: np.ndarray) -> np.ndarray:
        """Columns that benign traffic only ever fills with whole numbers.

        On CICIoT2023 these are the TCP flags and protocol indicators: 0 or 1 in
        every one of 2.5M rows. A gradient step adds a real-valued delta, so an
        attacked indicator lands on 0.37 almost surely.

        The tolerance is per column and proportional to the column's range: the
        float32 storage of X costs about range * 2^-24 when mapped back to raw
        units. Log1p columns are never integrality-checked (their round-trip
        error grows with the value, so no fixed tolerance is honest); the
        analyzer lists them as unverifiable.
        """
        if not len(self._int_idx):
            return np.zeros(len(raw), dtype=bool)
        sub = raw[:, self._int_idx]
        return (np.abs(sub - np.rint(sub)) > self._int_tol).any(axis=1)

    def check_dependency(self, raw: np.ndarray) -> np.ndarray:
        viol = np.zeros(len(raw), dtype=bool)
        for rule in self._deps:
            viol |= dependency_residual(raw, rule) > rule["tolerance"]
        return viol

    def groups(self, raw: np.ndarray) -> np.ndarray:
        return protocol_group(raw, self._group_idx)

    def distribution_score(self, raw: np.ndarray, groups: np.ndarray | None = None) -> np.ndarray:
        """Robust per-row outlier score against benign rows *of the same protocol*.

        The mean of clipped per-feature |x - median| / MAD, with median and MAD
        mined separately for each protocol group. One global profile would call
        every ICMP or ARP row an outlier simply for not looking like the TCP
        majority, and would have to set its threshold loose enough to tolerate
        that - wasting the budget.

        Mean rather than max, and clipped at Z_CLIP, so a single near-constant
        column cannot decide the score (the IDS2018 run found both the hard way).
        """
        g = self.groups(raw) if groups is None else groups
        z = np.abs(raw - self._median[g]) / self._mad[g]
        np.clip(z, 0.0, Z_CLIP, out=z)
        return z.mean(axis=1)

    def check_distribution(self, raw: np.ndarray) -> np.ndarray:
        g = self.groups(raw)
        return self.distribution_score(raw, g) > self._threshold[g]

    # --- combined ----------------------------------------------------------

    def check(self, X_scaled: np.ndarray, families: tuple[str, ...] = FAMILIES) -> ValidationResult:
        """Validate scaled rows, reporting which family fired.

        Attribution matters: a combined reject rate cannot tell you whether the
        defense rests on arithmetic (which an adaptive attacker can satisfy) or
        on distribution (which is harder to satisfy silently).
        """
        raw = self.to_raw(X_scaled)
        checks = {
            "range": self.check_range,
            "integrality": self.check_integrality,
            "dependency": self.check_dependency,
            "distribution": self.check_distribution,
        }
        by_family = {f: checks[f](raw) for f in families}
        reject = np.zeros(len(raw), dtype=bool)
        for mask in by_family.values():
            reject |= mask
        return ValidationResult(reject=reject, by_family=by_family)
