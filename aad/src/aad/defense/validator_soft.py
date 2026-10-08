"""A differentiable twin of the validator, for the adaptive attacker (M4).

The real validator (``validator.py``) answers yes/no with numpy and comparisons,
so it has no gradient: an attacker optimising against it would have nothing to
follow. This module re-expresses each rule family as a non-negative TensorFlow
*penalty* that is exactly zero when the rule passes and grows with the size of
the violation:

    penalty = relu(residual - tolerance)        (dependency rules)
    penalty = relu(lo - x) + relu(x - hi)       (range, normalised by span)
    penalty = sin^2(pi * x)                     (integrality; 0 on the lattice)
    penalty = relu(score - threshold_of_group)  (distribution)

so ``penalty == 0  <=>  the hard validator passes`` for range and dependency
(pinned by tests/test_validator_soft.py), and the attacker can descend on the
sum. It reads the same rules.json - mined rules, tolerances, scaling and log1p
columns - so it can never disagree with the deployed gate about what a rule is.

One part is not differentiable and is handled the standard way (BPDA-style):
which protocol group a row belongs to is a discrete choice, so it is computed
once from the input (or passed in) and held fixed while the score is
differentiated. The success of any attack must still be judged by the real
``Validator``, never by this twin.
"""

from __future__ import annotations

import numpy as np
import tensorflow as tf

from .validator import Z_CLIP, Validator

_F64 = tf.float64


def _const(x) -> tf.Tensor:
    return tf.constant(np.asarray(x, dtype=np.float64), dtype=_F64)


class SoftValidator:
    """Penalties over *scaled* inputs, i.e. the space the attack perturbs."""

    def __init__(self, rules: dict):
        self.hard = Validator(rules)          # for group assignment and parity
        sc = rules["scaling"]
        self.n_features = len(rules["feature_names"])
        self._min = _const(sc["data_min"])
        self._range = _const(sc["data_range"])
        mask = np.zeros(self.n_features, dtype=bool)
        mask[list(sc.get("log1p_indices", []))] = True
        self._log_mask = tf.constant(mask)

        lo = np.asarray(rules["range"]["min"], dtype=np.float64)
        hi = np.asarray(rules["range"]["max"], dtype=np.float64)
        self._lo, self._hi = _const(lo), _const(hi)
        self._span = _const(np.maximum(hi - lo, 1e-9))

        self._int_idx = list(rules["integrality"]["indices"])
        self._deps = rules["dependency"]["rules"]

        d = rules["distribution"]
        self._median = _const(d["median"])
        self._mad = _const(d["mad"])
        self._thr = _const(d["threshold"])

    # --- unit conversion (mirror of validator.scaled_to_raw) -------------------

    def to_raw(self, x_scaled: tf.Tensor) -> tf.Tensor:
        y = tf.cast(x_scaled, _F64) * self._range + self._min
        inv = tf.sign(y) * tf.math.expm1(tf.abs(y))
        return tf.where(self._log_mask, inv, y)

    # --- residuals (mirrors of validator.py, same formulas) --------------------

    @staticmethod
    def _rel(actual, expected):
        return tf.abs(actual - expected) / (tf.abs(expected) + 1.0)

    def dependency_residual(self, raw: tf.Tensor, rule: dict) -> tf.Tensor:
        kind = rule["kind"]
        col = lambda i: raw[:, i]  # noqa: E731
        if kind == "ordering":
            lo, mid, hi = (col(i) for i in rule["indices"])
            return tf.nn.relu(tf.maximum(lo - mid, mid - hi)) / (tf.abs(hi) + 1.0)
        if kind == "product":
            t, c, m = (col(i) for i in rule["indices"])
            return self._rel(t, c * m)
        if kind == "equal":
            a, b = (col(i) for i in rule["indices"])
            return self._rel(a, b)
        if kind == "linear_le":
            zero = tf.zeros_like(raw[:, 0])
            lhs = sum((c * col(i) for i, c in zip(rule["lhs_indices"], rule["lhs_coef"])), zero)
            rhs = sum((c * col(i) for i, c in zip(rule["rhs_indices"], rule["rhs_coef"])), zero)
            bound = rhs + rule["const"]
            return tf.nn.relu(lhs - bound) / (tf.abs(bound) + 1.0)
        raise ValueError(f"unknown dependency rule kind {kind!r}")

    # --- per-family penalties (one value per row, >= 0) -------------------------

    def range_penalty(self, raw: tf.Tensor) -> tf.Tensor:
        over = tf.nn.relu(self._lo - raw) + tf.nn.relu(raw - self._hi)
        return tf.reduce_sum(over / self._span, axis=1)

    def integrality_penalty(self, raw: tf.Tensor) -> tf.Tensor:
        if not self._int_idx:
            return tf.zeros_like(raw[:, 0])
        sub = tf.gather(raw, self._int_idx, axis=1)
        return tf.reduce_sum(tf.sin(np.pi * sub) ** 2, axis=1)

    def dependency_penalty(self, raw: tf.Tensor) -> tf.Tensor:
        total = tf.zeros_like(raw[:, 0])
        for rule in self._deps:
            total += tf.nn.relu(self.dependency_residual(raw, rule) - rule["tolerance"])
        return total

    def groups(self, x_scaled) -> np.ndarray:
        """Protocol group per row, from the hard validator (not differentiated)."""
        return self.hard.groups(self.hard.to_raw(np.asarray(x_scaled)))

    def distribution_score(self, raw: tf.Tensor, groups: np.ndarray) -> tf.Tensor:
        g = tf.constant(np.asarray(groups, dtype=np.int64))
        z = tf.abs(raw - tf.gather(self._median, g)) / tf.gather(self._mad, g)
        return tf.reduce_mean(tf.minimum(z, Z_CLIP), axis=1)

    def distribution_penalty(self, raw: tf.Tensor, groups: np.ndarray) -> tf.Tensor:
        thr = tf.gather(self._thr, tf.constant(np.asarray(groups, dtype=np.int64)))
        return tf.nn.relu(self.distribution_score(raw, groups) - thr)

    def penalties(self, x_scaled: tf.Tensor, groups: np.ndarray | None = None) -> dict:
        """Every family's penalty per row. ``groups`` fixed by the caller (e.g. from
        the clean source row) or computed from ``x_scaled`` and held constant."""
        if groups is None:
            groups = self.groups(x_scaled.numpy() if hasattr(x_scaled, "numpy") else x_scaled)
        raw = self.to_raw(x_scaled)
        return {
            "range": self.range_penalty(raw),
            "integrality": self.integrality_penalty(raw),
            "dependency": self.dependency_penalty(raw),
            "distribution": self.distribution_penalty(raw, groups),
        }

    def total(self, x_scaled: tf.Tensor, groups: np.ndarray | None = None,
              weights: dict | None = None) -> tf.Tensor:
        """Weighted sum of the family penalties, per row."""
        p = self.penalties(x_scaled, groups)
        w = weights or {}
        return tf.add_n([float(w.get(k, 1.0)) * v for k, v in p.items()])
