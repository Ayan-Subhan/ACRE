"""The realism spec and the projection P onto realizable feature vectors.

An adversarial row is only interesting if some attacker could have produced it.
``config/realism.yaml`` says, column by column, what a traffic-level attacker can
change (its own packets' size, timing and TTL) and how. ``Projector.project``
takes any candidate row and returns the closest row that obeys that spec, given
the original row it started from:

1. **immutable** columns are reset to the original value;
2. **increase_only** columns (packet sizes: padding) are clamped to
   ``[orig, max(orig, size_cap)]``, then ``Min <= AVG <= Max`` is restored;
3. **decrease_only** columns (``Rate``: throttling) are clamped to
   ``[floor * orig, orig]``, where the floor is the row's category's functional
   floor (a flood must keep half its rate);
4. **free_bounded** columns (``Duration``, the mean TTL) are clipped to their
   physical range;
5. **flow_age** columns (per-connection running totals in CIC's extractor) are
   immutable (spec A) or scaled within ``[min_factor, max_factor]`` x the
   original (spec B: keep-alive only, x1..x5; spec C: keep-alive or connection
   churn, x0.2..x5);
6. every base column is clipped to what the deployed scaler can represent;
7. **derived** columns (``Srate``, ``Tot sum``, ``Magnitue``) are recomputed from
   the projected base columns and the row's own original values, never perturbed.

The work happens in raw units (MinMax inverse, then the inverse signed log1p on
the log1p columns, exactly as phase 1 and the validator define them), and the
result is mapped back to the scaled [0,1] space the models read. Columns the
projection leaves unchanged come back as the *exact* original (or candidate)
scaled value, so "features changed" counts stay honest.

There is one implementation, in TensorFlow float64, so gradient-based attacks
can differentiate through it; ``project_np`` wraps the same code for numpy
callers, so checking and attacking can never disagree.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import tensorflow as tf
import yaml

log = logging.getLogger(__name__)

_F64 = tf.float64

CLASSES = ("immutable", "increase_only", "decrease_only", "free_bounded", "flow_age", "derived")
DERIVED_KINDS = ("equal", "scale_with", "sqrt_shift")
FLOW_AGE_MODES = ("immutable", "scaled")

# Projection is idempotent up to float noise; a saved row further than this (in
# scaled units) from its own projection was not produced by P.
PROJECTION_TOL = 1e-5


# --------------------------------------------------------------------------- #
# scaling
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Scaling:
    """Phase-1 transform: signed log1p on some columns, then MinMax."""

    feature_names: tuple[str, ...]
    data_min: np.ndarray
    data_range: np.ndarray
    log1p_indices: tuple[int, ...]

    @classmethod
    def from_dict(cls, t: dict) -> "Scaling":
        """Accepts ``transform.json`` (``minmax_*`` keys) or a rules.json ``scaling``
        block (``data_*`` keys) that carries ``feature_names``."""
        mn = t["minmax_data_min"] if "minmax_data_min" in t else t["data_min"]
        rg = t["minmax_data_range"] if "minmax_data_range" in t else t["data_range"]
        return cls(
            tuple(t["feature_names"]),
            np.asarray(mn, dtype=np.float64),
            np.asarray(rg, dtype=np.float64),
            tuple(int(i) for i in t.get("log1p_indices", [])),
        )

    @classmethod
    def load(cls, path: Path) -> "Scaling":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


# --------------------------------------------------------------------------- #
# the spec
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class RealismSpec:
    """``config/realism.yaml`` resolved for one flow-age spec ("A", "B" or "C")."""

    name: str
    classes: dict            # column -> class
    free_bounds: dict        # column -> (lo, hi)
    derived: dict            # column -> {kind, base, coef}
    size_cap: float
    flow_age_mode: str
    flow_age_min: float      # flow-age columns scaled within [min, max] x original
    flow_age_factor: float   # (the max)
    floors: dict             # category name -> rate floor ("default" required)
    max_slowdown: float

    @classmethod
    def from_dict(cls, cfg: dict, spec: str = "A") -> "RealismSpec":
        classes: dict[str, str] = {}
        for cls_name in CLASSES:
            block = cfg["classes"].get(cls_name) or []
            for col in block:
                if col in classes:
                    raise ValueError(f"{col!r} is classified twice ({classes[col]}, {cls_name})")
                classes[col] = cls_name
        unknown = set(cfg["classes"]) - set(CLASSES)
        if unknown:
            raise ValueError(f"unknown class(es) in realism spec: {sorted(unknown)}")

        derived = {}
        for col, d in (cfg["classes"].get("derived") or {}).items():
            if d["kind"] not in DERIVED_KINDS:
                raise ValueError(f"{col}: unknown derived kind {d['kind']!r}")
            derived[col] = {"kind": d["kind"], "base": d["base"], "coef": float(d.get("coef", 1.0))}

        specs = cfg["flow_age_specs"]
        if spec not in specs:
            raise ValueError(f"unknown flow-age spec {spec!r}; expected one of {sorted(specs)}")
        mode = specs[spec]["mode"]
        if mode not in FLOW_AGE_MODES:
            raise ValueError(f"flow-age spec {spec}: unknown mode {mode!r}")

        floors = {k: float(v["rate_floor"]) for k, v in cfg["floors"].items()}
        if "default" not in floors:
            raise ValueError("floors needs a 'default' entry")

        return cls(
            name=spec,
            classes=classes,
            free_bounds={k: (float(v[0]), float(v[1]))
                         for k, v in (cfg["classes"].get("free_bounded") or {}).items()},
            derived=derived,
            size_cap=float(cfg["size_cap_bytes"]),
            flow_age_mode=mode,
            flow_age_min=float(specs[spec].get("min_factor", 1.0)),
            flow_age_factor=float(specs[spec].get("max_factor", 1.0)),
            floors=floors,
            max_slowdown=float(cfg.get("max_slowdown", 20.0)),
        )

    @classmethod
    def load(cls, path: Path, spec: str = "A") -> "RealismSpec":
        return cls.from_dict(yaml.safe_load(Path(path).read_text(encoding="utf-8")), spec)

    def rate_floor(self, category_names) -> np.ndarray:
        """Functional rate floor per row, from its category name."""
        d = self.floors["default"]
        return np.array([self.floors.get(str(c), d) for c in category_names], dtype=np.float64)


# --------------------------------------------------------------------------- #
# the projection
# --------------------------------------------------------------------------- #

class Projector:
    """P: candidate row x original row -> nearest row the spec allows."""

    def __init__(self, spec: RealismSpec, scaling: Scaling):
        names = list(scaling.feature_names)
        missing = [n for n in names if n not in spec.classes]
        if missing:
            raise ValueError(f"realism spec does not classify: {missing}")

        self.spec, self.scaling = spec, scaling
        self.names = names
        self.idx = {n: i for i, n in enumerate(names)}
        self.n_features = len(names)
        of = lambda c: [i for i, n in enumerate(names) if spec.classes[n] == c]  # noqa: E731

        self.immutable = of("immutable")
        self.increase = of("increase_only")
        self.decrease = of("decrease_only")
        self.free = [(self.idx[n], lo, hi) for n, (lo, hi) in spec.free_bounds.items() if n in self.idx]
        self.flow_age = of("flow_age")
        if spec.flow_age_mode == "immutable":
            # Rate is the connection's packets / its age (CIC's extractor). With the
            # connection's age and packet counters frozen, Rate is frozen too: a
            # throttle that changed Rate alone would be traffic no connection can
            # produce (it made spec A *stronger* than B in the first test run).
            self.immutable = sorted(self.immutable + self.flow_age + self.decrease)
            self.decrease = []
            self.flow_age_scaled: list[int] = []
        else:
            self.flow_age_scaled = self.flow_age

        self.derived = []
        for col, d in spec.derived.items():
            if col not in self.idx:
                continue
            if d["base"] not in self.idx:
                raise ValueError(f"derived {col!r} needs base column {d['base']!r}, which is not a feature")
            if spec.classes[d["base"]] == "derived":
                raise ValueError(f"derived {col!r} has a derived base {d['base']!r}")
            self.derived.append((self.idx[col], d["kind"], self.idx[d["base"]], d["coef"]))
        derived_idx = {t for t, *_ in self.derived}
        self.base = [i for i in range(self.n_features) if i not in derived_idx]

        self.ordering = None
        if all(c in self.idx for c in ("Min", "AVG", "Max")):
            self.ordering = (self.idx["Min"], self.idx["AVG"], self.idx["Max"])

        self._min = tf.constant(scaling.data_min, dtype=_F64)
        self._range = tf.constant(scaling.data_range, dtype=_F64)
        mask = np.zeros(self.n_features, dtype=bool)
        mask[list(scaling.log1p_indices)] = True
        self._log_mask = tf.constant(mask)
        # What the deployed scaler can represent: the raw values of scaled 0 and 1.
        lo = self.to_raw(np.zeros((1, self.n_features))).numpy()[0]
        hi = self.to_raw(np.ones((1, self.n_features))).numpy()[0]
        self.raw_lo, self.raw_hi = np.minimum(lo, hi), np.maximum(lo, hi)

    # --- units -------------------------------------------------------------

    def to_raw(self, x_scaled) -> tf.Tensor:
        y = tf.convert_to_tensor(x_scaled, dtype=_F64) * self._range + self._min
        # Safe-where: expm1 on a non-log column above ~709 would be inf in the unused
        # branch, and its gradient inf * 0 = NaN (see validator_soft.to_raw).
        safe = tf.where(self._log_mask, tf.abs(y), tf.zeros_like(y))
        return tf.where(self._log_mask, tf.sign(y) * tf.math.expm1(safe), y)

    def to_scaled(self, raw) -> tf.Tensor:
        raw = tf.convert_to_tensor(raw, dtype=_F64)
        y = tf.where(self._log_mask, tf.sign(raw) * tf.math.log1p(tf.abs(raw)), raw)
        return (y - self._min) / self._range

    # --- P -------------------------------------------------------------------

    def project_raw(self, ra: tf.Tensor, ro: tf.Tensor, rate_floor) -> tf.Tensor:
        """The projection in raw units. ``ra`` candidate, ``ro`` original."""
        a, o = tf.unstack(ra, axis=1), tf.unstack(ro, axis=1)
        out = list(a)
        floor = tf.convert_to_tensor(rate_floor, dtype=_F64)
        cap = tf.constant(self.spec.size_cap, dtype=_F64)

        for j in self.immutable:
            out[j] = o[j]
        for j in self.increase:
            out[j] = tf.minimum(tf.maximum(a[j], o[j]), tf.maximum(o[j], cap))
        if self.ordering is not None:
            # Min <= AVG <= Max, up to each row's own original slack: float32 storage
            # leaves raw Min a hair above Max in windows of equal-size packets, and P
            # must not "repair" a clean row - only stop the attack making it worse.
            i_min, i_avg, i_max = self.ordering
            s_mm = tf.nn.relu(o[i_min] - o[i_max])
            s_lo = tf.nn.relu(o[i_min] - o[i_avg])
            s_hi = tf.nn.relu(o[i_avg] - o[i_max])
            out[i_max] = tf.maximum(out[i_max], out[i_min] - s_mm)
            out[i_avg] = tf.minimum(tf.maximum(out[i_avg], out[i_min] - s_lo), out[i_max] + s_hi)
        for j in self.decrease:
            out[j] = tf.maximum(tf.minimum(a[j], o[j]), floor * o[j])
        for j, lo, hi in self.free:
            # Widened to include the original: a captured row outside the physical
            # range (a few windows have mean TTL 0) is not moved unless attacked.
            out[j] = tf.clip_by_value(a[j], tf.minimum(o[j], lo), tf.maximum(o[j], hi))
        f_lo = tf.constant(self.spec.flow_age_min, dtype=_F64)
        f_hi = tf.constant(self.spec.flow_age_factor, dtype=_F64)
        for j in self.flow_age_scaled:
            out[j] = tf.minimum(tf.maximum(a[j], f_lo * o[j]), f_hi * o[j])

        for j in self.base:
            out[j] = tf.clip_by_value(out[j], self.raw_lo[j], self.raw_hi[j])

        for t, kind, b, coef in self.derived:
            if kind == "equal":
                v = out[b]
            elif kind == "scale_with":
                safe = tf.where(o[b] > 0, o[b], tf.ones_like(o[b]))
                v = tf.where(o[b] > 0, o[t] * out[b] / safe, o[t] + (out[b] - o[b]))
            else:  # sqrt_shift; floored so sqrt's gradient is finite at 0
                v = tf.sqrt(tf.maximum(o[t] ** 2 + coef * (out[b] - o[b]), 1e-30))
            if kind != "equal":
                # Base unmoved -> exactly the original (o*b/b and sqrt(o^2) are off
                # by an ulp, which would make P(x, x) != x). Straight-through, so the
                # gradient at theta = 0 is not cut.
                exact = tf.where(tf.equal(out[b], o[b]), o[t], v)
                v = tf.stop_gradient(exact) + (v - tf.stop_gradient(v))
            out[t] = tf.clip_by_value(v, self.raw_lo[t], self.raw_hi[t])

        return tf.stack(out, axis=1)

    def project(self, x_adv, x_orig, rate_floor) -> tf.Tensor:
        """P in scaled units (differentiable almost everywhere)."""
        xa = tf.convert_to_tensor(x_adv, dtype=_F64)
        xo = tf.convert_to_tensor(x_orig, dtype=_F64)
        ra, ro = self.to_raw(xa), self.to_raw(xo)
        rp = self.project_raw(ra, ro, rate_floor)
        return self.raw_to_output(rp, ro, xo, ra, xa)

    def raw_to_output(self, rp, ro, xo, ra=None, xa=None) -> tf.Tensor:
        """Projected raw rows -> scaled rows. Columns equal to the original (or to
        the scaled candidate ``xa``) keep that exact value, with no round-trip noise.

        The exact value is substituted with a straight-through estimator: the
        forward value is exact, but the gradient still flows through the
        computed path. A plain ``tf.where`` would cut it, and at theta = 0
        (every column equal to the original) the primitive attack would see a
        zero gradient and never move."""
        out = tf.clip_by_value(self.to_scaled(rp), 0.0, 1.0)
        exact = out
        if ra is not None:
            exact = tf.where(tf.equal(rp, ra), xa, exact)
        exact = tf.where(tf.equal(rp, ro), xo, exact)
        # Forward: exact + 0.0 (bit-exact). Backward: the gradient of `out`.
        return tf.stop_gradient(exact) + (out - tf.stop_gradient(out))

    def project_np(self, x_adv, x_orig, rate_floor) -> np.ndarray:
        return self.project(x_adv, x_orig, rate_floor).numpy()

    def violation(self, x_adv, x_orig, rate_floor) -> np.ndarray:
        """Per row: largest distance (scaled units) between x and P(x).
        Zero, up to float noise, exactly for rows P could have produced."""
        x_adv = np.asarray(x_adv, dtype=np.float64)
        v = np.abs(self.project_np(x_adv, x_orig, rate_floor) - x_adv).max(axis=1)
        # NaN > tol is False: without this a NaN row would pass as realizable.
        return np.where(np.isfinite(x_adv).all(axis=1) & np.isfinite(v), v, np.inf)

    def assert_realizable(self, x_adv, x_orig, rate_floor, what: str = "X_adv") -> None:
        """Run-time guard: refuse any row the spec does not allow."""
        v = self.violation(x_adv, x_orig, rate_floor)
        bad = np.flatnonzero(v > PROJECTION_TOL)
        if len(bad):
            raise AssertionError(
                f"{what}: {len(bad)} of {len(v)} rows are not realizable under spec "
                f"{self.spec.name} (max deviation {v.max():.3g}, first rows {bad[:5].tolist()})"
            )


def load_projector(realism_path: Path, transform_path: Path, spec: str = "A") -> Projector:
    return Projector(RealismSpec.load(realism_path, spec), Scaling.load(transform_path))
