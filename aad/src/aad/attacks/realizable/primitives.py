"""Traffic primitives theta and the map g(x, theta) -> realizable row.

Instead of moving 36 statistics, the primitive attacker chooses a few physical
actions per row (all zero = "send the attack unchanged"):

| theta     | meaning                                   | range                              |
| --------- | ----------------------------------------- | ---------------------------------- |
| `pad`     | bytes added to every packet               | [0, max(0, size_cap - Max)]        |
| `dttl`    | change of the mean IP TTL                 | [1 - Duration, 255 - Duration]     |
| `slow`    | throttling: Rate x (1 - slow)             | [0, 1 - max(floor, 1/max_slowdown)]|
| `stretch` | keep the flow alive (1 + stretch) x longer| [0, factor - 1] in spec B, else 0  |

``g`` applies the closed-form effect of each action in raw units and then the
projection P, which recomputes the derived columns (``Tot sum``, ``Magnitue``,
``Srate``) and enforces every bound. Assumptions behind the closed forms (each
one to be checked at packet level in M7):

* padding reaches every packet of the window, so every size statistic moves by
  ``pad`` and ``Std`` does not move;
* the window's TTL mean moves by ``dttl`` (the window is dominated by the
  attacker's own packets);
* throttling scales ``Rate`` by ``1 - slow``; in spec B it also stretches
  ``flow_duration`` by ``1 / (1 - slow)``;
* in spec B, stretching scales every flow-age column by ``1 + stretch``.

Everything is TensorFlow float64, so attacks can differentiate through g with
respect to theta.
"""

from __future__ import annotations

import numpy as np
import tensorflow as tf

from .constraints import Projector

_F64 = tf.float64

THETA = ("pad", "dttl", "slow", "stretch")
SIZE_COLUMNS = ("Min", "AVG", "Max", "Tot size")
FLOW_AGE_COLUMNS = ("flow_duration", "Header_Length",
                    "ack_count", "syn_count", "fin_count", "urg_count", "rst_count")


class Primitives:
    """g(x_orig, theta) for one projector (and so one realism spec)."""

    def __init__(self, projector: Projector):
        self.P = projector
        idx = projector.idx
        self.size_idx = [idx[c] for c in SIZE_COLUMNS if c in idx]
        self.i_max = idx.get("Max")
        self.i_ttl = idx.get("Duration")
        self.i_rate = idx.get("Rate")
        self.i_dur = idx.get("flow_duration")
        self.flow_idx = [idx[c] for c in FLOW_AGE_COLUMNS if c in idx]
        self.spec_b = projector.spec.flow_age_mode == "increase_only"

    @property
    def dim(self) -> int:
        return len(THETA)

    def bounds(self, x_orig, rate_floor) -> tuple[np.ndarray, np.ndarray]:
        """Per-row box for theta, shape (n, 4) each."""
        raw = self.P.to_raw(np.asarray(x_orig, dtype=np.float64)).numpy()
        n = len(raw)
        lo, hi = np.zeros((n, self.dim)), np.zeros((n, self.dim))
        spec = self.P.spec
        if self.i_max is not None:
            hi[:, 0] = np.maximum(0.0, spec.size_cap - raw[:, self.i_max])
        if self.i_ttl is not None:
            t_lo, t_hi = spec.free_bounds.get("Duration", (1.0, 255.0))
            lo[:, 1] = np.minimum(0.0, t_lo - raw[:, self.i_ttl])
            hi[:, 1] = np.maximum(0.0, t_hi - raw[:, self.i_ttl])
        if self.i_rate is not None:
            floor = np.maximum(np.asarray(rate_floor, dtype=np.float64), 1.0 / spec.max_slowdown)
            hi[:, 2] = np.clip(1.0 - floor, 0.0, 1.0)
        if self.spec_b:
            hi[:, 3] = spec.flow_age_factor - 1.0
        return lo, hi

    def clip(self, theta, lo, hi) -> np.ndarray:
        return np.minimum(np.maximum(np.asarray(theta, dtype=np.float64), lo), hi)

    def apply(self, x_orig, theta, rate_floor) -> tf.Tensor:
        """g: original scaled rows + theta -> projected scaled rows."""
        xo = tf.convert_to_tensor(x_orig, dtype=_F64)
        th = tf.convert_to_tensor(theta, dtype=_F64)
        pad, dttl, slow, stretch = (th[:, k] for k in range(self.dim))
        ro = self.P.to_raw(xo)
        cols = tf.unstack(ro, axis=1)

        for j in self.size_idx:
            cols[j] = cols[j] + pad
        if self.i_ttl is not None:
            cols[self.i_ttl] = cols[self.i_ttl] + dttl
        if self.i_rate is not None:
            cols[self.i_rate] = cols[self.i_rate] * (1.0 - slow)
        if self.spec_b:
            for j in self.flow_idx:
                cols[j] = cols[j] * (1.0 + stretch)
            if self.i_dur is not None:
                cols[self.i_dur] = cols[self.i_dur] / tf.maximum(1.0 - slow, 1e-6)

        # Project in raw units directly: a detour through scaled units would add
        # round-trip noise to columns theta did not touch.
        rp = self.P.project_raw(tf.stack(cols, axis=1), ro, rate_floor)
        return self.P.raw_to_output(rp, ro, xo)

    def apply_np(self, x_orig, theta, rate_floor) -> np.ndarray:
        return self.apply(x_orig, theta, rate_floor).numpy()

    def cost(self, x_orig, x_adv) -> dict[str, np.ndarray]:
        """Attacker cost per row in physical units, read off the rows themselves,
        so feature-space attacks (no theta) and primitive attacks are costed the
        same way."""
        r0 = self.P.to_raw(np.asarray(x_orig, dtype=np.float64)).numpy()
        r1 = self.P.to_raw(np.asarray(x_adv, dtype=np.float64)).numpy()
        idx, n = self.P.idx, len(r0)

        def col(name, default=0.0):
            return (r0[:, idx[name]], r1[:, idx[name]]) if name in idx else (
                np.full(n, default), np.full(n, default))

        avg0, avg1 = col("AVG", 1.0)
        ttl0, ttl1 = col("Duration")
        rate0, rate1 = col("Rate", 1.0)
        dur0, dur1 = col("flow_duration", 1.0)
        pad = avg1 - avg0
        return {
            "pad_bytes": pad,
            "byte_overhead_pct": 100.0 * pad / np.maximum(avg0, 1.0),
            "ttl_change": ttl1 - ttl0,
            "rate_loss_pct": 100.0 * (1.0 - np.divide(rate1, rate0, out=np.ones(n), where=rate0 > 0)),
            "lifetime_factor": np.divide(dur1, dur0, out=np.ones(n), where=dur0 > 0),
        }

    def floor_ok(self, x_orig, x_adv, rate_floor) -> np.ndarray:
        """The functional floor, checked on the rows (P enforces it; this is the
        independent run-time check the plan requires)."""
        if "Rate" not in self.P.idx:
            return np.ones(len(x_orig), dtype=bool)
        j = self.P.idx["Rate"]
        r0 = self.P.to_raw(np.asarray(x_orig, dtype=np.float64)).numpy()[:, j]
        r1 = self.P.to_raw(np.asarray(x_adv, dtype=np.float64)).numpy()[:, j]
        return r1 >= np.asarray(rate_floor) * r0 * (1 - 1e-6) - 1e-9
