"""The M4 attack suite: realizable attacks on the IDS and the validator.

Every attack here produces rows that the projection P accepts (they are
realizable by construction) and judges success with the *deployed* decision
rule: a target model detects a row iff P(attack) >= its calibrated threshold
(``artifacts/models/thresholds.json``, D2), and the validator is always the real
numpy ``Validator``, never its differentiable twin.

Attacks (docs/m4-plan.md section 3.3):

* ``feat_pgd``     - PGD in scaled feature space, P after every step: the
                     strongest attacker the realism spec allows.
* ``prim_pgd``     - PGD on the physical actions theta through g.
* ``*_ens``        - the same against several members at once: the loss is the
                     worst member's, so success means every member is fooled
                     (the OR-ensemble's rule).
* ``adaptive``     - the PGD loss plus lambda x the soft validator's penalty,
                     run up a lambda ladder; a row counts as soon as it fools the
                     targets AND passes the real validator.
* ``blackbox``     - decision-based search over theta: it sees only the
                     pipeline's allow/stop answer (validator + OR of the targets).

Gradients are taken on **logits** (the softmax is removed, as for DeepFool in
phase 3): on a saturated softmax the gradient vanishes, which froze 45% of the
MLP's rows in M3. ``score = (logit_attack - logit_benign) - logit(threshold)``
is >= 0 exactly when the deployed model detects the row.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass

import numpy as np
import tensorflow as tf
from tensorflow import keras

from ..wrappers import as_logits
from .constraints import Projector
from .primitives import Primitives

log = logging.getLogger(__name__)

_F64 = tf.float64


# --------------------------------------------------------------------------- #
# targets
# --------------------------------------------------------------------------- #

@dataclass
class Target:
    """One deployed IDS model and its operating point."""

    name: str
    model: keras.Model          # softmax output, as deployed
    logits: keras.Model         # same weights, softmax removed
    threshold: float            # on P(attack)

    @property
    def tau(self) -> float:
        """The threshold in logit-difference units."""
        t = min(max(self.threshold, 1e-12), 1 - 1e-12)
        return math.log(t / (1 - t))

    def detects(self, X: np.ndarray, batch_size: int = 8192) -> np.ndarray:
        p = self.model.predict(np.asarray(X, dtype=np.float32), batch_size=batch_size, verbose=0)
        return p[:, 1] >= self.threshold

    def p_attack(self, X: np.ndarray, batch_size: int = 8192) -> np.ndarray:
        p = self.model.predict(np.asarray(X, dtype=np.float32), batch_size=batch_size, verbose=0)
        return p[:, 1]


def make_target(name: str, model: keras.Model, threshold: float) -> Target:
    return Target(name, model, as_logits(model), float(threshold))


def detected_by_any(targets: list[Target], X: np.ndarray) -> np.ndarray:
    out = np.zeros(len(X), dtype=bool)
    for t in targets:
        out |= t.detects(X)
    return out


# --------------------------------------------------------------------------- #
# the attacker
# --------------------------------------------------------------------------- #

class Attacker:
    """All attacks share one projection, one primitive map, one validator."""

    def __init__(self, projector: Projector, primitives: Primitives,
                 validator=None, soft_validator=None, batch_size: int = 1024, kappa: float = 0.1):
        self.P, self.g = projector, primitives
        self.validator, self.soft = validator, soft_validator
        self.batch_size = batch_size
        # Margin in logit units: aim slightly past the threshold, so float noise
        # between the logit view and the softmax view cannot flip the verdict.
        self.kappa = kappa
        self._fns: dict = {}

    # --- shared pieces -------------------------------------------------------

    # In-loop success: the worst member's logit margin is below -SUCCESS_MARGIN,
    # i.e. every member says benign with a hair to spare. Every saved row is
    # re-judged by the deployed softmax models in 03b, so this only decides when a
    # row stops being optimised.
    SUCCESS_MARGIN = 1e-3

    def _margins(self, targets, x):
        """(n, members) logit margin above each member's threshold; >= 0 = detected."""
        x32 = tf.cast(x, tf.float32)
        out = []
        for t in targets:
            z = t.logits(x32, training=False)
            out.append(tf.cast(z[:, 1] - z[:, 0], _F64) - t.tau)
        return tf.stack(out, axis=1)

    def _step_fn(self, targets, lam: float, kind: str):
        """Compiled step: the loss gradient at the current point and the worst
        member's margin there (one forward pass serves both). Loss per row:
        relu(worst margin + kappa) + lambda x soft-validator penalty."""
        key = (kind, tuple(id(t) for t in targets), float(lam))
        if key in self._fns:
            return self._fns[key]

        def loss_of(x, groups):
            m = self._margins(targets, x)
            loss = tf.reduce_max(tf.nn.relu(m + self.kappa), axis=1)
            if lam > 0:
                loss = loss + lam * self.soft.total(x, groups)
            return tf.reduce_sum(loss), tf.reduce_max(m, axis=1)

        if kind == "feat":
            def f(x, groups):
                with tf.GradientTape() as tape:
                    tape.watch(x)
                    loss, worst = loss_of(x, groups)
                return tape.gradient(loss, x), worst
        else:
            def f(th, xo, fl, groups):
                with tf.GradientTape() as tape:
                    tape.watch(th)
                    x = self.g.apply(xo, th, fl)
                    loss, worst = loss_of(x, groups)
                return tape.gradient(loss, th), worst, x

        fn = tf.function(f, reduce_retracing=True)
        self._fns[key] = fn
        return fn

    def _won(self, worst, X, need_validator: bool) -> np.ndarray:
        """Rows whose worst member says benign; with the real validator checked
        only on those (it is the slow part)."""
        ok = np.asarray(worst) < -self.SUCCESS_MARGIN
        if need_validator and ok.any():
            idx = np.flatnonzero(ok)
            ok[idx] = ~self.validator.check(np.asarray(X[idx], dtype=np.float32)).reject
        return ok

    def succeeds(self, targets, X, need_validator: bool) -> np.ndarray:
        """The deployed verdict: no target detects the row (and, if asked, the
        real validator lets it through)."""
        ok = ~detected_by_any(targets, X)
        if need_validator:
            ok &= ~self.validator.check(np.asarray(X, dtype=np.float32)).reject
        return ok

    def _batches(self, n):
        for s in range(0, n, self.batch_size):
            yield slice(s, min(s + self.batch_size, n))

    def _groups(self, X, lam: float) -> np.ndarray:
        if lam > 0:
            return np.asarray(self.soft.groups(X), dtype=np.int64)
        return np.zeros(len(X), dtype=np.int64)        # unused when lambda = 0

    @staticmethod
    def _finite(grad: np.ndarray, where: str) -> np.ndarray:
        """sign(NaN) is NaN, and one NaN step poisons the row for good (theta and
        X_adv become NaN). Fail loudly instead of saving garbage."""
        if not np.isfinite(grad).all():
            bad = int((~np.isfinite(grad)).any(axis=1).sum())
            raise FloatingPointError(f"{where}: non-finite gradient on {bad} rows")
        return grad

    # --- feature-space PGD -----------------------------------------------------

    def _feat_run(self, targets, xo, fl, x0, steps, step_size, lam, need_validator):
        """One PGD run from ``x0`` (a realizable start) for one batch."""
        fn = self._step_fn(targets, lam, "feat")
        groups = tf.constant(self._groups(xo, lam))
        x, best = x0.copy(), x0.copy()
        hit = np.zeros(len(xo), dtype=bool)
        for k in range(steps + 1):
            grad, worst = fn(tf.constant(x), groups)
            ok = self._won(worst.numpy(), x, need_validator)
            new = ok & ~hit
            best[new], hit = x[new], hit | ok
            if hit.all() or k == steps:
                break
            grad = self._finite(grad.numpy(), "feat_pgd")
            cand = np.clip(x - step_size * np.sign(grad), 0.0, 1.0)
            cand = self.P.project_np(cand, xo, fl)
            x = np.where(hit[:, None], x, cand)
        return np.where(hit[:, None], best, x), hit

    def feat_pgd(self, targets, X, floor, steps=100, step_size=0.01, lam=0.0,
                 need_validator=False, restarts=0, seed=0) -> tuple[np.ndarray, np.ndarray]:
        """Returns ``(X_adv, success)``. The first run starts at the clean row;
        each restart starts the rows not yet won at a random realizable point (a
        uniform draw in [0,1]^d, projected). Successful rows keep their first
        successful point; the others keep the last run's final iterate."""
        rng = np.random.default_rng(seed)
        X = np.asarray(X, dtype=np.float64)
        floor = np.asarray(floor, dtype=np.float64)
        X_adv, done = X.copy(), np.zeros(len(X), dtype=bool)
        for sl in self._batches(len(X)):
            xo, fl = X[sl], floor[sl]
            xa, hit = self._feat_run(targets, xo, fl, xo, steps, step_size, lam, need_validator)
            for _ in range(restarts):
                todo = np.flatnonzero(~hit)
                if not len(todo):
                    break
                x0 = self.P.project_np(rng.random((len(todo), xo.shape[1])), xo[todo], fl[todo])
                xr, ok = self._feat_run(targets, xo[todo], fl[todo], x0, steps, step_size,
                                        lam, need_validator)
                xa[todo], hit[todo] = xr, ok
            X_adv[sl], done[sl] = xa, hit
        return X_adv, done

    # --- primitive-space PGD ---------------------------------------------------

    def _prim_run(self, targets, xo, fl, th0, lo, hi, steps, step_frac, lam, need_validator):
        """One PGD run on theta from ``th0`` for one batch."""
        fn = self._step_fn(targets, lam, "prim")
        step = step_frac * (hi - lo)
        groups = tf.constant(self._groups(xo, lam))
        xo_t, fl_t = tf.constant(xo), tf.constant(np.asarray(fl, dtype=np.float64))
        th, best_th = th0.copy(), th0.copy()
        hit = np.zeros(len(xo), dtype=bool)
        for k in range(steps + 1):
            grad, worst, x = fn(tf.constant(th), xo_t, fl_t, groups)
            ok = self._won(worst.numpy(), x.numpy(), need_validator)
            new = ok & ~hit
            best_th[new], hit = th[new], hit | ok
            if hit.all() or k == steps:
                break
            grad = self._finite(grad.numpy(), "prim_pgd")
            cand = self.g.clip(th - step * np.sign(grad), lo, hi)
            th = np.where(hit[:, None], th, cand)
        return np.where(hit[:, None], best_th, th), hit

    def prim_pgd(self, targets, X, floor, steps=100, step_frac=0.05, lam=0.0,
                 need_validator=False, restarts=0, seed=0
                 ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Returns ``(X_adv, theta, success)``. Steps are a fraction of each theta
        dimension's own range, signed, then clipped to the box. The first run
        starts at theta = 0 (the unchanged attack); each restart starts the rows
        not yet won at a uniform random theta in the box."""
        rng = np.random.default_rng(seed)
        X = np.asarray(X, dtype=np.float64)
        floor = np.asarray(floor, dtype=np.float64)
        X_adv, theta_out = X.copy(), np.zeros((len(X), self.g.dim))
        done = np.zeros(len(X), dtype=bool)
        for sl in self._batches(len(X)):
            xo, fl = X[sl], floor[sl]
            lo, hi = self.g.bounds(xo, fl)
            th, hit = self._prim_run(targets, xo, fl, np.zeros_like(lo), lo, hi, steps,
                                     step_frac, lam, need_validator)
            for _ in range(restarts):
                todo = np.flatnonzero(~hit)
                if not len(todo):
                    break
                th0 = lo[todo] + rng.random(lo[todo].shape) * (hi[todo] - lo[todo])
                tr, ok = self._prim_run(targets, xo[todo], fl[todo], th0, lo[todo], hi[todo],
                                        steps, step_frac, lam, need_validator)
                th[todo], hit[todo] = tr, ok
            theta_out[sl] = th
            X_adv[sl] = self.g.apply_np(xo, th, fl)
            done[sl] = hit
        return X_adv, theta_out, done

    # --- validator-aware: the lambda ladder --------------------------------------

    def adaptive(self, targets, X, floor, space="prim", ladder=(0.0, 0.1, 1.0, 10.0, 100.0),
                 **kw) -> tuple[np.ndarray, np.ndarray | None, np.ndarray, np.ndarray]:
        """Validator-aware attack: the PGD loss plus lambda x the soft validator.

        The first rung attacks every row; a row is won when it fools every
        target AND passes the real validator. Each later, larger lambda is spent
        only on the rows the previous rung got past the models but not past the
        validator: a validator penalty cannot help a row that never fooled the
        models, so re-attacking those would only cost time (2026-10-09 val run:
        the old full ladder spent 27-55 min per cell for 0-2 extra rows).

        Returns ``(X_adv, theta or None, success, lambda_used)``; lambda_used is
        NaN for rows no rung won."""
        if self.validator is None or self.soft is None:
            raise ValueError("the adaptive attack needs the real and the soft validator")
        X = np.asarray(X, dtype=np.float64)
        floor = np.asarray(floor, dtype=np.float64)
        X_adv = X.copy()
        theta = np.zeros((len(X), self.g.dim)) if space == "prim" else None
        won = self.succeeds(targets, X, need_validator=True)
        lam_used = np.where(won, 0.0, np.nan)
        todo = np.flatnonzero(~won)
        for lam in ladder:
            if not len(todo):
                break
            if space == "prim":
                xa, th, ok = self.prim_pgd(targets, X[todo], floor[todo], lam=lam,
                                           need_validator=True, **kw)
                theta[todo] = th
            else:
                xa, ok = self.feat_pgd(targets, X[todo], floor[todo], lam=lam,
                                       need_validator=True, **kw)
            X_adv[todo] = xa
            won[todo[ok]] = True
            lam_used[todo[ok]] = lam
            blocked = ~ok & ~detected_by_any(targets, xa)   # past the models, not the validator
            log.info("    adaptive lambda=%g: %d of %d rows won; %d fooled the models but not "
                     "the validator", lam, int(ok.sum()), len(todo), int(blocked.sum()))
            todo = todo[blocked]
        return X_adv, theta, won, lam_used

    # --- decision-based black box ------------------------------------------------

    def blackbox(self, targets, X, floor, queries=1000, refine_frac=0.3, seed=0
                 ) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Search theta using only allow/stop answers from validator + targets.

        Phase 1 samples theta uniformly in its box until a row is let through.
        Phase 2 spends the rest of the budget shrinking that theta towards zero
        (cheaper traffic) while it stays allowed: a (1+1) step that is kept only
        if the pipeline still allows it. Returns
        ``(X_adv, theta, success, queries_to_success)`` (queries NaN if none).
        """
        rng = np.random.default_rng(seed)
        X = np.asarray(X, dtype=np.float64)
        floor = np.asarray(floor, dtype=np.float64)
        lo, hi = self.g.bounds(X, floor)
        # The attacker only ever learns allow/stop. It is computed with one compiled
        # forward pass (worst logit margin, then the real validator on the rows the
        # models let through); 03b re-judges every saved row with the deployed models.
        key = ("fwd", tuple(id(t) for t in targets))
        if key not in self._fns:
            self._fns[key] = tf.function(
                lambda th, xo, fl: (lambda x: (tf.reduce_max(self._margins(targets, x), axis=1), x))(
                    self.g.apply(xo, th, fl)),
                reduce_retracing=True)
        fwd = self._fns[key]

        def allowed(th, rows):
            worst, x = fwd(tf.constant(th), tf.constant(X[rows]), tf.constant(floor[rows]))
            return self._won(worst.numpy(), x.numpy(), self.validator is not None)

        theta = np.zeros_like(lo)
        found = allowed(theta, np.arange(len(X)))
        q_to = np.where(found, 0.0, np.nan)
        used = np.ones(len(X))
        search_budget = int(queries * (1 - refine_frac))
        for _ in range(search_budget):
            rows = np.flatnonzero(~found)
            if not len(rows):
                break
            cand = lo[rows] + rng.random((len(rows), lo.shape[1])) * (hi[rows] - lo[rows])
            ok = allowed(cand, rows)
            used[rows] += 1
            theta[rows[ok]] = cand[ok]
            q_to[rows[ok]] = used[rows[ok]]
            found[rows[ok]] = True

        span = np.where(hi - lo > 0, hi - lo, 1.0)
        sigma = np.full(len(X), 0.1)
        for _ in range(queries - search_budget):
            rows = np.flatnonzero(found & (np.abs(theta).sum(axis=1) > 0))
            if not len(rows):
                break
            step = (0.8 + 0.2 * rng.random((len(rows), 1))) * theta[rows]
            step += sigma[rows, None] * span[rows] * rng.normal(size=step.shape)
            cand = self.g.clip(step, lo[rows], hi[rows])
            cheaper = np.abs(cand / span[rows]).sum(axis=1) < np.abs(theta[rows] / span[rows]).sum(axis=1)
            ok = allowed(cand, rows) & cheaper
            theta[rows[ok]] = cand[ok]
            sigma[rows] = np.where(ok, sigma[rows] * 1.2, sigma[rows] * 0.85)
            used[rows] += 1

        return self.g.apply_np(X, theta, floor), theta, found, q_to


# --------------------------------------------------------------------------- #
# source rows and populations
# --------------------------------------------------------------------------- #

# The extractor's packet window per class (CICIoT2023 paper, section 4;
# docs/ciciot2023-features.md): 100 packets for every flood and for
# VulnerabilityScan, 10 for everything else.
WINDOW_100_CATEGORIES = ("DDoS", "DoS", "Mirai")
WINDOW_100_CLASSES = ("VulnerabilityScan",)


def window_population(category_names, class_names) -> np.ndarray:
    """'100-pkt' or '10-pkt' per row, from its category and class."""
    cat = np.asarray(category_names).astype(str)
    cls = np.asarray(class_names).astype(str)
    big = np.isin(cat, WINDOW_100_CATEGORIES) | np.isin(cls, WINDOW_100_CLASSES)
    return np.where(big, "100-pkt", "10-pkt")


def select_rows_per_category(y_category: np.ndarray, eligible: np.ndarray, n_per_category: int,
                             seed: int, benign_code: int = 0) -> np.ndarray:
    """``n_per_category`` eligible rows from every attack category (all of them if
    fewer), drawn reproducibly. Sorted indices into the split."""
    rng = np.random.default_rng(seed)
    out = []
    for code in sorted(set(np.unique(y_category).tolist()) - {benign_code}):
        pool = np.flatnonzero((y_category == code) & eligible)
        take = min(n_per_category, len(pool))
        if take < n_per_category:
            log.warning("category %d: only %d eligible rows (wanted %d)", code, take, n_per_category)
        out.append(rng.choice(pool, size=take, replace=False))
    return np.sort(np.concatenate(out)).astype(np.int32)
