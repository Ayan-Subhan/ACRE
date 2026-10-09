"""M4 attack suite on a toy problem (synthetic rows, a hand-built linear model).

The toy IDS flags a row when its packets are small and fast, so padding and
throttling are exactly the moves that evade it. A toy validator rejects rows
whose mean TTL is above 100, and its soft twin penalises the same thing, so the
adaptive attack has a reason to need lambda > 0.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest
import tensorflow as tf
from tensorflow import keras

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aad.attacks.realizable.attacks import (  # noqa: E402
    Attacker, make_target, select_rows_per_category, window_population,
)
from aad.attacks.realizable.constraints import Projector, RealismSpec  # noqa: E402
from aad.attacks.realizable.primitives import Primitives  # noqa: E402
from aad.defense.validator import ValidationResult  # noqa: E402
from realizable_fixture import FEATURES, I, make_raw, make_scaling  # noqa: E402

REALISM = ROOT / "config" / "realism.yaml"


def toy_model(d: int) -> keras.Model:
    """logit(attack) - logit(benign) = 3.5 - AVG - Max + 4*Rate - 12*Duration (scaled).

    The TTL (Duration) is the strongest lever, so an attacker that ignores the
    validator raises it past 100, which the toy validator forbids."""
    inp = keras.Input((d,))
    out = keras.layers.Dense(2, activation="softmax")(inp)
    m = keras.Model(inp, out)
    w = np.zeros((d, 2), dtype=np.float32)
    w[I["AVG"], 1] = w[I["Max"], 1] = -1.0
    w[I["Rate"], 1] = 4.0
    w[I["Duration"], 1] = -12.0
    m.layers[-1].set_weights([w, np.array([0.0, 3.5], dtype=np.float32)])
    return m


class ToyValidator:
    def __init__(self, P: Projector):
        self.P = P

    def check(self, X):
        raw = self.P.to_raw(np.asarray(X, dtype=np.float64)).numpy()
        rej = raw[:, I["Duration"]] > 100.0
        return ValidationResult(reject=rej, by_family={"distribution": rej})


class ToySoft:
    def __init__(self, P: Projector):
        self.P = P

    def groups(self, X):
        return np.zeros(len(X), dtype=np.int64)

    def total(self, x, groups=None):
        return tf.nn.relu(self.P.to_raw(x)[:, I["Duration"]] - 90.0) / 10.0


@pytest.fixture(scope="module")
def setup():
    raw = make_raw(1500, seed=5)
    sc, X = make_scaling(raw)
    P = Projector(RealismSpec.load(REALISM, "B"), sc)
    g = Primitives(P)
    model = toy_model(len(FEATURES))
    p = model.predict(X, verbose=0)[:, 1]
    # attack rows the toy IDS detects, with TTL room below the validator's line
    rows = (p >= 0.5) & (raw[:, I["Duration"]] < 95) & (raw[:, I["Max"]] < 1000)
    Xs = X[rows]
    floor = np.zeros(len(Xs))
    target = make_target("toy", model, threshold=0.5)
    atk = Attacker(P, g, validator=ToyValidator(P), soft_validator=ToySoft(P), batch_size=64)
    assert len(Xs) > 30
    return Xs, floor, target, atk, P


def test_feat_pgd_evades_with_realizable_rows(setup):
    X, floor, target, atk, P = setup
    Xa, ok = atk.feat_pgd([target], X, floor, steps=60, step_size=0.02)
    assert ok.mean() > 0.5
    assert not target.detects(Xa[ok]).any()
    P.assert_realizable(Xa, X, floor)


def test_prim_pgd_evades_with_realizable_rows_and_theta_in_bounds(setup):
    X, floor, target, atk, P = setup
    Xa, th, ok = atk.prim_pgd([target], X, floor, steps=60, step_frac=0.05)
    assert ok.mean() > 0.5
    assert not target.detects(Xa[ok]).any()
    P.assert_realizable(Xa, X, floor)
    lo, hi = atk.g.bounds(X, floor)
    assert ((th >= lo - 1e-12) & (th <= hi + 1e-12)).all()
    np.testing.assert_allclose(atk.g.apply_np(X, th, floor), Xa)


def test_unaware_attack_trips_the_validator_and_the_ladder_fixes_it(setup):
    X, floor, target, atk, _ = setup
    Xa, _, ok = atk.prim_pgd([target], X, floor, steps=60)
    caught = atk.validator.check(Xa[ok]).reject.mean()
    assert caught > 0.05                    # raising the TTL is the easy way out

    Xv, _, won, lam = atk.adaptive([target], X, floor, space="prim", steps=60)
    assert won.mean() > ok.mean() - caught * ok.mean()    # validator-aware does better
    assert not atk.validator.check(Xv[won]).reject.any()
    assert not target.detects(Xv[won]).any()
    assert (lam[won] >= 0).all() and np.isnan(lam[~won]).all()
    assert (lam[won] > 0).any()             # some rows needed the penalty


def test_blackbox_uses_only_decisions_and_stays_realizable(setup):
    X, floor, target, atk, P = setup
    Xa, th, ok, q = atk.blackbox([target], X, floor, queries=150, seed=0)
    assert ok.mean() > 0.3
    assert not atk.validator.check(Xa[ok]).reject.any()
    assert not target.detects(Xa[ok]).any()
    assert np.isnan(q[~ok]).all() and (q[ok] >= 1).all()
    P.assert_realizable(Xa, X, floor)


def test_rows_per_category_are_balanced_and_eligible():
    ycat = np.repeat([0, 1, 2, 3], 100)
    eligible = np.ones(400, dtype=bool)
    eligible[200:280] = False               # category 2 has only 20 eligible rows
    idx = select_rows_per_category(ycat, eligible, 30, seed=0)
    assert (ycat[idx] != 0).all()
    assert eligible[idx].all()
    counts = np.bincount(ycat[idx], minlength=4)
    assert counts.tolist() == [0, 30, 20, 30]
    np.testing.assert_array_equal(idx, select_rows_per_category(ycat, eligible, 30, seed=0))


def test_window_population():
    pop = window_population(["DDoS", "Recon", "Recon", "Web"],
                            ["DDoS-SYN_Flood", "VulnerabilityScan", "Recon-PortScan", "XSS"])
    assert pop.tolist() == ["100-pkt", "100-pkt", "10-pkt", "10-pkt"]


def test_restarts_only_add_successes(setup):
    X, floor, target, atk, P = setup
    _, _, ok0 = atk.prim_pgd([target], X, floor, steps=2, step_frac=0.05)
    Xr, _, ok3 = atk.prim_pgd([target], X, floor, steps=2, step_frac=0.05, restarts=3, seed=1)
    assert (ok3 >= ok0).all() and ok3.sum() > ok0.sum()
    assert not target.detects(Xr[ok3]).any()
    P.assert_realizable(Xr, X, floor)
    Xf, okf = atk.feat_pgd([target], X, floor, steps=2, step_size=0.02, restarts=3, seed=1)
    P.assert_realizable(Xf, X, floor)
    assert not target.detects(Xf[okf]).any()
