"""The differentiable twin must agree with the real validator (M3).

If SoftValidator and Validator disagreed about what a rule is, the M4 adaptive
attacker would optimise against the wrong gate and report a meaningless result.
These tests pin the agreement on the synthetic CICIoT2023 fixture.
"""

from __future__ import annotations

import numpy as np
import pytest
import tensorflow as tf
from validator_fixture import I, build, make_benign, to_scaled

from aad.defense.validator import dependency_residual
from aad.defense.validator_soft import SoftValidator


@pytest.fixture(scope="module")
def setup():
    rules, v, data_min, data_range = build()
    return rules, v, SoftValidator(rules), data_min, data_range


def _perturbed(data_min, data_range, n=400, seed=21, eps=0.08, clip=True):
    """Benign rows plus a random +/-eps step in scaled space: a mix of rows that
    pass and rows that violate, which is what an attack produces. ``clip=False``
    lets values leave [0,1], which is the only way the range family can fire
    (the benign envelope is the train min/max, i.e. exactly [0,1] plus padding)."""
    rng = np.random.default_rng(seed)
    x = to_scaled(make_benign(n, seed=seed), data_min, data_range).astype(np.float64)
    step = rng.choice([-eps, 0.0, eps], size=x.shape, p=[0.3, 0.4, 0.3])
    return np.clip(x + step, 0, 1) if clip else x + step


def test_raw_units_match(setup):
    _, v, s, data_min, data_range = setup
    x = _perturbed(data_min, data_range)
    np.testing.assert_allclose(s.to_raw(tf.constant(x)).numpy(), v.to_raw(x), rtol=1e-12)


def test_dependency_residuals_match_numpy(setup):
    rules, v, s, data_min, data_range = setup
    x = _perturbed(data_min, data_range)
    raw_np, raw_tf = v.to_raw(x), s.to_raw(tf.constant(x))
    for rule in rules["dependency"]["rules"] + rules["dependency"]["excluded_loose"]:
        np.testing.assert_allclose(
            s.dependency_residual(raw_tf, rule).numpy(), dependency_residual(raw_np, rule),
            rtol=1e-9, atol=1e-12, err_msg=rule["name"])


@pytest.mark.parametrize("family", ["range", "dependency"])
def test_zero_penalty_iff_hard_family_passes(setup, family):
    _, v, s, data_min, data_range = setup
    x = _perturbed(data_min, data_range, eps=0.3, clip=(family != "range"))
    hard = v.check(x, families=(family,)).by_family[family]
    soft = s.penalties(tf.constant(x))[family].numpy() > 0
    assert hard.any() and (~hard).any(), "fixture must contain both outcomes"
    assert np.array_equal(hard, soft)


def test_distribution_score_matches_numpy(setup):
    _, v, s, data_min, data_range = setup
    x = _perturbed(data_min, data_range)
    raw = v.to_raw(x)
    g = v.groups(raw)
    np.testing.assert_allclose(
        s.distribution_score(s.to_raw(tf.constant(x)), g).numpy(),
        v.distribution_score(raw, g), rtol=1e-9)
    hard = v.check(x, families=("distribution",)).by_family["distribution"]
    soft = s.penalties(tf.constant(x), g)["distribution"].numpy() > 0
    assert np.array_equal(hard, soft)


def test_integrality_penalty_is_zero_on_the_lattice_and_large_off_it(setup):
    _, _, s, data_min, data_range = setup
    clean = to_scaled(make_benign(200, seed=31), data_min, data_range)
    assert s.penalties(tf.constant(clean))["integrality"].numpy().max() < 1e-9
    raw = make_benign(200, seed=31)
    raw[:, I["syn_flag_number"]] = 0.5
    bad = to_scaled(raw, data_min, data_range)
    assert s.penalties(tf.constant(bad))["integrality"].numpy().min() > 0.9


def test_gradients_are_finite_and_point_somewhere(setup):
    """The attacker needs a usable gradient on violating rows."""
    _, v, s, data_min, data_range = setup
    x = tf.Variable(_perturbed(data_min, data_range, seed=41))
    groups = s.groups(x.numpy())
    with tf.GradientTape() as tape:
        loss = tf.reduce_sum(s.total(x, groups))
    grad = tape.gradient(loss, x).numpy()
    assert np.isfinite(grad).all()
    violating = v.check(x.numpy(), families=("range", "dependency")).reject
    assert np.abs(grad[violating]).sum(axis=1).min() > 0
