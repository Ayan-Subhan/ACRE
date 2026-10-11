"""M4 realism layer: the projection P and the primitive map g.

Synthetic CICIoT2023-style rows only (no dataset needed). Rows obey the
extractor's invariants by construction - 0/1 flags and indicators,
Min <= AVG <= Max, Srate == Rate, Magnitue^2 = 2 AVG - and go through the same
signed-log1p + MinMax path as phase 1.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aad.attacks.realizable.constraints import (  # noqa: E402
    PROJECTION_TOL, Projector, RealismSpec, Scaling,
)
from aad.attacks.realizable.primitives import Primitives  # noqa: E402
from aad.defense.validator import scaled_to_raw  # noqa: E402
from realizable_fixture import CATS, FEATURES, I, make_raw, make_scaling  # noqa: E402,F401

REALISM = ROOT / "config" / "realism.yaml"

# The 46 columns of the raw CICIoT2023 CSV, in file order.
RAW_46 = [
    "flow_duration", "Header_Length", "Protocol Type", "Duration", "Rate", "Srate", "Drate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number",
    "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP", "ARP",
    "ICMP", "IPv", "LLC", "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT",
    "Number", "Magnitue", "Radius", "Covariance", "Variance", "Weight",
]


@pytest.fixture(scope="module")
def world():
    raw = make_raw(400)
    sc, X = make_scaling(raw)
    cats = CATS[np.random.default_rng(1).integers(0, len(CATS), len(X))]
    out = {}
    for spec in ("A", "B", "C"):
        rs = RealismSpec.load(REALISM, spec)
        P = Projector(rs, sc)
        out[spec] = (P, Primitives(P), rs.rate_floor(cats))
    return X, raw, cats, out


def raw_of(P, X):
    return P.to_raw(np.asarray(X, dtype=np.float64)).numpy()


def random_candidates(X, seed=2):
    """Unconstrained 'attacks': each row pushed to a random point of [0,1]^d."""
    return np.random.default_rng(seed).random(X.shape)


# --- the spec itself ---------------------------------------------------------


def test_spec_classifies_every_raw_column_exactly_once():
    rs = RealismSpec.load(REALISM, "A")
    assert sorted(rs.classes) == sorted(RAW_46)


def test_spec_rejects_a_column_in_two_classes():
    cfg = yaml.safe_load(REALISM.read_text(encoding="utf-8"))
    cfg["classes"]["decrease_only"].append("AVG")
    with pytest.raises(ValueError, match="classified twice"):
        RealismSpec.from_dict(cfg)


def test_projector_rejects_an_unclassified_feature():
    cfg = yaml.safe_load(REALISM.read_text(encoding="utf-8"))
    cfg["classes"]["immutable"].remove("Variance")
    rs = RealismSpec.from_dict(cfg)
    sc, _ = make_scaling(make_raw(50))
    with pytest.raises(ValueError, match="does not classify"):
        Projector(rs, sc)


def test_rate_floor_follows_category():
    rs = RealismSpec.load(REALISM, "A")
    np.testing.assert_array_equal(rs.rate_floor(["DDoS", "Web", "Mirai"]), [0.5, 0.0, 0.5])


# --- units -------------------------------------------------------------------


def test_raw_conversion_matches_the_validator(world):
    X, raw, _, out = world
    P = out["A"][0]
    ref = scaled_to_raw(X, P.scaling.data_min, P.scaling.data_range, P.scaling.log1p_indices)
    np.testing.assert_allclose(raw_of(P, X), ref, rtol=1e-12)
    np.testing.assert_allclose(P.to_scaled(ref).numpy(), X, atol=1e-12)


# --- P -----------------------------------------------------------------------


@pytest.mark.parametrize("spec", ["A", "B", "C"])
def test_clean_rows_are_fixed_points(world, spec):
    X, _, _, out = world
    P, _, floor = out[spec]
    np.testing.assert_array_equal(P.project_np(X, X, floor), X)


@pytest.mark.parametrize("spec", ["A", "B", "C"])
def test_projection_is_idempotent(world, spec):
    X, _, _, out = world
    P, _, floor = out[spec]
    once = P.project_np(random_candidates(X), X, floor)
    twice = P.project_np(once, X, floor)
    assert np.abs(twice - once).max() < 1e-9
    assert P.violation(once, X, floor).max() < PROJECTION_TOL


@pytest.mark.parametrize("spec", ["A", "B", "C"])
def test_immutable_columns_never_change(world, spec):
    X, _, _, out = world
    P, _, floor = out[spec]
    Xp = P.project_np(random_candidates(X), X, floor)
    imm = [I[c] for c in ("Protocol Type", "syn_flag_number", "ack_flag_number", "HTTP",
                          "TCP", "UDP", "Std", "Radius", "Variance")]
    np.testing.assert_array_equal(Xp[:, imm], X[:, imm])


def test_flow_age_is_immutable_in_spec_a_and_bounded_in_spec_b(world):
    X, _, _, out = world
    flow = [I[c] for c in ("flow_duration", "Header_Length", "urg_count", "rst_count")]
    cand = random_candidates(X)
    PA, _, fA = out["A"]
    np.testing.assert_array_equal(PA.project_np(cand, X, fA)[:, flow], X[:, flow])

    PB, _, fB = out["B"]
    r0, rp = raw_of(PB, X)[:, flow], raw_of(PB, PB.project_np(cand, X, fB))[:, flow]
    assert (rp >= r0 * (1 - 1e-9)).all()
    assert (rp <= 5.0 * r0 * (1 + 1e-9) + 1e-9).all()
    assert (rp[r0 == 0] == 0).all()          # zero stays zero

    PC, _, fC = out["C"]
    r0, rp = raw_of(PC, X)[:, flow], raw_of(PC, PC.project_np(cand, X, fC))[:, flow]
    assert (rp >= 0.2 * r0 * (1 - 1e-9) - 1e-9).all()
    assert (rp <= 5.0 * r0 * (1 + 1e-9) + 1e-9).all()
    assert (rp < r0 * (1 - 1e-6)).any()      # spec C can make flows younger


@pytest.mark.parametrize("spec", ["A", "B", "C"])
def test_monotone_clamps_and_floors_hold(world, spec):
    X, _, cats, out = world
    P, _, floor = out[spec]
    r0 = raw_of(P, X)
    rp = raw_of(P, P.project_np(random_candidates(X), X, floor))
    tol = 1e-9 * np.abs(r0) + 1e-9
    for c in ("Min", "AVG", "Max", "Tot size"):
        assert (rp[:, I[c]] >= r0[:, I[c]] - tol[:, I[c]]).all(), c
        cap = np.maximum(r0[:, I[c]], 1514.0)
        assert (rp[:, I[c]] <= cap + 1e-6).all(), c
    rate = I["Rate"]
    assert (rp[:, rate] <= r0[:, rate] + tol[:, rate]).all()
    assert (rp[:, rate] >= floor * r0[:, rate] - tol[:, rate]).all()
    flood = cats == "DDoS"
    assert (rp[flood, rate] >= 0.5 * r0[flood, rate] - tol[flood, rate]).all()
    assert ((rp[:, I["Duration"]] >= 1 - 1e-9) & (rp[:, I["Duration"]] <= 255 + 1e-9)).all()


@pytest.mark.parametrize("spec", ["A", "B", "C"])
def test_projected_rows_keep_the_extractor_invariants(world, spec):
    """What the validator's integrality and dependency families check comes for free."""
    X, _, _, out = world
    P, _, floor = out[spec]
    rp = raw_of(P, P.project_np(random_candidates(X), X, floor))
    tol = 1e-6
    assert (rp[:, I["Min"]] <= rp[:, I["AVG"]] * (1 + tol)).all()
    assert (rp[:, I["AVG"]] <= rp[:, I["Max"]] * (1 + tol)).all()
    np.testing.assert_allclose(rp[:, I["Srate"]], rp[:, I["Rate"]], rtol=1e-9)
    for c in ("syn_flag_number", "ack_flag_number", "HTTP", "TCP", "UDP"):
        np.testing.assert_allclose(rp[:, I[c]], np.round(rp[:, I[c]]), atol=1e-9)
    assert (rp[:, I["HTTP"]] <= rp[:, I["TCP"]] + 1e-9).all()


def test_derived_columns_follow_their_base(world):
    X, _, _, out = world
    P, _, floor = out["A"]
    r0 = raw_of(P, X)
    rp = raw_of(P, P.project_np(random_candidates(X), X, floor))
    d_avg = rp[:, I["AVG"]] - r0[:, I["AVG"]]
    np.testing.assert_allclose(rp[:, I["Tot sum"]],
                               r0[:, I["Tot sum"]] * rp[:, I["AVG"]] / r0[:, I["AVG"]], rtol=1e-6)
    np.testing.assert_allclose(rp[:, I["Magnitue"]] ** 2,
                               r0[:, I["Magnitue"]] ** 2 + 2 * d_avg, rtol=1e-6)


def test_assert_realizable_refuses_an_unprojected_row(world):
    X, _, _, out = world
    P, _, floor = out["A"]
    P.assert_realizable(P.project_np(random_candidates(X), X, floor), X, floor)
    with pytest.raises(AssertionError, match="not realizable"):
        P.assert_realizable(random_candidates(X), X, floor)


# --- g -----------------------------------------------------------------------


@pytest.mark.parametrize("spec", ["A", "B", "C"])
def test_zero_theta_is_the_identity(world, spec):
    X, _, _, out = world
    _, g, floor = out[spec]
    np.testing.assert_array_equal(g.apply_np(X, np.zeros((len(X), g.dim)), floor), X)


@pytest.mark.parametrize("spec", ["A", "B", "C"])
def test_g_output_is_realizable(world, spec):
    X, _, _, out = world
    P, g, floor = out[spec]
    lo, hi = g.bounds(X, floor)
    theta = lo + np.random.default_rng(3).random(lo.shape) * (hi - lo)
    Xg = g.apply_np(X, theta, floor)
    P.assert_realizable(Xg, X, floor)
    assert np.abs(P.project_np(Xg, X, floor) - Xg).max() < 1e-9


def test_g_closed_forms(world):
    X, _, _, out = world
    P, g, floor = out["B"]
    r0 = raw_of(P, X)
    theta = np.zeros((len(X), g.dim))
    theta[:, 0] = 10.0          # pad 10 bytes
    theta[:, 1] = 5.0           # TTL +5
    theta[:, 2] = 0.2           # 20% slower
    # rows with headroom: below the size cap, the TTL bound, and the largest value
    # the scaler can represent (P correctly refuses to pad beyond that)
    rows = (r0[:, I["Max"]] < 1400) & (r0[:, I["Duration"]] < 250)
    for c in ("Min", "AVG", "Max", "Tot size", "Tot sum", "Magnitue"):
        rows &= r0[:, I[c]] * 1.2 + 10 < P.raw_hi[I[c]]
    rows &= r0[:, I["Duration"]] + 5 < P.raw_hi[I["Duration"]]
    assert rows.sum() > 50
    rp = raw_of(P, g.apply_np(X, theta, floor))[rows]
    r0 = r0[rows]
    for c in ("Min", "AVG", "Max", "Tot size"):
        np.testing.assert_allclose(rp[:, I[c]], r0[:, I[c]] + 10.0, rtol=1e-6)
    np.testing.assert_allclose(rp[:, I["Duration"]], r0[:, I["Duration"]] + 5.0, rtol=1e-9)
    np.testing.assert_allclose(rp[:, I["Rate"]], 0.8 * r0[:, I["Rate"]], rtol=1e-6)
    np.testing.assert_allclose(rp[:, I["Srate"]], rp[:, I["Rate"]], rtol=1e-9)


def test_theta_bounds_respect_floor_and_spec(world):
    X, _, cats, out = world
    _, gA, fA = out["A"]
    lo, hi = gA.bounds(X, fA)
    assert (lo <= hi).all()
    assert (hi[:, 2] == 0).all() and (hi[:, 3] == 0).all()   # spec A: no throttling, no stretching
    _, gB0, fB0 = out["B"]
    hiB = gB0.bounds(X, fB0)[1]
    np.testing.assert_allclose(hiB[cats == "DDoS", 2], 0.5)
    np.testing.assert_allclose(hiB[cats == "Web", 2], 1 - 1 / 20)
    _, gB, fB = out["B"]
    assert (gB.bounds(X, fB)[1][:, 3] == 4.0).all()
    assert (gB.bounds(X, fB)[0][:, 3] == 0.0).all()
    _, gC, fC = out["C"]
    np.testing.assert_allclose(gC.bounds(X, fC)[0][:, 3], -0.8)


def test_g_is_differentiable_in_theta(world):
    import tensorflow as tf

    X, _, _, out = world
    _, g, floor = out["B"]
    theta = tf.Variable(np.full((len(X), g.dim), 0.1))
    with tf.GradientTape() as tape:
        y = tf.reduce_sum(g.apply(X, theta, floor))
    grad = tape.gradient(y, theta).numpy()
    assert np.isfinite(grad).all()
    assert (np.abs(grad[:, 0]) > 0).any()               # padding moves the output


def test_nan_rows_are_never_realizable(world):
    X, _, _, out = world
    P, _, floor = out["A"]
    bad = X.copy()
    bad[3, 0] = np.nan
    v = P.violation(bad, X, floor)
    assert np.isinf(v[3]) and (v[np.arange(len(v)) != 3] < PROJECTION_TOL).all()
    with pytest.raises(AssertionError, match="not realizable"):
        P.assert_realizable(bad, X, floor)


def test_gradient_is_finite_when_a_linear_column_is_large():
    """A non-log1p column above ~709 used to overflow expm1 in tf.where's unused
    branch, making every gradient through to_raw NaN (found in the M4 smoke run)."""
    import tensorflow as tf

    raw = make_raw(100)
    raw[:, I["Tot sum"]] *= 100.0                       # values up to ~1e5
    sc, X = make_scaling(raw)
    log_idx = tuple(i for i in sc.log1p_indices if i != I["Tot sum"])
    lin = Scaling(sc.feature_names, sc.data_min, sc.data_range, log_idx)
    # rescale Tot sum linearly so the column really is linear in this scaling
    y = raw[:, I["Tot sum"]]
    lin.data_min[I["Tot sum"]], lin.data_range[I["Tot sum"]] = y.min(), y.max() - y.min()
    X[:, I["Tot sum"]] = (y - y.min()) / (y.max() - y.min())
    P = Projector(RealismSpec.load(REALISM, "A"), lin)
    xt = tf.constant(X)
    with tf.GradientTape() as tape:
        tape.watch(xt)
        s = tf.reduce_sum(P.to_raw(xt))
    assert np.isfinite(tape.gradient(s, xt).numpy()).all()


def test_captured_quirks_are_fixed_points():
    """Clean rows the capture produced must survive P untouched, even where they
    break the spec's idealised bounds (found on the real data, M4 step 4.2):
    float32 storage leaves Min a hair above Max in equal-size windows, and a few
    windows have mean TTL 0, below the [1, 255] TTL range."""
    raw = make_raw(60, seed=9)
    raw[:10, I["Min"]] = raw[:10, I["Max"]] * (1 + 1e-7)      # Min an ulp above Max
    raw[:10, I["AVG"]] = raw[:10, I["Max"]]
    raw[10:20, I["Duration"]] = 0.0                            # TTL 0
    sc, X = make_scaling(raw)
    for spec in ("A", "B", "C"):
        P = Projector(RealismSpec.load(REALISM, spec), sc)
        floor = np.zeros(len(X))
        np.testing.assert_array_equal(P.project_np(X, X, floor), X)
        g = Primitives(P)
        np.testing.assert_array_equal(g.apply_np(X, np.zeros((len(X), g.dim)), floor), X)


def test_spec_a_freezes_rate_with_the_connection(world):
    """Rate = connection packets / connection age (CIC's extractor): with the
    connection frozen (spec A) the rate cannot move either."""
    X, _, _, out = world
    P, _, floor = out["A"]
    Xp = P.project_np(random_candidates(X), X, floor)
    for c in ("Rate", "Srate", "flow_duration"):
        np.testing.assert_array_equal(Xp[:, I[c]], X[:, I[c]])
