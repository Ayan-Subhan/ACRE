"""Contract tests for the CICIoT2023 analyzer and validator (M3).

Synthetic fixture with the real column names (tests/validator_fixture.py), so the
declared candidate rules resolve exactly as they do on the real feature set -
without needing the dataset on disk.
"""

from __future__ import annotations

import numpy as np
import pytest
from validator_fixture import FEATURES, I, LOG1P, LOG1P_IDX, build, make_benign, to_scaled

from aad.data.split import inverse_signed_log1p
from aad.defense.analyzer import mine
from aad.defense.validator import Z_CLIP, norm_name, protocol_group, scaled_to_raw


@pytest.fixture(scope="module")
def fitted():
    return build()


# --- mining ----------------------------------------------------------------


def test_binary_columns_are_discovered_as_integral(fitted):
    """On CICIoT2023 the flags and protocol indicators are 0/1 in every row, so
    integrality is discovered for them - from data, not from a hardcoded list."""
    rules, _, _, _ = fitted
    found = set(rules["integrality"]["columns"])
    for col in ["syn_flag_number", "ack_flag_number", "HTTP", "TCP", "UDP", "ARP", "IPv"]:
        assert col in found, f"{col} is 0/1 and should be integral"
    for col in ["Number", "Variance", "Protocol Type"]:
        assert col not in found, f"{col} is a window mean and must not be flagged"


def test_log1p_columns_are_never_integrality_checked(fitted):
    """After expm1 their float32 round-trip error grows with the value, so no
    fixed tolerance is honest for them."""
    rules, _, _, _ = fitted
    assert set(rules["integrality"]["columns"]).isdisjoint(LOG1P)


def test_no_integrality_rule_is_vacuous(fitted):
    rules, _, _, _ = fitted
    for col, tol in zip(rules["integrality"]["columns"], rules["integrality"]["tolerance"]):
        assert tol < 0.5, f"{col} has tolerance {tol}: every real number passes"
        assert tol <= rules["integrality"]["max_tolerance"]


def test_candidate_rules_resolve_against_the_schema(fitted):
    rules, _, _, _ = fitted
    names = {r["name"] for r in rules["dependency"]["rules"]}
    for expected in ["Min <= AVG <= Max", "Srate == Rate", "IPv == LLC",
                     "HTTP implies TCP", "DNS implies UDP", "SYN flag implies TCP",
                     "TCP + UDP + ICMP <= 1", "ARP + IPv <= 1"]:
        assert expected in names, f"{expected!r} should be kept"


def test_loose_candidate_is_pruned_and_recorded(fitted):
    """Tot sum ~= Number * AVG does not hold for window means; the analyzer must
    measure that, drop the rule, and say why - not enforce it."""
    rules, _, _, _ = fitted
    kept = {r["name"] for r in rules["dependency"]["rules"]}
    pruned = {r["name"]: r for r in rules["dependency"]["excluded_loose"]}
    assert "Tot sum ~= Number * AVG" not in kept
    assert "Tot sum ~= Number * AVG" in pruned
    assert "benign traffic does not obey it" in pruned["Tot sum ~= Number * AVG"]["reason"]


def test_rules_reference_only_present_columns():
    """A candidate naming a column phase 1 dropped is skipped, not a crash."""
    names = ["Number", "Variance"]
    raw = make_benign(500, seed=2)[:, [I[n] for n in names]]
    data_min, data_range = raw.min(axis=0), np.maximum(np.ptp(raw, axis=0), 1e-9)
    rules = mine(((raw - data_min) / data_range).astype(np.float32), names, data_min, data_range)
    assert rules["dependency"]["rules"] == []


def test_small_protocol_groups_get_their_own_profile_tiny_ones_fall_back(fitted):
    """Regression for the first real run: ARP (175 benign train rows) on the
    global profile meant 100% of benign ARP test rows were rejected."""
    rules, _, _, _ = fitted
    d = rules["distribution"]
    by = dict(zip(d["groups"], d["uses_global_profile"]))
    assert by["TCP"] is False and by["UDP"] is False
    assert by["ARP"] is False                          # ~240 rows >= 100: own profile
    assert by["ICMP"] is True                          # ~30 rows: global profile
    src = dict(zip(d["groups"], d["calibration"]["threshold_source"]))
    assert src["TCP"] == "val" and src["UDP"] == "val"
    assert src["ARP"] == "train+val (in-sample)"
    assert src["ICMP"] == "global"


def test_small_group_benign_rows_are_not_mass_rejected(fitted):
    _, v, data_min, data_range = fitted
    raw = make_benign(20000, seed=17)
    arp = raw[:, I["ARP"]] == 1
    rate = v.check(to_scaled(raw[arp], data_min, data_range)).family_rates()["distribution"]
    assert rate < 0.05, f"benign ARP rows rejected at {rate:.1%}"


# --- false positives -------------------------------------------------------


def test_benign_traffic_passes_within_budget(fitted):
    _, v, data_min, data_range = fitted
    assert v.check(to_scaled(make_benign(3000, seed=99), data_min, data_range)).reject_rate <= 0.03


def test_arithmetic_families_cost_nothing_on_benign(fitted):
    """Integrality and dependency describe how the extractor computes, so on
    genuine benign rows they must not fire (only clipping, which phase 1 applies
    to val/test, could break an identity - and is excluded here)."""
    _, v, data_min, data_range = fitted
    fresh = make_benign(3000, seed=7)
    unclipped = to_scaled(fresh, data_min, data_range, clip=False)
    inside = ((unclipped >= 0) & (unclipped <= 1)).all(axis=1)
    rates = v.check(unclipped[inside]).family_rates()
    assert rates["integrality"] == 0.0
    assert rates["dependency"] == 0.0


# --- catching violations ---------------------------------------------------


def test_fractional_flag_is_caught(fitted):
    """The CICIoT2023 analogue of IDS2018's 7.4 packets: a 0.4 SYN flag."""
    _, v, data_min, data_range = fitted
    raw = make_benign(300, seed=3)
    raw[:, I["syn_flag_number"]] = 0.4
    assert v.check(to_scaled(raw, data_min, data_range)).by_family["integrality"].all()


def test_http_without_tcp_is_caught(fitted):
    _, v, data_min, data_range = fitted
    raw = make_benign(300, seed=4)
    raw[:, I["HTTP"]] = 1.0
    raw[:, I["TCP"]] = 0.0
    assert v.check(to_scaled(raw, data_min, data_range)).by_family["dependency"].all()


def test_two_transport_protocols_at_once_is_caught(fitted):
    _, v, data_min, data_range = fitted
    raw = make_benign(300, seed=5)
    raw[:, I["TCP"]] = raw[:, I["UDP"]] = 1.0
    assert v.check(to_scaled(raw, data_min, data_range)).by_family["dependency"].all()


def test_broken_min_mean_max_ordering_is_caught(fitted):
    """Injected in scaled space, so every value stays inside the benign envelope
    and only the dependency family can see it."""
    _, v, data_min, data_range = fitted
    scaled = to_scaled(make_benign(300, seed=6), data_min, data_range)
    scaled[:, I["Min"]] = 1.0
    scaled[:, I["AVG"]] = 0.0
    assert v.check(scaled).by_family["dependency"].mean() > 0.99


def test_srate_drifting_from_rate_is_caught(fitted):
    _, v, data_min, data_range = fitted
    scaled = to_scaled(make_benign(300, seed=8), data_min, data_range)
    scaled[:, I["Srate"]] = np.clip(scaled[:, I["Srate"]] + 0.05, 0, 1)
    moved = scaled[:, I["Srate"]] != to_scaled(make_benign(300, seed=8), data_min, data_range)[:, I["Srate"]]
    assert v.check(scaled[moved]).by_family["dependency"].all()


def test_out_of_range_value_is_caught(fitted):
    _, v, data_min, data_range = fitted
    raw = make_benign(100, seed=9)
    raw[:, I["Variance"]] = 50.0
    assert v.check(to_scaled(raw, data_min, data_range, clip=False)).by_family["range"].all()


# --- distribution ----------------------------------------------------------


def test_each_group_gets_a_calibrated_unsaturated_threshold(fitted):
    rules, _, _, _ = fitted
    d = rules["distribution"]
    assert len(d["threshold"]) == len(d["groups"])
    for g, t in zip(d["groups"], d["threshold"]):
        assert 0 < t < Z_CLIP, f"group {g} threshold {t} is saturated or unset"


def test_distribution_budget_is_calibrated_not_guessed(fitted):
    _, v, data_min, data_range = fitted
    rate = v.check(to_scaled(make_benign(4000, seed=12), data_min, data_range)).family_rates()["distribution"]
    assert 0.001 < rate < 0.05, f"distribution FPR {rate} is nowhere near its 1% budget"


def test_distribution_family_fires_on_a_diffuse_shift(fitted):
    """A gradient attack nudges most columns a little; the mean-of-z score is
    built to see that."""
    _, v, data_min, data_range = fitted
    scaled = np.clip(to_scaled(make_benign(300, seed=11), data_min, data_range) + 0.3, 0, 1)
    assert v.check(scaled).by_family["distribution"].mean() > 0.5


def test_protocol_group_assignment():
    raw = np.zeros((4, 3))
    raw[0, 0] = 1          # TCP
    raw[1, 1] = 1          # UDP
    raw[2, 2] = 0.3        # nothing >= 0.5 -> other
    raw[3, 1] = 0.7        # perturbed UDP still UDP
    assert protocol_group(raw, [0, 1, 2]).tolist() == [0, 1, 3, 1]


# --- attribution and plumbing ----------------------------------------------


def test_check_reports_which_family_fired(fitted):
    _, v, data_min, data_range = fitted
    raw = make_benign(50, seed=13)
    raw[:, I["syn_flag_number"]] = 0.4
    res = v.check(to_scaled(raw, data_min, data_range))
    assert set(res.by_family) == {"range", "integrality", "dependency", "distribution"}
    assert res.by_family["integrality"].all() and res.reject.all()


def test_selected_families_can_be_run_alone(fitted):
    _, v, data_min, data_range = fitted
    res = v.check(to_scaled(make_benign(50, seed=14), data_min, data_range), families=("dependency",))
    assert set(res.by_family) == {"dependency"}


def test_round_trip_to_raw_units_is_lossless_including_log1p(fitted):
    _, v, data_min, data_range = fitted
    raw = make_benign(200, seed=10)
    back = v.to_raw(to_scaled(raw, data_min, data_range, clip=False))
    assert np.allclose(back, raw, rtol=1e-9, atol=1e-6)


def test_inverse_log1p_matches_phase_1():
    """validator.scaled_to_raw re-implements split.inverse_signed_log1p to stay
    sklearn-free; the two must agree exactly."""
    y = np.linspace(-20, 20, 101).reshape(-1, 1)
    via_validator = scaled_to_raw(y, np.zeros(1), np.ones(1), [0])
    assert np.array_equal(via_validator, inverse_signed_log1p(y))


def test_norm_name_absorbs_spacing_variants():
    assert norm_name("Protocol Type") == norm_name("protocol_type") == "protocoltype"
    assert norm_name("Tot sum") == norm_name("Tot  Sum")


def test_feature_list_matches_fixture():
    assert len(FEATURES) == len(I) and all(FEATURES[i] == n for n, i in I.items())
    assert LOG1P_IDX == sorted(LOG1P_IDX)
