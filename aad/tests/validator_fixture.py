"""Shared synthetic fixture for the validator tests (not a test module itself).

A small "benign" population with real CICIoT2023 column names, built so every
true invariant of the extractor holds by construction (0/1 flags and protocol
indicators, protocol hierarchy, Min <= AVG <= Max, Srate == Rate, IPv == LLC)
while the window-mean product ``Tot sum ~= Number * AVG`` is only approximate,
as it is on the real data. Rows go through the same signed-log1p + MinMax path
as phase 1, so the validator's inverse transform is exercised too.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aad.data.split import signed_log1p  # noqa: E402
from aad.defense.analyzer import calibrate_distribution, mine  # noqa: E402
from aad.defense.validator import Validator  # noqa: E402

FEATURES = [
    "flow_duration", "Header_Length", "Protocol Type", "Rate", "Srate",
    "syn_flag_number", "ack_flag_number",
    "HTTP", "HTTPS", "DNS", "TCP", "UDP", "ICMP", "ARP", "IPv", "LLC",
    "Tot sum", "Min", "AVG", "Max", "Number", "Variance",
]
I = {name: i for i, name in enumerate(FEATURES)}
LOG1P = ["flow_duration", "Header_Length", "Rate", "Srate", "Tot sum", "Min", "AVG", "Max"]
LOG1P_IDX = [I[c] for c in LOG1P]


def make_benign(n: int = 6000, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    # TCP, UDP, ICMP, ARP. ICMP is made tiny (~30 train rows -> global profile)
    # and ARP small (~240 train, ~120 val rows -> own profile, threshold from
    # pooled train+val), so every calibration path is exercised.
    proto = rng.choice(4, size=n, p=[0.60, 0.355, 0.005, 0.04])
    tcp, udp, icmp, arp = (proto == k for k in range(4))

    raw = np.zeros((n, len(FEATURES)))
    raw[:, I["TCP"]], raw[:, I["UDP"]] = tcp, udp
    raw[:, I["ICMP"]], raw[:, I["ARP"]] = icmp, arp
    raw[:, I["IPv"]] = raw[:, I["LLC"]] = ~arp
    web = rng.integers(0, 3, n)                                  # 0 none, 1 HTTP, 2 HTTPS
    raw[:, I["HTTP"]] = tcp & (web == 1)
    raw[:, I["HTTPS"]] = tcp & (web == 2)
    raw[:, I["DNS"]] = udp & (rng.random(n) < 0.5)
    raw[:, I["syn_flag_number"]] = tcp & (rng.random(n) < 0.3)
    raw[:, I["ack_flag_number"]] = tcp & (rng.random(n) < 0.6)
    raw[:, I["Protocol Type"]] = np.select([tcp, udp, icmp], [6.0, 17.0, 1.0], 0.0) \
        + rng.random(n) * 0.3

    rate = rng.lognormal(3.5, 2.0, n)
    raw[:, I["Rate"]] = raw[:, I["Srate"]] = rate
    raw[:, I["flow_duration"]] = rng.lognormal(1.5, 2.0, n)
    raw[:, I["Header_Length"]] = rng.lognormal(9.0, 2.0, n)
    mn = 42.0 + rng.lognormal(2.5, 1.0, n)
    avg = mn + rng.lognormal(3.0, 1.5, n)
    raw[:, I["Min"]], raw[:, I["AVG"]] = mn, avg
    raw[:, I["Max"]] = avg + rng.lognormal(3.0, 1.5, n)
    number = rng.choice([5.5, 9.5, 13.5], n)
    raw[:, I["Number"]] = number
    # mean of products != product of means: only approximately count * mean
    raw[:, I["Tot sum"]] = number * avg * (1.0 + 0.4 * rng.random(n))
    raw[:, I["Variance"]] = rng.random(n)
    return raw


def transform(raw: np.ndarray) -> np.ndarray:
    """Phase 1's fixed part: signed log1p on the LOG1P columns."""
    out = raw.astype(np.float64).copy()
    out[:, LOG1P_IDX] = signed_log1p(out[:, LOG1P_IDX])
    return out


def build(n_train: int = 6000, n_val: int = 3000):
    """Mine + calibrate exactly as phase 4 does. Returns (rules, validator, scale)."""
    t = transform(make_benign(n_train, seed=0))
    data_min = t.min(axis=0)
    data_range = np.maximum(t.max(axis=0) - data_min, 1e-9)
    scaled = ((t - data_min) / data_range).astype(np.float32)
    rules = mine(scaled, FEATURES, data_min, data_range, log1p_indices=LOG1P_IDX)
    val = to_scaled(make_benign(n_val, seed=1), data_min, data_range)
    rules = calibrate_distribution(rules, val, fpr_budget=0.01, X_train_benign_scaled=scaled)
    return rules, Validator(rules), data_min, data_range


def to_scaled(raw, data_min, data_range, clip: bool = True) -> np.ndarray:
    x = (transform(raw) - data_min) / data_range
    return (np.clip(x, 0, 1) if clip else x).astype(np.float32 if clip else np.float64)
