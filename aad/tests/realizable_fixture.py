"""Shared synthetic fixture for the M4 realism tests (not a test module itself).

CICIoT2023-style rows that obey the extractor's invariants by construction - 0/1
flags and indicators, Min <= AVG <= Max, Srate == Rate, Magnitue^2 = 2 AVG - and
a phase-1-style scaling (signed log1p on the heavy-tailed columns, then MinMax).
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aad.attacks.realizable.constraints import Scaling  # noqa: E402
from aad.data.split import signed_log1p  # noqa: E402

FEATURES = [
    "flow_duration", "Header_Length", "Protocol Type", "Duration", "Rate", "Srate",
    "syn_flag_number", "ack_flag_number", "urg_count", "rst_count",
    "HTTP", "TCP", "UDP", "Tot sum", "Min", "Max", "AVG", "Std", "Tot size",
    "Magnitue", "Radius", "Variance",
]
I = {n: i for i, n in enumerate(FEATURES)}
LOG1P = ["flow_duration", "Header_Length", "Rate", "Srate", "urg_count", "rst_count",
         "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "Radius"]
CATS = np.array(["Benign", "DDoS", "Recon", "Web"])


def make_raw(n: int, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    r = np.zeros((n, len(FEATURES)))
    tcp = rng.random(n) < 0.7
    r[:, I["TCP"]] = tcp
    r[:, I["UDP"]] = ~tcp
    r[:, I["HTTP"]] = tcp & (rng.random(n) < 0.3)
    r[:, I["syn_flag_number"]] = tcp & (rng.random(n) < 0.2)
    r[:, I["ack_flag_number"]] = tcp & (rng.random(n) < 0.8)
    r[:, I["Protocol Type"]] = np.where(tcp, 6.0, 17.0) + rng.random(n)
    r[:, I["Duration"]] = rng.uniform(30, 200, n)
    r[:, I["Rate"]] = np.exp(rng.normal(3, 2, n))
    r[:, I["Srate"]] = r[:, I["Rate"]]
    r[:, I["flow_duration"]] = np.exp(rng.normal(2, 2, n))
    r[:, I["Header_Length"]] = np.exp(rng.normal(9, 3, n))
    r[:, I["urg_count"]] = np.where(rng.random(n) < 0.3, 0.0, np.exp(rng.normal(2, 1.5, n)))
    r[:, I["rst_count"]] = np.exp(rng.normal(3, 2, n))
    mn = rng.uniform(40, 200, n)
    mx = mn + rng.uniform(0, 1400, n)
    avg = mn + rng.random(n) * (mx - mn)
    r[:, I["Min"]], r[:, I["Max"]], r[:, I["AVG"]] = mn, mx, avg
    r[:, I["Tot size"]] = avg * rng.uniform(0.95, 1.05, n)
    r[:, I["Tot sum"]] = avg * rng.choice([5.5, 13.5], n)
    r[:, I["Std"]] = (mx - mn) / 4
    r[:, I["Radius"]] = np.sqrt(2) * r[:, I["Std"]]
    r[:, I["Magnitue"]] = np.sqrt(2 * avg)
    r[:, I["Variance"]] = rng.random(n)
    return r


def make_scaling(raw: np.ndarray) -> tuple[Scaling, np.ndarray]:
    log_idx = [I[c] for c in LOG1P]
    y = raw.copy()
    y[:, log_idx] = signed_log1p(y[:, log_idx])
    lo, hi = y.min(axis=0), y.max(axis=0)
    rng_ = np.where(hi > lo, hi - lo, 1.0)
    sc = Scaling(tuple(FEATURES), lo, rng_, tuple(log_idx))
    return sc, np.clip((y - lo) / rng_, 0, 1)
