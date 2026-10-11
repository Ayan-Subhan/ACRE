"""Threshold calibration and bootstrap intervals (evaluate.py, M4 step 4.0)."""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aad.evaluate import bootstrap_ci, threshold_for_fpr  # noqa: E402


def test_threshold_meets_the_budget_and_is_tight():
    p = np.random.default_rng(0).random(10_000)
    for fpr in (0.0, 0.01, 0.02, 0.1):
        t = threshold_for_fpr(p, fpr)
        assert (p >= t).mean() <= fpr
        # one notch lower would exceed it (tight), unless the budget is unreachable
        lower = np.sort(p)[::-1][int(np.floor(fpr * len(p)))]
        assert (p >= lower).mean() > fpr


def test_threshold_handles_ties_at_saturation():
    """Saturated softmax: many benign rows at exactly 1.0 cannot all be flagged."""
    p = np.r_[np.ones(50), np.linspace(0, 0.9, 950)]
    t = threshold_for_fpr(p, 0.02)
    assert (p >= t).mean() <= 0.02
    assert t > 1.0                       # no threshold <= 1 keeps 50 tied rows out


def test_bootstrap_interval_covers_the_rate():
    hits = np.random.default_rng(1).random(900) < 0.5
    rate, lo, hi = bootstrap_ci(hits)
    assert lo < rate < hi
    assert 0.04 < hi - lo < 0.09         # about +/-3 points at n = 900


def test_bootstrap_is_reproducible_and_degenerate_cases():
    hits = np.r_[np.ones(30, bool), np.zeros(70, bool)]
    assert bootstrap_ci(hits) == bootstrap_ci(hits)
    assert bootstrap_ci(np.ones(10, bool)) == (1.0, 1.0, 1.0)
    assert np.isnan(bootstrap_ci(np.array([], bool))[0])
