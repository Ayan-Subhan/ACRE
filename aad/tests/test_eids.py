"""Contract tests for the EIDS.

Synthetic throughout -- no dataset, no trained models. What is checked is the
part that governs whether the phase-6 numbers can be believed: that the held-out
attack family really is held out, that adversarial rows enter training labelled
as attacks, and that the OR rule has the algebraic properties the report leans on
when it says a recall gain was bought with false positives.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aad.defense.discriminator import Cell  # noqa: E402
from aad.evaluate import binary_metrics  # noqa: E402
from aad.models.eids import (  # noqa: E402
    ATTACK_LABEL,
    build_augmented,
    disagreement,
    or_ensemble,
    or_ensemble_prob,
    select_pool,
)

N_FEATURES = 6
N_ROWS = 40
ATTACKS = ["fgsm", "bim", "pgd", "deepfool"]
MODELS = ["mlp", "cnn", "lstm"]


@pytest.fixture(scope="module")
def cells():
    rng = np.random.default_rng(0)
    idx = np.arange(N_ROWS, dtype=np.int32)
    return [
        Cell(a, m, rng.random((N_ROWS, N_FEATURES), dtype=np.float32),
             rng.random((N_ROWS, N_FEATURES), dtype=np.float32), idx, {})
        for a in ATTACKS for m in MODELS
    ]


@pytest.fixture(scope="module")
def clean_train():
    rng = np.random.default_rng(1)
    X = rng.random((500, N_FEATURES), dtype=np.float32)
    y = (np.arange(500) % 10 == 0).astype(np.int64)
    return X, y


def test_holdout_attack_never_reaches_training(cells):
    pool = select_pool(cells, "mlp", holdout_attacks=("deepfool",), sources="all")
    assert "deepfool" not in {c.attack for c in pool}
    assert {c.attack for c in pool} == {"fgsm", "bim", "pgd"}


def test_holdout_is_case_insensitive(cells):
    pool = select_pool(cells, "mlp", holdout_attacks=("DeepFool",), sources="all")
    assert "deepfool" not in {c.attack for c in pool}


def test_sources_own_keeps_only_its_own_examples(cells):
    pool = select_pool(cells, "cnn", holdout_attacks=(), sources="own")
    assert {c.model for c in pool} == {"cnn"}
    assert len(pool) == len(ATTACKS)


def test_sources_all_pools_every_model(cells):
    pool = select_pool(cells, "cnn", holdout_attacks=(), sources="all")
    assert {c.model for c in pool} == set(MODELS)


def test_unknown_sources_setting_is_rejected(cells):
    with pytest.raises(ValueError, match="'all' or 'own'"):
        select_pool(cells, "mlp", sources="everything")


def test_adversarial_rows_are_labelled_attack(cells, clean_train):
    """An adversarial example is still a malicious flow. Labelling it anything
    else teaches the model the attacker's intended answer."""
    X_train, y_train = clean_train
    pool = select_pool(cells, "mlp", ("deepfool",), "all")
    X, y, meta = build_augmented(X_train, y_train, pool)
    assert (y[len(X_train):] == ATTACK_LABEL).all()
    assert len(X) == len(X_train) + meta["n_adversarial"]
    assert meta["n_adversarial"] == len(pool) * N_ROWS


def test_augmentation_ratio_is_reported(clean_train, cells):
    X_train, y_train = clean_train
    pool = select_pool(cells, "mlp", ("deepfool",), "all")
    _, _, meta = build_augmented(X_train, y_train, pool)
    assert meta["augmentation_ratio"] == pytest.approx(meta["n_adversarial"] / len(X_train))


def test_fraction_subsamples_the_pool(clean_train, cells):
    X_train, y_train = clean_train
    pool = select_pool(cells, "mlp", ("deepfool",), "all")
    _, _, half = build_augmented(X_train, y_train, pool, fraction=0.5, seed=42)
    _, _, full = build_augmented(X_train, y_train, pool, fraction=1.0, seed=42)
    assert half["n_adversarial"] == pytest.approx(full["n_adversarial"] / 2, rel=0.02)


def test_an_empty_pool_fails_loudly(clean_train, cells):
    """Holding out every family leaves nothing to train on. Silently training a
    'hardened' model on clean data alone would be the worst possible outcome."""
    X_train, y_train = clean_train
    with pytest.raises(ValueError, match="no adversarial examples"):
        build_augmented(X_train, y_train, select_pool(cells, "mlp", tuple(ATTACKS), "all"))


def test_or_flags_when_any_member_does():
    preds = {
        "mlp": np.array([0, 1, 0, 0], np.int8),
        "cnn": np.array([0, 0, 1, 0], np.int8),
        "lstm": np.array([0, 0, 0, 0], np.int8),
    }
    assert or_ensemble(preds).tolist() == [0, 1, 1, 0]


def test_or_needs_a_member():
    with pytest.raises(ValueError, match="at least one"):
        or_ensemble({})


def test_or_recall_never_falls_below_the_best_member_and_fpr_never_below_the_worst():
    """The trade the report is built on, asserted rather than assumed."""
    rng = np.random.default_rng(7)
    y = rng.integers(0, 2, 2000)
    preds = {f"m{i}": (rng.random(2000) < 0.7).astype(np.int8) * y
                      | (rng.random(2000) < 0.02).astype(np.int8)
             for i in range(3)}
    members = [binary_metrics(y, p) for p in preds.values()]
    ens = binary_metrics(y, or_ensemble(preds))
    assert ens["recall"] >= max(m["recall"] for m in members) - 1e-12
    assert ens["fpr"] >= max(m["fpr"] for m in members) - 1e-12


def test_ensemble_probability_follows_the_deciding_member():
    probs = {
        "mlp": np.array([[0.9, 0.1], [0.4, 0.6]], np.float32),
        "cnn": np.array([[0.7, 0.3], [0.95, 0.05]], np.float32),
    }
    out = or_ensemble_prob(probs)
    assert out[:, 1].tolist() == pytest.approx([0.3, 0.6])
    assert out.sum(axis=1).tolist() == pytest.approx([1.0, 1.0])


def test_disagreement_finds_the_member_carrying_a_row():
    preds = {
        "mlp": np.array([1, 0, 0], np.int8),
        "cnn": np.array([0, 0, 0], np.int8),
        "lstm": np.array([1, 1, 0], np.int8),
    }
    d = disagreement(preds)
    assert d["unique_flags"] == {"mlp": 0, "cnn": 0, "lstm": 1}
    assert d["n_rows"] == 3


def test_disagreement_separates_a_unique_catch_from_a_unique_false_alarm():
    """Under OR a lone flag is added whatever the truth is. Counting both as
    'contribution' reads a member's false alarms as if they were saves."""
    preds = {
        "mlp": np.array([1, 0, 0, 0], np.int8),   # row 0: lone flag on an attack
        "cnn": np.array([0, 1, 0, 0], np.int8),   # row 1: lone flag on benign
        "lstm": np.array([0, 0, 1, 1], np.int8),  # rows 2,3: agreed with nobody
    }
    y = np.array([1, 0, 1, 0])
    d = disagreement(preds, y)
    assert d["unique_flags"] == {"mlp": 1, "cnn": 1, "lstm": 2}
    assert d["unique_catches"] == {"mlp": 1, "cnn": 0, "lstm": 1}
    assert d["unique_false_alarms"] == {"mlp": 0, "cnn": 1, "lstm": 1}


def test_disagreement_omits_the_split_without_labels():
    d = disagreement({"a": np.array([1, 0], np.int8), "b": np.array([0, 0], np.int8)})
    assert "unique_catches" not in d


def test_disagreement_reports_full_agreement():
    preds = {n: np.array([1, 1, 0], np.int8) for n in ("mlp", "cnn")}
    assert disagreement(preds)["unanimous_%"] == pytest.approx(1.0)
