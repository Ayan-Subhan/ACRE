"""Contract tests for the adversarial discriminator.

Built on synthetic cells rather than the real .npz, so the tests run without the
dataset on disk. What they check is not that the forest is accurate -- accuracy
is measured in the report -- but that the *evaluation cannot lie*: pairs stay
together across folds, held-out families really are held out, and clean rows
survive on both sides so there is always a false-positive rate to read.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aad.defense.discriminator import (  # noqa: E402
    NONE,
    ORIGIN_ADV,
    ORIGIN_POOL,
    ORIGIN_TWIN,
    Cell,
    build_dataset,
    build_forest,
    load_cells,
    per_group_rate,
    split_leave_one_out,
    split_random,
    top_importances,
)

N_FEATURES = 8
N_SOURCE = 60
ATTACKS = ["bim", "deepfool", "fgsm", "pgd"]
MODELS = ["cnn", "lstm", "mlp"]


@pytest.fixture(scope="module")
def pool():
    """A stand-in for test.npz: 4,000 rows, 25% attack, comfortably larger than
    the negatives an "auto" balance will ask it for."""
    rng = np.random.default_rng(0)
    X = rng.random((4000, N_FEATURES), dtype=np.float32)
    y = (np.arange(4000) % 4 == 0).astype(np.int64)
    return X, y


@pytest.fixture(scope="module")
def cells(pool):
    """Twelve cells over one shared sample of source rows, as phase 3 produces."""
    X_pool, y_pool = pool
    rng = np.random.default_rng(1)
    idx = np.sort(rng.choice(np.flatnonzero(y_pool == 1), N_SOURCE, replace=False)).astype(np.int32)
    X_clean = X_pool[idx]
    out = []
    for attack in ATTACKS:
        for model in MODELS:
            # A per-family perturbation direction, so an attack is separable in
            # principle and leave-one-out has something to fail at.
            delta = rng.normal(0, 0.05, X_clean.shape).astype(np.float32)
            out.append(Cell(attack, model, np.clip(X_clean + delta, 0, 1), X_clean, idx, {}))
    return out


@pytest.fixture(scope="module")
def dataset(cells, pool):
    X_pool, y_pool = pool
    return build_dataset(cells, X_pool, y_pool, extra_negatives="auto", seed=42)


RF = {
    "n_estimators": 12, "criterion": "gini", "max_depth": None, "min_samples_leaf": 1,
    "max_features": "sqrt", "class_weight": "balanced_subsample", "n_jobs": 1,
}


def test_positives_are_every_cell(dataset, cells):
    assert int(dataset.y.sum()) == len(cells) * N_SOURCE


def test_twins_appear_once_not_once_per_cell(dataset):
    """The clean originals are byte-identical across all twelve cells. Adding
    them twelve times would weight sixty source flows twelvefold."""
    assert int((dataset.origin == ORIGIN_TWIN).sum()) == N_SOURCE


def test_auto_negatives_balance_the_classes(dataset):
    assert int((dataset.y == 0).sum()) == int(dataset.y.sum())


def test_auto_negatives_preserve_the_pools_benign_mix(dataset, pool):
    """The pool negatives are what make the false-positive rate a statement
    about realistic traffic rather than about attack rows only."""
    _, y_pool = pool
    drawn = dataset.group[dataset.origin == ORIGIN_POOL]
    assert abs(float((y_pool[drawn] == 0).mean()) - float((y_pool == 0).mean())) < 0.02


def test_an_exhausted_pool_warns_instead_of_silently_unbalancing(cells, caplog):
    """A short pool still produces a usable dataset, but the class ratio the
    caller asked for is not what they get, and the FPR moves with it."""
    rng = np.random.default_rng(3)
    small = rng.random((N_SOURCE + 40, N_FEATURES), dtype=np.float32)
    y_small = np.ones(len(small), np.int64)
    small_cells = [
        Cell(c.attack, c.model, c.X_adv, c.X_clean, np.arange(N_SOURCE, dtype=np.int32), {})
        for c in cells
    ]
    with caplog.at_level("WARNING"):
        ds = build_dataset(small_cells, small, y_small, extra_negatives="auto", seed=42)
    assert "unbalanced" in caplog.text
    assert int((ds.y == 0).sum()) < int(ds.y.sum())


def test_negatives_include_unperturbed_attack_rows(dataset):
    """Without the twins the forest could score perfectly on 'is this malicious'
    and never look at the perturbation at all."""
    assert (dataset.origin == ORIGIN_TWIN).any()
    assert (dataset.attack[dataset.origin == ORIGIN_TWIN] == NONE).all()


def test_pool_negatives_never_reuse_a_source_row(dataset, cells):
    pool_groups = dataset.group[dataset.origin == ORIGIN_POOL]
    assert not set(pool_groups.tolist()) & set(cells[0].idx.tolist())


def test_a_pair_shares_one_group(dataset, cells):
    """The whole point of grouping: one source flow, thirteen rows, one group."""
    source = int(cells[0].idx[0])
    sel = dataset.group == source
    assert int(sel.sum()) == len(cells) + 1
    assert set(dataset.origin[sel].tolist()) == {ORIGIN_ADV, ORIGIN_TWIN}


def test_random_split_never_straddles_a_group(dataset):
    train, test = split_random(dataset, test_size=0.3, seed=42)
    assert not set(dataset.group[train].tolist()) & set(dataset.group[test].tolist())


def test_random_split_covers_every_row_once(dataset):
    train, test = split_random(dataset, test_size=0.3, seed=42)
    assert len(set(train.tolist()) & set(test.tolist())) == 0
    assert len(train) + len(test) == len(dataset)


@pytest.mark.parametrize("held", ATTACKS)
def test_leave_one_attack_out_really_holds_it_out(dataset, held):
    train, test = split_leave_one_out(dataset, "attack", held, test_size=0.3, seed=42)
    train_pos = dataset.attack[train][dataset.y[train] == 1]
    test_pos = dataset.attack[test][dataset.y[test] == 1]
    assert held not in set(train_pos.tolist())
    assert set(test_pos.tolist()) == {held}


def test_leave_one_out_keeps_clean_rows_on_both_sides(dataset):
    """A fold with no clean rows has no false-positive rate, and a catch rate
    reported without one is not a result."""
    train, test = split_leave_one_out(dataset, "attack", "fgsm", test_size=0.3, seed=42)
    assert (dataset.y[train] == 0).any()
    assert (dataset.y[test] == 0).any()


def test_leave_one_out_still_respects_groups(dataset):
    train, test = split_leave_one_out(dataset, "model", "mlp", test_size=0.3, seed=42)
    assert not set(dataset.group[train].tolist()) & set(dataset.group[test].tolist())


def test_leave_one_out_rejects_an_unknown_family(dataset):
    with pytest.raises(ValueError, match="not one of"):
        split_leave_one_out(dataset, "attack", "carlini", test_size=0.3, seed=42)


def test_load_cells_rejects_mismatched_source_rows(tmp_path):
    """Cells built from different samples cannot be paired or compared, and the
    grouping below would silently group nothing."""
    for name, idx in (("a_mlp", np.arange(5)), ("b_mlp", np.arange(5) + 100)):
        np.savez_compressed(
            tmp_path / f"{name}.npz",
            X_adv=np.zeros((5, N_FEATURES), np.float32),
            X_clean=np.zeros((5, N_FEATURES), np.float32),
            idx=idx.astype(np.int32),
            meta=json.dumps({"attack": name.split("_")[0], "model": "mlp"}),
        )
    with pytest.raises(ValueError, match="different source rows"):
        load_cells(tmp_path)


def test_load_cells_reports_a_missing_directory(tmp_path):
    with pytest.raises(FileNotFoundError, match="03_generate_ae"):
        load_cells(tmp_path / "nothing")


def test_per_group_rate_counts_only_positives(dataset):
    mask = np.arange(len(dataset))
    y_pred = dataset.y.copy()          # a perfect classifier
    rates = per_group_rate(dataset, mask, y_pred, "attack")
    assert set(rates) == set(ATTACKS)
    assert all(r["catch_rate"] == 1.0 for r in rates.values())
    assert sum(r["support"] for r in rates.values()) == int(dataset.y.sum())
    assert NONE not in rates


def test_per_group_rate_sees_a_family_specific_failure(dataset):
    """The number the aggregate hides: everything caught except one family."""
    y_pred = dataset.y.copy()
    y_pred[dataset.attack == "deepfool"] = 0
    rates = per_group_rate(dataset, np.arange(len(dataset)), y_pred, "attack")
    assert rates["deepfool"]["catch_rate"] == 0.0
    assert rates["fgsm"]["catch_rate"] == 1.0


def test_top_importances_are_named_and_ordered(dataset):
    names = [f"f{i}" for i in range(N_FEATURES)]
    clf = build_forest(RF, seed=42).fit(dataset.X, dataset.y)
    top = top_importances(clf, names, k=4)
    assert len(top) == 4
    assert [t["feature"] for t in top] == [names[t["index"]] for t in top]
    assert top == sorted(top, key=lambda t: -t["gini_importance"])
