"""Contract tests for the AAD pipeline.

Stages are injected as plain functions, so these run without rules.json, a forest
or any Keras model. What they pin down is the part the phase-7 numbers depend on:
that the pipeline short-circuits in the declared order, that attribution names the
stage that actually stopped each row, and that a redundant gate shows up as
redundant in the ablation instead of being credited twice.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aad.defense.pipeline import (  # noqa: E402
    ALLOWED,
    DISCRIMINATOR,
    EIDS,
    STAGES,
    VALIDATOR,
    Pipeline,
    ablate,
    marginal_contribution,
)

N = 8
X = np.arange(N, dtype=np.float32).reshape(N, 1)


def stops(indices):
    """A stage that stops exactly the rows whose first feature is in ``indices``."""
    wanted = set(indices)
    return lambda x: np.array([float(v[0]) in wanted for v in x], dtype=bool)


def stops_nothing(x):
    return np.zeros(len(x), dtype=bool)


def test_stages_run_in_pipeline_order_regardless_of_how_they_were_listed():
    p = Pipeline(validator_fn=stops_nothing, discriminator_fn=stops_nothing,
                 eids_fn=stops_nothing, stages=(EIDS, VALIDATOR))
    assert p.stages == (VALIDATOR, EIDS)


def test_the_first_stage_to_stop_a_row_owns_it():
    """Both the validator and the EIDS would stop row 0; the validator runs first,
    so the attribution must not credit the EIDS."""
    p = Pipeline(validator_fn=stops([0]), discriminator_fn=stops([1]), eids_fn=stops([0, 2]))
    v = p.decide(X)
    assert v.stage[0] == VALIDATOR
    assert v.stage[1] == DISCRIMINATOR
    assert v.stage[2] == EIDS
    assert v.stage[3] == ALLOWED


def test_a_stopped_row_never_reaches_a_later_stage():
    """Per-stage counts are what a stage saw and stopped, not what it would stop
    alone. A later stage must not be handed rows already blocked."""
    seen: list[int] = []

    def counting(x):
        seen.append(len(x))
        return np.zeros(len(x), dtype=bool)

    Pipeline(validator_fn=stops([0, 1, 2]), discriminator_fn=counting,
             eids_fn=counting).decide(X)
    assert seen == [N - 3, N - 3]


def test_stage_counts_partition_every_row():
    p = Pipeline(validator_fn=stops([0]), discriminator_fn=stops([1, 2]), eids_fn=stops([3]))
    counts = p.decide(X).stage_counts()
    assert sum(counts.values()) == N
    assert counts[VALIDATOR] == 1 and counts[DISCRIMINATOR] == 2 and counts[EIDS] == 1
    assert counts[ALLOWED] == N - 4


def test_stop_rate_matches_the_stopped_mask():
    v = Pipeline(validator_fn=stops([0, 1]), discriminator_fn=stops_nothing,
                 eids_fn=stops_nothing).decide(X)
    assert v.stop_rate == pytest.approx(2 / N)
    assert v.stopped.sum() == 2


def test_a_subset_can_run_without_the_other_predictors():
    p = Pipeline(eids_fn=stops([5]), stages=(EIDS,))
    v = p.decide(X)
    assert p.stages == (EIDS,)
    assert v.stage[5] == EIDS and v.stopped.sum() == 1


def test_enabling_a_stage_with_no_predictor_fails_loudly():
    with pytest.raises(ValueError, match="no predictor"):
        Pipeline(validator_fn=stops([0]), stages=(VALIDATOR, EIDS))


def test_an_unknown_stage_name_is_rejected():
    with pytest.raises(ValueError, match="unknown stage"):
        Pipeline(validator_fn=stops([0]), stages=("firewall",))


def test_a_stage_returning_the_wrong_length_fails_loudly():
    """Silently broadcasting a mis-shaped mask would mis-attribute every row."""
    with pytest.raises(ValueError, match="one boolean per row"):
        Pipeline(validator_fn=lambda x: np.zeros(3, dtype=bool), stages=(VALIDATOR,)).decide(X)


def test_empty_input_is_handled():
    v = Pipeline(validator_fn=stops([0]), stages=(VALIDATOR,)).decide(X[:0])
    assert len(v) == 0 and v.stop_rate == 0.0


def test_ablation_covers_every_non_empty_subset():
    fns = {VALIDATOR: stops([0]), DISCRIMINATOR: stops([1]), EIDS: stops([2])}
    subsets = [s for s, _ in ablate(fns, X)]
    assert len(subsets) == 7
    assert (VALIDATOR,) in subsets and tuple(STAGES) in subsets
    assert all(list(s) == [x for x in STAGES if x in s] for s in subsets)


def test_ablation_skips_a_stage_that_was_not_supplied():
    fns = {VALIDATOR: stops([0]), DISCRIMINATOR: None, EIDS: stops([2])}
    subsets = [s for s, _ in ablate(fns, X)]
    assert subsets == [(VALIDATOR,), (EIDS,), (VALIDATOR, EIDS)]


def test_a_redundant_gate_shows_zero_marginal_contribution():
    """Two gates stopping the same rows both look essential alone. The removal
    difference is what exposes the duplication -- this is the phase 4/5 overlap."""
    same = [0, 1, 2]
    fns = {VALIDATOR: stops(same), DISCRIMINATOR: stops(same), EIDS: stops([7])}
    results = {s: v.stop_rate for s, v in ablate(fns, X)}
    assert results[(VALIDATOR,)] == results[(DISCRIMINATOR,)] == pytest.approx(3 / N)
    marginal = marginal_contribution(results)
    assert marginal[VALIDATOR] == pytest.approx(0.0)
    assert marginal[DISCRIMINATOR] == pytest.approx(0.0)
    assert marginal[EIDS] == pytest.approx(1 / N)


def test_marginal_contribution_credits_a_gate_nothing_else_covers():
    fns = {VALIDATOR: stops([0]), DISCRIMINATOR: stops([1]), EIDS: stops([2])}
    results = {s: v.stop_rate for s, v in ablate(fns, X)}
    marginal = marginal_contribution(results)
    assert all(v == pytest.approx(1 / N) for v in marginal.values())
