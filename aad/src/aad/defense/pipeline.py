"""Phase 7 - the AAD pipeline: validator, then discriminator, then EIDS.

Three defences built and measured separately in phases 4, 5 and 6, wired into the
order the paper specifies:

    flow -> [validator] --reject--> blocked
              | passes
            [discriminator] --adversarial--> quarantined
              | passes
            [EIDS] --attack--> alerted
              | benign
            allowed

Each stage is cheaper than the next -- the validator is pure numpy arithmetic, the
discriminator is one forest, the EIDS is three neural networks -- so the ordering
is also the sensible cost ordering, and most traffic is decided before anything
expensive runs.

What this module adds over calling the three in sequence:

* **Attribution.** ``decide`` returns which stage produced each verdict, not just
  the verdict. Without that a combined catch rate cannot be apportioned, and the
  ablation below has nothing to compare against.

* **First-stop semantics.** A row rejected by the validator never reaches the
  discriminator, so per-stage counts are *what each stage actually saw and
  stopped*, not what it would have stopped in isolation. Those differ sharply
  here, and reporting the second while implying the first inflates every later
  stage.

* **Ablation over subsets.** Phases 4 and 5 arrived at the same conclusion from
  different directions -- 9 of the discriminator's top 15 features are the
  validator's integrality columns -- which predicts the two gates are largely
  redundant. ``ablate`` measures it instead of assuming it. If validator-only
  matches validator+discriminator, the framework has two gates doing one job and
  their catch rates must not be described as multiplying.

The false-positive rate is the honest cost, and it *stacks*: a benign flow is
dropped if any stage stops it, so the pipeline's FPR is at least the largest
member's and roughly the sum of the three. It is carried beside every catch rate
here for the same reason phase 4 refuses to blend them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from itertools import combinations

import numpy as np

log = logging.getLogger(__name__)

# Stage names, in pipeline order. Also the ablation vocabulary.
VALIDATOR = "validator"
DISCRIMINATOR = "discriminator"
EIDS = "eids"
STAGES = (VALIDATOR, DISCRIMINATOR, EIDS)

# Verdict for a row nothing stopped.
ALLOWED = "allowed"


@dataclass
class Verdict:
    """Per-row outcome of one pass through the pipeline.

    ``stopped`` is the pipeline's binary answer -- 1 means the flow was blocked,
    quarantined or alerted on, whatever the reason. ``stage`` says which of the
    three did it, or ``ALLOWED``. Keeping both is what makes attribution possible
    without re-running anything.
    """

    stopped: np.ndarray          # int8, 1 = stopped somewhere
    stage: np.ndarray            # object array of stage names / ALLOWED

    def __len__(self) -> int:
        return len(self.stopped)

    @property
    def stop_rate(self) -> float:
        return float(self.stopped.mean()) if len(self.stopped) else 0.0

    def stage_counts(self) -> dict[str, int]:
        """How many rows each stage stopped, counting only rows that reached it."""
        return {s: int((self.stage == s).sum()) for s in (*STAGES, ALLOWED)}


class Pipeline:
    """Validator -> discriminator -> EIDS, with any subset enabled.

    The three callables are injected rather than constructed here so the same
    class serves the real run and the tests, and so ``ablate`` can rebuild a
    pipeline over a subset without reloading a forest or three Keras models.

    Each predictor takes ``X`` (scaled, shape ``(n, n_features)``) and returns a
    boolean array: True means *this stage stops the row*.
    """

    def __init__(self, validator_fn=None, discriminator_fn=None, eids_fn=None,
                 stages: tuple[str, ...] = STAGES):
        self._fns = {VALIDATOR: validator_fn, DISCRIMINATOR: discriminator_fn, EIDS: eids_fn}
        unknown = set(stages) - set(STAGES)
        if unknown:
            raise ValueError(f"unknown stage(s) {sorted(unknown)}; expected {STAGES}")
        missing = [s for s in stages if self._fns[s] is None]
        if missing:
            raise ValueError(f"stage(s) {missing} enabled but no predictor was supplied")
        # Preserve pipeline order regardless of the order the caller listed them:
        # attribution is only meaningful if cheap gates really do run first.
        self.stages = tuple(s for s in STAGES if s in stages)

    def decide(self, X: np.ndarray) -> Verdict:
        """Run the enabled stages in order, short-circuiting on the first stop."""
        n = len(X)
        stopped = np.zeros(n, dtype=np.int8)
        stage = np.full(n, ALLOWED, dtype=object)
        remaining = np.arange(n)

        for name in self.stages:
            if len(remaining) == 0:
                break
            hit = np.asarray(self._fns[name](X[remaining]), dtype=bool)
            if hit.shape != remaining.shape:
                raise ValueError(
                    f"{name} returned {hit.shape} for {remaining.shape} rows; a stage "
                    "must return one boolean per row it was given"
                )
            caught = remaining[hit]
            stopped[caught] = 1
            stage[caught] = name
            remaining = remaining[~hit]

        return Verdict(stopped, stage)


def ablate(
    fns: dict, X: np.ndarray, min_size: int = 1
) -> list[tuple[tuple[str, ...], Verdict]]:
    """Every non-empty subset of the available stages, each run over ``X``.

    Returned in pipeline order within a subset and by increasing subset size, so
    a reader can walk from "one gate alone" to "all three" and see what each
    addition bought. A subset whose stop rate equals a smaller subset's has added
    a stage that stops nothing the others did not already stop.
    """
    available = [s for s in STAGES if fns.get(s) is not None]
    out = []
    for size in range(min_size, len(available) + 1):
        for subset in combinations(available, size):
            out.append((subset, Pipeline(**{f"{s}_fn": fns[s] for s in available},
                                         stages=subset).decide(X)))
    return out


def marginal_contribution(results: dict[tuple[str, ...], float]) -> dict[str, float]:
    """What each stage adds to the full pipeline, by removing it.

    Reported rather than the stage's standalone rate, because standalone rates
    over-credit a redundant gate: two gates that each stop 100% of something both
    look essential alone and neither is. The drop from removing a stage is the
    only number that answers "would we notice if this were switched off".
    """
    full = tuple(s for s in STAGES if s in max(results, key=len))
    if full not in results:
        return {}
    out = {}
    for stage in full:
        without = tuple(s for s in full if s != stage)
        if without in results:
            out[stage] = round(results[full] - results[without], 6)
    return out
