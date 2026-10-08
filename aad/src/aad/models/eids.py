"""Phase 6 - the EIDS: hardened models behind a logical OR.

Phases 4 and 5 are gates *in front of* an unchanged NIDS. If an adversarial row
gets past them the MLP still reads it as benign, exactly as in Table IV. This is
the only phase that changes the models themselves, and it does so two ways:

* **Adversarial training.** Retrain each architecture on the clean training set
  plus adversarial examples carrying their *true* label (attack). The model stops
  treating the perturbed neighbourhood of an attack flow as benign territory.

* **The OR ensemble.** The verdict is ``MLP or CNN or LSTM``. One model flagging
  attack is enough. That covers per-model blind spots -- the phase-2 LSTM detects
  0% of the three web-attack classes and the MLP detects most of them -- and it
  forces an evader to fool three models at once instead of one.

Two disciplines are wired in rather than left to the caller, because both are
easy to get wrong in a direction that flatters the result:

1. **The training examples come from the training split.** ``adv_dir`` defaults
   to ``artifacts/adversarial_train``, which ``03_generate_ae.py --split train``
   writes. Training on examples built from test rows and then reporting
   robustness on those rows is training on the test set.

2. **A whole attack family is withheld.** Static adversarial training teaches a
   model *the perturbations it was shown*; testing on those same families
   measures memorisation. ``holdout_attacks`` keeps DeepFool out of training so
   there is always one honest number in the report.

Neither buys real robustness on its own. Madry et al. show that needs adversarial
examples generated *inside* the training loop against the current weights; a
fixed pool is the weaker, cheaper version. The adaptive evaluation in
``06_train_eids.py`` -- re-attacking the hardened models rather than replaying
old examples -- is what keeps that limitation visible.
"""

from __future__ import annotations

import logging

import numpy as np

log = logging.getLogger(__name__)

ATTACK_LABEL = 1  # an adversarial example is still an attack flow


def select_pool(
    cells: list,
    model_name: str,
    holdout_attacks: tuple[str, ...] = (),
    sources: str = "all",
) -> list:
    """Choose which phase-3 cells feed one model's adversarial training.

    ``sources="own"`` restricts a model to examples crafted against itself, which
    is the conservative reading of adversarial training. ``"all"`` pools every
    model's examples: more data, and it exposes each model to the perturbation
    fingerprints of the other two, which is what makes the ensemble's members
    fail differently rather than together.
    """
    if sources not in ("all", "own"):
        raise ValueError(f"sources must be 'all' or 'own', got {sources!r}")
    held = {a.lower() for a in holdout_attacks}
    return [
        c for c in cells
        if c.attack.lower() not in held and (sources == "all" or c.model == model_name)
    ]


def build_augmented(
    X_train: np.ndarray,
    y_train: np.ndarray,
    pool: list,
    fraction: float = 1.0,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray, dict]:
    """Clean training rows plus adversarial rows labelled as attacks.

    ``fraction`` subsamples the pool. It exists because the augmentation ratio is
    a real knob: too little and nothing changes, too much and the model spends
    its capacity on perturbed traffic it will rarely see, which costs clean
    accuracy. The ratio actually used is returned so the report can state it.
    """
    if not pool:
        raise ValueError(
            "no adversarial examples left after the hold-out. Check "
            "holdout_attacks against the cells in adv_dir."
        )

    rng = np.random.default_rng(seed)
    parts, provenance = [], []
    for cell in pool:
        X = cell.X_adv
        if fraction < 1.0:
            take = max(1, int(round(len(X) * fraction)))
            X = X[np.sort(rng.choice(len(X), take, replace=False))]
        parts.append(X)
        provenance.append({"attack": cell.attack, "model": cell.model, "n": len(X)})

    X_adv = np.concatenate(parts).astype(np.float32)
    X = np.concatenate([X_train, X_adv])
    y = np.concatenate([y_train, np.full(len(X_adv), ATTACK_LABEL, dtype=y_train.dtype)])

    meta = {
        "n_clean": int(len(X_train)),
        "n_adversarial": int(len(X_adv)),
        "augmentation_ratio": round(len(X_adv) / len(X_train), 4),
        "fraction_of_pool": fraction,
        "cells": provenance,
    }
    log.info(
        "augmented training set: %d clean + %d adversarial (+%.1f%%) from %d cells",
        len(X_train), len(X_adv), 100 * meta["augmentation_ratio"], len(pool),
    )
    return X, y, meta


def or_ensemble(member_preds: dict[str, np.ndarray]) -> np.ndarray:
    """The EIDS decision: any member flagging attack wins.

    OR only ever adds detections, so recall cannot fall below the best member's
    and the false-positive rate cannot fall below the worst member's. Both halves
    of that trade are reported; a recall gain bought with an unusable alarm rate
    is not an improvement.
    """
    preds = list(member_preds.values())
    if not preds:
        raise ValueError("an ensemble needs at least one member")
    return np.max(np.stack(preds), axis=0).astype(np.int8)


def or_ensemble_prob(member_probs: dict[str, np.ndarray]) -> np.ndarray:
    """A 2-column probability vector consistent with the OR rule.

    OR has no probabilistic definition, so the attack probability is taken as the
    strongest member's -- the same member whose vote decides the hard label. This
    exists only so the ensemble's cross-entropy is comparable with its members';
    do not read it as a calibrated confidence.
    """
    p_attack = np.max(np.stack([p[:, 1] for p in member_probs.values()]), axis=0)
    return np.column_stack([1.0 - p_attack, p_attack]).astype(np.float32)


def disagreement(member_preds: dict[str, np.ndarray], y_true: np.ndarray | None = None) -> dict:
    """How often the members disagree, and what each one contributes.

    An OR ensemble whose members always agree is three copies of one model and
    buys nothing but cost. The rows where exactly one member flags attack are
    where a member earns its place -- or where it drags the ensemble down.

    Those two cases have to be counted apart. Under OR, a row only one member
    flags is added to the ensemble's output whatever the truth is: if the row is
    an attack the member carried the ensemble, and if it is benign the member
    handed it a false positive nobody else would have raised. A single
    "unique flags" count reads as contribution while silently including the
    opposite, so ``y_true`` splits it into ``unique_catches`` and
    ``unique_false_alarms``. Pass it whenever labels are available.
    """
    names = list(member_preds)
    stack = np.stack([member_preds[n] for n in names])
    flagged = stack.sum(axis=0)
    out = {
        "n_rows": int(stack.shape[1]),
        "unanimous_%": float((flagged == 0).mean() + (flagged == len(names)).mean()),
        "unique_flags": {},
    }
    if y_true is not None:
        out["unique_catches"], out["unique_false_alarms"] = {}, {}

    for i, name in enumerate(names):
        only_this = (stack[i] == 1) & (flagged == 1)
        out["unique_flags"][name] = int(only_this.sum())
        if y_true is not None:
            out["unique_catches"][name] = int((only_this & (y_true == 1)).sum())
            out["unique_false_alarms"][name] = int((only_this & (y_true == 0)).sum())
    return out
