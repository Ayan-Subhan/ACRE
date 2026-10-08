"""Metric computation shared by every phase.

One definition of accuracy/precision/recall/F1 for baselines, adversarial
evaluation, the discriminator and the EIDS, so numbers stay comparable across
the whole project.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
)

# Phase 1 writes the class vocabulary next to the .npz files, so every phase
# names classes the same way without a hardcoded table that goes stale when the
# dataset changes (the CSE-CIC-IDS2018 "Type1..Type5" table lived here before).
CLASSES_FILE = "classes.json"


def load_class_names(data_dir: Path) -> tuple[dict[int, str], dict[int, str]]:
    """``(class code -> name, category code -> name)`` from ``data_dir/classes.json``."""
    d = json.loads((Path(data_dir) / CLASSES_FILE).read_text(encoding="utf-8"))
    return (
        {int(k): v for k, v in d["classes"].items()},
        {int(k): v for k, v in d["categories"].items()},
    )


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray | None = None) -> dict:
    """Positive class = attack (1). Precision/recall/F1 are reported for that
    class, which is the convention in the IDS literature.

    ``balanced_accuracy`` (mean of benign and attack recall) travels with plain
    accuracy because the class mix is far from 50/50: on the raw CICIoT2023 data
    a model that always says "attack" scores 97.65% accuracy and 50% balanced.
    """
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        # An OR-ensemble buys recall with false positives, so FPR travels with
        # every accuracy figure in this project.
        "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "fnr": float(fn / (fn + tp)) if (fn + tp) else 0.0,
        "support_benign": int(tn + fp),
        "support_attack": int(fn + tp),
    }
    if y_prob is not None:
        out["loss"] = float(log_loss(y_true, y_prob, labels=[0, 1]))
    return out


def _recall_by_group(
    y_group: np.ndarray, y_pred: np.ndarray, names: dict[int, str], benign_code: int = 0
) -> dict:
    """Binary detection rate within each group. For the benign group "correct"
    means predicted benign; for every attack group it means predicted attack."""
    out = {}
    for code in np.unique(y_group):
        code = int(code)
        mask = y_group == code
        want = 0 if code == benign_code else 1
        out[names.get(code, str(code))] = {
            "support": int(mask.sum()),
            "correct_rate": float((y_pred[mask] == want).mean()),
        }
    return out


def per_type_recall(y_true_multi: np.ndarray, y_pred: np.ndarray, names: dict[int, str]) -> dict:
    """Detection rate per fine-grained class (34 on CICIoT2023). A binary score
    hides rare classes completely: missing every Web attack costs well under 1%
    of accuracy."""
    return _recall_by_group(y_true_multi, y_pred, names)


def per_category_recall(y_category: np.ndarray, y_pred: np.ndarray, names: dict[int, str]) -> dict:
    """Detection rate per attack category (8 on CICIoT2023: Benign, DDoS, ...)."""
    return _recall_by_group(y_category, y_pred, names)


def attack_success_rate(y_pred_on_adversarial: np.ndarray) -> float:
    """Fraction of adversarial attack-samples that evaded detection.

    Every adversarial example in this project is built from a true-attack row,
    so a prediction of 0 (benign) means the attack succeeded. Phase 3 onwards.
    """
    if len(y_pred_on_adversarial) == 0:
        return 0.0
    return float((y_pred_on_adversarial == 0).mean())


def format_row(name: str, m: dict) -> str:
    return (
        f"{name:<10s} {m['accuracy']*100:>8.4f} {m['precision']*100:>10.4f} "
        f"{m['recall']*100:>8.4f} {m['f1']*100:>8.4f} {m.get('loss', float('nan')):>9.5f} "
        f"{m['fpr']*100:>8.4f}"
    )


HEADER = (
    f"{'model':<10s} {'accuracy':>8s} {'precision':>10s} {'recall':>8s} "
    f"{'f1':>8s} {'loss':>9s} {'FPR%':>8s}"
)
