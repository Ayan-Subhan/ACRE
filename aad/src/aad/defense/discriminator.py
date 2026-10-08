"""Gate 2: tell a perturbed flow from a real one.

The validator asks "could this flow exist?". The discriminator asks a softer
question -- "does this flow look manufactured?" -- and answers it with a learned
model rather than arithmetic. It is the paper's second defense component, a
Random Forest over the same 68 features, trained on clean-vs-adversarial.

Everything in this module exists to stop the forest scoring 100% for the wrong
reason. Three shortcuts are available to it and all three are closed here:

* **The paired twin.** Every adversarial row was built from a specific clean
  row, and the two differ by a perturbation of L2 ~0.03-0.7. Split them randomly
  and the twin of every test row is in the training set: the forest memorises
  source flows, not perturbations. ``build_dataset`` therefore assigns both
  members of a pair -- and all twelve perturbations of one source -- the same
  ``group``, and every split is grouped.

* **Maliciousness.** Every positive is a perturbed *attack* flow. If the
  negatives were benign traffic only, "is this malicious" would separate the
  classes perfectly without the perturbation contributing anything. The 5,000
  exact clean twins are always negatives, which makes that shortcut unavailable.

* **Attack family.** FGSM, BIM and PGD are all signed-gradient methods and leave
  near-identical traces. Testing on the same families you trained on measures
  memorisation. ``split_leave_one_out`` holds a whole family (or a whole target
  model) out of training.

Positive class = adversarial (1), so ``recall`` reads as catch rate and ``fpr``
as the fraction of legitimate traffic wrongly quarantined -- the same convention
``evaluate.binary_metrics`` uses elsewhere, and the same two numbers phase 4
reports separately.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit

log = logging.getLogger(__name__)

# Row provenance, carried alongside X so any protocol can slice on it.
ORIGIN_ADV = "adversarial"
ORIGIN_TWIN = "clean_twin"     # the exact unperturbed source of a positive
ORIGIN_POOL = "clean_pool"     # further real traffic, never perturbed

NONE = "-"  # attack/model tag for a clean row


@dataclass(frozen=True)
class Cell:
    """One (attack, model) artefact from phase 3."""

    attack: str
    model: str
    X_adv: np.ndarray
    X_clean: np.ndarray
    idx: np.ndarray
    meta: dict


@dataclass
class Dataset:
    X: np.ndarray
    y: np.ndarray            # 1 = adversarial
    group: np.ndarray        # source-row id; pairs and siblings share one
    attack: np.ndarray       # per row, NONE for clean
    model: np.ndarray        # per row, NONE for clean
    origin: np.ndarray

    def __len__(self) -> int:
        return len(self.y)

    def subset(self, mask: np.ndarray) -> "Dataset":
        return Dataset(
            self.X[mask], self.y[mask], self.group[mask],
            self.attack[mask], self.model[mask], self.origin[mask],
        )

    @property
    def attacks(self) -> list[str]:
        return sorted(set(self.attack[self.y == 1].tolist()))

    @property
    def models(self) -> list[str]:
        return sorted(set(self.model[self.y == 1].tolist()))


def load_cells(adv_dir: Path, tag: str = "") -> list[Cell]:
    """Read every phase-3 artefact, and verify they describe the same rows.

    The cells are only comparable -- and the pairing below only correct -- if
    all twelve perturbed the identical source rows. Phase 3 guarantees it by
    construction; this re-checks it, because a mismatch would silently produce
    groups that do not group anything.
    """
    suffix = f"{tag}.npz" if tag else ".npz"
    paths = sorted(p for p in adv_dir.glob(f"*{suffix}") if p.stat().st_size)
    if not paths:
        raise FileNotFoundError(
            f"no adversarial artefacts in {adv_dir}. Run scripts/03_generate_ae.py first."
        )

    cells: list[Cell] = []
    reference: np.ndarray | None = None
    for path in paths:
        d = np.load(path, allow_pickle=False)
        meta = json.loads(str(d["meta"]))
        idx = d["idx"]
        if reference is None:
            reference = idx
        elif not np.array_equal(idx, reference):
            raise ValueError(
                f"{path.name} was built from different source rows than {paths[0].name}. "
                "Regenerate phase 3 in one run so every cell shares one sample."
            )
        cells.append(Cell(meta["attack"], meta["model"], d["X_adv"], d["X_clean"], idx, meta))

    log.info("loaded %d cells: %s", len(cells), ", ".join(f"{c.attack}x{c.model}" for c in cells))
    return cells


def build_dataset(
    cells: list[Cell],
    X_pool: np.ndarray,
    y_pool: np.ndarray,
    extra_negatives: int | str = "auto",
    stratify_extra: bool = True,
    seed: int = 42,
) -> Dataset:
    """Assemble the clean-vs-adversarial training set.

    Positives: every row of every cell. Negatives: the clean twins once (not
    twelve times -- they are byte-identical across cells and duplicating them
    would let the forest weight one source flow twelvefold), plus ``extra``
    further rows drawn from ``X_pool`` outside the source indices.

    ``group`` is the source row's index in the split, so a source flow and all
    thirteen rows derived from it never straddle a fold boundary. Pool negatives
    carry their own row index, which is disjoint from the source indices by
    construction, so every group id stays unique.
    """
    source_idx = cells[0].idx
    n_src = len(source_idx)

    X_parts = [c.X_adv for c in cells]
    groups = [source_idx for _ in cells]
    attacks = [np.full(len(c.X_adv), c.attack) for c in cells]
    models = [np.full(len(c.X_adv), c.model) for c in cells]
    origins = [np.full(len(c.X_adv), ORIGIN_ADV) for c in cells]
    n_pos = sum(len(p) for p in X_parts)

    # The twins, once.
    X_parts.append(cells[0].X_clean)
    groups.append(source_idx)
    attacks.append(np.full(n_src, NONE))
    models.append(np.full(n_src, NONE))
    origins.append(np.full(n_src, ORIGIN_TWIN))

    n_extra = max(0, n_pos - n_src) if extra_negatives == "auto" else int(extra_negatives)
    n_pool = 0
    if n_extra:
        available = np.setdiff1d(np.arange(len(X_pool), dtype=np.int64), source_idx)
        rng = np.random.default_rng(seed)
        if stratify_extra:
            # Keep the split's own benign/attack mix so the false-positive rate
            # below is measured against realistic traffic, not attack rows only.
            picks = []
            for label in (0, 1):
                bucket = available[y_pool[available] == label]
                share = int(round(n_extra * len(bucket) / len(available)))
                picks.append(rng.choice(bucket, size=min(share, len(bucket)), replace=False))
            extra_idx = np.concatenate(picks)
        else:
            extra_idx = rng.choice(available, size=min(n_extra, len(available)), replace=False)
        extra_idx = np.sort(extra_idx)
        n_pool = len(extra_idx)
        if n_pool < n_extra:
            # Not an error -- the run is still valid -- but the class balance the
            # caller asked for is not what it gets, and a forest trained on a
            # 5:1 split reports a different FPR than one trained on 1:1.
            log.warning(
                "pool supplied %d of the %d requested clean rows; classes will be "
                "unbalanced at %.1f:1 adversarial:clean",
                n_pool, n_extra, n_pos / max(1, n_src + n_pool),
            )

        X_parts.append(X_pool[extra_idx])
        groups.append(extra_idx)
        attacks.append(np.full(n_pool, NONE))
        models.append(np.full(n_pool, NONE))
        origins.append(np.full(n_pool, ORIGIN_POOL))
        benign_share = 100 * float((y_pool[extra_idx] == 0).mean())
    else:
        benign_share = 0.0

    X = np.concatenate(X_parts).astype(np.float32)
    y = np.concatenate([np.ones(n_pos, np.int8), np.zeros(len(X) - n_pos, np.int8)])
    ds = Dataset(
        X, y,
        np.concatenate(groups).astype(np.int64),
        np.concatenate(attacks), np.concatenate(models), np.concatenate(origins),
    )

    log.info(
        "dataset %d rows: %d adversarial, %d clean (%d twins + %d pool, %.1f%% benign)",
        len(ds), int(y.sum()), int((y == 0).sum()), n_src, n_pool, benign_share,
    )
    return ds


def split_random(ds: Dataset, test_size: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Grouped hold-out. Every row derived from one source flow lands together."""
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train, test = next(splitter.split(ds.X, ds.y, groups=ds.group))
    return train, test


def split_leave_one_out(
    ds: Dataset, field: str, held: str, test_size: float, seed: int
) -> tuple[np.ndarray, np.ndarray]:
    """Grouped hold-out *and* a family withheld from training.

    The grouped split runs first so clean rows are divided normally -- they have
    to appear on both sides or there is no false-positive rate to report. Then
    positives are filtered: training keeps every family except ``held``, testing
    keeps only ``held``. A row can therefore be dropped entirely, which is the
    intended behaviour and why the fold sizes in the report are uneven.
    """
    values = getattr(ds, field)
    if held not in set(values[ds.y == 1].tolist()):
        raise ValueError(f"{held!r} is not one of the {field}s in this dataset")

    train_g, test_g = split_random(ds, test_size, seed)
    in_train, in_test = np.zeros(len(ds), bool), np.zeros(len(ds), bool)
    in_train[train_g] = True
    in_test[test_g] = True

    clean = ds.y == 0
    return (
        np.flatnonzero(in_train & (clean | (values != held))),
        np.flatnonzero(in_test & (clean | (values == held))),
    )


def build_forest(cfg: dict, seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=int(cfg["n_estimators"]),
        criterion=str(cfg["criterion"]),
        max_depth=cfg["max_depth"],
        min_samples_leaf=int(cfg["min_samples_leaf"]),
        max_features=cfg["max_features"],
        class_weight=cfg["class_weight"],
        n_jobs=int(cfg["n_jobs"]),
        random_state=seed,
    )


def per_group_rate(ds: Dataset, mask: np.ndarray, y_pred: np.ndarray, field: str) -> dict:
    """Catch rate broken out by attack family or target model.

    An aggregate hides the case the whole phase turns on: a forest that catches
    every gradient attack and nothing DeepFool produces still reports a high
    combined number, because DeepFool is a quarter of the positives.
    """
    values = getattr(ds, field)[mask]
    y_true = ds.y[mask]
    out = {}
    for value in sorted(set(values[y_true == 1].tolist())):
        sel = (values == value) & (y_true == 1)
        out[value] = {"support": int(sel.sum()), "catch_rate": float((y_pred[sel] == 1).mean())}
    return out


def fit_and_score(
    ds: Dataset, train: np.ndarray, test: np.ndarray, cfg: dict, seed: int
) -> tuple[RandomForestClassifier, dict, np.ndarray]:
    """Train one forest on one fold and return it with its metrics."""
    from ..evaluate import binary_metrics  # local: keeps this module import-light

    clf = build_forest(cfg, seed)
    t0 = time.time()
    clf.fit(ds.X[train], ds.y[train])
    fit_seconds = round(time.time() - t0, 1)

    prob = clf.predict_proba(ds.X[test])
    y_pred = prob.argmax(axis=1).astype(np.int8)

    m = binary_metrics(ds.y[test], y_pred, y_prob=prob)
    m["fit_seconds"] = fit_seconds
    m["n_train"] = int(len(train))
    m["n_test"] = int(len(test))
    m["n_train_adversarial"] = int(ds.y[train].sum())
    m["per_attack"] = per_group_rate(ds, test, y_pred, "attack")
    m["per_model"] = per_group_rate(ds, test, y_pred, "model")
    return clf, m, y_pred


def top_importances(
    clf: RandomForestClassifier, feature_names: list[str], k: int = 15
) -> list[dict]:
    """The k features the Gini criterion leant on hardest.

    Read this against ``rules.json``'s integrality columns. If the forest's top
    features are the same count-like columns the validator checks for
    whole-numberedness, then gate 2 has independently rediscovered gate 1 and
    the two are one defense wearing two hats -- which matters, because a single
    adaptive adversary then defeats both at once.
    """
    order = np.argsort(clf.feature_importances_)[::-1][:k]
    return [
        {"feature": feature_names[i], "index": int(i),
         "gini_importance": float(clf.feature_importances_[i])}
        for i in order
    ]
