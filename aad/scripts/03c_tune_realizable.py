"""M4 - tune the white-box attacks on the VALIDATION split before the test run.

    python scripts/03c_tune_realizable.py                  # 100 rows/category, spec A

A reported robustness number is only as good as the attack behind it. The first
val run (2026-10-09) showed the black box beating the gradient attack on theta,
the classic sign of an under-optimised attack. This sweep varies steps, step size
and random restarts for the two ensemble PGD attacks and records success per
setting, so the test-run settings are chosen on val, with the evidence kept.

Writes artifacts/reports/realizable_tuning_val_spec{A|B}.{csv,md}.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tensorflow import keras  # noqa: E402

import aad.models.base  # noqa: E402,F401
from aad.attacks.realizable.attacks import (  # noqa: E402
    Attacker, make_target, select_rows_per_category, window_population,
)
from aad.attacks.realizable.constraints import load_projector  # noqa: E402
from aad.attacks.realizable.primitives import Primitives  # noqa: E402
from aad.defense.validator import Validator  # noqa: E402
from aad.defense.validator_soft import SoftValidator  # noqa: E402
from aad.evaluate import load_class_names  # noqa: E402

log = logging.getLogger("03c")

# (attack, steps, step, restarts)
GRID = [
    ("feat", 100, 0.01, 0), ("feat", 300, 0.01, 0), ("feat", 100, 0.03, 0),
    ("feat", 100, 0.01, 3), ("feat", 300, 0.03, 3), ("feat", 100, 0.01, 10), ("feat", 100, 0.01, 30),
    ("prim", 100, 0.05, 0), ("prim", 300, 0.05, 0), ("prim", 100, 0.20, 0),
    ("prim", 100, 0.05, 3), ("prim", 300, 0.10, 3), ("prim", 100, 0.05, 10), ("prim", 100, 0.05, 30),
]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--models-dir", default="artifacts/models")
    ap.add_argument("--spec", default="A", choices=["A", "B", "C"])
    ap.add_argument("--n-per-category", type=int, default=100)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(message)s",
                        datefmt="%H:%M:%S")

    data_dir, models_dir = ROOT / args.data_dir, ROOT / args.models_dir
    val = np.load(data_dir / "val.npz")
    class_names, cat_names = load_class_names(data_dir)
    thr = json.loads((models_dir / "thresholds.json").read_text(encoding="utf-8"))
    targets = [make_target(n, keras.models.load_model(models_dir / f"{n}.keras", compile=False),
                           thr["models"][n]["threshold"]) for n in ("mlp", "cnn", "lstm")]
    P = load_projector(ROOT / "config/realism.yaml", data_dir / "transform.json", args.spec)
    rules = json.loads((ROOT / "artifacts/rules.json").read_text(encoding="utf-8"))
    atk = Attacker(P, Primitives(P), Validator(rules), SoftValidator(rules))

    eligible = val["y"] == 1
    for t in targets:
        eligible &= t.detects(val["X"])
    idx = select_rows_per_category(val["y_category"], eligible, args.n_per_category, args.seed)
    X0 = val["X"][idx].astype(np.float64)
    cats = np.array([cat_names[int(c)] for c in val["y_category"][idx]])
    pop = window_population(cats, [class_names[int(c)] for c in val["y_multiclass"][idx]])
    floor = P.spec.rate_floor(cats)
    log.info("%d val rows (%d per category); spec %s", len(idx), args.n_per_category, args.spec)

    rows = []
    for kind, steps, step, restarts in GRID:
        t0 = time.time()
        if kind == "feat":
            Xa, _ = atk.feat_pgd(targets, X0, floor, steps=steps, step_size=step,
                                 restarts=restarts, seed=args.seed)
        else:
            Xa, _, _ = atk.prim_pgd(targets, X0, floor, steps=steps, step_frac=step,
                                    restarts=restarts, seed=args.seed)
        secs = time.time() - t0
        P.assert_realizable(Xa.astype(np.float32), X0, floor)
        evade = ~np.any([t.detects(Xa) for t in targets], axis=0)
        win = evade & ~atk.validator.check(Xa.astype(np.float32)).reject
        rows.append({"attack": f"{kind}_pgd_ens", "steps": steps, "step": step,
                     "restarts": restarts, "evasion_%": 100 * evade.mean(),
                     "pass_and_evade_%": 100 * win.mean(),
                     "pass_and_evade_10pkt_%": 100 * win[pop == "10-pkt"].mean(),
                     "pass_and_evade_100pkt_%": 100 * win[pop == "100-pkt"].mean(),
                     "seconds": round(secs, 1)})
        log.info("%s", rows[-1])

    df = pd.DataFrame(rows)
    stem = ROOT / "artifacts/reports" / f"realizable_tuning_val_spec{args.spec}"
    df.to_csv(stem.with_suffix(".csv"), index=False)
    stem.with_suffix(".md").write_text(
        f"# White-box attack tuning on val (spec {args.spec})\n\n"
        f"{len(idx)} val rows ({args.n_per_category} per attack category), detected by all three "
        "baselines at their calibrated thresholds; ensemble target (OR rule). `step` is the L-inf step "
        "in scaled units (feat) or the fraction of each theta range (prim). Success judged by the "
        "deployed models and the real validator.\n\n"
        + df.to_markdown(index=False, floatfmt=".2f") + "\n", encoding="utf-8")
    log.info("wrote %s.{csv,md}", stem)


if __name__ == "__main__":
    main()
