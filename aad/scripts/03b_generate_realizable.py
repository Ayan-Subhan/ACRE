"""M4 - realizable, defense-aware attacks (docs/m4-plan.md).

    python scripts/03b_generate_realizable.py --smoke                       # wiring check, minutes
    python scripts/03b_generate_realizable.py --split val --n-per-category 200   # tuning run
    python scripts/03b_generate_realizable.py --split test                  # the reported run
    python scripts/03b_generate_realizable.py --split test --spec B         # permissive flow-age spec
    python scripts/03b_generate_realizable.py --attacks art_projected       # Table IV-c only

Source rows: ``--n-per-category`` rows from every attack category, drawn (seed
42) from rows that ALL three baselines detect at their calibrated thresholds
(``artifacts/models/thresholds.json``, from 02c). Every cell perturbs the same
rows, so M5 can pair them (``discriminator.load_cells`` checks it).

Cells (``--attacks``), each saved as ``{attack}_{model}.npz``:

    feat_pgd, prim_pgd          one per model in --models          white box
    feat_pgd_ens, prim_pgd_ens  all --models at once (OR rule)     white box
    adaptive_prim, adaptive_feat  ensemble + real validator        white box, defense-aware
    greybox                     adaptive_prim on surrogate models   grey box
    blackbox                    allow/stop answers only            black box
    art_projected               the 12 phase-3 ART sets through P  (report only, own rows)

Success is always judged by the deployed models at their thresholds and by the
real validator; the run stops if any saved row is not realizable or breaks its
functional floor.

Writes (``<tag>`` = ``{split}_spec{A|B}``):
    artifacts/adversarial_real/<tag>/{attack}_{model}.npz
    artifacts/reports/table4b_realizable_<tag>.{csv,md}
    artifacts/reports/realizable_metrics_<tag>.json
    artifacts/reports/table4c_projection_spec{A|B}.{csv,md}     (art_projected)
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

import aad.models.base  # noqa: E402,F401  (portable .keras loading)
from aad.attacks.realizable.attacks import (  # noqa: E402
    Attacker, make_target, select_rows_per_category, window_population,
)
from aad.attacks.realizable.constraints import load_projector  # noqa: E402
from aad.attacks.realizable.primitives import Primitives  # noqa: E402
from aad.defense.validator import Validator  # noqa: E402
from aad.defense.validator_soft import SoftValidator  # noqa: E402
from aad.evaluate import bootstrap_ci, load_class_names, threshold_for_fpr  # noqa: E402

log = logging.getLogger("03b")

ALL_ATTACKS = ("feat_pgd", "prim_pgd", "feat_pgd_ens", "prim_pgd_ens",
               "adaptive_prim", "adaptive_feat", "greybox", "blackbox", "art_projected")
STRATEGY = {"feat_pgd": "feature", "prim_pgd": "primitive", "feat_pgd_ens": "feature",
            "prim_pgd_ens": "primitive", "adaptive_prim": "adaptive", "adaptive_feat": "adaptive",
            "greybox": "transfer", "blackbox": "query"}
TIER = {"greybox": "grey", "blackbox": "black"}
SURROGATES = ("mlp", "cnn")


# --------------------------------------------------------------------------- #
# setup
# --------------------------------------------------------------------------- #

def load_targets(models_dir: Path, names, thresholds: dict, tag: str = ""):
    out = []
    for n in names:
        model = keras.models.load_model(models_dir / f"{n}{tag}.keras", compile=False)
        out.append(make_target(f"{n}{tag}", model, thresholds[f"{n}{tag}"]))
    return out


def surrogate_thresholds(models_dir: Path, val: dict, fpr: float) -> dict:
    """The grey-box attacker calibrates its own surrogates the same way (2% on val)."""
    out = {}
    for n in SURROGATES:
        path = models_dir / f"{n}_surr.keras"
        if not path.exists():
            raise SystemExit(f"greybox needs {path}: run 02_train_baselines.py --models mlp cnn "
                             "--train-frac 0.5 --seed 7 --tag surr")
        m = keras.models.load_model(path, compile=False)
        p = m.predict(val["X"][val["y"] == 0], batch_size=8192, verbose=0)[:, 1]
        out[f"{n}_surr"] = threshold_for_fpr(p, fpr)
    return out


# --------------------------------------------------------------------------- #
# evaluating and saving one cell
# --------------------------------------------------------------------------- #

def evaluate_cell(name, model_tag, X0, Xa, ctx, extra) -> dict:
    """Deployed verdicts, cost and run-time checks for one cell. Returns arrays."""
    P, g, floor = ctx["P"], ctx["g"], ctx["floor"]
    Xa32 = np.asarray(Xa, dtype=np.float32)
    P.assert_realizable(Xa32, X0, floor, what=f"{name}_{model_tag}")
    floor_ok = g.floor_ok(X0, Xa32, floor)
    if not floor_ok.all():
        raise AssertionError(f"{name}_{model_tag}: {int((~floor_ok).sum())} rows break their "
                             "functional floor")

    det = {t.name: t.detects(Xa32) for t in ctx["targets"]}
    p_att = {t.name: t.p_attack(Xa32) for t in ctx["targets"]}
    # The deployed models the cell is judged on (grey-box: the real ones, not the
    # surrogates it was crafted on).
    det_target = np.any([det[n] for n in extra.pop("target_names")], axis=0)
    vres = ctx["validator"].check(Xa32)
    delta = Xa32.astype(np.float64) - X0
    p_max = np.max([p_att[n] for n in p_att], axis=0)
    out = {
        "X_adv": Xa32,
        "pred_adv": det_target.astype(np.int8),
        "prob_adv": np.stack([1 - p_max, p_max], axis=1).astype(np.float32),
        "linf": np.abs(delta).max(axis=1).astype(np.float32),
        "l2": np.linalg.norm(delta, axis=1).astype(np.float32),
        "n_changed": (delta != 0).sum(axis=1).astype(np.int32),
        "passes_validator": ~vres.reject,
        "floor_ok": floor_ok,
        "evades_target": ~det_target,
        "evades_ens": ~np.any(list(det.values()), axis=0),
        **{f"detected_{n}": d for n, d in det.items()},
        **{f"rejected_{f}": v for f, v in vres.by_family.items()},
        **{f"cost_{k}": v.astype(np.float32) for k, v in g.cost(X0, Xa32).items()},
    }
    out.update(extra)
    return out


def save_cell(out_dir: Path, name: str, model_tag: str, arrays: dict, ctx: dict, meta: dict):
    np.savez_compressed(
        out_dir / f"{name}_{model_tag}.npz",
        X_clean=ctx["X0"].astype(np.float32), idx=ctx["idx"], y_true=ctx["y"][ctx["idx"]],
        y_multiclass=ctx["ymc"], y_category=ctx["ycat"], pred_clean=np.ones(len(ctx["idx"]), np.int8),
        meta=json.dumps(meta), **arrays,
    )


def summarise_cell(name, model_tag, arrays, ctx) -> list[dict]:
    """One row per (category) and per (population), plus 'ALL'."""
    rows = []
    groups = [("ALL", np.ones(len(ctx["idx"]), bool))]
    groups += [(f"pop:{p}", ctx["pop"] == p) for p in ("10-pkt", "100-pkt")]
    groups += [(c, ctx["cat_names_rows"] == c) for c in ctx["categories"]]
    win = arrays["evades_target"] & arrays["passes_validator"]
    for gname, m in groups:
        if not m.any():
            continue
        ev, ev_lo, ev_hi = bootstrap_ci(arrays["evades_target"][m])
        pe, pe_lo, pe_hi = bootstrap_ci(win[m])
        s = m & win
        med = lambda k: float(np.median(arrays[k][s])) if s.any() else float("nan")  # noqa: E731
        rows.append({
            "attack": name, "model": model_tag, "group": gname, "n": int(m.sum()),
            "evasion_%": 100 * ev, "evasion_lo": 100 * ev_lo, "evasion_hi": 100 * ev_hi,
            "passes_validator_%": 100 * float(arrays["passes_validator"][m].mean()),
            "pass_and_evade_%": 100 * pe, "pass_and_evade_lo": 100 * pe_lo,
            "pass_and_evade_hi": 100 * pe_hi,
            "evades_all3_%": 100 * float(arrays["evades_ens"][m].mean()),
            "med_byte_overhead_%": med("cost_byte_overhead_pct"),
            "med_rate_loss_%": med("cost_rate_loss_pct"),
            "med_ttl_change": med("cost_ttl_change"),
            "med_features_changed": med("n_changed"),
        })
    return rows


# --------------------------------------------------------------------------- #
# art_projected (Table IV-c): the phase-3 sets through P
# --------------------------------------------------------------------------- #

def run_art_projected(args, ctx_base, reports_dir):
    adv_dir = ROOT / "artifacts" / "adversarial"
    P, g, val_ = ctx_base["P"], ctx_base["g"], ctx_base["validator"]
    test = np.load(ROOT / args.data_dir / "test.npz")
    targets = {t.name: t for t in ctx_base["targets"]}
    spec = ctx_base["spec_obj"]
    rows = []
    for path in sorted(adv_dir.glob("*.npz")):
        d = np.load(path, allow_pickle=False)
        meta = json.loads(str(d["meta"]))
        atk, model = meta["attack"], meta["model"]
        if model not in targets:
            continue
        idx = d["idx"]
        X0 = d["X_clean"].astype(np.float64)
        Xa = d["X_adv"].astype(np.float64)
        floor = spec.rate_floor([ctx_base["cat_name"][int(c)] for c in test["y_category"][idx]])
        t = targets[model]
        det0 = t.detects(X0)
        viol = P.violation(Xa, X0, floor) > 1e-5
        Xp = P.project_np(Xa, X0, floor)
        ev_before = ~t.detects(Xa)
        ev_after = ~t.detects(Xp)
        pass_before = ~val_.check(Xa.astype(np.float32)).reject
        pass_after = ~val_.check(Xp.astype(np.float32)).reject
        c = det0                      # rows the model detected before the attack
        rows.append({
            "attack": atk, "model": model, "n_detected_clean": int(c.sum()),
            "unrealizable_%": 100 * float(viol[c].mean()),
            "evasion_before_%": 100 * float(ev_before[c].mean()),
            "evasion_after_projection_%": 100 * float(ev_after[c].mean()),
            "pass_and_evade_before_%": 100 * float((ev_before & pass_before)[c].mean()),
            "pass_and_evade_after_%": 100 * float((ev_after & pass_after)[c].mean()),
        })
        log.info("art_projected %-8s x %-4s: %.1f%% unrealizable; evasion %.1f%% -> %.1f%% after P",
                 atk, model, rows[-1]["unrealizable_%"], rows[-1]["evasion_before_%"],
                 rows[-1]["evasion_after_projection_%"])
    if not rows:
        log.warning("art_projected: no phase-3 sets in %s", adv_dir)
        return
    df = pd.DataFrame(rows)
    stem = reports_dir / f"table4c_projection_spec{args.spec}"
    df.to_csv(stem.with_suffix(".csv"), index=False)
    lines = [f"# Table IV-c - phase-3 ART attacks projected onto realizable traffic (spec {args.spec})",
             "", "Rows: the phase-3 test-split source rows each model detected at its calibrated "
             "threshold. `unrealizable` = the ART row is not a fixed point of the realism projection P. "
             "`after projection` = the same rows repaired by P, i.e. the closest traffic an attacker "
             "could actually send.", "",
             df.to_markdown(index=False, floatfmt=".2f")]
    stem.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    log.info("wrote %s.{csv,md}", stem)


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--models-dir", default="artifacts/models")
    ap.add_argument("--rules", default="artifacts/rules.json")
    ap.add_argument("--realism", default="config/realism.yaml")
    ap.add_argument("--split", default="test", choices=["val", "test"])
    ap.add_argument("--spec", default="A", choices=["A", "B"])
    ap.add_argument("--models", nargs="+", default=["mlp", "cnn", "lstm"])
    ap.add_argument("--attacks", nargs="+", default=[a for a in ALL_ATTACKS], choices=ALL_ATTACKS)
    ap.add_argument("--n-per-category", type=int, default=900)
    ap.add_argument("--steps", type=int, default=100)
    ap.add_argument("--feat-step", type=float, default=0.01)
    ap.add_argument("--prim-step", type=float, default=0.05)
    ap.add_argument("--queries", type=int, default=1000)
    ap.add_argument("--restarts", type=int, default=0,
                    help="random restarts for rows a PGD run did not win (tuned on val)")
    ap.add_argument("--batch-size", type=int, default=1024)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--force", action="store_true", help="regenerate cells that already exist")
    ap.add_argument("--smoke", action="store_true",
                    help="10 rows/category, 10 steps, 50 queries; writes under data/smoke/")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(message)s",
                        datefmt="%H:%M:%S")

    if args.smoke:
        args.n_per_category, args.steps, args.queries = 10, 10, 50
    tag = f"{args.split}_spec{args.spec}"
    out_dir = (ROOT / "data/smoke/adversarial_real" if args.smoke
               else ROOT / "artifacts/adversarial_real") / tag
    reports_dir = ROOT / ("data/smoke/reports" if args.smoke else "artifacts/reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    data_dir, models_dir = ROOT / args.data_dir, ROOT / args.models_dir
    split = np.load(data_dir / f"{args.split}.npz")
    val = np.load(data_dir / "val.npz")
    class_names, cat_names = load_class_names(data_dir)
    thr = json.loads((models_dir / "thresholds.json").read_text(encoding="utf-8"))
    feature_names = json.loads((data_dir / "feature_names.json").read_text(encoding="utf-8"))
    if thr["feature_names"] != feature_names:
        raise SystemExit("thresholds.json was calibrated on another feature set: re-run 02c")
    thresholds = {k: v["threshold"] for k, v in thr["models"].items()}

    P = load_projector(ROOT / args.realism, data_dir / "transform.json", args.spec)
    g = Primitives(P)
    rules = json.loads((ROOT / args.rules).read_text(encoding="utf-8"))
    if rules["feature_names"] != feature_names:
        raise SystemExit("rules.json was mined on another feature set: re-run 04_analyze_validate.py")
    validator, soft = Validator(rules), SoftValidator(rules)
    targets = load_targets(models_dir, args.models, thresholds)
    attacker = Attacker(P, g, validator=validator, soft_validator=soft, batch_size=args.batch_size)
    spec_obj = P.spec

    base = {"P": P, "g": g, "validator": validator, "targets": targets, "spec_obj": spec_obj,
            "cat_name": cat_names}
    if "art_projected" in args.attacks:
        run_art_projected(args, base, reports_dir)
    cell_attacks = [a for a in args.attacks if a != "art_projected"]
    if not cell_attacks:
        return

    # ---- source rows ---------------------------------------------------------
    eligible = ~np.zeros(len(split["y"]), dtype=bool)
    for t in targets:
        eligible &= t.detects(split["X"])
    eligible &= split["y"] == 1
    idx = select_rows_per_category(split["y_category"], eligible, args.n_per_category, args.seed)
    # .npy, not .npz: discriminator.load_cells reads every .npz here as a cell.
    rows_path = out_dir / "source_rows.npy"
    if rows_path.exists() and not args.force:
        prev = np.load(rows_path)
        if not np.array_equal(prev, idx):
            raise SystemExit(f"{rows_path} holds different source rows; pass --force to rebuild "
                             "every cell from the new ones")
    np.save(rows_path, idx)
    X0 = split["X"][idx].astype(np.float64)
    ycat, ymc = split["y_category"][idx], split["y_multiclass"][idx]
    cat_rows = np.array([cat_names[int(c)] for c in ycat])
    floor = spec_obj.rate_floor(cat_rows)
    pop = window_population(cat_rows, [class_names[int(c)] for c in ymc])
    log.info("source rows: %d from %s (%s per category, detected by %s); populations %s",
             len(idx), args.split, args.n_per_category, ", ".join(t.name for t in targets),
             dict(zip(*np.unique(pop, return_counts=True))))

    ctx = {**base, "X0": X0, "idx": idx, "y": split["y"], "ycat": ycat, "ymc": ymc,
           "floor": floor, "pop": pop, "cat_names_rows": cat_rows,
           "categories": [c for c in cat_names.values() if c != "Benign"]}

    # ---- the cells ------------------------------------------------------------
    plan = []
    for a in cell_attacks:
        if a in ("feat_pgd", "prim_pgd"):
            plan += [(a, t.name, [t]) for t in targets]
        elif a == "greybox":
            sthr = surrogate_thresholds(models_dir, val, thr["fpr_budget"])
            plan.append((a, "surr", load_targets(models_dir, SURROGATES, sthr, tag="_surr")))
        else:
            plan.append((a, "ens", targets))

    summary, metrics = [], {}
    for name, model_tag, tgts in plan:
        path = out_dir / f"{name}_{model_tag}.npz"
        if path.exists() and not args.force:
            log.info("%s_%s: exists, skipping (use --force)", name, model_tag)
            d = np.load(path, allow_pickle=False)
            arrays = {k: d[k] for k in d.files}
            summary += summarise_cell(name, model_tag, arrays, ctx)
            continue
        log.info("=" * 70)
        log.info("%s against %s (%d rows)", name, ", ".join(t.name for t in tgts), len(idx))
        t0 = time.time()
        extra = {"theta": np.full((len(idx), g.dim), np.nan, dtype=np.float32)}
        settings = {}
        if name.startswith("feat_pgd"):
            Xa, _ = attacker.feat_pgd(tgts, X0, floor, steps=args.steps, step_size=args.feat_step,
                                      restarts=args.restarts, seed=args.seed)
            settings = {"steps": args.steps, "step_size": args.feat_step, "restarts": args.restarts}
        elif name.startswith("prim_pgd"):
            Xa, th, _ = attacker.prim_pgd(tgts, X0, floor, steps=args.steps, step_frac=args.prim_step,
                                          restarts=args.restarts, seed=args.seed)
            extra["theta"] = th.astype(np.float32)
            settings = {"steps": args.steps, "step_frac": args.prim_step, "restarts": args.restarts}
        elif name in ("adaptive_prim", "greybox"):
            Xa, th, _, lam = attacker.adaptive(tgts, X0, floor, space="prim", steps=args.steps,
                                               step_frac=args.prim_step, restarts=args.restarts,
                                               seed=args.seed)
            extra["theta"], extra["lambda"] = th.astype(np.float32), lam.astype(np.float32)
            settings = {"steps": args.steps, "step_frac": args.prim_step, "restarts": args.restarts,
                        "ladder": [0.0, 0.1, 1.0, 10.0, 100.0]}
        elif name == "adaptive_feat":
            Xa, _, _, lam = attacker.adaptive(tgts, X0, floor, space="feat", steps=args.steps,
                                              step_size=args.feat_step, restarts=args.restarts,
                                              seed=args.seed)
            extra["lambda"] = lam.astype(np.float32)
            settings = {"steps": args.steps, "step_size": args.feat_step, "restarts": args.restarts,
                        "ladder": [0.0, 0.1, 1.0, 10.0, 100.0]}
        elif name == "blackbox":
            Xa, th, _, q = attacker.blackbox(tgts, X0, floor, queries=args.queries, seed=args.seed)
            extra["theta"], extra["queries"] = th.astype(np.float32), q.astype(np.float32)
            settings = {"queries": args.queries}
        seconds = round(time.time() - t0, 1)

        # Grey-box rows were crafted on surrogates: judge them on the REAL models.
        judged = [t.name for t in (targets if name == "greybox" else tgts)]
        extra["target_names"] = judged
        arrays = evaluate_cell(name, model_tag, X0, Xa, ctx, extra)
        meta = {"attack": name, "model": model_tag, "strategy": STRATEGY[name],
                "tier": TIER.get(name, "white"), "spec": args.spec, "split": args.split,
                "crafted_on": [t.name for t in tgts], "judged_on": judged,
                "thresholds": {t.name: t.threshold for t in tgts}, "settings": settings,
                "seconds": seconds, "n": len(idx)}
        save_cell(out_dir, name, model_tag, arrays, ctx, meta)
        s = summarise_cell(name, model_tag, arrays, ctx)
        summary += s
        metrics[f"{name}_{model_tag}"] = {**meta, "summary": s}
        a = s[0]
        log.info("%s_%s: evasion %.2f%% [%.2f, %.2f], passes validator %.2f%%, pass+evade %.2f%% "
                 "(%.0fs)", name, model_tag, a["evasion_%"], a["evasion_lo"], a["evasion_hi"],
                 a["passes_validator_%"], a["pass_and_evade_%"], seconds)

    # ---- reports ----------------------------------------------------------------
    df = pd.DataFrame(summary)
    stem = reports_dir / f"table4b_realizable_{tag}"
    df.to_csv(stem.with_suffix(".csv"), index=False)
    head = df[df["group"].isin(["ALL", "pop:10-pkt", "pop:100-pkt"])]
    cat = df[~df["group"].str.startswith("pop:") & (df["group"] != "ALL")]
    piv = cat.pivot_table(index=["attack", "model"], columns="group", values="pass_and_evade_%")
    lines = [f"# Table IV-b - realizable attacks ({args.split} split, flow-age spec {args.spec})", "",
             f"{len(idx)} source rows ({args.n_per_category} per attack category), each detected by "
             f"every baseline at its calibrated threshold. `evasion` = no targeted model detects the "
             f"row; `pass_and_evade` = that AND the real validator lets it through. Brackets: 95% "
             f"bootstrap intervals. Costs are medians over the pass-and-evade rows.", "",
             "## Overall and by window population", "",
             head.to_markdown(index=False, floatfmt=".2f"), "",
             "## Pass-and-evade % by category", "", piv.to_markdown(floatfmt=".2f")]
    stem.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    prev_path = reports_dir / f"realizable_metrics_{tag}.json"
    prev = json.loads(prev_path.read_text(encoding="utf-8")) if prev_path.exists() else {}
    prev.update(metrics)
    prev_path.write_text(json.dumps(prev, indent=2, default=float), encoding="utf-8")
    log.info("wrote %s.{csv,md} and %s", stem, prev_path.name)


if __name__ == "__main__":
    main()
