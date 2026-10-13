"""Export M1-M4 results to compact JSON for the frontend.

Reads the CSV/JSON reports under aad/artifacts and writes one JSON file per
page to frontend/public/data/. Re-run whenever results change:

    python aad/scripts/export_frontend_data.py
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ART = ROOT / "aad" / "artifacts"
REP = ART / "reports"
MOD = ART / "models"
OUT = ROOT / "frontend" / "public" / "data"

MODELS = ["mlp", "cnn", "lstm"]
SPECS = ["A", "B", "C"]
CATEGORIES = ["Benign", "DDoS", "DoS", "Mirai", "Recon", "Spoofing", "Web", "BruteForce"]
ATTACK_CATS = CATEGORIES[1:]


def load_json(p: Path):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def load_csv(p: Path) -> list[dict]:
    with open(p, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    return [{k: _num(v) for k, v in r.items()} for r in rows]


def _num(v):
    if v is None or v == "":
        return None
    try:
        f = float(v)
        return int(f) if f.is_integer() and "." not in v else f
    except ValueError:
        return v


def r(x, nd=3):
    return None if x is None else round(float(x), nd)


def write(name: str, obj) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / f"{name}.json", "w", encoding="utf-8") as f:
        json.dump(obj, f, separators=(",", ":"), ensure_ascii=False)
    print(f"  {name}.json  {(OUT / f'{name}.json').stat().st_size / 1024:.1f} KB")


# ---------------------------------------------------------------- validator
def export_validator() -> dict:
    rules = load_json(ART / "rules.json")
    vm = load_json(REP / "validator_metrics.json")
    names = rules["feature_names"]
    dist = rules["distribution"]
    art_sets = [row for row in vm["rows"] if row["kind"] == "catch"]
    clean = {row["set"]: row for row in vm["rows"] if row["kind"] != "catch"}
    return {
        "provenance": rules["provenance"],
        "features": names,
        "range": [
            {"feature": n, "min": r(lo, 4), "max": r(hi, 4)}
            for n, lo, hi in zip(names, rules["range"]["min"], rules["range"]["max"])
        ],
        "log1p_columns": rules["scaling"]["log1p_columns"],
        "integrality": rules["integrality"]["columns"],
        "dependency": [
            {"name": d["name"], "kind": d["kind"], "tolerance": d["tolerance"],
             "p999": r(d["benign_residual"]["p99.9"], 8)}
            for d in rules["dependency"]["rules"]
        ],
        "dependency_pruned": [
            {"name": d["name"], "reason": d.get("reason", "")} for d in vm["dependency_pruned"]
        ],
        "distribution": [
            {"group": g, "threshold": r(t, 3), "train_rows": n, "global_profile": gp}
            for g, t, n, gp in zip(dist["groups"], dist["threshold"], dist["train_rows"],
                                   dist["uses_global_profile"])
        ],
        "fpr_budget": vm["fpr_budget"],
        "clean": {
            "benign_fpr": clean["clean benign (test)"]["combined_%"],
            "attack_reject": clean["clean attack (test)"]["combined_%"],
            "benign_n": clean["clean benign (test)"]["n"],
            "attack_n": clean["clean attack (test)"]["n"],
        },
        "fpr_by_group": [
            {"group": g["protocol group"], "n": g["benign test rows"], "fpr": g["FPR_%"]}
            for g in vm["fpr_by_group"]
        ],
        "reject_by_category": [
            {"category": c["category"], "n": c["test rows"], "rejected": c["rejected_%"],
             "range": c["range_%"], "integrality": c["integrality_%"],
             "dependency": c["dependency_%"], "distribution": c["distribution_%"]}
            for c in vm["reject_by_category"]
        ],
        "art_sets": [
            {"set": s["set"], "combined": s["combined_%"], "range": s["range_%"],
             "integrality": s["integrality_%"], "dependency": s["dependency_%"],
             "distribution": s["distribution_%"], "attributable": s.get("attributable_%"),
             "evade_model_only": s.get("evade_model_only_%"),
             "pass_and_evade": s.get("pass_and_evade_%")}
            for s in art_sets
        ],
        # Table IV-d section 5: what the validator adds against realizable attacks
        "realizable_stop": [
            {"spec": "A", "attack": "feat_pgd_ens", "fooled": 511, "stopped": 59},
            {"spec": "A", "attack": "prim_pgd_ens", "fooled": 220, "stopped": 25},
            {"spec": "B", "attack": "feat_pgd_ens", "fooled": 1536, "stopped": 213},
            {"spec": "B", "attack": "prim_pgd_ens", "fooled": 367, "stopped": 45},
            {"spec": "C", "attack": "feat_pgd_ens", "fooled": 2729, "stopped": 275},
            {"spec": "C", "attack": "prim_pgd_ens", "fooled": 1456, "stopped": 91},
        ],
    }


# ---------------------------------------------------------------- IDS
def export_ids() -> dict:
    bm = load_json(REP / "baseline_metrics.json")["results"]
    thr = load_json(MOD / "thresholds.json")
    table3 = {row["model"].lower(): row for row in load_csv(REP / "table3_nids.csv")}
    history = {}
    for m in MODELS:
        h = load_json(MOD / f"{m}_history.json")
        history[m] = {k: [r(v, 5) for v in h[k]]
                      for k in ("loss", "val_loss", "accuracy", "val_accuracy")}
    metrics = []
    for m in MODELS:
        b, t = bm[m], table3[m]
        metrics.append({
            "model": m.upper(), "accuracy": r(b["accuracy"] * 100), "balanced_accuracy": r(b["balanced_accuracy"] * 100),
            "precision": r(b["precision"] * 100), "recall": r(b["recall"] * 100), "f1": r(b["f1"] * 100),
            "fpr": r(b["fpr"] * 100), "tn": b["tn"], "fp": b["fp"], "fn": b["fn"], "tp": b["tp"],
            "params": t["params"], "epochs": t["epochs"], "train_s": t["train_s"],
            "threshold": r(thr["models"][m]["threshold"], 4),
        })
    per_cat = load_csv(REP / "per_category_recall.csv")
    evasion = [
        {"model": row["model"], "attack": row["attack"].replace("DEEPFOOL", "DeepFool"),
         "clean_acc": row["clean_acc_%"], "adv_acc": row["adv_acc_%"], "evasion": row["evasion_%"],
         "feats_changed": row["feats_changed"]}
        for row in load_csv(REP / "table4_evasion.csv")
    ]
    # realizable, one model at a time (feat_pgd / prim_pgd per spec)
    realizable = []
    for s in SPECS:
        rm = load_json(REP / f"realizable_metrics_test_spec{s}.json")
        for atk in ("feat_pgd", "prim_pgd"):
            for m in MODELS:
                cell = rm.get(f"{atk}_{m}")
                if not cell:
                    continue
                allrow = next(x for x in cell["summary"] if x["group"] == "ALL")
                realizable.append({"spec": s, "attack": atk, "model": m.upper(),
                                   "evasion": r(allrow["evasion_%"]),
                                   "pass_and_evade": r(allrow["pass_and_evade_%"]),
                                   "evades_all3": r(allrow["evades_all3_%"])})
    e = thr["or_ensemble_test"]
    ens = {"members": [x.upper() for x in e["members"]], "fpr": r(e["fpr"] * 100),
           "balanced_accuracy": r(e["balanced_accuracy"] * 100)}
    return {"metrics": metrics, "history": history, "per_category_recall": per_cat,
            "evasion": evasion, "realizable": realizable, "ensemble": ens,
            "fpr_budget": thr["fpr_budget"]}


# ---------------------------------------------------------------- adversary
ATTACKERS = [
    ("feat_pgd_ens", "feat_pgd_ens_ens", "white", "Feature-space PGD"),
    ("adaptive_feat", "adaptive_feat_ens", "white", "Adaptive feature PGD"),
    ("prim_pgd_ens", "prim_pgd_ens_ens", "white", "Physical-knob PGD"),
    ("adaptive_prim", "adaptive_prim_ens", "white", "Adaptive physical PGD"),
    ("greybox", "greybox_surr", "grey", "Grey-box (surrogates)"),
    ("blackbox", "blackbox_ens", "black", "Black-box (queries)"),
]


def export_adversary() -> dict:
    tiers = load_csv(REP / "table4d_tiers.csv")
    cells = {s: load_json(REP / f"realizable_metrics_test_spec{s}.json") for s in SPECS}
    flows, by_cat, cost = [], [], []
    for name, key, tier, label in ATTACKERS:
        for s in SPECS:
            cell = cells[s].get(key)
            if not cell:
                continue
            summ = {x["group"]: x for x in cell["summary"]}
            a = summ["ALL"]
            flows.append({"attack": name, "spec": s, "n": a["n"],
                          "passes_validator": r(a["passes_validator_%"]),
                          "evasion": r(a["evasion_%"]),
                          "pass_and_evade": r(a["pass_and_evade_%"]),
                          "pop10": r(summ.get("pop:10-pkt", {}).get("pass_and_evade_%")),
                          "pop100": r(summ.get("pop:100-pkt", {}).get("pass_and_evade_%"))})
            if s == "C":
                for c in ATTACK_CATS:
                    if c in summ:
                        by_cat.append({"attack": name, "category": c,
                                       "pass_and_evade": r(summ[c]["pass_and_evade_%"], 1)})
                cost.append({"attack": name, "byte_overhead": r(a["med_byte_overhead_%"], 2),
                             "rate_loss": r(a["med_rate_loss_%"], 2),
                             "features_changed": a["med_features_changed"],
                             "pass_and_evade": r(a["pass_and_evade_%"])})
    projection = []
    for s in SPECS:
        for row in load_csv(REP / f"table4c_projection_spec{s}.csv"):
            projection.append({"spec": s, "attack": row["attack"].upper().replace("DEEPFOOL", "DeepFool"),
                               "model": row["model"].upper(), "unrealizable": r(row["unrealizable_%"], 2),
                               "evasion_before": r(row["evasion_before_%"], 2),
                               "evasion_after": r(row["evasion_after_projection_%"], 2),
                               "pae_after": r(row["pass_and_evade_after_%"], 2)})
    levers = load_csv(REP / "realizable_levers.csv")
    return {
        "attackers": [{"attack": n, "tier": t, "label": l} for n, _, t, l in ATTACKERS],
        "tiers": [{"attack": t["attack"], "tier": t["tier"], "spec": t["spec"],
                   "value": r(t["pass_and_evade_%"]), "lo": r(t["lo"]), "hi": r(t["hi"])} for t in tiers],
        "flows": flows, "by_category": by_cat, "cost": cost, "projection": projection,
        "levers": [{k: (r(v, 2) if isinstance(v, float) else v) for k, v in row.items()} for row in levers],
        "n_source_rows": 6300,
        "specs": {
            "A": {"label": "Padding + TTL", "knobs": ["pad", "dttl"]},
            "B": {"label": "+ keep-alive (≤5×)", "knobs": ["pad", "dttl", "slow"]},
            "C": {"label": "+ fresh connections (×0.2–×5)", "knobs": ["pad", "dttl", "slow", "stretch"]},
        },
    }


# ---------------------------------------------------------------- pipeline / overview
def export_pipeline() -> dict:
    meta = load_json(REP / "prepare_meta.json")
    stats = load_csv(REP / "class_stats.csv")
    leak = load_json(REP / "leakage_probe.json")
    ing = meta["ingest"]
    return {
        "rows_in_file": ing["rows_in_file"], "distinct_rows": ing["distinct_rows"],
        "exact_duplicates": ing["exact_duplicate_rows"], "conflicting": ing["conflicting_feature_vectors"],
        "rows_kept": meta["rows_after_cleaning"], "cap_per_class": meta["cap_per_class"],
        "csv_gb": round(ing["csv_bytes"] / 1e9, 2), "split": meta["split_ratios"],
        "n_features": meta["n_features"], "features_before": meta["n_features_before_constant_drop"],
        "constant_columns": meta["constant_columns"], "dropped_columns": meta["drop_columns"],
        "log1p_columns": meta["log1p_columns"],
        "classes": [{"class": s["class"], "category": s["category"], "raw": s["rows_in_file"],
                     "kept": s["kept"], "train": s["train"], "val": s["val"], "test": s["test"]} for s in stats],
        "leakage": {"test_rows": leak["overlap"]["test_rows"],
                    "identical_to_train": leak["overlap"]["test_rows_identical_to_a_train_row"],
                    "flagged_features": len(leak["single_feature_flagged"]),
                    "top_single_feature": sorted(
                        [{"feature": x["feature"], "bal_acc": r(x["binary_balanced_acc"] * 100, 2)}
                         for x in leak["single_feature"]], key=lambda d: -d["bal_acc"])[:8]},
    }


def export_overview(val: dict, ids: dict, adv: dict) -> dict:
    best = max(adv["tiers"], key=lambda t: t["value"])
    return {
        "milestones": [
            {"id": "M1", "name": "Data pipeline", "status": "done"},
            {"id": "M2", "name": "Baseline NIDS", "status": "done"},
            {"id": "M3", "name": "Validator", "status": "done"},
            {"id": "M4", "name": "Realizable attacks", "status": "done"},
            {"id": "M5", "name": "Discriminator", "status": "next"},
            {"id": "M6", "name": "Adversarial training", "status": "planned"},
        ],
        "flow_rates": {
            "benign_fpr_validator": val["clean"]["benign_fpr"],
            "attack_reject_validator": val["clean"]["attack_reject"],
            "eids_recall": max(m["recall"] for m in ids["metrics"]),
            "leak_by_spec": {s: max(t["value"] for t in adv["tiers"] if t["spec"] == s) for s in SPECS},
        },
        "headline": {
            "best_bal_acc": max(m["balanced_accuracy"] for m in ids["metrics"]),
            "validator_fpr": val["clean"]["benign_fpr"],
            "best_pass_and_evade": best["value"], "best_attacker": best["attack"],
            "n_features": len(val["features"]),
        },
    }


def main() -> None:
    print(f"writing to {OUT}")
    val, ids, adv = export_validator(), export_ids(), export_adversary()
    write("validator", val)
    write("ids", ids)
    write("adversary", adv)
    write("pipeline", export_pipeline())
    write("overview", export_overview(val, ids, adv))
    write("basepaper", load_json(ROOT / "aad" / "docs" / "basepaper_results.json"))


if __name__ == "__main__":
    main()
