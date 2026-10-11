# Superseded: the 38-feature run (no `IAT`; with `Number`, `Weight`), M1-M3

Archived on 2026-10-09, when `Number` and `Weight` were dropped at the scan stage
(`config/data.yaml: drop_columns: [IAT, Number, Weight]`, M4 decision D1 in
`docs/m4-plan.md`). Both encode the extractor's packet-window size (10 vs 100 packets),
which CIC chose per class, so they are a capture setting, not attack behaviour.
Everything here was produced from the 38-feature dataset of 2026-10-08 (models trained
on machine A's GPU) and is kept so the numbers quoted in the M1-M3 docs stay checkable.

| path | what | produced by |
| --- | --- | --- |
| `reports/` | M1 Table I, feature stats, leakage probe; M2 Table III, per-class/category recall, feature reliance; M3 Table IV (ART evasion) and Table V (validator) | `01_prepare`, `01b`, `02`, `02b`, `03 --no-sweep`, `04` |
| `models/` | MLP / CNN / LSTM baselines (GPU-trained, WSL2), 38 inputs | `02_train_baselines.py` |
| `adversarial/` | the 12 unconstrained ART sets used for Table V | `03_generate_ae.py --no-sweep` |
| `rules.json` | the M3 validator rules mined on the 38-feature data | `04_analyze_validate.py` |
| `feature_names.json`, `transform.json` | the 38-feature input space these models and rules expect | `01_prepare.py` |

Models and adversarial sets are git-ignored (binary, ~17 MB); `rules.json`, the
reports and this README are tracked.
