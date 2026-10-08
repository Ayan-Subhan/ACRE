# Superseded: the 39-feature run (with `IAT`), M1-M3

Archived on 2026-10-08, when `IAT` was dropped at the scan stage (`config/data.yaml:
drop_columns: [IAT]`). Everything here was produced from the 39-feature dataset of
2026-10-07 and is kept so the numbers quoted in the M1-M3 docs stay checkable.

| path | what | produced by |
| --- | --- | --- |
| `reports/` | M1 Table I, feature stats, leakage probe; M2 Table III, per-class/category recall, feature reliance, category-weighting run; M3 Table IV (ART evasion) and Table V (validator) | `01_prepare`, `01b`, `02`, `02b`, `03 --no-sweep`, `04` |
| `models/` | MLP / CNN / LSTM baselines and the category-weighted MLP (CPU-trained), 39 inputs | `02_train_baselines.py` |
| `adversarial/` | the 12 unconstrained ART sets used for Table V | `03_generate_ae.py --no-sweep` |
| `rules.json` | the M3 validator rules mined on the 39-feature data | `04_analyze_validate.py` |
| `feature_names.json`, `transform.json` | the 39-feature input space these models and rules expect | `01_prepare.py` |

Models and adversarial sets are git-ignored (binary, ~20 MB); `rules.json`, the
reports and this README are tracked.
