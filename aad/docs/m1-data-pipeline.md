# M1 — the CICIoT2023 data pipeline, step by step

Milestone M1 of [`ciciot2023-implementation-plan.md`](ciciot2023-implementation-plan.md).
This document records **what was done, in what order, why, and what came out**, so
that every number in `artifacts/reports/` can be traced back to a decision here.

Run date: 2026-10-07. Machine: i5-12450H (8C/12T), 15.7 GB RAM, CPU-only.

---

## Contents

0. [Housekeeping before any code changed](#0-housekeeping-before-any-code-changed)
1. [Checking the downloaded dataset](#1-checking-the-downloaded-dataset)
2. [How to run M1](#2-how-to-run-m1)
3. [The pipeline, step by step](#3-the-pipeline-step-by-step)
4. [Leakage probe](#4-leakage-probe)
5. [Final dataset](#5-final-dataset)
6. [How the design evolved over three runs](#6-how-the-design-evolved-over-three-runs)
7. [What M1 means for M2–M8](#7-what-m1-means-for-m2m8)
8. [Every file M1 touched](#8-every-file-m1-touched)

---

## 0. Housekeeping before any code changed

### 0.1 Safety net

There is no git executable on the development machine, so edits have no undo. Before
touching anything, a snapshot of all code, configs, tests, docs and reports was zipped:

```
backups/pre_m1_code_and_reports_2026-10-07.zip   (110 files, 0.9 MB)
```

`backups/` is git-ignored. Restore any file from it if a change below needs reverting.

### 0.2 What happened to the CSE-CIC-IDS2018 implementation

The user chose **"Archive"** from three options (keep runnable / archive / delete all).
The deciding fact: later phase scripts write to `artifacts/models/mlp.keras` etc., so
once they run on CICIoT2023 they would **overwrite** the IDS2018 models. Everything
that is a result, or expensive to regenerate, was therefore moved out of the way first.

| Action | What | Where now / why |
| --- | --- | --- |
| **moved** | all IDS2018 reports, tables, figures (38 files) | `archive/cicids2018/reports/` |
| **moved** | trained weights `{mlp,cnn,lstm}{,_eids}.keras`, histories, test probabilities | `archive/cicids2018/models/` (~3 h of CPU to retrain) |
| **moved** | `rf.joblib`, `dataset_meta.json` | `archive/cicids2018/discriminator/` |
| **moved** | `artifacts/rules.json` | `archive/cicids2018/rules.json` |
| **moved** | `feature_names.json`, `scaler.pkl` (the input space of the archived models) | `archive/cicids2018/processed_inputs/` |
| **copied** | IDS2018 `config/data.yaml`, `README.md` | `archive/cicids2018/config/`, `archive/cicids2018/README.md` (with a path-mapping banner) |
| **deleted** | 2 raw IDS2018 CSVs (717 MB) | regenerable: public download |
| **deleted** | `data/interim/combined.parquet`, `data/processed/*.npz`, `data/processed_paperparity/` | regenerable from the raw CSVs in ~3 min |
| **deleted** | 21 `artifacts/adversarial*/*.npz` | regenerable by phase 3 |
| **deleted** | `__notebook_source__.ipynb` (empty: zero cells), `.pytest_cache/`, `__pycache__/` | junk |
| **moved** | `ciciot23.csv` from the repo root into `aad/data/raw/` | the documented raw location; it is git-ignored there and was **not** at the root |

**Code removed** because it only served IDS2018: the chunked `load_file`/`load_all`
reader and its embedded-header-row handling, the paper's hard-coded
`Type1 DoS-Hulk … Type5 SQL-Injection` name table in `evaluate.py`, the
`paper_type_names` config block, and the `--no-dedup` / `--out-dir` /
`--tag paperparity` options of `01_prepare.py`.

> Correction for the record: an earlier message claimed there were empty
> `interim/`, `processed/`, `processed_paperparity/` and `raw/` folders at the repo root.
> There were not. A directory listing had printed `aad\data`'s sub-folders directly
> after the root's, and they were misread. Nothing was lost; the deletion attempt
> simply found nothing.

### 0.3 `.gitignore`

Updated for the new layout: `backups/` ignored; the IDS2018-only
`aad/data/processed_paperparity/*` line removed; archived binary weights
(`archive/cicids2018/models/*`, `discriminator/*.joblib`) ignored exactly as they were
before archiving, while the archived reports, README and configs stay tracked.

---

## 1. Checking the downloaded dataset

The download is **one merged CSV**, not the 169 part files the plan assumed:

| Check | Expected | Found |
| --- | --- | --- |
| file | — | `ciciot23.csv`, 13,754,096,319 bytes |
| header | 46 features + `label` | 46 features + `label` ✔ |
| rows | 46,686,579 (published total) | **46,686,579** ✔ |
| labels | the 34 published classes | all 34, none unknown ✔ |
| NaN cells | — | **0** |
| infinite cells | — | **0** |

These are not one-off manual checks: `01_prepare.py` enforces the row count
(`raw.expected_rows`), the feature count (`raw.expected_feature_count`) and the label
vocabulary (`label_map`) on every scan and **stops with an error** if any differs, so a
truncated or different file can never silently produce a smaller dataset.

Two things the first rows already showed, both important later:

- **Values are window averages**, not per-flow counts: `Protocol Type` = 6.11, `Duration`
  (TTL) = 64.64. Count-like columns are not whole numbers, which is why the IDS2018
  validator's integrality rules will not transfer (M3).
- **`IAT` looks like a timestamp** (~8.3 × 10⁷), not an inter-arrival time in seconds.

---

## 2. How to run M1

From `aad/`, with the venv:

```powershell
..\.venv\Scripts\python.exe scripts\01_prepare.py                     # full run
..\.venv\Scripts\python.exe scripts\01b_probe_leakage.py              # leakage probe
..\.venv\Scripts\python.exe scripts\01_prepare.py --sample-frac 0.02  # smoke test -> data/smoke/
..\.venv\Scripts\python.exe -m pytest tests\ -q                       # 101 tests
```

| Run | Time | Why |
| --- | ---: | --- |
| first `01_prepare.py` (or `--rescan`) | ~9 min | streams the 13.75 GB CSV twice |
| any later `01_prepare.py` | ~45 s | reads the 237 MB interim cache |
| `01b_probe_leakage.py` | ~1 min | 39 one-feature trees + row hashing |
| smoke test | ~20 s | 2% stratified subsample, writes only to `data/smoke/` |

The cache (`data/interim/ciciot_capped.parquet` + `.json` sidecar) is invalidated
automatically when the CSV, the cap, the seed, the label map or the duplicate
definition changes. The fingerprint is stored in the sidecar.

All knobs are in [`config/data.yaml`](../config/data.yaml), each with a comment.

---

## 3. The pipeline, step by step

Code: [`scripts/01_prepare.py`](../scripts/01_prepare.py) drives
[`src/aad/data/loader.py`](../src/aad/data/loader.py),
[`clean.py`](../src/aad/data/clean.py) and [`split.py`](../src/aad/data/split.py).
Each step logs a line starting `step N`; the log of the final run is
`artifacts/reports/prepare_run.log`.

### Step 1 — ingest: two streaming passes over 13.75 GB

**Problem.** The file is 13.75 GB, which does not fit in 15.7 GB of RAM once pandas has
parsed it. And 90% of it is DDoS/DoS flood traffic: a single class, `DDoS-ICMP_Flood`,
has 7.2 M rows. Training on everything would cost ~22 h of CPU per baseline pass (see
the plan) and teach nothing the first tens of thousands of distinct flood windows do not.

**Pass 1 — `scan()`.** pyarrow streams the CSV in 64 MB blocks (multi-threaded parsing,
bounded memory, peak ~4 GB). For each of the 46.7 M rows it keeps only three things:

- the label code (int8);
- a 64-bit hash of the 46 feature values **at float32 precision** (see 6.2 for why
  float32 and not exact equality);
- a flag for any NaN or ±inf value.

That is ~0.5 GB in total, and it is enough to count classes, NaN/inf and duplicates
over the **full** file. Time: ~4.5–5 min.

**Duplicate analysis — `duplicate_analysis()`.** Two rows are *duplicates* when their
features (at float32) **and** their label match; only the first occurrence is kept.
Rows whose features match but whose labels differ are *conflicts*. They are reported,
not removed, because they cap achievable accuracy. Result on the full file:

| | rows |
| --- | ---: |
| rows in file | 46,686,579 |
| duplicates at float32 precision | **18,588,033 (39.81%)** |
| of which exact float64 copies | 34 |
| distinct rows | 28,098,546 |
| feature vectors under more than one label | **0** |

Duplication is concentrated in the floods: `DDoS-ICMP_Flood` loses 5.39 M of 7.2 M
rows (75%), `DDoS-RSTFINFlood` 73%, `DDoS-TCP_Flood` 65%, `DDoS-PSHACK_Flood` 60%.
Benign traffic has only 18 duplicates, and every Web and BruteForce class has zero.

**Selection — `select_capped()`.** For each class, drop NaN/inf rows and duplicates, then
keep at most **60,000** rows chosen uniformly at random with seed 42. `BenignTraffic` is
kept whole (`sampling.keep_all`). Classes smaller than the cap (all Web classes,
BruteForce, PingSweep, SlowLoris, DDoS-HTTP, VulnerabilityScan) are kept whole too.
Deduplicating **before** sampling matters: without it the 60 k cap on a flood class
would be filled partly with copies of the same window.

**Pass 2 — `load_selected()`.** Stream the file again and keep exactly the selected row
positions (2,547,910 rows), verifying the count. ~3 min. The result is cached as
Parquet (237 MB) with a JSON sidecar holding the full-file report.

**Why 60,000 per class.** It is the plan's sample size: all benign rows (1.10 M) plus
≤60 k per attack class gives ~2.5 M rows, so phase 2 trains in ~1.2 h. A cap of 150 k
would double that cost for classes whose 60 k sample already covers their behaviour.

### Step 2 — labels

`normalise_labels()` maps each raw label (slugified, so `DDoS-ICMP_Flood`,
`ddos icmp flood` and so on all match) to:

- `label_name` (34 names),
- `label_multiclass` (codes 0–33),
- `label_binary` (0 benign, 1 attack),
- **new:** `label_category`, the 8 CIC categories: Benign, DDoS, DoS, Mirai, Recon,
  Spoofing, Web, BruteForce.

The full mapping is `label_map` in the config. An unmapped label raises an error.

### Step 3 — clean (defensive)

The old IDS2018 cleaner (`clean_rows`) still runs on the sample: inf → NaN, drop NaN
rows, drop exact duplicates. Because step 1 already excluded all of those, it **must
drop zero rows**, and the script raises an error if it does not. In the final run it
dropped 0. This is a cheap tripwire against a regression in the sampler.

### Step 4 — split

70 / 15 / 15, stratified on the 34-way label, seed 42 (`stratified_split`, unchanged).
Stratifying on the fine label guarantees the rarest class, `Uploading_Attack`
(1,252 rows), is present in proportion in all three splits (876 / 188 / 188).

The split happens **before** anything is fitted, so validation and test rows never
influence a fitted parameter (steps 5–7 are all decided on train).

### Step 5 — constant and near-constant columns (train only)

A column is dropped if it is constant, **or if fewer than 100 training rows differ from
its most common value** (`clean.min_non_mode_rows`). Seven columns go:

| column | non-mode rows in 1.78 M train rows |
| --- | ---: |
| `DHCP` | 0 |
| `Telnet` | 1 |
| `SMTP` | 1 |
| `IRC` | 2 |
| `cwr_flag_number` | 9 |
| `ece_flag_number` | 15 |
| `Drate` | 38 |

Why the near-constant rule (see 6.4): a column that is nonzero in 1–38 rows carries no
learnable pattern, only rows a model can memorise. And whether it survives at all
depended on which rows the random sample happened to draw: `SMTP` was dropped in one
run and kept in the next. Columns with real support stay: `DNS` (2,318), `IPv`/`LLC`
(1,680), `SSH` (1,363), `ARP` (851). **46 → 39 features.**

### Step 6 — signed log1p on heavy-tailed columns (train only)

**Problem.** MinMax maps each column's min→0 and max→1. If a few extreme rows set the
max, every typical row is squashed near 0. For example, `AVG` (mean packet length) has
median 149 bytes but max 13,580, so after MinMax the median row sits at 0.008. That
breaks eps: in phases 3+ an eps of 0.1 is meant to be "10% of the feature's range", but
for `AVG` it would be about 12× the typical value.

**Fix.** Apply `signed_log1p(x) = sign(x)·log(1+|x|)` before MinMax. It is monotone
(order is preserved), exactly invertible (`inverse_signed_log1p`), and defined for
negative inputs. Nothing is fitted, so it cannot leak.

**Which columns.** A data-driven rule (`transform.log1p_columns: auto`), measured on
train: transform a column if its **median lands in the bottom 2% of its MinMax range**
(`auto_p50_position: 0.02`) and its span exceeds 10 (`auto_min_span`), so 0/1
indicators stay linear. Selected (16):

```
flow_duration, Header_Length, Rate, Srate, syn_count, fin_count, urg_count, rst_count,
Tot sum, Min, Max, AVG, Std, Tot size, Radius, Covariance
```

These are all magnitude columns: sizes, counts, rates and durations. The per-column
evidence (`p50_position`, `p99_position`, fraction of zeros, fraction of integers,
negatives) is in `artifacts/reports/feature_stats.csv`.

**Effect.** The median scaled value per feature is now 0.22 for `AVG` (was 0.008), 0.23
for `Rate`, 0.34 for `rst_count` and 0.64 for `Header_Length`. Across all 39 features,
the median of the per-feature medians is 0.22.

> For M4: perturbations on log-scaled columns are *multiplicative* in raw units (a step
> of δ in log space multiplies the raw value by about e^δ). That is closer to how real
> traffic varies (padding adds a fraction of the packet size) than an additive step.

### Step 7 — MinMax scale (train only), then save

`MinMaxScaler` is fitted on train only and applied to val and test, which are clipped to
[0, 1] (`fit_scaler`/`transform`, unchanged). Clipping touched 0.00003% (val) and
0.00005% (test) of cells. Assertions check shape, finiteness and range before anything
is written.

---

## 4. Leakage probe

Script: [`scripts/01b_probe_leakage.py`](../scripts/01b_probe_leakage.py).
Report: `artifacts/reports/leakage_probe.{md,json}`. Three questions:

**Probe 1: how much of the file is repeated?** 39.81% at model precision (above). Zero
conflicting feature vectors, so no accuracy ceiling from label noise of that kind.

**Probe 2: can one feature alone separate attack from benign?** A depth-3 decision tree
per feature, trained on a stratified 300 k-row train subsample and scored on the full
test set (balanced accuracy, so the 57/43 class mix cannot flatter it). Flag threshold:
99%.

| feature | binary balanced acc. | 8-category balanced acc. | distinct values (train) |
| --- | ---: | ---: | ---: |
| `IAT` | 94.1% | 49.6% | 79,675 |
| `Number` | 88.3% | 24.8% | 96 |
| `Weight` | 88.3% | 24.8% | 102 |
| `rst_count` | 88.2% | 34.2% | 40,569 |
| `urg_count` | 87.6% | 31.2% | 13,719 |

**No feature is flagged**, so none is dropped. Three need to be stated in the write-up:

- **`IAT`** alone gets 94% of the way. It behaves like a capture timestamp (~8.3 × 10⁷),
  so part of its power is probably *when* each attack was recorded, not *how* it
  behaves. A model leaning on it would not transfer to a new capture. M2 should report
  feature importance, and M4 must treat `IAT` as something an attacker can shift.
- **`Number` and `Weight`** take only ~100 distinct values and move together (weight =
  incoming × outgoing packet counts). They reflect the packet-window size used by the
  extractor, which is a capture setting rather than attack behaviour.

**Probe 3: are test rows copies of training rows?** After scaling, **2 of 382,187**
test rows are byte-identical to a training row, both same-label (one
`Mirai-greeth_flood`, one `Mirai-greip_flood`). They are distinct at float32 before the
transform and collide only through the rounding of log1p + MinMax. That is negligible,
and reported rather than removed. (Before the float32 deduplication of 6.2 this number
was 10,824.)

---

## 5. Final dataset

| | train | val | test |
| --- | ---: | ---: | ---: |
| rows | 1,783,537 | 382,186 | 382,187 |
| attack share | 56.90% | 56.90% | 56.90% |
| Benign | 768,724 | 164,726 | 164,727 |
| DDoS | 456,538 | 97,830 | 97,830 |
| DoS | 168,000 | 36,000 | 36,000 |
| Mirai | 126,000 | 27,000 | 27,000 |
| Recon | 153,750 | 32,946 | 32,946 |
| Spoofing | 84,000 | 18,000 | 18,000 |
| Web | 17,380 | 3,725 | 3,724 |
| BruteForce | 9,145 | 1,959 | 1,960 |

`X` is float32 in [0, 1] with **39 features**. Per-class counts for all 34 classes are
in `artifacts/reports/class_stats.md` (Table I).

Compare the raw file, where benign is 2.35% and the rarest category (BruteForce) 0.03%.
In the processed data, benign is 43% and every Web and BruteForce row that exists is
kept, so the rare categories are now measurable: 3,724 Web and 1,960 BruteForce test
rows, against 81 web-attack test rows in the IDS2018 run.

**Outputs** (`data/processed/`, git-ignored):

| file | contents | used by |
| --- | --- | --- |
| `{train,val,test}.npz` | `X`, `y` (binary), `y_multiclass` (34), `y_category` (8) | every phase |
| `feature_names.json` | the 39 feature names, in column order | models, validator, attacks |
| `classes.json` | code → name for classes and categories, class → category | `evaluate.load_class_names` |
| `transform.json` | log1p columns/indices, MinMax `data_min`/`data_range` | M3 validator (raw units), M4 attacker |
| `scaler.pkl` | the fitted `MinMaxScaler` | convenience |

**Reports** (`artifacts/reports/`, tracked): `class_stats.{csv,md}`,
`feature_stats.csv`, `leakage_probe.{json,md}`, `prepare_meta.json` (the full ledger),
and `prepare_run.log` / `probe_run.log`.

**Mapping a scaled row back to raw units** (for M3/M4):
`raw = X · data_range + data_min`, then `inverse_signed_log1p` on the `log1p_indices`.

---

## 6. How the design evolved over three runs

Recorded because each change was forced by evidence from the previous run, and that
reasoning belongs in the write-up.

### 6.1 Run 1 — exact deduplication, p99-based log1p

- Exact float64 deduplication found only **34** duplicates in 46.7 M rows.
- The log1p rule "p99 below 5% of the range" picked 5 columns.

### 6.2 Duplicates must be defined at the precision the model sees

The run-1 leakage probe found **10,824 test rows (2.8%) byte-identical to a training
row**, all with the same label, despite "only 34 duplicates". Diagnosis on the sample:
54,270 rows become duplicates once cast to float32, and in every inspected group the
**only** differing column was `IAT`. At ~8.3 × 10⁷, float32 resolves steps of ~8, and the
twins differed by less. They are the same window statistics with sub-precision jitter
in one column. A float32 model sees one row, so for every purpose that matters they are
duplicates crossing the train/test boundary.

**Change:** the scan hashes rows after casting to float32
(`loader._hash_rows_model_precision`). The exact float64 count is kept in the report
for transparency, and the cache fingerprint got a `dedup: float32-v2` field so the stale
cache was invalidated automatically. **Result:** duplicates went from 34 to 18,588,033
(39.81%), and test/train overlap went from 10,824 to 2. A unit test
(`test_rows_differing_only_below_float32_precision_are_duplicates`) pins this behaviour.

> Finding for the thesis: CICIoT2023 looks almost duplicate-free under exact
> comparison, but 40% of it is repeated at the precision any float32 model uses. Work
> that splits the raw file randomly is training and testing on copies.

### 6.3 log1p decided on the median, not the 99th percentile

The p99 rule missed the packet-size columns. `AVG`, `Min`, `Max`, `Std`, `Tot size`,
`Header_Length`, `rst_count` and `urg_count` had a p99 at 10–57% of their range (so
they passed), but their **median** at 0.1–1.4%. That means typical traffic was
squashed, which is the case eps cares about. Changing to "median in the bottom 2%"
selects 16 columns, all of them magnitude columns.

### 6.4 Near-constant columns

Run 2 kept `SMTP` because its single nonzero row in the whole sample landed in train
(run 1 had dropped it as constant). A feature whose existence depends on one random row
is not a feature. The `min_non_mode_rows: 100` rule (step 5) makes the feature set
stable, and drops six columns that carried 1–38 rows of signal each.

---

## 7. What M1 means for M2–M8

- **M2 (baselines).** Data is ready at `data/processed/`. 57/43 attack/benign, so
  report balanced accuracy (now in `evaluate.binary_metrics`) and per-category recall
  (`evaluate.per_category_recall`). Check whether models lean on `IAT`.
- **M3 (validator).** Integrality will find little: values are window means
  (`frac_integer` in `feature_stats.csv`). Rules must run in raw units through
  `transform.json`, and the IDS2018 `to_raw` must gain the `inverse_signed_log1p` step.
- **M4 (attacker).** Six columns an attacker might have used are gone from the model
  input (`ece`/`cwr` flags, `Drate`, the rare protocol indicators). Perturbing them
  cannot fool a model that never sees them, so the primitive set θ shrinks
  accordingly. Perturbations on the 16 log1p columns are multiplicative in raw units.
  `IAT`, `Number` and `Weight` need a decision on whether the attacker controls them.
- **Stratified attack sample.** `y_category` in the `.npz` files is what M4's
  "1,000 rows per category" draw uses.

---

## 8. Every file M1 touched

| file | change |
| --- | --- |
| `config/data.yaml` | **rewritten** for CICIoT2023 (IDS2018 version archived) |
| `src/aad/data/loader.py` | **rewritten**: `scan`, `duplicate_analysis`, `select_capped`, `load_selected`; IDS2018 reader removed |
| `src/aad/data/clean.py` | `normalise_labels` adds `label_category`; `find_constant_columns` adds the near-constant rule and returns non-mode counts |
| `src/aad/data/split.py` | added `signed_log1p`, `inverse_signed_log1p`, `apply_log1p` |
| `src/aad/evaluate.py` | removed `TYPE_NAMES`; added `load_class_names`, `balanced_accuracy`, `per_category_recall`; `per_type_recall` takes names |
| `scripts/01_prepare.py` | **rewritten** around the two-pass loader, cache, log1p, new reports |
| `scripts/01b_probe_leakage.py` | **new** |
| `scripts/02_train_baselines.py`, `scripts/06_train_eids.py` | read class names from `classes.json` instead of the removed table |
| `tests/test_data.py` | **new**: 10 tests (scan, unknown labels, duplicates vs conflicts, float32 duplicates, cap/keep-all/exclusions, pass-2 fidelity, log1p inverse, misspelt column, near-constant rule, category column) |
| `README.md` | **rewritten** for the CICIoT2023 project; IDS2018 README archived |
| `archive/cicids2018/README.md` | path-mapping banner added |
| `docs/ciciot2023-implementation-plan.md` | status-and-deviations note |
| `docs/phases-1-4-walkthrough.md`, `docs/phase03-04-explained.md` | "written for IDS2018" banner |
| `../.gitignore` | updated for the new layout |
