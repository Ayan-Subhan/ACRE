# AAD on IoT traffic — adversarial-attack detection on CICIoT2023

Final-year project extending a reproduction of Verma et al., *A Secure Adversarial
Attack Detector Framework for Monitoring Network Intrusion in IoT Environment*,
IEEE TCE 71(4), 2025 (DOI 10.1109/TCE.2025.3614806).

The framework under study (AAD) is three gates in front of an intrusion detector:

```
flow -> [rule-based validator] -> [Random-Forest adversarial discriminator] -> [EIDS: MLP v CNN v LSTM] -> allow
```

**Status.** The CSE-CIC-IDS2018 reproduction (phases 1–7) is complete and archived
in [`archive/cicids2018/`](archive/cicids2018/README.md). The project is now moving
to the IoT dataset **CICIoT2023**, following the approved plan
[`docs/ciciot2023-implementation-plan.md`](docs/ciciot2023-implementation-plan.md):

| Milestone | What | State |
| --- | --- | --- |
| M0 | environment + data | done |
| **M1** | **CICIoT2023 data pipeline + leakage probe** | **done — see [`docs/m1-data-pipeline.md`](docs/m1-data-pipeline.md)** |
| M2 | baseline NIDS (MLP, CNN, LSTM) on CICIoT2023 | done — balanced acc. 95.3 / 95.2 / 94.9% (99% target not met; Random Forest reference 97.7%) — see [`docs/m2-baselines.md`](docs/m2-baselines.md) |
| M3 | validator redesign for window-mean features | done — benign FPR 0.97%; stops ≥ 99.98% of unconstrained attacks end to end; distribution family carries it — see [`docs/m3-validator.md`](docs/m3-validator.md) |
| M4 | realizable, defense-adaptive attack generator | next |
| M5 | discriminator changes + arms race | planned |
| M6 | adversarial training (fixed pool + in-loop Madry) | planned |
| M7 | packet-level (PCAP) realizability spot-check | planned |
| M8 | end-to-end adaptive evaluation | planned |

Scripts `02_`–`07_` still contain the phase 2–7 implementation written for the IDS2018
run. They are dataset-agnostic in shape and are migrated milestone by milestone; do not
treat their output on CICIoT2023 as final until the matching milestone is marked done.

## Setup

**1. Environment.** Python 3.10 (TensorFlow 2.13 has no wheels for 3.12+). On the
development machine Python lives at `D:\Python310` — see "Environment notes" below
for why it is not in `%LOCALAPPDATA%`.

```powershell
D:\Python310\python.exe -m venv ..\.venv
..\.venv\Scripts\python.exe -m pip install -r ..\requirements.txt
```

TensorFlow 2.13 is CPU-only on native Windows.

**2. Data.** CICIoT2023, the single merged CSV (`ciciot23.csv`, 13,754,096,319 bytes,
46,686,579 rows, 46 features + `label`), placed at:

```
aad/data/raw/ciciot23.csv
```

It is the 169 part files of the official release (CIC, University of New Brunswick,
<https://www.unb.ca/cic/datasets/iotdataset-2023.html>) concatenated into one file, as
distributed on Kaggle. Phase 1 refuses to run if the row count differs from the
published 46,686,579, so a truncated download fails immediately.

**3. Build the processed dataset.**

```powershell
python scripts\01_prepare.py --sample-frac 0.02   # smoke test -> data/smoke/  (needs the cache, see below)
python scripts\01_prepare.py                      # full run   -> data/processed/
python scripts\01b_probe_leakage.py               # leakage probe -> artifacts/reports/leakage_probe.md
python -m pytest tests\ -q                        # 116 tests, synthetic data only
```

The first `01_prepare.py` run streams the 13.75 GB CSV twice (~10 min) and caches the
sampled rows in `data/interim/ciciot_capped.parquet`; every later run, including smoke
tests, reads the cache and takes about a minute. `--rescan` forces a fresh read.

## Phase 1 (M1) in one paragraph

Every class is **deduplicated on the full 46.7M rows first** (at float32 precision:
39.8% of the file turns out to be repeated rows), then capped at **60,000 distinct
rows** chosen uniformly at random (seed 42); benign traffic is kept whole. That turns a
97.6%-attack dataset into a tractable 2.55M-row set (56.9% attack) without throwing
away any rare class. It is split 70/15/15 stratified on the 34 labels; 7 near-constant
columns are dropped and 16 heavy-tailed columns get a signed log1p (both decided on
train only); everything is MinMax scaled to [0,1] with the scaler fitted on train only.
Result: **39 features**, 1,783,537 / 382,186 / 382,187 rows. The full walkthrough, every
number the run produced, and the reasoning behind each choice are in
[`docs/m1-data-pipeline.md`](docs/m1-data-pipeline.md).

Outputs that every later phase reads:

| File | Contents |
| --- | --- |
| `data/processed/{train,val,test}.npz` | `X` float32 in [0,1]; `y` binary; `y_multiclass` (34); `y_category` (8) |
| `data/processed/feature_names.json` | feature order — models, validator and attacks must all match it |
| `data/processed/classes.json` | code → name for the 34 classes and 8 categories |
| `data/processed/transform.json` | log1p columns + MinMax parameters, to map rows back to raw units |
| `data/processed/scaler.pkl` | the fitted MinMaxScaler |
| `artifacts/reports/class_stats.{csv,md}` | Table I for CICIoT2023 |
| `artifacts/reports/feature_stats.csv` | per-feature tail statistics behind the log1p choice |
| `artifacts/reports/leakage_probe.{json,md}` | duplicates, one-feature separability, train/test overlap |
| `artifacts/reports/prepare_meta.json` | complete ledger of the run |

## Repository layout

```
aad/
  config/          one YAML per phase; config/data.yaml is the M1 pipeline
  src/aad/data/    loader (two-pass streaming), clean, split (+ signed log1p)
  src/aad/...      models, attacks, defense, evaluate - phases 2-7
  scripts/         01_prepare, 01b_probe_leakage, 02_..07_ phase entry points
  tests/           synthetic-fixture tests, no dataset needed
  docs/            plan, per-milestone walkthroughs, background explainers
  archive/cicids2018/   the completed IDS2018 reproduction (reports, README, configs, weights)
  data/            raw / interim / processed / smoke   (git-ignored)
  artifacts/       models, adversarial examples, reports
```

`docs/phase03-04-explained.md` and `docs/phases-1-4-walkthrough.md` were written for
the IDS2018 run. Their explanations of attacks, eps, and validator calibration still
apply; their numbers and file paths refer to the archive.

## Environment notes

- **Python is at `D:\Python310`**, installed from the official NuGet package
  (`python.3.10.11.nupkg`, PSF-signed). The python.org MSI installer fails when run
  from the Claude desktop app's shell (error 0x80070003): writes to `%LOCALAPPDATA%`
  are redirected, so the Windows Installer service cannot find the cached `core.msi`.
- **There is no git on the development machine.** Before M1 changed any code, a full
  snapshot of code, configs, docs and reports was zipped to
  `../backups/pre_m1_code_and_reports_2026-10-07.zip`.
