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
| M2 | baseline NIDS (MLP, CNN, LSTM) on CICIoT2023 | done — re-trained 2026-10-08 on 38 features (no `IAT`) on the GPU: balanced acc. 95.25 / 95.11 / 94.82%, FPR 1.87–2.37% (99% target not met; Random Forest reference 95.40%) — see [`docs/m2-baselines.md`](docs/m2-baselines.md) |
| M3 | validator redesign for window-mean features | done — re-run on 38 features: benign FPR 1.03%; ≤ 0.02% of any unconstrained attack set passes the gate and fools its model; distribution family carries it — see [`docs/m3-validator.md`](docs/m3-validator.md) |
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

**1b. Optional: GPU training through WSL2** (set up 2026-10-08). The same TF 2.13.1
stack runs on the NVIDIA RTX 3050 (4 GB) inside WSL2 Ubuntu-22.04. The venv lives on
the Linux filesystem at `~/aad-venv`, because a venv on `/mnt/d` is slow. CUDA 11.8 and
cuDNN 8.6 come from NVIDIA's pip wheels, so there is no system CUDA install. The only
driver needed is the normal Windows NVIDIA driver.

```bash
# one-time, inside Ubuntu-22.04
apt-get install -y python3.10-venv python3-pip
python3 -m venv ~/aad-venv
grep -vE "^(tensorflow|keras)" /mnt/d/base_imp/requirements.txt > /tmp/req.txt
~/aad-venv/bin/pip install -r /tmp/req.txt tensorflow==2.13.1 \
  nvidia-cudnn-cu11==8.6.0.163 nvidia-cublas-cu11==11.11.3.6 nvidia-cuda-runtime-cu11==11.8.89 \
  nvidia-cufft-cu11==10.9.0.58 nvidia-curand-cu11==10.3.0.86 nvidia-cusolver-cu11==11.4.1.48 \
  nvidia-cusparse-cu11==11.7.5.86 nvidia-cuda-nvcc-cu11==11.8.89 nvidia-cuda-cupti-cu11==11.8.87
```

Run any script on the GPU from Windows with `scripts/gpu.sh`. It sets the CUDA library
path (including `/usr/lib/wsl/lib` for `libcuda.so`), turns on memory growth for the
4 GB card, and runs from `aad/`:

```powershell
wsl -d Ubuntu-22.04 -- /mnt/d/base_imp/aad/scripts/gpu.sh scripts/02_train_baselines.py --models mlp
```

`.keras` files move freely between the two environments. Keras 2.13 names weight groups
with the OS path separator, so a model saved on Windows would not load on Linux (and
the reverse). `aad/models/base.py` patches this on import: it saves with `/` and loads
either separator. Every script that loads a model imports it. Verified 2026-10-08: all
four models in `artifacts/models/` load and predict on both Windows CPU and WSL GPU.

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
python -m pytest tests\ -q                        # 118 tests, synthetic data only
```

The first `01_prepare.py` run streams the 13.75 GB CSV twice (~10 min) and caches the
sampled rows in `data/interim/ciciot_capped.parquet`; every later run, including smoke
tests, reads the cache and takes about a minute. `--rescan` forces a fresh read.

> **Feature set (2026-10-08):** 38 features. `IAT` is dropped at the scan (`config/data.yaml: drop_columns`)
> because it is a copy of `Number`, not an inter-arrival time; see
> [`docs/ciciot2023-features.md`](docs/ciciot2023-features.md) for how CICIoT2023's features were
> produced. The 39-feature results are archived in `artifacts/superseded/39features/`.

## Phase 1 (M1) in one paragraph

Every class is **deduplicated on the full 46.7M rows first** (at float32 precision:
39.8% of the file turns out to be repeated rows), then capped at **60,000 distinct
rows** chosen uniformly at random (seed 42); benign traffic is kept whole. That turns a
97.6%-attack dataset into a tractable 2.55M-row set (56.9% attack) without throwing
away any rare class. It is split 70/15/15 stratified on the 34 labels; 7 near-constant
columns are dropped and 16 heavy-tailed columns get a signed log1p (both decided on
train only); everything is MinMax scaled to [0,1] with the scaler fitted on train only.
Result: **38 features** (after dropping `IAT`), 1,783,517 / 382,182 / 382,183 rows. The full walkthrough, every
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
