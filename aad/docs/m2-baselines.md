# M2 — baseline NIDS on CICIoT2023, step by step

Milestone M2 of [`ciciot2023-implementation-plan.md`](ciciot2023-implementation-plan.md).
Input: the processed dataset from M1 ([`m1-data-pipeline.md`](m1-data-pipeline.md)) —
39 features, 1,783,537 / 382,186 / 382,187 rows, 56.9% attack.

Run date: 2026-10-07. Hardware: i5-12450H CPU only (see section 6 for why the RTX 3050
is not used).

> ## Update 2026-10-08: retrained on 38 features (no `IAT`), on the GPU (current state)
>
> Sections 1–7 describe the 39-feature CPU run of 2026-10-07, archived in
> `artifacts/superseded/39features/`. After `IAT` was dropped
> ([`ciciot2023-features.md`](ciciot2023-features.md)), the baselines were retrained
> unchanged (same architectures, schedule, seed and binary class weights) on an NVIDIA RTX
> 3050 Laptop GPU through WSL2 (`scripts/gpu.sh`). The current `artifacts/models/` and
> `artifacts/reports/table3_nids.md` are from this run.
>
> | model | balanced acc. | FPR | epochs | GPU time | s/epoch (GPU / CPU before) | before (39 f., CPU) |
> | --- | ---: | ---: | ---: | ---: | ---: | --- |
> | MLP | **95.25%** | **1.87%** | 30 | 9.1 min | 18.2 / 14.5 | 95.29% / 2.21% |
> | CNN | 95.11% | 2.21% | 27 | 8.4 min | 18.7 / 56.9 | 95.25% / 2.11% |
> | LSTM | 94.82% | 2.37% | 30 | 10.5 min | 20.9 / 282.8 | 94.93% / 3.08% |
>
> Total 29.5 min on the GPU, against 2 h 54 min on the CPU. The GPU speeds up the LSTM
> 13.5× (cuDNN kernel) and the CNN 3×; the tiny MLP is per-step-overhead bound and is
> not faster. (GPU kernels are not bit-identical to CPU ones, so comparisons between the
> two runs are approximate. Every comparison *within* this update is GPU vs GPU.)
>
> **Per category (MLP):** Benign 98.13 (was 97.79) · Recon 72.40 (73.67) · Spoofing 69.26
> (71.23) · Web 66.69 (69.71) · BruteForce 61.68 (65.46) · floods ≥ 99.98. Same balanced
> accuracy, slightly shifted operating point: fewer false alarms, a little less recall on
> the quiet categories.
>
> **Feature reliance, redone with correlated features permuted together** (|r| > 0.95:
> `Number + Weight`, `Rate + Srate`, `Std + Radius + Covariance`, …). The models rest on
> `rst_count`, `urg_count`, `flow_duration`, `Header_Length` (15–25 points each), and on
> `Number + Weight` (13–19 points). The ablation shows that dependence is not load-bearing:
> retraining the MLP **without `Number` and `Weight`** gives 95.23% (−0.01 points), FPR
> 1.73%. Full report: `artifacts/reports/feature_reliance.md`.
>
> **The reference forest changes the §4.3 conclusion.**
>
> | Random Forest (600k rows) | balanced acc. | FPR | Recon | Spoofing | Web | BruteForce |
> | --- | ---: | ---: | ---: | ---: | ---: | ---: |
> | with `IAT` (39 f.) | 97.68% | 1.44% | 88.46 | 86.24 | 89.58 | 84.69 |
> | **without `IAT` (38 f.)** | **95.40%** | **2.88%** | 76.99 | 73.42 | 79.83 | 70.92 |
>
> Without `IAT` the forest and the neural networks are level (95.40% vs MLP 95.25%), so the
> §4.3 claim that "the ceiling is the networks, not the features" was wrong. The forest's
> 2.4-point lead came almost entirely from `IAT`, which the networks never used (their
> scores are the same with or without it).
>
> A plausible mechanism: at the `Number = 5.5` level `IAT` holds a real gap (~0.006 s), but
> MinMax over a 1.7 × 10⁸ range squeezes those differences to ~10⁻¹¹. That is invisible to a
> network, while a tree can still split on it. **Open question:** is that signal genuine packet
> timing (worth recovering as a properly scaled feature) or a fingerprint of the capture
> session (a leak)? It needs a diagnostic before anything is changed; see the plan's
> status note.

---

## 1. What was run

| # | Command | What it does | Time |
| --- | --- | --- | ---: |
| 1 | `python scripts\02_train_baselines.py --smoke` | wiring check: 1 epoch on the 2% smoke set, writes only to `data/smoke/` | 87 s |
| 2 | `python scripts\02_train_baselines.py` | **the baselines**: MLP, CNN, LSTM on the full training split | 2 h 54 min |
| 3 | `python scripts\02_train_baselines.py --models mlp --class-weight category --tag catw` | experiment: per-category sample weights (plan's fallback for weak rare-class recall) | 5.8 min |
| 4 | `python scripts\02b_feature_reliance.py --n-rows 10000 --repeats 2 --reference-forest` | permutation importance, artefact-column ablation, Random Forest reference | 12.7 min |

Logs: `artifacts/reports/{train_run,train_catw_run,reliance_run}.log`.

## 2. Setup

**Architectures — unchanged from the IDS2018 reproduction** (`src/aad/models/`); only the
input width changed (68 → 39), and it is read from the data:

| model | layers | params |
| --- | --- | ---: |
| MLP | Dense 128 → 64 → 32 (ReLU, dropout 0.2) → softmax 2 | 15,522 |
| CNN | Conv1D 64×3 → MaxPool 2 → Conv1D 128×3 → GlobalMaxPool → Dense 64 → softmax 2 | 33,346 |
| LSTM | LSTM 64 over the 39 features as a pseudo-sequence → Dense 32 → softmax 2 | 19,042 |

All end in a 2-unit softmax, because the ART attacks of M4 differentiate a probability
vector (see `config/models.yaml`).

**Training — unchanged schedule:** Adam lr 1e-3, batch 1024, up to 30 epochs, early
stopping on validation loss (patience 4, best weights restored), learning rate halved
after 2 stagnant epochs (floor 1e-5), seed 42. Validation = the clean M1 val split.

**One change: binary class weighting is on** (`training.class_weight: binary`). The train
split is 56.9% attack, so the weights are mild (attack 0.88, benign 1.16). They keep the
loss from favouring "attack" on ambiguous rows, which would raise the benign
false-positive rate, the cost every later AAD gate adds to.

**Reporting additions** (`src/aad/evaluate.py`, `scripts/02_train_baselines.py`):
balanced accuracy next to plain accuracy (the class mix is not 50/50), per-category recall
(8 categories) next to per-class recall (34 classes), seconds per epoch, and a check
against the plan's acceptance target (balanced accuracy ≥ 99%).

## 3. Baseline results

Clean test set: 382,187 rows (217,460 attack, 164,727 benign). Full tables:
`artifacts/reports/table3_nids.md`; machine-readable: `baseline_metrics.json`.

| model | accuracy | **balanced acc.** | precision | recall | F1 | **FPR** | epochs | train time | s/epoch |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| MLP | 94.95% | **95.29%** | 98.23% | 92.80% | 95.43% | 2.21% | 28 (early stop) | 6.7 min | 14.5 |
| CNN | 94.88% | **95.25%** | 98.30% | 92.61% | 95.37% | **2.11%** | 30 | 28.5 min | 56.9 |
| LSTM | 94.65% | **94.93%** | 97.55% | 92.94% | 95.19% | 3.08% | 30 | 2 h 21 min | 282.8 |

**Detection rate per category** (for Benign: correctly passed = 100 − FPR):

| category | test rows | MLP | CNN | LSTM |
| --- | ---: | ---: | ---: | ---: |
| Benign | 164,727 | 97.79 | 97.89 | 96.92 |
| DDoS | 97,830 | 100.00 | 100.00 | 100.00 |
| DoS | 36,000 | 100.00 | 100.00 | 99.99 |
| Mirai | 27,000 | 100.00 | 100.00 | 100.00 |
| Recon | 32,946 | 73.67 | 72.95 | 75.44 |
| Spoofing | 18,000 | 71.23 | 70.77 | 70.16 |
| Web | 3,724 | 69.71 | 68.42 | 68.37 |
| BruteForce | 1,960 | 65.46 | 62.96 | 63.78 |

**The plan's 99% target is not met by any model.** What the numbers say:

1. **Floods are solved; the stealthy categories are not.** Every DDoS, DoS and Mirai class
   is detected at ≥ 99.94%. Every error is in Recon, Spoofing, Web and BruteForce. Their
   packet-window averages look like normal traffic. The hardest classes are close to a
   coin flip: Recon-OSScan 48–53%, Recon-PingSweep 47–55%, BrowserHijacking 55–57%,
   DNS_Spoofing 63–64%. Not every quiet attack is hard, though: VulnerabilityScan
   (also Recon) is detected at 99.96%.
2. **Three architectures, one ceiling.** MLP, CNN and LSTM land within 0.4 points of each
   other, so architecture is not the bottleneck among these three.
3. **The LSTM is the worst value again.** It took 21× the MLP's training time for lower
   balanced accuracy and the highest FPR, the same pattern as on IDS2018, where it
   contributed nothing but false positives to the OR ensemble.
4. **Why this is far below IDS2018 (99.99%) and the literature (99%+).** The M1 pipeline
   removed both things that inflate CICIoT2023 scores: 97.6% attack prevalence (trivial
   accuracy) and 40% duplicate rows (train/test copies). What remains is the honest
   difficulty of telling low-volume attacks from benign IoT traffic with window-mean
   features.

## 4. Experiments

### 4.1 Do the models lean on capture artefacts? (`02b_feature_reliance.py`)

> *Corrected 2026-10-08.* `IAT` was described below as "timestamp-like" and credited with
> 13–17 points of importance. Both overstate it. `IAT` is a 0.998-correlated copy of `Number`,
> and its permutation drop is inflated: shuffling it alone, with `Number` fixed, creates impossible
> rows. The ablation (−0.02 points) is the honest measure. `IAT` is dropped since 2026-10-08,
> `02b_feature_reliance.py` now permutes correlated features together, and the update at the top
> of this document has the 38-feature results. See [`ciciot2023-features.md`](ciciot2023-features.md).

The M1 leakage probe flagged `IAT` (timestamp-like; 94% balanced accuracy alone) and
`Number`/`Weight` (packet-window size) as possible capture artefacts. Two measurements:

**Permutation importance.** Shuffle one column in a fixed stratified test subsample
(9,990 rows), re-predict, record the drop in balanced accuracy (2 repeats). Top features,
in percentage points (full list: `artifacts/reports/feature_importance.csv`):

| feature | MLP | CNN | LSTM | mean |
| --- | ---: | ---: | ---: | ---: |
| `rst_count` | 28.0 | 27.8 | 20.2 | 25.3 |
| `urg_count` | 24.1 | 23.6 | 20.8 | 22.8 |
| `Header_Length` | 15.5 | 23.1 | 20.9 | 19.8 |
| `flow_duration` | 16.0 | 10.4 | 23.3 | 16.6 |
| **`IAT`** | 13.7 | 17.3 | 12.9 | 14.6 |
| `Number` | 1.0 | 2.6 | 6.4 | 3.3 |
| `Weight` | 1.5 | 2.4 | 0.0 | 1.3 |

**Ablation.** Retrain the MLP (same recipe, seed and CPU) without the suspect columns. The
full-feature control is the phase-2 MLP itself.

| variant | features | balanced acc. | FPR | Recon | Spoofing | Web | BruteForce |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| all 39 features | 39 | 95.29% | 2.21% | 73.67 | 71.23 | 69.71 | 65.46 |
| without `IAT` | 38 | 95.27% | 2.14% | 73.57 | 70.34 | 68.66 | 64.80 |
| without `IAT`, `Number`, `Weight` | 36 | **95.35%** | 2.13% | 73.89 | 71.05 | 71.78 | 66.79 |

**Reading the two together:**
- The models **do use** `IAT`: shuffling it costs 13–17 points.
- But they **do not need** it: removing it changes nothing (−0.02 points), and removing
  all three suspects is marginally *better* (+0.06). So the information in `IAT` is also
  carried by behavioural features, and the models just pick it up when it is offered.
- The models rest mainly on **behavioural** columns: RST/URG counts, header length,
  flow duration.
- Conclusion: **no capture artefact is load-bearing**, and the 39-feature set is kept
  for M3+. For M4, `IAT` still counts as a feature the attacker can shift.

### 4.2 Category weighting (the plan's fallback for weak rare-category recall)

The plan said: if Web or BruteForce recall stays below ~80%, try per-category class
weights. Mode `category`: per-row sample weights so each of the 8 categories carries equal
total weight, tempered by power 0.5. Resulting relative weights: Benign 0.29, DDoS 0.37,
DoS 0.61, Recon 0.64, Mirai 0.71, Spoofing 0.87, Web 1.90, BruteForce 2.62. Saved as
`artifacts/models/mlp_catw.keras`, reports `*_catw.*`.

| | baseline MLP | category-weighted MLP |
| --- | ---: | ---: |
| balanced accuracy | **95.29%** | 93.36% |
| FPR (benign flagged) | **2.21%** | 9.59% |
| Benign passed | **97.79** | 90.41 |
| Recon | 73.67 | **85.96** |
| Spoofing | 71.23 | **82.97** |
| Web | 69.71 | **96.13** |
| BruteForce | 65.46 | **90.15** |

**It is a trade-off, not a fix.** Rare-category recall jumps by 12–30 points, which
proves the features *do* contain the signal. But the benign false-positive rate quadruples
to 9.6%, because benign rows end up with the lowest weight of all (0.29). Low-volume attacks
and benign traffic overlap, and the weighting only moves the operating point along that
overlap. A 9.6% FPR is not deployable (every AAD gate adds to it), so **the binary-weighted
model stays the baseline**. Section 5 lists a better-designed variant.

### 4.3 Reference forest: is 95% the features or the networks?

A Random Forest (200 trees, balanced class weights) trained on a stratified 600k-row
subsample of the same train split, scored on the same test set:

| model | balanced acc. | FPR | Benign | Recon | Spoofing | Web | BruteForce | fit time |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| MLP (phase 2) | 95.29% | 2.21% | 97.79 | 73.67 | 71.23 | 69.71 | 65.46 | 6.7 min |
| **Random Forest** | **97.68%** | **1.44%** | **98.56** | **88.46** | **86.24** | **89.58** | **84.69** | 1.9 min |

**The ceiling is the networks, not the features.** With a third of the training rows,
the forest is better on every axis at once: +2.4 points balanced accuracy, a lower
FPR, and +15–20 points on every stealthy category. Unlike category weighting, it does
not buy recall with false alarms. The neural baselines are underfitting the boundary
between benign and low-volume attacks.

This matters for the thesis: the AAD framework's IDS is neural by design (its attacks
need gradients), and on honest IoT data it gives up ~2.4 points to a simple tree
ensemble before any adversary appears.

## 5. Decisions and open options

**Decided:**
- The **binary-weighted MLP / CNN / LSTM** in `artifacts/models/{mlp,cnn,lstm}.keras` are
  the M2 baselines that M3–M8 build on.
- All 39 features stay (section 4.1).
- The plan's 99% target is recorded as **not met**, with the reasons above.

**Open (cheap to try on CPU if the gap should be closed before M3):**
1. **Attack-only category weighting.** Keep benign/attack balanced at the binary level
   and reweight *within* attacks only, so benign is not starved (the cause of the 9.6%
   FPR in 4.2). One MLP run, ~6 min.
2. **More capacity.** E.g. MLP 512-256-128, which is still small and fast. One run,
   ~8 min.
3. **Threshold tuning on validation.** Choose the softmax threshold for a target FPR
   instead of argmax. No retraining needed.

## 6. Why the GPU was not used

The machine has an NVIDIA RTX 3050 Laptop GPU (4 GB). TensorFlow 2.13 (pinned for the whole
project) has no GPU support on native Windows; GPU support there ended at TF 2.10. WSL2 and
Ubuntu 22.04 were installed to run the same code with CUDA, but commands into WSL hung
from the automation shell, and the setup was paused at the user's request in favour of
finishing on CPU. The LSTM is where it hurts most (282.8 s/epoch on CPU, using only ~2.7 of
12 threads). Revisit before M6, where in-loop adversarial training repeats attack steps
inside every training batch.

## 7. Files M2 touched

| file | change |
| --- | --- |
| `config/models.yaml` | comments for CICIoT2023; `class_weight: binary` (was `false`); modes `false/binary/category`; `class_weight_power` |
| `scripts/02_train_baselines.py` | `--smoke`, `--class-weight`; balanced accuracy, per-category recall, s/epoch; 99% balanced-accuracy check; category sample weights |
| `scripts/02b_feature_reliance.py` | **new**: permutation importance, artefact ablation, reference forest |
| `src/aad/evaluate.py` | (from M1) `balanced_accuracy`, `per_category_recall`, data-driven class names |

**Outputs:** `artifacts/models/{mlp,cnn,lstm}.keras` (+ `_history.json`,
`_test_probs.npz`), `mlp_catw.keras`; `artifacts/reports/table3_nids.{csv,md}`,
`per_category_recall.csv`, `per_type_recall.csv`, `baseline_metrics.json`, the `*_catw`
equivalents, `feature_reliance.{json,md}`, `feature_importance.csv`.
