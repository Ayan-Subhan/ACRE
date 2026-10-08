# Plan: CICIoT2023 migration — training, realizable adaptive attacker, adversarial training, new gates

## Context

The AAD reproduction in `D:\base_imp\aad` (phases 1–7, CSE-CIC-IDS2018) is complete, and it surfaced four weaknesses that the FYP proposal is built around:
- **The data is not IoT.** CIC-IDS2018 is enterprise traffic (proposal gap #4).
- **The attacks are unrealistic.** Gradient attacks produce impossible flows such as "7.4 packets". The validator caught 100% of them through integrality alone (Table V), so phases 5–6 never mattered (Table IX).
- **Adversarial training did not produce robustness.** Fixed-pool hardening still collapsed to 0% under adaptive re-attack (Table VIII).
- **No attacker ever targeted the defense itself.** Every adversary in the experiments was defense-blind.

This plan moves the project to CICIoT2023 and builds:
1. A trained NIDS on that data.
2. A realizable, defense-adaptive attack generator, spot-checked at packet level.
3. In-loop (Madry) adversarial training, alongside the existing fixed-pool baseline.
4. A validator and discriminator redesigned for CICIoT2023's window-mean features.

**Decisions already made by the user:**
- Realism: feature-space constraints plus a PCAP spot-check on a sample.
- Adversarial training: in-loop constrained PGD, with fixed-pool kept as the baseline.
- LSTM: trained in the baseline; behind a flag in the EIDS.

**Ground rule:** CIC-IDS2018 stays runnable. Every script selects its dataset through `--data-dir` and a dataset config, so the two datasets can be compared side by side.

> **Status and deviations (updated 2026-10-07, end of M1).** M0 and M1 are done; the
> walkthrough with every number is `docs/m1-data-pipeline.md`. Where M1 departed from
> this plan, and why:
>
> 1. **Ground rule replaced: IDS2018 archived, not kept runnable.** At the start of M1
>    the user chose "Archive": IDS2018 results, README, configs and trained weights moved
>    to `archive/cicids2018/`; regenerable IDS2018 data deleted; IDS2018-only ingestion
>    code removed. Later milestones target CICIoT2023 only.
> 2. **One merged CSV, not 169 part files.** The download is the Kaggle-merged
>    `ciciot23.csv`, so `load_capped` became a two-pass streaming reader of one file
>    (`scan` → `select_capped` → `load_selected`), with an interim Parquet cache.
> 3. **Deduplication on the FULL file, at float32 precision.** Not in the plan's
>    detail. Exact float64 equality finds only 34 duplicates in 46.7M rows, yet left
>    2.8% of test rows byte-identical to a training row after scaling (twins differing
>    only in sub-float32 `IAT` jitter). Duplicates are therefore defined at the precision
>    the models see: 18,588,033 rows (39.81%) of the file are duplicates; overlap fell to 2.
> 4. **log1p columns chosen by a data-driven rule** (median in the bottom 2% of the MinMax
>    range, on train only) rather than the hand list above; it selects 16 columns.
> 5. **Near-constant columns dropped** (fewer than 100 non-mode train rows): DHCP, Telnet,
>    SMTP, IRC, cwr/ece flags, Drate. 46 → 39 features. M4's primitive set θ loses the
>    ECE/CWR flags accordingly.
> 6. **No single-feature leak.** The probe's strongest single feature is `IAT` (94.1%
>    binary balanced accuracy), below the 99% flag; no feature is dropped. `IAT`,
>    `Number`, `Weight` are named as capture artefacts to watch in M2/M4.
> 7. **Sample size as planned:** 2,547,910 rows → 1,783,537 / 382,186 / 382,187; 56.9% attack.
>
> **M2 (done, CPU only — see `docs/m2-baselines.md`).** Balanced accuracy MLP 95.29%,
> CNN 95.25%, LSTM 94.93%; FPR 2.1–3.1%. **The 99% target was not met.** Floods are at
> ~100%; Recon/Spoofing/Web/BruteForce are at 63–75%. The plan's category-weighting
> fallback raises those to 83–96% but takes FPR to 9.6%, so it was not adopted. A
> Random Forest reference reaches 97.68% (FPR 1.44%), so the gap is in the networks,
> not the features. No capture-artefact column is load-bearing (dropping
> IAT/Number/Weight: 95.35%). GPU/WSL2 paused at the user's request; training was on CPU.
>
> **M3 (done, see `docs/m3-validator.md`).** Deviations from the M3 section below:
> (1) flags and protocol indicators turned out to be strictly 0/1, so integrality covers 15
> columns rather than disappearing; (2) rules are declared as `ordering` / `equal` /
> `linear_le` / `product` (the `le` and `sum_le_one` kinds became `linear_le`, plus
> `equal` for Srate = Rate and IPv = LLC); 14 kept and 2 pruned as loose; (3) per-group
> distribution needed a low minimum (100 rows) after ARP was 100% rejected on the global
> profile. Results: benign FPR 0.97%; ≤ 0.02% of any unconstrained adversarial set passes
> the gate and fools its model; the distribution family carries the gate (5.95% sole
> catches; integrality and dependency 0% sole). The `IAT` drop proposed during M3 planning
> was then approved and carried out (below).
>
> **`IAT` dropped, M1–M3 re-run (2026-10-08).** `drop_columns: [IAT]` at the scan, so it
> no longer takes part in deduplication; the dataset was rebuilt (38 features; duplicates
> 40.37%, now 18.8M of them exact copies; 48,574 DDoS/DoS feature vectors share two labels),
> the baselines retrained on the GPU through WSL2 (29.5 min instead of ~2 h 54 min on CPU:
> MLP 95.25 / CNN 95.11 / LSTM 94.82% balanced accuracy, FPR 1.87–2.37%), and M3 re-run
> (FPR 1.03%, ≤ 0.02% pass-and-evade). 39-feature results archived in
> `artifacts/superseded/39features/`. Two corrections to earlier notes: `IAT` is a copy of
> `Number`, not a timestamp (`docs/ciciot2023-features.md`); and without `IAT` the Random
> Forest reference falls to 95.40%, level with the networks, so its earlier lead came from
> `IAT`. **Open before M4:** decide whether `IAT`'s real-gap component (the `Number` = 5.5
> rows) is genuine timing worth recovering as a properly scaled feature, or a capture
> fingerprint. This needs a diagnostic: re-extract `IAT` for the current sample and test it
> per `Number` level, and against capture order.

---

## M0 — Environment and data (½ day)

- **Rebuild `..\.venv`.** Its base interpreter, Python 3.10 (`...\Programs\Python\Python310`), is missing. Reinstall Python 3.10.11, then `pip install -r ..\requirements.txt`. Add `scapy` to `requirements.txt` for M7.
- **Download the CSVs.** Get CICIoT2023 `CSV/` (169 files, ~2.7 GB zipped, ~13 GB unzipped) from `cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/`. Extract to C: (D: has 36.5 GB free), and keep `config/data_ciciot2023.yaml` pointing at that path.
- **Defer the PCAPs.** Download only a few per-category PCAP files, and only when M7 starts.

## M1 — Data pipeline (Phase 1) (1–1.5 days, ~30 min compute)

**New: `config/data_ciciot2023.yaml`**
- 34-label `label_map`, where each entry carries `name`, `code`, `binary` and a new `category` (8-way).
- `label_column: label`, no `drop_columns`.
- `sampling: {cap_per_class: 60000, keep_all: [BenignTraffic]}`.
- `log1p_columns: [flow_duration, Header_Length, Rate, Srate, Drate, Tot sum, IAT, Covariance, Weight, Number]`.
- `split.stratify_on: multiclass`.

**Changes to `src/aad/data/loader.py`**
- Add `load_capped(raw_dir, files, cap, seed)`. It streams every CSV in chunks and keeps a seeded per-class reservoir capped at `cap`, so RAM stays well under 2 GB.
- The existing `load_file` and `load_all` stay for IDS2018. `01_prepare.py` chooses between them based on a `raw.mode: capped|full` key.
- Write `data/interim/ciciot_capped.parquet` once, so later runs skip the ~25-min CSV scan.

**Changes to `src/aad/data/clean.py` and `src/aad/data/split.py`**
- `normalise_labels` also emits `label_category`.
- Add a `log1p` step before `fit_scaler`.
- Store `log1p_indices` in `scaler.pkl`'s sidecar and in `prepare_meta.json`.

**Changes to `scripts/01_prepare.py`**
- `npz` files gain `y_category`.
- `feature_names.json` and `class_stats` work unchanged.

**New: `scripts/01b_probe_leakage.py`, three checks that must pass before M2**
1. Exact-duplicate rate per class.
2. A depth-3 tree per single feature. Any feature reaching >99% binary accuracy gets flagged, with IAT, Number and Weight as the expected suspects. Record the decision: drop the feature, or keep it with a caveat.
3. A test-vs-train byte-identical overlap check, reusing the README's leakage-probe approach.

Output goes to `artifacts/reports/leakage_probe_ciciot.json`.

**Change to `src/aad/evaluate.py`:** `TYPE_NAMES` becomes data-driven, loaded from `prepare_meta.json`. Add `per_category_recall` and `balanced_accuracy`. Update `scripts/06_train_eids.py:290`, which iterates `TYPE_NAMES`.

**Expected size:** ~2.55M rows → ~1.78M train / ~382k val / ~382k test, ~43% benign, 46 features before the constant-column drop.

## M2 — Baseline NIDS (Phase 2) (½ day, ~1.2 h compute)

- No architecture change. `models/mlp.py`, `models/cnn.py` and `models/lstm.py` already take `n_features`, and the 2-unit softmax is kept because the ART chain and `wrappers.wrap` depend on it.
- `config/models.yaml` becomes per-dataset: add `config/models_ciciot2023.yaml` with `class_weight: true`.
- Command: `02_train_baselines.py --data-dir data/processed_ciciot --config config/models_ciciot2023.yaml`.
- Reports carry balanced accuracy, benign FPR, and per-category and per-class recall beside Table III.
- **Target:** all three models above 99% balanced accuracy, with per-category recall stated. If the Web or BruteForce categories fall below ~80%, try `class_weight` per category before moving on.

## M3 — Validator redesign (Phase 4) (1.5–2 days, minutes of compute)

**Split the rule declarations by dataset**
- Move `ORDERING_RULES`, `PRODUCT_RULES`, `RATE_RULES` and `DURATION_COL` out of `src/aad/defense/validator.py` into `src/aad/defense/rules/cicids2018.py`.
- Add `src/aad/defense/rules/ciciot2023.py` for the new dataset.
- `analyzer.build_dependency_rules(feature_names, dataset)` picks the right module. `rules.json` records `dataset`.

**New rule kinds in `Validator.dependency_residual`.** These sit beside the existing `ordering`, `product`, `rate` and `nonnegative` kinds:

| kind | CICIoT2023 instances |
|---|---|
| `ordering` (reuse) | `Min ≤ AVG ≤ Max` |
| `product` (reuse) | `Tot sum ≈ AVG × Number` |
| `le` (new: a ≤ b) | `Srate ≤ Rate`, `Drate ≤ Rate`, `HTTP/HTTPS/SSH/Telnet/SMTP/IRC ≤ TCP`, `DNS/DHCP ≤ UDP`, `{fin,syn,rst,psh,ack,ece,cwr}_flag_number ≤ TCP` |
| `sum_le_one` (new) | `TCP + UDP + ICMP ≤ 1`, `ARP + IPv ≤ 1` (validate empirically) |
| `unit_interval` (new) | all flag fractions and protocol indicators within [0, 1] |

**Self-pruning rules.** The analyzer drops any candidate rule whose calibrated tolerance exceeds `DEPENDENCY_MAX_TOL`. It lists those rules under `excluded_loose` in `rules.json`, the same way `excluded_unverifiable` already works for integrality in `analyzer.py:195`. Rules are proposed declaratively, and the data decides which ones survive.

**Integrality stays as is.** `find_integer_columns` is empirical, and is expected to find only a few columns (Protocol Type, some indicators). This is a reported finding, not a bug.

**Conditional distribution family.** Benign IoT traffic is multimodal, so the median and MAD become per protocol group (TCP / UDP / ICMP / ARP / other, chosen by the dominant indicator). The threshold is still calibrated on benign validation rows at the FPR budget (`calibrate_distribution`).

**`Validator.to_raw` gains the log1p inverse:** `expm1` on `log1p_indices`, which are read from `rules.json` `scaling`.

**Differentiable twin for the attacker.** Add `validator_soft.py`, a TensorFlow re-implementation of the dependency and distribution residuals as hinge penalties, `relu(residual − tol)`. It imports the rule list and tolerances from `rules.json`, keeping the single-source-of-truth principle already used between the analyzer and validator. A test asserts that the numpy and TF residuals agree to 1e-5.

**Tests.** Rewrite the `tests/test_validator.py` fixtures as two parameterised sets: the existing IDS2018 synthetic fixtures, plus a CICIoT2023 set with violations such as `HTTP > TCP`, `Min > AVG` and an out-of-range flag fraction.

## M4 — Realizable, adaptive attack generator (Phase 3b) (3–4 days, ~1 h compute)

New package `src/aad/attacks/realizable/`, alongside the existing ART code. The existing code is kept, because it is the paper's "unconstrained" baseline.

### 4.1 Feature mutability spec — `constraints.py`

A table in `config/realism_ciciot2023.yaml` gives each of the 46 features a class:

| class | features | handling |
|---|---|---|
| `immutable` | Protocol Type, the protocol indicators (HTTP…LLC) | reset to the original value |
| `increase_only` | packet-size stats via padding, Header_Length, IAT, flow_duration | clamped to `≥ original` |
| `decrease_only` | Rate, Srate (throttling) | clamped to `≤ original` |
| `free` | Duration (TTL, 1–255), psh/urg/ece/cwr flag fractions (TCP only) | clamped to physical range |
| `derived` | Std, Variance, Covariance, Magnitue, Radius, Weight, Number, `*_count`, Tot sum | recomputed, never perturbed |

It also holds a **functional floor per category**:
- Floods (DDoS / DoS / Mirai): `Rate ≥ ρ·Rate_orig`, with ρ = 0.5 by default and swept.
- Web: padding only; payload must not shrink.
- Recon and BruteForce: delay allowed, bounded by a time-budget multiplier.

### 4.2 Traffic-primitive parameterisation — `primitives.py`

The attacker optimises a small vector **θ** of physical actions. It does not optimise the 46 features directly. θ contains:
- `pad_bytes ≥ 0` per packet
- `delay_s ≥ 0` per packet
- `ttl`
- PSH/URG/ECE/CWR set-fractions
- `tcp_opt_bytes ≥ 0`

A differentiable map `g(x_orig_raw, θ) → x_adv_raw`, written in TensorFlow, applies closed-form window-mean effects:
- Size stats: `AVG/Min/Max/Tot size += pad`
- `Tot sum += pad·Number`
- `Magnitue = sqrt(Magnitue² + 2·pad)`
- Std, Variance and Radius unchanged
- `IAT += delay`
- `Rate' = 1/(1/Rate + delay)`, and Srate likewise
- `flow_duration += delay·(Number−1)`
- `Header_Length += tcp_opt·Number`
- `Duration = ttl`
- Flag fractions blended toward 1 by the set-fraction

The output then goes through log1p → scaler → model, all in one TF graph.

Every adversarial example is realizable by construction, in the sense that it comes from an action an attacker can take. M7 checks that `g` matches the real extractor.

### 4.3 Attack suite — `attacks.py`

Every attack returns `(X_adv, θ, cost)`, where cost covers bytes overhead %, added latency, rate loss %, and whether the functional floor holds.

| id | knowledge | method |
|---|---|---|
| `art_<fgsm/bim/pgd/deepfool>` | white-box, unconstrained | existing `generate.py` (paper baseline) |
| `art_*_projected` | white-box | ART output, then projected onto the constraints. Reports what share of published-style attacks survive projection, i.e. reproduces Hasan et al.'s "80.3% invalidated" figure on this data |
| `prim_pgd` | white-box, single model | PGD on θ with sign steps and projection onto θ bounds |
| `prim_pgd_ens` | white-box, ensemble | loss = `max_m CE(m(x), benign)` (attack the weakest-margin member) |
| `adaptive_full` | white-box, defense-aware | `L = L_ens + λ_v·validator_soft(x) + λ_d·disc_surrogate(x)`. λ is chosen per sample by a binary search that keeps the smallest λ which passes the real gates. The success check always uses the real numpy validator and the real RF |
| `greybox_transfer` | grey-box | `prim_pgd_ens` crafted on surrogate MLP/CNN models trained on a disjoint 50% of the training data (different seed), then replayed against the real models |
| `blackbox_query` | black-box | decision-based random search over θ (θ is ≤ 8-dim, so this is cheap). Queries the full pipeline's allow/stop output; query budget 1k per sample, number of queries reported |

**Discriminator surrogate — `disc_surrogate.py`.** A small MLP distilled from the RF's `predict_proba` on the phase-5 dataset (BPDA-style). It gives `adaptive_full` a gradient through the forest. Distillation agreement with the RF is reported.

**Source rows — `select_attack_rows`, extended.** Stratify by `y_category`: 1,000 rows per category × 7 categories = 7,000. The fixed seed and shared indices are kept, because phases 5–7 rely on the pairing (`discriminator.load_cells` enforces identical `idx`).

**Script — new `scripts/03b_generate_realizable.py`.** It mirrors `03_generate_ae.py`: `--split`, `--models`, `--attacks`, `--force`, and resume-by-file. Output goes to `artifacts/adversarial_real/{attack}_{model}.npz`, using the same `.npz` schema plus `theta` and `cost`, so `discriminator.load_cells` reads it unchanged. Reports: `table4b_realizable.{csv,md}` (evasion and cost per category × attack × model) and `fig_cost_vs_evasion.png`.

**Two assertions that must fail the run**
1. Any `X_adv` violates the mutability spec, i.e. projection is idempotent: `‖P(x) − x‖ = 0`.
2. Any reported "evasion" fails the functional floor.

## M5 — Discriminator changes (Phase 5) (1 day, minutes of compute)

`src/aad/defense/discriminator.py`. The grouped-split machinery stays (it is correct). The changes:
- **Positives come from two sources:** the unconstrained ART cells (as now), and the realizable cells from `adversarial_real/`. A new `Dataset.strategy` field (`unconstrained | primitive | adaptive | query`) supports a **leave-one-strategy-out** protocol.
- **New protocol: leave-one-category-out.** For example, the forest never sees perturbed Web flows during training.
- **Threshold calibration.** Replace argmax-at-0.5 with a threshold set on clean *validation* rows at an FPR budget (default 0.5%), mirroring `analyzer.calibrate_distribution`. Store it next to `rf.joblib` in `discriminator_meta.json`.
- **Gate-overlap metric.** Generalise `05_train_discriminator.py:integrality_overlap` to the share of RF importance on columns used by any validator rule, so the redundancy finding is re-measured on the new data.
- **Arms-race rounds.** A new `--rounds N` flag (default 3). Each round:
  1. Retrain the forest including the previous round's `adaptive_full` outputs (train split only).
  2. Re-distil the surrogate.
  3. Re-attack.

  Catch rate per round goes to `table6b_arms_race.csv`. This shows whether the defense converges or the attacker keeps winning.

## M6 — Adversarial training of the IDS (Phase 6) (2 days, ~3–4 h compute)

**6a. Fixed-pool baseline (paper-faithful), existing code**
- Run `03b_generate_realizable.py --split train` for `prim_pgd` and `art_pgd_projected`, then `06_train_eids.py` with `adv_dir: artifacts/adversarial_real_train`.
- `models/eids.py` (`select_pool`, `build_augmented`, `or_ensemble`, `disagreement`) is reused unchanged.

**6b. In-loop constrained adversarial training (Madry), new**
- New `src/aad/models/adv_train.py`: an `AdversarialTrainer(keras.Model)` that overrides `train_step`.
  - For each batch it takes the attack rows (`y == 1`) and generates `prim_pgd` with `k = 5` steps against the **current weights**, using the same `g` and projection as M4 (shared import, so training and evaluation use one attacker).
  - Loss = `0.5·CE(clean batch) + 0.5·CE(adversarial attack rows, label = attack)`. Benign rows are never perturbed, because the attacker has no motive to perturb them.
- Initialise from the M2 baseline weights and fine-tune for 10 epochs. This is cheaper than training from scratch and keeps clean accuracy.
- **Ensemble-diversity option.** With `--ensemble-adv`, half of each batch's adversarial rows are crafted against the frozen *other* members (Tramèr et al., ensemble adversarial training), so members stop failing together.
- **Held out from training, so the report always has honest numbers:**
  - the `delay_only` primitive subset
  - `blackbox_query`
  - DeepFool (as now)
  - one whole category (default: Web), giving a zero-day check
- **Members.** MLP and CNN by default; LSTM with `--models mlp cnn lstm`. Report `MLP∨CNN` and `MLP∨CNN∨LSTM` side by side, as in the README's ensemble table.
- **Script.** New `scripts/06b_train_eids_inloop.py`. It reuses the evaluation half of `06_train_eids.py` (the Table VII clean and Table VIII adaptive blocks). Factor those blocks into `src/aad/eids_eval.py` so both scripts call the same code.
- **Compute (fine-tune, 10 epochs, ~1.78M rows):** MLP ~5 min, CNN ~45 min, LSTM ~1.5 h (optional).

## M7 — Packet-level spot-check (1.5–2 days, ~1 h compute)

New `scripts/09_pcap_realizability.py` and `src/aad/attacks/realizable/pcap.py`:
1. For each category, take ~200 flows/windows from the matching CICIoT2023 PCAP. Use CIC's released extractor from the dataset's `Supplementary Material`, with the windowing parameters the dataset used.
2. Apply the θ found in M4 with Scapy: pad the Raw payload by `pad_bytes`, shift timestamps by `delay_s`, set the TTL and flags, add TCP options.
3. Re-extract the features.
4. Report the **mapping fidelity**: per-feature relative error between `g(x, θ)` and the re-extracted features.
5. Score the re-extracted rows through the full pipeline and report the **realized evasion rate** against the feature-space evasion rate.

**Acceptance:** median per-feature error below 5% on mutable and derived features. Otherwise, fix `g` in `primitives.py` and re-run M4 for the affected primitives.

## M8 — End-to-end evaluation (Phase 7/8) (1 day, ~30 min compute)

- `scripts/07_pipeline.py`: add `--adv-dir` loops over `adversarial` (unconstrained) and `adversarial_real` (realizable). Add the hardened in-loop models as the `--eids inloop` choice.
- Keep the evaluation-fold logic in `rows_the_discriminator_trained_on`, so the discriminator is never scored on its own training rows.
- **New `table11_adaptive_pipeline.csv`** — per category × knowledge tier (white / grey / black):
  - evasion of the full pipeline
  - per-stage attribution (`Pipeline.decide`)
  - attacker cost
  - clean FPR of the pipeline
- **Ablation:** `ablate` and `marginal_contribution` in `defense/pipeline.py`, unchanged, run on both unconstrained and realizable attacks. This tests whether Table X's "no stage adds anything" survives on IoT data.
- **Optional cross-dataset check:** run the trained CICIoT2023 pipeline on a CICIoMT2024 sample (near-identical schema), with no retraining.

---

## Critical files

**Modify:**
- `src/aad/data/{loader,clean,split}.py`
- `scripts/01_prepare.py`
- `src/aad/evaluate.py`
- `src/aad/defense/{validator,analyzer,discriminator}.py`
- `src/aad/attacks/generate.py` (stratified `select_attack_rows`)
- `scripts/05_train_discriminator.py`, `scripts/06_train_eids.py`, `scripts/07_pipeline.py`
- `tests/test_validator.py`, `tests/test_attacks.py`

**New:**
- `config/{data,models,realism}_ciciot2023.yaml`
- `src/aad/defense/rules/{cicids2018,ciciot2023}.py`
- `src/aad/defense/validator_soft.py`
- `src/aad/attacks/realizable/{constraints,primitives,attacks,disc_surrogate,pcap}.py`
- `src/aad/models/adv_train.py`, `src/aad/eids_eval.py`
- `scripts/01b_probe_leakage.py`, `scripts/03b_generate_realizable.py`, `scripts/06b_train_eids_inloop.py`, `scripts/09_pcap_realizability.py`
- `tests/test_realizable.py`, `tests/test_adv_train.py`

**Reuse, don't rewrite:**
- `wrappers.wrap`, `wrappers.as_logits`, `generate.build_attack`, `generate.run_attack`, `generate.perturbation_norms`
- `discriminator.load_cells`, `build_dataset`, `split_random`, `split_leave_one_out`, `fit_and_score`
- `eids.select_pool`, `build_augmented`, `or_ensemble`, `or_ensemble_prob`, `disagreement`
- `pipeline.Pipeline`, `ablate`, `marginal_contribution`
- `analyzer._calibrate_dependencies`, `calibrate_distribution`
- `models/base.{compile_model, build_callbacks, set_seeds}`

## Timeline (single developer)

| Milestone | Dev time | Compute |
|---|---:|---:|
| M0 env + data | 0.5 d | ~30 min download |
| M1 data pipeline + probes | 1–1.5 d | ~30 min |
| M2 baselines | 0.5 d | ~1.2 h |
| M3 validator | 1.5–2 d | minutes |
| M4 realizable / adaptive generator | 3–4 d | ~1 h |
| M5 discriminator + arms race | 1 d | ~15 min |
| M6 adversarial training (6a + 6b) | 2 d | ~3–4 h |
| M7 PCAP spot-check | 1.5–2 d | ~1 h |
| M8 end-to-end evaluation | 1 d | ~30 min |
| **Total** | **~12–15 working days** | **~8–9 h CPU** |

## Verification

- **Unit tests.** `python -m pytest tests\ -v` stays green after every milestone. New tests (synthetic fixtures only, as the project already does):
  - the projection is idempotent
  - immutable features are never changed
  - monotone clamps hold
  - `g` with θ = 0 is the identity
  - numpy and TF validator residuals agree
  - in-loop `train_step` lowers adversarial loss on a toy model
  - a test-split guard: `06b` refuses an `adv_dir` built from test rows
- **Smoke run** after each milestone, on a 2% sample: `01_prepare.py --sample-frac 0.02` → `02 --epochs 2` → `03b --n-samples 50` → `05 --n-estimators 20` → `06b --epochs 1` → `07`. The whole chain must complete in under ~10 min.
- **Sanity checks on the full run:**
  - Clean balanced accuracy above 99%.
  - Validator clean FPR at or below its budget.
  - `art_*_projected` survival rate reported.
  - The `adaptive_full` success check always uses the real gates, not the surrogates.
  - Fixed-pool vs in-loop adaptive robustness reported side by side, so the README's Table VIII failure is either reproduced or fixed, with the numbers to show it.
- **Packet-level check:** M7 mapping-fidelity table within the acceptance threshold before any "realizable" claim goes into the report.
