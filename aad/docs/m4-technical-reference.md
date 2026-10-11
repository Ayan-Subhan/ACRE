# M4 technical reference — every part, where it lives, why it is realizable, what to improve

Companion to [`m4-realizable-attacks.md`](m4-realizable-attacks.md). That document *explains* M4 and
its results in reading order. This one is the **reference**: one entry per component, each with
the exact file and line where it is implemented, what it does, what makes its output realizable,
how it differs from what came before (the AAD paper, our IDS2018 reproduction, the ART library,
the M4 plan), how it is tested, and what could be improved.

Line numbers refer to commit `9901d7a` (branch `m4-realizable`, 2026-10-10). Paths are relative to
`aad/` unless they start with `supplementary-CIC/`, which is CIC's material at the repository root
(git-ignored; see the README, setup step 2b). Numbered references in square brackets, such as [3],
are listed in §8.

---

## Contents

1. [Map of M4](#1-map-of-m4)
2. [Component reference](#2-component-reference)
   - 2.1 [Step 4.0: the 36-feature rebuild (D1)](#21-step-40-the-36-feature-rebuild-d1)
   - 2.2 [Decision thresholds (D2)](#22-decision-thresholds-d2)
   - 2.3 [Bootstrap intervals](#23-bootstrap-intervals)
   - 2.4 [What CIC's extractor computes (step 4.1)](#24-what-cics-extractor-computes-step-41)
   - 2.5 [The realism spec](#25-the-realism-spec)
   - 2.6 [Scaling and raw units](#26-scaling-and-raw-units)
   - 2.7 [The projection P](#27-the-projection-p)
   - 2.8 [Traffic primitives θ and g](#28-traffic-primitives-θ-and-g)
   - 2.9 [Targets, loss and the compiled step](#29-targets-loss-and-the-compiled-step)
   - 2.10 [Feature-space PGD](#210-feature-space-pgd)
   - 2.11 [Primitive PGD](#211-primitive-pgd)
   - 2.12 [Validator-aware attack and the soft validator](#212-validator-aware-attack-and-the-soft-validator)
   - 2.13 [Grey box: surrogate models](#213-grey-box-surrogate-models)
   - 2.14 [Black box: decision-based search](#214-black-box-decision-based-search)
   - 2.15 [ART projected (Table IV-c)](#215-art-projected-table-iv-c)
   - 2.16 [Source rows and window populations](#216-source-rows-and-window-populations)
   - 2.17 [The driver: 03b](#217-the-driver-03b)
   - 2.18 [Audit, tuning and summary scripts](#218-audit-tuning-and-summary-scripts)
   - 2.19 [Tests](#219-tests)
3. [What makes the attacks realizable, and where that stops](#3-what-makes-the-attacks-realizable-and-where-that-stops)
4. [How M4 differs from what came before](#4-how-m4-differs-from-what-came-before)
5. [Results in one table](#5-results-in-one-table)
6. [Possible improvements](#6-possible-improvements)
7. [Reproducing M4](#7-reproducing-m4)
8. [References](#8-references)

---

## 1. Map of M4

```
 data/processed/{val,test}.npz  ──►  source rows  (attacks.select_rows_per_category, 03b:317-319)
 artifacts/models/*.keras       ──►  Target(model, threshold)        (attacks.py:53, 02c thresholds)
 config/realism.yaml            ──►  RealismSpec ─► Projector  P     (constraints.py:96, :168)
                                                    └► Primitives g  (primitives.py:48)
 artifacts/rules.json           ──►  Validator (real)  +  SoftValidator (differentiable, M3)

                      Attacker (attacks.py:91)
   feat_pgd ─ prim_pgd ─ *_ens ─ adaptive (λ ladder) ─ greybox ─ blackbox
                      │
                      ▼  every saved row:  P-fixed-point guard + floor guard (03b:110-111)
          deployed verdict (softmax ≥ threshold)  +  real validator
                      │
                      ▼
 artifacts/adversarial_real/<split>_spec<X>/{attack}_{model}.npz   (readable by M5's load_cells)
 artifacts/reports/table4b_* (per run) · table4c_* (ART projected) · table4d_tiers (03d)
```

| file | role | new / changed in M4 |
| --- | --- | --- |
| `config/realism.yaml` | what an attacker can change, per column; specs A/B/C; floors | new |
| `src/aad/attacks/realizable/constraints.py` | `Scaling`, `RealismSpec`, the projection `Projector` (P) | new |
| `src/aad/attacks/realizable/primitives.py` | θ, the map g, cost, floor check | new |
| `src/aad/attacks/realizable/attacks.py` | the attack suite, row selection, populations | new |
| `src/aad/defense/validator_soft.py` | M3's differentiable validator: safe `to_raw`, tensor groups | changed |
| `src/aad/evaluate.py` | `threshold_for_fpr`, `bootstrap_ci` | changed |
| `scripts/02_train_baselines.py` | `--train-frac`, `--seed` (grey-box surrogates) | changed |
| `scripts/02c_calibrate_thresholds.py` | D2 thresholds | new |
| `scripts/03a_audit_realism.py` | measures what the spec assumes | new |
| `scripts/03b_generate_realizable.py` | runs every attack, guards, saves cells and reports | new |
| `scripts/03c_tune_realizable.py` | validation sweep | new |
| `scripts/03d_summarize_realizable.py` | cross-spec tables | new |
| `config/data.yaml` | `drop_columns: [IAT, Number, Weight]` | changed |
| `tests/test_realizable.py`, `test_attacks_realizable.py`, `test_evaluate.py`, `realizable_fixture.py` | 47 tests on synthetic data | new |

---

## 2. Component reference

Each entry has the same parts: **what**, **where**, **how**, **why it is realizable / correct**,
**differs from**, **tested by**, **improve**.

### 2.1 Step 4.0: the 36-feature rebuild (D1)

- **What.** `Number` and `Weight` dropped at the scan, next to `IAT`; M1–M3 rebuilt.
- **Where.** `config/data.yaml` (`drop_columns`, with the reasoning in its comment); the drop is
  applied inside `loader.scan` (M1 code, unchanged). Outputs of the 38-feature run:
  `artifacts/superseded/38features/` (with its own README).
- **How.** Rescan of the 13.75 GB CSV (pass 1: 251 s). The cache fingerprint includes
  `drop_columns`, so the stale cache was rebuilt automatically (`scripts/01_prepare.py:75`,
  `_fingerprint`).
- **Why correct.** Both columns encode the extractor's packet-window size, which CIC set *per
  class* (100 packets for floods and `VulnerabilityScan`, 10 for the rest [2]). Kept as
  attacker-immutable columns, they would make floods unevadable through a capture setting rather
  than through the defense. The rebuild selected the **same 2,547,882 rows and splits**, so the
  36- and 38-feature results compare like for like.
- **Differs from.** The original plan kept them as attacker-immutable columns; decision D1
  (`m4-plan.md` §2) dropped them.
- **Tested by.** `tests/test_data.py` (M1) still passes. The like-for-like check is
  `artifacts/reports/prepare_run.log` (same kept rows as `superseded/38features`).
- **Improve.** The window size still leaks through every statistic it shapes: flood recall fell
  only to 98.6–99.99%. The real fix is re-extracting all classes with one window size, which needs
  the PCAPs (548 GB) and CIC's extractor (§2.4).

### 2.2 Decision thresholds (D2)

- **What.** Each model's operating point: the smallest threshold with ≤ 2% FPR on validation
  benign rows.
- **Where.** `src/aad/evaluate.py:108` (`threshold_for_fpr`); `scripts/02c_calibrate_thresholds.py:61`
  (`main`) → `artifacts/models/thresholds.json`, `artifacts/reports/thresholds.md`.
- **How.** Benign validation scores sorted in descending order; the threshold is placed just above
  the (k+1)-th highest score, where k = ⌊fpr·n⌋, so at most k rows are flagged. `np.nextafter`
  makes it exact under ties.
- **Why correct.** Calibrated on validation only; test only measures it (test FPR 1.93–1.96%).
- **Differs from.** M2 and our IDS2018 reproduction used argmax (0.5). M4 judges every evasion at
  these thresholds.
- **Tested by.** `tests/test_evaluate.py:15` (budget met and tight), `:25` (ties at a saturated
  softmax).
- **Improve.** One **pipeline-wide** budget: the OR-ensemble at 2% per member flags 3.27%, plus the
  validator's 1.01%. Allocate members' budgets jointly (M8).

### 2.3 Bootstrap intervals

- **What.** 95% percentile-bootstrap interval for every rate in the M4 tables.
- **Where.** `src/aad/evaluate.py:123` (`bootstrap_ci`), called by `03b:152` (`summarise_cell`)
  and `03d`.
- **How.** 2,000 resamples of the boolean outcome, seeded.
- **Tested by.** `tests/test_evaluate.py:33`, `:40`.
- **Improve.** For rates near 0 or 1 (floods), a Wilson or Clopper–Pearson interval is better
  behaved than the percentile bootstrap.

### 2.4 What CIC's extractor computes (step 4.1)

- **What.** The semantics of each CSV column, read from CIC's code (read, not run).
- **Where (CIC's files).**

  | finding | source |
  | --- | --- |
  | flows keyed by the **sorted** 5-tuple | `supplementary-CIC/pcap2csv/pcap2csv/Feature_extraction.py:279-280` (UDP), `:324-325` (TCP) |
  | `flow_duration` = last − first timestamp of the flow so far | `Supporting_functions.py:35-58` (`get_flow_info`, `duration = duration[-1] - duration[0]` at `:53`) |
  | `Rate` = flow packets / `flow_duration`; `Srate` from the same count; `Drate` from a reverse key that never exists | `Feature_extraction.py:358-361`; `Supporting_functions.py:106-132` (`get_src_dst_packets`, reverse key at `:124`) |
  | per-flow flag counters | `Supporting_functions.py:89-104` (`compare_flow_flags`); the per-flow dictionary is commented out at `Feature_extraction.py:337-346` |
  | `Header_Length`: the flow's byte total (strong hint) | `Supporting_functions.py:40-41`, debug print labelled "header length" at `:56` |
  | `Magnitue`/`Radius`/`Covariance`/`Variance`/`Weight` from in/out lists filled with the same packets | `Dynamic_features.py:22-43`; the list filling, commented out, at `Feature_extraction.py:160-170` |
  | per-packet frame size, then window statistics | `Feature_extraction.py:456` (`Tot size`), `:475-517` (the 10-row window loop) |

- **Why it matters.** The models' four most-used features are **per-connection running totals**,
  which an attacker controls by keeping connections alive or opening fresh ones. That is the basis
  of specs B and C (§2.5).
- **Caveat.** The release is **not** the exact version that produced the CSV: it lacks 9 of the
  CSV's columns, gives `Number` = 10, and would average the flags into fractions. The logic above is
  what explains the CSV's quirks (`Srate == Rate` exactly, `Drate ≈ 0`, `Magnitue² ≈ 2·AVG`); the
  exact CSV-producing code is not public.
- **Recorded in.** `docs/ciciot2023-features.md` §4; `docs/m4-realizable-attacks.md` §2.
- **Improve.** Ask CIC for the version that produced the CSV. Failing that, M7 re-extracts a sample
  with this release and compares column by column.

### 2.5 The realism spec

- **What.** For each of the 46 raw columns, what a traffic-level attacker may do with it.
- **Where.** `config/realism.yaml` (classes `:15-98`, size cap `:99`, flow-age specs `:111-114`,
  `max_slowdown` `:124`, floors `:126-130`); parsed by `constraints.py:96` (`RealismSpec`),
  `:111` (`from_dict`: every column classified exactly once, unknown classes and derived kinds
  rejected), `:158` (`rate_floor`).
- **How.**

  | class | columns | rule |
  | --- | --- | --- |
  | immutable | protocol, 7 flags, 13 indicators, `Std`, `Radius`, `Covariance`, `Variance`, `Number`, `Weight`, `IAT`, `Drate` | = original |
  | increase_only | `Min`, `AVG`, `Max`, `Tot size` | [orig, max(orig, 1514 B)] |
  | decrease_only | `Rate` | [floor·orig, orig]; spec A: immutable |
  | free_bounded | `Duration` (mean TTL) | [1, 255], widened to include the original |
  | flow_age | `flow_duration`, `Header_Length`, 5 `*_count` | A: ×1 · B: ×1…5 · C: ×0.2…5 |
  | derived | `Srate`, `Tot sum`, `Magnitue` | recomputed (§2.7) |

  Floors: floods keep ≥ 50% of their rate. Others have no floor, but the primitive attacker may not
  slow down more than 20×.
- **Why realizable.** Each class is a physical statement about the attacker's own packets: padding
  adds bytes; throttling only slows down; the attacker sets its own TTL; it cannot change its
  protocol or the flags its attack needs; connection lifetime follows from how it manages its
  connections (§2.4).
- **Differs from.** The plan had flags as "set-fractions" (they are 0/1), `IAT` as a delay knob
  (dropped), and only specs A/B. The AAD paper and our IDS2018 phase 3 have no spec at all: every
  feature is free within [0, 1].
- **Tested by.** `tests/test_realizable.py:67` (all 46 raw columns classified), `:72` (duplicate
  class rejected), `:79` (unclassified feature rejected), `:88` (floors by category).
  Measured against the data by `scripts/03a_audit_realism.py` → `artifacts/reports/realism_audit.md`.
- **Improve.** See §6.1: handshake cost of churn; variable-size padding (would free `Std`, `Radius`,
  `Covariance`); a per-protocol size cap; the attacker's share of a window's packets (§2.8).

### 2.6 Scaling and raw units

- **What.** The exact inverse and forward phase-1 transforms (signed log1p on 16 columns, then
  MinMax), differentiable.
- **Where.** `constraints.py:65` (`Scaling`, reads `transform.json` or a rules.json `scaling`
  block); `:227` (`to_raw`); `:234` (`to_scaled`).
- **How / why correct.** `to_raw` uses a **safe where** (`constraints.py:231`): `expm1` only ever
  sees the log1p columns. Without it, a non-log column above ~709 overflows in the discarded
  branch, and inf × 0 makes every gradient NaN. That happened in the M4 smoke run, and the same bug
  was in M3's `validator_soft.py` (fixed at `:68`).
- **Tested by.** `tests/test_realizable.py:96` (agrees with the validator's numpy `scaled_to_raw`
  to 10⁻¹²); `:294` and `tests/test_validator_soft.py:98` (finite gradients with a large linear
  column; both fail without the fix).

### 2.7 The projection P

- **What.** Maps any candidate row to the nearest row the spec allows, given the original row.
  "Realizable" is defined as "a fixed point of P".
- **Where.** `constraints.py:168` (`Projector`), `:241` (`project_raw`), `:294` (`project`),
  `:302` (`raw_to_output`), `:322` (`violation`), `:330` (`assert_realizable`),
  `:341` (`load_projector`).
- **How** (`project_raw`, in raw units):

  | step | line | rule |
  | --- | --- | --- |
  | immutable | `:248` | = original |
  | increase_only | `:250` | clamp to [orig, max(orig, cap)] |
  | ordering | `:252-261` | `Min ≤ AVG ≤ Max`, allowing each row its own original slack |
  | decrease_only | `:262` | clamp to [floor·orig, orig] |
  | free_bounded | `:264-267` | clip to the bounds widened to include the original |
  | flow_age | `:268-271` | clamp to [min·orig, max·orig] |
  | representable | `:273-274` | clip every base column to what scaled 0…1 can represent |
  | derived | `:276-290` | `Srate = Rate`; `Tot sum = Tot sum₀·AVG/AVG₀`; `Magnitue = √(Mag₀² + 2·ΔAVG)`; exactly the original when the base did not move |

  Spec A also moves `Rate` into the immutable set (`:193`): `Rate` = connection packets / age, so
  freezing the connection freezes the rate.

  `raw_to_output` (`:302-317`) maps back to scaled units. Columns P did not change keep their
  *exact* input value, through a **straight-through** substitution (`:317`): exact value forward,
  gradient of the computed value backward. A plain `tf.where` cut the gradient, and at θ = 0 the
  primitive attack never moved.
- **Why realizable.** Every rule in §2.5 is enforced. P is **idempotent** and the **identity on
  clean rows** (bit-exact on every real val and test row, all three specs). A projected row
  satisfies the validator's integrality and dependency families by construction: flags untouched,
  `Srate = Rate`, ordering kept.
- **Differs from.** ART clips each feature to a fixed box [7]. P is relative to each row's own
  original, couples columns, and depends on the row's category (floors). Constrained-attack
  frameworks [9] express such constraints generically; P encodes this extractor's semantics.
- **Tested by.** `tests/test_realizable.py:108` (fixed points), `:115` (idempotent), `:125`
  (immutables), `:134` (flow-age per spec), `:155` (monotone clamps, floors, TTL), `:174` (extractor
  invariants), `:188` (derived), `:200` (guard refuses an unprojected row), `:283` (NaN is never
  realizable), `:316` (capture quirks are fixed points), `:334` (spec A freezes `Rate`).
- **Improve.** P is a sequence of clamps, not a minimum-distance projection. With coupled
  constraints (ordering, derived columns) the clamp order decides the result. A true Euclidean
  projection (a small QP per row) would make "nearest" exact. In specs B/C, `Rate` and
  `flow_duration` are clamped independently, which is looser than physics (`Rate × duration` =
  packets); the primitive attacker couples them, the feature-space attacker does not (§3).

### 2.8 Traffic primitives θ and g

- **What.** Four physical knobs per row and a differentiable map from knobs to features.
- **Where.** `primitives.py:42` (`THETA`), `:48` (`Primitives`), `:66` (`bounds`), `:90`
  (`apply`, i.e. g), `:118` (`cost`, from rows), `:143` (`floor_ok`).
- **How.** `pad` adds bytes to `Min/AVG/Max/Tot size`; `dttl` shifts the mean TTL; `slow`
  multiplies `Rate` by (1 − slow) and, in B/C, divides `flow_duration` by it; `stretch` multiplies
  every flow-age column by (1 + stretch). Then `project_raw` (no detour through scaled units, which
  would add round-trip noise). θ = 0 is the identity. Spec A bounds `slow` and `stretch` to 0.
- **Why realizable.** Every output of g goes through P, so it is a fixed point. Its closed forms
  follow the extractor's arithmetic (§2.4). The **assumptions** to verify in M7 are listed in
  `primitives.py:1-40` and in `m4-realizable-attacks.md` §12.
- **Differs from.** The plan's g (`m4-plan.md` §3.2) had 4 knobs, but with `IAT`, flag fractions
  and `Tot sum = AVG × Number`, all now gone.
- **Tested by.** `tests/test_realizable.py:212` (θ = 0 identity), `:219` (realizable output),
  `:229` (closed forms), `:253` (bounds per spec and floor), `:270` (differentiable in θ).
- **Improve.** Padding is assumed to reach every packet of the window, including the victim's
  replies. A per-direction model (attacker vs victim packets) would make padding, TTL and
  `Magnitue` more faithful. Connection churn should add handshake packets (§6.1). θ could include
  discrete actions (TCP options, PSH/URG toggles).

### 2.9 Targets, loss and the compiled step

- **What.** The deployed models, and the quantity every gradient attack minimises.
- **Where.** `attacks.py:53` (`Target`), `:62` (`tau` = logit of the threshold), `:76`
  (`make_target`, logits view via `wrappers.py:37` `as_logits`), `:110` (`SUCCESS_MARGIN`), `:112`
  (`_margins`), `:121` (`_step_fn`), `:154` (`_won`), `:181` (`_finite`).
- **How.** Per member, margin = (logit_attack − logit_benign) − logit(threshold); ≥ 0 means
  "detected". Loss per row = relu(max over members (margin) + κ), κ = 0.1, plus λ × soft-validator
  penalty. This is a Carlini–Wagner-style margin loss [5] with the worst member, so success means
  fooling every member. `_step_fn` compiles, with `tf.function`, one step that returns both the
  gradient *and* the worst margin at the current point. The in-loop success check reuses that
  forward pass, and the real validator is consulted only for rows that already fool the models.
  `_finite` raises on any non-finite gradient (`sign(NaN)` once poisoned θ).
- **Why correct.** Gradients on **logits** avoid softmax saturation, which froze 45% of the MLP's
  rows in M3. The in-loop check only decides when a row stops being optimised; every saved row is
  re-judged by the deployed softmax models and the real validator (`03b:106`).
- **Differs from.** ART attacks optimise cross-entropy on the softmax [7]. Phase 3 ran DeepFool on
  logits only. Compiling made the suite **69–134× faster** with identical results (§2.18).
- **Improve.** An APGD-style adaptive step size with momentum [11] instead of fixed signed steps.
  A loss that minimises attacker cost once evasion is reached (today: stop at first success).

### 2.10 Feature-space PGD

- **What.** PGD in scaled feature space with P after every step: the strongest attacker the spec
  allows.
- **Where.** `attacks.py:191` (`_feat_run`), `:210` (`feat_pgd`: batching and restarts).
- **How.** Signed step of 0.01; clip to [0, 1]; P; stop a row at its first success. Ten restarts
  from random realizable points (a uniform draw, then projected).
- **Why realizable.** Every iterate is a P fixed point.
- **Differs from.** PGD [4] in ART projects onto an L∞ ball. Here the feasible set is the realism
  spec and there is no ε: distance is reported as attacker *cost* instead.
- **Tested by.** `tests/test_attacks_realizable.py:88`, `:149` (restarts only add successes).
- **Improve.** It treats coupled columns independently within their bounds (an upper bound,
  §2.7). A cost-aware variant would report the cheapest evasion, not the first found.

### 2.11 Primitive PGD

- **What.** PGD on θ through g: the realistic white-box attacker.
- **Where.** `attacks.py:236` (`_prim_run`), `:256` (`prim_pgd`).
- **How.** Signed step of 5% of each θ range, clipped to the box; 10 restarts from uniform θ.
- **Why realizable.** Output = g(θ), a P fixed point.
- **Tested by.** `tests/test_attacks_realizable.py:96`, `:149`.
- **Improve.** θ has only 4 dimensions, so a grid or CMA-ES search per row is cheap and immune to
  the local optima that restarts had to fix.

### 2.12 Validator-aware attack and the soft validator

- **What.** PGD loss + λ × the differentiable validator penalty, on a λ ladder (0, 0.1, 1, 10, 100).
- **Where.** `attacks.py:288` (`adaptive`); the rows that get the next rung are selected at `:323`
  (`blocked`: fooled the models, stopped by the validator). Soft validator:
  `src/aad/defense/validator_soft.py:40` (`SoftValidator`), `:134` (`penalties`), `:147` (`total`);
  groups accepted as a tensor at `:125-131`.
- **How.** Each family's penalty is zero exactly when the hard rule passes (range, dependency,
  distribution). Integrality uses sin²(πx). The protocol group is fixed from the input and held
  constant, which is the BPDA idea [6].
- **Why realizable.** Same projection as above; the soft penalty only shapes the search.
- **Differs from.** The plan's per-row binary search on λ. The full ladder cost 27–55 min per cell
  for 0–2 extra rows, because a penalty cannot help rows that never fooled the models.
- **Tested by.** `tests/test_attacks_realizable.py:107` (an unaware attack trips the validator; the
  ladder fixes it); `tests/test_validator_soft.py:53` (zero penalty ⇔ hard pass).
- **Result.** The validator stops 6–14% of model-fooling rows; the aware attacker wins a third of
  those back.

### 2.13 Grey box: surrogate models

- **What.** The adaptive attack run on the attacker's own MLP + CNN, trained on a random 50% of the
  training data (seed 7), then judged on the real models.
- **Where.** `scripts/02_train_baselines.py:128` (refuses `--train-frac`/`--seed` without `--tag`,
  protecting the baselines), `:145-150` (subsample); `03b:88` (`surrogate_thresholds`: the
  attacker calibrates its own thresholds the same way); judged on real models at `03b:106` via
  `target_names`.
- **Why realizable.** Same P and g.
- **Improve.** The surrogates share architecture and recipe with the real models: a strong grey
  box. A weaker one (another architecture, other data) would bound transferability from below.
  An ensemble of surrogates usually transfers better.

### 2.14 Black box: decision-based search

- **What.** θ search seeing only allow/stop (validator, then the three models).
- **Where.** `attacks.py:331` (`blackbox`); the compiled decision at `:348`; uniform search
  `:364-369`; refinement toward θ = 0 afterwards.
- **How.** 70% of 1,000 queries per row: uniform θ in the box until allowed. 30%: a (1+1) step
  that shrinks θ toward cheaper traffic while staying allowed. Queries-to-success recorded.
- **Why realizable.** g(θ) only.
- **Differs from.** Decision-based attacks such as the Boundary attack [8] walk along the decision
  boundary in input space. This one searches the 4-dimensional physical action space, which keeps
  it realizable and cheap.
- **Tested by.** `tests/test_attacks_realizable.py:121`.
- **Improve.** Use the remaining queries smarter (boundary-following in θ space, or CMA-ES), and
  report evasion against the query budget (curves at 10/100/1000).

### 2.15 ART projected (Table IV-c)

- **What.** The 12 phase-3 ART sets (FGSM [3], BIM [12], PGD [4], DeepFool [13]) passed through P.
- **Where.** `03b:185` (`run_art_projected`) → `artifacts/reports/table4c_projection_spec{A,B,C}.md`;
  the ART sets come from `scripts/03_generate_ae.py` and `src/aad/attacks/generate.py:72`
  (`build_attack`).
- **How.** Per set: share of rows that are not P fixed points; evasion and pass-and-evade before
  and after projection, on rows the model detected clean.
- **Result.** 82–100% unrealizable; PGD vs CNN 99.85% → 2.4/6.1/10.8% (A/B/C).
- **Improve.** Also project *during* the ART attack (a projected-ART baseline), to separate "ART's
  direction was wrong" from "ART's last step was not projected".

### 2.16 Source rows and window populations

- **Where.** `attacks.py:413` (`select_rows_per_category`), `:405` (`window_population`, with the
  100-packet classes at `:401-402`); used at `03b:317-319`. The row index is saved as
  `source_rows.npy` (not `.npz`: M5's `load_cells` reads every `.npz` as a cell).
- **How.** 900 rows per attack category, seed 42, only rows **all three** models detect at their
  thresholds (BruteForce has 911, which sets the 900).
- **Why correct.** "Evasion" always means turning a detected attack into a missed one, with equal
  denominators across categories.
- **Differs from.** Phase 3: 5,000 random attack rows (`generate.py:51`), including rows the model
  already missed.
- **Tested by.** `tests/test_attacks_realizable.py:131`, `:143`.

### 2.17 The driver: 03b

- **Where.** `scripts/03b_generate_realizable.py`: `ALL_ATTACKS` `:67`, `STRATEGY` `:69`,
  `load_targets` `:80`, `evaluate_cell` `:106`, `save_cell` `:143`, `summarise_cell` `:152`,
  `main` `:242`, `--flood-floor` `:262`.
- **Guards** (stop the run): every saved row must be a P fixed point (`:110`) and keep its
  functional floor (`:111`); thresholds and rules must match the current feature set (checked in
  `main`).
- **Outputs.** `artifacts/adversarial_real/<split>_spec<X>[_floor<ρ>]/{attack}_{model}.npz` (the
  phase-3 schema plus `theta`, `cost_*`, `passes_validator`, `floor_ok`, per-model detection, and
  `strategy` and `tier` in `meta`), plus `table4b_realizable_*.{csv,md}` and
  `realizable_metrics_*.json`.

### 2.18 Audit, tuning and summary scripts

| script | what | key result |
| --- | --- | --- |
| `scripts/03a_audit_realism.py:41` | measures every relation and bound the spec assumes, on 400k train rows | `Srate = Rate` exact; `Magnitue² ≈ 2·AVG` (0.28% median); 20% of rows already above the 1,514 B cap |
| `scripts/03c_tune_realizable.py:47` (`GRID`) | steps × step size × restarts on 700 val rows | steps converged at 100; 10 restarts (feature 10.4 → 12.4%, primitive 5.0 → 7.7%) |
| `scripts/03d_summarize_realizable.py:30` (`ENS_CELLS`) | cross-spec Table IV-d, levers, costs, floor sweep | `artifacts/reports/table4d_tiers.md` |

### 2.19 Tests

| file | tests | covers |
| --- | ---: | --- |
| `tests/test_realizable.py` | 22 functions (36 cases with parametrisation) | spec, units, P, g, regressions |
| `tests/test_attacks_realizable.py` | 7 | every attack on a hand-built toy IDS and toy validator |
| `tests/test_evaluate.py` | 4 | thresholds, bootstrap |
| `tests/test_validator_soft.py` | +1 | large-linear-column regression |

The whole suite: **166 tests** (`python -m pytest tests -q`). Every M4 bug fix has a test that
fails without it (verified for the NaN fix by reverting it).

---

## 3. What makes the attacks realizable, and where that stops

**The guarantee M4 gives (feature space).** Every saved adversarial row:
1. is a fixed point of P (checked at save time, `03b:110`), so it obeys every rule of
   `realism.yaml`. Its protocol, flags and indicators are the attack's own; its sizes only grew
   (≤ 1,514 B); its rate only fell, not below the category's floor; its TTL is in [1, 255]; its
   connection-lifetime columns moved only as the spec allows; its derived columns agree with
   their bases;
2. keeps its functional floor (`03b:111`);
3. was produced by an attacker that is limited to its own packets (§2.5).

**What M4 does not guarantee (problem space).** Pierazzi et al. [10] distinguish *feature-space*
attacks from *problem-space* attacks, where a real object (here, a packet capture) must exist whose
extracted features are the adversarial row. M4 gives feature-space realizability under an
extractor-informed spec. Problem-space realizability needs M7, which applies θ to real packets and
re-extracts. Known gaps until then:

| gap | effect | where to fix |
| --- | --- | --- |
| connection churn adds TCP handshakes, not modelled | spec C overstates the churn attacker | `primitives.py:90` (add handshake packets), M7 |
| padding assumed to reach every packet in the window, including replies | size statistics may move less than modelled | per-direction g, M7 |
| `Rate` and `flow_duration` clamped independently in specs B/C | the feature-space attacker is looser than physics | a coupled clamp in `project_raw` (`constraints.py:262-271`) |
| CIC's released extractor ≠ the CSV's version (§2.4) | column semantics inferred, not certain | CIC's exact code, or M7's comparison |

This is why every headline is a **range** (spec A = lower bound of a packet-level attacker,
spec C = upper estimate of a connection-managing one) and why "realizable" in the thesis should
read "realizable in feature space under the stated spec".

---

## 4. How M4 differs from what came before

| aspect | our reproduction of the AAD paper [1] (IDS2018, phases 3–4; `archive/cicids2018/`) | M4 |
| --- | --- | --- |
| attack space | all features, L∞ ball ε = 0.1 in [0, 1] (`config/attacks.yaml`) | the realism spec; no ε, cost reported instead |
| realizability | none; IDS2018 rows had 7.4 packets, 0.37 flags | every row a P fixed point; floors enforced |
| attacker knowledge | white box against one model | white / grey / black box; single model and the whole ensemble |
| defense awareness | none | validator-aware (λ ladder through the soft validator) |
| loss | softmax cross-entropy (ART) | logit margin to the calibrated threshold, worst member |
| operating point | argmax | 2% val-FPR threshold per model |
| source rows | 5,000 random attack rows | 900 per category, all detected by all three models |
| reporting | one evasion number per cell | per category, per window population, 95% intervals, attacker cost |
| result | up to 100% evasion; the validator stops ~all | ≤ 13.6% after repair; 39% / 15% / 10% (white / black / grey, spec C); the validator stops 6–14% |

**Against the M4 plan** (full list in `m4-realizable-attacks.md` §13): spec C added; spec A freezes
`Rate`; a λ ladder replaces the binary search; 10 restarts; compiled steps; discriminator-aware
attacks moved to M5; one TensorFlow implementation of P instead of a numpy twin;
`fig_cost_vs_evasion.png` **not produced** (the costs are in Table IV-d §7 as a table).

---

## 5. Results in one table

Pass-and-evade % on the test split (6,300 rows), 95% intervals in `table4d_tiers.md`:

| attacker | spec A | spec B | spec C |
| --- | ---: | ---: | ---: |
| white box, feature space (upper bound) | 7.17 | 21.00 | 38.95 |
| white box, feature space, validator-aware | 7.56 | 21.79 | 40.44 |
| white box, physical knobs | 3.10 | 5.11 | 21.67 |
| white box, physical knobs, validator-aware | 2.98 | 5.30 | 22.37 |
| grey box | 0.60 | 0.95 | 9.60 |
| black box | 3.29 | 3.71 | 15.06 |

10-packet population (Recon, Spoofing, Web, BruteForce) in spec C: 17.6–66.4%. 100-packet
population (floods, VulnerabilityScan): 0.1–9.7%. Lever: 90–98% of spec C wins shorten
connections. The validator stops 6–14% of model-fooling rows.

---

## 6. Possible improvements

Ordered by how much they would change the thesis's claims.

### 6.1 Realism (would move the headline numbers)

1. **Model the cost of connection churn.** Every fresh TCP connection adds a handshake; spec C
   ignores it. Add a "connections per window" knob to θ that injects SYN / SYN-ACK packets into
   the window's flag columns and counts (`primitives.py:90`, new immutable-but-derived flag
   handling in `project_raw`). Until then, spec C is an upper estimate.
2. **Validate g at packet level (M7).** Apply θ with Scapy to a sample of real flows per category,
   re-extract with `supplementary-CIC/pcap2csv`, and compare against `g` column by column. The
   assumptions are listed in `primitives.py:1-40`.
3. **Couple `Rate` and `flow_duration` in P** for specs B/C (`constraints.py:262-271`): packets =
   `Rate` × duration should not grow unless the attacker sends more.
4. **Per-direction model.** Pad and set TTL on the attacker's packets only; compute the window's
   mean from the attacker's share of packets.
5. **Variable-size padding** (frees `Std`, `Radius`, `Covariance`) and **protocol-specific caps**
   (UDP/DNS packets cannot always be padded to 1,514 B).

### 6.2 Attack strength (would make the numbers more trustworthy)

6. **Compare with an established constrained attack**, e.g. CAPGD or MoEvA2 [9], run against the
   same `realism.yaml`. That is an outside check on our PGD's strength.
7. **APGD-style step-size schedule** [11] and **AutoAttack-style ensembles of attacks**: the best
   per row over several attacks is the honest robustness number.
8. **Exhaustive search over θ.** With only 4 dimensions, a fine grid per row gives the exact
   optimum for the primitive attacker. It would settle whether 21.7% (spec C) is the true
   white-box number.
9. **Black box with a query-budget curve**, and a smarter search (boundary-following or CMA-ES in
   θ space).
10. **Cost-minimising objective:** report the cheapest successful θ per row, giving a cost-vs-evasion
    Pareto curve (the planned `fig_cost_vs_evasion.png`).

### 6.3 Evaluation (would make the numbers more robust)

11. **Several training seeds** for the baselines: today every number is one seed of one model each.
12. **Pipeline-wide FPR budget** (§2.2) before M8, and results at several budgets.
13. **Discriminator in the loop** (M5): attack the Random Forest through a distilled surrogate,
    BPDA-style [6], and run arms-race rounds.
14. **Cross-capture check** (CICIoMT2024 or a re-extracted PCAP sample): the only test free of
    the shuffled-CSV near-duplicate issue noted before M4.

### 6.4 Defense (what M4 suggests for M6)

15. **Adversarial training against spec C's churn attacker** [4], with ensemble diversity [14].
16. **Feature hardening:** reduce reliance on per-connection running totals, or add features that
    expose churn (connections per source per window, SYN share), and measure the trade-off.

### 6.5 Engineering

17. **Per-row random streams.** Restart draws depend on batch composition, which is why one tuning
    setting moved by 0.4 points when the in-loop check changed. A per-row seed would make cells
    reproducible independently of batching.
18. **GPU path for machine B** (AMD): only if TensorFlow is upgraded, which would put every result
    at risk; not recommended within the FYP.

---

## 7. Reproducing M4

From `aad/`, with the venv (all CPU; times on a Ryzen 5 8400F):

```powershell
..\.venv\Scripts\python.exe scripts\01_prepare.py                     # D1 rebuild (~15 min)
..\.venv\Scripts\python.exe scripts\02_train_baselines.py             # ~1.5 h (LSTM ~70 min)
..\.venv\Scripts\python.exe scripts\03_generate_ae.py --no-sweep      # phase-3 ART sets (~7 min)
..\.venv\Scripts\python.exe scripts\04_analyze_validate.py            # M3 rules (~1 min)
..\.venv\Scripts\python.exe scripts\02c_calibrate_thresholds.py       # D2
..\.venv\Scripts\python.exe scripts\02_train_baselines.py --models mlp cnn --train-frac 0.5 --seed 7 --tag surr
..\.venv\Scripts\python.exe scripts\03a_audit_realism.py
..\.venv\Scripts\python.exe scripts\03c_tune_realizable.py            # ~10 min
..\.venv\Scripts\python.exe scripts\03b_generate_realizable.py --attacks art_projected --spec C   # and A, B
..\.venv\Scripts\python.exe scripts\03b_generate_realizable.py --split test --spec C              # ~40 min; and A, B
..\.venv\Scripts\python.exe scripts\03b_generate_realizable.py --split test --spec C --flood-floor 0.25 --attacks feat_pgd_ens prim_pgd_ens blackbox
..\.venv\Scripts\python.exe scripts\03d_summarize_realizable.py
..\.venv\Scripts\python.exe -m pytest tests -q                        # 166 tests
```

---

## 8. References

1. A. Verma et al., "A Secure Adversarial Attack Detector Framework for Monitoring Network
   Intrusion in IoT Environment," *IEEE Transactions on Consumer Electronics*, 71(4), 2025.
   DOI 10.1109/TCE.2025.3614806.
2. E. C. P. Neto, S. Dadkhah, R. Ferreira, A. Zohourian, R. Lu, A. A. Ghorbani, "CICIoT2023: A
   Real-Time Dataset and Benchmark for Large-Scale Attacks in IoT Environment," *Sensors*,
   23(13):5941, 2023. Supplementary material: `pcap2csv` feature-extraction code.
3. I. J. Goodfellow, J. Shlens, C. Szegedy, "Explaining and Harnessing Adversarial Examples,"
   *ICLR*, 2015. (FGSM)
4. A. Madry, A. Makelov, L. Schmidt, D. Tsipras, A. Vladu, "Towards Deep Learning Models Resistant
   to Adversarial Attacks," *ICLR*, 2018. (PGD; adversarial training)
5. N. Carlini, D. Wagner, "Towards Evaluating the Robustness of Neural Networks," *IEEE S&P*, 2017.
   (margin loss with confidence κ)
6. A. Athalye, N. Carlini, D. Wagner, "Obfuscated Gradients Give a False Sense of Security:
   Circumventing Defenses to Adversarial Examples," *ICML*, 2018. (BPDA)
7. M.-I. Nicolae et al., "Adversarial Robustness Toolbox v1.0.0," arXiv:1807.01069, 2018. (ART)
8. W. Brendel, J. Rauber, M. Bethge, "Decision-Based Adversarial Attacks: Reliable Attacks Against
   Black-Box Machine Learning Models," *ICLR*, 2018. (Boundary attack)
9. T. Simonetto, S. Dyrmishi, S. Ghamizi, M. Cordy, Y. Le Traon, "A Unified Framework for
   Adversarial Attack and Defense in Constrained Feature Space," *IJCAI*, 2022. (CAPGD, MoEvA2)
10. F. Pierazzi, F. Pendlebury, J. Cortellazzi, L. Cavallaro, "Intriguing Properties of
    Adversarial ML Attacks in the Problem Space," *IEEE S&P*, 2020.
11. F. Croce, M. Hein, "Reliable Evaluation of Adversarial Robustness with an Ensemble of Diverse
    Parameter-Free Attacks," *ICML*, 2020. (APGD, AutoAttack)
12. A. Kurakin, I. Goodfellow, S. Bengio, "Adversarial Examples in the Physical World," *ICLR
    Workshop*, 2017. (BIM)
13. S.-M. Moosavi-Dezfooli, A. Fawzi, P. Frossard, "DeepFool: A Simple and Accurate Method to Fool
    Deep Neural Networks," *CVPR*, 2016.
14. F. Tramèr, A. Kurakin, N. Papernot, I. Goodfellow, D. Boneh, P. McDaniel, "Ensemble
    Adversarial Training: Attacks and Defenses," *ICLR*, 2018.
