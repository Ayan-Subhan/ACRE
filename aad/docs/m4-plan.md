# M4 plan — realizable, defense-aware attack generator

Detailed plan for milestone M4 of [`ciciot2023-implementation-plan.md`](ciciot2023-implementation-plan.md).
It **replaces that plan's M4 section**, which was written before M1–M3 measured the data
and is wrong in four places (see §1). Written 2026-10-09, after the move to machine B
(CPU only: Ryzen 5 8400F, 6 cores / 12 threads, 15.6 GB RAM; see the README's
"Environment notes").

**Goal.** Measure how well the M2 detectors and the M3 validator hold up against an
attacker who is limited to changes that real traffic can make, and who knows about the
validator. This is the core result of the thesis: the IDS2018 run showed that
unconstrained gradient attacks are an unfair test, because the validator caught 100% of
them through integrality alone.

---

## 1. What changed since the original M4 section, and why

| original assumption | what M1–M3 and the 2026-10-09 probes measured | consequence for M4 |
| --- | --- | --- |
| flag columns are window *fractions*; the attacker blends them toward 1 | flags and protocol indicators are **strictly 0/1** in every row (M3) | no "set-fraction" primitive; flags are immutable in v1 (binary toggles are an extension) |
| `IAT += delay` | `IAT` is a copy of `Number` and was dropped (2026-10-08) | delay acts only through `Rate` and `flow_duration` |
| `Tot sum = AVG × Number` (closed form) | false: median relative error 10.6%; M3 pruned the rule | `Tot sum` is updated with the row's own sum-to-mean ratio, not with `Number` |
| quiet attacks share the benign window size | **`VulnerabilityScan` (17% of Recon) uses the 100-packet window**, like the floods. Every 100-packet attack row is detected; every 10-packet attack category sits at 62–70% (MLP) | results are reported **per window population** (§3.4) |
| the attacker can target the discriminator | the M5 forest does not exist yet for CICIoT2023 | discriminator-aware attacks move to M5 (its arms-race rounds); M4 attacks validator + IDS |

**Measured on the raw 2.55M-row sample (2026-10-09).** These decide which features are
*derived* and so are recomputed by the attack instead of perturbed:

| relation | median relative error | use in M4 |
| --- | ---: | --- |
| `Magnitue² ≈ 2·AVG` | 0.22% | derived from `AVG` |
| `Radius² ≈ 2·Std²` | 0.09% | derived from `Std` |
| `log Covariance` vs `log Std²` | r = 0.989 | derived from `Std` (fitted per row ratio) |
| `Tot size ≈ AVG` | 5.8% | moves with `AVG` |
| `Tot sum ≈ AVG × Number` | 10.6% | ratio kept per row |
| `Weight` vs `Number` | r = 0.9999 | both immutable (window size) |
| `log Rate` vs `−log flow_duration` | r = 0.30 | **no closed form**: the extractor code must decide |

**An open problem that matters most.** The four features the models use most
(`rst_count`, `urg_count`, `Header_Length`, `flow_duration`, 15–25 points of
permutation importance each) grow with the *age of the flow*, not the window: benign
median `Header_Length` is 509,655 and median `urg_count` is 76. Seventy-six URG packets
per benign flow is not plausible traffic, so these columns are not what their names say.
Whether an attacker can move them, and in which direction, cannot be decided from the
names. Task 4.1 resolves it from CIC's extractor code. If that is not possible, the
attacks run under two specs and both are reported (§3.1, the sensitivity analysis).

---

## 2. Decisions needed before starting

Each has a recommended default, and the plan below assumes the defaults. **All five
recommended defaults were approved on 2026-10-09.**

| # | decision | recommended | cost on this CPU |
| --- | --- | --- | --- |
| D1 | **`Number` and `Weight`**: drop them (as with `IAT`), or keep them as immutable | **drop**: they encode an extraction setting (the window size), and the MLP without them scores 95.23% (−0.01 points) | retrain MLP ~7 min, CNN ~30 min, LSTM ~2 h 20 min (overnight); re-mine M3 rules and regenerate the 12 ART sets ~40 min |
| D2 | **Operating point**: argmax (0.5), or a threshold calibrated on validation for a benign-FPR budget | **calibrate on val for ≤ 2% IDS FPR**; the pipeline budget is then validator 1% + IDS 2% + discriminator (M5) 0.5% ≈ 3.5% | ~1 min, no retraining |
| D3 | **Download CIC's feature-extraction scripts** (Python source, small) from the CICIoT2023 page, to settle the semantics of each feature | **yes**: code only now; PCAP samples wait for M7 | minutes; needs your approval for the download |
| D4 | **Attack-row pool**: rows detected by all three models, 900 per attack category (BruteForce has 911 such test rows) | **yes**: equal denominators; tune on **val** rows, report on **test** rows | — |
| D5 | Order: discriminator-aware attacks in M5, not M4 | **yes** (the forest does not exist yet) | — |

---

## 3. Design

### 3.1 Threat model and realism spec — `config/realism.yaml`, `src/aad/attacks/realizable/constraints.py`

The attacker controls **its own packets** only: their size (padding), timing (sending
rate, flow lifetime) and IP TTL. It cannot change the protocol it uses, the flags its
attack needs, the victim's responses, or the extractor's window. Every one of the 38 (or
36, after D1) features gets a class in `config/realism.yaml`:

| class | features | projection rule |
| --- | --- | --- |
| `immutable` | `Protocol Type`, `HTTP`…`LLC`, `TCP`/`UDP`/`ARP`/`ICMP`/`IPv`, the 5 flag columns, `Number`, `Weight` (if kept), `Variance` | reset to the original value |
| `increase_only` (padding) | `AVG`, `Min`, `Max`, `Tot size`, `Tot sum` | `≥ original`; `Max ≤` MTU (1,514 bytes) |
| `decrease_only` (throttling) | `Rate`, `Srate` | `≤ original`, `≥ ρ_cat · original` (functional floor); `Srate := Rate` |
| `free_bounded` | `Duration` (mean TTL) | within [1, 255] |
| `flow_age` (decided in 4.1) | `flow_duration`, `Header_Length`, `ack/syn/fin/urg/rst_count` | **spec A (conservative):** immutable. **Spec B (permissive):** `increase_only`, scaled together by one "keep the flow alive longer" factor |
| `derived` | `Magnitue`, `Radius`, `Covariance` | recomputed from `AVG`/`Std` with each row's own fitted ratio (table in §1), never perturbed |

`Std` is `immutable` in v1 (uniform padding does not change it). Variable-size padding,
which would raise it, is an extension.

**Functional floors per category** (also in `realism.yaml`, swept in 4.5):

| category | floor |
| --- | --- |
| DDoS, DoS, Mirai | `Rate ≥ ρ · Rate_orig`, ρ = 0.5 (swept 0.25 / 0.5 / 0.75) |
| Web, BruteForce | payload never shrinks (sizes are `increase_only`); flow lifetime ≤ T × original, T = 5 |
| Recon, Spoofing | flow lifetime ≤ T × original, T = 5; throttling unbounded (a slow scan is still a scan) |

**Projection `P(x_adv, x_orig, category)`** works in raw units (through
`transform.json`: MinMax inverse, then `expm1` on the 16 log1p columns), applies the
table above, recomputes derived columns and maps back to scaled units. It has a numpy
version (for checking) and a TF version (for gradients), and they must agree. A projected
row satisfies the validator's integrality and dependency rules **by construction**: flags
and indicators are untouched, `Srate = Rate`, `Min ≤ AVG ≤ Max` survives uniform padding.
So the attacker only has to beat the range and distribution families, which is where
M3 found the gate's real strength.

### 3.2 Traffic primitives — `src/aad/attacks/realizable/primitives.py`

Besides attacking in feature space, the attacker can optimise a small vector **θ** of
physical actions, mapped by a differentiable `g(x_raw, θ)`:

| θ | range | effect (v1 closed form; each assumption is listed for checking in M7) |
| --- | --- | --- |
| `pad` (bytes per packet) | [0, 1514 − Max] | `AVG, Min, Max, Tot size += pad`; `Tot sum += pad · (Tot sum / AVG)`; `Magnitue = √(Magnitue² + 2·pad)` *(assumes the window is dominated by the attacker's own packets)* |
| `ttl` | [1, 255] | `Duration = ttl` *(same assumption)* |
| `throttle` r | [ρ_cat, 1] | `Rate, Srate ×= r`; `flow_duration /= r` |
| `stretch` s (spec B only) | [1, T] | flow-age columns `×= s` (exact form from 4.1) |

θ has 3 dimensions (spec A) or 4 (spec B). That keeps the black-box search cheap, and it
makes every result readable as "pad 40 bytes, set TTL 128, send at 60% speed". `g(x, 0)`
is the identity, and `P(g(x, θ)) = g(x, θ)`. Both are tests.

### 3.3 Attack suite — `src/aad/attacks/realizable/attacks.py`

Every attack returns `(X_adv, θ or None, cost)`. **Success is always judged by the real
models at the calibrated threshold (D2) and, where relevant, by the real numpy
`Validator`, never by a surrogate or the soft twin.**

| id | knowledge tier | method |
| --- | --- | --- |
| `art_projected` | white-box, unconstrained, then repaired | the 12 existing ART sets projected through `P`: the share that survives projection and still evades (comparable to Hasan et al.'s "80.3% invalidated") |
| `feat_pgd` | white-box, one model | PGD in scaled feature space with `P` after every step (constrained PGD). It is the strongest attacker the spec allows, and an upper bound for the primitives |
| `prim_pgd` | white-box, one model | PGD on θ through `g` (sign steps, clipped to θ's range) |
| `prim_pgd_ens` | white-box, OR-ensemble | loss = max over members of CE(member(x), benign): it must fool every member |
| `adaptive_val` | white-box, validator-aware | `L_ens + λ · SoftValidator.total(x)`; λ by per-row binary search (0 → 100, 7 steps), keeping the smallest λ that passes the **real** validator |
| `greybox_transfer` | grey-box | `prim_pgd_ens` crafted on surrogate MLP + CNN trained on a disjoint 50% of train (seed 7), replayed on the real models and validator |
| `blackbox_query` | black-box | (1+1)-evolution strategy over θ using only the hard allow/stop output of validator + IDS; 1,000 queries per row; queries-to-success reported |

**Cost per row:** byte overhead % (`pad / AVG_orig`), rate loss % (`1 − r`), lifetime
stretch, TTL change, and whether the functional floor holds.

**Library code vs our code.** ART is used for one thing: the unconstrained baseline, i.e.
the paper's attack. Every realizable attack is new code written for this project in
TensorFlow, because ART's attacks can only clip each feature to a fixed range such as
[0, 1].

| attack | implementation | role |
| --- | --- | --- |
| `art_projected` | **ART** (FGSM / BIM / PGD / DeepFool, the existing 12 sets), then **our** projection `P` | paper-faithful baseline: how much of a published-style attack survives once traffic must be real |
| `feat_pgd` | **ours**: PGD loop with `P` after every step | upper bound of the realism spec |
| `prim_pgd`, `prim_pgd_ens` | **ours**: PGD on θ through `g` | physically interpretable attacker |
| `adaptive_val` | **ours**, using the M3 `SoftValidator` | validator-aware attacker |
| `greybox_transfer` | **ours** (+ two surrogate models trained by us) | grey-box tier |
| `blackbox_query` | **ours**: (1+1)-ES over θ | black-box tier |

What ART cannot express, and so had to be written:

| requirement | where it lives |
| --- | --- |
| a feature may only rise (padding) or only fall (throttling) **relative to its own original value** | `constraints.py` (`P`), `realism.yaml` |
| derived features recomputed from others (`Magnitue` from `AVG`, `Radius` / `Covariance` from `Std`, `Srate = Rate`) | `constraints.py` |
| attacking 3–4 physical actions θ instead of all features | `primitives.py` (`g`) |
| functional floors per category (a flood keeps ≥ ρ of its rate; payload never shrinks) | `realism.yaml`, run-time assertion |
| a penalty for tripping the validator | `adaptive_val` + `validator_soft.py` (M3) |
| query-only search on the pipeline's allow/stop answer | `blackbox_query` |

**Optional outside comparison** (only if time allows): a published constrained
tabular attack (e.g. Simonetto et al.'s constrained PGD or MoEvA2) run against the same
`realism.yaml`, as a second baseline for the realizable attacks.

**Where realizability is established.** M4 makes every attacked row *feature-space
realizable by construction*: it obeys `realism.yaml`, and the run stops if one does not.
M7 checks *packet-level* realizability: it applies θ to real PCAP packets, re-extracts the
features, and compares them with what `g` predicted. M4 makes the claim; M7 verifies it.

### 3.4 Rows and reporting

- **Source rows:** 900 per attack category × 7 = 6,300 rows, drawn (seed 42) from
  rows **all three** baselines detect at the calibrated threshold. A val pool for tuning
  (steps, iterations, λ grid, ES step size), and a test pool, used once with frozen
  settings for the reported numbers.
- **Populations:** every table splits *10-packet-window* categories (Recon without
  `VulnerabilityScan`, Spoofing, Web, BruteForce), which share the benign window and are
  the honest test, from *100-packet-window* ones (DDoS, DoS, Mirai, `VulnerabilityScan`),
  which benign traffic never resembles in the window size.
- **Uncertainty:** 95% bootstrap intervals on every evasion rate (900 rows give about
  ±3 points at 50%).
- **Output:** `artifacts/adversarial_real/{attack}_{model}.npz`, the existing schema
  (`X_adv`, `X_clean`, `idx`, `y_true`, `y_multiclass`, `pred_clean`, `pred_adv`,
  `prob_adv`, `linf`, `l2`, `n_changed`, `meta`) plus `y_category`, `theta`, `cost_*`,
  `passes_validator`, `floor_ok`, and `strategy` / `tier` / `spec` in `meta`. All cells
  in the directory share one `idx`, so `discriminator.load_cells` reads them unchanged in
  M5.

---

## 4. Work plan

| step | what | files | CPU time |
| --- | --- | --- | ---: |
| **4.0** | **Prerequisites.** Commit the machine-B fixes. D1 retrain if chosen (run overnight), then re-mine `rules.json` and regenerate the 12 ART sets. D2: `scripts/02c_calibrate_thresholds.py` → `artifacts/models/thresholds.json`. Add `bootstrap_ci` to `evaluate.py` | `02c_calibrate_thresholds.py` (new), `evaluate.py` | ~3.5 h with D1 (unattended), else ~1 min |
| **4.1** | **Feature semantics.** Read CIC's extractor (D3) and write the formula of every feature into `docs/ciciot2023-features.md`, the flow-age columns above all. Fix the `flow_age` class: spec A, B, or a third spec the code supports | docs | — |
| **4.2** | **Realism spec + audit.** `config/realism.yaml`; `scripts/03a_audit_realism.py` re-measures every derived relation and bound on benign and attack **train** rows → `artifacts/reports/realism_audit.md` (the spec is a hypothesis; the data confirms it, as M3 did for rules) | `realism.yaml`, `03a_audit_realism.py`, `realizable/constraints.py` | ~2 min |
| **4.3** | **Primitives `g`** in TF, with numpy twin | `realizable/primitives.py` | — |
| **4.4** | **Tests** (synthetic fixtures, like the rest of the suite): `P` idempotent; immutables never change; monotone clamps hold; derived columns recomputed; `g(x, 0) = x`; `P(g(x, θ)) = g(x, θ)`; numpy and TF agree to 1e-6; a projected row passes integrality + dependency; the floor check fires on a violating row | `tests/test_realizable.py` | seconds |
| **4.5** | **First result: `art_projected`** (no new attack needed, quick) | `realizable/attacks.py` | ~2 min |
| **4.6** | **White-box attacks** `feat_pgd`, `prim_pgd`, `prim_pgd_ens`; driver script with `--split`, `--models`, `--attacks`, `--spec`, `--force`, resume per file; tune on val | `scripts/03b_generate_realizable.py` | ~30–45 min per split (LSTM dominates) |
| **4.7** | **`adaptive_val`** | `attacks.py` | ~30 min |
| **4.8** | **Grey-box:** train surrogates (MLP + CNN on the other 50%), then `greybox_transfer` | `03b` (`--train-surrogates`) | ~25 min + ~10 min |
| **4.9** | **Black-box** `blackbox_query` | `attacks.py` | ~45–60 min (6.3M queries per model) |
| **4.10** | **Test runs and reports.** All attacks on the test pool with frozen settings; both specs if 4.1 leaves it open; ρ sweep for floods | reports below | ~2–3 h |
| **4.11** | **Write-up**: `docs/m4-realizable-attacks.md` (same style as M1–M3), plan status log, README milestone table | docs | — |

**Run-time assertions that stop the run** (not only tests): any saved `X_adv` with
`‖P(x) − x‖ > 0`, and any counted evasion whose functional floor fails.

**Reports** (`artifacts/reports/`):

| file | content |
| --- | --- |
| `realism_audit.md` | every derived relation and bound, measured |
| `table4b_realizable.{csv,md}` | attack × model × category × population: n, evasion % [95% CI], passes validator %, passes validator *and* evades %, mean cost |
| `table4c_projection.{csv,md}` | ART sets before/after projection: share invalidated, share still evading |
| `table4d_tiers.{csv,md}` | white / grey / black box side by side, with queries-to-success for black box |
| `figures/fig_cost_vs_evasion.png` | evasion against byte overhead and rate loss, per category |

**Timeline:** about 5 working days of development, plus ~6–8 h of CPU, most of it
unattended (the D1 retrain overnight and the test runs). On this CPU, the slowest model
is the LSTM throughout. If time gets short, it is the first thing to drop from the attack
runs. Its numbers are least needed, because it is already the weakest baseline.

## 5. Done when

- `pytest` is green, including the new realism tests, and no run-time assertion fired.
- Every number in the tables comes from the test pool with settings frozen on val, and
  success was judged by the real models (calibrated threshold) and the real validator.
- Both window populations are reported separately, with bootstrap intervals.
- If the flow-age semantics stay ambiguous after 4.1, both specs are reported and the
  write-up says which result depends on which assumption.
- Every closed-form assumption in `g` is listed in the write-up with the M7 check that
  will confirm or refute it.

## 6. What M4 hands on

- **M5:** `artifacts/adversarial_real/` as new positives with `strategy` tags (for
  leave-one-strategy-out); the attack code, which M5 extends with a discriminator
  surrogate for its arms-race rounds.
- **M6:** `prim_pgd` and `P` as the shared attacker for in-loop adversarial training
  (one import, so training and evaluation use the same attacker).
- **M7:** θ per row and the list of `g` assumptions to verify at packet level.
