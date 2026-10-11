# M4 — realizable, defense-aware attacks, explained

Milestone M4 of [`ciciot2023-implementation-plan.md`](ciciot2023-implementation-plan.md), planned
in [`m4-plan.md`](m4-plan.md). This document is meant to be read start to finish by someone who
knows the project but did not write M4: *why* each part exists, *how* it works (with a worked
example), *what* came out, and what it means for the thesis. Run on machine B (CPU only), 2026-10-09.

> **M4 in six sentences.** Published-style gradient attacks are not traffic: 82–100% of every
> ART set is unrealizable, and once repaired into sendable traffic they evade the CNN on 2–11% of
> rows instead of 100%. A realizable attacker that controls only its own packets' size, timing,
> TTL and connections still gets **39% of detected attacks past all three models and the
> validator** (white box, spec C), **15% with only allow/stop answers** (black box) and 10% with
> its own surrogate models (grey box). Its main lever is **splitting traffic over many short
> connections**, because the models lean on per-connection running totals. The rule-based
> validator stops only 6–14% of rows that fool the models, and a validator-aware attacker wins a
> third of those back. Floods stay protected (≤ 5%) by their 100-packet-window statistics, not by
> the validator or throttling limits; the stealthy 10-packet categories (Recon, Spoofing, Web,
> BruteForce) carry almost all the risk. How large the hole is depends on how much an attacker
> can change about its connections (spec A 7% → B 21% → C 39%), and packet-level checks (M7) must
> confirm the connection-churn assumption before the spec C numbers go into the thesis as fact.

---

## Contents

1. [The question M4 answers](#1-the-question-m4-answers)
2. [What CIC's extractor actually computes](#2-what-cics-extractor-actually-computes)
3. [Step 4.0: the ground M4 stands on](#3-step-40-the-ground-m4-stands-on)
4. [The threat model: what a real attacker can change](#4-the-threat-model-what-a-real-attacker-can-change)
5. [The projection P](#5-the-projection-p)
6. [Traffic primitives θ and the map g](#6-traffic-primitives-θ-and-the-map-g)
7. [The attacks](#7-the-attacks)
8. [How success is judged](#8-how-success-is-judged)
9. [Bugs found on the way, and the guards they left behind](#9-bugs-found-on-the-way-and-the-guards-they-left-behind)
10. [Tuning on validation](#10-tuning-on-validation)
11. [Results](#11-results)
12. [What this means for the thesis and for M5–M8](#12-what-this-means-for-the-thesis-and-for-m5m8)
13. [Files, commands, and deviations from the plan](#13-files-commands-and-deviations-from-the-plan)

---

## 1. The question M4 answers

The AAD framework puts three gates in front of an IDS: a rule-based **validator**, a
**discriminator** (Random Forest) trained to spot adversarial rows, and an **ensemble IDS**
(MLP ∨ CNN ∨ LSTM). Its paper, and our IDS2018 reproduction, test it with gradient attacks from
the ART library (FGSM, BIM, PGD, DeepFool). Those attacks treat a row as a vector of numbers and
nudge every number freely. That produces rows **no network could ever produce**: 7.4 packets, a
SYN flag of 0.37, an HTTP packet that is not TCP. On IDS2018 the validator caught 100% of them
through integrality alone (is a count still a whole number?), so the other two gates were never
really tested.

M4 asks the question that matters in practice:

> **If the attacker may only send traffic that is physically possible, and knows about the
> defense, how often does a detected attack get through?**

To answer it, M4 builds four things:

| piece | what it is | section |
| --- | --- | --- |
| a **realism spec** | a column-by-column statement of what an attacker controls (its packets' size, timing, TTL) | 4 |
| a **projection P** | a function that turns *any* candidate row into the closest row a real attacker could send | 5 |
| **traffic primitives θ** | 4 physical knobs (padding, TTL change, slowing down, flow lifetime) and a map g from knobs to features | 6 |
| an **attack suite** | 7 attacks across white-, grey- and black-box knowledge, all producing only realizable rows | 7 |

ART is still used, but only for the baseline (the paper's attack). Everything else is written for
this project in TensorFlow, because ART's attacks can only clip each feature to a fixed range such as
[0, 1]; they cannot express "may only grow from its own original value", "must be recomputed from
another column", or "a flood must keep half its rate" (table in [`m4-plan.md`](m4-plan.md) §3.3).

---

## 2. What CIC's extractor actually computes

Deciding what an attacker can change requires knowing what each column *is*. Until 2026-10-09 we
only had names and statistics, and four of the columns the models rely on most
(`rst_count`, `urg_count`, `Header_Length`, `flow_duration`) did not behave like their names: the
median benign row has `urg_count` 76 and `Header_Length` 509,655, which no single window of
10 packets can produce.

The CIC supplementary material (`supplementary-CIC/`: `pcap2csv/` with 7 Python modules,
`tools/`, two README PDFs) settles it. It was **read, not run**.

### 2.1 The released code is not the exact version that produced the CSV

| evidence | released `Feature_extraction.py` | the CSV we use |
| --- | --- | --- |
| output columns | no `flow_duration`, `Duration`, `Srate`, `Drate`, `urg_count`, `Magnitue`, `Radius`, `Covariance`, `Weight` (their code is commented out) | all 46 |
| `Number` | always 10 (sum of 1 per packet over a 10-packet window) | 5.5 / 9.5 / 13.5 |
| flags | per-packet 0/1, then *averaged* over the window → fractions | strictly 0/1 |
| `Protocol Type` | the *mode* over the window | averaged (6.11, 47.0, …) |

So the CSV came from a later, unreleased version. What the release *does* give is the per-packet
and per-flow logic, and every quirk we measured in M1–M3 follows from it:

### 2.2 What each column is (and why it matters for M4)

| column(s) | how the code computes it | what that means |
| --- | --- | --- |
| `flow_duration` | `get_flow_info`: timestamp of the latest packet − timestamp of the first packet of this **flow** (sorted 5-tuple: both IPs and ports) seen so far in the 10 MB pcap chunk | the **age of the connection**, not of the window |
| `Rate`, `Srate` | packets of the flow so far ÷ `flow_duration` | the connection's average packet rate. The flow key is *sorted*, so "packets from source to destination" is every packet of the flow → **`Srate == Rate` in every row** (M3 found this exactly) |
| `Drate` | reverse-direction packets ÷ `flow_duration`, looked up under the *unsorted* reverse key, which never exists | **≈ 0 always** (M1 dropped it as near-constant) |
| `ack/syn/fin/urg/rst_count` | per-flow flag counters (`tcp_flow_flags[flow]`, commented out in the release) | **running totals per connection**: why benign rows show hundreds |
| `Header_Length` | the flow's running byte total (`get_flow_info`; its debug print is even labelled "header length") | **cumulative bytes of the connection** (strong hint, not certain) |
| `Tot size` | each packet's Ethernet frame length, averaged over the window | ≈ `AVG` (they differ only in window bookkeeping) |
| `Tot sum`, `Min`, `Max`, `AVG`, `Std` | sum / min / max / mean / std of frame lengths in the window | the window's packet-size statistics |
| `Magnitue`, `Radius`, `Covariance`, `Variance`, `Weight` | `dynamic_two_streams` over "incoming" and "outgoing" lists, which the code fills with the **same** packets | why `Magnitue² ≈ 2·AVG` (0.3% median error) and `Radius² ≈ 2·Std²` hold so tightly |
| `Duration` | the packets' IP TTL, averaged | mean TTL |
| flags, protocol indicators | from each packet's header bits / ports | 0/1, the attack's own protocol |

**The consequence for M4.** The four most-used columns describe **how long, and how much, a
connection has been talking**. An attacker controls that: keeping a connection alive longer raises
them; spreading traffic over fresh connections (new source ports) resets them. This is why the
realism spec has three versions for these columns (§4.3) and why spec C is the closest to the
extractor.

---

## 3. Step 4.0: the ground M4 stands on

Three decisions were taken before any attack ran (`m4-plan.md` §2, approved 2026-10-09).

### 3.1 D1: `Number` and `Weight` dropped (36 features)

Both encode the extractor's **packet-window size**, which CIC chose *per class*: 100 packets for
every flood and for `VulnerabilityScan`, 10 for everything else. Kept as attacker-immutable
columns, they would make every flood "unevadable" through a capture setting rather than through the
defense. They were dropped at the scan, like `IAT` before them.

| | 38 features (GPU, 2026-10-08) | **36 features (CPU, 2026-10-09)** |
| --- | --- | --- |
| rows, splits | 2,547,882; 1,783,517 / 382,182 / 382,183 | **identical** (no selected row changed) |
| MLP / CNN / LSTM balanced acc. | 95.25 / 95.11 / 94.82% | 95.17 / 95.12 / 94.39% |
| flood recall | 100.00% | 98.6–99.99% (the window signal is gone) |
| validator benign FPR | 1.03% | 1.01% |

Dropping them cost nothing overall. What they had carried shows in the floods, whose recall is no
longer exactly 100%.

### 3.2 D2: every model gets an explicit operating point

Argmax (P(attack) ≥ 0.5) is an accident of training. Each model now gets the smallest threshold
whose false-positive rate on **validation** benign rows is ≤ 2% (`scripts/02c_calibrate_thresholds.py`,
`artifacts/reports/thresholds.md`):

| model | threshold | val FPR | **test FPR** | test balanced acc. |
| --- | ---: | ---: | ---: | ---: |
| MLP | 0.487 | 2.00% | 1.96% | 95.19% |
| CNN | 0.575 | 2.00% | 1.93% | 95.07% |
| LSTM | 0.587 | 2.00% | 1.96% | 94.22% |

The thresholds transfer to test almost exactly. **Warning for M6/M8:** the OR-ensemble of the three
flags 3.27% of benign test traffic, and the validator adds ~1%; the pipeline is already near 4%
before the discriminator. A deployed configuration will need tighter per-member budgets.

### 3.3 D4: which rows are attacked, and the two window populations

Every attack perturbs the **same** source rows: 900 per attack category (6,300 in total, seed 42),
drawn only from rows that **all three** models detect at their thresholds. That way
"evasion" always means *turning a detected attack into a missed one*, and every category has the
same denominator (BruteForce has 911 eligible test rows, which sets the 900).

Every result is also split by **window population**:

- **10-packet** — Recon (without `VulnerabilityScan`), Spoofing, Web, BruteForce. These share the
  benign window size: the honest test.
- **100-packet** — DDoS, DoS, Mirai, `VulnerabilityScan`. Benign traffic never has this window
  size, so the window itself (through every statistic it shapes) separates them.

---

## 4. The threat model: what a real attacker can change

**The attacker controls its own packets only:** their size (it can pad them), their timing (it can
send slower, keep a connection open longer, or split it into fresh connections) and their IP TTL.
It cannot change the protocol its attack uses, the TCP flags the attack needs, the victim's replies,
or the extractor's window. `config/realism.yaml` turns that into a class for each of the 46 raw
columns (so it stays valid whichever columns M1 drops).

### 4.1 The classes

| class | columns | rule (raw units) | why |
| --- | --- | --- | --- |
| **immutable** | `Protocol Type`, 7 flag columns, 13 protocol indicators, `Std`, `Radius`, `Covariance`, `Variance`, `Number`, `Weight`, `IAT`, `Drate` | reset to the original | the attack's protocol and flags are what make it the attack; uniform padding leaves the spread (`Std`, …) unchanged |
| **increase_only** | `Min`, `AVG`, `Max`, `Tot size` | ≥ original, ≤ max(original, 1,514 B) | padding only adds bytes; 1,514 B is a full Ethernet frame |
| **decrease_only** | `Rate` | ≤ original, ≥ floor × original (spec A: immutable, §11.1) | throttling only slows down |
| **free_bounded** | `Duration` (mean TTL) | within [1, 255] (or the original, if it lies outside) | the attacker sets its own TTL |
| **flow_age** | `flow_duration`, `Header_Length`, `ack/syn/fin/urg/rst_count` | depends on the spec (4.3) | per-connection running totals (§2.2) |
| **derived** | `Srate`, `Tot sum`, `Magnitue` | recomputed, never perturbed | they are functions of other columns (§5) |

### 4.2 Functional floors

An evasion only counts if the traffic still does its job:

| category | floor |
| --- | --- |
| DDoS, DoS, Mirai | `Rate ≥ 0.5 × original` — a flood at a fraction of its rate is not a flood |
| all others | no rate floor (a slow scan is still a scan), but the primitive attacker may not slow down more than 20× |

### 4.3 Three specs for the flow-age columns

| spec | flow-age columns may be scaled by | the attacker can | role |
| --- | --- | --- | --- |
| **A** | ×1 (immutable; `Rate` frozen too) | only pad and change TTL | **lower bound** on the attacker |
| **B** | ×1 … ×5 | keep connections alive up to 5× longer | keep-alive only |
| **C** | ×0.2 … ×5 | keep alive *or* split over fresh connections | **closest to the extractor** (§2.2) |

Why both directions matter: benign connections are long (median `Header_Length` 509,655 B), so
growing a short attack connection helps; but a Web attack's median `flow_duration` (84.6 s) is
*longer* than benign's (26.8 s), so for it shortening helps. Zero stays zero under scaling.

---

## 5. The projection P

`src/aad/attacks/realizable/constraints.py`, `Projector.project(x_candidate, x_original, floor)`.

**What it does.** Takes any candidate row (from a gradient step, a random draw, an ART attack) and
returns the closest row the spec allows, given the original row it started from. The order matters:

1. go to **raw units** (undo MinMax, then `expm1` on the 16 log1p columns — exactly as phase 1 and
   the validator define it);
2. **immutable** columns ← original;
3. **increase_only** columns clamped to [original, max(original, 1,514)];
4. **`Min ≤ AVG ≤ Max`** restored (allowing each row its own original slack — see §9);
5. **`Rate`** clamped to [floor × original, original];
6. **`Duration`** clipped to [1, 255];
7. **flow-age** columns clamped to [min_factor × original, max_factor × original];
8. every base column clipped to what the deployed scaler can represent (scaled 0…1);
9. **derived** columns recomputed: `Srate = Rate`; `Tot sum = Tot sum₀ × AVG / AVG₀`;
   `Magnitue = √(Magnitue₀² + 2·(AVG − AVG₀))`;
10. back to scaled units. Columns P did not change keep their **exact** input value.

**Properties, all pinned by tests (`tests/test_realizable.py`):**

- **identity on clean rows:** P(x, x) = x bit-for-bit — verified on *every* real val and test row,
  for all three specs;
- **idempotent:** P(P(x)) = P(x), so "is this row realizable?" is simply "is it a fixed point of P?";
- a projected row automatically satisfies the validator's **integrality** and **dependency**
  families (flags stay 0/1, `Srate = Rate`, `Min ≤ AVG ≤ Max`, the protocol hierarchy is untouched).
  Only the **range** and **distribution** families remain for the attacker to beat;
- **differentiable** (one TensorFlow float64 implementation), so gradient attacks can optimise
  *through* it; a numpy wrapper calls the same code, so checking and attacking cannot disagree.

**The run-time guard.** Every saved adversarial row is re-projected and the run **stops** if any row
moves by more than 10⁻⁵ (scaled units), or is not finite. A second, independent guard re-checks
every functional floor on the saved rows.

---

## 6. Traffic primitives θ and the map g

`src/aad/attacks/realizable/primitives.py`. Instead of moving 36 numbers, the primitive attacker
picks 4 physical actions per row. θ = 0 means "send the attack unchanged".

| θ | meaning | range | effect on the row (then P) |
| --- | --- | --- | --- |
| `pad` | bytes added to every packet | [0, 1,514 − Max] | `Min, AVG, Max, Tot size` + pad; `Tot sum`, `Magnitue` follow |
| `dttl` | change of the mean TTL | [1 − TTL, 255 − TTL] | `Duration` + dttl |
| `slow` | throttling | spec A: 0; B/C: [0, 1 − max(floor, 1/20)] | `Rate`, `Srate` × (1 − slow); in B/C `flow_duration` ÷ (1 − slow) |
| `stretch` | connection lifetime | spec A: 0; B: [0, 4]; C: [−0.8, 4] | every flow-age column × (1 + stretch) |

**A worked example** (a real Web attack row from the test set, spec C, θ = pad 40 B, TTL +20,
30% slower, connections 2× longer):

| column | original | after g | why |
| --- | ---: | ---: | --- |
| `AVG` / `Min` / `Max` | 102.4 / 54.0 / 255.4 | 142.4 / 94.0 / 295.4 | + 40 bytes each |
| `Tot sum` | 1,633.2 | 2,271.1 | scales with `AVG` (× 142.4 / 102.4) |
| `Magnitue` | 14.28 | 16.85 | √(14.28² + 2 × 40) |
| `Duration` (TTL) | 61.6 | 81.6 | + 20 |
| `Rate` = `Srate` | 0.554 | 0.388 | × 0.7 |
| `flow_duration` | 414.1 | 1,183.3 | × 2 (stretch) ÷ 0.7 (slower) |
| `Header_Length`, `rst_count`, `urg_count` | 10,055 / 70.3 / 43.5 | 20,111 / 140.6 / 87.0 | × 2 |
| `Std`, `TCP`, flags | unchanged | unchanged | immutable |

Attacker cost for this row: 39% more bytes, 30% lower rate, TTL +20, connections 2.9× longer.

**Assumptions behind g, to be checked at packet level in M7:** padding reaches every packet of the
window; the window's TTL mean moves with the attacker's own packets; throttling stretches the
connection; `Header_Length` and the counters scale with connection lifetime. Every one of them is
listed in the M7 hand-over (§12).

---

## 7. The attacks

`src/aad/attacks/realizable/attacks.py`, driven by `scripts/03b_generate_realizable.py`.

| attack | knowledge | how it works |
| --- | --- | --- |
| `art_projected` | white box, *unconstrained*, then repaired | the 12 phase-3 ART sets passed through P: how much of a published-style attack survives once it must be real traffic (Table IV-c) |
| `feat_pgd` | white box, one model | PGD in feature space with P after every step. The **strongest** attacker the spec allows: anything it finds is reachable by *some* realizable change |
| `prim_pgd` | white box, one model | PGD on θ through g: the attacker moves the 4 physical knobs |
| `*_ens` | white box, all three models | loss = the **worst** member's margin, so success means fooling MLP *and* CNN *and* LSTM — the OR-ensemble's rule |
| `adaptive_prim`, `adaptive_feat` | white box, **defense-aware** | PGD loss + λ × the soft validator's penalty (M3's differentiable twin); λ climbs a ladder 0 → 0.1 → 1 → 10 → 100 |
| `greybox` | grey box | the adaptive attack run against **surrogate** MLP + CNN that the attacker trained itself on a different half of the training data (seed 7), then replayed against the real models |
| `blackbox` | black box | sees only the pipeline's **allow / stop** answer (validator, then the three models). Samples θ at random until a row is let through, then shrinks θ toward zero while it stays allowed; 1,000 queries per row |

**Implementation choices that matter for the numbers:**

- **Gradients on logits, not probabilities.** On a saturated softmax the gradient vanishes, which
  froze 45% of the MLP's rows in M3. The loss is
  `max over members of relu(logit_attack − logit_benign − logit(threshold) + 0.1)`: it is zero
  exactly when every member says "benign" with a small margin.
- **Signed steps, P every step, stop at first success.** A row is recorded at the first point where
  the *deployed* verdict flips (and, for the adaptive attacks, the *real* validator passes).
- **Random restarts** (10, chosen on validation, §10): rows not won from the clean starting point
  get further runs from random realizable starting points.
- **The λ ladder spends effort only where it can help.** Higher λ is given only to rows that fooled
  the models but were stopped by the validator. A row that never fooled the models cannot be helped
  by a validator penalty.

---

## 8. How success is judged

| question | how it is answered |
| --- | --- |
| does the model detect the row? | the **deployed** softmax model at its **calibrated threshold** (D2) — never the logit view used for gradients |
| does the validator let it through? | the **real** numpy `Validator` with the M3 `rules.json` — never the soft twin |
| is the row realizable? | fixed point of P (run-time guard, §5) |
| does the attack still work? | functional floor re-checked on the saved row |
| how sure are we? | 95% bootstrap interval on every rate (900 rows per category ≈ ±3 points at 50%) |
| grey box | crafted on surrogates, **judged on the real models** |

Reported per cell (`table4b_realizable_*.md`): **evasion** (no targeted model detects the row),
**passes validator**, **pass-and-evade** (both — the number that matters), evasion of all three
models, and median attacker cost over the pass-and-evade rows (byte overhead, rate loss, TTL change,
features changed).

---

## 9. Bugs found on the way, and the guards they left behind

The smoke runs (2% data, 1-epoch models) and the checks on real data found five problems. Each
is fixed and pinned by a test that fails without the fix.

| # | bug | symptom | fix |
| --- | --- | --- | --- |
| 1 | `to_raw` (in **M3's soft validator** and in P) evaluated `expm1` on *every* column and let `tf.where` discard the non-log ones | any linear column above ~709 overflowed to ∞ in the discarded branch; ∞ × 0 = NaN gradient; θ became NaN | `expm1` only ever sees the log1p columns ("safe where") |
| 2 | NaN rows passed the realizability check (`NaN > tol` is False) and counted as **evasions** (NaN passes every comparison) | an early "30 of 46 rows won" was entirely this | non-finite rows count as violations; PGD raises on a non-finite gradient |
| 3 | P substituted exact original values with `tf.where`, which also cut the gradient | at θ = 0 every gradient was 0: the primitive attack never moved | straight-through substitution: exact value forward, gradient of the computed value backward |
| 4 | P moved rows the capture itself produced (mean TTL 0; float32 leaving `Min` a hair above `Max`) | P(x, x) ≠ x on ~10% of real rows (by ≤ 3 × 10⁻⁸) | bounds widened to include the original; ordering repair allows the row's own slack |
| 5 | the source-row index was saved as `.npz` in the cell directory | M5's `load_cells` read it as an attack cell | saved as `.npy` |

---

## 10. Tuning on validation

All settings were chosen on the **validation** split; the test split was used once, with frozen
settings.

**First val run** (200 rows per category, spec A, 100 steps). Two problems showed:

1. The λ ladder's higher rungs won 0–2 extra rows at a cost of 27–55 minutes per cell → it now
   re-attacks only rows stopped by the validator (§7).
2. The **black box beat the white-box primitive attack** (8.6% vs 6.6%). A query-only attacker
   should not beat one with gradients; the classic explanation is a gradient attack stuck in a poor
   local optimum.

**The sweep** (`scripts/03c_tune_realizable.py`, 100 rows per category, OR-ensemble target,
`artifacts/reports/realizable_tuning_val_specA.md`):

| attack       |   steps |   step |   restarts |   evasion_% |   pass_and_evade_% |   pass_and_evade_10pkt_% |   pass_and_evade_100pkt_% |   seconds |
|:-------------|--------:|-------:|-----------:|------------:|-------------------:|-------------------------:|--------------------------:|----------:|
| feat_pgd_ens |     100 |   0.01 |          0 |       10.86 |              10.43 |                    16.10 |                      3.49 |      5.20 |
| feat_pgd_ens |     300 |   0.01 |          0 |       10.86 |              10.43 |                    16.10 |                      3.49 |     13.10 |
| feat_pgd_ens |     100 |   0.03 |          0 |       10.57 |              10.14 |                    15.84 |                      3.17 |      4.30 |
| feat_pgd_ens |     100 |   0.01 |          3 |       12.29 |              11.29 |                    17.40 |                      3.81 |     17.70 |
| feat_pgd_ens |     300 |   0.03 |          3 |       11.86 |              11.00 |                    17.14 |                      3.49 |     53.80 |
| feat_pgd_ens |     100 |   0.01 |         10 |       13.43 |              12.43 |                    19.22 |                      4.13 |     47.80 |
| feat_pgd_ens |     100 |   0.01 |         30 |       14.14 |              13.00 |                    20.26 |                      4.13 |    131.70 |
| prim_pgd_ens |     100 |   0.05 |          0 |        5.29 |               5.00 |                     8.83 |                      0.32 |      5.20 |
| prim_pgd_ens |     300 |   0.05 |          0 |        5.29 |               5.00 |                     8.83 |                      0.32 |     12.20 |
| prim_pgd_ens |     100 |   0.20 |          0 |        4.00 |               3.57 |                     6.23 |                      0.32 |      4.30 |
| prim_pgd_ens |     100 |   0.05 |          3 |        7.86 |               7.29 |                    12.73 |                      0.63 |     17.40 |
| prim_pgd_ens |     300 |   0.10 |          3 |        6.71 |               6.14 |                    10.91 |                      0.32 |     48.00 |
| prim_pgd_ens |     100 |   0.05 |         10 |        8.57 |               7.71 |                    13.51 |                      0.63 |     43.80 |
| prim_pgd_ens |     100 |   0.05 |         30 |        8.71 |               7.86 |                    13.77 |                      0.63 |    123.20 |

**Reading it:**

- **Steps and step size are converged.** 300 steps give *exactly* the 100-step result, and a
  larger step is no better (feature space) or worse (primitives). More iterations from the same
  start cannot find anything new.
- **Random restarts are what helps.** From 0 to 10 restarts, pass-and-evade rises from 10.4% to
  12.4% (feature space) and from 5.0% to 7.7% (primitives), then flattens (30 restarts: 13.0% /
  7.9% at 2.8× the time). So the first run was stuck in local optima, not hitting real
  robustness. With 10 restarts the primitive attacker matches what the black box found on the
  first val run.
- **Chosen for the test run: 100 steps, step 0.01 (feature) / 0.05 (primitive), 10 restarts.**

**Two caveats.**
- The sweep ran on spec A *before* the `Rate` fix of §11.1 (spec A then still allowed
  throttling). It tunes the optimiser (steps, step size, restarts), and those conclusions do not
  depend on the spec.
- The first version of the sweep took 4.6 hours. After the attacks were compiled
  (`tf.function`, one forward pass per step for both gradient and success check: §13) the same
  sweep took about 10 minutes and reproduced every number but one. That setting (300 steps, step
  0.10, 3 restarts) moved by 0.4 points, because borderline rows are now judged in logit space
  inside the loop, which changes the random restart draws.

---

## 11. Results

All numbers below come from the **test** split with the settings frozen on validation
(100 steps, 10 restarts), 6,300 source rows, 95% bootstrap intervals. Full tables:
`artifacts/reports/table4d_tiers.md` (cross-spec, built by `scripts/03d_summarize_realizable.py`),
`table4b_realizable_test_spec{A,B,C}.md` (every cell, every category), `table4c_projection_spec{A,B,C}.md`.

### 11.1 First, a correction found by the results themselves

The first test run produced an impossible ordering: spec B, which gives the attacker *more*
freedom than spec A, came out *weaker* for the primitive and black-box attacks (black box
3.7% vs 8.1%). The cause was in spec A, not in B. In CIC's extractor `Rate` is the connection's
packets divided by its age (§2.2). Spec A froze the connection's age and packet counters but still
let the attacker lower `Rate`, which no connection can do. In spec B the primitive attacker pays the
real price: slowing down makes the connection older. **Fix:** under spec A, `Rate` (and `Srate`) is
immutable too, so spec A is padding and TTL only, a true subset of B and C. Spec A was re-run; every
attack now orders A ≤ B ≤ C, as it must.

### 11.2 Published-style attacks do not survive becoming traffic (Table IV-c)

| target | ART PGD evasion | after projection, spec A | spec B | spec C |
| --- | ---: | ---: | ---: | ---: |
| MLP | 62.64% | 1.76% | 4.59% | 7.97% |
| CNN | 99.85% | 2.36% | 6.11% | 10.81% |
| LSTM | 48.03% | 1.62% | 7.79% | 13.58% |

- **82–100% of every ART set is unrealizable** (100% for CNN and LSTM sets and for DeepFool; 82% for
  the MLP's FGSM/BIM/PGD sets, whose remaining rows are essentially those the gradient attacks left
  untouched: the MLP's softmax still saturates on 16% of its rows).
- After repair, the evasion that remains also passes the validator almost entirely (pass-and-evade
  0% before → up to 11.8% after, spec C). The validator stopped ART's rows because they were
  impossible, not because they evaded.
- DeepFool collapses hardest (CNN: 100% → 0.2–1.4%). It looks for the *nearest* boundary crossing,
  and once that path must stay realizable, almost nothing of it is left.

### 11.3 The headline: realizable attacks against the full gate (Table IV-d)

Pass-and-evade %: **no model detects the row and the real validator lets it through.**

| attacker | knowledge | spec A | spec B | **spec C** |
| --- | --- | ---: | ---: | ---: |
| feature-space PGD | white box | 7.17 | 21.00 | **38.95** [37.7, 40.2] |
| feature-space PGD, validator-aware | white box | 7.56 | 21.79 | **40.44** [39.2, 41.7] |
| physical knobs (θ) PGD | white box | 3.10 | 5.11 | **21.67** [20.6, 22.7] |
| physical knobs, validator-aware | white box | 2.98 | 5.30 | **22.37** [21.3, 23.4] |
| physical knobs, own surrogate models | grey box | 0.60 | 0.95 | **9.60** [8.9, 10.3] |
| physical knobs, allow/stop answers only | black box | 3.29 | 3.71 | **15.06** [14.1, 16.0] |

**How to read the two white-box rows.** The feature-space attacker may move every mutable column
independently within its bounds, so it is an **upper bound** on what the realism spec allows. The
physical-knob attacker moves 4 actions that each change several columns together, as real traffic
would, so it is the **realistic** white-box number. The truth for a skilled attacker lies between
the two (22–39% in spec C).

**Knowledge matters, but not as much as freedom.** A black box with 1,000 allow/stop answers per
row reaches 70% of the white-box physical attacker (15.1 vs 21.7%). The grey box, which trains its
own models on half the data and never queries the real ones, still reaches 9.6% in spec C:
realizable evasions **transfer** from the attacker's models to the defender's.

**Fooling one model is not fooling the ensemble** (spec C, feature space): attacking only the CNN
gets past the CNN on 54% of rows but past all three on 6%. The OR-ensemble buys real robustness;
an attacker has to target all members at once (the `_ens` rows above).

### 11.4 Where the hole is: window population and category (spec C)

| attacker | 10-packet population | 100-packet population |
| --- | ---: | ---: |
| feature-space PGD | 64.60% | 8.66% |
| physical knobs PGD | 38.80% | 1.42% |
| black box | 27.26% | 0.66% |
| grey box | 17.64% | 0.10% |

| attacker (spec C) | BruteForce | Web | Recon | Spoofing | DDoS | DoS | Mirai |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| feature-space PGD | 62.9 | 84.1 | 53.6 | 62.4 | 4.7 | 4.8 | 0.2 |
| physical knobs PGD | 49.6 | 47.1 | 23.9 | 30.1 | 0.9 | 0.0 | 0.1 |
| black box | 40.0 | 27.1 | 14.4 | 23.2 | 0.7 | 0.0 | 0.0 |

- **Floods are safe; the stealthy categories are not.** Every attack category that shares the
  benign 10-packet window loses a quarter to two thirds of its detections to a realistic
  attacker; floods lose at most 5%.
- **The flood floor is not what protects them.** Allowing floods to drop to 25% of their rate
  instead of 50% changes their evasion by at most 0.4 points (sweep in Table IV-d §8). What
  separates floods is the 100-packet window's statistics, which the attacker cannot change.

### 11.5 The lever: short connections

Among successful spec C attacks (physical knobs, black box, grey box), **90–98% shorten the
attacker's connections**, to a median 0.28–0.58× of their original lifetime. The grey box's
successes use *nothing else*: median padding 0, throttling 0, TTL change 0.

| attack (spec C) | wins | younger connections | padding | throttling | TTL changed | median lifetime |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| physical knobs PGD | 1,365 | 94.1% | 57.3% | 50.8% | 91.5% | ×0.31 |
| grey box | 605 | 98.3% | 41.7% | 29.8% | 90.1% | ×0.28 |
| black box | 949 | 90.2% | 70.9% | 90.3% | 100% | ×0.58 |

In traffic terms: **a quiet attack spread over many short-lived connections** (new source port
every few packets) looks benign to models that read per-connection running totals (`rst_count`,
`urg_count`, `Header_Length`, `flow_duration`). This is also why spec B (keep-alive only) is so much
weaker than C: making a connection *longer* rarely helps, and the evidence is that the attacks do not
use it (5–10% of wins).

**The caveat that matters:** every fresh TCP connection costs a handshake (SYN, SYN-ACK, ACK).
Spec C does not model the extra handshake packets inside a window, which would change that window's
flag columns. Until M7 checks this at packet level, spec C is an **upper estimate** of the churn
attacker, and spec A a **lower bound** of the packet-level attacker.

### 11.6 What the validator adds against realistic attacks

Of the rows that fool all three models, the real validator stops **6–14%**:

| spec | feature-space PGD: fooled models → stopped by validator | physical knobs PGD |
| --- | --- | --- |
| A | 511 → 59 (11.5%) | 220 → 25 (11.4%) |
| B | 1,536 → 213 (13.9%) | 367 → 45 (12.3%) |
| C | 2,729 → 275 (10.1%) | 1,456 → 91 (6.2%) |

A validator-aware attacker wins about a third of those back (spec C feature space: 38.95% →
40.44%). **On IDS2018 the validator was the whole defense; here, against realizable attacks, it is
a minor obstacle.** By construction a realizable row satisfies the integrality and dependency rules
(§5), so only the range and distribution families can fire, and an attacker who stays close to its
own original traffic rarely trips them.

### 11.7 What success costs (spec C, medians over successful rows)

| attack | byte overhead | rate loss | TTL change |
| --- | ---: | ---: | ---: |
| physical knobs PGD | 16.3% | 4.7% | 0 |
| black box | 2.7% | 4.7% | 2.8 |
| grey box | 0% | 0% | 0 |

Cheap. The main cost of the successful attacks is operational (more, shorter connections), not
bandwidth or speed.


---

## 12. What this means for the thesis and for M5–M8

**For the thesis.**

1. **The paper's evaluation overstates both the threat and the defense.** Unconstrained attacks
   look devastating (up to 100% evasion) and the validator looks perfect against them (≤ 0.04%
   pass-and-evade). Both are artefacts of unrealizable rows. Against realizable attacks the models
   are much harder to fool (Table IV-c), but the validator also stops being the defense (§11.6).
2. **The real weakness is a feature-design one.** Per-connection running totals are
   attacker-controlled through connection management. That is a concrete, defensible finding:
   the models should either not rely on them, or the defense must account for connection churn.
3. **Report ranges, not points.** Every headline number is reported for specs A/B/C with
   intervals, because the size of the hole depends on an assumption about connection behaviour
   that only packet-level work (M7) can settle.

**Hand-over to M5 (discriminator + arms race).**
- `artifacts/adversarial_real/test_spec{A,B,C}/` hold 12 cells each, readable by
  `discriminator.load_cells`, tagged with `strategy` (feature / primitive / adaptive / transfer /
  query) and `tier` for leave-one-strategy-out.
- The discriminator should be trained on **train/val-split** adversarial rows and scored on these
  test cells. 03b runs on `--split val` (and a `--split train` option is a one-line change).
- Key question for M5: can a Random Forest learn "a row whose connection is unusually young for
  its packet sizes"? The churn attack is the obvious arms-race target.

**Hand-over to M6 (adversarial training).** `Attacker.prim_pgd` / `feat_pgd` with `P` are the
in-loop attacker. Compiled, a PGD step on 1,024 rows costs milliseconds on CPU, so in-loop
training is affordable here. Train against **spec C** (the strongest), evaluate on all three.

**Hand-over to M7 (packet level).** The assumptions of `g` to verify by applying θ to real PCAPs
and re-extracting features:
1. padding reaches every packet of the window (size statistics shift by `pad`);
2. `Magnitue² + 2·pad` and `Tot sum ∝ AVG` hold after padding;
3. the window's mean TTL moves with the attacker's own packets;
4. throttling stretches `flow_duration` by 1 / (1 − slow) and lowers `Rate` accordingly;
5. connection lifetime scales `flow_duration`, `Header_Length` and the `*_count` columns together;
6. **connection churn's handshake packets** — how much they change the flag columns of the
   windows they fall into (the biggest open question, §11.5).

**For M8.** The OR-ensemble at 2% per member (3.27%) plus the validator (1.01%) already flags
about 4% of benign traffic (§3.2). The end-to-end evaluation should fix one pipeline-wide FPR budget first.

---

## 13. Files, commands, and deviations from the plan

### Files

| file | what |
| --- | --- |
| `config/realism.yaml` | the realism spec (all 46 columns, floors, specs A/B/C) |
| `src/aad/attacks/realizable/constraints.py` | `RealismSpec`, `Scaling`, the projection `Projector` (P) |
| `src/aad/attacks/realizable/primitives.py` | θ, g, attacker cost, floor check |
| `src/aad/attacks/realizable/attacks.py` | the attack suite, row selection, window populations |
| `scripts/02c_calibrate_thresholds.py` | D2 thresholds → `artifacts/models/thresholds.json`, `reports/thresholds.md` |
| `scripts/03a_audit_realism.py` | measures every relation the spec assumes → `reports/realism_audit.md` |
| `scripts/03b_generate_realizable.py` | runs the attacks → `artifacts/adversarial_real/<split>_spec<X>/`, `reports/table4b_*`, `table4c_*` |
| `scripts/03c_tune_realizable.py` | the validation sweep → `reports/realizable_tuning_val_spec*.md` |
| `scripts/03d_summarize_realizable.py` | cross-spec tables → `reports/table4d_tiers.md`, `realizable_levers.csv` |
| `tests/test_realizable.py`, `tests/test_attacks_realizable.py`, `tests/test_evaluate.py` | 47 tests on synthetic data |

### Commands

```powershell
..\.venv\Scripts\python.exe scripts\02c_calibrate_thresholds.py
..\.venv\Scripts\python.exe scripts\02_train_baselines.py --models mlp cnn --train-frac 0.5 --seed 7 --tag surr
..\.venv\Scripts\python.exe scripts\03a_audit_realism.py
..\.venv\Scripts\python.exe scripts\03c_tune_realizable.py
..\.venv\Scripts\python.exe scripts\03b_generate_realizable.py --attacks art_projected
..\.venv\Scripts\python.exe scripts\03b_generate_realizable.py --split test --spec C        # also --spec A, --spec B
..\.venv\Scripts\python.exe scripts\03b_generate_realizable.py --split test --spec C --flood-floor 0.25 --attacks feat_pgd_ens prim_pgd_ens blackbox
..\.venv\Scripts\python.exe scripts\03d_summarize_realizable.py
```

### Deviations from `m4-plan.md`

| plan (`m4-plan.md`) | what was done | why |
| --- | --- | --- |
| flow-age specs A and B | **A, B and C** | CIC's extractor shows the columns are per-connection totals, which fresh connections *reset* (§2.2) |
| spec A = flow age frozen, throttling allowed | spec A also freezes `Rate` | `Rate` = connection packets / age; the first test run exposed the inconsistency (§11.1) |
| a numpy twin of P | one TF implementation used from numpy too | one source of truth; the tests pin it to the validator's numpy units instead |
| λ by per-row binary search | λ **ladder**, higher rungs only for rows the validator stopped | the full ladder cost 27–55 min per cell for 0–2 extra rows |
| PGD with fixed steps | **10 random restarts** | the black box beat the gradient attack; restarts fixed it (§10) |
| eager TensorFlow | compiled `tf.function` step, success read from the same forward pass | 69–134× faster on CPU, identical results; made 900 rows/category and three specs affordable |
| `table4d_tiers` from 03b | a separate summary script, 03d | it compares across specs, which no single 03b run sees |
| discriminator-aware attacks | moved to M5 (D5) | the M5 forest did not exist yet |

### Bugs fixed during M4 (each pinned by a test)

See §9 for the five found by the first smoke runs. Two more came later: spec A's free throttle
(§11.1) and a report-naming bug (`Path.with_suffix` treated the ".25" of `floor0.25` as a file
extension, so two sweep reports overwrote each other; rebuilt from the saved cells).
