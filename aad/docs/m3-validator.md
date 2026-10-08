# M3 — the validator (gate 1) on CICIoT2023, step by step

Milestone M3 of [`ciciot2023-implementation-plan.md`](ciciot2023-implementation-plan.md).
Inputs: the M1 dataset (39 features; [`m1-data-pipeline.md`](m1-data-pipeline.md)) and
the M2 baselines ([`m2-baselines.md`](m2-baselines.md)). Run date: 2026-10-08, CPU.

> ## Update 2026-10-08: re-run on 38 features (no `IAT`) (current state)
>
> Sections 1–7 below describe the first M3 run on the 39-feature data, archived in
> `artifacts/superseded/39features/`. After `IAT` was dropped and the baselines retrained on
> the GPU ([`m2-baselines.md`](m2-baselines.md), update), M3 was re-run: the 12 attack sets
> were regenerated on the GPU (`03_generate_ae.py --no-sweep`, < 2 min) and the rules re-mined
> (`04_analyze_validate.py`). The current `artifacts/rules.json` and
> `artifacts/reports/table5_validator.md` are from this run.
>
> - **Same rule set:** 15 integral columns, the same 14 dependency rules kept, the same 2
>   pruned. Distribution thresholds: TCP 6.43, UDP 10.11, ARP 8.52, other 8.80, ICMP 6.92.
> - **Benign FPR 1.031%**, almost all distribution (per group: TCP 1.03, UDP 1.07, other
>   1.05, ARP 2.63 on 38 rows).
> - **Gate 1 still stops the unconstrained attacks end to end.** At most **0.02%** of any set
>   passes the validator *and* fools its model (was ≤ 0.02%). Mean combined catch 95.54%,
>   62.64% attributable to perturbation. The distribution family still carries it (sole
>   catches 4.45%; integrality and dependency 0%).
> - **The attacks are weaker against the retrained models.** Without any gate, PGD fools the
>   CNN on 68.56% of rows (98.56% before) and the MLP on 34.96% (31.34% before); the MLP
>   attacks move only 16–18 of 38 features. The MLP saturation effect of §4.3 is stronger
>   (82.2% combined catch on its gradient-sign sets; the unperturbed rows explain the gap).
>   With the hardware, the data and the weights all changed, the cause is not isolated;
>   M4's attacks start from these models.

---

## 1. What was run

| # | Command | What it does | Time |
| --- | --- | --- | ---: |
| 1 | `python scripts\03_generate_ae.py --no-sweep` | the paper-baseline attacks (FGSM, BIM, PGD, DeepFool) on the M2 MLP/CNN/LSTM: 12 sets × 5,000 rows into `artifacts/adversarial/` | ~25 min |
| 2 | `python scripts\04_analyze_validate.py` | mine rules on benign **train**, calibrate on benign **val**, measure on **test** and on the 12 adversarial sets | ~1 min |
| 3 | `python -m pytest tests -q` | 116 tests (25 new for the validator and its differentiable twin) | ~6 s |

Logs: `artifacts/reports/generate_ae_run.log`, `validate_run.log`. Outputs:
`artifacts/rules.json`, `artifacts/reports/table5_validator.{csv,md}`,
`validator_metrics.json`.

## 2. Why the IDS2018 validator could not be reused

| | IDS2018 (CICFlowMeter, per flow) | CICIoT2023 (DPKT, per packet window) |
| --- | --- | --- |
| rules declared | `Fwd Pkt Len Min ≤ Mean ≤ Max`, `TotLen = count × mean`, `Flow Pkts/s = packets / duration`, … | none of these columns exist |
| raw units | MinMax inverse | MinMax inverse **plus** signed log1p inverse on 16 columns (M1 step 6) |
| integrality | packet counts, ports, flag counts | the 0/1 flags and protocol indicators (see below) |
| benign traffic | one profile | a mixture of protocols with very different statistics |

**First, the candidate rules were measured on the real data** (all 2.5 M rows of the M1
sample, raw units), rather than assumed:

| candidate relation | violated in benign rows | violated in all rows | verdict |
| --- | ---: | ---: | --- |
| `Min ≤ AVG ≤ Max` | 0% | 0% | exact |
| `Srate == Rate` | 0% (identical in every row) | 0% | exact |
| `IPv == LLC` | 0% | 0% | exact |
| `HTTP / HTTPS / SSH ≤ TCP`, `DNS ≤ UDP` | 0% | 0% | exact |
| every TCP flag ≤ `TCP` | 0% | 0% | exact |
| `TCP + UDP + ICMP ≤ 1`, `ARP + IPv ≤ 1` | 0% | 0% | exact |
| `6·TCP + 17·UDP + ICMP ≤ Protocol Type` | 13.8% | 14.9% | **false** |
| `Tot sum ≈ Number × AVG` | residual p99.9 = 0.51 | — | **false**: a mean of products is not a product of means |

The same measurement showed that **flags and protocol indicators are strictly 0 or 1 in
every row**. They are not window fractions, as the plan had assumed. So the integrality
family does not disappear on this dataset.

## 3. The rule set

### 3.1 How rules are declared, calibrated and pruned

- **Declared** in [`src/aad/defense/rules_ciciot2023.py`](../src/aad/defense/rules_ciciot2023.py)
  by column name. Four kinds:
  - `ordering`: min ≤ mean ≤ max.
  - `equal`: two columns the extractor emits identically.
  - `linear_le`: Σ coef·lhs ≤ Σ coef·rhs + c. This one form covers the protocol hierarchy,
    "flags exist only on TCP" and mutually exclusive transports.
  - `product`: total ≈ count × mean.
- **Calibrated** in [`src/aad/defense/analyzer.py`](../src/aad/defense/analyzer.py): each
  rule's residual is measured on the 768,724 benign train rows, and its tolerance is set
  to max(p99.9 × 10, 10⁻⁶).
- **Pruned (new):** a rule whose calibrated relative tolerance exceeds
  `DEPENDENCY_MAX_TOL = 0.05` is a tendency, not an invariant. It goes to
  `dependency.excluded_loose` in `rules.json` with its residual percentiles and the
  reason. So the declarations are hypotheses, and the data decides what is enforced.
- **Skipped automatically:** any candidate that references a column M1 dropped (Telnet,
  SMTP, IRC, DHCP, ECE/CWR flags).

### 3.2 What was mined (`artifacts/rules.json`)

| family | content |
| --- | --- |
| **range** | per-column [min, max] of benign train, padded by 1% of the span |
| **integrality** (15) | `fin/syn/rst/psh/ack_flag_number`, `HTTP`, `HTTPS`, `DNS`, `SSH`, `TCP`, `UDP`, `ARP`, `ICMP`, `IPv`, `LLC` |
| **dependency kept** (14) | `Min ≤ AVG ≤ Max`; `Srate == Rate`; `IPv == LLC`; HTTP/HTTPS/SSH ⇒ TCP; DNS ⇒ UDP; FIN/SYN/RST/PSH/ACK ⇒ TCP; `TCP+UDP+ICMP ≤ 1`; `ARP+IPv ≤ 1`, all at tolerance 10⁻⁶ (benign residual exactly 0) |
| **dependency pruned** (2) | `6·TCP+17·UDP+ICMP ≤ Protocol Type` (benign p99.9 0.489); `Tot sum ≈ Number × AVG` (0.51) |
| **distribution** | median/MAD per protocol group: TCP 661,088 benign train rows, UDP 52,446, ARP 175, other 55,007, ICMP 8 (global profile) |

`integrality.excluded_unverifiable` lists `IAT`. Its values look integral, but its span
(1.7 × 10⁸) makes the float32 tolerance far larger than 0.25, so no honest check is
possible. The 16 log1p columns are never integrality-checked: after `expm1` their
round-trip error grows with the value.

### 3.3 Raw units

`Validator.to_raw` = MinMax inverse, then `sign(y)·(exp|y|−1)` on the log1p columns. All
parameters are copied from `data/processed/transform.json` into `rules.json`, so the
validator stays pure numpy. Checked on 50,000 real rows: maximum relative error
**5.6 × 10⁻⁷** (float32 storage), median 1.4 × 10⁻¹⁰.

### 3.4 The distribution family is now per protocol

Benign IoT traffic is a mixture: TCP, UDP, ARP and indicator-less windows have very
different statistics. One global median/MAD calls every minority-protocol row an outlier.
So each row is scored against benign rows **of its own protocol group** (first set
indicator among TCP, UDP, ICMP, ARP; else "other"), and every group gets its own
threshold at the 1% budget:

| group | benign train rows | profile | threshold | calibrated on |
| --- | ---: | --- | ---: | --- |
| TCP | 661,088 | own | 5.175 | val |
| UDP | 52,446 | own | 10.789 | val |
| other | 55,007 | own | 9.879 | val |
| ARP | 175 | own | 10.331 | train + val (in-sample, recorded) |
| ICMP | 8 | global | 6.855 | global |

**A bug found and fixed on the way.** The first run required 1,000 benign train rows for
a group to get its own profile. ARP (175) fell back to the global, TCP-dominated profile,
and **100% of benign ARP test rows were rejected**. Lowering the minimum to 100 and
calibrating tiny groups on pooled train+val brought ARP to **1.85%** (1 of 54 test rows).
The in-sample calibration is recorded in `rules.json` (`threshold_source`), because it is
slightly optimistic. Regression tests:
`test_small_protocol_groups_get_their_own_profile_tiny_ones_fall_back` and
`test_small_group_benign_rows_are_not_mass_rejected`.

## 4. Results (Table V)

Full table: `artifacts/reports/table5_validator.md`.

### 4.1 Cost: false positives on unseen benign test traffic

| | rows | rejected | range | integrality | dependency | distribution |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| clean benign (test) | 164,727 | **0.968%** | 0.001% | 0% | 0% | 0.968% |

| protocol group | benign test rows | FPR |
| --- | ---: | ---: |
| TCP | 141,589 | 0.954% |
| UDP | 11,252 | 1.102% |
| other | 11,831 | 1.006% |
| ARP | 54 | 1.852% |
| ICMP | 1 | 0% |

The arithmetic families (range, integrality, dependency) cost essentially nothing. The
whole cost is the distribution family's deliberate 1% budget, spent evenly across groups.
This is the same as on IDS2018 (0.948%).

### 4.2 Baseline: clean attack rows already outside the benign envelope

| category | test rows | rejected unperturbed | mostly by |
| --- | ---: | ---: | --- |
| Mirai | 27,000 | 65.9% | range |
| DDoS | 97,830 | 50.2% | distribution |
| DoS | 36,000 | 39.7% | distribution |
| BruteForce | 1,960 | 18.3% | range |
| Recon | 32,946 | 12.2% | distribution |
| Web | 3,724 | 10.3% | range |
| Spoofing | 18,000 | 3.3% | both |

This is why every catch rate below must be read next to `clean_orig_%`, the same rows
unperturbed (39.3% of the 5,000 attack source rows). The stealthy categories mostly sit
**inside** the benign envelope: the validator does not see them as malicious, which is
right, because that is the EIDS's job.

### 4.3 Catch: the 12 unconstrained adversarial sets

| set | combined catch | clean_orig | attributable | evades model alone | **passes gate + evades model** |
| --- | ---: | ---: | ---: | ---: | ---: |
| FGSM × MLP | 86.42% | 39.32% | 47.10% | 12.72% | 0.02% |
| BIM × MLP | 86.42% | 39.32% | 47.10% | 25.34% | 0.02% |
| PGD × MLP | 86.42% | 39.32% | 47.10% | 31.34% | 0.02% |
| DeepFool × MLP | 99.98% | 39.32% | 60.66% | 70.04% | 0.02% |
| FGSM × CNN | 100% | 39.32% | 60.68% | 30.06% | 0 |
| BIM × CNN | 100% | 39.32% | 60.68% | 86.46% | 0 |
| PGD × CNN | 100% | 39.32% | 60.68% | 98.56% | 0 |
| DeepFool × CNN | 100% | 39.32% | 60.68% | 91.00% | 0 |
| FGSM × LSTM | 100% | 39.32% | 60.68% | 19.94% | 0 |
| BIM × LSTM | 100% | 39.32% | 60.68% | 57.62% | 0 |
| PGD × LSTM | 100% | 39.32% | 60.68% | 69.36% | 0 |
| DeepFool × LSTM | 100% | 39.32% | 60.68% | 85.96% | 0 |

**Reading it:**

1. **Against unconstrained attacks, gate 1 is essentially perfect end to end.** At most
   0.02% of any set both passes the validator and fools its target model, whereas without
   the gate PGD fools the CNN on 98.6% of rows.
2. **The MLP sets' 86.42% is not a hole in the validator.** For 45.26% of the MLP's
   source rows the gradient attacks changed **nothing**: zero features moved. Those rows
   are mostly floods the MLP is so confident about that its softmax saturates and the
   gradient vanishes. That is gradient masking by saturation, not robustness: 99.96% of
   them remain detected. Unperturbed rows can only be caught when they already sit
   outside the benign envelope. Every row that was actually perturbed is caught.
   (DeepFool works on logits, so it does not saturate. It moves those rows too, and they
   are caught at 99.98%.)
3. **Integrality no longer carries the gate alone.** On IDS2018 it caught 100% of every
   set and the other families were incidental. Here the families overlap heavily, and
   `sole_%` (rows caught by that family and no other) shows which one is load-bearing:

   | family | mean catch | mean sole catch |
   | --- | ---: | ---: |
   | range | 53.86% | 1.96% |
   | integrality | 88.68% | 0% |
   | dependency | 87.81% | 0% |
   | distribution | **93.73%** | **5.95%** |

   Integrality and dependency always fire together, because perturbing a 0/1 indicator
   breaks both its integrality and the protocol-hierarchy rules it takes part in. The
   **distribution** family is the only one with meaningful sole catches.

### 4.4 What this means for M4

These attacks never tried to satisfy the rules. A **realizable** attacker (M4) by
construction keeps flags and indicators binary, keeps `Srate = Rate`, keeps
`Min ≤ AVG ≤ Max` and never touches the protocol columns. So it satisfies integrality and
dependency **for free**, leaving range and distribution as the real gate, and only
distribution has shown sole catching power. That is exactly the gap the adaptive
attacker will probe, and why the differentiable twin below models distribution
explicitly.

## 5. The differentiable twin (for the M4 adaptive attacker)

[`src/aad/defense/validator_soft.py`](../src/aad/defense/validator_soft.py),
`SoftValidator(rules)`: the same rules as TensorFlow penalties over **scaled** inputs (the
space attacks perturb), reading the same `rules.json`.

| family | penalty | equivalence with the real gate |
| --- | --- | --- |
| range | Σ relu(lo − x) + relu(x − hi), per span | penalty > 0 ⇔ hard reject (tested) |
| dependency | Σ relu(residual − tolerance) | penalty > 0 ⇔ hard reject (tested) |
| integrality | Σ sin²(π·x) over the 15 binary columns | 0 on the lattice, ≈1 at x = 0.5 (smooth surrogate) |
| distribution | relu(score − group threshold) | penalty > 0 ⇔ hard reject, given the group (tested) |

The protocol group is a discrete choice, so it is computed once from the input and held
fixed while differentiating (BPDA-style). Tests (`tests/test_validator_soft.py`) pin
four things:
- raw-unit and residual agreement with numpy to 10⁻⁹;
- the zero-penalty ⇔ pass equivalences above;
- distribution-score parity;
- finite, nonzero gradients on violating rows.

Attack success must always be judged by the real `Validator`, never by this twin.

## 6. Decisions

- `artifacts/rules.json` (CICIoT2023, mined 2026-10-08) is the gate-1 rule set for
  M4–M8.
- Distribution budget stays at 1% per group (total FPR 0.97%, under the 3% usability line).
- The IDS2018 rule declarations were removed from the live code (the "Archive" decision);
  they are documented in `archive/cicids2018/rules.json`.

## 7. Files M3 touched

| file | change |
| --- | --- |
| `src/aad/defense/rules_ciciot2023.py` | **new**: candidate rules and protocol groups |
| `src/aad/defense/validator.py` | **rewritten**: `scaled_to_raw` (log1p-aware), `equal`/`linear_le` residuals, module-level `dependency_residual`, `protocol_group`, per-group distribution; CICFlowMeter rate rules removed |
| `src/aad/defense/analyzer.py` | **rewritten**: CICIoT2023 candidates, self-pruning (`excluded_loose`), log1p-aware integrality, per-group mining, per-group calibration with in-sample fallback for tiny groups |
| `src/aad/defense/validator_soft.py` | **new**: differentiable twin |
| `scripts/04_analyze_validate.py` | reads `transform.json`; per-group FPR, per-category reject, `sole_%`, `evade_model_only_%`, `pass_and_evade_%`; data-driven conclusions |
| `tests/validator_fixture.py` | **new**: shared synthetic CICIoT2023-style fixture |
| `tests/test_validator.py` | **rewritten** for CICIoT2023 (26 tests) |
| `tests/test_validator_soft.py` | **new** (7 tests) |
