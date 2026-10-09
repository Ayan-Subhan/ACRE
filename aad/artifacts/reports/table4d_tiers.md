# Table IV-d - realizable attacks across knowledge tiers and flow-age specs

Test split, 6,300 source rows (900 per attack category), each detected by MLP, CNN and LSTM at their calibrated thresholds. Cell = **pass-and-evade %**: no model detects the row AND the real validator lets it through [95% bootstrap interval]. Spec A: padding + TTL only; B: + longer connections; C: + longer or fresh connections.

## 1. Overall

| attacker | tier | spec A | spec B | spec C |
| --- | --- | ---: | ---: | ---: |
| `feat_pgd_ens` (feature space) | white | 7.17 [6.6, 7.8] | 21.00 [20.0, 22.0] | 38.95 [37.7, 40.2] |
| `adaptive_feat` (feature space, validator-aware) | white | 7.56 [6.9, 8.2] | 21.79 [20.8, 22.8] | 40.44 [39.2, 41.7] |
| `prim_pgd_ens` (physical knobs) | white | 3.10 [2.7, 3.5] | 5.11 [4.6, 5.6] | 21.67 [20.6, 22.7] |
| `adaptive_prim` (physical knobs, validator-aware) | white | 2.98 [2.6, 3.4] | 5.30 [4.7, 5.8] | 22.37 [21.3, 23.4] |
| `greybox` (physical knobs, own surrogate models) | grey | 0.60 [0.4, 0.8] | 0.95 [0.7, 1.2] | 9.60 [8.9, 10.3] |
| `blackbox` (physical knobs, allow/stop answers only) | black | 3.29 [2.8, 3.7] | 3.71 [3.2, 4.2] | 15.06 [14.1, 16.0] |

## 2. By window population (pass-and-evade %)

| attacker | A: 10-pkt | A: 100-pkt | B: 10-pkt | B: 100-pkt | C: 10-pkt | C: 100-pkt |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `feat_pgd_ens` | 10.08 | 3.74 | 33.18 | 6.61 | 64.60 | 8.66 |
| `adaptive_feat` | 10.58 | 3.98 | 33.94 | 7.44 | 66.44 | 9.73 |
| `prim_pgd_ens` | 5.42 | 0.35 | 9.06 | 0.45 | 38.80 | 1.42 |
| `adaptive_prim` | 5.19 | 0.38 | 9.35 | 0.52 | 40.01 | 1.52 |
| `greybox` | 1.11 | 0.00 | 1.70 | 0.07 | 17.64 | 0.10 |
| `blackbox` | 5.74 | 0.38 | 6.59 | 0.31 | 27.26 | 0.66 |

## 3. By category, spec C (pass-and-evade %)

| attacker | BruteForce | Web | Recon | Spoofing | DDoS | DoS | Mirai |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `feat_pgd_ens` | 62.9 | 84.1 | 53.6 | 62.4 | 4.7 | 4.8 | 0.2 |
| `adaptive_feat` | 63.7 | 87.3 | 56.9 | 63.9 | 5.4 | 5.7 | 0.2 |
| `prim_pgd_ens` | 49.6 | 47.1 | 23.9 | 30.1 | 0.9 | 0.0 | 0.1 |
| `adaptive_prim` | 49.2 | 48.7 | 25.3 | 32.3 | 1.0 | 0.0 | 0.0 |
| `greybox` | 23.4 | 23.1 | 10.3 | 10.3 | 0.0 | 0.0 | 0.0 |
| `blackbox` | 40.0 | 27.1 | 14.4 | 23.2 | 0.7 | 0.0 | 0.0 |

## 4. One model at a time (spec C): fooling one member is not fooling the ensemble

| attack | target | pass-and-evade on its target | also evades all three |
| --- | --- | ---: | ---: |
| `feat_pgd` | mlp | 49.52 | 12.10 |
| `feat_pgd` | cnn | 53.94 | 6.30 |
| `feat_pgd` | lstm | 54.29 | 4.56 |
| `prim_pgd` | mlp | 31.59 | 10.00 |
| `prim_pgd` | cnn | 35.59 | 8.52 |
| `prim_pgd` | lstm | 43.94 | 4.83 |

## 5. What the validator adds against realizable attacks (test, ensemble cells)

`fooled models` = rows no model detects; `stopped by validator` = of those, rows the real validator rejects.

| spec | attack | fooled models | stopped by validator | share stopped |
| --- | --- | ---: | ---: | ---: |
| A | `feat_pgd_ens` | 511 | 59 | 11.5% |
| A | `prim_pgd_ens` | 220 | 25 | 11.4% |
| B | `feat_pgd_ens` | 1536 | 213 | 13.9% |
| B | `prim_pgd_ens` | 367 | 45 | 12.3% |
| C | `feat_pgd_ens` | 2729 | 275 | 10.1% |
| C | `prim_pgd_ens` | 1456 | 91 | 6.2% |

## 6. Which physical actions the successful attacks use (spec C)

Among pass-and-evade rows. `younger` = connections shortened (stretch < 0, fresh connections); `lifetime` = median factor on `flow_duration`.

| attack | wins | younger connections | longer | padding | throttling | TTL changed | median lifetime |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `prim_pgd_ens_ens` | 1365 | 94.1% | 4.8% | 57.3% | 50.8% | 91.5% | ×0.31 |
| `adaptive_prim_ens` | 1409 | 93.5% | 5.5% | 57.2% | 52.7% | 91.8% | ×0.32 |
| `greybox_surr` | 605 | 98.3% | 1.5% | 41.7% | 29.8% | 90.1% | ×0.28 |
| `blackbox_ens` | 949 | 90.2% | 9.8% | 70.9% | 90.3% | 100.0% | ×0.58 |

## 7. What success costs the attacker (spec C, medians over pass-and-evade rows)

| attack | byte overhead | rate loss | TTL change | features changed |
| --- | ---: | ---: | ---: | ---: |
| `feat_pgd_ens` | 12.3% | 38.4% | 0.0 | 11 |
| `adaptive_feat` | 12.3% | 38.4% | 0.0 | 11 |
| `prim_pgd_ens` | 16.3% | 4.7% | 0.0 | 11 |
| `adaptive_prim` | 9.9% | 4.7% | 0.0 | 11 |
| `greybox` | 0.0% | 0.0% | 0.0 | 8 |
| `blackbox` | 2.7% | 4.7% | 2.8 | 13 |

## 8. Flood functional-floor sweep (spec C, pass-and-evade %)

Floods must keep at least ρ of their original rate.

| attack | category | ρ = 0.25 | ρ = 0.5 | ρ = 0.75 |
| --- | --- | ---: | ---: | ---: |
| `feat_pgd_ens` | DDoS | 4.78 | 4.67 | 4.56 |
| `feat_pgd_ens` | DoS | 5.22 | 4.78 | 4.22 |
| `feat_pgd_ens` | Mirai | 0.33 | 0.22 | 0.22 |
| `prim_pgd_ens` | DDoS | 1.11 | 0.89 | 0.44 |
| `prim_pgd_ens` | DoS | 0.11 | 0.00 | 0.00 |
| `prim_pgd_ens` | Mirai | 0.11 | 0.11 | 0.00 |
| `blackbox` | DDoS | 0.56 | 0.67 | 0.67 |
| `blackbox` | DoS | 0.00 | 0.00 | 0.00 |
| `blackbox` | Mirai | 0.00 | 0.00 | 0.00 |

## 9. Phase-3 ART attacks projected onto realizable traffic (Table IV-c, PGD)

| target | evasion before | after P, spec A | spec B | spec C |
| --- | ---: | ---: | ---: | ---: |
| mlp | 62.64 | 1.76 | 4.59 | 7.97 |
| cnn | 99.85 | 2.36 | 6.11 | 10.81 |
| lstm | 48.03 | 1.62 | 7.79 | 13.58 |
