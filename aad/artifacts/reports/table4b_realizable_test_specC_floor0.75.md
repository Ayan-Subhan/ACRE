# Table IV-b - realizable attacks (test split, flow-age spec C)

6300 source rows (900 per attack category), each detected by every baseline at its calibrated threshold. `evasion` = no targeted model detects the row; `pass_and_evade` = that AND the real validator lets it through. Brackets: 95% bootstrap intervals. Costs are medians over the pass-and-evade rows.

## Overall and by window population

| attack       | model   | group       |    n |   evasion_% |   evasion_lo |   evasion_hi |   passes_validator_% |   pass_and_evade_% |   pass_and_evade_lo |   pass_and_evade_hi |   evades_all3_% |   med_byte_overhead_% |   med_rate_loss_% |   med_ttl_change |   med_features_changed |
|:-------------|:--------|:------------|-----:|------------:|-------------:|-------------:|---------------------:|-------------------:|--------------------:|--------------------:|----------------:|----------------------:|------------------:|-----------------:|-----------------------:|
| feat_pgd_ens | ens     | ALL         | 6300 |       43.27 |        42.05 |        44.49 |                60.40 |              38.95 |               37.75 |               40.19 |           43.27 |                 12.28 |             37.05 |             0.00 |                  11.00 |
| feat_pgd_ens | ens     | pop:10-pkt  | 3412 |       69.20 |        67.56 |        70.69 |                76.14 |              64.74 |               63.07 |               66.35 |           69.20 |                 12.30 |             36.74 |             0.00 |                  11.00 |
| feat_pgd_ens | ens     | pop:100-pkt | 2888 |       12.64 |        11.39 |        13.96 |                41.79 |               8.48 |                7.51 |                9.59 |           12.64 |                  5.96 |             38.10 |             2.22 |                  12.00 |
| prim_pgd_ens | ens     | ALL         | 6300 |       23.02 |        21.98 |        24.03 |                45.21 |              21.67 |               20.65 |               22.70 |           23.02 |                  7.36 |              4.75 |             0.00 |                  11.00 |
| prim_pgd_ens | ens     | pop:10-pkt  | 3412 |       41.18 |        39.48 |        42.88 |                58.44 |              39.10 |               37.40 |               40.86 |           41.18 |                  3.25 |              1.09 |             0.00 |                  11.00 |
| prim_pgd_ens | ens     | pop:100-pkt | 2888 |        1.56 |         1.11 |         2.04 |                29.57 |               1.07 |                0.69 |                1.45 |            1.56 |                733.84 |             16.39 |            12.70 |                  15.00 |
| blackbox     | ens     | ALL         | 6300 |       14.79 |        13.90 |        15.67 |                64.30 |              14.79 |               13.90 |               15.67 |           14.79 |                  4.55 |              5.44 |             2.14 |                  13.00 |
| blackbox     | ens     | pop:10-pkt  | 3412 |       26.64 |        25.20 |        28.08 |                75.56 |              26.64 |               25.20 |               28.08 |           26.64 |                  3.53 |              5.16 |             2.08 |                  13.00 |
| blackbox     | ens     | pop:100-pkt | 2888 |        0.80 |         0.48 |         1.14 |                51.00 |               0.80 |                0.48 |                1.14 |            0.80 |                480.53 |              7.98 |            14.65 |                  15.00 |

## Pass-and-evade % by category

|                         |   BruteForce |   DDoS |   DoS |   Mirai |   Recon |   Spoofing |   Web |
|:------------------------|-------------:|-------:|------:|--------:|--------:|-----------:|------:|
| ('blackbox', 'ens')     |        39.11 |   0.67 |  0.00 |    0.00 |   14.67 |      23.89 | 25.22 |
| ('feat_pgd_ens', 'ens') |        63.00 |   4.56 |  4.22 |    0.22 |   53.56 |      63.00 | 84.11 |
| ('prim_pgd_ens', 'ens') |        48.89 |   0.44 |  0.00 |    0.00 |   23.67 |      30.89 | 47.78 |
