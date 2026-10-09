# Table IV-b - realizable attacks (test split, flow-age spec C)

6300 source rows (900 per attack category), each detected by every baseline at its calibrated threshold. `evasion` = no targeted model detects the row; `pass_and_evade` = that AND the real validator lets it through. Brackets: 95% bootstrap intervals. Costs are medians over the pass-and-evade rows.

## Overall and by window population

| attack       | model   | group       |    n |   evasion_% |   evasion_lo |   evasion_hi |   passes_validator_% |   pass_and_evade_% |   pass_and_evade_lo |   pass_and_evade_hi |   evades_all3_% |   med_byte_overhead_% |   med_rate_loss_% |   med_ttl_change |   med_features_changed |
|:-------------|:--------|:------------|-----:|------------:|-------------:|-------------:|---------------------:|-------------------:|--------------------:|--------------------:|----------------:|----------------------:|------------------:|-----------------:|-----------------------:|
| feat_pgd_ens | ens     | ALL         | 6300 |       43.35 |        42.13 |        44.56 |                60.30 |              39.05 |               37.86 |               40.25 |           43.35 |                 12.28 |             38.50 |             0.00 |                  11.00 |
| feat_pgd_ens | ens     | pop:10-pkt  | 3412 |       68.99 |        67.35 |        70.49 |                75.88 |              64.62 |               63.01 |               66.24 |           68.99 |                 12.30 |             38.09 |             0.00 |                  11.00 |
| feat_pgd_ens | ens     | pop:100-pkt | 2888 |       13.05 |        11.81 |        14.41 |                41.90 |               8.83 |                7.86 |                9.97 |           13.05 |                  5.97 |             50.22 |             2.55 |                  12.00 |
| prim_pgd_ens | ens     | ALL         | 6300 |       23.25 |        22.24 |        24.32 |                46.00 |              22.00 |               20.98 |               23.02 |           23.25 |                 16.93 |              4.75 |             0.00 |                  11.00 |
| prim_pgd_ens | ens     | pop:10-pkt  | 3412 |       41.24 |        39.54 |        42.91 |                59.32 |              39.16 |               37.49 |               40.83 |           41.24 |                  5.28 |              0.46 |             0.00 |                  11.00 |
| prim_pgd_ens | ens     | pop:100-pkt | 2888 |        2.01 |         1.49 |         2.56 |                30.26 |               1.73 |                1.25 |                2.22 |            2.01 |                912.37 |             27.08 |            27.63 |                  15.00 |
| blackbox     | ens     | ALL         | 6300 |       15.25 |        14.35 |        16.16 |                64.40 |              15.25 |               14.35 |               16.16 |           15.25 |                  2.32 |              4.63 |             2.17 |                  13.00 |
| blackbox     | ens     | pop:10-pkt  | 3412 |       27.61 |        26.08 |        29.07 |                75.73 |              27.61 |               26.08 |               29.07 |           27.61 |                  1.70 |              4.33 |             2.13 |                  13.00 |
| blackbox     | ens     | pop:100-pkt | 2888 |        0.66 |         0.38 |         0.97 |                51.00 |               0.66 |                0.38 |                0.97 |            0.66 |                626.99 |             11.48 |            10.30 |                  15.00 |

## Pass-and-evade % by category

|                         |   BruteForce |   DDoS |   DoS |   Mirai |   Recon |   Spoofing |   Web |
|:------------------------|-------------:|-------:|------:|--------:|--------:|-----------:|------:|
| ('blackbox', 'ens')     |        40.11 |   0.56 |  0.00 |    0.00 |   14.56 |      25.00 | 26.56 |
| ('feat_pgd_ens', 'ens') |        62.78 |   4.78 |  5.22 |    0.33 |   53.67 |      62.67 | 83.89 |
| ('prim_pgd_ens', 'ens') |        49.22 |   1.11 |  0.11 |    0.11 |   25.00 |      30.22 | 48.22 |
