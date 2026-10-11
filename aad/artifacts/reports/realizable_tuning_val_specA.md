# White-box attack tuning on val (spec A)

700 val rows (100 per attack category), detected by all three baselines at their calibrated thresholds; ensemble target (OR rule). `step` is the L-inf step in scaled units (feat) or the fraction of each theta range (prim). Success judged by the deployed models and the real validator.

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
