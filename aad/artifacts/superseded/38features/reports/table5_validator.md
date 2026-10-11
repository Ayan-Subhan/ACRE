# Table V - validator catch-rate and false-positive rate (CICIoT2023)

Rules mined from 768,708 **benign training** rows. Distribution thresholds calibrated per protocol group on benign *validation* rows at a 1.0% budget. Everything below is measured on **test**, which neither pass saw. Walkthrough: `docs/m3-validator.md`.

| set                 | kind   |      n |   combined_% |   range_% |   integrality_% |   dependency_% |   distribution_% |   clean_orig_% |   attributable_% |   evade_model_only_% |   pass_and_evade_% |
|:--------------------|:-------|-------:|-------------:|----------:|----------------:|---------------:|-----------------:|---------------:|-----------------:|---------------------:|-------------------:|
| clean benign (test) | FPR    | 164724 |        1.031 |     0.001 |            0    |           0    |            1.03  |          nan   |           nan    |               nan    |             nan    |
| clean attack (test) | reject | 217459 |       32.185 |     9.001 |            0    |           0    |           23.302 |          nan   |           nan    |               nan    |             nan    |
| bim x cnn           | catch  |   5000 |      100     |    65.38  |          100    |          99.72 |           99.96  |           32.9 |            67.1  |                51.8  |               0    |
| bim x lstm          | catch  |   5000 |       99.98  |    68.8   |           99.98 |          99.24 |           99.7   |           32.9 |            67.08 |                34.14 |               0.02 |
| bim x mlp           | catch  |   5000 |       82.2   |    34.8   |           56.54 |          56.5  |           74.36  |           32.9 |            49.3  |                26.62 |               0    |
| deepfool x cnn      | catch  |   5000 |      100     |    77.62  |          100    |         100    |           98.56  |           32.9 |            67.1  |                37.82 |               0    |
| deepfool x lstm     | catch  |   5000 |       99.98  |    78.9   |           99.98 |          99.98 |           97.52  |           32.9 |            67.08 |                55.36 |               0.02 |
| deepfool x mlp      | catch  |   5000 |      100     |    39.48  |          100    |         100    |           98.28  |           32.9 |            67.1  |                49.12 |               0    |
| fgsm x cnn          | catch  |   5000 |      100     |    70.96  |          100    |          92.9  |          100     |           32.9 |            67.1  |                24.92 |               0    |
| fgsm x lstm         | catch  |   5000 |       99.98  |    55.6   |           99.98 |          86.44 |           99.28  |           32.9 |            67.08 |                17.14 |               0.02 |
| fgsm x mlp          | catch  |   5000 |       82.2   |    22.08  |           56.54 |          53.8  |           73.88  |           32.9 |            49.3  |                17.04 |               0    |
| pgd x cnn           | catch  |   5000 |      100     |    65.74  |          100    |          99.78 |           99.92  |           32.9 |            67.1  |                68.56 |               0    |
| pgd x lstm          | catch  |   5000 |       99.98  |    70.22  |           99.98 |          98.32 |           99.76  |           32.9 |            67.08 |                43.1  |               0.02 |
| pgd x mlp           | catch  |   5000 |       82.2   |    35.34  |           56.54 |          56.28 |           74.34  |           32.9 |            49.3  |                34.96 |               0    |

## The mined rule set

- **integrality** (15 columns): fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number, ack_flag_number, HTTP, HTTPS, DNS, SSH, TCP, UDP, ARP, ICMP, IPv, LLC
- **dependency kept** (14): `Min <= AVG <= Max` (tol 1e-06); `Srate == Rate` (tol 1e-06); `IPv == LLC` (tol 1e-06); `HTTP implies TCP` (tol 1e-06); `HTTPS implies TCP` (tol 1e-06); `SSH implies TCP` (tol 1e-06); `DNS implies UDP` (tol 1e-06); `FIN flag implies TCP` (tol 1e-06); `SYN flag implies TCP` (tol 1e-06); `RST flag implies TCP` (tol 1e-06); `PSH flag implies TCP` (tol 1e-06); `ACK flag implies TCP` (tol 1e-06); `TCP + UDP + ICMP <= 1` (tol 1e-06); `ARP + IPv <= 1` (tol 1e-06)
- **dependency pruned as loose** (2): `6 TCP + 17 UDP + ICMP <= Protocol Type` (benign p99.9 residual 0.489); `Tot sum ~= Number * AVG` (benign p99.9 residual 0.51)
- **distribution groups**: TCP (661,221 train rows, threshold 6.434 from val); UDP (52,336 train rows, threshold 10.114 from val); ICMP (6 train rows, global profile, threshold 6.920 from global); ARP (171 train rows, threshold 8.520 from train+val (in-sample)); other (54,974 train rows, threshold 8.802 from val)

## False positives by protocol group (clean benign test)

| protocol group   |   benign test rows |   FPR_% |   range_% |   integrality_% |   dependency_% |   distribution_% |
|:-----------------|-------------------:|--------:|----------:|----------------:|---------------:|-----------------:|
| TCP              |             141563 |   1.026 |     0.001 |               0 |              0 |            1.024 |
| UDP              |              11130 |   1.069 |     0     |               0 |              0 |            1.069 |
| ICMP             |                  1 |   0     |     0     |               0 |              0 |            0     |
| ARP              |                 38 |   2.632 |     0     |               0 |              0 |            2.632 |
| other            |              11992 |   1.051 |     0     |               0 |              0 |            1.051 |

## Clean (unperturbed) test rows rejected, by category

For attack categories this is not an error - those rows are real intrusions - but it is the `clean_orig` baseline every catch rate below has to be read against.

| category   |   test rows |   rejected_% |   range_% |   integrality_% |   dependency_% |   distribution_% |
|:-----------|------------:|-------------:|----------:|----------------:|---------------:|-----------------:|
| Benign     |      164724 |        1.031 |     0.001 |               0 |              0 |            1.03  |
| DDoS       |       97830 |       32.907 |     0.077 |               0 |              0 |           32.89  |
| DoS        |       36000 |       40.653 |     0.064 |               0 |              0 |           40.625 |
| Mirai      |       27000 |       65.974 |    65.941 |               0 |              0 |            0.081 |
| Recon      |       32946 |       12.181 |     2.616 |               0 |              0 |            9.831 |
| Spoofing   |       18000 |        3.489 |     1.472 |               0 |              0 |            2.067 |
| Web        |        3723 |        9.347 |     5.372 |               0 |              0 |            4.298 |
| BruteForce |        1960 |       18.316 |    17.602 |               0 |              0 |            3.98  |

## Which family carries the gate?

`sole_%` = adversarial rows rejected by that family *and no other*. A family with a high catch but ~0 sole catches is redundant with the others.

| family       |   mean catch_% |   mean sole_% |
|:-------------|---------------:|--------------:|
| range        |          57.08 |          1.96 |
| integrality  |          89.13 |          0    |
| dependency   |          86.91 |          0    |
| distribution |          92.96 |          4.45 |

Mean across the 12 adversarial sets: combined catch 95.54%, attributable to perturbation 62.64%. The family carrying the most catches on its own is **distribution**.

`evade_model_only_%` = adversarial rows the target model calls benign with no gate in front; `pass_and_evade_%` = rows that also pass the validator, i.e. the attacker's real success through gate 1. Worst cell: bim x lstm at 0.02%.
