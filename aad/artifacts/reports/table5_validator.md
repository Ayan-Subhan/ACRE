# Table V - validator catch-rate and false-positive rate (CICIoT2023)

Rules mined from 768,708 **benign training** rows. Distribution thresholds calibrated per protocol group on benign *validation* rows at a 1.0% budget. Everything below is measured on **test**, which neither pass saw. Walkthrough: `docs/m3-validator.md`.

| set                 | kind   |      n |   combined_% |   range_% |   integrality_% |   dependency_% |   distribution_% |   clean_orig_% |   attributable_% |   evade_model_only_% |   pass_and_evade_% |
|:--------------------|:-------|-------:|-------------:|----------:|----------------:|---------------:|-----------------:|---------------:|-----------------:|---------------------:|-------------------:|
| clean benign (test) | FPR    | 164724 |        1.01  |     0.001 |            0    |           0    |            1.01  |          nan   |           nan    |               nan    |             nan    |
| clean attack (test) | reject | 217459 |       39.928 |     8.999 |            0    |           0    |           31.056 |          nan   |           nan    |               nan    |             nan    |
| bim x cnn           | catch  |   5000 |      100     |    92.42  |          100    |         100    |          100     |           40.1 |            59.9  |                96.74 |               0    |
| bim x lstm          | catch  |   5000 |       99.98  |    64.48  |           99.98 |          98.68 |           99.6   |           40.1 |            59.88 |                43.04 |               0.02 |
| bim x mlp           | catch  |   5000 |       99.98  |    38.46  |           83.66 |          83.64 |           92.18  |           40.1 |            59.88 |                61.72 |               0.02 |
| deepfool x cnn      | catch  |   5000 |      100     |    90.14  |          100    |         100    |           99.56  |           40.1 |            59.9  |                92.44 |               0    |
| deepfool x lstm     | catch  |   5000 |       99.98  |    71.98  |           99.98 |          99.98 |           98.7   |           40.1 |            59.88 |                73.92 |               0.02 |
| deepfool x mlp      | catch  |   5000 |       99.98  |    38.44  |           99.96 |          99.98 |           98.72  |           40.1 |            59.88 |                85.26 |               0.02 |
| fgsm x cnn          | catch  |   5000 |      100     |    84.98  |          100    |          99.78 |           99.94  |           40.1 |            59.9  |                56.04 |               0    |
| fgsm x lstm         | catch  |   5000 |       99.98  |    58.82  |           99.68 |          82.9  |           98.48  |           40.1 |            59.88 |                20.46 |               0.02 |
| fgsm x mlp          | catch  |   5000 |       99.94  |    15.6   |           83.6  |          80.88 |           91.02  |           40.1 |            59.84 |                39.62 |               0.04 |
| pgd x cnn           | catch  |   5000 |      100     |    93.48  |          100    |          99.94 |          100     |           40.1 |            59.9  |                99.78 |               0    |
| pgd x lstm          | catch  |   5000 |       99.98  |    61.1   |           99.98 |          95.6  |           99.72  |           40.1 |            59.88 |                51.16 |               0.02 |
| pgd x mlp           | catch  |   5000 |       99.98  |    37.24  |           83.66 |          82.74 |           92.24  |           40.1 |            59.88 |                66    |               0.02 |

## The mined rule set

- **integrality** (15 columns): fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number, ack_flag_number, HTTP, HTTPS, DNS, SSH, TCP, UDP, ARP, ICMP, IPv, LLC
- **dependency kept** (14): `Min <= AVG <= Max` (tol 1e-06); `Srate == Rate` (tol 1e-06); `IPv == LLC` (tol 1e-06); `HTTP implies TCP` (tol 1e-06); `HTTPS implies TCP` (tol 1e-06); `SSH implies TCP` (tol 1e-06); `DNS implies UDP` (tol 1e-06); `FIN flag implies TCP` (tol 1e-06); `SYN flag implies TCP` (tol 1e-06); `RST flag implies TCP` (tol 1e-06); `PSH flag implies TCP` (tol 1e-06); `ACK flag implies TCP` (tol 1e-06); `TCP + UDP + ICMP <= 1` (tol 1e-06); `ARP + IPv <= 1` (tol 1e-06)
- **dependency pruned as loose** (1): `6 TCP + 17 UDP + ICMP <= Protocol Type` (benign p99.9 residual 0.489)
- **distribution groups**: TCP (661,221 train rows, threshold 4.457 from val); UDP (52,336 train rows, threshold 8.481 from val); ICMP (6 train rows, global profile, threshold 4.821 from global); ARP (171 train rows, threshold 7.688 from train+val (in-sample)); other (54,974 train rows, threshold 7.255 from val)

## False positives by protocol group (clean benign test)

| protocol group   |   benign test rows |   FPR_% |   range_% |   integrality_% |   dependency_% |   distribution_% |
|:-----------------|-------------------:|--------:|----------:|----------------:|---------------:|-----------------:|
| TCP              |             141563 |   1.012 |     0.001 |               0 |              0 |            1.012 |
| UDP              |              11130 |   1.006 |     0     |               0 |              0 |            1.006 |
| ICMP             |                  1 | 100     |     0     |               0 |              0 |          100     |
| ARP              |                 38 |   0     |     0     |               0 |              0 |            0     |
| other            |              11992 |   0.984 |     0     |               0 |              0 |            0.984 |

## Clean (unperturbed) test rows rejected, by category

For attack categories this is not an error - those rows are real intrusions - but it is the `clean_orig` baseline every catch rate below has to be read against.

| category   |   test rows |   rejected_% |   range_% |   integrality_% |   dependency_% |   distribution_% |
|:-----------|------------:|-------------:|----------:|----------------:|---------------:|-----------------:|
| Benign     |      164724 |        1.01  |     0.001 |               0 |              0 |            1.01  |
| DDoS       |       97830 |       49.704 |     0.076 |               0 |              0 |           49.684 |
| DoS        |       36000 |       35.994 |     0.064 |               0 |              0 |           35.972 |
| Mirai      |       27000 |       65.944 |    65.93  |               0 |              0 |            0.026 |
| Recon      |       32946 |       18.448 |     2.616 |               0 |              0 |           16.157 |
| Spoofing   |       18000 |        3.15  |     1.472 |               0 |              0 |            1.756 |
| Web        |        3723 |       11.604 |     5.372 |               0 |              0 |            6.608 |
| BruteForce |        1960 |       18.52  |    17.602 |               0 |              0 |            4.337 |

## Which family carries the gate?

`sole_%` = adversarial rows rejected by that family *and no other*. A family with a high catch but ~0 sole catches is redundant with the others.

| family       |   mean catch_% |   mean sole_% |
|:-------------|---------------:|--------------:|
| range        |          62.26 |          1.95 |
| integrality  |          95.88 |          0.02 |
| dependency   |          93.68 |          0    |
| distribution |          97.51 |          2.14 |

Mean across the 12 adversarial sets: combined catch 99.98%, attributable to perturbation 59.88%. The family carrying the most catches on its own is **distribution**.

`evade_model_only_%` = adversarial rows the target model calls benign with no gate in front; `pass_and_evade_%` = rows that also pass the validator, i.e. the attacker's real success through gate 1. Worst cell: fgsm x mlp at 0.04%.
