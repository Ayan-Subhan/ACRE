# Table V - validator catch-rate and false-positive rate (CICIoT2023)

Rules mined from 768,724 **benign training** rows. Distribution thresholds calibrated per protocol group on benign *validation* rows at a 1.0% budget. Everything below is measured on **test**, which neither pass saw. Walkthrough: `docs/m3-validator.md`.

| set                 | kind   |      n |   combined_% |   range_% |   integrality_% |   dependency_% |   distribution_% |   clean_orig_% |   attributable_% |   evade_model_only_% |   pass_and_evade_% |
|:--------------------|:-------|-------:|-------------:|----------:|----------------:|---------------:|-----------------:|---------------:|-----------------:|---------------------:|-------------------:|
| clean benign (test) | FPR    | 164727 |        0.968 |     0.001 |            0    |           0    |            0.968 |         nan    |           nan    |               nan    |             nan    |
| clean attack (test) | reject | 217460 |       39.814 |     9.095 |            0    |           0    |           30.851 |         nan    |           nan    |               nan    |             nan    |
| bim x cnn           | catch  |   5000 |      100     |    79.16  |          100    |          99.94 |          100     |          39.32 |            60.68 |                86.46 |               0    |
| bim x lstm          | catch  |   5000 |      100     |    63.36  |          100    |          99.82 |           97.66  |          39.32 |            60.68 |                57.62 |               0    |
| bim x mlp           | catch  |   5000 |       86.42  |    21.92  |           54.74 |          54.62 |           78.54  |          39.32 |            47.1  |                25.34 |               0.02 |
| deepfool x cnn      | catch  |   5000 |      100     |    77.04  |          100    |         100    |           99     |          39.32 |            60.68 |                91    |               0    |
| deepfool x lstm     | catch  |   5000 |      100     |    68.62  |           99.98 |         100    |           97.26  |          39.32 |            60.68 |                85.96 |               0    |
| deepfool x mlp      | catch  |   5000 |       99.98  |    25.12  |           99.98 |          99.98 |           98.62  |          39.32 |            60.66 |                70.04 |               0.02 |
| fgsm x cnn          | catch  |   5000 |      100     |    68.66  |          100    |          96.48 |           99.98  |          39.32 |            60.68 |                30.06 |               0    |
| fgsm x lstm         | catch  |   5000 |      100     |    53.26  |           99.98 |          97.22 |           99.32  |          39.32 |            60.68 |                19.94 |               0    |
| fgsm x mlp          | catch  |   5000 |       86.42  |    12.98  |           54.74 |          52.26 |           78.12  |          39.32 |            47.1  |                12.72 |               0.02 |
| pgd x cnn           | catch  |   5000 |      100     |    82.98  |          100    |          99.74 |          100     |          39.32 |            60.68 |                98.56 |               0    |
| pgd x lstm          | catch  |   5000 |      100     |    67.86  |          100    |          99.5  |           97.7   |          39.32 |            60.68 |                69.36 |               0    |
| pgd x mlp           | catch  |   5000 |       86.42  |    25.36  |           54.74 |          54.16 |           78.54  |          39.32 |            47.1  |                31.34 |               0.02 |

## The mined rule set

- **integrality** (15 columns): fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number, ack_flag_number, HTTP, HTTPS, DNS, SSH, TCP, UDP, ARP, ICMP, IPv, LLC
- **dependency kept** (14): `Min <= AVG <= Max` (tol 1e-06); `Srate == Rate` (tol 1e-06); `IPv == LLC` (tol 1e-06); `HTTP implies TCP` (tol 1e-06); `HTTPS implies TCP` (tol 1e-06); `SSH implies TCP` (tol 1e-06); `DNS implies UDP` (tol 1e-06); `FIN flag implies TCP` (tol 1e-06); `SYN flag implies TCP` (tol 1e-06); `RST flag implies TCP` (tol 1e-06); `PSH flag implies TCP` (tol 1e-06); `ACK flag implies TCP` (tol 1e-06); `TCP + UDP + ICMP <= 1` (tol 1e-06); `ARP + IPv <= 1` (tol 1e-06)
- **dependency pruned as loose** (2): `6 TCP + 17 UDP + ICMP <= Protocol Type` (benign p99.9 residual 0.489); `Tot sum ~= Number * AVG` (benign p99.9 residual 0.51)
- **distribution groups**: TCP (661,088 train rows, threshold 5.175 from val); UDP (52,446 train rows, threshold 10.789 from val); ICMP (8 train rows, global profile, threshold 6.855 from global); ARP (175 train rows, threshold 10.331 from train+val (in-sample)); other (55,007 train rows, threshold 9.879 from val)

## False positives by protocol group (clean benign test)

| protocol group   |   benign test rows |   FPR_% |   range_% |   integrality_% |   dependency_% |   distribution_% |
|:-----------------|-------------------:|--------:|----------:|----------------:|---------------:|-----------------:|
| TCP              |             141589 |   0.954 |     0.001 |               0 |              0 |            0.954 |
| UDP              |              11252 |   1.102 |     0.009 |               0 |              0 |            1.093 |
| ICMP             |                  1 |   0     |     0     |               0 |              0 |            0     |
| ARP              |                 54 |   1.852 |     0     |               0 |              0 |            1.852 |
| other            |              11831 |   1.006 |     0     |               0 |              0 |            1.006 |

## Clean (unperturbed) test rows rejected, by category

For attack categories this is not an error - those rows are real intrusions - but it is the `clean_orig` baseline every catch rate below has to be read against.

| category   |   test rows |   rejected_% |   range_% |   integrality_% |   dependency_% |   distribution_% |
|:-----------|------------:|-------------:|----------:|----------------:|---------------:|-----------------:|
| Benign     |      164727 |        0.968 |     0.001 |               0 |              0 |            0.968 |
| DDoS       |       97830 |       50.249 |     0.095 |               0 |              0 |           50.224 |
| DoS        |       36000 |       39.65  |     0.067 |               0 |              0 |           39.628 |
| Mirai      |       27000 |       65.948 |    65.922 |               0 |              0 |            0.067 |
| Recon      |       32946 |       12.171 |     3.075 |               0 |              0 |            9.403 |
| Spoofing   |       18000 |        3.278 |     1.517 |               0 |              0 |            1.817 |
| Web        |        3724 |       10.258 |     6.176 |               0 |              0 |            4.511 |
| BruteForce |        1960 |       18.316 |    17.704 |               0 |              0 |            3.98  |

## Which family carries the gate?

`sole_%` = adversarial rows rejected by that family *and no other*. A family with a high catch but ~0 sole catches is redundant with the others.

| family       |   mean catch_% |   mean sole_% |
|:-------------|---------------:|--------------:|
| range        |          53.86 |          1.96 |
| integrality  |          88.68 |          0    |
| dependency   |          87.81 |          0    |
| distribution |          93.73 |          5.95 |

Mean across the 12 adversarial sets: combined catch 96.60%, attributable to perturbation 57.28%. The family carrying the most catches on its own is **distribution**.

`evade_model_only_%` = adversarial rows the target model calls benign with no gate in front; `pass_and_evade_%` = rows that also pass the validator, i.e. the attacker's real success through gate 1. Worst cell: bim x mlp at 0.02%.
