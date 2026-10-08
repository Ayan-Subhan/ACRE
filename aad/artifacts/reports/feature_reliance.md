# Feature reliance of the baseline models (phase 2b)

Method and interpretation: `docs/m2-baselines.md`, section 'Do the models lean on capture artefacts?'.

## Permutation importance - drop in balanced accuracy (percentage points), 9,990 stratified test rows, 2 repeats

Baseline balanced accuracy on this subsample: MLP 95.107%, CNN 95.102%, LSTM 94.591%.

| feature                   |    MLP |    CNN |   LSTM |   mean |
|:--------------------------|-------:|-------:|-------:|-------:|
| rst_count                 | 24.546 | 25.332 | 18.601 | 22.826 |
| urg_count                 | 24.348 | 23.468 | 18.767 | 22.194 |
| flow_duration             | 15.146 | 15.233 | 22.123 | 17.5   |
| Number + Weight           | 17.559 | 18.924 | 13.041 | 16.508 |
| Header_Length             | 15.533 | 18.605 | 13.973 | 16.037 |
| TCP                       |  1.17  |  4.871 |  4.447 |  3.496 |
| Std + Radius + Covariance |  0.425 |  2.533 |  5.009 |  2.656 |
| HTTP                      |  1.852 |  2.843 |  2.689 |  2.461 |
| Rate + Srate              |  1.843 |  4.091 |  0.836 |  2.257 |
| HTTPS                     |  1.267 |  1.954 |  3.084 |  2.102 |
| syn_flag_number           |  3.328 |  0.974 |  1.049 |  1.784 |
| Max                       |  3.181 |  1.604 |  0.448 |  1.744 |
| Protocol Type             |  0.98  |  2.209 |  1.544 |  1.578 |
| Variance                  |  2.523 |  1.382 |  0.818 |  1.574 |
| syn_count                 |  1.637 |  0.915 |  1.149 |  1.234 |

Artefact suspects: 

| feature         |    MLP |    CNN |   LSTM |   mean |
|:----------------|-------:|-------:|-------:|-------:|
| Number + Weight | 17.559 | 18.924 | 13.041 | 16.508 |

Features correlated above |r| = 0.95 are permuted together and shown as one row (`A + B`): permuting one alone would create impossible rows.

## Ablation - MLP retrained without the suspect columns

| variant                |   features |   balanced_acc_% |   accuracy_% |   recall_% |   fpr_% |   Benign_% |   DDoS_% |   DoS_% |   Mirai_% |   Recon_% |   Spoofing_% |   Web_% |   BruteForce_% |   epochs |   train_s |
|:-----------------------|-----------:|-----------------:|-------------:|-----------:|--------:|-----------:|---------:|--------:|----------:|----------:|-------------:|--------:|---------------:|---------:|----------:|
| all 38 features        |         38 |          95.2455 |      94.847  |    92.3572 |  1.8662 |      98.13 |   100    |  100    |    100    |     72.4  |        69.26 |   66.69 |          61.68 |       30 |     546.7 |
| without Number, Weight |         36 |          95.231  |      94.8114 |    92.1898 |  1.7277 |      98.27 |    99.92 |   99.97 |     99.95 |     71.68 |        69.23 |   65.78 |          62.5  |       30 |     467.7 |

## Reference forest - is the ceiling the features or the networks?

| model                                        |   balanced_acc_% |   fpr_% |   Benign_% |   DDoS_% |   DoS_% |   Mirai_% |   Recon_% |   Spoofing_% |   Web_% |   BruteForce_% |
|:---------------------------------------------|-----------------:|--------:|-----------:|---------:|--------:|----------:|----------:|-------------:|--------:|---------------:|
| RandomForest (200 trees, 599,993 train rows) |          95.4035 |  2.8842 |      97.12 |    99.97 |     100 |     99.99 |     76.99 |        73.42 |   79.83 |          70.92 |
