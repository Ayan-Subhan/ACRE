# Feature reliance of the baseline models (phase 2b)

Method and interpretation: `docs/m2-baselines.md`, section 'Do the models lean on capture artefacts?'.

## Permutation importance - drop in balanced accuracy (percentage points), 9,990 stratified test rows, 2 repeats

Baseline balanced accuracy on this subsample: MLP 95.034%, CNN 94.963%, LSTM 94.824%.

| feature         |    MLP |    CNN |   LSTM |   mean |
|:----------------|-------:|-------:|-------:|-------:|
| rst_count       | 28.042 | 27.766 | 20.213 | 25.34  |
| urg_count       | 24.084 | 23.649 | 20.777 | 22.837 |
| Header_Length   | 15.47  | 23.125 | 20.855 | 19.817 |
| flow_duration   | 16.042 | 10.375 | 23.277 | 16.565 |
| IAT             | 13.674 | 17.258 | 12.881 | 14.604 |
| Number          |  0.966 |  2.636 |  6.415 |  3.339 |
| HTTPS           |  1.577 |  2.324 |  3.233 |  2.378 |
| HTTP            |  1.948 |  1.871 |  2.574 |  2.131 |
| TCP             |  0.235 |  5.101 |  1.048 |  2.128 |
| syn_flag_number |  3.618 |  1.337 |  0.803 |  1.919 |
| syn_count       |  2.041 |  1.001 |  2.378 |  1.806 |
| Max             |  4.023 |  0.923 |  0.107 |  1.684 |
| Tot size        |  2.74  |  0.402 |  0.811 |  1.318 |
| Weight          |  1.512 |  2.41  |  0.02  |  1.314 |
| Protocol Type   |  0.777 |  1.286 |  1.381 |  1.148 |

Artefact suspects: 

| feature   |    MLP |    CNN |   LSTM |   mean |
|:----------|-------:|-------:|-------:|-------:|
| IAT       | 13.674 | 17.258 | 12.881 | 14.604 |
| Number    |  0.966 |  2.636 |  6.415 |  3.339 |
| Weight    |  1.512 |  2.41  |  0.02  |  1.314 |

## Ablation - MLP retrained without the suspect columns

| variant                     |   features |   balanced_acc_% |   accuracy_% |   recall_% |   fpr_% |   Benign_% |   DDoS_% |   DoS_% |   Mirai_% |   Recon_% |   Spoofing_% |   Web_% |   BruteForce_% |   epochs |   train_s |
|:----------------------------|-----------:|-----------------:|-------------:|-----------:|--------:|-----------:|---------:|--------:|----------:|----------:|-------------:|--------:|---------------:|---------:|----------:|
| all 39 features             |         39 |          95.2924 |      94.948  |    92.7964 |  2.2115 |      97.79 |   100    |  100    |    100    |     73.67 |        71.23 |   69.71 |          65.46 |       28 |     404.7 |
| without IAT                 |         38 |          95.2706 |      94.914  |    92.686  |  2.1448 |      97.86 |   100    |  100    |    100    |     73.57 |        70.34 |   68.66 |          64.8  |       28 |     300   |
| without IAT, Number, Weight |         36 |          95.3534 |      95.0056 |    92.8327 |  2.1259 |      97.87 |    99.94 |   99.98 |     99.97 |     73.89 |        71.05 |   71.78 |          66.79 |       30 |     216.1 |

## Reference forest - is the ceiling the features or the networks?

| model                                        |   balanced_acc_% |   fpr_% |   Benign_% |   DDoS_% |   DoS_% |   Mirai_% |   Recon_% |   Spoofing_% |   Web_% |   BruteForce_% |
|:---------------------------------------------|-----------------:|--------:|-----------:|---------:|--------:|----------:|----------:|-------------:|--------:|---------------:|
| RandomForest (200 trees, 599,995 train rows) |          97.6788 |  1.4381 |      98.56 |      100 |     100 |       100 |     88.46 |        86.24 |   89.58 |          84.69 |
