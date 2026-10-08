# Tables VII & VIII - the EIDS

Hardened on 1,047,517 clean training rows plus adversarial examples from `artifacts/adversarial_train`, labelled attack. `deepfool` withheld from training entirely. Same builders, seed 42 and callbacks as phase 2, so any difference is attributable to the data.

## Table VII - clean test set (the cost of hardening)

| model    | variant   |   accuracy_% |   precision_% |   recall_% |    f1_% |   fpr_% |   fn |   fp |
|:---------|:----------|-------------:|--------------:|-----------:|--------:|--------:|-----:|-----:|
| MLP      | baseline  |      99.9898 |       99.9817 |    99.9131 | 99.9474 |  0.002  |   19 |    4 |
| CNN      | baseline  |      99.9791 |       99.9771 |    99.808  | 99.8925 |  0.0025 |   42 |    5 |
| LSTM     | baseline  |      99.6997 |       97.5588 |    99.4056 | 98.4735 |  0.2685 |  130 |  544 |
| ENSEMBLE | baseline  |      99.7478 |       97.5536 |    99.9177 | 98.7215 |  0.2705 |   18 |  548 |
| MLP      | eids      |      99.9898 |       99.9817 |    99.9131 | 99.9474 |  0.002  |   19 |    4 |
| CNN      | eids      |      99.9728 |       99.9862 |    99.7348 | 99.8604 |  0.0015 |   58 |    3 |
| LSTM     | eids      |      99.7585 |       98.0534 |    99.497  | 98.7699 |  0.2132 |  110 |  432 |
| ENSEMBLE | eids      |      99.7986 |       98.0526 |    99.9177 | 98.9764 |  0.2142 |   18 |  434 |

OR only ever adds detections, so ensemble recall cannot fall below its best member and ensemble FPR cannot fall below its worst. Read the two columns together.

### Detection rate per attack type (%)

| class                  |   support |   MLP baseline |   MLP eids |   CNN baseline |   CNN eids |   LSTM baseline |   LSTM eids |   OR baseline |   OR hardened |
|:-----------------------|----------:|---------------:|-----------:|---------------:|-----------:|----------------:|------------:|--------------:|--------------:|
| Benign                 |    202599 |         99.998 |     99.998 |         99.998 |     99.999 |          99.731 |      99.787 |        99.73  |        99.786 |
| Type1 DoS-Hulk         |     21780 |         99.995 |     99.995 |        100     |    100     |          99.775 |      99.908 |       100     |       100     |
| Type2 DoS-SlowHTTPTest |         9 |        100     |    100     |        100     |      0     |         100     |       0     |       100     |       100     |
| Type3 BruteForce-Web   |        51 |         66.667 |     66.667 |         49.02  |     37.255 |           0     |       0     |        66.667 |        66.667 |
| Type4 BruteForce-XSS   |        23 |         95.652 |     95.652 |         39.13  |     39.13  |           0     |       0     |        95.652 |        95.652 |
| Type5 SQL-Injection    |         7 |        100     |    100     |         71.429 |     57.143 |           0     |       0     |       100     |       100     |

The phase-2 LSTM detects 0% of the three web-attack classes and still reports 99.8% accuracy, because those classes are 81 of 224,469 test rows. Whether OR recovers them is the row to read here.

## Table VIII - robustness, two regimes

| regime      | attack   | crafted_against   |    n |   MLP_% |   CNN_% |   LSTM_% |   ENSEMBLE_% |   baseline_% |
|:------------|:---------|:------------------|-----:|--------:|--------:|---------:|-------------:|-------------:|
| transferred | bim      | cnn (baseline)    | 5000 |  100    |  100    |    98.98 |       100    |         0    |
| transferred | bim      | lstm (baseline)   | 5000 |  100    |  100    |    99.52 |       100    |         0.02 |
| transferred | bim      | mlp (baseline)    | 5000 |  100    |  100    |    99.48 |       100    |         0    |
| transferred | deepfool | cnn (baseline)    | 5000 |   99.88 |   99.68 |    99.52 |        99.88 |         0.04 |
| transferred | deepfool | lstm (baseline)   | 5000 |   99.98 |   99.82 |    99.48 |        99.98 |         0.58 |
| transferred | deepfool | mlp (baseline)    | 5000 |  100    |   99.72 |    99.54 |       100    |         0.12 |
| transferred | fgsm     | cnn (baseline)    | 5000 |  100    |  100    |    99.36 |       100    |         0    |
| transferred | fgsm     | lstm (baseline)   | 5000 |  100    |  100    |    98.74 |       100    |         0.18 |
| transferred | fgsm     | mlp (baseline)    | 5000 |  100    |  100    |    99.46 |       100    |         0    |
| transferred | pgd      | cnn (baseline)    | 5000 |  100    |  100    |    98.48 |       100    |         0    |
| transferred | pgd      | lstm (baseline)   | 5000 |  100    |  100    |    99.38 |       100    |         0.02 |
| transferred | pgd      | mlp (baseline)    | 5000 |  100    |  100    |    99.46 |       100    |         0    |
| adaptive    | fgsm     | mlp (hardened)    | 5000 |    0    |   72.26 |     6.14 |        73.36 |       nan    |
| adaptive    | bim      | mlp (hardened)    | 5000 |    0    |   89.72 |    16.68 |        99.44 |       nan    |
| adaptive    | pgd      | mlp (hardened)    | 5000 |    0    |   89.62 |    13.22 |        95.9  |       nan    |
| adaptive    | deepfool | mlp (hardened)    | 5000 |    5.94 |   99.78 |    99.36 |        99.8  |       nan    |
| adaptive    | fgsm     | cnn (hardened)    | 5000 |   99.86 |   89.38 |    98.28 |        99.9  |       nan    |
| adaptive    | bim      | cnn (hardened)    | 5000 |   30.48 |   81.84 |    84.72 |        99.36 |       nan    |
| adaptive    | pgd      | cnn (hardened)    | 5000 |   22.92 |   72.44 |    90.98 |        98.24 |       nan    |
| adaptive    | deepfool | cnn (hardened)    | 5000 |   99.76 |   12.84 |    89.4  |       100    |       nan    |
| adaptive    | fgsm     | lstm (hardened)   | 5000 |  100    |   96.84 |     0    |       100    |       nan    |
| adaptive    | bim      | lstm (hardened)   | 5000 |  100    |   95.94 |     0    |       100    |       nan    |
| adaptive    | pgd      | lstm (hardened)   | 5000 |  100    |   99.94 |     0    |       100    |       nan    |
| adaptive    | deepfool | lstm (hardened)   | 5000 |  100    |   99.82 |     4.16 |       100    |       nan    |

- **transferred** replays phase 3's saved examples -- built against the *baseline* weights -- at the hardened models. This is the number an attacker gets if they hold a stale copy of the model. `baseline_%` is what the original model scored on the same rows (Table IV), so the improvement is read across that pair.
- **adaptive** regenerates each attack against the *hardened* weights, on the same 5,000 source rows Table IV used. This is the white-box threat model the paper states, and it is the only regime that describes a current adversary.

A large transferred number beside a small adaptive one is the expected result of static adversarial training, not a bug: the model learned the perturbations it was shown. Real robustness needs examples generated inside the training loop against the current weights (Madry et al.), which a fixed pool cannot provide. `deepfool` was never trained on, so its row is the cleanest measure of generalisation to an unanticipated attack.
