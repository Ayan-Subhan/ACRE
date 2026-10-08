# Table IV - evasion of the baseline NIDS under white-box attack

Source rows: 5,000 true-attack flows drawn from `data/processed/test.npz` with seed 42. The **same rows** are used for every cell, so the twelve results are directly comparable.

`clean_acc` is the model's detection rate on those rows before perturbation; `adv_acc` is the same rows after. `evasion` is the fraction of the *correctly-classified* rows that the attack flipped to benign -- the honest denominator. Precision and FPR are undefined on an all-attack subset and are deliberately omitted.

| model   | attack   | eps   |   clean_acc_% |   adv_acc_% |   evasion_% |   linf_max |   l2_mean |   feats_changed |   seconds |
|:--------|:---------|:------|--------------:|------------:|------------:|-----------:|----------:|----------------:|----------:|
| MLP     | FGSM     | 0.1   |         92.38 |       82.96 |      13.293 |    0.1     |    0.2992 |            16.4 |       0.5 |
| MLP     | BIM      | 0.1   |         92.38 |       73.38 |      20.567 |    0.1     |    0.2112 |            17.3 |       1.5 |
| MLP     | PGD      | 0.1   |         92.38 |       65.04 |      29.595 |    0.1     |    0.2486 |            17.6 |       4.5 |
| MLP     | DEEPFOOL | -     |         92.38 |       50.88 |      50.725 |    0.90354 |    0.476  |            32.5 |      13.1 |
| CNN     | FGSM     | 0.1   |         92.4  |       75.08 |      19.805 |    0.1     |    0.5263 |            29.5 |       1.2 |
| CNN     | BIM      | 0.1   |         92.4  |       48.2  |      47.835 |    0.1     |    0.3852 |            30.6 |       1.7 |
| CNN     | PGD      | 0.1   |         92.4  |       31.44 |      65.974 |    0.1     |    0.4409 |            31.2 |       6.8 |
| CNN     | DEEPFOOL | -     |         92.4  |       62.18 |      39.481 |    0.37636 |    0.3354 |            33.1 |      24.7 |
| LSTM    | FGSM     | 0.1   |         92.26 |       82.86 |      13.917 |    0.1     |    0.5174 |            28.5 |       0.3 |
| LSTM    | BIM      | 0.1   |         92.26 |       65.86 |      28.615 |    0.1     |    0.3923 |            31   |       2   |
| LSTM    | PGD      | 0.1   |         92.26 |       56.9  |      38.326 |    0.1     |    0.4484 |            31.3 |       9   |
| LSTM    | DEEPFOOL | -     |         92.26 |       44.64 |      58.899 |    0.96695 |    0.4962 |            33.4 |      32.6 |

## Paper comparison

Verma et al. report a single unattributed collapse figure per model. Ours is reported per attack, which is why there are twelve numbers here and three there.

| Model | Paper (under attack) | This run (worst attack) |
| --- | ---: | ---: |
| MLP | 24.95% | 50.88% |
| CNN | 49.76% | 31.44% |
| LSTM | 4.89% | 44.64% |
