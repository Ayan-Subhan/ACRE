# Table IV - evasion of the baseline NIDS under white-box attack

Source rows: 5,000 true-attack flows drawn from `data/processed/test.npz` with seed 42. The **same rows** are used for every cell, so the twelve results are directly comparable.

`clean_acc` is the model's detection rate on those rows before perturbation; `adv_acc` is the same rows after. `evasion` is the fraction of the *correctly-classified* rows that the attack flipped to benign -- the honest denominator. Precision and FPR are undefined on an all-attack subset and are deliberately omitted.

| model   | attack   | eps   |   clean_acc_% |   adv_acc_% |   evasion_% |   linf_max |   l2_mean |   feats_changed |   seconds |
|:--------|:---------|:------|--------------:|------------:|------------:|-----------:|----------:|----------------:|----------:|
| MLP     | FGSM     | 0.1   |         92.36 |       87.28 |       8.185 |    0.1     |    0.2906 |            16.2 |       0.1 |
| MLP     | BIM      | 0.1   |         92.36 |       74.66 |      19.164 |    0.1     |    0.2088 |            16.4 |       1.1 |
| MLP     | PGD      | 0.1   |         92.36 |       68.66 |      25.66  |    0.1     |    0.2458 |            16.7 |       4.4 |
| MLP     | DEEPFOOL | -     |         92.36 |       29.96 |      74.946 |    1       |    0.4962 |            32.2 |      12.6 |
| CNN     | FGSM     | 0.1   |         92.26 |       69.94 |      27.227 |    0.1     |    0.5333 |            30.5 |       0.5 |
| CNN     | BIM      | 0.1   |         92.26 |       13.54 |      85.324 |    0.1     |    0.3839 |            32   |       5.5 |
| CNN     | PGD      | 0.1   |         92.26 |        1.44 |      98.439 |    0.1     |    0.4417 |            32.4 |      21.4 |
| CNN     | DEEPFOOL | -     |         92.26 |        9    |      97.854 |    0.47682 |    0.2438 |            34.2 |      62.7 |
| LSTM    | FGSM     | 0.1   |         92.46 |       80.06 |      17.024 |    0.1     |    0.5234 |            29.5 |       2.1 |
| LSTM    | BIM      | 0.1   |         92.46 |       42.38 |      54.164 |    0.1     |    0.3966 |            30.9 |      28.8 |
| LSTM    | PGD      | 0.1   |         92.46 |       30.64 |      66.861 |    0.1     |    0.4478 |            30.6 |     160.5 |
| LSTM    | DEEPFOOL | -     |         92.46 |       14.04 |      92.191 |    1       |    0.456  |            33.3 |    1040.7 |

## Paper comparison

Verma et al. report a single unattributed collapse figure per model. Ours is reported per attack, which is why there are twelve numbers here and three there.

| Model | Paper (under attack) | This run (worst attack) |
| --- | ---: | ---: |
| MLP | 24.95% | 29.96% |
| CNN | 49.76% | 1.44% |
| LSTM | 4.89% | 14.04% |
