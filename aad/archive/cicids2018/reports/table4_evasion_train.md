# Table IV - evasion of the baseline NIDS under white-box attack

Source rows: 10,000 true-attack flows drawn from `data/processed/train.npz` with seed 42. The **same rows** are used for every cell, so the twelve results are directly comparable.

`clean_acc` is the model's detection rate on those rows before perturbation; `adv_acc` is the same rows after. `evasion` is the fraction of the *correctly-classified* rows that the attack flipped to benign -- the honest denominator. Precision and FPR are undefined on an all-attack subset and are deliberately omitted.

| model   | attack   |   eps |   clean_acc_% |   adv_acc_% |   evasion_% |   linf_max |   l2_mean |   feats_changed |   seconds |
|:--------|:---------|------:|--------------:|------------:|------------:|-----------:|----------:|----------------:|----------:|
| MLP     | FGSM     |   0.1 |         99.89 |        0    |      100    |        0.1 |    0.7131 |            57   |       0.4 |
| MLP     | BIM      |   0.1 |         99.89 |        0    |      100    |        0.1 |    0.5783 |            47.2 |       2   |
| MLP     | PGD      |   0.1 |         99.89 |        0    |      100    |        0.1 |    0.6298 |            47.2 |       6.9 |
| CNN     | FGSM     |   0.1 |         99.8  |        0    |      100    |        0.1 |    0.4064 |            21.1 |       1.1 |
| CNN     | BIM      |   0.1 |         99.8  |        0    |      100    |        0.1 |    0.3305 |            22.4 |      10.9 |
| CNN     | PGD      |   0.1 |         99.8  |        0    |      100    |        0.1 |    0.3523 |            23.3 |      40.9 |
| LSTM    | FGSM     |   0.1 |         99.48 |        0.22 |      100    |        0.1 |    0.5815 |            43.2 |       5.4 |
| LSTM    | BIM      |   0.1 |         99.48 |        0.01 |       99.99 |        0.1 |    0.2207 |            62.1 |      55.7 |
| LSTM    | PGD      |   0.1 |         99.48 |        0.02 |       99.98 |        0.1 |    0.2401 |            62.3 |     209.2 |

## Paper comparison

Verma et al. report a single unattributed collapse figure per model. Ours is reported per attack, which is why there are twelve numbers here and three there.

| Model | Paper (under attack) | This run (worst attack) |
| --- | ---: | ---: |
| MLP | 24.95% | 0.00% |
| CNN | 49.76% | 0.00% |
| LSTM | 4.89% | 0.01% |
