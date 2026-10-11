# Table IV - evasion of the baseline NIDS under white-box attack

Source rows: 5,000 true-attack flows drawn from `data/processed/test.npz` with seed 42. The **same rows** are used for every cell, so the twelve results are directly comparable.

`clean_acc` is the model's detection rate on those rows before perturbation; `adv_acc` is the same rows after. `evasion` is the fraction of the *correctly-classified* rows that the attack flipped to benign -- the honest denominator. Precision and FPR are undefined on an all-attack subset and are deliberately omitted.

| model   | attack   | eps   |   clean_acc_% |   adv_acc_% |   evasion_% |   linf_max |   l2_mean |   feats_changed |   seconds |
|:--------|:---------|:------|--------------:|------------:|------------:|-----------:|----------:|----------------:|----------:|
| MLP     | FGSM     | 0.1   |         92.12 |       60.38 |      36.974 |    0.1     |    0.4203 |            22.1 |       0.1 |
| MLP     | BIM      | 0.1   |         92.12 |       38.28 |      58.446 |    0.1     |    0.3095 |            24   |       0.7 |
| MLP     | PGD      | 0.1   |         92.12 |       34    |      63.113 |    0.1     |    0.3634 |            24.1 |       2.5 |
| MLP     | DEEPFOOL | -     |         92.12 |       14.74 |      91.337 |    0.52992 |    0.2972 |            29.9 |       7.2 |
| CNN     | FGSM     | 0.1   |         93.16 |       43.96 |      53.328 |    0.1     |    0.5017 |            27.1 |       0.3 |
| CNN     | BIM      | 0.1   |         93.16 |        3.26 |      96.501 |    0.1     |    0.3601 |            29.4 |       2.8 |
| CNN     | PGD      | 0.1   |         93.16 |        0.22 |      99.764 |    0.1     |    0.4265 |            29.5 |      10.5 |
| CNN     | DEEPFOOL | -     |         93.16 |        7.56 |      98.454 |    0.26323 |    0.1797 |            30.8 |      34.4 |
| LSTM    | FGSM     | 0.1   |         91.46 |       79.54 |      17.407 |    0.1     |    0.4948 |            26.7 |       1.1 |
| LSTM    | BIM      | 0.1   |         91.46 |       56.96 |      37.743 |    0.1     |    0.3747 |            28.2 |      13.1 |
| LSTM    | PGD      | 0.1   |         91.46 |       48.84 |      46.6   |    0.1     |    0.4257 |            28.5 |      57.6 |
| LSTM    | DEEPFOOL | -     |         91.46 |       26.08 |      79.882 |    1       |    0.4684 |            30.4 |     263.4 |

## Paper comparison

Verma et al. report a single unattributed collapse figure per model. Ours is reported per attack, which is why there are twelve numbers here and three there.

| Model | Paper (under attack) | This run (worst attack) |
| --- | ---: | ---: |
| MLP | 24.95% | 14.74% |
| CNN | 49.76% | 0.22% |
| LSTM | 4.89% | 26.08% |
