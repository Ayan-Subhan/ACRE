# Table IV - evasion of the baseline NIDS under white-box attack

Source rows: 5,000 true-attack flows drawn from `data/processed/test.npz` with seed 42. The **same rows** are used for every cell, so the twelve results are directly comparable.

`clean_acc` is the model's detection rate on those rows before perturbation; `adv_acc` is the same rows after. `evasion` is the fraction of the *correctly-classified* rows that the attack flipped to benign -- the honest denominator. Precision and FPR are undefined on an all-attack subset and are deliberately omitted.

| model   | attack   | eps   |   clean_acc_% |   adv_acc_% |   evasion_% |   linf_max |   l2_mean |   feats_changed |   seconds |
|:--------|:---------|:------|--------------:|------------:|------------:|-----------:|----------:|----------------:|----------:|
| MLP     | FGSM     | 0.1   |         99.88 |        0    |     100     |    0.1     |    0.7133 |            57   |       0.2 |
| MLP     | BIM      | 0.1   |         99.88 |        0    |     100     |    0.1     |    0.5787 |            47.2 |       1   |
| MLP     | PGD      | 0.1   |         99.88 |        0    |     100     |    0.1     |    0.6299 |            47.2 |       3.3 |
| MLP     | DEEPFOOL | -     |         99.88 |        0.12 |     100     |    0.23973 |    0.0406 |            57   |       4.5 |
| CNN     | FGSM     | 0.1   |         99.76 |        0    |     100     |    0.1     |    0.4066 |            21.1 |       0.5 |
| CNN     | BIM      | 0.1   |         99.76 |        0    |     100     |    0.1     |    0.3307 |            22.4 |       6   |
| CNN     | PGD      | 0.1   |         99.76 |        0    |     100     |    0.1     |    0.3526 |            23.3 |      20.4 |
| CNN     | DEEPFOOL | -     |         99.76 |        0.04 |     100     |    0.05831 |    0.0265 |            21.2 |      63   |
| LSTM    | FGSM     | 0.1   |         99.46 |        0.18 |     100     |    0.1     |    0.5816 |            43.2 |       2.2 |
| LSTM    | BIM      | 0.1   |         99.46 |        0.02 |      99.98  |    0.1     |    0.2201 |            62.2 |      26   |
| LSTM    | PGD      | 0.1   |         99.46 |        0.02 |      99.98  |    0.1     |    0.2391 |            62.3 |     104.7 |
| LSTM    | DEEPFOOL | -     |         99.46 |        0.58 |      99.718 |    1       |    0.0653 |            43.3 |     434.4 |

## Paper comparison

Verma et al. report a single unattributed collapse figure per model. Ours is reported per attack, which is why there are twelve numbers here and three there.

| Model | Paper (under attack) | This run (worst attack) |
| --- | ---: | ---: |
| MLP | 24.95% | 0.00% |
| CNN | 49.76% | 0.00% |
| LSTM | 4.89% | 0.02% |

## Accuracy vs. perturbation budget

Computed on a fixed 1,000-row subset of the same source rows. DeepFool is absent because its `epsilon` is an overshoot multiplier, not an L-inf budget -- sweeping it would not mean anything.

|                  |   0.001 |   0.002 |   0.005 |   0.01 |   0.02 |   0.05 |   0.1 |   0.3 |
|:-----------------|--------:|--------:|--------:|-------:|-------:|-------:|------:|------:|
| ('cnn', 'bim')   |    99.9 |    99.9 |    99.8 |   89.7 |    5.1 |    0   |   0   |     0 |
| ('cnn', 'fgsm')  |    99.9 |    99.9 |    99.8 |   90   |    5.7 |    0   |   0   |     0 |
| ('cnn', 'pgd')   |    99.9 |    99.9 |    99.8 |   89.7 |    5.1 |    0   |   0   |     0 |
| ('lstm', 'bim')  |    99.3 |    99.2 |    88.5 |    5.9 |    0   |    0   |   0   |     0 |
| ('lstm', 'fgsm') |    99.3 |    99.2 |    88.5 |    5.3 |    0   |    0.5 |   0.5 |     0 |
| ('lstm', 'pgd')  |    99.3 |    99.2 |    88.5 |    5.9 |    0   |    0   |   0   |     0 |
| ('mlp', 'bim')   |    99.9 |    99.9 |     7.9 |    2.5 |    0   |    0   |   0   |     0 |
| ('mlp', 'fgsm')  |    99.9 |    99.9 |     8   |    5.5 |    0   |    0   |   0   |     0 |
| ('mlp', 'pgd')   |    99.9 |    99.9 |     7.9 |    2.5 |    0   |    0   |   0   |     0 |

Detection rate (%). Accuracy must fall as eps rises; a non-monotone row is evidence of gradient masking and is itself a reportable finding.
