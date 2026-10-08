# Table VI - adversarial discriminator (Random Forest, Gini)

120,000 rows: 60,000 adversarial and 60,000 clean (5,000 exact unperturbed twins of the positives, plus 55,000 further rows sampled from the same split). 200 trees, `criterion=gini`, `class_weight=balanced_subsample`, seed 42.

**Positive class = adversarial.** `catch_%` is recall over perturbed rows; `fpr_%` is the fraction of legitimate traffic wrongly quarantined. As in phase 4 these are reported apart and never blended.

Every split is **grouped on the source flow**, so a perturbed row and its clean twin can never land on opposite sides. Without that, the forest is tested on flows whose originals it memorised, and the number is meaningless.

| protocol             | held_out   |   n_train |   n_test |   accuracy_% |   precision_% |   catch_% |    f1_% |   fpr_% |   fn |   fp |   fit_s |
|:---------------------|:-----------|----------:|---------:|-------------:|--------------:|----------:|--------:|--------:|-----:|-----:|--------:|
| random               | -          |     84192 |    35808 |      100     |           100 |   100     | 100     |       0 |    0 |    0 |     5.5 |
| leave_one_attack_out | bim        |     73644 |    22452 |      100     |           100 |   100     | 100     |       0 |    0 |    0 |     4.6 |
| leave_one_attack_out | deepfool   |     73644 |    22452 |       80.737 |           100 |     2.853 |   5.547 |       0 | 4325 |    0 |     4.9 |
| leave_one_attack_out | fgsm       |     73644 |    22452 |      100     |           100 |   100     | 100     |       0 |    0 |    0 |     5.3 |
| leave_one_attack_out | pgd        |     73644 |    22452 |      100     |           100 |   100     | 100     |       0 |    0 |    0 |     5.3 |
| leave_one_model_out  | cnn        |     70128 |    23936 |       78.697 |           100 |    14.1   |  24.716 |       0 | 5099 |    0 |     4.8 |
| leave_one_model_out  | lstm       |     70128 |    23936 |       99.971 |           100 |    99.882 |  99.941 |       0 |    7 |    0 |     4.5 |
| leave_one_model_out  | mlp        |     70128 |    23936 |       99.992 |           100 |    99.966 |  99.983 |       0 |    2 |    0 |     4.6 |

## Reading this

- **random** trains on all four attack families and tests on all four. This is the protocol the paper reports, and it is the optimistic one: the adversary the forest meets at test time is the adversary it was trained on.
- **leave_one_attack_out** withholds an entire family from training. The gap between it and `random` is the part of the paper's number that comes from having seen the attack before.
- **leave_one_model_out** withholds every example crafted against one target model, testing whether a perturbation fingerprint transfers across the architecture it was built to fool.

The weakest hold-out is **deepfool** at 2.85% catch, against 100.00% when it is in the training set. That difference, not the headline, is what the discriminator is worth against an adversary who picks an attack you did not anticipate.

## What the forest actually looks at

Gini importance, top 15.

| feature          |   gini_importance |
|:-----------------|------------------:|
| Protocol         |           0.14539 |
| Bwd Header Len   |           0.06388 |
| Subflow Bwd Pkts |           0.06157 |
| Tot Fwd Pkts     |           0.06066 |
| Active Max       |           0.0589  |
| Tot Bwd Pkts     |           0.05031 |
| Idle Max         |           0.04343 |
| Subflow Fwd Pkts |           0.04328 |
| Idle Min         |           0.03541 |
| Down/Up Ratio    |           0.03475 |
| Fwd Seg Size Min |           0.03067 |
| TotLen Fwd Pkts  |           0.03001 |
| FIN Flag Cnt     |           0.02103 |
| Dst Port         |           0.02091 |
| Active Min       |           0.01772 |

**9 of the top 15** are columns phase 4's validator already checks for whole-numberedness (0.469 of the total importance mass). The two gates are therefore *not* independent: to the extent this overlap is large, the discriminator has rediscovered the validator's arithmetic rather than adding a second, separate obstacle -- and one adaptive attacker who rounds onto the integer lattice degrades both at once. Phase 7 should not treat their catch rates as multiplying.
