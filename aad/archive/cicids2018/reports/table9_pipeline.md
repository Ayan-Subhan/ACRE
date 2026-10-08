# Tables IX & X - the AAD pipeline end to end

`validator -> discriminator -> EIDS (eids)`, short-circuiting on the first stage that stops a flow. Per-stage columns are therefore *what each stage saw and stopped*, not what it would stop alone -- a row the validator rejects never reaches the forest.

**Evaluated on the 182,469 test rows the phase-5 forest never trained on** (42,000 excluded). Phase 5 drew its clean negatives from `test.npz`, so scoring this pipeline on the full split would grade the discriminator on its own training data. The fold is rebuilt from the same seed rather than stored.

## Table IX - end to end

| traffic         | kind   |      n |   stopped_% |   by_validator_% |   by_discriminator_% |   by_eids_% |   allowed_% |
|:----------------|:-------|-------:|------------:|-----------------:|---------------------:|------------:|------------:|
| clean benign    | FPR    | 167040 |       1.159 |            0.952 |                    0 |       0.207 |      98.841 |
| clean attack    | detect |  15429 |      99.994 |            0.097 |                    0 |      99.896 |       0.006 |
| bim x cnn       | catch  |   1484 |     100     |          100     |                    0 |       0     |       0     |
| bim x lstm      | catch  |   1484 |     100     |          100     |                    0 |       0     |       0     |
| bim x mlp       | catch  |   1484 |     100     |          100     |                    0 |       0     |       0     |
| deepfool x cnn  | catch  |   1484 |     100     |          100     |                    0 |       0     |       0     |
| deepfool x lstm | catch  |   1484 |     100     |          100     |                    0 |       0     |       0     |
| deepfool x mlp  | catch  |   1484 |     100     |          100     |                    0 |       0     |       0     |
| fgsm x cnn      | catch  |   1484 |     100     |          100     |                    0 |       0     |       0     |
| fgsm x lstm     | catch  |   1484 |     100     |          100     |                    0 |       0     |       0     |
| fgsm x mlp      | catch  |   1484 |     100     |          100     |                    0 |       0     |       0     |
| pgd x cnn       | catch  |   1484 |     100     |          100     |                    0 |       0     |       0     |
| pgd x lstm      | catch  |   1484 |     100     |          100     |                    0 |       0     |       0     |
| pgd x mlp       | catch  |   1484 |     100     |          100     |                    0 |       0     |       0     |

`clean benign` is the deployment cost: the share of legitimate traffic the pipeline drops. It stacks across stages, because a benign flow is lost if *any* stage stops it. `clean attack` and the twelve adversarial rows are the benefit. Read them together; neither is a result on its own.

## Table X - ablation

Every subset of the three gates, over all 17,808 pooled adversarial rows and 167,040 benign rows.

| stages                       |   n_stages |   catch_% |   fpr_% |
|:-----------------------------|-----------:|----------:|--------:|
| discriminator                |          1 |   100     |   0     |
| eids                         |          1 |    99.983 |   0.219 |
| validator                    |          1 |   100     |   0.952 |
| discriminator+eids           |          2 |   100     |   0.219 |
| validator+discriminator      |          2 |   100     |   0.952 |
| validator+eids               |          2 |   100     |   1.159 |
| validator+discriminator+eids |          3 |   100     |   1.159 |

### What each stage actually adds

| stage | catch lost if removed | FPR saved if removed |
| --- | ---: | ---: |
| validator | +0.000 pp | +0.941 pp |
| discriminator | +0.000 pp | +0.000 pp |
| eids | +0.000 pp | +0.207 pp |

Standalone rates over-credit a redundant gate -- two gates that each stop the same 100% both look essential alone and neither is. The drop from removing a stage is the only number that answers *would we notice if this were switched off*. Phases 4 and 5 predicted redundancy here: 9 of the forest's top 15 features are the validator's integrality columns.
