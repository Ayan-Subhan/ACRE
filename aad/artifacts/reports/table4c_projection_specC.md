# Table IV-c - phase-3 ART attacks projected onto realizable traffic (spec C)

Rows: the phase-3 test-split source rows each model detected at its calibrated threshold. `unrealizable` = the ART row is not a fixed point of the realism projection P. `after projection` = the same rows repaired by P, i.e. the closest traffic an attacker could actually send.

| attack   | model   |   n_detected_clean |   unrealizable_% |   evasion_before_% |   evasion_after_projection_% |   pass_and_evade_before_% |   pass_and_evade_after_% |
|:---------|:--------|-------------------:|-----------------:|-------------------:|-----------------------------:|--------------------------:|-------------------------:|
| bim      | cnn     |               4614 |           100.00 |              97.94 |                        10.23 |                      0.00 |                     9.43 |
| bim      | lstm    |               4508 |           100.00 |              39.24 |                        13.31 |                      0.00 |                    11.69 |
| bim      | mlp     |               4615 |            82.32 |              57.79 |                         8.41 |                      0.00 |                     8.08 |
| deepfool | cnn     |               4614 |           100.00 |             100.00 |                         1.37 |                      0.00 |                     1.37 |
| deepfool | lstm    |               4508 |           100.00 |              96.65 |                        10.29 |                      0.00 |                     9.58 |
| deepfool | mlp     |               4615 |           100.00 |               5.40 |                         0.26 |                      0.00 |                     0.26 |
| fgsm     | cnn     |               4614 |           100.00 |              64.15 |                        11.01 |                      0.00 |                     9.97 |
| fgsm     | lstm    |               4508 |           100.00 |              19.14 |                         9.67 |                      0.00 |                     7.92 |
| fgsm     | mlp     |               4615 |            82.32 |              35.95 |                         8.60 |                      0.00 |                     7.78 |
| pgd      | cnn     |               4614 |           100.00 |              99.85 |                        10.81 |                      0.00 |                     9.99 |
| pgd      | lstm    |               4508 |           100.00 |              48.03 |                        13.58 |                      0.00 |                    11.78 |
| pgd      | mlp     |               4615 |            82.32 |              62.64 |                         7.97 |                      0.00 |                     7.41 |
