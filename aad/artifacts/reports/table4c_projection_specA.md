# Table IV-c - phase-3 ART attacks projected onto realizable traffic (spec A)

Rows: the phase-3 test-split source rows each model detected at its calibrated threshold. `unrealizable` = the ART row is not a fixed point of the realism projection P. `after projection` = the same rows repaired by P, i.e. the closest traffic an attacker could actually send.

| attack   | model   |   n_detected_clean |   unrealizable_% |   evasion_before_% |   evasion_after_projection_% |   pass_and_evade_before_% |   pass_and_evade_after_% |
|:---------|:--------|-------------------:|-----------------:|-------------------:|-----------------------------:|--------------------------:|-------------------------:|
| bim      | cnn     |               4614 |           100.00 |              97.94 |                         3.38 |                      0.00 |                     3.14 |
| bim      | lstm    |               4508 |           100.00 |              39.24 |                         3.97 |                      0.00 |                     3.84 |
| bim      | mlp     |               4615 |            82.32 |              57.79 |                         2.58 |                      0.00 |                     2.49 |
| deepfool | cnn     |               4614 |           100.00 |             100.00 |                         0.20 |                      0.00 |                     0.20 |
| deepfool | lstm    |               4508 |           100.00 |              96.65 |                         0.53 |                      0.00 |                     0.51 |
| deepfool | mlp     |               4615 |           100.00 |               5.40 |                         0.00 |                      0.00 |                     0.00 |
| fgsm     | cnn     |               4614 |           100.00 |              64.15 |                         5.57 |                      0.00 |                     5.22 |
| fgsm     | lstm    |               4508 |           100.00 |              19.14 |                         4.50 |                      0.00 |                     4.39 |
| fgsm     | mlp     |               4615 |            82.32 |              35.95 |                         4.31 |                      0.00 |                     4.16 |
| pgd      | cnn     |               4614 |           100.00 |              99.85 |                         3.66 |                      0.00 |                     3.45 |
| pgd      | lstm    |               4508 |           100.00 |              48.03 |                         3.99 |                      0.00 |                     3.88 |
| pgd      | mlp     |               4615 |            82.32 |              62.64 |                         2.77 |                      0.00 |                     2.71 |
