# Table IV-c - phase-3 ART attacks projected onto realizable traffic (spec A)

Rows: the phase-3 test-split source rows each model detected at its calibrated threshold. `unrealizable` = the ART row is not a fixed point of the realism projection P. `after projection` = the same rows repaired by P, i.e. the closest traffic an attacker could actually send.

| attack   | model   |   n_detected_clean |   unrealizable_% |   evasion_before_% |   evasion_after_projection_% |   pass_and_evade_before_% |   pass_and_evade_after_% |
|:---------|:--------|-------------------:|-----------------:|-------------------:|-----------------------------:|--------------------------:|-------------------------:|
| bim      | cnn     |               4614 |           100.00 |              97.94 |                         2.17 |                      0.00 |                     1.95 |
| bim      | lstm    |               4508 |           100.00 |              39.24 |                         1.60 |                      0.00 |                     1.55 |
| bim      | mlp     |               4615 |            82.32 |              57.79 |                         1.47 |                      0.00 |                     1.43 |
| deepfool | cnn     |               4614 |           100.00 |             100.00 |                         0.02 |                      0.00 |                     0.02 |
| deepfool | lstm    |               4508 |           100.00 |              96.65 |                         0.04 |                      0.00 |                     0.04 |
| deepfool | mlp     |               4615 |           100.00 |               5.40 |                         0.00 |                      0.00 |                     0.00 |
| fgsm     | cnn     |               4614 |           100.00 |              64.15 |                         4.44 |                      0.00 |                     4.14 |
| fgsm     | lstm    |               4508 |           100.00 |              19.14 |                         2.86 |                      0.00 |                     2.77 |
| fgsm     | mlp     |               4615 |            82.32 |              35.95 |                         3.55 |                      0.00 |                     3.45 |
| pgd      | cnn     |               4614 |           100.00 |              99.85 |                         2.36 |                      0.00 |                     2.17 |
| pgd      | lstm    |               4508 |           100.00 |              48.03 |                         1.62 |                      0.00 |                     1.57 |
| pgd      | mlp     |               4615 |            82.32 |              62.64 |                         1.76 |                      0.00 |                     1.71 |
