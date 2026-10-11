# Table IV-c - phase-3 ART attacks projected onto realizable traffic (spec B)

Rows: the phase-3 test-split source rows each model detected at its calibrated threshold. `unrealizable` = the ART row is not a fixed point of the realism projection P. `after projection` = the same rows repaired by P, i.e. the closest traffic an attacker could actually send.

| attack   | model   |   n_detected_clean |   unrealizable_% |   evasion_before_% |   evasion_after_projection_% |   pass_and_evade_before_% |   pass_and_evade_after_% |
|:---------|:--------|-------------------:|-----------------:|-------------------:|-----------------------------:|--------------------------:|-------------------------:|
| bim      | cnn     |               4614 |           100.00 |              97.94 |                         6.09 |                      0.00 |                     5.61 |
| bim      | lstm    |               4508 |           100.00 |              39.24 |                         7.72 |                      0.00 |                     7.05 |
| bim      | mlp     |               4615 |            82.32 |              57.79 |                         4.75 |                      0.00 |                     4.53 |
| deepfool | cnn     |               4614 |           100.00 |             100.00 |                         0.41 |                      0.00 |                     0.41 |
| deepfool | lstm    |               4508 |           100.00 |              96.65 |                         2.00 |                      0.00 |                     1.93 |
| deepfool | mlp     |               4615 |           100.00 |               5.40 |                         0.00 |                      0.00 |                     0.00 |
| fgsm     | cnn     |               4614 |           100.00 |              64.15 |                         7.91 |                      0.00 |                     6.76 |
| fgsm     | lstm    |               4508 |           100.00 |              19.14 |                         6.30 |                      0.00 |                     5.21 |
| fgsm     | mlp     |               4615 |            82.32 |              35.95 |                         5.70 |                      0.00 |                     5.18 |
| pgd      | cnn     |               4614 |           100.00 |              99.85 |                         6.11 |                      0.00 |                     5.59 |
| pgd      | lstm    |               4508 |           100.00 |              48.03 |                         7.79 |                      0.00 |                     7.08 |
| pgd      | mlp     |               4615 |            82.32 |              62.64 |                         4.59 |                      0.00 |                     4.27 |
