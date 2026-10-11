# Decision thresholds - 2% benign-FPR budget per model (D2)

Calibrated on validation benign rows; test rows only measure the result. Rule: attack iff P(attack) >= threshold. Written by `scripts/02c_calibrate_thresholds.py`.

| model | threshold | val FPR | test FPR | test bal. acc. | argmax test FPR | argmax bal. acc. |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| mlp | 0.487006 | 2.000% | 1.964% | 95.189% | 1.832% | 95.167% |
| cnn | 0.575074 | 2.000% | 1.927% | 95.073% | 2.743% | 95.117% |
| lstm | 0.587073 | 2.000% | 1.955% | 94.217% | 2.955% | 94.393% |

OR-ensemble of mlp, cnn, lstm at these thresholds: test FPR 3.267%, balanced accuracy 95.246%.

Detection rate per category on test at the calibrated threshold (%):

| model | DDoS | DoS | Mirai | Recon | Spoofing | Web | BruteForce |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| mlp | 99.89 | 99.97 | 99.93 | 72.13 | 69.82 | 67.93 | 63.78 |
| cnn | 99.98 | 99.99 | 99.99 | 71.30 | 68.92 | 64.03 | 58.06 |
| lstm | 98.41 | 99.36 | 99.30 | 66.80 | 67.88 | 62.77 | 58.21 |
