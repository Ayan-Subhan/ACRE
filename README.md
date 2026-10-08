# ACRE — adversarial-attack detection for IoT intrusion detection

Final-year project: an evaluation and extension of the AAD framework (Verma et al., *A Secure
Adversarial Attack Detector Framework for Monitoring Network Intrusion in IoT Environment*,
IEEE TCE 71(4), 2025, DOI [10.1109/TCE.2025.3614806](https://doi.org/10.1109/TCE.2025.3614806))
on the CICIoT2023 dataset, against realizable and defense-aware adversaries.

Everything lives in [`aad/`](aad/README.md): setup, milestone status, and the per-milestone
walkthroughs in [`aad/docs/`](aad/docs/).

| Path | Contents |
| --- | --- |
| [`aad/README.md`](aad/README.md) | setup, data, how to run each phase, milestone status |
| [`aad/docs/ciciot2023-implementation-plan.md`](aad/docs/ciciot2023-implementation-plan.md) | the M0–M8 plan, with a status and deviations log |
| [`aad/docs/m1-data-pipeline.md`](aad/docs/m1-data-pipeline.md), [`m2-baselines.md`](aad/docs/m2-baselines.md), [`m3-validator.md`](aad/docs/m3-validator.md) | step-by-step records of each completed milestone |
| [`aad/archive/cicids2018/`](aad/archive/cicids2018/README.md) | the completed CSE-CIC-IDS2018 reproduction (phases 1–7) and its results |
| `requirements.txt` | pinned Python 3.10 / TensorFlow 2.13 environment |

Data, trained weights and generated examples are not in version control; `aad/README.md`
explains how to download CICIoT2023 and regenerate everything.

The project's earlier history (the IDS2018 reproduction, phases 1–4) is in
[github.com/Ayan-Subhan/aad](https://github.com/Ayan-Subhan/aad).
