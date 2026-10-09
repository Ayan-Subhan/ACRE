# Table III - NIDS accuracy and loss (clean test set)

Data: `data/processed` | 36 features | test rows: 382,183 (217,459 attack, 164,724 benign) | trained on CPU
Seed 7, batch 1024, Adam lr=0.001, early stopping on val_loss (patience 4), weighting: binary. `fpr_%` = benign flows flagged as attack; `balanced_acc_%` = mean of benign and attack recall.


| model   |   accuracy_% |   balanced_acc_% |   precision_% |   recall_% |    f1_% |   test_loss |   fpr_% |    fn |   fp |   params |   epochs |   train_s |   s_per_epoch |
|:--------|-------------:|-----------------:|--------------:|-----------:|--------:|------------:|--------:|------:|-----:|---------:|---------:|----------:|--------------:|
| MLP     |      94.5963 |          94.9916 |       98.268  |    92.1268 | 95.0984 |     0.13624 |  2.1436 | 17121 | 3531 |    15138 |       30 |      74.7 |           2.5 |
| CNN     |      94.5314 |          94.9034 |       98.0657 |    92.2077 | 95.0465 |     0.13691 |  2.401  | 16945 | 3955 |    33346 |       30 |     565.7 |          18.9 |

## Detection rate per category (%)

For Benign, "detection" means correctly passed as benign (= 100 - FPR).

| category   |   support |    MLP |    CNN |
|:-----------|----------:|-------:|-------:|
| Benign     |    164724 | 97.856 | 97.599 |
| DDoS       |     97830 | 99.74  | 99.962 |
| DoS        |     36000 | 99.931 | 99.992 |
| Mirai      |     27000 | 99.844 | 99.974 |
| Recon      |     32946 | 72.164 | 71.96  |
| Spoofing   |     18000 | 68.656 | 68.961 |
| Web        |      3723 | 66.344 | 65.995 |
| BruteForce |      1960 | 62.551 | 58.827 |

## Detection rate per class (%)

| class                   |   support |    MLP |     CNN |
|:------------------------|----------:|-------:|--------:|
| BenignTraffic           |    164724 | 97.856 |  97.599 |
| DDoS-ACK_Fragmentation  |      9000 | 99.7   |  99.911 |
| DDoS-HTTP_Flood         |      4316 | 99.676 |  99.954 |
| DDoS-ICMP_Flood         |      9000 | 99.956 |  99.989 |
| DDoS-ICMP_Fragmentation |      9000 | 99.789 |  99.978 |
| DDoS-PSHACK_Flood       |      9000 | 99.978 | 100     |
| DDoS-RSTFINFlood        |      9000 | 99.944 | 100     |
| DDoS-SlowLoris          |      3514 | 95.731 |  99.488 |
| DDoS-SYN_Flood          |      9000 | 99.978 | 100     |
| DDoS-SynonymousIP_Flood |      9000 | 99.978 |  99.989 |
| DDoS-TCP_Flood          |      9000 | 99.933 |  99.989 |
| DDoS-UDP_Flood          |      9000 | 99.944 |  99.989 |
| DDoS-UDP_Fragmentation  |      9000 | 99.8   |  99.967 |
| DoS-HTTP_Flood          |      9000 | 99.867 |  99.989 |
| DoS-SYN_Flood           |      9000 | 99.933 |  99.989 |
| DoS-TCP_Flood           |      9000 | 99.944 | 100     |
| DoS-UDP_Flood           |      9000 | 99.978 |  99.989 |
| Mirai-greeth_flood      |      9000 | 99.889 |  99.989 |
| Mirai-greip_flood       |      9000 | 99.722 |  99.956 |
| Mirai-udpplain          |      9000 | 99.922 |  99.978 |
| Recon-HostDiscovery     |      9000 | 85.867 |  85.089 |
| Recon-OSScan            |      9000 | 48.422 |  46.333 |
| Recon-PingSweep         |       338 | 44.97  |  44.675 |
| Recon-PortScan          |      9000 | 67.856 |  68.233 |
| VulnerabilityScan       |      5608 | 96.826 |  99.643 |
| DNS_Spoofing            |      9000 | 61.733 |  61.9   |
| MITM-ArpSpoofing        |      9000 | 75.578 |  76.022 |
| Backdoor_Malware        |       482 | 71.784 |  69.71  |
| BrowserHijacking        |       879 | 53.015 |  53.242 |
| CommandInjection        |       812 | 71.429 |  70.32  |
| SqlInjection            |       786 | 69.847 |  72.519 |
| Uploading_Attack        |       187 | 66.31  |  64.171 |
| XSS                     |       577 | 70.191 |  67.938 |
| DictionaryBruteForce    |      1960 | 62.551 |  58.827 |
