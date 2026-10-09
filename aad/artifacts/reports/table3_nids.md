# Table III - NIDS accuracy and loss (clean test set)

Data: `data/processed` | 36 features | test rows: 382,183 (217,459 attack, 164,724 benign) | trained on CPU
Seed 42, batch 1024, Adam lr=0.001, early stopping on val_loss (patience 4), weighting: binary. `fpr_%` = benign flows flagged as attack; `balanced_acc_%` = mean of benign and attack recall.


| model   |   accuracy_% |   balanced_acc_% |   precision_% |   recall_% |    f1_% |   test_loss |   fpr_% |    fn |   fp |   params |   epochs |   train_s |   s_per_epoch |
|:--------|-------------:|-----------------:|--------------:|-----------:|--------:|------------:|--------:|------:|-----:|---------:|---------:|----------:|--------------:|
| MLP     |      94.7525 |          95.1666 |       98.5165 |    92.1654 | 95.2352 |     0.13213 |  1.8322 | 17037 | 3018 |    15138 |       30 |     142.9 |           4.8 |
| CNN     |      94.8219 |          95.1171 |       97.8143 |    92.9771 | 95.3344 |     0.13058 |  2.7428 | 15272 | 4518 |    33346 |       27 |    1061.1 |          39.3 |
| LSTM    |      94.0269 |          94.3929 |       97.6185 |    91.7405 | 94.5883 |     0.14646 |  2.9546 | 17961 | 4867 |    19042 |       30 |    4148   |         138.3 |

## Detection rate per category (%)

For Benign, "detection" means correctly passed as benign (= 100 - FPR).

| category   |   support |    MLP |    CNN |   LSTM |
|:-----------|----------:|-------:|-------:|-------:|
| Benign     |    164724 | 98.168 | 97.257 | 97.045 |
| DDoS       |     97830 | 99.888 | 99.986 | 98.566 |
| DoS        |     36000 | 99.969 | 99.992 | 99.483 |
| Mirai      |     27000 | 99.93  | 99.985 | 99.389 |
| Recon      |     32946 | 71.566 | 74.34  | 71.748 |
| Spoofing   |     18000 | 69.167 | 71.839 | 71.328 |
| Web        |      3723 | 66.694 | 71.421 | 71.072 |
| BruteForce |      1960 | 62.296 | 66.122 | 66.276 |

## Detection rate per class (%)

| class                   |   support |    MLP |     CNN |   LSTM |
|:------------------------|----------:|-------:|--------:|-------:|
| BenignTraffic           |    164724 | 98.168 |  97.257 | 97.045 |
| DDoS-ACK_Fragmentation  |      9000 | 99.833 |  99.989 | 98.811 |
| DDoS-HTTP_Flood         |      4316 | 99.838 |  99.93  | 98.494 |
| DDoS-ICMP_Flood         |      9000 | 99.989 | 100     | 99.689 |
| DDoS-ICMP_Fragmentation |      9000 | 99.911 | 100     | 98.533 |
| DDoS-PSHACK_Flood       |      9000 | 99.989 | 100     | 99.9   |
| DDoS-RSTFINFlood        |      9000 | 99.989 | 100     | 99.711 |
| DDoS-SlowLoris          |      3514 | 98.207 |  99.829 | 74.36  |
| DDoS-SYN_Flood          |      9000 | 99.989 | 100     | 99.867 |
| DDoS-SynonymousIP_Flood |      9000 | 99.989 | 100     | 99.933 |
| DDoS-TCP_Flood          |      9000 | 99.989 |  99.989 | 99.789 |
| DDoS-UDP_Flood          |      9000 | 99.967 |  99.989 | 99.822 |
| DDoS-UDP_Fragmentation  |      9000 | 99.911 |  99.978 | 99.089 |
| DoS-HTTP_Flood          |      9000 | 99.944 |  99.989 | 98.622 |
| DoS-SYN_Flood           |      9000 | 99.989 |  99.989 | 99.667 |
| DoS-TCP_Flood           |      9000 | 99.967 | 100     | 99.833 |
| DoS-UDP_Flood           |      9000 | 99.978 |  99.989 | 99.811 |
| Mirai-greeth_flood      |      9000 | 99.944 |  99.989 | 99.567 |
| Mirai-greip_flood       |      9000 | 99.889 |  99.989 | 98.778 |
| Mirai-udpplain          |      9000 | 99.956 |  99.978 | 99.822 |
| Recon-HostDiscovery     |      9000 | 85.189 |  87.689 | 85.378 |
| Recon-OSScan            |      9000 | 46.878 |  49.689 | 52.7   |
| Recon-PingSweep         |       338 | 43.491 |  47.633 | 49.112 |
| Recon-PortScan          |      9000 | 66.356 |  70.778 | 71.433 |
| VulnerabilityScan       |      5608 | 99.376 |  99.804 | 82.311 |
| DNS_Spoofing            |      9000 | 62.211 |  64.711 | 64.789 |
| MITM-ArpSpoofing        |      9000 | 76.122 |  78.967 | 77.867 |
| Backdoor_Malware        |       482 | 72.822 |  74.896 | 77.178 |
| BrowserHijacking        |       879 | 54.608 |  59.613 | 63.936 |
| CommandInjection        |       812 | 74.015 |  76.478 | 70.69  |
| SqlInjection            |       786 | 68.957 |  75.827 | 75.7   |
| Uploading_Attack        |       187 | 63.102 |  68.449 | 70.588 |
| XSS                     |       577 | 67.764 |  74.35  | 71.231 |
| DictionaryBruteForce    |      1960 | 62.296 |  66.122 | 66.276 |
