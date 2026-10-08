# Table III - NIDS accuracy and loss (clean test set)

Data: `data/processed` | test rows: 382,187 (217,460 attack, 164,727 benign)
Seed 42, batch 1024, Adam lr=0.001, early stopping on val_loss (patience 4), class_weight on. `fpr_%` = benign flows flagged as attack; `balanced_acc_%` = mean of benign and attack recall.


| model   |   accuracy_% |   balanced_acc_% |   precision_% |   recall_% |    f1_% |   test_loss |   fpr_% |    fn |   fp |   params |   epochs |   train_s |   s_per_epoch |
|:--------|-------------:|-----------------:|--------------:|-----------:|--------:|------------:|--------:|------:|-----:|---------:|---------:|----------:|--------------:|
| MLP     |      94.948  |          95.2924 |       98.2267 |    92.7964 | 95.4344 |     0.12884 |  2.2115 | 15665 | 3643 |    15522 |       28 |     404.7 |          14.5 |
| CNN     |      94.8837 |          95.2484 |       98.3046 |    92.6051 | 95.3698 |     0.12843 |  2.1083 | 16081 | 3473 |    33346 |       30 |    1708   |          56.9 |
| LSTM    |      94.6539 |          94.9289 |       97.5523 |    92.9362 | 95.1883 |     0.1326  |  3.0784 | 15361 | 5071 |    19042 |       30 |    8482.8 |         282.8 |

## Detection rate per category (%)

For Benign, "detection" means correctly passed as benign (= 100 - FPR).

| category   |   support |    MLP |     CNN |   LSTM |
|:-----------|----------:|-------:|--------:|-------:|
| Benign     |    164727 | 97.788 |  97.892 | 96.922 |
| DDoS       |     97830 | 99.996 |  99.995 | 99.995 |
| DoS        |     36000 | 99.997 | 100     | 99.994 |
| Mirai      |     27000 | 99.996 | 100     | 99.996 |
| Recon      |     32946 | 73.669 |  72.95  | 75.436 |
| Spoofing   |     18000 | 71.228 |  70.767 | 70.156 |
| Web        |      3724 | 69.71  |  68.421 | 68.367 |
| BruteForce |      1960 | 65.459 |  62.959 | 63.776 |

## Detection rate per class (%)

| class                   |   support |     MLP |     CNN |    LSTM |
|:------------------------|----------:|--------:|--------:|--------:|
| BenignTraffic           |    164727 |  97.788 |  97.892 |  96.922 |
| DDoS-ACK_Fragmentation  |      9000 |  99.989 |  99.978 |  99.989 |
| DDoS-HTTP_Flood         |      4316 | 100     | 100     | 100     |
| DDoS-ICMP_Flood         |      9000 | 100     | 100     | 100     |
| DDoS-ICMP_Fragmentation |      9000 |  99.989 | 100     |  99.989 |
| DDoS-PSHACK_Flood       |      9000 | 100     | 100     |  99.989 |
| DDoS-RSTFINFlood        |      9000 | 100     | 100     | 100     |
| DDoS-SlowLoris          |      3514 |  99.943 |  99.943 |  99.943 |
| DDoS-SYN_Flood          |      9000 | 100     | 100     | 100     |
| DDoS-SynonymousIP_Flood |      9000 | 100     | 100     | 100     |
| DDoS-TCP_Flood          |      9000 | 100     | 100     | 100     |
| DDoS-UDP_Flood          |      9000 | 100     | 100     | 100     |
| DDoS-UDP_Fragmentation  |      9000 | 100     |  99.989 | 100     |
| DoS-HTTP_Flood          |      9000 |  99.989 | 100     |  99.978 |
| DoS-SYN_Flood           |      9000 | 100     | 100     | 100     |
| DoS-TCP_Flood           |      9000 | 100     | 100     | 100     |
| DoS-UDP_Flood           |      9000 | 100     | 100     | 100     |
| Mirai-greeth_flood      |      9000 | 100     | 100     | 100     |
| Mirai-greip_flood       |      9000 |  99.989 | 100     | 100     |
| Mirai-udpplain          |      9000 | 100     | 100     |  99.989 |
| Recon-HostDiscovery     |      9000 |  87.5   |  86.667 |  86.744 |
| Recon-OSScan            |      9000 |  49.411 |  47.989 |  53.378 |
| Recon-PingSweep         |       339 |  48.083 |  47.198 |  54.867 |
| Recon-PortScan          |      9000 |  68.667 |  68.333 |  71.678 |
| VulnerabilityScan       |      5607 |  99.982 |  99.964 |  99.964 |
| DNS_Spoofing            |      9000 |  64.244 |  63.178 |  63.4   |
| MITM-ArpSpoofing        |      9000 |  78.211 |  78.356 |  76.911 |
| Backdoor_Malware        |       482 |  77.801 |  74.274 |  73.237 |
| BrowserHijacking        |       879 |  55.29  |  57.338 |  55.176 |
| CommandInjection        |       812 |  73.768 |  72.906 |  72.291 |
| SqlInjection            |       786 |  71.756 |  71.12  |  73.41  |
| Uploading_Attack        |       188 |  73.936 |  70.213 |  68.617 |
| XSS                     |       577 |  75.043 |  69.844 |  71.924 |
| DictionaryBruteForce    |      1960 |  65.459 |  62.959 |  63.776 |
