# Table III - NIDS accuracy and loss (clean test set)

Data: `data/processed` | 38 features | test rows: 382,183 (217,459 attack, 164,724 benign) | trained on GPU: NVIDIA GeForce RTX 3050 Laptop GPU
Seed 42, batch 1024, Adam lr=0.001, early stopping on val_loss (patience 4), weighting: binary. `fpr_%` = benign flows flagged as attack; `balanced_acc_%` = mean of benign and attack recall.


| model   |   accuracy_% |   balanced_acc_% |   precision_% |   recall_% |    f1_% |   test_loss |   fpr_% |    fn |   fp |   params |   epochs |   train_s |   s_per_epoch |
|:--------|-------------:|-----------------:|--------------:|-----------:|--------:|------------:|--------:|------:|-----:|---------:|---------:|----------:|--------------:|
| MLP     |      94.847  |          95.2455 |       98.4925 |    92.3572 | 95.3262 |     0.12989 |  1.8662 | 16620 | 3074 |    15394 |       30 |     546.7 |          18.2 |
| CNN     |      94.7457 |          95.1146 |       98.22   |    92.4409 | 95.2429 |     0.1309  |  2.2116 | 16438 | 3643 |    33346 |       27 |     504.7 |          18.7 |
| LSTM    |      94.4278 |          94.8159 |       98.0851 |    92.0031 | 94.9468 |     0.13563 |  2.3712 | 17390 | 3906 |    19042 |       30 |     628.1 |          20.9 |

## Detection rate per category (%)

For Benign, "detection" means correctly passed as benign (= 100 - FPR).

| category   |   support |     MLP |    CNN |   LSTM |
|:-----------|----------:|--------:|-------:|-------:|
| Benign     |    164724 |  98.134 | 97.788 | 97.629 |
| DDoS       |     97830 |  99.998 | 99.997 | 99.976 |
| DoS        |     36000 | 100     | 99.997 | 99.989 |
| Mirai      |     27000 | 100     | 99.996 | 99.993 |
| Recon      |     32946 |  72.397 | 72.519 | 71.89  |
| Spoofing   |     18000 |  69.261 | 69.817 | 67.889 |
| Web        |      3723 |  66.694 | 67.741 | 61.832 |
| BruteForce |      1960 |  61.684 | 61.99  | 54.133 |

## Detection rate per class (%)

| class                   |   support |     MLP |     CNN |    LSTM |
|:------------------------|----------:|--------:|--------:|--------:|
| BenignTraffic           |    164724 |  98.134 |  97.788 |  97.629 |
| DDoS-ACK_Fragmentation  |      9000 | 100     |  99.978 |  99.933 |
| DDoS-HTTP_Flood         |      4316 | 100     | 100     |  99.838 |
| DDoS-ICMP_Flood         |      9000 | 100     | 100     | 100     |
| DDoS-ICMP_Fragmentation |      9000 | 100     | 100     | 100     |
| DDoS-PSHACK_Flood       |      9000 | 100     | 100     |  99.989 |
| DDoS-RSTFINFlood        |      9000 | 100     | 100     | 100     |
| DDoS-SlowLoris          |      3514 |  99.972 | 100     |  99.858 |
| DDoS-SYN_Flood          |      9000 | 100     | 100     | 100     |
| DDoS-SynonymousIP_Flood |      9000 | 100     | 100     | 100     |
| DDoS-TCP_Flood          |      9000 |  99.989 |  99.989 |  99.989 |
| DDoS-UDP_Flood          |      9000 | 100     | 100     |  99.989 |
| DDoS-UDP_Fragmentation  |      9000 | 100     | 100     |  99.978 |
| DoS-HTTP_Flood          |      9000 | 100     |  99.989 |  99.956 |
| DoS-SYN_Flood           |      9000 | 100     | 100     | 100     |
| DoS-TCP_Flood           |      9000 | 100     | 100     | 100     |
| DoS-UDP_Flood           |      9000 | 100     | 100     | 100     |
| Mirai-greeth_flood      |      9000 | 100     | 100     |  99.978 |
| Mirai-greip_flood       |      9000 | 100     | 100     | 100     |
| Mirai-udpplain          |      9000 | 100     |  99.989 | 100     |
| Recon-HostDiscovery     |      9000 |  85.611 |  85.433 |  83.467 |
| Recon-OSScan            |      9000 |  47.911 |  47.844 |  48.478 |
| Recon-PingSweep         |       338 |  45.858 |  43.787 |  42.012 |
| Recon-PortScan          |      9000 |  67.5   |  68.267 |  67.389 |
| VulnerabilityScan       |      5608 |  99.947 |  99.947 |  99.911 |
| DNS_Spoofing            |      9000 |  62.322 |  62.611 |  61.422 |
| MITM-ArpSpoofing        |      9000 |  76.2   |  77.022 |  74.356 |
| Backdoor_Malware        |       482 |  72.199 |  73.859 |  68.672 |
| BrowserHijacking        |       879 |  54.039 |  55.404 |  51.536 |
| CommandInjection        |       812 |  73.522 |  73.03  |  62.931 |
| SqlInjection            |       786 |  68.702 |  72.137 |  66.158 |
| Uploading_Attack        |       187 |  66.31  |  64.171 |  60.428 |
| XSS                     |       577 |  69.151 |  69.151 |  64.818 |
| DictionaryBruteForce    |      1960 |  61.684 |  61.99  |  54.133 |
