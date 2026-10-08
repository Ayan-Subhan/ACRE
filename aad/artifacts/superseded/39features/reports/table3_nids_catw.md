# Table III - NIDS accuracy and loss (clean test set)

Data: `data/processed` | test rows: 382,187 (217,460 attack, 164,727 benign)
Seed 42, batch 1024, Adam lr=0.001, early stopping on val_loss (patience 4), weighting: category. `fpr_%` = benign flows flagged as attack; `balanced_acc_%` = mean of benign and attack recall.


| model   |   accuracy_% |   balanced_acc_% |   precision_% |   recall_% |    f1_% |   test_loss |   fpr_% |   fn |    fp |   params |   epochs |   train_s |   s_per_epoch |
|:--------|-------------:|-----------------:|--------------:|-----------:|--------:|------------:|--------:|-----:|------:|---------:|---------:|----------:|--------------:|
| MLP     |      93.7669 |          93.3603 |       92.9883 |    96.3074 | 94.6187 |     0.15014 |  9.5868 | 8030 | 15792 |    15522 |       25 |     345.1 |          13.8 |

## Detection rate per category (%)

For Benign, "detection" means correctly passed as benign (= 100 - FPR).

| category   |   support |     MLP |
|:-----------|----------:|--------:|
| Benign     |    164727 |  90.413 |
| DDoS       |     97830 |  99.998 |
| DoS        |     36000 | 100     |
| Mirai      |     27000 | 100     |
| Recon      |     32946 |  85.959 |
| Spoofing   |     18000 |  82.972 |
| Web        |      3724 |  96.133 |
| BruteForce |      1960 |  90.153 |

## Detection rate per class (%)

| class                   |   support |     MLP |
|:------------------------|----------:|--------:|
| BenignTraffic           |    164727 |  90.413 |
| DDoS-ACK_Fragmentation  |      9000 | 100     |
| DDoS-HTTP_Flood         |      4316 | 100     |
| DDoS-ICMP_Flood         |      9000 | 100     |
| DDoS-ICMP_Fragmentation |      9000 | 100     |
| DDoS-PSHACK_Flood       |      9000 | 100     |
| DDoS-RSTFINFlood        |      9000 | 100     |
| DDoS-SlowLoris          |      3514 |  99.972 |
| DDoS-SYN_Flood          |      9000 | 100     |
| DDoS-SynonymousIP_Flood |      9000 |  99.989 |
| DDoS-TCP_Flood          |      9000 | 100     |
| DDoS-UDP_Flood          |      9000 | 100     |
| DDoS-UDP_Fragmentation  |      9000 | 100     |
| DoS-HTTP_Flood          |      9000 | 100     |
| DoS-SYN_Flood           |      9000 | 100     |
| DoS-TCP_Flood           |      9000 | 100     |
| DoS-UDP_Flood           |      9000 | 100     |
| Mirai-greeth_flood      |      9000 | 100     |
| Mirai-greip_flood       |      9000 | 100     |
| Mirai-udpplain          |      9000 | 100     |
| Recon-HostDiscovery     |      9000 |  98.189 |
| Recon-OSScan            |      9000 |  64.522 |
| Recon-PingSweep         |       339 |  75.516 |
| Recon-PortScan          |      9000 |  86.822 |
| VulnerabilityScan       |      5607 |  99.982 |
| DNS_Spoofing            |      9000 |  79.056 |
| MITM-ArpSpoofing        |      9000 |  86.889 |
| Backdoor_Malware        |       482 |  99.378 |
| BrowserHijacking        |       879 |  91.354 |
| CommandInjection        |       812 |  98.03  |
| SqlInjection            |       786 |  95.42  |
| Uploading_Attack        |       188 |  97.872 |
| XSS                     |       577 |  98.44  |
| DictionaryBruteForce    |      1960 |  90.153 |
