# Leakage probe (phase 1b)

Read this before trusting any accuracy figure. Method and interpretation: `docs/m1-data-pipeline.md`, section 'Leakage probe'.

## 1. Duplicates in the full file

18,588,033 of 46,686,579 rows (39.81%) are exact repeats of an earlier row with the same label, and were removed before sampling. 0 distinct feature vectors occur under more than one label; they were kept, and they put a ceiling on achievable accuracy.

| class                   |   rows_in_file |   exact_duplicate_% |   conflicting_rows |   sampled |
|:------------------------|---------------:|--------------------:|-------------------:|----------:|
| DDoS-ICMP_Flood         |        7200504 |               74.87 |                  0 |     60000 |
| DDoS-RSTFINFlood        |        4045285 |               73.5  |                  0 |     60000 |
| DDoS-TCP_Flood          |        4497667 |               65.1  |                  0 |     60000 |
| DDoS-PSHACK_Flood       |        4094755 |               59.78 |                  0 |     60000 |
| DDoS-SYN_Flood          |        4059190 |               52.37 |                  0 |     60000 |
| DoS-TCP_Flood           |        2671445 |               33.41 |                  0 |     60000 |
| Mirai-greeth_flood      |         991866 |               32.12 |                  0 |     60000 |
| Mirai-greip_flood       |         751682 |               26.78 |                  0 |     60000 |
| DoS-SYN_Flood           |        2028834 |               19.68 |                  0 |     60000 |
| DDoS-SynonymousIP_Flood |        3598138 |               14.79 |                  0 |     60000 |
| DoS-UDP_Flood           |        3318595 |               10.81 |                  0 |     60000 |
| DDoS-ACK_Fragmentation  |         285104 |                3.57 |                  0 |     60000 |
| DDoS-ICMP_Fragmentation |         452489 |                1.88 |                  0 |     60000 |
| Recon-PortScan          |          82284 |                0.19 |                  0 |     60000 |
| Recon-OSScan            |          98259 |                0.15 |                  0 |     60000 |
| DoS-HTTP_Flood          |          71864 |                0.11 |                  0 |     60000 |
| Recon-PingSweep         |           2262 |                0.09 |                  0 |      2260 |
| DDoS-HTTP_Flood         |          28790 |                0.06 |                  0 |     28772 |
| Recon-HostDiscovery     |         134378 |                0.02 |                  0 |     60000 |
| DNS_Spoofing            |         178911 |                0.02 |                  0 |     60000 |
| Backdoor_Malware        |           3218 |                0    |                  0 |      3218 |
| SqlInjection            |           5245 |                0    |                  0 |      5245 |
| Uploading_Attack        |           1252 |                0    |                  0 |      1252 |
| CommandInjection        |           5409 |                0    |                  0 |      5409 |
| XSS                     |           3846 |                0    |                  0 |      3846 |
| BrowserHijacking        |           5859 |                0    |                  0 |      5859 |
| BenignTraffic           |        1098195 |                0    |                  0 |   1098177 |
| MITM-ArpSpoofing        |         307593 |                0    |                  0 |     60000 |
| VulnerabilityScan       |          37382 |                0    |                  0 |     37382 |
| Mirai-udpplain          |         890576 |                0    |                  0 |     60000 |
| DDoS-UDP_Fragmentation  |         286925 |                0    |                  0 |     60000 |
| DDoS-UDP_Flood          |        5412287 |                0    |                  0 |     60000 |
| DDoS-SlowLoris          |          23426 |                0    |                  0 |     23426 |
| DictionaryBruteForce    |          13064 |                0    |                  0 |     13064 |

## 2. What one feature alone can do (depth-3 tree, 300,009 train rows, full test)

Flagged (binary balanced accuracy >= 99%): none.

| feature         |   binary_balanced_acc |   category_balanced_acc |   n_distinct_train | suspect   |
|:----------------|----------------------:|------------------------:|-------------------:|:----------|
| IAT             |                0.9411 |                  0.4957 |              79675 | False     |
| Number          |                0.8825 |                  0.2478 |                 96 | False     |
| Weight          |                0.8825 |                  0.2478 |                102 | False     |
| rst_count       |                0.8816 |                  0.342  |              40569 | False     |
| urg_count       |                0.8761 |                  0.3118 |              13719 | False     |
| Variance        |                0.8377 |                  0.296  |                247 | False     |
| flow_duration   |                0.8182 |                  0.3171 |             260561 | False     |
| Header_Length   |                0.8058 |                  0.3658 |             213514 | False     |
| HTTPS           |                0.7991 |                  0.2131 |                  2 | False     |
| Duration        |                0.7924 |                  0.2779 |               7284 | False     |
| ack_flag_number |                0.7875 |                  0.2302 |                  2 | False     |
| Tot size        |                0.7782 |                  0.3855 |              42319 | False     |
| Magnitue        |                0.777  |                  0.3844 |             210401 | False     |
| AVG             |                0.7767 |                  0.3882 |             211699 | False     |
| Std             |                0.7742 |                  0.2988 |             205182 | False     |
| Radius          |                0.7736 |                  0.2989 |             202521 | False     |
| Max             |                0.7712 |                  0.3833 |              40903 | False     |
| Min             |                0.7564 |                  0.3382 |              26905 | False     |
| Covariance      |                0.7509 |                  0.2764 |             202418 | False     |
| Tot sum         |                0.725  |                  0.3922 |             118910 | False     |
| Srate           |                0.7099 |                  0.2642 |             294869 | False     |
| Rate            |                0.7099 |                  0.2642 |             294869 | False     |
| Protocol Type   |                0.684  |                  0.3044 |               2435 | False     |
| syn_count       |                0.6514 |                  0.2758 |                676 | False     |
| TCP             |                0.6424 |                  0.2317 |                  2 | False     |
| fin_count       |                0.5952 |                  0.1804 |                546 | False     |
| syn_flag_number |                0.5769 |                  0.1609 |                  2 | False     |
| ack_count       |                0.5567 |                  0.1897 |                265 | False     |
| UDP             |                0.551  |                  0.1582 |                  2 | False     |
| ICMP            |                0.5408 |                  0.1476 |                  2 | False     |
| rst_flag_number |                0.5338 |                  0.1375 |                  2 | False     |
| HTTP            |                0.5237 |                  0.1482 |                  2 | False     |
| fin_flag_number |                0.5208 |                  0.1365 |                  2 | False     |
| psh_flag_number |                0.5177 |                  0.1366 |                  2 | False     |
| SSH             |                0.5006 |                  0.1424 |                  2 | False     |
| DNS             |                0.5005 |                  0.1257 |                  2 | False     |
| LLC             |                0.5002 |                  0.1256 |                  2 | False     |
| IPv             |                0.5002 |                  0.1256 |                  2 | False     |
| ARP             |                0.5002 |                  0.1253 |                  2 | False     |

## 3. Train/test overlap after scaling

- test rows: 382,187
- identical to some training row: 2
  - with the same binary label: 2
  - only with a different label (conflicts): 0

| class              |   test_rows |   in_train |   in_train_same_binary_label |
|:-------------------|------------:|-----------:|-----------------------------:|
| Mirai-greeth_flood |        9000 |          1 |                            1 |
| Mirai-greip_flood  |        9000 |          1 |                            1 |
