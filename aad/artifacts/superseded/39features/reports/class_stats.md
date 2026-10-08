# Table I - CICIoT2023 as processed for this project

Source: `ciciot23.csv` (13.75 GB, 46,686,579 rows).
Distinct rows at float32 (model) precision: 28,098,546; duplicates removed: 18,588,033 (of which exact float64 copies: 34; the rest differ only below float32 precision, almost always in `IAT`). Feature vectors that occur under more than one label: 0.
Sampling: every class deduplicated, then capped at 60,000 rows (seed 42); kept whole: ['benigntraffic'].
Kept: 2,547,910 rows, 39 of 46 features. Split 0.7/0.15/0.15, stratified on the 34-way label.

`rows_in_file`, `exact_duplicates` and `conflicting` describe the full file; `kept` onward describe this project's sample.

| code   | class                   | category   |   rows_in_file |   exact_duplicates |   conflicting |    kept |   train |    val |   test |
|:-------|:------------------------|:-----------|---------------:|-------------------:|--------------:|--------:|--------:|-------:|-------:|
| 0      | BenignTraffic           | Benign     |        1098195 |                 18 |             0 | 1098177 |  768724 | 164726 | 164727 |
| 1      | DDoS-ACK_Fragmentation  | DDoS       |         285104 |              10171 |             0 |   60000 |   42000 |   9000 |   9000 |
| 2      | DDoS-HTTP_Flood         | DDoS       |          28790 |                 18 |             0 |   28772 |   20140 |   4316 |   4316 |
| 3      | DDoS-ICMP_Flood         | DDoS       |        7200504 |            5391331 |             0 |   60000 |   42000 |   9000 |   9000 |
| 4      | DDoS-ICMP_Fragmentation | DDoS       |         452489 |               8510 |             0 |   60000 |   42000 |   9000 |   9000 |
| 5      | DDoS-PSHACK_Flood       | DDoS       |        4094755 |            2447671 |             0 |   60000 |   42000 |   9000 |   9000 |
| 6      | DDoS-RSTFINFlood        | DDoS       |        4045285 |            2973326 |             0 |   60000 |   42000 |   9000 |   9000 |
| 7      | DDoS-SlowLoris          | DDoS       |          23426 |                  0 |             0 |   23426 |   16398 |   3514 |   3514 |
| 8      | DDoS-SYN_Flood          | DDoS       |        4059190 |            2125743 |             0 |   60000 |   42000 |   9000 |   9000 |
| 9      | DDoS-SynonymousIP_Flood | DDoS       |        3598138 |             532172 |             0 |   60000 |   42000 |   9000 |   9000 |
| 10     | DDoS-TCP_Flood          | DDoS       |        4497667 |            2928062 |             0 |   60000 |   42000 |   9000 |   9000 |
| 11     | DDoS-UDP_Flood          | DDoS       |        5412287 |                  0 |             0 |   60000 |   42000 |   9000 |   9000 |
| 12     | DDoS-UDP_Fragmentation  | DDoS       |         286925 |                  0 |             0 |   60000 |   42000 |   9000 |   9000 |
| 13     | DoS-HTTP_Flood          | DoS        |          71864 |                 78 |             0 |   60000 |   42000 |   9000 |   9000 |
| 14     | DoS-SYN_Flood           | DoS        |        2028834 |             399238 |             0 |   60000 |   42000 |   9000 |   9000 |
| 15     | DoS-TCP_Flood           | DoS        |        2671445 |             892537 |             0 |   60000 |   42000 |   9000 |   9000 |
| 16     | DoS-UDP_Flood           | DoS        |        3318595 |             358862 |             0 |   60000 |   42000 |   9000 |   9000 |
| 17     | Mirai-greeth_flood      | Mirai      |         991866 |             318634 |             0 |   60000 |   42000 |   9000 |   9000 |
| 18     | Mirai-greip_flood       | Mirai      |         751682 |             201280 |             0 |   60000 |   42000 |   9000 |   9000 |
| 19     | Mirai-udpplain          | Mirai      |         890576 |                  0 |             0 |   60000 |   42000 |   9000 |   9000 |
| 20     | Recon-HostDiscovery     | Recon      |         134378 |                 33 |             0 |   60000 |   42000 |   9000 |   9000 |
| 21     | Recon-OSScan            | Recon      |          98259 |                147 |             0 |   60000 |   42000 |   9000 |   9000 |
| 22     | Recon-PingSweep         | Recon      |           2262 |                  2 |             0 |    2260 |    1582 |    339 |    339 |
| 23     | Recon-PortScan          | Recon      |          82284 |                160 |             0 |   60000 |   42000 |   9000 |   9000 |
| 24     | VulnerabilityScan       | Recon      |          37382 |                  0 |             0 |   37382 |   26168 |   5607 |   5607 |
| 25     | DNS_Spoofing            | Spoofing   |         178911 |                 38 |             0 |   60000 |   42000 |   9000 |   9000 |
| 26     | MITM-ArpSpoofing        | Spoofing   |         307593 |                  2 |             0 |   60000 |   42000 |   9000 |   9000 |
| 27     | Backdoor_Malware        | Web        |           3218 |                  0 |             0 |    3218 |    2253 |    483 |    482 |
| 28     | BrowserHijacking        | Web        |           5859 |                  0 |             0 |    5859 |    4101 |    879 |    879 |
| 29     | CommandInjection        | Web        |           5409 |                  0 |             0 |    5409 |    3786 |    811 |    812 |
| 30     | SqlInjection            | Web        |           5245 |                  0 |             0 |    5245 |    3672 |    787 |    786 |
| 31     | Uploading_Attack        | Web        |           1252 |                  0 |             0 |    1252 |     876 |    188 |    188 |
| 32     | XSS                     | Web        |           3846 |                  0 |             0 |    3846 |    2692 |    577 |    577 |
| 33     | DictionaryBruteForce    | BruteForce |          13064 |                  0 |             0 |   13064 |    9145 |   1959 |   1960 |
|        | ALL                     |            |       46686579 |           18588033 |             0 | 2547910 | 1783537 | 382186 | 382187 |

## Cleaning ledger

- NaN cells in the file: 0 
- Infinite cells in the file: 0 
- Rows dropped by the post-sample clean pass (must be 0): NaN 0, duplicate 0
- Constant / near-constant columns dropped (fewer than 100 train rows differ from the column's mode; train only): {'Drate': 38, 'ece_flag_number': 15, 'cwr_flag_number': 9, 'Telnet': 1, 'SMTP': 1, 'IRC': 2, 'DHCP': 0}
- Signed-log1p columns: ['flow_duration', 'Header_Length', 'Rate', 'Srate', 'syn_count', 'fin_count', 'urg_count', 'rst_count', 'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size', 'Radius', 'Covariance']
