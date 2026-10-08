# CICIoT2023 features — how they were produced, and what that means here

The dataset paper (Neto et al., *CICIoT2023*, Sensors 23(13):5941, 2023, §4) describes the
extraction. This document summarises that description, adds what we **measured** on the
data, and records the decisions taken because of it, in particular dropping `IAT`
(2026-10-08).

---

## 1. The extraction pipeline

```
105 IoT devices --Wireshark--> pcap per experiment --mergecap--> 548 GB of pcap
      --tcpdump--> 10 MB chunks --DPKT (parallel)--> one feature vector per PACKET
      --group consecutive packets into fixed windows--> MEAN of each window = one CSV row
      --pandas merge--> CSV (46 features + label)
```

1. **Capture.** Traffic was recorded with Wireshark for every benign and attack
   experiment, then merged per experiment with `mergecap`.
2. **Split.** The 548 GB were cut into 10 MB chunks with `tcpdump` so extraction could run
   in parallel.
3. **Per-packet features (DPKT).** Each packet gets its header fields (header length, TTL,
   which TCP flags are set, protocol indicators) and statistics about the flow it belongs
   to: rate, flag counts, packet-length min/max/mean/std, and the in/out-length measures
   below. Incomplete packets were removed. The timestamp was used only to sort packets and
   was then dropped.
4. **Windowing.** Consecutive packets are grouped into fixed windows and **each CSV row is
   the mean of its window**. The window size depends on the class, "to mitigate data size
   discrepancy":

   | window | classes |
   | --- | --- |
   | **10 packets** | BenignTraffic; all Recon (HostDiscovery, OSScan, PingSweep, PortScan, VulnerabilityScan); Spoofing (DNS, MITM-ARP); all Web (Backdoor, BrowserHijacking, CommandInjection, SqlInjection, Uploading, XSS); DictionaryBruteForce |
   | **100 packets** | every DDoS and DoS class, and the three Mirai classes |

5. **Merge** into the CSVs; the project uses the Kaggle file that concatenates all 169
   parts (`ciciot23.csv`).

## 2. The features

| # | feature | definition (paper) | what it looks like in the CSV (measured) |
| --- | --- | --- | --- |
| 1 | `flow_duration` | duration of the packet's flow | continuous, heavy-tailed → log1p |
| 2 | `Header_Length` | header length | heavy-tailed → log1p |
| 3 | `Protocol Type` | IP protocol number (TCP 6, UDP 17, ICMP 1, …) | **averaged**: 6.11, 47, … no longer a category |
| 4 | `Duration` | time-to-live (TTL) | averaged TTL, e.g. 64.64 |
| 5–7 | `Rate`, `Srate`, `Drate` | packet rate overall / outbound / inbound | `Srate` equals `Rate` in every row; `Drate` almost always 0 (dropped in M1 as near-constant) |
| 8–14 | `fin/syn/rst/psh/ack/ece/cwr_flag_number` | that flag's value | **strictly 0 or 1 in every row**: not averaged. ECE/CWR dropped as near-constant |
| 15–19 | `ack/syn/fin/urg/rst_count` | packets in the flow with that flag | averaged, non-integer (e.g. 0.1) |
| 20–33 | `HTTP` … `LLC` | protocol indicators | **strictly 0 or 1**; Telnet, SMTP, IRC, DHCP dropped as near-constant |
| 34–38 | `Tot sum`, `Min`, `Max`, `AVG`, `Std` | packet-length sum/min/max/mean/std in the flow | averaged; `Min ≤ AVG ≤ Max` holds in every row |
| 39 | `Tot size` | packet length | averaged |
| 40 | **`IAT`** | "time difference with the previous packet" | **not that**: see section 3 |
| 41 | `Number` | packets in the flow | three values: 5.5, 9.5, 13.5 |
| 42 | `Magnitue` | √(mean in-length + mean out-length) | continuous |
| 43 | `Radius` | √(var in-length + var out-length) | continuous |
| 44 | `Covariance` | cov(in-lengths, out-lengths) | heavy-tailed → log1p |
| 45 | `Variance` | var(in) / var(out) | in [0, 1] |
| 46 | `Weight` | (#in packets) × (#out packets) | three values: 38.5, 141.6, 244.6 |

### What window averaging does, and why it matters for this project

- **A row is a window, not a flow.** Consecutive windows of one flow are near-identical,
  so **39.8% of the file is duplicate rows** at float32 precision (M1). Splitting the raw
  file randomly trains and tests on copies.
- **Arithmetic identities hold only where averaging preserves them.** Min ≤ mean ≤ max,
  "a flag implies TCP" and "at most one transport" survive. "Total = count × mean" does
  not, because a mean of products is not a product of means. The M3 validator measures
  this and prunes the identities that fail.
- **Flags and indicators stay binary**, so they are integrality-checkable (15 columns in
  M3).
- **The window size is a class-dependent capture setting**, and it leaks into the data
  (section 3).

## 3. `IAT`, `Number`, `Weight`: one window-size variable, three times

Measured on the 2.55M-row M1 sample:

| `Number` | `Weight` | `IAT` median | share of benign | share of floods (DDoS/DoS/Mirai) | share of quiet attacks |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 5.5 | 38.5 | 0.006 | 50% | 0% | 45% |
| 9.5 | 141.6 | 8.33 × 10⁷ | **0%** | **99.6%** | 9.9% |
| 13.5 | 244.6 | 1.665 × 10⁸ | 50% | 0% | 45% |

- **`Number` and `Weight` are in one-to-one correspondence**, and `IAT` correlates
  **0.998** with `Number`: roughly `IAT ≈ gap + (Number − 5.5)/4 × 8.33 × 10⁷`.
- **`IAT` holds a real inter-arrival time only at the lowest level.** Elsewhere it is a
  large offset plus jitter. That jitter is what hid the duplicates from exact comparison
  in M1.
- **`Number = 9.5` is the 100-packet window**: 99.6% of floods, no benign rows. It is an
  extraction setting that correlates with the class, not attack behaviour.

### What earlier documents got wrong

The M1 and M2 write-ups (2026-10-07) described `IAT` as "timestamp-like" and suggested its
predictive power reflected *when* attacks were recorded. That was wrong: `IAT` is a
re-encoding of `Number`. They also reported a 13–17 point permutation importance for
`IAT`. That number is inflated: shuffling `IAT` alone, while `Number` stays put, creates
`IAT`/`Number` combinations that never occur, and the drop measures the models' confusion
on impossible rows. The ablation was the honest measure: removing `IAT` cost **0.02
points**. Since 2026-10-08, `02b_feature_reliance.py` permutes correlated features
together, so this cannot recur.

### Decision (2026-10-08): drop `IAT`, keep `Number` and `Weight`

- **`IAT`** is dropped **at the scan** (`config/data.yaml: drop_columns: [IAT]`), so it
  plays no part in deduplication either: windows that differed only in `IAT` jitter are now
  the same row. Its units are meaningless for most rows, and it adds nothing (M2 ablation).
- **`Number` and `Weight`** are kept by user decision. They are documented as the
  window-size encoding: in M4 the attacker cannot change them (the extractor's window is
  not attacker-controlled), and M2+ reports name them whenever they matter.

The 39-feature results produced before the drop (M1–M3 on 2026-10-07/08) are archived in
`artifacts/superseded/39features/`.
