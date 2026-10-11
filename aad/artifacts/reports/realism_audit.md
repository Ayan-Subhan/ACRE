# Realism audit (M4 step 4.2)

Every relation and bound `config/realism.yaml` relies on, measured on 400,000 stratified-random TRAIN rows in raw units. *holds* = exact on the data; *approximate* = true up to the stated error; *assumption* = a modelling choice the data can only describe, to be confirmed by the extractor code (4.1) and at packet level (M7).

### coverage — holds

*every model feature has a realism class*

- features: 36
- unclassified: 0

### Srate = Rate — holds

*Srate is recomputed as Rate*

- benign: max rel. err 0.00e+00
- attack: max rel. err 0.00e+00
- all: max rel. err 0.00e+00

### Magnitue² ≈ 2·AVG — holds

*padding by p adds 2p to Magnitue² (sqrt_shift)*

- benign: median rel. err 0.56%, p90 9.64%
- attack: median rel. err 0.05%, p90 5.00%
- all: median rel. err 0.28%, p90 7.58%

### Tot sum ∝ AVG — assumption

*Tot sum scales with AVG at the row's own ratio (scale_with)*

- benign: Tot sum / AVG median 14.97 (p10 5.11, p90 15.86)
- attack: Tot sum / AVG median 10.50 (p10 6.17, p90 15.27)
- all: Tot sum / AVG median 10.50 (p10 5.48, p90 15.59)
- note: the ratio is a per-row packet count; padding keeps it, so Tot sum moves with AVG

### Tot size ≈ AVG — approximate

*both padded by the same amount (increase_only)*

- benign: median rel. err 25.21%
- attack: median rel. err 0.94%
- all: median rel. err 6.16%

### Min ≤ AVG ≤ Max — holds

*restored by P after the size clamps*

- benign: 100.0000% of rows
- attack: 100.0000% of rows
- all: 100.0000% of rows

### binary columns — holds

*flags and protocol indicators are 0/1 and immutable*

- all: 15 immutable columns are strictly 0/1
- note: fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number, ack_flag_number, HTTP, HTTPS, DNS, SSH, TCP, UDP, ARP, ICMP, IPv, LLC

### size cap — assumption

*packets are padded to at most 1514 bytes*

- benign: 37.42% of rows already exceed it (they keep their own Max as the cap)
- attack: 6.89% of rows already exceed it (they keep their own Max as the cap)
- all: 20.05% of rows already exceed it (they keep their own Max as the cap)

### TTL range — holds

*Duration (mean TTL) lies in [1, 255]*

- benign: 99.995% inside; min 0.00
- attack: 99.992% inside; min 0.00
- all: 99.993% inside; min 0.00

### Rate > 0 — assumption

*throttling scales a positive rate*

- benign: 0.00% of rows have Rate 0 (throttling cannot move them)
- attack: 0.45% of rows have Rate 0 (throttling cannot move them)
- all: 0.26% of rows have Rate 0 (throttling cannot move them)

### flow-age zeros (spec B) — assumption

*stretching multiplies; a zero stays zero*

- attack: flow_duration 22.2% zero, Header_Length 6.3% zero, ack_count 79.3% zero, syn_count 50.1% zero, fin_count 79.1% zero, urg_count 55.9% zero, rst_count 41.7% zero

### representable headroom — assumption

*P clips to what the scaler represents (scaled 1.0)*

- attack: AVG: median row can grow 152.7x, Max: median row can grow 270.8x, Duration: median row can grow 4.0x
