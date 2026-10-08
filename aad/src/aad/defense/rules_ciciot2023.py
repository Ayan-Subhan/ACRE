"""Candidate dependency rules for CICIoT2023, declared by column name.

These are *candidates*. The analyzer instantiates every rule whose columns
survived phase 1, measures its residual on benign training traffic, and keeps it
only if benign traffic satisfies it tightly (``analyzer.DEPENDENCY_MAX_TOL``).
Rules that benign traffic does not obey are pruned and listed in rules.json under
``dependency.excluded_loose`` - so a wrong guess here costs nothing but a line in
the ledger, and the data, not this file, decides what is enforced.

Each rule states a fact about how the CICIoT2023 extractor produces a row (see
docs/m3-validator.md section 2 for the measurement behind each one):

* ordering     - min <= mean <= max of the same packet-length statistic.
* equal        - two columns the extractor emits identically (Srate is Rate,
                 IPv is LLC, in every one of 2.5M rows).
* linear_le    - sum(lhs coef * column) <= sum(rhs coef * column) + constant:
                 a protocol hierarchy (HTTP implies TCP), mutually exclusive
                 transport protocols, and flags that only exist on TCP.
* product      - total ~= count * mean.

Names are matched through ``validator.norm_name``, so spacing and case drift in
the CSV header do not matter.
"""

from __future__ import annotations

# min <= mean <= max
ORDERING_RULES: list[tuple[str, str, str]] = [
    ("Min", "AVG", "Max"),
]

# a == b
EQUAL_RULES: list[tuple[str, str]] = [
    ("Srate", "Rate"),
    ("IPv", "LLC"),
]

# (lhs {column: coef}, rhs {column: coef}, rhs constant): lhs <= rhs + const
LINEAR_LE_RULES: list[tuple[str, dict[str, float], dict[str, float], float]] = [
    # application protocols run over TCP / UDP
    ("HTTP implies TCP", {"HTTP": 1}, {"TCP": 1}, 0.0),
    ("HTTPS implies TCP", {"HTTPS": 1}, {"TCP": 1}, 0.0),
    ("SSH implies TCP", {"SSH": 1}, {"TCP": 1}, 0.0),
    ("Telnet implies TCP", {"Telnet": 1}, {"TCP": 1}, 0.0),
    ("SMTP implies TCP", {"SMTP": 1}, {"TCP": 1}, 0.0),
    ("IRC implies TCP", {"IRC": 1}, {"TCP": 1}, 0.0),
    ("DNS implies UDP", {"DNS": 1}, {"UDP": 1}, 0.0),
    ("DHCP implies UDP", {"DHCP": 1}, {"UDP": 1}, 0.0),
    # TCP flags only exist on TCP packets
    ("FIN flag implies TCP", {"fin_flag_number": 1}, {"TCP": 1}, 0.0),
    ("SYN flag implies TCP", {"syn_flag_number": 1}, {"TCP": 1}, 0.0),
    ("RST flag implies TCP", {"rst_flag_number": 1}, {"TCP": 1}, 0.0),
    ("PSH flag implies TCP", {"psh_flag_number": 1}, {"TCP": 1}, 0.0),
    ("ACK flag implies TCP", {"ack_flag_number": 1}, {"TCP": 1}, 0.0),
    ("ECE flag implies TCP", {"ece_flag_number": 1}, {"TCP": 1}, 0.0),
    ("CWR flag implies TCP", {"cwr_flag_number": 1}, {"TCP": 1}, 0.0),
    # mutually exclusive protocol families
    ("TCP + UDP + ICMP <= 1", {"TCP": 1, "UDP": 1, "ICMP": 1}, {}, 1.0),
    ("ARP + IPv <= 1", {"ARP": 1, "IPv": 1}, {}, 1.0),
    # IP protocol numbers (TCP 6, UDP 17, ICMP 1) bounded by the Protocol Type
    # column. Plausible from the schema; measured violated by 14% of benign rows,
    # so it is expected to be pruned - kept to show that pruning works.
    ("6 TCP + 17 UDP + ICMP <= Protocol Type",
     {"TCP": 6, "UDP": 17, "ICMP": 1}, {"Protocol Type": 1}, 0.0),
]

# total ~= count * mean. Holds per packet window but not for window MEANS
# (mean of a product != product of means): expected to be pruned.
PRODUCT_RULES: list[tuple[str, str, str]] = [
    ("Tot sum", "Number", "AVG"),
]

# Columns the conditional distribution family groups rows by: each row belongs
# to the protocol whose indicator it carries (benign IoT traffic is a mixture of
# TCP, UDP, ICMP and ARP behaviour with very different statistics).
PROTOCOL_GROUPS: list[str] = ["TCP", "UDP", "ICMP", "ARP"]
