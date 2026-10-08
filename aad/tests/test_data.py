"""Phase 1 (M1) wiring tests on synthetic CSVs - no dataset needed, runs in seconds.

What is pinned here, because each would silently corrupt every later phase:

* the scan counts every row and every class, and refuses unknown labels;
* exact duplicates and conflicting duplicates are counted correctly;
* the sampler never exceeds the cap, keeps "keep_all" classes whole, never
  selects NaN/inf rows or duplicates, and is reproducible under a fixed seed;
* pass 2 returns exactly the rows pass 1 selected;
* the signed log1p is exactly invertible, including for negative values;
* labels gain the 8-way category.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aad.data.clean import normalise_labels  # noqa: E402
from aad.data.loader import (  # noqa: E402
    duplicate_analysis,
    load_selected,
    scan,
    select_capped,
)
from aad.data.split import apply_log1p, inverse_signed_log1p, signed_log1p  # noqa: E402

LABEL_MAP = {
    "benigntraffic": {"name": "BenignTraffic", "code": 0, "binary": 0, "category": "Benign"},
    "ddosicmpflood": {"name": "DDoS-ICMP_Flood", "code": 1, "binary": 1, "category": "DDoS"},
    "sqlinjection": {"name": "SqlInjection", "code": 2, "binary": 1, "category": "Web"},
}
CATEGORIES = {"Benign": 0, "DDoS": 1, "Web": 2}


def _write_csv(path: Path, rows: list[tuple]) -> Path:
    """rows: (f1, f2, label). Written with the real file's header style."""
    df = pd.DataFrame(rows, columns=["flow_duration", "Tot sum", "label"])
    df.to_csv(path, index=False)
    return path


@pytest.fixture
def csv_file(tmp_path: Path) -> Path:
    rng = np.random.default_rng(0)
    rows = []
    # 50 distinct benign rows
    rows += [(float(i), float(rng.integers(0, 1000)), "BenignTraffic") for i in range(50)]
    # 100 flood rows but only 10 distinct -> 90 exact duplicates
    rows += [(float(1000 + i % 10), 5.0, "DDoS-ICMP_Flood") for i in range(100)]
    # 5 SQLi rows, one of which shares its features with benign row 0 -> a conflict
    rows += [(float(2000 + i), 7.0, "SqlInjection") for i in range(4)]
    rows += [(rows[0][0], rows[0][1], "SqlInjection")]
    # one row with a missing value -> must never be selected
    rows += [(float("nan"), 1.0, "SqlInjection")]
    order = rng.permutation(len(rows))  # shuffle so classes interleave
    return _write_csv(tmp_path / "toy.csv", [rows[i] for i in order])


def test_scan_counts_rows_classes_and_bad_cells(csv_file):
    s = scan(csv_file, "label", LABEL_MAP, block_size_mb=1)
    assert s.n_rows == 156
    assert s.feature_columns == ["flow_duration", "Tot sum"]
    assert s.raw_label_counts == {"DDoS-ICMP_Flood": 100, "BenignTraffic": 50, "SqlInjection": 6}
    assert s.nan_by_column == {"flow_duration": 1}
    assert int(s.bad.sum()) == 1
    assert np.bincount(s.codes).tolist() == [50, 100, 6]


def test_scan_rejects_an_unmapped_label(tmp_path):
    path = _write_csv(tmp_path / "bad.csv", [(1.0, 2.0, "BenignTraffic"), (3.0, 4.0, "Zeroday")])
    with pytest.raises(ValueError, match="zeroday"):
        scan(path, "label", LABEL_MAP)


def test_duplicate_analysis_separates_duplicates_from_conflicts(csv_file):
    s = scan(csv_file, "label", LABEL_MAP)
    is_first, rep = duplicate_analysis(s)
    assert rep["exact_duplicate_rows"] == 90
    assert rep["per_code"][1]["exact_duplicates"] == 90
    # benign row 0 and its SQLi twin: one feature vector under two labels
    assert rep["conflicting_feature_vectors"] == 1
    assert rep["per_code"][0]["conflicting_rows"] == 1
    assert rep["per_code"][2]["conflicting_rows"] == 1
    assert int(is_first.sum()) == 156 - 90


def test_rows_differing_only_below_float32_precision_are_duplicates(tmp_path):
    # IAT-like magnitude: 83,677,067.32 and .33 are one float32 value.
    path = _write_csv(tmp_path / "jitter.csv", [
        (83677067.32, 5.0, "DDoS-ICMP_Flood"),
        (83677067.33, 5.0, "DDoS-ICMP_Flood"),   # sub-float32 jitter -> duplicate
        (83677167.32, 5.0, "DDoS-ICMP_Flood"),   # +100: a genuinely different row
    ])
    s = scan(path, "label", LABEL_MAP)
    _, rep = duplicate_analysis(s)
    assert rep["exact_duplicate_rows"] == 1
    assert rep["exact_duplicate_rows_float64"] == 0


def test_dropped_column_is_excluded_and_ignored_by_deduplication(tmp_path):
    """drop_columns must act at the scan, so a row differing only in a dropped
    column is a duplicate - the reason IAT is dropped there, not after loading."""
    path = _write_csv(tmp_path / "drop.csv", [
        (1.0, 5.0, "DDoS-ICMP_Flood"),
        (2.0, 5.0, "DDoS-ICMP_Flood"),   # differs only in flow_duration
        (3.0, 6.0, "DDoS-ICMP_Flood"),   # differs in Tot sum too: distinct
    ])
    s = scan(path, "label", LABEL_MAP, drop_columns=["flow_duration"])
    assert s.feature_columns == ["Tot sum"]
    assert s.extra["header_feature_count"] == 2
    _, rep = duplicate_analysis(s)
    assert rep["exact_duplicate_rows"] == 1

    df = load_selected(path, np.array([0, 2]), "label", drop_columns=["flow_duration"])
    assert list(df.columns) == ["Tot sum", "label"]


def test_unknown_drop_column_is_an_error(tmp_path):
    path = _write_csv(tmp_path / "x.csv", [(1.0, 2.0, "BenignTraffic")])
    with pytest.raises(ValueError, match="not in the CSV header"):
        scan(path, "label", LABEL_MAP, drop_columns=["IATT"])


def test_select_capped_honours_cap_keep_all_and_exclusions(csv_file):
    s = scan(csv_file, "label", LABEL_MAP)
    is_first, _ = duplicate_analysis(s)
    pos, kept = select_capped(s, is_first, cap=8, keep_all_codes={0}, seed=1)

    assert kept == {0: 50, 1: 8, 2: 5}           # benign whole; flood capped; SQLi minus NaN row
    assert np.all(np.diff(pos) > 0)              # sorted, unique
    assert not s.bad[pos].any()                  # never a NaN/inf row
    assert is_first[pos].all()                   # never a duplicate
    again, _ = select_capped(s, is_first, cap=8, keep_all_codes={0}, seed=1)
    assert np.array_equal(pos, again)            # reproducible


def test_load_selected_returns_exactly_the_selected_rows(csv_file):
    s = scan(csv_file, "label", LABEL_MAP, block_size_mb=1)
    is_first, _ = duplicate_analysis(s)
    pos, _ = select_capped(s, is_first, cap=8, keep_all_codes={0}, seed=1)
    df = load_selected(csv_file, pos, "label", block_size_mb=1)

    full = pd.read_csv(csv_file)
    expected = full.iloc[pos].reset_index(drop=True)
    assert len(df) == len(pos)
    np.testing.assert_array_equal(df["flow_duration"].to_numpy(), expected["flow_duration"].to_numpy())
    assert df["label"].astype(str).tolist() == expected["label"].tolist()


def test_signed_log1p_is_exactly_invertible_including_negatives():
    x = np.array([-1e9, -3.5, -1.0, 0.0, 1e-9, 2.0, 8.3e7, 1e12])
    np.testing.assert_allclose(inverse_signed_log1p(signed_log1p(x)), x, rtol=1e-12)
    assert np.all(np.diff(signed_log1p(x)) > 0)  # monotone: order preserved


def test_apply_log1p_rejects_a_misspelt_column():
    df = pd.DataFrame({"Rate": [1.0, 10.0]})
    with pytest.raises(KeyError, match="Rat"):
        apply_log1p(df, ["Rat"])


def test_near_constant_columns_are_dropped_by_non_mode_count():
    from aad.data.clean import find_constant_columns
    n = 1000
    df = pd.DataFrame({
        "constant": np.zeros(n),
        "one_hit": np.r_[np.zeros(n - 1), 1.0],          # 1 non-mode row  -> dropped
        "rare_flag": np.r_[np.zeros(n - 150), np.ones(150)],  # 150 rows -> kept
        "dense": np.arange(n, dtype=float),
    })
    dropped, non_mode = find_constant_columns(df, list(df.columns), min_non_mode_rows=100)
    assert dropped == ["constant", "one_hit"]
    assert non_mode["rare_flag"] == 150
    # with the rule off, only the exactly-constant column goes
    assert find_constant_columns(df, list(df.columns))[0] == ["constant"]


def test_normalise_labels_adds_the_category_column():
    df = pd.DataFrame({"x": [1.0, 2.0, 3.0],
                       "label": ["BenignTraffic", "DDoS-ICMP_Flood", "SqlInjection"]})
    out, _ = normalise_labels(df, "label", LABEL_MAP, CATEGORIES)
    assert out["label_category"].tolist() == [0, 1, 2]
    assert out["label_binary"].tolist() == [0, 1, 1]
