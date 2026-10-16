"""`apps.disktier.classify` and `apps.disktier.tiers` — pure, no database.

The thresholds are spelled out here as literals (the design doc's tables),
not read back from the module: a threshold edited by mistake must fail a
test, not move the test with it.
"""

from __future__ import annotations

import pytest

from apps.disktier.classify import (
    FAILURE_IO_ERRORS,
    FAILURE_SUSPECT_CACHE,
    PROFILE_D1,
    PROFILE_V1,
    classify,
)
from apps.disktier.tiers import SELLABLE_TIERS, DiskTier, rank, satisfies

NVME, SSD, HDD, UNFIT, UNKNOWN = (
    DiskTier.NVME,
    DiskTier.SSD,
    DiskTier.HDD,
    DiskTier.UNFIT,
    DiskTier.UNKNOWN,
)

# (metric, higher_is_better, nvme, ssd, hdd) — design §3.2, profile v1.
V1_TABLE = (
    ("seq_read_mbps", True, 900, 300, 80),
    ("seq_write_mbps", True, 500, 200, 60),
    ("rr_iops", True, 25_000, 8_000, 300),
    ("rw_iops", True, 10_000, 3_000, 150),
    ("qd1_p99_us", False, 1_000, 3_000, 50_000),
    ("rr_p99_us", False, 8_000, 25_000, 400_000),
)
# design §3.3, profile d1: hdd floors only.
D1_TABLE = (
    ("seq_read_inner_mbps", True, 60),
    ("seq_read_outer_mbps", True, 120),
    ("rr_iops", True, 200),
    ("qd1_p99_us", False, 60_000),
    ("rw_sustained_iops", True, 100),
)

#: Clears nvme on every v1 axis with room to spare.
V1_FAST = {
    "seq_read_mbps": 2_000,
    "seq_write_mbps": 1_200,
    "rr_iops": 60_000,
    "rw_iops": 25_000,
    "qd1_p99_us": 400,
    "rr_p99_us": 3_000,
    "qd1_p50_us": 90,
}
#: Clears the d1 hdd floor on every axis.
D1_GOOD = {
    "seq_read_inner_mbps": 110,
    "seq_read_outer_mbps": 250,
    "rr_iops": 450,
    "qd1_p99_us": 25_000,
    "rw_sustained_iops": 300,
    "surface_errors": 0,
    "qd1_p50_us": 4_000,
}


def _v1(**overrides: int) -> dict[str, int]:
    return {**V1_FAST, **overrides}


def _d1(**overrides: int) -> dict[str, int]:
    return {**D1_GOOD, **overrides}


# ─── the module tables are the design tables ─────────────────────────


def test_v1_table_matches_the_design() -> None:
    got = tuple((t.metric, t.higher_is_better, t.nvme, t.ssd, t.hdd) for t in PROFILE_V1.thresholds)
    assert got == V1_TABLE


def test_d1_table_matches_the_design() -> None:
    got = tuple((t.metric, t.higher_is_better, t.hdd) for t in PROFILE_D1.thresholds)
    assert got == D1_TABLE
    assert all(t.nvme is None and t.ssd is None for t in PROFILE_D1.thresholds)


# ─── v1: each metric at each boundary, ±1 ────────────────────────────

_V1_BOUNDARIES = [
    pytest.param(metric, better, limit, tier, below, id=f"{metric}-{tier}")
    for metric, better, nvme, ssd, hdd in V1_TABLE
    for limit, tier, below in ((nvme, NVME, SSD), (ssd, SSD, HDD), (hdd, HDD, UNFIT))
]


@pytest.mark.parametrize(("metric", "higher_is_better", "limit", "tier", "below"), _V1_BOUNDARIES)
def test_v1_boundary(
    metric: str, higher_is_better: bool, limit: int, tier: str, below: str
) -> None:
    # Exactly on the threshold clears the tier...
    on = classify("v1", _v1(**{metric: limit}))
    assert on.per_metric[metric] == tier
    assert on.tier == tier
    assert not on.failed
    # ...one unit on the wrong side does not.
    worse = limit - 1 if higher_is_better else limit + 1
    off = classify("v1", _v1(**{metric: worse}))
    assert off.per_metric[metric] == below
    assert off.tier == below
    # One unit on the right side still clears it.
    better = limit + 1 if higher_is_better else limit - 1
    assert classify("v1", _v1(**{metric: better})).per_metric[metric] == tier


def test_v1_all_fast_is_nvme() -> None:
    verdict = classify("v1", V1_FAST)
    assert verdict.tier == NVME
    assert set(verdict.per_metric.values()) == {NVME}
    assert verdict.failure == ""


# ─── min over metrics ────────────────────────────────────────────────


def test_one_bad_axis_caps_the_tier() -> None:
    # RAID-1 SATA SSDs: reads clear nvme, the cacheless write path does not.
    verdict = classify("v1", _v1(seq_write_mbps=250, rw_iops=4_000, qd1_p99_us=160))
    assert verdict.per_metric["seq_read_mbps"] == NVME
    assert verdict.per_metric["seq_write_mbps"] == SSD
    assert verdict.tier == SSD


def test_the_lowest_axis_wins_across_three_tiers() -> None:
    verdict = classify("v1", _v1(rr_iops=9_000, qd1_p99_us=20_000))
    assert verdict.per_metric["rr_iops"] == SSD
    assert verdict.per_metric["qd1_p99_us"] == HDD
    assert verdict.tier == HDD


def test_below_the_hdd_floor_on_any_axis_is_unfit() -> None:
    verdict = classify("v1", _v1(rr_p99_us=400_001))
    assert verdict.tier == UNFIT
    assert verdict.failure == ""  # a measured verdict, not a failed probe


def test_unfit_on_every_axis() -> None:
    slow = {
        "seq_read_mbps": 10,
        "seq_write_mbps": 5,
        "rr_iops": 50,
        "rw_iops": 20,
        "qd1_p99_us": 90_000,
        "rr_p99_us": 900_000,
        "qd1_p50_us": 8_000,
    }
    verdict = classify("v1", slow)
    assert verdict.tier == UNFIT
    assert set(verdict.per_metric.values()) == {UNFIT}


# ─── suspect-cache sanity ────────────────────────────────────────────


def test_qd1_p50_below_25us_is_a_failed_probe_not_a_tier() -> None:
    verdict = classify("v1", _v1(qd1_p50_us=24))
    assert verdict.failed
    assert verdict.failure == FAILURE_SUSPECT_CACHE
    assert verdict.tier == UNKNOWN


def test_qd1_p50_at_25us_passes_the_sanity_check() -> None:
    verdict = classify("v1", _v1(qd1_p50_us=25))
    assert not verdict.failed
    assert verdict.tier == NVME


def test_suspect_cache_wins_over_an_otherwise_unfit_result() -> None:
    verdict = classify("v1", _v1(qd1_p50_us=3, rr_iops=1))
    assert verdict.failure == FAILURE_SUSPECT_CACHE
    assert verdict.tier == UNKNOWN


def test_suspect_cache_applies_to_d1_too() -> None:
    verdict = classify("d1", _d1(qd1_p50_us=24))
    assert verdict.failure == FAILURE_SUSPECT_CACHE
    assert verdict.tier == UNKNOWN


# ─── d1 ──────────────────────────────────────────────────────────────


def test_d1_good_disk_is_hdd_never_higher() -> None:
    # Even a disk far above the hdd floor grades hdd: d1 has no ssd/nvme
    # columns until calibration adds them.
    fast = _d1(
        seq_read_inner_mbps=3_000,
        seq_read_outer_mbps=3_000,
        rr_iops=500_000,
        qd1_p99_us=100,
        rw_sustained_iops=200_000,
        qd1_p50_us=60,
    )
    assert classify("d1", D1_GOOD).tier == HDD
    assert classify("d1", fast).tier == HDD


@pytest.mark.parametrize(
    ("metric", "higher_is_better", "floor"),
    [pytest.param(m, b, f, id=m) for m, b, f in D1_TABLE],
)
def test_d1_floor_boundary(metric: str, higher_is_better: bool, floor: int) -> None:
    assert classify("d1", _d1(**{metric: floor})).tier == HDD
    worse = floor - 1 if higher_is_better else floor + 1
    verdict = classify("d1", _d1(**{metric: worse}))
    assert verdict.tier == UNFIT
    assert verdict.per_metric[metric] == UNFIT


def test_d1_any_surface_error_is_unfit_and_failed() -> None:
    verdict = classify("d1", _d1(surface_errors=1))
    assert verdict.tier == UNFIT
    assert verdict.failure == FAILURE_IO_ERRORS


def test_d1_io_errors_win_over_suspect_cache() -> None:
    # An I/O error is a fact about the disk: the disk is failed even when
    # the latency numbers look cached.
    verdict = classify("d1", _d1(surface_errors=3, qd1_p50_us=2))
    assert verdict.tier == UNFIT
    assert verdict.failure == FAILURE_IO_ERRORS


# ─── malformed results ───────────────────────────────────────────────


def test_unknown_profile_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown probe profile"):
        classify("v9", V1_FAST)


def test_missing_metric_is_refused() -> None:
    metrics = dict(V1_FAST)
    del metrics["rw_iops"]
    with pytest.raises(ValueError, match="missing metrics"):
        classify("v1", metrics)


def test_missing_sanity_metric_is_refused() -> None:
    metrics = dict(V1_FAST)
    del metrics["qd1_p50_us"]
    with pytest.raises(ValueError, match="missing metrics"):
        classify("v1", metrics)


def test_unknown_metric_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown metrics"):
        classify("v1", _v1(rr_p50_us=500))


def test_reported_metrics_are_accepted_and_not_graded() -> None:
    # The full v1 output: the random-write tail and the wipe rate are
    # measured, never graded — even a terrible value changes nothing.
    verdict = classify("v1", _v1(rw_p99_us=9_000_000, wipe_mbps=1))
    assert verdict.tier == NVME
    assert "rw_p99_us" not in verdict.per_metric
    assert classify("d1", _d1(seq_read_mid_mbps=1, seq_write_mbps=1)).tier == HDD


def test_a_reported_metric_is_still_validated() -> None:
    with pytest.raises(ValueError, match="not an integer"):
        classify("v1", _v1(wipe_mbps=-1))


def test_d1_metrics_are_not_v1_metrics() -> None:
    with pytest.raises(ValueError):
        classify("v1", D1_GOOD)


@pytest.mark.parametrize("bad", [-1, 1.5, "900", True, None])
def test_non_integer_or_negative_value_is_refused(bad: object) -> None:
    with pytest.raises(ValueError, match="not an integer"):
        classify("v1", {**V1_FAST, "seq_read_mbps": bad})


# ─── tier order ──────────────────────────────────────────────────────


def test_rank_order() -> None:
    assert rank(NVME) > rank(SSD) > rank(HDD) > rank(UNFIT)
    assert rank(UNFIT) == rank(UNKNOWN) == 0


def test_rank_refuses_a_non_tier() -> None:
    with pytest.raises(ValueError):
        rank("sata")


@pytest.mark.parametrize(
    ("actual", "required", "ok"),
    [
        (NVME, NVME, True),
        (NVME, SSD, True),
        (NVME, HDD, True),
        (SSD, NVME, False),
        (SSD, SSD, True),
        (SSD, HDD, True),
        (HDD, SSD, False),
        (HDD, HDD, True),
        (UNFIT, HDD, False),
        (UNKNOWN, HDD, False),
    ],
)
def test_satisfies_is_a_minimum(actual: str, required: str, ok: bool) -> None:
    assert satisfies(actual, required) is ok


@pytest.mark.parametrize("required", [UNFIT, UNKNOWN, "sata"])
def test_satisfies_refuses_a_non_sellable_requirement(required: str) -> None:
    with pytest.raises(ValueError):
        satisfies(NVME, required)


def test_sellable_tiers() -> None:
    assert SELLABLE_TIERS == (NVME, SSD, HDD)
