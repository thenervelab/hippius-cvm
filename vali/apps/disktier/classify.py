"""Grade one probe result against a versioned threshold table (design §3).

Pure: no database, no settings, no clock. A profile names the benchmark a
probe ran and the thresholds it is graded against; changing a threshold is
an edit to this table and nothing else.

- `v1` — a storage pool, benchmarked through the OS disk (LUKS2 +
  dm-integrity) from a `medium` probe VM.
- `d1` — a dedicated physical disk, benchmarked whole through dm-crypt with
  an ephemeral key. It grades `hdd` / `unfit` only: dedicated disks are sold
  as `hdd`-minimum, and its ssd/nvme columns come with calibration.

Rules:

- Each metric clears the highest tier whose threshold it meets. A metric
  with no threshold for a tier cannot clear that tier.
- The verdict is the MINIMUM over all graded metrics: one bad axis caps the
  tier. Below the hdd floor on any axis is `unfit`.
- `qd1_p50_us` below `SUSPECT_CACHE_P50_US` is implausible through virtio +
  SNP + disk crypto: the numbers came from host RAM or page cache, so the
  probe FAILED (`suspect-cache`) and yields no tier at all.
- `d1` only: any I/O error in the surface sample is `unfit`, and the disk
  is failed (`io-errors`).

Every value is a non-negative integer in the unit its name carries (`_mbps`
MB/s, `_iops` operations/s, `_us` microseconds). A result carries every
graded and sanity metric, and may carry the profile's ungraded
`reported_metrics`; a missing, unknown or non-integer metric is a malformed
result: `ValueError`, never a guess.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .tiers import DiskTier, rank

#: QD1 4 KiB read p50 below this is host RAM, not a disk (both profiles).
SUSPECT_CACHE_P50_US = 25

#: Why a probe failed instead of yielding a tier.
FAILURE_SUSPECT_CACHE = "suspect-cache"
FAILURE_IO_ERRORS = "io-errors"


@dataclass(frozen=True)
class Threshold:
    """One graded metric. `higher_is_better` metrics clear a tier at
    `value >= limit`, the others at `value <= limit`. `None` = this metric
    cannot clear that tier."""

    metric: str
    higher_is_better: bool
    nvme: int | None
    ssd: int | None
    hdd: int

    def clears(self, value: int, limit: int | None) -> bool:
        if limit is None:
            return False
        return value >= limit if self.higher_is_better else value <= limit

    def tier_of(self, value: int) -> DiskTier:
        for tier, limit in (
            (DiskTier.NVME, self.nvme),
            (DiskTier.SSD, self.ssd),
            (DiskTier.HDD, self.hdd),
        ):
            if self.clears(value, limit):
                return tier
        return DiskTier.UNFIT


@dataclass(frozen=True)
class Profile:
    name: str
    thresholds: tuple[Threshold, ...]
    #: Ungraded metrics the result must still carry (sanity checks).
    sanity_metrics: tuple[str, ...]
    #: The metric counting surface-read I/O errors, if the profile has one.
    error_metric: str | None = None
    #: Outputs the profile measures but does not grade (yet). Optional, and
    #: validated like the others when present.
    reported_metrics: tuple[str, ...] = ()

    @property
    def required_metrics(self) -> frozenset[str]:
        names = {t.metric for t in self.thresholds} | set(self.sanity_metrics)
        if self.error_metric is not None:
            names.add(self.error_metric)
        return frozenset(names)

    @property
    def known_metrics(self) -> frozenset[str]:
        return self.required_metrics | set(self.reported_metrics)


PROFILE_V1 = Profile(
    name="v1",
    thresholds=(
        Threshold("seq_read_mbps", True, nvme=900, ssd=300, hdd=80),
        Threshold("seq_write_mbps", True, nvme=500, ssd=200, hdd=60),
        Threshold("rr_iops", True, nvme=25_000, ssd=8_000, hdd=300),
        Threshold("rw_iops", True, nvme=10_000, ssd=3_000, hdd=150),
        Threshold("qd1_p99_us", False, nvme=1_000, ssd=3_000, hdd=50_000),
        Threshold("rr_p99_us", False, nvme=8_000, ssd=25_000, hdd=400_000),
    ),
    sanity_metrics=("qd1_p50_us",),
    # The random-write tail and the first-boot integrity wipe rate.
    reported_metrics=("rw_p99_us", "wipe_mbps"),
)

PROFILE_D1 = Profile(
    name="d1",
    thresholds=(
        Threshold("seq_read_inner_mbps", True, nvme=None, ssd=None, hdd=60),
        Threshold("seq_read_outer_mbps", True, nvme=None, ssd=None, hdd=120),
        Threshold("rr_iops", True, nvme=None, ssd=None, hdd=200),
        Threshold("qd1_p99_us", False, nvme=None, ssd=None, hdd=60_000),
        Threshold("sustained_rw_iops", True, nvme=None, ssd=None, hdd=100),
    ),
    sanity_metrics=("qd1_p50_us",),
    error_metric="surface_errors",
    # The middle zone of the sequential read and the bounded-window write.
    reported_metrics=("seq_read_middle_mbps", "seq_write_mbps"),
)

PROFILES: dict[str, Profile] = {p.name: p for p in (PROFILE_V1, PROFILE_D1)}


@dataclass(frozen=True)
class Verdict:
    """The grade of one probe target.

    - `tier`        the classified tier; `unknown` when the probe failed
                    without telling us anything about the disk
                    (`suspect-cache`).
    - `per_metric`  the tier each graded metric cleared on its own.
    - `failure`     `""` for a usable probe, else why it failed.
    """

    profile: str
    tier: DiskTier
    per_metric: dict[str, DiskTier]
    failure: str = ""

    @property
    def failed(self) -> bool:
        return bool(self.failure)


def _validated(profile: Profile, metrics: Mapping[str, object]) -> dict[str, int]:
    missing = profile.required_metrics - metrics.keys()
    if missing:
        raise ValueError(f"profile {profile.name}: missing metrics {sorted(missing)}")
    extra = metrics.keys() - profile.known_metrics
    if extra:
        raise ValueError(f"profile {profile.name}: unknown metrics {sorted(extra)}")
    out: dict[str, int] = {}
    for name in sorted(metrics.keys()):
        value = metrics[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"profile {profile.name}: {name}={value!r} is not an integer >= 0")
        out[name] = value
    return out


def classify(profile_name: str, metrics: Mapping[str, object]) -> Verdict:
    """Grade `metrics` against the named profile. Raises `ValueError` on an
    unknown profile or a malformed result."""
    profile = PROFILES.get(profile_name)
    if profile is None:
        raise ValueError(f"unknown probe profile {profile_name!r}")
    values = _validated(profile, metrics)
    per_metric = {t.metric: t.tier_of(values[t.metric]) for t in profile.thresholds}

    # An I/O error is a fact about the disk whatever else the run shows, so
    # it wins over the cache sanity check.
    if profile.error_metric is not None and values[profile.error_metric] > 0:
        return Verdict(profile.name, DiskTier.UNFIT, per_metric, FAILURE_IO_ERRORS)
    if values["qd1_p50_us"] < SUSPECT_CACHE_P50_US:
        return Verdict(profile.name, DiskTier.UNKNOWN, per_metric, FAILURE_SUSPECT_CACHE)
    tier = min(per_metric.values(), key=rank)
    return Verdict(profile.name, DiskTier(tier), per_metric)
