"""`vm_liveness.current_released_guest` — which guest vali may re-seed
into a wiped KBS keepalive-binding store (`vali_kbs_recover`). It must
only ever vouch for the guest that is running NOW and that the KBS
released to; otherwise it skips (the VM then stays `first-use`).
"""

from __future__ import annotations

import hashlib

import pytest

from apps.telemetry import vm_liveness
from apps.telemetry.models import VmLiveAttestation

pytestmark = pytest.mark.django_db

VM = "vm-a"
CHIP = "5e" * 64
PLATFORM = CHIP
NOW = 1_800_000_000
CURRENT = "44" * 48  # the VM's current launch measurement (the recovery's ticket)


def _row(
    at: int,
    *,
    source: str = "release",
    report: str = "7a",
    chip: str = CHIP,
    measurement: str = CURRENT,
) -> None:
    VmLiveAttestation.objects.create(
        vm_id=VM,
        node_id_hex="aa" * 32,
        attestation_seq=at,
        epoch=1,
        observed_at_unix=at,
        verified_at_unix=at,
        expiry_unix=at + 900,
        measurement=measurement,
        snp_report_digest="11" * 32,
        body_digest=hashlib.sha256(f"{at}/{report}/{source}".encode()).hexdigest(),
        binding_source=source,
        chip_id=chip,
        report_id=report * 32,
    )


def _guest() -> vm_liveness.ReleasedGuest | str:
    return vm_liveness.current_released_guest(
        VM, platform_id=PLATFORM, measurement_hex=CURRENT, now_unix=NOW, max_age_s=3600
    )


def test_the_released_guest_still_attesting_is_vouched_for() -> None:
    _row(NOW - 1800)
    # After a KBS restart the survivor attests as first-use — same guest.
    _row(NOW - 60, source="first-use")
    assert _guest() == vm_liveness.ReleasedGuest(chip_id_hex=CHIP, report_id_hex="7a" * 32)


def test_a_turin_platform_matches_its_padded_chip() -> None:
    chip = "c0ffee0012345678" + "00" * 56
    _row(NOW - 60, chip=chip)
    assert isinstance(
        vm_liveness.current_released_guest(
            VM,
            platform_id="c0ffee0012345678",
            measurement_hex=CURRENT,
            now_unix=NOW,
            max_age_s=3600,
        ),
        vm_liveness.ReleasedGuest,
    )


def test_an_enforce_restart_is_measured_against_the_max_age() -> None:
    # In enforce no sample arrives after the restart: a 20-min-old one is
    # still the guest vali saw alive, well past the 15-min coverage span.
    _row(NOW - 1200)
    assert isinstance(_guest(), vm_liveness.ReleasedGuest)


@pytest.mark.parametrize(
    "setup",
    [
        "no-release",
        "another-guest-since",
        "stale",
        "other-chip",
        "relaunched",
    ],
)
def test_anything_less_than_certain_is_skipped(setup: str) -> None:
    if setup == "no-release":
        _row(NOW - 60, source="first-use")
    elif setup == "another-guest-since":
        _row(NOW - 1800)
        _row(NOW - 60, source="first-use", report="7b")  # a relaunched guest
    elif setup == "stale":
        _row(NOW - 7200)  # older than max_age_s
    elif setup == "other-chip":
        _row(NOW - 60, chip="6f" * 64)  # a §25 source not yet attested at its dest
    elif setup == "relaunched":
        # The VM was relaunched (new measured nonce ⇒ new measurement); the
        # old guest, still alive on a hostile miner, keeps attesting
        # release-bound with the pre-relaunch measurement.
        _row(NOW - 60, measurement="55" * 48)
    assert isinstance(_guest(), str)
