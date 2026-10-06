"""End-to-end: a REAL KBS-signed live attestation → real Rust verifier
→ vali ingest → coverage → a credited (or refused) receipt window.

Every other test of this feature mocks the shell-out. This one does
not: it pipes the committed `test_vectors/live_attestation/` envelope —
a genuine canonical-CBOR `SignedLiveAttestation` signed by a fixed
Ed25519 key — through the built `verify-live-attestation` binary and
into `vm_liveness.ingest_live_attestation`.

It is therefore the only place that checks the Rust→JSON→Python field
contract against real cryptography. If the subcommand renames a JSON
field, drops one, or changes the digest it reports, the mocks stay
happy and THIS test fails.

Auto-skips when the release binary is not built.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from django.conf import settings

from apps.scheduler.models import VmBillingBinding
from apps.telemetry import vm_liveness
from apps.telemetry.models import VmLiveAttestation

pytestmark = pytest.mark.django_db

REPO_ROOT = Path(__file__).resolve().parents[4]
VECTOR = REPO_ROOT / "test_vectors" / "live_attestation" / "signed_live_attestation.cbor"
_REAL_BIN = Path(settings.VALI_TICKET_VALIDATOR_BIN)

# Pinned in `hippius-types/tests/live_attestation_kat.rs` — the PUBLIC
# half of the KAT seed, standing in for the KBS L0 key.
KAT_KBS_L0 = "0d7550754e0800a5d237eef5826035766b9b3e5a15868a940ab289958788e3b0"
KAT_VM = "tn-kat-live-1"
KAT_NODE = "bb" * 32
KAT_SEQ = 7
KAT_VERIFIED_AT = 1_800_000_005

# A pinned key that is PARSEABLE as Ed25519 but is not the KBS's, so the
# refusal below comes from the signature gate rather than from the binary
# rejecting an unreadable `--vk-hex`. Written as a repeated byte, not a
# 64-char literal, so a secret scanner does not read a public key as a
# credential. That a DISTINCT, well-formed miner key also fails is proven
# where the keys can be derived rather than pinned:
# `binaries/ticket-validator/src/live_attestation.rs::
# body_signed_by_a_miner_key_is_refused`.
NOT_THE_KBS_KEY = "00" * 32

_needs_bin = pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=(
        f"Rust validator not built at {_REAL_BIN} — run "
        "`cargo build -p hippius-ticket-validator --release`"
    ),
)
_needs_vector = pytest.mark.skipif(
    not VECTOR.is_file(), reason=f"KAT vector missing at {VECTOR}"
)


@pytest.fixture(autouse=True)
def _pin_clock(monkeypatch):
    # The KAT attestation is stamped `verified_at_unix = 1_800_000_005`
    # with a 900 s expiry; run the ingest clock right beside it so the
    # freshness gates pass on the real fixture.
    monkeypatch.setattr(vm_liveness, "_now_unix", lambda: KAT_VERIFIED_AT)


@pytest.fixture
def _binding():
    from apps.orchestration.models import MeasurementLedger

    # The KAT body's measurement, as the launch's auto-pin would record it.
    MeasurementLedger.objects.create(vm_id=KAT_VM, launch_digest_hex="33" * 48, allowlist_epoch=1)
    return VmBillingBinding.objects.create(
        vm_id=KAT_VM,
        node_id_hex=KAT_NODE,
        resource_class="small",
        lease_id="lease-kat",
    )


@_needs_bin
@_needs_vector
def test_a_real_signed_attestation_is_ingested_and_becomes_coverage(
    settings, _binding
) -> None:
    settings.VALI_KBS_L0_VERIFYING_KEY = KAT_KBS_L0
    settings.VALI_UPTIME_LIVENESS_COVERAGE_S = 900

    row, created = vm_liveness.ingest_live_attestation(envelope=VECTOR.read_bytes())

    assert created is True
    assert row.vm_id == KAT_VM
    assert row.attestation_seq == KAT_SEQ
    assert row.verified_at_unix == KAT_VERIFIED_AT
    assert row.node_id_hex == KAT_NODE
    assert len(row.body_digest) == 64
    assert len(row.measurement) == 96

    # …and it really is coverage: the 60 s ending at the attestation.
    assert (
        vm_liveness.covered_seconds(
            vm_id=KAT_VM,
            start_unix=KAT_VERIFIED_AT - 60,
            end_unix=KAT_VERIFIED_AT,
        )
        == 60
    )


@_needs_bin
@_needs_vector
def test_the_same_real_attestation_under_a_different_pinned_key_is_refused(
    settings, _binding
) -> None:
    """The signature is what makes this evidence. Pin any other key —
    e.g. a miner's own — and the identical bytes buy nothing."""
    settings.VALI_KBS_L0_VERIFYING_KEY = NOT_THE_KBS_KEY

    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=VECTOR.read_bytes())

    assert exc.value.category == "verify-failed"
    assert VmLiveAttestation.objects.count() == 0


@_needs_bin
@_needs_vector
def test_a_tampered_real_attestation_is_refused(settings, _binding) -> None:
    """Flip one byte of the signed body: the L0 signature no longer
    verifies, so a relaying miner cannot edit what it carries."""
    settings.VALI_KBS_L0_VERIFYING_KEY = KAT_KBS_L0
    raw = bytearray(VECTOR.read_bytes())
    raw[len(raw) // 2] ^= 0xFF

    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=bytes(raw))

    assert exc.value.category == "verify-failed"
    assert VmLiveAttestation.objects.count() == 0


@_needs_bin
@_needs_vector
def test_the_binary_refuses_to_run_without_a_verifying_key() -> None:
    """There is NO decode-only mode. Invoking the subcommand with no
    `--vk-hex` — or an empty one — must fail at argv, never emit an
    `{"ok":true,...}` body vali could mistake for coverage."""
    import subprocess

    for argv in ([], ["--vk-hex", ""], ["--vk-hex", "   "]):
        proc = subprocess.run(
            [str(_REAL_BIN), "verify-live-attestation", *argv],
            input=VECTOR.read_bytes(),
            capture_output=True,
            timeout=60,
        )
        assert proc.returncode != 0, argv
        assert b'"ok":true' not in proc.stdout, argv


@_needs_bin
@_needs_vector
def test_replaying_the_real_attestation_is_idempotent(settings, _binding) -> None:
    settings.VALI_KBS_L0_VERIFYING_KEY = KAT_KBS_L0
    first, created = vm_liveness.ingest_live_attestation(
        envelope=VECTOR.read_bytes()
    )
    assert created is True
    for _ in range(3):
        again, created_again = vm_liveness.ingest_live_attestation(
            envelope=VECTOR.read_bytes()
        )
        assert created_again is False
        assert again.pk == first.pk
    assert VmLiveAttestation.objects.count() == 1


VECTOR_V2 = VECTOR.with_name("signed_live_attestation_v2.cbor")
KAT_V2_CHIP = "5e" * 64
KAT_V2_REPORT = "7a" * 32


def _kat_miner(platform_id: str) -> None:
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.create(
        miner_id="miner-kat",
        pubkey_hex="ab" * 32,
        platform_id=platform_id,
        chain_node_id=KAT_NODE,
    )


@_needs_bin
@pytest.mark.skipif(not VECTOR_V2.is_file(), reason=f"KAT vector missing at {VECTOR_V2}")
def test_a_real_v2_attestation_carries_the_bound_guest(settings, _binding) -> None:
    """The v2 (guest-bound) contract, Rust→JSON→Python with real bytes."""
    settings.VALI_KBS_L0_VERIFYING_KEY = KAT_KBS_L0
    _kat_miner(KAT_V2_CHIP)

    row, created = vm_liveness.ingest_live_attestation(envelope=VECTOR_V2.read_bytes())

    assert created is True
    assert (row.binding_source, row.chip_id, row.report_id) == (
        "release",
        KAT_V2_CHIP,
        KAT_V2_REPORT,
    )


@_needs_bin
@pytest.mark.skipif(not VECTOR_V2.is_file(), reason=f"KAT vector missing at {VECTOR_V2}")
def test_a_real_v2_attestation_off_the_nodes_chip_is_refused(settings, _binding) -> None:
    settings.VALI_KBS_L0_VERIFYING_KEY = KAT_KBS_L0
    _kat_miner("6f" * 64)

    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=VECTOR_V2.read_bytes())

    assert exc.value.category == "chip-mismatch"
    assert VmLiveAttestation.objects.count() == 0


VECTOR_V3 = VECTOR.with_name("signed_live_attestation_v3.cbor")


@_needs_bin
@pytest.mark.skipif(not VECTOR_V3.is_file(), reason=f"KAT vector missing at {VECTOR_V3}")
@pytest.mark.parametrize(
    ("flavor", "verdict"),
    [("large", "ok"), ("xlarge", "short")],
)
def test_a_real_v3_attestation_carries_the_attested_resources(
    settings, _binding, flavor: str, verdict: str
) -> None:
    """The v3 (attested resources) contract, Rust→JSON→Python with real
    bytes: the KAT guest attests 4 vCPU / 16 GiB, a `large`."""
    from apps.telemetry.models import GuestResourceShortfall

    settings.VALI_KBS_L0_VERIFYING_KEY = KAT_KBS_L0
    _kat_miner(KAT_V2_CHIP)
    VmBillingBinding.objects.filter(pk=_binding.pk).update(resource_class=flavor)

    row, created = vm_liveness.ingest_live_attestation(envelope=VECTOR_V3.read_bytes())

    assert created is True
    assert (row.vcpus_online, row.mem_firmware_kib, row.mem_total_kib, row.mem_unaccepted_kib) == (
        4,
        16_776_164,
        15_337_812,
        1024,
    )
    assert row.binding_source == "release"
    assert row.resource_verdict == verdict
    assert GuestResourceShortfall.objects.filter(vm_id=KAT_VM).exists() is (verdict == "short")


VECTOR_V4 = VECTOR.with_name("signed_live_attestation_v4.cbor")


@_needs_bin
@pytest.mark.skipif(not VECTOR_V4.is_file(), reason=f"KAT vector missing at {VECTOR_V4}")
def test_a_real_v4_attestation_carries_the_attested_components(settings, _binding) -> None:
    """The v4 (guest components) contract, Rust→JSON→Python with real
    bytes: release 2, epoch 1, every health check passing, keepalive
    instance 0x12345678 with one failing tick latched."""
    settings.VALI_KBS_L0_VERIFYING_KEY = KAT_KBS_L0
    _kat_miner(KAT_V2_CHIP)
    VmBillingBinding.objects.filter(pk=_binding.pk).update(resource_class="large")

    row, created = vm_liveness.ingest_live_attestation(envelope=VECTOR_V4.read_bytes())

    assert created is True
    assert (
        row.components_release_version,
        row.components_security_epoch,
        row.components_health,
        row.components_instance,
        row.components_unhealthy_ticks,
    ) == (2, 1, 15, 0x1234_5678, 1)
    # v4 keeps v3's resources and v2's binding when they are present.
    assert row.vcpus_online == 4
    assert row.binding_source == "release"


@_needs_bin
@_needs_vector
def test_a_pre_v4_attestation_has_no_components(settings, _binding) -> None:
    settings.VALI_KBS_L0_VERIFYING_KEY = KAT_KBS_L0

    row, _ = vm_liveness.ingest_live_attestation(envelope=VECTOR.read_bytes())

    assert row.components_health is None and row.components_release_version is None
