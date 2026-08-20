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
