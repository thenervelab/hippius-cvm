"""Tenant-CVM liveness attestations — ingest + the uptime COVERAGE meter.

## The hole this closes

Miner rewards are computed from "attested uptime": the guest emits a
signed `ServedDeliveryReceipt`, `apps.scheduler.usage` accrues
`unit_seconds` into `UsageAccrual`, and that becomes the on-chain
`EpochWeights` a miner is paid on.

Until this module, that receipt was signed ONLY by the guest telemetry
key — which is HKDF-derived from the §7 lifecycle key and therefore
readable by ROOT INSIDE THE CVM. The attack is entirely within a
miner's legitimate powers:

  1. the miner launches a tenant VM on its own node (anyone may);
  2. root inside that VM reads `/run/hippius/lifecycle.key` and derives
     the telemetry key;
  3. the miner KILLS the VM;
  4. it keeps signing uptime receipts forever, from anywhere, and gets
     paid. A red team reproduced this live: ONE fabricated receipt
     credited 5,716,050 unit_seconds for a VM that served nothing.

Every other field in the reward path is already bound to a
`VmBillingBinding` vali wrote itself (`resource_class`, `node_id`,
`lease_id`) and re-submission is watermarked. The SIGNATURE was the
remaining lever, because possession of an extracted key IS the
signature and a dead VM's key still signs.

## The proof a killed VM cannot produce

The KBS `/v1/attest/keepalive` flow (§322 Phase B) already mints
exactly the artifact that closes this, and this module reuses it
verbatim rather than inventing a parallel mechanism:

  - the guest fetches a FRESH single-use nonce from the KBS
    (`POST /v1/kbs/nonce`, durable store, TTL);
  - it asks `/dev/sev-guest` for an `SNP_GET_REPORT` whose `REPORT_DATA`
    byte-equals `nonce ‖ SHA-256(CBOR{live-attestation domain, vm_id})`;
  - the KBS verifies that report VCEK → ASK → ARK against AMD's silicon
    root, checks `measurement ∈ §22 allowlist` + launch-policy bounds,
    checks the nonce is one it issued and has not spent, and only then
    signs a `LiveAttestation` with its L0 key.

Producing those bytes requires the real hardware path inside a LIVE
SEV-SNP guest running the measured image. An extracted software key
does not help — the nonce is not known in advance and the report is
signed by the AMD-rooted VCEK, not by anything in the guest's
filesystem. A dead VM cannot answer at all.

## Coverage semantics — credit only PROVEN-ALIVE time

Each accepted attestation is a liveness SAMPLE at `verified_at_unix`.
`covered_seconds` integrates the samples into the covered subset of a
receipt window; `apps.scheduler.usage` bills only that subset.

A sample at `t` covers `[t - span, t]` — BACKWARD ONLY:

  - backward, because the guest that answered at `t` was demonstrably a
    live CVM, and one span of look-back is what lets a normal cadence
    (a keepalive every few minutes) cover the contiguous receipt windows
    that ended just before it. `span` MUST be >= the keepalive cadence
    or an honest miner is under-paid.
  - never forward, because that is precisely the attack: a last
    attestation before the kill must not vouch for any time after it.
    Coverage stops the moment the VM does.

The look-back is additionally floored at the VM's `VmBillingBinding`
creation time, so the very first sample of a VM's life cannot credit
`span` seconds of uptime from before the VM existed.

## The KBS sequence is NOT durable — and a replay is not a restart

`attestation_seq` is minted by the KBS and is monotonic only within one
KBS chain: the per-VM `(next_seq, prev_attestation_hash)` state lives in
the KBS CVM's state directory (an emptyDir inside a Kata CVM), so every
KBS restart reseeds it to genesis. Deduping on `(vm_id, attestation_seq)`
therefore silently discarded every post-restart attestation until the
fresh sequence climbed past the old maximum — with the gate armed, a KBS
restart stopped paying every running tenant, and nothing said so.

`_resolve_chain` scopes the seq axis to the lineage it is actually
monotonic in, using the SIGNED `prev_attestation_hash` back-pointer. The
anti-replay property is untouched and lives where it always did: the
`body_digest` unique constraint (the content identity of the signed
body), the Ed25519 L0 signature, and the expiry/skew window.

## Fail-closed / fail-open

`apps.scheduler.usage` consults this module ONLY when
`VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION` is armed. That flag's
compiled default is `False` — the SAFE value here, because arming it on
a fleet whose guests do not yet answer keepalive challenges would stop
ALL reward accrual. See the arming sequence beside the flag in
`vali/settings.py`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from . import verifier
from .models import VmLiveAttestation

log = logging.getLogger("apps.telemetry.vm_liveness")

# Postgres BIGINT is signed 64-bit — a u64 field past this cannot be
# stored and is pre-rejected so the write can never raise DataError
# (which would surface as an unhandled 500). Mirrors `service._I64_MAX`.
_I64_MAX = 2**63 - 1

# The `prev_attestation_hash` a KBS stamps at a chain's GENESIS
# (`kbs_core::live_attestation::LiveAttestationChain::genesis`). It names
# no parent, so it can never resolve a lineage by linkage.
_ZERO_DIGEST = "00" * 32

# `_resolve_chain` verdicts — how an incoming attestation relates to what
# vali already holds for this VM.
LINK_FIRST = "first"  # nothing recorded for this VM yet
LINK_CONTINUES = "continues"  # links onto a row vali holds
LINK_RESET = "reset"  # links onto nothing — a NEW lineage
LINK_FORK = "fork"  # links onto a row that already has this seq


class LiveAttestationRefused(Exception):
    """A live attestation vali refuses to record as coverage.

    `category` is a short stable string for the HTTP error body / logs;
    `http_status` is what the view returns.
    """

    def __init__(self, *, message: str, category: str, http_status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.category = category
        self.http_status = http_status


@dataclass(frozen=True)
class Interval:
    """A half-open-ish covered interval in Unix seconds, `[start, end]`."""

    start: int
    end: int


# ─── tunables ────────────────────────────────────────────────────────


def coverage_span_seconds() -> int:
    """How far BACK one liveness sample vouches, in seconds.

    MUST be >= the guest keepalive cadence or honest uptime goes
    uncredited (each receipt window would fall in the gap between
    samples). Default 900 s — comfortably above the few-minute cadence
    the keepalive agent runs at, and small enough that a single sample
    can never credit an unbounded stretch of history.
    """
    return int(getattr(settings, "VALI_UPTIME_LIVENESS_COVERAGE_S", 900))


def _skew_seconds() -> int:
    """±window a live attestation's `verified_at_unix` may differ from
    vali's clock at ingest. Bounds both a pre-forged future timestamp
    and a hoarded stale one. Mirrors the host-beacon skew."""
    return int(getattr(settings, "VALI_UPTIME_LIVENESS_SKEW_S", 300))


def _kbs_l0_verifying_key() -> bytes | None:
    """The pinned KBS L0 Ed25519 public key, or `None` when unwired.

    Shared with the host-attestor cert path (`service._kbs_l0_verifying_key`)
    — same env var, same fail-closed-on-malformed handling. Imported
    lazily-by-duplication rather than cross-imported to keep this module
    free of the (large) `service` import at load time.
    """
    raw = str(getattr(settings, "VALI_KBS_L0_VERIFYING_KEY", "") or "").strip()
    if not raw:
        return None
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        log.error("VALI_KBS_L0_VERIFYING_KEY is not valid hex — treating as unset")
        return None
    if len(key) != 32:
        log.error(
            "VALI_KBS_L0_VERIFYING_KEY must be 32 bytes (got %d) — treating as unset",
            len(key),
        )
        return None
    return key


def _now_unix() -> int:
    """Wall-clock Unix seconds. A module-level indirection so tests pin it."""
    return int(timezone.now().timestamp())


# ─── the KBS chain lineage ───────────────────────────────────────────


def _resolve_chain(*, vm_id: str, prev_hash_hex: str, attestation_seq: int) -> tuple[int, str]:
    """Which LINEAGE does this attestation belong to? `(chain_epoch, link)`.

    ## The bug this exists to kill

    `attestation_seq` is minted by the KBS from
    `kbs_core::live_attestation::LiveAttestationStateStore`, whose per-VM
    `(next_seq, prev_attestation_hash)` chain lives in the KBS CVM's state
    directory — an **emptyDir inside a Kata CVM**. Every KBS restart
    reseeds `LiveAttestationChain::genesis()`, so the guest's next
    attestation arrives at seq 1 while vali already holds rows 1..N.

    Under a bare `(vm_id, attestation_seq)` unique constraint each one
    collided with a row from the PREVIOUS chain and was written off as a
    replay. With the uptime-liveness gate armed that stops paying a
    running tenant until the fresh sequence climbs past the old maximum —
    silently, because every component involved reports success. Observed
    live on `gateproof-a` 2026-08-13: 3.7 h at zero.

    ## The discriminator, and why it needs no wire change

    `prev_attestation_hash` is already in the SIGNED body
    (`hippius_types::live_attestation::LiveAttestation`) and already
    decoded by `verifier.verify_live_attestation`. It is the KBS's own
    hash-chain back-pointer: SHA-256 of the previous body for this VM, or
    the all-zero digest at a chain's genesis. Two attestations at the same
    seq from two different KBS chains have different back-pointers; the
    SAME attestation resubmitted has the same one — and the same
    `body_digest`, which is what actually refuses it.

    So vali resolves the lineage by LINKING: if the incoming
    back-pointer names a body vali has recorded, this attestation
    continues that row's lineage. If it names nothing vali holds, the
    chain vali was tracking has ended (a KBS restart, or a sample lost in
    transit) and this attestation opens a NEW lineage rather than
    colliding with a stale seq.

    ## Why an unlinkable attestation is ACCEPTED, not refused

    Because refusing it is the outage. The property that stops a replay is
    `body_digest` uniqueness plus the expiry/skew window above — neither of
    which this function can weaken: an attacker choosing WHICH signed body
    to submit cannot mint a new one (Ed25519 L0), cannot resubmit an old
    one (body_digest), and cannot hoard one (skew). Opening a lineage buys
    nothing, and every sample still only ever covers BACKWARD from a
    KBS-verified instant, merged, so duplicates cannot double-count.
    """
    latest = (
        VmLiveAttestation.objects.filter(vm_id=vm_id)
        .order_by("-chain_epoch", "-attestation_seq")
        .first()
    )
    if latest is None:
        return 0, LINK_FIRST
    prev = (prev_hash_hex or "").lower()
    if prev and prev != _ZERO_DIGEST:
        parent = VmLiveAttestation.objects.filter(
            vm_id=vm_id, body_digest=prev
        ).first()
        if parent is not None:
            occupied = VmLiveAttestation.objects.filter(
                vm_id=vm_id,
                chain_epoch=parent.chain_epoch,
                attestation_seq=attestation_seq,
            ).exists()
            if not occupied:
                return parent.chain_epoch, LINK_CONTINUES
            # A FORK: a second, different body claiming the same position
            # in a lineage vali already filled. The KBS should never mint
            # one (the chain advance is a CAS), so this is anomalous — but
            # it is still a body only the KBS could have signed, and
            # dropping it is the failure mode this whole function exists
            # to end. Record it in its own lineage, loudly.
            return int(latest.chain_epoch) + 1, LINK_FORK
    return int(latest.chain_epoch) + 1, LINK_RESET


# ─── ingest ──────────────────────────────────────────────────────────


def ingest_live_attestation(*, envelope: bytes) -> tuple[VmLiveAttestation, bool]:
    """Verify + record one KBS-L0-signed `SignedLiveAttestation`.

    Returns `(row, created)`; `created is False` means this attestation
    was already recorded (a replay) and coverage is UNCHANGED. Raises
    `LiveAttestationRefused` on any refusal.

    Fail-closed gate order:

      1. the KBS L0 key must be wired — an unverified attestation is
         worth nothing, so vali refuses to record one at all (503, a
         vali misconfiguration, not a miner fault);
      2. the Rust verifier checks canonical CBOR, byte-exact re-encode,
         the Ed25519 L0 signature, the typed body schema, and that the
         body's self-certified `signer_pubkey` is the key we verified
         under;
      3. i64 range (so the write cannot DataError);
      4. not expired — an attestation past its `expiry_unix` can never
         become coverage;
      5. clock skew — `verified_at_unix` within ±skew of now, bounding
         both a pre-forged future sample and a hoarded stale one;
      6. the VM must have a launch `VmBillingBinding` and the KBS-signed
         `node_id` must match it — coverage is only meaningful for a VM
         vali would actually credit, on the node it would credit;
      7. resolve the KBS chain lineage from the SIGNED
         `prev_attestation_hash` (`_resolve_chain`), so an attestation
         minted after a KBS restart is not mistaken for a replay of the
         same seq in the previous chain;
      8. append-only insert, unique on `body_digest` (the CONTENT
         identity — a replayed attestation collides and extends no
         coverage) and on `(vm_id, chain_epoch, attestation_seq)` (the
         seq axis, scoped to the lineage it is monotonic in).
    """
    vk = _kbs_l0_verifying_key()
    if vk is None:
        raise LiveAttestationRefused(
            message=(
                "live-attestation ingest requires VALI_KBS_L0_VERIFYING_KEY "
                "to be wired"
            ),
            category="kbs-key-unwired",
            http_status=503,
        )
    try:
        fields = verifier.verify_live_attestation(envelope=envelope, verifying_key=vk)
    except verifier.VerifierUnavailable as exc:
        log.error("live-attestation verifier unavailable: %s", exc)
        raise LiveAttestationRefused(
            message="live-attestation verifier is unavailable",
            category="internal",
            http_status=503,
        ) from exc
    except verifier.VerifierFailed as exc:
        log.info("live-attestation rejected: category=%s", exc.category)
        raise LiveAttestationRefused(
            message=f"live-attestation verification failed ({exc.category})",
            category="verify-failed",
        ) from exc

    for name, value in (
        ("attestation_seq", fields.attestation_seq),
        ("epoch", fields.epoch),
        ("observed_at_unix", fields.observed_at_unix),
        ("verified_at_unix", fields.verified_at_unix),
        ("expiry_unix", fields.expiry_unix),
    ):
        if value > _I64_MAX:
            raise LiveAttestationRefused(
                message=f"live-attestation {name} exceeds the storable range",
                category="out-of-range",
            )

    now = _now_unix()
    if fields.expiry_unix <= now:
        raise LiveAttestationRefused(
            message="live attestation is expired",
            category="expired",
        )
    skew = _skew_seconds()
    if fields.verified_at_unix > now + skew:
        raise LiveAttestationRefused(
            message="live attestation is future-dated beyond the skew window",
            category="future-dated",
        )
    if fields.verified_at_unix < now - skew:
        raise LiveAttestationRefused(
            message="live attestation is stale beyond the skew window",
            category="stale",
        )

    # Imported here (not at module load) to avoid a telemetry↔scheduler
    # import cycle — the same discipline `service.py` uses.
    from apps.scheduler.models import VmBillingBinding

    binding = VmBillingBinding.objects.filter(vm_id=fields.vm_id).first()
    if binding is None:
        raise LiveAttestationRefused(
            message="no launch billing binding for this vm_id",
            category="no-binding",
        )
    if fields.node_id_hex.lower() != binding.node_id_hex.lower():
        raise LiveAttestationRefused(
            message="live attestation node_id does not match the launch binding",
            category="node-mismatch",
        )

    chain_epoch, link = _resolve_chain(
        vm_id=fields.vm_id,
        prev_hash_hex=fields.prev_attestation_hash_hex,
        attestation_seq=fields.attestation_seq,
    )
    if link in (LINK_RESET, LINK_FORK):
        # THE signal this incident was missing. A KBS restart is routine
        # and expected; being unable to say so is what made 3.7 h of
        # unpaid uptime look like a healthy INFO line. WARNING, named, and
        # counted by `apps.synthetic.checks.check_uptime_liveness`.
        log.warning(
            "live-attestation chain %s: vm=%s seq=%d prev=%s opens chain_epoch=%d "
            "(the KBS sequence was reseeded — a restart, or a lost sample; "
            "recording it, NOT treating it as a replay)",
            link.upper(),
            fields.vm_id,
            fields.attestation_seq,
            (fields.prev_attestation_hash_hex or "")[:16],
            chain_epoch,
        )

    try:
        with transaction.atomic():
            row = VmLiveAttestation.objects.create(
                vm_id=fields.vm_id,
                node_id_hex=fields.node_id_hex.lower(),
                attestation_seq=fields.attestation_seq,
                epoch=fields.epoch,
                observed_at_unix=fields.observed_at_unix,
                verified_at_unix=fields.verified_at_unix,
                expiry_unix=fields.expiry_unix,
                measurement=fields.measurement_hex,
                snp_report_digest=fields.snp_report_digest_hex,
                body_digest=fields.body_digest_hex,
                prev_attestation_hash=(fields.prev_attestation_hash_hex or "").lower(),
                chain_epoch=chain_epoch,
            )
    except IntegrityError:
        # ⛔ THE anti-replay path. `body_digest` is the CONTENT identity of
        # a signed attestation: the same bytes resubmitted collide here,
        # and coverage is UNCHANGED (the row they collided with is the one
        # that counts). This is the only collision that means "the same
        # attestation" — and it is why a post-restart attestation, which
        # is a genuinely DIFFERENT body, must not be swept in with it.
        existing = VmLiveAttestation.objects.filter(
            body_digest=fields.body_digest_hex
        ).first()
        if existing is not None:
            log.info(
                "live-attestation replay ignored: vm=%s seq=%d digest=%s",
                fields.vm_id,
                fields.attestation_seq,
                fields.body_digest_hex[:16],
            )
            return existing, False
        # A DIFFERENT body collided on `(vm_id, chain_epoch, seq)` — the
        # lineage `_resolve_chain` picked was filled between the resolve
        # and the insert (concurrent ingest of the same VM). Refuse LOUDLY
        # rather than silently calling it a replay: that mislabel is
        # exactly the defect this module was fixed for.
        log.error(
            "live-attestation chain conflict: vm=%s seq=%d chain_epoch=%d — a "
            "DIFFERENT body already occupies this chain position; refusing "
            "(this attestation is NOT recorded and its uptime is NOT credited)",
            fields.vm_id,
            fields.attestation_seq,
            chain_epoch,
        )
        raise LiveAttestationRefused(
            message="live attestation collided with a different body at this chain position",
            category="chain-conflict",
            http_status=409,
        ) from None

    log.info(
        "live-attestation recorded: vm=%s seq=%d verified_at=%d",
        row.vm_id,
        row.attestation_seq,
        row.verified_at_unix,
    )
    # Feed the in-guest liveness watermark (`apps.lifecycle.guest_liveness`)
    # — the OTHER half of the "is anything alive inside this VM?" signal.
    # A live attestation is the strongest possible evidence (a KBS-verified
    # SNP report can only come out of a running SEV-SNP guest), it is just
    # not universal: only newly-baked images carry the keepalive agent. Both
    # signals feed ONE watermark and the freshest wins, so a keepalive-only
    # image is covered without any further change.
    #
    # Only on a NEWLY created row: a replay is not fresh evidence of life,
    # exactly as it extends no billing coverage. Stamped at the ingest
    # instant, which gate (5) above has already bounded to within ±skew of
    # `verified_at_unix`.
    from apps.lifecycle import guest_liveness

    guest_liveness.record_signal(row.vm_id, guest_liveness.SIGNAL_LIVE_ATTESTATION)
    return row, True


# ─── the coverage meter ──────────────────────────────────────────────


def covered_intervals(
    *, vm_id: str, start_unix: int, end_unix: int, floor_unix: int = 0
) -> list[Interval]:
    """The merged, clipped intervals of `[start_unix, end_unix]` this VM
    has an SNP-attested liveness sample for.

    A sample at `t` contributes `[max(t - span, floor_unix, start_unix),
    min(t, end_unix)]` — backward-only look-back (see the module doc).
    Overlapping contributions are merged so a burst of samples cannot
    double-count a second.

    `floor_unix` is the VM's binding-creation instant: the first sample
    of a VM's life must not credit look-back from before the VM existed.
    """
    if end_unix <= start_unix:
        return []
    span = coverage_span_seconds()
    if span < 0:
        span = 0
    # A sample can only touch the window if it is at/after its start
    # (backward-only look-back) and its look-back reaches the window.
    # A sample slightly AFTER `end_unix` still vouches backwards into
    # the window — that is the normal case, since the attestation for a
    # receipt's window typically lands just after the window closes.
    samples = (
        VmLiveAttestation.objects.filter(
            vm_id=vm_id,
            verified_at_unix__gte=start_unix,
            verified_at_unix__lte=end_unix + span,
        )
        .order_by("verified_at_unix")
        .values_list("verified_at_unix", flat=True)
    )
    raw: list[Interval] = []
    for t in samples:
        lo = max(int(t) - span, floor_unix, start_unix)
        hi = min(int(t), end_unix)
        if hi > lo:
            raw.append(Interval(start=lo, end=hi))
    if not raw:
        return []
    raw.sort(key=lambda i: (i.start, i.end))
    merged: list[Interval] = [raw[0]]
    for nxt in raw[1:]:
        last = merged[-1]
        if nxt.start <= last.end:
            if nxt.end > last.end:
                merged[-1] = Interval(start=last.start, end=nxt.end)
        else:
            merged.append(nxt)
    return merged


def covered_seconds(
    *, vm_id: str, start_unix: int, end_unix: int, floor_unix: int = 0
) -> int:
    """Seconds of `[start_unix, end_unix]` backed by an SNP-attested
    liveness sample. `0` when nothing covers the window — the fail-closed
    answer the armed uptime meter bills on."""
    return sum(i.end - i.start for i in covered_intervals(
        vm_id=vm_id, start_unix=start_unix, end_unix=end_unix, floor_unix=floor_unix
    ))
