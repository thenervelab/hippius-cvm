"""§9 telemetry-broker service layer — ingest, pull, poison, GC.

Spec of record: ARCHITECTURE.md §9.

`ingest()` is the write path: schema-version gate → registered-source
+ quarantine gate → backpressure gate → signature/schema verify →
durable enqueue. `pull()` is the read path: a cursor-paged, atomic,
concurrent-pull-safe drain. `gc()` reaps terminal envelopes.

The broker is **pull-only and inbound-only**: nothing here ever
constructs an outbound request, and `source_id` is only ever a
database key / registry lookup — never a host or URL.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from django.conf import settings
from django.db import IntegrityError, connection, transaction
from django.db.models import Q
from django.utils import timezone

from . import verifier
from .models import (
    KNOWN_SCHEMA_VERSIONS,
    EnvelopeKind,
    HostAttestor,
    HostAttestorNonce,
    HostAttestorStatus,
    ProcessingStatus,
    SourceType,
    TelemetryEnvelope,
    TelemetrySource,
)

# The §K heartbeat wire-format version (`MinerHeartbeat.SCHEMA_VERSION`)
# — the value `verify-heartbeat` gates the signed body to. A heartbeat
# `TelemetryEnvelope` is stamped with it; it is a member of
# `KNOWN_SCHEMA_VERSIONS`.
_HEARTBEAT_SCHEMA_VERSION = 1

# Largest value a Postgres signed `bigint` (`MinerIdentity.
# last_heartbeat_sequence`) can hold. The heartbeat `sequence` is a
# Rust `u64`, so a value past this must be rejected before the write.
_I64_MAX = 2**63 - 1

log = logging.getLogger("apps.telemetry.service")

# How long after a VM's creation we keep trying to resolve its NetBird
# overlay IP from served-receipt ingests. A netbird guest enrols within
# ~1-2 min of boot; past this window a still-empty `netbird_ip` means the
# VM is netbird-disabled or failed to enrol, so we stop probing the
# NetBird API on every receipt (bounds the per-receipt cost on the
# synchronous ingest path).
_NETBIRD_RESOLVE_WINDOW = timedelta(minutes=30)


class IngestError(Exception):
    """An ingest was refused. Carries the HTTP status + stable
    `category` the view returns, and an optional `Retry-After`.
    """

    def __init__(
        self,
        *,
        message: str,
        category: str,
        http_status: int,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.category = category
        self.http_status = http_status
        self.retry_after = retry_after


# ─── tuning knobs ────────────────────────────────────────────────────


def _max_pending() -> int:
    return int(getattr(settings, "VALI_TELEMETRY_MAX_PENDING", 100_000))


def _max_pending_per_source() -> int:
    """Per-source Pending cap (RA-M4). A single source can hold at most this
    many un-drained envelopes, so it cannot monopolise the GLOBAL queue and
    503 every OTHER source's heartbeats + billing receipts. Clamped to the
    global budget (never larger, so it stays inert if misconfigured high)."""
    raw = int(getattr(settings, "VALI_TELEMETRY_MAX_PENDING_PER_SOURCE", 1000))
    return max(1, min(raw, _max_pending()))


def _assert_backpressure_ok(source: str, source_id: str) -> None:
    """Bounded-queue gate: fail-closed 503 if either this SOURCE's share OR
    the GLOBAL Pending queue is at capacity. The per-source check runs FIRST
    (RA-M4) so one source flooding valid envelopes is refused on its own
    quota long before it can fill the global queue and starve everyone else.
    Both are plain COUNTs — no lock. The per-source count is narrowed by the
    `source_id` index and is bounded (a source's Pending rows are ≤ its cap
    and drained each meter cycle)."""
    per_source = TelemetryEnvelope.objects.filter(
        source=source,
        source_id=source_id,
        processing_status=ProcessingStatus.PENDING.value,
    ).count()
    if per_source >= _max_pending_per_source():
        raise IngestError(
            message="telemetry source queue is at capacity",
            category="backpressure-source",
            http_status=503,
            retry_after=_backpressure_retry_after(),
        )
    pending = TelemetryEnvelope.objects.filter(
        processing_status=ProcessingStatus.PENDING.value
    ).count()
    if pending >= _max_pending():
        raise IngestError(
            message="telemetry queue is at capacity",
            category="backpressure",
            http_status=503,
            retry_after=_backpressure_retry_after(),
        )


def _quarantine_threshold() -> int:
    return int(getattr(settings, "VALI_TELEMETRY_QUARANTINE_THRESHOLD", 3))


def _quarantine_window() -> int:
    return int(getattr(settings, "VALI_TELEMETRY_QUARANTINE_WINDOW_S", 300))


def _quarantine_ttl() -> int:
    return int(getattr(settings, "VALI_TELEMETRY_QUARANTINE_TTL_S", 3600))


def _backpressure_retry_after() -> int:
    return int(getattr(settings, "VALI_TELEMETRY_BACKPRESSURE_RETRY_AFTER_S", 30))


def _gc_age_days() -> int:
    return int(getattr(settings, "VALI_TELEMETRY_GC_AGE_DAYS", 7))


def _nonce_gc_grace_s() -> int:
    """Grace, in seconds, before a spent/expired host-attestor nonce is
    reaped by `gc()`. Default 3600 s — long enough for a brief audit trail,
    short enough that spent/expired (permanently unclaimable) rows can't
    accumulate once the chantier is armed."""
    return int(getattr(settings, "VALI_HOST_ATTESTOR_NONCE_GC_GRACE_S", 3600))


def _heartbeat_skew_seconds() -> int:
    """±window, in seconds, a heartbeat's `timestamp_unix` may differ
    from vali's clock (§K anti-skew). Default 300 s.
    """
    return int(getattr(settings, "VALI_HEARTBEAT_SKEW_SECONDS", 300))


def pull_max_limit() -> int:
    return int(getattr(settings, "VALI_TELEMETRY_PULL_MAX_LIMIT", 1000))


def max_envelope_bytes() -> int:
    """Hard cap on a single decoded telemetry payload. Kept small —
    telemetry envelopes are tiny — so the hex-encoded JSON ingest
    request stays well under Django's `DATA_UPLOAD_MAX_MEMORY_SIZE`.
    """
    return int(getattr(settings, "VALI_TELEMETRY_MAX_ENVELOPE_BYTES", 16384))


# ─── dedupe ──────────────────────────────────────────────────────────


def _dedupe_digest(
    *, source: str, source_id: str, kind: str, schema_version: int, body: bytes
) -> str:
    """SHA-256 over the envelope *identity* — not the body alone.

    Two distinct sources (or two kinds) emitting byte-identical
    bodies must NOT collapse into one row; the digest therefore binds
    `(source, source_id, kind, schema_version)` ahead of the body.
    NUL separators keep the field boundaries unambiguous.
    """
    h = hashlib.sha256()
    for field in (source, source_id, kind, str(schema_version)):
        h.update(field.encode("utf-8"))
        h.update(b"\x00")
    h.update(body)
    return h.hexdigest()


# ─── ingest ──────────────────────────────────────────────────────────


def _node_id_is_onchain_active(node_id_hex: str) -> bool:
    """`True` iff `node_id_hex` is registered + `Active` on-chain.

    Reuses the Edge-registry-feed cache (warm — the Edge polls it every
    ~30 s); on a cache miss it does a fresh `read-miner-status` chain
    read. Fail-closed: any chain-read failure returns `False`.
    """
    from django.core.cache import cache

    cached = cache.get("edge_registry_feed_v1")
    if cached is not None:
        # The scheduler stores this entry as a `(canonical_json_str,
        # sig_hex)` tuple (see `EdgeRegistryFeedView`), NOT a dict.
        # Decode it exactly like the feed view; on ANY malformed shape
        # fall through to the authoritative chain read (fail-closed) —
        # never crash and never treat a decode failure as "active".
        try:
            canonical, _sig = cached
            miners = json.loads(canonical).get("miners", [])
            return any(
                m.get("node_id_hex") == node_id_hex and m.get("status") == "active"
                for m in miners
            )
        except (ValueError, TypeError, AttributeError):
            pass

    from apps.scheduler import chain

    try:
        cs = chain.read_miner_status()
    except chain.ChainReadUnavailable:
        return False
    return any(
        m.node_id == node_id_hex and m.status == "active" for m in cs.miners
    )


def autoprovision_node_heartbeat_source(
    node_id_hex: str, envelope: bytes
) -> str | None:
    """Permissionless first-contact provisioning (§K).

    A heartbeat arriving under a `hippius-node:<node_id>` peer-id whose
    node_id vali does not yet know is provisioned a `MinerIdentity` +
    `TelemetrySource` ON THE SPOT — no operator step — iff BOTH gates
    pass:

      1. **Cryptographic** — the heartbeat is signed by `node_id` (which
         IS the miner's Ed25519 public key). A forged peer-id cannot
         pass: the signature is checked against the claimed key itself.
      2. **On-chain** — `node_id` is registered + `Active` on
         `pallet-compute-scoring` (§23). Defence-in-depth beyond the
         Edge's admission: vali never provisions an unregistered node.

    Returns the provisioned `miner_id` (== the signed body's `miner_id`,
    so the peer-vs-body gate passes on the subsequent ingest), or `None`
    to fail-closed. Idempotent — a re-provision heals an existing row.
    """
    try:
        node_id = bytes.fromhex(node_id_hex)
    except ValueError:
        return None
    if len(node_id) != 32:
        return None
    # (1) Cryptographic gate — the node_id is the verifying key.
    try:
        hb = verifier.verify_heartbeat(envelope=envelope, verifying_key=node_id)
    except (verifier.VerifierFailed, verifier.VerifierUnavailable):
        return None
    # (2) On-chain gate.
    if not _node_id_is_onchain_active(node_id_hex):
        log.warning("autoprovision refused: node_id is not on-chain Active")
        return None
    # (3) Provision (idempotent). `source_id == hb.miner_id` so the
    #     peer-vs-body gate (5) passes on the ingest that follows.
    from apps.miners.models import MinerIdentity, autoprovision_platform_id

    miner_id = hb.miner_id
    with transaction.atomic():
        MinerIdentity.objects.get_or_create(
            miner_id=miner_id,
            defaults={
                "pubkey_hex": node_id_hex,
                # Per node — `platform_id` is unique, so a shared literal
                # would let only one unregistered miner exist at a time.
                "platform_id": autoprovision_platform_id(node_id_hex),
                "chain_node_id": node_id_hex,
            },
        )
        TelemetrySource.objects.update_or_create(
            source=SourceType.MINER.value,
            source_id=miner_id,
            defaults={"verifying_key": node_id, "is_active": True},
        )
    log.info("autoprovisioned permissionless miner source: miner_id=%s", miner_id)
    return miner_id


def ingest(
    *,
    source: str,
    source_id: str,
    kind: str,
    schema_version: int,
    body: bytes,
    sig: bytes,
) -> tuple[TelemetryEnvelope, bool]:
    """Verify + enqueue one telemetry envelope.

    Raises `IngestError` on any refusal (the view maps it to a
    status code). Returns `(envelope, created)` — `created` is
    `False` when this was an idempotent re-ingest of a byte-identical
    valid envelope (the pre-existing row is returned).
    """
    # 1. Schema-version gate — fail closed on an unknown version.
    if schema_version not in KNOWN_SCHEMA_VERSIONS:
        raise IngestError(
            message=f"unknown schema_version {schema_version}",
            category="schema-version",
            http_status=400,
        )

    # 2. Registered-source gate — the verifying key is the trust
    #    anchor; an unregistered / inactive source is refused. This
    #    is NOT a verification failure, so it is not a poison strike.
    src = TelemetrySource.objects.filter(
        source=source, source_id=source_id
    ).first()
    if src is None or not src.is_active:
        raise IngestError(
            message="telemetry source is not registered or is inactive",
            category="source-not-registered",
            http_status=403,
        )

    now = timezone.now()

    # 3. Quarantine gate — a poisoned source is refused outright,
    #    without even spending a verify.
    if src.quarantined_until is not None and src.quarantined_until > now:
        retry_after = int((src.quarantined_until - now).total_seconds()) + 1
        raise IngestError(
            message="telemetry source is quarantined",
            category="source-quarantined",
            http_status=429,
            retry_after=retry_after,
        )

    # 4. Backpressure gate — a bounded queue, per-source THEN global
    #    (RA-M4): a source flooding valid envelopes is 503'd on its own
    #    quota before it can starve every other source.
    _assert_backpressure_ok(source, source_id)

    # 5. Signature + schema verification (shell-out, parser-hardened).
    try:
        verifier.verify_envelope(
            kind=kind,
            body=body,
            sig=sig,
            verifying_key=bytes(src.verifying_key),
        )
    except verifier.VerifierUnavailable as exc:
        # vali / the binary is broken — NOT the source's fault, so
        # no poison strike. 503.
        log.error("telemetry verifier unavailable: %s", exc)
        raise IngestError(
            message="telemetry verifier is unavailable",
            category="internal",
            http_status=503,
        ) from exc
    except verifier.VerifierFailed as exc:
        # A genuinely bad envelope — store it for forensics and count
        # a §9 poison strike against the source.
        TelemetryEnvelope.objects.create(
            source=source,
            source_id=source_id,
            kind=kind,
            schema_version=schema_version,
            payload_cbor=body,
            signature=sig,
            processing_status=ProcessingStatus.FAILED.value,
        )
        _record_failure(source, source_id, now)
        log.info(
            "telemetry envelope rejected: source=%s:%s category=%s",
            source,
            source_id,
            exc.category,
        )
        raise IngestError(
            message=f"telemetry verification failed ({exc.category})",
            category="verify-failed",
            http_status=400,
        ) from exc

    # 6. Verified — reset the poison counter, enqueue.
    _record_success(source, source_id)
    digest = _dedupe_digest(
        source=source,
        source_id=source_id,
        kind=kind,
        schema_version=schema_version,
        body=body,
    )
    # 6b. Zombie gate — a NEW, verified served receipt from a VM whose
    #     §24 crypto-erase already ran proves a miner is still running a
    #     VM it was told to kill. Refuse it (never enqueued ⇒ never
    #     billed) and record the observation. A byte-identical REPLAY of a
    #     receipt accepted while the VM was live is not new evidence: it
    #     falls through to the dedupe below, unchanged.
    if (
        source == SourceType.TENANT_VM.value
        and kind == EnvelopeKind.SERVED_RECEIPT.value
        and not TelemetryEnvelope.objects.filter(dedupe_digest=digest).exists()
    ):
        from apps.lifecycle import zombie

        dead_vm = zombie.erased_vm(source_id, now)
        if dead_vm is not None:
            zombie.observe(dead_vm, kind=kind, now=now)
            raise IngestError(
                message=f"vm is past its {zombie.erase_phrase(dead_vm)}; receipt refused",
                category="vm-not-live",
                http_status=410,
            )
    try:
        with transaction.atomic():
            envelope = TelemetryEnvelope.objects.create(
                source=source,
                source_id=source_id,
                kind=kind,
                schema_version=schema_version,
                payload_cbor=body,
                signature=sig,
                dedupe_digest=digest,
                processing_status=ProcessingStatus.PENDING.value,
            )
    except IntegrityError:
        # Dedupe: a byte-identical valid envelope is already stored.
        # Idempotent — return the existing row.
        existing = TelemetryEnvelope.objects.filter(dedupe_digest=digest).first()
        if existing is not None:
            log.info(
                "telemetry envelope deduplicated: envelope_id=%s",
                existing.envelope_id,
            )
            return existing, False
        raise

    # Miner-fleet liveness — a genuinely NEW verified envelope from a
    # registered miner refreshes that miner's `last_seen_at`. Placed
    # here, on the created path only: it runs AFTER every fail-closed
    # gate (schema → registered source → quarantine → backpressure →
    # signature verify → enqueue), so a rejected — or a deduplicated
    # replay — envelope never bumps it. A no-op for non-miner sources.
    _touch_miner_last_seen(source, source_id, now)
    # A verified `served_receipt` from a `tenant_vm` proves the guest is
    # fully up (it only emits uptime receipts once serving) — advance that
    # VM's display-only boot milestone to `running` + self-heal its
    # NetBird overlay IP. Fail-open, isolated: never touches ingest.
    _advance_tenant_vm_boot_progress(source, source_id, kind, now)
    log.info(
        "telemetry envelope ingested: envelope_id=%s kind=%s source=%s:%s",
        envelope.envelope_id,
        kind,
        source,
        source_id,
    )
    return envelope, True


# ─── heartbeat ingest (§K / PR-Part4-B) ──────────────────────────────


#: The largest value a `MinerCapacity.declared_*` column can hold.
_DECLARED_MAX = 2_147_483_647


def declared_capacity_columns(
    declared: verifier.DeclaredCapacity,
) -> dict[str, int | None]:
    """Map a `v3` declaration onto the `MinerCapacity.declared_*` columns.

    `0` on the wire means "the miner could not read it", so it is stored
    as NULL (no clamp) — never as a literal 0, which would be read as a
    zero budget and starve the miner.
    """

    def _known(value: int) -> int | None:
        # 0 = unknown. Above the column's range (signed 32-bit on
        # Postgres) is not a real host either — and a u32 the heartbeat
        # schema allows must not turn into a 500 on the write. Both mean
        # "no clamp", which can only leave vali's trusted bound in charge.
        return value if 0 < value <= _DECLARED_MAX else None

    return {
        "declared_cpu_budget": _known(declared.cvm_cpu_budget),
        "declared_memory_mb_budget": _known(declared.cvm_memory_mb_budget),
        "declared_asid_capacity": _known(declared.asid_capacity),
        "declared_asid_used": _known(declared.asid_used),
    }


def declared_disk_columns(declared: verifier.DeclaredDisk) -> dict[str, int | None]:
    """Map a `v4` disk report onto the `MinerCapacity` disk columns.

    Same rule as [`declared_capacity_columns`]: `0` on the wire means
    "unknown" and is stored as NULL (no term), and a value above the
    column's range is not a real host either — never a 500 on the write.
    One exception: a data-fs `available` of 0 next to a known total is a
    full disk, and is kept (it can only LOWER capacity)."""

    def _known(value: int) -> int | None:
        return value if 0 < value <= _DECLARED_MAX else None

    def _available(value: int, total: int | None) -> int | None:
        # statvfs rounds DOWN to whole GiB, so a genuinely full fs reports
        # available = 0. Next to a known total that 0 is a MEASUREMENT (the
        # most important one — it is what stops placements onto a full
        # disk), not "unknown"; without a total it stays unknown.
        if value == 0 and total is not None:
            return 0
        return _known(value)

    data_total = _known(declared.data_disk_total_gb)
    return {
        "declared_disk_gb_budget": _known(declared.cvm_disk_gb_budget),
        "reported_data_disk_total_gb": data_total,
        "reported_data_disk_available_gb": _available(
            declared.data_disk_available_gb, data_total
        ),
        "reported_staging_disk_available_gb": _known(declared.staging_disk_available_gb),
    }


def host_health_columns(declared: verifier.DeclaredHostHealth) -> dict[str, int | bool | None]:
    """Map a `v5` host-health report onto the `MinerCapacity` columns.

    Unlike the capacity figures, `0` is a real reading here (no CPU
    offline, no flush failure) and is stored as is. A count above the
    column's range is not a real host and is stored as NULL rather than
    turning the write into a 500."""

    def _count(value: int) -> int | None:
        return value if 0 <= value <= _DECLARED_MAX else None

    return {
        "reported_snp_enabled": declared.snp_enabled,
        "reported_cpus_offline": _count(declared.cpus_offline),
        "reported_snp_launches_since_boot": _count(declared.snp_launches_since_boot),
        "reported_df_flush_failures": _count(declared.df_flush_failures),
    }


def ingest_heartbeat(
    *, miner_id: str, envelope: bytes
) -> tuple[TelemetryEnvelope, bool]:
    """Verify + enqueue one signed miner heartbeat (§K / PR-Part4-B).

    `miner_id` is resolved by the view from the Edge-stamped
    `x-hippius-peer-id` mTLS-identity header — NOT from the opaque CBOR
    `envelope` (vali never decodes CBOR). `envelope` is the raw
    canonical-CBOR `SignedMinerHeartbeat`.

    Fail-closed gate order: registered miner-source → quarantine →
    backpressure → signature verify (data-bearing shell-out) →
    peer-vs-body `miner_id` match → ±skew → atomic
    `select_for_update`(`MinerIdentity`) { lifecycle status → monotonic
    `sequence` → enqueue + bump `last_heartbeat_sequence` /
    `last_seen_at` }. Raises `IngestError` on any refusal.

    Returns `(envelope_row, True)` — a heartbeat is never an idempotent
    re-ingest: a byte-identical replay carries a non-increasing
    `sequence` and is refused by the monotonic gate.
    """
    # 1. Registered-source gate. Registering a `MinerIdentity`
    #    provisions a linked `TelemetrySource` (source=miner); its
    #    `verifying_key` is the trust anchor. An unregistered / inactive
    #    source is refused — not a verification failure, no poison.
    src = TelemetrySource.objects.filter(
        source=SourceType.MINER.value, source_id=miner_id
    ).first()
    if src is None or not src.is_active:
        raise IngestError(
            message="miner telemetry source is not registered or is inactive",
            category="source-not-registered",
            http_status=403,
        )

    now = timezone.now()

    # 2. Quarantine gate — a §9-poisoned source is refused outright.
    if src.quarantined_until is not None and src.quarantined_until > now:
        retry_after = int((src.quarantined_until - now).total_seconds()) + 1
        raise IngestError(
            message="miner telemetry source is quarantined",
            category="source-quarantined",
            http_status=429,
            retry_after=retry_after,
        )

    # 3. Backpressure gate — the bounded queue, per-source THEN global
    #    (RA-M4): a flooding source is 503'd on its own quota before it can
    #    fill the global queue and starve every other miner's heartbeats.
    _assert_backpressure_ok(SourceType.MINER.value, miner_id)

    # 4. Signature + schema verification — the data-bearing shell-out.
    try:
        hb = verifier.verify_heartbeat(
            envelope=envelope, verifying_key=bytes(src.verifying_key)
        )
    except verifier.VerifierUnavailable as exc:
        # vali / the binary is broken — NOT the miner's fault. 503.
        log.error("heartbeat verifier unavailable: %s", exc)
        raise IngestError(
            message="heartbeat verifier is unavailable",
            category="internal",
            http_status=503,
        ) from exc
    except verifier.VerifierFailed as exc:
        # A genuinely bad envelope (bad signature / non-canonical /
        # wrong schema|domain) — retain it `Failed` for forensics and
        # count a §9 poison strike.
        TelemetryEnvelope.objects.create(
            source=SourceType.MINER.value,
            source_id=miner_id,
            kind=EnvelopeKind.HEARTBEAT.value,
            schema_version=_HEARTBEAT_SCHEMA_VERSION,
            payload_cbor=envelope,
            signature=b"",
            processing_status=ProcessingStatus.FAILED.value,
        )
        _record_failure(SourceType.MINER.value, miner_id, now)
        log.info(
            "heartbeat rejected: miner_id=%s error_class=%s",
            miner_id,
            exc.category,
        )
        raise IngestError(
            message=f"heartbeat verification failed ({exc.category})",
            category="verify-failed",
            http_status=400,
        ) from exc

    # The §9 poison counter is touched ONLY at the two genuine
    #   endpoints: `_record_failure` above (a verification failure) and
    #   `_record_success` after a FULL accept (below). A heartbeat that
    #   verifies but is then policy-rejected (gates 5–7) leaves the
    #   counter untouched — a captured-and-replayed valid heartbeat must
    #   not be able to clear a miner's accumulating strikes.

    # 5. The peer-derived `miner_id` MUST equal the signed body's
    #    `miner_id`. The signature already proved the body authentic to
    #    THIS source's key; a divergent body `miner_id` is a
    #    misconfigured / hostile miner. Reject (no poison — the
    #    signature itself was valid).
    if hb.miner_id != miner_id:
        log.warning(
            "heartbeat miner_id mismatch: peer=%s body=%s",
            miner_id,
            hb.miner_id,
        )
        raise IngestError(
            message="heartbeat body miner_id does not match the authenticated peer",
            category="miner-id-mismatch",
            http_status=400,
        )

    # 6. ±skew anti-replay-across-time — the signed `timestamp_unix`
    #    must be within the window of vali's own clock.
    skew = abs(hb.timestamp_unix - int(now.timestamp()))
    if skew > _heartbeat_skew_seconds():
        log.info(
            "heartbeat timestamp skew too large: miner_id=%s skew=%ds",
            miner_id,
            skew,
        )
        raise IngestError(
            message="heartbeat timestamp is outside the allowed skew window",
            category="timestamp-skew",
            http_status=400,
        )

    # 7. Range gate. The signed `sequence` is a Rust `u64` (up to
    #    2**64-1), but `MinerIdentity.last_heartbeat_sequence` is a
    #    Postgres signed `bigint` (`i64`, max 2**63-1). A miner that
    #    signs a `sequence` past `i64::MAX` would otherwise blow up the
    #    `miner.save()` below with an unhandled `DataError`/500 — so
    #    pre-reject it here with a clean 400 (mirrors the §6
    #    `check_u64_fits_i64` guard in `ticket-validator`'s ticket path).
    if hb.sequence > _I64_MAX:
        log.info(
            "heartbeat sequence out of i64 range: miner_id=%s", miner_id
        )
        raise IngestError(
            message="heartbeat sequence exceeds the storable range",
            category="sequence-out-of-range",
            http_status=400,
        )

    # 8. Monotonic `sequence` + accept — atomic, under a row lock on
    #    `MinerIdentity` so two concurrent heartbeats from one miner
    #    cannot both pass the check (a lost-update would let a replay
    #    through). The lock is taken AFTER the shell-out so no DB row
    #    lock is ever held across the subprocess.
    try:
        with transaction.atomic():
            miner = _lock_miner(miner_id)
            if miner is None:
                raise IngestError(
                    message="miner is not in the identity registry",
                    category="miner-not-registered",
                    http_status=404,
                )
            from apps.miners.models import MinerStatus

            if miner.status != MinerStatus.ACTIVE.value:
                raise IngestError(
                    message="miner is quarantined",
                    category="miner-quarantined",
                    http_status=403,
                )
            if (
                miner.last_heartbeat_sequence is not None
                and hb.sequence <= miner.last_heartbeat_sequence
            ):
                # A sequence not strictly greater than the last accepted
                # one is a replay (==) or a regression (<).
                raise IngestError(
                    message="heartbeat sequence is a replay or regression",
                    category="sequence-replay",
                    http_status=400,
                )
            envelope_row = TelemetryEnvelope.objects.create(
                source=SourceType.MINER.value,
                source_id=miner_id,
                kind=EnvelopeKind.HEARTBEAT.value,
                schema_version=hb.schema_version,
                payload_cbor=envelope,
                signature=b"",
                # No content-dedupe: the monotonic `sequence` gate IS
                # the heartbeat replay defence (a byte-identical replay
                # is already refused above), so `dedupe_digest` stays
                # empty — every accepted heartbeat is a fresh row.
                dedupe_digest="",
                # DONE, not PENDING: a heartbeat's ENTIRE effect —
                # `last_seen_at` + `last_heartbeat_sequence` — is applied
                # synchronously right below, and NOTHING ever `pull()`s
                # `kind=heartbeat` (only `served_receipt` is drained, for
                # billing). Left PENDING the row would never drain, pile up
                # unboundedly, and — since #742's per-source backpressure
                # quota counts PENDING rows — eventually 503 the source's
                # own future heartbeats (freezing `last_seen` → the miner
                # goes stale → undispatchable). As a terminal audit record
                # it stays out of the backpressure count and is GC-reaped.
                processing_status=ProcessingStatus.DONE.value,
            )
            miner.last_heartbeat_sequence = hb.sequence
            miner.last_seen_at = now
            miner.save(
                update_fields=["last_heartbeat_sequence", "last_seen_at"]
            )
            # Record the UNTRUSTED self-reported free RAM onto the
            # scheduler mirror (keyed by the on-chain node_id), for the
            # DOWN-ONLY dynamic-capacity throttle. It can never raise a
            # miner's admission bound (see `scheduler.capacity`), so this
            # is a soft signal — a plain filtered UPDATE that no-ops when
            # the miner has no bridged node_id / no mirror row yet.
            if (
                hb.memory_available_mib is not None
                and miner.chain_node_id
            ):
                from apps.scheduler.models import MinerCapacity

                MinerCapacity.objects.filter(
                    miner_node_id=miner.chain_node_id
                ).update(
                    reported_memory_available_mib=hb.memory_available_mib,
                    reported_at=now,
                )
            # The `v3` capacity declarations (capacity v2 §4.2) — the
            # miner's own #668 budget and SEV-ES ASID figures. UNTRUSTED,
            # consumed only as DOWN-ONLY clamps (`budget_inputs`), so this
            # is the same kind of targeted, filtered UPDATE as the RAM
            # report. A `v1`/`v2` heartbeat carries no declaration
            # (`declared_capacity is None`) and leaves the stored one
            # UNTOUCHED — it goes stale on its own via `declared_at`
            # instead of being clobbered by a miner mid-upgrade.
            if hb.declared_capacity is not None and miner.chain_node_id:
                from apps.scheduler.models import MinerCapacity

                MinerCapacity.objects.filter(
                    miner_node_id=miner.chain_node_id
                ).update(
                    **declared_capacity_columns(hb.declared_capacity),
                    declared_at=now,
                )
            # The `v4` DATA-disk figures (storage-aware placement). UNTRUSTED,
            # consumed only as DOWN-ONLY terms of the disk budget
            # (`scheduler.capacity.disk_budget`) and the over-claim alarm.
            # A pre-v4 heartbeat carries none and leaves the stored ones
            # UNTOUCHED — they age out via `disk_reported_at`.
            if hb.declared_disk is not None and miner.chain_node_id:
                from apps.scheduler.models import MinerCapacity

                MinerCapacity.objects.filter(
                    miner_node_id=miner.chain_node_id
                ).update(
                    **declared_disk_columns(hb.declared_disk),
                    disk_reported_at=now,
                )
            # The `v5` SEV-SNP host-health report. UNTRUSTED, alerted on
            # only (`vali_scheduler_reeval`); a pre-v5 heartbeat leaves the
            # stored report untouched — it ages out via
            # `host_health_reported_at`.
            if hb.declared_host_health is not None and miner.chain_node_id:
                from apps.scheduler.models import MinerCapacity

                MinerCapacity.objects.filter(
                    miner_node_id=miner.chain_node_id
                ).update(
                    **host_health_columns(hb.declared_host_health),
                    host_health_reported_at=now,
                )
            # The `v6` miner-agent release tag. UNTRUSTED, observability
            # only; a pre-v6 heartbeat leaves the stored tag untouched — it
            # ages out via `agent_version_reported_at`.
            if hb.agent_version is not None and miner.chain_node_id:
                from apps.scheduler.models import MinerCapacity

                MinerCapacity.objects.filter(
                    miner_node_id=miner.chain_node_id
                ).update(
                    agent_version=hb.agent_version,
                    agent_version_reported_at=now,
                )
    except IngestError:
        raise
    except IntegrityError:
        # No `dedupe_digest` is set above, so the partial-unique index
        # cannot trip — but fail closed loudly if that ever changes.
        log.error("unexpected IntegrityError enqueuing heartbeat")
        raise IngestError(
            message="heartbeat enqueue conflict",
            category="internal",
            http_status=503,
        ) from None

    # 9. Fully accepted — NOW reset the §9 poison counter (a genuinely
    #    delivered heartbeat breaks any consecutive-failure run). Placed
    #    after the accept so a verified-but-policy-rejected heartbeat
    #    (gates 5–8) never resets it.
    _record_success(SourceType.MINER.value, miner_id)
    log.info(
        "heartbeat ingested: envelope_id=%s miner_id=%s sequence=%d",
        envelope_row.envelope_id,
        miner_id,
        hb.sequence,
    )

    # 10. Piggybacked graceful-exit (transport (B)). A `v2` heartbeat may
    #     ALSO carry `graceful_exit_requested=true` — the miner is alive
    #     (we recorded its liveness above) but wants to leave. Run the
    #     SAME row-locked quarantine the Edge-relayed `SignedGracefulExit`
    #     path uses (`apply_graceful_exit_quarantine`, #524) so the
    #     §13/§25 auto-migration warm-migrates its VMs off. The heartbeat
    #     is NOT rejected — it is accepted AND the miner is quarantined.
    #     Idempotent: a re-quarantine of an already-QUARANTINED miner is a
    #     no-op (a later heartbeat from the now-quarantined miner is
    #     refused by gate 8's status check, which is correct — the
    #     graceful exit is a one-way transition). Imported lazily to avoid
    #     a telemetry↔miners import cycle at module load.
    if hb.graceful_exit_requested:
        from apps.miners.views import apply_graceful_exit_quarantine

        applied = apply_graceful_exit_quarantine(miner_id, hb)
        log.warning(
            "heartbeat carried graceful-exit flag → quarantine %s: "
            "miner_id=%s sequence=%d",
            "applied" if applied else "skipped (miner row vanished)",
            miner_id,
            hb.sequence,
        )

    return envelope_row, True


# ─── blackbox host-attestor ingest (PR-8, INERT) ─────────────────────
#
# Two ingest paths, fail-closed throughout: a KBS-minted enrollment cert
# (`ingest_host_attestor_cert`) and a signed liveness beacon
# (`ingest_host_beacon`). Ships INERT — nothing reads the persisted
# `HostAttestor` rows for reward / dispatchability yet.


def _kbs_l0_verifying_key() -> bytes | None:
    """The KBS L0 Ed25519 public key vali verifies host-attestor certs
    against, or `None` when it is not configured.

    SEAM: vali does not universally hold the KBS L0 pubkey today (it
    relays other L0-signed artifacts to tenants for offline
    re-verification rather than verifying them itself), so this defaults
    UNSET. When unset, an ingested cert can only be structurally decoded
    and is persisted `pending` — never `attested`. An operator wires the
    real key (staged in Vault/k8s) via `VALI_KBS_L0_VERIFYING_KEY` for
    certs to reach `attested`. A malformed value fail-closes to `None`
    (treated as unset) with a loud log — never a partial trust anchor.
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


def _host_beacon_skew_seconds() -> int:
    """±window, in seconds, a host beacon's `observed_at_unix` may differ
    from vali's clock. Default 300 s (mirrors the heartbeat skew)."""
    return int(getattr(settings, "VALI_HOST_ATTESTOR_SKEW_SECONDS", 300))


def _unix_to_dt(unix_seconds: int) -> datetime:
    """Convert a Unix-seconds field to an aware UTC datetime."""
    return datetime.fromtimestamp(unix_seconds, tz=UTC)


# ─── blackbox host-attestor single-use nonce authority (PR-10) ───────


def _host_attestor_nonce_ttl() -> int:
    """The minted-nonce TTL in seconds (default 300)."""
    return int(getattr(settings, "VALI_HOST_ATTESTOR_NONCE_TTL_S", 300))


def _require_issued_nonce() -> bool:
    """Whether cert-ingest REQUIRES a vali-issued single-use nonce
    (default OFF — the INERT / legacy informational-nonce path)."""
    return bool(getattr(settings, "VALI_HOST_ATTESTOR_REQUIRE_NONCE", False))


def mint_host_attestor_nonce(
    *, node_id: str, signer_pubkey: bytes
) -> tuple[bytes, datetime]:
    """Mint a fresh, single-use, freshness-bounded enrollment nonce bound
    to `{node_id, signer_pubkey}` (blackbox host-attestor PR-10).

    `node_id` is the Edge-stamped mTLS peer identity (never a body-declared
    one); `signer_pubkey` is the attestor key surfaced from the (hostile,
    Rust-decoded) challenge request. The nonce is a CSPRNG 32-byte draw,
    stored unspent with `expires_at = now + TTL`. Returns
    `(nonce_bytes, expires_at)`.

    SECURITY: vali is the SOLE authority — the guest never chooses this
    value. The returned nonce becomes the enrollment `REPORT_DATA[0..32]`;
    a cert carrying any other nonce (or the wrong node_id / pk) cannot spend
    it at ingest.
    """
    if len(signer_pubkey) != 32:
        raise IngestError(
            message="host-attestor challenge signer_pubkey must be 32 bytes",
            category="wire",
            http_status=400,
        )
    now = timezone.now()
    expires_at = now + timedelta(seconds=_host_attestor_nonce_ttl())
    nonce = secrets.token_bytes(32)
    HostAttestorNonce.objects.create(
        nonce=nonce,
        node_id=node_id,
        signer_pubkey=signer_pubkey,
        expires_at=expires_at,
    )
    log.info(
        "host-attestor nonce minted: node_id=%s… ttl=%ss",
        node_id[:16],
        _host_attestor_nonce_ttl(),
    )
    return nonce, expires_at


def issue_host_attestor_challenge(
    *, node_id: str, envelope: bytes
) -> tuple[bytes, datetime]:
    """Decode a `HostChallengeRequest` + mint a fresh single-use enrollment
    nonce bound to `{node_id, signer_pubkey}` (blackbox host-attestor
    PR-10). `node_id` is the Edge-stamped mTLS peer identity (never a
    body-declared one); the `signer_pubkey` is surfaced from the hostile
    request by the Rust validator. Returns `(nonce_bytes, expires_at)`.

    Raises `IngestError` on a malformed request / verifier failure —
    translating the verifier exceptions the same way the cert path does.
    """
    try:
        req = verifier.verify_host_challenge_request(envelope=envelope)
    except verifier.VerifierUnavailable as exc:
        log.error("host-attestor challenge verifier unavailable: %s", exc)
        raise IngestError(
            message="host-attestor challenge verifier is unavailable",
            category="internal",
            http_status=503,
        ) from exc
    except verifier.VerifierFailed as exc:
        log.info("host-attestor challenge rejected: category=%s", exc.category)
        raise IngestError(
            message=f"host-attestor challenge request invalid ({exc.category})",
            category="verify-failed",
            http_status=400,
        ) from exc

    try:
        signer_pubkey = bytes.fromhex(req.signer_pubkey_hex)
    except ValueError as exc:  # Guarded by the Rust binary — defence in depth.
        raise IngestError(
            message="host-attestor challenge signer_pubkey is not hex",
            category="verify-failed",
            http_status=400,
        ) from exc

    return mint_host_attestor_nonce(node_id=node_id, signer_pubkey=signer_pubkey)


def _spend_host_attestor_nonce(
    *, nonce: bytes, node_id: str, signer_pubkey: bytes, now: datetime
) -> bool:
    """Atomically claim a vali-issued nonce bound to `{node_id,
    signer_pubkey}` that is unspent AND unexpired — single-use, no TOCTOU.

    A single conditional `UPDATE … WHERE spent_at IS NULL AND expires_at >
    now` claims the row; the DB guarantees exactly one of N concurrent
    ingests wins (the others update 0 rows). Returns True iff this call
    claimed it. Binding to `{node_id, signer_pubkey}` means a nonce cannot
    be redirected to another host / key.
    """
    claimed = HostAttestorNonce.objects.filter(
        nonce=nonce,
        node_id=node_id,
        signer_pubkey=signer_pubkey,
        spent_at__isnull=True,
        expires_at__gt=now,
    ).update(spent_at=now)
    return claimed == 1


def ingest_host_attestor_cert(*, envelope: bytes) -> tuple[HostAttestor, bool]:
    """Verify + persist one KBS-minted `SignedHostAttestorCert` (PR-8).

    Fail-closed gate order: verify/decode (KBS L0 signature IFF the key is
    configured) → cert-not-expired → i64-range → attribution status
    (`attested` iff the L0 signature verified AND `node_id` is on-chain
    Active; else `pending`) → upsert `HostAttestor` keyed by the
    AMD-signed `chip_id`. Raises `IngestError` on any refusal.

    SECURITY: every persisted trust field is the enrollment-pinned value
    the KBS attested (chip_id / measurement / node_id / attestor_pubkey),
    never a self-declared beacon copy. Returns `(row, created)`.
    """
    kbs_l0 = _kbs_l0_verifying_key()
    try:
        cert = verifier.verify_host_attestor_cert(
            envelope=envelope, verifying_key=kbs_l0
        )
    except verifier.VerifierUnavailable as exc:
        log.error("host-attestor cert verifier unavailable: %s", exc)
        raise IngestError(
            message="host-attestor cert verifier is unavailable",
            category="internal",
            http_status=503,
        ) from exc
    except verifier.VerifierFailed as exc:
        log.info("host-attestor cert rejected: category=%s", exc.category)
        raise IngestError(
            message=f"host-attestor cert verification failed ({exc.category})",
            category="verify-failed",
            http_status=400,
        ) from exc

    now = timezone.now()

    # Cert-not-expired gate — an already-expired cert is refused outright.
    if cert.expiry_unix <= int(now.timestamp()):
        raise IngestError(
            message="host-attestor cert is expired",
            category="cert-expired",
            http_status=400,
        )
    # Postgres BIGINT is signed (i64) — reject a `tcb` past i64::MAX so
    # the write cannot raise an unhandled DataError/500.
    if cert.tcb > _I64_MAX:
        raise IngestError(
            message="host-attestor cert tcb exceeds the storable range",
            category="tcb-out-of-range",
            http_status=400,
        )
    try:
        signer_pubkey = bytes.fromhex(cert.attestor_pubkey_hex)
    except ValueError as exc:  # Guarded by the Rust binary — defence in depth.
        raise IngestError(
            message="host-attestor cert attestor_pubkey is not hex",
            category="verify-failed",
            http_status=400,
        ) from exc

    # Attribution status. `attested` requires BOTH the KBS L0 signature to
    # have verified AND the cert's `node_id` to be registered + Active
    # on-chain — reuse the same on-chain-Active mechanism the miner
    # heartbeat autoprovision path gates on (never trust a self-declared
    # node_id). Otherwise the row is `pending`.
    #
    # SEAM (PR-12): the on-chain read exposes `node_id` + status but NOT
    # the registered CHIP_ID, so vali cannot yet enforce
    # `cert.chip_id == on-chain CHIP_ID for node_id`. The cert already
    # binds chip↔node cryptographically (the KBS recomputed `node_id`
    # into the report's REPORT_DATA and surfaced `chip_id` from the SAME
    # AMD-signed report), so the residual gap is only the on-chain
    # registry cross-check — deferred to PR-12's chip↔node reg-equality.
    node_active = _node_id_is_onchain_active(cert.node_id)
    status = (
        HostAttestorStatus.ATTESTED.value
        if (cert.verified and node_active)
        else HostAttestorStatus.PENDING.value
    )

    with transaction.atomic():
        # SECURITY (PR-10) — single-use nonce gate. When armed, the cert's
        # nonce MUST match a vali-issued, unspent, unexpired nonce bound to
        # this {node_id, attestor_pubkey}; claim it atomically (single-use,
        # no TOCTOU). Inside the txn so a later failure rolls the spend
        # back. DEFAULT-OFF: absent the flag this is the legacy path where
        # the nonce is stored informationally (see the model doc).
        if _require_issued_nonce():
            try:
                nonce_bytes = bytes.fromhex(cert.nonce_hex)
            except ValueError as exc:
                raise IngestError(
                    message="host-attestor cert nonce is not hex",
                    category="nonce-invalid",
                    http_status=400,
                ) from exc
            if len(nonce_bytes) != 32 or not _spend_host_attestor_nonce(
                nonce=nonce_bytes,
                node_id=cert.node_id,
                signer_pubkey=signer_pubkey,
                now=now,
            ):
                # Not issued by vali, already spent, expired, or bound to a
                # different host/key — the enrollment is refused fail-closed.
                raise IngestError(
                    message=(
                        "host-attestor cert nonce is not a vali-issued, "
                        "unspent, unexpired nonce for this host/key"
                    ),
                    category="nonce-invalid",
                    http_status=400,
                )
        row = _lock_host_attestor_by_chip(cert.chip_id_hex)
        created = row is None
        if row is None:
            row = HostAttestor(chip_id=cert.chip_id_hex)
        else:
            # A re-enrollment that rotates the derived key (new boot →
            # new pk) resets the per-`(node_id, boot_id)` monotonic beacon
            # counter so the new boot's `seq=1` is accepted.
            if bytes(row.signer_pubkey) != signer_pubkey:
                row.last_seq = None
                row.last_seen_at = None
                row.boot_id = ""
        row.node_id = cert.node_id
        row.signer_pubkey = signer_pubkey
        row.measurement = cert.measurement_hex
        row.tcb = cert.tcb
        row.cert_nonce = cert.nonce_hex
        row.cert_expiry_at = _unix_to_dt(cert.expiry_unix)
        row.status = status
        row.enrolled_at = now
        row.save()

    log.info(
        "host-attestor cert ingested: chip_id=%s… node_id=%s status=%s verified=%s",
        cert.chip_id_hex[:16],
        cert.node_id,
        status,
        cert.verified,
    )
    return row, created


def ingest_host_beacon(*, node_id: str, envelope: bytes) -> HostAttestor:
    """Verify + apply one `SignedHostBeacon` (PR-8).

    `node_id` is resolved by the view from the Edge-stamped mTLS peer
    identity (NOT the opaque beacon body). Fail-closed gate order:
    resolve the enrolled `HostAttestor` → cert-not-expired → signature
    verify against the CERTIFIED `signer_pubkey` (never the beacon's
    self-declared key) → peer/body `node_id` bind → cert `chip_id` bind
    (credit the enrollment-pinned chip, never the beacon's copy) →
    beacon-not-expired → i64-range → atomic monotonic `seq`. Raises
    `IngestError` on any refusal.

    A beacon only ever refreshes liveness (`last_seen_at` / `last_seq` +
    the informational `boot_id`); it never mints a row, rotates the key,
    or changes the attributed identity. Returns the updated row.
    """
    row = HostAttestor.objects.filter(node_id=node_id).first()
    if row is None:
        raise IngestError(
            message="no enrolled host-attestor for this node",
            category="host-not-enrolled",
            http_status=404,
        )

    now = timezone.now()
    if row.cert_expiry_at <= now:
        # The enrollment cert has lapsed — mark the row EXPIRED and refuse
        # the beacon (a fresh cert must re-enroll first).
        if row.status != HostAttestorStatus.EXPIRED.value:
            row.status = HostAttestorStatus.EXPIRED.value
            row.save(update_fields=["status", "updated_at"])
        raise IngestError(
            message="host-attestor enrollment cert is expired",
            category="cert-expired",
            http_status=400,
        )

    try:
        beacon = verifier.verify_host_beacon(
            envelope=envelope, verifying_key=bytes(row.signer_pubkey)
        )
    except verifier.VerifierUnavailable as exc:
        log.error("host-beacon verifier unavailable: %s", exc)
        raise IngestError(
            message="host-beacon verifier is unavailable",
            category="internal",
            http_status=503,
        ) from exc
    except verifier.VerifierFailed as exc:
        log.info("host-beacon rejected: node_id=%s category=%s", node_id, exc.category)
        raise IngestError(
            message=f"host-beacon verification failed ({exc.category})",
            category="verify-failed",
            http_status=400,
        ) from exc

    # Defence in depth: the peer-selected node AND the signed body must
    # name the SAME host (mirrors the vm-progress peer-vs-body bind).
    if beacon.node_id != row.node_id:
        raise IngestError(
            message="host-beacon body node_id does not match the peer",
            category="node-mismatch",
            http_status=400,
        )
    # Credit the ENROLLMENT-PINNED chip, never the beacon's self-declared
    # copy — a beacon claiming a different chip is refused.
    if beacon.chip_id_hex != row.chip_id:
        raise IngestError(
            message="host-beacon chip_id does not match the enrolled cert",
            category="chip-mismatch",
            http_status=400,
        )
    if beacon.expiry_unix <= int(now.timestamp()):
        raise IngestError(
            message="host-beacon is expired",
            category="beacon-expired",
            http_status=400,
        )
    if beacon.seq > _I64_MAX:
        raise IngestError(
            message="host-beacon seq exceeds the storable range",
            category="seq-out-of-range",
            http_status=400,
        )

    # Atomic monotonic `seq` under a row lock so two concurrent beacons
    # from one host cannot both pass a lost-update replay.
    with transaction.atomic():
        locked = _lock_host_attestor_by_chip(row.chip_id)
        if locked is None:  # Deregistered mid-flight.
            raise IngestError(
                message="host-attestor row vanished",
                category="host-not-enrolled",
                http_status=404,
            )
        # Re-baseline the monotonic gate on a genuine host restart. The
        # attestor's beacon `seq` restarts at 1 every boot, but the SNP
        # derived key — and thus the certified `signer_pubkey` — is
        # reboot-stable (same chip + measurement + TCB ⇒ same key, R1). So
        # the cert-ingest key-rotation reset never fires across a reboot,
        # and the monotonic gate below would reject the WHOLE new boot until
        # its `seq` climbed back past the pre-restart high-water-mark — a
        # dark (un-attested) window as long as the prior uptime. A CHANGED
        # `boot_id` on a beacon that has already passed the Ed25519 check
        # against the certified key (above) is an authentic new boot: only
        # the measured guest holds the key, and a stale cross-boot beacon is
        # independently dropped by the `beacon-expired` gate — so `boot_id`
        # is safe to use HERE as a re-baseline trigger (it remains untrusted
        # for identity/attribution). Re-seed rather than reject.
        new_boot = locked.boot_id != beacon.boot_id
        if (
            not new_boot
            and locked.last_seq is not None
            and beacon.seq <= locked.last_seq
        ):
            raise IngestError(
                message="host-beacon seq is a replay or regression",
                category="seq-replay",
                http_status=400,
            )
        locked.last_seq = beacon.seq
        locked.last_seen_at = now
        # A re-baseline trigger for the monotonic `seq` gate on a reboot
        # (see above); still NOT an SNP-attested identity input.
        locked.boot_id = beacon.boot_id
        locked.save(update_fields=["last_seq", "last_seen_at", "boot_id", "updated_at"])
        row = locked

    log.info(
        "host-beacon accepted: node_id=%s chip_id=%s… seq=%d",
        node_id,
        row.chip_id[:16],
        beacon.seq,
    )
    return row


def _lock_host_attestor_by_chip(chip_id: str) -> HostAttestor | None:
    """Re-fetch a `HostAttestor` `FOR UPDATE` so the monotonic-`seq` and
    the cert-upsert read-modify-writes are race-free. Skips the lock on a
    backend without row locks (SQLite, used in tests — it serializes
    writers at the DB level regardless)."""
    qs = HostAttestor.objects.filter(chip_id=chip_id)
    if connection.features.has_select_for_update:
        qs = qs.select_for_update()
    return qs.first()


def _lock_source(source: str, source_id: str) -> TelemetrySource | None:
    """Re-fetch a `TelemetrySource` `FOR UPDATE` so the poison-counter
    read-modify-write is race-free.

    Concurrent bad ingests from one source must not lose increments
    (a lost increment lets a poisoned source evade quarantine — the
    §9 control). The row is locked for the duration of the enclosing
    `transaction.atomic()`. On a backend without row locks (SQLite,
    used in tests) the lock is skipped — SQLite serializes writers at
    the database level regardless, so the RMW is still atomic.
    """
    qs = TelemetrySource.objects.filter(source=source, source_id=source_id)
    if connection.features.has_select_for_update:
        qs = qs.select_for_update()
    return qs.first()


def _lock_miner(miner_id: str):
    """Re-fetch a `MinerIdentity` `FOR UPDATE` so the heartbeat
    monotonic-`sequence` read-modify-write is race-free.

    Two concurrent heartbeats from one miner must serialize on this
    lock — otherwise both could read the same `last_heartbeat_sequence`
    and a lost update would let a replayed `sequence` through. The row
    is locked for the enclosing `transaction.atomic()`. On a backend
    without row locks (SQLite, used in tests) the lock is skipped —
    SQLite serializes writers at the database level regardless.

    The import is local so the telemetry app carries no import-time
    dependency on `apps.miners` (mirrors `_touch_miner_last_seen`).
    """
    from apps.miners.models import MinerIdentity

    qs = MinerIdentity.objects.filter(miner_id=miner_id)
    if connection.features.has_select_for_update:
        qs = qs.select_for_update()
    return qs.first()


def _record_failure(source: str, source_id: str, now) -> None:
    """Count a §9 poison strike. Consecutive verification failures
    inside a rolling window quarantine the source; a stale window
    resets to a fresh count of 1.

    The whole read-modify-write runs under a row lock so concurrent
    failing ingests cannot lose an increment.
    """
    window = timedelta(seconds=_quarantine_window())
    with transaction.atomic():
        src = _lock_source(source, source_id)
        if src is None:  # Deregistered mid-flight — nothing to poison.
            return

        if (
            src.failure_window_started_at is None
            or now - src.failure_window_started_at > window
        ):
            src.failure_window_started_at = now
            src.consecutive_failures = 1
        else:
            src.consecutive_failures += 1

        if src.consecutive_failures >= _quarantine_threshold():
            src.quarantined_until = now + timedelta(seconds=_quarantine_ttl())
            # The source is no longer trusted — pull its still-queued
            # Pending envelopes out of the deliverable queue.
            reclassified = TelemetryEnvelope.objects.filter(
                source=src.source,
                source_id=src.source_id,
                processing_status=ProcessingStatus.PENDING.value,
            ).update(
                processing_status=ProcessingStatus.QUARANTINED.value,
                processed_at=now,
            )
            log.warning(
                "§9 telemetry source quarantined: source=%s:%s until=%s "
                "(%d queued envelopes reclassified)",
                src.source,
                src.source_id,
                src.quarantined_until.isoformat(),
                reclassified,
            )
        src.save(
            update_fields=[
                "consecutive_failures",
                "failure_window_started_at",
                "quarantined_until",
                "updated_at",
            ]
        )


def _record_success(source: str, source_id: str) -> None:
    """A verification success resets the consecutive-failure counter
    (§9 "3x **consécutifs**" — a good envelope breaks the run).

    Runs under the same row lock as `_record_failure` so a success
    racing a failure cannot have its reset silently clobbered.
    """
    with transaction.atomic():
        src = _lock_source(source, source_id)
        if src is None:
            return
        if src.consecutive_failures or src.failure_window_started_at is not None:
            src.consecutive_failures = 0
            src.failure_window_started_at = None
            src.save(
                update_fields=[
                    "consecutive_failures",
                    "failure_window_started_at",
                    "updated_at",
                ]
            )


def _touch_miner_last_seen(source: str, source_id: str, now) -> None:
    """Refresh `MinerIdentity.last_seen_at` when a verified envelope
    from a registered miner is ingested.

    Best-effort and isolated: a single PK-indexed `UPDATE`, a no-op
    when `source` is not `miner` or `source_id` is not a registered
    miner. The import is lazy so the telemetry app carries no
    import-time dependency on `apps.miners`.
    """
    if source != SourceType.MINER.value:
        return
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.filter(miner_id=source_id).update(last_seen_at=now)


def _advance_tenant_vm_boot_progress(
    source: str, source_id: str, kind: str, now
) -> None:
    """Advance a tenant VM's display-only `boot_phase` to `running` when a
    `served_receipt` is accepted+verified for it, and self-heal its
    NetBird overlay IP.

    A guest that is fully up produces `served_receipt` uptime-billing
    envelopes; the `running` milestone (defined in `VmBootPhase`) is
    otherwise never emitted. Resolves the `Vm` by `vm_id == source_id`;
    a missing row is benign (skipped). The advance is monotonic +
    idempotent via `Vm.advance_boot_phase` — a no-op once already
    `running`, and it never regresses a higher phase (a late
    `kek_released` milestone cannot pull `running` back). Only writes
    `boot_phase` / `boot_phase_at` / `updated_at` (the exact
    `vm-progress` view pattern) — it NEVER touches lifecycle state or the
    optimistic-concurrency `version`.

    While the VM's `netbird_ip` is still empty it ALSO opportunistically
    resolves the tenant's NetBird overlay IP and caches it on the row —
    retried on each receipt within a bounded post-launch window
    (`_NETBIRD_RESOLVE_WINDOW`) until resolved, then stopped, so `GET
    /state` reads make no outbound NetBird call and a netbird-disabled /
    never-enrolling VM does not probe the NetBird API forever. A NetBird
    API failure is swallowed (fail-open, logged) and never breaks receipt
    ingest. NB: `ingest` runs synchronously in the inbound HTTP handler,
    so the (bounded, post-commit) resolve adds latency only to the
    served_receipt POST response, never to billing.

    A no-op for any non-`tenant_vm` / non-`served_receipt` envelope, and
    display-only end-to-end: any error here is swallowed. The imports are
    lazy so the telemetry app carries no import-time dependency on
    `apps.lifecycle` / `apps.orchestration` (mirrors
    `_touch_miner_last_seen`).
    """
    if (
        source != SourceType.TENANT_VM.value
        or kind != EnvelopeKind.SERVED_RECEIPT.value
    ):
        return
    # In-guest LIVENESS watermark. Distinct from `boot_phase`, which is
    # monotonic and therefore permanently `running` once reached: this
    # value goes STALE, which is what lets the control plane tell a
    # booted-and-alive guest from one wedged in its initramfs behind a
    # still-`running` libvirt domain. Recorded FIRST and independently of
    # the (best-effort) boot-progress/NetBird work below, so a failure
    # there can never cost us the liveness beat. Never raises. Lazy
    # import — the same discipline the boot-progress block below uses (no
    # import-time telemetry→lifecycle dependency).
    from apps.lifecycle import guest_liveness

    guest_liveness.record_signal(
        source_id, guest_liveness.SIGNAL_SERVED_RECEIPT, at=now
    )
    try:
        from apps.lifecycle.models import Vm

        vm = Vm.objects.filter(vm_id=source_id).first()
        if vm is None:
            return
        if vm.advance_boot_phase("running"):
            vm.boot_phase_at = now
            vm.save(update_fields=["boot_phase", "boot_phase_at", "updated_at"])
            log.info(
                "served-receipt advanced boot_phase to running: vm_id=%s",
                vm.vm_id,
            )
        # Self-heal the NetBird overlay IP: resolve once, then stop. BOUNDED
        # to a window after launch — a netbird guest enrols within ~1-2 min of
        # boot, so if it hasn't resolved within the window the VM is netbird-
        # disabled or failed to enrol, and must NOT trigger a NetBird API call
        # on every subsequent served receipt (~1/min) forever on the
        # synchronous ingest path.
        if not vm.netbird_ip and (now - vm.created_at) < _NETBIRD_RESOLVE_WINDOW:
            _resolve_tenant_netbird_ip(vm)
    except Exception:  # noqa: BLE001 — display-only, never break ingest.
        log.warning(
            "boot-progress hook failed for served_receipt source_id=%s",
            source_id,
            exc_info=True,
        )


def _resolve_tenant_netbird_ip(vm) -> None:
    """Resolve + persist the tenant VM's NetBird overlay IP if found.

    A NetBird API failure (`EffectError` / `EffectUnavailable`) — or any
    other error — is swallowed with a warning: the IP resolves on a later
    receipt once the peer enrols (self-healing). The token stays a §20
    secret (the effect never logs it). Import is lazy to avoid a
    telemetry↔orchestration import cycle at module load.
    """
    from apps.orchestration import effects

    try:
        ip = effects.resolve_netbird_peer_ip(vm.vm_id)
    except effects.EffectError as exc:
        log.warning(
            "netbird ip resolve unavailable for vm_id=%s: %s", vm.vm_id, exc
        )
        return
    # Only while still empty: the orchestration tick's refresh
    # (`netbird_binding.refresh_overlay_ips`) may have written a newer
    # address while this call was out.
    if ip and type(vm).objects.filter(pk=vm.pk, netbird_ip="").update(netbird_ip=ip):
        vm.netbird_ip = ip
        log.info("resolved netbird ip for vm_id=%s", vm.vm_id)


# ─── pull ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PullResult:
    """A page of drained envelopes + the cursor the caller advances to."""

    envelopes: list[TelemetryEnvelope]
    next_since: int


def pull(*, kind: str, since: int, limit: int) -> PullResult:
    """Drain up to `limit` `Pending` envelopes of `kind` with
    `envelope_id > since`, oldest first.

    Concurrent-pull safe: each pull mints a unique `pull_token` and
    claims its batch with a single CAS-style `UPDATE … WHERE
    processing_status = pending`. Two pulls racing the same range
    each flip only the rows still `Pending`; `WHERE pull_token = T`
    then returns exactly the rows THIS pull won — never a double
    delivery, with no row locks (works on SQLite + Postgres).
    """
    candidate_ids = list(
        TelemetryEnvelope.objects.filter(
            kind=kind,
            processing_status=ProcessingStatus.PENDING.value,
            envelope_id__gt=since,
        )
        .order_by("envelope_id")
        .values_list("envelope_id", flat=True)[:limit]
    )
    if not candidate_ids:
        return PullResult(envelopes=[], next_since=since)

    token = secrets.token_hex(16)
    now = timezone.now()
    TelemetryEnvelope.objects.filter(
        envelope_id__in=candidate_ids,
        processing_status=ProcessingStatus.PENDING.value,
    ).update(
        processing_status=ProcessingStatus.DONE.value,
        processed_at=now,
        pull_token=token,
    )
    claimed = list(
        TelemetryEnvelope.objects.filter(pull_token=token).order_by("envelope_id")
    )
    next_since = claimed[-1].envelope_id if claimed else since
    log.info(
        "telemetry pull: kind=%s since=%d claimed=%d next_since=%d",
        kind,
        since,
        len(claimed),
        next_since,
    )
    return PullResult(envelopes=claimed, next_since=next_since)


# ─── garbage collection ──────────────────────────────────────────────


def gc(now=None) -> int:
    """Delete terminal envelopes (`Done` / `Failed` / `Quarantined`)
    older than `VALI_TELEMETRY_GC_AGE_DAYS`. Returns the count
    deleted. `Pending` envelopes are never GC'd.
    """
    now = now or timezone.now()
    cutoff = now - timedelta(days=_gc_age_days())
    deleted, _ = (
        TelemetryEnvelope.objects.filter(
            processing_status__in=[
                ProcessingStatus.DONE.value,
                ProcessingStatus.FAILED.value,
                ProcessingStatus.QUARANTINED.value,
            ],
            received_at__lt=cutoff,
        ).delete()
    )
    if deleted:
        log.info("telemetry gc: deleted %d terminal envelopes", deleted)

    # Reap host-attestor enrollment nonces that can never be claimed again:
    # spent (the atomic consume already committed) or past their TTL. Both
    # are permanently unclaimable, so removing them is safe; a short grace
    # keeps a brief audit trail and avoids racing an in-flight spend tx.
    nonce_cutoff = now - timedelta(seconds=_nonce_gc_grace_s())
    nonces_deleted, _ = HostAttestorNonce.objects.filter(
        Q(spent_at__lt=nonce_cutoff) | Q(expires_at__lt=nonce_cutoff)
    ).delete()
    if nonces_deleted:
        log.info("telemetry gc: reaped %d host-attestor nonces", nonces_deleted)

    return deleted + nonces_deleted
