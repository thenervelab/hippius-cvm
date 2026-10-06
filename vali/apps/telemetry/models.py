"""§9 pull-only telemetry broker models.

Spec of record: ARCHITECTURE.md §9 (diode telemetry — bounded
queues, backpressure, poison-message quarantine, dedupe, schema
versioning + validation).

The broker is **pull-only**: telemetry sources `POST` to
`/v1/telemetry/ingest`; internal consumers (sentinel, the scheduler
re-eval, …) `GET /v1/telemetry/pull` to drain. The broker NEVER
calls back out to a source — there is no field here, and no code
path anywhere in the app, that turns a `source_id` into an outbound
address (no SSRF surface).

Two models:

- `TelemetrySource` — the **trusted key registry** + per-source
  poison-quarantine state. A source must be registered (its Ed25519
  verifying key recorded out-of-band) before its telemetry is
  accepted: the verifying key is NEVER taken from the (untrusted)
  envelope itself.
- `TelemetryEnvelope` — one ingested, signature-verified telemetry
  envelope, queued for pull. `envelope_id` is a monotonic integer —
  the durable pagination cursor consumers page on.
"""

from __future__ import annotations

import uuid

from django.db import models

from apps.miners.models import SnpGeneration

# The broker wire-format versions this build understands. An ingest
# carrying any other `schema_version` is rejected fail-closed (§9
# "schema versioning + validation"). Forward-compatible migration:
# a future broker adds the new version here and keeps the old one
# until every source has upgraded.
KNOWN_SCHEMA_VERSIONS: frozenset[int] = frozenset({1})


class SourceType(models.TextChoices):
    """Where a telemetry envelope originated. Pinned strings.

    `miner` (PR-vali-miner-register) is a miner-signed source: its
    `TelemetrySource` is provisioned by registering a `MinerIdentity`
    (`apps.miners`), and `source_id` is that registry's `miner_id`. It
    is a distinct trust plane from `tenant_vm` — a tenant-signed
    `served_receipt` is verified against a tenant key, never a miner's.
    """

    TENANT_VM = "tenant_vm", "Tenant VM"
    AUDIT_VM = "audit_vm", "Audit VM"
    EDGE_GATEWAY = "edge_gateway", "Edge gateway"
    MINER = "miner", "Miner"
    # Blackbox host-attestor (blackbox host-attestor chantier PR-8). A
    # measured SNP guest running ON the bare-metal host (outside every
    # tenant CVM) that signs liveness beacons with a key the KBS L0
    # enrollment cert pinned to the physical CHIP_ID. Distinct trust
    # plane: a host-attestor beacon is verified against the CERTIFIED
    # `signer_pubkey` (see `HostAttestor`), never a tenant / miner key.
    HOST_ATTESTOR = "host_attestor", "Host attestor"


class EnvelopeKind(models.TextChoices):
    """The telemetry payload kind — selects the verifier subcommand.

    `edge_telemetry` → `verify-edge-telemetry`; `served_receipt` →
    `verify-served-receipt`; `heartbeat` → `verify-heartbeat`. An
    unknown kind is rejected fail-closed.

    `heartbeat` (§K / PR-Part4-B) is distinct: it is a miner-signed
    `SignedMinerHeartbeat` ingested as raw `application/cbor` (not the
    JSON wrapper the other kinds use), and its verifier subcommand is
    **data-bearing** — it returns the decoded `{timestamp_unix,
    sequence, miner_id, …}` the ingest gate needs for the ±300 s skew
    and monotonic-`sequence` replay checks.
    """

    EDGE_TELEMETRY = "edge_telemetry", "Edge telemetry envelope"
    SERVED_RECEIPT = "served_receipt", "Tenant served-delivery receipt"
    HEARTBEAT = "heartbeat", "Miner heartbeat"


class ProcessingStatus(models.TextChoices):
    """`TelemetryEnvelope` lifecycle.

    - `Pending`     — verified + queued; counts toward backpressure;
                      drainable by a pull.
    - `Done`        — drained by a consumer pull.
    - `Failed`      — signature / schema verification failed at
                      ingest; retained for forensics.
    - `Quarantined` — was `Pending` when its source crossed the
                      poison-quarantine threshold; pulled out of the
                      deliverable queue (the source is no longer
                      trusted), retained for forensics.

    `Done` / `Failed` / `Quarantined` are terminal and garbage-
    collected after `VALI_TELEMETRY_GC_AGE_DAYS`.
    """

    PENDING = "pending", "Pending"
    QUARANTINED = "quarantined", "Quarantined"
    DONE = "done", "Done"
    FAILED = "failed", "Failed"


# Terminal (non-deliverable) statuses — the GC sweep target, and
# what the dedupe partial-unique excludes-by-being-Failed logic and
# the pull query treat as "not Pending".
TERMINAL_STATUSES: frozenset[str] = frozenset(
    {
        ProcessingStatus.DONE.value,
        ProcessingStatus.FAILED.value,
        ProcessingStatus.QUARANTINED.value,
    }
)


class TelemetrySource(models.Model):
    """A registered telemetry source — its trusted verifying key plus
    its rolling poison-quarantine state.

    Field-by-field:

    - `source` / `source_id` — the source identity (`(source,
      source_id)` is unique). `source_id` is opaque data: a peer id,
      a `vm_id`, a node id. It is a registry key only — never used
      to build an address.
    - `verifying_key`   — the source's 32-byte Ed25519 public key.
      The trust anchor: every envelope is verified against THIS key,
      registered out-of-band, never read from the envelope.
    - `is_active`       — a disabled source's telemetry is refused
      without deleting its row.
    - `consecutive_failures` / `failure_window_started_at` — the §9
      poison counter: consecutive verification failures inside a
      rolling `VALI_TELEMETRY_QUARANTINE_WINDOW_S` window. A
      verification success resets it.
    - `quarantined_until` — set when the counter crosses
      `VALI_TELEMETRY_QUARANTINE_THRESHOLD`; while it is in the
      future, every ingest from this source is refused (429).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.CharField(max_length=32, choices=SourceType.choices)
    source_id = models.CharField(max_length=256)
    # 32-byte Ed25519 public key. BinaryField keeps it byte-exact.
    verifying_key = models.BinaryField(max_length=32)
    is_active = models.BooleanField(default=True)
    consecutive_failures = models.PositiveIntegerField(default=0)
    failure_window_started_at = models.DateTimeField(null=True, blank=True)
    quarantined_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["source", "source_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["source", "source_id"],
                name="telemetry_source_unique",
            ),
        ]

    def __str__(self) -> str:
        return f"TelemetrySource {self.source}:{self.source_id}"


class TelemetryEnvelope(models.Model):
    """One ingested telemetry envelope.

    `envelope_id` is a `BigAutoField` — a strictly-increasing
    integer. Consumers page the pull endpoint on it
    (`?since=<envelope_id>`) and keep that cursor durably on their
    own side; the broker never needs to track per-consumer delivery.

    Field-by-field:

    - `source` / `source_id` / `kind` — envelope routing metadata.
    - `schema_version`  — the broker wire-format version; an unknown
      value was already rejected at ingest.
    - `payload_cbor`    — the signed canonical-CBOR telemetry body.
      NEVER logged (§20 — it is signed content, not a secret, but
      logging payload bytes is still forbidden discipline).
    - `signature`       — the detached Ed25519 signature over
      `payload_cbor` (empty only on a `Failed` row that never
      decomposed cleanly).
    - `dedupe_digest`   — SHA-256 hex binding
      `(source, source_id, kind, schema_version, payload_cbor)` for a
      verified envelope (`""` for `Failed`). A partial unique index
      makes a re-ingest of an identical valid envelope idempotent;
      scoping the digest by source keeps two distinct sources that
      emit byte-identical bodies as separate rows.
    - `processing_status` — see `ProcessingStatus`.
    - `received_at`     — ingest wall-clock.
    - `processed_at`    — set when drained by a pull (or reclassified
      `Quarantined`).
    - `pull_token`      — per-pull claim token; how a pull atomically
      claims a batch so two concurrent pulls never double-deliver.

    Indexes: `(processing_status, received_at)` serves the
    backpressure count + the GC sweep; `(kind, processing_status)`
    serves the pull query (`envelope_id` is the PK, already ordered).
    """

    envelope_id = models.BigAutoField(primary_key=True)
    source = models.CharField(max_length=32, choices=SourceType.choices)
    source_id = models.CharField(max_length=256, db_index=True)
    kind = models.CharField(max_length=32, choices=EnvelopeKind.choices)
    schema_version = models.PositiveIntegerField()
    payload_cbor = models.BinaryField()
    signature = models.BinaryField(blank=True, default=b"")
    dedupe_digest = models.CharField(max_length=64, blank=True, default="")
    processing_status = models.CharField(
        max_length=32,
        choices=ProcessingStatus.choices,
        default=ProcessingStatus.PENDING,
    )
    received_at = models.DateTimeField(auto_now_add=True, db_index=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    pull_token = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        ordering = ["envelope_id"]
        indexes = [
            models.Index(fields=["processing_status", "received_at"]),
            models.Index(fields=["kind", "processing_status"]),
        ]
        constraints = [
            # Re-ingest of an identical VERIFIED envelope (same
            # source + body) is idempotent. `Failed` rows carry an
            # empty digest and are excluded — a hostile source
            # re-sending the same bad blob still gets each attempt
            # counted.
            models.UniqueConstraint(
                fields=["dedupe_digest"],
                condition=~models.Q(dedupe_digest=""),
                name="telemetry_envelope_dedupe",
            ),
        ]

    def __str__(self) -> str:
        return (
            f"TelemetryEnvelope {self.envelope_id} "
            f"({self.kind} from {self.source}:{self.source_id}, "
            f"{self.processing_status})"
        )


# ─── blackbox host-attestor (PR-8, INERT) ────────────────────────────
#
# The blackbox host-attestor chantier gives vali the data model + ingest
# to RECEIVE, verify, and persist host-attestor enrollment certs +
# liveness beacons. Ships INERT: nothing reads these rows for reward or
# dispatchability yet (that arms in PR-9/PR-11). Verified rows just
# accumulate.


class HostAttestorStatus(models.TextChoices):
    """`HostAttestor` lifecycle.

    - `Pending`   — a cert was ingested but the FULL trust chain is not
                    established yet: either the KBS L0 signature could not
                    be checked (vali does not hold the KBS L0 pubkey — see
                    `service.ingest_host_attestor_cert`) OR the claimed
                    `node_id` is not registered + Active on-chain. The
                    row's `signer_pubkey` is therefore NOT trusted.
    - `Attested`  — the KBS L0 signature over the cert verified AND the
                    `node_id` is on-chain Active. The certified
                    `signer_pubkey` is a trust anchor for this host's
                    beacons.
    - `Expired`   — the cert's `cert_expiry_at` has passed.
    """

    PENDING = "pending", "Pending"
    ATTESTED = "attested", "Attested"
    EXPIRED = "expired", "Expired"


class HostAttestor(models.Model):
    """The verified per-host-attestor state — one row per physical host.

    Keyed by `chip_id` (the AMD-signed platform `CHIP_ID`, the stable
    identity): a cert re-enrollment for the same host (new boot → new
    derived key) UPSERTS this row by `chip_id`, rotating `signer_pubkey`.

    SECURITY — attribution binding (blackbox host-attestor must-have #2):
    every trust-bearing field here is the **enrollment-pinned value from
    the KBS L0 cert** (`chip_id`, `measurement`, `node_id`,
    `signer_pubkey`), NEVER a beacon's self-declared copy. A beacon is
    verified against THIS row's certified `signer_pubkey` and may only
    refresh `last_seen_at` / `last_seq` — it can never mint a row, rotate
    the key, or change the attributed identity.

    Field-by-field:

    - `chip_id`         — AMD-signed platform `CHIP_ID`, hex (64 bytes ⇒
      128 hex chars). The stable unique identity key.
    - `node_id`         — the host node identity the cert bound in its
      `REPORT_DATA` (matches the miner-agent `node_id`). Cross-checked
      against on-chain registration before a row reaches `attested`.
    - `signer_pubkey`   — the certified attestor Ed25519 public key (32
      bytes). The trust anchor every beacon is verified against.
    - `measurement`     — the platform launch measurement the KBS
      allowlisted (host-attestor class), hex (48 bytes ⇒ 96 hex chars).
    - `tcb`             — the platform `reported_tcb` (comparable integer)
      from the verified report.
    - `cert_nonce`      — the single-use nonce the cert bound, hex.
      Informational (PR-10 owns nonce freshness).
    - `cert_expiry_at`  — hard cert expiry; a beacon past it is refused.
    - `status`          — see `HostAttestorStatus`.
    - `last_seq`        — the last accepted beacon `seq` (monotonic replay
      gate). `seq` is per-`(node_id, boot)` and restarts at 1 every boot,
      while the reboot-stable derived key keeps `signer_pubkey` constant —
      so the gate is re-baselined when the beacon's `boot_id` changes (an
      authentic new boot; safe because the beacon is key-verified and stale
      cross-boot beacons are dropped by the expiry gate), and also reset to
      NULL when a re-enrollment rotates `signer_pubkey`.
    - `last_seen_at`    — wall-clock of the last accepted beacon.
    - `boot_id`         — the beacon's self-declared per-boot id. NOT
      SNP-attested (per the PR-1 review note) — never an identity /
      attribution input; used ONLY as the monotonic-`seq` re-baseline
      trigger on a reboot (guarded by the beacon signature + expiry gates).
    - `enrolled_at`     — wall-clock of the last accepted cert ingest.
    - `first_seen_at`   — wall-clock of the first cert ingest for this
      chip.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    chip_id = models.CharField(max_length=128, unique=True)
    node_id = models.CharField(max_length=256, db_index=True)
    # 32-byte certified attestor Ed25519 key. BinaryField keeps it
    # byte-exact (mirrors `TelemetrySource.verifying_key`).
    signer_pubkey = models.BinaryField(max_length=32)
    measurement = models.CharField(max_length=96)
    tcb = models.BigIntegerField(default=0)
    cert_nonce = models.CharField(max_length=64, blank=True, default="")
    cert_expiry_at = models.DateTimeField()
    status = models.CharField(
        max_length=16,
        choices=HostAttestorStatus.choices,
        default=HostAttestorStatus.PENDING,
    )
    last_seq = models.BigIntegerField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    # NOT SNP-attested — informational only (PR-1 review note).
    boot_id = models.CharField(max_length=256, blank=True, default="")
    enrolled_at = models.DateTimeField(null=True, blank=True)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["node_id", "chip_id"]
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["node_id"]),
        ]

    def __str__(self) -> str:
        return f"HostAttestor {self.chip_id[:16]}… ({self.node_id}, {self.status})"


class HostAttestorNonce(models.Model):
    """A vali-minted, single-use, freshness-bounded host-attestor
    **enrollment nonce** (blackbox host-attestor chantier PR-10).

    SECURITY — anti-pre-generation replay (blackbox host-attestor must-have
    #3): `REPORT_DATA[0..32]` of a host-attestor enrollment report MUST be
    a vali-chosen nonce, never a guest-generated value. Otherwise a guest
    could pre-generate a valid enrollment report while attested and replay
    it later from a paused / migrated / rehosted VM.

    Lifecycle:

    - **mint** — `service.mint_host_attestor_nonce` draws a CSPRNG 32-byte
      `nonce`, binds it to `{node_id, signer_pubkey}` (the node_id is the
      Edge-stamped mTLS identity, never a body-declared one), and stores it
      unspent with `expires_at = now + VALI_HOST_ATTESTOR_NONCE_TTL_S`.
    - **spend** — at cert-ingest (behind `VALI_HOST_ATTESTOR_REQUIRE_NONCE`)
      a single conditional `UPDATE … WHERE spent_at IS NULL AND expires_at >
      now` claims it; exactly one concurrent ingest can win (single-use, no
      TOCTOU). A row past `expires_at` is rejected even if unspent.

    Field-by-field:

    - `nonce`          — the minted single-use nonce (32 bytes). Unique —
      a CSPRNG collision is astronomically unlikely, and uniqueness makes
      the spend claim a clean single-row update.
    - `node_id`        — the host node identity the nonce is bound to (hex,
      the Edge-stamped mTLS peer identity at mint time).
    - `signer_pubkey`  — the attestor Ed25519 public key the nonce is bound
      to (32 bytes). A cert carrying a different pk cannot spend this nonce.
    - `expires_at`     — hard TTL; a nonce past it is rejected.
    - `spent_at`       — NULL until claimed; set to the wall-clock of the
      accepting cert-ingest. Non-NULL ⇒ already used (single-use).
    - `issued_at`      — wall-clock of the mint.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # 32-byte nonce. BinaryField keeps it byte-exact.
    nonce = models.BinaryField(max_length=32, unique=True)
    node_id = models.CharField(max_length=256, db_index=True)
    # 32-byte attestor Ed25519 key the nonce is bound to.
    signer_pubkey = models.BinaryField(max_length=32)
    expires_at = models.DateTimeField()
    spent_at = models.DateTimeField(null=True, blank=True)
    issued_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-issued_at"]
        indexes = [
            models.Index(fields=["expires_at"]),
            models.Index(fields=["node_id"]),
        ]

    def __str__(self) -> str:
        state = "spent" if self.spent_at is not None else "unspent"
        return f"HostAttestorNonce {self.node_id} ({state})"


class HostAttestorRelease(models.Model):
    """A desired/allowed host-attestor measurement release.

    The append-only registry of measurements the operator (PR-9's
    cosign-verified `POST /v1/admin/host-attestor/release`) has approved
    for the fleet — the desired image a miner polls + relaunches onto.
    Modelled now so the ingest can reference it read-only, but **PR-9
    populates it**: nothing in PR-8 writes an `active` row, and the
    host-attestor measurement is OPERATOR/CI-pinned, NEVER auto-pinned
    from a miner report (closes the C2 warn-mode measurement bleed —
    blackbox host-attestor must-have #1).

    - `measurement`      — the SNP launch measurement, hex (48 bytes ⇒ 96
      hex chars). Unique.
    - `version`          — the release version label (opaque).
    - `cosign_issuer` / `cosign_identity` / `cosign_rekor_log_index` —
      the keyless-cosign provenance PR-9 records when it admits a release.
    - `is_active`        — whether this release is the current desired
      measurement. Defaults `False` — a release is inert until the
      operator flow flips it (PR-9).
    - `generation`       — the SEV-SNP CPU generation (`SnpGeneration`:
      `genoa` | `turin` | `milan`) this measurement is FOR. The launch
      measurement covers the VMSA, which carries the vCPU model's CPUID
      signature, so the SAME blackbox UKI measures differently per
      generation — the {current, previous} grace window is therefore kept
      PER GENERATION (`release_service.desired_releases(generation)`).
      "" = legacy/untagged: those rows form their own group, so a table
      with no tagged row behaves exactly as the old single fleet-wide
      window.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    measurement = models.CharField(max_length=96, unique=True)
    version = models.CharField(max_length=64, blank=True, default="")
    cosign_issuer = models.CharField(max_length=256, blank=True, default="")
    cosign_identity = models.CharField(max_length=256, blank=True, default="")
    cosign_rekor_log_index = models.BigIntegerField(null=True, blank=True)
    is_active = models.BooleanField(default=False)
    generation = models.CharField(
        max_length=8,
        choices=SnpGeneration.choices,
        blank=True,
        default="",
        # DB-side default too: a pod still on the previous image INSERTs
        # without this column during a rollout, and must not hit NOT NULL.
        db_default="",
        help_text=(
            "SEV-SNP CPU generation this measurement is for (the VMSA carries "
            "the vCPU CPUID signature, so one UKI measures differently per "
            "generation). The {current, previous} grace window is kept per "
            "generation. Empty = legacy/untagged group."
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["is_active"]),
        ]

    def __str__(self) -> str:
        return (
            f"HostAttestorRelease {self.measurement[:16]}… "
            f"({self.generation or 'untagged'}, active={self.is_active})"
        )


# ─── tenant-CVM live attestation (§23 uptime-coverage meter) ─────────


class VmLiveAttestation(models.Model):
    """One KBS-L0-signed proof that a tenant CVM was ALIVE at an instant.

    This is the answer to the one hole left in uptime billing. A
    `ServedDeliveryReceipt` is signed by the guest telemetry key, which
    is HKDF-derived from the §7 lifecycle key and therefore readable by
    ROOT INSIDE THE CVM. A miner can legitimately launch a tenant VM on
    its own node, read that key, KILL the VM, and keep signing
    well-formed receipts forever from anywhere — nothing in a receipt
    requires the VM to still exist. Possession of the key IS the
    signature.

    A `LiveAttestation` cannot be produced that way. The KBS mints one
    only after it has verified a fresh `SNP_GET_REPORT` — VCEK → ASK →
    ARK against AMD's silicon root, `measurement ∈ §22 allowlist`,
    launch-policy bounds — whose `REPORT_DATA` binds a SINGLE-USE
    KBS-issued nonce to this `vm_id`. That report can only come out of
    `/dev/sev-guest` inside a RUNNING SEV-SNP guest running the measured
    image. An extracted software key does not help; a dead VM cannot
    answer at all.

    Each row is therefore a timestamped liveness sample. The uptime
    meter (`apps.scheduler.usage`) credits a receipt window ONLY for the
    part of it covered by these samples — see
    `apps.telemetry.vm_liveness.covered_seconds`.

    Field-by-field (every one is a KBS-attested value off the signed
    body, never a self-declared relay copy):

    - `vm_id`                 the CVM the SNP report was bound to.
    - `node_id_hex`           the miner the KBS body credits.
    - `attestation_seq`       KBS's per-VM monotonic counter — monotonic
                              only WITHIN one KBS chain (see
                              `chain_epoch`), never across a KBS restart.
    - `prev_attestation_hash` the signed hash-chain back-pointer: SHA-256
                              of the previous body for this VM, or the
                              all-zero digest at a chain's genesis. This
                              is the field that tells a post-restart
                              attestation apart from a replay.
    - `chain_epoch`           vali-assigned lineage counter, resolved from
                              `prev_attestation_hash`. `0` for a VM's
                              first chain; +1 each time an attestation
                              fails to link to anything vali holds (a KBS
                              restart reseeded the chain, or a sample was
                              lost in transit). UNIQUE per
                              `(vm_id, chain_epoch, attestation_seq)`.
    - `epoch`                 the billing epoch KBS stamped.
    - `observed_at_unix`      when the guest took the report (KBS's view).
    - `verified_at_unix`      when KBS verified it — the LIVENESS INSTANT
                              the coverage meter integrates over.
    - `expiry_unix`           hard expiry; an expired body is refused at
                              ingest and can never become coverage.
    - `measurement`           the allowlisted launch measurement KBS
                              confirmed (hex).
    - `snp_report_digest`     SHA-256 of the raw SNP report (audit
                              cross-reference against the §280 evidence
                              bundle).
    - `body_digest`           SHA-256 of the signed canonical body — the
                              CONTENT IDENTITY of an attestation, and the
                              anti-replay gate. UNIQUE: re-POSTing a
                              captured attestation collides here and
                              extends no coverage, whatever its seq.

    ## Why `(vm_id, attestation_seq)` alone was WRONG (fixed 2026-08-13)

    That constraint encoded an assumption vali cannot verify and the KBS
    does not honour: that `attestation_seq` is unique per VM for the VM's
    whole life. `kbs_core::live_attestation::LiveAttestationStateStore`
    keeps the per-VM `(next_seq, prev_attestation_hash)` chain in the KBS
    CVM's state directory — an emptyDir inside a Kata CVM — so every KBS
    restart reseeds `LiveAttestationChain::genesis()` and the guest's next
    attestation arrives at seq 1 again.

    Live consequence, observed in production: rows existed at seq 1..43;
    two KBS restarts later the guest was at seq 11; every attestation
    collided with a row from the OLD chain and was logged as a replay at
    INFO. With the liveness gate armed the VM kept running and earned
    NOTHING for 3.7 h, and every component reported success.

    `body_digest` did not save us because it is the CONTENT identity and
    is correct: a post-restart attestation is a genuinely different body,
    so it collided on nothing there and fell through to the seq lookup.

    So the seq axis is now scoped to the lineage it is actually monotonic
    in — `(vm_id, chain_epoch, attestation_seq)` — and `chain_epoch` is
    resolved from the SIGNED `prev_attestation_hash`. Exactly as tight
    inside one KBS chain; correctly permissive across a reseed. The
    anti-replay property is unchanged and still carried by `body_digest`.

    Rows are append-only. `apps.scheduler.usage` reads them; nothing
    mutates them.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vm_id = models.CharField(max_length=128, db_index=True)
    node_id_hex = models.CharField(max_length=64)
    attestation_seq = models.BigIntegerField()
    epoch = models.BigIntegerField()
    observed_at_unix = models.BigIntegerField()
    verified_at_unix = models.BigIntegerField()
    expiry_unix = models.BigIntegerField()
    measurement = models.CharField(max_length=96)
    snp_report_digest = models.CharField(max_length=64)
    body_digest = models.CharField(max_length=64, unique=True)
    # The signed hash-chain back-pointer off the KBS body. Blank only on
    # rows written before this column existed (backfilled rows carry no
    # linkage, so they can only ever be a chain ANCESTOR, never a parent
    # a later attestation links to — which is the safe direction: an
    # unlinkable parent opens a new `chain_epoch` rather than dropping).
    prev_attestation_hash = models.CharField(max_length=64, blank=True, default="")
    # vali-assigned lineage counter — see the class docstring.
    chain_epoch = models.BigIntegerField(default=0)
    # The guest the KBS bound this `vm_id` to (schema v2 bodies; blank on
    # v1): `release` = recorded at the §20 release, `first-use` = no
    # release on record (e.g. after a KBS restart) — the guest that asked. Only `release` rows are
    # capacity proof (`capacity_earn`). `chip_id` was checked against the
    # node's registered platform at ingest. DB defaults so a pod on the
    # previous image can still INSERT during a rollout.
    binding_source = models.CharField(max_length=16, blank=True, default="", db_default="")
    chip_id = models.CharField(max_length=128, blank=True, default="", db_default="")
    report_id = models.CharField(max_length=64, blank=True, default="", db_default="")
    # What the guest attested it runs with (schema v3 bodies; NULL before)
    # and vali's verdict at ingest (`apps.telemetry.guest_resources`): `ok`,
    # `short` (less than the launch's flavor), `superseded` (a guest of an
    # earlier launch of this VM), `unattested` (the launch asked, the body
    # has none), blank (not asked). The last three but `ok` and blank are
    # not coverage once ENFORCE is armed. DB defaults so a pod on the
    # previous image can still INSERT during a rollout.
    vcpus_online = models.PositiveIntegerField(null=True, blank=True, default=None)
    mem_firmware_kib = models.BigIntegerField(null=True, blank=True, default=None)
    mem_total_kib = models.BigIntegerField(null=True, blank=True, default=None)
    mem_unaccepted_kib = models.BigIntegerField(null=True, blank=True, default=None)
    resource_verdict = models.CharField(max_length=16, blank=True, default="", db_default="")
    # Schema v4 only (NULL before): the guest components release the guest
    # attested it booted, its epoch, its agents' health bitmap, the
    # keepalive process's instance and that process's failing-tick count
    # (`apps.orchestration.guest_upgrade` judges them).
    components_release_version = models.BigIntegerField(null=True, blank=True, default=None)
    components_security_epoch = models.BigIntegerField(null=True, blank=True, default=None)
    components_health = models.BigIntegerField(null=True, blank=True, default=None)
    components_instance = models.BigIntegerField(null=True, blank=True, default=None)
    components_unhealthy_ticks = models.BigIntegerField(null=True, blank=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["vm_id", "verified_at_unix"]
        indexes = [
            models.Index(fields=["vm_id", "verified_at_unix"]),
            # The chain-resolution read path: "the newest lineage this VM
            # has" and "which row does this prev_attestation_hash name".
            models.Index(fields=["vm_id", "chain_epoch", "attestation_seq"]),
            # The guest report's T4 read: superseded samples, fleet-wide, by
            # time (`apps.orchestration.guest_report`). Partial: a handful
            # of rows out of the whole liveness stream.
            models.Index(
                fields=["verified_at_unix"],
                name="telemetry_vla_superseded_idx",
                condition=models.Q(resource_verdict="superseded"),
            ),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["vm_id", "chain_epoch", "attestation_seq"],
                name="telemetry_vm_live_attestation_unique_vm_chain_seq",
            ),
        ]

    def __str__(self) -> str:
        return (
            f"VmLiveAttestation vm={self.vm_id} seq={self.attestation_seq} "
            f"at={self.verified_at_unix}"
        )


class GuestResourceShortfall(models.Model):
    """Evidence that a miner runs a VM with less than its flavor — or runs
    a stale launch of it.

    SEV-SNP measures the vCPU count (one VMSA per vCPU) but not the RAM.
    The guest therefore attests what it was given — vCPUs online, the
    firmware map's `System RAM`, `MemTotal` — inside its live attestation
    (schema v3), bound into the PSP-signed `REPORT_DATA` the KBS verified.
    The relaying miner cannot change a value. A sample below the flavor is
    recorded here, one row per `(vm_id, node_id_hex, flavor)`, refreshed
    by every further short sample:

    - `first_seen_at` / `last_seen_at` / `samples` — how long and how
      often; a row whose `last_seen_at` is within
      `VALI_GUEST_RESOURCES_FLAG_S` marks the VM degraded for the operator
      (`/v1/operator/fleet`) and the synthetic monitor;
    - `want_*` — the flavor; `vcpus_online` / `mem_*_kib` — the last
      finding's attested figures (NULL for a `superseded-launch` finding
      on a body without resources); `reason` — which dimension, or
      `superseded-launch`;
    - `last_body_digest` — the `VmLiveAttestation` that proves it.

    What it is NOT: proof against the TENANT. Root inside the guest can
    request a report over any figures it likes, so a tenant could make
    its own VM look short (or, as the miner's accomplice, full). The
    penalty is scoped accordingly: that VM's uptime is not credited (with
    ENFORCE armed) and an operator looks at the row; nothing here excludes
    the miner from placement.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vm_id = models.CharField(max_length=128, db_index=True)
    node_id_hex = models.CharField(max_length=64, db_index=True)
    flavor = models.CharField(max_length=32)
    want_vcpus = models.PositiveIntegerField()
    want_memory_mb = models.PositiveIntegerField()
    vcpus_online = models.PositiveIntegerField(null=True, blank=True)
    mem_firmware_kib = models.BigIntegerField(null=True, blank=True)
    mem_total_kib = models.BigIntegerField(null=True, blank=True)
    mem_unaccepted_kib = models.BigIntegerField(null=True, blank=True)
    reason = models.CharField(max_length=64)
    samples = models.PositiveIntegerField(default=1)
    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField(db_index=True)
    last_body_digest = models.CharField(max_length=64)

    class Meta:
        ordering = ["-last_seen_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["vm_id", "node_id_hex", "flavor"],
                name="telemetry_guest_resource_shortfall_unique",
            ),
        ]

    def __str__(self) -> str:
        return (
            f"GuestResourceShortfall vm={self.vm_id} node={self.node_id_hex[:12]} "
            f"{self.flavor} ({self.reason})"
        )
