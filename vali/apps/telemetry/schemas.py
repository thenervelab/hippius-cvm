"""Doc-only serializers for the §9 telemetry OpenAPI schema.

Referenced from `@extend_schema` in `views.py` only — NEVER wired into
request handling (every view keeps its own manual `request.data` /
`request.body` parsing). Fields mirror the JSON-wrapper ingest body
(`TelemetryIngestView._ingest_json` + the `_require_*` helpers), the
shared `_ingested_response` / `_serialize_envelope` helpers, and the
graceful-exit `Response`.

The raw-CBOR ingress shapes (§K heartbeat, graceful-exit) carry an
opaque `application/cbor` body — those are documented as
`OpenApiTypes.BINARY`, not a JSON serializer.
"""

from __future__ import annotations

from rest_framework import serializers

from apps.miners.models import SnpGeneration

from .models import EnvelopeKind, SourceType


class TelemetryIngestRequestSerializer(serializers.Serializer):
    """`POST /v1/telemetry/ingest` JSON-wrapper body.

    The direct-source (`application/json`) ingress. `body_hex` /
    `sig_hex` are hex strings vali hex-decodes and pipes to the Rust
    verifier — vali never decodes the CBOR body itself. The raw-CBOR §K
    heartbeat ingress uses the SAME URL but an `application/cbor` body
    (documented separately as binary).
    """

    schema_version = serializers.IntegerField(
        help_text="Broker wire-format version (must be a KNOWN_SCHEMA_VERSIONS value)."
    )
    source = serializers.ChoiceField(
        choices=SourceType.values, help_text="Originating source plane."
    )
    source_id = serializers.CharField(
        max_length=256,
        help_text="Opaque registry key (peer id / vm_id / miner_id); never an address.",
    )
    kind = serializers.ChoiceField(
        choices=EnvelopeKind.values,
        help_text=(
            "Telemetry kind (selects the verifier subcommand). `heartbeat` is "
            "rejected here — it must be posted as raw application/cbor."
        ),
    )
    body_hex = serializers.CharField(
        help_text="Hex of the signed canonical-CBOR telemetry body."
    )
    sig_hex = serializers.CharField(
        help_text="Hex of the 64-byte detached Ed25519 signature over the body."
    )


class TelemetryIngestResponseSerializer(serializers.Serializer):
    """Shared ingest response (`_ingested_response`) — 202 on a newly
    created envelope, 200 on an idempotent re-ingest of an existing row.
    """

    envelope_id = serializers.IntegerField(help_text="Monotonic envelope cursor id.")
    processing_status = serializers.ChoiceField(
        choices=["pending", "quarantined", "done", "failed"],
        help_text="Envelope lifecycle status.",
    )
    created = serializers.BooleanField(
        help_text="True on first ingest (202); False on idempotent re-ingest (200)."
    )


class TelemetryEnvelopeSerializer(serializers.Serializer):
    """One drained envelope in the pull response (`_serialize_envelope`).

    `payload_cbor_hex` / `signature_hex` are hex-encoded signed telemetry
    the consumer may re-verify — never write them to a log line.
    """

    envelope_id = serializers.IntegerField()
    source = serializers.CharField()
    source_id = serializers.CharField()
    kind = serializers.CharField()
    schema_version = serializers.IntegerField()
    payload_cbor_hex = serializers.CharField(help_text="Hex of the signed CBOR body.")
    signature_hex = serializers.CharField(help_text="Hex of the Ed25519 signature.")
    received_at = serializers.DateTimeField()
    processing_status = serializers.CharField()


class TelemetryPullResponseSerializer(serializers.Serializer):
    """`GET /v1/telemetry/pull` response — a claimed batch + the next
    durable cursor the caller keeps on its side.
    """

    envelopes = TelemetryEnvelopeSerializer(many=True)
    count = serializers.IntegerField(help_text="Number of envelopes in this batch.")
    next_since = serializers.IntegerField(
        help_text="Cursor to pass as `since` on the next pull."
    )


class GracefulExitResponseSerializer(serializers.Serializer):
    """`POST /v1/telemetry/graceful-exit` 200 body — the miner was
    quarantined on an accepted, signature-verified request.
    """

    miner_id = serializers.CharField()
    status = serializers.CharField(help_text="Resulting miner status (`quarantined`).")
    accepted = serializers.BooleanField()


class VmProgressResponseSerializer(serializers.Serializer):
    """`POST /v1/telemetry/vm-progress` 200 body — the guest-boot
    milestone was accepted (signature + identity + skew verified).

    Fail-open display semantics: an accepted milestone for a VM whose
    `Vm` row is not queryable yet still returns 200 with `tracked=False`
    and an empty `boot_phase` (never a hard 404).
    """

    ok = serializers.BooleanField()
    vm_id = serializers.CharField()
    boot_phase = serializers.CharField(
        allow_blank=True,
        help_text="Recorded boot phase (booting | kek_released | running), or empty.",
    )
    tracked = serializers.BooleanField(
        help_text="False when no `Vm` row exists yet (benign fail-open)."
    )
    advanced = serializers.BooleanField(
        help_text="True when this milestone advanced the recorded phase."
    )


class HostAttestorCertResponseSerializer(serializers.Serializer):
    """`POST /v1/telemetry/host-attestor/cert` 200 body — the enrollment
    cert was verified/decoded and the `HostAttestor` row upserted."""

    chip_id = serializers.CharField(help_text="AMD-signed platform CHIP_ID (hex).")
    node_id = serializers.CharField(help_text="Enrollment-pinned host node id.")
    status = serializers.ChoiceField(
        choices=["pending", "attested", "expired"],
        help_text="attested iff KBS-L0-verified AND node on-chain Active; else pending.",
    )
    created = serializers.BooleanField(
        help_text="True when a new HostAttestor row was created (vs an upsert)."
    )


class HostBeaconResponseSerializer(serializers.Serializer):
    """`POST /v1/telemetry/host-attestor/heartbeat` 200 body — the beacon
    verified against the certified key and refreshed liveness."""

    chip_id = serializers.CharField(help_text="Enrollment-pinned CHIP_ID (hex).")
    node_id = serializers.CharField()
    status = serializers.CharField(help_text="Current HostAttestor status.")
    last_seq = serializers.IntegerField(help_text="The accepted monotonic beacon seq.")


class HostAttestorChallengeResponseSerializer(serializers.Serializer):
    """`POST /v1/telemetry/host-attestor/challenge` 200 body (blackbox
    host-attestor PR-10) — the fresh, single-use, vali-minted enrollment
    nonce bound to `{node_id, signer_pubkey}`. The miner-agent translates
    it into the guest's canonical-CBOR `HostChallengeResponse`."""

    nonce_hex = serializers.CharField(
        help_text="The vali-minted single-use enrollment nonce (hex, 32 bytes)."
    )
    node_id = serializers.CharField(
        help_text=(
            "The host node_id vali stamped from the miner's mTLS peer "
            "identity (PR-10b-S2a). The guest folds it into its enrollment "
            "node_id + REPORT_DATA binding — it can't read it from the "
            "measured cmdline. The nonce is bound to this node_id."
        )
    )
    expiry_unix = serializers.IntegerField(
        help_text="Hard TTL of the nonce, Unix seconds."
    )


class HostAttestorReleaseRequestSerializer(serializers.Serializer):
    """`POST /v1/admin/host-attestor/release` body (blackbox host-attestor
    PR-9). The CI-signed blackbox UKI + its keyless cosign bundle.

    `artifact_b64` is the base64 of the signed UKI blob (rides the request
    body — no vali-side URL fetch, no SSRF); `cosign_signature_b64` /
    `cosign_certificate_pem` are the detached signature + Fulcio cert PR-6
    emits. `measurement_hex` is the SNP launch measurement CI pinned
    alongside the artifact (what gets class-pinned into the §22 allowlist).
    """

    measurement_hex = serializers.CharField(
        max_length=96,
        help_text="SNP launch measurement to class-pin (96 hex / 48 bytes).",
    )
    version = serializers.CharField(
        max_length=64, help_text="Release version label (opaque)."
    )
    generation = serializers.ChoiceField(
        choices=SnpGeneration.values,
        help_text=(
            "SEV-SNP CPU generation the measurement is for (the VMSA carries "
            "the vCPU CPUID signature, so one UKI measures differently per "
            "generation). Selects the per-generation {current, previous} "
            "grace window. Required."
        ),
    )
    artifact_b64 = serializers.CharField(
        help_text="Base64 of the cosign-signed blackbox UKI blob."
    )
    cosign_signature_b64 = serializers.CharField(
        help_text="Base64 detached cosign signature (from cosign sign-blob)."
    )
    cosign_certificate_pem = serializers.CharField(
        help_text="Fulcio certificate PEM (from cosign sign-blob keyless)."
    )
    rekor_log_index = serializers.IntegerField(
        required=False,
        help_text="Optional Rekor transparency-log index recorded as provenance.",
    )


class HostAttestorReleaseResponseSerializer(serializers.Serializer):
    """`POST /v1/admin/host-attestor/release` body — the admitted release
    (201 created / 200 re-admitted) after cosign verify + class pin."""

    measurement = serializers.CharField(help_text="The class-pinned measurement (hex).")
    version = serializers.CharField(allow_blank=True)
    generation = serializers.CharField(help_text="SEV-SNP generation of the release.")
    is_active = serializers.BooleanField(help_text="True — the new desired release.")
    allowlist_epoch = serializers.IntegerField(
        help_text="The §22 epoch the host-attestor-class pin landed at."
    )
    cosign_identity = serializers.CharField(help_text="Verified cosign SAN identity.")
    cosign_issuer = serializers.CharField(help_text="Verified cosign OIDC issuer.")
    created = serializers.BooleanField(
        help_text="True on a new measurement; False re-admitting an existing one."
    )


class _HostAttestorReleaseView(serializers.Serializer):
    """One release in the desired grace-window response."""

    measurement = serializers.CharField()
    version = serializers.CharField(allow_blank=True)
    generation = serializers.CharField(
        allow_blank=True, help_text='SEV-SNP generation ("" = legacy untagged).'
    )
    cosign_identity = serializers.CharField()
    created_at = serializers.DateTimeField()


class HostAttestorDesiredResponseSerializer(serializers.Serializer):
    """`GET /v1/miner/<node_id>/host-attestor/desired` body — the {current,
    previous} grace window a miner boots its host attestor onto, for the
    miner's SEV-SNP generation. Both null before the operator has admitted
    any release."""

    generation = serializers.CharField(
        allow_blank=True,
        help_text=(
            'The generation whose window is served ("" = legacy untagged '
            "window: the node's generation is unresolved or has no release)."
        ),
    )
    current = _HostAttestorReleaseView(allow_null=True)
    previous = _HostAttestorReleaseView(allow_null=True)


class VmLiveAttestationResponseSerializer(serializers.Serializer):
    """`POST /v1/telemetry/vm-liveness` 200 body — the KBS-L0-signed
    tenant-CVM live attestation was verified and recorded as uptime
    coverage (or recognised as a replay)."""

    vm_id = serializers.CharField(help_text="The CVM the SNP report was bound to.")
    attestation_seq = serializers.IntegerField(
        help_text="KBS's per-VM monotonic attestation counter."
    )
    verified_at_unix = serializers.IntegerField(
        help_text="The liveness instant the coverage meter integrates over."
    )
    recorded = serializers.BooleanField(
        help_text=(
            "True when this attestation was newly recorded. False = a replay "
            "of an already-recorded attestation; coverage is UNCHANGED."
        )
    )
