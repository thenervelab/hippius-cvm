"""Doc-only serializers for the lifecycle OpenAPI schema (§24/§25 VM state
machine + attestation). Referenced from `@extend_schema` in `views.py` only
— never wired into request handling. Fields mirror the `_serialize_vm`
helper, `_parse_request` (transition body) and each view's hand-built
`Response` dict.
"""

from __future__ import annotations

from rest_framework import serializers

from apps.network.schemas import VmPublicIpSummarySerializer


class GuardianWaitSerializer(serializers.Serializer):
    boot = serializers.ChoiceField(choices=["awaiting-guardian"])
    reason = serializers.CharField(
        help_text=(
            "Closed vocabulary: `unreachable`, `timeout`, `bad-response`, or "
            "`refused:<reason>` (`awaiting-approval`, `release-not-pinned`, "
            "`measurement-mismatch`, `policy`, `tcb`, `chip-not-approved`, "
            "`mode-mismatch`, `unknown-vm`, `erased`, …)."
        )
    )
    since = serializers.DateTimeField(allow_null=True, help_text="When this wait began.")
    last_report_at = serializers.DateTimeField(help_text="The newest report of it.")
    terminal = serializers.BooleanField(
        help_text="`refused:erased`: the key was erased, the data is unrecoverable."
    )


class VmSerializer(serializers.Serializer):
    """A `Vm` row as rendered by `_serialize_vm`.

    `eol_nonce` is OMITTED on purpose — only the guest ever sees it, via
    the measured EOL command channel, and only once.
    """

    vm_id = serializers.CharField()
    tenant_id = serializers.CharField()
    lease_id = serializers.CharField()
    state = serializers.CharField(
        help_text="active | migrating | decommissioning | destroyed."
    )
    generation = serializers.IntegerField(help_text="Current §25 generation.")
    new_generation = serializers.IntegerField(
        allow_null=True, help_text="Target generation while Migrating (else null)."
    )
    host = serializers.CharField(allow_blank=True, help_text="Current placement host.")
    region = serializers.CharField(
        allow_null=True,
        help_text=(
            "ISO 3166-1 alpha-2 country the VM runs in: its host's DETECTED and "
            "verified location (see GET /v1/operator/regions). Null when the host "
            "has no fresh verified location, or the VM is not placed."
        ),
    )
    public_ip = VmPublicIpSummarySerializer(
        allow_null=True,
        help_text=(
            "The public IPv4 attached to the VM (see /v1/vm/{vm_id}/public-ip): the "
            "address, the ingress edge serving it and that edge's region. Null when none."
        ),
    )
    backup_state = serializers.ChoiceField(
        choices=["disabled", "pending", "ok", "stale"],
        help_text=(
            "Live backups (see /v1/vm/{vm_id}/backups): `disabled` (no policy), "
            "`pending` (no backup completed yet), `ok` (a restorable backup no older "
            "than the interval plus two hours), `stale` (none restorable — e.g. since "
            "the last reboot — or the newest is too old)."
        ),
    )
    migration_dest = serializers.CharField(
        allow_blank=True, help_text="Destination host while Migrating (else empty)."
    )
    version = serializers.IntegerField(help_text="Optimistic-concurrency version.")
    boot_phase = serializers.CharField(
        allow_blank=True,
        help_text=(
            "Guest-boot progress mirror (miner-agent → Edge → vali): "
            "booting | kek_released | running, or empty before the first "
            "signed milestone. Advances monotonically; DISPLAY-only."
        ),
    )
    boot_phase_at = serializers.DateTimeField(
        allow_null=True, help_text="When `boot_phase` was last advanced (else null)."
    )
    boot_stalled = serializers.BooleanField(
        help_text=(
            "True when the VM is active and running on a host but NO "
            "in-guest signal (served receipt or live attestation) has "
            "arrived since its current boot began (`boot_started_at`) for "
            "longer than its deadline: 900 s + 15 s per GiB of the flavor's "
            "data disk (capped at 3 h), which covers the golden first-boot "
            "disk format. The guest never came up (e.g. its ticket was never "
            "delivered, or it hung after its KEK release). Applies to first "
            "launches, relaunches and §25 activations; `boot_phase` plays no "
            "part. When true, `guest_liveness` reads `wedged`. Consumers "
            "should show the VM as FAILED/WEDGED, never as running. False "
            "positive: an image baked without the telemetry agent."
        )
    )
    boot_started_at = serializers.DateTimeField(
        allow_null=True,
        help_text=(
            "When the VM's current boot began: its first launch, its last "
            "§25 activation, or its last relaunch (reboot-recovery or power "
            "start). Rows that predate the field report their creation "
            "time."
        ),
    )
    netbird_ip = serializers.CharField(
        allow_blank=True,
        help_text=(
            "Tenant NetBird overlay IP (`100.x.y.z`), resolved from the first "
            "served receipt after enrolment; empty until resolved. DISPLAY-"
            "only — the read path makes no outbound NetBird call. Carried "
            "across a §25 migration VERBATIM — read `netbird_status` to "
            "know whether it is still reachable."
        ),
    )
    netbird_status = serializers.CharField(
        allow_blank=True,
        help_text=(
            "Post-§25 overlay verdict: empty (nothing to verify) | pending "
            "| ok | lost. `lost` means the VM is running but OFF the "
            "NetBird overlay after a migration and cannot re-enrol itself "
            "— operator action is required."
        ),
    )
    guest_liveness = serializers.ChoiceField(
        choices=["alive", "wedged", "unknown"],
        help_text=(
            "Is there POSITIVE evidence from INSIDE the guest, recently? "
            "`alive` — an in-guest-originated signal (§23 served receipt or "
            "§322 live attestation) landed within the staleness bound. "
            "`wedged` — this VM HAS emitted before but has gone silent, OR "
            "its current boot has produced no signal past its deadline "
            "(`boot_stalled`): the "
            "guest is hung (e.g. stuck in its initramfs after a refused KEK "
            "release) even though `state=active` and `boot_phase=running`, "
            "because the libvirt domain is still up and `boot_phase` is "
            "monotonic. `unknown` — NEVER emitted a signal (no telemetry "
            "agent in the image, or still on its first boot); NOT a "
            "statement that the VM is dead."
        ),
    )
    key_mode = serializers.ChoiceField(
        choices=["hippius", "split", "customer"],
        help_text=(
            "Who holds the disk key, pinned at launch: `hippius` (M0), `split` "
            "(M1 — Hippius and the customer's key guardian each hold a share) or "
            "`customer` (M2 — the customer's guardian alone)."
        ),
    )
    guardian_wait = GuardianWaitSerializer(
        allow_null=True,
        help_text=(
            "An M1/M2 guest waiting in its initramfs on the customer's key "
            "guardian, or null. DISPLAY-only: the miner reports it and can forge "
            "or suppress it; the guardian's own audit log is the truth."
        ),
    )
    data_death = serializers.ChoiceField(
        choices=["crypto-erased", "customer-erase-required"],
        allow_null=True,
        help_text=(
            "What §24 decommission achieved for the data, once its erase step "
            "ran (else null): `crypto-erased` — Hippius destroyed the key the "
            "disk needs; `customer-erase-required` — an M2 VM, whose disk key "
            "Hippius never held: its stored copies are deleted, and only the "
            "customer's `guardian erase <vm>` makes the data cryptographically "
            "unrecoverable."
        ),
    )
    guest_signal_at = serializers.DateTimeField(
        allow_null=True,
        help_text=(
            "Wall-clock of the newest in-guest signal, or null when the VM "
            "has never emitted one."
        ),
    )
    guest_signal_age_s = serializers.IntegerField(
        allow_null=True,
        help_text="Seconds since `guest_signal_at` (floored at 0), or null.",
    )
    guest_signal_kind = serializers.CharField(
        allow_blank=True,
        help_text="served_receipt | live_attestation, or empty when never.",
    )
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()


class VmListSerializer(serializers.Serializer):
    """`GET /v1/vm` paginated response."""

    vms = VmSerializer(many=True)
    limit = serializers.IntegerField()
    offset = serializers.IntegerField()
    total = serializers.IntegerField()


class VmTransitionRequestSerializer(serializers.Serializer):
    """`POST /v1/vm/<vm_id>/transition` body — mirrors `_parse_request` /
    `TransitionRequest`. Strict JSON: unknown / wrongly-typed fields are a
    `wire` error at parse time.
    """

    to_state = serializers.ChoiceField(
        choices=["active", "migrating", "decommissioning", "destroyed"],
        help_text="Target state — must form a legal source→target pair.",
    )
    if_version = serializers.IntegerField(
        min_value=1,
        help_text=(
            "Optimistic-concurrency guard: the row is updated only WHERE "
            "version == if_version (stale ⇒ 409). Must be ≥ 1."
        ),
    )
    new_generation = serializers.IntegerField(
        required=False,
        allow_null=True,
        min_value=0,
        help_text=(
            "Required for Active→Migrating (must be > current generation) and "
            "for Migrating→Active (must equal the row's stored new_generation). "
            "u64 on the wire; bounded to i64 max at intake."
        ),
    )
    migration_dest = serializers.CharField(
        required=False,
        allow_null=True,
        help_text="Destination host — required for the Active→Migrating target.",
    )
    signed_stopped_ack_hex = serializers.CharField(
        required=False,
        allow_null=True,
        help_text=(
            "Hex-encoded guest-signed StoppedAck CBOR. Required for the two "
            "ack-gated transitions (Decommissioning→Destroyed, "
            "Migrating→Active); shelled out to the Rust `verify-stopped-ack`."
        ),
    )


class VmTransitionConflictSerializer(serializers.Serializer):
    """409 body when `if_version` is stale — carries the winning row so the
    caller can re-read without a second request.
    """

    error = serializers.CharField()
    category = serializers.CharField(help_text="Always `version-conflict`.")
    current = VmSerializer(allow_null=True, help_text="The winning row (or null).")


class _VmAttestationLifecycleSerializer(serializers.Serializer):
    """The `lifecycle` sub-object of the attestation response."""

    state = serializers.CharField()
    generation = serializers.IntegerField()
    host = serializers.CharField(allow_null=True)
    lifecycle_vk_hex = serializers.CharField(
        allow_null=True, help_text="Guest lifecycle verify-key (hex) or null."
    )


class _VmAttestationErrorSerializer(serializers.Serializer):
    """The `kbs_evidence_error` sub-object (present when the KBS fetch failed)."""

    reason = serializers.CharField(help_text="`kbs-unavailable` | `kbs-error`.")
    detail = serializers.CharField()


class _VmLiveAttestationSerializer(serializers.Serializer):
    """The `live_attestation` sub-object: one `VmLiveAttestation` row — a
    keepalive SNP report the KBS verified and signed, whose signature vali
    verified against the pinned KBS L0 key before storing it — by the guest
    the KBS released the disk key to, of the current launch, on the VM's
    current host."""

    verified_at_unix = serializers.IntegerField(help_text="When the KBS verified the report.")
    expiry_unix = serializers.IntegerField(help_text="The signed body's hard expiry.")
    age_s = serializers.IntegerField()
    fresh = serializers.BooleanField(
        help_text="`age_s <= max_age_s` and not past `expiry_unix`."
    )
    max_age_s = serializers.IntegerField()
    measurement_hex = serializers.CharField(help_text="The allowlisted launch measurement.")
    attestation_seq = serializers.IntegerField()
    chain_epoch = serializers.IntegerField()
    binding_source = serializers.CharField(
        help_text=(
            "`release`, or `first-use` (a KBS restart wiped the binding) from "
            "the same guest a `release` sample named."
        )
    )
    chip_id_hex = serializers.CharField()
    report_id_hex = serializers.CharField(help_text="SNP REPORT_ID of the guest.")
    node_id_hex = serializers.CharField()
    snp_report_digest_hex = serializers.CharField(help_text="SHA-256 of the raw SNP report.")
    body_digest_hex = serializers.CharField(help_text="SHA-256 of the KBS-signed body.")


class VmAttestationSerializer(serializers.Serializer):
    """`GET /v1/vm/<vm_id>/attestation` response.

    Composes vali's lifecycle facts with the KBS-signed evidence bundle
    (fetched from the KBS `#280` evidence endpoint) so a tenant can
    re-verify the SNP report offline. `kbs_evidence` is the opaque signed
    bundle (measurement, snp_report_hex, vcek_chain_pem, boot_counter,
    kbs_signature_hex, …) relayed verbatim — null if the fetch failed.
    """

    vm_id = serializers.CharField()
    tenant_id = serializers.CharField(allow_null=True)
    user_id = serializers.CharField(allow_null=True)
    attested = serializers.BooleanField(
        allow_null=True,
        help_text=(
            "True when the VM is proven attested — `attestation_state` is "
            "`attested-live` or `attested-at-boot`. NULL otherwise: absent "
            "proof does NOT mean the VM is unattested. Never false."
        ),
    )
    attestation_status = serializers.ChoiceField(
        choices=[
            "evidence-recorded",
            "no-evidence-recorded",
            "evidence-unavailable",
        ],
        help_text=(
            "Legacy three-value form of `attestation_state`, kept for existing "
            "consumers: `evidence-recorded` (proven — `attested-live` or "
            "`attested-at-boot`), `no-evidence-recorded` (unknown — `stale` or "
            "`unproven`), `evidence-unavailable` (`unavailable` — see "
            "`kbs_evidence_error`)."
        ),
    )
    attestation_state = serializers.ChoiceField(
        # `apps.lifecycle.attestation.AttestationState` (pinned by a test).
        choices=["attested-live", "attested-at-boot", "stale", "unavailable", "unproven"],
        help_text=(
            "`attested-live` — the VM is meant to be running and `live_attestation` "
            "is fresh: the guest the KBS released to is running the current "
            "launch on the current host now. `attested-at-boot` — no fresh live "
            "sample, but the KBS holds the signed release bundle of the current "
            "launch (`kbs_evidence`). `unavailable` — no live proof and the KBS "
            "could not be asked (`kbs_evidence_error`). `stale` — the current "
            "launch attested live before but not within the window, and the KBS "
            "holds no bundle. `unproven` — nothing on record for the current "
            "launch (NOT a negative verdict)."
        ),
    )
    live_attestation = _VmLiveAttestationSerializer(
        allow_null=True,
        help_text=(
            "The newest KBS-verified live attestation of the current launch, or "
            "null. Survives a KBS restart, unlike `kbs_evidence`."
        ),
    )
    lifecycle = _VmAttestationLifecycleSerializer()
    platform_id = serializers.CharField(
        allow_null=True, help_text="Attested AMD chip_id the ticket pins the VM to."
    )
    kbs_evidence = serializers.JSONField(
        allow_null=True, help_text="KBS-signed attestation bundle, or null."
    )
    kbs_evidence_error = _VmAttestationErrorSerializer(
        allow_null=True, help_text="Populated when the KBS fetch failed (else null)."
    )


class StoppedAckAcceptedSerializer(serializers.Serializer):
    """`POST /v1/lifecycle/stopped` 202 acknowledgement (opaque store)."""

    ok = serializers.BooleanField()
    vm_id = serializers.CharField()
    generation = serializers.IntegerField()
