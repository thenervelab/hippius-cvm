"""Doc-only serializers for the lifecycle OpenAPI schema (§24/§25 VM state
machine + attestation). Referenced from `@extend_schema` in `views.py` only
— never wired into request handling. Fields mirror the `_serialize_vm`
helper, `_parse_request` (transition body) and each view's hand-built
`Response` dict.
"""

from __future__ import annotations

from rest_framework import serializers


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
            "`wedged` — this VM HAS emitted before but has gone silent: the "
            "guest is hung (e.g. stuck in its initramfs after a refused KEK "
            "release) even though `state=active` and `boot_phase=running`, "
            "because the libvirt domain is still up and `boot_phase` is "
            "monotonic. `unknown` — NEVER emitted a signal (no telemetry "
            "agent in the image, or still on its first boot); NOT a "
            "statement that the VM is dead."
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
            "True when the KBS holds a recorded signed release for this VM. "
            "NULL when that cannot be determined — absent evidence does NOT "
            "mean the VM is unattested (the KBS records evidence only when "
            "its §280 evidence sink is enabled, and the archive is not "
            "retained across a KBS restart). Never false on absent evidence; "
            "see `attestation_status`."
        ),
    )
    attestation_status = serializers.ChoiceField(
        choices=[
            "evidence-recorded",
            "no-evidence-recorded",
            "evidence-unavailable",
        ],
        help_text=(
            "Why `attested` has the value it does: `evidence-recorded` (proven "
            "— a signed release bundle exists), `no-evidence-recorded` (unknown "
            "— the KBS returned no bundle, which happens both for a VM that "
            "never attested AND for one whose release predates/outlived the "
            "evidence archive), or `evidence-unavailable` (the KBS fetch "
            "failed — see `kbs_evidence_error`)."
        )
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
