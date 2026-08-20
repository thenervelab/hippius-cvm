"""Doc-only serializers for the §23 scheduler OpenAPI schema.

These serializers exist SOLELY to shape the generated OpenAPI document —
they are referenced from `@extend_schema` in `views.py` and NEVER wired
into request handling (every view keeps its own manual `request.data`
parsing and hand-built `Response`). Fields mirror the view `_require_*`
body checks (request) and the `_serialize_placement` /
`_serialize_recommendation` helpers + inline `Response` bodies (response).
"""

from __future__ import annotations

from rest_framework import serializers

from apps.common.schemas import ErrorSerializer


class PlacementSerializer(serializers.Serializer):
    """A `Placement` row (`_serialize_placement`)."""

    id = serializers.CharField(help_text="Placement UUID (string).")
    vm_id = serializers.CharField()
    vm_family = serializers.CharField(help_text="Anti-affinity family = the VM's tenant id.")
    resource_class = serializers.CharField()
    miner_node_id = serializers.CharField(help_text="Chosen miner node id (hex).")
    status = serializers.CharField(help_text="Pending | Bound | Failed.")
    chain_epoch = serializers.IntegerField(help_text="On-chain epoch the decision snapshotted.")
    reason = serializers.CharField(allow_null=True, help_text="Failure reason (fail path only).")
    kbs_release_ref = serializers.CharField(
        allow_null=True, help_text="KBS release audit reference (set on bind)."
    )
    decided_by = serializers.CharField(help_text="Principal name that decided the placement.")
    decided_at = serializers.DateTimeField()
    bound_at = serializers.DateTimeField(allow_null=True)
    failed_at = serializers.DateTimeField(allow_null=True)
    version = serializers.IntegerField(help_text="Optimistic-concurrency version.")


class PlacementConflictSerializer(serializers.Serializer):
    """409 body when a VM already holds an active placement with a
    different `resource_class` (or a stale-`if_version` CAS loss). Extends
    the uniform `{error, category}` envelope with the current row."""

    error = serializers.CharField()
    category = serializers.CharField(
        help_text="`placement-conflict` | `version-conflict`."
    )
    current = PlacementSerializer(allow_null=True, help_text="The current placement row.")


# ─── /v1/scheduler/place ─────────────────────────────────────────────


class SchedulerPlaceRequestSerializer(serializers.Serializer):
    """`POST /v1/scheduler/place` body."""

    vm_id = serializers.CharField(help_text="VM to place (must exist and have an OrderTicket).")
    resource_class = serializers.CharField(
        max_length=128, help_text="Resource class / flavor of the VM (≤128 chars)."
    )


# ─── /v1/scheduler/<vm_id>/bind ──────────────────────────────────────


class SchedulerBindRequestSerializer(serializers.Serializer):
    """`POST /v1/scheduler/<vm_id>/bind` body — CAS Pending→Bound."""

    if_version = serializers.IntegerField(
        min_value=1, help_text="Expected current placement `version` (CAS guard, ≥1)."
    )
    kbs_release_ref = serializers.CharField(
        max_length=256,
        help_text="KBS release reference recorded as the bind audit trail (≤256 chars).",
    )


# ─── /v1/scheduler/<vm_id>/fail ──────────────────────────────────────


class SchedulerFailRequestSerializer(serializers.Serializer):
    """`POST /v1/scheduler/<vm_id>/fail` body — CAS Pending→Failed."""

    if_version = serializers.IntegerField(
        min_value=1, help_text="Expected current placement `version` (CAS guard, ≥1)."
    )
    reason = serializers.CharField(max_length=256, help_text="Failure reason (≤256 chars).")


class SchedulerFailResponseSerializer(serializers.Serializer):
    """`/fail` 200 body: the failed placement plus a best-effort
    re-placement (`replacement`/`replacement_error` — exactly one is set)."""

    failed = PlacementSerializer(help_text="The placement just marked Failed.")
    replacement = PlacementSerializer(
        allow_null=True, help_text="The new Pending placement, or null if re-placement failed."
    )
    replacement_error = ErrorSerializer(
        allow_null=True, help_text="Why re-placement could not proceed (null on success)."
    )


# ─── /v1/scheduler/capacity ──────────────────────────────────────────


class MinerCapacitySerializer(serializers.Serializer):
    """Per-dispatchable-miner capacity row."""

    node_id = serializers.CharField()
    status = serializers.CharField(help_text="On-chain miner status.")
    quality = serializers.CharField(help_text="Miner quality (u128 as decimal string).")
    capacity_slots = serializers.IntegerField(help_text="Proven placement capacity.")
    load = serializers.IntegerField(help_text="Active placements on this miner.")
    free_slots = serializers.IntegerField(
        help_text=(
            "max(0, capacity - load), or 0 when the miner is epoch-stale or "
            "`cvm_capability` is `incapable` (gate (e) hard-excludes it, so "
            "its slots are not offerable)."
        )
    )
    epoch_fresh = serializers.BooleanField(help_text="Miner's data_epoch within max lag.")
    cvm_capability = serializers.CharField(
        help_text=(
            "OBSERVED SEV-SNP start capability (§23 gate (e)): `proven` — vali "
            "watched a confidential guest start here recently; `unknown` — no "
            "evidence either way (eligible, no bonus); `degraded` — a recent "
            "observed start FAILURE, or a host on post-exclusion probation "
            "(soft: chosen only as a last resort); `incapable` — a streak of "
            "observed start failures (HARD-excluded from placement)."
        )
    )


class SchedulerCapacitySerializer(serializers.Serializer):
    """`GET /v1/scheduler/capacity` 200 body — advisory availability view."""

    current_epoch = serializers.IntegerField()
    pallet_live = serializers.BooleanField(
        help_text=(
            "`false` ⇒ `current_epoch` and every miner's `quality` are a "
            "FOSSIL: the configured pallet is no longer in the runtime, but "
            "its orphaned storage prefix still answers reads, so the values "
            "look plausible while being frozen at the last epoch close. Do "
            "not treat quality as merit when this is false."
        )
    )
    dispatchable_miners = serializers.IntegerField()
    total_capacity_slots = serializers.IntegerField()
    total_free_slots = serializers.IntegerField()
    has_capacity = serializers.BooleanField(help_text="`total_free_slots > 0`.")
    cvm_incapable_miners = serializers.IntegerField(
        help_text=(
            "Dispatchable miners currently HARD-excluded by the observed "
            "SNP-start-capability gate. Non-zero ⇒ the placeable fleet is "
            "smaller than `dispatchable_miners`, and the per-miner "
            "`cvm_capability` says which hosts and why."
        )
    )
    miners = MinerCapacitySerializer(many=True)


# ─── /v1/admin/epoch-weights ─────────────────────────────────────────


class AttestorRewardPreviewSerializer(serializers.Serializer):
    """WARN/preview of the blackbox host-attestor reward MULTIPLIER (PR-11) —
    what `weights` WOULD become if `VALI_REWARD_REQUIRE_ATTESTOR` were armed
    (base × host-attestor liveness ratio). Preview-only, never applied."""

    enforced = serializers.BooleanField(
        help_text="Whether the multiplier is actually applied (always False in preview)."
    )
    weights = serializers.DictField(
        child=serializers.IntegerField(),
        help_text="`{node_id_hex: base×liveness_ratio}` — the would-be emitted weights.",
    )
    total_weight = serializers.IntegerField()
    miners = serializers.IntegerField()
    note = serializers.CharField()


class EpochWeightsSerializer(serializers.Serializer):
    """`GET /v1/admin/epoch-weights` 200 body — §23 per-miner reward
    weights, plus the priced `owed` bill once attested usage exists."""

    weights = serializers.DictField(
        child=serializers.IntegerField(),
        help_text="`{node_id_hex: weight}` summed over Bound placements.",
    )
    total_weight = serializers.IntegerField()
    miners = serializers.IntegerField(help_text="Number of weighted miners.")
    usage_epoch = serializers.IntegerField(
        required=False, help_text="Latest usage epoch (only when attested usage exists)."
    )
    owed_usd_micros = serializers.DictField(
        child=serializers.IntegerField(),
        required=False,
        allow_null=True,
        help_text="`{node_id: owed_micro_usd}`; null if the chain price read failed.",
    )
    owed_total_usd_micros = serializers.IntegerField(
        required=False, help_text="Sum of `owed_usd_micros` (only when usage exists)."
    )
    pallet_live = serializers.BooleanField(
        required=False,
        help_text=(
            "Is the configured pallet still wired into the runtime metadata? "
            "`false` ⇒ it was removed by a runtime upgrade but its storage "
            "prefix survived, so every on-chain value vali reads is frozen. "
            "Present only alongside the authenticated `owed_*` bill — the "
            "unauthenticated weights path makes no chain read."
        ),
    )
    attestor_reward_preview = AttestorRewardPreviewSerializer(
        required=False,
        help_text=(
            "Blackbox host-attestor reward-gate PREVIEW (PR-11). Present only "
            "when the gate is off (default) AND attested host-attestor rows "
            "exist — what `weights` WOULD become if armed. Never applied."
        ),
    )


# ─── /v1/edge/registry ───────────────────────────────────────────────


class EdgeRegistryMinerSerializer(serializers.Serializer):
    """One miner in the Edge registry feed."""

    node_id_hex = serializers.CharField()
    status = serializers.CharField()
    last_transition_epoch = serializers.IntegerField()
    data_epoch = serializers.IntegerField()
    quality_dec = serializers.CharField(help_text="Miner quality (u128 as decimal string).")


class EdgeRegistryFeedSerializer(serializers.Serializer):
    """`GET /v1/edge/registry` 200 body — the registered+Active miner set.

    Served as a raw signed `HttpResponse` (compact, sorted JSON) with an
    `X-Hippius-Registry-Sig` Ed25519 header; this documents the JSON shape.
    """

    current_epoch = serializers.IntegerField()
    miners = EdgeRegistryMinerSerializer(many=True)


# ─── /v1/price-recommendations ───────────────────────────────────────


class PriceRecommendationSerializer(serializers.Serializer):
    """A `PriceMigrationRecommendation` row (`_serialize_recommendation`)."""

    recommendation_id = serializers.CharField(help_text="Public opaque URL-safe id.")
    vm_id = serializers.CharField()
    current_node_id = serializers.CharField(help_text="Miner the VM runs on (the one repricing).")
    suggested_dest_node_id = serializers.CharField(
        allow_null=True, help_text="Within-budget destination, or null if none found."
    )
    new_price = serializers.IntegerField(help_text="Announced price breaching the ceiling.")
    ceiling = serializers.IntegerField(help_text="Tenant `max_price_per_unit` at the time.")
    effective_block = serializers.IntegerField(help_text="Block the new price takes effect.")
    status = serializers.CharField(help_text="Pending | Approved | Dismissed.")
    decided_by = serializers.CharField(allow_null=True, help_text="Deciding principal name.")
    decided_at = serializers.DateTimeField(allow_null=True)
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()
    version = serializers.IntegerField(help_text="Optimistic-concurrency version.")


class PriceRecommendationListSerializer(serializers.Serializer):
    """`GET /v1/price-recommendations` 200 body — open Pending alerts."""

    recommendations = PriceRecommendationSerializer(many=True)


class IfVersionRequestSerializer(serializers.Serializer):
    """`{"if_version": N}` CAS-guard body for approve/dismiss."""

    if_version = serializers.IntegerField(
        min_value=1, help_text="Expected current recommendation `version` (CAS guard, ≥1)."
    )


class PriceRecommendationApproveSerializer(serializers.Serializer):
    """`.../approve` 200 body — the decided recommendation + started job."""

    recommendation = PriceRecommendationSerializer()
    migration_job_id = serializers.CharField(help_text="The started §25 migration job id.")


class RecommendationConflictSerializer(serializers.Serializer):
    """409 body for a stale-`if_version` / already-decided recommendation."""

    error = serializers.CharField()
    category = serializers.CharField(help_text="`version-conflict`.")
    current = PriceRecommendationSerializer(
        allow_null=True, help_text="The current recommendation row."
    )
