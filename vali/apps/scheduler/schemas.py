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
    capacity_slots = serializers.IntegerField(
        help_text=(
            "Admission capacity in the active model's units (`model`): v1 slots, "
            "or v2 resource-true reference-flavor units (a flavor N× the "
            "reference consumes N)."
        )
    )
    load = serializers.IntegerField(
        help_text="Committed units (v1: active placements); `capacity_slots = load + free`."
    )
    free_slots = serializers.IntegerField(
        help_text=(
            "max(0, capacity - load), or 0 when the miner is epoch-stale, "
            "cordoned, or `cvm_capability` is `incapable` (gate (e) "
            "hard-excludes it, so its slots are not offerable)."
        )
    )
    epoch_fresh = serializers.BooleanField(help_text="Miner's data_epoch within max lag.")
    cordoned = serializers.BooleanField(
        required=False,
        help_text=(
            "Operator-cordoned: takes no new placement (its `free_slots` and "
            "`free_by_flavor` read 0). The VMs already on it are untouched."
        ),
    )
    cordon_reason = serializers.CharField(
        allow_null=True, required=False, help_text="Why it was cordoned (null when not)."
    )
    max_booting = serializers.IntegerField(
        required=False,
        help_text=(
            "Concurrent-boot cap a launch respects on this miner: its own "
            "override, else the fleet value (`0` = no cap)."
        ),
    )
    model = serializers.CharField(
        allow_null=True, required=False, help_text="`v1` slots or `v2` resource-true."
    )
    free_by_flavor = serializers.DictField(
        child=serializers.IntegerField(min_value=0),
        required=False,
        help_text=(
            "Per flavor: how many more admission would take here NOW (0 when "
            "the miner is not offerable, the flavor does not fit, or it is not "
            "offered)."
        ),
    )
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


# ─── /v1/scheduler/feasibility ───────────────────────────────────────


class HostFitSerializer(serializers.Serializer):
    """One dispatchable host, and whether the flavor fits on it."""

    node_id = serializers.CharField()
    big_enough = serializers.BooleanField(
        help_text=(
            "Is the HARDWARE big enough, ignoring what is placed on it? "
            "`false` on every host is what makes a verdict `never`."
        )
    )
    size_unknown = serializers.BooleanField(
        help_text=(
            "vali has no trusted hardware anchor for this host, so neither "
            "`big_enough` nor `fits` is an ANSWER — both are `false` so this "
            "never reads as a fit, but the host does not count towards a "
            "`never` verdict either. Unknown is not \"too small\"."
        )
    )
    fits = serializers.BooleanField(
        help_text=(
            "Is there room RIGHT NOW — RAM and vCPU both fit in this host's "
            "trusted FREE budget. Implies `big_enough`."
        )
    )
    free_memory_mb = serializers.IntegerField(
        allow_null=True,
        help_text=(
            "`null` ⇒ vali has no trusted hardware anchor for this host and "
            "cannot say. Treated as NOT fitting — an unknown host must never "
            "be the reason a VM was sold."
        ),
    )
    free_cpus = serializers.IntegerField(allow_null=True)
    budget_memory_mb = serializers.IntegerField(
        allow_null=True,
        help_text=(
            "The host's whole tenant budget (`total − reserve`), independent "
            "of what is placed on it. This is what `big_enough` compares "
            "against."
        ),
    )
    budget_cpus = serializers.IntegerField(allow_null=True)
    shortfall = serializers.CharField(
        allow_blank=True,
        help_text="Which dimension fell short, and by how much. Empty when it fits.",
    )
    free_vms = serializers.IntegerField(
        allow_null=True,
        required=False,
        help_text=(
            "Resource admission only (`null` otherwise): VMs this host can still "
            "take under its VM ceiling / hard cap / SEV-ES ASID limit."
        ),
    )
    headroom = serializers.IntegerField(
        allow_null=True,
        required=False,
        help_text="Resource admission only: how many of THIS flavor fit now.",
    )
    disk_checked = serializers.BooleanField(
        required=False,
        help_text=(
            "vali has DATA-disk data for this host (an operator anchor or a "
            "fresh heartbeat-v4 disk report). Disk joins `fits` / `big_enough` "
            "only when `disk_gate` is `apply` or `deny`."
        ),
    )
    budget_disk_gb = serializers.IntegerField(
        allow_null=True,
        required=False,
        help_text="The host's DATA-disk budget (GiB); `null` = unknown.",
    )
    free_disk_gb = serializers.IntegerField(
        allow_null=True,
        required=False,
        help_text="DATA disk free of vali's committed ledger (GiB); `null` = unknown.",
    )
    disk_gate = serializers.ChoiceField(
        choices=["off", "apply", "deny"],
        required=False,
        help_text=(
            "How admission applies disk here: `off` (gate off / record, or "
            "unknown data allowed), `apply` (enforced), `deny` (enforced, "
            "unknown data denied)."
        ),
    )


class FeasibilitySerializer(serializers.Serializer):
    """`GET /v1/scheduler/feasibility` 200 element — one flavor's answer."""

    flavor = serializers.CharField()
    verdict = serializers.ChoiceField(
        choices=["yes", "not-now", "never"],
        help_text=(
            "Branch on this. `yes` — a miner would be chosen and the flavor "
            "fits it. `not-now` — the fleet COULD run this flavor but nothing "
            "is free or eligible right now; retrying can succeed. `never` — no "
            "reachable host is big enough, so retrying cannot help. `never` is "
            "the answer that must stop a sale."
        ),
    )
    placeable_now = serializers.BooleanField(help_text="`verdict == \"yes\"`.")
    fits_any_host = serializers.BooleanField(
        help_text=(
            "Could the HARDWARE ever run this flavor? Judged against the host "
            "budget, never against what is free — otherwise a merely-full "
            "fleet would report a flavor as permanently impossible."
        )
    )
    headroom = serializers.IntegerField(
        help_text=(
            "How many more VMs of this flavor the reachable fleet could take, "
            "summed over hosts. Advisory, NOT a reservation: it is a snapshot "
            "and any concurrent launch consumes it."
        )
    )
    cpu_count = serializers.IntegerField()
    memory_mb = serializers.IntegerField()
    data_disk_size_gb = serializers.IntegerField()
    reason = serializers.CharField(
        allow_blank=True,
        help_text=(
            "Why not `yes`. `flavor-not-offered` (`never`): the flavor is above "
            "the largest size the fleet sells (`VALI_SCHEDULER_MAX_FLAVOR`), "
            "whatever the hardware could hold. Fleet-wide: `no-dispatchable-miner`, "
            "`host-size-unknown`, `flavor-exceeds-every-host`, `fleet-full`, "
            "`no-eligible-miner`, `chain-unavailable`. With `?region=`: "
            "`region-unknown` (no miner has a detected location yet — the "
            "probe has not run; retry), `no-miner-in-region` (the fleet is "
            "located and none of it is there — `never`), `region-unverified` "
            "(miners detected there but none verified; retry)."
        ),
    )
    scheduler_error = serializers.CharField(allow_blank=True)
    region = serializers.CharField(
        allow_blank=True,
        help_text=(
            "The `?region=` this answer was computed for (uppercased), or "
            "empty when asked fleet-wide."
        ),
    )
    disk_checked = serializers.BooleanField(
        help_text=(
            "`true` only when `VALI_SCHEDULER_DISK_GATE=enforce` AND every host "
            "counted as fitting had DATA-disk data, i.e. `fits` covers disk. "
            "`false` otherwise: disk is then still gated at dispatch (the miner "
            "answers 507 `insufficient-disk` and vali re-places). Stated rather "
            "than implied, so a caller knows exactly how far this answer reaches."
        )
    )
    hosts = HostFitSerializer(many=True)


class FeasibilityListSerializer(serializers.Serializer):
    """`GET /v1/scheduler/feasibility` 200 body."""

    flavors = FeasibilitySerializer(many=True)


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
