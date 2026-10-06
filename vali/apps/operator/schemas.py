"""Doc-only serializers for the operator OpenAPI schema. Referenced from
`@extend_schema` in `views.py` only — never wired into request handling.
Fields mirror `service.operator_node_rows`.
"""

from __future__ import annotations

from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from apps.miners.models import MinerStatus
from apps.scheduler.reasons import REFUSAL_REASONS, SCHEDULABLE_REASONS
from apps.telemetry.models import HostAttestorStatus

# Closed vocabularies, rendered as `enum` in the schema so the upstream
# product API (which validates every string it receives) can be generated /
# checked against the same list.
_NODE_STATUS = sorted(s.value for s in MinerStatus)
_ATTESTOR_STATUS = sorted(s.value for s in HostAttestorStatus)
_SCHEDULABLE_REASON = sorted(SCHEDULABLE_REASONS)
_REFUSAL_REASON = sorted(REFUSAL_REASONS)


class OperatorAttestorSerializer(serializers.Serializer):
    status = serializers.ChoiceField(
        choices=_ATTESTOR_STATUS, help_text="Host-attestor enrollment state."
    )
    cert_expiry_at = serializers.DateTimeField()
    measurement = serializers.CharField(help_text="Host-attestor launch measurement (hex).")
    last_seen_at = serializers.DateTimeField(allow_null=True, help_text="Last beacon.")


class OperatorCapacitySerializer(serializers.Serializer):
    total_units = serializers.IntegerField(
        help_text="Effective admission slots (the scheduler's own bound)."
    )
    committed_units = serializers.IntegerField(
        help_text="Active placements (pending + bound) on the node."
    )


@extend_schema_field({"nullable": True})
class NullOnlyField(serializers.Field):
    """A field whose only value is `null` — reserved for a future structured
    payload. `to_representation` ignores its input, so even a regression in
    the service that put a string under this key would serialise `null`;
    the published schema is `nullable` with NO type, so a generated
    consumer cannot type it as a string either."""

    def __init__(self, **kwargs: object) -> None:
        kwargs.setdefault("required", False)
        kwargs.setdefault("allow_null", True)
        super().__init__(**kwargs)  # type: ignore[arg-type]

    def to_representation(self, value: object) -> None:
        return None

    def to_internal_value(self, data: object) -> None:
        return None


class OperatorRefusalSerializer(serializers.Serializer):
    at = serializers.DateTimeField(
        help_text="When the placement ended (the drain, or the failed launch)."
    )
    reason = serializers.ChoiceField(
        choices=_REFUSAL_REASON,
        help_text=(
            "The gate the node failed when the scheduler drained the placement; "
            "`launch-rejected` / `launch-unreachable` / `launch-failed` when the node "
            "refused, could not be reached, or lost the VM at launch; or `unknown` when "
            "the recorded cause has no public equivalent (the stored text is never echoed)."
        ),
    )
    detail = NullOnlyField(
        help_text=(
            "Reserved for a future structured detail. Always `null` today, never the "
            "stored text. Optional during the rollout: a consumer defaults it to `null`."
        ),
    )


class OperatorLocationSerializer(serializers.Serializer):
    """The DETECTED location of a node (`vali_geo_probe`). Every field is
    something vali observed — none is declared by the miner."""

    country_code = serializers.CharField(
        allow_blank=True,
        help_text="ISO 3166-1 alpha-2 of the observed egress IP; empty when unknown.",
    )
    region = serializers.CharField(
        allow_blank=True, help_text="The region key — equals `country_code`."
    )
    city = serializers.CharField(
        allow_blank=True, help_text="GeoIP city when the source knows one (often empty)."
    )
    connection_ip = serializers.IPAddressField(
        allow_null=True,
        help_text=(
            "Public IP the miner's NetBird peer connects FROM, as the management server saw it."
        ),
    )
    asn = serializers.IntegerField(allow_null=True, help_text="Announcing AS number of that IP.")
    as_holder = serializers.CharField(allow_blank=True, help_text="AS holder name.")
    rtt_ms = serializers.FloatField(
        allow_null=True,
        help_text="Min TCP-connect round-trip vali→miner (ms) — the physical distance bound.",
    )
    verdict = serializers.ChoiceField(
        choices=["verified", "unverified", "mismatch", "unknown"],
        help_text=(
            "`verified`: GeoIP location within the RTT bound, sources agree, tenant egress "
            "matches. `unverified`: a check is missing/failed. `mismatch`: evidence "
            "contradicts itself (tenant CVMs egress elsewhere, or GeoIP sources disagree). "
            "`unknown`: no evidence."
        ),
    )
    verdict_reasons = serializers.ListField(
        child=serializers.CharField(),
        help_text=(
            "Why not `verified`: `no-netbird-peer`, `no-public-connection-ip`, "
            "`geo-lookup-failed`, `geo-source-disagree`, `guest-egress-mismatch`, "
            "`peer-stale`, `rtt-unavailable`, `latency-inconsistent`, "
            "`rtt-exceeds-claimed-distance`, `geo-rtt-arbitrated-country-only`. "
            "Informational (never lowers the verdict, may accompany `verified`): "
            "`geo-rtt-arbitrated` — the GeoIP sources disagreed and the RTT ruled one out."
        ),
    )
    observed_at = serializers.DateTimeField(help_text="When this evidence was last collected.")


class OperatorNodeSerializer(serializers.Serializer):
    """One node's status row."""

    node_id = serializers.CharField(help_text="On-chain node_id, 64 hex chars, lower-case.")
    miner_id = serializers.CharField(help_text="Control-plane miner identity.")
    status = serializers.ChoiceField(choices=_NODE_STATUS, help_text="Local registry status.")
    last_seen_at = serializers.DateTimeField(allow_null=True, help_text="Last heartbeat.")
    attestor = OperatorAttestorSerializer(allow_null=True)
    schedulable = serializers.BooleanField(
        help_text=(
            "Whether the scheduler would place onto this node right now — the "
            "SAME predicate `decide_placement` uses."
        )
    )
    schedulable_reason = serializers.ChoiceField(
        choices=_SCHEDULABLE_REASON,
        allow_null=True,
        help_text=(
            "`null` when schedulable; otherwise the first gate the node fails, in scheduler order."
        ),
    )
    hosted_vm_count = serializers.IntegerField(help_text="Active placements on the node.")
    capacity = OperatorCapacitySerializer(allow_null=True)
    recent_refusals = OperatorRefusalSerializer(
        many=True,
        help_text=(
            "Most recent placements that ended because of the node itself (newest "
            "first, max 10): the scheduler drained it off the node, or the node "
            "refused / could not be reached / lost the VM at launch. Placements "
            "that ended for other reasons (VM released by its tenant, a launch that "
            "failed on the control-plane side, manual `/fail`, or an end recorded "
            "before its provenance was) are not refusals and are not listed."
        ),
    )
    refusal_count_30d = serializers.IntegerField(
        required=False,
        help_text=(
            "Number of such refusals in the last 30 days (not capped at 10). Equals "
            "the sum of `refusal_breakdown_30d`. Optional during the rollout: a "
            "consumer defaults it to `0`."
        ),
    )
    refusal_breakdown_30d = serializers.DictField(
        child=serializers.IntegerField(min_value=1),
        required=False,
        help_text=(
            "The same 30-day refusals counted per public reason, e.g. "
            '`{"launch-rejected": 3, "heartbeat-stale": 1}`. Keys are the '
            "`OperatorRefusal.reason` enum; a reason with no refusal is absent. "
            "Optional during the rollout: a consumer defaults it to `{}`."
        ),
    )
    location = OperatorLocationSerializer(
        required=False,
        allow_null=True,
        help_text=(
            "The DETECTED location (`vali_geo_probe`) — `null` before the first probe "
            "cycle. Optional during the rollout."
        ),
    )


class OperatorRegionCapacitySerializer(serializers.Serializer):
    total_units = serializers.IntegerField(
        min_value=0,
        help_text=(
            "Capacity in the active admission model's units (`model`): v1 slots, "
            "or v2 resource-true units of the reference flavor (`unit`) — a flavor "
            "N× the reference consumes N. `total = committed + free`."
        ),
    )
    committed_units = serializers.IntegerField(min_value=0)
    free_units = serializers.IntegerField(min_value=0)
    model = serializers.ChoiceField(
        choices=["v1", "v2"],
        required=False,
        help_text="`v1` slot admission or `v2` resource-true admission.",
    )
    unit = serializers.DictField(
        child=serializers.IntegerField(),
        required=False,
        help_text="The reference flavor one unit is worth: `{cpus, memory_mb}`.",
    )
    free_vms = serializers.IntegerField(
        allow_null=True,
        required=False,
        help_text="v2 only: VMs still admissible (VM ceiling / hard cap / SEV-ES ASIDs).",
    )
    free_by_flavor = serializers.DictField(
        child=serializers.IntegerField(min_value=0),
        required=False,
        help_text=(
            "Per flavor: how many more admission would take in this region NOW, "
            "summed over its dispatchable hosts. 0 where no host fits it (or it "
            "is not offered) — the precise answer when `free_units` rounds a "
            "small flavor away."
        ),
    )


class OperatorRegionSerializer(serializers.Serializer):
    region = serializers.CharField(
        help_text=(
            "ISO 3166-1 alpha-2 (`FR`). The value to pass as `region` on launch / feasibility."
        )
    )
    country_code = serializers.CharField(
        help_text="Same as `region` (kept for when regions become finer than a country)."
    )
    miners_total = serializers.IntegerField(
        min_value=0, help_text="Every miner detected in this region, any verdict."
    )
    miners_verified = serializers.IntegerField(min_value=0, help_text="Of which `verified`.")
    miners_dispatchable = serializers.IntegerField(
        min_value=0,
        help_text="Counted miners that also pass the scheduler's dispatchability gates right now.",
    )
    hosted_vm_count = serializers.IntegerField(
        min_value=0, help_text="Active placements on the counted miners."
    )
    capacity = OperatorRegionCapacitySerializer(
        allow_null=True,
        help_text="Summed admission capacity of the counted miners; null when none reports one.",
    )
    node_ids = serializers.ListField(
        child=serializers.CharField(), help_text="On-chain node_ids of the counted miners."
    )


class OperatorVantageSerializer(serializers.Serializer):
    name = serializers.CharField()
    latitude = serializers.FloatField()
    longitude = serializers.FloatField()


class OperatorRegionsSerializer(serializers.Serializer):
    """`GET /v1/operator/regions` 200 body."""

    regions = OperatorRegionSerializer(many=True, help_text="Sorted by `region`.")
    unlocated_miners = serializers.IntegerField(
        min_value=0,
        help_text="Registered (scheduler-bridged) miners with no detected location yet.",
    )
    require_verified = serializers.BooleanField(
        help_text="Whether the counted set was restricted to `verified` miners."
    )
    vantage = OperatorVantageSerializer(help_text="Where the RTT is measured from.")
    generated_at = serializers.DateTimeField()


class OperatorNodesSerializer(serializers.Serializer):
    """`GET /v1/operator/nodes` 200 body."""

    nodes = OperatorNodeSerializer(many=True)
    count = serializers.IntegerField(help_text="Rows returned.")


# ─── /v1/operator/fleet ──────────────────────────────────────────────


class FleetVmResourceShortfallSerializer(serializers.Serializer):
    """`apps.telemetry.guest_resources` — the last short sample of a VM."""

    node_id = serializers.CharField()
    flavor = serializers.CharField()
    reason = serializers.CharField(
        help_text=(
            "`vcpus` / `mem-firmware` / `mem-total` / `mem-unaccepted`, `+`-joined; "
            "or `superseded-launch` (a guest of an earlier launch of this VM)."
        )
    )
    want_vcpus = serializers.IntegerField()
    want_memory_mb = serializers.IntegerField()
    vcpus_online = serializers.IntegerField(allow_null=True)
    mem_firmware_kib = serializers.IntegerField(allow_null=True)
    mem_total_kib = serializers.IntegerField(allow_null=True)
    mem_unaccepted_kib = serializers.IntegerField(allow_null=True)
    samples = serializers.IntegerField()
    first_seen_at = serializers.DateTimeField()
    last_seen_at = serializers.DateTimeField()


class FleetVmSerializer(serializers.Serializer):
    vm_id = serializers.CharField()
    flavor = serializers.CharField(
        allow_null=True, help_text="`resource_class` of its live (else latest) placement."
    )
    role = serializers.ChoiceField(
        choices=["host", "migration-dest", "placement-only"],
        help_text=(
            "`host`: `Vm.host` is this miner. `migration-dest`: a §25 destination. "
            "`placement-only`: a live placement whose VM is no longer hosted."
        ),
    )
    admission_counted = serializers.BooleanField(
        help_text="Scheduler admission counts it on this node (a pending/bound placement)."
    )
    placement_status = serializers.CharField(
        allow_null=True, help_text="Status of its live (else latest) placement."
    )
    placement_reason = serializers.CharField(allow_null=True)
    state = serializers.CharField(help_text="`Vm.state`.")
    power_state = serializers.CharField()
    boot_phase = serializers.CharField(allow_null=True)
    tenant_id = serializers.CharField(allow_null=True)
    owner = serializers.CharField(allow_null=True, help_text="Order ticket `user_id`.")
    netbird_ip = serializers.CharField(allow_null=True)
    public_ip = serializers.CharField(allow_null=True)
    created_at = serializers.DateTimeField()
    placed_at = serializers.DateTimeField(allow_null=True)
    bound_at = serializers.DateTimeField(allow_null=True)
    resource_shortfall = FleetVmResourceShortfallSerializer(
        allow_null=True,
        help_text=(
            "The guest attested fewer vCPUs online or less RAM than its flavor "
            "within `VALI_GUEST_RESOURCES_FLAG_S` (degraded); null otherwise."
        ),
    )


class FleetDiskSerializer(serializers.Serializer):
    """The host's DATA-disk dimension (GiB) — storage-aware placement."""

    gate_mode = serializers.ChoiceField(
        choices=["off", "record", "enforce"], help_text="`VALI_SCHEDULER_DISK_GATE`."
    )
    gate_state = serializers.ChoiceField(
        choices=["off", "apply", "deny"],
        help_text=(
            "How admission applies disk HERE: `off` (gate off / record, or unknown "
            "data allowed), `apply` (enforced), `deny` (enforced, unknown data denied)."
        ),
    )
    known = serializers.BooleanField(help_text="vali has at least one disk term for this host.")
    anchor_total_gb = serializers.IntegerField(
        allow_null=True, help_text="Operator-registered data-fs size (trusted)."
    )
    declared_budget_gb = serializers.IntegerField(
        allow_null=True, help_text="UNTRUSTED heartbeat-v4 `cvm_disk_gb_budget` (down-only)."
    )
    reported_total_gb = serializers.IntegerField(
        allow_null=True, help_text="UNTRUSTED statvfs total of the data fs (down-only)."
    )
    reported_free_gb = serializers.IntegerField(
        allow_null=True, help_text="UNTRUSTED statvfs available of the data fs (down-only)."
    )
    reported_staging_free_gb = serializers.IntegerField(
        allow_null=True, help_text="UNTRUSTED statvfs available of the staging fs."
    )
    reported_at = serializers.DateTimeField(allow_null=True)
    earned_disk_gb = serializers.IntegerField(
        allow_null=True, help_text="Disk ceiling vali cut after disk refusals (null = never)."
    )
    committed_gb = serializers.IntegerField(
        help_text="vali's ledger: Σ (flavor disk_gb + rootfs) over counted placements."
    )
    effective_gb = serializers.IntegerField(
        allow_null=True, help_text="The down-only min of every known term; null = unknown."
    )
    free_gb = serializers.IntegerField(allow_null=True)
    binding = serializers.CharField(allow_null=True, help_text="The term that set the budget.")
    over_claim = serializers.BooleanField(
        help_text=(
            "Reported free data disk < committed − slack. An ALARM (sparse disks, "
            "shared fs usage), never a gate."
        )
    )


class FleetCapacitySerializer(serializers.Serializer):
    operator_max_slots = serializers.IntegerField(help_text="Operator ceiling.")
    effective_slots = serializers.IntegerField(help_text="The scheduler's admission bound.")
    used_slots = serializers.IntegerField(help_text="Active placements.")
    free_slots = serializers.IntegerField()
    dynamic = serializers.BooleanField(
        help_text="True when the trusted hardware anchor drove the bound."
    )
    over_claim = serializers.BooleanField(
        help_text="The miner self-reported more free RAM than physically possible."
    )
    total_memory_mb = serializers.IntegerField(allow_null=True, help_text="Trusted anchor.")
    total_cpus = serializers.IntegerField(allow_null=True, help_text="Trusted anchor.")
    budget_memory_mb = serializers.IntegerField(allow_null=True, help_text="total − reserve.")
    budget_cpus = serializers.IntegerField(allow_null=True)
    free_memory_mb = serializers.IntegerField(allow_null=True)
    free_cpus = serializers.IntegerField(allow_null=True)
    committed_memory_mb = serializers.IntegerField()
    committed_cpus = serializers.IntegerField()
    uncounted_vms = serializers.IntegerField(
        help_text="Active VMs running here that admission does not count (over-booking risk)."
    )
    uncounted_memory_mb = serializers.IntegerField()
    uncounted_cpus = serializers.IntegerField()
    reported_memory_available_mib = serializers.IntegerField(
        allow_null=True, help_text="UNTRUSTED heartbeat self-report (down-only throttle)."
    )
    reported_at = serializers.DateTimeField(allow_null=True)
    flavor_headroom = serializers.DictField(
        child=serializers.DictField(),
        help_text=(
            "Per flavor, in the ACTIVE admission model: `fits_now` (count) and "
            "`fits_hardware` (bool), null when vali cannot size the host; "
            "`offered` (bool) is false above `VALI_SCHEDULER_MAX_FLAVOR`; `disk` — "
            "the data-disk dimension alone, whatever the gate mode: `need_gb`, "
            "`fits_now`, `fits_hardware` (null without disk data)."
        ),
    )
    model = serializers.CharField(
        allow_null=True, required=False, help_text="`v1` slots or `v2` resource-true."
    )
    units = serializers.DictField(
        child=serializers.IntegerField(),
        allow_null=True,
        required=False,
        help_text="`{total, committed, free}` in the active model's units (regions sums these).",
    )
    trust_class = serializers.CharField(
        required=False, help_text="`operator` (anchored) or `earned` (proof-based)."
    )
    cpu_ratio = serializers.CharField(
        allow_null=True,
        required=False,
        help_text="Per-miner vCPU:thread overcommit; null follows the fleet setting.",
    )
    v2 = serializers.DictField(
        allow_null=True,
        required=False,
        help_text=(
            "Capacity v2 budget, shown also while v1 decides: vCPU/RAM/VM budgets, "
            "widest VM, free figures, and which term binds each (`binding`)."
        ),
    )
    disk = FleetDiskSerializer(required=False)


class FleetMinerSerializer(serializers.Serializer):
    node_id = serializers.CharField(allow_null=True, help_text="Null for an unbridged identity.")
    miner_id = serializers.CharField(allow_null=True)
    status = serializers.CharField(allow_null=True, help_text="vali-local `MinerIdentity.status`.")
    identity = serializers.DictField(allow_null=True)
    vcpu_model = serializers.CharField(
        allow_null=True,
        help_text=(
            "`EpycTurin` / `EpycGenoa` / `EpycMilan`: the registered "
            "`snp_generation`, else inferred from the CHIP_ID length "
            "(8 bytes ⇒ Turin, 64 ⇒ Genoa). Null when unresolvable."
        ),
    )
    last_seen_at = serializers.DateTimeField(allow_null=True, help_text="Last heartbeat.")
    heartbeat_age_s = serializers.IntegerField(allow_null=True)
    heartbeat_stale = serializers.BooleanField()
    on_chain = serializers.BooleanField(
        allow_null=True, help_text="Null when the chain was not read; false for a leftover row."
    )
    dispatchable = serializers.BooleanField(
        help_text="vali can reach + attest it (the `/v1/operator/nodes` predicate)."
    )
    dispatchable_reason = serializers.CharField(allow_null=True)
    schedulable = serializers.BooleanField(
        help_text="A launch could land here now: every hard `decide_placement` gate."
    )
    schedulable_reason = serializers.CharField(
        allow_null=True, help_text="The first hard gate failed."
    )
    chain = serializers.DictField(
        allow_null=True,
        help_text="On-chain status/quality/price; `source` says chain read or DB mirror.",
    )
    location = OperatorLocationSerializer(allow_null=True)
    capacity = FleetCapacitySerializer(allow_null=True)
    vm_count = serializers.IntegerField()
    vm_count_by_state = serializers.DictField(child=serializers.IntegerField())
    incoming_migrations = serializers.IntegerField(
        help_text="§25 moves landing here (still counted on their source)."
    )
    vms = FleetVmSerializer(many=True)
    attestor = serializers.DictField(allow_null=True)
    cvm_start = serializers.DictField(help_text="Observed SEV-SNP start capability.")
    zombie = serializers.DictField(allow_null=True)
    usage = serializers.DictField(help_text="Current billing epoch usage + reward weight.")
    backups = serializers.DictField(allow_null=True, help_text="Backup runs over the last 24 h.")
    alerts = serializers.ListField(child=serializers.CharField())


class OperatorFleetSerializer(serializers.Serializer):
    """`GET /v1/operator/fleet` 200 body."""

    miners = FleetMinerSerializer(many=True)
    totals = serializers.DictField()
    chain = serializers.DictField()
    billing_epoch = serializers.IntegerField(allow_null=True)
    policy = serializers.DictField()
    unresolved_vms = serializers.ListField(
        child=serializers.DictField(),
        help_text="Hosted VMs whose `Vm.host` names no known miner.",
    )
    generated_at = serializers.DateTimeField()
