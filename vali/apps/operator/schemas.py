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
    as_holder = serializers.CharField(allow_blank=True, help_text="AS holder name (e.g. `AS-X`).")
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


class OperatorStorageRequirementSerializer(serializers.Serializer):
    """The node's family against "compute requires storage"
    (`apps.scheduler.storage_requirement`)."""

    state = serializers.ChoiceField(
        choices=["ok", "grace", "lapsed", "exempt", "off"],
        help_text=(
            "`ok`: healthy storage (or a gap still inside the lapse debounce); "
            "`grace`: lapsed, rights kept until `grace_until`; `lapsed`: cut — no new "
            "VM, no reward; `exempt`: never cut; `off`: the requirement is not enforced."
        ),
    )
    family_storage_children = serializers.IntegerField(
        allow_null=True,
        help_text="The family's healthy Arion storage nodes at the last read (null when off).",
    )
    lapsed_since = serializers.DateTimeField(
        allow_null=True,
        help_text="The first read without healthy storage of the run that lapsed.",
    )
    grace_until = serializers.DateTimeField(
        allow_null=True,
        help_text=(
            "`lapsed_since + VALI_COMPUTE_STORAGE_GRACE_S`: when the rights end. Null "
            "when not lapsed, and for a family that never had storage (no grace)."
        ),
    )


class OperatorLaunchErrorSerializer(serializers.Serializer):
    """One failed launch attempt on the node, as vali observed the node's
    answer (`apps.miners.launch_errors`)."""

    code = serializers.CharField(
        help_text=(
            "The finest reason known, a static code matching `[a-z0-9][a-z0-9._:/-]*` "
            "(max 128): the agent's own reason (`libvirt-driver/define`, "
            "`tenant-preflight/ovmf-missing`, `cvm-launch-failed/timeout`, …) when it "
            "sends one, else `class`. vali's own codes: `miner-unreachable` (the Edge "
            "could not reach the node, or timed out waiting on it), `unclassified` (an "
            "answer with no code), `invalid` (the node sent something that is not a code)."
        ),
    )
    class_ = serializers.CharField(
        allow_null=True,
        help_text=(
            "The coarse class in the answer's body (`dispatch-failed`, "
            "`insufficient-resources`, `launch-input`, …) — what vali acted on. `null` "
            "for an answer with no body."
        ),
    )
    http_status = serializers.IntegerField(help_text="Status of the answer (502/504: the Edge).")
    stage = serializers.ChoiceField(
        choices=["preflight", "launch"],
        help_text="`preflight`: artifact staging + measurement; `launch`: the domain start.",
    )
    order_id = serializers.CharField(
        allow_null=True, help_text="The refused order, as the node logged it."
    )
    at = serializers.DateTimeField(help_text="When vali received the answer.")

    def get_fields(self) -> dict[str, serializers.Field]:
        # `class` is a Python keyword: declared as `class_`, published as `class`.
        fields = super().get_fields()
        fields["class"] = fields.pop("class_")
        return fields


class AgentReleaseSerializer(serializers.Serializer):
    """The newest COMPLETE miner-agent release of the public repository, as
    vali last read it (`vali_agent_release_watch`): not a draft or
    prerelease, every file the updater needs attached."""

    tag = serializers.CharField(help_text="`vYYYY.MM.DD` or `vYYYY.MM.DD.N`.")
    published_at = serializers.DateTimeField(help_text="GitHub `published_at`.")
    eligible_at = serializers.DateTimeField(
        help_text=(
            "When the miners' updater may install it: its last required file "
            "landed + the default soak (24 h). In the future = still soaking."
        )
    )


class AutoUpdateSerializer(serializers.Serializer):
    """The miner-agent auto-updater as the node reports it (host inventory
    `software.auto_update`): SELF-REPORTED, display only. Off is abnormal:
    show a warning with the remedy for `disabled_reason`
    (deploy/ansible/playbooks/miner-tasks/AUTO_UPDATE.md, "Dashboard")."""

    enabled = serializers.BooleanField(
        help_text="No opt-out in force and the updater's timer is enabled."
    )
    disabled_reason = serializers.ChoiceField(
        choices=["no_auto_update_file", "disabled_in_env", "timer_disabled"],
        allow_null=True,
        help_text=(
            "`null` when enabled. `no_auto_update_file`: "
            "/var/lib/hippius-miner/.no-auto-update exists. `disabled_in_env`: "
            "`AUTO_UPDATE_DISABLED=true` (ansible `miner_auto_update_enabled: false`). "
            "`timer_disabled`: hippius-miner-update.timer not enabled (or never "
            "installed)."
        ),
    )
    last_check_at = serializers.DateTimeField(
        allow_null=True,
        help_text=(
            "When a timer run last read the release list; `null` before the first "
            "one. Runs every 30 min plus up to 6 h of jitter, and reaches vali with "
            "the node's 6-hourly report: older than ~13 h while `enabled` means the "
            "updater is not running or cannot reach GitHub."
        ),
    )
    failed_tag = serializers.CharField(
        allow_null=True,
        help_text=(
            "The newest release that failed its health check on the node and is "
            "newer than the agent reporting: the updater never retries it (remove "
            "/var/lib/hippius-miner/.update-failed-<tag> to retry)."
        ),
    )
    reported_at = serializers.DateTimeField(
        help_text="The signed timestamp of the report that carried this block."
    )


_AGENT_RELEASE_HELP = (
    "The newest complete miner-agent release vali knows; `null` before the "
    "release watch ever ran (`VALI_AGENT_RELEASE_WATCH`). Optional during the rollout."
)
_UPDATE_PENDING_HELP = (
    "The node's `agent_version` is older than the newest release past the "
    "soak (eligible now). `null` when it cannot be told: no release known, or "
    "no release tag reported (none yet, or a `dev` build). Optional during the rollout."
)
_AUTO_UPDATE_HELP = (
    "The auto-updater's state as the node reports it; `null` until the node's "
    "host inventory carries it (agent collector run with `--report-auto-update`). "
    "Optional during the rollout."
)


class OperatorLastProbeSerializer(serializers.Serializer):
    """vali's last synthetic probe of the node that reached it
    (`apps.synthetic.per_miner`): a throwaway VM launched onto the node
    through the real launch path, booted, then decommissioned."""

    at = serializers.DateTimeField(help_text="When the probe finished.")
    ok = serializers.BooleanField(help_text="Every stage passed.")
    stage = serializers.CharField(
        allow_null=True,
        help_text=(
            "The stage that failed, `null` on a pass: `launch`, `launch_complete`, "
            "`release`, `kek_alive`, `boot`, `resources` (the guest attested fewer "
            "vCPUs or less RAM than its flavor), `netbird`, `decommission`, "
            "`crypto_erase`."
        ),
    )
    vm_id = serializers.CharField(help_text="The probe VM (`synmon-pm-…`).")


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
    storage_requirement = OperatorStorageRequirementSerializer(
        required=False,
        allow_null=True,
        help_text=(
            "Compute requires storage, for the node's family. `null` while enforced "
            "for a node vali has not read as an Active compute node on chain. "
            "Optional during the rollout."
        ),
    )
    last_launch_error = OperatorLaunchErrorSerializer(
        required=False,
        allow_null=True,
        help_text=(
            "The node's most recent failed launch attempt (= `recent_launch_errors[0]`), "
            "or `null` if none was ever recorded. Kept after a later success: compare "
            "`at` with `launch_fail_streak`. Observability only — it never changes "
            "placement. Optional during the rollout."
        ),
    )
    launch_fail_streak = serializers.IntegerField(
        required=False,
        min_value=0,
        help_text=(
            "Failed launch attempts on the node since the last launch it accepted "
            "(every attempt counts, a retry on the same node included); `0` after an "
            "accepted launch. Optional during the rollout: a consumer defaults it to `0`."
        ),
    )
    recent_launch_errors = OperatorLaunchErrorSerializer(
        many=True,
        required=False,
        help_text="The node's last failed launch attempts, newest first (max 5).",
    )
    agent_version = serializers.CharField(
        required=False,
        allow_null=True,
        help_text=(
            "The release tag the node's miner agent last reported in its heartbeat "
            "(e.g. `v2026.10.21.1`), self-reported; `null` before the first report. "
            "Optional during the rollout."
        ),
    )
    latest_agent_release = AgentReleaseSerializer(
        required=False, allow_null=True, help_text=_AGENT_RELEASE_HELP
    )
    update_pending = serializers.BooleanField(
        required=False, allow_null=True, help_text=_UPDATE_PENDING_HELP
    )
    auto_update = AutoUpdateSerializer(required=False, allow_null=True, help_text=_AUTO_UPDATE_HELP)
    last_probe = OperatorLastProbeSerializer(
        required=False,
        allow_null=True,
        help_text=(
            "vali's last synthetic probe of the node, `null` if none reached it yet. "
            "A probe vali could not place on the node is not recorded. Observability "
            "only — a failed probe changes nothing by itself; the launch it made "
            "counts like any launch. Optional during the rollout."
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


class OperatorRegionTierSerializer(serializers.Serializer):
    placeable = serializers.BooleanField(
        help_text="The tier is sold (`launch` would not answer `disk-tier-not-offered`) "
        "and, with the tier gate enforced, `hosts` > 0; otherwise a dispatchable miner "
        "is counted here (placement does not check the tier)."
    )
    hosts = serializers.IntegerField(
        min_value=0,
        help_text="Dispatchable, offering miners of the region with an OS pool at the "
        "tier (a minimum: an nvme pool counts for ssd and hdd), room or not, as of now: "
        "a pool unreported, inactive or degraded for now does not count (feasibility "
        "then answers `not-now`, not `never`).",
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
    failover_capable = serializers.BooleanField(
        help_text="The region holds at least one pair of dispatchable, active, uncordoned "
        "miners of the same SNP generation: a VM placed here with "
        "`require_failover_peer` can be failed over within the region."
    )
    node_ids = serializers.ListField(
        child=serializers.CharField(), help_text="On-chain node_ids of the counted miners."
    )
    os_disk_tiers = serializers.DictField(
        child=OperatorRegionTierSerializer(),
        help_text="Per OS-disk tier (`nvme`, `ssd`, `hdd`): whether a VM sold at it can "
        "be placed in the region, and on how many hosts.",
    )
    dedicated_disks = serializers.DictField(
        required=False,
        help_text="Only while dedicated disks are sold: per tier (`hdd`), `{sizes: "
        "[{size_gb, free, max_per_host}]}` — per size class (GiB, floored to 100), the "
        "free disks a launch could take in the region and the most on one host. "
        "Advisory: the launch is authoritative.",
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
    capacity_source = serializers.ChoiceField(
        choices=["trusted", "declared+earned", "earned", "unknown"],
        required=False,
        help_text=(
            "What the ACTIVE admission model sizes this host from: `trusted` — the "
            "operator anchor; `declared+earned` — an `earned` host, sized by what it "
            "has proven (floor first) clamped by a hardware figure it declared; "
            "`earned` — the same with no hardware figure (proof alone); `unknown` — "
            "vali cannot size it. With VALI_CAPACITY_DECLARED_CEILING on, "
            "`no-hardware-anchor` fires for `earned` and `unknown` only."
        ),
    )
    earned = serializers.DictField(
        required=False,
        help_text=(
            "`{vms, vcpus, memory_mb}` the earned ceiling (floor-resolved; binds only "
            "`earned` hosts), `hardware_ceiling` `{vms, vcpus, memory_mb}` (null per "
            "dimension = no figure) — the most conservative self-reported / anchor "
            "figure, which bounds growth under VALI_CAPACITY_DECLARED_CEILING and "
            "never grants capacity — `declared_at`, `last_reason`, `last_change_at`."
        ),
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
    agent_version = serializers.CharField(
        required=False,
        allow_null=True,
        help_text=(
            "The release tag the miner agent last reported in its heartbeat "
            "(self-reported); null before the first report."
        ),
    )
    latest_agent_release = AgentReleaseSerializer(
        required=False, allow_null=True, help_text=_AGENT_RELEASE_HELP
    )
    update_pending = serializers.BooleanField(
        required=False, allow_null=True, help_text=_UPDATE_PENDING_HELP
    )
    auto_update = AutoUpdateSerializer(required=False, allow_null=True, help_text=_AUTO_UPDATE_HELP)
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
    disk_health = serializers.DictField(
        allow_null=True,
        required=False,
        help_text=(
            "Passive disk health, RECORD ONLY (never a gate): per pool and dedicated "
            "disk, the latest graded hour of the last 48 h — `tier`, `verdict` "
            "(`ok` / `suspect`, null = ungraded), `owners`, `vms`, `suspect_owners`, "
            "median / p90 across owners of the QD>=4 read await (µs) — plus "
            "`worst_verdict`, `latest_hour` and `last_would_reprobe_at` (24 h). "
            "Aggregates only. Null when nothing was graded."
        ),
    )
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
