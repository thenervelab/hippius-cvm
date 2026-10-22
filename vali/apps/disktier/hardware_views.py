"""Operator host-inventory reads: `/v1/operator/miners/{node_id}/…`
(disk-tier design §18.10.4, the providers dashboard's "Hardware" tab,
proxied 1:1 by the backend).

    GET …/hardware             every section of the latest host inventory
    GET …/hardware/history     section changes (which fields), newest first
    GET …/disk-inventory       the storage section + vali's cross-check
    GET …/host-disk-advisories the disk health feed (§18.5), by subject

UNTRUSTED: what the miner reports about its own machine. Every response
says `"verified": false`, and nothing that decides reads it. The one
exception, kept apart in `hardware`'s `attested` block, comes from vali's
ATTESTED sources only (the registered identity and the host attestor's
KBS-certified row), never from the report. Serials and by-id names are the node owner's: they
are served only here, under the same posture as the storage API
(`_NodeStorageView`: operator principal + the acting family re-checked on
chain), and never logged.

A section's `status` is the collector's (`ok`, `partial`, `timeout`,
`unavailable`), or `stale` when its last report is older than its cadence
allows, or `never` when none has arrived (agent too old or opted out).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from django.db.models.functions import Lower
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import serializers
from rest_framework.request import Request
from rest_framework.response import Response

from apps.scheduler import reasons

from .host_advisories import HISTORY_DAYS_MAX, advisories_readout
from .host_inventory import section_status
from .models import (
    DedicatedDisk,
    DedicatedDiskState,
    HostInventoryChange,
    HostInventorySection,
    MinerStoragePool,
)
from .routing import DEFAULT_POOL_ID
from .storage_views import _AUTH_RESPONSES, _COMMON_PARAMS, _error, _NodeStorageView

SECTIONS = ("system", "cpu", "memory", "storage", "network", "pci", "sensors", "software")
HISTORY_DEFAULT = 50
HISTORY_MAX = 200

#: A device role that says vali placed something on it.
_POOL_ROLES = frozenset({"pool_backing", "state_root"})
_DEDICATED_ROLES = frozenset({"dedicated_assigned", "dedicated_free"})
#: Dedicated disks vali no longer expects on the host.
_GONE_DISK_STATES = frozenset({DedicatedDiskState.RETIRED, DedicatedDiskState.REPLACED})
#: …and one vali already knows vanished: not worth a second flag.
_KNOWN_MISSING_STATES = frozenset({DedicatedDiskState.FAILED})


def _section(row: HostInventorySection | None, now: datetime) -> dict[str, Any]:
    if row is None:
        return {"status": "never", "reported_status": None, "reported_at": None, "data": None}
    body = dict(row.body)
    reported = body.pop("status", None)
    return {
        "status": section_status(row, now),
        "reported_status": reported,
        "reported_at": row.reported_at,
        "data": body,
    }


class SectionSerializer(serializers.Serializer):
    status = serializers.CharField(help_text="ok|partial|timeout|unavailable|stale|never")
    reported_status = serializers.CharField(allow_null=True)
    reported_at = serializers.DateTimeField(allow_null=True)
    data = serializers.DictField(
        allow_null=True, help_text="The section as the agent reported it (wire format)."
    )


class PlatformTcbSerializer(serializers.Serializer):
    current = serializers.CharField(
        allow_null=True, help_text="Not tracked by vali yet (always null)."
    )
    reported = serializers.CharField(
        help_text="The platform reported_tcb the KBS certified at enrollment, "
        "as `0x` + 16 hex digits (a 64-bit bitfield: a JSON number would lose bits)."
    )


class AttestedSerializer(serializers.Serializer):
    snp_generation = serializers.CharField(
        allow_null=True, help_text="turin|genoa|milan, from the miner's registration."
    )
    snp_generation_source = serializers.CharField(
        allow_null=True,
        help_text="registered (operator-set) | inferred (from the CHIP_ID length: "
        "a Milan host registered without its generation reads genoa).",
    )
    chip_id_present = serializers.BooleanField(
        help_text="A real CHIP_ID is registered (the id itself is never served)."
    )
    chip_matches_attestor = serializers.BooleanField(
        allow_null=True,
        help_text="The attestor row shown certifies the registered CHIP_ID; null "
        "without a registered chip or an attestor row.",
    )
    platform_tcb = PlatformTcbSerializer(
        allow_null=True, help_text="Only from an attested host attestor."
    )
    attestor_status = serializers.CharField(help_text="attested|pending|missing|stale")
    attestor_gate_reason = serializers.CharField(
        allow_null=True,
        help_text="The dispatchability gate's reason the node is not covered (null = "
        "covered). With no host-attestor release pinned it is release-unpinned for "
        "every node, while attestor_status still judges the row itself.",
    )
    as_of = serializers.DateTimeField(
        allow_null=True, help_text="The attestor's last beacon, else its enrollment."
    )


class HardwareSerializer(serializers.Serializer):
    node_id = serializers.CharField()
    verified = serializers.BooleanField(help_text="Always false: host-reported.")
    reported_at = serializers.DateTimeField(allow_null=True)
    attested = AttestedSerializer(
        help_text="From vali's attested sources, NOT the host's report: shown apart."
    )
    sections = serializers.DictField(child=SectionSerializer())


class HardwareChangeSerializer(serializers.Serializer):
    section = serializers.CharField()
    at = serializers.DateTimeField()
    fields = serializers.ListField(child=serializers.CharField())


class HardwareHistorySerializer(serializers.Serializer):
    node_id = serializers.CharField()
    verified = serializers.BooleanField()
    changes = HardwareChangeSerializer(many=True)


class MismatchSerializer(serializers.Serializer):
    kind = serializers.CharField(
        help_text="pool_not_declared|pool_not_reported|dedicated_not_declared|"
        "dedicated_not_reported"
    )
    device = serializers.CharField(allow_null=True)
    pool_id = serializers.CharField(allow_null=True)
    disk_id = serializers.CharField(allow_null=True)


class DiskInventorySerializer(serializers.Serializer):
    node_id = serializers.CharField()
    verified = serializers.BooleanField()
    status = serializers.CharField()
    reported_at = serializers.DateTimeField(allow_null=True)
    devices = serializers.ListField(child=serializers.DictField())
    devices_truncated = serializers.BooleanField()
    cross_check = serializers.DictField()


def _snp_generation(miner: Any) -> tuple[str | None, str | None]:
    """(generation, source): the registered generation, else the one the
    launch digest infers from the CHIP_ID length; `(None, None)` when
    neither resolves."""
    from apps.orchestration.services.launch_digest import (
        SNP_GENERATION_VCPU,
        _vcpu_type_for_platform,
    )

    if miner.snp_generation:
        return str(miner.snp_generation), "registered"
    try:
        vcpu = _vcpu_type_for_platform(miner.platform_id, None)
    except Exception:  # noqa: BLE001 — a placeholder / malformed id: unknown.
        return None, None
    generation = next((g for g, (v, _n) in SNP_GENERATION_VCPU.items() if v == vcpu), None)
    return generation, ("inferred" if generation else None)


#: The gate's reason for a row → what the dashboard shows.
_ATTESTOR_STATUS = {
    None: "attested",
    reasons.REASON_ATTESTOR_PENDING: "pending",
    reasons.REASON_ATTESTOR_STALE: "stale",
    reasons.REASON_CERT_EXPIRED: "stale",
    reasons.REASON_MEASUREMENT_STALE: "stale",
}


def attested_readout(node_id: str, *, now: datetime) -> dict[str, Any]:
    """The node's ATTESTED facts: the registered identity and the host
    attestor row the dispatchability gate judges (the one that got
    furthest through it, `operator.fleet._attestors`' rule). Nothing from
    the host's own report; never the CHIP_ID itself; the TCB only from an
    attested (KBS-certified, on-chain-checked) row."""
    from datetime import timedelta

    from apps.miners.models import MinerIdentity, is_autoprovision_placeholder
    from apps.operator.service import _attestor_sort_key
    from apps.telemetry import release_service
    from apps.telemetry.models import HostAttestor, HostAttestorStatus
    from apps.telemetry.vm_liveness import chip_matches_platform

    miner = MinerIdentity.objects.filter(chain_node_id__iexact=node_id).first()
    desired = release_service._desired_measurement_set()
    live_cutoff = now - timedelta(seconds=release_service._liveness_window_seconds())

    def reason_of(row: HostAttestor) -> str | None:
        # No release pinned: every node is `release-unpinned` for the gate,
        # but that says nothing of this row; judge the rest of it.
        rows_set = desired or {row.measurement}
        return release_service._row_coverage_reason(
            row, desired_set=rows_set, live_cutoff=live_cutoff
        )

    rank = release_service._REASON_RANK
    best: tuple[tuple[int, Any], HostAttestor, str | None] | None = None
    for row in HostAttestor.objects.filter(node_id__iexact=node_id):
        reason = reason_of(row)
        key = (-1 if reason is None else rank[reason], _attestor_sort_key(row))
        if best is None or key < best[0]:
            best = (key, row, reason)

    chip_registered = bool(
        miner is not None
        and miner.platform_id
        and not is_autoprovision_placeholder(miner.platform_id)
    )
    if best is None:
        status, reason, tcb, as_of, chip_match = (
            "missing",
            reasons.REASON_ATTESTOR_MISSING,
            None,
            None,
            None,
        )
    else:
        _key, row, reason = best
        status = _ATTESTOR_STATUS[reason]
        tcb = (
            {"current": None, "reported": f"0x{int(row.tcb) & (2**64 - 1):016x}"}
            if row.status == HostAttestorStatus.ATTESTED
            else None
        )
        as_of = row.last_seen_at or row.enrolled_at
        chip_match = (
            chip_matches_platform(chip_id_hex=row.chip_id, platform_id=miner.platform_id)
            if chip_registered and miner is not None
            else None
        )
    generation, source = _snp_generation(miner) if miner is not None else (None, None)
    return {
        "snp_generation": generation,
        "snp_generation_source": source,
        "chip_id_present": chip_registered,
        "chip_matches_attestor": chip_match,
        "platform_tcb": tcb,
        "attestor_status": status,
        # The gate itself: with no release pinned every node is unpinned.
        "attestor_gate_reason": reason if desired else reasons.REASON_RELEASE_UNPINNED,
        "as_of": as_of,
    }


def hardware_readout(node_id: str, *, now: datetime) -> dict[str, Any]:
    rows = {r.section: r for r in HostInventorySection.objects.filter(miner_node_id=node_id)}
    return {
        "node_id": node_id,
        "verified": False,
        "reported_at": max((r.reported_at for r in rows.values()), default=None),
        "attested": attested_readout(node_id, now=now),
        "sections": {name: _section(rows.get(name), now) for name in SECTIONS},
    }


#: `software.auto_update.disabled_reason` (`hippius-host-inventory`).
AUTO_UPDATE_DISABLED_REASONS = frozenset(
    {"no_auto_update_file", "disabled_in_env", "timer_disabled"}
)


def _unix_iso(value: Any) -> str | None:
    """A miner-reported unix time as ISO, `None` when it is not one a
    calendar holds: the report is untrusted, and one bad value must never
    fail a request that lists other nodes."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return None
    try:
        return datetime.fromtimestamp(value, tz=UTC).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def _auto_update(body: Any, reported_at: datetime) -> dict[str, Any] | None:
    block = body.get("auto_update") if isinstance(body, dict) else None
    if not isinstance(block, dict) or not isinstance(block.get("enabled"), bool):
        return None
    reason = block.get("disabled_reason")
    failed = block.get("failed_tag")
    return {
        "enabled": block["enabled"],
        "disabled_reason": reason if reason in AUTO_UPDATE_DISABLED_REASONS else None,
        "last_check_at": _unix_iso(block.get("last_check_unix")),
        "failed_tag": failed if isinstance(failed, str) else None,
        "reported_at": reported_at.isoformat(),
    }


def auto_update_by_node(node_ids: list[str]) -> dict[str, dict[str, Any]]:
    """`software.auto_update` of each node's latest host inventory (keys
    lowercase), for the operator rows (`/v1/operator/nodes`, `/fleet`): the
    miner-agent updater's state as the node reports it. UNTRUSTED, display
    only; no serial, no by-id name. A node whose software section carries
    no `auto_update` (collector without `--report-auto-update`, or a source
    it could not read) is absent. ONE query."""
    out: dict[str, dict[str, Any]] = {}
    rows = (
        HostInventorySection.objects.annotate(nid=Lower("miner_node_id"))
        .filter(nid__in=[n.lower() for n in node_ids], section="software")
        .values_list("nid", "body", "reported_at")
    )
    for nid, body, reported_at in rows:
        readout = _auto_update(body, reported_at)
        if readout is not None:
            out[nid] = readout
    return out


def cross_check(
    node_id: str, devices: list[dict[str, Any]], *, complete: bool, truncated: bool
) -> list[dict[str, Any]]:
    """Where the host's own device roles and vali's records disagree.

    - `pool_not_declared`: a device backs a pool vali does not hold;
    - `dedicated_not_declared`: a device the host calls dedicated carries
      no by-id name of a vali dedicated disk (not from a trimmed report:
      its by-id lists may be cut);
    - `pool_not_reported` / `dedicated_not_reported`: vali holds it, no
      device lists it — only from a complete (`ok`, untrimmed) report;
      never the `default` pool (on the state root, the host may not list
      it) nor a disk vali already marks failed."""
    pools = set(
        MinerStoragePool.objects.filter(miner_node_id=node_id, retired_at__isnull=True)
        .exclude(pool_id=DEFAULT_POOL_ID)
        .values_list("pool_id", flat=True)
    )
    disk_states = dict(
        DedicatedDisk.objects.filter(miner_node_id=node_id)
        .exclude(state__in=_GONE_DISK_STATES)
        .values_list("disk_id", "state")
    )

    def mismatch(
        kind: str, *, device: Any = None, pool_id: Any = None, disk_id: Any = None
    ) -> dict[str, Any]:
        return {"kind": kind, "device": device, "pool_id": pool_id, "disk_id": disk_id}

    out: list[dict[str, Any]] = []
    reported_pools: set[str] = set()
    reported_ids: set[str] = set()
    for d in devices:
        ids = set(d.get("ids") or [])
        reported_ids |= ids
        device_pools = set(d.get("pool_ids") or [])
        reported_pools |= device_pools
        if d.get("role") in _POOL_ROLES:
            out += [
                mismatch("pool_not_declared", device=d.get("name"), pool_id=p)
                for p in sorted(device_pools - pools - {DEFAULT_POOL_ID})
            ]
        if d.get("role") in _DEDICATED_ROLES and not truncated and not ids & set(disk_states):
            out.append(mismatch("dedicated_not_declared", device=d.get("name")))
    if complete:
        out += [mismatch("pool_not_reported", pool_id=p) for p in sorted(pools - reported_pools)]
        out += [
            mismatch("dedicated_not_reported", disk_id=k)
            for k in sorted(set(disk_states) - reported_ids)
            if disk_states[k] not in _KNOWN_MISSING_STATES
        ]
    return out


def disk_inventory_readout(node_id: str, *, now: datetime) -> dict[str, Any]:
    row = HostInventorySection.objects.filter(miner_node_id=node_id, section="storage").first()
    section = _section(row, now)
    data = section["data"] or {}
    devices = list(data.get("devices") or [])
    truncated = bool(data.get("devices_truncated", False))
    mismatches = (
        cross_check(
            node_id,
            devices,
            complete=section["status"] == "ok" and not truncated,
            truncated=truncated,
        )
        if row is not None
        else []
    )
    return {
        "node_id": node_id,
        "verified": False,
        "status": section["status"],
        "reported_at": section["reported_at"],
        "devices": devices,
        "devices_truncated": truncated,
        "cross_check": {"mismatches": mismatches},
    }


class OperatorHardwareView(_NodeStorageView):
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="A node's host-reported hardware (not verified)",
        description=(
            "Every section of the latest host inventory (§18.10): system, cpu, memory, "
            "storage, network, pci, sensors, software, each with its status and report "
            "time. Untrusted, owner-only: carries serials."
        ),
        tags=["Operator"],
        parameters=_COMMON_PARAMS,
        responses={200: HardwareSerializer, **_AUTH_RESPONSES},
    )
    def get(self, request: Request, node_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        return Response(hardware_readout(call.node_id, now=timezone.now()))


class OperatorHardwareHistoryView(_NodeStorageView):
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="A node's hardware changes (not verified)",
        description=(
            "Newest first: a section whose content changed, when, and which of its "
            "fields (BIOS updated, DIMM added, kernel changed …). Values are not kept."
        ),
        tags=["Operator"],
        parameters=[
            *_COMMON_PARAMS,
            OpenApiParameter("limit", int, OpenApiParameter.QUERY, description=f"1..{HISTORY_MAX}"),
        ],
        responses={200: HardwareHistorySerializer, **_AUTH_RESPONSES},
    )
    def get(self, request: Request, node_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        limit = history_limit(request)
        if limit is None:
            return _error(400, f"limit is 1..{HISTORY_MAX}", "wire")
        return Response(hardware_history_readout(call.node_id, limit=limit))


def history_limit(request: Request) -> int | None:
    """The history `limit` query parameter (default 50), `None` if invalid."""
    raw = request.query_params.get("limit", str(HISTORY_DEFAULT))
    if not (raw.isascii() and raw.isdigit()) or not 1 <= int(raw) <= HISTORY_MAX:
        return None
    return int(raw)


def hardware_history_readout(node_id: str, *, limit: int) -> dict[str, Any]:
    rows = HostInventoryChange.objects.filter(miner_node_id=node_id).order_by("-at", "-id")[
        :limit
    ]
    return {
        "node_id": node_id,
        "verified": False,
        "changes": [{"section": r.section, "at": r.at, "fields": r.fields} for r in rows],
    }


class OperatorDiskInventoryView(_NodeStorageView):
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="A node's host-reported disks (not verified)",
        description=(
            "The storage section of the latest host inventory: every block device with "
            "its role (§18.9.2) and, `cross_check`, where the host's roles and vali's "
            "pools / dedicated disks disagree. Untrusted, owner-only: by-id names."
        ),
        tags=["Operator"],
        parameters=_COMMON_PARAMS,
        responses={200: DiskInventorySerializer, **_AUTH_RESPONSES},
    )
    def get(self, request: Request, node_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        return Response(disk_inventory_readout(call.node_id, now=timezone.now()))


class AdvisorySerializer(serializers.Serializer):
    code = serializers.CharField()
    severity = serializers.CharField(help_text="info|warning|critical")
    count = serializers.IntegerField()
    value = serializers.IntegerField()
    first_seen = serializers.DateTimeField()
    last_seen = serializers.DateTimeField()
    sample = serializers.CharField(allow_null=True)
    suggested_action = serializers.CharField(
        allow_null=True, help_text="A closed vocabulary the dashboard renders as text."
    )
    resolved_at = serializers.DateTimeField(allow_null=True)


class AdvisorySubjectSerializer(serializers.Serializer):
    kind = serializers.CharField(help_text="pool|dedicated_disk|controller|md|device|collector")
    ref = serializers.CharField()
    severity = serializers.CharField(
        help_text="The worst OPEN advisory: info|warning|critical; `ok` = none open "
        "(not a health verdict — see `collector.status`)."
    )
    advisories = AdvisorySerializer(many=True)


class AdvisoriesSerializer(serializers.Serializer):
    node_id = serializers.CharField()
    verified = serializers.BooleanField()
    reported_at = serializers.DateTimeField(allow_null=True)
    collector = serializers.DictField()
    subjects = AdvisorySubjectSerializer(many=True)
    truncated = serializers.BooleanField()
    history = serializers.ListField(child=serializers.DictField(), required=False)
    history_truncated = serializers.BooleanField(required=False)


class OperatorHostDiskAdvisoriesView(_NodeStorageView):
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="A node's host-reported disk health (not verified)",
        description=(
            "Open disk advisories by subject (pool, dedicated disk, controller, md, "
            "device, collector) with a suggested action; `include_resolved` adds the "
            f"resolved ones, `history_days` (≤ {HISTORY_DAYS_MAX}) the transitions."
        ),
        tags=["Operator"],
        parameters=[
            *_COMMON_PARAMS,
            OpenApiParameter("include_resolved", bool, OpenApiParameter.QUERY),
            OpenApiParameter(
                "history_days", int, OpenApiParameter.QUERY, description=f"0..{HISTORY_DAYS_MAX}"
            ),
        ],
        responses={200: AdvisoriesSerializer, **_AUTH_RESPONSES},
    )
    def get(self, request: Request, node_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        params = advisories_params(request)
        if isinstance(params, str):
            return _error(400, params, "wire")
        include_resolved, history_days = params
        return Response(
            advisories_readout(
                call.node_id,
                include_resolved=include_resolved,
                history_days=history_days,
                now=timezone.now(),
            )
        )


def advisories_params(request: Request) -> tuple[bool, int] | str:
    """`(include_resolved, history_days)` from the query, or the 400 text."""
    include = request.query_params.get("include_resolved", "false").lower()
    if include not in ("true", "false"):
        return "include_resolved is true or false"
    raw = request.query_params.get("history_days", "0")
    if not (raw.isascii() and raw.isdigit()) or int(raw) > HISTORY_DAYS_MAX:
        return f"history_days is 0..{HISTORY_DAYS_MAX}"
    return include == "true", int(raw)
