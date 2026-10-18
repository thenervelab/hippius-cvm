"""Operator host-inventory reads: `/v1/operator/miners/{node_id}/…`
(disk-tier design §18.10.4, the providers dashboard's "Hardware" tab,
proxied 1:1 by the backend).

    GET …/hardware             every section of the latest host inventory
    GET …/hardware/history     section changes (which fields), newest first
    GET …/disk-inventory       the storage section + vali's cross-check
    GET …/host-disk-advisories the disk health feed (§18.5), by subject

UNTRUSTED: what the miner reports about its own machine. Every response
says `"verified": false`; nothing here comes from attestation, and nothing
that decides reads it. Serials and by-id names are the node owner's: they
are served only here, under the same posture as the storage API
(`_NodeStorageView`: operator principal + the acting family re-checked on
chain), and never logged.

A section's `status` is the collector's (`ok`, `partial`, `timeout`,
`unavailable`), or `stale` when its last report is older than its cadence
allows, or `never` when none has arrived (agent too old or opted out).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import serializers
from rest_framework.request import Request
from rest_framework.response import Response

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


class HardwareSerializer(serializers.Serializer):
    node_id = serializers.CharField()
    verified = serializers.BooleanField(help_text="Always false: host-reported.")
    reported_at = serializers.DateTimeField(allow_null=True)
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


def hardware_readout(node_id: str, *, now: datetime) -> dict[str, Any]:
    rows = {r.section: r for r in HostInventorySection.objects.filter(miner_node_id=node_id)}
    return {
        "node_id": node_id,
        "verified": False,
        "reported_at": max((r.reported_at for r in rows.values()), default=None),
        "sections": {name: _section(rows.get(name), now) for name in SECTIONS},
    }


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
        raw = request.query_params.get("limit", str(HISTORY_DEFAULT))
        if not (raw.isascii() and raw.isdigit()) or not 1 <= int(raw) <= HISTORY_MAX:
            return _error(400, f"limit is 1..{HISTORY_MAX}", "wire")
        rows = HostInventoryChange.objects.filter(miner_node_id=call.node_id).order_by(
            "-at", "-id"
        )[: int(raw)]
        return Response(
            {
                "node_id": call.node_id,
                "verified": False,
                "changes": [{"section": r.section, "at": r.at, "fields": r.fields} for r in rows],
            }
        )


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
        include = request.query_params.get("include_resolved", "false").lower()
        if include not in ("true", "false"):
            return _error(400, "include_resolved is true or false", "wire")
        raw = request.query_params.get("history_days", "0")
        if not (raw.isascii() and raw.isdigit()) or int(raw) > HISTORY_DAYS_MAX:
            return _error(400, f"history_days is 0..{HISTORY_DAYS_MAX}", "wire")
        return Response(
            advisories_readout(
                call.node_id,
                include_resolved=include == "true",
                history_days=int(raw),
                now=timezone.now(),
            )
        )
