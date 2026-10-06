"""Public-IP and ingress-edge endpoints.

Every route here is root-only (`IsOrchestrationRoot`, `OPERATOR_ONLY`),
the same gate as the VM power operations: attaching an address changes
where a tenant VM's traffic goes, and the edge routes hand out the
address ↔ VM table. The ingress edges themselves never call vali — the
layer above fetches their desired state here and relays their reports.

  GET|POST|DELETE /v1/vm/<vm_id>/public-ip
  GET  /v1/network/availability[?region=XX]
  GET|POST /v1/network/edges
  GET|PATCH|DELETE /v1/network/edges/<name>
  POST|DELETE /v1/network/edges/<name>/addresses
  GET  /v1/network/edges/<name>/desired
  POST /v1/network/edges/<name>/applied

Refusals answer `{"error": <stable code>, "detail": <text>}`.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from django.db import IntegrityError, transaction
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.identity import scoping
from apps.lifecycle.models import Vm
from apps.orchestration.permissions import IsOrchestrationRoot
from apps.scheduler.placement import REGION_RE

from . import service
from .models import EdgeStatus, IngressEdge
from .schemas import (
    AppliedRequestSerializer,
    AttachRequestSerializer,
    AvailabilitySerializer,
    DesiredStateSerializer,
    EdgeAddressesRequestSerializer,
    EdgeCreateRequestSerializer,
    EdgeListSerializer,
    EdgePatchRequestSerializer,
    EdgeSerializer,
    NetworkErrorSerializer,
    PublicIpSerializer,
)
from .service import NetworkError

log = logging.getLogger("apps.network")

_TAGS = ["Public IPs"]
_MAX_ADDRESSES_PER_CALL = 256
_MAX_PER_IP_MBPS = 100_000
_EDGE_NAME_MAX = 28
#: Ends up in NetBird object names; see `IngressEdge.name`.
_EDGE_NAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,26}[a-z0-9])?")

_ERROR_STATUS = {
    "vm-not-found": status.HTTP_404_NOT_FOUND,
    "edge-not-found": status.HTTP_404_NOT_FOUND,
    "no-public-ip": status.HTTP_404_NOT_FOUND,
    "address-not-found": status.HTTP_404_NOT_FOUND,
    "no-free-public-ip": status.HTTP_409_CONFLICT,
    "vm-not-live": status.HTTP_409_CONFLICT,
    "edge-exists": status.HTTP_409_CONFLICT,
    "address-taken": status.HTTP_409_CONFLICT,
    "address-unavailable": status.HTTP_409_CONFLICT,
    "address-not-free": status.HTTP_409_CONFLICT,
    "edge-has-attached-ips": status.HTTP_409_CONFLICT,
    "edge-has-quarantined-ips": status.HTTP_409_CONFLICT,
    "revision-ahead": status.HTTP_409_CONFLICT,
    "netbird-unavailable": status.HTTP_503_SERVICE_UNAVAILABLE,
}


def _refuse(exc: NetworkError) -> Response:
    return Response(
        {"error": exc.code, "detail": exc.detail},
        status=_ERROR_STATUS.get(exc.code, status.HTTP_400_BAD_REQUEST),
    )


def _body(request: Request) -> dict[str, Any]:
    data = request.data
    if data in (None, ""):
        return {}
    if not isinstance(data, dict):
        raise NetworkError("bad-request", "body must be a JSON object")
    return data


def _region(raw: Any) -> str:
    if raw is None or raw == "":
        return ""
    if not isinstance(raw, str) or not REGION_RE.fullmatch(raw):
        raise NetworkError("bad-region", "region must be an ISO 3166-1 alpha-2 code (e.g. 'FR')")
    return raw.upper()


def _addresses(raw: Any) -> list[str]:
    if not isinstance(raw, list) or not raw:
        raise NetworkError("bad-address", "addresses must be a non-empty list")
    if len(raw) > _MAX_ADDRESSES_PER_CALL:
        raise NetworkError("bad-address", f"at most {_MAX_ADDRESSES_PER_CALL} addresses per call")
    return sorted({service.parse_public_address(a) for a in raw})


def _per_ip_mbps(raw: Any) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not 1 <= raw <= _MAX_PER_IP_MBPS:
        raise NetworkError(
            "bad-request", f"per_ip_mbps must be an integer in 1..{_MAX_PER_IP_MBPS}"
        )
    return raw


def _provider(raw: Any) -> str:
    if not isinstance(raw, str) or len(raw) > 64:
        raise NetworkError("bad-request", "provider must be a string of at most 64 characters")
    return raw.strip()


def _edge_name(raw: Any) -> str:
    if not isinstance(raw, str) or not _EDGE_NAME_RE.fullmatch(raw):
        raise NetworkError(
            "bad-name",
            f"name must be 1..{_EDGE_NAME_MAX} of [a-z0-9-], not starting or ending with '-'",
        )
    return raw


def _get_vm(vm_id: str) -> Vm:
    vm = Vm.objects.filter(vm_id=vm_id).first()
    if vm is None:
        raise NetworkError("vm-not-found", "vm not found")
    return vm


def _get_edge(name: str) -> IngressEdge:
    edge = IngressEdge.objects.filter(name=name).first()
    if edge is None:
        raise NetworkError("edge-not-found", "edge not found")
    return edge


class _RootView(APIView):
    # P2 object-level authorization: a tenant VM's public address and the
    # fleet's edges — root principal only.
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated, IsOrchestrationRoot]


_VM_ID = OpenApiParameter("vm_id", str, OpenApiParameter.PATH)
_EDGE = OpenApiParameter("name", str, OpenApiParameter.PATH, description="Edge name.")
_COMMON = {
    403: OpenApiResponse(NetworkErrorSerializer, "Not the orchestration root principal."),
}


class VmPublicIpView(_RootView):
    """`/v1/vm/<vm_id>/public-ip` — read, attach, detach."""

    http_method_names = ["get", "post", "delete", "options"]

    @extend_schema(
        summary="The VM's public IPv4 address",
        tags=_TAGS,
        parameters=[_VM_ID],
        responses={
            200: PublicIpSerializer,
            404: OpenApiResponse(NetworkErrorSerializer, "`vm-not-found` / `no-public-ip`."),
            **_COMMON,
        },
    )
    def get(self, request: Request, vm_id: str) -> Response:
        try:
            ip = service.get_attached(_get_vm(vm_id))
            if ip is None:
                raise NetworkError("no-public-ip", "the vm has no public address")
        except NetworkError as exc:
            return _refuse(exc)
        return Response(service.public_ip_view(ip))

    @extend_schema(
        summary="Attach a public IPv4 address to the VM",
        description=(
            "Idempotent: a VM that already holds an address gets it back with 200. "
            "The edge is chosen in the region the VM runs in, else `region`, else the "
            "region its launch asked for, else any other region of the same zone (EU, "
            "APAC, NA) — never one in another zone; a region with no zone gets an exact "
            "match only, and `no-free-public-ip` when that is full. In each tier an "
            "address the VM's tenant released and that is still in quarantine comes back "
            "first (the most recently released), then a free one on the edge with the "
            "most free addresses. A quarantined address never goes to another tenant. "
            "`address` asks for one specific address instead: free, or quarantined from "
            "this tenant, and in the VM's zone — anything else is `address-unavailable`. "
            "The address carries "
            "traffic once the VM's NetBird peer is resolved (the next orchestration tick)."
        ),
        tags=_TAGS,
        parameters=[_VM_ID],
        request=AttachRequestSerializer,
        responses={
            200: OpenApiResponse(PublicIpSerializer, "Already attached."),
            201: OpenApiResponse(PublicIpSerializer, "Attached."),
            400: OpenApiResponse(NetworkErrorSerializer, "`bad-region` / `bad-address`."),
            404: OpenApiResponse(NetworkErrorSerializer, "`vm-not-found`."),
            409: OpenApiResponse(
                NetworkErrorSerializer,
                "`no-free-public-ip` / `vm-not-live` / `address-unavailable`.",
            ),
            **_COMMON,
        },
    )
    def post(self, request: Request, vm_id: str) -> Response:
        try:
            body = _body(request)
            region = _region(body.get("region"))
            raw_address = body.get("address")
            address = (
                "" if raw_address in (None, "") else service.parse_public_address(raw_address)
            )
            ip, created = service.attach(_get_vm(vm_id), region, address)
        except NetworkError as exc:
            return _refuse(exc)
        return Response(
            service.public_ip_view(ip),
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    @extend_schema(
        summary="Detach the VM's public IPv4 address",
        description=(
            "The address stops carrying traffic on the edge's next render and is "
            "held out of the pool for the quarantine window."
        ),
        tags=_TAGS,
        parameters=[_VM_ID],
        request=None,
        responses={
            204: OpenApiResponse(description="Detached."),
            404: OpenApiResponse(NetworkErrorSerializer, "`vm-not-found` / `no-public-ip`."),
            **_COMMON,
        },
    )
    def delete(self, request: Request, vm_id: str) -> Response:
        try:
            if service.detach(_get_vm(vm_id)) is None:
                raise NetworkError("no-public-ip", "the vm has no public address")
        except NetworkError as exc:
            return _refuse(exc)
        return Response(status=status.HTTP_204_NO_CONTENT)


class AvailabilityView(_RootView):
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Free public addresses per region",
        description=(
            "Active edges only. Without `region`, `total_free` counts every region. With "
            "one, it counts what an attach for a VM there can reach: that region and the "
            "rest of its zone (EU, APAC, NA), or that region alone when it has no zone; "
            "`regions` is filtered to `region`."
        ),
        tags=_TAGS,
        parameters=[OpenApiParameter("region", str, OpenApiParameter.QUERY, required=False)],
        responses={200: AvailabilitySerializer, 400: NetworkErrorSerializer, **_COMMON},
    )
    def get(self, request: Request) -> Response:
        try:
            region = _region(request.query_params.get("region"))
        except NetworkError as exc:
            return _refuse(exc)
        return Response(service.availability(region))


class EdgeListView(_RootView):
    http_method_names = ["get", "post", "options"]

    @extend_schema(
        summary="List ingress edges",
        tags=_TAGS,
        responses={200: EdgeListSerializer, **_COMMON},
    )
    def get(self, request: Request) -> Response:
        return Response({"edges": [service.edge_view(e) for e in IngressEdge.objects.all()]})

    @extend_schema(
        summary="Register an ingress edge",
        description=(
            "The edge must already be a NetBird peer: its peer is found by "
            "`netbird_ip`. Its exit routing is created by the next orchestration tick. "
            "`netbird_ip` may be omitted: the edge is then created UNBOUND (`bound: "
            "false`) — it takes no attachment, gets no routing and is served no "
            "address until `PATCH {\"netbird_ip\"}` binds it."
        ),
        tags=_TAGS,
        request=EdgeCreateRequestSerializer,
        responses={
            201: EdgeSerializer,
            400: OpenApiResponse(
                NetworkErrorSerializer,
                "Invalid field, `netbird-peer-not-found` or `netbird-peer-not-an-edge`.",
            ),
            409: OpenApiResponse(NetworkErrorSerializer, "`edge-exists` / `address-taken`."),
            503: OpenApiResponse(NetworkErrorSerializer, "`netbird-unavailable`."),
            **_COMMON,
        },
    )
    def post(self, request: Request) -> Response:
        try:
            body = _body(request)
            name = _edge_name(body.get("name"))
            region = _region(body.get("region"))
            if not region:
                raise NetworkError("bad-region", "region is required")
            # Optional: an edge is registered BEFORE it can enrol in NetBird
            # (its setup key is minted for an existing edge), then bound with
            # PATCH `netbird_ip`. Until then it is unbound — see the model.
            raw_ip = body.get("netbird_ip")
            netbird_ip = service.parse_overlay_address(raw_ip) if raw_ip else None
            provider = _provider(body.get("provider", ""))
            per_ip_mbps = _per_ip_mbps(body.get("per_ip_mbps", 1000))
            addresses = _addresses(body.get("addresses")) if body.get("addresses") else []
            if IngressEdge.objects.filter(name=name).exists():
                raise NetworkError("edge-exists", f"edge {name!r} already exists")
            peer_id = service.resolve_edge_peer(netbird_ip).id if netbird_ip else ""
            try:
                with transaction.atomic():
                    edge = IngressEdge.objects.create(
                        name=name,
                        provider=provider,
                        region=region,
                        netbird_ip=netbird_ip,
                        netbird_peer_id=peer_id,
                        per_ip_mbps=per_ip_mbps,
                    )
                    if addresses:
                        service.add_addresses(edge, addresses)
            except IntegrityError as exc:
                raise NetworkError(
                    "edge-exists", "an edge with this name or NetBird address exists"
                ) from exc
        except NetworkError as exc:
            return _refuse(exc)
        # The routing itself is created by the next orchestration tick: the
        # tick is the single writer of NetBird routing state, so two
        # processes never race to create the same group.
        service.request_netbird_sync()
        return Response(service.edge_view(edge), status=status.HTTP_201_CREATED)


class EdgeDetailView(_RootView):
    http_method_names = ["get", "patch", "delete", "options"]

    @extend_schema(
        summary="One ingress edge",
        tags=_TAGS,
        parameters=[_EDGE],
        responses={200: EdgeSerializer, 404: NetworkErrorSerializer, **_COMMON},
    )
    def get(self, request: Request, name: str) -> Response:
        try:
            return Response(service.edge_view(_get_edge(name)))
        except NetworkError as exc:
            return _refuse(exc)

    @extend_schema(
        summary="Update an edge's status, rate cap or provider, or re-bind its peer",
        description=(
            "`draining` and `disabled` stop new attachments; addresses already "
            "attached keep working. `netbird_ip` re-binds the edge to the NetBird "
            "peer now holding that address — the only way an edge's peer changes "
            "(after a re-enrolment); the reconcile loop never re-binds on its own."
        ),
        tags=_TAGS,
        parameters=[_EDGE],
        request=EdgePatchRequestSerializer,
        responses={
            200: EdgeSerializer,
            400: NetworkErrorSerializer,
            404: NetworkErrorSerializer,
            409: OpenApiResponse(NetworkErrorSerializer, "`edge-exists`."),
            503: OpenApiResponse(NetworkErrorSerializer, "`netbird-unavailable`."),
            **_COMMON,
        },
    )
    def patch(self, request: Request, name: str) -> Response:
        try:
            body = _body(request)
            unknown = set(body) - {"status", "per_ip_mbps", "provider", "netbird_ip"}
            if unknown:
                raise NetworkError("bad-request", f"unknown fields: {sorted(unknown)}")
            with transaction.atomic():
                edge = IngressEdge.objects.select_for_update().filter(name=name).first()
                if edge is None:
                    raise NetworkError("edge-not-found", "edge not found")
                fields: list[str] = []
                if "status" in body:
                    if body["status"] not in EdgeStatus.values:
                        raise NetworkError(
                            "bad-request", f"status must be one of {sorted(EdgeStatus.values)}"
                        )
                    edge.status = body["status"]
                    fields.append("status")
                if "provider" in body:
                    edge.provider = _provider(body["provider"])
                    fields.append("provider")
                if "netbird_ip" in body:
                    edge.netbird_ip = service.parse_overlay_address(body["netbird_ip"])
                    edge.netbird_peer_id = service.resolve_edge_peer(edge.netbird_ip).id
                    fields += ["netbird_ip", "netbird_peer_id"]
                rate_changed = False
                if "per_ip_mbps" in body:
                    mbps = _per_ip_mbps(body["per_ip_mbps"])
                    rate_changed = mbps != edge.per_ip_mbps
                    edge.per_ip_mbps = mbps
                    fields.append("per_ip_mbps")
                if fields:
                    try:
                        with transaction.atomic():
                            edge.save(update_fields=[*fields, "updated_at"])
                    except IntegrityError as exc:
                        raise NetworkError(
                            "edge-exists", "another edge has this NetBird address"
                        ) from exc
                if rate_changed:
                    service.bump_revision(edge.pk)
            if "netbird_ip" in body:
                service.request_netbird_sync()
        except NetworkError as exc:
            return _refuse(exc)
        edge.refresh_from_db()
        return Response(service.edge_view(edge))

    @extend_schema(
        summary="Delete an edge and its address pool",
        tags=_TAGS,
        parameters=[_EDGE],
        request=None,
        responses={
            204: OpenApiResponse(description="Deleted."),
            404: NetworkErrorSerializer,
            409: OpenApiResponse(
                NetworkErrorSerializer, "`edge-has-attached-ips` / `edge-has-quarantined-ips`."
            ),
            503: OpenApiResponse(NetworkErrorSerializer, "`netbird-unavailable`."),
            **_COMMON,
        },
    )
    def delete(self, request: Request, name: str) -> Response:
        from apps.orchestration import effects

        try:
            edge = _get_edge(name)
            service.check_edge_deletable(edge)
            # NetBird first: once the row is gone nothing would know to
            # retry a failed cleanup. (A pass of the reconcile loop that
            # races this is swept by its own garbage collection.)
            if edge.bound:
                try:
                    effects.remove_edge_routing(name)
                except effects.EffectError as exc:
                    raise NetworkError("netbird-unavailable", str(exc)) from exc
            service.delete_edge(edge)
        except NetworkError as exc:
            return _refuse(exc)
        return Response(status=status.HTTP_204_NO_CONTENT)


class EdgeAddressesView(_RootView):
    http_method_names = ["post", "delete", "options"]

    @extend_schema(
        summary="Add addresses to an edge's pool",
        tags=_TAGS,
        parameters=[_EDGE],
        request=EdgeAddressesRequestSerializer,
        responses={
            200: EdgeSerializer,
            400: NetworkErrorSerializer,
            404: NetworkErrorSerializer,
            409: OpenApiResponse(NetworkErrorSerializer, "`address-taken`."),
            **_COMMON,
        },
    )
    def post(self, request: Request, name: str) -> Response:
        try:
            edge = _get_edge(name)
            addresses = _addresses(_body(request).get("addresses"))
            try:
                service.add_addresses(edge, addresses)
            except IntegrityError as exc:
                raise NetworkError("address-taken", "an address was taken concurrently") from exc
        except NetworkError as exc:
            return _refuse(exc)
        return Response(service.edge_view(edge))

    @extend_schema(
        summary="Remove free addresses from an edge's pool",
        description="All or nothing: refused if any address is attached or quarantined.",
        tags=_TAGS,
        parameters=[_EDGE],
        request=EdgeAddressesRequestSerializer,
        responses={
            200: EdgeSerializer,
            400: NetworkErrorSerializer,
            404: NetworkErrorSerializer,
            409: OpenApiResponse(NetworkErrorSerializer, "`address-not-free`."),
            **_COMMON,
        },
    )
    def delete(self, request: Request, name: str) -> Response:
        try:
            edge = _get_edge(name)
            service.remove_addresses(edge, _addresses(_body(request).get("addresses")))
        except NetworkError as exc:
            return _refuse(exc)
        return Response(service.edge_view(edge))


class EdgeDesiredView(_RootView):
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="What the edge must render",
        description="Attached addresses whose VM NetBird address is known.",
        tags=_TAGS,
        parameters=[_EDGE],
        responses={200: DesiredStateSerializer, 404: NetworkErrorSerializer, **_COMMON},
    )
    def get(self, request: Request, name: str) -> Response:
        try:
            return Response(service.desired_state(_get_edge(name)))
        except NetworkError as exc:
            return _refuse(exc)


class EdgeAppliedView(_RootView):
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="The edge applied a revision",
        tags=_TAGS,
        parameters=[_EDGE],
        request=AppliedRequestSerializer,
        responses={
            204: OpenApiResponse(description="Recorded."),
            400: NetworkErrorSerializer,
            404: NetworkErrorSerializer,
            409: OpenApiResponse(NetworkErrorSerializer, "`revision-ahead`."),
            **_COMMON,
        },
    )
    def post(self, request: Request, name: str) -> Response:
        try:
            edge = _get_edge(name)
            body = _body(request)
            revision = body.get("revision")
            report = body.get("report", {})
            if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
                raise NetworkError("bad-request", "revision must be a non-negative integer")
            if not isinstance(report, dict):
                raise NetworkError("bad-request", "report must be a JSON object")
            service.record_applied(edge, revision, report)
        except NetworkError as exc:
            return _refuse(exc)
        return Response(status=status.HTTP_204_NO_CONTENT)
