"""CDN endpoints (docs/design/cdn.md, contract §B). Root-only
(`IsOrchestrationRoot`), like `/v1/network/edges`: the backend calls them
with the orchestration-root token. Every route answers 404 while
`VALI_CDN_ENABLED` is off.

  GET   /v1/cdn/ca.pem                         the CA bundle PEM (every published CA, active first)
  GET   /v1/cdn/nodes                          §B.1 the fleet: CA, fleet keys, nodes
  POST  /v1/cdn/nodes/<node_id>/dns-released   §B.2 the backend removed the node's record
  POST  /v1/cdn/nodes/<node_id>/drain          §B.3 ask for the node's replacement
  GET   /v1/cdn/regions                        §B.4
  PATCH /v1/cdn/regions/<region>               §B.4 desired_nodes, flavor, active

Every GET carries `ETag: "<revision>"` (and answers 304 to a matching
`If-None-Match`). Refusals answer `{"code", "detail"}`.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from django.db import transaction
from django.http import HttpResponse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.cdn import cdn_enabled
from apps.identity import scoping
from apps.orchestration.permissions import IsOrchestrationRoot

from . import ca, reconcile, serialize
from .models import CdnNode, CdnNodeState, CdnRegion, CdnRevision, DrainReason

_TAGS = ["CDN"]


def refuse(code: str, detail: str, http_status: int) -> Response:
    return Response({"code": code, "detail": detail}, status=http_status)


def disabled() -> Response:
    return refuse("cdn-disabled", "the CDN is not enabled", status.HTTP_404_NOT_FOUND)


def etag(revision: int) -> str:
    return f'"{revision}"'


class CdnRootView(APIView):
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated, IsOrchestrationRoot]


class CdnCaBundleView(CdnRootView):
    """`GET /v1/cdn/ca.pem` — the certificates a node certificate may chain
    to: the active CA, a pending one being introduced and a retiring one
    whose certificates are still valid. The backend's node registration
    verifies node certificates against it (`vali_cdn_ca export` prints the
    same bytes)."""

    http_method_names = ["get", "options"]

    @extend_schema(
        summary="CDN CA bundle (PEM)",
        tags=_TAGS,
        responses={
            (200, "application/x-pem-file"): OpenApiResponse(description="PEM bundle."),
            404: OpenApiResponse(description="`cdn-disabled` / `ca-not-initialised`."),
        },
    )
    def get(self, request: Request) -> HttpResponse:
        if not cdn_enabled():
            return disabled()
        revision = CdnRevision.current()
        pem = ca.bundle_pem()
        if not pem:
            return refuse("ca-not-initialised", "no CDN CA exists yet", status.HTTP_404_NOT_FOUND)
        response = HttpResponse(pem, content_type="application/x-pem-file")
        response["ETag"] = etag(revision)
        return response


def _not_modified(request: Request, revision: int) -> HttpResponse | None:
    if request.headers.get("If-None-Match") == etag(revision):
        response = HttpResponse(status=status.HTTP_304_NOT_MODIFIED)
        response["ETag"] = etag(revision)
        return response
    return None


def _with_etag(body: dict[str, Any], revision: int, http_status: int = 200) -> Response:
    response = Response(body, status=http_status)
    response["ETag"] = etag(revision)
    return response


def _body(request: Request) -> dict[str, Any] | None:
    data = request.data
    if data in (None, ""):
        return {}
    return data if isinstance(data, dict) else None


def _node_response(node_id: str) -> Response:
    revision = CdnRevision.current()
    node = CdnNode.objects.select_related("vm").get(node_id=node_id)
    return _with_etag(serialize.node(node), revision)


class CdnNodesView(CdnRootView):
    """`GET /v1/cdn/nodes` — the fleet as the backend routes it (§B.1)."""

    http_method_names = ["get", "options"]

    @extend_schema(summary="CDN fleet", tags=_TAGS)
    def get(self, request: Request) -> HttpResponse:
        if not cdn_enabled():
            return disabled()
        revision = CdnRevision.current()
        cached = _not_modified(request, revision)
        if cached is not None:
            return cached
        return _with_etag(serialize.nodes(revision), revision)


#: §B.2: the ack applies to a node vali asked to remove — draining, or
#: failed (which the backend treats like draining).
_ACKABLE = (CdnNodeState.DRAINING, CdnNodeState.FAILED)


class CdnNodeDnsReleasedView(CdnRootView):
    """`POST /v1/cdn/nodes/<node_id>/dns-released` — the backend removed the
    node's DNS record and Route 53 reports the change INSYNC (§B.2). vali
    decommissions the node `VALI_CDN_DRAIN_GRACE_S` after this, never
    before. Idempotent."""

    http_method_names = ["post", "options"]

    @extend_schema(summary="CDN node DNS released", tags=_TAGS)
    def post(self, request: Request, node_id: str) -> Response:
        if not cdn_enabled():
            return disabled()
        body = _body(request)
        if body is None:
            return refuse("bad-request", "body must be a JSON object", 400)
        # `null` is "no Route 53 change": the backend sends it for a node
        # that never had a record (§B.2), like an absent field.
        change_id = body.get("change_id")
        if change_id is None:
            change_id = ""
        insync_raw = body.get("insync_at")
        revision_seen = body.get("revision_seen")
        if not isinstance(change_id, str) or len(change_id) > 256:
            return refuse("bad-request", "change_id must be a string", 400)
        if revision_seen is not None and (
            isinstance(revision_seen, bool) or not isinstance(revision_seen, int)
        ):
            return refuse("bad-request", "revision_seen must be an integer", 400)
        insync_at: dt.datetime | None = None
        if insync_raw is not None:
            insync_at = parse_datetime(insync_raw) if isinstance(insync_raw, str) else None
            if insync_at is None or insync_at.tzinfo is None:
                return refuse("bad-request", "insync_at must be an ISO 8601 timestamp", 400)
        now = timezone.now()
        with transaction.atomic():
            node = CdnNode.objects.select_for_update().filter(node_id=node_id).first()
            if node is None:
                return refuse("node-not-found", "no such CDN node", 404)
            if node.dns_released_at is None:
                if node.state not in _ACKABLE:
                    return refuse("not-draining", f"node {node_id} is {node.state}", 409)
                # The grace runs from when vali got the ack, never from an
                # earlier time the body claims.
                node.dns_released_at = now
                node.dns_release_change_id = change_id
                node.dns_release_revision_seen = revision_seen
                node.save(
                    update_fields=[
                        "dns_released_at",
                        "dns_release_change_id",
                        "dns_release_revision_seen",
                        "updated_at",
                    ]
                )
                CdnRevision.bump()
        return _node_response(node_id)


class CdnNodeDrainView(CdnRootView):
    """`POST /v1/cdn/nodes/<node_id>/drain` — ask for the node's replacement
    (§B.3). vali launches the replacement first, then drains the node."""

    http_method_names = ["post", "options"]

    @extend_schema(summary="Drain a CDN node", tags=_TAGS)
    def post(self, request: Request, node_id: str) -> Response:
        if not cdn_enabled():
            return disabled()
        body = _body(request)
        if body is None:
            return refuse("bad-request", "body must be a JSON object", 400)
        reason = body.get("reason", DrainReason.OPERATOR)
        if reason not in (DrainReason.OPERATOR, DrainReason.REPLACE):
            return refuse("bad-request", "reason must be 'operator' or 'replace'", 400)
        try:
            reconcile.request_drain(node_id, reason)
        except LookupError:
            return refuse("node-not-found", "no such CDN node", 404)
        except ValueError:
            state = CdnNode.objects.filter(node_id=node_id).values_list("state", flat=True).first()
            return refuse("not-drainable", f"node {node_id} is {state}", 409)
        return _node_response(node_id)


class CdnRegionsView(CdnRootView):
    """`GET /v1/cdn/regions` (§B.4)."""

    http_method_names = ["get", "options"]

    @extend_schema(summary="CDN regions", tags=_TAGS)
    def get(self, request: Request) -> HttpResponse:
        if not cdn_enabled():
            return disabled()
        revision = CdnRevision.current()
        cached = _not_modified(request, revision)
        if cached is not None:
            return cached
        regions = [serialize.region(r) for r in CdnRegion.objects.all()]
        return _with_etag({"revision": revision, "regions": regions}, revision)


_MAX_DESIRED = 64


class CdnRegionView(CdnRootView):
    """`PATCH /v1/cdn/regions/<region>` — `desired_nodes`, `flavor`, `active`
    (§B.4). An operator creates the region with `vali_cdn_region`."""

    http_method_names = ["patch", "options"]

    @extend_schema(summary="Set a CDN region's target", tags=_TAGS)
    def patch(self, request: Request, region: str) -> Response:
        from apps.orchestration.services.flavors import is_offered

        if not cdn_enabled():
            return disabled()
        body = _body(request)
        if body is None or not body or set(body) - {"desired_nodes", "flavor", "active"}:
            return refuse("bad-request", "body takes desired_nodes, flavor and active only", 400)
        desired = body.get("desired_nodes")
        if desired is not None and (
            isinstance(desired, bool)
            or not isinstance(desired, int)
            or not 0 <= desired <= _MAX_DESIRED
        ):
            return refuse("bad-request", f"desired_nodes must be in 0..{_MAX_DESIRED}", 400)
        active = body.get("active")
        if active is not None and not isinstance(active, bool):
            return refuse("bad-request", "active must be a boolean", 400)
        flavor = body.get("flavor")
        if flavor is not None:
            if not isinstance(flavor, str) or not is_offered(flavor):
                return refuse("bad-request", "flavor is not offered", 400)
        with transaction.atomic():
            row = CdnRegion.objects.select_for_update().filter(region=region.upper()).first()
            if row is None:
                return refuse("region-not-found", "no such CDN region", 404)
            for key, value in (("desired_nodes", desired), ("flavor", flavor), ("active", active)):
                if value is not None:
                    setattr(row, key, value)
            row.save()
            CdnRevision.bump()
        return _with_etag(serialize.region(row), CdnRevision.current())
