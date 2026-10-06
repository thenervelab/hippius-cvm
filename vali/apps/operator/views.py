"""Operator node-status endpoints.

  GET /v1/operator/fleet[?chain=true|false]
      Same auth + scope. The WHOLE fleet in one response, for Hippius
      staff (the upstream exposes it to superusers only): per miner the
      scheduler's own dispatchability, capacity, attestor, CVM start
      capability, zombie state, chain status + price, epoch usage, and
      the hosted VMs by id. `chain=false` skips the one chain read.
      → 200 {miners, totals, chain, …} / 400 wire / 401 / 403.

  GET /v1/operator/regions[?verified_only=true|false]
      Same auth + scope. The regions vali has DETECTED miners in (ISO
      3166-1 alpha-2, from `vali_geo_probe` — nothing declared), with the
      count of verified / dispatchable miners and the capacity they add up
      to. What a `region`-constrained launch can land on.
      → 200 {regions, unlocated_miners, …} / 400 wire / 401 / 403.

  GET /v1/operator/nodes?node_id=<hex>&node_id=<hex>…
      Auth: any classified service principal (the upstream product API);
      operator-only scope — no tenant object is served.
      `node_id` repeatable, 1..100 values, each 64 hex chars (case-
      insensitive). Returns one row per node vali knows; an unknown
      `node_id` is silently absent (nothing is confirmed about ids the
      caller did not already hold).
      → 200 {nodes, count} / 400 wire / 401 / 403.

The upstream API resolves WHICH node_ids a signed-in operator may see
(on chain, `FamilyChildren`) before calling this; vali only answers "what
is the state of these nodes". By design there is NO per-family check
here: the caller is a service principal (mTLS / `ServiceToken`,
`OPERATOR_ONLY` scope), not an end user, and vali keeps no family table —
the chain ACL lives in exactly one place, upstream. No tenant data crosses
this surface.
"""

from __future__ import annotations

import re

from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.schemas import ErrorSerializer
from apps.identity import scoping

from .fleet import operator_fleet
from .schemas import OperatorFleetSerializer, OperatorNodesSerializer, OperatorRegionsSerializer
from .service import MAX_NODE_IDS, operator_node_rows, operator_region_rows

_NODE_ID_HEX_LEN = 64
# Exactly 64 lower-case hex digits — nothing else. `bytes.fromhex` was NOT
# used on purpose: it accepts whitespace between byte pairs, and a `strip()`
# would silently repair padded input.
_NODE_ID_RE = re.compile(r"[0-9a-f]{64}")


def _error(http_status: int, message: str, category: str) -> Response:
    return Response({"error": message, "category": category}, status=http_status)


def _parse_node_ids(raw: list[str]) -> list[str]:
    """Validate the repeated `node_id` query values. Raises `ValueError`
    with the wire message on any refusal."""
    if not raw:
        raise ValueError("at least one node_id is required")
    if len(raw) > MAX_NODE_IDS:
        raise ValueError(f"at most {MAX_NODE_IDS} node_id values per request")
    out: list[str] = []
    for value in raw:
        candidate = value.lower()
        if not _NODE_ID_RE.fullmatch(candidate):
            raise ValueError(f"node_id must be exactly {_NODE_ID_HEX_LEN} hex chars")
        out.append(candidate)
    return out


class OperatorNodesView(APIView):
    """`GET /v1/operator/nodes` — per-node status for an operator dashboard."""

    # P2 object-level authorization: fleet/node operational state — not a
    # tenant object; tenant principals are refused before the view runs.
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Node status for an operator dashboard",
        description=(
            "One row per requested on-chain `node_id`: registry status + last "
            "heartbeat, host-attestor state, `schedulable` (the scheduler's own "
            "dispatchability predicate) with the failing gate as `schedulable_reason`, "
            "active placement count, effective capacity, and the most recent failed "
            "placements. Unknown node_ids are absent from the response. No tenant data."
        ),
        tags=["Operator"],
        parameters=[
            OpenApiParameter(
                "node_id",
                str,
                OpenApiParameter.QUERY,
                many=True,
                required=True,
                description=f"On-chain node_id (64 hex). Repeatable, max {MAX_NODE_IDS}.",
            ),
        ],
        responses={
            200: OperatorNodesSerializer,
            400: OpenApiResponse(ErrorSerializer, "Missing / malformed / too many node_id."),
            401: OpenApiResponse(ErrorSerializer, "No / invalid service credential."),
            403: OpenApiResponse(ErrorSerializer, "Not an operator principal."),
        },
    )
    def get(self, request: Request) -> Response:
        try:
            node_ids = _parse_node_ids(request.query_params.getlist("node_id"))
        except ValueError as exc:
            return _error(status.HTTP_400_BAD_REQUEST, str(exc), "wire")
        rows = operator_node_rows(node_ids)
        return Response({"nodes": rows, "count": len(rows)}, status=status.HTTP_200_OK)


_BOOL = {"true": True, "1": True, "yes": True, "false": False, "0": False, "no": False}


class OperatorRegionsView(APIView):
    """`GET /v1/operator/regions` — where the fleet is, as measured."""

    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Regions with detected miners, for a region-aware seller",
        description=(
            "One row per ISO 3166-1 alpha-2 country in which `vali_geo_probe` has "
            "DETECTED at least one miner — from the public IP its NetBird peer connects "
            "from, GeoIP/ASN of that IP, the round-trip time vali measures to it and the "
            "egress IP its tenant CVMs report. Nothing is declared by a miner. "
            "`miners_total`/`miners_verified` count every located miner; `node_ids`, "
            "`miners_dispatchable`, `hosted_vm_count` and `capacity` cover only the miners "
            "a `region`-constrained launch may use (verified ones, unless "
            "`verified_only=false`). `unlocated_miners` is how many registered miners have "
            "no location yet. No tenant data."
        ),
        tags=["Operator"],
        parameters=[
            OpenApiParameter(
                "verified_only",
                bool,
                OpenApiParameter.QUERY,
                required=False,
                description=(
                    "Count only miners whose location verdict is `verified` "
                    "(default: the server's `VALI_GEO_REQUIRE_VERIFIED`)."
                ),
            ),
        ],
        responses={
            200: OperatorRegionsSerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed verified_only."),
            401: OpenApiResponse(ErrorSerializer, "No / invalid service credential."),
            403: OpenApiResponse(ErrorSerializer, "Not an operator principal."),
        },
    )
    def get(self, request: Request) -> Response:
        raw = request.query_params.get("verified_only")
        verified_only: bool | None = None
        if raw is not None:
            if raw.strip().lower() not in _BOOL:
                return _error(
                    status.HTTP_400_BAD_REQUEST, "verified_only must be true or false", "wire"
                )
            verified_only = _BOOL[raw.strip().lower()]
        return Response(
            operator_region_rows(verified_only=verified_only), status=status.HTTP_200_OK
        )


class OperatorFleetView(APIView):
    """`GET /v1/operator/fleet` — the whole fleet, for a staff dashboard."""

    # Fleet operational state + hosted VM ids: operator-only, never a
    # tenant principal. Not published per family — the upstream gates it
    # to its own superusers.
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Whole-fleet observability for Hippius staff",
        description=(
            "One row per miner vali knows (bridged identity, scheduler mirror row or "
            "on-chain node): dispatchability + the failing gate, effective capacity and "
            "trusted free RAM/vCPU with per-flavor headroom, hosted VMs, host-attestor "
            "coverage, observed CVM start capability, zombie quarantine, on-chain status "
            "and price, current-epoch usage and reward weight, 24 h backup runs, and a "
            "closed list of `alerts`. Plus fleet `totals`. At most one chain read; "
            "`chain=false` skips it (rows then carry the DB mirror of the chain status)."
        ),
        tags=["Operator"],
        parameters=[
            OpenApiParameter(
                "chain",
                bool,
                OpenApiParameter.QUERY,
                required=False,
                description="Read the chain for live status + price (default true).",
            ),
        ],
        responses={
            200: OperatorFleetSerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed chain."),
            401: OpenApiResponse(ErrorSerializer, "No / invalid service credential."),
            403: OpenApiResponse(ErrorSerializer, "Not an operator principal."),
        },
    )
    def get(self, request: Request) -> Response:
        raw = request.query_params.get("chain")
        include_chain = True
        if raw is not None:
            if raw.strip().lower() not in _BOOL:
                return _error(status.HTTP_400_BAD_REQUEST, "chain must be true or false", "wire")
            include_chain = _BOOL[raw.strip().lower()]
        return Response(operator_fleet(include_chain=include_chain), status=status.HTTP_200_OK)
