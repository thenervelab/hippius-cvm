"""§9 pull-only telemetry broker endpoints.

  POST /v1/telemetry/ingest
      Auth: any authenticated ServiceClient (ServiceToken).
      Body (JSON): {schema_version, source, source_id, kind,
                    body_hex, sig_hex}.
      `body_hex` is the hex of the signed canonical-CBOR telemetry
      body; `sig_hex` the hex of its 64-byte detached Ed25519
      signature. vali NEVER decodes CBOR in Python — it hex-decodes
      (trivial, safe) and pipes the bytes to the parser-hardened
      Rust verifier.
      → 202 ingested / 200 idempotent re-ingest / 400 wire ·
        schema-version · verify-failed / 403 source-not-registered /
        413 too-large / 429 source-quarantined / 503 backpressure ·
        internal.

  GET /v1/telemetry/pull?kind=<kind>&since=<envelope_id>&limit=<N>
      Auth: telemetry root principal ONLY.
      Drains up to N `Pending` envelopes of `kind` with
      `envelope_id > since`, oldest first; the caller keeps `since`
      durably as its own cursor.
      → 200 {envelopes, count, next_since} / 400 wire / 403.

Strictly pull-only: there is no webhook, no callback. The broker
never makes an outbound request to a source — `source_id` is only
ever a DB key (no SSRF surface).
"""

from __future__ import annotations

import base64
import binascii
import logging
from typing import Any

from django.conf import settings
from django.utils import timezone
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.schemas import ErrorSerializer
from apps.identity import scoping
from apps.identity.authentication import ServiceTokenAuthentication

from . import service, verifier, vm_liveness
from .models import EnvelopeKind, SourceType, TelemetryEnvelope, TelemetrySource
from .permissions import (
    IsAuthenticatedOrCborHeartbeat,
    IsHostAttestorAdmin,
    IsTelemetryRoot,
    is_cbor_request,
)
from .schemas import (
    GracefulExitResponseSerializer,
    HostAttestorCertResponseSerializer,
    HostAttestorChallengeResponseSerializer,
    HostAttestorDesiredResponseSerializer,
    HostAttestorReleaseRequestSerializer,
    HostAttestorReleaseResponseSerializer,
    HostBeaconResponseSerializer,
    TelemetryIngestRequestSerializer,
    TelemetryIngestResponseSerializer,
    TelemetryPullResponseSerializer,
    VmLiveAttestationResponseSerializer,
    VmProgressResponseSerializer,
)

log = logging.getLogger("apps.telemetry.views")

_MAX_SOURCE_ID = 256

# ─── §K heartbeat ingress (PR-Part4-B) ───────────────────────────────
# `x-hippius-peer-id` — the Edge stamps the connection's mTLS identity
# here on a forwarded heartbeat; vali resolves the miner from it (it
# cannot read the `miner_id` from the opaque CBOR body — §5.6). Header
# lookup is case-insensitive; the spelling matches the Edge constant
# `vali_forward::HEARTBEAT_PEER_ID_HEADER` for grep-ability.
_PEER_ID_HEADER = "x-hippius-peer-id"
# Two SAN conventions, two eras (see `binaries/edge-gateway/src/mtls/`):
#   - LEGACY operator-CA cert: `hippius-miner:<miner_id>` — strip the
#     prefix to recover the registry `miner_id` directly.
#   - PERMISSIONLESS self-signed identity cert
#     (docs/design/permissionless-miner-auth.md):
#     `hippius-node:<node_id_hex>`, where the node_id IS the miner's
#     Ed25519 public key. vali resolves the miner by matching that key
#     against the registered `TelemetrySource.verifying_key` (which the
#     on-chain-gated Edge already vouched for at the handshake).
# In BOTH cases the Ed25519 signature is the real trust gate — the
# peer-id only selects which verifying key to check against.
_PEER_ID_PREFIX = "hippius-miner:"
_NODE_PEER_ID_PREFIX = "hippius-node:"
# Mirrors `apps.miners.MinerIdentity.miner_id` max_length.
_MAX_MINER_ID_LEN = 64
# Upper bound on a raw-CBOR heartbeat body — pinned to the SAME
# 4096-byte cap `verify-heartbeat` enforces, so an oversize body draws
# a clean `413` here (no subprocess spawn, no §9 poison strike) at
# exactly the binary's security boundary.
_MAX_HEARTBEAT_BYTES = 4096
# Upper bound on a raw-CBOR graceful-exit body — matches the path-based
# `miners.MinerGracefulExitView._MAX_GRACEFUL_EXIT_BYTES` and the
# `verify-graceful-exit` binary's cap, so an oversize body draws a clean
# `413` here at exactly the verifier's security boundary.
_MAX_GRACEFUL_EXIT_BYTES = 4096
# Upper bound on a raw-CBOR vm-progress body — matches the
# `verify-vm-progress` binary's cap, so an oversize body draws a clean
# `413` here at exactly the verifier's security boundary.
_MAX_VM_PROGRESS_BYTES = 4096
# Upper bounds on the raw-CBOR blackbox host-attestor bodies — matched to
# the `verify-host-attestor-cert` / `verify-host-beacon` binary caps, so
# an oversize body draws a clean `413` at the verifier's boundary.
_MAX_HOST_CERT_BYTES = 4096
_MAX_HOST_BEACON_BYTES = 4096
_MAX_HOST_CHALLENGE_BYTES = 4096
# Upper bound on a raw-CBOR tenant-CVM `SignedLiveAttestation` — matched
# to the `verify-live-attestation` binary's cap.
_MAX_LIVE_ATTESTATION_BYTES = 4096


class _WireError(Exception):
    """A request failed a shape check. Carries the HTTP status."""

    def __init__(
        self, message: str, category: str = "wire", http_status: int = 400
    ) -> None:
        super().__init__(message)
        self.message = message
        self.category = category
        self.http_status = http_status


# ─── POST /v1/telemetry/ingest ───────────────────────────────────────


class TelemetryIngestView(APIView):
    """`POST /v1/telemetry/ingest` — accept one signed envelope.

    Two ingress shapes share this URL:

    - **JSON wrapper** (`application/json`) — a direct telemetry source
      POSTs `{schema_version, source, source_id, kind, body_hex,
      sig_hex}` with a `ServiceToken`. The `edge_telemetry` /
      `served_receipt` kinds.
    - **Raw CBOR** (`application/cbor`) — the Edge forwards a §K
      `SignedMinerHeartbeat` verbatim (PR-Part4-B). vali resolves the
      miner from the `X-Hippius-Peer-Id` header (the Edge's mTLS peer
      identity), reads no JSON wrapper, and runs the heartbeat replay
      gates. This path carries no bearer token — see
      `IsAuthenticatedOrCborHeartbeat`.
    """

    # The JSON path pins ServiceToken auth (telemetry sources carry a
    # bearer token). The raw-CBOR heartbeat path is token-exempt — the
    # permission class makes that distinction; see its docstring.
    authentication_classes = [ServiceTokenAuthentication]
    # P2 object-level authorization: fleet telemetry; the unauthenticated
    # CBOR heartbeat path carries no principal and is unaffected.
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticatedOrCborHeartbeat]
    # RA-N5 — every ingest (both shapes) shells out to the Rust heartbeat
    # verifier BEFORE any backpressure/quarantine, and the CBOR path is
    # token-exempt, so an un-throttled valid-replay or unknown-node
    # autoprovision flood from one miner starves the sync workers. Cap it
    # per Edge-stamped peer-id (PeerIdScopedRateThrottle); the JSON path
    # keys per authenticated source instead (same throttle, `user.pk`).
    throttle_scope = "telemetry_ingest"
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Ingest one signed telemetry envelope",
        description=(
            "Two ingress shapes share this URL. `application/json` — a direct "
            "source POSTs the `{schema_version, source, source_id, kind, "
            "body_hex, sig_hex}` wrapper with a ServiceToken. `application/"
            "cbor` — the Edge forwards a raw §K `SignedMinerHeartbeat` (no "
            "bearer token; miner resolved from the `X-Hippius-Peer-Id` "
            "header). 202 on a new envelope, 200 on an idempotent re-ingest."
        ),
        tags=["Telemetry"],
        request={
            "application/json": TelemetryIngestRequestSerializer,
            "application/cbor": OpenApiTypes.BINARY,
        },
        responses={
            200: TelemetryIngestResponseSerializer,
            202: TelemetryIngestResponseSerializer,
            400: OpenApiResponse(
                ErrorSerializer, "Malformed body / schema-version / verify-failed."
            ),
            403: OpenApiResponse(ErrorSerializer, "Source not registered."),
            413: OpenApiResponse(ErrorSerializer, "Body too large."),
            429: OpenApiResponse(ErrorSerializer, "Source quarantined (Retry-After)."),
            503: OpenApiResponse(ErrorSerializer, "Backpressure / internal fault."),
        },
    )
    def post(self, request: Request) -> Response:
        # The Edge forwards a §K heartbeat as a raw canonical-CBOR
        # `SignedMinerHeartbeat` under `content-type: application/cbor`;
        # every other telemetry kind uses the JSON wrapper.
        if is_cbor_request(request):
            return self._ingest_heartbeat(request)
        return self._ingest_json(request)

    def _ingest_json(self, request: Request) -> Response:
        """The JSON-wrapper ingest path — `edge_telemetry` /
        `served_receipt` from a token-authenticated direct source.
        """
        body = request.data
        if not isinstance(body, dict):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "request body must be a JSON object",
                "wire",
            )
        try:
            schema_version = _require_int(body, "schema_version")
            source = _require_choice(body, "source", SourceType.values)
            source_id = _require_str(body, "source_id", max_len=_MAX_SOURCE_ID)
            kind = _require_choice(body, "kind", EnvelopeKind.values)
            # `kind=heartbeat` consistency. A §K heartbeat is a signed
            # `SignedMinerHeartbeat` ingested as raw `application/cbor`
            # — it never travels the JSON wrapper. (A `miner` source is
            # still valid here for its NON-heartbeat telemetry kinds.)
            if kind == EnvelopeKind.HEARTBEAT.value:
                return _error(
                    status.HTTP_400_BAD_REQUEST,
                    "heartbeat envelopes must be posted as application/cbor",
                    "wire",
                )
            payload = _require_hex(
                body, "body_hex", max_bytes=service.max_envelope_bytes()
            )
            signature = _require_hex(body, "sig_hex", exact_bytes=64)
        except _WireError as exc:
            return _error(exc.http_status, exc.message, exc.category)

        try:
            envelope, created = service.ingest(
                source=source,
                source_id=source_id,
                kind=kind,
                schema_version=schema_version,
                body=payload,
                sig=signature,
            )
        except service.IngestError as exc:
            return _error(
                exc.http_status,
                exc.message,
                exc.category,
                retry_after=exc.retry_after,
            )

        return _ingested_response(envelope, created)

    def _ingest_heartbeat(self, request: Request) -> Response:
        """The §K raw-CBOR heartbeat ingest path (PR-Part4-B).

        The miner identity is the Edge-stamped `X-Hippius-Peer-Id`
        header; the body is the opaque `SignedMinerHeartbeat` CBOR.
        """
        peer_id = request.headers.get(_PEER_ID_HEADER)
        envelope = request.body
        if not envelope:
            return _error(
                status.HTTP_400_BAD_REQUEST, "empty heartbeat body", "wire"
            )
        if len(envelope) > _MAX_HEARTBEAT_BYTES:
            return _error(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"heartbeat exceeds {_MAX_HEARTBEAT_BYTES} bytes",
                "too-large",
            )
        miner_id = _resolve_peer_to_miner_id(peer_id)
        if miner_id is None:
            # Permissionless first-contact: a `hippius-node:<id>` peer
            # whose node_id we don't know yet — auto-provision it (no
            # operator step) iff the heartbeat verifies against the
            # node_id AND the node is registered + Active on-chain.
            node_id = _node_id_from_peer(peer_id)
            if node_id is not None:
                miner_id = service.autoprovision_node_heartbeat_source(
                    node_id.hex(), bytes(envelope)
                )
        if miner_id is None:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                f"missing or malformed {_PEER_ID_HEADER} header",
                "wire",
            )
        try:
            row, created = service.ingest_heartbeat(
                miner_id=miner_id, envelope=bytes(envelope)
            )
        except service.IngestError as exc:
            return _error(
                exc.http_status,
                exc.message,
                exc.category,
                retry_after=exc.retry_after,
            )
        return _ingested_response(row, created)


# ─── POST /v1/telemetry/graceful-exit ────────────────────────────────


class MinerGracefulExitIngestView(APIView):
    """`POST /v1/telemetry/graceful-exit` — Edge-relayed graceful exit.

    The miner→vali transport for a signed graceful-exit request: a real
    miner box cannot reach vali directly, so it POSTs a
    `SignedGracefulExit` to the Edge `/v1/edge/graceful-exit` route over
    mTLS, and the Edge relays the opaque CBOR here (PR graceful-exit-edge-
    relay). It mirrors the §K heartbeat ingress exactly:

    - raw `application/cbor` body (the opaque `SignedGracefulExit`),
    - the miner identity is the Edge-stamped `X-Hippius-Peer-Id` header
      (vali cannot read `miner_id` from the opaque body — §5.6),
    - NO bearer token: the Ed25519 signature the Rust verifier checks
      against the registered key is the credential, same as the
      operator-facing path-based `miners.MinerGracefulExitView`.

    The shared quarantine tail (`miners.apply_graceful_exit_quarantine`)
    is identical to that path-based view; only the miner-resolution
    differs (peer header here vs. URL path there).
    """

    # The signed envelope is the credential — no service-token auth, like
    # the §K heartbeat CBOR ingress and the path-based graceful-exit view.
    authentication_classes: list[Any] = []
    # P2 object-level authorization: `AllowAny` miner-signed ingress.
    object_scope = scoping.PUBLIC
    permission_classes = [AllowAny]
    # RA-M2 — same anti-amplification throttle as the path-based view: the
    # verifier subprocess runs before any auth, so cap per source IP.
    throttle_scope = "graceful_exit"
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Ingest an Edge-relayed miner graceful exit",
        description=(
            "The Edge relays a signed `SignedGracefulExit` (raw application/"
            "cbor) here. No bearer token — the Ed25519 signature the Rust "
            "verifier checks is the credential; the miner is resolved from "
            "the Edge-stamped `X-Hippius-Peer-Id` header. On acceptance the "
            "miner is quarantined."
        ),
        tags=["Telemetry"],
        request=OpenApiTypes.BINARY,
        responses={
            200: GracefulExitResponseSerializer,
            400: OpenApiResponse(ErrorSerializer, "Empty / bad body or peer-id header."),
            403: OpenApiResponse(
                ErrorSerializer, "Verify failed / miner_id mismatch / timestamp skew."
            ),
            404: OpenApiResponse(ErrorSerializer, "Miner not found."),
            413: OpenApiResponse(ErrorSerializer, "Body too large."),
            500: OpenApiResponse(ErrorSerializer, "Registry key malformed."),
            503: OpenApiResponse(ErrorSerializer, "Verifier unavailable."),
        },
    )
    def post(self, request: Request) -> Response:
        # Imported lazily: `apps.miners` imports `apps.telemetry` at module
        # load (verifier + models), so a top-level import here would be a
        # circular dependency.
        from apps.miners.models import MinerIdentity, MinerStatus
        from apps.miners.views import (
            _graceful_exit_skew_seconds,
            apply_graceful_exit_quarantine,
        )

        peer_id = request.headers.get(_PEER_ID_HEADER)
        envelope = request.body
        if not envelope:
            return _error(
                status.HTTP_400_BAD_REQUEST, "empty graceful-exit body", "wire"
            )
        if len(envelope) > _MAX_GRACEFUL_EXIT_BYTES:
            return _error(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"graceful-exit exceeds {_MAX_GRACEFUL_EXIT_BYTES} bytes",
                "too-large",
            )
        # Resolve the miner from the Edge-stamped mTLS peer identity —
        # EXACTLY as the heartbeat ingest does (both SAN schemes).
        miner_id = _resolve_peer_to_miner_id(peer_id)
        if miner_id is None:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                f"missing or malformed {_PEER_ID_HEADER} header",
                "wire",
            )
        miner = MinerIdentity.objects.filter(miner_id=miner_id).first()
        if miner is None:
            return _error(
                status.HTTP_404_NOT_FOUND, "miner not found", "not-found"
            )
        try:
            vk = bytes.fromhex(miner.pubkey_hex)
        except ValueError:
            return _error(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "registry key malformed",
                "internal",
            )
        try:
            body = verifier.verify_graceful_exit(
                envelope=bytes(envelope), verifying_key=vk
            )
        except verifier.VerifierFailed as exc:
            return _error(
                status.HTTP_403_FORBIDDEN,
                "graceful-exit verification failed",
                exc.category,
            )
        except verifier.VerifierUnavailable:
            return _error(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "verifier unavailable",
                "internal",
            )
        # Defence in depth: the mTLS peer identity AND the signed body
        # must name the SAME miner (the peer-id selected the verifying
        # key; the signature proves authorship; this binds the two).
        if body.miner_id != miner_id:
            return _error(
                status.HTTP_403_FORBIDDEN, "body miner_id mismatch", "identity"
            )
        # ±skew anti-replay-across-time on the signed timestamp.
        skew = abs(body.timestamp_unix - int(timezone.now().timestamp()))
        if skew > _graceful_exit_skew_seconds():
            return _error(
                status.HTTP_403_FORBIDDEN,
                "timestamp outside skew window",
                "timestamp-skew",
            )
        if not apply_graceful_exit_quarantine(miner_id, body):
            return _error(
                status.HTTP_404_NOT_FOUND, "miner not found", "not-found"
            )
        return Response(
            {
                "miner_id": miner_id,
                "status": MinerStatus.QUARANTINED,
                "accepted": True,
            },
            status=status.HTTP_200_OK,
        )


# ─── POST /v1/telemetry/vm-progress ──────────────────────────────────


def _vm_progress_reporter_hosts_vm(vm: Any, miner: Any) -> tuple[bool, str]:
    """Does `miner` HOST `vm`? — the vm-progress ownership bind.

    Returns `(accepted, reason)`; `reason` is an operator-facing label
    for the log line, NEVER surfaced to the reporter (telling a miner
    *why* it was refused tells it which binding to aim at).

    FAILS CLOSED. The bind is decided against vali's OWN placement
    records — the reporting miner supplies neither side of the
    comparison (the identity comes from the Edge-stamped mTLS peer-id;
    the binding from vali's launch bookkeeping) — and an ownership that
    cannot be RESOLVED is a refusal, not an accept:

    1. **Host binding** (`MinerIdentity` pk space) — `effects.
       bound_miner_id`: `vm.host` (stamped on an accepted dispatch and
       on §25 dest-activation), else the latest SUCCEEDED `LaunchJob.
       miner_id`. This is the SAME resolver §24 destroy / §25 relay /
       reboot-recovery route on, so "who may report progress" and "who
       holds the domain" can never disagree.

       While the VM is `Migrating`, `vm.migration_dest` is accepted TOO:
       the §25 destination emits `booting` from inside `handle_launch`,
       which lands milliseconds BEFORE `mark_activate_done` stamps
       `vm.host = dest`. Without this term every migration would lose
       the destination's first milestones (the exact loss the fence-time
       `boot_phase` reset was written to prevent). It is not a widening:
       `migration_dest` is vali's own record of where IT sent the VM.

    2. **Placement fallback** (chain `node_id` space) — only when NO
       host binding exists yet, i.e. the window between the scheduler
       recording the Pending `Placement` and the dispatch being
       accepted. The launch path resolves its miner BY `chain_node_id`,
       so a legitimately-placed VM's host always has one; a reporter
       WITHOUT a `chain_node_id` therefore cannot be that host and is
       refused rather than waved through.

    3. **Neither resolvable** ⇒ REFUSED. Previously this degraded to
       "accept", which made a display field any registered miner could
       write for any `vm_id` it knew.
    """
    from apps.lifecycle.models import VmState
    from apps.orchestration.effects import bound_miner_id
    from apps.scheduler.models import Placement

    hosts: set[str] = set()
    bound = bound_miner_id(vm)
    if bound:
        hosts.add(bound)
    if vm.state == VmState.MIGRATING.value and vm.migration_dest:
        hosts.add(vm.migration_dest)
    if hosts:
        return (miner.miner_id in hosts, "host-binding")

    placement_node_id = (
        Placement.objects.filter(vm=vm)
        .order_by("-decided_at")
        .values_list("miner_node_id", flat=True)
        .first()
    )
    if placement_node_id:
        reporter_node_id = miner.chain_node_id or ""
        return (
            bool(reporter_node_id) and reporter_node_id == placement_node_id,
            "placement",
        )
    return (False, "unbound")


class MinerVmProgressIngestView(APIView):
    """`POST /v1/telemetry/vm-progress` — Edge-relayed guest-boot progress.

    After a launch is accepted (`LaunchJob.phase=launched`) the tenant
    guest boots asynchronously on the miner. The miner-agent signs a
    `SignedVmProgress` milestone (`booting` → `kek-released` → `running`)
    and POSTs it to the Edge, which relays the opaque CBOR here — exactly
    like the graceful-exit ingress:

    - raw `application/cbor` body (the opaque `SignedVmProgress`),
    - the miner identity is the Edge-stamped `X-Hippius-Peer-Id` header,
    - NO bearer token: the Ed25519 signature the Rust verifier checks
      against the registered key is the credential.

    On acceptance the milestone advances `Vm.boot_phase` MONOTONICALLY
    (a late/replayed lower milestone never regresses it).

    A verified signature only proves WHO is speaking, so the ownership
    bind is the second half of the credential: the reporter must be the
    miner vali's own records say HOSTS this VM (`_vm_progress_reporter_
    hosts_vm`), and an ownership vali cannot resolve is a 403 — NOT an
    accept (P9/#19).

    The one surviving fail-open is a milestone for a `vm_id` with NO `Vm`
    row: that path WRITES NOTHING, so it is a benign 200 (`tracked=
    false`) rather than a hard 404 (a report can race the row becoming
    queryable). Nothing about it is attacker-writable.
    """

    # The signed envelope is the credential — no service-token auth, like
    # the graceful-exit CBOR ingress.
    authentication_classes: list[Any] = []
    # P2 object-level authorization: `AllowAny` miner-signed ingress.
    object_scope = scoping.PUBLIC
    permission_classes = [AllowAny]
    # Anti-amplification throttle per Edge-stamped peer-id: the verifier
    # subprocess runs before any auth, mirroring graceful-exit.
    throttle_scope = "vm_progress"
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Ingest an Edge-relayed guest-boot progress milestone",
        description=(
            "The Edge relays a signed `SignedVmProgress` (raw application/"
            "cbor) here. No bearer token — the Ed25519 signature the Rust "
            "verifier checks is the credential; the miner is resolved from "
            "the Edge-stamped `X-Hippius-Peer-Id` header. The reporter must "
            "also be the miner vali's records say HOSTS the VM (an "
            "unresolvable ownership is a 403). On acceptance the milestone "
            "advances `Vm.boot_phase` monotonically. A milestone for a VM "
            "with no row yet writes nothing and returns a benign 200."
        ),
        tags=["Telemetry"],
        request=OpenApiTypes.BINARY,
        responses={
            200: VmProgressResponseSerializer,
            400: OpenApiResponse(ErrorSerializer, "Empty / bad body or peer-id header."),
            403: OpenApiResponse(
                ErrorSerializer,
                "Verify failed / miner_id mismatch / timestamp skew / the "
                "reporter does not host this VM (incl. an ownership vali "
                "cannot resolve).",
            ),
            404: OpenApiResponse(ErrorSerializer, "Miner not found."),
            413: OpenApiResponse(ErrorSerializer, "Body too large."),
            500: OpenApiResponse(ErrorSerializer, "Registry key malformed."),
            503: OpenApiResponse(ErrorSerializer, "Verifier unavailable."),
        },
    )
    def post(self, request: Request) -> Response:
        # Imported lazily: `apps.miners`/`apps.lifecycle` import
        # `apps.telemetry` at module load, so a top-level import here
        # would be a circular dependency.
        from apps.lifecycle.models import Vm
        from apps.miners.models import MinerIdentity
        from apps.miners.views import _graceful_exit_skew_seconds

        peer_id = request.headers.get(_PEER_ID_HEADER)
        envelope = request.body
        if not envelope:
            return _error(
                status.HTTP_400_BAD_REQUEST, "empty vm-progress body", "wire"
            )
        if len(envelope) > _MAX_VM_PROGRESS_BYTES:
            return _error(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"vm-progress exceeds {_MAX_VM_PROGRESS_BYTES} bytes",
                "too-large",
            )
        # Resolve the miner from the Edge-stamped mTLS peer identity —
        # EXACTLY as the graceful-exit / heartbeat ingest does.
        miner_id = _resolve_peer_to_miner_id(peer_id)
        if miner_id is None:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                f"missing or malformed {_PEER_ID_HEADER} header",
                "wire",
            )
        miner = MinerIdentity.objects.filter(miner_id=miner_id).first()
        if miner is None:
            return _error(
                status.HTTP_404_NOT_FOUND, "miner not found", "not-found"
            )
        try:
            vk = bytes.fromhex(miner.pubkey_hex)
        except ValueError:
            return _error(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "registry key malformed",
                "internal",
            )
        try:
            body = verifier.verify_vm_progress(
                envelope=bytes(envelope), verifying_key=vk
            )
        except verifier.VerifierFailed as exc:
            return _error(
                status.HTTP_403_FORBIDDEN,
                "vm-progress verification failed",
                exc.category,
            )
        except verifier.VerifierUnavailable:
            return _error(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "verifier unavailable",
                "internal",
            )
        # Defence in depth: the mTLS peer identity AND the signed body
        # must name the SAME miner (the peer-id selected the verifying
        # key; the signature proves authorship; this binds the two).
        if body.miner_id != miner_id:
            return _error(
                status.HTTP_403_FORBIDDEN, "body miner_id mismatch", "identity"
            )
        # ±skew anti-replay-across-time on the signed timestamp.
        skew = abs(body.timestamp_unix - int(timezone.now().timestamp()))
        if skew > _graceful_exit_skew_seconds():
            return _error(
                status.HTTP_403_FORBIDDEN,
                "timestamp outside skew window",
                "timestamp-skew",
            )

        # Record the milestone on the VM row. Fail-open DISPLAY semantics:
        # a verified milestone for a VM whose row isn't queryable yet
        # returns a benign 200 (`tracked=false`), never a hard 404 — the
        # guest may report progress before the row is queryable in edge
        # cases (normally it exists).
        vm = Vm.objects.filter(vm_id=body.vm_id).first()
        if vm is None:
            log.info(
                "vm-progress for untracked vm: vm_id=%s milestone=%s miner_id=%s",
                body.vm_id,
                body.milestone,
                miner_id,
            )
            return Response(
                {
                    "ok": True,
                    "vm_id": body.vm_id,
                    "boot_phase": "",
                    "tracked": False,
                    "advanced": False,
                },
                status=status.HTTP_200_OK,
            )
        # Cross-miner ownership bind — FAIL CLOSED. Only the miner that
        # HOSTS this VM may advance its `boot_phase`; otherwise a registered
        # miner B, knowing a vm_id hosted by miner A, could drive A's tenant
        # VM's readout over its own (verified) mTLS leg. `_vm_progress_
        # reporter_hosts_vm` resolves the host from vali's OWN records and
        # refuses when it cannot conclude (P9/#19 — this check used to
        # degrade to "accept" whenever the binding was unresolvable).
        #
        # A refusal is logged at WARNING with the resolved binding, because
        # the one legitimate way to hit it is a vali bookkeeping gap, and
        # that must be diagnosable from vali's log alone: the miner-agent's
        # sink is fire-and-forget (it swallows the 403 and never retries),
        # so the only other symptom is a `boot_phase` that stops advancing.
        accepted, reason = _vm_progress_reporter_hosts_vm(vm, miner)
        if not accepted:
            log.warning(
                "vm-progress REFUSED (reporter does not host vm): vm_id=%s "
                "milestone=%s reporter=%s bind=%s vm_host=%r "
                "vm_state=%s migration_dest=%r",
                body.vm_id,
                body.milestone,
                miner_id,
                reason,
                vm.host,
                vm.state,
                vm.migration_dest,
            )
            # Deliberately the SAME opaque message/category for a spoof and
            # for an unresolvable binding — a probing miner learns nothing
            # about which VMs vali has records for.
            return _error(
                status.HTTP_403_FORBIDDEN,
                "reporting miner does not host this vm",
                "identity",
            )
        advanced = vm.advance_boot_phase(body.milestone)
        if advanced:
            vm.boot_phase_at = timezone.now()
            vm.save(update_fields=["boot_phase", "boot_phase_at", "updated_at"])
            log.info(
                "vm-progress advanced: vm_id=%s boot_phase=%s miner_id=%s",
                vm.vm_id,
                vm.boot_phase,
                miner_id,
            )
        return Response(
            {
                "ok": True,
                "vm_id": vm.vm_id,
                "boot_phase": vm.boot_phase,
                "tracked": True,
                "advanced": advanced,
            },
            status=status.HTTP_200_OK,
        )


# ─── POST /v1/telemetry/host-attestor/cert ───────────────────────────


class HostAttestorCertIngestView(APIView):
    """`POST /v1/telemetry/host-attestor/cert` — blackbox host-attestor
    enrollment-cert ingest (blackbox host-attestor chantier PR-8, INERT).

    Receives the KBS-minted `SignedHostAttestorCert` (raw
    `application/cbor`, relayed through the untrusted miner). The KBS L0
    signature is the credential — no bearer token, exactly like the other
    signed-envelope ingress paths. On a valid cert vali upserts a
    `HostAttestor` row keyed by the AMD-signed `chip_id`, storing the
    certified `signer_pubkey`.

    Ships INERT: nothing reads the persisted rows for reward /
    dispatchability yet.
    """

    # The KBS-signed cert is the credential — no service-token auth (like
    # the graceful-exit / vm-progress CBOR ingress).
    authentication_classes: list[Any] = []
    # P2 object-level authorization: `AllowAny` attestor-signed ingress.
    object_scope = scoping.PUBLIC
    permission_classes = [AllowAny]
    throttle_scope = "host_attestor_cert"
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Ingest a KBS-minted host-attestor enrollment cert (INERT)",
        description=(
            "A relayed `SignedHostAttestorCert` (raw application/cbor). The "
            "KBS L0 signature is the credential — vali verifies it against the "
            "configured KBS L0 key (persisting `attested`) or, when that key "
            "is not wired, decode-only-persists `pending`. Ships INERT."
        ),
        tags=["Telemetry"],
        request=OpenApiTypes.BINARY,
        responses={
            200: HostAttestorCertResponseSerializer,
            400: OpenApiResponse(ErrorSerializer, "Empty / bad / expired cert."),
            413: OpenApiResponse(ErrorSerializer, "Body too large."),
            503: OpenApiResponse(ErrorSerializer, "Verifier unavailable."),
        },
    )
    def post(self, request: Request) -> Response:
        envelope = request.body
        if not envelope:
            return _error(
                status.HTTP_400_BAD_REQUEST, "empty host-attestor cert body", "wire"
            )
        if len(envelope) > _MAX_HOST_CERT_BYTES:
            return _error(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"host-attestor cert exceeds {_MAX_HOST_CERT_BYTES} bytes",
                "too-large",
            )
        try:
            row, created = service.ingest_host_attestor_cert(envelope=bytes(envelope))
        except service.IngestError as exc:
            return _error(exc.http_status, exc.message, exc.category)
        return Response(
            {
                "chip_id": row.chip_id,
                "node_id": row.node_id,
                "status": row.status,
                "created": created,
            },
            status=status.HTTP_200_OK,
        )


# ─── POST /v1/telemetry/host-attestor/heartbeat ──────────────────────


class HostAttestorBeaconIngestView(APIView):
    """`POST /v1/telemetry/host-attestor/heartbeat` — blackbox
    host-attestor liveness-beacon ingest (PR-8, INERT).

    Receives a `SignedHostBeacon` (raw `application/cbor`) relayed by the
    miner over its mTLS leg; the host identity is the Edge-stamped
    `X-Hippius-Peer-Id` header (vali resolves the `node_id` from it, NEVER
    the opaque beacon body — §5.6). vali verifies the Ed25519 signature
    against the CERTIFIED `signer_pubkey` stored from the enrollment cert
    (not the beacon's self-declared key), enforces a monotonic `seq`, and
    refreshes `last_seen_at` / `last_seq`.

    Ships INERT: nothing reads the persisted liveness yet.
    """

    authentication_classes: list[Any] = []
    # P2 object-level authorization: `AllowAny` attestor-signed ingress.
    object_scope = scoping.PUBLIC
    permission_classes = [AllowAny]
    throttle_scope = "host_attestor_beacon"
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Ingest a host-attestor liveness beacon (INERT)",
        description=(
            "A relayed `SignedHostBeacon` (raw application/cbor). The host is "
            "resolved from the Edge-stamped `X-Hippius-Peer-Id`; the Ed25519 "
            "signature is verified against the CERTIFIED `signer_pubkey` from "
            "the enrollment cert, with a monotonic `seq` replay gate. INERT."
        ),
        tags=["Telemetry"],
        request=OpenApiTypes.BINARY,
        responses={
            200: HostBeaconResponseSerializer,
            400: OpenApiResponse(
                ErrorSerializer, "Empty / bad / replayed / expired beacon."
            ),
            404: OpenApiResponse(ErrorSerializer, "No enrolled host-attestor."),
            413: OpenApiResponse(ErrorSerializer, "Body too large."),
            503: OpenApiResponse(ErrorSerializer, "Verifier unavailable."),
        },
    )
    def post(self, request: Request) -> Response:
        peer_id = request.headers.get(_PEER_ID_HEADER)
        envelope = request.body
        if not envelope:
            return _error(
                status.HTTP_400_BAD_REQUEST, "empty host-beacon body", "wire"
            )
        if len(envelope) > _MAX_HOST_BEACON_BYTES:
            return _error(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"host-beacon exceeds {_MAX_HOST_BEACON_BYTES} bytes",
                "too-large",
            )
        node_id = _node_id_hex_from_peer(peer_id)
        if node_id is None:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                f"missing or malformed {_PEER_ID_HEADER} header",
                "wire",
            )
        try:
            row = service.ingest_host_beacon(node_id=node_id, envelope=bytes(envelope))
        except service.IngestError as exc:
            return _error(exc.http_status, exc.message, exc.category)
        return Response(
            {
                "chip_id": row.chip_id,
                "node_id": row.node_id,
                "status": row.status,
                "last_seq": row.last_seq,
            },
            status=status.HTTP_200_OK,
        )


# ─── POST /v1/telemetry/host-attestor/challenge ──────────────────────


class HostAttestorChallengeView(APIView):
    """`POST /v1/telemetry/host-attestor/challenge` — mint a fresh
    single-use enrollment nonce (blackbox host-attestor chantier PR-10).

    vali is the SOLE nonce authority. A blackbox host-attestor (relayed by
    the miner over its mTLS leg) POSTs a `HostChallengeRequest`
    (`application/cbor`) carrying its Ed25519 signer public key. vali:

      1. resolves the host `node_id` from the Edge-stamped
         `X-Hippius-Peer-Id` (NEVER a body-declared node — §5.6),
      2. Rust-decodes the hostile request to surface the `signer_pubkey`,
      3. mints a CSPRNG 32-byte nonce bound to `{node_id, signer_pubkey}`,
         stored unspent with a short TTL,

    and returns `{nonce_hex, expiry_unix}` (relayed back down to the guest,
    which folds the nonce into its enrollment `REPORT_DATA[0..32]`). At
    cert-ingest that nonce is claimed single-use — closing the
    pre-generation replay hole.

    Unauthenticated + CNP-gated, mirroring the miner-facing feeds: only the
    Edge may reach vali. The minted nonce is worthless without the measured
    attestor guest (it is bound to a pk only a genuine host-attestor SNP
    report can carry into REPORT_DATA), so minting is not a secret release.
    """

    authentication_classes: list[Any] = []
    # P2 object-level authorization: `AllowAny` attestor challenge.
    object_scope = scoping.PUBLIC
    permission_classes = [AllowAny]
    throttle_scope = "host_attestor_challenge"
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Mint a single-use host-attestor enrollment nonce",
        description=(
            "A relayed `HostChallengeRequest` (raw application/cbor). vali "
            "resolves the host `node_id` from the Edge-stamped "
            "`X-Hippius-Peer-Id`, surfaces the `signer_pubkey`, and mints a "
            "CSPRNG single-use nonce bound to `{node_id, signer_pubkey}` "
            "returned as `{nonce_hex, expiry_unix}`."
        ),
        tags=["Telemetry"],
        request=OpenApiTypes.BINARY,
        responses={
            200: HostAttestorChallengeResponseSerializer,
            400: OpenApiResponse(ErrorSerializer, "Empty / bad request / missing peer."),
            413: OpenApiResponse(ErrorSerializer, "Body too large."),
            503: OpenApiResponse(ErrorSerializer, "Verifier unavailable."),
        },
    )
    def post(self, request: Request) -> Response:
        peer_id = request.headers.get(_PEER_ID_HEADER)
        envelope = request.body
        if not envelope:
            return _error(
                status.HTTP_400_BAD_REQUEST, "empty host-challenge body", "wire"
            )
        if len(envelope) > _MAX_HOST_CHALLENGE_BYTES:
            return _error(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"host-challenge exceeds {_MAX_HOST_CHALLENGE_BYTES} bytes",
                "too-large",
            )
        node_id = _node_id_hex_from_peer(peer_id)
        if node_id is None:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                f"missing or malformed {_PEER_ID_HEADER} header",
                "wire",
            )
        try:
            nonce, expires_at = service.issue_host_attestor_challenge(
                node_id=node_id, envelope=bytes(envelope)
            )
        except service.IngestError as exc:
            return _error(exc.http_status, exc.message, exc.category)
        # Return the peer-stamped `node_id` alongside the nonce (PR-10b-S2a
        # wire amendment): the attestor guest CANNOT read its node_id from
        # the measured cmdline (that would make the SNP measurement
        # per-node, breaking the fleet-pinned host-attestor measurement), so
        # vali surfaces it here. The nonce is already bound to this same
        # `{node_id, signer_pubkey}`, so a lying miner can only supply its
        # OWN peer-stamped node_id and only breaks its own attestation.
        return Response(
            {
                "nonce_hex": nonce.hex(),
                "node_id": node_id,
                "expiry_unix": int(expires_at.timestamp()),
            },
            status=status.HTTP_200_OK,
        )


# ─── POST /v1/admin/host-attestor/release ────────────────────────────


class HostAttestorReleaseView(APIView):
    """`POST /v1/admin/host-attestor/release` — publish a cosign-verified
    blackbox host-attestor UKI release (blackbox host-attestor PR-9).

    Admin-only (the host-attestor-admin principal). The operator supplies
    the CI-signed blackbox UKI blob + its keyless cosign bundle (Fulcio
    cert + detached signature from PR-6's `blackbox-uki-build.yml`) plus
    the SNP measurement CI pinned alongside it. On a verified release vali:
      1. cosign verify-blob with the pinned CI identity + issuer + Rekor,
      2. APPEND-ONLY pins the measurement into the §22 allowlist under the
         `host_attestor` CLASS (never aliasing a tenant measurement, NEVER
         auto-pinned from a miner report),
      3. records a `HostAttestorRelease` active (the desired image miners
         relaunch onto).

    Ships INERT: this manages the release + pins the measurement; nothing
    here gates reward / dispatchability (that arms in PR-11). It inherits
    the open M-of-N GA-blocker — a single-signer release can pin but the
    downstream emission stays default-off.
    """

    authentication_classes = [ServiceTokenAuthentication]
    # P2 object-level authorization: already admin-gated fleet trust root.
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated, IsHostAttestorAdmin]
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Publish a cosign-verified host-attestor UKI release (admin)",
        description=(
            "Host-attestor-admin only. Keyless-cosign-verifies the CI-signed "
            "blackbox UKI (Fulcio cert + Rekor, pinned identity + issuer), then "
            "APPEND-ONLY pins its measurement into the §22 allowlist under the "
            "`host_attestor` class and records it as the active desired release. "
            "The measurement is operator/CI-pinned here ONLY — never auto-pinned "
            "from a miner report. Ships INERT (does not gate reward/dispatch)."
        ),
        tags=["Telemetry"],
        request=HostAttestorReleaseRequestSerializer,
        responses={
            200: HostAttestorReleaseResponseSerializer,
            201: HostAttestorReleaseResponseSerializer,
            400: OpenApiResponse(
                ErrorSerializer, "Malformed body / cosign verify failed."
            ),
            403: OpenApiResponse(
                ErrorSerializer, "Not the host-attestor-admin principal."
            ),
            413: OpenApiResponse(ErrorSerializer, "Release artifact too large."),
            502: OpenApiResponse(ErrorSerializer, "Allowlist pin failed."),
            503: OpenApiResponse(ErrorSerializer, "cosign / pin unavailable."),
        },
    )
    def post(self, request: Request) -> Response:
        # Imported lazily to avoid a module-load import cycle (release_service
        # imports apps.orchestration, which imports apps.telemetry).
        from . import release_service

        body = request.data
        if not isinstance(body, dict):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "request body must be a JSON object",
                "wire",
            )
        try:
            measurement_hex = _require_str(body, "measurement_hex", max_len=96)
            version = _require_str(body, "version", max_len=64)
            artifact = _require_b64(
                body, "artifact_b64", max_bytes=_max_release_artifact_bytes()
            )
            signature_b64 = _require_str(body, "cosign_signature_b64", max_len=8192)
            certificate_pem = _require_str(
                body, "cosign_certificate_pem", max_len=32768
            )
            rekor_log_index = _optional_int(body, "rekor_log_index")
        except _WireError as exc:
            return _error(exc.http_status, exc.message, exc.category)

        try:
            result = release_service.admit_release(
                measurement_hex=measurement_hex,
                version=version,
                artifact=artifact,
                signature_b64=signature_b64,
                certificate_pem=certificate_pem,
                rekor_log_index=rekor_log_index,
            )
        except release_service.ReleaseError as exc:
            return _error(exc.http_status, exc.message, exc.category)

        return Response(
            {
                "measurement": result.release.measurement,
                "version": result.release.version,
                "is_active": result.release.is_active,
                "allowlist_epoch": result.new_epoch,
                "cosign_identity": result.release.cosign_identity,
                "cosign_issuer": result.release.cosign_issuer,
                "created": result.created,
            },
            status=(
                status.HTTP_201_CREATED
                if result.created
                else status.HTTP_200_OK
            ),
        )


# ─── GET /v1/miner/<node_id>/host-attestor/desired ───────────────────


class HostAttestorDesiredView(APIView):
    """`GET /v1/miner/<node_id>/host-attestor/desired` — the desired
    blackbox UKI release for a miner to boot (blackbox host-attestor PR-9).

    Miner-facing: the miner-agent polls this to learn which measurement +
    artifact to relaunch its host attestor onto. Returns the {current,
    previous} grace window so a miner mid-rolling-update on the previous
    measurement is still valid (the miner-agent already fail-closed asserts
    the measurement pin locally — PR-7).

    Unauthenticated + CNP-gated, mirroring the `edge/registry` feed: the
    desired measurement is public data (it is already in the public §22
    allowlist), and the artifact reference is a public CI artifact. The
    `node_id` is accepted for symmetry / future per-node rollout + logged;
    the release is fleet-wide today.
    """

    authentication_classes: list[Any] = []
    # P2 object-level authorization: `AllowAny` miner-facing desired-release feed.
    object_scope = scoping.PUBLIC
    permission_classes = [AllowAny]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="The desired host-attestor UKI release for a miner",
        description=(
            "Miner-facing (CNP-gated, unauthenticated — public allowlist data). "
            "Returns the {current, previous} active releases: the measurement "
            "the miner should boot its host attestor onto, plus the previous "
            "one still accepted during a rolling update. Empty `current` before "
            "the operator has admitted any release."
        ),
        tags=["Telemetry"],
        parameters=[
            OpenApiParameter(
                "node_id",
                str,
                OpenApiParameter.PATH,
                description="The miner's host node id (informational today).",
            ),
        ],
        responses={
            200: HostAttestorDesiredResponseSerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed node_id."),
        },
    )
    def get(self, request: Request, node_id: str) -> Response:
        from . import release_service

        if not node_id or len(node_id) > _MAX_SOURCE_ID:
            return _error(
                status.HTTP_400_BAD_REQUEST, "malformed node_id", "wire"
            )
        desired = release_service.desired_releases()
        log.info(
            "host-attestor desired polled: node_id=%s current=%s",
            node_id,
            desired.current.measurement[:16] + "…" if desired.current else "none",
        )
        return Response(
            {
                "current": _serialize_release(desired.current),
                "previous": _serialize_release(desired.previous),
            },
            status=status.HTTP_200_OK,
        )


# ─── GET /v1/telemetry/pull ──────────────────────────────────────────


class TelemetryPullView(APIView):
    """`GET /v1/telemetry/pull` — root-only cursor drain."""

    # P2 object-level authorization: already root-gated broker drain.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated, IsTelemetryRoot]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Drain pending telemetry envelopes (root-only)",
        description=(
            "Root-only cursor drain: claims up to `limit` Pending envelopes of "
            "`kind` with `envelope_id > since`, oldest first. The caller keeps "
            "`next_since` durably as its own cursor."
        ),
        tags=["Telemetry"],
        parameters=[
            OpenApiParameter(
                "kind",
                str,
                OpenApiParameter.QUERY,
                required=True,
                enum=EnvelopeKind.values,
                description="Envelope kind to drain.",
            ),
            OpenApiParameter(
                "since",
                int,
                OpenApiParameter.QUERY,
                description="Cursor — return envelopes with envelope_id > since (default 0).",
            ),
            OpenApiParameter(
                "limit",
                int,
                OpenApiParameter.QUERY,
                description="Max envelopes to drain (default 100, capped by the broker).",
            ),
        ],
        responses={
            200: TelemetryPullResponseSerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed query parameter."),
            403: OpenApiResponse(ErrorSerializer, "Not the telemetry root principal."),
        },
    )
    def get(self, request: Request) -> Response:
        try:
            kind = _require_choice_qp(request, "kind", EnvelopeKind.values)
            since = _require_int_qp(request, "since", default=0)
            limit = _require_int_qp(request, "limit", default=100, minimum=1)
        except _WireError as exc:
            return _error(exc.http_status, exc.message, exc.category)

        limit = min(limit, service.pull_max_limit())
        result = service.pull(kind=kind, since=since, limit=limit)
        return Response(
            {
                "envelopes": [
                    _serialize_envelope(env) for env in result.envelopes
                ],
                "count": len(result.envelopes),
                "next_since": result.next_since,
            },
            status=status.HTTP_200_OK,
        )


# ─── helpers ─────────────────────────────────────────────────────────


def _serialize_envelope(env: TelemetryEnvelope) -> dict[str, Any]:
    """Render a `TelemetryEnvelope` for a pull response. `payload_cbor`
    + `signature` are hex-encoded — they are signed telemetry the
    consumer needs (it may re-verify); they are returned here but
    must NEVER be written to a log line.
    """
    return {
        "envelope_id": env.envelope_id,
        "source": env.source,
        "source_id": env.source_id,
        "kind": env.kind,
        "schema_version": env.schema_version,
        "payload_cbor_hex": bytes(env.payload_cbor).hex(),
        "signature_hex": bytes(env.signature).hex(),
        "received_at": env.received_at.isoformat(),
        "processing_status": env.processing_status,
    }


def _max_release_artifact_bytes() -> int:
    """Cap on the inline base64 blackbox-UKI blob a release POSTs. The
    artifact rides the request body (no vali-side URL fetch → no SSRF), so
    an operator with a larger UKI raises this + Django's upload cap."""
    return int(getattr(settings, "VALI_HOST_ATTESTOR_MAX_ARTIFACT_BYTES", 64 * 1024 * 1024))


def _serialize_release(release: Any) -> dict[str, Any] | None:
    """Render a `HostAttestorRelease` (or `None`) for the desired response.
    Only public fields — measurement + version + provenance identity."""
    if release is None:
        return None
    return {
        "measurement": release.measurement,
        "version": release.version,
        "cosign_identity": release.cosign_identity,
        "created_at": release.created_at.isoformat(),
    }


def _ingested_response(envelope: TelemetryEnvelope, created: bool) -> Response:
    """The shared ingest response — `202` on a newly-created envelope,
    `200` on an idempotent re-ingest of an existing row.
    """
    return Response(
        {
            "envelope_id": envelope.envelope_id,
            "processing_status": envelope.processing_status,
            "created": created,
        },
        status=status.HTTP_202_ACCEPTED if created else status.HTTP_200_OK,
    )


def _miner_id_from_peer(peer_id: str | None) -> str | None:
    """Recover the registry `miner_id` from the `X-Hippius-Peer-Id`
    header value.

    The Edge stamps the connection's mTLS `PeerId`, whose SAN
    convention is `hippius-miner:<miner_id>`. Returns `None` when the
    header is absent or not that shape — the caller fail-closes with a
    `400`.
    """
    peer_id = (peer_id or "").strip()
    if not peer_id.startswith(_PEER_ID_PREFIX):
        return None
    miner_id = peer_id[len(_PEER_ID_PREFIX) :]
    if not miner_id or len(miner_id) > _MAX_MINER_ID_LEN:
        return None
    return miner_id


def _resolve_peer_to_miner_id(peer_id: str | None) -> str | None:
    """Resolve the registry `miner_id` from the Edge-stamped peer-id,
    handling BOTH SAN schemes.

    - `hippius-miner:<id>` (legacy operator-CA cert) → the id directly.
    - `hippius-node:<node_id_hex>` (permissionless self-signed identity
      cert) → match the 32-byte node_id (== the miner's Ed25519 public
      key) against a registered miner `TelemetrySource.verifying_key`
      and return that source's `source_id`. The on-chain-gated Edge has
      already vouched the node is registered + Active, so a miss here is
      a vali-side provisioning gap, not an authorisation decision.

    Returns `None` on a missing / malformed header or an unknown
    node_id — the caller fail-closes with a `400`.
    """
    legacy = _miner_id_from_peer(peer_id)
    if legacy is not None:
        return legacy
    node_id = _node_id_from_peer(peer_id)
    if node_id is None:
        return None
    src = TelemetrySource.objects.filter(
        source=SourceType.MINER.value, verifying_key=node_id
    ).first()
    return src.source_id if src is not None else None


def _node_id_hex_from_peer(peer_id: str | None) -> str | None:
    """Resolve the host `node_id` (hex) a blackbox host-attestor beacon
    belongs to, from the Edge-stamped mTLS peer identity — NEVER the
    opaque beacon body.

    - `hippius-node:<node_id_hex>` (permissionless self-signed cert) →
      the hex directly (the host-attestor `node_id` matches the
      miner-agent `node_id`).
    - `hippius-miner:<id>` (legacy operator-CA cert) → the registered
      `MinerIdentity.chain_node_id` for that miner.

    Returns `None` on a missing / malformed header or an unresolvable
    miner — the caller fail-closes with a `400`.
    """
    node_id = _node_id_from_peer(peer_id)
    if node_id is not None:
        return node_id.hex()
    legacy = _miner_id_from_peer(peer_id)
    if legacy is None:
        return None
    # Imported lazily: `apps.miners` imports `apps.telemetry` at module
    # load, so a top-level import here would be a circular dependency.
    from apps.miners.models import MinerIdentity

    miner = MinerIdentity.objects.filter(miner_id=legacy).first()
    if miner is None or not miner.chain_node_id:
        return None
    return miner.chain_node_id


def _node_id_from_peer(peer_id: str | None) -> bytes | None:
    """The 32-byte node_id from a `hippius-node:<hex>` peer-id, or `None`
    for the legacy / a malformed value. (The permissionless self-signed
    cert scheme; the node_id IS the miner's Ed25519 public key.)
    """
    pid = (peer_id or "").strip()
    if not pid.startswith(_NODE_PEER_ID_PREFIX):
        return None
    try:
        node_id = bytes.fromhex(pid[len(_NODE_PEER_ID_PREFIX) :])
    except ValueError:
        return None
    return node_id if len(node_id) == 32 else None


def _require_int(body: dict[str, Any], field: str) -> int:
    """Require a JSON integer body field. `bool` is rejected (it is
    an `int` subclass in Python).
    """
    if field not in body:
        raise _WireError(f"missing {field!r}")
    value = body[field]
    if isinstance(value, bool) or not isinstance(value, int):
        raise _WireError(f"{field} must be an integer")
    return value


def _require_str(body: dict[str, Any], field: str, *, max_len: int) -> str:
    if field not in body:
        raise _WireError(f"missing {field!r}")
    value = body[field]
    if not isinstance(value, str) or not value.strip():
        raise _WireError(f"{field} must be a non-empty string")
    if len(value) > max_len:
        raise _WireError(f"{field} exceeds {max_len} chars")
    return value


def _require_choice(
    body: dict[str, Any], field: str, choices: list[str]
) -> str:
    value = _require_str(body, field, max_len=64)
    if value not in choices:
        raise _WireError(f"{field} must be one of {sorted(choices)}")
    return value


def _require_hex(
    body: dict[str, Any],
    field: str,
    *,
    max_bytes: int | None = None,
    exact_bytes: int | None = None,
) -> bytes:
    """Require a hex-string body field; decode to bytes with bounds.

    The hex string length is bounded BEFORE decoding so a hostile
    caller cannot force a large allocation (parser hardening).
    """
    if field not in body:
        raise _WireError(f"missing {field!r}")
    value = body[field]
    if not isinstance(value, str):
        raise _WireError(f"{field} must be a hex string")
    # Bound the hex string before `bytes.fromhex` allocates.
    if max_bytes is not None and len(value) > 2 * max_bytes:
        raise _WireError(
            f"{field} exceeds {max_bytes} bytes",
            "too-large",
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        )
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise _WireError(f"{field} is not valid hex") from exc
    if max_bytes is not None and len(decoded) > max_bytes:
        raise _WireError(
            f"{field} exceeds {max_bytes} bytes",
            "too-large",
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        )
    if exact_bytes is not None and len(decoded) != exact_bytes:
        raise _WireError(
            f"{field} must decode to exactly {exact_bytes} bytes"
        )
    return decoded


def _require_b64(body: dict[str, Any], field: str, *, max_bytes: int) -> bytes:
    """Require a base64 body field; decode to bytes with a size bound.

    The base64 string length is bounded BEFORE decoding so a hostile
    caller cannot force a large allocation (parser hardening).
    """
    if field not in body:
        raise _WireError(f"missing {field!r}")
    value = body[field]
    if not isinstance(value, str) or not value.strip():
        raise _WireError(f"{field} must be a non-empty base64 string")
    # base64 inflates ~4/3; bound the encoded length before decoding.
    if len(value) > (max_bytes // 3 + 1) * 4 + 8:
        raise _WireError(
            f"{field} exceeds {max_bytes} bytes",
            "too-large",
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        )
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _WireError(f"{field} is not valid base64") from exc
    if len(decoded) > max_bytes:
        raise _WireError(
            f"{field} exceeds {max_bytes} bytes",
            "too-large",
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        )
    if not decoded:
        raise _WireError(f"{field} decoded to empty")
    return decoded


def _optional_int(body: dict[str, Any], field: str) -> int | None:
    """An optional non-negative integer body field. Absent / null ⇒ None;
    `bool` is rejected (an `int` subclass)."""
    if field not in body or body[field] is None:
        return None
    value = body[field]
    if isinstance(value, bool) or not isinstance(value, int):
        raise _WireError(f"{field} must be an integer")
    if value < 0:
        raise _WireError(f"{field} must be ≥ 0")
    return value


def _require_choice_qp(
    request: Request, field: str, choices: list[str]
) -> str:
    value = request.query_params.get(field)
    if not value:
        raise _WireError(f"missing query parameter {field!r}")
    if value not in choices:
        raise _WireError(f"{field} must be one of {sorted(choices)}")
    return value


def _require_int_qp(
    request: Request, field: str, *, default: int, minimum: int = 0
) -> int:
    raw = request.query_params.get(field)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise _WireError(f"{field} must be an integer") from exc
    if value < minimum:
        raise _WireError(f"{field} must be ≥ {minimum}")
    return value


def _error(
    http_status: int,
    message: str,
    category: str,
    *,
    retry_after: int | None = None,
) -> Response:
    response = Response(
        {"error": message, "category": category}, status=http_status
    )
    if retry_after is not None:
        response["Retry-After"] = str(retry_after)
    return response


# ─── POST /v1/telemetry/vm-liveness ──────────────────────────────────


class VmLiveAttestationIngestView(APIView):
    """`POST /v1/telemetry/vm-liveness` — tenant-CVM live-attestation
    ingest, the uptime-COVERAGE meter's input (§23).

    Receives a KBS-L0-signed `SignedLiveAttestation` (raw
    `application/cbor`), produced by the guest keepalive agent talking to
    KBS `/v1/attest/keepalive` and relayed opaquely by the untrusted
    miner. The KBS L0 signature is the credential — no bearer token,
    exactly like the other signed-envelope ingress paths — and the miner
    cannot alter a single field of what it relays.

    Why this endpoint exists: a served receipt proves only that SOMEONE
    holds the guest telemetry key, which root inside the CVM can extract
    and keep using after the VM is killed. A live attestation proves the
    CVM was RUNNING: the KBS mints one only after verifying a fresh SNP
    report (AMD silicon root + §22 allowlist) whose REPORT_DATA bound a
    single-use KBS nonce to this vm_id.

    The persisted rows only ever become reward when
    `VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION` is armed; until then they
    accumulate as evidence an operator can inspect before arming (step 3
    of the arming sequence).
    """

    # The KBS-signed attestation is the credential (like the
    # host-attestor cert / graceful-exit / vm-progress CBOR ingress).
    authentication_classes: list[Any] = []
    # P2 object-level authorization: `AllowAny` miner-signed ingress.
    object_scope = scoping.PUBLIC
    permission_classes = [AllowAny]
    throttle_scope = "vm_liveness"
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Ingest a KBS-signed tenant-CVM live attestation",
        description=(
            "A relayed `SignedLiveAttestation` (raw application/cbor). vali "
            "verifies the KBS L0 signature against the pinned "
            "`VALI_KBS_L0_VERIFYING_KEY` (503 when unwired — an unverified "
            "attestation is never recorded), checks expiry + clock skew + "
            "the launch billing binding, and records the sample as uptime "
            "coverage. A replay is idempotent and extends no coverage."
        ),
        tags=["Telemetry"],
        request=OpenApiTypes.BINARY,
        responses={
            200: VmLiveAttestationResponseSerializer,
            400: OpenApiResponse(
                ErrorSerializer, "Empty / bad / expired / unbound attestation."
            ),
            413: OpenApiResponse(ErrorSerializer, "Body too large."),
            503: OpenApiResponse(
                ErrorSerializer, "KBS L0 key unwired / verifier unavailable."
            ),
        },
    )
    def post(self, request: Request) -> Response:
        envelope = request.body
        if not envelope:
            return _error(
                status.HTTP_400_BAD_REQUEST, "empty live-attestation body", "wire"
            )
        if len(envelope) > _MAX_LIVE_ATTESTATION_BYTES:
            return _error(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"live attestation exceeds {_MAX_LIVE_ATTESTATION_BYTES} bytes",
                "too-large",
            )
        try:
            row, created = vm_liveness.ingest_live_attestation(
                envelope=bytes(envelope)
            )
        except vm_liveness.LiveAttestationRefused as exc:
            return _error(exc.http_status, exc.message, exc.category)
        return Response(
            {
                "vm_id": row.vm_id,
                "attestation_seq": row.attestation_seq,
                "verified_at_unix": row.verified_at_unix,
                "recorded": created,
            },
            status=status.HTTP_200_OK,
        )
