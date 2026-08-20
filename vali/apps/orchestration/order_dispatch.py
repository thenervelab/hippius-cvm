"""§H phase-2 — vali → Edge → miner-agent lifecycle-order dispatch.

The signing chain laid down by PR #144 (Vault-loaded Ed25519 order seed
+ matching pubkey rendered into every miner's Ansible config) and
closed by the Edge inner-listener (`POST /v1/edge/order`) is exercised
from here: vali builds a canonical-CBOR ``OrderBody``, posts it to the
Edge, the Edge signs it + forwards to the target miner-agent, the
miner-agent verifies + dispatches.

## What this module does NOT do

- No signature work in Python. The body bytes are built by the
  Rust ``ticket-validator encode-order`` subprocess (canonical CBOR via
  ``hippius_types::cbor::to_canonical_vec`` — the same helper the §6
  ticket envelope uses). The Ed25519 signing lives on the Edge.
- No URL composition with caller data. The target miner address comes
  from ``MinerIdentity.netbird_ip`` (PR #120) — a chain-provisioned
  attribute, NEVER from the request body — and is sent to the Edge as
  the ``X-Hippius-Target-Addr`` header where the Edge re-validates it
  against the NetBird CGNAT range (defense-in-depth).
- No retries here. The orchestrator's existing tick policy
  (``vali_orchestration_tick``) governs retry-on-502-or-timeout; this
  module's job is a single round-trip whose outcome is reported back
  faithfully (status code + decoded miner-side classifier).

## Wire contract (vali → Edge)

POST ``{VALI_EDGE_ORDER_URL}/v1/edge/order``::

    Content-Type: application/cbor
    X-Hippius-Target-Addr: 100.64.0.10:9700
    X-Hippius-Order-Kind: launch        # or stop / destroy / migrate
    <body: canonical-CBOR OrderBody bytes from `encode-order`>

Response: the miner's HTTP status verbatim (200 on accept, 4xx static
classifier like ``bad-signature`` / ``order-id-collision`` / ``replay``
on reject), or 502 on Edge transport failure to the miner.

The Edge has NO mTLS for vali — access is gated by the Cilium
NetworkPolicy on the edge-gateway Service's inner-listener port (only
the vali pod's PodSelector is admitted). See the chart's
``networkpolicy.yaml``.
"""

from __future__ import annotations

import base64
import http.client
import logging
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from django.conf import settings

log = logging.getLogger("apps.orchestration.order_dispatch")


class OrderDispatchError(Exception):
    """The vali → Edge → miner dispatch did not succeed."""


class OrderDispatchUnavailable(OrderDispatchError):
    """The Edge or miner is unreachable. Transient — the orchestrator
    retries on the next tick until the phase deadline.
    """


class OrderDispatchMisconfigured(OrderDispatchError):
    """A required setting (e.g. ``VALI_EDGE_ORDER_URL``,
    ``VALI_TICKET_VALIDATOR_BIN``) is missing or empty, or the
    miner-id has no NetBird IP recorded. Operator misconfiguration —
    surfaced distinctly so the orchestrator does not loop on it.
    """


# ── Header constants — mirrored from
#    ``binaries/edge-gateway/src/listeners/inner_router.rs`` ───────────


#: Header carrying the target miner's NetBird socket address
#: (``100.64.x.y:9700``). The Edge validates this against the
#: ``100.64.0.0/10`` CGNAT range before invoking the miner forwarder.
TARGET_ADDR_HEADER = "X-Hippius-Target-Addr"

#: Header carrying the kebab-case ``OrderKind`` — ``launch`` /
#: ``stop`` / ``destroy`` / ``migrate``. Closed vocabulary; anything
#: else is rejected by the Edge with ``bad-kind``.
ORDER_KIND_HEADER = "X-Hippius-Order-Kind"

#: Default miner orders-server port. The miner-agent binds this port
#: on its NetBird interface only (see
#: ``deploy/ansible/playbooks/miner-tasks/templates/miner-agent-config.toml.j2``).
DEFAULT_MINER_ORDERS_PORT = 9700

#: HTTP timeout (seconds) for the vali → Edge POST. Sized above the
#: Edge → miner forwarder's whole-request timeout (30 s) plus slack so
#: a slow miner does not race vali's client-side timeout.
DEFAULT_DISPATCH_TIMEOUT_S = 45.0


@dataclass(frozen=True)
class DispatchResult:
    """Outcome of a single dispatch round-trip.

    - ``ok`` is true iff the miner returned 2xx (signed order accepted).
    - ``status`` is the upstream status the miner replied with, or 502
      if the Edge could not reach the miner.
    - ``classifier`` is the static string the miner-agent responds with
      on 4xx — opaque to vali, surfaced verbatim so the orchestrator
      can branch on the exact failure mode (``bad-signature``,
      ``order-id-collision``, ``replay``, …).
    """

    ok: bool
    status: int
    classifier: str


def _required_setting(name: str) -> str:
    value = str(getattr(settings, name, "") or "").strip()
    if not value:
        raise OrderDispatchMisconfigured(f"{name} is not configured")
    return value


def _validated_edge_url() -> str:
    """Return the configured edge URL after a structural sanity check.

    Catches the operator-misconfig path codex r2 Low flagged: a
    malformed ``VALI_EDGE_ORDER_URL`` (embedded credentials, whitespace
    in the host, missing scheme) raises ``http.client.InvalidURL`` /
    ``ValueError`` from ``urllib.request.Request`` whose ``str(exc)``
    can include URL fragments — and ``urlopen`` raises them too late
    for the static `except` to catch as transport. Reject up-front
    with a STATIC `Misconfigured` classifier; the bad value never
    reaches a log line.
    """
    raw = _required_setting("VALI_EDGE_ORDER_URL")
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError as exc:
        # `urlsplit` itself is extremely forgiving — this branch is
        # defensive, fired only on a value `urlsplit` actively refuses.
        raise OrderDispatchMisconfigured(
            "VALI_EDGE_ORDER_URL is malformed"
        ) from exc
    if parsed.scheme not in ("http", "https"):
        raise OrderDispatchMisconfigured(
            "VALI_EDGE_ORDER_URL must be http(s)://"
        )
    if not parsed.hostname:
        raise OrderDispatchMisconfigured(
            "VALI_EDGE_ORDER_URL is missing a hostname"
        )
    # Reject embedded credentials — the inner listener is plain HTTP
    # behind a NetworkPolicy, so a `user:pass@` in the URL is at best a
    # noisy misconfig and at worst leaks secrets into the InvalidURL
    # exception text when urlopen rejects it.
    if parsed.username is not None or parsed.password is not None:
        raise OrderDispatchMisconfigured(
            "VALI_EDGE_ORDER_URL must not embed credentials"
        )
    return raw


def _encode_order_body(
    *,
    order_id: str,
    kind: str,
    target_miner_id: str,
    issued_at_unix: int,
    payload_json: bytes,
) -> bytes:
    """Shell out to ``hippius-ticket-validator encode-order``.

    The Rust binary builds the canonical-CBOR ``OrderBody`` (the §H
    phase-2 wire shape the miner-agent decodes); Python here is
    deliberately blind to the CBOR layout — single source of truth.

    ``target_miner_id`` + ``issued_at_unix`` close the gemini r1 High
    findings (cross-miner replay + long-term replay): the body now
    cryptographically binds to a specific host AND a freshness window
    that the miner-agent enforces post-signature-verify.

    Raises ``OrderDispatchMisconfigured`` on a binary / args problem,
    ``OrderDispatchError`` on an empty stdout (validator bug — never
    expected).
    """
    binary = _required_setting("VALI_TICKET_VALIDATOR_BIN")
    timeout = float(
        getattr(settings, "VALI_TICKET_VALIDATOR_TIMEOUT_S", 2.0)
    )
    try:
        completed = subprocess.run(
            [
                binary,
                "encode-order",
                "--order-id",
                order_id,
                "--kind",
                kind,
                "--target-miner-id",
                target_miner_id,
                "--issued-at-unix",
                str(int(issued_at_unix)),
            ],
            input=payload_json,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise OrderDispatchMisconfigured(
            "encode-order: validator binary not found"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise OrderDispatchError("encode-order: validator timeout") from exc

    if completed.returncode != 0:
        # The validator's stderr carries the static classifier (e.g.
        # ``encode-order: bad-kind``); surface it so the operator sees
        # the cause. Never leak stdout — it could be partial CBOR
        # bytes the §20 logging discipline forbids.
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise OrderDispatchError(f"encode-order: validator exit {completed.returncode}: {stderr}")

    body = completed.stdout
    if not body:
        # An empty body would still be accepted by the Edge (it would
        # fail the miner-side CBOR decode), so surface this here.
        raise OrderDispatchError("encode-order: validator produced empty body")
    return body


def _post_to_edge(
    *,
    body_bytes: bytes,
    target_addr: str,
    kind: str,
    edge_url: str,
    timeout_s: float,
) -> tuple[int, bytes]:
    """One HTTP POST to the Edge inner listener. Returns
    ``(status, response_body)``. Raises ``OrderDispatchUnavailable`` on
    a transport failure — the URL never reaches the exception text.
    """
    # Build the Request inside the try/except so even
    # `http.client.InvalidURL` / `ValueError` raised by `Request.__init__`
    # for a pathological URL value (codex r2 Low) flows through the
    # static-classifier path rather than bubbling a message that
    # contains URL fragments.
    try:
        request = urllib.request.Request(
            edge_url.rstrip("/") + "/v1/edge/order",
            data=body_bytes,
            headers={
                "Content-Type": "application/cbor",
                TARGET_ADDR_HEADER: target_addr,
                ORDER_KIND_HEADER: kind,
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=timeout_s) as resp:  # noqa: S310
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        # The Edge / miner answered with a non-2xx — read the body for
        # the classifier and return; never raise on an HTTP response.
        return exc.code, exc.read()
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        # Transport failure — Edge unreachable, DNS, connect refused,
        # timeout. The error text is a STATIC classifier; the original
        # exception is preserved as `__cause__` for traceback debugging
        # but never interpolated into the message. Some lower-level
        # exceptions (e.g. `socket.gaierror`) can stringify with host
        # info; keeping the message static — codex r1 Low — keeps the
        # `URL never in exception text` rule airtight against any
        # future exception subclass.
        raise OrderDispatchUnavailable("edge-order: peer unreachable") from exc
    except (http.client.InvalidURL, ValueError) as exc:
        # Codex r2 Low: an embedded-credential or whitespace-in-host
        # URL value raises `InvalidURL` / `ValueError` from `Request`
        # whose `str(exc)` echoes URL fragments (incl. the password
        # half of `user:pass@host`). `_validated_edge_url` rejects
        # most of these up-front, but keep this as a belt-and-suspenders
        # catch with a STATIC classifier — vali's URL is operator-set,
        # not derived from request input, so `Misconfigured` is the
        # right class.
        raise OrderDispatchMisconfigured("VALI_EDGE_ORDER_URL is malformed") from exc


def dispatch_order(
    *,
    miner_id: str,
    netbird_ip: str,
    order_id: str,
    kind: str,
    payload_json: bytes,
    timeout_s: float | None = None,
) -> DispatchResult:
    """Build + sign-via-Edge + forward-to-miner one lifecycle order.

    ``miner_id``: caller-supplied for log attribution ONLY; routing is
    keyed on ``netbird_ip`` (the trusted source — vali's
    ``MinerIdentity.netbird_ip``, chain-provisioned per PR #120).
    ``netbird_ip``: the miner's NetBird ``100.64.x.y`` address. vali
    composes the ``:9700`` socket address from it — the orders-server
    port is fixed per the Ansible template; if a per-miner override is
    ever needed it goes in a new MinerIdentity column, never in the
    request body.
    ``order_id``: idempotency key. Same id processed twice → same
    outcome on the miner side, the second a no-op success.
    ``kind``: ``launch`` / ``stop`` / ``destroy`` / ``migrate``.
    ``payload_json``: raw JSON bytes (the kind-specific fields — see
    ``binaries/ticket-validator/src/encode_order.rs`` for the schema).
    """
    if not netbird_ip:
        raise OrderDispatchMisconfigured(
            f"miner {miner_id!r} has no netbird_ip recorded"
        )

    edge_url = _validated_edge_url()
    # `issued_at_unix` stamped HERE (vali side) is the value the
    # miner-agent's ±MAX_ORDER_AGE_SECS window is checked against. Once
    # the body is built the order can be retried for the full window;
    # past that, regenerate so the same `order_id` rides a fresher
    # timestamp (idempotency holds because the miner-agent dedups on
    # order_id alone).
    body_bytes = _encode_order_body(
        order_id=order_id,
        kind=kind,
        target_miner_id=miner_id,
        issued_at_unix=int(time.time()),
        payload_json=payload_json,
    )
    target_addr = f"{netbird_ip}:{DEFAULT_MINER_ORDERS_PORT}"
    timeout = float(timeout_s if timeout_s is not None else DEFAULT_DISPATCH_TIMEOUT_S)

    status, resp_body = _post_to_edge(
        body_bytes=body_bytes,
        target_addr=target_addr,
        kind=kind,
        edge_url=edge_url,
        timeout_s=timeout,
    )
    classifier = resp_body.decode("utf-8", errors="replace").strip()
    ok = 200 <= status < 300
    log.info(
        "order_dispatch: miner=%s kind=%s order_id=%s target=%s status=%d ok=%s",
        miner_id,
        kind,
        order_id,
        target_addr,
        status,
        ok,
    )
    return DispatchResult(ok=ok, status=status, classifier=classifier)


# ── Convenience builders for typical payloads ────────────────────────


def build_launch_payload(
    *,
    vm_id: str,
    ovmf_path: str,
    kernel_path: str,
    initrd_path: str,
    cmdline: str,
    luks_disk_path: str,
    luks_disk_size_gb: int,
    rootfs_data_path: str,
    rootfs_hash_path: str,
    cpu_count: int,
    memory_mb: int,
    cose_ticket: bytes,
    data_disk_size_gb: int = 0,
) -> dict[str, Any]:
    """Build the JSON payload for a ``launch`` order — mirrors the
    Rust ``LaunchOrder`` shape.

    ``cose_ticket`` is the byte-exact L1-emitted COSE_Sign1 envelope —
    the same bytes ``apps.orders.models.OrderTicket.cose_blob`` stores.
    The miner-agent pushes them to the guest over AF_VSOCK after the
    domain reaches Running (``binaries/miner-agent/src/vsock/
    ticket_push.rs``). On the JSON wire the blob travels as a base64
    string; the Rust ``LaunchOrder.cose_ticket: ByteBuf`` decodes that
    back to raw bytes byte-identical to ``OrderTicket.cose_blob``.
    Empty / oversize bytes are caught at the miner-agent boundary
    (``MinerAgentError::TicketDelivery``); vali rejects only the
    structurally-impossible inputs (non-bytes, empty).
    """
    if not isinstance(cose_ticket, (bytes, bytearray)):
        raise TypeError(
            "cose_ticket must be bytes — the raw L1 COSE_Sign1 envelope"
        )
    if len(cose_ticket) == 0:
        # An empty COSE blob would dispatch fine but stall every guest
        # at the §21 ticket-load stage. Fail loud at the producer.
        raise ValueError("cose_ticket is empty — refusing to dispatch")
    return {
        "vm_id": vm_id,
        "ovmf_path": ovmf_path,
        "kernel_path": kernel_path,
        "initrd_path": initrd_path,
        "cmdline": cmdline,
        "luks_disk_path": luks_disk_path,
        "luks_disk_size_gb": int(luks_disk_size_gb),
        # #365 — size of the tenant data disk the miner attaches at
        # /dev/vde (the flavor `disk_gb`); 0 ⇒ no data disk. The Rust
        # LaunchOrder reads this via `#[serde(default)]`, so an absent
        # field (older vali) is also accepted.
        "data_disk_size_gb": int(data_disk_size_gb),
        "rootfs_data_path": rootfs_data_path,
        "rootfs_hash_path": rootfs_hash_path,
        "cpu_count": int(cpu_count),
        "memory_mb": int(memory_mb),
        # `serde_bytes::ByteBuf` JSON-decodes from a base64 string by
        # convention — same shape as ``SignedOrder.body`` / ``…sig``.
        "cose_ticket": base64.b64encode(bytes(cose_ticket)).decode("ascii"),
    }


def build_stop_payload(*, vm_id: str, graceful: bool) -> dict[str, Any]:
    """JSON payload for a ``stop`` order."""
    return {"vm_id": vm_id, "graceful": bool(graceful)}


def build_destroy_payload(*, vm_id: str) -> dict[str, Any]:
    """JSON payload for a ``destroy`` order."""
    return {"vm_id": vm_id}


def build_migrate_payload(*, vm_id: str) -> dict[str, Any]:
    """JSON payload for a ``migrate`` order (the miner-agent currently
    answers 501 — wire is in place ahead of §25 mechanics).
    """
    return {"vm_id": vm_id}


def build_migrate_activate_payload(
    *,
    vm_id: str,
    get_url: str,
    state_get_url: str = "",
    new_gen: int,
    ovmf_path: str,
    kernel_path: str,
    initrd_path: str,
    cmdline: str,
    luks_disk_path: str,
    luks_disk_size_gb: int,
    rootfs_data_path: str,
    rootfs_hash_path: str,
    cpu_count: int,
    memory_mb: int,
    cose_ticket: bytes,
    boot_artifacts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the JSON payload for a §25 M4 ``migrate-activate`` order —
    mirrors the Rust ``MigrateActivateOrder`` shape.

    The dual of [`build_launch_payload`]: it carries the SAME measured
    launch tuple (ovmf / kernel / initrd / cmdline / luks / cpu / mem /
    cose_ticket) plus the §25-specific ``get_url`` (presigned snapshot
    GET), ``new_gen`` (the forward-only destination generation the cmdline
    re-attests at), and the optional ``boot_artifacts`` M3 staging bundle.

    ``cose_ticket`` travels as a base64 string on the JSON wire (the same
    convention as the launch payload); the ticket-validator
    ``encode-order`` re-emits it as a CBOR byte-string so the miner-agent's
    ``ByteBuf`` decodes it byte-identical. ``boot_artifacts`` is passed
    through verbatim (already the ``DestStagingArtifacts`` JSON shape from
    `effects.resolve_boot_artifacts`); ``None`` ⇒ the key is omitted and the
    dest relies on its pre-staged-artifact existence check.
    """
    if not isinstance(cose_ticket, (bytes, bytearray)):
        raise TypeError("cose_ticket must be bytes — the raw L1 COSE_Sign1 envelope")
    if len(cose_ticket) == 0:
        raise ValueError("cose_ticket is empty — refusing to dispatch")
    payload: dict[str, Any] = {
        "vm_id": vm_id,
        "get_url": get_url,
        "new_gen": int(new_gen),
        "ovmf_path": ovmf_path,
        "kernel_path": kernel_path,
        "initrd_path": initrd_path,
        "cmdline": cmdline,
        "luks_disk_path": luks_disk_path,
        "luks_disk_size_gb": int(luks_disk_size_gb),
        "rootfs_data_path": rootfs_data_path,
        "rootfs_hash_path": rootfs_hash_path,
        "cpu_count": int(cpu_count),
        "memory_mb": int(memory_mb),
        "cose_ticket": base64.b64encode(bytes(cose_ticket)).decode("ascii"),
    }
    # Presigned GET for the source's anti-rollback state disk. OMITTED
    # when empty, not emitted as "": the encoder's `optional_string_field`
    # rejects an empty string outright, and an omitted key keeps the body
    # BYTE-IDENTICAL to the pre-#876 wire so a miner-agent that predates
    # the field (`deny_unknown_fields`) still decodes the order.
    if state_get_url:
        payload["state_get_url"] = state_get_url
    # Omit `boot_artifacts` entirely when absent — the ticket-validator
    # encoder + the miner-agent's `#[serde(default)]` both treat an absent
    # key as "no staging bundle" (out-of-band / pre-staged artifacts).
    if boot_artifacts is not None:
        payload["boot_artifacts"] = boot_artifacts
    return payload
