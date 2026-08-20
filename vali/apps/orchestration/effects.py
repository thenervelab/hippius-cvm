"""External-system effects for the §24/§25 orchestrators.

vali **orchestrates only** — it never sees plaintext or relays the
ciphertext bytes (§25). Every cross-service interaction the
orchestrator needs goes through one of the functions here:

- the **Edge gateway** (`VALI_EDGE_GATEWAY_URL`) relays guest-ward
  commands + carries back guest-signed acks (quiesce, snapshot
  trigger/poll, source-stopped ack, EOL shutdown, EOL ack);
- the **KBS admin** surface (`VALI_KBS_ADMIN_URL`) performs the §25
  destination key release. (It does NOT crypto-erase: the §24 data-death
  is a Vault-Transit key destroy — see `crypto_erase_kek_transit`.)
- the **NetBird** management API revokes the VM's peer (§12/§24
  graceful teardown).

Each function is the orchestrator's single mockable seam for that
interaction — the test suite monkeypatches them. The transport is
stdlib `urllib` (no new dependency); the peer endpoints are internal
control-plane services configured per deployment.

Failure model: `EffectUnavailable` (infra unreachable / unconfigured
— the orchestrator retries) and `EffectError` (the peer answered but
the operation failed — retried until the phase deadline). Neither
ever carries a credential: error strings name the effect, never the
URL or the NetBird token.
"""

from __future__ import annotations

import json
import logging
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover — typing only, no runtime import edge
    from apps.orchestration.services.kbs_admin_tls import KbsAdminTransport

from django.conf import settings

from apps.lifecycle.models import Vm

log = logging.getLogger("apps.orchestration.effects")

#: Golden dm-verity-overlay disk mode (mirrors `service._DISK_MODE_GOLDEN_
#: VERITY` / `launch_jobs._DISK_MODE_GOLDEN_VERITY` / `TenantBakeDiskMode`).
#: A golden VM boots the OS from a SHARED read-only dm-verity base, so its §25
#: dest-activation must stage that base (rootfs.img + rootfs.verity), unlike a
#: legacy VM whose OS rides the per-VM LUKS volume.
_DISK_MODE_GOLDEN_VERITY = "golden_verity_overlay"

#: `vm_id` charset lock — the SAME `[a-z0-9-]{1,64}` rule the launch API
#: enforces before a vm_id is ever interpolated into a Vault path. Re-checked
#: here as defence-in-depth before the golden crypto-erase derives the Transit
#: key name + KV path from `vm.vm_id`, so "erase the WRONG key" is impossible
#: even if a malformed vm_id ever reached the DB.
_VM_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")


class EffectError(Exception):
    """Base class — an orchestration side-effect did not succeed."""


class EffectUnavailable(EffectError):
    """The peer service is unreachable or not configured. Transient:
    the orchestrator retries on the next tick until the phase
    deadline.
    """


# ─── HTTP transport (stdlib urllib — no third-party dependency) ──────


def _timeout() -> float:
    return float(getattr(settings, "VALI_ORCHESTRATION_EFFECT_TIMEOUT_S", 15.0))


def _http(
    method: str,
    url: str,
    *,
    label: str,
    json_body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    context: ssl.SSLContext | None = None,
) -> tuple[int, bytes]:
    """One HTTP round-trip. Returns `(status, body)` for any HTTP
    response (incl. 4xx/5xx, so callers can treat e.g. 404 as "not
    found"); raises `EffectUnavailable` only on a transport failure.

    `label` names the effect for diagnostics — the URL (which may
    embed a credential) is NEVER placed in an exception or log line.

    `context` is the TLS context for the hop. `None` reproduces the
    stdlib default exactly (plaintext for http, system trust store for
    https), which is what every non-KBS caller here wants; the KBS admin
    callers pass the pinned-CA + client-identity context from
    `services.kbs_admin_tls` so their hop is mutually authenticated.
    It is a per-call argument rather than a module default because the
    other peers on this function (Edge, NetBird) have their own trust
    stories and must not silently inherit the admin identity.
    """
    data: bytes | None = None
    hdrs = dict(headers or {})
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(  # noqa: S310
            request, timeout=_timeout(), context=context
        ) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        # An HTTP error *response* — return it so the caller decides
        # (404 may be benign). Reading the body cannot fail closed.
        return exc.code, exc.read()
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        # A transport failure — never includes the URL.
        raise EffectUnavailable(f"{label}: peer unreachable ({exc})") from exc


def _json(body: bytes, *, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EffectError(f"{label}: non-JSON response") from exc
    if not isinstance(parsed, dict):
        raise EffectError(f"{label}: response is not a JSON object")
    return parsed


def _required_setting(name: str) -> str:
    value = str(getattr(settings, name, "") or "").strip()
    if not value:
        raise EffectUnavailable(f"{name} is not configured")
    return value


# ─── Edge-gateway relay (guest-ward, §25) ────────────────────────────


def _edge_post(vm: Vm, command: str, body: dict[str, Any]) -> None:
    base = _required_setting("VALI_EDGE_GATEWAY_URL").rstrip("/")
    url = f"{base}/v1/relay/{vm.vm_id}/{command}"
    label = f"edge-relay:{command}"
    status, _ = _http("POST", url, label=label, json_body=body)
    if not 200 <= status < 300:
        raise EffectError(f"{label}: peer returned HTTP {status}")


#: Header the Edge relay's GET routes (`snapshot` status, §25 M2
#: `source-ack`) read to learn the SOURCE miner's NetBird socket address
#: — a GET has no JSON body to carry `miner_addr`, so the routing target
#: rides here. Mirrors the inner order router's `x-hippius-target-addr`
#: (`binaries/edge-gateway/src/listeners`); the Edge re-validates it
#: against the NetBird CGNAT range before dialing.
_TARGET_ADDR_HEADER = "x-hippius-target-addr"


def _edge_get(vm: Vm, path: str) -> tuple[int, bytes]:
    # Default: route to the SOURCE miner (snapshot status, §25 M2 source-ack).
    return _edge_get_addr(vm, path, _source_miner_addr(vm))


def _edge_get_addr(vm: Vm, path: str, target_addr: str) -> tuple[int, bytes]:
    base = _required_setting("VALI_EDGE_GATEWAY_URL").rstrip("/")
    url = f"{base}/v1/relay/{vm.vm_id}/{path}"
    # The Edge GET relay routes route on the `x-hippius-target-addr` header
    # (no body on a GET). The default source-side polls carry the source
    # miner's address; the §25 dest-activation poll carries the DESTINATION's
    # (so the SAME `migration/{vm}/status` route reads the dest's phase).
    headers = {_TARGET_ADDR_HEADER: target_addr}
    return _http("GET", url, label=f"edge-relay:{path}", headers=headers)


#: Fixed port the miner-agent orders server binds on its NetBird
#: interface (`binaries/miner-agent/src/orders/mod.rs::ORDERS_PORT`).
#: The §25 M1 relay routes reach the source miner's quiesce/snapshot
#: handlers there, exactly as the launch/stop order-dispatch path does.
_MINER_ORDERS_PORT = 9700


def destroy_target_miner_id(vm: Vm) -> str:
    """Resolve which miner might be holding a domain for this VM, for the
    §24 force-stop ONLY. Deliberately WIDER than [`_bound_miner_id`].

    `_bound_miner_id` answers "where is this VM bound", and its strict
    `vm.host`-or-SUCCEEDED-launch semantics are load-bearing for the §25
    relay and the EOL push — do not widen it.

    The destroy asks a different question: "who might have a domain to
    stop". A launch that FAILED after the order reached the miner can
    still have left a running domain, and its `LaunchJob` records the
    miner it was sent to. Discarding that and skipping the destroy would
    leave a live CVM tombstoned as Destroyed — the exact zombie the
    fail-loud check exists to prevent. Dispatching to a merely-POSSIBLE
    host costs nothing: the order carries the `vm_id`, and the miner's
    `handle_destroy` is an idempotent no-op for a `vm_id` it does not
    know, so a misroute is fail-safe.

    ⚠️ That no-op is a CROSS-REPO invariant, and it is load-bearing for
    THIS resolver specifically. In `CvmLifecycle::destroy`
    (`binaries/miner-agent/src/lifecycle/mod.rs`) it is now the
    "nothing to reclaim ⇒ nothing to prove" early return: the agent stats
    the VM's per-VM footprint FIRST and returns `Ok` before it ever
    consults libvirt when none of those paths exist. `handle_destroy` does
    NOT map `VmNotFound → Ok` the way `handle_stop` does, so that early
    return is the whole of the guarantee.

    Make the agent prove domain liveness UNCONDITIONALLY and this widened
    resolver becomes a §24-FAILURE AMPLIFIER: a destroy aimed at a
    merely-possible host whose libvirtd is down — or whose domain
    enumeration lost a benign race — would raise, the job would retry to
    its step timeout, `_destroy_vm` would never run, and the VM would pin
    in `Decommissioning` with no API-reachable recovery. That regression
    was written and caught in review (#880); keep the stat-first shape.

    Behaviour this widening already implies: a possible-host that is DARK
    makes `dispatch_destroy` raise where skipping would have completed.
    That is deliberate §24 policy — failing loud beats silently tombstoning
    a VM whose domain was never proven gone — but such a teardown only
    finishes once that miner answers.

    Order: `vm.host` → latest SUCCEEDED `LaunchJob` → latest `LaunchJob`
    in ANY state that names a miner. `""` only when no vali record has
    ever named a miner for this VM (a placement that never dispatched),
    in which case there is genuinely nowhere to send it.

    Every source is an authoritative vali placement record — never
    request, tenant or miner-supplied data — so no untrusted input can
    steer the destroy.
    """
    bound = _bound_miner_id(vm)
    if bound:
        return bound
    from apps.orchestration.models import LaunchJob

    miner_id = (
        LaunchJob.objects.filter(vm_id=vm.vm_id)
        .exclude(miner_id="")
        .order_by("-started_at")
        .values_list("miner_id", flat=True)
        .first()
    )
    return str(miner_id) if miner_id else ""


def _bound_miner_id(vm: Vm) -> str:
    """Resolve the ``node_id`` (== ``MinerIdentity`` primary key) of the
    miner this VM is currently bound to, from TRUSTED vali records ONLY.

    Prefers ``vm.host`` (written on a successful launch + on §25
    migrate-activation). Falls back to the miner recorded on the VM's
    latest SUCCEEDED ``LaunchJob`` when ``vm.host`` is empty — the case
    for every VM launched via the async ``POST /v1/vm/launch`` path
    BEFORE the launch worker began stamping ``vm.host`` (the async worker
    historically recorded the placed miner ONLY on ``LaunchJob.miner_id``;
    ``vm.host`` was written solely by §25 activation). Without this
    fallback, ``dispatch_destroy`` / the EOL relay resolve a miner from an
    empty ``vm.host`` → the §24 destroy order never routes (zombie
    domain) and the EOL push silently no-ops (``node_id=""``).

    Both sources are authoritative vali placement records — NEVER request,
    tenant, or miner-supplied data — so no untrusted input can steer the
    destroy/EOL routing. Returns ``""`` when neither is known; callers
    fail LOUD (a destroy that cannot route must not tombstone a zombie as
    Destroyed).
    """
    if vm.host:
        return str(vm.host)
    # Local import to avoid a module-level cycle (models → effects).
    from apps.orchestration.models import LaunchJob, LaunchJobState

    miner_id = (
        LaunchJob.objects.filter(
            vm_id=vm.vm_id, state=LaunchJobState.SUCCEEDED.value
        )
        .exclude(miner_id="")
        .order_by("-finished_at")
        .values_list("miner_id", flat=True)
        .first()
    )
    return str(miner_id) if miner_id else ""


def bound_miner_id(vm: Vm) -> str:
    """Public alias of [`_bound_miner_id`] for CONSUMERS OUTSIDE this app.

    The §K telemetry ingress (`apps.telemetry.views.MinerVmProgressIngest
    View`) authorizes a miner-signed boot-progress report against the
    miner this VM is bound to, and that question has exactly one correct
    answer in vali — the one `_bound_miner_id` computes from vali's own
    launch records. Exporting it (rather than re-deriving the binding in
    the telemetry app) keeps ONE resolver: widen or narrow it here and
    every consumer moves together.

    Returns the `MinerIdentity` primary key, or `""` when no vali record
    has ever bound this VM to a miner (the caller decides the policy for
    that — the telemetry gate REFUSES).
    """
    return _bound_miner_id(vm)


def _source_miner_addr(vm: Vm) -> str:
    """Resolve the source miner's NetBird ``100.64.x.y:9700`` socket
    address from the VM's bound ``node_id`` (== the ``MinerIdentity``
    primary key), via [`_bound_miner_id`] (``vm.host`` or the latest
    SUCCEEDED ``LaunchJob.miner_id`` fallback).

    The §25 M1 Edge relay needs BOTH the routing address AND the
    ``node_id`` — exactly the two pieces the launch/stop order-dispatch
    path resolves (``MinerIdentity.netbird_ip`` for routing, the
    ``miner_id`` for the miner-agent's signed-order target binding).
    The relay route forwards to this address the SAME way
    ``order_dispatch.dispatch_order`` does. Imported lazily so this
    module stays import-light for the non-relay effects.
    """
    # Local import to avoid a module-level dependency on the miners app
    # from the orchestration effects (which the §24 paths do not need).
    from apps.miners.models import MinerIdentity

    node_id = _bound_miner_id(vm)
    try:
        identity = MinerIdentity.objects.get(miner_id=node_id)
    except MinerIdentity.DoesNotExist as exc:
        raise EffectError(
            f"edge-relay: source miner {node_id!r} has no MinerIdentity"
        ) from exc
    if not identity.netbird_ip:
        raise EffectError(
            f"edge-relay: source miner {node_id!r} has no netbird_ip recorded"
        )
    return f"{identity.netbird_ip}:{_MINER_ORDERS_PORT}"


def relay_quiesce(vm: Vm, *, source_gen: int) -> None:
    """§25 step 2 — tell the source miner to quiesce (clean stop) the
    measured guest so the snapshot is crash-consistent.

    ``node_id`` is the source miner_id the Edge binds into the signed
    order's ``target_miner_id``; ``miner_addr`` is the NetBird socket
    address the Edge routes to (mirroring the launch/stop dispatch).

    §25 M3 — the quiesce ALSO carries vali's single-use ``eol_nonce`` +
    the ``source_gen`` the source guest must sign its ``stopped{}`` ack
    at (its CURRENT generation, NOT ``new_gen`` — SECURITY INVARIANT #1)
    + the ``lease_id``. The source miner hands these to the still-running
    guest's signer, captures the opaque signed ack, and surfaces it for
    ``poll_source_ack``. The nonce is a §20 single-use secret: it is
    minted fresh per migration and cleared on dest-activation, so it can
    never be replayed. It rides the signed relay body (the same channel
    the measured launch order's ticket travels) and is NEVER logged.

    The nonce MUST already be minted on the VM (``start_migration`` mints
    it before the first quiesce); a missing nonce is a producer bug —
    fail closed loudly rather than relay a quiesce the guest cannot sign.
    """
    if not vm.eol_nonce:
        raise EffectError(
            "relay-quiesce: vm has no eol_nonce — not prepared for the §25 ack"
        )
    _edge_post(
        vm,
        "quiesce",
        {
            "node_id": _bound_miner_id(vm),
            "miner_addr": _source_miner_addr(vm),
            "lease_id": vm.lease_id,
            "source_gen": int(source_gen),
            "eol_nonce_hex": bytes(vm.eol_nonce).hex(),
        },
    )


def trigger_snapshot(vm: Vm, *, put_url: str, state_put_url: str = "") -> None:
    """§25 step 3 — tell the source miner to snapshot the LUKS2 +
    dm-integrity writable volume and upload it to the presigned PUT
    URL. The URL is short-TTL + single-object; it is passed here and
    never persisted in a job record.

    ``state_put_url`` carries the per-VM anti-rollback state disk (the
    guest's boot counter) in the same way. Both must land: a snapshot
    without the counter produces a destination that boots and never
    unlocks, so the miner marks the whole snapshot failed if the state
    upload fails.
    """
    _edge_post(
        vm,
        "snapshot",
        {
            "node_id": _bound_miner_id(vm),
            "miner_addr": _source_miner_addr(vm),
            "put_url": put_url,
            "state_put_url": state_put_url,
        },
    )


def poll_snapshot(vm: Vm) -> str:
    """§25 step 4 — poll the snapshot/upload progress. Returns
    `"running"`, `"done"`, or `"failed"`.
    """
    status, body = _edge_get(vm, "snapshot")
    if status != 200:
        raise EffectError(f"edge-relay:snapshot: poll returned HTTP {status}")
    state = _json(body, label="edge-relay:snapshot").get("status")
    if state not in ("running", "done", "failed"):
        raise EffectError(f"edge-relay:snapshot: unknown status {state!r}")
    return str(state)


def poll_domain_running(vm: Vm) -> bool | None:
    """Reboot-recovery liveness probe — ask the VM's bound miner whether
    the tenant domain is actually running RIGHT NOW.

    Relays `GET /v1/miner/vm/<vm_id>/domain-state` through the Edge to the
    bound miner (the same per-VM relay the §25 snapshot poll uses). The
    miner answers from libvirt truth:

      * ``True``  — the domain is Live (running / paused / …).
      * ``False`` — the domain is Down (shut-off / crashed / absent) — the
        state a host reboot leaves behind (the miner-agent re-adopts only
        still-running domains, so a powered-off tenant CVM stays down).
      * ``None``  — the signal is UNAVAILABLE: the miner is unreachable, or
        libvirt itself could not be queried (the miner answers HTTP 503),
        or any transport/decoding error. This is the FAIL-SAFE boundary —
        the caller MUST take NO recovery action on ``None``. A miner we
        cannot reach is a §25 (migration / quarantine) concern, never a
        reboot-recovery relaunch trigger.

    NEVER raises — a probe failure is folded into ``None`` so a single
    unreachable miner cannot break the reconcile tick.
    """
    try:
        addr = _source_miner_addr(vm)
    except (EffectError, EffectUnavailable):
        return None
    return _poll_domain_running_at(vm, addr)


def poll_domain_running_on(vm: Vm, node_id: str) -> bool | None:
    """[`poll_domain_running`], but against a miner vali merely SUSPECTS
    might hold a domain for this VM — resolved by the caller, not from
    ``vm.host``.

    Same widening, and the same justification, as
    [`destroy_target_miner_id`]: a launch that failed can still have left
    a running domain on the miner its order was sent to, and for such a VM
    ``vm.host`` is empty, so ``_bound_miner_id`` (and therefore
    ``poll_domain_running``) resolves NOTHING and answers ``None`` forever.
    An abandoned-launch reap needs the opposite of a routing decision: it
    needs to ASK the one host that could possibly be running the guest
    whether it is, and to treat any answer short of a definite ``False``
    as "do not touch this VM".

    ``node_id`` must come from an authoritative vali placement record (the
    VM's `LaunchJob` / `Placement`), never from request or miner data.
    Empty ⇒ ``None`` (unknown), never a licence to act.

    The verdict semantics are IDENTICAL to `poll_domain_running` and that
    is the point: ``False`` (the miner affirmatively reports no live
    domain) is the ONLY value a destructive caller may act on; ``True``
    and ``None`` both mean "not proven absent".
    """
    if not node_id:
        return None
    try:
        _miner_id, netbird_ip = _miner_identity(node_id)
    except (EffectError, EffectUnavailable):
        return None
    return _poll_domain_running_at(vm, f"{netbird_ip}:{_MINER_ORDERS_PORT}")


def _poll_domain_running_at(vm: Vm, target_addr: str) -> bool | None:
    """Relay one ``domain-state`` GET to ``target_addr``. Folds EVERY
    failure into ``None`` (see the two callers for what that means).
    """
    try:
        status, body = _edge_get_addr(vm, "domain-state", target_addr)
    except (EffectError, EffectUnavailable):
        return None
    if status != 200:
        return None
    try:
        running = _json(body, label="edge-relay:domain-state").get("running")
    except EffectError:
        return None
    return running if isinstance(running, bool) else None


def dispatch_graceful_stop(vm: Vm) -> None:
    """§24 step 1 — GRACEFULLY stop the VM's guest so its baked
    `hippius-eol-sign.service` (`ExecStop`, `Before=shutdown.target`) fires,
    signs the `StoppedAck` from the measured cmdline, and pushes it over the
    vsock lifecycle relay into vali's `StoppedAckIngest` — the ack `§24`
    `poll_eol_ack` then verifies before crypto-erase.

    This REPLACES the former `relay_eol_shutdown`, which POSTed to a
    `/v1/relay/{vm}/eol-shutdown` route that DOES NOT EXIST (edge + miner-agent
    never implemented it) — a 404 no-op. Because §24 never gracefully stopped
    the guest, the ExecStop hook never fired, no ack was ever produced, and
    every decommission fell through to the ack-timeout FORCED reclaim (which
    §13-quarantines the source miner). Confirmed live: 0/40 DecommissionJobs
    ever had `eol_ack_verified=True`.

    Fix: dispatch a real `stop` order with `graceful=true` — the same
    mechanism §25's quiesce uses (`handle_stop` → `virsh shutdown` → ACPI →
    guest systemd shutdown → the hook). Idempotent + fail-safe exactly like
    `dispatch_destroy`: targets the VM's bound miner from TRUSTED vali records
    (`_bound_miner_id` → `MinerIdentity.netbird_ip`), carries the `vm_id`
    (a misroute no-ops), dedups on `order_id`. It is BEST-EFFORT in the
    draining step: if the graceful stop cannot be dispatched, §24 still falls
    back to the ack-timeout forced reclaim (no worse than before), but the
    common case now delivers a verified ack → a clean, non-quarantining §24.
    """
    from . import order_dispatch

    node_id = _bound_miner_id(vm)
    if not node_id:
        raise EffectError(
            f"decommission-eol-stop: vm {vm.vm_id!r} has no bound miner "
            "(empty host and no SUCCEEDED launch) — cannot route the stop"
        )
    miner_id, netbird_ip = _miner_identity(node_id)
    payload = order_dispatch.build_stop_payload(vm_id=vm.vm_id, graceful=True)
    order_id = f"dec-eol-stop-{vm.vm_id}-{vm.generation}"
    try:
        result = order_dispatch.dispatch_order(
            miner_id=miner_id,
            netbird_ip=netbird_ip,
            order_id=order_id,
            kind="stop",
            payload_json=json.dumps(payload).encode("utf-8"),
        )
    except order_dispatch.OrderDispatchUnavailable as exc:
        raise EffectUnavailable(f"decommission-eol-stop: {exc}") from exc
    except order_dispatch.OrderDispatchError as exc:
        raise EffectError(f"decommission-eol-stop: {exc}") from exc
    if not result.ok:
        raise EffectError(
            f"decommission-eol-stop: miner rejected (status={result.status} "
            f"class={result.classifier!r})"
        )


def poll_source_ack(vm: Vm) -> bytes | None:
    """§25 step 6 — poll for the source guest's signed `stopped{}` ack.

    Returns the raw `SignedStoppedAck` CBOR bytes, or `None` if the guest
    has not produced + delivered one yet.

    The guest signs + POSTs its ack at its BAKED ``hippius.vm_generation``
    — the launch (signing) generation, which a §25 migration does NOT
    re-bake — and it lands in the ``StoppedAckIngest`` store keyed by
    ``(vm_id, signing_generation)``. Read THAT generation (not the live
    ``generation``, which migration bumps) so a migrated VM's re-migration
    ack — signed at its launch generation — is found.
    """
    return _poll_stored_ack(vm.vm_id, vm.signing_generation)


def poll_eol_ack(vm: Vm) -> bytes | None:
    """§24 — poll for the guest's signed end-of-life `stopped{}` ack.

    The decommissioning guest signs at its BAKED ``hippius.vm_generation``
    (the launch / signing generation, unchanged by any prior §25 migration)
    and pushes to the same ``/v1/lifecycle/stopped`` ingress; we read the
    stored bytes for ``(vm_id, signing_generation)`` — NOT the live
    ``generation``, so a migrated VM's §24 ack is found (else the guest's
    launch-gen ack mismatches the bumped gen → forced-reclaim).
    """
    return _poll_stored_ack(vm.vm_id, vm.signing_generation)


def _poll_stored_ack(vm_id: str, generation: int) -> bytes | None:
    """Read the guest-pushed `SignedStoppedAck` bytes for
    ``(vm_id, generation)`` from the `StoppedAckIngest` store, or `None`
    if the guest has not delivered one yet (the orchestrator then WAITs
    until the phase deadline — fail-closed, never advance without a
    verified ack).

    The store holds OPAQUE bytes — verification (signature + nonce +
    generation) happens in the caller's `_verify_ack`, not here.
    """
    # Local import to keep this effects module import-light for the
    # non-ack effects + avoid a hard import cycle with the lifecycle app.
    from apps.lifecycle.models import StoppedAckIngest

    row = (
        StoppedAckIngest.objects.filter(vm_id=vm_id, generation=generation)
        .order_by("-received_at")
        .first()
    )
    if row is None:
        return None
    return bytes(row.signed_ack)


# ─── KBS admin (§24 crypto-erase, §25 destination release) ───────────


def _kbs_admin_transport() -> KbsAdminTransport:
    """The decided admin transport (plaintext / mTLS), or a fail-closed
    `EffectUnavailable`.

    Local import: `services.kbs_admin_tls` is a leaf module, but this
    file is imported by nearly everything in the orchestration app and a
    module-level edge would create an import cycle through `services`.
    """
    from apps.orchestration.services.kbs_admin_tls import (
        KbsAdminTlsMisconfigured,
        admin_transport,
    )

    try:
        return admin_transport()
    except KbsAdminTlsMisconfigured as exc:
        raise EffectUnavailable(str(exc)) from exc


def _kbs_post(vm: Vm, command: str, body: dict[str, Any]) -> None:
    transport = _kbs_admin_transport()
    url = transport.url(f"/v1/admin/vm/{vm.vm_id}/{command}")
    label = f"kbs-admin:{command}"
    status, _ = _http(
        "POST", url, label=label, json_body=body, context=transport.context
    )
    if not 200 <= status < 300:
        raise EffectError(f"{label}: KBS returned HTTP {status}")


class KbsRouteMissing(EffectError):
    """The KBS answered 404 — the deployed KBS does not serve this admin
    route (an older image). Distinct from a functional failure: the caller
    can report "not deployed" rather than crash.
    """


class KbsAdminContractMismatch(EffectError):
    """The KBS answered 400 — our request violated the server's contract
    (`counter-zero`, `seed-above-cap`, `seed-body-decode`).

    Every client-side precondition here is meant to make this UNREACHABLE, so
    seeing it means vali and the deployed KBS disagree about the contract
    (e.g. the server lowered its cap below ours). That is a whole-run fault,
    not a per-VM one: every subsequent VM would fail identically, so the
    caller must ABORT rather than iterate past it. Error bodies are CBOR and
    are not decoded, so the specific reason is not available here — which is
    another argument for aborting loudly instead of guessing.
    """


#: Server-side ceiling on a seeded boot counter (`MAX_SEED_COUNTER` in
#: `kbs-core::boot_counter`). Re-checked client-side so a fat-fingered extra
#: digit is refused before it leaves vali.
#:
#: INVARIANT: this must stay <= the server's cap. If the server ever lowers
#: its own, a value this pre-check waves through comes back as a bare
#: `400 seed-above-cap` we cannot decode — hence [`KbsAdminContractMismatch`]
#: aborting the run rather than reporting a confusing per-VM failure.
MAX_SEED_COUNTER = 4096


@dataclass(frozen=True)
class SeedBootCounterOk:
    """Parsed `200` body of the seed-boot-counter admin route, or the
    `409 seed-already-recovered` no-op.

    `already_recovered=True` carries LESS information than its name suggests:
    the KBS's guard 1 fires on `stored != 0`, so all it means is **the row is
    not wiped**. Two very different situations produce the identical wire
    response:

    a. a prior seed (possibly ours, on a retry) already landed — benign;
    b. the counter was NEVER wiped — the operator's premise ("this VM lost
       its counter") was false, nothing was done, and no recovery happened.

    (b) is NOT success, and reporting it as such during a lockout incident
    tells the operator a recovery occurred that did not. This layer cannot
    distinguish them — `previous` is 0 by construction on every success, so
    it carries no signal either — so the CALLER must, by tracking whether it
    saw a 200 for that vm_id earlier in the same run. See
    `vali_kbs_recover._seed_one`.

    Guard 1 exists because silently overwriting a LIVE counter is a
    brick-the-tenant primitive (seed the cap ⇒ the guest can never submit
    `stored + 1`).
    """

    counter: int
    previous: int
    already_recovered: bool


def seed_boot_counter(vm_id: str, *, counter: int) -> SeedBootCounterOk:
    """`POST {VALI_KBS_ADMIN_URL}/v1/admin/vm/{vm_id}/seed-boot-counter` —
    re-establish a boot counter the KBS lost when its (CVM-sealed, emptyDir)
    state was wiped by a restart.

    ONE SHOT PER VM. `counter` means "N boots already consumed", so the
    guest's next boot submits `N+1`. A wrong value cannot be corrected: every
    later seed is refused, and a too-low value locks the VM out permanently.
    The caller is responsible for sourcing the value from the miner's per-VM
    state disk rather than from a human's memory.

    Returns [`SeedBootCounterOk`] on 200, and on 409 — which means only "the
    row is not wiped"; read that type's docstring before treating it as
    success. Raises:

    - [`KbsRouteMissing`] on 404 — the route is not deployed (the caller
      renders that as a non-fatal skip). `vm_id` is charset-validated FIRST
      so a 404 cannot instead mean "empty vm_id path segment".
    - [`KbsAdminContractMismatch`] on 400 — abort the run, do not iterate.
    - [`EffectError`] on any other non-2xx (413, 429, 5xx). A 5xx now means
      nothing was written: `FileBootCounterStore` rolls its in-memory cache
      back when the persist fails, so a re-run after a 500 is clean (it used
      to leave memory advanced and answer 409 on the retry).
    - [`EffectUnavailable`] when the admin listener is unreachable /
      unconfigured.

    §20: nothing secret crosses this call — a boot counter is public
    anti-rollback metadata. Non-2xx bodies are CBOR (`AdminErrorResponse`),
    NOT JSON, so they are deliberately not decoded here — the status code
    carries the decision. That costs nothing: `seed-not-monotonic` is
    unreachable through the real store (guard 1 intercepts every non-zero
    row, and the only input that could reach the monotonic guard on a wiped
    row is `counter == 0`, which is rejected earlier as `400 counter-zero`),
    so `seed-already-recovered` is the only observable 409. Keying off the
    status keeps a CBOR dependency out of vali for a distinction with no
    reachable values.
    """
    if not isinstance(vm_id, str) or not _VM_ID_RE.match(vm_id):
        raise EffectError("seed-boot-counter: vm_id failed the charset lock")
    if not isinstance(counter, int) or isinstance(counter, bool):
        raise EffectError("seed-boot-counter: counter must be an integer")
    if counter <= 0:
        # The KBS answers 400 `counter-zero`; refuse locally so an obviously
        # wrong value never consumes the VM's single seed attempt.
        raise EffectError("seed-boot-counter: counter must be >= 1 (counter-zero)")
    if counter > MAX_SEED_COUNTER:
        raise EffectError(
            f"seed-boot-counter: counter {counter} exceeds the KBS cap "
            f"{MAX_SEED_COUNTER} (seed-above-cap)"
        )

    transport = _kbs_admin_transport()
    url = transport.url(f"/v1/admin/vm/{vm_id}/seed-boot-counter")
    label = "kbs-admin:seed-boot-counter"
    status, body = _http(
        "POST",
        url,
        label=label,
        json_body={"counter": counter},
        context=transport.context,
    )

    if status == 404:
        raise KbsRouteMissing(
            f"{label}: KBS returned 404 — the seed-boot-counter route is not "
            "served by the deployed KBS image"
        )
    if status == 400:
        raise KbsAdminContractMismatch(
            f"{label}: KBS returned 400 — vali's preconditions should make "
            "this unreachable, so vali and the deployed KBS disagree about "
            "the seed contract (e.g. a lowered server cap). ABORT."
        )
    if status == 409:
        # The row is NOT wiped. Nothing was written and a retry cannot help.
        # Whether that is benign (our own earlier seed) or a false premise
        # (the counter was never lost) is the CALLER's call — see the type.
        return SeedBootCounterOk(counter=counter, previous=0, already_recovered=True)
    if not 200 <= status < 300:
        raise EffectError(f"{label}: KBS returned HTTP {status}")

    parsed = _json(body, label=label)
    try:
        return SeedBootCounterOk(
            counter=int(parsed["counter"]),
            previous=int(parsed.get("previous", 0)),
            already_recovered=False,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise EffectError(f"{label}: 200 body missing `counter`") from exc


def crypto_erase_kek_transit(vm: Vm) -> None:
    """§24 — crypto-erase ANY VM's tenant data (golden or legacy) by
    DESTROYING its Vault-Transit KEK + the wrapped-KEK KV secret.

    EVERY VM's KEK is wrapped under its OWN per-VM Transit key `kek-<vm_id>`:
    the golden async path stages it in `_provision_golden_overlay_kek` (#833),
    the legacy/sync path wraps with `transit_key_name(vm_id)` in
    `launch_on_miner`. The KBS `require_wrapped_kek` gate REFUSES a
    non-`vault:`-prefixed KEK on release (403), so a VM that ever booted
    necessarily has that key.

    There is NO KBS record to erase for either kind — the KBS admin
    `crypto-erase` route was never implemented (`build_admin_router` exposes
    only register-vm / activate / evidence / allowlist-reload), so the old
    KBS-based erase 404'd for every VM. The cryptographic data-death
    guarantee is instead:

      1. DESTROY the Transit key `kek-<vm_id>` — once it is gone the wrapped
         per-VM KEK can NEVER be unwrapped again ⇒ the overlay upper's
         in-guest LUKS master key is unrecoverable ⇒ TRUE crypto-erase; then
      2. DELETE the wrapped-KEK KV blob (defence-in-depth — inert once the
         Transit key is gone).

    Idempotent — an already-deleted key / secret (Vault 404) means the erase
    goal is already met ⇒ SUCCESS. Fail-closed — any other Vault failure
    (unreachable → `EffectUnavailable`, permission-denied / 5xx →
    `EffectError`) propagates so the decommission stays retryable and the VM
    is NEVER marked Destroyed as if erased. The Transit key name + KV path
    are derived STRICTLY from `vm.vm_id` (charset-locked here), so erasing a
    sibling / other-tenant key is impossible.
    """
    # Lazy import — `vault_kv` imports from THIS module (`EffectError`), so a
    # module-level import would be circular. Consistent with the other lazily-
    # imported effects here.
    from .services import vault_kv

    vm_id = vm.vm_id
    if not isinstance(vm_id, str) or not _VM_ID_RE.match(vm_id):
        # Fail closed — never interpolate an unvalidated vm_id into a Vault
        # write/delete path (defeats any `../` traversal out of the per-VM
        # namespace, and refuses to erase an ambiguous target).
        raise EffectError("crypto-erase-transit: vm_id failed the charset lock")
    mount = str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret"))
    prefix = str(getattr(settings, "VALI_VAULT_KV_PREFIX", "") or "").strip()
    if not prefix:
        raise EffectUnavailable("VALI_VAULT_KV_PREFIX is not configured")
    transit_key = vault_kv.transit_key_name(vm_id)  # `kek-<vm_id>`
    luks_path = f"{prefix}/{vm_id}/luks-kek"
    # (1) THE data-death: destroy the Transit key. (2) Delete the wrapped-KEK
    # KV blob. Both idempotent + fail-closed inside `vault_kv`.
    vault_kv.transit_key_delete(transit_key)
    vault_kv.delete_kv_all_versions(mount, luks_path)


def dispatch_destroy(vm: Vm) -> None:
    """§24 — force-stop the VM's domain via an explicit `destroy` order to
    the bound miner.

    Belt-and-suspenders: §24 must NOT rely on the guest self-powering-off on
    the EOL vsock push (golden guests don't honour it → the domain kept
    RUNNING as a zombie even after the placement released). This dispatches a
    signed `destroy` order through the EXACT path launch/stop use
    (`order_dispatch.dispatch_order` → Edge → the miner-agent's destroy
    route), so the control plane force-stops the domain.

    Targets the VM's currently-bound miner, resolved via
    [`_bound_miner_id`] (`vm.host` == `MinerIdentity` primary key, OR the
    latest SUCCEEDED `LaunchJob.miner_id` when `vm.host` is empty — the
    async-launch case, from TRUSTED vali placement records only). The
    routing address comes from `MinerIdentity.netbird_ip`, NEVER from
    request/tenant/miner data, so no misroute is possible; and the order
    carries the `vm_id`, so a hypothetical misroute is fail-safe (a miner
    without that `vm_id` no-ops). Idempotent on the miner side (dedup on
    `order_id`). Fails LOUD when no bound miner is known (empty `vm.host`
    AND no SUCCEEDED launch) — a destroy that cannot route must never
    tombstone a zombie domain as Destroyed.
    """
    from . import order_dispatch

    # WIDER than `_bound_miner_id` on purpose — see
    # `destroy_target_miner_id`. A launch that FAILED after the order
    # reached the miner can still have left a running domain, and the
    # LaunchJob records where it was sent; skipping on that would tombstone
    # a live CVM as Destroyed.
    node_id = destroy_target_miner_id(vm)
    if not node_id:
        raise EffectError(
            f"decommission-destroy: vm {vm.vm_id!r} has no bound miner and no "
            "launch record naming one — cannot route the destroy"
        )
    miner_id, netbird_ip = _miner_identity(node_id)
    payload = order_dispatch.build_destroy_payload(vm_id=vm.vm_id)
    order_id = f"dec-destroy-{vm.vm_id}-{vm.generation}"
    try:
        result = order_dispatch.dispatch_order(
            miner_id=miner_id,
            netbird_ip=netbird_ip,
            order_id=order_id,
            kind="destroy",
            payload_json=json.dumps(payload).encode("utf-8"),
        )
    except order_dispatch.OrderDispatchUnavailable as exc:
        raise EffectUnavailable(f"decommission-destroy: {exc}") from exc
    except order_dispatch.OrderDispatchError as exc:
        raise EffectError(f"decommission-destroy: {exc}") from exc
    if not result.ok:
        raise EffectError(
            f"decommission-destroy: miner rejected (status={result.status} "
            f"class={result.classifier!r})"
        )


def dispatch_source_reclaim(vm: Vm, *, source_node_id: str, job_id: str) -> None:
    """§25 (P9/#15) — reclaim the SOURCE host's per-VM artifacts after a
    migration whose destination is PROVEN good.

    A §25 migration is a COPY: `quiesce` stops the source guest and
    `snapshot` uploads its volume, but nothing ever removed the source's
    `overlay/<vm>.img` (the tenant's LUKS ciphertext), `state/<vm>.raw`
    (the boot counter) or `staging/<vm>/`. They sit on a host that no
    longer runs the VM and is UNTRUSTED. This dispatches the SAME signed
    `destroy` order §24 uses, at the SOURCE, so the miner-agent's
    `CvmLifecycle::destroy` reclaims that exact per-VM footprint.

    ## Why `destroy` and not a new order kind

    `CvmLifecycle::destroy` is already the hardened reclaim (#880): it
    stats the per-VM footprint BEFORE touching libvirt (so a host that
    never held the VM is a no-op even with libvirtd down), it PROVES the
    domain is `Down` before unlinking (`Unknown` fails closed), it unlinks
    by EXACT path, and it removes the per-VM staging directory without
    following a symlink out of it. Writing a second reclaim would mean a
    second copy of every one of those guarantees.

    ## THE routing invariant (the #880 shape, on this path)

    The source is taken from the `MigrationJob`, NEVER from `vm.host` —
    `_activate_dest_vm` has already overwritten `vm.host` with the
    DESTINATION by the time this runs. Reading the VM would aim the
    destroy at the host the tenant is LIVE on. Two guards, because one
    silent misroute here is a live-tenant data loss:

      1. `source_node_id` must be non-empty and must NOT equal `vm.host`;
      2. the miner-side liveness proof refuses to unlink under a running
         domain (`Destroy("domain-still-up")` → a dispatch error here).

    Guard (2) is what also makes this safe against the reboot-watcher: a
    source domain the watcher resurrected is `Live`, the miner refuses,
    and the sweep retries later rather than racing it.

    NEVER a crypto-erase. The source and destination copies are the SAME
    ciphertext under the SAME per-VM KEK — that is what makes the
    migration work at all — so destroying the Transit key here would brick
    the RUNNING migrated VM. Unlinking the source copy is the only correct
    source-side action; §24 remains the only crypto-erase.

    Fails LOUD (`EffectError` / `EffectUnavailable`): the caller leaves the
    job `pending` and retries. Never reports a reclaim it did not dispatch.
    """
    from . import order_dispatch

    source_node_id = str(source_node_id or "").strip()
    if not source_node_id:
        raise EffectError(
            f"source-reclaim: migration {job_id!r} records no source miner "
            "— refusing to guess"
        )
    if source_node_id == str(vm.host or ""):
        # The VM is bound to the very host we were about to reclaim.
        # Either the migration was a same-node no-op or the source was
        # resolved from the wrong record. Refuse — this is the one
        # misroute that would delete a live tenant's disks.
        raise EffectError(
            f"source-reclaim: source {source_node_id!r} is the vm's CURRENT "
            f"host — refusing to reclaim under a live placement"
        )
    miner_id, netbird_ip = _miner_identity(source_node_id)
    payload = order_dispatch.build_destroy_payload(vm_id=vm.vm_id)
    # Keyed on the migration job, not the VM generation: a re-migration
    # must be able to reclaim its own source even though the §24
    # `dec-destroy-<vm>-<gen>` namespace may already have been used.
    order_id = f"mig-reclaim-{vm.vm_id}-{job_id}"
    try:
        result = order_dispatch.dispatch_order(
            miner_id=miner_id,
            netbird_ip=netbird_ip,
            order_id=order_id,
            kind="destroy",
            payload_json=json.dumps(payload).encode("utf-8"),
        )
    except order_dispatch.OrderDispatchUnavailable as exc:
        raise EffectUnavailable(f"source-reclaim: {exc}") from exc
    except order_dispatch.OrderDispatchError as exc:
        raise EffectError(f"source-reclaim: {exc}") from exc
    if not result.ok:
        raise EffectError(
            f"source-reclaim: source miner rejected (status={result.status} "
            f"class={result.classifier!r})"
        )


def kbs_activate_dest(
    vm: Vm, *, dest_node_id: str, new_gen: int, get_url: str
) -> None:
    """§25 step 7 — instruct the KBS to release the VM key to the
    destination at `new_gen`. Only ever called AFTER a verified
    source-stopped ack — the §25 split-brain gate. `get_url` is the
    short-TTL presigned snapshot GET; passed here, never persisted.

    The KBS stores `Migrating{dest}` and its `check_releasable` compares
    that `dest` against the value the dest guest's SNP report attests —
    which is the **chip_id / platform_id** (`kbs-core/release.rs`:
    `attested_node = hex(report.chip_id)`), NOT the `MinerIdentity`
    node_id string. So the `dest` we send the KBS admin MUST be the dest
    miner's `platform_id`, exactly as the launch/register path sets
    `host = ticket.platform_id`. Sending the node_id string here makes
    `check_releasable` deny the dest forever (`migration: attested node
    != destination`). Resolve the dest's registered platform_id.
    """
    from apps.miners.models import MinerIdentity

    try:
        dest_platform_id = MinerIdentity.objects.get(miner_id=dest_node_id).platform_id
    except MinerIdentity.DoesNotExist as exc:
        raise EffectError(
            f"migrate-activate: dest miner {dest_node_id!r} has no MinerIdentity"
        ) from exc
    if not dest_platform_id:
        raise EffectError(
            f"migrate-activate: dest miner {dest_node_id!r} has no platform_id "
            "(the KBS release gate compares the attested chip_id against this)"
        )
    _kbs_post(
        vm,
        "activate",
        {
            # The KBS lifecycle `dest` is the attested chip_id, not the
            # node_id (see the docstring).
            "dest_node_id": dest_platform_id,
            "new_gen": new_gen,
            "snapshot_get_url": get_url,
        },
    )


# ─── §25 M4 — dest-activation order dispatch ─────────────────────────


def _miner_identity(node_id: str):
    """Resolve a miner's ``(miner_id, netbird_ip)`` from its bound
    ``node_id`` (the ``MinerIdentity`` primary key). Mirrors
    [`_source_miner_addr`] but returns the pair the signed-order dispatch
    needs (``miner_id`` for the order's ``target_miner_id`` binding,
    ``netbird_ip`` for routing). Shared by the §25 dest-activation and the
    §24 decommission destroy-order dispatch. Imported lazily so this module
    stays import-light for the non-dispatch effects.
    """
    from apps.miners.models import MinerIdentity

    try:
        identity = MinerIdentity.objects.get(miner_id=node_id)
    except MinerIdentity.DoesNotExist as exc:
        raise EffectError(
            f"order-dispatch: miner {node_id!r} has no MinerIdentity"
        ) from exc
    if not identity.netbird_ip:
        raise EffectError(
            f"order-dispatch: miner {node_id!r} has no netbird_ip recorded"
        )
    return identity.miner_id, str(identity.netbird_ip)


def resolve_boot_artifacts(vm: Vm) -> dict[str, Any] | None:
    """Resolve the §25 M3 dest staging bundle for `vm` from its most
    recent successful launch record — presigned S3 GET URLs + the pinned
    SHAs for the measured kernel + initrd (and, when recorded, the
    dm-verity rootfs split). Returns the JSON-shaped
    ``DestStagingArtifacts`` dict the dest miner fetch-verify-stages
    before the domain build, or ``None`` when no launch record exists
    (the dest then relies on its ``dest-artifacts-missing`` existence
    check — never a half boot).

    The artifact LOCATIONS + SHAs live on the launch record's
    ``spec_json`` (the non-secret `LaunchSpec` — `s3_bucket`,
    `s3_key_prefix`, the per-artifact `*_sha256_hex`); the canonical S3
    keys are the bake prefix's ``tenant.vmlinuz`` / ``tenant.initrd.img``
    (mirroring `services/launch.py`'s preflight artifact wiring). OVMF is
    operator-staged on every miner (same file every tenant measures
    against), so it is NOT staged here — the dest's existing
    `/var/lib/hippius-miner/ovmf.fd` is reused.

    §20: the presigned URLs are short-TTL secrets — returned to the
    caller for the order body, never logged or persisted.
    """
    # Local imports: the launch-record model + S3 client are only needed on
    # the §25 dest-activation path; a module-level import would couple every
    # effect (incl. the §24 paths) to the orchestration models / storage at
    # load.
    from apps.storage import s3

    from .models import LaunchJob, LaunchJobState

    record = (
        LaunchJob.objects.filter(
            vm_id=vm.vm_id, state=LaunchJobState.SUCCEEDED
        )
        .order_by("-finished_at")
        .first()
    )
    if record is None:
        return None
    spec = record.spec_json or {}
    bucket = str(spec.get("s3_bucket") or "")
    prefix = str(spec.get("s3_key_prefix") or "").rstrip("/")
    kernel_sha = str(spec.get("kernel_sha256_hex") or "")
    initrd_sha = str(spec.get("initrd_sha256_hex") or "")
    if not (bucket and prefix and kernel_sha and initrd_sha):
        # An incomplete launch record cannot stage a measured boot — fall
        # back to the dest's pre-staged artifacts (existence-checked).
        return None

    client = s3.get_s3_client()
    ttl = int(getattr(settings, "VALI_ORCHESTRATION_PRESIGN_TTL_SECS", 3600))

    def _staged(key_name: str, sha_hex: str) -> dict[str, str]:
        got = client.presign_get(
            bucket=bucket, key=f"{prefix}/{key_name}", ttl_seconds=ttl
        )
        return {"url": got.url, "sha256_hex": sha_hex}

    staging: dict[str, Any] = {
        "kernel": _staged("tenant.vmlinuz", kernel_sha),
        "initrd": _staged("tenant.initrd.img", initrd_sha),
    }
    # GOLDEN (`disk_mode=golden_verity_overlay`): the dest MUST also stage the
    # SHARED read-only dm-verity base — `rootfs.img` (data, /dev/vdb) +
    # `rootfs.verity` (hash tree, /dev/vdc) — keyed by the golden bake SHAs
    # (`rootfs_img_sha256_hex` / `rootfs_verity_sha256_hex`, same S3 keys the
    # fresh-launch preflight uses, `services/launch.py:_select_preflight_
    # artifacts`). The golden guest boots the root from these and NEVER
    # self-fetches them, so a golden dest-activation without them fails its
    # `dest-artifacts-missing` existence check (fail-closed, no half-boot).
    # Both are PUBLIC integrity-only artifacts — the verity ROOT is SNP-
    # measured in the cmdline, so a wrong base is caught by the measurement /
    # dm-verity, not by trusting the miner.
    if str(spec.get("disk_mode") or "") == _DISK_MODE_GOLDEN_VERITY:
        rootfs_img_sha = str(spec.get("rootfs_img_sha256_hex") or "")
        rootfs_verity_sha = str(spec.get("rootfs_verity_sha256_hex") or "")
        if not (rootfs_img_sha and rootfs_verity_sha):
            # A golden launch record must carry both base SHAs; an incomplete
            # one cannot stage a measured base ⇒ fall back to the dest's
            # pre-staged artifacts (existence-checked, fail-closed).
            return None
        staging["rootfs_data"] = _staged("rootfs.img", rootfs_img_sha)
        staging["rootfs_hash"] = _staged("rootfs.verity", rootfs_verity_sha)
        return staging
    # The LEGACY dm-verity rootfs split is optional — only stage it when the
    # launch recorded its SHA (split-rootfs bakes). A deployment that
    # pre-stages the (large, immutable) rootfs out-of-band omits it.
    rootfs_sha = str(spec.get("rootfs_sha256_hex") or "")
    if rootfs_sha:
        staging["rootfs_data"] = _staged("rootfs.img", rootfs_sha)
    return staging


def dispatch_migrate_activate(
    vm: Vm,
    *,
    dest_node_id: str,
    new_gen: int,
    get_url: str,
    state_get_url: str = "",
    boot_artifacts: dict[str, Any] | None,
    job_id: str = "",
) -> None:
    """§25 M4 — dispatch the ``migrate-activate`` order to the DEST miner.

    The transport vali's `_h_mig_dest_activating` was missing: after the
    KBS releases the key to the destination at ``new_gen`` (the split-brain
    fence already passed), the dest miner must actually DOWNLOAD the
    snapshot, stage the measured boot artifacts, and boot the domain. This
    posts that order through the EXACT signed-order path launch/stop use —
    `order_dispatch.dispatch_order` → the Edge `/v1/edge/order` inner
    router (canonical-CBOR `OrderBody`, Edge Ed25519 signature, the
    `x-hippius-target-addr` + `x-hippius-order-kind` headers) → the dest
    miner's `/v1/miner/order/migrate-activate` route.

    The order carries the measured launch tuple resolved from the VM's
    launch record (the cmdline is carried VERBATIM — NEVER re-stamped with
    ``new_gen``; the SNP measurement covers it, and the new generation is
    ticket-carried, see below), the presigned snapshot GET ``get_url``, and
    the optional ``boot_artifacts`` staging bundle.

    ## SECURITY — never called outside the fence

    The caller (`_h_mig_dest_activating`) reaches this only from the
    `DestActivating` state, which `_migration_guard` refuses to enter
    without ``source_ack_verified``. The KBS additionally releases the KEK
    only to ``(new_gen, dest)`` and denies the source forever after, so even
    a forged / replayed activate cannot boot a second LIVE copy.

    ## The cose_ticket at new_gen (the §25 re-mint — now wired)

    The dest guest re-attests at ``new_gen``; `kbs_core::check_releasable`
    during ``Migrating`` releases the KEK ONLY to a ticket whose
    ``vm_generation == new_gen`` AND denies the source's ``source_gen``
    ticket forever after (the split-brain fence). So this dispatch carries a
    FRESH OrderTicket minted at ``new_gen`` —
    `migration_ticket.remint_dest_ticket` re-mints it from the launch record
    (SAME measurement: the dest boots the byte-identical measured guest, so
    its launch_digest equals the source's — the generation is carried by the
    TICKET, not the measured cmdline) and re-derives the §6 userdata digest
    for the fresh ticket_id. The dest then unlocks the migrated disk at
    ``new_gen`` and the migration completes end-to-end.

    The cmdline is carried VERBATIM from the launch record — it is
    deliberately NOT rewritten with a generation token. The SNP launch
    measurement covers the cmdline; rewriting it would change the dest's
    launch_digest and the KBS would refuse the KEK. The generation lives in
    the OrderTicket the boot pipeline reads (`order.vm_generation`), never in
    a measured cmdline token.
    """
    # Lazy imports — keep the module import-light for the §24 paths.
    from . import order_dispatch
    from .services import migration_ticket

    miner_id, netbird_ip = _miner_identity(dest_node_id)

    # §25 — mint (or resolve, idempotently) the dest ticket at `new_gen`.
    # Fail-closed: no new_gen ticket ⇒ no dispatch ⇒ the dest is never
    # activated with a stale-gen ticket the KBS would deny.
    cose_ticket = migration_ticket.remint_dest_ticket(
        vm, dest_node_id=dest_node_id, new_gen=new_gen
    )

    # Resolve the measured launch tuple from the launch record. The cmdline
    # is carried VERBATIM — the generation is ticket-carried, not a measured
    # cmdline token (see the docstring).
    paths = _launch_paths(vm)
    cmdline = paths["cmdline"]

    # The order_id is the dest miner's idempotency key
    # (`orders::IdempotencyStore`), and `migrate-activate` ACKs
    # IMMEDIATELY — the multi-GB restore runs on a background task — so
    # the agent records `Done(true)` for this id the instant it accepts,
    # whatever the restore later does. A `(vm_id, new_gen)`-only key
    # therefore makes every RE-DRIVE of a failed dest activation a
    # `idempotent-replay` no-op: the dest returns 200, restores nothing,
    # and vali's poll reads the stale `Failed` phase. Scoping the key to
    # the JOB keeps it stable across a job's own tick retries (which is
    # all the dedup is for — `_guarded` already covers those) while
    # letting a NEW job re-drive the same destination at the same
    # generation. `job_id` is optional so a caller with no job (tests)
    # keeps the historical key.
    order_id = f"mig-activate-{vm.vm_id}-{new_gen}"
    if job_id:
        order_id = f"{order_id}-{job_id}"
    payload = order_dispatch.build_migrate_activate_payload(
        vm_id=vm.vm_id,
        get_url=get_url,
        state_get_url=state_get_url,
        new_gen=new_gen,
        ovmf_path=paths["ovmf_path"],
        kernel_path=paths["kernel_path"],
        initrd_path=paths["initrd_path"],
        cmdline=cmdline,
        luks_disk_path=paths["luks_disk_path"],
        luks_disk_size_gb=paths["luks_disk_size_gb"],
        rootfs_data_path=paths["rootfs_data_path"],
        rootfs_hash_path=paths["rootfs_hash_path"],
        cpu_count=paths["cpu_count"],
        memory_mb=paths["memory_mb"],
        cose_ticket=cose_ticket,
        boot_artifacts=boot_artifacts,
    )
    import json as _json

    try:
        result = order_dispatch.dispatch_order(
            miner_id=miner_id,
            netbird_ip=netbird_ip,
            order_id=order_id,
            kind="migrate-activate",
            payload_json=_json.dumps(payload).encode("utf-8"),
        )
    except order_dispatch.OrderDispatchUnavailable as exc:
        raise EffectUnavailable(f"migrate-activate: {exc}") from exc
    except order_dispatch.OrderDispatchError as exc:
        raise EffectError(f"migrate-activate: {exc}") from exc
    if not result.ok:
        # `order-in-flight` (409): the dest already ACCEPTED an identical
        # migrate-activate and is restoring it on a background task. That is
        # IN PROGRESS, not a failure — the dest ACKs the order immediately
        # (the restore is a multi-GB download + boot) and vali tracks the
        # terminal outcome via `poll_dest_activation`, NOT this dispatch's
        # response. Treat it as a successful (idempotent) dispatch.
        if result.status == 409 and result.classifier == "order-in-flight":
            return
        # Any other miner 4xx/5xx (e.g. `dest-artifacts-missing`) — surface it
        # so the orchestrator retries until the phase deadline.
        raise EffectError(
            f"migrate-activate: dest miner rejected (status={result.status} "
            f"class={result.classifier!r})"
        )


def poll_dest_activation(vm: Vm, *, dest_node_id: str) -> str:
    """§25 M4 — poll the DESTINATION miner's restore/boot progress. Returns
    ``"running"``, ``"done"``, or ``"failed"``.

    `dispatch_migrate_activate` ACK-then-async on the dest (the restore is a
    multi-GB snapshot download + boot that far exceeds the order-relay
    timeout), so the dispatch confirms only that the dest ACCEPTED the order.
    This polls the dest miner's migration-status surface (the SAME
    `migration/{vm}/status` route the source snapshot uses — the dest sets its
    local `MigrationPhase::Activating → Done/Failed`) to learn the terminal
    outcome, targeting the DEST's socket address rather than the source's.
    """
    _, netbird_ip = _miner_identity(dest_node_id)
    dest_addr = f"{netbird_ip}:{_MINER_ORDERS_PORT}"
    status, body = _edge_get_addr(vm, "snapshot", dest_addr)
    if status != 200:
        raise EffectError(f"edge-relay:dest-activation: poll returned HTTP {status}")
    state = _json(body, label="edge-relay:dest-activation").get("status")
    if state not in ("running", "done", "failed"):
        raise EffectError(f"edge-relay:dest-activation: unknown status {state!r}")
    return str(state)


def _launch_paths(vm: Vm) -> dict[str, Any]:
    """Resolve the measured launch tuple (paths + sizes + cmdline) for
    `vm` from its most recent successful launch record. Raises
    `EffectError` when no usable record exists — the dest cannot be
    activated without the measured tuple the source launched with.
    """
    from .models import LaunchJob, LaunchJobState

    record = (
        LaunchJob.objects.filter(
            vm_id=vm.vm_id, state=LaunchJobState.SUCCEEDED
        )
        .order_by("-finished_at")
        .first()
    )
    if record is None:
        raise EffectError(
            f"migrate-activate: vm {vm.vm_id!r} has no successful launch record"
        )
    from .services import flavors

    spec = record.spec_json or {}
    result = record.result_json or {}
    # The dest MUST boot the EXACT SNP-MEASURED cmdline the source launched
    # with (see `dispatch_migrate_activate`): its launch_digest has to equal
    # the re-minted ticket's `allowed_measurement_hex`, and a GOLDEN VM is
    # classified golden by the dest miner ONLY if the cmdline carries
    # `dm-verity.root=` — a token that is augmented at launch but is NOT in
    # `spec_json["cmdline"]` (the BASE cmdline). The launch persists the
    # augmented bytes as `result_json["emit"]["measured_cmdline"]`; prefer it.
    emit = result.get("emit") or {}
    measured_cmdline = str(emit.get("measured_cmdline") or "")
    base_cmdline = str(spec.get("cmdline") or "")
    is_golden = str(spec.get("disk_mode") or "") == _DISK_MODE_GOLDEN_VERITY
    if measured_cmdline:
        cmdline = measured_cmdline
    elif is_golden:
        # A golden VM launched BEFORE measured_cmdline was persisted cannot be
        # migrated safely: carrying the base cmdline would misclassify it as
        # legacy on the dest (no overlay restore) AND boot a mismatched
        # measurement the KBS would deny. Fail closed — relaunch to migrate.
        raise EffectError(
            f"migrate-activate: golden vm {vm.vm_id!r} has no persisted "
            "measured_cmdline (launched before the fix) — relaunch it to "
            "make it migratable; refusing to migrate with a mismatched cmdline"
        )
    else:
        # Legacy VM: the base cmdline is the migration cmdline (unchanged
        # pre-fix behaviour). Post-fix launches carry measured_cmdline above.
        cmdline = base_cmdline
    if not cmdline:
        raise EffectError(
            f"migrate-activate: launch record for {vm.vm_id!r} has no cmdline"
        )
    # The guest size + the rootfs LUKS disk size derive from the flavor —
    # the same `resolve_flavor` the launch path uses, so the dest measures
    # the SAME tuple. A bad/absent flavor on the record is a corrupt launch
    # record — fail closed rather than guess a size.
    try:
        size = flavors.resolve_flavor(str(spec.get("flavor") or ""))
    except flavors.UnknownFlavor as exc:
        raise EffectError(
            f"migrate-activate: launch record for {vm.vm_id!r} has an unknown flavor"
        ) from exc
    # The miner-staged paths the source launched against are echoed back on
    # the launch result. Where one is missing, fall back to the PER-VM
    # staging layout the miner-agent itself uses — never to a shared path.
    #
    # ## P9/#16 — why the old fallbacks were a data-loss vector
    #
    # `rootfs_data_path` used to read `spec["rootfs_data_path"]`, whose
    # default is the SHARED `/var/lib/hippius-miner/rootfs.img`; kernel and
    # initrd fell back to the equally shared `/var/lib/hippius-miner/
    # tenant.vmlinuz`. The dest miner STAGES to these paths (`orders::
    # migration::stage_dest_artifacts`), so a §25 activation wrote multi-GB
    # verified bytes onto files that are not the migrating VM's:
    #
    #   miner-3 carries all four at the miner root, dated 2026-07-29 14:20,
    #     and `/var/lib/hippius-miner/rootfs.img` is byte-identical
    #     (`c6ffbc4a…`) to `staging/realtenant-ubuntu-1/rootfs.img`;
    #   miner-2 has the SAME two paths as SYMLINKS into `staging/`, the
    #     shared legacy base — the identical order would have replaced the
    #     base image every legacy VM on that host boots, in place.
    #
    # The miner-agent now redirects anything it stages into
    # `staging/<vm_id>/` regardless of what the order says (belt), and
    # these fallbacks name that layout directly (braces) so an accurate
    # order is sent even to an agent that predates the redirect.
    per_vm = f"/var/lib/hippius-miner/staging/{vm.vm_id}"
    is_golden = str(spec.get("disk_mode") or "") == _DISK_MODE_GOLDEN_VERITY
    if is_golden:
        # GOLDEN: the base is a per-VM staged copy of a content-pinned
        # image. `result` carries the exact path the source booted from
        # (recorded since P9/#16); older records fall back to the layout,
        # NOT to the shared path they were dispatched with.
        rootfs_data_path = str(result.get("rootfs_data_path") or f"{per_vm}/rootfs.img")
        rootfs_hash_path = str(
            result.get("rootfs_hash_path") or f"{per_vm}/rootfs.verity"
        )
    else:
        # LEGACY: the rootfs genuinely IS an operator-pre-staged shared
        # file the miner never fetches (no `rootfs_data` descriptor is
        # emitted for it unless the launch recorded a sha), so the spec's
        # shared path is the right answer here and stays.
        rootfs_data_path = str(
            spec.get("rootfs_data_path") or "/var/lib/hippius-miner/rootfs.img"
        )
        rootfs_hash_path = str(
            spec.get("rootfs_hash_path") or "/var/lib/hippius-miner/rootfs.verity"
        )
    return {
        "ovmf_path": str(spec.get("ovmf_path") or "/var/lib/hippius-miner/ovmf.fd"),
        "kernel_path": str(result.get("kernel_path") or f"{per_vm}/tenant.vmlinuz"),
        "initrd_path": str(result.get("initrd_path") or f"{per_vm}/tenant.initrd.img"),
        "luks_disk_path": str(
            result.get("luks_disk_path") or f"{per_vm}/tenant.qcow2"
        ),
        "luks_disk_size_gb": int(size.luks_disk_size_gb),
        "rootfs_data_path": rootfs_data_path,
        "rootfs_hash_path": rootfs_hash_path,
        "cpu_count": int(size.cpu_count),
        "memory_mb": int(size.memory_mb),
        "cmdline": cmdline,
    }


# ─── NetBird (§12/§24 graceful teardown + §F enrolment) ──────────────


def _resolve_netbird_group_ids(
    base: str, token: str, groups: list[str]
) -> list[str]:
    """Map NetBird group NAMES → IDs (the `auto_groups` field rejects
    names with a 422). A value already equal to a group id passes
    through. Raises `EffectError` naming any group that does not exist
    (clearer than the opaque upstream 422)."""
    status, raw = _http(
        "GET",
        f"{base}/api/groups",
        label="netbird:list-groups",
        headers={"Authorization": f"Token {token}"},
    )
    if status != 200:
        raise EffectError(f"netbird:list-groups: API returned HTTP {status}")
    try:
        all_groups = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EffectError("netbird:list-groups: non-JSON response") from exc
    if not isinstance(all_groups, list):
        raise EffectError("netbird:list-groups: expected a JSON list")
    by_name = {
        g.get("name"): g.get("id") for g in all_groups if isinstance(g, dict)
    }
    ids = {g.get("id") for g in all_groups if isinstance(g, dict)}
    resolved: list[str] = []
    for g in groups:
        if g in by_name:
            resolved.append(by_name[g])
        elif g in ids:
            resolved.append(g)
        else:
            raise EffectError(
                f"netbird:mint-setup-key: group not found: {g!r}"
            )
    return resolved


def mint_netbird_setup_key(
    *,
    vm_id: str,
    tenant_id: str,
    auto_group_name: str,
    expires_in_seconds: int = 3600,
) -> str:
    """§F (#306) — mint a one-off NetBird setup key for the tenant VM.

    Calls `POST /api/setup-keys` on the configured NetBird management
    instance. The minted key is single-use (`usage_limit=1`), expires
    in 1 hour by default (operator-tunable), and the new peer auto-
    joins `auto_group_name` so ACL rules can isolate the tenant from
    operator infra.

    The setup key is treated as a §20 secret end-to-end:
    - `Authorization` header carries `VALI_NETBIRD_API_TOKEN`, never
      logged (`_http` redacts URLs from exceptions).
    - The minted key is RETURNED to the caller and is expected to
      ride the §21 KBS release envelope (same channel as KEK +
      userdata); it MUST NOT be written to durable storage on the
      vali side.

    Returns the setup-key string (UUID-shaped). Raises:
      EffectUnavailable — peer unreachable / token unconfigured.
      EffectError       — NetBird returned a 4xx/5xx, or the
                          response body lacked the `key` field.
    """
    base = _required_setting("VALI_NETBIRD_API_BASE").rstrip("/")
    token = _required_setting("VALI_NETBIRD_API_TOKEN")
    # The NetBird API's `auto_groups` wants group IDs, NOT names — resolve
    # the operator-facing group name to its id first (a value already
    # matching a group id passes through).
    group_ids = _resolve_netbird_group_ids(base, token, [auto_group_name])
    url = f"{base}/api/setup-keys"
    name = f"hippius-tenant-{vm_id}"
    body: dict[str, Any] = {
        "name": name,
        "type": "one-off",
        "expires_in": expires_in_seconds,
        "usage_limit": 1,
        "auto_groups": group_ids,
        "revoked": False,
        "ephemeral": True,
        # The `description` field is operator-visible in the NetBird
        # dashboard and surfaces which tenant the key was minted for.
        # Never embed secret material here.
        "description": f"hippius vm_id={vm_id} tenant_id={tenant_id}",
    }
    status, raw = _http(
        "POST",
        url,
        label="netbird:mint-setup-key",
        json_body=body,
        headers={"Authorization": f"Token {token}"},
    )
    if status not in (200, 201):
        raise EffectError(
            f"netbird:mint-setup-key: API returned HTTP {status}"
        )
    parsed = _json(raw, label="netbird:mint-setup-key")
    key = parsed.get("key")
    if not isinstance(key, str) or not key:
        raise EffectError("netbird:mint-setup-key: response missing 'key'")
    return key


@dataclass(frozen=True)
class NetbirdPeer:
    """The management-side peer record for one tenant VM.

    `ip` is the assigned overlay address, or "" when NetBird has not
    assigned a `100.` CGNAT address to the match. `connected` is the
    management server's live view of the WireGuard session.

    The DISTINCTION this type exists for: a peer record that is ABSENT is
    categorically different from one that is present-but-disconnected. An
    absent record means NetBird's ephemeral GC has deleted it (every
    tenant key is minted `ephemeral: True`), and since the launch-time
    setup key is `usage_limit=1` and already consumed, the guest can never
    re-register — the loss is PERMANENT. A present-but-disconnected peer
    is merely a guest that has not finished booting.
    """

    ip: str
    connected: bool


def _resolve_netbird_peer(vm_id: str) -> NetbirdPeer | None:
    """The implementation behind BOTH public resolvers.

    Private on purpose: the two public entry points must not be layered on
    each other by module-global name, or monkeypatching one (the test
    suite's `FakeEffects` patches `resolve_netbird_peer`) would silently
    re-route the other.

    Mirrors `mint_netbird_setup_key`'s auth + error discipline: the admin
    token rides the `Authorization` header and is NEVER logged (`_http`
    redacts URLs from exceptions). Lists the peers (`GET /api/peers`) and
    returns the record of the peer enrolled for THIS VM.

    Robust VM→peer association (verified against the LIVE NetBird API):
    the peer's `name` is the per-VM setup-key name `hippius-tenant-<vm_id>`
    minted by `mint_netbird_setup_key` — a STABLE, exact identifier. The
    peer's `hostname`, by contrast, is the guest-reported OS hostname
    (observed live as `localhost.localdomain`, or the bare truncated
    `hippius-tenant` from an older enrolment bug), so it must NOT be
    trusted for the association. We therefore match on an EXACT
    `name == hippius-tenant-<vm_id>` (the NetBird API does not expose the
    enrolling setup-key on the peer object, so its `name` — which NetBird
    seeds from that key — is the robust anchor) and prefer a `connected`
    peer when more than one matches.

    Raises:
      EffectUnavailable — peer unreachable / token unconfigured.
      EffectError       — NetBird returned a 4xx/5xx, or a non-JSON body.

    A raise is NOT evidence of absence — callers that act on "the peer is
    gone" MUST distinguish `None` (a successful listing with no match)
    from an exception (we simply could not ask).
    """
    base = _required_setting("VALI_NETBIRD_API_BASE").rstrip("/")
    token = _required_setting("VALI_NETBIRD_API_TOKEN")
    status, raw = _http(
        "GET",
        f"{base}/api/peers",
        label="netbird:resolve-peer-ip",
        headers={"Authorization": f"Token {token}"},
    )
    if status != 200:
        raise EffectError(f"netbird:resolve-peer-ip: API returned HTTP {status}")
    try:
        peers = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EffectError("netbird:resolve-peer-ip: non-JSON response") from exc
    if not isinstance(peers, list):
        raise EffectError("netbird:resolve-peer-ip: expected a JSON list")
    want = f"hippius-tenant-{vm_id}"
    matches = [
        p for p in peers if isinstance(p, dict) and p.get("name") == want
    ]
    if not matches:
        return None
    # A name collision should never happen (one setup-key per VM), but if
    # it does, prefer a live (connected) peer over a stale one.
    matches.sort(key=lambda p: bool(p.get("connected")), reverse=True)
    for p in matches:
        ip = p.get("ip")
        if isinstance(ip, str) and ip.startswith("100."):
            return NetbirdPeer(ip=ip, connected=bool(p.get("connected")))
    # Matched by name but with no assigned overlay address: the peer
    # RECORD exists (so it has not been GC'd) — report it with an empty
    # `ip` rather than pretending it is absent.
    return NetbirdPeer(ip="", connected=bool(matches[0].get("connected")))


def resolve_netbird_peer(vm_id: str) -> NetbirdPeer | None:
    """The VM's NetBird management-side peer RECORD, or `None` when
    NetBird holds no peer for this VM.

    `None` is the load-bearing answer for the post-§25 sweep: it means the
    ephemeral GC deleted the record, which the guest cannot undo (its
    launch setup key is a consumed one-off). See [`_resolve_netbird_peer`]
    for the association rule, the auth discipline and the raise semantics
    — a raise is NOT evidence of absence.
    """
    return _resolve_netbird_peer(vm_id)


def resolve_netbird_peer_ip(vm_id: str) -> str | None:
    """The VM's NetBird overlay IP (`100.x.y.z`), or `None` when no peer
    is enrolled yet / the match has no assigned overlay IP.

    Projection of [`_resolve_netbird_peer`]. Kept as a separate entry
    point because its caller (the served-receipt self-heal) only ever
    wants the address.
    """
    peer = _resolve_netbird_peer(vm_id)
    if peer is None or not peer.ip:
        return None
    return peer.ip


def revoke_netbird(vm: Vm) -> None:
    """§24 — revoke the VM's NetBird peer (and its one-off enrol key).

    Best-effort graceful teardown (§24: "NOT trusted for data
    destruction"). The peer is keyed by `vm_id`; a `404` means it was
    already revoked ⇒ success (idempotent). The admin token rides in
    the `Authorization` header and is never logged.
    """
    base = _required_setting("VALI_NETBIRD_API_BASE").rstrip("/")
    token = _required_setting("VALI_NETBIRD_API_TOKEN")
    url = f"{base}/api/peers/{vm.vm_id}"
    status, _ = _http(
        "DELETE",
        url,
        label="netbird:revoke-peer",
        headers={"Authorization": f"Token {token}"},
    )
    if status in (200, 204, 404):
        return  # 404 ⇒ already revoked
    raise EffectError(f"netbird:revoke-peer: API returned HTTP {status}")
