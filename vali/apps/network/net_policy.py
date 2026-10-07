"""The host-wide `net-policy` order: build, sign, push, record the ack
(docs/design/egress-and-bandwidth.md §7, §7.1).

Each miner gets one policy describing its guests' network: the per-VM
bandwidth caps, the VMs allowed out on TCP 25 (a public IP unblocked by
support), the local-mode action, and
in edge mode the endpoints its guests may still reach directly. vali signs
it through the Edge like any other order and the miner acks
`applied:<revision>:<content sha256>`.

## Revision

The miner refuses a revision lower than the one it holds, and the same
revision with other content, so an old signed `enforce: false` can never
reopen a host. vali keeps the revision per miner (`MinerNetPolicy`) and
bumps it only when the content changes. `not_after_unix` is outside the
content: re-sending the same policy with a later expiry keeps the
revision, and the miner re-acks it as a no-op.

## Push cadence

A pass runs in the orchestration tick (`reconcile`). It sends a miner's
policy at once when its content changed, again every
`VALI_NET_POLICY_SYNC_S` (drift repair, expiry renewal), and every
`VALI_NET_POLICY_RETRY_S` while the current revision is not acked —
doubled per `net-policy-apply` refusal, up to
`VALI_NET_POLICY_APPLY_BACKOFF_MAX_S`. An agent that refuses edge mode as
unsupported is sent no edge-mode policy for
`VALI_NET_POLICY_UNSUPPORTED_RETRY_S`. An ack means the rules are
installed (C2). Every
push carries a fresh `order_id`: the miner's order dedup would otherwise
answer an earlier outcome, and the revision already makes a re-send safe.

## Launch spec

`launch_net_spec` is the `net` object a launch, relaunch or §25
activation carries: the VM's cap from its first packet, plus the NIC
hardening (egress design §6.1). It is sent only under
`VALI_NET_LAUNCH_SPEC`, and only to a miner listed in
`VALI_NET_LAUNCH_SPEC_MINERS` that has acked a policy: an agent that
predates the field refuses the whole order at decode, and an ack does not
prove the agent knows it (the net-policy agents shipped first).

## Placement

A miner of an edge-mode region whose ack of its current edge-mode policy
is missing or stale takes no new VM (`unready_node_ids`). While every
region is local the gate costs one query and refuses nothing.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.db import transaction
from django.db.models import F
from django.db.models.functions import Upper
from django.utils import timezone

from apps.common.cdn import cdn_enabled, cdn_tenant_id
from apps.lifecycle.models import Vm, VmState
from apps.miners.models import MinerIdentity
from apps.orchestration import order_dispatch
from apps.orchestration.services.flavors import UnknownFlavor, ticket_flavor

from .models import EgressMode, EgressRegion, MinerNetPolicy, PublicIP, PublicIpState

log = logging.getLogger("apps.network.net_policy")

#: The miner refuses a policy valid for longer than this.
MAX_TTL_S = 7 * 24 * 3600
#: Miner-side bounds (`binaries/miner-agent/src/netpolicy/mod.rs`).
MAX_ENTRIES = 1024
MAX_VM_CAP_MBPS = 100_000
MAX_DNS_LIMIT_PPS = 10_000
#: In edge mode the miner cap leaves room for the WireGuard overhead (§7).
EDGE_MINER_CAP_FACTOR = (11, 10)

#: The miner's answers that mean "your revision is behind mine". vali's
#: own counter lost ground (a database restore); it moves past the miner's.
STALE_REVISION = "net-policy-stale-revision"
REVISION_CONFLICT = "net-policy-revision-conflict"
#: 422: the agent has no edge mode. Not re-sent until it may have changed.
UNSUPPORTED = "net-policy-unsupported"
#: 500: the agent could not install the rules. The same revision again,
#: with a backoff.
APPLY_FAILED = "net-policy-apply"

_NOT_PUBLIC = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/3",
    )
]


class PolicyError(Exception):
    """The policy cannot be built (a configuration or data problem); the
    message is recorded on the miner's row."""


# ─── caps ────────────────────────────────────────────────────────────


def flavor_cap_mbps(flavor: str) -> int:
    """The cap of `flavor` (`VALI_NET_CAP_MBPS_BY_FLAVOR`): a `runner-*`
    flavor takes its base flavor's, an unlisted one the default."""
    table: dict[str, Any] = dict(settings.VALI_NET_CAP_MBPS_BY_FLAVOR)
    if flavor in table:
        return int(table[flavor])
    try:
        base = ticket_flavor(flavor)
    except UnknownFlavor:
        base = ""
    if base in table:
        return int(table[base])
    return int(settings.VALI_NET_CAP_DEFAULT_MBPS)


def effective_cap_mbps(flavor: str, *, has_public_ip: bool) -> int:
    """The one cap of a VM (§7.1). A VM holding a public IP gets at least
    `VALI_NET_CAP_PUBLIC_IP_MBPS`."""
    cap = flavor_cap_mbps(flavor)
    if has_public_ip:
        cap = max(cap, int(settings.VALI_NET_CAP_PUBLIC_IP_MBPS))
    return cap


def cdn_cap_mbps(mode: str) -> int:
    """The miner-side cap of a CDN node (CDN plan N2) in a policy of `mode`:
    `VALI_CDN_NET_CAP_MBPS` with the edge-mode tunnel room, like a flavor
    cap. `0` (the default) means none — sent as `MAX_VM_CAP_MBPS`, the most
    an order carries, rather than left out, so a cap already on the domain
    is lifted, not kept."""
    cap = int(getattr(settings, "VALI_CDN_NET_CAP_MBPS", 0) or 0)
    if cap < 0:
        raise PolicyError("VALI_CDN_NET_CAP_MBPS must be >= 0")
    return MAX_VM_CAP_MBPS if cap == 0 else min(miner_cap_mbps(cap, mode), MAX_VM_CAP_MBPS)


def cdn_vm_ids(vm_ids: list[str]) -> set[str]:
    """The CDN nodes among `vm_ids` — empty while `VALI_CDN_ENABLED` is off,
    so the policies stay what they were."""
    tenant = cdn_tenant_id()
    if not vm_ids or not tenant or not cdn_enabled():
        return set()
    return set(
        Vm.objects.filter(vm_id__in=vm_ids, tenant_id=tenant).values_list("vm_id", flat=True)
    )


def miner_cap_mbps(cap: int, mode: str) -> int:
    """The cap the miner applies: `cap × 1.1` in edge mode, rounded up."""
    if mode != EgressMode.EDGE:
        return cap
    num, den = EDGE_MINER_CAP_FACTOR
    return -(-cap * num // den)


def _has_public_ip(vm_id: str) -> bool:
    return PublicIP.objects.filter(state=PublicIpState.ATTACHED, vm__vm_id=vm_id).exists()


def launch_net_spec(
    *, miner_id: str, vm_id: str, flavor: str | None = None
) -> dict[str, Any] | None:
    """The `net` spec for an order that boots `vm_id` on `miner_id`, or
    `None` (key omitted, the order unchanged) while `VALI_NET_LAUNCH_SPEC`
    is off, the miner is not in `VALI_NET_LAUNCH_SPEC_MINERS`, or it has
    never acked a policy. `flavor` defaults to the
    VM's launch record. The cap is the one the miner's policy lists for
    the VM (`vm_caps`), at the mode of the policy it acked."""
    if not settings.VALI_NET_LAUNCH_SPEC:
        return None
    allow = [m.strip() for m in settings.VALI_NET_LAUNCH_SPEC_MINERS if m.strip()]
    if "*" not in allow and miner_id not in allow:
        return None
    policy = MinerNetPolicy.objects.filter(miner__miner_id=miner_id).first()
    if policy is None or policy.acked_revision < 1:
        return None
    if flavor is None:
        flavor = _recorded_flavors([vm_id]).get(vm_id, "")
    if cdn_vm_ids([vm_id]):
        cap = cdn_cap_mbps(policy.mode)
    else:
        cap = min(
            miner_cap_mbps(
                effective_cap_mbps(flavor, has_public_ip=_has_public_ip(vm_id)), policy.mode
            ),
            MAX_VM_CAP_MBPS,
        )
    if cap < 1:
        raise PolicyError("a VM cap is below 1 Mbit/s — check VALI_NET_CAP_*")
    return {"cap_mbps": cap, "isolate": bool(settings.VALI_NET_LAUNCH_ISOLATE)}


# ─── body ────────────────────────────────────────────────────────────


def is_public_ipv4(text: str) -> bool:
    """The miner's rule for an allowed destination: canonical dotted-quad
    public unicast IPv4."""
    try:
        ip = ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return str(ip) == text and not any(ip in net for net in _NOT_PUBLIC)


def _endpoints(raw: Any, name: str) -> list[dict[str, Any]]:
    """`[{ip, proto, port}]` from a setting, checked like the miner checks
    it — a bad entry is a misconfiguration and fails the whole build."""
    if not isinstance(raw, list):
        raise PolicyError(f"{name}: expected a JSON list")
    out: list[dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict) or set(entry) != {"ip", "proto", "port"}:
            raise PolicyError(f"{name}: each entry is {{ip, proto, port}}")
        ip, proto, port = entry["ip"], entry["proto"], entry["port"]
        if not isinstance(ip, str) or not is_public_ipv4(ip):
            raise PolicyError(f"{name}: {ip!r} is not a public IPv4 address")
        if proto not in ("tcp", "udp"):
            raise PolicyError(f"{name}: proto must be tcp or udp")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise PolicyError(f"{name}: bad port {port!r}")
        out.append({"ip": ip, "proto": proto, "port": port})
    if len(out) > MAX_ENTRIES:
        raise PolicyError(f"{name}: more than {MAX_ENTRIES} entries")
    return sorted(out, key=lambda e: (e["ip"], e["proto"], e["port"]))


def miner_region(miner: MinerIdentity) -> str:
    """The region the policy is built for: the miner's detected country,
    whatever the verdict. A verdict flap must not flip a host between
    policies; whether the miner may be PLACED in that region stays the
    geo gate's call."""
    location = getattr(miner, "location", None)
    region = (location.country_code if location is not None else "").upper()
    if len(region) != 2 or not region.isascii() or not region.isalpha():
        return ""
    return region


def _region_mode(region: str) -> tuple[str, bool]:
    row = EgressRegion.objects.filter(region=region).first()
    if row is None or row.mode != EgressMode.EDGE:
        return EgressMode.LOCAL, False
    return EgressMode.EDGE, row.enforce


def _hosted_vm_ids(miner_id: str) -> list[str]:
    """The VMs whose domain is, or is about to be, on the miner: hosted
    there (stopped ones too — `domiftune --config` keeps the cap) or
    migrating in."""
    from django.db.models import Q

    return sorted(
        Vm.objects.filter(Q(host=miner_id) | Q(migration_dest=miner_id))
        .exclude(state=VmState.DESTROYED)
        .values_list("vm_id", flat=True)
    )


def _recorded_flavors(vm_ids: list[str]) -> dict[str, str]:
    """`{vm_id: flavor}` from each VM's launch record (its latest
    SUCCEEDED `LaunchJob`), in one query."""
    from apps.orchestration.models import LaunchJob, LaunchJobState

    flavors: dict[str, str] = {}
    rows = (
        LaunchJob.objects.filter(vm_id__in=vm_ids, state=LaunchJobState.SUCCEEDED.value)
        .order_by("vm_id", "-finished_at")
        .values_list("vm_id", "spec_json")
    )
    for vm_id, spec in rows:
        if vm_id not in flavors:
            flavors[vm_id] = str((spec or {}).get("flavor") or "")
    return flavors


def _valid_vm_id(vm_id: str) -> bool:
    # The miner's `VmId`: [a-z0-9-], 1..=64, no leading/trailing hyphen.
    return (
        0 < len(vm_id) <= 64
        and all(c.isascii() and (c.islower() or c.isdigit() or c == "-") for c in vm_id)
        and not vm_id.startswith("-")
        and not vm_id.endswith("-")
    )


def build_content(miner: MinerIdentity, region: str) -> dict[str, Any]:
    """The miner's policy body without `revision` and `not_after_unix` —
    deterministic, so equal inputs give an equal `content_key`."""
    mode, enforce = _region_mode(region)
    action = str(settings.VALI_NET_POLICY_LOCAL_ACTION)
    if action not in ("count", "drop"):
        raise PolicyError(f"VALI_NET_POLICY_LOCAL_ACTION must be count or drop, not {action!r}")
    dns_pps = int(settings.VALI_NET_POLICY_DNS_LIMIT_PPS)
    if not 1 <= dns_pps <= MAX_DNS_LIMIT_PPS:
        raise PolicyError(f"VALI_NET_POLICY_DNS_LIMIT_PPS must be 1..{MAX_DNS_LIMIT_PPS}")

    vm_ids = []
    for vm_id in _hosted_vm_ids(miner.miner_id):
        if _valid_vm_id(vm_id):
            vm_ids.append(vm_id)
        else:
            log.warning(
                "net-policy: miner=%s vm %r has no miner-valid id — no cap", miner.miner_id, vm_id
            )
    flavors = _recorded_flavors(vm_ids)
    with_ip = set(
        PublicIP.objects.filter(state=PublicIpState.ATTACHED, vm__vm_id__in=vm_ids).values_list(
            "vm__vm_id", flat=True
        )
    )
    # Port 25 stays closed for every VM unless it was unblocked for the
    # holder of its public IP.
    smtp_allowed = set(
        PublicIP.objects.filter(
            state=PublicIpState.ATTACHED, smtp_allowed=True, vm__vm_id__in=vm_ids
        ).values_list("vm__vm_id", flat=True)
    )
    # A CDN node is exempt from the flavor caps (CDN plan N2): they would
    # throttle it far below what it serves.
    cdn = cdn_vm_ids(vm_ids)
    vm_caps = {
        vm_id: cdn_cap_mbps(mode)
        if vm_id in cdn
        else min(
            miner_cap_mbps(
                effective_cap_mbps(flavors.get(vm_id, ""), has_public_ip=vm_id in with_ip), mode
            ),
            MAX_VM_CAP_MBPS,
        )
        for vm_id in vm_ids
    }
    if len(vm_caps) > MAX_ENTRIES:
        raise PolicyError(f"more than {MAX_ENTRIES} VMs on the miner")
    if any(cap < 1 for cap in vm_caps.values()):
        raise PolicyError("a VM cap is below 1 Mbit/s — check VALI_NET_CAP_*")

    infra: list[dict[str, Any]] = []
    nb_control: list[dict[str, Any]] = []
    region_miners: list[str] = []
    if mode == EgressMode.EDGE:
        infra = _endpoints(settings.VALI_NET_POLICY_INFRA, "VALI_NET_POLICY_INFRA")
        nb_control = _endpoints(settings.VALI_NET_POLICY_NB_CONTROL, "VALI_NET_POLICY_NB_CONTROL")
        metered = {e["ip"] for e in nb_control}
        if metered & {e["ip"] for e in infra}:
            raise PolicyError("VALI_NET_POLICY_NB_CONTROL overlaps VALI_NET_POLICY_INFRA")
        if enforce and not nb_control:
            # An enforcing miner with no NetBird control endpoint cuts every
            # guest off the overlay.
            raise PolicyError("enforce needs VALI_NET_POLICY_NB_CONTROL")
        region_miners = _region_miner_ips(region, exclude=metered)

    return {
        "region": region,
        "mode": str(mode),
        "enforce": bool(enforce),
        "local_action": action,
        "infra": infra,
        "region_miners": region_miners,
        "nb_control": nb_control,
        "dns_limit_pps": dns_pps,
        "smtp_allowed_vms": sorted(smtp_allowed),
        "vm_caps": vm_caps,
    }


def _region_miner_ips(region: str, *, exclude: set[str]) -> list[str]:
    """The public connection IPs of the miners detected in `region`."""
    from apps.miners.models import MinerLocation

    ips = {
        str(ip)
        for ip in MinerLocation.objects.annotate(cc=Upper("country_code"))
        .filter(cc=region, connection_ip__isnull=False)
        .values_list("connection_ip", flat=True)
    }
    out = sorted(ip for ip in ips if is_public_ipv4(ip) and ip not in exclude)
    if len(out) > MAX_ENTRIES:
        raise PolicyError(f"more than {MAX_ENTRIES} miners in region {region}")
    return out


def content_key(content: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def order_payload(content: dict[str, Any], *, revision: int, not_after_unix: int) -> bytes:
    return json.dumps(
        {**content, "revision": revision, "not_after_unix": not_after_unix}, sort_keys=True
    ).encode()


def expected_ack(revision: int, body_sha: str) -> str:
    return f"applied:{revision}:{body_sha}"


# ─── reconcile ───────────────────────────────────────────────────────


@dataclass
class ReconcileReport:
    enabled: bool = False
    pushed: int = 0
    acked: int = 0
    failed: list[str] = field(default_factory=list)
    #: Miners left for the next pass (tick budget spent).
    deferred: int = 0


def selected(miner_id: str) -> bool:
    """Whether `miner_id` is in `VALI_NET_POLICY_MINERS` (`*` = all)."""
    allow = [m.strip() for m in settings.VALI_NET_POLICY_MINERS if m.strip()]
    return "*" in allow or miner_id in allow


def reconcile(*, now: datetime | None = None) -> ReconcileReport:
    """One push pass over the selected miners. Nothing at all while
    `VALI_NET_POLICY_PUSH` is off."""
    report = ReconcileReport(enabled=bool(settings.VALI_NET_POLICY_PUSH))
    if not report.enabled:
        return report
    miners = [
        m
        for m in MinerIdentity.objects.filter(netbird_ip__isnull=False)
        .select_related("location", "net_policy")
        if selected(m.miner_id)
    ]
    # Least recently sent first, so a spent budget rotates.
    epoch = timezone.make_aware(datetime(1970, 1, 1))
    miners.sort(key=lambda m: (_policy(m).sent_at if _policy(m) else None) or epoch)
    started = time.monotonic()
    budget = float(settings.VALI_NET_POLICY_TICK_BUDGET_S)
    for i, miner in enumerate(miners):
        if time.monotonic() - started > budget:
            report.deferred = len(miners) - i
            log.warning("net-policy: tick budget spent, %d miner(s) deferred", report.deferred)
            break
        try:
            outcome = sync_miner(miner, now=now)
        except Exception:  # noqa: BLE001 — one miner must not stop the pass.
            log.exception("net-policy: miner=%s unhandled error", miner.miner_id)
            report.failed.append(miner.miner_id)
            continue
        if outcome == "acked":
            report.pushed += 1
            report.acked += 1
        elif outcome == "failed":
            report.pushed += 1
            report.failed.append(miner.miner_id)
    return report


def _policy(miner: MinerIdentity) -> MinerNetPolicy | None:
    try:
        return miner.net_policy
    except MinerNetPolicy.DoesNotExist:
        return None


def _record_error(miner: MinerIdentity, error: str) -> None:
    MinerNetPolicy.objects.update_or_create(miner=miner, defaults={"last_error": error[:256]})


def _stage(miner: MinerIdentity, content: dict[str, Any]) -> tuple[MinerNetPolicy, bool]:
    """The miner's row at the revision of `content`: unchanged when the
    content is, else one revision up with its digest. Returns
    `(row, bumped)`."""
    key = content_key(content)
    with transaction.atomic():
        row, _ = MinerNetPolicy.objects.select_for_update().get_or_create(miner=miner)
        if row.content_key == key and row.revision > 0 and row.body_sha:
            return row, False
        revision = row.revision + 1
        # Any value works for the digest: it leaves the expiry out.
        body_sha = order_dispatch.net_policy_digest(
            order_payload(content, revision=revision, not_after_unix=0)
        )
        row.revision = revision
        row.content_key = key
        row.body_sha = body_sha
        row.body = {**content, "revision": revision}
        row.region = content["region"]
        row.mode = content["mode"]
        row.apply_failures = 0
        row.save()
        return row, True


def edge_held(row: MinerNetPolicy, *, now: datetime) -> bool:
    """The agent refused edge mode as unsupported recently: no edge-mode
    revision goes to it, new or not."""
    if row.mode != EgressMode.EDGE or row.edge_unsupported_at is None:
        return False
    hold = timedelta(seconds=int(settings.VALI_NET_POLICY_UNSUPPORTED_RETRY_S))
    return now - row.edge_unsupported_at < hold


def _retry_period_s(row: MinerNetPolicy) -> int:
    if row.acked_current:
        return int(settings.VALI_NET_POLICY_SYNC_S)
    base = int(settings.VALI_NET_POLICY_RETRY_S)
    if row.apply_failures:
        cap = int(settings.VALI_NET_POLICY_APPLY_BACKOFF_MAX_S)
        return min(base << min(row.apply_failures - 1, 20), max(cap, base))
    return base


def _due(row: MinerNetPolicy, *, bumped: bool, now: datetime) -> bool:
    if edge_held(row, now=now):
        return False
    if bumped or row.sent_at is None:
        return True
    return now - row.sent_at >= timedelta(seconds=_retry_period_s(row))


def sync_miner(miner: MinerIdentity, *, now: datetime | None = None, force: bool = False) -> str:
    """Bring one miner's policy up to date. Returns `skipped` (not due),
    `acked` or `failed`; the outcome is recorded on its `MinerNetPolicy`."""
    now = now or timezone.now()
    region = miner_region(miner)
    if not region:
        _record_error(miner, "no-region: the miner has no detected country")
        return "failed"
    try:
        content = build_content(miner, region)
        row, bumped = _stage(miner, content)
    except PolicyError as exc:
        _record_error(miner, f"build: {exc}")
        return "failed"
    except order_dispatch.OrderDispatchError as exc:
        _record_error(miner, f"digest: {exc}")
        return "failed"
    if not force and not _due(row, bumped=bumped, now=now):
        return "skipped"
    return _push(miner, row, content, now=now)


def _push(
    miner: MinerIdentity, row: MinerNetPolicy, content: dict[str, Any], *, now: datetime
) -> str:
    ttl = min(int(settings.VALI_NET_POLICY_TTL_S), MAX_TTL_S)
    payload = order_payload(
        content, revision=row.revision, not_after_unix=int(now.timestamp()) + ttl
    )
    order_id = f"np-{miner.miner_id}-r{row.revision}-{uuid.uuid4().hex[:12]}"[:128]
    want = expected_ack(row.revision, row.body_sha)
    error = ""
    try:
        result = order_dispatch.dispatch_order_settled(
            miner_id=miner.miner_id,
            netbird_ip=str(miner.netbird_ip),
            order_id=order_id,
            kind="net-policy",
            payload_json=payload,
            attempts=2,
            retry_after_s=5.0,
            deadline_s=60.0,
            timeout_s=25.0,
        )
    except order_dispatch.OrderDispatchUnavailable as exc:
        error = f"unreachable: {exc}"
    except order_dispatch.OrderDispatchError as exc:
        error = f"dispatch: {exc}"
    else:
        if result.ok and result.classifier == want:
            pass
        elif result.ok:
            error = f"ack-mismatch: {result.classifier[:160]!r}"
        else:
            error = f"refused: status={result.status} class={result.classifier[:120]!r}"
            if result.status == 409 and result.classifier in (STALE_REVISION, REVISION_CONFLICT):
                _jump_revision(row, stale=result.classifier == STALE_REVISION)
            elif result.status == 422 and result.classifier == UNSUPPORTED:
                if content["mode"] == EgressMode.EDGE:
                    MinerNetPolicy.objects.filter(pk=row.pk).update(edge_unsupported_at=now)
                    error = f"unsupported: edge mode refused, held for r{row.revision}"
            elif result.status == 500 and result.classifier == APPLY_FAILED:
                # Only while this revision is still the row's: a new one
                # starts its own count.
                MinerNetPolicy.objects.filter(pk=row.pk, revision=row.revision).update(
                    apply_failures=F("apply_failures") + 1
                )

    MinerNetPolicy.objects.filter(pk=row.pk).update(sent_at=now, last_error=error[:256])
    if not error:
        # A slower push of an older revision must not overwrite a newer ack.
        acked = MinerNetPolicy.objects.filter(pk=row.pk, acked_revision__lte=row.revision)
        acked.update(acked_revision=row.revision, acked_sha=row.body_sha, acked_at=now)
        acked.filter(revision=row.revision).update(apply_failures=0)
        if content["mode"] == EgressMode.EDGE:
            MinerNetPolicy.objects.filter(pk=row.pk).update(edge_unsupported_at=None)
    if error:
        log.warning(
            "net-policy: miner=%s revision=%d not acked: %s", miner.miner_id, row.revision, error
        )
        return "failed"
    log.info("net-policy: miner=%s revision=%d acked", miner.miner_id, row.revision)
    return "acked"


def _jump_revision(row: MinerNetPolicy, *, stale: bool) -> None:
    """The miner holds a revision vali no longer knows about. Clear the
    content key so the next pass stages a new revision: one up for a
    conflict (same revision, other content), doubled for a stale one (the
    miner's is higher by an unknown amount)."""
    revision = max(row.revision * 2, row.revision + 1) - 1 if stale else row.revision
    MinerNetPolicy.objects.filter(pk=row.pk).update(revision=revision, content_key="", body_sha="")


# ─── placement gate ──────────────────────────────────────────────────


def readiness(policy: MinerNetPolicy | None, *, region: str, now: datetime) -> str:
    """`""` when the miner acked, recently, its current edge-mode policy
    for `region`, else why not."""
    if policy is None or policy.revision == 0:
        return "net-policy-missing"
    if policy.mode != EgressMode.EDGE or policy.region != region or not policy.acked_current:
        return "net-policy-not-acked"
    stale = timedelta(seconds=int(settings.VALI_NET_POLICY_ACK_STALE_S))
    if policy.acked_at is None or now - policy.acked_at > stale:
        return "net-policy-ack-stale"
    return ""


def unready_node_ids(*, now: datetime | None = None) -> dict[str, str]:
    """`{lower-case chain node_id: reason}` of the miners in an edge-mode
    region that must take no new VM. `{}` after one query while every
    region is local."""
    edge_regions = list(
        EgressRegion.objects.filter(mode=EgressMode.EDGE).values_list("region", flat=True)
    )
    if not edge_regions:
        return {}
    now = now or timezone.now()
    miners = (
        MinerIdentity.objects.filter(chain_node_id__isnull=False)
        .annotate(cc=Upper("location__country_code"))
        .filter(cc__in=[r.upper() for r in edge_regions])
        .select_related("net_policy")
    )
    out: dict[str, str] = {}
    for miner in miners:
        reason = readiness(_policy(miner), region=miner.cc, now=now)
        if reason:
            out[str(miner.chain_node_id).lower()] = reason
    return out
