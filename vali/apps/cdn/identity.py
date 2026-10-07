"""Whether a launch is a CDN node's (CDN plan V2).

The reconciler records a `CdnNode` before it launches the node's VM. The
launch then BINDS the node to the VM row it creates (`CdnNode.vm`), after
checking that the VM runs as the CDN tenant, boots the cdn-node image and
carries the node's own user-data. From then on the binding is the one
durable fact every mint and every pin derives the role from — never the
launch request, a setting or a flag:

- the ticket carries the lifecycle perm `cdn-node` and one `cdn-fleet-v<N>`
  per fleet key version vali publishes (pending, active, retiring): the
  KBS releases exactly those keys, and only to a `cdn_node`-class
  measurement (`docs/operator/cdn-fleet-keyring.md`). At the launch mint
  and at the §25 / KBS-recovery re-mint, so every relaunch (power start,
  reboot recovery, resize, guest upgrade) keeps them;
- the measured cmdline carries `hippius.cdn_node=1` and
  `hippius.cdn_fleet_dir=/run/hippius/cdn-fleet` (where guest-release
  writes the keyring);
- the measurement is pinned under the `cdn_node` allowlist class, and the
  allowlist carry-forward classes the VM's measurements the same way.

`VALI_CDN_LAUNCH_ROLE` (with `VALI_CDN_ENABLED`) gates LAUNCHING a CDN node:
while off such a launch refuses, loudly, before anything is staged. The
role of a VM already bound does not depend on it.
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.db import transaction

from apps.common.cdn import cdn_enabled, is_cdn_tenant

#: The ticket lifecycle perm (`kbs_core::lifecycle::CDN_NODE_PERM`). An older
#: KBS ignores unknown perms.
CDN_NODE_PERM = "cdn-node"
#: One perm per fleet key version the node receives
#: (`kbs_core::cdn_fleet::CDN_FLEET_VERSION_PERM_PREFIX`), 1 to
#: `MAX_FLEET_VERSIONS` of them (`hippius_types::vault_broker::
#: MAX_CDN_FLEET_VERSIONS`).
CDN_FLEET_VERSION_PERM_PREFIX = "cdn-fleet-v"
MAX_FLEET_VERSIONS = 4

#: Measured cmdline tokens of a CDN node's launch.
CDN_NODE_CMDLINE_KEY = "hippius.cdn_node"
CDN_FLEET_DIR_CMDLINE_KEY = "hippius.cdn_fleet_dir"
CDN_FLEET_DIR = "/run/hippius/cdn-fleet"

#: The only disk mode a CDN node boots (a dm-verity golden base).
_GOLDEN_DISK_MODE = "golden_verity_overlay"


class CdnRoleError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def launch_role_enabled() -> bool:
    return cdn_enabled() and bool(getattr(settings, "VALI_CDN_LAUNCH_ROLE", False))


def _node(vm_id: str) -> Any:
    from .models import CdnNode

    return CdnNode.objects.filter(node_id=vm_id).first() if vm_id else None


def is_reserved(vm_id: str) -> bool:
    """A CDN node names `vm_id`: only the fleet launches it."""
    return _node(vm_id) is not None


def is_cdn_vm(vm_id: str) -> bool:
    """`vm_id`'s VM is a CDN node: a node is bound to that VM row. The one
    predicate the ticket perm and the allowlist class read."""
    from .models import CdnNode

    return bool(vm_id) and CdnNode.objects.filter(node_id=vm_id, vm__vm_id=vm_id).exists()


def fleet_versions() -> list[int]:
    """The fleet key versions a node's ticket names: every one vali
    publishes (pending, active, retiring), ascending."""
    from .models import CdnFleetKey, CdnFleetKeyState

    return list(
        CdnFleetKey.objects.filter(
            state__in=(
                CdnFleetKeyState.PENDING,
                CdnFleetKeyState.ACTIVE,
                CdnFleetKeyState.RETIRING,
            )
        )
        .order_by("version")
        .values_list("version", flat=True)
    )


def check_launch(vm_id: str, tenant_id: str) -> bool:
    """Whether a launch of `vm_id` for `tenant_id` is a CDN node's; raises
    `CdnRoleError` for one that must not happen:

    - `cdn-node-id-reserved` — a node names `vm_id` but the launch, or the
      VM row that already exists for it, is not the CDN tenant's;
    - `cdn-role-disabled` — a CDN node's launch while `VALI_CDN_LAUNCH_ROLE`
      or `VALI_CDN_ENABLED` is off;
    - `cdn-fleet-no-version` / `cdn-fleet-too-many-versions` — no fleet key
      published, or more than the KBS releases: it would refuse the
      ticket."""
    from apps.lifecycle.models import Vm

    node = _node(vm_id)
    if node is None:
        return False
    row_tenant = Vm.objects.filter(vm_id=vm_id).values_list("tenant_id", flat=True).first()
    if not is_cdn_tenant(tenant_id) or (row_tenant is not None and not is_cdn_tenant(row_tenant)):
        raise CdnRoleError(
            "cdn-node-id-reserved", f"vm id {vm_id!r} is a CDN node's; only the CDN tenant runs it"
        )
    if not launch_role_enabled():
        raise CdnRoleError(
            "cdn-role-disabled",
            f"vm {vm_id!r} is a CDN node and VALI_CDN_LAUNCH_ROLE (or VALI_CDN_ENABLED) is off",
        )
    versions = fleet_versions()
    if not versions:
        raise CdnRoleError(
            "cdn-fleet-no-version", "no fleet key is published: mint one first (vali_cdn_fleet)"
        )
    if len(versions) > MAX_FLEET_VERSIONS:
        raise CdnRoleError(
            "cdn-fleet-too-many-versions",
            f"{len(versions)} fleet key versions published; the KBS releases at most "
            f"{MAX_FLEET_VERSIONS} (retire one)",
        )
    return True


def check_launch_spec(spec: Any) -> None:
    """A CDN node's launch boots exactly a cdn-node bake blessed restricted to
    the CDN tenant — its kernel and dm-verity base, and either the bake's
    initrd or a guest-release build of it — and carries exactly the node's
    own user-data with NetBird on, on the base cmdline `VALI_CDN_CMDLINE`
    and with no caller-supplied measurement. Checked on the final launch
    spec, so no caller field can swap anything in. Raises `CdnRoleError`
    (`cdn-node-needs-cdn-image`, `cdn-node-userdata`)."""
    from apps.images.models import GoldenImage
    from apps.orchestration.models import GuestInitrdBuild
    from apps.tenant_bake.models import TenantBake, TenantBakeProfile, TenantBakeState

    from . import userdata as cdn_userdata

    def refuse(why: str) -> CdnRoleError:
        return CdnRoleError("cdn-node-needs-cdn-image", f"vm {spec.vm_id!r} is a CDN node: {why}")

    bake = TenantBake.objects.filter(bake_id=spec.bake_id).first() if spec.bake_id else None
    if (
        bake is None
        or bake.profile != TenantBakeProfile.CDN_NODE.value
        or bake.state != TenantBakeState.SUCCEEDED.value
    ):
        raise refuse(f"bake {spec.bake_id!r} is not a succeeded cdn-node bake")
    if not GoldenImage.objects.filter(
        bake_id=bake.bake_id, restricted_tenant=spec.tenant_id
    ).exists():
        raise refuse(f"bake {bake.bake_id!r} is not blessed restricted to the CDN tenant")
    expected = {
        "disk_mode": _GOLDEN_DISK_MODE,
        "kernel_sha256_hex": bake.kernel_sha256,
        "verity_root_hash_hex": bake.verity_root_hash,
        "rootfs_img_sha256_hex": bake.rootfs_img_sha256,
        "rootfs_verity_sha256_hex": bake.rootfs_verity_sha256,
    }
    for field, value in expected.items():
        got = str(getattr(spec, field, "") or "").lower()
        if not value or got != str(value).lower():
            raise refuse(f"its {field} is not the bake's")
    if spec.measurement_hex:
        raise refuse("a CDN node's measurement is vali's own recompute, never a caller's")
    cmdline = str(getattr(settings, "VALI_CDN_CMDLINE", "") or "")
    if spec.cmdline != cmdline:
        # The base of the MEASURED cmdline: a token added here (a debug
        # shell on the miner-owned console) would be pinned with the role.
        raise refuse("its base cmdline is not VALI_CDN_CMDLINE")
    initrd = str(spec.initrd_sha256_hex or "").lower()
    if initrd != str(bake.initrd_sha256 or "").lower() and not (
        GuestInitrdBuild.objects.filter(
            initrd_sha256=initrd,
            base_initrd_sha256=bake.initrd_sha256,
            kernel_sha256=bake.kernel_sha256,
            rootfs_img_sha256=bake.rootfs_img_sha256,
            rootfs_verity_sha256=bake.rootfs_verity_sha256,
            verity_root_hash=bake.verity_root_hash,
            withdrawn_at__isnull=True,
            release__withdrawn_at__isnull=True,
        ).exists()
    ):
        raise refuse("its initrd is neither the bake's nor a guest-release build of it")

    node = _node(spec.vm_id)
    try:
        expected_userdata = cdn_userdata.render(spec.vm_id, node.region)
    except cdn_userdata.CdnUserdataError as exc:
        raise CdnRoleError("cdn-node-userdata", str(exc)) from exc
    if not spec.enable_netbird or bytes(spec.userdata) != expected_userdata:
        raise CdnRoleError(
            "cdn-node-userdata",
            f"vm {spec.vm_id!r} is a CDN node: it carries its own user-data, with NetBird on",
        )


def bind_vm(vm_id: str, vm: Any) -> None:
    """Bind the node named `vm_id` to its VM row, once: a node already bound
    to another row refuses (`cdn-node-id-reserved`)."""
    from .models import CdnNode

    with transaction.atomic():
        node = CdnNode.objects.select_for_update().filter(node_id=vm_id).first()
        if node is None or vm is None or vm.vm_id != vm_id:
            raise CdnRoleError("cdn-node-id-reserved", f"no CDN node to bind to vm {vm_id!r}")
        if node.vm_id is None:
            # Only the row this node's own launch created: a row that
            # predates the node was made by another launch of the id, whose
            # guest got the vm id's first-write-wins lifecycle seed.
            if vm.created_at < node.created_at:
                raise CdnRoleError(
                    "cdn-node-id-reserved",
                    f"vm row {vm_id!r} predates its CDN node: refusing to adopt it",
                )
            node.vm = vm
            node.save(update_fields=["vm", "updated_at"])
        elif node.vm_id != vm.pk:
            raise CdnRoleError(
                "cdn-node-id-reserved", f"CDN node {vm_id!r} is bound to another VM row"
            )


def ticket_perms(base: tuple[str, ...], vm_id: str) -> tuple[str, ...]:
    """`base`, plus `cdn-node` and the published fleet versions for a CDN
    node's VM (`is_cdn_vm`)."""
    if CDN_NODE_PERM in base or not is_cdn_vm(vm_id):
        return base
    versions = tuple(f"{CDN_FLEET_VERSION_PERM_PREFIX}{v}" for v in fleet_versions())
    return (*base, CDN_NODE_PERM, *versions)
