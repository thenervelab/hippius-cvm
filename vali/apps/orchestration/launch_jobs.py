"""Admin→API launch jobs (PR-A2) — intake + async worker.

`POST /v1/vm/launch` stages the cloud-init userdata to Vault and records
a `LaunchJob(queued)` carrying ONLY the non-secret intent + Vault refs
(§20: no plaintext secret on the row). `vali_launch_tick` claims one
queued job (CAS), reads the secrets back from Vault, drives
[`launch.launch_vm`] (scheduler place → dispatch → re-place), and records
the outcome.

Async because the miner preflight inside `launch_vm` can take up to 30
min — far longer than an HTTP request can hold.
"""

from __future__ import annotations

import logging
import re
import secrets
from typing import Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from apps.identity import scoping
from apps.orchestration import power_policy, webhook
from apps.orchestration.effects import EffectError, EffectUnavailable
from apps.orchestration.models import LaunchJob, LaunchJobState, LaunchPhase
from apps.orchestration.services import customer_keys, flavors, launch, vault_kv
from apps.scheduler.placement import REGION_RE

log = logging.getLogger("apps.orchestration.launch_jobs")

# `vm_id` is interpolated into Vault KV paths (`{prefix}/{vm_id}/…`), the
# minted OrderTicket, and the netbird hostname — so it is charset-locked
# to defeat path traversal (`../`) into another tenant's Vault namespace.
# Same shape as `apps.tenant_bake.views._VM_ID_RE`.
_VM_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")
# `image` (launch-by-image) is a catalog LOOKUP key — charset-locked to the
# same shape as an image_name so junk is rejected early. Mirrors
# `apps.images.management.commands.vali_bless_golden_image._IMAGE_NAME_RE`.
_IMAGE_NAME_RE = re.compile(r"^[a-z0-9-]{1,64}$")
# Upper bound on `kek_vault_path` — matches the LaunchJob column.
_MAX_VAULT_PATH = 512
# Bounds on the minted ticket's lifetime. The ticket is the authorization
# to release this VM's KEK + userdata to whoever attests, so how long it
# stays redeemable is a security parameter and not a free-form knob: the
# floor keeps it usable long enough to reach a miner, the ceiling keeps a
# caller from minting a year-long release authorization. 86400 is also the
# API default.
_MIN_EXPIRY_SECONDS = 60
_MAX_EXPIRY_SECONDS = 86400

# Boot-disk integrity modes (mirror `launch.py` / `TenantBakeDiskMode`).
_DISK_MODE_LEGACY_LUKS = "legacy_luks"
_DISK_MODE_GOLDEN_VERITY = "golden_verity_overlay"

# Non-secret `LaunchSpec` fields the POST supplies (everything except the
# `kek_bytes` / `userdata` secrets). `(name, required, default)`.
#
# NOTE: `luks_header_sha256_hex` is DELIBERATELY not here — it is required
# ONLY for `legacy_luks` (a golden bake has no per-VM LUKS header). It lives
# in `_OPTIONAL` with an empty default and is validated conditionally in
# `_build_spec_json` after `disk_mode` is known.
_REQUIRED = (
    "tenant_id",
    "user_id",
    "vm_id",
    "lease_id",
    "flavor",
    "cmdline",
    "s3_bucket",
    "s3_key_prefix",
    "luks_disk_sha256_hex",
    "kernel_sha256_hex",
    "initrd_sha256_hex",
)
_OPTIONAL: dict[str, Any] = {
    "platform_id": "",
    "ticket_id": "",
    "order_id": "",
    "rootfs_sha256_hex": "",
    # Per-VM LUKS-header MAC — required + validated ONLY for `legacy_luks`
    # (see `_build_spec_json`). A golden bake binds the shared dm-verity
    # base via `verity_root_hash_hex` instead, so this stays empty and the
    # golden branch of `_augment_disk_binding` never reads it.
    "luks_header_sha256_hex": "",
    # golden-bake (option b): the boot-disk integrity mode + the golden
    # base's dm-verity root hash. Defaults keep the legacy per-VM LUKS vda
    # path byte-identical; a golden launch supplies `disk_mode` +
    # `verity_root_hash_hex` (from the bake's `golden-*.measurement.json`).
    "disk_mode": "legacy_luks",
    "verity_root_hash_hex": "",
    # golden-bake PR4: the SHARED golden base artifact SHAs (from the
    # golden bake's measurement.json). Only used in golden mode; the
    # miner fetches rootfs.img + rootfs.verity by these SHAs (cache-keyed).
    "rootfs_img_sha256_hex": "",
    "rootfs_verity_sha256_hex": "",
    "measurement_hex": "",
    "auto_pin_allowlist": False,
    # NetBird is ON by default for every VM (overlay reachability). Opt out
    # by POSTing `"enable_netbird": false`. When enabled, the userdata MUST
    # carry the literal `{{NETBIRD_SETUP_KEY}}` placeholder (validated at
    # intake) — see docs/operator/userdata-templates/netbird-enabled.yaml.example.
    "enable_netbird": True,
    "netbird_group": "vms",
    "netbird_key_ttl_seconds": 3600,
    "netbird_hostname_template": "hippius-tenant-{vm_id}",
    "ovmf_path": "/var/lib/hippius-miner/ovmf.fd",
    "rootfs_data_path": "/var/lib/hippius-miner/rootfs.img",
    "rootfs_hash_path": "/var/lib/hippius-miner/rootfs.verity",
    "kid": "l1-order-ticket-v1",
    "expiry_seconds": 86400,
    # P9/#16 — carry the NAMED base forward onto the spec. Both are
    # resolved above (`_resolve_image` → `_resolve_bake`) and were then
    # dropped, so nothing downstream could say WHICH base a VM booted;
    # `launch._record_base_image` stamps them onto `VmBaseImage` so
    # "move this VM to the current blessed image" is an answerable
    # question. Inert for the launch itself — the artifacts are already
    # resolved into the sha fields by the time these are copied.
    "bake_id": "",
    "image_name": "",
    # Region constraint — ISO 3166-1 alpha-2 country code, validated +
    # uppercased in `_build_spec_json`. Empty ⇒ unconstrained (every
    # pre-existing caller). Consumed by scheduler gate (f); the VM lands
    # only on a miner the geo-probe has DETECTED there, or the launch
    # fails `no-miner-in-region` — it never falls back to another region.
    "region": "",
    # Anti-affinity — `[a-z0-9-]{1,64}`, namespaced by the tenant. Empty ⇒
    # none. Consumed by scheduler gate (k): never two VMs of one group on a
    # miner; an unsatisfiable launch fails
    # `placement-anti-affinity-unsatisfiable`.
    "placement_group": "",
}


class LaunchIntentError(Exception):
    """A `POST /v1/vm/launch` body failed validation. `category` maps to
    an HTTP status in the view (`wire`/`bad-field` → 400, `conflict` →
    409, `internal` → 503)."""

    def __init__(self, message: str, category: str = "wire") -> None:
        super().__init__(message)
        self.message = message
        self.category = category


def _check_flavor(flavor: object) -> None:
    """Refuse a flavor outside the catalogue (`bad-field`) or above the
    offered maximum (`flavor-not-offered`).

    In the catalogue is not the same as for sale: sizes above
    `VALI_SCHEDULER_MAX_FLAVOR` are refused even where a host could hold
    them (feasibility answers `never` / `flavor-not-offered` for them)."""
    if not isinstance(flavor, str) or flavor not in flavors.LAUNCHABLE_FLAVOR_NAMES:
        raise LaunchIntentError(
            f"flavor must be one of: {', '.join(flavors.LAUNCHABLE_FLAVOR_NAMES)}",
            "bad-field",
        )
    if not flavors.is_offered(flavor):
        raise LaunchIntentError(
            f"flavor {flavor!r} is not offered (largest offered: "
            f"{flavors.max_offered_flavor()})",
            "flavor-not-offered",
        )


def _build_spec_json(intent: dict[str, Any]) -> dict[str, Any]:
    """Validate + normalise the non-secret launch intent into the
    `spec_json` dict the worker feeds to `LaunchSpec(**spec_json, …)`.
    """
    spec: dict[str, Any] = {}
    for key in _REQUIRED:
        val = intent.get(key)
        if not isinstance(val, str) or not val.strip():
            raise LaunchIntentError(f"missing or empty {key!r}")
        spec[key] = val
    # vm_id flows into Vault paths + the ticket — charset-lock it.
    if not _VM_ID_RE.fullmatch(spec["vm_id"]):
        raise LaunchIntentError(
            "vm_id must match [a-z0-9-]{1,64} (no path separators)", "bad-field"
        )
    _check_flavor(spec["flavor"])
    # `auto_pin_allowlist` is a PRODUCTION control-plane operation: the
    # worker's `allowlist_pin` signs the §22 artifact with the prod root
    # seed held in Vault (not a committed dev seed) and pins the
    # miner-preflight-computed launch digest (not a caller-supplied
    # measurement). It is therefore safe on prod and no longer gated on
    # VALI_ALLOW_PROD. (#587 Phase 1A — dev→prod allowlist-root rotation.)
    for key, default in _OPTIONAL.items():
        if key not in intent or intent[key] is None:
            spec[key] = default
            continue
        val = intent[key]
        if not isinstance(val, type(default)) or isinstance(val, bool) != isinstance(
            default, bool
        ):
            raise LaunchIntentError(f"{key} must be a {type(default).__name__}", "bad-field")
        spec[key] = val
    expiry = spec["expiry_seconds"]
    if not _MIN_EXPIRY_SECONDS <= expiry <= _MAX_EXPIRY_SECONDS:
        raise LaunchIntentError(
            f"expiry_seconds must be between {_MIN_EXPIRY_SECONDS} and "
            f"{_MAX_EXPIRY_SECONDS} (the ticket is a KEK-release "
            "authorization — its lifetime is a security parameter)",
            "bad-field",
        )

    # Region: shape-checked HERE, not left to the scheduler. An unparseable
    # value ("France", "FRA") would otherwise match no miner and surface,
    # minutes later, as a fleet-wide `no-miner-in-region` — a capacity
    # problem that is really a typo. Case is normalised so `fr` and `FR`
    # are one region, as `MinerLocation.region` is uppercase.
    region = spec["region"].strip()
    if region and not REGION_RE.match(region):
        raise LaunchIntentError(
            "region must be an ISO 3166-1 alpha-2 country code (e.g. 'FR')",
            "bad-field",
        )
    spec["region"] = region.upper()

    group = spec["placement_group"]
    if group and not _IMAGE_NAME_RE.fullmatch(group):
        raise LaunchIntentError("placement_group must match [a-z0-9-]{1,64}", "bad-field")

    # Guest-poweroff policy — `restart` (default) | `stop`; anything else is
    # a synchronous 400, never a silent default. Written into `spec_json`
    # only for `stop`, so every other launch's record is as before (and an
    # older image rolled back to can still rebuild its relaunch spec).
    if intent.get("on_guest_poweroff") is not None:
        try:
            policy = power_policy.parse_policy(intent["on_guest_poweroff"])
        except ValueError as exc:
            raise LaunchIntentError(str(exc), "bad-field") from exc
        if policy == power_policy.STOP:
            spec["on_guest_poweroff"] = policy

    # Tenant price ceiling — optional positive int (USD/unit ×1e6) or None
    # (no ceiling ⇒ the VM is never migrated on a miner price change).
    # Handled outside `_OPTIONAL` because its default is None (the type-
    # coercion loop keys off the default's type).
    mpu = intent.get("max_price_per_unit")
    if mpu is None:
        spec["max_price_per_unit"] = None
    elif isinstance(mpu, int) and not isinstance(mpu, bool) and mpu > 0:
        spec["max_price_per_unit"] = mpu
    else:
        raise LaunchIntentError(
            "max_price_per_unit must be a positive integer", "bad-field"
        )

    # Disk-integrity binding is mode-gated (golden-bake option b): the
    # LUKS-header MAC is required ONLY for `legacy_luks`; a golden bake binds
    # the shared read-only dm-verity base via the verity trio instead. Mirror
    # `launch._augment_disk_binding` / `_select_preflight_artifacts` so a
    # golden POST is not forced to carry an inert LUKS-header placeholder.
    if spec["disk_mode"] == _DISK_MODE_GOLDEN_VERITY:
        for field in (
            "rootfs_img_sha256_hex",
            "rootfs_verity_sha256_hex",
            "verity_root_hash_hex",
        ):
            if not spec.get(field):
                raise LaunchIntentError(
                    f"disk_mode=golden_verity_overlay requires a non-empty "
                    f"{field!r} (from the golden bake's measurement.json)",
                    "bad-field",
                )
    elif spec["disk_mode"] == _DISK_MODE_LEGACY_LUKS:
        if not spec["luks_header_sha256_hex"]:
            raise LaunchIntentError("missing or empty 'luks_header_sha256_hex'")
    else:
        raise LaunchIntentError(
            f"unknown disk_mode {spec['disk_mode']!r} (expected "
            f"{_DISK_MODE_LEGACY_LUKS!r} or {_DISK_MODE_GOLDEN_VERITY!r})",
            "bad-field",
        )
    # Customer-held keys: carried on the spec ONLY for M1/M2, so an M0
    # `spec_json` is exactly what it was. Every relaunch rebuilds its
    # `LaunchSpec` from this dict, and `launch._ensure_vm_row` holds it to
    # the mode pinned on the `Vm` row.
    binding = _intent_binding(intent)
    if binding is not None:
        spec.update(customer_keys.spec_fields(binding))
    return spec


def _intent_binding(intent: dict[str, Any]) -> customer_keys.GuardianBinding | None:
    """The intent's `key_mode` / `guardian_endpoint` / `guardian_pubkey`,
    validated by the guardian cmdline grammar (`None` ⇒ M0)."""
    try:
        binding = customer_keys.binding_of(intent)
        # An address the miner relay refuses would fail the launch only
        # AFTER the worker pinned the mode on the `Vm` row, burning the
        # vm_id. Refused at intake instead.
        customer_keys.check_endpoint_allowed(binding)
        return binding
    except customer_keys.CustomerKeysError as exc:
        raise LaunchIntentError(str(exc), "bad-field") from exc


def _resolve_image(intent: dict[str, Any]) -> None:
    """Launch-by-image (golden-everywhere): resolve an `intent['image']`
    NAME to the CURRENT operator-blessed golden `bake_id`. A no-op when
    `image` is absent.

    TRUST BOUNDARY: the tenant supplies only the image NAME; vali maps it —
    through the OPERATOR-controlled `GoldenImage` catalog (written only by
    `vali_bless_golden_image`) — to the blessed golden `bake_id`. A tenant
    can therefore NEVER cause a launch off an un-blessed or arbitrary bake:

      - `image` + `bake_id` together are REJECTED (mutually exclusive) — so a
        tenant cannot pair a blessed name with an arbitrary bake_id.
      - an UNKNOWN image is REJECTED (fail closed) — it never falls through
        to a launch.
      - the resolved value is exactly whatever the operator blessed; the
        tenant's only input is the lookup key.

    `image` is pure sugar for "use the current golden bake for this distro":
    once resolved to a `bake_id` the EXISTING golden bake resolution below
    runs unchanged (golden-ness stays transparent).
    """
    image = intent.get("image")
    if not image:
        return
    if not isinstance(image, str):
        raise LaunchIntentError("image must be a string", "bad-field")
    # Mutually exclusive with an explicit bake_id — reject both so a tenant
    # can never pin a blessed image name to a bake_id of their choosing.
    if intent.get("bake_id"):
        raise LaunchIntentError(
            "image and bake_id are mutually exclusive", "bad-field"
        )
    if not _IMAGE_NAME_RE.match(image):
        raise LaunchIntentError(
            "image must match [a-z0-9-]{1,64}", "bad-field"
        )

    from apps.images.models import GoldenImage

    try:
        golden = GoldenImage.objects.get(image_name=image)
    except GoldenImage.DoesNotExist:
        # Fail closed: an unknown image never resolves to a launch.
        raise LaunchIntentError(
            f"image {image!r} is not a known launchable image", "bad-field"
        ) from None
    # An image restricted to one tenant (CDN plan N2) launches for that
    # tenant only; `_resolve_bake` re-checks by bake.
    if golden.restricted_tenant and golden.restricted_tenant != intent.get("tenant_id"):
        raise LaunchIntentError(
            f"image {image!r} is restricted to another tenant", "image-restricted"
        )
    # The catalog decides EVERY artifact of a launch by image: a caller value
    # would survive the fill-only resolution below (and a miner's cache is
    # keyed by sha, so a named rootfs/verity pair already cached elsewhere
    # would boot whatever the blessed prefix says).
    named = sorted(k for k in _IMAGE_ARTIFACT_KEYS if intent.get(k))
    if named:
        raise LaunchIntentError(
            f"a launch by image picks its own artifacts: {', '.join(named)} are not "
            "caller fields",
            "bad-field",
        )
    # Map the tenant-supplied NAME to the operator-blessed golden bake. The
    # existing `_resolve_bake` path below re-validates the bake is Succeeded.
    intent["bake_id"] = golden.bake_id
    # Keep the NAME too (P9/#16): `image_name` + `bake_id` together are what
    # an operator needs to tell a VM booting a stale base from one on the
    # current blessed image. Set from the OPERATOR-blessed lookup, not from
    # a free-form caller field, so it cannot be spoofed away from the bake
    # it actually resolved to.
    intent["image_name"] = image
    # The blessed guest release (phase 7), carried under a key no caller can
    # set: `_resolve_bake` pops it after resolving the bake.
    intent[_IMAGE_GUEST_RELEASE_KEY] = golden.guest_release


#: Set ONLY by `_resolve_image` from the operator-blessed catalog; any value
#: a caller put there is dropped first.
_IMAGE_GUEST_RELEASE_KEY = "_image_guest_release"

#: The launch-spec fields a launch by image takes from the catalog only.
_IMAGE_ARTIFACT_KEYS: tuple[str, ...] = (
    "disk_mode",
    "s3_bucket",
    "s3_key_prefix",
    "kernel_sha256_hex",
    "initrd_sha256_hex",
    "rootfs_img_sha256_hex",
    "rootfs_verity_sha256_hex",
    "verity_root_hash_hex",
    "luks_disk_sha256_hex",
    "luks_header_sha256_hex",
)


def _apply_guest_release(intent: dict[str, Any], bake: Any, release: int) -> None:
    """Point a golden launch at the image's blessed guest release: the
    bake's kernel and dm-verity base, the release's build of the bake's
    initrd. Fails closed (`conflict`) when that build is gone (withdrawn
    since the bless) — never a silent fallback to the bare bake, which may
    run an older, less secure set of agents."""
    from apps.orchestration.models import GuestInitrdBuild

    build = (
        GuestInitrdBuild.objects.select_related("release")
        .filter(
            release_id=release,
            base_initrd_sha256=bake.initrd_sha256,
            kernel_sha256=bake.kernel_sha256,
            rootfs_img_sha256=bake.rootfs_img_sha256,
            rootfs_verity_sha256=bake.rootfs_verity_sha256,
            verity_root_hash=bake.verity_root_hash,
            withdrawn_at__isnull=True,
            release__withdrawn_at__isnull=True,
        )
        .first()
    )
    if build is None:
        raise LaunchIntentError(
            f"the image's guest release {release} has no usable build for bake "
            f"{bake.bake_id!r} — an operator must re-bless it",
            "conflict",
        )
    intent["s3_bucket"] = build.s3_bucket
    intent["s3_key_prefix"] = build.s3_key_prefix
    intent["initrd_sha256_hex"] = build.initrd_sha256


def _check_bake_restriction(bake: Any, tenant_id: str, vm_id: str) -> None:
    """Refuse (`image-restricted`) a launch of `bake` by `tenant_id` when the
    bake is restricted to another tenant — by image name or by `bake_id`:

    - a cdn-node bake holds the CDN fleet's keys once released (CDN plan
      I3): only a CDN node's launch boots it — the role check of CDN plan
      V2 (`apps.cdn.identity`: a node names `vm_id`, the CDN tenant runs
      it, `VALI_CDN_LAUNCH_ROLE` is on);
    - a bake blessed as an image restricted to a tenant
      (`GoldenImage.restricted_tenant`, CDN plan N2) launches for that
      tenant only, whatever name the launch used."""
    from apps.cdn import identity as cdn_identity
    from apps.common.cdn import is_cdn_tenant
    from apps.images.models import GoldenImage
    from apps.tenant_bake.models import TenantBakeProfile

    if bake.profile == TenantBakeProfile.CDN_NODE.value and not (
        cdn_identity.launch_role_enabled()
        and is_cdn_tenant(tenant_id)
        and cdn_identity.is_reserved(vm_id)
    ):
        raise LaunchIntentError(
            f"bake {bake.bake_id!r} is a cdn-node image: only a CDN node's launch boots it",
            "image-restricted",
        )
    owners = set(
        GoldenImage.objects.filter(bake_id=bake.bake_id)
        .exclude(restricted_tenant="")
        .values_list("restricted_tenant", flat=True)
    )
    if owners - {tenant_id}:
        raise LaunchIntentError(
            f"bake {bake.bake_id!r} is restricted to another tenant", "image-restricted"
        )


def _check_artifact_restriction(intent: dict[str, Any]) -> None:
    """[`_check_bake_restriction`] on every golden bake whose shared base
    the launch would boot, by the artifacts it ends up with rather than the
    `bake_id` it named: caller fields win over a bake's (`_resolve_bake`),
    so a launch could name an open bake — or none — and carry a restricted
    image's dm-verity base."""
    from django.db.models import Q

    from apps.tenant_bake.models import TenantBake

    match = Q()
    for field, key in (
        ("verity_root_hash", "verity_root_hash_hex"),
        ("rootfs_img_sha256", "rootfs_img_sha256_hex"),
        ("rootfs_verity_sha256", "rootfs_verity_sha256_hex"),
    ):
        value = intent.get(key)
        if isinstance(value, str) and value:
            match |= Q(**{field: value.lower()})
    if not match:
        return
    tenant_id = str(intent.get("tenant_id") or "")
    vm_id = str(intent.get("vm_id") or "")
    for bake in TenantBake.objects.filter(match):
        _check_bake_restriction(bake, tenant_id, vm_id)


def _check_cdn_role(intent: dict[str, Any], *, cdn_node: bool) -> None:
    """The CDN role at intake (`apps.cdn.identity`), before anything is
    staged. A CDN node's vm id is launched only by the fleet reconciler,
    in-process, which says so (`cdn_node=True`); never through the HTTP
    API, whoever calls it (`cdn-node-id-reserved`). Its launch must be
    allowed to run (`cdn-role-disabled`) and name a cdn-node bake blessed
    restricted to the CDN tenant (`cdn-node-needs-cdn-image`). The launch
    re-checks all of it on the final spec, artifacts and user-data included
    (`launch.launch_on_miner`)."""
    from apps.cdn import identity as cdn_identity
    from apps.images.models import GoldenImage
    from apps.tenant_bake.models import TenantBake, TenantBakeProfile

    vm_id = str(intent.get("vm_id") or "")
    tenant_id = str(intent.get("tenant_id") or "")
    reserved = cdn_identity.is_reserved(vm_id)
    if reserved != cdn_node:
        raise LaunchIntentError(
            f"vm id {vm_id!r} is a CDN node's: only the CDN fleet launches it"
            if reserved
            else f"no CDN node names vm id {vm_id!r}",
            "cdn-node-id-reserved",
        )
    if not cdn_node:
        return
    try:
        cdn_identity.check_launch(vm_id, tenant_id)
    except cdn_identity.CdnRoleError as exc:
        raise LaunchIntentError(exc.detail, exc.code) from exc
    bake_id = str(intent.get("bake_id") or "")
    bake = TenantBake.objects.filter(bake_id=bake_id).first() if bake_id else None
    blessed = GoldenImage.objects.filter(bake_id=bake_id, restricted_tenant=tenant_id).exists()
    if bake is None or bake.profile != TenantBakeProfile.CDN_NODE.value or not blessed:
        raise LaunchIntentError(
            f"vm {vm_id!r} is a CDN node: it boots a cdn-node bake blessed restricted to "
            f"{tenant_id!r} only",
            "cdn-node-needs-cdn-image",
        )


def _resolve_bake(intent: dict[str, Any]) -> None:
    """Fill the launch-spec artifact fields from a Succeeded `TenantBake`
    named by `intent['bake_id']`. A no-op when `bake_id` is absent.
    Caller-supplied values are NOT overwritten — `bake_id` is a
    convenience that resolves only the fields the bake determines.

    Launch-by-image is resolved FIRST: if the intent names an `image`, it is
    mapped (via the operator-blessed `GoldenImage` catalog) to the current
    golden `bake_id`, which then flows through the normal bake resolution.

    Raises [`LaunchIntentError`] if the image/bake is unknown (`bad-field`)
    or the bake is not yet Succeeded (`conflict` — poll the bake + retry).
    """
    # Launch-by-image → resolve the blessed golden bake_id first (no-op
    # unless `intent['image']` is set). Rejects image+bake_id conflicts and
    # unknown images (fail closed) before any bake lookup.
    intent.pop(_IMAGE_GUEST_RELEASE_KEY, None)
    _resolve_image(intent)
    guest_release = intent.pop(_IMAGE_GUEST_RELEASE_KEY, None)
    bake_id = intent.get("bake_id")
    if not bake_id:
        return
    if not isinstance(bake_id, str):
        raise LaunchIntentError("bake_id must be a string", "bad-field")
    from apps.tenant_bake.models import TenantBake, TenantBakeState

    try:
        bake = TenantBake.objects.get(bake_id=bake_id)
    except TenantBake.DoesNotExist:
        raise LaunchIntentError(
            f"bake_id {bake_id!r} not found", "bad-field"
        ) from None
    if bake.state != TenantBakeState.SUCCEEDED.value:
        raise LaunchIntentError(
            f"bake {bake_id!r} is not Succeeded (state={bake.state!r})",
            "conflict",
        )
    _check_bake_restriction(
        bake, str(intent.get("tenant_id") or ""), str(intent.get("vm_id") or "")
    )
    # bake field → launch-spec field. Empty bake fields are skipped so an
    # older bake missing `luks_header_sha256` falls back to requiring it
    # on the intent (validated downstream).
    from apps.tenant_bake.models import TenantBakeDiskMode

    if bake.disk_mode == TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY.value:
        # GOLDEN (golden-bake PR6): the bake produced a SHARED, non-
        # confidential dm-verity base — NO per-VM qcow2 and NO KEK. Resolve
        # the golden fields the launch fetches by sha (cache-keyed) + the
        # measured verity root; DELIBERATELY do NOT copy `kek_vault_path`
        # (the golden bake staged no KEK — the per-VM overlay-upper KEK is
        # the launch's own per-VM luks-kek, caller-supplied). `luks_disk_
        # sha256_hex` is unused on the golden fetch path (that slot carries
        # `rootfs.img` keyed by `rootfs_img_sha256_hex`); fill it with the
        # rootfs.img sha only to satisfy the required-non-empty intent
        # check — the golden branch in `launch._select_preflight_artifacts`
        # never reads it.
        resolved = {
            "disk_mode": bake.disk_mode,
            "s3_bucket": bake.s3_output_bucket,
            "s3_key_prefix": bake.s3_output_prefix,
            "kernel_sha256_hex": bake.kernel_sha256,
            "initrd_sha256_hex": bake.initrd_sha256,
            "rootfs_img_sha256_hex": bake.rootfs_img_sha256,
            "rootfs_verity_sha256_hex": bake.rootfs_verity_sha256,
            "verity_root_hash_hex": bake.verity_root_hash,
            "luks_disk_sha256_hex": bake.rootfs_img_sha256,
            # A golden base is non-confidential dm-verity — there is no
            # per-VM LUKS header to bind. Leave `luks_header_sha256_hex`
            # empty so `_augment_disk_binding` takes the golden branch
            # (measured `dm-verity.root=`, no `hippius.luks_header_sha256`).
        }
    else:
        resolved = {
            "kek_vault_path": bake.kek_vault_path,
            "s3_bucket": bake.s3_output_bucket,
            "s3_key_prefix": bake.s3_output_prefix,
            "luks_disk_sha256_hex": bake.qcow2_sha256,
            "kernel_sha256_hex": bake.kernel_sha256,
            "initrd_sha256_hex": bake.initrd_sha256,
            "luks_header_sha256_hex": bake.luks_header_sha256,
        }
    if guest_release is not None:
        if bake.disk_mode != TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY.value:
            raise LaunchIntentError(
                f"bake {bake_id!r} is not golden: it cannot boot a guest release", "conflict"
            )
        _apply_guest_release(intent, bake, int(guest_release))
    for key, val in resolved.items():
        if val and not intent.get(key):
            intent[key] = val


def _canonical_kek_path(intent: dict[str, Any]) -> str:
    """`{prefix}/{vm_id}/luks-kek` — the KV path the KBS releases a KEK from
    (and derives `lifecycle-key` from)."""
    vm_id = intent.get("vm_id")
    # vm_id is interpolated into a Vault path — charset-lock it BEFORE
    # interpolation (defeats `../` traversal out of the per-VM namespace).
    # `_build_spec_json` re-checks it; this earlier check guards the write.
    if not isinstance(vm_id, str) or not _VM_ID_RE.fullmatch(vm_id):
        raise LaunchIntentError(
            "vm_id must match [a-z0-9-]{1,64} (no path separators)", "bad-field"
        )
    prefix = str(getattr(settings, "VALI_VAULT_KV_PREFIX", ""))
    if not prefix:
        raise LaunchIntentError("VALI_VAULT_KV_PREFIX is not configured", "internal")
    return f"{prefix}/{vm_id}/luks-kek"


def _provision_golden_overlay_kek(intent: dict[str, Any]) -> None:
    """Generate + stage the per-VM golden overlay-upper KEK server-side.

    A golden bake produces an UNKEYED, non-confidential dm-verity base and
    stages NO KEK (`_resolve_bake` skips `kek_vault_path`). The per-VM
    writable overlay upper is `luksFormat`'d IN THE GUEST at first boot with
    a KEK the KBS releases to the attested guest. Generate that KEK ENTIRELY
    inside Vault Transit (`transit/datakey/wrapped/kek-<vm_id>`) so vali never
    holds the plaintext (C1 / KEK-HSM Phase 4) and stage the `vault:v1:…`
    CIPHERTEXT at the canonical `{prefix}/{vm_id}/luks-kek` path.

    This is the golden counterpart to how a LEGACY launch obtains a wrapped
    KEK from its bake: the KBS `require_wrapped_kek` gate REFUSES a non-
    `vault:`-prefixed (plaintext) KEK on release (→ 403), so the async prod
    path MUST stage the Transit-wrapped form. The sync/CLI path (`kek_bytes`)
    wraps via `launch_on_miner`'s `transit_encrypt`; the async path has no
    plaintext KEK to wrap, so vali provisions it here.

    A caller that pre-staged its OWN (already wrapped) KEK and supplied
    `kek_vault_path` is respected — this only fires when the golden intent
    carries no KEK path.

    FIRST-WRITE-WINS (data-loss guard): the write is `cas=0` (create-only).
    A golden overlay is `luksFormat`'d IN THE GUEST at first boot with the
    datakey THIS function staged; the LUKS master key is then sealed in the
    on-disk header keyslot under that datakey and NEVER regenerated. So if a
    KEK is ALREADY staged for this vm_id (a RELAUNCH of an existing golden
    VM — e.g. reboot-recovery — where `_resolve_bake` deliberately drops the
    bake's `kek_vault_path`, so we land here again), overwriting it with a
    freshly generated datakey would strand the existing overlay
    (irrecoverable) → tenant DATA LOSS. The `cas=0` write refuses to clobber;
    on the resulting `VaultCasConflict` we REUSE the already-staged datakey.
    This mirrors the lifecycle-key first-write-wins discipline
    (`launch._stage_lifecycle_key`, `cas=0`).
    """
    luks_path = _canonical_kek_path(intent)
    vm_id = intent["vm_id"]
    mount = str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret"))
    try:
        transit_key = vault_kv.transit_key_name(vm_id)
        vault_kv.ensure_transit_key(transit_key)
        wrapped = vault_kv.transit_datakey_wrapped(transit_key)
        try:
            # `cas=0` — create ONLY if no KEK is staged yet (first-write-wins).
            vault_kv.put_kv(mount, luks_path, wrapped, cas=0)
        except vault_kv.VaultCasConflict:
            # A KEK is already staged for this vm_id — REUSE it (a relaunch of
            # an existing golden VM). Overwriting would strand the existing
            # overlay → data loss. The `wrapped` datakey just generated is
            # discarded (never persisted); the KBS releases the ORIGINAL
            # datakey the overlay was formatted with.
            log.info(
                "golden overlay KEK already staged for vm_id=%s — reusing "
                "(first-write-wins, no overwrite)",
                vm_id,
            )
    except (EffectError, EffectUnavailable) as exc:
        raise LaunchIntentError(
            f"golden overlay KEK provisioning failed: {exc}", "internal"
        ) from exc
    # Point the launch at the canonical (KV-relative) path — the validation
    # below asserts `kek_vault_path == {prefix}/{vm_id}/luks-kek`.
    intent["kek_vault_path"] = luks_path


def _refuse_held(locked: Any) -> None:
    """Under the Vm row lock: a job holding the VM (a guest upgrade, a
    resize, a §25 or §24) owns its launch record — a launch admitted now
    would replace that record under the job. No row (a first launch):
    nothing holds it."""
    if locked is None:
        return
    from .service import _has_active_job

    if _has_active_job(locked):
        raise LaunchIntentError(f"vm {locked.vm_id!r} is held by another operation", "conflict")


def start_launch(
    *, intent: dict[str, Any], userdata: bytes, decided_by: Any, cdn_node: bool = False
) -> LaunchJob:
    """Validate the intent, stage `userdata` to Vault, and enqueue a
    `LaunchJob`. The KEK is NOT staged here — `intent['kek_vault_path']`
    names where the worker reads it (the bake's path).

    `cdn_node` is the CDN fleet reconciler's, in-process only: it launches
    the CDN node the intent's `vm_id` names (`_check_cdn_role`). No HTTP
    caller can set it.

    Raises [`LaunchIntentError`] on a bad body / an in-flight launch for
    the same VM / a Vault failure.
    """
    if not userdata:
        raise LaunchIntentError("userdata must be non-empty", "bad-field")
    # The flavor FIRST — before the golden overlay KEK is provisioned and
    # the userdata staged. A refusal after those writes would strand Vault
    # material under a vm_id that has no `Vm` row, where §24 never looks.
    # (`_build_spec_json` re-checks; a missing flavor falls through to its
    # "missing or empty" message.)
    if intent.get("flavor"):
        _check_flavor(intent["flavor"])
    # `vault:` is the discriminator that says "this value is Transit
    # ciphertext" wherever a staged userdata is read back
    # (`launch.open_userdata_working_copy`). A cloud-config never starts
    # with it, so refusing it costs nothing and keeps the discriminator
    # unambiguous for caller-supplied bytes. `vali_create_vm` applies the
    # same rule.
    if userdata.startswith(b"vault:"):
        raise LaunchIntentError(
            "userdata must be cloud-init plaintext (a `vault:`-prefixed "
            "value is reserved for Transit ciphertext)",
            "bad-field",
        )
    # P2 — BIND the object's owner to the credential before anything else.
    # `tenant_id` arrives in the request body, so authorization built on it
    # unchecked would be authorization built on nothing. For a TENANT-scoped
    # principal the token's own tenant wins (a mismatching claim is
    # rejected, an absent one is filled in), so such a caller can neither
    # plant a VM in someone else's namespace nor create one it would then be
    # unable to see. For an OPERATOR principal (the upstream product API,
    # which is what calls this today) the body value stands: it is a trusted
    # caller's assertion about which end user it already authorized, and
    # vali cannot independently verify it — see `scoping.bind_tenant_id`.
    try:
        intent["tenant_id"] = scoping.bind_tenant_id(
            decided_by, intent.get("tenant_id")
        )
    except ValueError as exc:
        raise LaunchIntentError(str(exc), "bad-field") from exc
    # #587 Phase 1C — bake→launch chaining: if the intent names a
    # `bake_id`, fill the artifact fields a Succeeded TenantBake already
    # determined (the qcow2/kernel/initrd SHAs + the LUKS-header MAC + the
    # KEK Vault path + the S3 location) so the caller need not copy them
    # from the bake's measurement.json by hand. Caller-supplied values
    # win; only ABSENT fields are filled.
    # A DESTROYED (or decommissioning) vm_id must never be relaunched.
    # §24 crypto-erased that VM: its Transit keys are gone and its KV
    # blobs deleted. Staging fresh secrets under the same vm_id recreates
    # exactly the material the erase removed — and nothing can clean it up
    # afterwards, because a second decommission is refused for a VM that
    # is already Destroyed. (The KBS has also spent that vm_id's lifecycle
    # state, so such a launch could never release a KEK anyway.)
    from apps.lifecycle.models import Vm, VmState

    spent = (
        Vm.objects.filter(vm_id=intent.get("vm_id") or "")
        .filter(state__in=(VmState.DESTROYED, VmState.DECOMMISSIONING))
        .values_list("state", flat=True)
        .first()
    )
    if spent:
        raise LaunchIntentError(
            f"vm {intent.get('vm_id')!r} is {spent} — a decommissioned vm_id "
            "cannot be relaunched (its keys were crypto-erased; staging new "
            "secrets under it would recreate material §24 can no longer "
            "reach). Launch under a fresh vm_id.",
            "conflict",
        )

    _resolve_bake(intent)
    _check_artifact_restriction(intent)
    _check_cdn_role(intent, cdn_node=cdn_node)
    binding = _intent_binding(intent)
    # M1/M2: nothing that reaches the measured cmdline may carry a
    # cloud-init `cc:` / `end_cc` marker. Every relaunch or the worker
    # would only find out after the `Vm` pin, burning the vm_id.
    try:
        customer_keys.check_cloud_init_markers(
            binding,
            cmdline=intent.get("cmdline"),
            vm_id=intent.get("vm_id"),
            lease_id=intent.get("lease_id"),
        )
        # M1/M2: the lease_id is measured (`hippius.lease_id=`) — a
        # restricted charset, refused before any pin.
        customer_keys.check_lease_id(binding, intent.get("lease_id"))
        # M1/M2 with NetBird: vali hardens the userdata's `netbird up` at
        # launch; one it cannot find is refused now, before any KEK is
        # provisioned or anything is staged or pinned.
        if intent.get("enable_netbird", _OPTIONAL["enable_netbird"]) is not False:
            customer_keys.harden_netbird_up(binding, userdata)
    except customer_keys.CustomerKeysError as exc:
        raise LaunchIntentError(str(exc), "bad-field") from exc
    existing = Vm.objects.filter(vm_id=intent.get("vm_id") or "").first()
    # A VM another operation holds is refused BEFORE any Vault write (KEK,
    # userdata); the insert below re-checks it under the row lock.
    _refuse_held(existing)
    if existing is not None:
        # A re-POST for an existing vm_id is held to the mode pinned on its
        # row and to NOTHING else: the new-launch gates below (flag, golden,
        # capable bake) are not re-run, so a flag flip or a bake losing its
        # mark never strands an already-pinned M1/M2 VM. Refused HERE,
        # before any KEK is provisioned or not-provisioned for the wrong
        # mode (the worker refuses it anyway).
        try:
            customer_keys.check_pinned(existing, binding)
        except customer_keys.CustomerKeysError as exc:
            raise LaunchIntentError(str(exc), "conflict") from exc
        # The placement group is fixed when the row is created: a re-POST
        # may omit it (the row's stays), never name another.
        asked = intent.get("placement_group") or ""
        if asked and asked != existing.placement_group:
            raise LaunchIntentError(
                f"vm {existing.vm_id!r} is in placement group "
                f"{existing.placement_group or None!r}; it cannot change",
                "conflict",
            )
    else:
        # Customer-held keys (M1/M2) FIRST launch: the new-launch gates,
        # namely flag on, golden only, and a bake the operator marked
        # capable whose artifacts are exactly the ones launched. BEFORE any
        # Vault write, so a refusal stages nothing.
        try:
            customer_keys.check_new_launch(intent, binding)
        except customer_keys.CustomerKeysError as exc:
            raise LaunchIntentError(str(exc), "bad-field") from exc
    if not customer_keys.releases_kek(binding):
        # M2 (`customer`): Hippius holds NO disk KEK — nothing is generated
        # (no Transit datakey), wrapped or staged. The job still records the
        # canonical path, which the ticket names without a secret behind it.
        if intent.get("kek_vault_path"):
            raise LaunchIntentError(
                "key_mode=customer takes no kek_vault_path (Hippius holds no "
                "disk KEK in customer mode)",
                "bad-field",
            )
        intent["kek_vault_path"] = _canonical_kek_path(intent)
        try:
            customer_keys.assert_no_provider_kek(
                str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret")),
                intent["kek_vault_path"],
            )
        except customer_keys.CustomerKeysError as exc:
            raise LaunchIntentError(str(exc), "conflict") from exc
        except (EffectError, EffectUnavailable) as exc:
            raise LaunchIntentError(f"vault check failed: {exc}", "internal") from exc
    # GOLDEN-BAKE (option b): the golden bake stages no KEK — the per-VM
    # overlay-upper KEK is the launch's own per-VM secret. Provision it
    # server-side as a Transit-WRAPPED KEK the KBS `require_wrapped_kek` gate
    # accepts on release. (Legacy launches get their wrapped KEK from the
    # bake; a caller that supplied its own `kek_vault_path` is respected.)
    # M1 (`split`): exactly this — the staged KEK IS the Hippius share.
    elif (
        intent.get("disk_mode") == _DISK_MODE_GOLDEN_VERITY
        and not intent.get("kek_vault_path")
    ):
        _provision_golden_overlay_kek(intent)
    kek_vault_path = intent.get("kek_vault_path")
    if not isinstance(kek_vault_path, str) or not kek_vault_path.strip():
        raise LaunchIntentError("missing or empty 'kek_vault_path'")
    # A bake (and the `vali_tenant_bake_create --kek-vault-path` CLI
    # convention) stores the KV-v2 DATA path `<mount>/data/…`, but the
    # launch API validation below AND the worker's `vault_kv.get_kv` want
    # the KV-RELATIVE path (`get_kv` prepends `/data/` itself). Strip a
    # leading `<mount>/data/` so launch-by-bake_id — and a caller who
    # copied the CLI form — validate + read the KEK correctly instead of
    # 400-ing on the prefix check or double-`/data/`-ing at read time.
    _kek_data_prefix = f"{getattr(settings, 'VALI_VAULT_KV_MOUNT', 'secret')}/data/"
    if kek_vault_path.startswith(_kek_data_prefix):
        kek_vault_path = kek_vault_path[len(_kek_data_prefix):]
    if len(kek_vault_path) > _MAX_VAULT_PATH:
        raise LaunchIntentError("kek_vault_path too long", "bad-field")

    spec_json = _build_spec_json(intent)

    mount = str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret"))
    prefix = str(getattr(settings, "VALI_VAULT_KV_PREFIX", ""))
    if not prefix:
        raise LaunchIntentError("VALI_VAULT_KV_PREFIX is not configured", "internal")

    # The KEK MUST already be staged at the canonical
    # `{prefix}/{vm_id}/luks-kek` — the exact path the KBS releases from
    # (it derives lifecycle-key by swapping that final segment). Requiring
    # the exact path (not merely "somewhere under `{prefix}/{vm_id}/`")
    # means the worker never has to COPY the KEK into place, so it never
    # reads the plaintext back — a vali/node RCE cannot exfil a tenant disk
    # KEK (C1 / KEK-HSM Phase 1). It also still confines the path to THIS
    # vm's namespace (no cross-tenant key confusion). The operator/bake
    # convention already stages here (`--kek-vault-path …/luks-kek`).
    vm_id = spec_json["vm_id"]
    canonical_kek_path = f"{prefix}/{vm_id}/luks-kek"
    if kek_vault_path != canonical_kek_path:
        raise LaunchIntentError(
            f"kek_vault_path must be exactly {canonical_kek_path!r} "
            "(the canonical luks-kek path the KBS releases from)",
            "bad-field",
        )

    # NetBird template is a pure check — fail fast at POST (the worker
    # applies the same rule).
    nb_err = launch.check_netbird_userdata(
        userdata,
        enable=spec_json["enable_netbird"],
        hostname_template=spec_json["netbird_hostname_template"],
        vm_id=spec_json["vm_id"],
    )
    if nb_err is None:
        nb_err = launch.check_netbird_hostname(
            enable=spec_json["enable_netbird"],
            hostname_template=spec_json["netbird_hostname_template"],
            vm_id=spec_json["vm_id"],
        )
    if nb_err is not None:
        raise LaunchIntentError(nb_err, "bad-field")

    # §20: stage the userdata to a transport path BEFORE the row exists,
    # so the plaintext never touches the DB — and Transit-WRAPPED (under
    # `ud-<vm_id>`, the per-VM key vali may open), so it never touches
    # Vault storage in the clear either. `launch_on_miner` later re-stages
    # it to the canonical `{prefix}/{vm_id}/userdata` under the KBS-only
    # `kek-<vm_id>`; this copy is vali's working copy, retained because
    # reboot-recovery and the §25/recovery re-mint both need the plaintext
    # again (see `launch.stage_userdata_working_copy`).
    # Its OWN path, not the working copy `launch_on_miner` maintains. Two
    # different things live here: this is the TEMPLATE the caller POSTed
    # (NetBird placeholder still in it), read by the worker and by
    # reboot-recovery, which each substitute a fresh setup key. The
    # working copy at `…/userdata-pending` holds the SUBSTITUTED bytes and
    # is written in version lockstep with the canonical copy, which is
    # what lets the §25 re-mint pin the two together. Sharing one path
    # made those versions drift apart by one and the pairing unprovable.
    intake_path = f"{prefix}/{vm_id}/userdata-intake"
    try:
        staged = launch.stage_userdata_intake_copy(
            mount, intake_path, vm_id, userdata
        )
    except (EffectError, EffectUnavailable) as exc:
        raise LaunchIntentError(f"vault stage failed: {exc}", "internal") from exc

    now = timezone.now()
    try:
        with transaction.atomic():
            # Serialize with every writer that decides against this VM's
            # launch record under the Vm row lock (`vali_swap_vm_initrd`):
            # the job this creates becomes that record once it succeeds, so
            # it must either be visible to their decision or come after it.
            # No row yet (a first launch) ⇒ nothing to serialize with.
            _refuse_held(Vm.objects.select_for_update().filter(vm_id=vm_id).first())
            job = LaunchJob.objects.create(
                job_id=secrets.token_hex(16),
                vm_id=vm_id,
                tenant_id=spec_json["tenant_id"],
                flavor=spec_json["flavor"],
                spec_json=spec_json,
                userdata_vault_path=intake_path,
                userdata_vault_version=staged.version,
                kek_vault_path=kek_vault_path,
                state=LaunchJobState.QUEUED.value,
                phase=LaunchPhase.QUEUED.value,
                phase_started_at=now,
                decided_by=decided_by,
            )
    except IntegrityError as exc:
        # Partial unique index: an in-flight launch already exists for
        # this VM.
        raise LaunchIntentError(
            f"vm {vm_id!r} already has an in-flight launch job", "conflict"
        ) from exc
    log.info("launch job queued: job_id=%s vm_id=%s", job.job_id, vm_id)
    return job


# ── worker ───────────────────────────────────────────────────────────


def _set_phase(job: LaunchJob, phase: LaunchPhase) -> None:
    """Advance the observable launch `phase` (+ `phase_started_at`).

    Purely-additive progress instrumentation: it writes ONLY the `phase`
    and `phase_started_at` columns (never `state`/`version`), so it can
    never race or interfere with the CAS state machine in `claim_one` /
    `_finish`. Best-effort + fail-open — a phase-write failure must never
    fail an otherwise-healthy launch.
    """
    try:
        job.phase = phase.value
        job.phase_started_at = timezone.now()
        # Only while `running`: a job the orphan janitor already closed
        # must not grow a live-looking phase afterwards.
        LaunchJob.objects.filter(id=job.id, state=LaunchJobState.RUNNING.value).update(
            phase=job.phase, phase_started_at=job.phase_started_at
        )
    except Exception as exc:  # noqa: BLE001 — instrumentation is non-load-bearing
        log.warning(
            "launch job %s: phase write to %s skipped: %s",
            job.job_id,
            phase.value,
            exc,
        )


def claim_one() -> LaunchJob | None:
    """CAS-claim the oldest `queued` job to `running`. Returns the
    claimed job, or `None` if the queue is empty / the claim was lost to
    a concurrent tick.
    """
    job = (
        LaunchJob.objects.filter(state=LaunchJobState.QUEUED.value)
        .order_by("started_at")
        .first()
    )
    if job is None:
        return None
    updated = LaunchJob.objects.filter(
        id=job.id, version=job.version, state=LaunchJobState.QUEUED.value
    ).update(
        state=LaunchJobState.RUNNING.value,
        version=job.version + 1,
        phase_started_at=timezone.now(),
    )
    if not updated:
        return None
    return LaunchJob.objects.select_related("decided_by").get(id=job.id)


def run_job(job: LaunchJob) -> None:
    """Execute one claimed (`running`) launch job: read the userdata
    working copy back from Vault (and unwrap it), drive `launch_vm`, and
    CAS to a terminal state.

    The KEK is deliberately NOT read here. `start_launch` enforced that
    `kek_vault_path` is the canonical `{prefix}/{vm_id}/luks-kek` the KBS
    releases from, so the KEK is already where it needs to be; `launch_vm`
    only reads its KV VERSION (metadata, non-secret). vali therefore never
    holds a plaintext tenant disk KEK on the async path — a vali/node RCE
    cannot exfil it (C1 / KEK-HSM Phase 1).
    """
    mount = str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret"))
    # `running` = the worker is now staging the secrets it needs before it
    # can drive `launch_vm`. Additive progress marker (see `_set_phase`).
    _set_phase(job, LaunchPhase.STAGING)
    userdata = b""
    try:
        try:
            userdata = launch.open_userdata_intake_copy(
                mount,
                job.userdata_vault_path,
                job.userdata_vault_version,
                job.vm_id,
            )
        except (EffectError, EffectUnavailable) as exc:
            _finish(
                job,
                LaunchJobState.FAILED,
                reason=f"secret-fetch-failed: {exc}",
                result={"ok": False, "outcome": "secret-fetch-failed"},
                phase=LaunchPhase.FAILED,
            )
            return

        spec = launch.LaunchSpec(**job.spec_json, kek_bytes=None, userdata=userdata)
        try:
            # `on_phase` lets the in-process choreography advance the job's
            # progress phase (placing → dispatching) as it moves through the
            # scheduler + dispatch — purely additive, mapped to `LaunchPhase`.
            result = launch.launch_vm(
                spec,
                job.decided_by,
                on_phase=_phase_callback(job),
                queued_for_s=(timezone.now() - job.started_at).total_seconds(),
            )
        except Exception as exc:
            # `launch_vm` can RAISE (e.g. `OrderDispatchUnavailable` when a
            # miner / the Edge is unreachable) rather than return a failed
            # result. Unhandled, that bubbles out of `tick_once` and leaves
            # the job wedged `running` forever — `claim_one` only ever picks
            # `queued`, so it is never retried. Finish it FAILED so the row
            # reaches a terminal state; the upstream re-POSTs to retry (the
            # in-flight unique index frees once the job is no longer
            # queued/running). The `finally` below still zeroizes the secrets.
            log.warning(
                "launch job %s: launch_vm raised %s: %s",
                job.job_id,
                type(exc).__name__,
                exc,
            )
            _finish(
                job,
                LaunchJobState.FAILED,
                reason=f"launch-error: {type(exc).__name__}: {exc}"[:256],
                result={"ok": False, "outcome": "launch-error"},
                phase=LaunchPhase.FAILED,
            )
            return
    finally:
        # §20 — drop our secret buffer (launch_on_miner zeroized its own).
        # The KEK is never read on this path, so there is nothing to zeroize.
        try:
            userdata = b"\x00" * len(userdata)
        except Exception:
            pass

    result_json = {
        "ok": result.ok,
        "outcome": result.outcome,
        "miner_id": result.miner_id,
        "miner_node_id": result.miner_node_id,
        "ticket_id": result.ticket_id,
        "placement_id": result.placement_id,
        "attempts": result.attempts,
        "emit": result.emit,
    }
    if result.ok:
        # The ticket's OrderTicketIntake was written by launch_on_miner
        # at mint time; nothing more to persist here.
        _finish(
            job,
            LaunchJobState.SUCCEEDED,
            reason="",
            result=result_json,
            miner_id=result.miner_id or "",
            placement_id=result.placement_id or "",
            phase=LaunchPhase.LAUNCHED,
        )
    else:
        _finish(
            job,
            LaunchJobState.FAILED,
            reason=result.outcome[:256],
            result=result_json,
            miner_id=result.miner_id or "",
            placement_id=result.placement_id or "",
            phase=LaunchPhase.FAILED,
        )


def _phase_callback(job: LaunchJob):
    """Build the `on_phase` sink handed to `launch_vm`.

    `launch_vm` reports its in-process progress as plain wire strings
    (`"placing"`/`"dispatching"`); map each to a `LaunchPhase` and persist
    it. An unknown/None name is ignored — the callback must never raise
    into the launch path (`_set_phase` is itself fail-open too).
    """

    def _sink(name: str) -> None:
        phase = _PHASE_BY_NAME.get(name)
        if phase is not None:
            _set_phase(job, phase)

    return _sink


# Wire-string → `LaunchPhase`, for the `launch_vm` progress callback.
_PHASE_BY_NAME: dict[str, LaunchPhase] = {p.value: p for p in LaunchPhase}


def _finish(
    job: LaunchJob,
    state: LaunchJobState,
    *,
    reason: str,
    result: dict[str, Any],
    miner_id: str = "",
    placement_id: str = "",
    phase: LaunchPhase,
    expect_phase_started_at: Any = None,
) -> bool:
    """CAS `running → terminal`. A lost CAS (a second tick, or a manual
    intervention) is logged, not raised. Returns whether this call won.
    `expect_phase_started_at` additionally requires the phase the caller
    judged to still be the current one.

    The terminal `phase` (`launched`/`failed`) is written in the SAME CAS
    update as `state`, so the progress field flips atomically with the
    authoritative state — a poller never sees `succeeded`+`dispatching`.
    """
    fence = LaunchJob.objects.filter(
        id=job.id, version=job.version, state=LaunchJobState.RUNNING.value
    )
    if expect_phase_started_at is not None:
        # Phase writes do not bump `version`; this is what fences a caller
        # that judged the job on its phase (the orphan janitor).
        fence = fence.filter(phase_started_at=expect_phase_started_at)
    updated = fence.update(
        state=state.value,
        version=job.version + 1,
        finished_at=timezone.now(),
        reason=reason,
        result_json=result,
        miner_id=miner_id,
        placement_id=placement_id,
        phase=phase.value,
    )
    if not updated:
        log.warning(
            "launch job %s: terminal CAS lost (concurrent transition)",
            job.job_id,
        )
        return False
    else:
        log.info("launch job %s → %s", job.job_id, state.value)
        # #587 Phase 3 — fire a `launch.<state>` webhook (best-effort,
        # fail-open: a webhook must never affect the authoritative job
        # state). We re-read the row so the payload reflects the values
        # the CAS just wrote (miner_id, reason, finished_at).
        try:
            fresh = LaunchJob.objects.get(id=job.id)
            webhook.enqueue_launch_terminal(fresh)
        except Exception as exc:  # noqa: BLE001 — webhook is non-load-bearing
            log.warning("webhook enqueue skipped job=%s: %s", job.job_id, exc)
        return True


def launch_job_orphan_after_s() -> int:
    """Age of a `running` job's current phase past which its worker is
    presumed dead. Measured from `phase_started_at`, which every phase
    change refreshes, so a launch that is still progressing never ages
    out; only the longest SINGLE phase has to fit. That phase is
    `dispatching`: emitted once, then up to `1 + max_dispatch_retries`
    miner preflights of `VALI_PREFLIGHT_TIMEOUT_SECS` each. The bound is
    never below twice that, whatever `VALI_LAUNCH_JOB_ORPHAN_S` says
    (default 3 h — exactly twice the defaults)."""
    from apps.orchestration.services.preflight import DEFAULT_PREFLIGHT_DISPATCH_TIMEOUT_S

    preflight_s = float(
        getattr(settings, "VALI_PREFLIGHT_TIMEOUT_SECS", DEFAULT_PREFLIGHT_DISPATCH_TIMEOUT_S)
    )
    longest_phase_s = (1 + launch.max_dispatch_retries()) * preflight_s
    configured = int(getattr(settings, "VALI_LAUNCH_JOB_ORPHAN_S", 10800))
    return max(configured, int(2 * longest_phase_s))


def launch_job_silent_guest_s() -> int:
    """How long a job dead in `dispatching`, whose VM never got a host,
    must have been silent before vali concludes no guest exists. A guest
    that booted reports `verify-vm-progress` milestones (accepted for a
    VM with no host via its placement) and in-guest frames; 24 h of
    neither is the evidence. Default 24 h."""
    return int(getattr(settings, "VALI_LAUNCH_JOB_SILENT_GUEST_S", 86400))


#: Phases a job reaches BEFORE any dispatch: `launch_vm` records the
#: Pending placement, THEN emits `dispatching`, THEN `launch_on_miner`
#: registers and dispatches.
_PRE_DISPATCH_PHASES: frozenset[str] = frozenset(
    {"", LaunchPhase.QUEUED.value, LaunchPhase.STAGING.value, LaunchPhase.PLACING.value}
)

# Jobs already warned about as unresolvable, so a job vali cannot judge
# is logged once per process, not every 10 s tick.
_orphan_warned: set[str] = set()


def _orphan_verdict(job: LaunchJob, vm: Any) -> tuple[str, str]:
    """`(verdict, why)` for one orphaned job — `verdict` is `succeeded`,
    `failed` or `""` (leave it). See `reap_orphaned_launch_jobs`."""
    from apps.lifecycle.models import VmState
    from apps.miners.models import MinerIdentity
    from apps.scheduler.models import ACTIVE_PLACEMENT_STATES, Placement, PlacementStatus

    if vm is None:
        return "failed", "no-vm-row"
    if vm.state == VmState.DESTROYED.value:
        return "failed", "vm-destroyed"
    if vm.state != VmState.ACTIVE.value:
        return "", f"vm-{vm.state}"
    opened_by_job = Placement.objects.filter(
        vm=vm, status__in=ACTIVE_PLACEMENT_STATES, decided_at__gte=job.started_at
    )
    if job.phase == LaunchPhase.DISPATCHING.value:
        if vm.host:
            # The host must be THIS job's: its own placement names that
            # miner. A host left by an earlier launch (whose placement a
            # drain freed, letting this job place again) proves nothing.
            host_chain = (
                MinerIdentity.objects.filter(miner_id=vm.host)
                .values_list("chain_node_id", flat=True)
                .first()
            )
            ours = opened_by_job.filter(miner_node_id=host_chain) if host_chain else None
            if ours is not None and ours.exists():
                # ...and the host ACCEPTED it: the placement got bound, or
                # the guest has spoken since this job began. A Pending row
                # alone is also what a job that died before the accept
                # leaves on a host an earlier launch stamped.
                if (
                    ours.filter(status=PlacementStatus.BOUND).exists()
                    or (vm.boot_phase_at is not None and vm.boot_phase_at >= job.started_at)
                    or (vm.guest_signal_at is not None and vm.guest_signal_at >= job.started_at)
                ):
                    return "succeeded", "vm-live-on-host"
            return "", "host-not-this-jobs"
        silent_since = timezone.now() - timezone.timedelta(seconds=launch_job_silent_guest_s())
        if job.phase_started_at < silent_since and not vm.boot_phase and vm.guest_signal_at is None:
            return "failed", "no-guest-evidence"
        return "", "dispatched-no-host"
    if job.phase in _PRE_DISPATCH_PHASES:
        # A Pending/Bound placement opened during THIS job means it got as
        # far as the line right before `dispatching` — a failed (fail-open)
        # phase write could hide a dispatch behind it. Not provable.
        if opened_by_job.exists():
            return "", "placement-opened"
        return "failed", "never-dispatched"
    return "", f"phase-{job.phase}"


def reap_orphaned_launch_jobs() -> tuple[int, int]:
    """Resolve every `running` job whose worker died, from the facts.
    Returns `(completed, failed)`.

    `claim_one` only picks `queued`, and a worker that crashes (or is
    killed by a deploy) mid-launch leaves its job `running` for ever: the
    in-flight unique index then refuses any new launch of that `vm_id`, and
    the operator sees a launch that never ends. A job is orphaned once its
    CURRENT phase is older than `launch_job_orphan_after_s`. Then:

    - died in `dispatching`, its VM has a host, the job's OWN placement
      names that host, and that host accepted it (the placement is Bound,
      or the guest reported a boot milestone / in-guest frame since the
      job began) ⇒ `succeeded`;
    - no `Vm` row, or the VM is `destroyed` ⇒ `failed`;
    - died before `dispatching` and opened no placement ⇒ `failed`
      (`never-dispatched`): nothing was registered or dispatched;
    - died in `dispatching` with no host, and in `launch_job_silent_guest_s`
      the VM produced no boot milestone and no in-guest frame ⇒ `failed`
      (`no-guest-evidence`); its Pending placement is released;
    - anything else is LEFT, with one warning: vali cannot tell.

    A `failed` VM row with no host is marked abandoned, which hands it to
    `sweep_abandoned_launches` (and its own live-evidence veto). Released
    placements carry `failure_source=release`: never a refusal, so the
    circuit breaker does not count them.

    Every write is `_finish`'s CAS on `(id, version, state=running)` AND the
    `phase_started_at` the verdict was taken on, so a worker that was only
    slow — and moved on, or finished — wins.
    """
    from apps.lifecycle.models import Vm
    from apps.scheduler.models import (
        Placement,
        PlacementFailureSource,
        PlacementStatus,
    )

    cutoff = timezone.now() - timezone.timedelta(seconds=launch_job_orphan_after_s())
    completed = 0
    failed = 0
    for job in LaunchJob.objects.filter(
        state=LaunchJobState.RUNNING.value, phase_started_at__lt=cutoff
    ).select_related("decided_by"):
        vm = Vm.objects.filter(vm_id=job.vm_id).first()
        verdict, why = _orphan_verdict(job, vm)
        if not verdict:
            if job.job_id not in _orphan_warned:
                _orphan_warned.add(job.job_id)
                log.warning(
                    "launch job %s: worker died in phase=%r (%s) — cannot tell "
                    "whether a guest started, LEAVING it running",
                    job.job_id,
                    job.phase,
                    why,
                )
            continue
        if verdict == "succeeded":
            active = (
                Placement.objects.filter(vm=vm, status__in=["pending", "bound"])
                .values_list("id", flat=True)
                .first()
            )
            if not _finish(
                job,
                LaunchJobState.SUCCEEDED,
                reason="",
                result={"ok": True, "outcome": f"orphan-resolved:{why}"},
                miner_id=vm.host,
                placement_id=str(active or ""),
                phase=LaunchPhase.LAUNCHED,
                expect_phase_started_at=job.phase_started_at,
            ):
                continue
            completed += 1
            log.error(
                "launch job %s: worker died but vm=%s is live on %s — completed",
                job.job_id,
                job.vm_id,
                vm.host,
            )
            continue
        with transaction.atomic():
            if not _finish(
                job,
                LaunchJobState.FAILED,
                reason=f"orphaned:{why}",
                result={"ok": False, "outcome": f"orphaned:{why}"},
                phase=LaunchPhase.FAILED,
                expect_phase_started_at=job.phase_started_at,
            ):
                continue  # the worker moved on or finished first
            if why == "no-guest-evidence":
                Placement.objects.filter(vm=vm, status=PlacementStatus.PENDING).update(
                    status=PlacementStatus.FAILED,
                    version=F("version") + 1,
                    failed_at=timezone.now(),
                    reason="released:orphaned-launch",
                    failure_source=PlacementFailureSource.RELEASE,
                )
            if vm is not None:
                # Filters on host="" + active itself: a bound VM is untouched.
                # A job that died in `dispatching` may or may not have
                # reached the KBS register; the outcome says so rather than
                # let `registered=False` read as "still launchable".
                launch._mark_launch_abandoned(
                    job.vm_id,
                    outcome=(
                        "orphaned-launch-job:register-unknown"
                        if why == "no-guest-evidence"
                        else "orphaned-launch-job"
                    ),
                    registered=False,
                )
        failed += 1
        log.error(
            "launch job %s: worker died, vm=%s %s — failed",
            job.job_id,
            job.vm_id,
            why,
        )
    return completed, failed


def tick_once() -> bool:
    """Claim + run at most one queued job. Returns True if one ran."""
    job = claim_one()
    if job is None:
        return False
    run_job(job)
    return True
