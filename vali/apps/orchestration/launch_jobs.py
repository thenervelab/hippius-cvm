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
from django.utils import timezone

from apps.identity import scoping
from apps.orchestration import webhook
from apps.orchestration.effects import EffectError, EffectUnavailable
from apps.orchestration.models import LaunchJob, LaunchJobState, LaunchPhase
from apps.orchestration.services import flavors, launch, vault_kv

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
}


class LaunchIntentError(Exception):
    """A `POST /v1/vm/launch` body failed validation. `category` maps to
    an HTTP status in the view (`wire`/`bad-field` → 400, `conflict` →
    409, `internal` → 503)."""

    def __init__(self, message: str, category: str = "wire") -> None:
        super().__init__(message)
        self.message = message
        self.category = category


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
    if not _VM_ID_RE.match(spec["vm_id"]):
        raise LaunchIntentError(
            "vm_id must match [a-z0-9-]{1,64} (no path separators)", "bad-field"
        )
    if spec["flavor"] not in flavors.FLAVOR_NAMES:
        raise LaunchIntentError(
            f"flavor must be one of: {', '.join(flavors.FLAVOR_NAMES)}",
            "bad-field",
        )
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
    return spec


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
    # Map the tenant-supplied NAME to the operator-blessed golden bake. The
    # existing `_resolve_bake` path below re-validates the bake is Succeeded.
    intent["bake_id"] = golden.bake_id
    # Keep the NAME too (P9/#16): `image_name` + `bake_id` together are what
    # an operator needs to tell a VM booting a stale base from one on the
    # current blessed image. Set from the OPERATOR-blessed lookup, not from
    # a free-form caller field, so it cannot be spoofed away from the bake
    # it actually resolved to.
    intent["image_name"] = image


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
    _resolve_image(intent)
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
    for key, val in resolved.items():
        if val and not intent.get(key):
            intent[key] = val


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
    vm_id = intent.get("vm_id")
    # vm_id is interpolated into a Vault WRITE path — charset-lock it BEFORE
    # interpolation (defeats `../` traversal out of the per-VM namespace).
    # `_build_spec_json` re-checks it; this earlier check guards the write.
    if not isinstance(vm_id, str) or not _VM_ID_RE.match(vm_id):
        raise LaunchIntentError(
            "vm_id must match [a-z0-9-]{1,64} (no path separators)", "bad-field"
        )
    mount = str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret"))
    prefix = str(getattr(settings, "VALI_VAULT_KV_PREFIX", ""))
    if not prefix:
        raise LaunchIntentError("VALI_VAULT_KV_PREFIX is not configured", "internal")
    luks_path = f"{prefix}/{vm_id}/luks-kek"
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


def start_launch(*, intent: dict[str, Any], userdata: bytes, decided_by: Any) -> LaunchJob:
    """Validate the intent, stage `userdata` to Vault, and enqueue a
    `LaunchJob`. The KEK is NOT staged here — `intent['kek_vault_path']`
    names where the worker reads it (the bake's path).

    Raises [`LaunchIntentError`] on a bad body / an in-flight launch for
    the same VM / a Vault failure.
    """
    if not userdata:
        raise LaunchIntentError("userdata must be non-empty", "bad-field")
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
    _resolve_bake(intent)
    # GOLDEN-BAKE (option b): the golden bake stages no KEK — the per-VM
    # overlay-upper KEK is the launch's own per-VM secret. Provision it
    # server-side as a Transit-WRAPPED KEK the KBS `require_wrapped_kek` gate
    # accepts on release. (Legacy launches get their wrapped KEK from the
    # bake; a caller that supplied its own `kek_vault_path` is respected.)
    if (
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
    if nb_err is not None:
        raise LaunchIntentError(nb_err, "bad-field")

    # §20: stage the userdata to a transport path BEFORE the row exists,
    # so the plaintext never touches the DB. `launch_on_miner` later
    # re-stages it to the canonical `{prefix}/{vm_id}/userdata` that the
    # minted ticket binds; this copy is transport only.
    pending_path = f"{prefix}/{vm_id}/userdata-pending"
    try:
        staged = vault_kv.put_kv(mount, pending_path, userdata)
    except (EffectError, EffectUnavailable) as exc:
        raise LaunchIntentError(f"vault stage failed: {exc}", "internal") from exc

    now = timezone.now()
    try:
        with transaction.atomic():
            job = LaunchJob.objects.create(
                job_id=secrets.token_hex(16),
                vm_id=vm_id,
                tenant_id=spec_json["tenant_id"],
                flavor=spec_json["flavor"],
                spec_json=spec_json,
                userdata_vault_path=pending_path,
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
        job.save(update_fields=["phase", "phase_started_at"])
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
    """Execute one claimed (`running`) launch job: read the userdata back
    from Vault, drive `launch_vm`, and CAS to a terminal state.

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
            userdata = vault_kv.get_kv(
                mount, job.userdata_vault_path, version=job.userdata_vault_version
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
                spec, job.decided_by, on_phase=_phase_callback(job)
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
        # OrderTicketIntake persistence is intentionally deferred: the
        # KBS already holds the ticket (launch_on_miner registered it),
        # and the scheduler's anti-affinity reads Placement.vm_family —
        # not the intake row — so the launch is complete without it.
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
) -> None:
    """CAS `running → terminal`. A lost CAS (a second tick, or a manual
    intervention) is logged, not raised.

    The terminal `phase` (`launched`/`failed`) is written in the SAME CAS
    update as `state`, so the progress field flips atomically with the
    authoritative state — a poller never sees `succeeded`+`dispatching`.
    """
    updated = LaunchJob.objects.filter(
        id=job.id, version=job.version, state=LaunchJobState.RUNNING.value
    ).update(
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


def tick_once() -> bool:
    """Claim + run at most one queued job. Returns True if one ran."""
    job = claim_one()
    if job is None:
        return False
    run_job(job)
    return True
