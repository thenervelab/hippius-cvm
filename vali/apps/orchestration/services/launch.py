"""`launch_on_miner` / `launch_vm` — the BYO base-OS launch choreography
as a reusable service.

This is the choreography `vali_create_vm` used to run inline, lifted out
so two callers share ONE code path:

- the **CLI** (`vali_create_vm`) calls [`launch_on_miner`] directly with
  an operator-named miner — byte-identical behaviour to before (no
  scheduler, no `Placement`, no `Vm` row);
- the **launch pipeline** ([`launch_vm`]) wraps [`launch_on_miner`] in the
  §23 scheduler loop: it picks the miner, records a `Placement`, and
  re-places onto another miner when one rejects.

[`launch_on_miner`] performs, for ONE given miner identity:

    1.  (optional) NetBird setup-key enrolment + userdata substitution
    2.  Vault stage (LUKS KEK + cloud-init userdata)
    3.  `allowed_userdata_digest_hex`
    4.  cmdline augmentation (#296 luks-header-sha, rootfs-sha, #365 disk_gb)
    5.  preflight order → miner-side artefact fetch + SNP launch_digest
    6.  (optional) §22 allowlist auto-pin
    7.  L1 OrderTicket mint (node_id = the miner's human `miner_id`)
    8.  kbs-admin register-vm
    9.  build + dispatch the launch order

and returns a typed [`LaunchOutcome`]: the CLI reads `.emit` + `.exit_code`
(so its stdout JSON + exit code are unchanged); the scheduler reads
`.disposition` to decide bind / re-place / stop.

§20: the KEK + userdata plaintext buffers handed in via [`LaunchSpec`] are
zeroized here as soon as they reach Vault / the digest. The caller still
owns its own copy and should drop it too.
"""

from __future__ import annotations

import logging
import re
import secrets
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from django.conf import settings

from apps.miners.models import MinerIdentity
from apps.orchestration import effects, kbs_admin, order_dispatch
from apps.orchestration.effects import EffectError, EffectUnavailable
from apps.orchestration.models import MeasurementLedger
from apps.orchestration.services import (
    allowlist_pin,
    lifecycle_keygen,
    telemetry_keygen,
    ticket_mint,
    userdata_digest,
    vault_kv,
)
from apps.orchestration.services import (
    launch_digest as launch_digest_svc,
)
from apps.orchestration.services import (
    preflight as preflight_svc,
)

log = logging.getLogger("apps.orchestration.launch")

# ── Exit / outcome codes ─────────────────────────────────────────────
# Owned here (the launch domain) so the CLI and any future caller map a
# failure to the SAME code. Mirror `vali_dispatch_launch`.
EXIT_OK = 0
EXIT_MINER_REJECTED = 2
EXIT_EDGE_FAILURE = 3
EXIT_KBS_ADMIN_FAILURE = 4
EXIT_VAULT_FAILURE = 5
EXIT_ALLOWLIST_FAILURE = 6
EXIT_MINT_FAILURE = 7
EXIT_CONFIG_ERROR = 8
EXIT_PREFLIGHT_FAILURE = 9
EXIT_NETBIRD_FAILURE = 10  # #306
EXIT_MEASUREMENT_MISMATCH = 11  # C2 — miner digest != vali recompute

# `LaunchOutcome.disposition` values.
ACCEPTED = "accepted"  # miner took the launch order (2xx)
RETRIABLE = "retriable"  # preflight reject OR miner 4xx → scheduler re-places
TERMINAL = "terminal"  # vault / mint / kbs / edge-transport / config error

# vm_id is interpolated into Vault KV paths — charset-lock it (no `../`).
# Mirrors `apps.orchestration.launch_jobs._VM_ID_RE` + tenant_bake.
_VM_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")

# ── cmdline token keys (kept in sync with the keyscript parser) ──────
_LUKS_HEADER_CMDLINE_KEY = "hippius.luks_header_sha256"
_ROOTFS_SHA_CMDLINE_KEY = "hippius.rootfs_sha256"
_DISK_GB_CMDLINE_KEY = "hippius.disk_gb"

# ── golden-bake disk modes + the dm-verity root-hash cmdline token ───
# `disk_mode` selects how the boot disk's integrity is anchored into the
# MEASURED cmdline:
#   - `legacy_luks` (default) — the per-VM LUKS2+integrity vda; the guest
#     keyscript unlocks it with the KBS-released KEK and asserts the
#     header MAC via `hippius.luks_header_sha256` (byte-identical to the
#     pre-golden behaviour).
#   - `golden_verity_overlay` — the shared read-only dm-verity GOLDEN base
#     (rootfs.img + rootfs.verity). The base is an UNKEYED Merkle tree, NOT
#     LUKS, so the LUKS-header token is DROPPED and the verity root hash is
#     bound instead. `dm-verity.root=<64-hex>` is the EXACT token the guest
#     reads (`agent-initramfs::stages::verity::CMDLINE_VERITY_ROOT_KEY`);
#     the guest derives salt/uuid/hash-alg/block-sizes from the on-disk
#     verity superblock (`crypt_load(CRYPT_VERITY)`), so ONLY the root hash
#     travels on the cmdline. Per-VM authz is UNCHANGED (the KBS ticket +
#     per-VM nonces); the now-shared golden measurement does not weaken it.
_DISK_MODE_LEGACY_LUKS = "legacy_luks"
_DISK_MODE_GOLDEN_VERITY = "golden_verity_overlay"
_VERITY_ROOT_CMDLINE_KEY = "dm-verity.root"
# initramfs-tools boot-script selector (golden-bake PR3). In golden mode
# the guest's `/init` sources `/scripts/hippius-golden` (installed by the
# golden bake hook) instead of the stock `/scripts/local` crypttab→ext4
# path, so it can OWN root assembly (dm-verity lower + per-VM guest-keyed
# overlay upper). MEASURED like every other token, so a miner cannot flip
# it. Legacy mode never carries it (`/scripts/local` byte-identical).
_BOOT_SELECTOR_CMDLINE_KEY = "boot"
_GOLDEN_BOOT_SELECTOR = "hippius-golden"
# The dm-verity SHA-256 root hash is exactly 32 bytes = 64 lowercase hex
# chars — the guest's `resolve_verity_root_hash_from` rejects anything
# else (`cat::ROOT_HEX`), so vali fails closed on the same shape.
_VERITY_ROOT_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

# §23 — served-receipt telemetry inputs the guest's tenant-telemetry
# agent (`hippius-agent-tenant-telemetry`) resolves from the MEASURED
# cmdline to BUILD + sign each `ServedDeliveryReceipt`. All three are
# measured ⇒ the allowlist auto-pins them at launch; none is a secret.
#   - `hippius.node_id`        the miner's 64-hex §23 compute node_id —
#                              vali keys the `UsageAccrual` ledger + the
#                              owed readout by `hex(receipt.node_id)`, so
#                              the guest emits the RAW identity bytes.
#   - `hippius.resource_class` the flavor tier the VM serves at; vali's
#                              meter maps it to `resource_units`.
#   - `hippius.family_id`      the tenant family (hex) — carried in the
#                              signed receipt (billing does not key on it).
_NODE_ID_CMDLINE_KEY = "hippius.node_id"
_RESOURCE_CLASS_CMDLINE_KEY = "hippius.resource_class"
_FAMILY_ID_CMDLINE_KEY = "hippius.family_id"

# §23 — the validator challenge the guest binds each receipt to. The
# tenant-telemetry agent's receipt loop only builds a receipt when a
# challenge is present (`Config::resolve_challenge` — all three tokens or
# none); with none it idles and emits NOTHING. vali does NOT validate the
# nonce for freshness on ingest (the verifier checks only the guest
# Ed25519 signature), so a launch-baked STATIC challenge is sufficient to
# activate billing. All three are measured ⇒ auto-pinned; none is a secret.
#   - `hippius.validator_id`      this validator's identity (hex bytes).
#   - `hippius.validator_nonce`   32-byte anti-replay nonce (hex); per-launch.
#   - `hippius.telemetry_epoch`   the billing epoch the receipts accrue to.
# NOTE (follow-up): the epoch is fixed for the VM's life here, so a VM that
# outlives its launch epoch keeps accruing to the OLD epoch. Live-epoch
# tracking needs the Edge-pulled challenge refresh (the PR-E2.3 refinement)
# or ingest-time epoch stamping in the meter — tracked separately.
_VALIDATOR_ID_CMDLINE_KEY = "hippius.validator_id"
_VALIDATOR_NONCE_CMDLINE_KEY = "hippius.validator_nonce"
_TELEMETRY_EPOCH_CMDLINE_KEY = "hippius.telemetry_epoch"

# This validator's telemetry-challenge identity (hex bytes). Overridable
# via settings; the default is a stable non-secret marker. The guest binds
# each receipt to it; vali does not gate accrual on the value.
_DEFAULT_VALIDATOR_ID_HEX = "686970706975732d76616c692d7631"  # "hippius-vali-v1"


def _current_billing_epoch() -> int:
    """Best-effort current billing epoch from the DB-cached on-chain
    `CurrentEpoch` (`MinerCapacity.observed_epoch`) — no network call in the
    launch hot path. Falls back to the newest usage-ledger epoch, then 0.
    """
    from django.db.models import Max

    from apps.scheduler.models import MinerCapacity
    from apps.scheduler.scoring import latest_usage_epoch

    epoch = MinerCapacity.objects.aggregate(m=Max("observed_epoch"))["m"]
    if epoch is None:
        epoch = latest_usage_epoch()
    return int(epoch or 0)
# §24/§25 — the single-use EOL nonce the guest signs into its
# `StoppedAck` on a clean shutdown. Baked into the MEASURED cmdline at
# launch so the guest reads it from `/proc/cmdline`
# (`agent-initramfs::main::eol_push_inputs`) and vali stores the SAME
# value on `Vm.eol_nonce` for `_verify_ack`. The token is measured →
# the allowlist auto-pins it at launch (the value is per-launch, NOT a
# secret the attacker benefits from learning — the GENERATION is the
# replay guard).
_EOL_NONCE_CMDLINE_KEY = "hippius.eol_nonce"

# §7 — the TMPFS path the guest writes its released lifecycle SIGNING
# key to AND the measured `eol` signer reads it from. Baked into the
# MEASURED cmdline at launch (measured → allowlist auto-pins it; the
# PATH is not a secret, the KEY is — released only over the §21 attested
# channel). The `hippius-guest-release` keyscript materialises the key
# here via `--lifecycle-key-out`; `agent-initramfs eol` reads
# `hippius.lifecycle_key_path` from `/proc/cmdline`. `/run` is tmpfs in
# the guest, so the key NEVER lands on the miner-backed encrypted disk.
_LIFECYCLE_KEY_PATH_CMDLINE_KEY = "hippius.lifecycle_key_path"
_LIFECYCLE_KEY_TMPFS_PATH = "/run/hippius/lifecycle.key"

# §24/§25 — the identity + vali-reach tokens the guest's `eol` signer
# resolves from `/proc/cmdline` (`agent-initramfs::main::eol_push_inputs`)
# to sign + DELIVER its `stopped{}` ack. All measured ⇒ the allowlist
# auto-pins them at launch (none is a secret — the GENERATION is the
# replay guard, and the vali reach is a vsock authority, not a route).
#
# - `hippius.vm_id` / `hippius.lease_id` bind the ack to this VM + lease.
# - `hippius.vm_generation` is the generation the guest signs at; vali's
#   `_verify_ack` checks the ack at `source_gen` (== the source VM's live
#   generation), which equals this baked value for the source guest's
#   whole life (the same baked image is never re-measured at a new gen).
# - `hippius.vali_url` is where the guest POSTs the ack. The confidential
#   guest has NO IP route to vali, so the DEFAULT is the host vsock proxy
#   authority (`vsock://2:<port>`) — the SAME relay the KBS exchange uses;
#   the miner-agent forwards the opaque ack to vali's
#   `/v1/lifecycle/stopped` ingress. An operator may pre-bake an https
#   `hippius.vali_url=` only where a direct route exists.
_VM_ID_CMDLINE_KEY = "hippius.vm_id"
_LEASE_ID_CMDLINE_KEY = "hippius.lease_id"
_VM_GENERATION_CMDLINE_KEY = "hippius.vm_generation"
_VALI_URL_CMDLINE_KEY = "hippius.vali_url"
# Where the guest's §21 release stage fetches its KEK. Like `vali_url`, the
# confidential guest has NO IP route, so this is the host vsock-proxy
# authority the miner-agent listens on — the SAME proxy and port, routed by
# path (`hippius_types::kbs_vsock`).
#
# This used to be caller-supplied ONLY. vali baked vm_id / lease_id /
# generation / vali_url and left the KBS reach to whatever the caller put in
# `cmdline`, which meant a launch through the public API — where the caller
# has no way to know this token exists — produced a guest with no KBS
# endpoint. It could never fetch its KEK, never unlock, never open its vsock
# listener; the only symptom was `ticket-delivery/connect-timeout` eight
# minutes later, from a domain that libvirt reports as running and that
# burns a core in the retry loop. Observed live on 2026-08-18 on two
# different miners. The synthetic monitor never caught it because its
# `VALI_SYNTHETIC_CMDLINE` happens to carry the token.
#
# A boot input the guest CANNOT boot without is vali's to bake, not the
# caller's to remember.
_KBS_URL_CMDLINE_KEY = "hippius.kbs_url"

# The generation a fresh launch bakes — matches `_ensure_vm_row`'s `1`.
_LAUNCH_GENERATION = 1

# Default vali reach baked when the operator pre-bakes none: the host
# vsock proxy authority the miner-agent listens on. The PORT mirrors the
# KBS-over-vsock proxy port (`hippius_types::kbs_vsock::PORT` = 0x4B42 =
# 19266) — the stopped-ack rides the SAME proxy, routed by path. The CID
# is the well-known host CID (2 = `VMADDR_CID_HOST`). Overridable via the
# `VALI_GUEST_VSOCK_URL` setting for a non-default port.
_DEFAULT_VALI_VSOCK_URL = "vsock://2:19266"


def _augment_cmdline_with_token(cmdline: str, key: str, value: str) -> str:
    """Append `<key>=<value>` to `cmdline` iff `<key>=` is absent.

    Idempotent + byte-stable (the launch_digest covers the cmdline
    bytes): an operator-supplied token is left untouched, a missing one
    is appended after a single space.
    """
    needle = f"{key}="
    if needle in cmdline:
        return cmdline
    return f"{cmdline.rstrip()} {key}={value}"


def _augment_disk_binding(cmdline: str, spec: LaunchSpec) -> str:
    """Bind the boot disk's integrity anchor into the MEASURED cmdline,
    gated on `spec.disk_mode`.

    - `legacy_luks` (default): append `hippius.luks_header_sha256=<hex>` —
      byte-identical to the pre-golden behaviour (the guest keyscript
      asserts the per-VM LUKS header MAC before unlocking with the KEK).
    - `golden_verity_overlay`: the shared golden base is an UNKEYED
      dm-verity volume, NOT LUKS, so DROP the LUKS-header token and append
      `dm-verity.root=<64-hex>` — the exact token the guest's §21 verity
      stage reads (`CMDLINE_VERITY_ROOT_KEY`). The guest reads
      salt/uuid/hash-alg/block-sizes from the on-disk verity superblock, so
      only the root hash rides the cmdline.

    Idempotent + byte-stable via `_augment_cmdline_with_token`: an
    operator-baked token is left untouched. Raises `LaunchConfigError`
    (caller-fixable) on an unknown mode or a malformed golden root hash —
    the guest rejects a non-64-lower-hex root, so vali fails closed too.
    """
    if spec.disk_mode == _DISK_MODE_GOLDEN_VERITY:
        if not _VERITY_ROOT_HEX_RE.match(spec.verity_root_hash_hex):
            raise LaunchConfigError(
                "disk_mode=golden_verity_overlay requires verity_root_hash_hex "
                "to be 64 lowercase hex chars (the dm-verity root hash the "
                "golden bake emitted)"
            )
        # Golden base is not LUKS — the luks_header token is intentionally
        # NOT appended; the verity root hash is the integrity binding.
        cmdline = _augment_cmdline_with_token(
            cmdline, _VERITY_ROOT_CMDLINE_KEY, spec.verity_root_hash_hex
        )
        # Select the golden initramfs boot script so the guest owns root
        # assembly (dm-verity lower + per-VM guest-keyed overlay upper).
        return _augment_cmdline_with_token(
            cmdline, _BOOT_SELECTOR_CMDLINE_KEY, _GOLDEN_BOOT_SELECTOR
        )
    if spec.disk_mode != _DISK_MODE_LEGACY_LUKS:
        raise LaunchConfigError(
            f"unknown disk_mode {spec.disk_mode!r} (expected "
            f"{_DISK_MODE_LEGACY_LUKS!r} or {_DISK_MODE_GOLDEN_VERITY!r})"
        )
    return _augment_cmdline_with_token(
        cmdline, _LUKS_HEADER_CMDLINE_KEY, spec.luks_header_sha256_hex
    )


def _select_preflight_artifacts(spec: LaunchSpec) -> Any:
    """Choose the boot-disk artifact set the miner fetches, gated on
    `spec.disk_mode` (golden-bake PR4).

    - `legacy_luks` (default): `luks_disk` = the per-VM `tenant.qcow2`;
      NO `rootfs_hash`. Byte-shape-identical to the pre-golden path.
    - `golden_verity_overlay`: there is NO per-VM qcow2 — `luks_disk` =
      the SHARED golden `rootfs.img` and `rootfs_hash` = the golden
      `rootfs.verity`, each keyed by its bake SHA so the miner's
      content-addressed cache (#823) HITs on a same-distro relaunch. The
      per-VM overlay-upper vda is NOT fetched; the miner derives + creates
      it blank. Fail-closed (caller-fixable) if the golden SHAs are absent
      or malformed — the same discipline as the golden root-hash check.

    kernel + initrd are staged identically in both modes.
    """
    prefix = spec.s3_key_prefix.rstrip("/")
    kernel_art = preflight_svc.S3Artifact(
        bucket=spec.s3_bucket,
        key=prefix + "/tenant.vmlinuz",
        sha256_hex=spec.kernel_sha256_hex,
    )
    initrd_art = preflight_svc.S3Artifact(
        bucket=spec.s3_bucket,
        key=prefix + "/tenant.initrd.img",
        sha256_hex=spec.initrd_sha256_hex,
    )
    if spec.disk_mode == _DISK_MODE_GOLDEN_VERITY:
        if not (
            _VERITY_ROOT_HEX_RE.match(spec.rootfs_img_sha256_hex or "")
            and _VERITY_ROOT_HEX_RE.match(spec.rootfs_verity_sha256_hex or "")
        ):
            raise ValueError(
                "golden_verity_overlay requires 64-hex rootfs_img_sha256_hex + "
                "rootfs_verity_sha256_hex (from the golden bake's measurement.json)"
            )
        return preflight_svc.PreflightArtifacts(
            luks_disk=preflight_svc.S3Artifact(
                bucket=spec.s3_bucket,
                key=prefix + "/rootfs.img",
                sha256_hex=spec.rootfs_img_sha256_hex,
            ),
            kernel=kernel_art,
            initrd=initrd_art,
            rootfs_hash=preflight_svc.S3Artifact(
                bucket=spec.s3_bucket,
                key=prefix + "/rootfs.verity",
                sha256_hex=spec.rootfs_verity_sha256_hex,
            ),
        )
    return preflight_svc.PreflightArtifacts(
        luks_disk=preflight_svc.S3Artifact(
            bucket=spec.s3_bucket,
            key=prefix + "/tenant.qcow2",
            sha256_hex=spec.luks_disk_sha256_hex,
        ),
        kernel=kernel_art,
        initrd=initrd_art,
    )


def _extract_cmdline_token(cmdline: str, key: str) -> str | None:
    """Return the value of the `<key>=<value>` token in `cmdline`, or
    `None` if absent. Whitespace-delimited, first match wins — mirrors
    the guest's `/proc/cmdline` token parser
    (`agent-initramfs::main::resolve_value`).
    """
    prefix = f"{key}="
    for tok in cmdline.split():
        if tok.startswith(prefix):
            return tok[len(prefix):]
    return None


def _resolve_vali_url(spec_cmdline: str) -> str:
    """Resolve the `hippius.vali_url` the guest POSTs its stopped-ack to.

    An operator-baked `hippius.vali_url=` token in the launch cmdline wins
    (already measured); else the `VALI_GUEST_VSOCK_URL` setting; else the
    built-in vsock-proxy default. The guest has NO IP route to vali, so the
    default is a `vsock://` authority — the miner-agent forwards the opaque
    ack to vali's `/v1/lifecycle/stopped` ingress over its own network.
    """
    return (
        _extract_cmdline_token(spec_cmdline, _VALI_URL_CMDLINE_KEY)
        or str(getattr(settings, "VALI_GUEST_VSOCK_URL", _DEFAULT_VALI_VSOCK_URL))
    )


def _resolve_kbs_url(spec_cmdline: str) -> str:
    """Resolve the `hippius.kbs_url` the guest fetches its KEK from.

    Same precedence as [`_resolve_vali_url`]: an operator-baked token wins
    (it is already measured), else the setting, else the vsock-proxy
    default. Both endpoints are the same miner-agent proxy authority — the
    KBS release and the stopped-ack ride it together, routed by path — so
    resolving them from one setting keeps them from disagreeing.
    """
    return (
        _extract_cmdline_token(spec_cmdline, _KBS_URL_CMDLINE_KEY)
        or str(getattr(settings, "VALI_GUEST_VSOCK_URL", _DEFAULT_VALI_VSOCK_URL))
    )


def _augment_eol_delivery_inputs(
    cmdline: str, *, vm_id: str, lease_id: str
) -> str:
    """Bake the §24/§25 stopped-ack delivery inputs into the MEASURED
    cmdline: `hippius.vm_id` / `hippius.lease_id` / `hippius.vm_generation`
    / `hippius.vali_url`.

    All four are measured ⇒ the allowlist auto-pins them at launch (none is
    a secret — the GENERATION is the replay guard, and the vali reach is a
    vsock authority, not a route). Each append is idempotent: an
    operator-baked token in `cmdline` is left untouched.

    `vm_generation` is the launch generation (`_LAUNCH_GENERATION` == the
    `_ensure_vm_row` default of 1). The guest signs at this generation; the
    source guest is never re-measured at a new generation in its lifetime,
    so vali's `_verify_ack` at `source_gen` matches the baked value.
    """
    cmdline = _augment_cmdline_with_token(cmdline, _VM_ID_CMDLINE_KEY, vm_id)
    cmdline = _augment_cmdline_with_token(cmdline, _LEASE_ID_CMDLINE_KEY, lease_id)
    cmdline = _augment_cmdline_with_token(
        cmdline, _VM_GENERATION_CMDLINE_KEY, str(_LAUNCH_GENERATION)
    )
    cmdline = _augment_cmdline_with_token(
        cmdline, _VALI_URL_CMDLINE_KEY, _resolve_vali_url(cmdline)
    )
    # The KBS reach, baked for the same reason and by the same rule. Without
    # it the guest cannot obtain its KEK, so it never unlocks and never
    # reaches the point of accepting a ticket — see `_KBS_URL_CMDLINE_KEY`.
    cmdline = _augment_cmdline_with_token(
        cmdline, _KBS_URL_CMDLINE_KEY, _resolve_kbs_url(cmdline)
    )
    return cmdline


@dataclass(frozen=True)
class LaunchSpec:
    """The full launch intent — everything the choreography needs that is
    NOT derived from the chosen miner.

    `platform_id` is OPTIONAL: when empty, [`launch_on_miner`] uses the
    chosen miner's registered `platform_id` (the launch-pipeline path);
    the CLI pins it explicitly (operator-supplied) for byte-identical
    behaviour. `kek_bytes` / `userdata` are secret-bearing — the caller
    zeroizes its own copy; this module zeroizes the ones it stages.
    """

    # identity
    tenant_id: str
    user_id: str
    vm_id: str
    lease_id: str
    # artefacts (S3) + their SHAs
    s3_bucket: str
    s3_key_prefix: str
    luks_disk_sha256_hex: str
    kernel_sha256_hex: str
    initrd_sha256_hex: str
    luks_header_sha256_hex: str
    # launch knobs
    flavor: str
    cmdline: str
    # secrets (caller-owned; zeroized once staged)
    #
    # `kek_bytes` is None on the ASYNC launch path: there the KEK is
    # ALREADY staged at the canonical `{prefix}/{vm_id}/luks-kek` (the
    # launch API enforces `kek_vault_path == luks_path`), so `launch_vm`
    # reads ONLY the KV version (metadata, non-secret) and never the
    # plaintext KEK — a compromised vali cannot exfil the disk key (C1 /
    # KEK-HSM Phase 1). The SYNC/CLI path generates the KEK in-process and
    # passes the bytes here for `launch_vm` to stage.
    kek_bytes: bytes | None
    userdata: bytes
    # optional / defaulted
    platform_id: str = ""  # empty ⇒ use miner.platform_id
    ticket_id: str = ""  # empty ⇒ fresh `tk-<vm>-<rand8>`
    order_id: str = ""  # empty ⇒ fresh `ord-<vm>-<rand8>`
    # §24/§25 EOL nonce (64-char hex of 32 bytes) the guest signs into
    # its StoppedAck. Empty ⇒ `launch_on_miner` mints a fresh per-launch
    # value. When the operator pre-bakes `hippius.eol_nonce=` into the
    # cmdline, that token wins and is reflected back onto `Vm.eol_nonce`
    # — the two are ALWAYS kept in lockstep so `_verify_ack` matches.
    eol_nonce_hex: str = ""
    rootfs_sha256_hex: str = ""
    # golden-bake (option b): `disk_mode` selects the boot-disk integrity
    # anchor folded into the MEASURED cmdline. Default keeps the legacy
    # per-VM LUKS vda path byte-identical. `golden_verity_overlay` binds
    # the shared read-only dm-verity golden base's root hash instead (see
    # `_augment_disk_binding`). `verity_root_hash_hex` is the 64-hex
    # dm-verity root the bake emitted (`golden-*.measurement.json`
    # `verity_root_hash`); required + validated ONLY in golden mode.
    disk_mode: str = _DISK_MODE_LEGACY_LUKS
    verity_root_hash_hex: str = ""
    # golden-bake PR4: the SHARED golden base artifact SHAs. In
    # `golden_verity_overlay` mode there is NO per-VM `tenant.qcow2` — the
    # miner fetches the golden `rootfs.img` (`rootfs_img_sha256_hex`) +
    # `rootfs.verity` (`rootfs_verity_sha256_hex`) by sha through its
    # content-addressed cache (#823). Both come from the golden bake's
    # `golden-*.measurement.json` (`rootfs_img_sha256` / `rootfs_verity_sha256`).
    # Required + validated ONLY in golden mode; empty on the legacy path.
    rootfs_img_sha256_hex: str = ""
    rootfs_verity_sha256_hex: str = ""
    measurement_hex: str = ""  # empty ⇒ preflight-computed
    auto_pin_allowlist: bool = False
    enable_netbird: bool = True
    netbird_group: str = "vms"
    netbird_key_ttl_seconds: int = 3600
    netbird_hostname_template: str = "hippius-tenant-{vm_id}"
    ovmf_path: str = "/var/lib/hippius-miner/ovmf.fd"
    # ⚠️ SHARED, MUTABLE paths — used ONLY on the LEGACY disk path, where
    # the rootfs really is an operator-pre-staged file the miner never
    # fetches. A `golden_verity_overlay` launch resolves its base from the
    # miner's per-VM staging reply and REFUSES to fall back to these (see
    # `_assert_per_vm_base`): one path cannot name two miners' different
    # bytes, and staging onto it replaces whatever else is booting it.
    rootfs_data_path: str = "/var/lib/hippius-miner/rootfs.img"
    rootfs_hash_path: str = "/var/lib/hippius-miner/rootfs.verity"
    # The named base this launch resolved (`image=ubuntu` → the blessed
    # golden `bake_id`). Recorded on `VmBaseImage`; inert for the launch.
    bake_id: str = ""
    image_name: str = ""
    kid: str = "l1-order-ticket-v1"
    expiry_seconds: int = 86400
    # Tenant price ceiling (USD per resource-unit ×1e6); None ⇒ no ceiling
    # (the VM is never migrated on a miner price change). Persisted on the
    # `Vm` row at creation; consumed by the §3.2 price-watch.
    max_price_per_unit: int | None = None


@dataclass
class LaunchOutcome:
    """The result of one [`launch_on_miner`] attempt.

    - `disposition` — `ACCEPTED` | `RETRIABLE` | `TERMINAL`. The scheduler
      keys off this: ACCEPTED → bind, RETRIABLE → re-place, TERMINAL → stop.
    - `emit` — the JSON object the CLI prints (identical to the old
      `vali_create_vm` stdout).
    - `exit_code` — the CLI's `sys.exit` code.
    - `cose_ticket` / `ticket_id` — set on ACCEPTED so the scheduler can
      persist the `OrderTicketIntake` + record the bind.
    """

    disposition: str
    emit: dict[str, Any]
    exit_code: int
    cose_ticket: bytes | None = None
    ticket_id: str | None = None
    # True once the §24 KBS `register-vm` (step 8) has bound this vm_id to
    # THIS miner's host — set on EVERY outcome produced at or after that
    # register, terminal ones included (`_terminal_after_register`). Two
    # consumers, reading it for different reasons:
    #
    #   - `launch_vm` distinguishes a pre-register RETRIABLE (preflight
    #     failed — safe to re-place) from a post-register one (dispatch
    #     failed — re-placing would re-mint a ticket for a new host and hit
    #     the KBS anti-migration CAS fence → `kbs-admin-conflict`; retry the
    #     SAME miner instead).
    #   - the abandoned-launch reap reads it as "this vm_id is SPENT": it
    #     can never be launched anywhere again, so the orphaned KEK its
    #     failed launch left behind is safe to destroy.
    #
    # It therefore has to be True on the terminal returns between the
    # register and the dispatch too — those used to say `False`, which
    # claimed the KBS had not been touched when it had.
    registered: bool = False


class LaunchConfigError(Exception):
    """A misconfiguration the caller must fix (e.g. missing Vault prefix,
    miner without a netbird_ip). Distinct from the per-step effect
    failures, which become `TERMINAL`/`RETRIABLE` outcomes.
    """


def _fresh_id(prefix: str, vm_id: str) -> str:
    return f"{prefix}-{vm_id}-{uuid.uuid4().hex[:8]}"


def check_netbird_userdata(
    userdata: bytes, *, enable: bool, hostname_template: str, vm_id: str
) -> str | None:
    """Validate the NetBird userdata template (#306/#309). Returns an
    error message, or `None` if OK / NetBird disabled.

    Shared by the CLI (which raises `CommandError`) and
    [`launch_on_miner`] (which turns it into a `TERMINAL` outcome) so the
    two callers apply ONE rule. The message wording is load-bearing —
    `test_create_vm_command` matches on `NETBIRD_SETUP_KEY` / `vm_id`.
    """
    if not enable:
        return None
    if b"{{NETBIRD_SETUP_KEY}}" not in userdata:
        return (
            "--enable-netbird requires the userdata template to carry the "
            "literal placeholder {{NETBIRD_SETUP_KEY}}"
        )
    try:
        hostname_template.format(vm_id=vm_id)
    except (KeyError, IndexError) as exc:
        return f"netbird_hostname_template only supports {{vm_id}} ({exc})"
    return None


def launch_on_miner(spec: LaunchSpec, miner: MinerIdentity) -> LaunchOutcome:
    """Run the full launch choreography for ONE miner. Never raises for a
    step failure — returns a typed [`LaunchOutcome`]; raises
    [`LaunchConfigError`] only for caller-fixable misconfiguration.
    """
    # vm_id is interpolated into Vault KV paths below — charset-lock it so
    # neither the CLI nor the API can path-traverse out of the per-VM
    # Vault namespace. (The API also rejects this earlier, at intake.)
    if not _VM_ID_RE.match(spec.vm_id):
        raise LaunchConfigError(
            "vm_id must match [a-z0-9-]{1,64} (no path separators)"
        )
    if not miner.netbird_ip:
        raise LaunchConfigError(
            f"miner {miner.miner_id!r} has no netbird_ip — register via "
            "PR #120 first"
        )

    # ── 0. the control-plane row, BEFORE any effect that can leave a
    #        running domain behind (P9/#18) ─────────────────────────────
    #
    # This used to live ONLY in `launch_vm`, so `vali_create_vm` — which
    # calls this function directly — dispatched a real, attested, RUNNING
    # CVM while `Vm` stayed empty. Everything the control plane does to a
    # VM keys off that row, so an unbound VM is invisible to all of it:
    #
    #   - §24 decommission is UNREACHABLE. `DecommissionJob.vm` is a
    #     non-null FK and `DecommissionStartView` 404s on the missing row,
    #     so the VM's Vault-Transit KEK is never destroyed and its overlay
    #     is never unlinked. That is the `data-death` hazard by a second
    #     route, and it is not theoretical: production carries a live KEK
    #     for `nbproof-3`, a vm_id with a launch billing binding and NO
    #     `Vm` row.
    #   - `sweep_guest_liveness`, `reboot_recovery_once`,
    #     `verify_netbird_enrolments` and `reclaim_migrated_sources` all
    #     iterate `Vm` — an unbound VM is outside every one of them.
    #   - §25 cannot migrate it (`MigrateStartView` 404s the same way).
    #   - `_persist_lifecycle_vk` / `_persist_eol_nonce` are filtered
    #     UPDATEs: with no row they silently touch zero rows, so the §24/25
    #     guest-signed EOL fence has nothing to verify against.
    #
    # Creating it HERE — in the shared choreography every launch path runs
    # — makes "launched by vali but unknown to vali" unrepresentable
    # rather than merely discouraged. Idempotent `get_or_create`, so
    # `launch_vm` (which still needs the object for its `Placement`) and
    # reboot-recovery (row already exists) are unaffected.
    #
    # Ordered AFTER the `LaunchConfigError` gates above so a caller-fixable
    # misconfiguration still creates nothing, and BEFORE the Vault staging
    # so there is no window in which secrets/tickets/domains exist for a
    # vm_id with no row.
    _ensure_vm_row(spec)

    # ── C2 fail-closed posture ──────────────────────────────────────
    # If launch-digest ENFORCE is on, the independent recompute MUST be
    # configured (binary + pinned OVMF SHA). Otherwise step 5b's
    # `if launch_digest_svc.is_enabled():` guard is skipped and the §22
    # pin silently falls back to the UNTRUSTED miner-reported digest
    # (`measurement_hex` = `preflight_result.launch_digest_hex`) —
    # re-opening C2 on a config drift. Refuse BEFORE doing any Vault /
    # preflight / dispatch work rather than pin an unverified measurement.
    if launch_digest_svc.enforce() and not launch_digest_svc.is_enabled():
        return _terminal(
            "launch-digest-not-configured",
            "VALI_LAUNCH_DIGEST_ENFORCE is set but the recompute is not "
            "configured (VALI_LAUNCH_DIGEST_BIN / VALI_SNP_OVMF_S3_URI / "
            "VALI_SNP_OVMF_SHA256) — refusing to pin an unverified miner "
            "digest",
            EXIT_MEASUREMENT_MISMATCH,
        )

    from apps.orchestration.services.flavors import resolve_flavor

    flavor = resolve_flavor(spec.flavor)
    ticket_id = spec.ticket_id or _fresh_id("tk", spec.vm_id)
    order_id = spec.order_id or _fresh_id("ord", spec.vm_id)
    # node_id binds the ticket to the miner the order-intake gate checks
    # (`target_miner_id` ~= `[miner].miner_id`, case-insensitive). It is
    # the HUMAN miner_id, never a hex key.
    node_id = miner.miner_id
    platform_id = spec.platform_id or miner.platform_id

    # mutable secret-bearing copies we own + zeroize here.
    userdata = spec.userdata
    kek_bytes = spec.kek_bytes

    # ── 1. Optional NetBird enrolment (#306, #309) ──────────────────
    if spec.enable_netbird:
        nb_err = check_netbird_userdata(
            userdata,
            enable=True,
            hostname_template=spec.netbird_hostname_template,
            vm_id=spec.vm_id,
        )
        if nb_err is not None:
            return _terminal("netbird-bad-userdata", nb_err, EXIT_NETBIRD_FAILURE)
        nb_hostname = spec.netbird_hostname_template.format(vm_id=spec.vm_id)
        try:
            nb_key = effects.mint_netbird_setup_key(
                vm_id=spec.vm_id,
                tenant_id=spec.tenant_id,
                auto_group_name=spec.netbird_group,
                expires_in_seconds=int(spec.netbird_key_ttl_seconds),
            )
        except (EffectUnavailable, EffectError) as exc:
            return _terminal(
                "netbird-mint-failure", str(exc), EXIT_NETBIRD_FAILURE
            )
        userdata = userdata.replace(
            b"{{NETBIRD_SETUP_KEY}}", nb_key.encode("utf-8")
        )
        userdata = userdata.replace(
            b"{{NETBIRD_HOSTNAME}}", nb_hostname.encode("utf-8")
        )
        try:
            nb_key = "\x00" * len(nb_key)
        except Exception:
            pass

    # ── 2. Vault stage (KEK + userdata) ─────────────────────────────
    mount = str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret"))
    prefix = str(getattr(settings, "VALI_VAULT_KV_PREFIX", ""))
    if not prefix:
        raise LaunchConfigError("VALI_VAULT_KV_PREFIX is not configured")

    luks_path = f"{prefix}/{spec.vm_id}/luks-kek"
    userdata_path = f"{prefix}/{spec.vm_id}/userdata"
    # §7: the KBS DERIVES this path from the luks path (swaps the final
    # `luks-kek` segment for `lifecycle-key`) — keep the two in lockstep.
    lifecycle_path = f"{prefix}/{spec.vm_id}/lifecycle-key"

    try:
        if kek_bytes is not None:
            # SYNC / CLI path: vali generated the KEK in-process — WRAP it
            # with its per-VM Vault Transit key (KEK-HSM Phase 2) and stage
            # the CIPHERTEXT, never the plaintext. The KEK exists in the
            # clear at rest NOWHERE: a vali/broker/node compromise reading
            # this path gets only `vault:v1:…` ciphertext; only the attested
            # SNP KBS `transit/decrypt`s it (per-VM scoped by the broker) on
            # release. vali holds encrypt (wrap) but never decrypt.
            transit_key = vault_kv.transit_key_name(spec.vm_id)
            vault_kv.ensure_transit_key(transit_key)
            wrapped = vault_kv.transit_encrypt(transit_key, kek_bytes)
            luks_version = vault_kv.put_kv(mount, luks_path, wrapped).version
        else:
            # ASYNC launch path: the KEK is ALREADY staged at the canonical
            # `luks_path` by the caller (the launch API enforces
            # `kek_vault_path == luks_path`). Read ONLY the KV VERSION from
            # the metadata endpoint — NEVER the plaintext KEK. This is the
            # C1 / KEK-HSM-Phase-1 win: vali (and thus a vali/node RCE) can
            # no longer read a tenant disk KEK back out of Vault.
            luks_version = vault_kv.latest_version(mount, luks_path)
        ud_v = vault_kv.put_kv(mount, userdata_path, userdata)
    except (EffectUnavailable, EffectError) as exc:
        return _terminal("vault-failure", str(exc), EXIT_VAULT_FAILURE)
    finally:
        if kek_bytes is not None:
            try:
                kek_bytes = b"\x00" * len(kek_bytes)
            except Exception:
                pass

    # ── 2b. §7 lifecycle key — FIRST-WRITE-WINS. The KBS reads the seed
    #        from `lifecycle_path` at PINNED Vault version 1 forever
    #        (`kbs-core/src/release.rs` `LIFECYCLE_KEY_VERSION`), so the
    #        keypair is a per-VM-LIFETIME identity: the FIRST launch of a
    #        vm_id generates + stages it (KV v2 `cas=0` — refuse to
    #        overwrite); every re-launch (re-place after a retriable
    #        dispatch, an `already-launched` running guest, a reboot)
    #        REUSES the version-1 seed and re-derives the same PUBLIC
    #        keys. Rotating here would desync `Vm.lifecycle_vk` + the
    #        telemetry source from the key the guest actually holds — the
    #        guest can only ever receive the version-1 seed.
    #        The KBS HPKE-seals the seed to the attested guest in the §21
    #        envelope; the miner never sees it. The vk is what
    #        `_verify_ack` checks against the guest-signed StoppedAck
    #        (§24/§25).
    try:
        lifecycle_seed, lifecycle_vk = _stage_lifecycle_key(mount, lifecycle_path)
    except lifecycle_keygen.LifecycleKeygenError as exc:
        # Fail closed: a VM with no lifecycle key silently loses the
        # §24/§25 guest-signed fence. Surface as a terminal vault-class
        # failure (the keygen is part of the per-VM secret staging).
        return _terminal("lifecycle-keygen-failure", str(exc), EXIT_VAULT_FAILURE)
    except (EffectUnavailable, EffectError) as exc:
        return _terminal("vault-failure", str(exc), EXIT_VAULT_FAILURE)

    # Record the PUBLIC key on the Vm row (no-op for the CLI/dev path
    # with no row). The vk is non-secret and stable for the vm_id's
    # lifetime (version-1 seed), so a re-launch persist is a value
    # no-op — and it REPAIRS a row a pre-first-write-wins launch left
    # desynced.
    _persist_lifecycle_vk(spec.vm_id, lifecycle_vk)

    # ── 2c. §23 telemetry key — DERIVED from the lifecycle seed (NOT a
    #        separate released secret). vali derives the PUBLIC key so it
    #        can provision the `TelemetrySource` it verifies the guest's
    #        served-receipts against for uptime billing; the guest
    #        reproduces the SAME key from the lifecycle seed it receives in
    #        the §21 release (HKDF, domain-separated). Non-fatal: a failure
    #        only makes billing inert for this VM (its receipts 403 at
    #        ingest), it never blocks the launch or the §24/§25 fence.
    try:
        telemetry_vk = telemetry_keygen.derive_telemetry_vk(lifecycle_seed)
    except telemetry_keygen.TelemetryKeygenError as exc:
        log.warning(
            "launch: vm_id=%s telemetry-vk derive failed (billing inert): %s",
            spec.vm_id,
            exc,
        )
    else:
        _persist_telemetry_source(spec.vm_id, telemetry_vk)
    finally:
        # Drop our reference to the seed the moment the derivations are
        # done (§20 — never keep the private key around, never log it).
        del lifecycle_seed

    # ── 2d. §23 billing binding — record the AUTHORITATIVE (node_id,
    #        resource_class, lease) vali provisioned, so the meter can
    #        reject a receipt whose self-declared fields were inflated by
    #        a party with root inside the CVM (the guest key is
    #        extractable; the receipt is not host-attested). The receipt's
    #        node_id is the miner's 64-hex chain_node_id (baked into the
    #        measured cmdline as `hippius.node_id`); resource_class is the
    #        flavor tier. Non-fatal (best-effort, same as the source).
    _persist_billing_binding(
        spec.vm_id, miner.chain_node_id, spec.flavor, spec.lease_id
    )

    # ── 3. allowed_userdata_digest_hex ──────────────────────────────
    digest_hex = userdata_digest.userdata_digest_hex(
        tenant_id=spec.tenant_id,
        vm_id=spec.vm_id,
        ticket_id=ticket_id,
        secret_type=userdata_digest.SECRET_TYPE_USERDATA,
        path=userdata_path,
        version=ud_v.version,
        plaintext=userdata,
    )
    try:
        userdata = b"\x00" * len(userdata)
    except Exception:
        pass

    # ── 4. cmdline augmentation (#296 / rootfs / #365 / golden-bake) ─
    # Disk-integrity binding is mode-gated: legacy_luks → the LUKS-header
    # MAC token (byte-identical to today); golden_verity_overlay → the
    # dm-verity golden base's root hash (the luks token is dropped).
    augmented_cmdline = _augment_disk_binding(spec.cmdline, spec)
    if spec.rootfs_sha256_hex:
        augmented_cmdline = _augment_cmdline_with_token(
            augmented_cmdline, _ROOTFS_SHA_CMDLINE_KEY, spec.rootfs_sha256_hex
        )
    augmented_cmdline = _augment_cmdline_with_token(
        augmented_cmdline, _DISK_GB_CMDLINE_KEY, str(flavor.data_disk_size_gb)
    )
    # §7 — bake the lifecycle-key tmpfs path into the MEASURED cmdline so
    # the guest's keyscript writes the released key there and the `eol`
    # signer reads it. Measured ⇒ allowlist auto-pins (handled below).
    augmented_cmdline = _augment_cmdline_with_token(
        augmented_cmdline,
        _LIFECYCLE_KEY_PATH_CMDLINE_KEY,
        _LIFECYCLE_KEY_TMPFS_PATH,
    )

    # §23 — bake the served-receipt telemetry inputs the guest agent needs
    # to build each receipt (node_id / resource_class / family_id). Without
    # these the guest's `Config::resolve` fails closed and no receipt is
    # ever emitted, so uptime billing stays inert. `node_id` is the miner's
    # 64-hex compute id (the guest hex-decodes it to the raw identity bytes
    # vali keys the UsageAccrual ledger by); `resource_class` is the flavor
    # tier; `family_id` is the tenant family as hex bytes.
    augmented_cmdline = _augment_cmdline_with_token(
        augmented_cmdline, _NODE_ID_CMDLINE_KEY, miner.chain_node_id
    )
    augmented_cmdline = _augment_cmdline_with_token(
        augmented_cmdline, _RESOURCE_CLASS_CMDLINE_KEY, spec.flavor
    )
    augmented_cmdline = _augment_cmdline_with_token(
        augmented_cmdline, _FAMILY_ID_CMDLINE_KEY, spec.tenant_id.encode().hex()
    )

    # §23 — bake the validator challenge so the guest's receipt loop
    # actually BUILDS receipts (a `None` challenge idles the loop and emits
    # nothing). vali verifies only the guest signature, so a launch-baked
    # static challenge activates billing. validator_id is this validator's
    # identity; the nonce is a fresh per-launch 32-byte anti-replay value;
    # the epoch is the current billing epoch the receipts accrue to.
    validator_id_hex = str(
        getattr(settings, "VALI_TELEMETRY_VALIDATOR_ID_HEX", _DEFAULT_VALIDATOR_ID_HEX)
    )
    augmented_cmdline = _augment_cmdline_with_token(
        augmented_cmdline, _VALIDATOR_ID_CMDLINE_KEY, validator_id_hex
    )
    augmented_cmdline = _augment_cmdline_with_token(
        augmented_cmdline,
        _VALIDATOR_NONCE_CMDLINE_KEY,
        secrets.token_bytes(32).hex(),
    )
    augmented_cmdline = _augment_cmdline_with_token(
        augmented_cmdline,
        _TELEMETRY_EPOCH_CMDLINE_KEY,
        str(_current_billing_epoch()),
    )

    # ── 4a-bis. §24/§25 EOL identity + vali-reach — bake the inputs the
    #            guest's `eol` signer needs to RESOLVE + DELIVER its
    #            stopped-ack (vm_id / lease_id / vm_generation / vali_url).
    #            Without these the guest logs `eol-inputs-unresolved` and
    #            never produces an ack, so the §25 fence stalls at
    #            `awaiting_source_ack`.
    augmented_cmdline = _augment_eol_delivery_inputs(
        augmented_cmdline, vm_id=spec.vm_id, lease_id=spec.lease_id
    )

    # ── 4b. §24/§25 EOL nonce — bake the SAME nonce into the measured
    #        cmdline AND persist it on `Vm.eol_nonce` (GAP 3). The guest
    #        signs THIS value into its StoppedAck on a clean shutdown;
    #        `_verify_ack` checks the signature against the persisted
    #        copy. Resolution order: an operator-baked `hippius.eol_nonce=`
    #        token in the cmdline wins (already measured); else
    #        `spec.eol_nonce_hex`; else a fresh per-launch mint. Whatever
    #        ends up in the cmdline is reflected onto the Vm row so the
    #        two can NEVER drift. Generation is the per-migration replay
    #        guard (the KBS fence forever denies a migrated generation),
    #        so a per-launch nonce — stable across reboots / the VM's
    #        lifetime — is correct and is NOT re-minted at migration /
    #        decommission (see `service.start_migration`).
    nonce_seed = (
        spec.eol_nonce_hex
        or _extract_cmdline_token(spec.cmdline, _EOL_NONCE_CMDLINE_KEY)
        or secrets.token_bytes(32).hex()
    )
    augmented_cmdline = _augment_cmdline_with_token(
        augmented_cmdline, _EOL_NONCE_CMDLINE_KEY, nonce_seed
    )
    effective_eol_nonce_hex = _extract_cmdline_token(
        augmented_cmdline, _EOL_NONCE_CMDLINE_KEY
    )
    _persist_eol_nonce(spec.vm_id, effective_eol_nonce_hex)

    # ── 5. Preflight (miner-side fetch + SNP launch_digest) ─────────
    #
    # The boot-disk artifact set diverges by disk_mode. LEGACY fetches the
    # per-VM `tenant.qcow2`. GOLDEN (golden-bake PR4) has NO per-VM qcow2:
    # the `luks_disk` slot carries the SHARED golden `rootfs.img` and
    # `rootfs_hash` carries the golden `rootfs.verity`, both keyed by their
    # bake SHAs so the miner's content-addressed cache (#823) HITs on a
    # same-distro relaunch. kernel/initrd are staged identically.
    _preflight_artifacts = _select_preflight_artifacts(spec)
    try:
        preflight_result = preflight_svc.dispatch_preflight(
            miner_id=miner.miner_id,
            netbird_ip=str(miner.netbird_ip),
            order_id=preflight_svc.fresh_order_id(),
            vm_id=spec.vm_id,
            ovmf_path=spec.ovmf_path,
            cmdline=augmented_cmdline,
            cpu_count=flavor.cpu_count,
            artifacts=_preflight_artifacts,
        )
    except (EffectUnavailable, EffectError) as exc:
        # A preflight rejection means THIS miner could not stage/verify
        # the artefacts — retriable: the scheduler re-places elsewhere.
        return LaunchOutcome(
            disposition=RETRIABLE,
            emit={
                "ok": False,
                "outcome": "preflight-failure",
                "error": str(exc),
            },
            exit_code=EXIT_PREFLIGHT_FAILURE,
        )

    measurement_hex = spec.measurement_hex or preflight_result.launch_digest_hex

    # ── 5b. C2: independent launch-digest recompute ─────────────────
    # vali recomputes the digest a HONEST guest MUST produce from its OWN
    # LaunchOrder inputs (pinned OVMF + the kernel/initrd/cmdline/vcpus/
    # vcpu-type it built) and compares to the MINER's preflight report.
    # Never trust the miner's asserted measurement for the §22 pin — a
    # backdoored guest would report a different digest.
    #   WARN mode  (VALI_LAUNCH_DIGEST_ENFORCE=false): log a mismatch,
    #              still pin the miner value (byte-exact validation window).
    #   ENFORCE    (true): a mismatch REFUSES the launch (no pin, no KEK);
    #              vali pins ONLY its own recomputed value.
    if launch_digest_svc.is_enabled():
        try:
            expected_digest = launch_digest_svc.recompute_expected_digest(
                s3_bucket=spec.s3_bucket,
                s3_key_prefix=spec.s3_key_prefix,
                kernel_sha256_hex=spec.kernel_sha256_hex,
                initrd_sha256_hex=spec.initrd_sha256_hex,
                cmdline=augmented_cmdline,
                cpu_count=flavor.cpu_count,
                platform_id=platform_id or "",
            )
        except launch_digest_svc.LaunchDigestUnavailable:
            expected_digest = None
        except (EffectUnavailable, EffectError) as exc:
            # Can't validate ⇒ fail-closed under ENFORCE; logged in WARN.
            if launch_digest_svc.enforce():
                return _terminal(
                    "launch-digest-recompute-failure",
                    str(exc),
                    EXIT_MEASUREMENT_MISMATCH,
                )
            log.warning(
                "C2 recompute failed (WARN) vm=%s: %s", spec.vm_id, exc
            )
            expected_digest = None

        if expected_digest is not None:
            miner_digest = (preflight_result.launch_digest_hex or "").lower()
            if expected_digest != miner_digest:
                if launch_digest_svc.enforce():
                    log.error(
                        "C2 REFUSE vm=%s: miner digest %s != vali recompute %s",
                        spec.vm_id,
                        miner_digest,
                        expected_digest,
                    )
                    return _terminal(
                        "launch-digest-mismatch",
                        f"miner-reported launch_digest {miner_digest} != vali "
                        f"recompute {expected_digest}",
                        EXIT_MEASUREMENT_MISMATCH,
                    )
                log.error(
                    "C2 WARN vm=%s: miner digest %s != vali recompute %s "
                    "(WARN mode — NOT blocking)",
                    spec.vm_id,
                    miner_digest,
                    expected_digest,
                )
            else:
                log.info(
                    "C2 OK vm=%s: vali recompute == miner digest (%s)",
                    spec.vm_id,
                    expected_digest,
                )
            # ENFORCE: pin ONLY vali's recomputed value (unless an explicit
            # operator override was supplied).
            if launch_digest_svc.enforce() and not spec.measurement_hex:
                measurement_hex = expected_digest

    # ── 6. Allowlist re-pin (optional) ──────────────────────────────
    pin_result = None
    if spec.auto_pin_allowlist:
        try:
            pin_result = allowlist_pin.pin_measurement(
                measurement_hex=measurement_hex
            )
        except (EffectUnavailable, EffectError) as exc:
            return _terminal(
                "allowlist-pin-failure", str(exc), EXIT_ALLOWLIST_FAILURE
            )
        # #587 Phase 3 — append the pinned digest to the audit ledger
        # (GET /v1/admin/audit/measurements). Best-effort: the KBS pin
        # above is the authoritative record; a ledger write failure must
        # never fail an otherwise-good launch.
        try:
            MeasurementLedger.objects.create(
                vm_id=spec.vm_id,
                launch_digest_hex=measurement_hex,
                platform_id=platform_id or "",
                node_id=node_id or "",
                allowlist_epoch=pin_result.new_epoch,
                allowlist_sha256=pin_result.new_cose_sha256_hex,
                # A tenant launch always pins under the tenant class;
                # recording it lets the carry-forward veto a class flip.
                measurement_class=allowlist_pin.ALLOWLIST_CLASS_TENANT,
            )
        except Exception as exc:  # noqa: BLE001 — audit is non-load-bearing
            log.warning(
                "measurement-ledger write failed (non-fatal) vm=%s: %s",
                spec.vm_id,
                exc,
            )

    # ── 7. Mint the L1 OrderTicket ──────────────────────────────────
    try:
        cose_ticket = ticket_mint.mint(
            ticket_mint.MintArgs(
                kid=spec.kid,
                ticket_id=ticket_id,
                tenant_id=spec.tenant_id,
                user_id=spec.user_id,
                vm_id=spec.vm_id,
                lease_id=spec.lease_id,
                node_id=node_id,
                platform_id=platform_id,
                allowed_measurement_hex=measurement_hex,
                userdata_vault_path=userdata_path,
                userdata_vault_version=ud_v.version,
                luks_vault_path=luks_path,
                luks_vault_version=luks_version,
                allowed_userdata_digest_hex=digest_hex,
                flavor=spec.flavor,
                lifecycle_perm=("launch",),
                expiry_seconds=spec.expiry_seconds,
            )
        )
    except (EffectUnavailable, EffectError) as exc:
        return _terminal("mint-failure", str(exc), EXIT_MINT_FAILURE)

    # ── 8. kbs-admin register ───────────────────────────────────────
    try:
        admin_ok = kbs_admin.register_vm_active_with_vm_id(
            vm_id=spec.vm_id, cose_ticket=cose_ticket
        )
    except kbs_admin.KbsAdminConflict as exc:
        return _terminal(
            "kbs-admin-conflict", str(exc), EXIT_KBS_ADMIN_FAILURE
        )
    except kbs_admin.KbsAdminTerminal as exc:
        return _terminal(
            "kbs-admin-terminal", str(exc), EXIT_KBS_ADMIN_FAILURE
        )
    except EffectUnavailable as exc:
        return _terminal(
            "kbs-admin-unavailable", str(exc), EXIT_KBS_ADMIN_FAILURE
        )
    except EffectError as exc:
        return _terminal("kbs-admin-error", str(exc), EXIT_KBS_ADMIN_FAILURE)

    log.info(
        "kbs-admin: registered vm_id=%s gen=%s cached=%s",
        admin_ok.vm_id,
        admin_ok.vm_generation,
        admin_ok.cached,
    )

    # From HERE on, this vm_id is PERMANENTLY bound at the KBS to THIS
    # miner's host: the anti-migration CAS fence means no other host can
    # ever be registered for it, so the launch can no longer be re-placed
    # and the vm_id can never be re-used. Every failure return below must
    # therefore say `registered=True` — `launch_vm` reads it to decide
    # retry-in-place vs re-place, AND (the phantom leak) to decide whether
    # an abandoned launch left a KEK that is safe to reap. Before this fix
    # only the DISPATCH-RESULT return carried the flag; the four terminal
    # returns between here and it reported `registered=False`, i.e. they
    # claimed the KBS had not been touched when it had.

    def _terminal_after_register(
        outcome: str, error: str, exit_code: int
    ) -> LaunchOutcome:
        out = _terminal(outcome, error, exit_code)
        out.registered = True
        return out

    # ── 9. Dispatch the launch order ────────────────────────────────
    #
    # GOLDEN (golden-bake PR4): vdb/vdc point at the miner-staged golden
    # base (`preflight_result.rootfs_{data,hash}_path`), NOT the operator
    # pre-staged legacy paths; `luks_disk_path` is IGNORED by the miner in
    # golden mode (it derives + creates the blank per-VM overlay upper vda
    # itself from `data_disk_size_gb`), so we still pass the staged value
    # for a uniform payload. LEGACY keeps the pre-staged rootfs paths.
    #
    # P9/#16 — the golden base is resolved by CONTENT, never by a shared
    # path. `spec.rootfs_data_path` defaults to
    # `/var/lib/hippius-miner/rootfs.img`: fixed, shared and MUTABLE. On
    # 2026-08-13 that one path was a symlink into the shared legacy base
    # on miner-2 and a real 709 MB 2026-07-29 file on miner-3 — the same
    # spec resolving to two different operating systems. Falling back to
    # it made the divergence invisible AND aimed the launch at bytes some
    # other VM may be booting. There is nothing to fall back TO: the
    # preflight-resolved path is the only correct answer, so a missing one
    # is terminal.
    if spec.disk_mode == _DISK_MODE_GOLDEN_VERITY:
        rootfs_data_path = preflight_result.rootfs_data_path or ""
        rootfs_hash_path = preflight_result.rootfs_hash_path or ""
        try:
            _assert_per_vm_base(spec.vm_id, rootfs_data_path, rootfs_hash_path)
        except ValueError as exc:
            return _terminal_after_register(
                "golden-base-unresolved", str(exc), EXIT_MINER_REJECTED
            )
    else:
        # LEGACY: the rootfs really is an operator-pre-staged shared file
        # the miner never fetches. Recorded honestly (unpinned) rather
        # than pretended to be per-VM.
        rootfs_data_path = spec.rootfs_data_path
        rootfs_hash_path = spec.rootfs_hash_path
    payload = order_dispatch.build_launch_payload(
        vm_id=spec.vm_id,
        ovmf_path=spec.ovmf_path,
        kernel_path=preflight_result.kernel_path,
        initrd_path=preflight_result.initrd_path,
        cmdline=augmented_cmdline,
        luks_disk_path=preflight_result.luks_disk_path,
        luks_disk_size_gb=flavor.luks_disk_size_gb,
        data_disk_size_gb=flavor.data_disk_size_gb,
        rootfs_data_path=rootfs_data_path,
        rootfs_hash_path=rootfs_hash_path,
        cpu_count=flavor.cpu_count,
        memory_mb=flavor.memory_mb,
        cose_ticket=cose_ticket,
    )
    import json as _json

    payload_json = _json.dumps(payload).encode("utf-8")

    try:
        result = order_dispatch.dispatch_order(
            miner_id=miner.miner_id,
            netbird_ip=str(miner.netbird_ip),
            order_id=order_id,
            kind="launch",
            payload_json=payload_json,
        )
    except order_dispatch.OrderDispatchMisconfigured as exc:
        return _terminal_after_register("misconfigured", str(exc), EXIT_EDGE_FAILURE)
    except order_dispatch.OrderDispatchUnavailable as exc:
        # ⚠️ THE AMBIGUOUS ONE. `OrderDispatchUnavailable` covers the vali→Edge
        # POST TIMING OUT (45 s) as well as a refused connection — and the
        # miner's `/v1/miner/order/launch` AWAITS its dispatch task, so a host
        # that is merely SLOW to create+start the domain produces this exact
        # exception while the guest goes on to boot and release its KEK. The
        # launch is reported failed; the VM may nevertheless be alive. Nothing
        # downstream may treat this outcome as proof that no guest exists —
        # see `service._abandoned_reap_veto`, which requires POSITIVE evidence
        # (a live domain-state probe of the miner) and never the error string.
        return _terminal_after_register("edge-unreachable", str(exc), EXIT_EDGE_FAILURE)
    except order_dispatch.OrderDispatchError as exc:
        return _terminal_after_register("edge-error", str(exc), EXIT_EDGE_FAILURE)

    emit: dict[str, Any] = {
        "ok": result.ok,
        "outcome": "miner-accepted" if result.ok else "miner-rejected",
        "status": result.status,
        "classifier": result.classifier,
        "miner_id": miner.miner_id,
        "target_addr": (
            f"{miner.netbird_ip}:{order_dispatch.DEFAULT_MINER_ORDERS_PORT}"
        ),
        "ticket_id": ticket_id,
        "order_id": order_id,
        "vault_luks_version": luks_version,
        "vault_userdata_version": ud_v.version,
        "allowed_userdata_digest_hex": digest_hex,
        "measurement_hex": measurement_hex,
        "measurement_source": (
            "operator-pinned" if spec.measurement_hex else "preflight-auto"
        ),
        "luks_disk_path": preflight_result.luks_disk_path,
        "kernel_path": preflight_result.kernel_path,
        "initrd_path": preflight_result.initrd_path,
        # P9/#16 — the per-VM staged base this VM ACTUALLY booted. §25's
        # `effects._launch_paths` reads these back so a dest-activation
        # stages the base into the VM's own directory instead of the
        # shared `/var/lib/hippius-miner/rootfs.img` the spec defaults to.
        "rootfs_data_path": rootfs_data_path,
        "rootfs_hash_path": rootfs_hash_path,
        # §25 — the EXACT SNP-measured cmdline this VM launched with (base +
        # every augmentation: dm-verity.root / boot selector / disk_gb / the
        # §23 telemetry trio / the §24-25 EOL delivery tokens / eol_nonce …).
        # `spec_json["cmdline"]` holds only the BASE cmdline; the augmented
        # bytes are otherwise transient. A §25 dest MUST boot the
        # byte-identical measured cmdline — else (a) its launch_digest differs
        # from the re-minted ticket's `allowed_measurement_hex` and the KBS
        # denies the KEK, and (b) for a GOLDEN VM the dest miner classifies it
        # as legacy (no `dm-verity.root=`) and never restores the overlay. So
        # persist it here for `effects._launch_paths` to carry verbatim.
        "measured_cmdline": augmented_cmdline,
    }
    if pin_result is not None:
        emit["allowlist_epoch"] = pin_result.new_epoch
        emit["allowlist_sha256"] = pin_result.new_cose_sha256_hex

    # Stamp the placed miner onto the `Vm` row when there is one.
    #
    # ⚠️ CORRECTION to what this comment said when it shipped in #878: it
    # claimed this "closes it at the source" for the operator CLI. It does
    # NOT. `_bind_vm_host` is `filter(...).update(...)` — it never CREATES
    # a row — and `vali_create_vm` calls this function directly while
    # touching `Vm` nowhere. `_ensure_vm_row` is the only row creator in
    # the tree and its only caller is `launch_vm`. So a CLI-launched VM has
    # NO `Vm` row at all, and this stamp is a no-op for it: **the CLI path
    # is still unbound-but-running** (tracked separately).
    #
    # What this stamp actually buys, per caller:
    #   - `launch_vm`        — redundant; it already stamps at the ACCEPTED
    #                          branch below.
    #   - `vali_create_vm`   — no-op, no row to update.
    #   - reboot-recovery    — the ONLY place it does new work: the row
    #                          exists and its `host` may be empty.
    #
    # ONLY on an ACCEPTED dispatch. `_bind_vm_host` filters on `host=""`,
    # so the FIRST stamp wins forever — a rejected-dispatch stamp would let
    # miner A claim `vm.host`, and a later SUCCESSFUL launch of the same
    # `vm_id` on miner B would silently no-op. `_bound_miner_id` PREFERS
    # `vm.host`, so every consumer would then point at A while the VM runs
    # on B: §24 destroys into the void, §25 uses A as its source,
    # reboot-recovery polls A. A WRONG binding is worse than an empty one,
    # because nothing fails loud.
    #
    # Reachability, precisely: NOT within a single `launch_vm`. The
    # RETRIABLE that re-places comes from the preflight failure, which
    # returns before this line; the RETRIABLE that reaches here carries
    # `registered=True` and retries the SAME miner, then gives up with
    # `dispatch-failed-after-register`. It is reachable ACROSS calls — a
    # fresh LaunchJob or CLI retry for the same `vm_id` on a different
    # miner, after an operator clears the KBS registration, which is the
    # documented recovery for exactly that outcome (and the path that
    # produced `migproof-1`).
    #
    # A rejected dispatch that nonetheless left a domain up is covered
    # instead by `effects.destroy_target_miner_id`, which reads the
    # LaunchJob — deliberately widened for the destroy ONLY, so it cannot
    # leak into `_bound_miner_id`'s routing.
    if result.ok:
        _bind_vm_host(spec.vm_id, miner.miner_id)
        _record_base_image(
            spec,
            rootfs_data_path=rootfs_data_path,
            rootfs_hash_path=rootfs_hash_path,
        )

    # §23 gate (e) — record what this dispatch PROVED about the host's
    # ability to start a confidential guest. This is the single writer for
    # the launch side, placed here (rather than in `launch_vm`) so it also
    # covers the operator CLI + the reboot-recovery relaunch, which call
    # this function directly.
    #
    # The dispatch is the honest observation point: `/v1/miner/order/launch`
    # AWAITS its dispatch task, so `result.ok` (a 2xx) means the miner
    # actually created and started the domain, and a non-2xx here means the
    # host was asked to start a CVM and could not — precisely the SEV-init
    # failure shape (`sev_common_kvm_init: EBUSY` → libvirt refuses the
    # domain → `handle_launch` errors → 5xx).
    #
    # Only reached with `registered=True`; the PREFLIGHT rejection above
    # returns early and is deliberately NOT recorded. A preflight failure is
    # an artifact staging/fetch/digest problem, not evidence about the SNP
    # subsystem, and the soft circuit-breaker already routes around it. The
    # negative signal is kept high-precision on purpose: it is the one that
    # HARD-excludes a host.
    #
    # ⚠️ A non-2xx is NOT automatically a host-capability failure either.
    # The miner answers with a static class, and only some of them are a
    # statement about the SEV start — a `launch-input` 422 says THIS
    # ORDER was bad, `insufficient-resources` says the host is FULL, and
    # `ticket-delivery-failed` fires only once the domain already reached
    # `Running`. `cvm_capability.is_start_capability_failure` owns that
    # split; everything not explicitly excused still counts, so a class
    # nobody foresaw fails towards recording rather than towards silence.
    _record_cvm_start_evidence(
        miner, accepted=result.ok, classifier=result.classifier
    )

    # A miner 4xx/5xx ("miner-rejected") is retriable — but the vm is now
    # KBS-registered to THIS miner (step 8), so `registered=True` tells
    # `launch_vm` to retry the SAME miner rather than re-place (a re-place
    # would kbs-admin-conflict). A 2xx is the accepted terminal-success.
    return LaunchOutcome(
        disposition=ACCEPTED if result.ok else RETRIABLE,
        emit=emit,
        exit_code=EXIT_OK if result.ok else EXIT_MINER_REJECTED,
        cose_ticket=cose_ticket if result.ok else None,
        ticket_id=ticket_id if result.ok else None,
        registered=True,
    )


def _record_cvm_start_evidence(
    miner: MinerIdentity, *, accepted: bool, classifier: str = ""
) -> None:
    """Write one observed CVM-start outcome into the §23 capability
    ledger (`apps.scheduler.cvm_capability`).

    `classifier` is the miner's static rejection class (ignored on an
    accepted dispatch). It decides only whether a REJECTION is evidence
    about the host's ability to start a confidential guest at all — see
    `cvm_capability.is_start_capability_failure`. It is never persisted:
    the stored `reason` stays this module's closed vocabulary.

    The node id is taken from the OPERATOR-CURATED registry row vali
    dispatched to (`MinerIdentity.chain_node_id`, DB-unique), never from
    anything in the miner's response. That is what makes the ledger
    un-poisonable across miners: a host has no channel through which to
    name a node other than itself, so it can mark only ITSELF incapable
    — which is safe to believe, since it only costs the claimant work.

    The converse — a host lying "accepted" to keep its `proven` bonus —
    buys it nothing worth having: it must first have been chosen and
    handed a real tenant, the tenant's guest then never unlocks (the KBS
    release is measurement-gated and vali-side), and the lie is
    contradicted by every downstream liveness signal. It cannot inflate
    the #668 fit gate, which is anchored on operator-registered hardware.

    Fail-open: bookkeeping must never turn a good launch into a failure.
    """
    from apps.scheduler import cvm_capability

    node_id = getattr(miner, "chain_node_id", "") or ""
    try:
        if accepted:
            cvm_capability.record_start_ok(node_id)
        elif cvm_capability.is_start_capability_failure(classifier):
            cvm_capability.record_start_failure(
                node_id, reason=cvm_capability.REASON_LAUNCH_REJECTED
            )
        else:
            log.info(
                "cvm-capability: miner=%s rejected the launch with a class "
                "that is not evidence about SNP start capability — not "
                "recorded against the host",
                miner.miner_id,
            )
    except Exception as exc:  # noqa: BLE001 — never load-bearing
        log.warning("cvm-capability record skipped for %s: %s", miner.miner_id, exc)


def _terminal(outcome: str, error: str, exit_code: int) -> LaunchOutcome:
    """Build a `TERMINAL` outcome carrying the CLI's `{ok,outcome,error}`
    emit shape — the scheduler stops re-placing on these.
    """
    return LaunchOutcome(
        disposition=TERMINAL,
        emit={"ok": False, "outcome": outcome, "error": error},
        exit_code=exit_code,
    )


# ── scheduler-driven orchestrator (launch pipeline) ──────────────────


def max_replace_attempts() -> int:
    """How many distinct miners `launch_vm` tries before giving up."""
    return int(getattr(settings, "VALI_LAUNCH_MAX_REPLACE", 3))


def max_dispatch_retries() -> int:
    """How many times `launch_vm` retries the SAME miner after a
    post-register dispatch failure before giving up. Re-placing to a
    different miner after the KBS register is impossible (the anti-
    migration CAS fence), so a transient miner-side dispatch failure
    (e.g. a vsock CID collision) is retried in place."""
    return int(getattr(settings, "VALI_LAUNCH_MAX_DISPATCH_RETRIES", 2))


def dispatch_retry_backoff_s() -> float:
    """Seconds to wait between same-miner dispatch retries."""
    return float(getattr(settings, "VALI_LAUNCH_DISPATCH_RETRY_BACKOFF_S", 3.0))


@dataclass
class LaunchResult:
    """The terminal result of a scheduler-driven [`launch_vm`].

    `ok` is True iff a miner accepted. `attempts` records each
    (miner_node_id, disposition) tried — the re-place audit trail.
    `cose_ticket` is the minted L1 envelope on success, so the caller
    can persist an `OrderTicketIntake` through the canonical validated
    intake path (NOT reconstructed here — that would bypass validation).
    """

    ok: bool
    outcome: str
    vm_id: str
    miner_id: str | None = None
    miner_node_id: str | None = None
    ticket_id: str | None = None
    placement_id: str | None = None
    cose_ticket: bytes | None = None
    emit: dict[str, Any] = field(default_factory=dict)
    attempts: list[dict[str, str]] = field(default_factory=list)
    # True iff the launch got PAST the §24 KBS `register-vm` on some miner
    # (`LaunchOutcome.registered`). Only meaningful when `ok` is False: it
    # says the vm_id is now permanently bound at the KBS to a host it may
    # never have run on, which is what makes an abandoned launch reapable
    # (`service.sweep_abandoned_launches`). Never inferred from `outcome`.
    registered: bool = False


def launch_vm(
    spec: LaunchSpec,
    decided_by: Any,
    *,
    max_attempts: int | None = None,
    on_phase: Callable[[str], None] | None = None,
) -> LaunchResult:
    """Scheduler-driven launch — [`_place_and_launch`], plus the
    abandoned-launch marker on any non-`ok` terminal.

    The marker is stamped HERE, around every failure return at once,
    rather than at each of them: `launch_on_miner` has already created the
    `Vm` row and staged this VM's secrets by the time most of those
    returns are reachable, so a return that forgot to mark would silently
    re-open the phantom leak. Wrapping makes "a launch that ends without a
    host marks its row" a property of the function, not of its authors.
    """
    result = _place_and_launch(
        spec, decided_by, max_attempts=max_attempts, on_phase=on_phase
    )
    if not result.ok:
        _mark_launch_abandoned(
            spec.vm_id, outcome=result.outcome, registered=result.registered
        )
    return result


def _place_and_launch(
    spec: LaunchSpec,
    decided_by: Any,
    *,
    max_attempts: int | None = None,
    on_phase: Callable[[str], None] | None = None,
) -> LaunchResult:
    """Scheduler-driven launch: pick a miner, launch, re-place on reject.

    For up to `max_attempts` distinct miners (default
    `VALI_LAUNCH_MAX_REPLACE`):

      1. read a fresh on-chain snapshot + refresh the `MinerCapacity`
         mirror; `decide_placement` (§23 admission / anti-affinity /
         epoch-freshness, `excluded` accumulates rejected miners);
      2. bridge the chosen chain `node_id` → `MinerIdentity`
         (`chain_node_id`); a node with no registered identity is
         skipped (excluded) — vali can't dispatch to it;
      3. record a Pending `Placement`, run [`launch_on_miner`];
      4. ACCEPTED → bind the placement, return; RETRIABLE → fail it,
         exclude the miner, loop; TERMINAL → fail it, stop.

    Exhausting the attempts (or running out of eligible miners) returns
    `ok=False`. `decided_by` is the `ServiceClient` that authorised the
    launch (the `Placement.decided_by` audit field).

    `on_phase` (optional) is a purely-additive progress sink invoked with a
    wire-string phase name at each observable boundary: `"placing"` at the
    top of every placement attempt, `"dispatching"` just before handing the
    launch to the chosen miner. It NEVER affects control flow — a raising
    callback is swallowed — and defaults to `None` (the CLI path passes
    none, so its behaviour is byte-identical).
    """
    def _emit_phase(name: str) -> None:
        if on_phase is None:
            return
        try:
            on_phase(name)
        except Exception:  # noqa: BLE001 — progress must never break a launch
            log.warning("launch: on_phase(%s) callback raised (ignored)", name)
    from django.db import IntegrityError, transaction

    from apps.scheduler import chain, service
    from apps.scheduler.models import (
        ACTIVE_PLACEMENT_STATES,
        Placement,
        PlacementStatus,
    )
    from apps.scheduler.placement import (
        PlacementError,
        SelectionWeights,
        decide_placement,
    )

    cap_attempts = max_attempts or max_replace_attempts()
    vm = _ensure_vm_row(spec)
    excluded: set[str] = set()
    audit: list[dict[str, str]] = []

    for _ in range(cap_attempts):
        # Progress: the scheduler is (re-)choosing a miner for this VM.
        _emit_phase("placing")
        try:
            snapshot = chain.read_miner_status()
        except chain.ChainReadUnavailable as exc:
            return LaunchResult(
                ok=False,
                outcome="chain-unavailable",
                vm_id=spec.vm_id,
                emit={"ok": False, "outcome": "chain-unavailable", "error": str(exc)},
                attempts=audit,
            )

        service.refresh_miner_capacity(snapshot)
        cap, load, fam = service.decision_inputs(spec.tenant_id)
        try:
            node_id = decide_placement(
                snapshot=snapshot,
                capacity_by_node=cap,
                load_by_node=load,
                family_load_by_node=fam,
                max_family_per_node=service.max_family_per_node(),
                max_epoch_lag=service.max_epoch_lag(),
                excluded=frozenset(excluded),
                dispatchable=service.dispatchable_node_ids(),
                weights=SelectionWeights.from_settings(),
                max_host_share=service.max_host_share(),
                # §23 marketplace — cheaper announced prices rank up.
                price_by_node=service.price_by_node(snapshot),
                # Circuit-breaker — route around a miner with too many
                # recent launch failures (AUDIT-4).
                recent_failures_by_node=service.recent_failures_by_node(),
                max_recent_failures=service.max_recent_failures(),
                # Per-owner sub-budget — spread one owner's VMs across the
                # fleet instead of monopolising a miner (audit M-per-tenant-cap).
                owner_load_by_node=service.owner_load_by_node(spec.user_id),
                max_owner_placements_per_miner=service.max_owner_placements_per_miner(),
                # Gate (e) — the OBSERVED SEV-SNP start-capability ledger.
                # A host vali has watched fail to boot a confidential
                # guest is not a candidate; one it has watched succeed
                # outranks one it has never watched at all.
                cvm_capability_by_node=service.cvm_capability_by_node(),
            )
        except PlacementError as exc:
            return LaunchResult(
                ok=False,
                outcome=exc.category,
                vm_id=spec.vm_id,
                emit={"ok": False, "outcome": exc.category, "error": exc.message},
                attempts=audit,
            )

        # Bridge the chain node_id → the dispatchable identity (#463).
        miner = MinerIdentity.objects.filter(chain_node_id=node_id).first()
        if miner is None:
            # The scheduler picked a chain node with no registered
            # MinerIdentity — vali cannot recover its netbird_ip to
            # dispatch. Exclude it and try the next-ranked miner.
            log.warning(
                "placement node %s has no registered MinerIdentity — "
                "skipping (operator must backfill chain_node_id)",
                node_id,
            )
            excluded.add(node_id)
            audit.append({"miner_node_id": node_id, "disposition": "no-identity"})
            continue

        # Record the Pending placement. The partial unique index makes
        # this the race boundary; a pre-existing active placement for
        # this VM is a conflict the caller must resolve.
        try:
            with transaction.atomic():
                placement = Placement.objects.create(
                    vm=vm,
                    vm_family=spec.tenant_id,
                    owner=spec.user_id,
                    resource_class=spec.flavor,
                    miner_node_id=node_id,
                    status=PlacementStatus.PENDING.value,
                    chain_epoch=snapshot.current_epoch,
                    decided_by=decided_by,
                )
        except IntegrityError:
            existing = Placement.objects.filter(
                vm=vm, status__in=ACTIVE_PLACEMENT_STATES
            ).first()
            return LaunchResult(
                ok=False,
                outcome="placement-conflict",
                vm_id=spec.vm_id,
                placement_id=str(existing.id) if existing else None,
                emit={
                    "ok": False,
                    "outcome": "placement-conflict",
                    "error": "vm already has an active placement",
                },
                attempts=audit,
            )

        # Progress: a miner is chosen + the Pending placement recorded —
        # `launch_on_miner` now stages refs, mints, KBS-registers + dispatches.
        _emit_phase("dispatching")
        out = launch_on_miner(spec, miner)

        # Post-register dispatch failure: the KBS has already bound this
        # vm_id to THIS miner's host (step 8), so re-placing to another
        # miner would re-mint a ticket for a new host and hit the anti-
        # migration CAS fence (kbs-admin-conflict → terminal). The
        # registration is only valid HERE, so retry the SAME miner — a
        # transient miner-side dispatch failure (e.g. a vsock CID
        # collision) clears on retry; `register-vm` is idempotent-cached
        # for the same host so the retry does not re-conflict.
        dispatch_retries = 0
        while (
            out.disposition == RETRIABLE
            and out.registered
            and dispatch_retries < max_dispatch_retries()
        ):
            dispatch_retries += 1
            log.warning(
                "launch: vm_id=%s dispatch failed on miner=%s AFTER "
                "kbs-register (retry %d/%d same miner — re-place would "
                "kbs-admin-conflict)",
                spec.vm_id,
                miner.miner_id,
                dispatch_retries,
                max_dispatch_retries(),
            )
            time.sleep(dispatch_retry_backoff_s())
            out = launch_on_miner(spec, miner)

        audit.append(
            {
                "miner_node_id": node_id,
                "miner_id": miner.miner_id,
                "disposition": out.disposition,
                **(
                    {"dispatch_retries": str(dispatch_retries)}
                    if dispatch_retries
                    else {}
                ),
            }
        )

        if out.disposition == ACCEPTED:
            _bind_placement(placement, out)
            # Root-cause fix: stamp the placed miner's node_id onto the Vm
            # row. The async launch worker records the miner ONLY on
            # `LaunchJob.miner_id`; historically `vm.host` stayed "" until
            # §25 migrate-activation, which meant `effects.dispatch_destroy`
            # + the §24 EOL relay resolved an EMPTY miner → the §24 destroy
            # order never routed (zombie domain) and the EOL push no-op'd.
            # `vm.host` is the `MinerIdentity` primary key (== `miner.miner_id`,
            # the human node_id), the SAME shape §25 stamps + the destroy/EOL
            # `_miner_identity(vm.host)` lookup keys on. Idempotent: filter on
            # host="" so a re-adopt / migration-set host is never clobbered.
            _bind_vm_host(spec.vm_id, miner.miner_id)
            return LaunchResult(
                ok=True,
                outcome="miner-accepted",
                vm_id=spec.vm_id,
                miner_id=miner.miner_id,
                miner_node_id=node_id,
                ticket_id=out.ticket_id,
                placement_id=str(placement.id),
                cose_ticket=out.cose_ticket,
                emit=out.emit,
                attempts=audit,
            )

        # Not accepted — fail the placement so it stops counting against
        # the miner's load + the one-active-placement index frees up.
        _fail_placement(placement, reason=out.emit.get("outcome", "launch-failed"))

        # A post-register dispatch failure that survived the same-miner
        # retries is TERMINAL: the vm is KBS-bound to this miner and the
        # miner won't accept, but we cannot re-place (the CAS fence). Stop
        # rather than loop into a guaranteed kbs-admin-conflict.
        if out.disposition == RETRIABLE and out.registered:
            return LaunchResult(
                ok=False,
                outcome="dispatch-failed-after-register",
                vm_id=spec.vm_id,
                miner_id=miner.miner_id,
                miner_node_id=node_id,
                placement_id=str(placement.id),
                emit={
                    **out.emit,
                    "outcome": "dispatch-failed-after-register",
                    "error": (
                        "miner rejected the launch after the KBS registered "
                        "the vm to it; cannot re-place (anti-migration fence)"
                    ),
                },
                attempts=audit,
                registered=True,
            )

        if out.disposition == TERMINAL:
            # A vault/mint/kbs/edge error is not the miner's fault —
            # re-placing would just hit the same wall. Stop.
            #
            # `registered` is carried through VERBATIM, never inferred from
            # the outcome string: `edge-unreachable` here can mean either
            # "the Edge refused the connection" (nothing started) or "the
            # POST timed out while the miner was still starting the domain"
            # (a guest that is now alive). Only the flag says whether the
            # KBS was touched; only a live probe says whether a guest runs.
            return LaunchResult(
                ok=False,
                outcome=out.emit.get("outcome", "terminal"),
                vm_id=spec.vm_id,
                miner_id=miner.miner_id,
                miner_node_id=node_id,
                placement_id=str(placement.id),
                emit=out.emit,
                attempts=audit,
                registered=out.registered,
            )

        # RETRIABLE — this miner couldn't honour it; exclude + re-place.
        excluded.add(node_id)

    return LaunchResult(
        ok=False,
        outcome="no-capacity-after-replace",
        vm_id=spec.vm_id,
        emit={
            "ok": False,
            "outcome": "no-capacity-after-replace",
            "error": f"no miner accepted after {cap_attempts} attempt(s)",
        },
        attempts=audit,
    )


# ─── operator-FORCED launch (the CLI's path) ─────────────────────────

# The well-known principal a forced CLI launch is attributed to. Created
# on demand and INERT BY CONSTRUCTION: `is_active=False` makes
# `identity.authentication` reject it on BOTH credential paths (the mTLS
# CN lookup filters `is_active=True`, the token lookup filters
# `is_active=True, client__is_active=True`), and `scope` defaults to
# UNCLASSIFIED, which grants nothing. It exists purely so
# `Placement.decided_by` — a non-null PROTECT FK, and the §15 audit field
# — can say truthfully WHO forced the placement, without minting a usable
# credential as a side-effect of running a CLI.
OPERATOR_CLI_PRINCIPAL = "operator-cli"


class ActivePlacementConflict(LaunchConfigError):
    """This vm_id already holds a Pending/Bound `Placement`.

    Raised INSTEAD of launching. Subclasses `LaunchConfigError` so an
    existing `except LaunchConfigError` caller keeps its exit code; the
    CLI catches it first to report the precise outcome.
    """


def resolve_forced_launch_principal(name: str = "") -> Any:
    """Resolve the `ServiceClient` a forced launch is attributed to.

    `name` — an EXISTING client to credit the placement to (the operator
    ran the CLI on behalf of a real principal). Unknown ⇒
    `LaunchConfigError`; this never creates a client an operator named,
    because a typo must not silently manufacture a principal.

    Empty `name` ⇒ the well-known inert [`OPERATOR_CLI_PRINCIPAL`],
    created if absent. See that constant for why creating it grants
    nothing.
    """
    from apps.identity.models import PrincipalScope, ServiceClient

    if name:
        client = ServiceClient.objects.filter(name=name).first()
        if client is None:
            raise LaunchConfigError(
                f"--decided-by {name!r} is not a registered ServiceClient"
            )
        return client
    client, _created = ServiceClient.objects.get_or_create(
        name=OPERATOR_CLI_PRINCIPAL,
        defaults={
            "description": (
                "Audit principal for operator-forced launches "
                "(`vali_create_vm`). is_active=False — it cannot "
                "authenticate; it exists only to own Placement rows."
            ),
            "is_active": False,
            "scope": PrincipalScope.UNCLASSIFIED,
        },
    )
    return client


def _forced_placement_epoch(node_id: str) -> int:
    """`Placement.chain_epoch` for a forced placement.

    A forced launch takes no placement DECISION, so there is no snapshot
    to pin. Report the epoch the local `MinerCapacity` mirror was last
    refreshed at (the same number `launch_vm` would have pinned had it
    chosen this miner in the same tick), and `0` when the miner has no
    mirror row. The field is audit-only — no gate reads it — so a
    best-effort value is honest and a chain read here would only add a
    failure mode to a path that deliberately has none.

    Same answer, same reasoning, as the §25 custody hand-over needs — so
    both read it from `scheduler.service.mirror_epoch`.
    """
    from apps.scheduler.service import mirror_epoch

    return mirror_epoch(node_id)


def launch_on_named_miner(
    spec: LaunchSpec, miner: MinerIdentity, *, decided_by: Any
) -> LaunchOutcome:
    """Launch onto an OPERATOR-NAMED miner, writing the SAME durable
    ledger `launch_vm` writes for a scheduler-chosen one (P9/#18).

    `vali_create_vm` used to call [`launch_on_miner`] directly. That skips
    the scheduler — which is the whole point of the CLI, the operator has
    already decided WHERE — but it also skipped the ledger, and the ledger
    is not part of the decision. Two consequences, both closed here:

    - **no `Vm` row** ⇒ the VM is outside every control-plane sweep and
      §24 can never crypto-erase it (see [`launch_on_miner`] step 0,
      which now creates the row for every caller).
    - **no `Placement` row** ⇒ `scheduler.service.decision_inputs` sums
      `load` / `committed_memory_mb` / `committed_cpus` over ACTIVE
      placements ONLY, so a forced VM consumed real RAM and CPU on the
      miner while contributing ZERO to the #668 fit gate. The miner was
      oversubscribed by exactly the forced VMs and nothing noticed. Note
      the miner's own heartbeat cannot compensate: `reported_free_mib` is
      a DOWN-ONLY throttle capped by vali's trusted math, so a miner
      truthfully reporting less free RAM is disbelieved above vali's own
      (understated) committed figure.

    The placement is created Pending BEFORE the dispatch and settled after
    it — Bound on ACCEPTED, Failed otherwise — so a failed forced launch
    frees the slot exactly like a failed scheduled one.

    Raises [`ActivePlacementConflict`] when the vm_id already holds a
    Pending/Bound placement: the partial unique index is the same race
    boundary `/place` uses, and re-launching a vm_id that the control
    plane believes is live would be a duplicate the KBS anti-migration
    fence rejects later anyway — refusing here fails loud and early.
    """
    from django.db import IntegrityError, transaction

    from apps.scheduler.models import (
        ACTIVE_PLACEMENT_STATES,
        Placement,
        PlacementStatus,
    )

    vm = _ensure_vm_row(spec)
    node_id = miner.chain_node_id
    try:
        with transaction.atomic():
            placement = Placement.objects.create(
                vm=vm,
                vm_family=spec.tenant_id,
                owner=spec.user_id,
                resource_class=spec.flavor,
                miner_node_id=node_id,
                status=PlacementStatus.PENDING.value,
                chain_epoch=_forced_placement_epoch(node_id),
                decided_by=decided_by,
            )
    except IntegrityError as exc:
        existing = Placement.objects.filter(
            vm=vm, status__in=ACTIVE_PLACEMENT_STATES
        ).first()
        raise ActivePlacementConflict(
            f"vm {spec.vm_id!r} already has an active placement "
            f"({existing.id if existing else 'unknown'}) on miner "
            f"{existing.miner_node_id if existing else '?'} — refusing to "
            "force a second launch. Decommission it (§24) or fail the "
            "placement before re-launching this vm_id."
        ) from exc

    out = launch_on_miner(spec, miner)
    if out.disposition == ACCEPTED:
        _bind_placement(placement, out)
        # `launch_on_miner` already stamped this on ACCEPTED; repeat it
        # for the same reason `launch_vm` does — `_bind_vm_host` filters
        # on `host=""`, so a second call is a no-op and the binding is
        # never left to a single call site.
        _bind_vm_host(spec.vm_id, miner.miner_id)
    else:
        _fail_placement(placement, reason=out.emit.get("outcome", "launch-failed"))
        # Same phantom leak, same marker: a forced launch creates the `Vm`
        # row + stages the KEK exactly like a scheduled one, so a forced
        # launch that fails leaves the identical `active host=""` orphan.
        _mark_launch_abandoned(
            spec.vm_id,
            outcome=out.emit.get("outcome", "launch-failed"),
            registered=out.registered,
        )
    return out


def _persist_telemetry_source(vm_id: str, vk: bytes) -> None:
    """§23 — register the tenant VM as a telemetry source so its
    served-delivery receipts verify + accrue billable uptime.

    `vk` is the telemetry PUBLIC key derived from the lifecycle seed; the
    guest signs receipts with the matching private key it derives from the
    same seed. The served-receipt ingest gate (`apps.telemetry.service`)
    rejects a receipt whose `(tenant_vm, vm_id)` source is not registered
    here — this is that provisioning.

    Provisioned for EVERY launch path (production `launch_vm` AND the CLI
    `vali_create_vm`): the `TelemetrySource` is keyed independently by
    `(tenant_vm, vm_id)` and does NOT reference the `Vm` row, so a launch
    that skips `_ensure_vm_row` (the CLI path) still gets billing — a
    running guest that emits attested uptime must accrue regardless of how
    it was launched. `update_or_create` is idempotent: a re-launch (new
    generation) overwrites the vk in lockstep with the freshly-derived key.

    A launch provisions a FRESH telemetry key, so the source becomes a
    fresh trust anchor — we therefore also CLEAR any §9 poison counter /
    quarantine left by a PRIOR instance of this `vm_id`. Without this, a
    re-launched / re-used `vm_id` inherits a stale `quarantined_until`
    from the previous guest (whose now-superseded key made receipts fail
    verify), and the NEW guest's perfectly-valid receipts are refused
    `429 source-quarantined` until the window expires — a silent billing
    gap. Safe: this runs on a vali-AUTHORISED launch with a vali-generated
    key, never on guest input, so the poison-pill still protects vali
    against a LIVE source spamming bad receipts.
    """
    from apps.telemetry.models import SourceType, TelemetrySource

    if len(vk) != 32:
        log.warning(
            "launch: vm_id=%s telemetry vk is %d bytes (want 32) — skipping source",
            vm_id,
            len(vk),
        )
        return
    TelemetrySource.objects.update_or_create(
        source=SourceType.TENANT_VM.value,
        source_id=vm_id,
        defaults={
            "verifying_key": vk,
            "is_active": True,
            "consecutive_failures": 0,
            "failure_window_started_at": None,
            "quarantined_until": None,
        },
    )
    log.info("launch: vm_id=%s telemetry source provisioned for billing", vm_id)


def _persist_billing_binding(
    vm_id: str, node_id_hex: str, resource_class: str, lease_id: str
) -> None:
    """§23 — record the authoritative billing identity vali provisioned for
    `vm_id` (the miner `node_id`, `resource_class`, `lease_id`). The usage
    meter rejects any served receipt whose self-declared fields do not
    match this row — the guest telemetry key is extractable by in-CVM root,
    so the guest-signed payload cannot be trusted for WHAT is billed; the
    launch record is authoritative. Idempotent (a re-launch overwrites);
    best-effort (billing tolerates a missing binding by falling back to
    the legacy no-cross-check path — see the meter).

    Also opens the VM's billing CUSTODY history (`VmBillingAssignment`) —
    "from now on, `node_id_hex` is the miner PAID for this VM's uptime".
    Written here, BEFORE the domain is dispatched, so it precedes the
    guest's very first receipt window; and append-if-changed, so a
    re-launch on the SAME host (reboot-recovery re-runs this whole path)
    records no custody change. The two rows answer different questions —
    the binding is WHAT the guest may declare (immutable, it is on the
    measured cmdline), the assignment is WHO is paid (it moves on §25)."""
    import time as _time

    from apps.scheduler import billing
    from apps.scheduler.models import VmBillingAssignment, VmBillingBinding

    VmBillingBinding.objects.update_or_create(
        vm_id=vm_id,
        defaults={
            "node_id_hex": node_id_hex,
            "resource_class": resource_class,
            "lease_id": lease_id,
        },
    )
    billing.record_assignment(
        vm_id=vm_id,
        node_id_hex=node_id_hex,
        at_unix=int(_time.time()),
        reason=VmBillingAssignment.LAUNCH,
    )
    log.info(
        "launch: vm_id=%s billing binding recorded (node=%s rc=%s)",
        vm_id,
        node_id_hex[:12],
        resource_class,
    )


def _stage_lifecycle_key(mount: str, lifecycle_path: str) -> tuple[bytes, bytes]:
    """§7 — stage (or reuse) the per-VM lifecycle keypair, FIRST-WRITE-WINS.

    The KBS reads the seed at PINNED KV v2 version 1 forever
    (`kbs-core/src/release.rs` `LIFECYCLE_KEY_VERSION`), so whatever bytes
    land at version 1 are the vm_id's lifecycle identity for its lifetime —
    a later write is invisible to the KBS and only desyncs vali's persisted
    PUBLIC keys from the seed the guest actually receives.

    Order of operations:

    1. Read version 1. If present → REUSE (re-derive the vk from it).
    2. Absent → generate a fresh keypair and write it with `cas=0`
       ("create only"). A concurrent launch of the same vm_id can win
       that race — on `VaultCasConflict` fall back to reading the
       winner's version 1 and reuse it.

    Returns `(seed, vk)` — the seed is SECRET (§20: the caller derives
    from it and drops the reference; it is never logged).

    Raises `LifecycleKeygenError` (keygen/derive failure) or
    `EffectError`/`EffectUnavailable` (Vault) — the caller maps both to
    terminal outcomes.
    """
    try:
        seed = vault_kv.get_kv(mount, lifecycle_path, version=1)
    except vault_kv.VaultNotFound:
        seed = None
    if seed is not None:
        return seed, lifecycle_keygen.derive_lifecycle_vk(seed)

    kp = lifecycle_keygen.generate_lifecycle_keypair()
    try:
        vault_kv.put_kv(mount, lifecycle_path, kp.seed, cas=0)
    except vault_kv.VaultCasConflict:
        # Lost the first-write race — a concurrent launch of this vm_id
        # staged version 1 between our read and write. Its seed is the
        # identity; discard ours and reuse the winner's. A `VaultNotFound`
        # here (path exists but version 1 destroyed) is a genuine error
        # and propagates as EffectError.
        seed = vault_kv.get_kv(mount, lifecycle_path, version=1)
        return seed, lifecycle_keygen.derive_lifecycle_vk(seed)
    return kp.seed, kp.vk


def _persist_lifecycle_vk(vm_id: str, vk: bytes) -> None:
    """§7 — record the guest lifecycle PUBLIC key on the `Vm` row,
    replacing the all-zero placeholder set by `_ensure_vm_row`.

    The vk is the 32-byte Ed25519 verifying key of the version-1 staged
    seed (freshly generated on a first launch, re-derived from the
    version-1 read on a re-launch — see `_stage_lifecycle_key`).
    `_verify_ack` / `lifecycle_vk_hex()` check a guest-signed §24/§25
    StoppedAck against THIS value, so it MUST match the seed the KBS
    releases — first-write-wins staging guarantees it.

    Best-effort + idempotent, same discipline as `_persist_eol_nonce`:
    a filtered `update` no-ops when the row does not exist yet (CLI
    smoke path with no `_ensure_vm_row`); the production `launch_vm`
    creates the row first so the vk lands. We never create the row here.
    """
    from apps.lifecycle.models import Vm

    if len(vk) != 32:
        # A non-32-byte vk is a keygen bug — never stamp a malformed key
        # (it would make every ack fail closed). Log the LENGTH only.
        log.warning(
            "launch: vm_id=%s lifecycle vk is %d bytes (want 32) — skipping persist",
            vm_id,
            len(vk),
        )
        return
    updated = Vm.objects.filter(vm_id=vm_id).update(lifecycle_vk=vk)
    if updated == 0:
        # No Vm row (CLI smoke path) — nothing to stamp. The seed is
        # still staged in Vault + the cmdline carries the key path; a
        # production launch_vm run creates the row first so this is the
        # dev-only branch.
        log.info(
            "launch: vm_id=%s has no Vm row yet — lifecycle vk staged in "
            "Vault only (CLI/dev path)",
            vm_id,
        )


def _persist_eol_nonce(vm_id: str, nonce_hex: str | None) -> None:
    """Persist the launch-time EOL nonce onto the `Vm` row so
    `_verify_ack` checks the guest's StoppedAck against the SAME value
    that is baked into the measured cmdline (GAP 3).

    Best-effort + idempotent:

    - `nonce_hex` must be 64 hex chars (32 bytes); a malformed token is
      skipped with a warning (the launch still proceeds — the EOL ack
      path simply has no nonce to verify against until a re-launch, and
      `_verify_ack` fails closed in that case).
    - The Vm row may not exist yet on the CLI path
      (`vali_create_vm` skips `_ensure_vm_row`) — `update_or_create`
      then no-ops the persist (filtered update touches zero rows). The
      production `launch_vm` path always creates the row first, so the
      nonce lands. We do NOT create a Vm row here (that would duplicate
      `_ensure_vm_row`'s richer defaults); we only stamp the nonce when
      a row exists.
    """
    from apps.lifecycle.models import Vm

    if not nonce_hex or len(nonce_hex) != 64:
        log.warning(
            "launch: vm_id=%s has no valid hippius.eol_nonce token "
            "(got %r) — EOL ack verification will fail closed until re-launch",
            vm_id,
            nonce_hex,
        )
        return
    try:
        nonce_bytes = bytes.fromhex(nonce_hex)
    except ValueError:
        log.warning("launch: vm_id=%s eol_nonce is not hex — skipping persist", vm_id)
        return
    updated = Vm.objects.filter(vm_id=vm_id).update(eol_nonce=nonce_bytes)
    if updated == 0:
        # No Vm row (CLI smoke path) — nothing to stamp. The measured
        # cmdline still carries the nonce; a production launch_vm run
        # creates the row first so this branch is the dev-only case.
        log.info(
            "launch: vm_id=%s has no Vm row yet — eol_nonce baked into "
            "cmdline only (CLI/dev path)",
            vm_id,
        )


def _ensure_vm_row(spec: LaunchSpec) -> Any:
    """Get-or-create the `lifecycle.Vm` row a `Placement` FKs to.

    A launch's intended lifecycle position is Active, gen 1 (the CLI's
    default). `lifecycle_vk` starts as a 32-byte all-zero placeholder;
    `launch_on_miner` overwrites it (via `_persist_lifecycle_vk`) with
    the real §7 guest lifecycle PUBLIC key the moment it generates the
    keypair + stages the private seed in Vault — so by the time a launch
    is dispatched the row carries the real vk that `_verify_ack` checks.
    """
    from apps.lifecycle.models import Vm, VmState

    vm, _created = Vm.objects.get_or_create(
        vm_id=spec.vm_id,
        defaults={
            "lease_id": spec.lease_id,
            # #587 Phase 2 — stamp the owning tenant for the GET /v1/vm
            # display filter (getattr: older LaunchSpecs / smoke callers
            # may omit it).
            "tenant_id": getattr(spec, "tenant_id", "") or "",
            "state": VmState.ACTIVE,
            "generation": 1,
            # The guest bakes `hippius.vm_generation=_LAUNCH_GENERATION` into
            # its measured cmdline and signs EOL acks at it for life; a §25
            # migration bumps `generation` but never re-bakes, so this stays
            # put. vali verifies acks at `signing_generation`, not `generation`.
            "signing_generation": _LAUNCH_GENERATION,
            "host": "",
            "lifecycle_vk": bytes(32),
            "max_price_per_unit": spec.max_price_per_unit,
        },
    )
    return vm


def _assert_per_vm_base(vm_id: str, data_path: str, hash_path: str) -> None:
    """Raise `ValueError` unless BOTH golden base paths live inside this
    VM's own per-VM staging directory (P9/#16).

    The miner stages a golden base at `<staging-root>/<vm_id>/rootfs.img`;
    every path it will ever hand back therefore has `vm_id` as its parent
    directory name. Anything else — above all the shared, mutable
    `/var/lib/hippius-miner/rootfs.img` — means either an agent too old to
    resolve the base per-VM, or an order aimed at bytes that are not this
    VM's. Both are refused: a shared path is not an identity, and writing
    one is how a live tenant's base gets replaced underneath it.

    This is a SHAPE check on vali's side. It is not the security boundary
    — the miner verifies the base's sha256 before staging it and the SNP
    measurement binds the dm-verity root — it is what stops a silent
    fallback from re-introducing the shared path.
    """
    import posixpath

    for label, path in (("rootfs_data_path", data_path), ("rootfs_hash_path", hash_path)):
        if not path:
            raise ValueError(
                f"golden launch resolved no {label}: the miner-agent did not "
                f"return a per-VM staged base (agent too old?)"
            )
        parent = posixpath.basename(posixpath.dirname(posixpath.normpath(path)))
        if parent != vm_id:
            raise ValueError(
                f"golden {label}={path!r} is not inside this VM's own staging "
                f"directory (parent {parent!r} != vm_id {vm_id!r}) — refusing "
                f"to launch against a shared, mutable base image"
            )


def _record_base_image(
    spec: LaunchSpec, *, rootfs_data_path: str, rootfs_hash_path: str
) -> None:
    """Record WHICH base image this VM was dispatched against, by content.

    Written only on an ACCEPTED dispatch, so a row means "this VM really
    was launched onto these bytes". `update_or_create` because a relaunch
    (reboot-recovery, a re-placed launch) legitimately re-answers the
    question — and, when it moves the VM to a newer bake, the row is the
    only place that change is visible.

    Best-effort by design: the launch has already been accepted by the
    miner by the time we get here, and the record is an OBSERVATION that
    no delete path reads (see `VmBaseImage`'s docstring). Failing the
    launch over a bookkeeping write would be strictly worse than a
    missing row.
    """
    from apps.lifecycle.models import VmBaseImage

    try:
        VmBaseImage.objects.update_or_create(
            vm_id=spec.vm_id,
            defaults={
                "disk_mode": spec.disk_mode,
                "bake_id": getattr(spec, "bake_id", "") or "",
                "image_name": getattr(spec, "image_name", "") or "",
                "rootfs_img_sha256_hex": spec.rootfs_img_sha256_hex or "",
                "rootfs_verity_sha256_hex": spec.rootfs_verity_sha256_hex or "",
                "verity_root_hash_hex": spec.verity_root_hash_hex or "",
                "rootfs_data_path": rootfs_data_path,
                "rootfs_hash_path": rootfs_hash_path,
            },
        )
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("launch: base-image record failed for vm_id=%s: %s", spec.vm_id, exc)


def _bind_vm_host(vm_id: str, node_id: str) -> None:
    """Stamp the placed miner's `node_id` onto the `Vm.host` on a
    successful launch.

    `vm.host` is the bound-miner pointer the §24 decommission destroy
    order + EOL relay AND the §25 migration source-routing all resolve
    from (`MinerIdentity` primary key). Filter on `host=""` so this only
    fills the empty placeholder `_ensure_vm_row` created — a §25
    migrate-activation (or a re-adopt) that already advanced `host` is
    NEVER clobbered by a late/duplicate launch tick. A lost filter (host
    already set) is a no-op, not an error.

    Binding a host is also what UN-abandons the row: the abandoned-launch
    marker means "the last launch for this vm_id gave up without a host",
    and this is the exact instant that stops being true. Cleared in the
    SAME UPDATE as `host` so a reaper can never observe a bound row that
    still looks abandoned. This is the guard against the cross-call
    re-placement hazard: miner A abandons the launch, an operator clears
    the KBS registration and re-launches onto miner B — B's bind wipes A's
    marker, so A's failure can never reap the KEK B's guest is using.
    """
    from apps.lifecycle.models import Vm

    Vm.objects.filter(vm_id=vm_id, host="").update(
        host=node_id,
        launch_abandoned_at=None,
        launch_abandoned_outcome="",
        launch_abandoned_registered=False,
    )


def _mark_launch_abandoned(
    vm_id: str, *, outcome: str, registered: bool
) -> None:
    """Record that a launch for `vm_id` TERMINATED without binding a host.

    `launch_on_miner` creates the `Vm` row before any effect (P9/#18), so a
    launch that then fails leaves that row `state=active host=""` — with a
    live per-VM Vault-Transit KEK (staged at step 2, or at intake for the
    golden async path) and no VM anywhere. Every sweep that filters
    `exclude(state='destroyed')` counts it as a running tenant, and nothing
    reaps it: this marker is what makes the row DISTINGUISHABLE from a
    launch that is merely still in flight (the row looks identical for the
    whole preflight window, which can be 30 minutes).

    Deliberately NOT a state change. Rolling the row straight to
    `destroyed` here would tombstone a VM whose KEK is still live — §24's
    invariant is that the tombstone FOLLOWS the erase, never precedes it —
    and rolling it to `decommissioning` would fabricate a job that does not
    exist. The honest record is "this launch gave up at T with outcome X,
    having (not) reached the KBS register"; `service.sweep_abandoned_
    launches` decides, later and on live evidence, what to do about it.

    Filters:

    - `host=""` — a bound VM is not abandoned. This is what keeps a
      reboot-recovery relaunch (which calls `launch_on_miner` directly for
      an already-bound VM) from ever marking a live tenant's row.
    - `state=active` — `_destroy_vm` clears `host` on the tombstone, so a
      re-launch attempt against an already-Destroyed vm_id must not
      resurrect it as a fresh phantom.
    """
    from django.utils import timezone

    from apps.lifecycle.models import Vm, VmState

    Vm.objects.filter(
        vm_id=vm_id, host="", state=VmState.ACTIVE.value
    ).update(
        launch_abandoned_at=timezone.now(),
        launch_abandoned_outcome=(outcome or "launch-failed")[:64],
        launch_abandoned_registered=bool(registered),
    )


def _bind_placement(placement: Any, out: LaunchOutcome) -> None:
    """CAS Pending→Bound for an accepted launch.

    `kbs_release_ref` records the dispatch evidence (the accepted order +
    ticket) as the §23 audit reference. A lost CAS (concurrent /fail or
    re-eval drain) is logged, not raised — the launch itself succeeded.
    """
    from django.utils import timezone

    from apps.scheduler.models import Placement, PlacementStatus

    ref = f"launch-accepted:{out.ticket_id}" if out.ticket_id else "launch-accepted"
    updated = Placement.objects.filter(
        id=placement.id,
        version=placement.version,
        status=PlacementStatus.PENDING.value,
    ).update(
        status=PlacementStatus.BOUND.value,
        version=placement.version + 1,
        bound_at=timezone.now(),
        kbs_release_ref=ref[:256],
    )
    if not updated:
        log.warning(
            "launch bind lost the CAS for placement=%s (concurrent "
            "transition) — launch dispatched, placement left as-is",
            placement.id,
        )


def _fail_placement(placement: Any, *, reason: str) -> None:
    """CAS Pending→Failed for a rejected / errored launch attempt."""
    from django.utils import timezone

    from apps.scheduler.models import Placement, PlacementStatus

    Placement.objects.filter(
        id=placement.id,
        version=placement.version,
        status=PlacementStatus.PENDING.value,
    ).update(
        status=PlacementStatus.FAILED.value,
        version=placement.version + 1,
        failed_at=timezone.now(),
        reason=(reason or "launch-failed")[:256],
    )
