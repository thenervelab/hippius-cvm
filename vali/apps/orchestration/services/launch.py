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
from django.utils import timezone

from apps.cdn import identity as cdn_identity
from apps.miners.models import MinerIdentity
from apps.network import net_policy
from apps.orchestration import effects, kbs_admin, order_dispatch, power_policy
from apps.orchestration.effects import EffectError, EffectUnavailable
from apps.orchestration.services import (
    allowlist_pin,
    customer_keys,
    launch_record,
    lifecycle_keygen,
    register_gate,
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
from apps.telemetry import guest_resources

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

#: The RETRIABLE outcome of a pin that waited out `PIN_LOCK_TIMEOUT_S`
#: behind other pins — vali-side, so the miner is not excluded for it.
ALLOWLIST_PIN_BUSY = "allowlist-pin-busy"

# vm_id is interpolated into Vault KV paths — charset-lock it (no `../`).
# Mirrors `apps.orchestration.launch_jobs._VM_ID_RE` + tenant_bake.
_VM_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")

# ── cmdline token keys (kept in sync with the keyscript parser) ──────
_LUKS_HEADER_CMDLINE_KEY = "hippius.luks_header_sha256"
_ROOTFS_SHA_CMDLINE_KEY = "hippius.rootfs_sha256"
_DISK_GB_CMDLINE_KEY = "hippius.disk_gb"

# ── M0 untrusted-miner guest hardening (measured) ────────────────────
# The miner writes the libvirt domain XML, and only OVMF + kernel + initrd
# + cmdline are in the SNP launch measurement. Everything else the miner
# adds — SMBIOS type 11 OEM strings, `-fw_cfg opt/...` blobs — is fetched
# by the guest AFTER launch and is NOT measured. systemd imports
# credentials (`io.systemd.credential:*`: root ssh keys, `tmpfiles.extra`,
# `fstab.extra`) from exactly those unmeasured surfaces by default, which
# is a host->guest root channel independent of cloud-init and of any guest
# agent. `systemd.import_credentials=no` on the MEASURED cmdline is the
# only reliable kill switch (there is no config-file equivalent), so vali
# bakes it into every launch. Purely a hardening flag; the guest keyscript
# / initramfs parser ignores it, and it auto-pins into the §22 allowlist
# like every other measured token. See scripts/tenant-image-bake.sh (the
# cloud-init + guest-agent half of the same M0 hardening).
_IMPORT_CREDENTIALS_CMDLINE_KEY = "systemd.import_credentials"
_IMPORT_CREDENTIALS_VALUE = "no"

# Attested guest resources (`apps.telemetry.guest_resources`): SNP measures
# the vCPU count but not the RAM, so a keepalive image reads both and
# attests them in its live attestation — only when this MEASURED token
# says so (`scripts/guest/hippius-keepalive-start`). Gated on
# `VALI_GUEST_ATTEST_RESOURCES`, which goes on once the KBS accepts the
# field; measured, so the miner cannot strip it. An older image ignores it.
_ATTEST_RESOURCES_CMDLINE_KEY = "hippius.attest_resources"

# OrderTicket lifecycle perm (`kbs_core::lifecycle::SUPERSEDE_PERM`): the
# KBS makes the registered launch the VM's current one at register. An
# older KBS ignores unknown perms.
_SUPERSEDE_PERM = "supersede"
# `accept_memory=eager` (kernel >= 6.5; ignored before): the guest accepts —
# PVALIDATEs — every page of its RAM at boot instead of on first use, so the
# host must back the whole flavor before the guest runs: no lazily-promised
# memory a miner could overcommit across VMs. Gated on
# `VALI_GUEST_ACCEPT_MEMORY_EAGER` (boot time grows with the RAM size).
_ACCEPT_MEMORY_CMDLINE_KEY = "accept_memory"

# x86 COMMAND_LINE_SIZE is 2048 bytes INCLUDING the NUL; the kernel
# SILENTLY truncates a longer cmdline while SEV measures the whole string.
# And OVMF prepends `initrd=initrd ` (14 bytes) to the measured cmdline
# before the kernel sees it, so a MEASURED cmdline past 2033 bytes would be
# measured (and recomputed by vali / the KBS / the guardian) yet never
# reach the guest's /proc/cmdline whole — the guest would boot a different
# cmdline than was measured. Mirrors
# `hippius_types::guardian::MAX_MEASURED_CMDLINE_LEN`. We validate the
# FINAL augmented cmdline against this before preflight, fail-closed, in
# every key mode.
_MAX_CMDLINE_BYTES = customer_keys.MAX_MEASURED_CMDLINE_LEN

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


def _cmdline_token_key(token: str) -> str:
    """The key of a `key=value` (or bare `key`) cmdline token — the text
    before the FIRST `=`. Exact, so `rd.systemd.import_credentials=no` and
    `systemd.import_credentials=no` are distinct keys, not a substring
    match."""
    return token.split("=", 1)[0]


def _force_cmdline_token(cmdline: str, key: str, value: str | None) -> str:
    """The cmdline with exactly one `<key>=<value>` (or none at all when
    `value` is `None`), whatever the base cmdline carried — the token is
    vali's decision, never the base cmdline's. Matched on the exact key.
    Unchanged bytes when there is nothing to remove or add; appended after
    a single space otherwise, as `_augment_guest_hardening` does."""
    tokens = cmdline.split()
    if not any(_cmdline_token_key(tok) == key for tok in tokens):
        return cmdline if value is None else f"{cmdline.rstrip()} {key}={value}"
    kept = [tok for tok in tokens if _cmdline_token_key(tok) != key]
    if value is not None:
        kept.append(f"{key}={value}")
    return " ".join(kept)


def _cmdline_has_token(cmdline: str, key: str, value: str) -> bool:
    return f"{key}={value}" in cmdline.split()


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


def _augment_guest_hardening(cmdline: str) -> str:
    """FORCE the M0 untrusted-miner guest-hardening token(s) on the
    MEASURED cmdline.

    Today that is `systemd.import_credentials=no`: it disables systemd's
    native import of credentials (`io.systemd.credential:*` — root ssh
    keys, `tmpfiles.extra`, `fstab.extra`) from the SMBIOS type 11 / fw_cfg
    surfaces the untrusted miner controls and which are NOT in the SNP
    launch measurement. The kernel cmdline is the only reliable kill
    switch (no config-file equivalent), and it IS measured, so this is
    trustworthy. Disk-mode-independent (every tenant gets it).

    Unlike the plain `_augment_cmdline_with_token`, this FORCES the value:
    a security kill switch must not be defeated by a base cmdline that
    already carries `systemd.import_credentials=yes` (or a duplicate). Any
    existing `systemd.import_credentials=` token is dropped and a single
    canonical `=no` is appended. The match is on the EXACT key, so the
    dracut/initramfs variant `rd.systemd.import_credentials=` and any other
    lookalike are left untouched. Deterministic ⇒ byte-stable across
    relaunch/§25 (the same base cmdline always yields the same output; the
    production base cmdline never carries the token, so the common path is
    a plain append that preserves spacing).
    """
    key = _IMPORT_CREDENTIALS_CMDLINE_KEY
    canonical = f"{key}={_IMPORT_CREDENTIALS_VALUE}"
    tokens = cmdline.split()
    if not any(_cmdline_token_key(tok) == key for tok in tokens):
        # Common case: nothing to override — append, preserving the base
        # cmdline's original internal spacing.
        return f"{cmdline.rstrip()} {canonical}"
    kept = [tok for tok in tokens if _cmdline_token_key(tok) != key]
    kept.append(canonical)
    return " ".join(kept)


def _spec_binding(spec: LaunchSpec) -> customer_keys.GuardianBinding | None:
    """The spec's customer-keys binding (`None` ⇒ M0), validated by the
    guardian cmdline grammar. M1/M2 are golden-only: a legacy rootfs is
    `luksFormat`ted by the online baker, which holds that KEK, so no
    customer key could ever protect it. Caller-fixable ⇒ `LaunchConfigError`.
    """
    try:
        binding = customer_keys.binding_of(spec)
    except customer_keys.CustomerKeysError as exc:
        raise LaunchConfigError(str(exc)) from exc
    if binding is not None and spec.disk_mode != _DISK_MODE_GOLDEN_VERITY:
        raise LaunchConfigError(
            f"customer-keys-golden-only: key_mode={binding.mode} requires "
            f"disk_mode={_DISK_MODE_GOLDEN_VERITY}"
        )
    return binding


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
    # The tenant DATA disk (GiB) when it is not `flavor`'s: a resized VM
    # keeps the disk it was launched with — LUKS2 + dm-integrity cannot be
    # resized — so its measured `hippius.disk_gb` and the LaunchOrder's
    # `data_disk_size_gb` stay pinned while vCPU/RAM follow the flavor.
    # 0 ⇒ the flavor's own `disk_gb` (every launch).
    data_disk_size_gb: int = 0
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
    # Region constraint (ISO 3166-1 alpha-2, uppercased at intake). `""` ⇒
    # unconstrained, and it MUST default: reboot-recovery rebuilds a spec
    # from a `spec_json` written before this field existed, and a required
    # field would make every such VM unrecoverable. Consumed by gate (f)
    # in `decide_placement` via `service.placement_arguments`.
    region: str = ""
    # Anti-affinity group (`[a-z0-9-]{1,64}`, validated at intake), stamped
    # on the Vm row at creation. Defaulted for the same reason as `region`.
    placement_group: str = ""
    # Customer-held disk keys (`services.customer_keys`). `hippius` (M0)
    # with empty guardian fields is today's launch, byte for byte; `split`
    # (M1) / `customer` (M2) need both guardian fields, validated by the
    # guardian cmdline grammar. Defaulted for the same reason as `region`:
    # reboot-recovery rebuilds specs from old `spec_json`s. Pinned on the
    # `Vm` row at first launch and immutable after.
    key_mode: str = "hippius"
    guardian_endpoint: str = ""
    guardian_pubkey: str = ""
    # Guest-poweroff policy (`apps.orchestration.power_policy`): `restart`
    # (default — and the only value an old `spec_json` can mean) or `stop`.
    # `stop` limits placement to miners whose agent knows it (gate (l)) and
    # rides the launch order; intake writes the key into `spec_json` only
    # for `stop`. A relaunch passes the VM's CURRENT choice instead.
    on_guest_poweroff: str = "restart"


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


def check_netbird_hostname(
    *, enable: bool, hostname_template: str, vm_id: str
) -> str | None:
    """INTAKE-only rule: the NetBird hostname must render to exactly
    `hippius-tenant-<vm_id>`. Returns an error message, or `None`.

    Tenant peers are persistent, and the only way vali finds one to delete
    (§24 `revoke_netbird`, the peer janitor) is that name. A custom
    template would enrol a peer nothing ever revokes; one like
    `hippius-tenant-{vm_id}-x` would also make the peer read, to the
    janitor, as belonging to another vm_id. No caller sends one (the
    backend and the synthetic monitor use the default).

    Deliberately NOT applied by [`launch_on_miner`]: a relaunch rebuilds its
    spec from the recorded launch, and a VM launched before this rule with
    a custom template must still come back up.
    """
    if not enable:
        return None
    try:
        rendered = hostname_template.format(vm_id=vm_id)
    except (KeyError, IndexError, ValueError) as exc:
        return f"netbird_hostname_template only supports {{vm_id}} ({exc})"
    if rendered != effects.tenant_peer_name(vm_id):
        return (
            "netbird_hostname_template must render to "
            f"{effects.tenant_peer_name('{vm_id}')!r} — the name the VM's "
            "NetBird peer is revoked by"
        )
    return None


def _netbird_key_is_persistent(vm_id: str) -> bool:
    """Whether this launch's NetBird setup key may enrol a PERSISTENT peer.

    Only a FIRST launch's may. A relaunch (power start, reboot-recovery —
    both rebuild their spec from the VM's SUCCEEDED `LaunchJob`) boots the
    same overlay, so the guest still holds its NetBird identity and LOGS IN
    with it; the fresh key is never used. It is still a live credential in
    a userdata the guest's root can read, and a persistent peer enrolled
    with it — under any hostname — would outlive the VM, because revoke and
    the janitor find peers by `hippius-tenant-<vm_id>` only. Minting it
    ephemeral keeps such a peer to the old ~10-min-offline lifetime. (A
    golden relaunch whose guest provably holds its identity gets no key at
    all — `_netbird_relaunch_needs_no_key`.)

    The discriminator is "a launch of this vm_id already SUCCEEDED" —
    exactly the record both relaunch paths require, and read here so every
    caller of `launch_on_miner` is covered without passing a flag. A first
    launch's own job is still `running`; a first launch that failed and is
    retried (as a new job, or a re-place / same-miner retry inside
    `launch_vm`) has no succeeded job and stays persistent.

    Trade-off: a VM whose FIRST boot never enrolled gets its peer from a
    relaunch key, i.e. an ephemeral one — today's behaviour for that VM, no
    worse. Making that case persistent would hand a tenant who withholds
    enrolment a persistent spare key on every stop/start.
    """
    from apps.orchestration.models import LaunchJob, LaunchJobState

    return not LaunchJob.objects.filter(
        vm_id=vm_id, state=LaunchJobState.SUCCEEDED.value
    ).exists()


#: What a relaunch that needs no NetBird key gets in place of one. A valid
#: UUID (so `netbird up --setup-key-file` parses it) that NetBird never
#: issued: the guest's `netbird up` LOGS IN with the identity it holds, and
#: the client only sends a setup key when the management server says the
#: peer is unknown — which is exactly the case this placeholder is never
#: handed to.
NO_NETBIRD_SETUP_KEY = "00000000-0000-0000-0000-000000000000"

#: Upper bound on a relaunch key's lifetime (see `_netbird_key_ttl_s`).
RELAUNCH_NETBIRD_KEY_TTL_S = 600


def _netbird_relaunch_needs_no_key(spec: LaunchSpec, *, require_existing_disks: bool) -> bool:
    """Whether this launch's guest provably already holds its NetBird
    identity, so it is handed NO usable setup key.

    The key rides the userdata, and the guest's root reads it back: from
    the released seed and from cloud-init's own copies under
    `/var/lib/cloud` (an M0 guest re-applies the userdata every boot). A
    first launch's key is consumed by the enrolment (`usage_limit=1`), so
    that copy is dead. A relaunch's key is NOT — the guest never uses it —
    and stayed a live credential for its whole TTL: one more peer in the
    tenant group, enrolled from any machine. This closes that window.

    All three must hold, each for a reason:
    - `require_existing_disks` — a relaunch (reboot-recovery, power start,
      reboot) the miner refuses (`relaunch-disks-missing`) unless it boots
      the VM's existing disks; a re-place or a retried first launch may
      boot a blank overlay. (§25 mints nothing: it re-binds the userdata
      already staged.)
    - golden — the overlay upper is the guest's whole writable root, so
      `/var/lib/netbird` (its WireGuard identity) is on what the miner
      guarantees. A legacy VM's identity lives on the order-staged image.
    - one of the VM's BOUND peers is persistent AND still exists at NetBird
      — asked every time, never taken from vali's records alone: a peer
      deleted at NetBird (an admin, a cleanup, a revoke) leaves the guest
      an identity the management server rejects, and a guest handed no key
      then is off the mesh for good. Persistent means NetBird's record says
      `ephemeral: false` (a peer enrolled ephemeral and flipped since), or
      it says nothing and vali minted the peer's key persistent; a record
      saying `ephemeral: true` is never proof. Only bound peers count — a
      peer's NAME is the hostname the guest sent, any tenant can send any
      VM's. A NetBird failure proves nothing: a key is minted (fail-open
      toward connectivity, at the relaunch TTL).
    """
    if not require_existing_disks or spec.disk_mode != _DISK_MODE_GOLDEN_VERITY:
        return False
    from apps.lifecycle.models import VmNetbirdKey

    from ..netbird_binding import bindings_for

    peer_ids = bindings_for([spec.vm_id])[spec.vm_id].ranked
    if not peer_ids:
        return False
    minted_persistent = set(
        VmNetbirdKey.objects.filter(vm__vm_id=spec.vm_id, persistent=True)
        .exclude(peer_id="")
        .values_list("peer_id", flat=True)
    )
    try:
        peers = effects.list_netbird_peers()
    except EffectError as exc:  # EffectUnavailable included
        log.warning(
            "launch: vm_id=%s NetBird peer listing failed (%s) — cannot prove the "
            "guest's identity, minting a relaunch key",
            spec.vm_id,
            exc,
        )
        return False
    for peer_id in peer_ids:
        peer = effects.peer_by_id_from_listing(peers, peer_id)
        if peer is None or peer.ephemeral is True:
            continue
        if peer.ephemeral is False or peer_id in minted_persistent:
            return True
    return False


def _netbird_key_ttl_s(spec: LaunchSpec, *, persistent: bool) -> int:
    """A first launch's key keeps the caller's TTL: a slow first boot must
    still enrol. A relaunch's is capped at `RELAUNCH_NETBIRD_KEY_TTL_S` —
    it is only ever needed by a guest re-enrolling during that boot, and it
    sits readable in the guest's cloud-init state for as long as it lives
    (`netbird_binding.revoke_unneeded_relaunch_keys` deletes it sooner once
    the guest is back on its own identity)."""
    ttl = int(spec.netbird_key_ttl_seconds)
    return ttl if persistent else min(ttl, RELAUNCH_NETBIRD_KEY_TTL_S)


def _record_netbird_key(
    vm_row: Any, minted: effects.MintedSetupKey, *, persistent: bool, ttl_s: int
) -> None:
    """Record a minted setup key's id (never the key) against its VM."""
    from datetime import timedelta

    from django.utils import timezone

    from apps.lifecycle.models import VmNetbirdKey

    VmNetbirdKey.objects.create(
        vm=vm_row,
        setup_key_id=minted.id,
        persistent=persistent,
        expires_at=timezone.now() + timedelta(seconds=ttl_s),
    )


def data_disk_gb(spec: LaunchSpec) -> int:
    """The VM's DATA disk (GiB): pinned on the spec (a resized VM), else
    its flavor's."""
    from apps.orchestration.services.flavors import resolve_flavor

    return int(spec.data_disk_size_gb) or resolve_flavor(spec.flavor).data_disk_size_gb


def _derive_measured_cmdline(
    spec: LaunchSpec,
    binding: customer_keys.GuardianBinding | None,
    *,
    disk_gb: int,
    node_id_hex: str,
    validator_nonce_hex: str,
    telemetry_epoch: int,
    eol_nonce_hex: str,
    cdn_node: bool = False,
) -> str:
    """The MEASURED cmdline of a launch of `spec`, from its per-launch
    inputs. `cdn_node` (a CDN node's launch, `apps.cdn.identity`) adds the
    CDN role tokens. Pure: no Vault, no DB write, no randomness. `launch_on_miner`
    calls it with the real values; `_ensure_vm_row` calls it with
    same-length stand-ins BEFORE it pins a new M1/M2 row (see
    `_refuse_measured_cmdline_before_pin`), so a cmdline that would be
    refused never burns the vm_id. Raises `LaunchConfigError` on a
    malformed disk binding."""
    # ── 4. cmdline augmentation (#296 / rootfs / #365 / golden-bake) ─
    # Disk-integrity binding is mode-gated: legacy_luks → the LUKS-header
    # MAC token (byte-identical to today); golden_verity_overlay → the
    # dm-verity golden base's root hash (the luks token is dropped).
    augmented_cmdline = _augment_disk_binding(spec.cmdline, spec)
    # M0 untrusted-miner hardening: disable systemd credential import from
    # the unmeasured SMBIOS/fw_cfg surfaces the miner controls. Applies to
    # every disk_mode.
    augmented_cmdline = _augment_guest_hardening(augmented_cmdline)
    # Forced both ways: a base-cmdline `=1` must not turn the attestation on
    # before the KBS accepts it, nor a `=0` keep it off once vali asks.
    augmented_cmdline = _force_cmdline_token(
        augmented_cmdline,
        _ATTEST_RESOURCES_CMDLINE_KEY,
        "1" if guest_resources.attest_on_launch() else None,
    )
    augmented_cmdline = _force_cmdline_token(
        augmented_cmdline,
        _ACCEPT_MEMORY_CMDLINE_KEY,
        "eager" if guest_resources.accept_memory_eagerly() else None,
    )
    # The CDN role (CDN plan V2), forced both ways: a CDN node's guest-release
    # writes the KBS-released fleet keyring to the measured directory, and a
    # tenant cmdline never carries either token, whatever its base said.
    augmented_cmdline = _force_cmdline_token(
        augmented_cmdline, cdn_identity.CDN_NODE_CMDLINE_KEY, "1" if cdn_node else None
    )
    augmented_cmdline = _force_cmdline_token(
        augmented_cmdline,
        cdn_identity.CDN_FLEET_DIR_CMDLINE_KEY,
        cdn_identity.CDN_FLEET_DIR if cdn_node else None,
    )
    if spec.rootfs_sha256_hex:
        augmented_cmdline = _augment_cmdline_with_token(
            augmented_cmdline, _ROOTFS_SHA_CMDLINE_KEY, spec.rootfs_sha256_hex
        )
    augmented_cmdline = _augment_cmdline_with_token(
        augmented_cmdline, _DISK_GB_CMDLINE_KEY, str(disk_gb)
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
        augmented_cmdline, _NODE_ID_CMDLINE_KEY, node_id_hex
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
        validator_nonce_hex,
    )
    augmented_cmdline = _augment_cmdline_with_token(
        augmented_cmdline,
        _TELEMETRY_EPOCH_CMDLINE_KEY,
        str(telemetry_epoch),
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
    augmented_cmdline = _augment_cmdline_with_token(
        augmented_cmdline, _EOL_NONCE_CMDLINE_KEY, eol_nonce_hex
    )

    # ── 4c. Customer-held keys — the MEASURED guardian binding. Appended
    #        here, BEFORE the length check, the preflight and the C2
    #        recompute below, so the tokens are in the digest vali
    #        recomputes, the miner reports and the allowlist pins — and in
    #        what the guardian recomputes. M0 appends nothing
    #        (byte-identical cmdline).
    return customer_keys.augment_cmdline(augmented_cmdline, binding)


def _measured_cmdline_refusal(
    cmdline: str, binding: customer_keys.GuardianBinding | None
) -> tuple[str, str] | None:
    """`(outcome, message)` if the FINAL measured `cmdline` must not be
    minted, else `None`."""
    try:
        # No cloud-init `cc:` / `end_cc` marker, whatever put it there (an
        # input, or a config value an `_augment_*` step appended) — checked
        # first so the refusal names it. Then the FINAL cmdline must carry
        # exactly the spec's binding: an operator-baked token that disagrees
        # (augmentation never overrides one), a guardian token on an M0
        # cmdline, or anything else the guest's grammar refuses (incl. the
        # other cloud-init directives) refuses here.
        customer_keys.check_cloud_init_markers(binding, measured_cmdline=cmdline)
        customer_keys.check_cmdline(cmdline, binding)
    except customer_keys.CustomerKeysError as exc:
        return "customer-keys-cmdline-refused", str(exc)
    # Fail-closed on an over-long MEASURED cmdline: the guest's
    # /proc/cmdline is OVMF's 14-byte `initrd=initrd ` + this, and the
    # kernel keeps 2047 bytes of it while SEV measures the whole string, so
    # a token past 2033 would boot a cmdline different from the one
    # measured/pinned.
    cmdline_len = len(cmdline.encode("utf-8"))
    if cmdline_len > _MAX_CMDLINE_BYTES:
        return (
            "cmdline-too-long",
            f"measured cmdline is {cmdline_len} bytes (> {_MAX_CMDLINE_BYTES}); "
            "with OVMF's initrd= prefix the kernel would truncate it below the "
            "measured length",
        )
    # H5b: the guest refuses to boot a /proc/cmdline of >= 2022 bytes
    # (measured >= 2008) that has no `hippius.key_mode` token (it cannot
    # tell an M0 launch from an M1/M2 one whose token the EFI stub cut
    # off). M1/M2 always carry the token, so this band is only reachable by
    # M0: refuse it here rather than dispatch a VM that can never boot.
    if customer_keys.cmdline_may_hide_key_mode(cmdline):
        return (
            "cmdline-too-long",
            f"measured cmdline is {cmdline_len} bytes (>= "
            f"{customer_keys.KEY_MODE_TRUNCATION_FLOOR_MEASURED}) with no "
            f"{customer_keys.KEY_MODE_TOKEN} token; the guest refuses to boot "
            "such a cmdline (a key-mode token may have been truncated off)",
        )
    return None


#: Same-length stand-ins for the per-launch cmdline values that are not
#: known before the pin (the miner's 64-hex `chain_node_id`, the two
#: 32-byte nonces). Hex, like the real values, so they add no marker.
#: `launch_on_miner` refuses an M1/M2 launch on a miner whose
#: `chain_node_id` is not 64 lowercase hex, so the stand-in is exact.
_PRE_PIN_HEX64 = "0" * 64
#: The billing epoch is an UPPER BOUND, not a sample: `launch_vm` refreshes
#: the cached chain epoch between the pin and `launch_on_miner`, so a
#: sample could gain digits. 20 digits = u64::MAX, so the pre-pin length is
#: never shorter than the real one (at worst it refuses an M1/M2 cmdline
#: within ~18 bytes of the 2033-byte measured limit that would have fitted:
#: that margin is the epoch's growth room, and it moved down with the cap).
_PRE_PIN_EPOCH_UPPER_BOUND = 2**64 - 1
#: What a miner's `chain_node_id` must be for an M1/M2 launch.
_CHAIN_NODE_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def _refuse_miner_for_customer_keys(
    binding: customer_keys.GuardianBinding | None, miner: MinerIdentity
) -> None:
    """The miner's `chain_node_id` goes into the measured cmdline, and the
    pre-pin check stands in for it with 64 hex (it is not known when
    `launch_vm` pins; the scheduler only picks miners by their 64-hex
    on-chain node id). An M1/M2 launch therefore requires exactly that
    shape, so nothing the miner contributes can differ from what the pin
    checked. Every caller that knows the miner runs this BEFORE it pins a
    row or writes a placement. No-op for M0."""
    if binding is not None and not _CHAIN_NODE_ID_RE.match(miner.chain_node_id or ""):
        raise LaunchConfigError(
            f"miner {miner.miner_id!r} has no 64-hex chain_node_id; "
            f"key_mode={binding.mode} launches only on a registered compute node"
        )


def _refuse_measured_cmdline_before_pin(
    spec: LaunchSpec, binding: customer_keys.GuardianBinding | None
) -> None:
    """Customer-held keys: run the measured-cmdline refusals BEFORE a new
    M1/M2 `Vm` row pins the mode, so a cmdline that could never be minted
    (a `cc:` / `end_cc` marker a config-derived `_augment_*` value put
    there, a guardian binding the base cmdline contradicts, a length past
    the limit) refuses the launch without burning the vm_id.

    `launch_on_miner` runs the same refusals on the real cmdline; this is
    the same derivation with same-length stand-ins for the values not known
    yet, and an upper bound for the billing epoch. No-op for M0."""
    if binding is None:
        return

    eol_nonce_hex = (
        spec.eol_nonce_hex
        or _extract_cmdline_token(spec.cmdline, _EOL_NONCE_CMDLINE_KEY)
        or _PRE_PIN_HEX64
    )
    cmdline = _derive_measured_cmdline(
        spec,
        binding,
        disk_gb=data_disk_gb(spec),
        node_id_hex=_PRE_PIN_HEX64,
        validator_nonce_hex=_PRE_PIN_HEX64,
        telemetry_epoch=_PRE_PIN_EPOCH_UPPER_BOUND,
        eol_nonce_hex=eol_nonce_hex,
    )
    refusal = _measured_cmdline_refusal(cmdline, binding)
    if refusal is not None:
        raise LaunchConfigError(f"{refusal[0]}: {refusal[1]}")


def launch_on_miner(
    spec: LaunchSpec,
    miner: MinerIdentity,
    *,
    generation: int = _LAUNCH_GENERATION,
    require_existing_disks: bool = False,
    supersede: bool = False,
    launch_ref: str = "",
) -> LaunchOutcome:
    """Run the full launch choreography for ONE miner. Never raises for a
    step failure — returns a typed [`LaunchOutcome`]; raises
    [`LaunchConfigError`] only for caller-fixable misconfiguration.

    `supersede` (a resize relaunch, after vali confirmed the VM stopped)
    mints the ticket with the `supersede` lifecycle perm: the KBS makes
    this launch the VM's current one at register, so every earlier launch's
    ticket — the pre-resize one — is refused before this one is even
    dispatched (`kbs_core::lifecycle::check_current_launch`). Every other
    launch becomes current at its first release: a same-miner retry
    answered `already-launched` must not strand the domain that runs.

    `generation` is the KBS generation the ticket is minted at: the launch
    generation for a fresh VM, the VM's CURRENT generation for a relaunch
    of one that §25 moved (its KEK is releasable only there). The measured
    cmdline keeps the launch generation either way — the guest signs its
    acks at it for life, and a §25 destination boots the same measurement.

    `require_existing_disks` — set by a RELAUNCH of a VM that already ran
    on `miner`: the miner refuses (class `relaunch-disks-missing`) rather
    than create blank per-VM disks. See `order_dispatch.build_launch_payload`.

    `launch_ref` is written on this launch's `MeasurementLedger` row (a
    guest upgrade links its attempt to its pin by it).
    """
    # vm_id is interpolated into Vault KV paths below — charset-lock it so
    # neither the CLI nor the API can path-traverse out of the per-VM
    # Vault namespace. (The API also rejects this earlier, at intake.)
    if not _VM_ID_RE.fullmatch(spec.vm_id):
        raise LaunchConfigError(
            "vm_id must match [a-z0-9-]{1,64} (no path separators)"
        )
    if not miner.netbird_ip:
        raise LaunchConfigError(
            f"miner {miner.miner_id!r} has no netbird_ip — register via "
            "PR #120 first"
        )
    # Customer-held keys: the binding (None ⇒ M0) — grammar-validated and
    # golden-only. M2 has NO Hippius-held KEK, so a caller handing one in
    # is refused before anything is staged.
    binding = _spec_binding(spec)
    if not customer_keys.releases_kek(binding) and spec.kek_bytes is not None:
        raise LaunchConfigError(
            "key_mode=customer holds no Hippius disk KEK — refusing kek_bytes"
        )
    _refuse_miner_for_customer_keys(binding, miner)
    # The guest-poweroff policy this order carries — refused here, before
    # any row, secret or pin exists, for a first launch of a `stop` VM onto
    # a miner whose agent cannot honour it (gate (l) keeps those out; this
    # backstops every other caller). Never a silent `restart`.
    try:
        poweroff_field = power_policy.launch_field(
            getattr(spec, "on_guest_poweroff", power_policy.RESTART),
            miner,
            relaunch=require_existing_disks,
        )
    except power_policy.PowerPolicyRefused as exc:
        return _terminal(exc.reason, exc.detail, EXIT_CONFIG_ERROR)
    # The CDN role (`apps.cdn.identity`): a CDN node's launch carries the
    # role in its ticket, cmdline and pin class. Refused before any row,
    # secret or pin exists when it must not run, or would boot anything but
    # the cdn-node image with the node's own user-data.
    try:
        cdn_node = cdn_identity.check_launch(spec.vm_id, spec.tenant_id)
        if cdn_node:
            cdn_identity.check_launch_spec(spec)
    except cdn_identity.CdnRoleError as exc:
        return _terminal("cdn-role-refused", str(exc), EXIT_CONFIG_ERROR)

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
    vm_row = _ensure_vm_row(spec)
    if cdn_node:
        # The durable fact every later mint and pin reads (`is_cdn_vm`).
        try:
            cdn_identity.bind_vm(spec.vm_id, vm_row)
        except cdn_identity.CdnRoleError as exc:
            return _terminal("cdn-role-refused", str(exc), EXIT_CONFIG_ERROR)
    # The register gate (step 8) decides this under the row lock at the
    # end; asking the same question here first spares a launch that can
    # never register — above all reboot-recovery of a §25-migrated VM
    # (generation >= 2 vs the launch's `_LAUNCH_GENERATION`), or a row
    # bound to another miner — all the Vault staging, preflight and bake
    # work before it is refused anyway.
    # The guest components floor (docs/design/guest-component-rollout.md,
    # G3): never a launch of a set below the VM's required epoch, whoever
    # asks for it (power start, reboot-recovery, a guest upgrade's own
    # rollback), whatever disk mode the spec claims. Asked here before
    # anything is staged, and again by the register gate under the row lock
    # right before the KBS call (a floor raised meanwhile is seen there).
    from . import guest_components

    epoch_refusal = guest_components.launch_epoch_refusal(spec.vm_id, spec.initrd_sha256_hex)
    if epoch_refusal:
        return _terminal("guest-epoch-below-required", epoch_refusal, EXIT_KBS_ADMIN_FAILURE)
    early_refusal = register_gate.register_refusal(
        vm_row,
        generation=generation,
        miner_id=miner.miner_id,
        initrd_sha256_hex=spec.initrd_sha256_hex,
    )
    if early_refusal is not None:
        return _terminal("kbs-admin-vm-state-refused", early_refusal, EXIT_KBS_ADMIN_FAILURE)

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
    # A launch that names a `platform_id` must land on THAT chip: the ticket
    # binds its VCEK and the C2 recompute uses its CPU family, so on any
    # other host it fails late (`launch-digest-mismatch`) or boots a guest
    # the KBS will never release to. Placement already honours the pin;
    # this refuses the explicit-miner paths (CLI, tests) before anything
    # is minted or registered.
    if (
        spec.platform_id
        and spec.platform_id.strip().lower() != (miner.platform_id or "").strip().lower()
    ):
        return _terminal(
            "platform-id-mismatch",
            f"launch names platform_id {spec.platform_id[:16]}… but miner "
            f"{miner.miner_id} is registered with a different one",
            EXIT_CONFIG_ERROR,
        )
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
        if _netbird_relaunch_needs_no_key(spec, require_existing_disks=require_existing_disks):
            # Nothing minted, nothing recorded: there is no key to trace.
            nb_key = NO_NETBIRD_SETUP_KEY
        else:
            persistent = _netbird_key_is_persistent(spec.vm_id)
            ttl_s = _netbird_key_ttl_s(spec, persistent=persistent)
            try:
                minted = effects.mint_netbird_setup_key(
                    vm_id=spec.vm_id,
                    tenant_id=spec.tenant_id,
                    auto_group_name=spec.netbird_group,
                    persistent=persistent,
                    expires_in_seconds=ttl_s,
                )
            except (EffectUnavailable, EffectError) as exc:
                return _terminal(
                    "netbird-mint-failure", str(exc), EXIT_NETBIRD_FAILURE
                )
            # Recorded BEFORE the key leaves vali: whatever peer enrols with
            # it, under whatever name, is then traceable to this VM
            # (`netbird_binding`), so §24 and the janitor can delete it by id.
            _record_netbird_key(vm_row, minted, persistent=persistent, ttl_s=ttl_s)
            nb_key = minted.key
        userdata = userdata.replace(
            b"{{NETBIRD_SETUP_KEY}}", nb_key.encode("utf-8")
        )
        userdata = userdata.replace(
            b"{{NETBIRD_HOSTNAME}}", nb_hostname.encode("utf-8")
        )
        # M1/M2: the overlay must not let Hippius' NetBird management
        # plane steer the guest's DNS or routes. M0: unchanged bytes.
        try:
            userdata = customer_keys.harden_netbird_up(binding, userdata)
        except customer_keys.CustomerKeysError as exc:
            return _terminal("netbird-bad-userdata", str(exc), EXIT_NETBIRD_FAILURE)
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
    # vali's own working copy of the same bytes — see
    # `stage_userdata_working_copy`.
    userdata_working_path = f"{prefix}/{spec.vm_id}/userdata-pending"
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
        elif not customer_keys.releases_kek(binding):
            # M2 (`customer`): NO disk KEK exists — nothing was generated
            # or staged at `luks_path`, and nothing is read from it here.
            # The ticket still names the canonical path (the schema needs
            # a ref and the KBS derives the lifecycle-key path from it) at
            # the constant M2 version; the KBS never reads it in M2.
            # `kek-<vm_id>` is still created by `_stage_userdata` below —
            # it wraps the userdata. A KEK some earlier attempt left at the
            # path (metadata probe only) is refused, never launched beside.
            try:
                customer_keys.assert_no_provider_kek(mount, luks_path)
            except customer_keys.CustomerKeysError as exc:
                raise EffectError(str(exc)) from exc
            luks_version = customer_keys.M2_LUKS_REF_VERSION
        else:
            # ASYNC launch path: the KEK is ALREADY staged at the canonical
            # `luks_path` by the caller (the launch API enforces
            # `kek_vault_path == luks_path`). Read ONLY the KV VERSION from
            # the metadata endpoint — NEVER the plaintext KEK. This is the
            # C1 / KEK-HSM-Phase-1 win: vali (and thus a vali/node RCE) can
            # no longer read a tenant disk KEK back out of Vault.
            luks_version = vault_kv.latest_version(mount, luks_path)
        ud_v = _stage_userdata(mount, userdata_path, spec.vm_id, userdata)
        # Re-stage vali's working copy with the SUBSTITUTED bytes, so it
        # holds what the canonical copy holds. Intake staged the template
        # (it had no NetBird key yet); the §6 digest binds the substituted
        # form, and the §25 / KBS-recovery re-mint re-derives that digest
        # from this copy — it is the only one vali can open. A template
        # here would digest bytes the guest never receives, i.e. a
        # migration that reports Done and a VM that cannot unlock.
        #
        # After the canonical write on purpose: that is the copy the
        # ticket binds, so a failure between the two aborts the launch
        # rather than leaving a working copy that claims to describe a
        # canonical version nobody staged.
        stage_userdata_working_copy(
            mount,
            userdata_working_path,
            spec.vm_id,
            userdata,
            canonical_version=ud_v.version,
        )
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

    # ── 4. the MEASURED cmdline (`_derive_measured_cmdline`) ─────────
    validator_nonce_hex = secrets.token_bytes(32).hex()
    # §24/§25 EOL nonce: an operator-baked `hippius.eol_nonce=` token in
    # the cmdline wins (already measured); else `spec.eol_nonce_hex`; else a
    # fresh per-launch mint. Whatever ends up in the cmdline is reflected
    # onto `Vm.eol_nonce` below so the two can NEVER drift.
    nonce_seed = (
        spec.eol_nonce_hex
        or _extract_cmdline_token(spec.cmdline, _EOL_NONCE_CMDLINE_KEY)
        or secrets.token_bytes(32).hex()
    )
    augmented_cmdline = _derive_measured_cmdline(
        spec,
        binding,
        disk_gb=data_disk_gb(spec),
        node_id_hex=miner.chain_node_id,
        validator_nonce_hex=validator_nonce_hex,
        telemetry_epoch=_current_billing_epoch(),
        eol_nonce_hex=nonce_seed,
        cdn_node=cdn_node,
    )
    effective_eol_nonce_hex = _extract_cmdline_token(
        augmented_cmdline, _EOL_NONCE_CMDLINE_KEY
    )
    _persist_eol_nonce(spec.vm_id, effective_eol_nonce_hex)
    refusal = _measured_cmdline_refusal(augmented_cmdline, binding)
    if refusal is not None:
        return _terminal(refusal[0], refusal[1], EXIT_CONFIG_ERROR)

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
        if _preflight_refusal_is_disk(exc):
            # 507 `insufficient-disk` BEFORE the KBS register: no room for
            # this VM's DATA disk (declared budget or measured free space).
            # A CAPACITY refusal — nothing about SEV is recorded (the
            # preflight never is) — and, since vali placed it within the
            # disk budget the host let it compute, it cuts an `earned`
            # miner's DISK ceiling. The RETRIABLE below re-places.
            _record_capacity_event(miner, "disk-insufficient", incident=f"vm={spec.vm_id}")
        elif _preflight_refusal_is_capacity(exc):
            # The host told us it is full: an `earned` miner's ceiling
            # drops to what it holds (capacity v2 §3). Keyed on the node
            # vali dispatched to, never on anything the miner sent.
            _record_capacity_event(
                miner, "preflight-insufficient", incident=f"vm={spec.vm_id}"
            )
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
    recomputed = False

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
                snp_generation=miner.snp_generation,
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
            # An explicitly supplied measurement is a caller override that is
            # pinned + ticketed AS-IS while the guest boots `augmented_cmdline`.
            # If it does not match vali's recompute of THAT cmdline, the pin
            # and ticket carry a digest the guest can never produce →
            # guaranteed KBS denial. Refuse loudly rather than launch a brick.
            # Production never supplies measurement_hex (0/100 live launches),
            # so this only guards an operator/dev override gone stale — e.g.
            # after a measured-cmdline change like systemd.import_credentials=no.
            if spec.measurement_hex and spec.measurement_hex.lower() != expected_digest:
                return _terminal(
                    "explicit-measurement-stale",
                    f"supplied measurement_hex {spec.measurement_hex.lower()} != "
                    f"vali recompute {expected_digest} of the measured cmdline; "
                    "refusing to pin/ticket a digest the guest will not produce",
                    EXIT_MEASUREMENT_MISMATCH,
                )
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
                recomputed = True

    # A CDN node's measurement is trusted with the fleet keyring: only
    # vali's own recompute of it is ever ticketed or pinned, never the
    # miner's report (the C2 WARN mode above) — and it must be pinned.
    if cdn_node and (not recomputed or not spec.auto_pin_allowlist):
        return _terminal(
            "cdn-role-refused",
            "cdn-node-unverified-digest: a CDN node launches only with vali's own "
            "launch-digest recompute, pinned (VALI_LAUNCH_DIGEST_ENFORCE)",
            EXIT_CONFIG_ERROR,
        )

    # ── 6. Allowlist re-pin (optional) ──────────────────────────────
    # The pin also records the digest in the audit ledger (#587 Phase 3,
    # GET /v1/admin/audit/measurements) under its lock: the next pin's
    # carry-forward reads that row, and the live-attestation ingest
    # refuses a VM with none (`vm_liveness.pinned_measurements`). A tenant
    # launch always pins under the tenant class, a CDN node's under
    # `cdn_node` (the KBS releases the fleet keyring to that class only).
    pin_result = None
    if spec.auto_pin_allowlist:
        try:
            pin_result = allowlist_pin.pin_measurement(
                measurement_hex=measurement_hex,
                **(
                    {"measurement_class": allowlist_pin.ALLOWLIST_CLASS_CDN_NODE}
                    if cdn_node
                    else {}
                ),
                ledger=allowlist_pin.PinLedger(
                    vm_id=spec.vm_id,
                    platform_id=platform_id or "",
                    node_id=node_id or "",
                    flavor=spec.flavor,
                    attests_resources=_cmdline_has_token(
                        augmented_cmdline, _ATTEST_RESOURCES_CMDLINE_KEY, "1"
                    ),
                    accepts_memory_eagerly=_cmdline_has_token(
                        augmented_cmdline, _ACCEPT_MEMORY_CMDLINE_KEY, "eager"
                    ),
                    recomputed=recomputed,
                    launch_ref=launch_ref,
                ),
            )
        except allowlist_pin.AllowlistPinBusy as exc:
            # Other pins held the lock past its wait: nothing was signed and
            # the KBS is not registered yet, so this is retriable — a
            # re-place re-pins, a reboot-recovery relaunch retries on its
            # backoff. Terminal would fail the tail of a burst of starts.
            return LaunchOutcome(
                disposition=RETRIABLE,
                # The literal, not `ALLOWLIST_PIN_BUSY`: the outcome drift guard
                # (`scheduler/tests/test_reasons.py`) reads literals.
                emit={"ok": False, "outcome": "allowlist-pin-busy", "error": str(exc)},
                exit_code=EXIT_ALLOWLIST_FAILURE,
            )
        except (EffectUnavailable, EffectError) as exc:
            return _terminal(
                "allowlist-pin-failure", str(exc), EXIT_ALLOWLIST_FAILURE
            )

    # ── 7. Mint the L1 OrderTicket ──────────────────────────────────
    try:
        mint_args = ticket_mint.MintArgs(
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
            lifecycle_perm=cdn_identity.ticket_perms(
                ("launch", _SUPERSEDE_PERM) if supersede else ("launch",), spec.vm_id
            ),
            expiry_seconds=spec.expiry_seconds,
            # The generation the KBS releases this VM's KEK at; the
            # register gate and the entry check compare the Vm row against
            # the same value.
            vm_generation=generation,
            # Customer-held keys: signed into the ticket for M1/M2 only
            # (the KBS pins it at register and gates the KEK release on
            # it); M0 passes no flag — byte-identical ticket.
            key_mode=customer_keys.ticket_key_mode(binding),
        )
        cose_ticket = ticket_mint.mint(mint_args)
        # Recorded BEFORE anything can release against it: the KBS evidence
        # names only the ticket_id it granted, and a §25 stranded-VM restore
        # refuses any grant vali has no record of — so an unrecorded launch
        # ticket leaves the VM down after its first failed migration.
        from .migration_ticket import persist_intake

        persist_intake(
            cose_ticket,
            vm_id=spec.vm_id,
            generation=mint_args.vm_generation,
            ticket_id=ticket_id,
            received_from="system:launch",
            expected_key_mode=mint_args.key_mode,
        )
    except (EffectUnavailable, EffectError) as exc:
        return _terminal("mint-failure", str(exc), EXIT_MINT_FAILURE)

    # ── 8. kbs-admin register ───────────────────────────────────────
    #
    # Re-checked under the Vm row lock, held across the KBS call: this
    # function runs for many minutes after `_ensure_vm_row`'s entry check
    # (Vault staging, preflight, bake), and reboot-recovery reaches it for
    # a VM that has a live history. A §24 decommission or §25 migration
    # that started meanwhile — or a placement that moved — must never be
    # re-bound at the KBS by this late call. Refused BEFORE the register,
    # so the outcome is a plain pre-register terminal.
    def register() -> kbs_admin.KbsAdminRegisterOk | None:
        if mint_args.vm_generation != _LAUNCH_GENERATION and supersede:
            # A resize of a VM §25 moved: the KBS accepts a SUPERSEDING
            # register against the `Migrating` row that admits this
            # (generation, host, lease) without touching it, and makes
            # this launch current — the pre-resize ticket is refused from
            # here on. A KBS that predates that answers 409, and the
            # relaunch fails like any refused register (KBS first, then
            # vali): falling back to an unregistered launch would let a
            # later retry, once the KBS has it, strand this one if it
            # comes up.
            return kbs_admin.register_vm_active_with_vm_id(
                vm_id=spec.vm_id, cose_ticket=cose_ticket
            )
        if mint_args.vm_generation != _LAUNCH_GENERATION:
            # A relaunch of a VM §25 moved: its KBS row is the
            # `Migrating{new_gen, dest, lease}` the last activate wrote,
            # which admits exactly this (generation, host, lease) — as it
            # does for that hop's destination, whose re-minted ticket is
            # never registered either. `register-vm` would 409 against it
            # (it only writes `Active`). Nothing to bind; the KBS still
            # checks the ticket against its own row at release.
            return None
        return kbs_admin.register_vm_active_with_vm_id(
            vm_id=spec.vm_id, cose_ticket=cose_ticket
        )

    try:
        admin_ok = register_gate.register_under_vm_lock(
            spec.vm_id,
            generation=mint_args.vm_generation,
            miner_id=miner.miner_id,
            register=register,
            initrd_sha256_hex=spec.initrd_sha256_hex,
        )
    except register_gate.RegisterRefused as exc:
        outcome = (
            "guest-epoch-below-required"
            if "guest-epoch-below-required" in str(exc)
            else "kbs-admin-vm-state-refused"
        )
        return _terminal(outcome, str(exc), EXIT_KBS_ADMIN_FAILURE)
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

    if admin_ok is None:
        log.info(
            "kbs-admin: vm_id=%s relaunched at gen=%s — bound by its last §25 "
            "activate, not re-registered",
            spec.vm_id,
            mint_args.vm_generation,
        )
    else:
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

    if (
        admin_ok is not None
        and supersede
        and not _mark_superseded_at_register(spec.vm_id, measurement_hex)
    ):
        # Nothing is dispatched without the mark: a retry that does not know
        # this register landed would supersede again, and strand this launch
        # if it came up. Not dispatched ⇒ nothing can come up, so the retry
        # superseding again is safe.
        return _terminal_after_register(
            "supersede-mark-failed",
            "the KBS made this launch current but vali could not record it — "
            "not dispatched; a retry supersedes again",
            EXIT_KBS_ADMIN_FAILURE,
        )

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
    # on one host and a real 709 MB 2026-07-29 file on another — the same
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
        data_disk_size_gb=data_disk_gb(spec),
        rootfs_data_path=rootfs_data_path,
        rootfs_hash_path=rootfs_hash_path,
        cpu_count=flavor.cpu_count,
        memory_mb=flavor.memory_mb,
        cose_ticket=cose_ticket,
        require_existing_disks=require_existing_disks,
        net=net_policy.launch_net_spec(
            miner_id=miner.miner_id, vm_id=spec.vm_id, flavor=spec.flavor
        ),
        on_guest_poweroff=poweroff_field,
    )
    import json as _json

    payload_json = _json.dumps(payload).encode("utf-8")
    # What this order boots, carried on EVERY outcome from here on: a
    # dispatch answered as failed may have booted all the same (an Edge
    # timeout, a ticket push that failed), and a retry the miner answers
    # `already-launched` then needs the boot that runs, not its own.
    dispatched_boot: dict[str, Any] = {
        "measurement_hex": measurement_hex,
        "measurement_source": "operator-pinned" if spec.measurement_hex else "preflight-auto",
        "measured_cmdline": augmented_cmdline,
        "luks_disk_path": preflight_result.luks_disk_path,
        "kernel_path": preflight_result.kernel_path,
        "initrd_path": preflight_result.initrd_path,
        "rootfs_data_path": rootfs_data_path,
        "rootfs_hash_path": rootfs_hash_path,
        **(
            {
                "allowlist_epoch": pin_result.new_epoch,
                "allowlist_sha256": pin_result.new_cose_sha256_hex,
            }
            if pin_result is not None
            else {}
        ),
    }

    def _undelivered(out: LaunchOutcome) -> LaunchOutcome:
        out.emit[DISPATCHED_BOOT_KEY] = dispatched_boot
        return out

    try:
        result = order_dispatch.dispatch_order(
            miner_id=miner.miner_id,
            netbird_ip=str(miner.netbird_ip),
            order_id=order_id,
            kind="launch",
            payload_json=payload_json,
        )
    except order_dispatch.OrderDispatchMisconfigured as exc:
        # Refused before anything was sent: no boot to keep.
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
        return _undelivered(
            _terminal_after_register("edge-unreachable", str(exc), EXIT_EDGE_FAILURE)
        )
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
        DISPATCHED_BOOT_KEY: dispatched_boot,
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
    # produced `vm-migrate-1`).
    #
    # A rejected dispatch that nonetheless left a domain up is covered
    # instead by `effects.destroy_target_miner_id`, which reads the
    # LaunchJob — deliberately widened for the destroy ONLY, so it cannot
    # leak into `_bound_miner_id`'s routing.
    if result.ok:
        _bind_vm_host(spec.vm_id, miner.miner_id)
        if result.classifier != _ALREADY_LAUNCHED:
            # The miner persisted this order's guest-poweroff policy before
            # starting the domain (an `already-launched` started nothing, so
            # it says nothing about the running domain's).
            power_policy.record_effective(
                spec.vm_id, poweroff_field or power_policy.RESTART, miner.miner_id
            )
        if result.classifier == _ALREADY_LAUNCHED:
            # The miner started nothing: the domain running is an EARLIER
            # attempt's (a ticket push that failed, retried inside the
            # re-push window). This launch's measurement is not what runs,
            # so it must not become current nor evict the one that does.
            log.warning(
                "launch: vm_id=%s answered already-launched — measurement %s is NOT "
                "the running domain's; not marked current%s",
                spec.vm_id,
                measurement_hex[:16],
                " (the KBS already made it current at register: a superseding "
                "relaunch over a domain still running)" if supersede else "",
            )
        else:
            _mark_measurement_launched(spec.vm_id, measurement_hex)
            if spec.auto_pin_allowlist:
                _evict_superseded_launches(spec.vm_id)
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
    if not result.ok and _launch_refusal_is_disk(result.status, result.classifier):
        # 507 `insufficient-disk` AFTER the KBS register (the budget
        # reservation or the statvfs check at disk-file create). A capacity
        # event, NOT a SEV start failure (`is_start_capability_failure`
        # excuses it, so the ledger above recorded nothing and no
        # `start-failed` halving follows): it cuts the earned DISK ceiling.
        #
        # It cannot re-place: vali has no KBS deregister/rollback, and the
        # vm_id is now bound to THIS host — a re-place would re-mint for a
        # new host and hit the anti-migration fence (kbs-admin-conflict).
        # `launch_vm` retries the same miner (space may have been freed by
        # a concurrent teardown) and then gives up with
        # `dispatch-failed-after-register`; the reapable-abandoned-launch
        # path handles the rest. The disk gate (`VALI_SCHEDULER_DISK_GATE`)
        # is what keeps this rare: it refuses the host before any register.
        # A LEGACY agent answered the same condition as a bare 500
        # `dispatch-failed` (the `data-disk/insufficient-space` detail only
        # reached the host's log), which is indistinguishable from a real
        # start failure and is still counted as one.
        _record_capacity_event(miner, "disk-insufficient", incident=f"vm={spec.vm_id}")
    elif not result.ok and _start_failure_is_miner_attributable(result.status, result.classifier):
        # A start the MINER itself answered as failed, after the KBS
        # register: halves an `earned` miner's ceiling (capacity v2 §3).
        # Once per VM however often the launch retries this miner.
        _record_capacity_event(miner, "start-failed", incident=f"vm={spec.vm_id}")

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


#: Edge statuses whose body is empty and whose outcome is UNKNOWN (the
#: miner may never have been reached) — never evidence against a miner.
_EDGE_UNKNOWN_STATUSES = frozenset({502, 504})


def _start_failure_is_miner_attributable(status: int, classifier: str) -> bool:
    """A launch rejection the MINER answered, about starting the guest.

    Positive rules only: a real miner class (never empty — an Edge 502/504
    has no body and an unknown outcome), not an in-flight replay, and a
    class `cvm_capability` counts as start-capability evidence (so a bad
    order or a full host is not charged here)."""
    from apps.scheduler import cvm_capability

    return (
        status not in _EDGE_UNKNOWN_STATUSES
        and bool(classifier)
        and classifier != "order-in-flight"
        and cvm_capability.is_start_capability_failure(classifier)
    )


def _preflight_refusal_is_capacity(exc: Exception) -> bool:
    """The miner refused the preflight because it is FULL (#668 / ASID)."""
    return (
        isinstance(exc, preflight_svc.PreflightRejected)
        and exc.classifier == "insufficient-resources"
    )


def _preflight_refusal_is_disk(exc: Exception) -> bool:
    """The miner refused the preflight for lack of DATA-disk room (507
    `insufficient-disk`, or any class naming `insufficient-space`)."""
    from apps.scheduler import cvm_capability

    return isinstance(exc, preflight_svc.PreflightRejected) and cvm_capability.is_disk_refusal(
        exc.classifier
    )


def _launch_refusal_is_disk(status: int, classifier: str) -> bool:
    """A launch rejection the MINER answered as a DATA-disk refusal (never
    an Edge 502/504, whose body is empty and whose outcome is unknown)."""
    from apps.scheduler import cvm_capability

    return status not in _EDGE_UNKNOWN_STATUSES and cvm_capability.is_disk_refusal(classifier)


def _record_capacity_event(miner: MinerIdentity, kind: str, *, incident: str = "") -> None:
    """Hand a capacity event to `capacity_earn` for the node vali
    dispatched to (`MinerIdentity.chain_node_id`, operator-curated).
    `record_event` never raises into the launch path."""
    from apps.scheduler import capacity_earn

    node_id = getattr(miner, "chain_node_id", "") or ""
    if node_id:
        capacity_earn.record_event(node_id, kind, incident=incident)


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


def max_pin_busy_retries() -> int:
    """How many times `launch_vm` re-places after `allowlist-pin-busy`
    without spending a miner attempt. Each try has already waited
    `allowlist_pin.PIN_LOCK_TIMEOUT_S` for the lock."""
    return int(getattr(settings, "VALI_LAUNCH_MAX_PIN_BUSY_RETRIES", 4))


def boot_wait_s() -> float:
    """How long a launch may wait for a boot slot when every eligible miner
    is at its concurrent-boot cap (`miners-booting`), counted from when the
    request was QUEUED (`launch_vm(queued_for_s=)`), before it fails under
    that outcome. The wait holds the (serial) launch tick, so a burst
    drains at the fleet's boot rate instead of piling up on one host.
    Counting queue time keeps every job's queue + wait inside this bound,
    well under a caller's own launch timeout (the SDK's `wait_for_launch`
    gives up after 30 min) — a job is never launched after its caller has
    given up on it just because it waited behind others."""
    return max(0.0, float(getattr(settings, "VALI_SCHEDULER_BOOT_WAIT_S", 900)))


def boot_wait_poll_s() -> float:
    """Seconds between placement re-asks while waiting for a boot slot
    (each re-ask reads the chain and the DB; floored at 1 s)."""
    return max(1.0, float(getattr(settings, "VALI_SCHEDULER_BOOT_WAIT_POLL_S", 15)))


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
    queued_for_s: float = 0.0,
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
        spec, decided_by, max_attempts=max_attempts, on_phase=on_phase, queued_for_s=queued_for_s
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
    queued_for_s: float = 0.0,
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

    `queued_for_s` is how long the request already waited in the launch
    queue; it is spent from the boot-slot wait (`boot_wait_s`).
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
        MINERS_BOOTING,
        PlacementError,
        decide_placement,
    )

    cap_attempts = max_attempts or max_replace_attempts()
    vm = _ensure_vm_row(spec)
    excluded: set[str] = set()
    audit: list[dict[str, str]] = []

    attempts_used = 0
    pin_busy_retries = 0
    boot_wait_until: float | None = None
    while attempts_used < cap_attempts:
        attempts_used += 1
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
                # Every gate, assembled in ONE place so the feasibility
                # check (`apps.scheduler.feasibility`) asks the scheduler
                # the identical question. A preflight built from its own
                # copy of these arguments drifts, and a drifted preflight
                # is worse than none: the caller sells on its answer.
                **service.placement_arguments(
                    snapshot=snapshot,
                    tenant_id=spec.tenant_id,
                    user_id=spec.user_id,
                    flavor=spec.flavor,
                    excluded=frozenset(excluded),
                    region=spec.region,
                    platform_id=spec.platform_id,
                    boot_gate=True,
                    vm_id=spec.vm_id,
                    power_policy_stop=(
                        getattr(spec, "on_guest_poweroff", power_policy.RESTART)
                        == power_policy.STOP
                    ),
                ),
            )
        except PlacementError as exc:
            # Every eligible miner is busy booting: a boot slot frees up in
            # minutes, so wait for it — without spending a miner attempt —
            # rather than fail a launch the fleet can take.
            if exc.category == MINERS_BOOTING:
                now = time.monotonic()
                if boot_wait_until is None:
                    boot_wait_until = now + boot_wait_s() - max(0.0, queued_for_s)
                if now < boot_wait_until:
                    log.warning(
                        "launch: vm_id=%s waiting for a boot slot (%.0fs left): %s",
                        spec.vm_id,
                        boot_wait_until - now,
                        exc.message,
                    )
                    attempts_used -= 1
                    time.sleep(min(boot_wait_poll_s(), boot_wait_until - now))
                    continue
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
        dispatched: list[dict[str, Any]] = []
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
            dispatched.extend(_candidate_of(spec, out))
            out = launch_on_miner(spec, miner)
        if answered_already_launched(out):
            _await_the_attested_boot(
                spec.vm_id, out, [*_earlier_dispatched_boots(spec.vm_id), *dispatched]
            )
        elif out.disposition != ACCEPTED and (sent := [*dispatched, *_candidate_of(spec, out)]):
            # Failed for good — but any of these dispatches may be up: a
            # re-POSTed launch answered `already-launched` settles on them
            # (`_earlier_dispatched_boots`).
            keep = launch_record.MAX_DISPATCHED_BOOTS
            out.emit[launch_record.DISPATCHED_BOOTS_KEY] = sent[-keep:]

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

        # A busy allowlist pin is vali's own queue, not a verdict on the
        # miner: re-place WITHOUT excluding it or spending a miner attempt,
        # up to its own cap — then fail under its own outcome, never as
        # `no-capacity-after-replace`.
        if out.emit.get("outcome") == ALLOWLIST_PIN_BUSY:
            if pin_busy_retries < max_pin_busy_retries():
                pin_busy_retries += 1
                attempts_used -= 1
                log.warning(
                    "launch: vm_id=%s allowlist pin busy (retry %d/%d)",
                    spec.vm_id,
                    pin_busy_retries,
                    max_pin_busy_retries(),
                )
                continue
            return LaunchResult(
                ok=False,
                outcome=ALLOWLIST_PIN_BUSY,
                vm_id=spec.vm_id,
                emit=out.emit,
                attempts=audit,
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


def _refuse_cordoned_miner(miner: MinerIdentity) -> None:
    """A cordoned miner takes no new VM, even one an operator names: lift
    the cordon first (`vali_set_miner_capacity --uncordon`)."""
    from apps.scheduler import service as sched

    reason = sched.miner_cordon_reason(miner.miner_id)
    if reason is not None:
        raise LaunchConfigError(
            f"miner {miner.miner_id!r} is cordoned ({reason or 'no reason given'}) — "
            "uncordon it to launch there"
        )


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

    # Before the row / placement: an M1/M2 launch refused for this miner's
    # identity must leave nothing behind.
    _refuse_miner_for_customer_keys(_spec_binding(spec), miner)
    _refuse_cordoned_miner(miner)
    from apps.scheduler import service as sched

    reason = sched.cdn_dest_reason(spec.tenant_id, spec.vm_id, miner.miner_id)
    # The group a row already carries wins: it never changes.
    from apps.lifecycle.models import Vm

    group = (
        Vm.objects.filter(vm_id=spec.vm_id).values_list("placement_group", flat=True).first()
        or spec.placement_group
    )
    reason = reason or sched.group_dest_reason(spec.tenant_id, group, spec.vm_id, miner.miner_id)
    if reason is not None:
        raise LaunchConfigError(reason)
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


# The working copy's self-describing header: which canonical KV version
# the bytes under it correspond to. Written inside the Transit-wrapped
# blob, so it cannot be edited by anyone who cannot also re-wrap.
_WORKING_STAMP = b"hippius-userdata-for-canonical-v"


class UserdataPairingError(EffectError):
    """The working copy does not demonstrably correspond to the canonical
    version being bound — see [`open_userdata_working_copy`]."""


def stage_userdata_intake_copy(mount: str, path: str, vm_id: str, userdata: bytes):
    """Stage the cloud-init TEMPLATE the caller POSTed, wrapped under
    `ud-<vm_id>` — the per-VM Transit key vali may decrypt.

    This copy used to be written in the CLEAR, and is retained for the
    life of the VM (the launch worker reads it, and so does
    reboot-recovery, each substituting a FRESH NetBird setup key into it),
    so a tenant's cloud-init — SSH keys, API tokens, the NetBird enrolment
    secret — sat readable at rest in Vault KV for the VM's lifetime and
    past its death: §24 destroyed `kek-<vm_id>` and deleted the luks-kek
    blob, and nothing ever deleted this one.

    Wrapped rather than removed because vali genuinely still needs the
    plaintext after intake, and under a key vali can open rather than the
    KBS-only `kek-<vm_id>` for the same reason. See
    `vault_kv.userdata_transit_key_name` for exactly what that does and
    does not protect against.

    Deliberately UNSTAMPED: a template corresponds to no canonical
    version. That is also what distinguishes it from a working copy, so a
    template can never be mistaken for one (see below).
    """
    transit_key = vault_kv.userdata_transit_key_name(vm_id)
    vault_kv.ensure_transit_key(transit_key)
    return vault_kv.put_kv(mount, path, vault_kv.transit_encrypt(transit_key, userdata))


def stage_userdata_working_copy(
    mount: str, path: str, vm_id: str, userdata: bytes, *, canonical_version: int
):
    """Stage vali's working copy of the bytes it just wrote to the
    CANONICAL path, wrapped under `ud-<vm_id>` and STAMPED with that
    canonical version.

    The stamp is what makes the correspondence provable rather than
    assumed. The §25 / KBS-recovery re-mint has to digest the plaintext of
    a specific canonical version (that is what its ticket binds) and can
    only obtain it from here, so "is this copy the right one?" has to have
    an answer. Two independent KV writes cannot be atomic: a canonical
    success followed by a failure here would otherwise leave the two paths
    at different contents with no way to tell — and the re-mint would hash
    the older bytes and produce a ticket that denies at release, i.e. a
    migration that reports Done and a VM that never unlocks.

    Inside the wrapped blob, so only a party holding
    `transit/encrypt/ud-<vm_id>` can write a stamp at all.
    """
    transit_key = vault_kv.userdata_transit_key_name(vm_id)
    vault_kv.ensure_transit_key(transit_key)
    stamped = _WORKING_STAMP + str(int(canonical_version)).encode("ascii") + b"\n" + userdata
    return vault_kv.put_kv(mount, path, vault_kv.transit_encrypt(transit_key, stamped))


def open_userdata_intake_copy(
    mount: str, path: str, version: int | None, vm_id: str
) -> bytes:
    """Read the intake TEMPLATE back and unwrap it.

    A value with no `vault:` prefix is a LEGACY plaintext copy (staged
    before the wrapping) and is returned verbatim — those VMs must keep
    launching and recovering.
    """
    stored = vault_kv.get_kv(mount, path, version=version or None)
    if not stored.startswith(b"vault:"):
        return stored
    return vault_kv.transit_decrypt(vault_kv.userdata_transit_key_name(vm_id), stored)


def open_userdata_working_copy(mount: str, path: str, vm_id: str, canonical_version: int) -> bytes:
    """Read the working copy back, unwrap it, and RETURN IT ONLY IF it
    stamps the canonical version asked for.

    Three ways this refuses, all of them cases where the alternative is a
    ticket bound to bytes the guest will never receive:

    - not `vault:`-wrapped — a pre-substitution template an older intake
      wrote to this path, not a copy of the canonical bytes;
    - no stamp — written before the stamping, so its correspondence is
      unknown;
    - a DIFFERENT stamp — the canonical write succeeded and this one did
      not (or a later attempt advanced only one of the two), so these are
      some other version's bytes.
    """
    stored = vault_kv.get_kv(mount, path)
    if not stored.startswith(b"vault:"):
        raise UserdataPairingError(
            f"{path}: not Transit-wrapped — a pre-substitution intake "
            "template, not a working copy of the canonical bytes"
        )
    opened = vault_kv.transit_decrypt(vault_kv.userdata_transit_key_name(vm_id), stored)
    if not opened.startswith(_WORKING_STAMP):
        raise UserdataPairingError(
            f"{path}: carries no canonical-version stamp — it predates the "
            "pairing and cannot be shown to hold the bytes any particular "
            "canonical version holds"
        )
    head, _, body = opened[len(_WORKING_STAMP) :].partition(b"\n")
    try:
        stamped = int(head.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise UserdataPairingError(f"{path}: malformed canonical-version stamp") from exc
    if stamped != int(canonical_version):
        raise UserdataPairingError(
            f"{path}: stamped for canonical version {stamped}, but the ticket "
            f"binds version {canonical_version} — the two staging writes are "
            "not atomic and this one is stale. Re-stage the userdata (or "
            "relaunch) so both paths describe the same bytes."
        )
    return body


def _stage_userdata(mount: str, path: str, vm_id: str, userdata: bytes):
    """Stage the CANONICAL cloud-init userdata at `path`, Transit-WRAPPED
    under `kek-<vm_id>` — the key vali may encrypt with and never decrypt.
    This is the copy the minted ticket binds and the attested KBS releases.

    It used to be written in plaintext while the KEK four lines above was
    enveloped — and a tenant's cloud-init routinely carries SSH keys, API
    tokens and the NetBird enrolment secret. Vault enforces the asymmetry
    that makes wrapping worth it: vali holds `transit/encrypt/kek-*`
    (`update`) and is DENIED `transit/decrypt/kek-*`, so once wrapped,
    vali — and a vali/node RCE — cannot read it back. Only the attested
    SNP KBS unwraps it, per-VM scoped by the broker.

    Wrapped under the SAME per-VM key as the KEK (`kek-<vm_id>`) rather
    than a second one, for the bonus: §24's crypto-erase DESTROYS that
    key, so decommission now makes the userdata cryptographically
    unreadable. The erase path never deleted this KV entry, so a
    destroyed VM's cloud-init outlived it indefinitely, KV version
    history included.

    ⚠️ The caller still digests the PLAINTEXT. The KBS unwraps before it
    recomputes and constant-time-compares, so digesting the ciphertext
    would fail every launch with DigestMismatch.

    `ensure_transit_key` is idempotent and is needed on the ASYNC path
    too: there the caller staged the KEK so the key already exists, but
    this must not depend on that ordering.
    """
    transit_key = vault_kv.transit_key_name(vm_id)
    vault_kv.ensure_transit_key(transit_key)
    return vault_kv.put_kv(mount, path, vault_kv.transit_encrypt(transit_key, userdata))


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
    from django.db import transaction

    from apps.lifecycle.models import Vm, VmState

    # Customer-held keys: validate the spec's binding BEFORE a row exists,
    # then pin it on a NEW row and hold every later launch of the vm_id
    # (relaunch, reboot-recovery, power start, re-place) to that pin.
    binding = _spec_binding(spec)
    # An address the miner relay refuses would fail the launch only after
    # the row below pinned it, burning the vm_id. Intake refuses it too;
    # this covers launch paths that skip intake (operator CLI).
    try:
        customer_keys.check_endpoint_allowed(binding)
        customer_keys.check_cloud_init_markers(
            binding, cmdline=spec.cmdline, vm_id=spec.vm_id, lease_id=spec.lease_id
        )
        customer_keys.check_lease_id(binding, spec.lease_id)
        if spec.enable_netbird:
            customer_keys.harden_netbird_up(binding, spec.userdata)
    except customer_keys.CustomerKeysError as exc:
        raise LaunchConfigError(str(exc)) from exc
    if not Vm.objects.filter(vm_id=spec.vm_id).exists():
        # About to PIN a new row: refuse a measured cmdline that could never
        # be minted first (config-derived markers, length), not after.
        _refuse_measured_cmdline_before_pin(spec, binding)
    # The row and its birth floor commit together: a retry (or a concurrent
    # launch) never sees a new VM without the floor of the release it boots.
    with transaction.atomic():
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
                "placement_group": getattr(spec, "placement_group", "") or "",
                "on_guest_poweroff": getattr(spec, "on_guest_poweroff", power_policy.RESTART),
                **customer_keys.spec_fields(binding),
            },
        )
        if _created:
            # G3 (docs/design/guest-component-rollout.md): a VM born on a
            # guest release (a launch by image of a blessed release) never
            # relaunches below it — its floor starts at that release's epoch.
            from . import guest_components

            epoch = guest_components.epoch_of_initrd(spec.initrd_sha256_hex)
            if epoch > 0:
                guest_components.raise_required_epoch(
                    vm, epoch, by="launch", reason="the vm's first launch boots a guest release"
                )
    try:
        customer_keys.check_pinned(vm, binding)
    except customer_keys.CustomerKeysError as exc:
        raise LaunchConfigError(str(exc)) from exc
    # A DECOMMISSIONED vm_id must never be relaunched. §24 crypto-erased
    # that VM — both per-VM Transit keys destroyed, all its KV blobs
    # deleted — and a launch under the same id stages fresh secrets that
    # nothing can reach again: a second decommission is refused for a VM
    # that is already Destroyed. (The KBS has also spent that vm_id's
    # lifecycle state, so the launch could not release a KEK anyway.)
    #
    # Checked HERE, in the one function every launch path goes through,
    # rather than only at API intake: the operator CLI does not go through
    # intake at all, and the async worker re-checks a state that may have
    # changed since the POST.
    # A MIGRATING vm_id belongs to a §25 move that owns its KBS state
    # (`Migrating{old,new,source,dest}`); a launch here would either be
    # refused by the KBS after staging and a bake, or — if the row were
    # absent after a KBS wipe — re-bind the fenced-out source. Refused up
    # front; the register step re-checks under the row lock regardless.
    if vm.state == VmState.MIGRATING:
        raise LaunchConfigError(
            f"vm {spec.vm_id!r} is migrating — a §25 move owns it; finish or "
            "recover the migration before relaunching it"
        )
    if vm.state in (VmState.DESTROYED, VmState.DECOMMISSIONING):
        raise LaunchConfigError(
            f"vm {spec.vm_id!r} is {vm.state} — a decommissioned vm_id cannot "
            "be relaunched (its keys were crypto-erased; staging new secrets "
            "under it would recreate material §24 can no longer reach). "
            "Launch under a fresh vm_id."
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


def _mark_superseded_at_register(vm_id: str, measurement_hex: str) -> bool:
    """Record that the KBS made this launch current at its register
    (`MeasurementLedger.superseded_at_register`): a resize stops asking for
    `supersede` from here on. `False` (loudly) when it could not be
    recorded — no pin row, or the write failed; the caller then does not
    dispatch."""
    from django.utils import timezone

    from apps.orchestration.models import MeasurementLedger

    try:
        # The register's own time, not the pin row's: the row may be an
        # older pin of the same measurement (this launch's insert failed).
        marked = MeasurementLedger.objects.filter(
            vm_id=vm_id, launch_digest_hex__iexact=measurement_hex
        ).update(superseded_at_register=timezone.now())
    except Exception as exc:  # noqa: BLE001 — reported to the caller
        log.error("measurement-ledger superseded_at_register mark failed vm=%s: %s", vm_id, exc)
        return False
    if not marked:
        log.error(
            "measurement-ledger: superseding launch vm=%s measurement=%s has NO pin row "
            "to mark — not dispatching it",
            vm_id,
            measurement_hex[:16],
        )
    return bool(marked)


#: The miner-agent's 2xx class for a launch of a domain already running
#: (`orders::handler::handle_launch`).
_ALREADY_LAUNCHED = "already-launched"

#: The emit key naming what a dispatched order booted (`launch_record.BOOT_KEYS`).
DISPATCHED_BOOT_KEY = "dispatched_boot"


def _candidate_of(spec: LaunchSpec, out: LaunchOutcome) -> list[dict[str, Any]]:
    """`out`'s dispatched boot as a candidate (`launch_record`), with the
    artefacts and size `spec` booted it from; `[]` when nothing was sent."""
    boot = (out.emit or {}).get(DISPATCHED_BOOT_KEY)
    if not boot or not boot.get("measurement_hex"):
        return []
    return [
        launch_record.dispatched_boot_candidate(
            boot, booted=(spec.s3_key_prefix, spec.initrd_sha256_hex), flavor=spec.flavor
        )
    ]


def _earlier_dispatched_boots(vm_id: str) -> list[dict[str, Any]]:
    """What the FAILED launch jobs of `vm_id` dispatched, oldest first: a
    re-POSTed launch answered `already-launched` meets one of them."""
    from apps.orchestration.models import LaunchJob, LaunchJobState

    boots: list[dict[str, Any]] = []
    for result in (
        LaunchJob.objects.filter(vm_id=vm_id, state=LaunchJobState.FAILED.value)
        .order_by("finished_at")
        .values_list("result_json", flat=True)
    ):
        emit = (result or {}).get("emit") or {}
        boots.extend(emit.get(launch_record.DISPATCHED_BOOTS_KEY) or [])
    return boots


def _await_the_attested_boot(
    vm_id: str, out: LaunchOutcome, dispatched: list[dict[str, Any]]
) -> None:
    """A launch answered `already-launched`: the domain up is one of the
    earlier dispatches, not this one. The record this emit becomes carries
    them as candidates and waits for the guest's attestation to say which
    (`launch_record` module docstring)."""
    log.warning(
        "launch: vm_id=%s answered already-launched after %d earlier dispatch(es) — "
        "its record waits for the guest's attestation",
        vm_id,
        len(dispatched),
    )
    out.emit[launch_record.DISPATCHED_BOOTS_KEY] = dispatched[-launch_record.MAX_DISPATCHED_BOOTS :]
    out.emit[launch_record.BOOT_UNVERIFIED_KEY] = timezone.now().isoformat()


def answered_already_launched(out: LaunchOutcome) -> bool:
    """An accepted launch the miner answered `already-launched`: it started
    nothing, and its measurement is NOT the running domain's — an earlier
    dispatch's is."""
    return (
        out.disposition == ACCEPTED
        and (getattr(out, "emit", None) or {}).get("classifier") == _ALREADY_LAUNCHED
    )


def _mark_measurement_launched(vm_id: str, measurement_hex: str) -> None:
    """Stamp `MeasurementLedger.launched_at` on this launch's pin: from now
    on it is the VM's current launch, and a guest of an earlier one is
    `superseded` (`apps.telemetry.guest_resources`). Best-effort like the
    ledger write itself — a lost stamp only means the earlier launches are
    not flagged — but never silent."""
    from django.utils import timezone

    from apps.orchestration.models import MeasurementLedger

    try:
        stamped = MeasurementLedger.objects.filter(
            vm_id=vm_id, launch_digest_hex__iexact=measurement_hex, launched_at__isnull=True
        ).update(launched_at=timezone.now())
    except Exception as exc:  # noqa: BLE001 — must not fail an accepted launch
        log.error(
            "measurement-ledger launched_at stamp failed vm=%s: %s — a guest of an "
            "earlier launch of this VM will not be flagged as superseded",
            vm_id,
            exc,
        )
        return
    if not stamped and not MeasurementLedger.objects.filter(
        vm_id=vm_id, launch_digest_hex__iexact=measurement_hex
    ).exists():
        # No pin row for this launch (no auto-pin, or its ledger write
        # failed — logged there): nothing can mark it current.
        log.error(
            "measurement-ledger: accepted launch vm=%s measurement=%s has NO ledger "
            "row — a guest of an earlier launch of this VM will not be flagged as "
            "superseded",
            vm_id,
            measurement_hex[:16],
        )


def _evict_superseded_launches(vm_id: str) -> None:
    """This launch is now the VM's current one: drop every earlier launch's
    measurement from the §22 allowlist (defence in depth — the KBS already
    refuses a superseded launch's ticket once this one registered, see
    `kbs_core::lifecycle::check_current_launch`). Never fails an accepted
    launch: a busy lock or an S3 / KBS error is retried by the
    orchestration tick (`sweep_superseded_measurements`), loudly."""
    try:
        allowlist_pin.evict_superseded_measurements()
    except (allowlist_pin.AllowlistPinBusy, EffectUnavailable, EffectError) as exc:
        log.error(
            "allowlist: could not evict the superseded launches after vm=%s was "
            "relaunched (%s) — still allowlisted until the tick retries",
            vm_id,
            exc,
        )
    except Exception:  # noqa: BLE001 — never lose an accepted launch over this
        log.exception(
            "allowlist: unexpected error evicting the superseded launches after vm=%s",
            vm_id,
        )


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
    from django.utils import timezone

    from apps.lifecycle.models import Vm, VmState

    # `state=ACTIVE` too: a §24 decommission that committed between the
    # register and this dispatch owns the row now, and stamping a host
    # there would re-point its destroy/EOL routing at a launch it is
    # already tearing down. Losing that race is harmless — the teardown
    # routes by `effects._bound_miner_id` — but it is logged.
    updated = Vm.objects.filter(vm_id=vm_id, host="", state=VmState.ACTIVE).update(
        host=node_id,
        # The boot-stall clock starts at the FIRST bind only: a same-miner
        # retry answered `already-launched` finds the host set and must not
        # push the verdict back.
        boot_started_at=timezone.now(),
        launch_abandoned_at=None,
        launch_abandoned_outcome="",
        launch_abandoned_registered=False,
    )
    if not updated:
        state = Vm.objects.filter(vm_id=vm_id).values_list("state", flat=True).first()
        if state is not None and state != VmState.ACTIVE:
            log.warning(
                "launch: vm=%s is %s — not stamping host=%s after the dispatch",
                vm_id,
                state,
                node_id,
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
    """CAS Pending→Failed for a rejected / errored launch attempt.

    `reason` is `launch_on_miner`'s outcome string, stored verbatim;
    `failure_source = launch` is the provenance the operator readout
    selects on before it maps that string (`apps.scheduler.reasons`)."""
    from django.utils import timezone

    from apps.scheduler.models import Placement, PlacementFailureSource, PlacementStatus

    Placement.objects.filter(
        id=placement.id,
        version=placement.version,
        status=PlacementStatus.PENDING.value,
    ).update(
        status=PlacementStatus.FAILED.value,
        version=placement.version + 1,
        failed_at=timezone.now(),
        reason=(reason or "launch-failed")[:256],
        failure_source=PlacementFailureSource.LAUNCH,
    )
