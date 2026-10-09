#!/usr/bin/env bash
#
# ┌────────────────────────────────────────────────────────────────┐
# │  Production path is `vali_tenant_bake_create` (#334 Phase 2).  │
# │                                                                │
# │  This script is the bake-logic source-of-truth that the        │
# │  `hippius-tenant-baker` container image copies in + runs from  │
# │  its entrypoint when the operator POSTs to                     │
# │  `/v1/tenant-bakes`. Running it directly from an operator      │
# │  workstation is still supported but DISCOURAGED — production   │
# │  deployments do NOT give the operator workstation root access  │
# │  to qemu-img / cryptsetup / losetup / chroot.                  │
# │                                                                │
# │  Modern operator workflow:                                     │
# │    1. Stage KEK in Vault via tenant-secrets-stage.sh.          │
# │    2. Call `python manage.py vali_tenant_bake_create ...`      │
# │       which spawns a k8s Job running THIS script inside the    │
# │       `hippius-tenant-baker` pod, and emits the resulting      │
# │       sha256s + measurement_hex on stdout.                     │
# │    3. Feed the envelope into `vali_create_vm`.                 │
# │                                                                │
# │  See docs/operator/byo-base-os-bake-runbook.md for the         │
# │  end-to-end runbook + `vali/apps/tenant_bake/README.md` for    │
# │  the API contract.                                             │
# └────────────────────────────────────────────────────────────────┘
#
# `tenant-image-bake.sh` — bake a Hippius-ready encrypted qcow2 from a
# vanilla cloud image (Ubuntu / Debian) by injecting the Hippius KBS
# keyscript into the distro's own initramfs and LUKS-encrypting the
# root partition.
#
# Architecture (§257 Phase B production-ready path)
# -------------------------------------------------
# This script replaces the abandoned custom Rust agent-initramfs
# tenant-luks pivot (which failed at `switch-root-failed:mount-rootfs`
# because `libcryptsetup-rs` can't substitute for `udev` in the
# `mount(2)` device-node resolution path — see issue #257 comment
# 4565408534 + memory `byo-os-mount-rootfs-enoent.md`).
#
# Adapted from `thenervelab/hccs::hcc-image-builder::ubuntu.rs` (the
# `UbuntuImageInstaller::generate_chroot_script` function), tailored
# to the Hippius KBS release model (the legacy `agent-initramfs::
# stages::verify` library exposed via the new `hippius-guest-release`
# binary the operator builds + drops into the image).
#
# What it produces
# ----------------
#   ${HCC_BAKE_OUTPUT_DIR}/
#     ├── tenant-<base-name>.qcow2          # LUKS-encrypted root
#     ├── tenant-<base-name>.sha256         # output qcow2 digest
#     └── tenant-<base-name>.measurement.json
#
# Bake flow
# ---------
#   1. Download + sha256-verify the base cloud image.
#   2. `qemu-img convert` to raw + `losetup --partscan` it.
#   3. Mount the root partition + bind /dev /proc /sys.
#   4. `chroot` in and:
#        - `apt install cryptsetup cryptsetup-initramfs initramfs-tools`
#        - drop the keyscript at `/etc/hippius/hippius-luks-keyscript`
#        - drop the hook at `/etc/initramfs-tools/hooks/hippius-luks`
#        - install the cross-built `hippius-guest-release` +
#          `hippius-vsock-ticket` binaries to `/usr/sbin/`
#        - add `IP=dhcp` to `/etc/initramfs-tools/initramfs.conf`
#        - add the `cryptroot ... keyscript=/sbin/hippius-luks-keyscript`
#          entry to `/etc/crypttab`
#        - `update-initramfs -u -k <extracted-kernel-version>`
#   5. Unmount + `losetup -d`.
#   6. `cryptsetup luksFormat --type luks2 --batch-mode --pbkdf
#      pbkdf2 --key-file=-` on a fresh qcow2 partition + `e2image`
#      the customised root's used blocks in.
#   7. Convert back to qcow2 + compute sha256.
#
# Native-only (like hccs::scripts/build-hccam-image.sh) — needs root
# for qemu-img, cryptsetup, losetup, mount, chroot.
#
# §20 secret discipline
# ---------------------
# - The LUKS KEK never lands in any file the bake writes. It flows
#   from `--kek-source vault|stdin|file` → SSH stdin (mirrored from
#   the now-archived `tenant-disk-create.sh` pattern, with the SSH
#   step replaced by a local pipe — the bake runs on the operator
#   workstation, not on the miner) → `cryptsetup luksFormat
#   --key-file=-`.
# - `bash -x` is intentionally NOT supported; cleanup trap guards
#   against partial unencrypted root mounts surviving on disk.
# - Output qcow2 has no plaintext credentials (the keyscript fetches
#   the KEK at boot from KBS; nothing is baked in).
#
# §257 AES-XTS malleability — closed
# ----------------------------------
# Step 6 of the bake formats with `--integrity hmac-sha256` so every
# 512-byte sector is HMAC-tagged. A malicious miner that flips
# ciphertext bits triggers EIO at the dm-integrity layer instead of
# delivering attacker-controlled plaintext to the guest. The runbook's
# "AES-XTS integrity is not yet enabled" warning is no longer current.

set -Eeuo pipefail

# ── Secret hygiene trap ─────────────────────────────────────────────
cleanup() {
    local rc=$?
    set +e
    # The xfs→ext4 rsync copy holds TWO mounts simultaneously (source
    # ro at SRC_MNT, the LUKS mapper at DST_MNT) — release both before
    # the mapper close.
    if [[ -n "${DST_MNT:-}" ]]; then
        sudo umount "${DST_MNT}" 2>/dev/null || true
    fi
    if [[ -n "${SRC_MNT:-}" ]]; then
        sudo umount "${SRC_MNT}" 2>/dev/null || true
    fi
    if [[ -n "${LOOP_DEV:-}" ]]; then
        sudo umount -R "${MNT_ROOT:-}" 2>/dev/null || true
        sudo cryptsetup close hippius-bake 2>/dev/null || true
        sudo losetup -d "${LOOP_DEV}" 2>/dev/null || true
    fi
    if [[ -n "${WORK_DIR:-}" && -d "${WORK_DIR}" ]]; then
        # The work dir holds the customised plaintext root for a few
        # seconds between chroot-exit and LUKS-encrypt. Wipe it on
        # ANY exit path so a crashed bake doesn't leave a tenant's
        # rootfs on the operator workstation.
        sudo rm -rf -- "${WORK_DIR}"
    fi
    if [[ -n "${KEK_TMPFS_DIR:-}" && -d "${KEK_TMPFS_DIR}" ]]; then
        # Best-effort overwrite-then-unlink. /dev/shm is tmpfs so it
        # never hits backing storage, but `shred` mirrors §20 secret
        # discipline if the operator's /dev/shm is unexpectedly disk-
        # backed.
        sudo shred -u -- "${KEK_TMPFS_DIR}"/* 2>/dev/null || true
        sudo rm -rf -- "${KEK_TMPFS_DIR}"
    fi
    unset KEK_B64 KEK_FILE_FD
    exit "$rc"
}
trap cleanup EXIT

# ── Defaults ────────────────────────────────────────────────────────

PROG="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# The in-cluster baker pod (binaries/tenant-baker) runs this script
# as root in a container image that does NOT ship `sudo`. On an
# operator workstation the script runs unprivileged and needs the
# real sudo. Shim only when we're already root AND sudo is absent —
# so the workstation path is untouched and the pod path stops
# failing at the first `sudo losetup`.
if [[ ${EUID} -eq 0 ]] && ! command -v sudo >/dev/null 2>&1; then
    sudo() { "$@"; }
fi

# Materialise /dev/loopNpM partition nodes after a `losetup
# --partscan`. On a workstation udev creates them; inside the baker
# pod there is no udev and the container's /dev is a static snapshot
# from start-time, so kernel-created partitions never appear and the
# partition discovery dies with "no ext4/xfs/btrfs partition found"
# (observed live 2026-06-10). sysfs always reflects the kernel's
# truth — mknod from its `dev` files. Idempotent; harmless no-op on
# a udev host where the nodes already exist.
ensure_loop_partitions() {
    local loopdev="$1" base sys name devno cur
    base="$(basename "${loopdev}")"
    for sys in "/sys/block/${base}/${base}"p*; do
        [[ -e "${sys}" ]] || continue
        name="$(basename "${sys}")"
        devno="$(cat "${sys}/dev")"
        if [[ -b "/dev/${name}" ]]; then
            # A node from a PREVIOUS attach can go stale after
            # growpart + partprobe (the kernel deletes + re-adds the
            # partition; opens then fail ENXIO — observed live
            # 2026-06-10, bake take-7). Compare the node's
            # major:minor against sysfs truth and re-mknod on drift.
            cur="$(stat -c '%Hr:%Lr' "/dev/${name}" 2>/dev/null || echo '?')"
            if [[ "${cur}" == "${devno}" ]]; then
                continue
            fi
            sudo rm -f "/dev/${name}"
        fi
        sudo mknod "/dev/${name}" b "${devno%%:*}" "${devno##*:}"
    done
}
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
KEYSCRIPT_SRC="${SCRIPT_DIR}/initramfs/hippius-luks-keyscript"
# Shared §21 release core (multi-OS series): sourced by BOTH the
# Debian-family keyscript and the RHEL-family dracut runner.
CORE_SRC="${SCRIPT_DIR}/initramfs/hippius-release-core.sh"
# RHEL-family dracut module dir (multi-OS): installed into the guest at
# /usr/lib/dracut/modules.d/90hippius-luks/ by stage_unlock_assets_rhel.
DRACUT_MODULE_SRC="${SCRIPT_DIR}/dracut/90hippius-luks"
HOOK_SRC="${SCRIPT_DIR}/initramfs/hippius-luks-hook"
# Debian family: last-running initramfs hook that keeps the BUILD HOST's
# state (md arrays, efivarfs, /dev/random seed) out of the guest initrd.
HOST_STATE_HOOK_SRC="${SCRIPT_DIR}/initramfs/hippius-host-state-hook"
# Debian family: initramfs hook making Ubuntu's initramfs dhcpcd send the
# raw-MAC client-id the booted guest sends (#289 multi-IP).
DHCP_CLIENTID_HOOK_SRC="${SCRIPT_DIR}/initramfs/hippius-dhcp-clientid-hook"
# GOLDEN-mode (disk_mode=golden_verity_overlay, golden-bake PR3) guest
# boot assets — staged into the chroot ONLY in golden mode so the
# regenerated initrd carries the overlay assembly. Legacy images never
# see these files → their initrd is byte-identical.
GOLDEN_OVERLAY_SRC="${SCRIPT_DIR}/initramfs/hippius-golden-overlay.sh"
GOLDEN_BOOT_SRC="${SCRIPT_DIR}/initramfs/hippius-golden-boot"
GOLDEN_HOOK_SRC="${SCRIPT_DIR}/initramfs/hippius-golden-hook"
# RHEL-family (dracut) GOLDEN-mode module dir — the dracut counterpart of
# the initramfs-tools golden boot/hook pair. Installed into the guest at
# /usr/lib/dracut/modules.d/95hippius-golden/ ONLY for RHEL golden bakes;
# owns /sysroot assembly (dm-verity lower + guest-keyed overlay upper).
GOLDEN_DRACUT_MODULE_SRC="${SCRIPT_DIR}/dracut/95hippius-golden"
# §23 keepalive ExecStart shim — reads the PER-VM identity
# (hippius.vm_id / node_id / kbs_url / telemetry_epoch) off the MEASURED
# cmdline and execs `hippius-agent-keepalive`. A committed file, not a
# heredoc, so shellcheck + `scripts/dev/keepalive-unit-test.sh` can lint
# and EXECUTE the exact bytes the guest runs.
KEEPALIVE_SHIM_SRC="${SCRIPT_DIR}/guest/hippius-keepalive-start"
CDN_INSTALL_SRC="${SCRIPT_DIR}/cdn-node/install-cdn-node.sh"
# #289 — init-bottom DHCP/static teardown. Installed into the guest's
# `/etc/initramfs-tools/scripts/init-bottom/` (NOT hook-copied into
# DESTDIR — mkinitramfs generates the `ORDER` execution manifest from
# the rootfs script dirs BEFORE hooks run, so a hook-copied script is
# shipped but never executed). Runs right before `switch_root` and
# flushes IPv4 state on every non-`lo` interface so userspace starts
# with a clean NIC.
NET_TEARDOWN_SRC="${SCRIPT_DIR}/initramfs/hippius-net-teardown"

base_image_url=""
base_image_sha256=""
output_dir="${HCC_BAKE_OUTPUT_DIR:-./out/tenant-bake}"
# #365: the rootfs is a fixed, flavor-INDEPENDENT minimal image. This
# is the ONLY knob that sizes it; --flavor no longer touches it (the
# flavor's disk_gb is a separate miner-attached data disk — see the
# `--flavor` resolution block below). ~10 GiB comfortably holds a
# minimal Ubuntu cloud rootfs (used blocks ~2–3 GiB) plus slack.
output_qcow2_gb="${HCC_BAKE_QCOW2_GB:-10}"
flavor=""
# Multi-OS (#multi-distro): `--distro auto` (default) detects the guest
# distro from the mounted image's /etc/os-release and dispatches the
# package-manager / initramfs / unlock / copy decisions. A non-`auto`
# value is an ASSERTION — the bake dies if the detected ID disagrees —
# never a selector (the image's content, not a flag, decides what
# tooling is present). Supported IDs resolved by `resolve_distro_plan`.
distro="auto"
print_plan_osrelease=""   # set by --print-plan FILE (dry-run, no root)
# No built-in default: the KBS a guest attests to is deployment
# config. Set $HIPPIUS_KBS_URL or pass --kbs-url.
kbs_url="${HIPPIUS_KBS_URL:-}"
hippius_release_bin=""
hippius_vsock_bin=""
# Optional §24/§25 guest shutdown-sign binary (hippius-agent-initramfs).
# Empty ⇒ the shutdown hook is NOT baked (the §25 cold-migration ack
# delivery then fails closed — see --hippius-eol-bin in the help).
hippius_eol_bin=""
# Optional §23 served-receipt telemetry agent (hippius-agent-tenant-telemetry).
# Empty ⇒ the telemetry service is NOT baked (uptime billing stays inert —
# no guest emits served receipts; see --hippius-telemetry-bin in the help).
hippius_telemetry_bin=""
# Optional §23 SNP live-attestation keepalive agent (hippius-agent-keepalive).
# Empty ⇒ the keepalive service is NOT baked, no guest ever produces a
# `SignedLiveAttestation`, vali's `VmLiveAttestation` table stays empty and
# `uptimeLiveness.requireAttestation` can NEVER be armed (arming it would
# zero the whole fleet's uptime credit). See --hippius-keepalive-bin.
hippius_keepalive_bin=""
# Guest keepalive tick cadence, seconds. MUST be <= vali's
# `uptimeLiveness.coverageSeconds` (deploy/gitops/apps/vali/values.yaml,
# currently 900): one attestation vouches BACKWARD for exactly that span,
# so samples spaced further apart leave uncovered gaps in genuinely-live
# time that the armed gate credits as ZERO. 300 s is a third of the span,
# leaving headroom for restarts and transient KBS failures.
# `scripts/dev/keepalive-unit-test.sh` pins this default against the CHART
# value, so lowering coverageSeconds below the cadence fails CI instead of
# silently un-crediting honest uptime.
keepalive_interval_secs=300
# vali's `uptimeLiveness.coverageSeconds` — how far BACK one liveness
# sample vouches. The bake refuses any cadence above it (see the
# validation block). Mirrored here because the bake cannot read the chart;
# `scripts/dev/keepalive-unit-test.sh` diffs the two, so a chart change
# that would invalidate this ceiling fails CI.
KEEPALIVE_MAX_INTERVAL_SECS=900
# AF_VSOCK port on the host the guest pushes its signed attestation to —
# the miner-agent's `VSOCK_RELAY_PORT` guest-frame listener, the same one
# the §23 served-receipt pusher uses. 0 would DISABLE the push (minted
# KBS-side, never delivered to vali) so it is rejected.
keepalive_relay_port=5000
kek_source="stdin"
kek_file=""
# NetBird overlay agent — PINNED version pre-installed into the tenant
# image during the chroot (see the "NetBird pre-install" blocks in the
# apt + dnf chroot arms). Pinned (never `latest`) so the agent is part
# of the reproducible/measured build. Kept in lock-step with the miner
# side (deploy/ansible/group_vars/miner_nodes.yml `versions.netbird`).
# Override for a bump via HCC_BAKE_NETBIRD_VERSION.
#
# WHY pre-install: NetBird's first-boot installer
# (`curl … pkgs.netbird.io/install.sh | sh`) runs
# `apt-get install -y ca-certificates curl gnupg`, which tries to
# UPGRADE the `curl`/`ca-certificates` the bake holds (apt-mark hold,
# for reproducible/measured images) → apt aborts with `E: Held packages
# were changed and -y was used without --allow-change-held-packages`,
# netbird never installs, first-boot `netbird up` → `netbird: not
# found`, and the guest never joins the overlay (prodcheck-1/-2 saw
# setup-key used=0). Pre-installing here removes the boot-time
# apt/internet dependency entirely and keeps the holds intact.
netbird_version="${HCC_BAKE_NETBIRD_VERSION:-0.71.3}"
# #284 reproducibility: epoch the chroot uses for every timestamp.
# `update-initramfs` / `mkinitramfs` already honor `SOURCE_DATE_EPOCH`
# (Debian / Ubuntu's initramfs-tools have respected it since 0.131,
# 2017). Set to the COMMIT timestamp of the bake script or any other
# stable value — two operators running the bake with the same epoch +
# same inputs should converge on the same output SHAs. Without it
# every bake stamps the cpio with the wall-clock time → guaranteed
# divergence. Default: 1970-01-02T00:00:00Z (a non-zero epoch — some
# tools special-case `0` as "fall back to live clock").
source_date_epoch="${SOURCE_DATE_EPOCH:-86400}"
# Stage-1 cache (perf): when set to a writable directory, the
# tenant-INDEPENDENT half of the bake (download base image → chroot
# customise → extract kernel/initramfs; stages 1-5) is stored there
# content-addressed and reused by subsequent bakes. The cache key
# covers every input that shapes the stage-1 bytes: base image sha,
# this script, the keyscript/hook/teardown sources, both release
# binaries, the grow size, and SOURCE_DATE_EPOCH — so ANY change to
# ANY input misses cleanly and rebuilds. Cached artifacts are
# sha256-verified on load (fail → rebuild, never trust a torn entry).
# Empty (the default) disables caching — workstation behavior
# unchanged. The in-cluster baker mounts a PVC here via
# `VALI_TENANT_BAKE_CACHE_PVC`.
stage1_cache_dir="${HCC_BAKE_STAGE1_CACHE_DIR:-}"

# ── Golden dm-verity base mode (golden-bake PR1) ─────────────────────
# `--disk-mode` selects how the customised root is packaged at stage 6:
#
#   legacy_luks (DEFAULT, unchanged) — the current path: `luksFormat`
#     a per-VM LUKS2+integrity vda with the tenant's KEK, e2image the
#     used blocks in, emit `tenant-*.qcow2`. Per-tenant confidential
#     writable root. LEFT FULLY INTACT.
#
#   golden_verity_overlay (NEW, feature-flagged, INERT until PR2-PR6) —
#     package the SHARED customised root as a READ-ONLY dm-verity base
#     (squashfs `rootfs.img` + `rootfs.verity` hash tree), byte-identical
#     across every same-distro tenant so the miner-agent content-addressed
#     image cache (#823) HITs on it → fresh launches ~15min→~2-3min. The
#     base is INTEGRITY-ONLY + NON-CONFIDENTIAL: it is a public distro OS
#     carrying NO tenant secret (per-tenant userdata/SSH keys arrive via
#     the §21 KBS release to tmpfs; ALL per-VM writes land on a guest-keyed
#     overlay generated inside the SNP guest — PR3). It consumes NO KEK.
#
# WHY dm-verity and NOT a shared-master-key LUKS `--integrity` volume for
# the base (the make-or-break invariant): a golden disk shares ONE LUKS
# master key across all same-distro tenants. Under a FULLY UNTRUSTED miner
# that holds the golden disk, a miner running its OWN same-distro VM could
# extract that MK and — because LUKS2 `--integrity` folds the HMAC key into
# the MK — FORGE integrity-valid tampered ciphertext for every victim guest
# (RCE), not just read at rest. dm-verity is an UNKEYED Merkle tree whose
# root hash is folded into the SNP-MEASURED cmdline (PR2), so a host-tampered
# block is caught (EIO) with NO shared secret key in play. Reuses the
# veritysetup machinery + pinned zero salt/uuid from
# `packer/tenant-uki/uki/scripts/build-rootfs.sh` (no new crypto).
disk_mode="${HCC_BAKE_DISK_MODE:-legacy_luks}"
# Package refresh (F6, scheduled golden re-bake): a non-empty stamp makes
# the chroot apply every pending distro update (apt dist-upgrade / dnf
# upgrade) before the hippius install, and folds the stamp into the
# stage-1 cache key so the refresh cannot be served from a cached stage-1
# baked against older packages. Empty (the default) keeps the bake
# byte-identical to a bake without the flag: no upgrade, same packages as
# the dated base image ships plus what the bake installs.
package_refresh="${HCC_BAKE_PKG_REFRESH:-}"
# Bake profile (CDN plan I3). `standard` is every existing bake, unchanged.
# `cdn-node` additionally stages the CDN data plane (OpenResty + cdn-agent),
# removes sshd and bakes the public-IP inbound guard and input firewall —
# golden_verity_overlay + Debian family only. Its inputs are required
# with it and refused without it.
profile="${HCC_BAKE_PROFILE:-standard}"
cdn_agent_bin=""
cdn_openresty_tarball=""
cdn_config_dir=""
cdn_backend_url=""
cdn_fleet_wildcard=""
# Pinned verity parameters — IDENTICAL to build-rootfs.sh so the root hash
# and the `rootfs.verity` bytes are byte-reproducible across same-distro
# bakes. `veritysetup format`'s salt AND uuid both default to random; the
# salt folds into the Merkle tree (changes the root hash) and the uuid
# lives in the verity superblock (changes the file bytes), so BOTH must be
# pinned for a stable cache key.
VERITY_SALT="0000000000000000000000000000000000000000000000000000000000000000"
VERITY_UUID="00000000-0000-0000-0000-000000000000"
VERITY_HASH_ALG="sha256"
VERITY_BLOCK_SIZE="4096"

# ── Logging ─────────────────────────────────────────────────────────

log() { printf '%s: %s\n' "${PROG}" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# SSRF-safe HTTPS fetch (audit RA-M1). The vali intake check validated
# base_image_url at POST time, but this baker runs LATER in a DIFFERENT
# pod: re-resolving the host here is exposed to DNS-rebinding, and a plain
# `curl -L` would follow a redirect into an internal target (the cloud
# metadata endpoint / RFC-1918 / an in-cluster service). Resolve the host
# ONCE, reject any non-public address (same public-only policy as the vali
# intake check), PIN the IPs for the connection (`--resolve`, so curl
# never re-resolves ⇒ no rebind window), and FORBID redirects
# (`--max-redirs 0` ⇒ no redirect into an internal target). The caller's
# SHA256 check still verifies integrity of the fetched bytes afterwards.
# The heredoc is QUOTED (<<'PY') and the URL is passed via argv, so the
# outer shell never expands the body (bake-heredoc-guard requirement).
#
# MULTI-ADDRESS (2026-08, bake c08e520e05044c9a894214e250bf950e — golden
# fedora — died with `curl: (18) end of response with 402721299 bytes
# missing`, i.e. a mirror truncated ~1.6 GB into a ~2 GB transfer):
#   * `--retry` does NOT cover a truncated transfer. curl retries only the
#     classes it calls transient (timeouts, 408, 429, 5xx); a short body is
#     exit 18 and is never retried. `--retry 3` was already on that command
#     and the bake still died on the FIRST truncation.
#   * the guard resolved SIX addresses for dl.fedoraproject.org, validated
#     every one of them, and then pinned only the FIRST — so a single
#     degraded mirror killed a bake that had two healthy validated public
#     IPv4s sitting unused.
# So the resolver now emits EVERY validated public address (IPv4 first —
# the baker pod's egress is IPv4 — with IPv6 kept, just ordered after) and
# the transfer walks them, a bounded number of rounds.
#
# The security properties are UNCHANGED and are hard constraints:
#   * every address curl connects to came out of the fail-CLOSED policy
#     below. A non-public address ANYWHERE in the resolution set aborts
#     the WHOLE fetch — it is NEVER skipped in favour of a good sibling.
#     That refusal IS the DNS-rebinding defence: a rebinding attacker's
#     answer set is "one public + one internal", and "skip the bad one"
#     would turn the defence into a no-op.
#   * `--resolve` still pins, so curl never re-resolves mid-fetch.
#   * `--max-redirs 0` still forbids redirects.
#   * the caller's sha256 over the fetched bytes remains the integrity
#     authority; nothing here weakens it.
# There is deliberately NO env var that disables any of this.

# Address policy + resolution. Echoes `<host> <port> <addr>...` on stdout
# (IPv4 first, then IPv6, duplicates collapsed, resolution order otherwise
# preserved) and exits non-zero with the reason on stderr if the guard
# REFUSES. On refusal NOTHING is printed — a caller cannot accidentally
# use a "good" address out of a refused set.
ssrf_resolve_public_addrs() {
    python3 - "$1" <<'PY'
import ipaddress
import socket
import sys
from urllib.parse import urlsplit


def is_public(addr):
    """The ONE definition of "safe for the baker to connect to".

    Kept as a named predicate so scripts/dev/ssrf-fetch-test.sh can drive
    it directly instead of the policy being loosened to make it testable.
    """
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast
                or addr.is_unspecified)


u = urlsplit(sys.argv[1])
host = u.hostname
if not host:
    sys.exit("no host in url")
port = u.port or (443 if u.scheme == "https" else 80)
try:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
except OSError:
    sys.exit("host does not resolve")
v4 = []
v6 = []
for info in infos:
    addr = ipaddress.ip_address(info[4][0])
    if not is_public(addr):
        # FAIL CLOSED for the WHOLE fetch. Skipping this one and using a
        # public sibling would defeat the DNS-rebinding defence.
        sys.exit("non-public address in resolution set: %s (refusing the "
                 "whole fetch, not just this address)" % addr)
    bucket = v4 if addr.version == 4 else v6
    if str(addr) not in bucket:
        bucket.append(str(addr))
addrs = v4 + v6
if not addrs:
    sys.exit("host resolved to no usable address")
print("%s %s %s" % (host, port, " ".join(addrs)))
PY
}

# Transfer the URL, pinned in turn to each ALREADY-VALIDATED address, for a
# bounded number of rounds (`HCC_BAKE_FETCH_ROUNDS`, default 2 — bounded so a
# permanently broken upstream cannot spin the baker Job forever; it is a
# retry budget, NOT a switch that can relax any part of the guard).
# Args: <url> <out> <host> <port> <addr>...
#
# Each attempt re-fetches FROM SCRATCH. `-C -` resume is deliberately NOT
# used: a resumed transfer that switched mirrors would concatenate bytes
# from two sources. The sha256 would catch that, but not paying the
# bandwidth is worth less than not having to reason about it.
#
# The partial output is deleted BEFORE every attempt and after the final
# failure, so a truncated file can never be mistaken downstream for a
# complete image.
ssrf_pinned_fetch_rounds() {
    local url="$1" out="$2" host="$3" port="$4"
    shift 4
    local addrs=("$@")
    local rounds="${HCC_BAKE_FETCH_ROUNDS:-2}"
    local round ip rc last_rc=0 tried=""
    for (( round = 1; round <= rounds; round++ )); do
        for ip in "${addrs[@]}"; do
            log "fetch: attempt ${round}/${rounds} pinned ${host}:${port} -> ${ip} (no-redirect)"
            rm -f -- "${out}"
            rc=0
            curl -fsS -L --max-redirs 0 --retry 3 --retry-delay 2 \
                --resolve "${host}:${port}:${ip}" \
                -o "${out}" "${url}" || rc=$?
            if [[ "${rc}" -eq 0 ]]; then
                log "fetch: transfer complete from ${ip} (attempt ${round}/${rounds})"
                return 0
            fi
            last_rc="${rc}"
            tried="${tried}${tried:+, }${ip} (curl exit ${rc})"
            log "fetch: TRANSFER from ${ip} failed with curl exit ${rc} — the guard allowed this address; retrying against the next validated address"
        done
    done
    rm -f -- "${out}"
    log "ERROR: TRANSFER failed from every validated public address after ${rounds} round(s): ${tried}; last curl exit ${last_rc}"
    return 3
}

# Returns 0 on success, 2 when the GUARD REFUSED (host unresolvable or a
# non-public address in the set — upstream was never contacted), 3 when the
# guard allowed the fetch but every transfer failed. The caller turns those
# into distinct messages: "base image fetch failed (ssrf-guard or curl)"
# cost a live debugging cycle chasing a guard that had done nothing wrong.
ssrf_safe_https_fetch() {
    local url="$1" out="$2" resolved host port rest
    local addrs=()
    if ! resolved="$(ssrf_resolve_public_addrs "${url}")"; then
        log "ERROR: ssrf-guard REFUSED ${url} (reason above) — upstream was NOT contacted"
        rm -f -- "${out}"
        return 2
    fi
    read -r host port rest <<<"${resolved}"
    read -r -a addrs <<<"${rest}"
    if [[ "${#addrs[@]}" -eq 0 ]]; then
        log "ERROR: ssrf-guard returned no address for ${url}"
        return 2
    fi
    log "fetch: guard validated ${#addrs[@]} public address(es) for ${host}:${port}: ${addrs[*]}"
    ssrf_pinned_fetch_rounds "${url}" "${out}" "${host}" "${port}" "${addrs[@]}"
}

# ── Multi-OS dispatch (#multi-distro) ───────────────────────────────
#
# `resolve_distro_plan` is the SINGLE source of dispatch truth: given an
# `/etc/os-release` ID / VERSION_ID / ID_LIKE it echoes shell-eval-able
# `DISTRO_*` assignments describing every per-distro decision. Both the
# runtime path (`detect_distro`, after the root mount) and the no-root
# `--print-plan` dry-run consume it, so the golden CI test and the live
# bake can never disagree.
#
# Families:
#   debian — apt + initramfs-tools + cryptsetup-initramfs keyscript=
#            (Ubuntu + Debian). The unlock path that exists today.
#   rhel   — dnf + dracut + the 90hippius-luks keyfile module
#            (CentOS Stream + Fedora). Wired in the RHEL-family PRs;
#            until then the runtime dies loudly for this family.
resolve_distro_plan() {
    local id="$1" ver="$2" like="$3"
    local family kernel_pkg pkgmgr initramfs unlock
    case "${id}" in
        ubuntu)
            family=debian; pkgmgr=apt; initramfs="initramfs-tools"; unlock=keyscript
            kernel_pkg="linux-image-virtual" ;;
        debian)
            family=debian; pkgmgr=apt; initramfs="initramfs-tools"; unlock=keyscript
            # full linux-image-amd64 (NOT -cloud-): the cloud kernel may
            # omit sev-guest/tsm. The module gate is the enforcement.
            kernel_pkg="linux-image-amd64" ;;
        centos|rhel|almalinux|rocky)
            family=rhel; pkgmgr=dnf; initramfs=dracut; unlock=keyfile
            kernel_pkg="kernel-core" ;;
        fedora)
            family=rhel; pkgmgr=dnf; initramfs=dracut; unlock=keyfile
            kernel_pkg="kernel-core" ;;
        *)
            # Fall back on ID_LIKE so derivatives resolve.
            case " ${like} " in
                *" debian "*|*" ubuntu "*)
                    family=debian; pkgmgr=apt; initramfs="initramfs-tools"; unlock=keyscript
                    kernel_pkg="linux-image-amd64" ;;
                *" rhel "*|*" fedora "*|*" centos "*)
                    family=rhel; pkgmgr=dnf; initramfs=dracut; unlock=keyfile
                    kernel_pkg="kernel-core" ;;
                *)
                    echo "DISTRO_UNSUPPORTED=1"
                    return 0 ;;
            esac ;;
    esac
    printf 'DISTRO_ID=%q\n'          "${id}"
    printf 'DISTRO_VERSION=%q\n'     "${ver}"
    printf 'DISTRO_FAMILY=%q\n'      "${family}"
    printf 'DISTRO_PKGMGR=%q\n'      "${pkgmgr}"
    printf 'DISTRO_INITRAMFS=%q\n'   "${initramfs}"
    printf 'DISTRO_UNLOCK=%q\n'      "${unlock}"
    printf 'DISTRO_KERNEL_PKG=%q\n'  "${kernel_pkg}"
}

# Read os-release KEY from a file without sourcing it into our shell
# (avoids an attacker-controlled os-release running code at bake time).
osrelease_field() {
    local file="$1" key="$2" line
    line="$(grep -E "^${key}=" "${file}" 2>/dev/null | head -1)" || return 0
    line="${line#"${key}"=}"
    # strip surrounding quotes
    line="${line%\"}"; line="${line#\"}"
    printf '%s' "${line}"
}

# Detect + assert the distro from a mounted root's /etc/os-release, then
# populate the DISTRO_* globals. `--distro X` (non-auto) is verified
# against the detected ID and dies on mismatch.
detect_distro() {
    local osr="$1"
    [[ -r "${osr}" ]] || die "no readable /etc/os-release in image (${osr}) — cannot detect distro (exit 3)"
    local id ver like
    id="$(osrelease_field "${osr}" ID)"
    ver="$(osrelease_field "${osr}" VERSION_ID)"
    like="$(osrelease_field "${osr}" ID_LIKE)"
    [[ -n "${id}" ]] || die "os-release has no ID= field (exit 3)"
    local plan; plan="$(resolve_distro_plan "${id}" "${ver}" "${like}")"
    if [[ "${plan}" == *"DISTRO_UNSUPPORTED=1"* ]]; then
        die "unsupported distro ID=${id} ID_LIKE='${like}' — supported: ubuntu, debian, centos/rhel/almalinux/rocky, fedora (exit 3)"
    fi
    eval "${plan}"
    if [[ "${distro}" != "auto" && "${distro}" != "${DISTRO_ID}" ]]; then
        die "--distro ${distro} but the image is ID=${DISTRO_ID} (exit 1)"
    fi
    log "distro: ${DISTRO_ID} ${DISTRO_VERSION} (family=${DISTRO_FAMILY} pkgmgr=${DISTRO_PKGMGR} initramfs=${DISTRO_INITRAMFS} unlock=${DISTRO_UNLOCK} kernel=${DISTRO_KERNEL_PKG})"
}

# `--print-plan FILE`: resolve the dispatch decisions from an os-release
# fixture and print them as JSON, WITHOUT root / network / a real image.
# Backs the CI golden test that pins per-distro behaviour.
print_plan() {
    local osr="$1"
    [[ -r "${osr}" ]] || die "--print-plan: cannot read ${osr}"
    local id ver like
    id="$(osrelease_field "${osr}" ID)"
    ver="$(osrelease_field "${osr}" VERSION_ID)"
    like="$(osrelease_field "${osr}" ID_LIKE)"
    local plan; plan="$(resolve_distro_plan "${id}" "${ver}" "${like}")"
    if [[ "${plan}" == *"DISTRO_UNSUPPORTED=1"* ]]; then
        printf '{"id":%s,"supported":false}\n' "$(json_str "${id}")"
        return 0
    fi
    eval "${plan}"
    printf '{"id":%s,"version":%s,"family":%s,"pkgmgr":%s,"initramfs":%s,"unlock":%s,"kernel_pkg":%s,"supported":true}\n' \
        "$(json_str "${DISTRO_ID}")" "$(json_str "${DISTRO_VERSION}")" \
        "$(json_str "${DISTRO_FAMILY}")" "$(json_str "${DISTRO_PKGMGR}")" \
        "$(json_str "${DISTRO_INITRAMFS}")" "$(json_str "${DISTRO_UNLOCK}")" \
        "$(json_str "${DISTRO_KERNEL_PKG}")"
}

# Minimal JSON string escaper (the only metachars os-release fields can
# realistically carry are " and \).
json_str() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '"%s"' "${s}"
}

usage() {
    cat >&2 <<EOF
${PROG} — bake a Hippius-ready encrypted qcow2 from a vanilla cloud image.

Usage:
  ${PROG} --base-image-url URL --base-image-sha256 HEX \\
          --hippius-release-bin PATH --hippius-vsock-bin PATH \\
          [--output-dir DIR] [--output-qcow2-gb N] \\
          [--flavor small|medium|large] \\
          [--kbs-url URL] \\
          [--kek-source stdin|file] [--kek-file PATH]

Required:
  --base-image-url URL    HTTPS / S3 URL of the Ubuntu or Debian
                          cloud-image qcow2 to start from. Same
                          accepted shape as
                          (matches the now-archived
                          tenant-disk-create.sh's --base-image-url
                          contract for cross-tool consistency).
  --base-image-sha256 HEX 64-hex SHA-256 of the original cloud-image
                          bytes (qcow2 format, not the converted raw).
  --hippius-release-bin P Path to the cross-built
                          \`hippius-guest-release\` binary
                          (x86_64-unknown-linux-gnu, dynamically
                          linked against the cloud image's glibc).
                          Build with:
                            cargo build --release \\
                              --bin hippius-guest-release \\
                              --target x86_64-unknown-linux-gnu
                          inside the pinned tenant-uki Docker image
                          for byte-reproducibility.
  --hippius-vsock-bin P   Path to \`hippius-vsock-ticket\` binary
                          (same build envelope).

Optional:
  --hippius-eol-bin P     Path to the \`hippius-agent-initramfs\` binary
                          (§24/§25 guest shutdown-sign hook). When given,
                          the bake stages it at /usr/sbin/hippius-agent-
                          initramfs and installs hippius-eol-sign.service
                          (Before=shutdown.target, runs \`eol --sign-only\`)
                          so a CLEAN guest shutdown (ACPI poweroff — which
                          a §25 quiesce / §24 decommission triggers) signs
                          + pushes the StoppedAck to vali BEFORE the disk
                          goes away. Build with:
                            cargo build --release \\
                              --bin hippius-agent-initramfs \\
                              --target x86_64-unknown-linux-gnu
                          (same pinned tenant-uki envelope as the two
                          required binaries). Omit to skip the hook — the
                          §25 cold-migration ack delivery then fails closed
                          (vali never gets the ack, the migration times out
                          and the source is quarantined; never advances).
  --hippius-telemetry-bin P
                          Path to the \`hippius-agent-tenant-telemetry\`
                          binary (§23 served-receipt agent). When given,
                          the bake stages it at /usr/sbin/hippius-agent-
                          tenant-telemetry and installs
                          hippius-tenant-telemetry.service (Type=simple,
                          Restart=on-failure) so the guest emits
                          guest-signed ServedDeliveryReceipts over vsock
                          for uptime billing. Build with:
                            cargo build --release \\
                              --bin hippius-agent-tenant-telemetry \\
                              --target x86_64-unknown-linux-gnu
                          Omit to skip the agent — uptime billing then
                          stays inert (no guest emits served receipts).
  --hippius-keepalive-bin P
                          Path to the \`hippius-agent-keepalive\` binary
                          (§23 SNP live-attestation keepalive). When given,
                          the bake stages it at /usr/sbin/hippius-agent-
                          keepalive, stages the cmdline shim at
                          /usr/sbin/hippius-keepalive-start, and installs +
                          ENABLES hippius-keepalive.service (Type=simple,
                          Restart=always) so from boot the guest proves it
                          is a live SEV-SNP CVM: each tick it asks
                          /dev/sev-guest for a fresh report bound to a
                          single-use KBS nonce, POSTs it to KBS
                          \`/v1/attest/keepalive\`, and relays the returned
                          SignedLiveAttestation over vsock → miner-agent →
                          Edge → vali \`/v1/telemetry/vm-liveness\`. Build:
                            cargo build --release \\
                              --bin hippius-agent-keepalive \\
                              --target x86_64-unknown-linux-gnu
                          Omit to skip it — no guest then produces a
                          liveness proof, vali's VmLiveAttestation table
                          stays empty, and \`uptimeLiveness.
                          requireAttestation\` can never be armed (arming
                          it would zero the whole fleet's uptime credit).
  --keepalive-interval-secs N
                          Guest keepalive tick cadence. Default 300. MUST
                          be <= vali's \`uptimeLiveness.coverageSeconds\`
                          (900): one sample vouches BACKWARD for that span,
                          so a wider cadence leaves uncovered gaps in live
                          time that the armed gate credits as ZERO.
  --keepalive-relay-port N
                          AF_VSOCK port of the host miner-agent's
                          guest-frame listener the signed attestation is
                          pushed to. Default 5000. 0 is REFUSED: it would
                          mint attestations that never reach vali.
  --output-dir DIR        Where to drop the baked qcow2 +
                          measurement. Default: \$HCC_BAKE_OUTPUT_DIR,
                          else \`./out/tenant-bake\`.
  --output-qcow2-gb N     Final qcow2 virtual size in GiB. Must be
                          ≥ raw cloud-image size + LUKS2 header
                          (~16 MiB) + dm-integrity overhead (~7 %
                          for \`--integrity hmac-sha256\`, see luksFormat
                          call site below). The bake script's
                          \`dst_size < src_size\` check fails closed if
                          the encrypted plaintext device cannot fit
                          the source root after integrity reservation.
                          Default: 10.
  --flavor NAME           Tenant VM size catalogue identifier (#312).
                          When set, overrides --output-qcow2-gb with
                          the canonical disk size for the named
                          \`hippius_types::flavor::Flavor\` variant:
                            small  → 8  GiB
                            medium → 16 GiB
                            large  → 32 GiB
                          Pair with \`vali_create_vm --flavor <same>\`
                          for matching cpu / memory at launch time.
                          The CI test \`flavor_bake_catalogue\` pins
                          this bash table to the Rust enum so future
                          drift surfaces loud.
  --distro auto|ID        Guest distro. Default \`auto\` detects it from
                          the mounted image's /etc/os-release. A
                          non-auto value (ubuntu|debian|centos|fedora)
                          is an ASSERTION — the bake dies if the image
                          disagrees. Resolves the apt-vs-dnf /
                          initramfs-tools-vs-dracut / keyscript-vs-keyfile
                          dispatch. (Debian family wired now; RHEL family
                          per the multi-OS PR series.)
  --print-plan FILE       Dry-run: resolve + print the per-distro
                          dispatch decisions for an os-release FILE as
                          JSON, then exit. No root / network / image.
  --disk-mode MODE        How the customised root is packaged at stage 6:
                            legacy_luks (default) — per-VM LUKS2+integrity
                              vda encrypted with the tenant KEK (the
                              current, unchanged path).
                            golden_verity_overlay — a SHARED read-only
                              dm-verity base (\`rootfs.img\` squashfs +
                              \`rootfs.verity\` hash tree), byte-identical
                              across same-distro tenants (cache HIT), no
                              KEK, integrity-only + non-confidential.
                              Emits the verity root hash for the measured
                              cmdline (PR2). INERT until the guest overlay
                              PRs (PR2-PR6) wire it — the base does not
                              boot on its own yet. Default: \$HCC_BAKE_DISK_MODE
                              else legacy_luks.
  --package-refresh STAMP Apply every pending distro update in the chroot
                          (apt dist-upgrade / dnf upgrade) and key the
                          stage-1 cache on STAMP ([A-Za-z0-9._-]{1,64}),
                          so a new STAMP always rebuilds with current
                          packages. Default: \$HCC_BAKE_PKG_REFRESH, else
                          empty (no upgrade).
  --profile NAME          standard (default) or cdn-node: the CDN cache
                          node image (golden_verity_overlay, Debian
                          family): OpenResty + cdn-agent staged, no
                          sshd, public-IP inbound guard + input firewall
                          baked. Default: \$HCC_BAKE_PROFILE, else
                          standard.
  --cdn-agent-bin PATH    cdn-node: the hippius-cdn-agent binary.
  --cdn-openresty-tarball PATH
                          cdn-node: the OpenResty tree (build-openresty.sh
                          output; PATH.sha256 must match).
  --cdn-config-dir PATH   cdn-node: the data-plane config dir as the
                          tenant-baker image lays it out (Lua,
                          nginx.conf.in, origin.conf, render.sh, and
                          geoip/ from fetch-geoip.sh).
  --cdn-backend-url URL   cdn-node: the backend base URL baked into the
                          agent config (https).
  --cdn-fleet-wildcard W  cdn-node: the fleet certificate's wildcard baked
                          into the agent config. Default: *.c.hipcdn.net.
  --kbs-url URL           KBS HTTPS base URL baked into the image's
                          kernel cmdline at install time. Default:
                          \$HIPPIUS_KBS_URL, else
                          e.g. https://kbs.example.invalid
                          REQUIRED — no built-in default.
  --kek-source SRC        Where to read the LUKS KEK (32 raw bytes):
                            stdin (default) — pipe in from your
                              secret manager.
                            file — --kek-file PATH.
  --kek-file PATH         Required with --kek-source=file.
  --source-date-epoch TS  #284 reproducibility: Unix timestamp the
                          chroot uses for every \`SOURCE_DATE_EPOCH\`-
                          aware tool (initramfs-tools, dpkg post-
                          install, etc.). Two operators running the
                          bake with the same TS + same inputs should
                          converge on the same output SHAs (verify
                          with \`scripts/verify-reproducible-bake.sh\`).
                          Default: \$SOURCE_DATE_EPOCH, else 86400
                          (1970-01-02T00:00:00Z).
  -h, --help              Show this header.

Output (stdout, single-line JSON):
  { "qcow2_path": "...", "qcow2_sha256": "<64 hex>",
    "qcow2_size_bytes": N, "base_image_url": "...",
    "base_image_sha256": "...", "kbs_url": "...",
    "luks_version": 2, "luks_pbkdf": "pbkdf2" }

Exit codes:
  0  — bake succeeded.
  1  — usage / input rejection.
  2  — host tooling missing (qemu-img / cryptsetup / debootstrap-tools).
  3  — bake step failed (download / sha / chroot / mount / cryptsetup).
EOF
}

require_arg() { [[ -n "${2-}" ]] || die "$1 requires a value"; }

# ── Parse args ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --base-image-url)       require_arg "$1" "${2-}"; base_image_url="$2";       shift 2;;
        --base-image-sha256)    require_arg "$1" "${2-}"; base_image_sha256="$2";    shift 2;;
        --hippius-release-bin)  require_arg "$1" "${2-}"; hippius_release_bin="$2";  shift 2;;
        --hippius-vsock-bin)    require_arg "$1" "${2-}"; hippius_vsock_bin="$2";    shift 2;;
        --hippius-eol-bin)      require_arg "$1" "${2-}"; hippius_eol_bin="$2";      shift 2;;
        --hippius-telemetry-bin) require_arg "$1" "${2-}"; hippius_telemetry_bin="$2"; shift 2;;
        --hippius-keepalive-bin) require_arg "$1" "${2-}"; hippius_keepalive_bin="$2"; shift 2;;
        --keepalive-interval-secs) require_arg "$1" "${2-}"; keepalive_interval_secs="$2"; shift 2;;
        --keepalive-relay-port) require_arg "$1" "${2-}"; keepalive_relay_port="$2"; shift 2;;
        --output-dir)           require_arg "$1" "${2-}"; output_dir="$2";           shift 2;;
        --output-qcow2-gb)      require_arg "$1" "${2-}"; output_qcow2_gb="$2";      shift 2;;
        --flavor)               require_arg "$1" "${2-}"; flavor="$2";               shift 2;;
        --distro)               require_arg "$1" "${2-}"; distro="$2";              shift 2;;
        --disk-mode)            require_arg "$1" "${2-}"; disk_mode="$2";           shift 2;;
        --package-refresh)      require_arg "$1" "${2-}"; package_refresh="$2";     shift 2;;
        --profile)              require_arg "$1" "${2-}"; profile="$2";             shift 2;;
        --cdn-agent-bin)        require_arg "$1" "${2-}"; cdn_agent_bin="$2";       shift 2;;
        --cdn-openresty-tarball) require_arg "$1" "${2-}"; cdn_openresty_tarball="$2"; shift 2;;
        --cdn-config-dir)       require_arg "$1" "${2-}"; cdn_config_dir="$2";      shift 2;;
        --cdn-backend-url)      require_arg "$1" "${2-}"; cdn_backend_url="$2";     shift 2;;
        --cdn-fleet-wildcard)   require_arg "$1" "${2-}"; cdn_fleet_wildcard="$2";  shift 2;;
        --print-plan)           require_arg "$1" "${2-}"; print_plan_osrelease="$2"; shift 2;;
        --kbs-url)              require_arg "$1" "${2-}"; kbs_url="$2";              shift 2;;
        --kek-source)           require_arg "$1" "${2-}"; kek_source="$2";           shift 2;;
        --kek-file)             require_arg "$1" "${2-}"; kek_file="$2";             shift 2;;
        --source-date-epoch)    require_arg "$1" "${2-}"; source_date_epoch="$2";    shift 2;;
        -h|--help)              usage; exit 0;;
        *) die "unknown argument: $1 (try --help)";;
    esac
done

# ── --print-plan: dry-run distro dispatch, no root/network ───────────
# Resolve + print the per-distro decisions for an os-release fixture
# and exit. Backs the CI golden test (scripts/dev/distro-plan-fixtures).
if [[ -n "${print_plan_osrelease}" ]]; then
    print_plan "${print_plan_osrelease}"
    exit 0
fi

# ── Resolve --flavor (#312, redesigned #365) ─────────────────────────
# #365: --flavor NO LONGER sizes the rootfs. A LUKS2 + --integrity
# volume cannot be grown (`cryptsetup resize` refuses an
# integrity-protected device outright), so the old "bake the full
# flavor disk" approach is replaced: the rootfs is a fixed,
# flavor-INDEPENDENT minimal image (sized by --output-qcow2-gb /
# HCC_BAKE_QCOW2_GB), and the flavor's `disk_gb` is the size of a
# SEPARATE tenant data disk the miner attaches blank at /dev/vde, which
# the guest formats fresh (LUKS2+integrity, guest-held key) at first
# boot. So the bake no longer needs disk_gb at all.
#
# The flag is still accepted + name-validated so callers
# (`vali_create_vm --flavor X`) pass it uniformly and so a Rust-side
# variant addition surfaces here (CI's tests/flavor_bake_catalogue.rs
# now guards NAME parity, not disk size). Keep this list in lockstep
# with `hippius_types::flavor::Flavor::all()`.
case "${flavor}" in
    ""|small|medium|large|xlarge|2xlarge|4xlarge) ;;
    *) die "--flavor must be one of: small, medium, large, xlarge, 2xlarge, 4xlarge (got '${flavor}')";;
esac

# ── Resolve --disk-mode (golden-bake PR1) ────────────────────────────
case "${disk_mode}" in
    legacy_luks|golden_verity_overlay) ;;
    *) die "--disk-mode must be legacy_luks or golden_verity_overlay (got '${disk_mode}') (exit 1)";;
esac

# ── Resolve --package-refresh (F6) ──────────────────────────────────
# The stamp rides the stage-1 cache key and the chroot env(1) line, so
# it is charset-locked like a vm_id: no shell- or path-active bytes.
if [[ -n "${package_refresh}" && ! "${package_refresh}" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
    die "--package-refresh must match [A-Za-z0-9._-]{1,64} (got '${package_refresh}') (exit 1)"
fi

# ── Resolve --profile (CDN plan I3) ─────────────────────────────────
# Gated here, root-free, like --disk-mode (scripts/dev/cdn-node-profile-test.sh).
case "${profile}" in
    standard)
        if [[ -n "${cdn_agent_bin}${cdn_openresty_tarball}${cdn_config_dir}${cdn_backend_url}${cdn_fleet_wildcard}" ]]; then
            die "--cdn-* flags need --profile cdn-node (exit 1)"
        fi
        ;;
    cdn-node)
        [[ "${disk_mode}" == "golden_verity_overlay" ]] \
            || die "--profile cdn-node needs --disk-mode golden_verity_overlay (exit 1)"
        [[ -n "${cdn_agent_bin}" && -x "${cdn_agent_bin}" ]] \
            || die "--profile cdn-node needs an executable --cdn-agent-bin (exit 1)"
        [[ -n "${cdn_openresty_tarball}" && -r "${cdn_openresty_tarball}" && -r "${cdn_openresty_tarball}.sha256" ]] \
            || die "--profile cdn-node needs --cdn-openresty-tarball PATH with PATH.sha256 (exit 1)"
        [[ -n "${cdn_config_dir}" && -r "${cdn_config_dir}/nginx.conf.in" && -x "${cdn_config_dir}/render.sh" ]] \
            || die "--profile cdn-node needs --cdn-config-dir with nginx.conf.in and render.sh (exit 1)"
        [[ "${cdn_backend_url}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$ ]] \
            || die "--profile cdn-node needs --cdn-backend-url https://host[:port][/path] (got '${cdn_backend_url}') (exit 1)"
        cdn_fleet_wildcard="${cdn_fleet_wildcard:-*.c.hipcdn.net}"
        [[ "${cdn_fleet_wildcard}" =~ ^\*(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){2,}$ ]] \
            || die "--cdn-fleet-wildcard must be *.<domain> in lower case (got '${cdn_fleet_wildcard}') (exit 1)"
        [[ -r "${CDN_INSTALL_SRC}" ]] || die "${CDN_INSTALL_SRC}: cdn-node installer missing (exit 1)"
        ;;
    *) die "--profile must be standard or cdn-node (got '${profile}') (exit 1)";;
esac

# ── Resolve the §23 keepalive cadence knobs ─────────────────────────
# Gated HERE, alongside --disk-mode and ahead of the required-arg checks,
# so a value that would silently un-credit uptime is rejected without
# needing root, a network or a real image — and so the gate is unit-
# testable (scripts/dev/keepalive-unit-test.sh).
[[ "${keepalive_interval_secs}" =~ ^[1-9][0-9]*$ ]] \
    || die "--keepalive-interval-secs must be a positive integer (got '${keepalive_interval_secs}') (exit 1)"
(( keepalive_interval_secs <= KEEPALIVE_MAX_INTERVAL_SECS )) \
    || die "--keepalive-interval-secs ${keepalive_interval_secs} exceeds vali's uptimeLiveness.coverageSeconds (${KEEPALIVE_MAX_INTERVAL_SECS}): a sample vouches BACKWARD only, so a wider cadence leaves live time uncovered and the armed gate credits it ZERO (exit 1)"
[[ "${keepalive_relay_port}" =~ ^[1-9][0-9]*$ ]] \
    || die "--keepalive-relay-port must be a positive integer (0 would mint attestations that never reach vali) (exit 1)"

# ── Validate ────────────────────────────────────────────────────────

[[ -n "${base_image_url}" ]]      || { usage; die "--base-image-url is required"; }
[[ -n "${kbs_url}" ]] \
    || die "--kbs-url is required (or export HIPPIUS_KBS_URL) — there is no default KBS (exit 1)"
[[ -n "${base_image_sha256}" ]]   || die "--base-image-sha256 is required"
[[ -n "${hippius_release_bin}" ]] || die "--hippius-release-bin is required"
[[ -n "${hippius_vsock_bin}" ]]   || die "--hippius-vsock-bin is required"
[[ "${base_image_sha256}" =~ ^[0-9a-f]{64}$ ]] \
    || die "--base-image-sha256 must be 64 lowercase hex chars"
case "${base_image_url}" in
    https://*|s3://*|file://*) ;;
    *) die "--base-image-url must be https://, s3://, or file://" ;;
esac
# KEK is legacy_luks-only: the golden dm-verity base is non-confidential
# and consumes no key. Skip all KEK validation in golden mode.
if [[ "${disk_mode}" == "legacy_luks" ]]; then
    case "${kek_source}" in
        stdin|file) ;;
        *) die "--kek-source must be stdin or file (got '${kek_source}')";;
    esac
    if [[ "${kek_source}" == "file" ]]; then
        [[ -n "${kek_file}" && -r "${kek_file}" ]] \
            || die "--kek-source=file needs --kek-file PATH (readable)"
    fi
fi
[[ -x "${hippius_release_bin}" ]] || die "${hippius_release_bin}: not executable"
[[ -x "${hippius_vsock_bin}" ]]   || die "${hippius_vsock_bin}: not executable"
# Optional EOL binary: validate only when supplied.
if [[ -n "${hippius_eol_bin}" ]]; then
    [[ -x "${hippius_eol_bin}" ]] || die "${hippius_eol_bin}: not executable"
fi
# Optional §23 telemetry agent: validate only when supplied.
if [[ -n "${hippius_telemetry_bin}" ]]; then
    [[ -x "${hippius_telemetry_bin}" ]] || die "${hippius_telemetry_bin}: not executable"
fi
# Optional §23 keepalive agent: validate only when supplied. (The cadence
# knobs are gated earlier, ahead of the required-arg checks.)
if [[ -n "${hippius_keepalive_bin}" ]]; then
    [[ -x "${hippius_keepalive_bin}" ]] || die "${hippius_keepalive_bin}: not executable"
    [[ -r "${KEEPALIVE_SHIM_SRC}" ]] || die "${KEEPALIVE_SHIM_SRC}: keepalive shim missing"
fi
[[ -r "${KEYSCRIPT_SRC}" ]]       || die "${KEYSCRIPT_SRC}: keyscript missing"
[[ -r "${CORE_SRC}" ]]            || die "${CORE_SRC}: release core missing"
[[ -d "${DRACUT_MODULE_SRC}" ]]   || die "${DRACUT_MODULE_SRC}: dracut module dir missing"
[[ -r "${HOOK_SRC}" ]]            || die "${HOOK_SRC}: initramfs hook missing"
[[ -r "${HOST_STATE_HOOK_SRC}" ]] || die "${HOST_STATE_HOOK_SRC}: initramfs host-state hook missing"
[[ -r "${DHCP_CLIENTID_HOOK_SRC}" ]] || die "${DHCP_CLIENTID_HOOK_SRC}: initramfs DHCP client-id hook missing"
[[ -r "${NET_TEARDOWN_SRC}" ]]    || die "${NET_TEARDOWN_SRC}: init-bottom teardown missing"
[[ "${output_qcow2_gb}" =~ ^[1-9][0-9]*$ ]] || die "--output-qcow2-gb must be a positive integer"

# Tooling — fail fast (exit 2 per header).
missing=()
for tool in curl sha256sum qemu-img qemu-nbd cryptsetup losetup chroot dd mount umount jq growpart e2fsck resize2fs e2image; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
# golden_verity_overlay needs the dm-verity packaging tools on top.
if [[ "${disk_mode}" == "golden_verity_overlay" ]]; then
    for tool in veritysetup mksquashfs; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
    done
    # Golden boot assets — both families' guest boot modules must be
    # present so a golden bake of EITHER family carries a bootable initrd.
    [[ -r "${GOLDEN_OVERLAY_SRC}" ]]       || die "${GOLDEN_OVERLAY_SRC}: golden overlay lib missing"
    [[ -r "${GOLDEN_BOOT_SRC}" ]]          || die "${GOLDEN_BOOT_SRC}: golden boot script missing"
    [[ -r "${GOLDEN_HOOK_SRC}" ]]          || die "${GOLDEN_HOOK_SRC}: golden initramfs hook missing"
    [[ -d "${GOLDEN_DRACUT_MODULE_SRC}" ]] || die "${GOLDEN_DRACUT_MODULE_SRC}: golden dracut module dir missing"
fi
if (( ${#missing[@]} > 0 )); then
    log "missing host tools: ${missing[*]}"
    log "install qemu-utils + cryptsetup-bin + coreutils + jq + cloud-guest-utils + e2fsprogs"
    exit 2
fi

# ── Workspace ───────────────────────────────────────────────────────

output_dir="$(cd "$(dirname "${output_dir}")" 2>/dev/null && pwd)/$(basename "${output_dir}")"
mkdir -p "${output_dir}"
WORK_DIR="$(mktemp -d -t hippius-bake.XXXXXX)"
log "work dir: ${WORK_DIR}"

# ── KEK staging (read stdin ONCE; tmpfs file for the two cryptsetup
#                 invocations) ─────────────────────────────────────
#
# `cryptsetup luksFormat --key-file=-` consumes stdin; a second
# `cryptsetup open --key-file=-` from the same pipe would see EOF.
# Read the 32-byte KEK once and stash it in a tmpfs-backed file so
# luksFormat + open both read the same bytes. Wipes on cleanup trap.

# golden_verity_overlay is non-confidential and consumes no KEK — skip
# staging entirely (nothing reads `kek_buf` on the golden path, which
# dispatches before stage 6's luksFormat).
if [[ "${disk_mode}" == "legacy_luks" ]]; then
    KEK_TMPFS_DIR="$(mktemp -d -p /dev/shm hippius-bake-kek.XXXXXX 2>/dev/null || mktemp -d -t hippius-bake-kek.XXXXXX)"
    chmod 0700 "${KEK_TMPFS_DIR}"
    kek_buf="${KEK_TMPFS_DIR}/kek.bin"
    case "${kek_source}" in
        stdin) cat > "${kek_buf}" ;;
        file)  cp -- "${kek_file}" "${kek_buf}" ;;
    esac
    chmod 0400 "${kek_buf}"
    kek_len=$(stat -c '%s' "${kek_buf}")
    if (( kek_len != 32 )); then
        die "KEK must be exactly 32 bytes (got ${kek_len}) (exit 1)"
    fi
    log "KEK buffered (${kek_len} bytes, tmpfs, sha256=$(sha256sum < "${kek_buf}" | awk '{print $1}'))"
else
    log "disk-mode=golden_verity_overlay: no KEK consumed (base is non-confidential dm-verity)"
fi

# ── Kernel / initrd pairing ─────────────────────────────────────────
#
# Stage 5 picks the kernel and the initrd with two independent
# `sort -V | tail -1`s, so nothing else ties them together. A package
# refresh can leave two kernels (dnf upgrade on CentOS Stream/Fedora
# installs a new kernel-core beside the old one); the chroot builds the
# initrd for the highest /lib/modules, and if the new vmlinuz never reached
# /boot the bake would ship the OLD kernel with the NEW initrd — modules
# for another kernel, an unbootable guest. Refuse. Initrd names:
# `initrd.img-<kver>` (initramfs-tools) or `initramfs-<kver>.img` (dracut).
# Covered by scripts/dev/package-refresh-test.sh.
assert_kernel_initrd_match() {
    local kernel_ver initrd_ver
    kernel_ver="${1##*/vmlinuz-}"
    initrd_ver="${2##*/}"
    initrd_ver="${initrd_ver#initrd.img-}"
    initrd_ver="${initrd_ver#initramfs-}"
    initrd_ver="${initrd_ver%.img}"
    [[ -n "${kernel_ver}" && "${kernel_ver}" == "${initrd_ver}" ]] \
        || die "kernel ${1##*/} and initrd ${2##*/} are for different kernels (${kernel_ver} != ${initrd_ver}) (exit 3)"
}

# ── Stage-1 cache helpers ───────────────────────────────────────────
#
# The stage-1 artifact (customised plaintext raw + kernel + initrd)
# is identical for every tenant baking from the same base image with
# the same script revision — only stage 6 (per-tenant LUKS encrypt
# with the tenant's KEK) differs. Caching it cuts ~6-10 min of
# download + apt + update-initramfs per bake.
#
# Trust model: the cache directory sits in the SAME trust domain as
# WORK_DIR (the baker pod's PVC / the operator's disk — both inside
# the bake TCB). The sha256 verification on load is torn-write /
# corruption insurance, not an authentication boundary.

src_raw="${WORK_DIR}/base.raw"
STAGE1_KEY=""
if [[ -n "${stage1_cache_dir}" ]]; then
    STAGE1_KEY="$(
        {
            sha256sum \
                "${BASH_SOURCE[0]}" \
                "${KEYSCRIPT_SRC}" "${CORE_SRC}" "${HOOK_SRC}" "${HOST_STATE_HOOK_SRC}" "${DHCP_CLIENTID_HOOK_SRC}" "${NET_TEARDOWN_SRC}" \
                "${DRACUT_MODULE_SRC}"/* \
                "${GOLDEN_OVERLAY_SRC}" "${GOLDEN_BOOT_SRC}" "${GOLDEN_HOOK_SRC}" \
                "${GOLDEN_DRACUT_MODULE_SRC}"/* \
                "${hippius_release_bin}" "${hippius_vsock_bin}" \
                | awk '{print $1}'
            # §24/§25 EOL binary affects the cached rootfs (staged into it
            # at chroot-customise time) — fold its content into the key so
            # a bake WITH the shutdown-sign hook never collides with a
            # cached stage-1 baked WITHOUT it. Absent ⇒ a stable marker.
            if [[ -n "${hippius_eol_bin}" ]]; then
                sha256sum "${hippius_eol_bin}" | awk '{print "eol="$1}'
            else
                echo "eol=none"
            fi
            # §23 telemetry agent — same rationale as the EOL binary: it is
            # staged into the cached rootfs, so its content must key the
            # cache (a WITH-agent bake must never reuse a WITHOUT-agent
            # stage-1). Absent ⇒ a stable marker.
            if [[ -n "${hippius_telemetry_bin}" ]]; then
                sha256sum "${hippius_telemetry_bin}" | awk '{print "telemetry="$1}'
            else
                echo "telemetry=none"
            fi
            # §23 keepalive agent + its cmdline shim + the cadence baked
            # into /etc/hippius/keepalive.env — all staged into the cached
            # rootfs, so all must key the cache. Without this a re-bake
            # that only changes the cadence would silently reuse a stage-1
            # carrying the OLD interval.
            if [[ -n "${hippius_keepalive_bin}" ]]; then
                sha256sum "${hippius_keepalive_bin}" | awk '{print "keepalive="$1}'
                sha256sum "${KEEPALIVE_SHIM_SRC}" | awk '{print "keepalive-shim="$1}'
                echo "keepalive-interval=${keepalive_interval_secs}"
                echo "keepalive-relay-port=${keepalive_relay_port}"
            else
                echo "keepalive=none"
            fi
            echo "base=${base_image_sha256}"
            echo "grow=${HCC_BAKE_SRC_GROW_GB:-4}"
            echo "sde=${source_date_epoch}"
            # disk-mode (golden-bake PR6) — the customise phase stages
            # MODE-SPECIFIC bytes into the cached rootfs+initrd BEFORE
            # `stage1_cache_store` runs: golden installs the overlay boot
            # assets + golden hook and writes an EMPTY crypttab + overlay
            # fstab, legacy writes the cryptroot crypttab + regenerates a
            # LUKS-keyscript initrd. Without folding the mode into the key
            # a golden and a legacy bake of the SAME base would collide and
            # one would boot the other's rootfs (unbootable). Keying on the
            # mode keeps the two caches disjoint.
            echo "disk_mode=${disk_mode}"
            # package refresh (F6) — an upgraded chroot carries different
            # package bytes than the dated base image would, and the stamp
            # is what tells two refreshes apart: a new stamp is a new key,
            # so a scheduled re-bake always pulls the updates of its day.
            echo "pkg_refresh=${package_refresh:-none}"
            # Bake profile (CDN plan I3): a cdn-node stage-1 carries the
            # data plane, so every input that shapes it keys the cache.
            echo "profile=${profile}"
            if [[ "${profile}" == "cdn-node" ]]; then
                sha256sum "${CDN_INSTALL_SRC}" "${cdn_agent_bin}" "${cdn_openresty_tarball}" \
                    | awk '{print "cdn="$1}'
                (cd "${cdn_config_dir}" && find . -type f -print0 | LC_ALL=C sort -z \
                    | xargs -0 sha256sum) | sha256sum | awk '{print "cdn-config="$1}'
                echo "cdn-backend=${cdn_backend_url}"
                echo "cdn-fleet-wildcard=${cdn_fleet_wildcard}"
            fi
            # schema marker — bump on any change that alters stage-1
            # bytes but isn't captured by the hashed file list above
            # (the BASH_SOURCE hash already covers this script's logic;
            # this guards refactors that move logic into not-yet-hashed
            # helper files). The GOLDEN boot assets (overlay lib + boot
            # script + initramfs hook + the 95hippius-golden dracut module)
            # ARE now in the hashed list above, so a golden-asset edit
            # self-busts the cache without a manual schema bump (the
            # stale-cache trap that masked #834 on Debian).
            echo "schema=4"
        } | sha256sum | awk '{print $1}'
    )"
    log "stage-1 cache key: ${STAGE1_KEY} (dir: ${stage1_cache_dir})"
fi

stage1_cache_load() {
    [[ -n "${stage1_cache_dir}" ]] || return 1
    local entry="${stage1_cache_dir}/${STAGE1_KEY}"
    [[ -f "${entry}/meta.json" ]] || return 1
    local want_raw want_kernel want_initrd part_num
    want_raw="$(jq -re '.src_raw_sha256' "${entry}/meta.json")" || return 1
    want_kernel="$(jq -re '.kernel_sha256' "${entry}/meta.json")" || return 1
    want_initrd="$(jq -re '.initrd_sha256' "${entry}/meta.json")" || return 1
    part_num="$(jq -re '.root_part_num' "${entry}/meta.json")" || return 1
    local got
    for pair in \
        "${entry}/src.raw:${want_raw}" \
        "${entry}/kernel.vmlinuz:${want_kernel}" \
        "${entry}/initrd.img:${want_initrd}"; do
        got="$(sha256sum "${pair%%:*}" 2>/dev/null | awk '{print $1}')"
        if [[ "${got}" != "${pair##*:}" ]]; then
            log "stage-1 cache entry corrupt (${pair%%:*}); rebuilding"
            return 1
        fi
    done
    cp --sparse=always "${entry}/src.raw" "${src_raw}" || return 1
    cp "${entry}/kernel.vmlinuz" "${WORK_DIR}/kernel.vmlinuz" || return 1
    cp "${entry}/initrd.img" "${WORK_DIR}/initrd.img" || return 1
    root_part_num="${part_num}"
    return 0
}

stage1_cache_store() {
    # Best-effort: a failed store must never fail the bake.
    [[ -n "${stage1_cache_dir}" ]] || return 0
    # A package-refresh stage-1 is single-use: its key carries the stamp,
    # so no later bake can ever hit it, and the cache PVC has no GC. Storing
    # it would fill the PVC with ~4-5 GiB per distro per refresh and every
    # ordinary bake after it would silently go cold.
    if [[ -n "${package_refresh}" ]]; then
        log "stage-1 cache store skipped: package refresh ${package_refresh} is single-use"
        return 0
    fi
    local entry="${stage1_cache_dir}/${STAGE1_KEY}"
    local tmp="${entry}.tmp.$$"
    if ! mkdir -p "${tmp}"; then
        log "stage-1 cache store: mkdir failed (non-fatal)"
        return 0
    fi
    if cp --sparse=always "${src_raw}" "${tmp}/src.raw" \
        && cp "${WORK_DIR}/kernel.vmlinuz" "${tmp}/kernel.vmlinuz" \
        && cp "${WORK_DIR}/initrd.img" "${tmp}/initrd.img"; then
        jq -n \
            --arg raw "$(sha256sum "${tmp}/src.raw" | awk '{print $1}')" \
            --arg kernel "$(sha256sum "${tmp}/kernel.vmlinuz" | awk '{print $1}')" \
            --arg initrd "$(sha256sum "${tmp}/initrd.img" | awk '{print $1}')" \
            --argjson part "${root_part_num}" \
            '{src_raw_sha256:$raw, kernel_sha256:$kernel,
              initrd_sha256:$initrd, root_part_num:$part}' \
            > "${tmp}/meta.json"
        # Atomic publish; a concurrent bake may have won the race —
        # `mv -nT` skips silently and we discard our copy.
        mv -nT "${tmp}" "${entry}" 2>/dev/null || true
    else
        log "stage-1 cache store: copy failed (non-fatal)"
    fi
    rm -rf "${tmp}" 2>/dev/null || true
    log "stage-1 cache stored: ${entry}"
    return 0
}

# ── helpers used by BOTH the cache-miss customise path AND the
# cache-HIT stage-6 copy (mount_guest_root) — defined at top level,
# NOT inside the cache-miss branch below, or a warm-cache bake hits
# 'mount_guest_root: command not found' in stage 6.
# Mount a guest root partition, transparently resolving the btrfs
# SYSTEM subvolume. Fedora Cloud's btrfs default mount lands the
# TOP-LEVEL (subvolid 5) whose children are `root` + `home` subdirs —
# /etc/os-release lives under `root/`, not at the mount root. ext4/xfs
# (and a btrfs whose default subvol already IS the system root) mount
# straight through. Args: <part> <mnt> <rw|ro>. Dies on failure.
mount_guest_root() {
    local part="$1" mnt="$2" mode="${3:-rw}"
    if [[ "${mode}" == "ro" ]]; then
        sudo mount -o ro "${part}" "${mnt}" || die "mount ${part} (ro) failed (exit 3)"
    else
        sudo mount "${part}" "${mnt}" || die "mount ${part} failed (exit 3)"
    fi
    # Only btrfs can present a subvol-less top-level; probe + remount.
    if [[ "$(sudo blkid -s TYPE -o value "${part}" 2>/dev/null)" == "btrfs" \
          && ! -r "${mnt}/etc/os-release" ]]; then
        local cand sysvol=""
        for cand in root @ @root sysroot; do
            if [[ -r "${mnt}/${cand}/etc/os-release" ]]; then sysvol="${cand}"; break; fi
        done
        [[ -n "${sysvol}" ]] \
            || die "btrfs: no system subvol with /etc/os-release under ${part} (tried root,@,@root,sysroot) (exit 3)"
        sudo umount "${mnt}"
        if [[ "${mode}" == "ro" ]]; then
            sudo mount -o "ro,subvol=${sysvol}" "${part}" "${mnt}" \
                || die "btrfs remount subvol=${sysvol} (ro) failed (exit 3)"
        else
            sudo mount -o "subvol=${sysvol}" "${part}" "${mnt}" \
                || die "btrfs remount subvol=${sysvol} failed (exit 3)"
        fi
        log "btrfs: mounted system subvol '${sysvol}' at ${mnt}"
    fi
}

# Mount a SEPARATE /boot partition under <mnt>/boot if the image's fstab
# names one (Fedora Cloud splits /boot onto its own ext4 partition;
# CS10/Ubuntu/Debian keep /boot on the root fs → no-op). The preinstalled
# vmlinuz lives there AND the chroot's dracut/update-initramfs writes the
# new initrd there, so stage 5's `/boot/{vmlinuz,initramfs}-*` extraction
# finds both. The baked LUKS root deliberately does NOT carry /boot — the
# kernel+initrd are direct-boot artifacts the hypervisor supplies and
# stage 4 rewrites fstab to a single `/` mount.
#
# Sets global BOOT_PART_NUM (the partition NUMBER, stable across a loop
# re-attach) when it mounts — the stage-5 re-mount reuses it directly
# because by then stage 4 has rewritten the image fstab (dropping the
# /boot line), so re-reading fstab there would find nothing.
BOOT_PART_NUM=""
mount_boot_if_separate() {
    local mnt="$1" spec part="" key val cand
    spec="$(awk '($2=="/boot"){print $1; exit}' "${mnt}/etc/fstab" 2>/dev/null || true)"
    [[ -n "${spec}" ]] || return 0
    # Resolve the fstab spec ONLY among THIS loop's partitions — NEVER a
    # global `blkid -U/-L` lookup. Every bake of the same base image
    # carries the same fs UUID/LABEL (noble's p16 is LABEL=BOOT), so the
    # global lookup can resolve to a STALE loop of some OTHER attach of
    # the same image on the host and silently mount the WRONG file's
    # /boot. Bitten live 2026-07-04: a leaked /dev/loop2 (/tmp/noble.raw
    # host debris) won `blkid -L BOOT`; the chroot then wrote the new
    # kernel + hooked initrd into THAT file while the shipped image kept
    # its pristine hookless /boot — every guest hung at cryptroot. The
    # stage-5 extracted-initrd audit fails the bake if this ever
    # recurs by another route.
    case "${spec}" in
        UUID=*|LABEL=*)
            key="${spec%%=*}"
            val="${spec#*=}"
            for cand in "${LOOP_DEV}"p*; do
                [[ -b "${cand}" ]] || continue
                if [[ "$(sudo blkid -o value -s "${key}" "${cand}" 2>/dev/null)" == "${val}" ]]; then
                    part="${cand}"
                    break
                fi
            done
            ;;
        /dev/*)
            # A guest-view device path (/dev/sda16, /dev/vda16, …) — map
            # its partition NUMBER onto the current loop.
            if [[ "${spec}" =~ ([0-9]+)$ ]]; then
                part="${LOOP_DEV}p${BASH_REMATCH[1]}"
            fi
            ;;
    esac
    if [[ -n "${part}" && -b "${part}" ]]; then
        sudo mount "${part}" "${mnt}/boot" \
            || die "mount separate /boot (${part}) failed (exit 3)"
        BOOT_PART_NUM="${part##*p}"
        log "mounted separate /boot partition: ${part} (p${BOOT_PART_NUM})"
    else
        log "fstab names a /boot (${spec}) but no partition on ${LOOP_DEV} matches — assuming /boot on root"
    fi
}

# ── Golden base per-instance identity + secret scrub (golden-bake PR4) ─
#
# The golden base becomes the SHARED, read-only lowerdir under every
# same-distro tenant's overlayfs root. Anything PER-INSTANCE or
# PER-TENANT baked into it is READ IDENTICALLY by every VM (the overlay
# only copies a path UP to the guest-keyed upper on the first WRITE — a
# never-written file is served straight from the shared lower). So a
# per-instance secret on the base is a cross-tenant leak.
#
# This is proof-B (write-redirection completeness): the shared base must
# carry NONE of it. Each item below is regenerated PER-VM on the
# guest-keyed overlay upper at first boot (the regenerating write lands
# on the upper via overlayfs copy-up), NOT read from the shared lower.
#
# Runs INSIDE build_golden_verity_base, AFTER the root is mounted rw and
# BEFORE the mtime sweep + mksquashfs, so it captures anything the whole
# stage-1..5 customise (incl. apt/dnf postinsts) generated. Golden-only:
# the legacy per-VM LUKS path never calls this (its vda is per-VM, so
# baked identity is not shared) — legacy bytes are untouched.
golden_sanitize_base() {
    local root="$1"
    log "golden: scrubbing per-instance identity + secrets from the shared base (PR4 write-redirection)"

    # 1. SSH host keys. A chroot `openssh-server` postinst runs
    #    `ssh-keygen -A`, baking host keys into the base. Shared host keys
    #    across same-distro tenants = a host-identity/MITM leak. Delete
    #    them; cloud-init's `ssh` module regenerates a UNIQUE pair on first
    #    boot (write → upper), kept stable across reboots by the
    #    99-hippius-ssh-hostkeys.cfg `ssh_deletekeys:false` already baked.
    sudo find "${root}/etc/ssh" -maxdepth 1 -name 'ssh_host_*' -delete 2>/dev/null || true

    # 2. machine-id. Must be EMPTY on a reusable/golden image so systemd
    #    (ConditionFirstBoot / systemd-machine-id-setup) generates a fresh
    #    per-VM id onto the upper. A populated id would be SHARED across
    #    tenants (breaks journald, systemd-networkd DHCP DUID, etc.). An
    #    empty file (not a missing one) is the systemd-sanctioned
    #    "uninitialised, generate on first boot" marker.
    sudo truncate -s 0 "${root}/etc/machine-id" 2>/dev/null \
        || sudo rm -f "${root}/etc/machine-id" 2>/dev/null || true
    # dbus reuses /etc/machine-id; a regular-file COPY here would re-share
    # it. Remove a regular-file copy (a symlink to /etc/machine-id is fine
    # and left in place — it resolves to the per-VM upper id at runtime).
    if [[ -f "${root}/var/lib/dbus/machine-id" && ! -L "${root}/var/lib/dbus/machine-id" ]]; then
        sudo rm -f "${root}/var/lib/dbus/machine-id" 2>/dev/null || true
    fi

    # 3. cloud-init instance state. A baked `/var/lib/cloud` would make
    #    cloud-init think it already ran for a prior instance-id and SKIP
    #    the per-instance modules (ssh keygen, netbird, the §21 userdata),
    #    so first boot would not provision. Clear it so cloud-init runs
    #    fresh (release-core writes a per-boot instance-id; the run's
    #    writes land on the upper).
    if [[ -d "${root}/var/lib/cloud" ]]; then
        sudo find "${root}/var/lib/cloud" -mindepth 1 -delete 2>/dev/null || true
    fi

    # 4. Logs. Build-time logs must not ship on the shared base (info leak
    #    + a non-deterministic squashfs). Truncate every file; the running
    #    guest re-creates them on the upper.
    if [[ -d "${root}/var/log" ]]; then
        sudo find "${root}/var/log" -type f -exec truncate -s 0 {} + 2>/dev/null || true
    fi

    # 5. NO swap on the shared bytes (HARD invariant). A swapfile on the RO
    #    base (or a swap fstab entry pointing at shared storage) would page
    #    tenant plaintext to bytes the untrusted miner holds. The golden
    #    fstab is written EMPTY (no swap) upstream; assert BOTH here and
    #    FAIL the bake closed if a swapfile or swap fstab entry slipped in.
    if sudo find "${root}" -xdev \( -name 'swapfile' -o -name 'swap.img' \) -type f 2>/dev/null | grep -q .; then
        sudo umount "${root}" 2>/dev/null || true
        die "golden: a swapfile exists on the shared base — swap must be guest-keyed or NONE (exit 3)"
    fi
    if [[ -f "${root}/etc/fstab" ]] && grep -qiE '^[[:space:]]*[^#].*[[:space:]]swap[[:space:]]' "${root}/etc/fstab" 2>/dev/null; then
        sudo umount "${root}" 2>/dev/null || true
        die "golden: /etc/fstab declares swap on the shared base — must be guest-keyed or NONE (exit 3)"
    fi

    # 5b. systemd `.swap` units (NAME-AGNOSTIC). The name-based swapfile
    #     scan (5) + the fstab scan both miss a differently-named systemd
    #     `.swap` unit (e.g. `data-swap.swap` whose `What=` points at an
    #     arbitrary device/file). Activating swap on the shared base would
    #     page tenant plaintext to bytes the untrusted miner holds — the
    #     same HARD invariant as (5). FAIL the bake closed on ANY on-disk
    #     `.swap` unit or any ENABLED swap `.wants` symlink. (A golden base
    #     must carry NO static swap unit; gpt-auto-generated units live in
    #     /run at runtime, never on the baked tree.)
    local _swapdir
    for _swapdir in \
        "${root}/etc/systemd/system" \
        "${root}/lib/systemd/system" \
        "${root}/usr/lib/systemd/system"; do
        [[ -d "${_swapdir}" ]] || continue
        if sudo find "${_swapdir}" -maxdepth 1 -name '*.swap' 2>/dev/null | grep -q .; then
            sudo umount "${root}" 2>/dev/null || true
            die "golden: a systemd .swap unit exists on the shared base (${_swapdir}) — swap must be guest-keyed or NONE (exit 3)"
        fi
    done
    # An ENABLED swap unit is a `*.wants/*.swap` symlink (e.g.
    # swap.target.wants/foo.swap) — catch it even if the unit file itself
    # lives elsewhere (or is a dangling symlink).
    if sudo find \
        "${root}/etc/systemd/system" \
        "${root}/lib/systemd/system" \
        "${root}/usr/lib/systemd/system" \
        -path '*.wants/*.swap' 2>/dev/null | grep -q .; then
        sudo umount "${root}" 2>/dev/null || true
        die "golden: an enabled swap .wants symlink exists on the shared base — swap must be guest-keyed or NONE (exit 3)"
    fi

    # 5c. NO #365 data-disk provisioner (#1350). A golden VM gets no data
    #     disk, so on a golden base the unit could only ever act on a
    #     /dev/vde the miner attached on its own: formatted and mounted at
    #     /data with no anti-rollback. The bake skips it for goldens; FAIL
    #     closed if the unit, its enablement or its script slipped in.
    if sudo find \
        "${root}/etc/systemd/system" \
        "${root}/lib/systemd/system" \
        "${root}/usr/lib/systemd/system" \
        -name 'hippius-data-disk.service' 2>/dev/null | grep -q . \
        || [[ -e "${root}/usr/local/sbin/hippius-data-disk-init" ]]; then
        sudo umount "${root}" 2>/dev/null || true
        die "golden: the #365 data-disk provisioner is on the shared base — a golden VM has no data disk, it would format a miner-attached /dev/vde (exit 3)"
    fi

    # 6. systemd CSPRNG seed + credential secret. A SHARED random-seed
    #    across same-distro VMs feeds correlated entropy into the guest pool
    #    at boot — BEFORE the in-guest overlay luksFormat MK + ssh keygen run
    #    (a cross-tenant crypto invariant, not a mere info leak). Remove both
    #    so systemd writes a FRESH per-VM seed + credential secret onto the
    #    upper at first boot. Do it by construction — never rely on the
    #    upstream cloud image happening to have been virt-sysprep'd.
    sudo rm -f "${root}/var/lib/systemd/random-seed" 2>/dev/null || true
    sudo rm -f "${root}/var/lib/systemd/credential.secret" 2>/dev/null || true

    # 7. DHCP + NetworkManager runtime state. Stale DHCP leases
    #    (/var/lib/dhcp) and NetworkManager runtime state
    #    (/var/lib/NetworkManager — leases, seen-bssids, timestamps, any
    #    generated connection carrying a baked DUID/client-id) are
    #    per-instance runtime cruft. Not a hard secret, but shipping them
    #    on the SHARED base is a determinism + hygiene regression (a stale
    #    lease/DUID shared across same-distro tenants). Clear both; the
    #    running guest re-creates them PER-VM on the overlay upper.
    if [[ -d "${root}/var/lib/dhcp" ]]; then
        sudo find "${root}/var/lib/dhcp" -mindepth 1 -delete 2>/dev/null || true
    fi
    if [[ -d "${root}/var/lib/NetworkManager" ]]; then
        sudo find "${root}/var/lib/NetworkManager" -mindepth 1 -delete 2>/dev/null || true
    fi

    # 8. Package-manager indexes and caches (reproducibility). apt's lists
    #    hold the mirrors' InRelease files, re-signed (new Date/Valid-Until)
    #    every few hours, and the binary caches built from them; ldconfig's
    #    aux-cache and apt-listchanges' databases record build-time state.
    #    Shipping them made two bakes of the same inputs differ in their
    #    verity root. Drop them so the base is a function of the installed
    #    package set only: a guest refreshes its index before installing
    #    (`apt-get update`, which cloud-init runs itself for `packages:`;
    #    dnf fetches metadata on demand).
    local _lists="${root}/var/lib/apt/lists"
    if [[ -d "${_lists}" ]]; then
        # Everything, subdirectories (auxfiles/) included, except apt's
        # lock and the (emptied) partial/ directory.
        sudo find "${_lists}" -mindepth 1 ! -path "${_lists}/lock" ! -path "${_lists}/partial" \
            -delete 2>/dev/null || true
    fi
    if [[ -d "${root}/var/cache/apt" ]]; then
        sudo find "${root}/var/cache/apt" -maxdepth 1 -name '*.bin' -delete 2>/dev/null || true
    fi
    if [[ -d "${root}/var/lib/apt" ]]; then
        sudo find "${root}/var/lib/apt" -maxdepth 1 -name 'listchanges*' -delete 2>/dev/null || true
    fi
    sudo rm -f "${root}/var/cache/ldconfig/aux-cache" 2>/dev/null || true
    # Caches apt's update hooks rebuild from the same index (Ubuntu): the
    # AppStream catalog and command-not-found's database metadata.
    if [[ -d "${root}/var/cache/swcatalog" ]]; then
        sudo find "${root}/var/cache/swcatalog" -mindepth 1 -delete 2>/dev/null || true
    fi
    if [[ -d "${root}/var/cache/app-info" ]]; then
        sudo find "${root}/var/cache/app-info" -mindepth 1 -delete 2>/dev/null || true
    fi
    if [[ -d "${root}/var/lib/command-not-found" ]]; then
        sudo find "${root}/var/lib/command-not-found" -maxdepth 1 -name 'commands.db*' -delete 2>/dev/null || true
    fi
    local _pmcache
    for _pmcache in "${root}/var/cache/dnf" "${root}/var/cache/libdnf5" "${root}/var/cache/yum"; do
        if [[ -d "${_pmcache}" ]]; then
            sudo find "${_pmcache}" -mindepth 1 -delete 2>/dev/null || true
        fi
    done
    # dnf's own build-time records: the transaction history (dnf4 and dnf5,
    # with its SQLite side files), the per-repo countme week counters, and
    # the timestamp each versionlock entry carries in its comment. The
    # locks themselves stay; the rpm database is untouched.
    sudo rm -f "${root}"/var/lib/dnf/history.sqlite* \
        "${root}"/usr/lib/sysimage/libdnf5/transaction_history.sqlite* 2>/dev/null || true
    if [[ -d "${root}/var/lib/dnf/repos" ]]; then
        sudo find "${root}/var/lib/dnf/repos" -name countme -type f -delete 2>/dev/null || true
    fi
    # Rewritten in place (same inode), never `sed -i`: a renamed copy would
    # drop the file's SELinux label on the RHEL family.
    local _lock _pattern _kept
    for _lock in "${root}/etc/dnf/plugins/versionlock.list" "${root}/etc/dnf/versionlock.toml"; do
        [[ -f "${_lock}" && ! -L "${_lock}" ]] || continue
        case "${_lock}" in
            *.list) _pattern='^#' ;;
            *)      _pattern='^[[:space:]]*comment[[:space:]]*=' ;;
        esac
        # grep exits 1 when every line is a comment; 2 is a read error and
        # must not empty the lock file.
        _kept="$(sudo grep -v "${_pattern}" "${_lock}")" || [[ $? -eq 1 ]] \
            || die "golden: cannot read ${_lock}"
        printf '%s\n' "${_kept}" | sudo tee "${_lock}" >/dev/null
    done

    log "golden: base scrub done (ssh-host-keys/machine-id/cloud-state/logs/random-seed/dhcp/NetworkManager/package indexes cleared; no swap file/fstab/systemd-unit on shared bytes)"
}

# ── Golden dm-verity base builder (golden-bake PR1) ─────────────────
#
# Runs INSTEAD of the legacy stage-6 (per-VM luksFormat) when
# `--disk-mode golden_verity_overlay`. It packages the SHARED, already-
# customised plaintext root (produced identically by stages 1-5, which
# consume no KEK and are tenant-agnostic) as a READ-ONLY dm-verity base:
#
#   rootfs.img     — squashfs of the root tree (reproducible flags +
#                    forced mtimes so it is byte-identical across bakes).
#   rootfs.verity  — dm-verity hash tree, UNKEYED, pinned zero salt/uuid.
#   verity_root_hash — the 64-hex Merkle root PR2 folds into the
#                    SNP-measured cmdline (`dm-verity.root=<hex>`).
#
# Security invariants (the untrusted-miner make-or-break):
#   * NO LUKS, NO KEK, NO shared master key. Integrity is an UNKEYED
#     Merkle tree bound to the measured cmdline — a host-tampered block
#     is caught (EIO) with no secret in play. This is why it is NOT a
#     shared-MK LUKS `--integrity` volume (which would let a
#     miner-with-golden-MK forge integrity-valid tampered ciphertext).
#   * NO tenant secret in the base — it is a public distro OS; per-tenant
#     userdata/SSH keys travel via the §21 KBS release to tmpfs, and all
#     per-VM writes land on a guest-keyed overlay (PR3), never here.
#
# INERT until PR2-PR6 wire the measured cmdline + guest overlay + write
# redirection: the base carries the legacy LUKS crypttab/fstab and does
# NOT boot on its own yet. PR1 only produces the artifacts + root hash.
build_golden_verity_base() {
    log "disk-mode=golden_verity_overlay — building read-only dm-verity base (no LUKS, no KEK)"

    # Re-attach the customised plaintext root (mirrors the legacy stage-6
    # re-attach) and mount it read-write so the reproducibility mtime
    # sweep can run in place. Safe: stage1_cache_store already persisted a
    # pristine copy, and the golden dispatch is terminal (exit 0 after).
    LOOP_DEV="$(sudo losetup --find --show --partscan "${src_raw}")"
    sudo partprobe "${LOOP_DEV}" 2>/dev/null || true
    sleep 1
    ensure_loop_partitions "${LOOP_DEV}"
    local root_part="${LOOP_DEV}p${root_part_num}"
    [[ -b "${root_part}" ]] || die "golden: re-attached source has no ${root_part} (exit 3)"

    local golden_mnt="${WORK_DIR}/golden-src"
    mkdir -p "${golden_mnt}"
    # Resolve a btrfs system subvol transparently (Fedora); ext4/xfs mount
    # straight through. Read-write so the mtime sweep + PR4 scrub can run.
    mount_guest_root "${root_part}" "${golden_mnt}" rw

    # PR4 write-redirection: scrub per-instance identity + secrets from the
    # SHARED base (ssh host keys, machine-id, cloud-init state, logs) and
    # assert NO swap, so nothing tenant-mutable persists on the golden
    # bytes — each regenerates PER-VM on the guest-keyed overlay upper.
    golden_sanitize_base "${golden_mnt}"

    # Reproducibility: force every entry's mtime (files, dirs, symlinks) to
    # SOURCE_DATE_EPOCH so squashfs cannot leak the build wall-clock — the
    # same regime build-rootfs.sh uses. `-h` covers symlinks.
    sudo find "${golden_mnt}" -depth -exec touch -h -d "@${source_date_epoch}" {} +

    local rootfs_img="${output_dir}/golden-${base_image_sha256:0:12}.rootfs.img"
    local verity_img="${output_dir}/golden-${base_image_sha256:0:12}.rootfs.verity"
    rm -f "${rootfs_img}" "${verity_img}"

    # ── squashfs: read-only, reproducible ───────────────────────────
    # Same reproducibility flags as build-rootfs.sh (-noappend, gzip -9,
    # single processor), EXCEPT we KEEP real uid/gid + xattrs (no
    # -all-root / -no-xattrs): a full bootable distro needs correct
    # ownership and RHEL needs its `security.selinux` labels, unlike the
    # minimal §F rootfs. `env SOURCE_DATE_EPOCH=` pins the squashfs
    # superblock mkfs time (portable across the real-sudo workstation and
    # the baker-pod `sudo` shim, which forwards args verbatim).
    log "golden: mksquashfs root tree → rootfs.img (reproducible)"
    sudo env SOURCE_DATE_EPOCH="${source_date_epoch}" \
        mksquashfs "${golden_mnt}" "${rootfs_img}" \
            -noappend -comp gzip -Xcompression-level 9 -processors 1 >/dev/null \
        || { sudo umount "${golden_mnt}" 2>/dev/null || true; die "golden: mksquashfs failed (exit 3)"; }

    sudo umount "${golden_mnt}"
    sudo losetup -d "${LOOP_DEV}" || true
    LOOP_DEV=""

    # squashfs is written root-owned; hand it to the invoking user so the
    # unprivileged veritysetup/sha steps (and downstream staging) can read
    # it. veritysetup format over plain files needs no root.
    sudo chown "$(id -u):$(id -g)" "${rootfs_img}" 2>/dev/null || true

    # ── dm-verity hash tree + root hash — UNKEYED, pinned salt/uuid ──
    log "golden: veritysetup format → rootfs.verity (unkeyed Merkle tree)"
    local verity_out
    verity_out="$(veritysetup format "${rootfs_img}" "${verity_img}" \
        --salt="${VERITY_SALT}" \
        --uuid="${VERITY_UUID}" \
        --hash="${VERITY_HASH_ALG}" \
        --data-block-size="${VERITY_BLOCK_SIZE}" \
        --hash-block-size="${VERITY_BLOCK_SIZE}")" \
        || die "golden: veritysetup format failed (exit 3)"
    local root_hash
    root_hash="$(echo "${verity_out}" | awk '/^Root hash:/ {print $NF}')"
    [[ "${root_hash}" =~ ^[0-9a-f]{64}$ ]] \
        || die "golden: could not parse a 64-hex verity root hash from veritysetup (exit 3)"
    log "golden: dm-verity root hash = ${root_hash}"

    # ── Emit measurement.json (PR2 consumes verity_root_hash) ───────
    local rootfs_img_sha rootfs_img_bytes verity_sha verity_bytes kernel_sha initrd_sha
    rootfs_img_sha="$(sha256sum "${rootfs_img}" | cut -d' ' -f1)"
    rootfs_img_bytes="$(stat -c '%s' "${rootfs_img}")"
    verity_sha="$(sha256sum "${verity_img}" | cut -d' ' -f1)"
    verity_bytes="$(stat -c '%s' "${verity_img}")"
    kernel_sha="$(sha256sum "${WORK_DIR}/kernel.vmlinuz" | cut -d' ' -f1)"
    initrd_sha="$(sha256sum "${WORK_DIR}/initrd.img" | cut -d' ' -f1)"

    cp "${WORK_DIR}/kernel.vmlinuz" "${output_dir}/golden-${base_image_sha256:0:12}.vmlinuz"
    cp "${WORK_DIR}/initrd.img"    "${output_dir}/golden-${base_image_sha256:0:12}.initrd.img"

    local measurement_json="${output_dir}/golden-${base_image_sha256:0:12}.measurement.json"
    jq -n \
        --arg mode "golden_verity_overlay" \
        --arg rootfs_img "${rootfs_img}" \
        --arg rootfs_img_sha "${rootfs_img_sha}" \
        --argjson rootfs_img_size "${rootfs_img_bytes}" \
        --arg verity_img "${verity_img}" \
        --arg verity_sha "${verity_sha}" \
        --argjson verity_size "${verity_bytes}" \
        --arg root_hash "${root_hash}" \
        --arg salt "${VERITY_SALT}" \
        --arg uuid "${VERITY_UUID}" \
        --arg halg "${VERITY_HASH_ALG}" \
        --argjson dblk "${VERITY_BLOCK_SIZE}" \
        --argjson hblk "${VERITY_BLOCK_SIZE}" \
        --arg base_url "${base_image_url}" \
        --arg base_sha "${base_image_sha256}" \
        --arg kbs "${kbs_url}" \
        --arg kernel_sha "${kernel_sha}" \
        --arg initrd_sha "${initrd_sha}" \
        '{
            disk_mode: $mode,
            rootfs_img_path: $rootfs_img,
            rootfs_img_sha256: $rootfs_img_sha,
            rootfs_img_size_bytes: $rootfs_img_size,
            rootfs_verity_path: $verity_img,
            rootfs_verity_sha256: $verity_sha,
            rootfs_verity_size_bytes: $verity_size,
            verity_root_hash: $root_hash,
            verity_salt: $salt,
            verity_uuid: $uuid,
            verity_hash_alg: $halg,
            verity_data_block_size: $dblk,
            verity_hash_block_size: $hblk,
            base_image_url: $base_url,
            base_image_sha256: $base_sha,
            kbs_url: $kbs,
            kernel_sha256: $kernel_sha,
            initrd_sha256: $initrd_sha
         }' > "${measurement_json}"

    cat "${measurement_json}"
    log "golden rootfs.img:    ${rootfs_img}"
    log "golden rootfs.verity: ${verity_img}"
    log "golden root hash:     ${root_hash}"
    log "measurement:          ${measurement_json}"
    log "GOLDEN BAKE OK — dm-verity base (INERT until PR2-PR6 wire the measured cmdline + guest overlay)"
}

if stage1_cache_load; then
    log "stage-1 cache HIT — skipping download + chroot customise (root_part_num=${root_part_num})"
else

# ── 1. Fetch + verify the base image ────────────────────────────────

src_qcow2="${WORK_DIR}/base.qcow2"
log "fetching base image: ${base_image_url}"
case "${base_image_url}" in
    file://*)
        cp -- "${base_image_url#file://}" "${src_qcow2}" \
            || die "base image copy failed (exit 3)"
        ;;
    s3://*)
        command -v aws >/dev/null 2>&1 || die "aws-cli not on PATH (exit 2)"
        aws s3 cp "${base_image_url}" "${src_qcow2}" \
            || die "aws s3 cp failed (exit 3)"
        ;;
    https://*)
        # Distinct messages per failure class. The old single message,
        # "base image fetch failed (ssrf-guard or curl)", is why a live
        # truncated download (curl exit 18) was first diagnosed as the
        # SSRF guard blocking the host — it had in fact validated three
        # public IPv4s and connected fine.
        fetch_rc=0
        ssrf_safe_https_fetch "${base_image_url}" "${src_qcow2}" || fetch_rc=$?
        case "${fetch_rc}" in
            0) ;;
            2) die "base image fetch REFUSED BY THE SSRF GUARD: the host did not resolve, or an address in its resolution set is non-public (fail-closed DNS-rebinding defence). Upstream was never contacted (exit 3)" ;;
            *) die "base image TRANSFER failed: the SSRF guard allowed the fetch and every validated public address was tried (see the per-address curl exit codes above) (exit 3)" ;;
        esac
        ;;
esac

actual="$(sha256sum "${src_qcow2}" | cut -d' ' -f1)"
if [[ "${actual}" != "${base_image_sha256}" ]]; then
    die "sha256 mismatch: expected ${base_image_sha256}, got ${actual} (exit 3)"
fi
log "base image verified (sha256=${base_image_sha256})"

# ── 2. Convert to raw + grow root partition + losetup ──────────────
#
# Ubuntu cloud images ship with `/boot/` STRIPPED (the cloud-image
# kernel is delivered out-of-band on managed clouds), and the root
# partition is sized to ~700 MB of free space — not enough to
# `apt-get install linux-image-virtual` (the BYO-OS bake's required
# step to repopulate `/boot/`). We grow the raw image by
# `HCC_BAKE_SRC_GROW_GB` (default 4 GiB) and reshape the partition
# + ext4 in-place before mounting. growpart / e2fsck / resize2fs
# is the same pattern cloud-init runs at first boot.

HCC_BAKE_SRC_GROW_GB="${HCC_BAKE_SRC_GROW_GB:-4}"

src_raw="${WORK_DIR}/base.raw"
log "qemu-img convert qcow2 → raw"
qemu-img convert -O raw "${src_qcow2}" "${src_raw}" \
    || die "qemu-img convert failed (exit 3)"
log "qemu-img resize +${HCC_BAKE_SRC_GROW_GB} GiB (room for kernel install)"
qemu-img resize -f raw "${src_raw}" "+${HCC_BAKE_SRC_GROW_GB}G" >/dev/null \
    || die "qemu-img resize failed (exit 3)"

LOOP_DEV="$(sudo losetup --find --show --partscan "${src_raw}")"
log "loop device: ${LOOP_DEV}"
sleep 1  # let partscan settle
ensure_loop_partitions "${LOOP_DEV}"

# Discover the root partition (largest ext4). Cloud images typically
# expose the root partition as the FIRST partition with `cloudimg-rootfs`
# label, but we identify by size to tolerate distro variations.
root_part=""
biggest=0
for p in "${LOOP_DEV}"p*; do
    [[ -b "$p" ]] || continue
    sz=$(sudo blockdev --getsize64 "$p")
    if (( sz > biggest )) && sudo blkid -s TYPE -o value "$p" 2>/dev/null | grep -qE '^(ext4|xfs|btrfs)$'; then
        biggest=$sz
        root_part="$p"
    fi
done
[[ -n "${root_part}" ]] || die "no ext4/xfs/btrfs partition found on ${LOOP_DEV} (exit 3)"
root_part_num="${root_part##*p}"
# Source root filesystem type drives the copy mode (#multi-distro):
# ext4 → the fast e2image used-blocks block copy (Ubuntu/Debian); xfs
# → mkfs.ext4 + rsync into the LUKS mapper (CentOS/Fedora roots — the
# output is ALWAYS ext4, which the fstab + #365 data disk assume).
SRC_ROOT_FSTYPE="$(sudo blkid -s TYPE -o value "${root_part}" 2>/dev/null || echo unknown)"
case "${SRC_ROOT_FSTYPE}" in
    ext4|xfs|btrfs) ;;
    *) die "unrecognised root fs type '${SRC_ROOT_FSTYPE}' on ${root_part} (exit 3)" ;;
esac
log "root partition: ${root_part} (#${root_part_num}, $((biggest / 1024 / 1024)) MiB, fstype=${SRC_ROOT_FSTYPE}) before grow"

# Grow the root partition into the headroom we added. `growpart`
# rewrites the partition table (fs-agnostic); `partprobe` re-reads it.
# The FILESYSTEM grow then differs by type: ext4 resizes OFFLINE
# (resize2fs on the unmounted partition); xfs + btrfs can only grow
# MOUNTED (`xfs_growfs` / `btrfs filesystem resize`), so they are
# deferred to just after the stage-3 mount.
log "growpart ${LOOP_DEV} ${root_part_num}"
sudo growpart "${LOOP_DEV}" "${root_part_num}" 2>&1 | sed 's/^/growpart: /' || true
sudo partprobe "${LOOP_DEV}" 2>/dev/null || true
sleep 1
ensure_loop_partitions "${LOOP_DEV}"
if [[ "${SRC_ROOT_FSTYPE}" == "ext4" ]]; then
    sudo e2fsck -fy "${root_part}" 2>&1 | tail -2 || true
    sudo resize2fs "${root_part}" 2>&1 | tail -2 || true
fi
new_size=$(sudo blockdev --getsize64 "${root_part}")
log "root partition grown: $((new_size / 1024 / 1024)) MiB"

# ── 3. Mount + bind virtual filesystems ─────────────────────────────

MNT_ROOT="${WORK_DIR}/mnt"
mkdir -p "${MNT_ROOT}"
mount_guest_root "${root_part}" "${MNT_ROOT}" rw

# xfs + btrfs grow ONLY while mounted — the deferred half of the
# stage-2 grow. (For btrfs, Fedora Cloud mounts the default `root`
# subvolume here; `resize ... max` grows the whole pool.)
if [[ "${SRC_ROOT_FSTYPE}" == "xfs" ]]; then
    command -v xfs_growfs >/dev/null 2>&1 \
        || die "xfs_growfs missing (install xfsprogs) — required for xfs-rooted images (exit 2)"
    sudo xfs_growfs "${MNT_ROOT}" 2>&1 | tail -2 || true
    log "xfs root grown (mounted xfs_growfs)"
elif [[ "${SRC_ROOT_FSTYPE}" == "btrfs" ]]; then
    command -v btrfs >/dev/null 2>&1 \
        || die "btrfs tool missing (install btrfs-progs) — required for btrfs-rooted images (exit 2)"
    sudo btrfs filesystem resize max "${MNT_ROOT}" 2>&1 | tail -2 || true
    log "btrfs root grown (mounted btrfs filesystem resize max)"
fi

# Detect the guest distro now that the root is mounted (sets DISTRO_*
# + asserts vs --distro). The debian family is the only one this PR's
# chroot path implements; a rhel-family image is detected + reported but
# the dnf/dracut path is wired in the RHEL-family PRs.
detect_distro "${MNT_ROOT}/etc/os-release"
if [[ "${profile}" == "cdn-node" && "${DISTRO_FAMILY}" != "debian" ]]; then
    die "--profile cdn-node supports the Debian family only (got ${DISTRO_ID}) (exit 3)"
fi

mount_boot_if_separate "${MNT_ROOT}"

for vfs in dev dev/pts proc sys run; do
    sudo mkdir -p "${MNT_ROOT}/${vfs}"
    sudo mount --bind "/${vfs}" "${MNT_ROOT}/${vfs}" || die "bind /${vfs} failed (exit 3)"
done

# ── 4. Stage Hippius tooling + keyscript ────────────────────────────

log "staging Hippius tooling into the image (family=${DISTRO_FAMILY})"
# Common to BOTH families: the shared release core + the two static
# musl binaries (one artifact serves initramfs-tools copy_exec AND
# dracut inst — PR #422).
sudo install -d -m 0755 "${MNT_ROOT}/etc/hippius"
sudo install -m 0644 "${CORE_SRC}" "${MNT_ROOT}/etc/hippius/hippius-release-core.sh"
sudo install -d -m 0755 "${MNT_ROOT}/lib/hippius"
sudo install -m 0644 "${CORE_SRC}" "${MNT_ROOT}/lib/hippius/hippius-release-core.sh"
sudo install -d -m 0755 "${MNT_ROOT}/usr/sbin"
sudo install -m 0755 "${hippius_release_bin}" "${MNT_ROOT}/usr/sbin/hippius-guest-release"
sudo install -m 0755 "${hippius_vsock_bin}" "${MNT_ROOT}/usr/sbin/hippius-vsock-ticket"

# ── GOLDEN mode: stage the overlay boot assets (golden-bake PR3) ─────
# In golden_verity_overlay mode the guest root is a dm-verity lower +
# per-VM guest-keyed overlay upper, assembled by an initramfs-tools boot
# script the golden hook bakes into the regenerated initrd. Staged HERE
# (customise phase) so the later `update-initramfs -u` (Debian) picks up
# the golden hook. Legacy mode never installs these ⇒ initrd unchanged.
if [[ "${disk_mode}" == "golden_verity_overlay" ]]; then
    log "golden: staging overlay boot assets (overlay lib + boot script + initramfs hook)"
    [[ -r "${GOLDEN_OVERLAY_SRC}" ]] || die "golden: ${GOLDEN_OVERLAY_SRC} missing (exit 2)"
    [[ -r "${GOLDEN_BOOT_SRC}" ]]    || die "golden: ${GOLDEN_BOOT_SRC} missing (exit 2)"
    [[ -r "${GOLDEN_HOOK_SRC}" ]]    || die "golden: ${GOLDEN_HOOK_SRC} missing (exit 2)"
    sudo install -m 0644 "${GOLDEN_OVERLAY_SRC}" "${MNT_ROOT}/etc/hippius/hippius-golden-overlay.sh"
    sudo install -m 0644 "${GOLDEN_OVERLAY_SRC}" "${MNT_ROOT}/lib/hippius/hippius-golden-overlay.sh"
    sudo install -m 0644 "${GOLDEN_BOOT_SRC}"    "${MNT_ROOT}/etc/hippius/hippius-golden-boot"
    if [[ "${DISTRO_FAMILY}" == "debian" ]]; then
        sudo install -d -m 0755 "${MNT_ROOT}/etc/initramfs-tools/hooks"
        sudo install -m 0755 "${GOLDEN_HOOK_SRC}" "${MNT_ROOT}/etc/initramfs-tools/hooks/hippius-golden"
        # cdn-node profile only: the ephemeral-root marker. mkinitramfs
        # copies /etc/initramfs-tools/conf.d/* into the initrd's
        # /conf/conf.d/, where the golden overlay library looks for it: with
        # it, every boot discards the overlay upper before the root is
        # assembled (a root implant cannot survive a reboot). Standard
        # golden initrds never carry it. /init sources conf.d files before
        # it parses the cmdline, so the marker also sets panic=10: a panic in
        # any initramfs stage reboots instead of opening a console shell.
        if [[ "${profile}" == "cdn-node" ]]; then
            sudo install -d -m 0755 "${MNT_ROOT}/etc/initramfs-tools/conf.d"
            printf '%s\n' '# hippius-bake-managed (cdn-node profile): ephemeral golden root.' 'panic=10' \
                | sudo tee "${MNT_ROOT}/etc/initramfs-tools/conf.d/hippius-cdn-ephemeral-upper" >/dev/null
            sudo chmod 0644 "${MNT_ROOT}/etc/initramfs-tools/conf.d/hippius-cdn-ephemeral-upper"
        fi
    else
        # RHEL/dracut: the golden overlay module (95hippius-golden) that
        # OWNS /sysroot assembly is staged with the other unlock assets in
        # the family block below (gated on disk_mode), so the later
        # `dracut --force` bakes it into the initrd. The shared overlay lib
        # installed just above at /etc/hippius/ + /lib/hippius/ is what the
        # module `inst`s into the initrd.
        log "golden: dracut overlay module staged in the RHEL unlock-asset block (95hippius-golden)"
    fi
fi

# §24/§25 guest shutdown-sign hook (optional). When the operator passed
# --hippius-eol-bin, stage the hippius-agent-initramfs binary into the
# ROOTFS (the running guest is the distro's own systemd, NOT this binary
# as /init — so the shutdown hook needs its own copy here) and install a
# systemd shutdown hook that runs `eol --sign-only` on a CLEAN poweroff.
#
# IMPORTANT — the RELIABLE shutdown-hook pattern is ExecStop, NOT a
# oneshot ExecStart pulled into shutdown.target.wants. systemd does NOT
# start a fresh unit while transitioning to the poweroff/reboot targets
# (those are reached by isolating; a stopped unit in shutdown.target.wants
# is not started during the final transition). The unit that reliably
# "runs at shutdown" is one ACTIVE since boot that does its work in
# ExecStop, which systemd invokes when it stops the unit during the
# shutdown job — ordered Before=shutdown.target so it fires while the NIC
# (vsock proxy reach) + dm-crypt mapping are still up. This is the same
# pattern long-lived shutdown actions (e.g. rc-local-style hooks) use.
#
# So: the service is enabled at boot (WantedBy=multi-user.target), starts
# as a no-op (ExecStart=/bin/true), RemainAfterExit=yes keeps it active,
# and the real sign+push is ExecStop. `eol --sign-only` does NOT luksClose
# / poweroff itself (systemd owns those) and NEVER crypto-erases — §25
# preserves the disk.
if [[ -n "${hippius_eol_bin}" ]]; then
    log "staging §24/§25 guest shutdown-sign hook (hippius-eol-sign.service)"
    sudo install -m 0755 "${hippius_eol_bin}" "${MNT_ROOT}/usr/sbin/hippius-agent-initramfs"
    # The boot-activated, ExecStop-at-shutdown unit. Ordering rationale:
    #   - After=network-online.target + the dm-crypt mapping at boot, so
    #     when its ExecStop runs (Before=shutdown.target) the network +
    #     dm-crypt are STILL up (the push needs the vsock proxy reach).
    #   - Before=shutdown.target umount.target + (legacy)
    #     After=systemd-cryptsetup@cryptroot.service: the ExecStop fires
    #     before the filesystems go and before the LUKS mapping closes.
    #   - RemainAfterExit=yes: the no-op ExecStart leaves the unit "active"
    #     so systemd issues the ExecStop on the shutdown transition.
    #   - TimeoutStopSec bounds the vali push so an unreachable vali can
    #     never wedge the shutdown (the binary already swallows the miss,
    #     but the systemd timeout is the belt-and-braces fail-closed).
    sudo tee "${MNT_ROOT}/etc/systemd/system/hippius-eol-sign.service" >/dev/null <<'EOLUNIT_EOF'
[Unit]
Description=Hippius §24/§25 guest EOL stopped-ack sign + push (clean shutdown)
# Order the shutdown action BEFORE the net + dm-crypt teardown so the
# ExecStop push still has the vsock-proxy reach + the signing key.
#
# DefaultDependencies=no drops the implicit After=basic.target /
# sysinit.target edges, which this unit does not want (it is ordered off
# network-online.target instead). We re-add the two default-dep edges it
# actually needs by
# hand: Conflicts+Before=shutdown.target — that pair is what makes
# systemd STOP the RemainAfterExit oneshot on the shutdown transition
# (which is what fires ExecStop), ordered before the final target. The
# explicit Before=umount.target keeps the push ahead of the filesystem
# teardown, and the dm-crypt close follows the unmounts.
#
# NOT Before=cryptsetup.target. That is an EARLY-BOOT target, and pairing
# it with After=network-online.target (a LATE one) is an ordering cycle by
# construction: cryptsetup.target -> hippius-eol-sign -> network-online ->
# cloud-init-network -> basic.target -> sysinit.target -> cryptsetup.target.
# DefaultDependencies=no does NOT break it: the cycle closes through these
# explicit edges, not the default ones. systemd then deletes one job per
# boot to break the cycle, and WHICH job is graph-dependent. On the RHEL
# family it deleted cloud-init-network.service, so cloud-init never
# finished and the guest never enrolled in NetBird (observed on the Fedora
# and CentOS Stream P0 gate; the blessed Fedora carries the same cycle and
# happens to sacrifice the harmless cryptsetup.target instead). Shutdown
# ordering never needed that edge — stopping before umount.target already
# puts the push ahead of the storage teardown.
DefaultDependencies=no
After=network-online.target
Wants=network-online.target
# LEGACY guests only: the per-VM LUKS root is opened by
# systemd-cryptsetup@cryptroot.service (from /etc/crypttab). Ordering
# AFTER it at boot means systemd stops it AFTER this unit at shutdown, so
# the ExecStop signs + pushes while the mapping is still open. This is the
# direct edge; Before=umount.target only orders against that target, not
# against the cryptsetup instance's own stop job. Ordering does not pull
# the unit in, so on a GOLDEN guest (empty crypttab — the overlay is
# LUKS-opened by the initramfs) this line is inert.
After=systemd-cryptsetup@cryptroot.service
Conflicts=shutdown.target
Before=shutdown.target umount.target

[Service]
Type=oneshot
RemainAfterExit=yes
# No-op at boot — keeps the unit ACTIVE so the ExecStop fires at shutdown.
ExecStart=/bin/true
# The real work, run when systemd STOPS the unit during the shutdown
# transition: sign the StoppedAck from the measured cmdline (hippius.vm_id
# / lease_id / vm_generation / eol_nonce / vali_url) + push it over the
# vsock proxy to vali. NEVER luksClose / poweroff (systemd owns those).
ExecStop=/usr/sbin/hippius-agent-initramfs eol --sign-only
# Fail-closed on the shutdown side: a stuck push must not wedge poweroff.
TimeoutStopSec=20
# A sign/push miss is swallowed by the binary (exit 0); even so, do not
# let a non-zero exit abort the shutdown transition.
SuccessExitStatus=0 1 2

[Install]
# Enabled at BOOT — active-since-boot is what makes the ExecStop fire on
# the shutdown transition (a shutdown.target.wants oneshot would NOT run).
WantedBy=multi-user.target
EOLUNIT_EOF
    sudo install -d -m 0755 "${MNT_ROOT}/etc/systemd/system/multi-user.target.wants"
    sudo ln -sf ../hippius-eol-sign.service \
        "${MNT_ROOT}/etc/systemd/system/multi-user.target.wants/hippius-eol-sign.service"
else
    log "WARN: --hippius-eol-bin not given — §24/§25 guest shutdown-sign hook NOT baked"
    log "      (the §25 cold-migration stopped-ack will not be delivered; the"
    log "       migration will fail closed / time out — see --hippius-eol-bin)"
fi

# §23 served-receipt telemetry agent. When --hippius-telemetry-bin is given,
# stage the hippius-agent-tenant-telemetry binary into the rootfs and install
# a boot-activated systemd unit that runs it for the VM's lifetime. The agent
# reads its inputs (node_id / vm_id / lease_id / resource_class / family_id /
# lifecycle_key_path) from the MEASURED cmdline, HKDF-derives its signing key
# from the §7 lifecycle key at /run/hippius/lifecycle.key, and pushes
# guest-signed ServedDeliveryReceipts over AF_VSOCK to the host miner-agent's
# relay (port 5000) every interval. The receipts ride vsock, NOT the tenant
# overlay, so the unit needs no network dependency. Restart=on-failure with
# the rate-limiter disabled makes the unit retry until the lifecycle key +
# the host vsock listener are both ready (the KBS releases the key early in
# boot, but the unit may start before the tmpfs write lands).
if [[ -n "${hippius_telemetry_bin}" ]]; then
    log "staging §23 served-receipt telemetry agent (hippius-tenant-telemetry.service)"
    sudo install -m 0755 "${hippius_telemetry_bin}" \
        "${MNT_ROOT}/usr/sbin/hippius-agent-tenant-telemetry"
    sudo tee "${MNT_ROOT}/etc/systemd/system/hippius-tenant-telemetry.service" >/dev/null <<'TELEMUNIT_EOF'
[Unit]
Description=Hippius §23 served-receipt telemetry agent (uptime billing)
After=local-fs.target
DefaultDependencies=yes
# The rate-limiter is disabled so a slow key release never trips systemd's
# start-limit into a permanent failed state. It MUST sit in [Unit]: systemd
# 255 rejects it in [Service] ("Unknown key name") and keeps the limiter on.
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/sbin/hippius-agent-tenant-telemetry
# Retry until the §7 lifecycle key (/run/hippius/lifecycle.key) + the host
# vsock relay are both ready (rate-limiter disabled in [Unit] above).
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
TELEMUNIT_EOF
    sudo install -d -m 0755 "${MNT_ROOT}/etc/systemd/system/multi-user.target.wants"
    sudo ln -sf ../hippius-tenant-telemetry.service \
        "${MNT_ROOT}/etc/systemd/system/multi-user.target.wants/hippius-tenant-telemetry.service"
else
    log "WARN: --hippius-telemetry-bin not given — §23 served-receipt agent NOT baked"
    log "      (uptime billing stays inert: no guest emits served receipts)"
fi

# §23 SNP live-attestation keepalive agent. When --hippius-keepalive-bin is
# given, stage the hippius-agent-keepalive binary + its cmdline shim into
# the rootfs and install a boot-activated unit that runs it for the VM's
# lifetime.
#
# WHY IT MATTERS: the served-receipt telemetry key above is readable by
# root inside the CVM, so a miner can lift it, KILL the VM, and keep
# signing well-formed uptime receipts from anywhere. The keepalive agent
# is the counter-proof: every tick it asks `/dev/sev-guest` for a fresh
# SNP report bound to a single-use KBS nonce, and the KBS signs a
# `LiveAttestation` only after verifying that report VCEK→ASK→ARK against
# AMD's silicon root with `measurement ∈ §22 allowlist`. An extracted
# software key cannot produce one; a dead VM cannot produce one at all.
# Uncovered time accrues ZERO once `uptimeLiveness.requireAttestation` is
# armed — so WITHOUT this unit no guest emits a proof, vali's
# VmLiveAttestation table stays empty, and arming the gate would zero the
# whole fleet's credit. This staging IS step 2 of the arming sequence in
# deploy/gitops/apps/vali/values.yaml.
#
# The unit is deliberately inert on failure: `Type=simple`, ordered
# `Before=` NOTHING, pulled in by a `Wants=` (not `Requires=`) from
# multi-user.target, and the agent's own tick loop swallows every KBS
# error and sleeps to the next tick. An unreachable KBS therefore costs
# the miner uncredited uptime and costs the tenant nothing — which is the
# designed incentive, and it only holds because the guest survives.
#
# Family-neutral: the same /etc/systemd/system unit + explicit
# multi-user.target.wants symlink the eol + telemetry units use. `systemctl
# enable` cannot run here (the baker container's pid1 is not systemd), and
# the symlink is what makes the unit ENABLED rather than merely installed.
#
# The sentinels below delimit the block `scripts/dev/keepalive-unit-test.sh`
# extracts and EXECUTES verbatim against a temp rootfs (sudo stubbed) — so
# the test asserts on the bytes this script really installs, not a copy.
# >>> BEGIN keepalive-staging-block
if [[ -n "${hippius_keepalive_bin}" ]]; then
    log "staging §23 SNP live-attestation keepalive agent (hippius-keepalive.service, interval=${keepalive_interval_secs}s)"
    sudo install -m 0755 "${hippius_keepalive_bin}" \
        "${MNT_ROOT}/usr/sbin/hippius-agent-keepalive"
    sudo install -m 0755 "${KEEPALIVE_SHIM_SRC}" \
        "${MNT_ROOT}/usr/sbin/hippius-keepalive-start"
    # Bake-time tunables the shim reads via the unit's EnvironmentFile. A
    # file rather than baked-in argv so an operator can read the cadence
    # off a running guest, and the shim keeps identical defaults if it is
    # ever absent.
    sudo install -d -m 0755 "${MNT_ROOT}/etc/hippius"
    sudo tee "${MNT_ROOT}/etc/hippius/keepalive.env" >/dev/null <<KEEPALIVEENV_EOF
# hippius-bake-managed. Read by hippius-keepalive.service.
# HIPPIUS_KEEPALIVE_INTERVAL_SECS MUST stay <= vali's
# uptimeLiveness.coverageSeconds (${KEEPALIVE_MAX_INTERVAL_SECS}) — one attestation vouches
# BACKWARD for that span only, so a wider cadence leaves live time
# uncovered and the armed gate credits it ZERO.
HIPPIUS_KEEPALIVE_INTERVAL_SECS=${keepalive_interval_secs}
HIPPIUS_KEEPALIVE_RELAY_PORT=${keepalive_relay_port}
KEEPALIVEENV_EOF
    sudo chmod 0644 "${MNT_ROOT}/etc/hippius/keepalive.env"
    sudo tee "${MNT_ROOT}/etc/systemd/system/hippius-keepalive.service" >/dev/null <<'KEEPALIVEUNIT_EOF'
[Unit]
Description=Hippius §23 SEV-SNP live-attestation keepalive (uptime liveness)
# local-fs.target only: the KBS is reached over AF_VSOCK through the host
# miner-agent (hippius.kbs_url=vsock://2:19266), which needs no network,
# no DNS and no route. `network-online.target` is ordered-after WITHOUT a
# Wants= so an https:// KBS URL (dev/staging) starts after the NIC if
# something else pulls that target in — but this unit never pulls it in
# itself and so can never extend boot.
After=local-fs.target network-online.target
# NO Before= ANYTHING. A guest whose KBS path a hostile miner blocks must
# still boot and serve its tenant normally; the miner's only penalty is
# its own uncredited uptime, and that incentive collapses if a blocked
# keepalive can wedge the VM.
DefaultDependencies=yes
# Disable the start rate-limiter so a long KBS outage can never leave the
# unit permanently `failed` — which would silently end this VM's ability
# to be credited for uptime for the rest of its life. Declared in [Unit]:
# systemd 255 no longer accepts it in [Service].
StartLimitIntervalSec=0

[Service]
Type=simple
EnvironmentFile=-/etc/hippius/keepalive.env
ExecStart=/usr/sbin/hippius-keepalive-start
# The daemon only returns on error; restart it forever (the rate-limiter
# is disabled in [Unit] above).
Restart=always
RestartSec=15
# Two terminal conditions restarting cannot fix:
#   2  — /dev/sev-guest is unavailable, so this is not a real SNP guest
#        and signing liveness attestations for it would be a lie;
#   78 — EX_CONFIG: the measured cmdline carries no hippius.vm_id /
#        node_id / kbs_url, so this is not a Hippius tenant VM.
RestartPreventExitStatus=2 78

[Install]
WantedBy=multi-user.target
KEEPALIVEUNIT_EOF
    sudo install -d -m 0755 "${MNT_ROOT}/etc/systemd/system/multi-user.target.wants"
    sudo ln -sf ../hippius-keepalive.service \
        "${MNT_ROOT}/etc/systemd/system/multi-user.target.wants/hippius-keepalive.service"
else
    log "WARN: --hippius-keepalive-bin not given — §23 SNP liveness agent NOT baked"
    log "      (no guest emits a live attestation; vali's VmLiveAttestation stays"
    log "       empty and uptimeLiveness.requireAttestation can never be armed)"
fi
# <<< END keepalive-staging-block

# Stable SSH host keys across reboots (all families). The §21 release-core
# writes a PER-BOOT cloud-init instance-id (so the KBS-released userdata is
# re-applied every boot), which makes cloud-init re-run its per-instance
# `ssh` module on every reboot. cloud-init's default `ssh_deletekeys: true`
# would then DELETE + regenerate /etc/ssh/ssh_host_* on every boot — so the
# host key changes each reboot and the operator's known_hosts breaks
# ("REMOTE HOST IDENTIFICATION HAS CHANGED"). The rootfs is persistent
# (LUKS ext4), so disabling the delete keeps the keys cloud-init generates
# on FIRST boot (unique per VM) stable for the VM's lifetime. The confidential
# trust anchor is the SNP attestation, not the SSH host key — this only fixes
# operator UX, it does not weaken any guarantee.
sudo install -d -m 0755 "${MNT_ROOT}/etc/cloud/cloud.cfg.d"
sudo tee "${MNT_ROOT}/etc/cloud/cloud.cfg.d/99-hippius-ssh-hostkeys.cfg" >/dev/null <<'EOF'
# hippius-bake-managed: keep SSH host keys stable across reboots.
# (cloud-init re-runs per-instance modules every boot via a per-boot
# instance-id; without this it would regenerate host keys each reboot.)
ssh_deletekeys: false
EOF

# Deterministically pin cloud-init to the NoCloud seed on the initramfs
# tmpfs (§20-safe: userdata NEVER touches disk). The §21 release-core
# fail-closes the KBS-released userdata to /run/cloud-init/seed/{user-
# data,meta-data} in the initramfs; that tmpfs is CARRIED into the real
# root across switch_root. Without this pin the image had NO
# datasource_list, NO seedfrom, and let ds-identify GUESS the datasource
# per boot — a per-boot random instance-id with no /var/lib/cloud
# fallback means one flaky guess = total userdata loss (no SSH key, no
# `netbird up`; the ~80% intermittent provisioning failure).
#
# The fix removes the guesswork two ways at once:
#   1. datasource_list: [ NoCloud, None ] is EXACTLY the ds-identify
#      single-entry short-circuit ("$# -eq 2 -a $2 = None") — ds-identify
#      selects NoCloud WITHOUT probing any dscheck_* heuristic, so the
#      per-boot guess can no longer land on the wrong (or no) datasource.
#      None stays as the explicit fail-open fallback.
#   2. datasource.NoCloud.seedfrom points the local NoCloud datasource
#      (the /-or-file:// filesystem variant, cloud-init >=24.1's
#      DataSourceNoCloud) straight at the tmpfs seed dir. Its ds_detect
#      returns True purely from this sys_cfg key, so consumption no
#      longer depends on ds-identify honouring the kernel `ds=nocloud;s=`
#      token or on the seed dir being probed. The bare path matches the
#      measured cmdline's `s=/run/cloud-init/seed/`; the trailing slash
#      is required (cloud-init appends user-data / meta-data).
# Applies to every family: cloud-init reads /etc/cloud/cloud.cfg.d on
# Ubuntu/Debian AND RHEL/CentOS, and the seed path is distro-independent.
sudo tee "${MNT_ROOT}/etc/cloud/cloud.cfg.d/99-hippius-nocloud.cfg" >/dev/null <<'EOF'
# hippius-bake-managed: force the NoCloud datasource + the initramfs
# tmpfs seed (no ds-identify guessing, no on-disk userdata — §20).
datasource_list: [ NoCloud, None ]
datasource:
  NoCloud:
    fs_label: null
    seedfrom: /run/cloud-init/seed/
EOF

# Untrusted miner vs. cloud-init (M0 hardening). The miner writes the
# libvirt domain XML, and nothing it attaches beyond OVMF + kernel +
# initrd + cmdline is in the SNP launch measurement. NoCloud's default
# `fs_label: cidata` would mount any disk the miner labels `cidata` and
# MERGE its user-data/meta-data over ours (root runcmd, ssh keys) —
# `fs_label: null` above turns that volume probe off; the tmpfs seed is
# the only source. ds-identify gets `policy: enabled`: it writes no
# datasource_list and probes nothing (no blkid/DMI heuristics), and
# cloud-init runs on the pinned list above. NOT `disabled` — in
# ds-identify that mode disables cloud-init itself, and with it the
# userdata + NetBird enrolment.
# The SMBIOS system-serial-number `ds=nocloud;s=<url>` seedfrom vector is
# closed by the same pin: NoCloud parses the DMI serial and the kernel
# cmdline first, then assigns our `ds_cfg.seedfrom` (/run/cloud-init/seed/)
# into meta-data, and only then dereferences it — so a miner-set serial URL
# is overwritten before it is read (DataSourceNoCloud._get_data, verified
# across cloud-init 22.4.2, 24.1.3 and current). The remaining unmeasured
# credential path — systemd's SMBIOS type 11 / fw_cfg import — is closed by
# `systemd.import_credentials=no` on the SNP-measured kernel cmdline (vali
# emitter), not here.
sudo tee "${MNT_ROOT}/etc/cloud/ds-identify.cfg" >/dev/null <<'EOF'
# hippius-bake-managed: no datasource probing; cloud-init uses the
# pinned datasource_list in cloud.cfg.d/99-hippius-nocloud.cfg.
policy: enabled
EOF
sudo chmod 0644 "${MNT_ROOT}/etc/cloud/ds-identify.cfg"

# Single guest IP (#289 multi-IP, userspace half — the initramfs
# network itself is boot-load-bearing and must NOT be gated, two P0s:
# #670/#673). Two userspace mechanisms stack stray addresses on the
# tenant NIC (live smokeip3 forensics, 2026-07-04):
#
#   1. `cloud-initramfs-dyn-netconf` (an init-bottom script) snapshots
#      the initramfs network state — the release-core's static
#      192.168.122.253 AND the klibc-ipconfig DHCP lease — and hands
#      it to userspace for re-application, UNDOING the
#      `hippius-net-teardown` flush that runs alongside it. That is
#      where the `.253` static and the `metric 100` forever-lease
#      addresses come from. The tenant image never needs it: its
#      network is plain DHCP on one NIC, brought up fresh by
#      the image's own DHCP profile below. PURGED in the chroot below.
#
#   2. systemd-networkd then DHCPs with an RFC-4361 DUID client-id
#      while the initramfs client used type-1 `01:<MAC>` — dnsmasq
#      sees two clients on one MAC and hands out a SECOND lease.
#      `ClientIdentifier=mac` in the .network below makes userspace
#      present the SAME client-id so dnsmasq re-issues the initramfs
#      lease (a global networkd.conf.d default for it does NOT exist —
#      noble logs "Unknown key name" — the key is per-.network only).
#      Ubuntu 24.04's initramfs DHCP client is dhcpcd, whose stock
#      config says `duid ll` (client-id = IAID + DUID, not 01:<MAC>);
#      the zz-hippius-dhcp-clientid initramfs hook switches it to
#      `clientid` (01:<MAC>). Debian's initramfs runs klibc ipconfig,
#      which sends no client-id: dnsmasq matches its lease on the MAC.
#      initramfs-dhcp-clientid-test checks both against a real dnsmasq.
#
# The guest network does NOT come from cloud-init. With no network-config
# in the seed, cloud-init generated a fallback config at init-local on
# EVERY boot (the per-boot instance-id makes every boot a first boot), and
# on Fedora 43 (cloud-init 25.2) that raced udev renaming eth0 → enp1s0:
# read_sys_net_safe("eth0", "address") returned False, `.lower()` raised,
# and 1 boot in 5 came up with no cloud-init network (bake 5).
# `network: {config: disabled}` in system config stops it before any
# fallback is generated (cloud-init checks system_cfg before the
# datasource and before falling back). The network comes instead from a
# static, bake-time DHCP profile per family, matching every Ethernet NIC
# by name (`en*`/`eth*`: the miner picks the PCI slot, so the name is not
# fixed); nothing miner-controlled feeds it beyond the DHCP lease itself,
# as before:
#   - debian family (Ubuntu, Debian): systemd-networkd, enabled in both
#     cloud images, with an empty /etc/netplan and no default .network —
#     cloud-init's netplan was the ONLY network config they had. A tenant
#     netplan file still wins: netplan's generated 10-netplan-*.network
#     sorts before 50-hippius-dhcp.network.
#   - rhel family (CS10, Fedora): a NetworkManager keyfile, so DHCP does
#     not rest on NM's implicit "Wired connection" default.
sudo install -d -m 0755 "${MNT_ROOT}/etc/cloud/cloud.cfg.d"
sudo tee "${MNT_ROOT}/etc/cloud/cloud.cfg.d/99-hippius-network.cfg" >/dev/null <<'HIPPIUS_CI_NETWORK'
# hippius-bake-managed: cloud-init writes no network config; the image's
# own DHCP profile brings the NIC up (no per-boot fallback generation).
network:
  config: disabled
HIPPIUS_CI_NETWORK
case "${DISTRO_FAMILY}" in
debian)
    # The enablement link is absolute (/usr/lib/...): test the link and the
    # GUEST's unit, never `test -e` through the link (that resolves on the
    # baker's own filesystem).
    { sudo test -L "${MNT_ROOT}/etc/systemd/system/multi-user.target.wants/systemd-networkd.service" \
        && sudo test -f "${MNT_ROOT}/usr/lib/systemd/system/systemd-networkd.service"; } \
        || die "base image does not enable systemd-networkd — the hippius DHCP profile would not bring the NIC up (exit 3)"
    sudo install -d -m 0755 "${MNT_ROOT}/etc/systemd/network"
    sudo tee "${MNT_ROOT}/etc/systemd/network/50-hippius-dhcp.network" >/dev/null <<'HIPPIUS_NETWORKD_DHCP'
# hippius-bake-managed: DHCPv4 on every Ethernet NIC (cloud-init writes no
# network config). ClientIdentifier=mac: the raw-MAC client-id of #289
# (multi-IP).
[Match]
Name=en* eth*
Type=ether

[Network]
DHCP=ipv4

[DHCPv4]
ClientIdentifier=mac
HIPPIUS_NETWORKD_DHCP
    sudo chmod 0644 "${MNT_ROOT}/etc/systemd/network/50-hippius-dhcp.network"
    ;;
*)
    sudo test -x "${MNT_ROOT}/usr/sbin/NetworkManager" \
        || die "base image has no NetworkManager — the hippius DHCP profile would not bring the NIC up (exit 3)"
    sudo install -d -m 0700 "${MNT_ROOT}/etc/NetworkManager/system-connections"
    sudo tee "${MNT_ROOT}/etc/NetworkManager/system-connections/hippius-dhcp.nmconnection" >/dev/null <<'HIPPIUS_NM_DHCP'
# hippius-bake-managed: DHCP on every Ethernet NIC (cloud-init writes no
# network config).
[connection]
id=hippius-dhcp
uuid=cfd11484-f30f-4f37-abc3-6757a00191b5
type=ethernet
autoconnect=true
# 3 = multiple (the keyfile reader takes the number; the name is ignored).
multi-connect=3

[match]
interface-name=en*;eth*;

[ipv4]
method=auto

[ipv6]
method=auto
HIPPIUS_NM_DHCP
    # NM ignores a keyfile that is not root-only.
    sudo chmod 0600 "${MNT_ROOT}/etc/NetworkManager/system-connections/hippius-dhcp.nmconnection"
    ;;
esac

if [[ "${DISTRO_FAMILY}" == "debian" ]]; then
    # Debian family: initramfs-tools hook + crypttab keyscript= model.
    sudo install -m 0644 "${KEYSCRIPT_SRC}" "${MNT_ROOT}/etc/hippius/hippius-luks-keyscript"
    # ALSO at the crypttab-referenced path, executable: Debian 12's
    # cryptsetup-initramfs VALIDATES keyscript= against the rootfs at
    # update-initramfs time and SKIPS the crypttab entry when missing
    # ("invalid value for 'keyscript' option") — an initrd that can
    # never unlock. Ubuntu accepts a late-staged path; both is correct.
    sudo install -m 0755 "${KEYSCRIPT_SRC}" "${MNT_ROOT}/sbin/hippius-luks-keyscript"
    # #289 — init-bottom DHCP/static teardown. Installed into the guest's
    # /etc/initramfs-tools/scripts/init-bottom/ so mkinitramfs BOTH copies
    # it into the initrd AND lists it in `/scripts/init-bottom/ORDER` —
    # the execution manifest. The previous approach (the hippius-luks
    # hook cp'ing it into DESTDIR/scripts/) shipped the file but it NEVER
    # RAN: hooks execute after mkinitramfs generates ORDER from the
    # rootfs script dirs, so the hook-copied script had no ORDER entry
    # (proven live 2026-07-04 on smokeip4 — the release-core's static
    # .253 survived the pivot).
    sudo install -d -m 0755 "${MNT_ROOT}/etc/initramfs-tools/scripts/init-bottom"
    sudo install -m 0755 "${NET_TEARDOWN_SRC}" \
        "${MNT_ROOT}/etc/initramfs-tools/scripts/init-bottom/hippius-net-teardown"
    sudo install -d -m 0755 "${MNT_ROOT}/etc/initramfs-tools/hooks"
    sudo install -m 0755 "${HOOK_SRC}" "${MNT_ROOT}/etc/initramfs-tools/hooks/hippius-luks"
    # Runs after every stock hook (/etc hooks follow /usr/share ones):
    # drops the build host's md arrays, efivarfs and /dev/random seed the
    # bind-mounted /proc, /sys and /dev let the stock hooks capture.
    sudo install -m 0755 "${HOST_STATE_HOOK_SRC}" "${MNT_ROOT}/etc/initramfs-tools/hooks/zz-hippius-host-state"
    # Also after the stock dhcpcd hook: Ubuntu 24.04's initramfs DHCP
    # client is dhcpcd with `duid ll` (client-id = IAID + DUID), so
    # dnsmasq gave the booted guest's 01:<MAC> (50-hippius-dhcp.network,
    # ClientIdentifier=mac) a SECOND lease and held the initramfs one until
    # it expired. The hook makes it `clientid` (01:<MAC>). No-op on
    # Debian, whose initramfs runs klibc ipconfig (no client-id at all).
    sudo install -m 0755 "${DHCP_CLIENTID_HOOK_SRC}" "${MNT_ROOT}/etc/initramfs-tools/hooks/zz-hippius-dhcp-clientid"

    # Force apt to use IPv4 inside the chroot — same workaround HCCS
    # documents for the IPv6-blackholed builder pod case.
    sudo tee "${MNT_ROOT}/etc/apt/apt.conf.d/99force-ipv4" >/dev/null <<'EOF'
Acquire::ForceIPv4 "true";
EOF
elif [[ "${disk_mode}" == "golden_verity_overlay" ]]; then
    # RHEL family, GOLDEN mode: the dracut 95hippius-golden module OWNS
    # /sysroot assembly (dm-verity lower + per-VM guest-keyed overlay
    # upper). It REPLACES 90hippius-luks — the legacy crypttab unlock must
    # NOT run in golden mode (the crypttab is empty and, critically, a
    # second §21 release would spend the single-use nonce-bound ticket and
    # fail closed). module-setup.sh inst's the core, the overlay lib, the
    # binaries, the cmdline rootok hook and the units into the initrd; the
    # conf.d drop-in makes every dracut invocation include it (and ONLY
    # it — no hippius-luks).
    sudo install -d -m 0755 "${MNT_ROOT}/usr/lib/dracut/modules.d/95hippius-golden"
    sudo install -m 0755 "${GOLDEN_DRACUT_MODULE_SRC}"/*.sh      "${MNT_ROOT}/usr/lib/dracut/modules.d/95hippius-golden/"
    sudo install -m 0644 "${GOLDEN_DRACUT_MODULE_SRC}"/*.service "${MNT_ROOT}/usr/lib/dracut/modules.d/95hippius-golden/"
    sudo tee "${MNT_ROOT}/etc/dracut.conf.d/95-hippius-golden.conf" >/dev/null <<'EOF'
# hippius-bake-managed (golden_verity_overlay): include the Hippius golden
# overlay-root module. NOT hippius-luks — golden owns /sysroot assembly
# and must run the §21 KBS release exactly once.
add_dracutmodules+=" hippius-golden "
EOF
    # dnf's IPv4 forcing (apt's Acquire::ForceIPv4 equivalent).
    if ! sudo grep -q '^ip_resolve=' "${MNT_ROOT}/etc/dnf/dnf.conf" 2>/dev/null; then
        echo 'ip_resolve=4' | sudo tee -a "${MNT_ROOT}/etc/dnf/dnf.conf" >/dev/null
    fi
else
    # RHEL family: the dracut 90hippius-luks module (keyfile unlock —
    # dracut has no keyscript=). module-setup.sh inst's the core, the
    # binaries, the units and the crypttab into the initrd; the
    # conf.d drop-in makes every dracut invocation include it.
    sudo install -d -m 0755 "${MNT_ROOT}/usr/lib/dracut/modules.d/90hippius-luks"
    sudo install -m 0755 "${DRACUT_MODULE_SRC}"/*.sh         "${MNT_ROOT}/usr/lib/dracut/modules.d/90hippius-luks/"
    sudo install -m 0644 "${DRACUT_MODULE_SRC}"/*.service         "${MNT_ROOT}/usr/lib/dracut/modules.d/90hippius-luks/"
    sudo tee "${MNT_ROOT}/etc/dracut.conf.d/90-hippius.conf" >/dev/null <<'EOF'
# hippius-bake-managed: always include the Hippius KBS unlock module.
add_dracutmodules+=" hippius-luks "
EOF
    # dnf's IPv4 forcing (apt's Acquire::ForceIPv4 equivalent).
    if ! sudo grep -q '^ip_resolve=' "${MNT_ROOT}/etc/dnf/dnf.conf" 2>/dev/null; then
        echo 'ip_resolve=4' | sudo tee -a "${MNT_ROOT}/etc/dnf/dnf.conf" >/dev/null
    fi
fi

# Working DNS inside the chroot. Cloud images symlink
# /etc/resolv.conf -> ../run/systemd/resolve/stub-resolv.conf, which
# resolves to NOTHING under the bind-mounted /run of the baker pod —
# apt indexes then partially fail and `udhcpc` / `isc-dhcp-client`
# become unlocatable (observed live 2026-06-10, bake take-8). Swap in
# the build environment's resolv.conf for the chroot run; stage 5
# restores the distro symlink so the baked image keeps the
# systemd-resolved default. Same pattern as
# thenervelab/hccs::generate_chroot_script.
# Record what the image originally had so stage 5 can restore it
# EXACTLY: Ubuntu noble = symlink to systemd-resolved's stub; Debian
# genericcloud = plain file (or absent). A hardcoded restore would
# graft Ubuntu's symlink onto every distro.
RESOLV_WAS="absent"
RESOLV_LINK_TARGET=""
if [[ -L "${MNT_ROOT}/etc/resolv.conf" ]]; then
    RESOLV_WAS="symlink"
    RESOLV_LINK_TARGET="$(readlink "${MNT_ROOT}/etc/resolv.conf")"
elif [[ -f "${MNT_ROOT}/etc/resolv.conf" ]]; then
    RESOLV_WAS="file"
    sudo cp "${MNT_ROOT}/etc/resolv.conf" "${WORK_DIR}/resolv.conf.orig"
fi
sudo rm -f "${MNT_ROOT}/etc/resolv.conf"
sudo cp /etc/resolv.conf "${MNT_ROOT}/etc/resolv.conf"

# Bring eth0 up at initramfs time — UNCONDITIONALLY, even for a
# `vsock://` KBS that needs no IP network. Skipping this for vsock has
# been tried TWICE and both bakers silently hung every guest pre-KBS:
# #670 (dropping `IP=dhcp` also dropped virtio_net from the initrd) and
# #673 (IP=dhcp dropped, virtio_net pinned, release-core net_up skipped
# — STILL hung; some other effect of `IP=dhcp`/configure_networking is
# boot-load-bearing). Both reverted (#672/#675). DO NOT re-gate this.
# The multi-IP it used to leave behind is fixed in USERSPACE instead:
# `cloud-initramfs-dyn-netconf` is purged (it re-applied the initramfs
# net state in userspace, undoing the `hippius-net-teardown` flush)
# and the `ClientIdentifier=mac` .network file makes userspace
# systemd-networkd present the SAME DHCP client-id as the initramfs
# client, so dnsmasq re-issues the SAME lease.
if [[ -f "${MNT_ROOT}/etc/initramfs-tools/initramfs.conf" ]]; then
    if ! sudo grep -q '^IP=' "${MNT_ROOT}/etc/initramfs-tools/initramfs.conf"; then
        echo 'IP=dhcp' | sudo tee -a "${MNT_ROOT}/etc/initramfs-tools/initramfs.conf" >/dev/null
    fi
fi

# /etc/crypttab — the entry cryptsetup-initramfs reads at boot. The
# `cryptroot` name is what `/dev/mapper/cryptroot` becomes after
# unlock. We reference the source as `/dev/vda` (the LUKS-encrypted
# qcow2 attached as the first virtio-blk device) rather than UUID=
# because the UUID isn't known until the OUTPUT raw is luksFormat'd
# later in the script — and patching the crypttab after the chroot
# would force a second `update-initramfs -u` round. Device-path is
# stable for the dispatch model (always /dev/vda).
# #296 in both variants: `header=/run/hippius/luks.header` opens
# against the VERIFIED tmpfs copy the release core staged, closing the
# TOCTOU between the SHA check and the open (CVE-2025-59054 family).
#
# GOLDEN mode (golden-bake PR3): there is NO cryptroot-as-root. The
# guest root is a dm-verity lower + per-VM guest-keyed overlay upper the
# `boot=hippius-golden` boot script assembles at /root (initramfs-tools
# owns the switch_root). So write an EMPTY crypttab (no cryptsetup-
# initramfs cryptroot) and an overlay-friendly fstab (root is already
# mounted by the boot script; systemd must NOT try to mount a
# nonexistent /dev/mapper/cryptroot). The per-VM upper's LUKS open is
# done by the boot script with the KBS KEK, NOT by crypttab.
if [[ "${disk_mode}" == "golden_verity_overlay" ]]; then
    sudo tee "${MNT_ROOT}/etc/crypttab" >/dev/null <<'EOF'
# hippius-bake-managed (golden_verity_overlay): intentionally EMPTY.
# Root is an overlayfs (RO dm-verity lower + per-VM guest-keyed upper)
# assembled by /scripts/hippius-golden (boot=hippius-golden). The upper
# is LUKS-opened by the boot script with the KBS KEK, not via crypttab.
EOF
    sudo tee "${MNT_ROOT}/etc/fstab" >/dev/null <<'EOF'
# hippius-bake-managed (golden_verity_overlay): root is the overlayfs the
# initramfs boot script already mounted — no root entry here (systemd
# treats an already-mounted / as satisfied). Tenant-mutable trees live
# on the overlay upper (PR4 write-redirection audits full coverage).
EOF
elif [[ "${DISTRO_FAMILY}" == "debian" ]]; then
    sudo tee "${MNT_ROOT}/etc/crypttab" >/dev/null <<'EOF'
# hippius-bake-managed; cryptroot maps /dev/vda → /dev/mapper/cryptroot
# keyscript= = cryptsetup-initramfs extension; the keyscript emits the
# KBS-released KEK on fd3 after the §296 header verification.
cryptroot /dev/vda none luks,discard,header=/run/hippius/luks.header,keyscript=/sbin/hippius-luks-keyscript
EOF
else
    sudo tee "${MNT_ROOT}/etc/crypttab" >/dev/null <<'EOF'
# hippius-bake-managed; cryptroot maps /dev/vda → /dev/mapper/cryptroot
# RHEL/dracut variant: NO keyscript= (dracut doesn't support it). The
# third field names the tmpfs keyfile hippius-release.service stages
# (Wants/Before=cryptsetup-pre.target) after the §296 header gate;
# x-initrd.attach marks the volume as initrd-attached for clean
# shutdown ordering.
# NO `discard`: the rootfs is LUKS2 + dm-integrity (authenticated
# encryption) which cannot support TRIM, and systemd-cryptsetup treats
# a `discard` request on an integrity volume as FATAL ("Failed to
# activate ...: Invalid argument"), dropping the guest into the dracut
# emergency shell. The Debian arm keeps `discard` only because
# cryptsetup-initramfs WARNS and proceeds; systemd-cryptsetup does not.
cryptroot /dev/vda /run/hippius/kek luks,header=/run/hippius/luks.header,x-initrd.attach
EOF
fi

# /etc/fstab — root is now /dev/mapper/cryptroot. (Golden mode already
# wrote its overlay-friendly fstab above — skip the legacy cryptroot
# root entry so it is not overwritten.)
if [[ "${disk_mode}" != "golden_verity_overlay" ]]; then
    sudo tee "${MNT_ROOT}/etc/fstab" >/dev/null <<'EOF'
/dev/mapper/cryptroot / ext4 errors=remount-ro 0 1
EOF
fi

# ── #365 tenant data disk first-boot provisioner ────────────────────
#
# A LUKS2 + --integrity volume cannot be grown (`cryptsetup resize`
# refuses an integrity-protected device), so bigger flavors get their
# space from a SEPARATE blank disk the miner attaches at /dev/vde. This
# guest-side unit formats it fresh at first boot: a plain
# `luksFormat --integrity` with a key the guest generates inside the SNP
# boundary and seals on the (already encrypted) rootfs at
# /etc/hippius/data.key — the miner never sees it, and every
# dm-integrity HMAC tag is written by the guest, so a miner tampering
# any byte makes the guest read fault (EIO). The size is anchored by the
# measured `hippius.disk_gb=` cmdline token (folded into the SNP launch
# digest): a short or missing disk fails closed/visible.
#
# Subsequent boots just `cryptsetup open` with the persisted key. The
# first-boot integrity wipe (~1 GiB/s) runs WITHOUT blocking sshd/login;
# /data simply appears once it completes.
#
# LEGACY ONLY (#1350). A golden VM never gets a data disk (its disk size
# goes into the guest-keyed overlay upper), yet its measured cmdline
# carries `hippius.disk_gb=`: the unit would fail on every golden boot and
# format + mount at /data any /dev/vde a miner attaches on its own, with no
# anti-rollback. Golden tenants use /var/lib/hippius-data instead.
# `golden_sanitize_base` fails a golden bake that still carries it.
if [[ "${disk_mode}" != "golden_verity_overlay" ]]; then
sudo install -d -m 0755 "${MNT_ROOT}/usr/local/sbin"
sudo tee "${MNT_ROOT}/usr/local/sbin/hippius-data-disk-init" >/dev/null <<'DDINIT_EOF'
#!/bin/bash
# #365 — provision the tenant data disk (/dev/vde) at first boot.
# Fail-closed: any structural failure exits non-zero (surfaced in
# `systemctl status hippius-data-disk`) and leaves /data unmounted.
set -u
DEV=/dev/vde
# Distinct from the rootfs mapper names (`cryptroot` in the BYO
# crypttab path; `hippius-data`/`hippius-rootfs` in the agent-initramfs
# path) so the data disk can never collide with the root volume's
# device-mapper node.
NAME=hippius-datadisk
MAP="/dev/mapper/${NAME}"
KEYDIR=/etc/hippius
KEY="${KEYDIR}/data.key"
MNT=/data
# `shred` the staged key on error paths for §20 secret discipline (the
# rootfs is encrypted, so this is defense-in-depth + house consistency
# with hippius-luks-keyscript); fall back to rm where shred is absent.
wipe_tmp() { shred -u "${KEY}.tmp" 2>/dev/null || rm -f "${KEY}.tmp"; }
log() { echo "hippius-data-disk: $*"; }

# dm-integrity/dm-crypt are already live (the rootfs is integrity-
# protected), but make the dependency explicit + harmless if built-in.
modprobe dm_integrity 2>/dev/null || true
modprobe dm_crypt 2>/dev/null || true

# Read the attested data-disk size from the MEASURED kernel cmdline.
DISK_GB=""
for tok in $(cat /proc/cmdline); do
    case "$tok" in
        hippius.disk_gb=*) DISK_GB="${tok#hippius.disk_gb=}" ;;
    esac
done
if [ -z "$DISK_GB" ] || [ "$DISK_GB" = "0" ]; then
    log "no hippius.disk_gb= token — no data disk for this flavor"
    exit 0
fi
case "$DISK_GB" in
    *[!0-9]*) log "FATAL: non-numeric hippius.disk_gb=$DISK_GB"; exit 1 ;;
esac

# The disk must be present and AT LEAST the attested size. A miner who
# shorts the disk (or omits it) fails closed here; a larger device is
# tolerated (we format the whole thing — the tenant only gains space).
if [ ! -b "$DEV" ]; then
    log "FATAL: $DEV absent but hippius.disk_gb=$DISK_GB attested"
    exit 1
fi
want_sectors=$(( DISK_GB * 2097152 ))   # 1 GiB = 2097152 × 512 B
have_sectors=$(blockdev --getsz "$DEV" 2>/dev/null || echo 0)
if [ "$have_sectors" -lt "$want_sectors" ]; then
    log "FATAL: $DEV has ${have_sectors} sectors < attested ${want_sectors} (disk_gb=$DISK_GB)"
    exit 1
fi

install -d -m 0700 "$KEYDIR"
install -d -m 0755 "$MNT"

# Already open (a re-run after RemainAfterExit was cleared)? Skip to mount.
if [ ! -e "$MAP" ]; then
    if [ ! -f "$KEY" ]; then
        # FIRST BOOT: generate a fresh guest-held key and format the
        # disk. The integrity wipe initialises every HMAC tag.
        log "first boot: formatting $DEV (disk_gb=$DISK_GB) — fresh LUKS2+integrity"
        umask 077
        # /dev/random (not /dev/urandom): on Linux ≥5.6 it blocks ONLY
        # until the CRNG is first seeded, then never again — so it is the
        # fail-safe primitive (a never-seeded pool blocks rather than
        # emitting a weak key). The CRNG is seeded in early boot via
        # RDRAND/RDSEED, long before this multi-user.target unit runs, so
        # the read returns immediately in practice.
        if ! head -c 32 /dev/random > "${KEY}.tmp"; then
            log "FATAL: key generation failed"; wipe_tmp; exit 1
        fi
        # Defense-in-depth: refuse to format with a short/empty key.
        if [ "$(stat -c %s "${KEY}.tmp" 2>/dev/null || echo 0)" -ne 32 ]; then
            log "FATAL: generated key is not 32 bytes"; wipe_tmp; exit 1
        fi
        chmod 600 "${KEY}.tmp"
        if ! cryptsetup luksFormat --type luks2 --integrity hmac-sha256 \
                --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
                -d "${KEY}.tmp" "$DEV"; then
            log "FATAL: luksFormat failed"; wipe_tmp; exit 1
        fi
        if ! cryptsetup open -d "${KEY}.tmp" "$DEV" "$NAME"; then
            log "FATAL: open-after-format failed"; wipe_tmp; exit 1
        fi
        if ! mkfs.ext4 -q -F -L hippius-data "$MAP"; then
            log "FATAL: mkfs.ext4 failed"; cryptsetup close "$NAME" 2>/dev/null; wipe_tmp; exit 1
        fi
        # Commit the key ONLY after a clean format+open+mkfs, so a crash
        # mid-format leaves no key claiming a half-built disk.
        mv "${KEY}.tmp" "$KEY"
    else
        # SUBSEQUENT BOOT: open with the persisted key.
        log "reopening $DEV with persisted key"
        if ! cryptsetup open -d "$KEY" "$DEV" "$NAME"; then
            log "FATAL: open failed (key/device mismatch or tamper)"; exit 1
        fi
    fi
fi

if ! mountpoint -q "$MNT"; then
    if ! mount "$MAP" "$MNT"; then
        log "FATAL: mount $MAP -> $MNT failed"; exit 1
    fi
fi
log "data disk ready at $MNT (disk_gb=$DISK_GB)"
exit 0
DDINIT_EOF
sudo chmod 0755 "${MNT_ROOT}/usr/local/sbin/hippius-data-disk-init"

# systemd unit. Type=oneshot + RemainAfterExit so it runs once per boot;
# After=cryptsetup.target local-fs.target (rootfs + /etc/hippius key are
# available) but deliberately NOT ordered Before sshd/cloud-init so the
# multi-minute first-boot integrity wipe of a big flavor never blocks
# login. WantedBy=multi-user.target enables it.
sudo tee "${MNT_ROOT}/etc/systemd/system/hippius-data-disk.service" >/dev/null <<'DDUNIT_EOF'
[Unit]
Description=Hippius tenant data disk (/dev/vde) first-boot format + mount (#365)
# Default dependencies kept (ordered after sysinit/basic) so the unit
# only runs once the system is sane. After= the encrypted rootfs is
# mounted (the /etc/hippius key dir lives there) and modules are loaded.
# Deliberately NOT ordered Before sshd/cloud-init, so the multi-minute
# first-boot integrity wipe of a big flavor never blocks login.
After=cryptsetup.target local-fs.target systemd-modules-load.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/hippius-data-disk-init

[Install]
WantedBy=multi-user.target
DDUNIT_EOF

# Enable via the wants symlink (no systemctl in the chroot needed —
# reproducible + offline).
sudo install -d -m 0755 "${MNT_ROOT}/etc/systemd/system/multi-user.target.wants"
sudo ln -sf ../hippius-data-disk.service \
    "${MNT_ROOT}/etc/systemd/system/multi-user.target.wants/hippius-data-disk.service"
fi

# ── 4b. Run the chroot apt install ──────────────────────────────────
#
# Cloud images ship with VERY tight root-partition free space (~700 MB
# on noble), so a tmpfs is mounted under /var/cache/apt/archives to
# absorb the apt download cache without overflowing the rootfs. The
# stock kernel (linux-image-virtual on Ubuntu cloud images) is reused
# — it already has virtio_net, dm-crypt, aes-xts and ext4 built-in /
# modular, which is everything the BYO-OS boot path needs. Installing
# linux-image-generic would pull 800+ MB of headers/firmware that does
# not fit and is not used.

if [[ "${DISTRO_FAMILY}" == "debian" ]]; then
log "chroot: apt install cryptsetup-initramfs + tools (stock kernel kept, SOURCE_DATE_EPOCH=${source_date_epoch})"
sudo mkdir -p "${MNT_ROOT}/var/cache/apt/archives"
sudo mount -t tmpfs -o size=2G tmpfs "${MNT_ROOT}/var/cache/apt/archives"
# The chroot script is staged as a FILE via a QUOTED heredoc and the
# outer values ride the env(1) line — NEVER an unquoted heredoc. An
# unquoted heredoc command-substitutes every backtick in the body,
# INCLUDING inside comments: that is exactly how the 2026-07-04 baker
# (66ef008b) silently lost the hippius initramfs hook — a `word` in a
# comment EXECUTED (hippius-guest-release ran bare mid-bake!) and the
# mangled script skipped the hook staging, so every guest hung at
# cryptroot with zero hippius files in the initrd. The same class bug
# is the best explanation for the #673 baker hang. Guarded by
# scripts/dev/bake-heredoc-guard.sh.
sudo tee "${MNT_ROOT}/tmp/hippius-chroot-install.sh" >/dev/null <<'CHROOT_EOF'
set -eu
export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
# #284 reproducibility env: pin every locale-/time-/sort-sensitive
# knob so two operators baking the same inputs see the same byte
# output. Each variable has a documented effect:
#   - SOURCE_DATE_EPOCH (env-passed by the caller): initramfs-tools
#     (>=0.131), dpkg, and most cpio/tar variants use this as the
#     mtime ceiling for emitted files. Without it the cpio header is
#     wall-clock-stamped → SHA diverges per second.
#   - LC_ALL=C / LANG=C: forces ASCII collation. `find` / `sort`
#     inside cpio assembly differ between en_US.UTF-8 and zh_CN.UTF-8
#     when filenames carry non-ASCII bytes.
#   - TZ=UTC: dpkg's per-package post-install hooks call `date`;
#     without UTC the log files included in the initramfs (if any)
#     diverge.
#   - LANGUAGE=C: secondary to LC_ALL but some Debian helpers honor
#     it preferentially.
#
# These are the minimal set #284 needs to MAKE reproducibility
# achievable. Proving reproducibility (acceptance items 1+2+3) is a
# separate CI gate — see scripts/verify-reproducible-bake.sh for the
# manual two-bake check operators can run today.
export LC_ALL=C
export LANG=C
export LANGUAGE=C
export TZ=UTC

apt-get update
# F6 package refresh (env-passed PKG_REFRESH, empty = off): bring every
# package the base image ships up to the archive's current version BEFORE
# the hippius install, so the golden does not leave the bake already
# carrying pending security updates (openssh, openssl, sudo, libc6…).
# dist-upgrade, not upgrade: a security fix that needs a NEW dependency is
# held back by plain upgrade. Kernel selection below picks the highest
# installed version, so an upgraded kernel is the one extracted. confold:
# keep the image's config files, never prompt.
if [ -n "${PKG_REFRESH:-}" ]; then
    echo "package refresh ${PKG_REFRESH}: apt-get dist-upgrade"
    apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade
fi
# /boot/ is stripped from Ubuntu cloud images — reinstall a kernel.
# The package is per-distro (resolve_distro_plan, env-passed as
# DISTRO_KERNEL_PKG): Ubuntu = linux-image-virtual (cloud
# metapackage); Debian = the FULL linux-image-amd64 — Debian's
# preinstalled -cloud- kernel omits sev-guest/tsm, so the bake
# installs the full image and every kernel-selection expression below
# filters -cloud- out. The verify_required_modules gate is the
# enforcement either way. linux-image-virtual is the cloud-friendly
# metapackage; its installed footprint (~140 MiB) is well under the
# +HCC_BAKE_SRC_GROW_GB headroom we added to the partition.
apt-get install -y --no-install-recommends \
    cryptsetup cryptsetup-initramfs initramfs-tools \
    ${DISTRO_KERNEL_PKG} \
    curl ca-certificates \
    udhcpc isc-dhcp-client iproute2
# Detect the installed kernel version and install the matching
# linux-modules-extra-<KVER>-generic package — Ubuntu noble does not
# ship a `linux-modules-extra-virtual` metapackage, so the version
# string must be derived at runtime. The `extra` package carries
# sev-guest, tsm, and the crypto/configfs chain that linux-image-
# virtual omits.
# Install modules-extra for the kernel /boot/vmlinuz now points at
# (linux-image-virtual just installed; its dependency pulled in the
# latest -generic kernel). The extras package is per-KVER; we use a
# single dpkg-query to derive the version installed by
# linux-image-virtual instead of iterating /lib/modules (which often
# has stale entries from cloud-image base layers).
#
# KVER_PKG is derived on EVERY apt distro, not just Ubuntu: the hold
# block below needs the concrete version the meta-package pulled in
# (Ubuntu: 6.8.0-NN-generic, Debian: 6.12.NN+deb13-amd64). It used to
# be Ubuntu-only, so on Debian no concrete kernel version was ever
# held. Only the linux-modules-extra INSTALL stays Ubuntu-only — Debian
# has no such package (sev-guest/tsm ship in the full linux-image).
KVER_PKG=$(dpkg-query -W -f='${Depends}' ${DISTRO_KERNEL_PKG} 2>/dev/null | tr ',' '\n' | awk '{print $1}' | grep -E '^linux-image-[0-9]' | sed 's/^linux-image-//' | sort -V | tail -1)
if [ "${DISTRO_ID}" = "ubuntu" ] && [ -n "${KVER_PKG:-}" ]; then
    apt-get install -y --no-install-recommends \
        "linux-modules-extra-${KVER_PKG}" || true
fi

# ── cdn-node profile packages (CDN plan I3) ─────────────────────────
# nftables for the guest input firewall and the inbound guard; openssl
# for the throwaway TLS placeholder OpenResty needs at each start.
# Env-gated: every standard bake installs nothing more.
if [ "${HIPPIUS_PROFILE:-standard}" = "cdn-node" ]; then
    apt-get install -y --no-install-recommends nftables openssl
fi

# ── NetBird pre-install (held-curl first-boot fix) ──────────────────
# Install the NetBird overlay agent HERE, in the measured chroot (which
# has internet), at the PINNED NETBIRD_VERSION — NOT at first boot. The
# upstream first-boot installer (`pkgs.netbird.io/install.sh`) does an
# `apt-get install -y ca-certificates curl gnupg` that would UPGRADE the
# held curl/ca-certificates below and abort with `E: Held packages were
# changed and -y was used without --allow-change-held-packages`, so the
# netbird package never landed and the guest never joined the overlay
# (prodcheck-1/-2: setup-key used=0). curl/ca-certificates are already
# installed (above) but NOT yet held, so apt resolves netbird's deps
# cleanly. First-boot userdata is reduced to just `netbird up`.
#
# apt supports an ASCII-armored keyring in `signed-by=` (>=apt 1.4, i.e.
# every supported Ubuntu/Debian), so no gnupg dependency is pulled in.
install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://pkgs.netbird.io/debian/public.key -o /etc/apt/keyrings/netbird.asc
chmod 0644 /etc/apt/keyrings/netbird.asc
echo 'deb [signed-by=/etc/apt/keyrings/netbird.asc] https://pkgs.netbird.io/debian stable main' \
    > /etc/apt/sources.list.d/netbird.list
apt-get update
apt-get install -y --no-install-recommends "netbird=${NETBIRD_VERSION}"
# The netbird deb's postinst installs AND STARTS the daemon (netbird's own
# service manager, not systemd). A running netbird process is rooted in the
# bake mountpoint and makes the teardown `umount -R` fail "target is busy",
# so the bake never finishes. Stop the transient bake-time daemon; the
# systemd unit stays installed + enabled, so it starts cleanly at guest
# first boot and idles until the first-boot `netbird up --setup-key`.
netbird service stop >/dev/null 2>&1 || true
pkill -x netbird 2>/dev/null || true
command -v netbird >/dev/null 2>&1 || { echo "FATAL: netbird binary absent after install (pin ${NETBIRD_VERSION})" >&2; exit 3; }
# The bake-time daemon wrote a per-machine WireGuard identity to
# /var/lib/netbird. If that state is baked, EVERY VM from this image
# shares ONE NetBird peer — the management server dedupes them all onto a
# single overlay IP ("peer registered again"). Wipe the identity/state so
# each guest's first-boot `netbird up --setup-key` mints a FRESH keypair.
# The management-url + setup-key ride the first-boot `netbird up`
# (userdata runcmd), so nothing here needs pre-baking.
rm -rf /var/lib/netbird/* /etc/netbird/*.json 2>/dev/null || true

# Bundle the vsock kernel modules into the initramfs so the
# hippius-vsock-ticket binary's VsockListener::bind() succeeds at
# boot. Without these the receiver fails-closed with `vsock-bind` and
# the miner-agent's ticket push connect-times out, even though both
# binaries are otherwise wired up correctly.
#
# Also bundle the SEV-SNP attestation module chain — sev-guest +
# tsm + configfs and the crypto modules its gcm(aes) AEAD probe
# allocates. Without these /dev/sev-guest is never created and
# `hippius-guest-release` fail-closes with `snp-device-failed`
# before it can run the §21 release exchange. Same pattern the
# legacy agent-initramfs uses (test_vectors/allowlist/dev-manifest
# epoch 10 note).
cat >> /etc/initramfs-tools/modules <<'MOD'
vsock
vmw_vsock_virtio_transport_common
vmw_vsock_virtio_transport
crypto_null
gf128mul
ghash-generic
gcm
configfs
tsm
sev-guest
virtio_net
virtio_pci
MOD
# `virtio_net`/`virtio_pci` are pinned here so the tenant NIC is present
# in the initrd INDEPENDENTLY of `IP=dhcp` — initramfs-tools' MODULES=dep
# only auto-includes a driver that backs a mounted device, and the root
# is on virtio-blk, not the NIC. (`IP=dhcp` also drags virtio_net in,
# and stays: removing it for vsock hung boot twice — #670/#673.)

# Purge `cloud-initramfs-dyn-netconf` (#289 multi-IP): its init-bottom
# script snapshots the initramfs network state (the release-core's
# static 192.168.122.253 + the klibc DHCP lease) and re-applies it in
# USERSPACE, undoing the hippius-net-teardown flush — the guest then
# stacks 2-3 addresses on the NIC. The tenant image never needs the
# takeover: its network is plain DHCP that the image's own DHCP profile
# brings up fresh. Purge BEFORE the final update-initramfs so the regenerated
# initrd drops the script too. `|| true`: absent on Debian genericcloud
# (Ubuntu-only package).
apt-get purge -y cloud-initramfs-dyn-netconf 2>/dev/null || true

# Untrusted miner (M0 hardening): the miner can attach any virtio
# channel. A guest agent listening on one is a host→guest root command
# channel (qemu-ga guest-exec / guest-file-*, vmtoolsd, spice-vdagent),
# so none of them ship in the tenant image. `|| true`: most are absent
# from the cloud images; a purge of an absent package is not an error.
apt-get purge -y open-vm-tools open-vm-tools-desktop qemu-guest-agent spice-vdagent 2>/dev/null || true

# Tell cryptsetup-initramfs to pick up the keyscript path. The
# KEYFILE_PATTERN line is unneeded because we use keyscript= in
# crypttab; we keep CRYPTSETUP=y so the initramfs even bothers
# including dm-crypt at all.
mkdir -p /etc/cryptsetup-initramfs
{
    echo 'CRYPTSETUP=y'
    echo 'KEYFILE_PATTERN='
} > /etc/cryptsetup-initramfs/conf-hook

# Regenerate the initramfs so the Hippius hook stages everything.
# SOURCE_DATE_EPOCH (env-passed) is read by mkinitramfs via
# /usr/share/initramfs-tools/scripts/init-bottom which calls
# `cpio --reproducible` when SDE is set — that's what makes the cpio
# byte-stable.
#
# Build the initramfs ONLY for the kernel the host-side extraction
# step will pick (highest-versioned /boot/vmlinuz-*, `.signed`
# excluded — the selection expression below MUST stay byte-identical
# to the `kernel_src=` line in stage 5). `-k all` used to rebuild an
# initrd for every installed kernel; only one ever ships with the
# bake, so the extra builds were pure latency (~1-2 min each).
KVER=$(ls /boot/vmlinuz-* 2>/dev/null | grep -v '\.signed$' | grep -v -- '-cloud-' | sed 's|.*/vmlinuz-||' | sort -V | tail -1)
[ -n "${KVER}" ] || { echo "no /boot/vmlinuz-* after kernel install" >&2; exit 1; }

# Module-availability gate (#multi-distro): every kernel module the
# §21 boot path modprobes MUST be present for the kernel that just got
# installed — built-in OR an installed .ko. A guest whose kernel lacks
# sev-guest/tsm can't attest, or one lacking vsock can't pull the
# ticket; without this gate that surfaces only as a dead guest on the
# serial console long after the bake "succeeded". Builtin check first
# (modules.builtin), then modinfo for loadable ones.
# tsm + configfs are SOFT requirements: they are sev-guest dependency
# helpers on kernels >= 6.7 (modprobe resolves them via modules.dep);
# on older kernels (Debian 12 = 6.1) they don't exist and
# /dev/sev-guest works without them. The runtime modprobe chain treats
# every module as best-effort, so soft-missing only costs a warning.
soft_mods="configfs tsm"
missing_soft=""
for m in ${soft_mods}; do
    bm="${m//-/_}"
    if grep -qE "/(${bm}|${m})\.ko" "/lib/modules/${KVER}/modules.builtin" 2>/dev/null; then continue; fi
    if modinfo -k "${KVER}" "${m}" >/dev/null 2>&1; then continue; fi
    missing_soft="${missing_soft} ${m}"
done
[ -n "${missing_soft}" ] && echo "WARN: kernel ${KVER} lacks optional module(s):${missing_soft} (ok on <6.7 kernels)" >&2

missing_mods=""
for m in sev-guest vsock vmw_vsock_virtio_transport vmw_vsock_virtio_transport_common crypto_null gf128mul gcm dm_integrity dm_crypt ext4 xts; do
    bm="${m//-/_}"
    if grep -qE "/(${bm}|${m})\.ko" "/lib/modules/${KVER}/modules.builtin" 2>/dev/null; then
        continue
    fi
    if modinfo -k "${KVER}" "${m}" >/dev/null 2>&1; then
        continue
    fi
    missing_mods="${missing_mods} ${m}"
done
# GHASH provider gate (any-of). dm-integrity/LUKS AEAD rides the
# gcm(aes) crypto stack whose hash is GHASH, so a GHASH provider MUST
# exist — but its module name is not stable across distros/arches. The
# classic discrete module is `ghash-generic` (with the x86 PCLMULQDQ
# accelerated `ghash-clmulni-intel` as the fast variant on Intel/AMD);
# Fedora 43+ (kernel >= 7.1) folded the generic GHASH+POLYVAL into the
# built-in `libgf128hash` library and no longer ships a discrete
# `ghash-generic`. Accept ANY known provider (builtin OR loadable) via
# the same builtin+modinfo mechanism; still FATAL if none is present.
ghash_ok=""
for gm in ghash-generic ghash-clmulni-intel ghash libgf128hash; do
    gb="${gm//-/_}"
    if grep -qE "/(${gb}|${gm})\.ko" "/lib/modules/${KVER}/modules.builtin" 2>/dev/null; then ghash_ok=1; break; fi
    if modinfo -k "${KVER}" "${gm}" >/dev/null 2>&1; then ghash_ok=1; break; fi
done
[ -n "${ghash_ok}" ] || missing_mods="${missing_mods} ghash(none of: ghash-generic/ghash-clmulni-intel/libgf128hash)"
if [ -n "${missing_mods}" ]; then
    echo "FATAL: kernel ${KVER} is missing required module(s):${missing_mods}" >&2
    echo "hint(debian): install the FULL linux-image-amd64 (the cloud kernel omits sev-guest/tsm)" >&2
    echo "hint(ubuntu): ensure linux-modules-extra-${KVER} is installed" >&2
    echo "hint(rhel):   dnf install kernel-modules kernel-modules-extra" >&2
    exit 3
fi

update-initramfs -u -k "${KVER}"

# Fail-closed hook audit: the whole point of the regenerate above is
# that the hippius hook staged the release core + keyscript into the
# initrd. If they are absent the guest can NEVER unlock (it hangs at
# cryptroot) — catch that at BAKE time, not on a dead serial console.
if ! lsinitramfs "/boot/initrd.img-${KVER}" | grep -q 'hippius-release-core.sh'; then
    echo "FATAL: initrd for ${KVER} carries NO hippius release core (hook did not run)" >&2
    exit 3
fi

# #284 reproducibility: pin every installed package version so a
# tenant `apt upgrade` inside the running VM (or an inadvertent
# re-bake) cannot perturb the kernel + cryptsetup + initramfs that
# are part of the SEV-SNP launch measurement. `apt-mark hold` writes
# to /var/lib/dpkg/status which is part of the rootfs we then encrypt
# + measure; the held set is therefore visible to a tenant's
# `apt-mark showhold`.
#
# This does NOT pin transitive versions across bakes — that needs a
# lockfile + a snapshot apt repo (see #284 deferred items 1 & 2).
# What it DOES is freeze the installed set against in-VM apt churn,
# which is the smaller but more common drift source.
apt-mark hold \
    cryptsetup cryptsetup-initramfs initramfs-tools \
    curl ca-certificates \
    udhcpc isc-dhcp-client iproute2 \
    netbird \
    || true

# Kernel hold. WHY: the guest boots a platform-supplied, measured UKI
# (kernel + initrd + cmdline in one PE, part of the launch digest); it
# never boots from /boot and grub has no role. A tenant apt upgrade
# that installs a new kernel runs postinst hooks that can only fail in
# a CVM — update-grub / grub-probe / initramfs-tools cannot resolve the
# live dm-crypt root (opened by the attested initramfs with a key
# released after attestation) — which leaves dpkg half-configured and
# breaks every later apt run. Kernel updates reach a tenant as a new
# attested image, never through apt.
#
# TWO kernels are installed on Debian, and BOTH must be held:
# genericcloud PRE-INSTALLS linux-image-cloud-amd64 (+ its concrete
# linux-image-6.12.NN+deb13-cloud-amd64); the bake installs the FULL
# linux-image-amd64 on top (resolve_distro_plan — the cloud kernel may
# omit sev-guest/tsm). Holding only ${DISTRO_KERNEL_PKG} left the
# -cloud- meta-package and its concrete version unheld, so a tenant
# `apt upgrade` pulled the next linux-image-*-cloud-amd64 and its hooks
# wedged dpkg. And holding a META-package alone does not stop apt from
# installing a newer concrete linux-image-<ver> it depends on: every
# installed concrete linux-image / -headers / -modules(-extra) package
# is therefore held by name as well (dpkg Status-filtered, so a removed
# / config-files kernel is not held).
#
# The pre-installed -cloud- kernel is HELD, not purged, in this change.
# Purging a kernel from the image is a larger blast radius (its /boot
# entries and initrd are present; the stage-5 selection and the KVER
# line above already filter -cloud- out, so keeping it is harmless).
# Whether to purge it is a separate follow-up decision.
KERNEL_META_INSTALLED=""
for meta in ${DISTRO_KERNEL_PKG} linux-image-amd64 linux-image-cloud-amd64 linux-image-virtual; do
    case " ${KERNEL_META_INSTALLED} " in *" ${meta} "*) continue ;; esac
    if dpkg-query -W -f='${Status}\n' "${meta}" 2>/dev/null | grep -q '^install ok installed'; then
        KERNEL_META_INSTALLED="${KERNEL_META_INSTALLED}${KERNEL_META_INSTALLED:+ }${meta}"
    fi
done
KERNEL_PKGS=$(dpkg-query -W -f='${Package} ${Status}\n' 'linux-image-*' 'linux-headers-*' 'linux-modules-*' 2>/dev/null \
    | awk '$4 == "installed" {print $1}' \
    | grep -E '^linux-(image|headers|modules)(-extra)?-[0-9]' || true)
for pkg in ${KERNEL_META_INSTALLED} ${KERNEL_PKGS}; do
    apt-mark hold "${pkg}" || echo "WARNING: apt-mark hold ${pkg} failed" >&2
done
if [ "${DISTRO_ID}" = "ubuntu" ] && [ -n "${KVER_PKG:-}" ]; then
    apt-mark hold "linux-modules-extra-${KVER_PKG}" || echo "WARNING: apt-mark hold linux-modules-extra-${KVER_PKG} failed" >&2
fi
# Explicit check instead of a swallowed error: at least one
# linux-image-* package must be on hold, or a tenant apt upgrade will
# replace the measured kernel.
if ! apt-mark showhold 2>/dev/null | grep -qE '^linux-image-'; then
    echo "WARNING: no linux-image-* package is on hold (distro ID='${DISTRO_ID}', kernel meta-package: ${DISTRO_KERNEL_PKG}, installed meta-packages: ${KERNEL_META_INSTALLED:-none}, installed concrete kernel packages: ${KERNEL_PKGS:-none})" >&2
fi
# One line in the bake log naming what got held (word-split on purpose:
# KERNEL_PKGS is newline-separated).
echo "kernel hold: meta=${KERNEL_META_INSTALLED:-none} kver=${KVER_PKG:-none} concrete:" ${KERNEL_PKGS:-none}

# The grub kernel hooks are inert in a CVM (the guest never boots via
# grub) and are the ones that return non-zero and wedge dpkg. run-parts
# skips non-executable hooks, so drop the x bit instead of deleting the
# conffiles. initramfs-tools hooks are left alone: the minimal change
# is to disable the hook that fails, not every hook.
for hook in /etc/kernel/postinst.d/zz-update-grub /etc/kernel/postrm.d/zz-update-grub; do
    if [ -e "${hook}" ]; then chmod -x "${hook}"; fi
done

# A note the tenant can find next to the holds. apt ignores a file
# that contains only comments.
cat > /etc/apt/apt.conf.d/99-hippius-kernel-hold <<'NOTE'
// The kernel packages on this system are held on purpose (apt-mark showhold).
// This guest boots a platform-attested unified kernel image; the kernel in
// /boot is not what runs, and kernel package upgrades cannot complete here.
// Kernel updates arrive as a new attested image, not through apt.
NOTE

apt-get clean
CHROOT_EOF
sudo chroot "${MNT_ROOT}" /usr/bin/env \
    SOURCE_DATE_EPOCH="${source_date_epoch}" \
    DISTRO_ID="${DISTRO_ID}" \
    DISTRO_KERNEL_PKG="${DISTRO_KERNEL_PKG}" \
    NETBIRD_VERSION="${netbird_version}" \
    PKG_REFRESH="${package_refresh}" \
    HIPPIUS_PROFILE="${profile}" \
    /bin/bash /tmp/hippius-chroot-install.sh
sudo rm -f "${MNT_ROOT}/tmp/hippius-chroot-install.sh"

sudo umount "${MNT_ROOT}/var/cache/apt/archives" || true

else
# ── 4b-rhel. dnf install + dracut initramfs (CentOS Stream / Fedora) ─
#
# The RHEL-family counterpart of the apt chroot. dracut (NOT
# initramfs-tools) builds the initrd, and the unlock rides the
# 90hippius-luks keyfile module already staged at
# /usr/lib/dracut/modules.d/ + the /etc/dracut.conf.d/90-hippius.conf
# drop-in. The cloud image already carries a kernel-core; we install
# the matching module packages (sev-guest lives in kernel-modules /
# kernel-modules-core) + dracut + cryptsetup, then build one initrd
# for the highest installed kernel — the SAME version stage 5 extracts.
log "chroot: dnf install dracut + cryptsetup + kernel-modules (SOURCE_DATE_EPOCH=${source_date_epoch})"
sudo mkdir -p "${MNT_ROOT}/var/cache/libdnf5" "${MNT_ROOT}/var/cache/dnf"
sudo mount -t tmpfs -o size=2G tmpfs "${MNT_ROOT}/var/cache/libdnf5"
# Same QUOTED-heredoc + env(1) discipline as the apt arm (see the
# comment there — an unquoted heredoc command-substitutes backticks in
# comments; guarded by scripts/dev/bake-heredoc-guard.sh).
sudo tee "${MNT_ROOT}/tmp/hippius-chroot-install.sh" >/dev/null <<'CHROOT_RHEL_EOF'
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
# #284 reproducibility env (same rationale as the apt arm): dracut
# honors SOURCE_DATE_EPOCH (env-passed by the caller) for the cpio
# mtime ceiling under --reproducible; LC_ALL/LANG/TZ pin collation +
# timestamps.
export LC_ALL=C
export LANG=C
export LANGUAGE=C
export TZ=UTC

DNF="dnf -y --setopt=install_weak_deps=False --setopt=tsflags=nodocs"
# F6 package refresh (env-passed PKG_REFRESH, empty = off) — the dnf
# counterpart of the apt arm's dist-upgrade: every package the base image
# ships goes to the repos' current version before the hippius install.
if [ -n "${PKG_REFRESH:-}" ]; then
    echo "package refresh ${PKG_REFRESH}: dnf upgrade"
    ${DNF} upgrade \
        || { echo "FATAL: dnf upgrade failed (package refresh ${PKG_REFRESH})" >&2; exit 3; }
fi
# Two transactions so a missing optional package name can't abort the
# whole install: the unlock toolchain first (must succeed), then the
# kernel module set (kernel-modules-core exists on Fedora, not CS10).
${DNF} install \
    dracut dracut-network cryptsetup \
    curl ca-certificates iproute \
    policycoreutils \
    || { echo "FATAL: dnf could not install the dracut/cryptsetup toolchain" >&2; exit 3; }

# GOLDEN mode needs veritysetup (opens the RO dm-verity golden lower) +
# e2fsprogs (mkfs.ext4 for the first-boot per-VM upper). On RHEL/Fedora
# `veritysetup` is a SEPARATE package split out of `cryptsetup` (unlike
# Debian, where it rides the cryptsetup-bin package) — without it the
# 95hippius-golden module's `inst_multiple veritysetup` fails and the
# guest cannot open the golden base. squashfs-tools' mount is kernel-side
# (squashfs.ko, force-instmod'd) so no extra userspace is needed there.
if [ "${BAKE_DISK_MODE:-legacy_luks}" = "golden_verity_overlay" ]; then
    # `attr` (setfattr/getfattr) — the 95hippius-golden module stamps the RO
    # lower's "/" SELinux label onto the per-VM overlay upper-root dir so the
    # enforcing guest does not see "/" as `unlabeled_t` (which denies every
    # confined domain `search /`). Without it `inst_multiple setfattr getfattr`
    # fails and the golden initrd cannot label the overlay root.
    ${DNF} install veritysetup e2fsprogs attr \
        || { echo "FATAL: golden mode could not install veritysetup/e2fsprogs/attr" >&2; exit 3; }
    command -v veritysetup >/dev/null 2>&1 \
        || { echo "FATAL: veritysetup absent after install (golden dm-verity lower open)" >&2; exit 3; }
    command -v mkfs.ext4 >/dev/null 2>&1 \
        || { echo "FATAL: mkfs.ext4 absent after install (golden first-boot upper format)" >&2; exit 3; }
    command -v setfattr >/dev/null 2>&1 \
        || { echo "FATAL: setfattr absent after install (golden overlay-root SELinux label)" >&2; exit 3; }
fi
${DNF} install ${DISTRO_KERNEL_PKG} kernel-modules kernel-modules-extra \
    || ${DNF} install kernel-modules-extra \
    || echo "WARN: kernel-modules-extra install non-clean; the module gate will verify" >&2
${DNF} install kernel-modules-core 2>/dev/null || true

# ── NetBird pre-install (held-package first-boot fix, dnf parity) ────
# Same rationale as the apt arm: pre-install the NetBird agent in the
# measured chroot at the PINNED NETBIRD_VERSION instead of running the
# upstream first-boot installer (which apt/dnf-upgrades held packages
# and aborts). First-boot userdata is reduced to just `netbird up`.
cat > /etc/yum.repos.d/netbird.repo <<'REPO'
[netbird]
name=netbird
baseurl=https://pkgs.netbird.io/yum/
enabled=1
gpgcheck=0
repo_gpgcheck=0
REPO
${DNF} install "netbird-${NETBIRD_VERSION}" \
    || { echo "FATAL: dnf could not install netbird-${NETBIRD_VERSION}" >&2; exit 3; }
command -v netbird >/dev/null 2>&1 || { echo "FATAL: netbird binary absent after install (pin ${NETBIRD_VERSION})" >&2; exit 3; }
# ── Canned systemd unit + offline enable (dnf-arm only) ─────────────
# The netbird RPM ships ONLY /usr/bin/netbird; its %post runs
# `netbird service install` (kardianos/service), which picks the init
# system from pid1. In the containerized k8s/docker baker pid1 != systemd,
# so kardianos falls back to SysVinit and tries /etc/init.d/netbird —
# which CS10/Fedora do NOT ship ("install service: open /etc/init.d/netbird:
# no such file") → NO unit is installed → netbird never starts, and a
# first-boot userdata `netbird up` has no daemon to talk to. (The apt/
# Debian arm is unaffected: those bases ship /etc/init.d, so this is a
# DNF-arm-only gap — do NOT mirror this into the apt arm.)
# Fix: write the SAME unit `netbird service install` emits on a real
# systemd host (ExecStart=/usr/bin/netbird service run — the kardianos
# foreground-run entrypoint the service manager invokes), and enable it
# OFFLINE via the multi-user.target.wants symlink. The symlink is
# pid1-independent; `systemctl enable` in the chroot would hit the same
# non-systemd pid1 and fail identically.
cat > /usr/lib/systemd/system/netbird.service <<'NETBIRD_UNIT'
[Unit]
Description=NetBird mesh network client
ConditionFileIsExecutable=/usr/bin/netbird
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/netbird service run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
NETBIRD_UNIT
install -d -m 0755 /etc/systemd/system/multi-user.target.wants
ln -sf /usr/lib/systemd/system/netbird.service \
    /etc/systemd/system/multi-user.target.wants/netbird.service
# The netbird rpm's %post also STARTS a transient daemon — a running
# netbird holds the bake mountpoint and makes the teardown `umount -R`
# fail "target is busy". Stop it now; the canned unit above is what the
# guest boots with.
netbird service stop >/dev/null 2>&1 || true
pkill -x netbird 2>/dev/null || true
# Wipe the bake-time NetBird per-machine identity/state so each guest mints
# a FRESH keypair on first `netbird up` — else every VM from this image
# collides onto ONE NetBird peer/overlay-IP. (See the apt arm for detail.)
rm -rf /var/lib/netbird/* /etc/netbird/*.json 2>/dev/null || true

# KVER = highest installed module tree (RHEL has no -cloud- variants).
KVER=$(ls /lib/modules 2>/dev/null | sort -V | tail -1)
[ -n "${KVER}" ] || { echo "no /lib/modules/<kver> after kernel-modules install" >&2; exit 1; }

# Module-availability gate (#multi-distro) — identical contract to the
# apt arm: every module the §21 boot path needs must be builtin or an
# installed .ko for THIS kernel. configfs/tsm are soft (sev-guest
# helpers on >=6.7; CS10/Fedora kernels are well past that, so this is
# belt-and-suspenders).
soft_mods="configfs tsm"
missing_soft=""
for m in ${soft_mods}; do
    bm="${m//-/_}"
    if grep -qE "/(${bm}|${m})\.ko" "/lib/modules/${KVER}/modules.builtin" 2>/dev/null; then continue; fi
    if modinfo -k "${KVER}" "${m}" >/dev/null 2>&1; then continue; fi
    missing_soft="${missing_soft} ${m}"
done
[ -n "${missing_soft}" ] && echo "WARN: kernel ${KVER} lacks optional module(s):${missing_soft}" >&2

missing_mods=""
for m in sev-guest vsock vmw_vsock_virtio_transport vmw_vsock_virtio_transport_common crypto_null gf128mul gcm dm_integrity dm_crypt ext4 xts; do
    bm="${m//-/_}"
    if grep -qE "/(${bm}|${m})\.ko" "/lib/modules/${KVER}/modules.builtin" 2>/dev/null; then
        continue
    fi
    if modinfo -k "${KVER}" "${m}" >/dev/null 2>&1; then
        continue
    fi
    missing_mods="${missing_mods} ${m}"
done
# GHASH provider gate (any-of). dm-integrity/LUKS AEAD rides the
# gcm(aes) crypto stack whose hash is GHASH, so a GHASH provider MUST
# exist — but its module name is not stable across distros/arches. The
# classic discrete module is `ghash-generic` (with the x86 PCLMULQDQ
# accelerated `ghash-clmulni-intel` as the fast variant on Intel/AMD);
# Fedora 43+ (kernel >= 7.1) folded the generic GHASH+POLYVAL into the
# built-in `libgf128hash` library and no longer ships a discrete
# `ghash-generic`. Accept ANY known provider (builtin OR loadable) via
# the same builtin+modinfo mechanism; still FATAL if none is present.
ghash_ok=""
for gm in ghash-generic ghash-clmulni-intel ghash libgf128hash; do
    gb="${gm//-/_}"
    if grep -qE "/(${gb}|${gm})\.ko" "/lib/modules/${KVER}/modules.builtin" 2>/dev/null; then ghash_ok=1; break; fi
    if modinfo -k "${KVER}" "${gm}" >/dev/null 2>&1; then ghash_ok=1; break; fi
done
[ -n "${ghash_ok}" ] || missing_mods="${missing_mods} ghash(none of: ghash-generic/ghash-clmulni-intel/libgf128hash)"
if [ -n "${missing_mods}" ]; then
    echo "FATAL: kernel ${KVER} is missing required module(s):${missing_mods}" >&2
    echo "hint(rhel): dnf install kernel-modules kernel-modules-core kernel-modules-extra" >&2
    exit 3
fi

# Build ONE initrd for that kernel. The conf.d drop-in pulls in the
# hippius module (90hippius-luks legacy, or 95hippius-golden in golden
# mode — each force-insts the SNP/vsock chain via hostonly=''); the
# golden module additionally carries the dm-verity/overlay/squashfs stack
# for the overlay-root assembly. --no-hostonly keeps the rest generic so
# it boots on any miner, and --reproducible + SOURCE_DATE_EPOCH make
# the cpio byte-stable (#284 parity with the apt arm's update-initramfs).
# Compression: dracut takes zstd when the kernel can unpack it, else the
# first of pigz / gzip it finds. pigz's multi-threaded output is not byte-
# stable: two CS10 bakes of the same tree gave the same cpio content but
# different initrd bytes. So unless the kernel can unpack zstd AND the zstd
# binary is there (dracut falls back to pigz otherwise), plain gzip.
dracut_compress=(--compress "gzip -n -9")
if grep -qs '^CONFIG_RD_ZSTD=y' "/lib/modules/${KVER}/config" "/boot/config-${KVER}" \
    && command -v zstd >/dev/null 2>&1; then
    dracut_compress=()
fi
dracut --force --reproducible --no-hostonly --no-hostonly-cmdline \
    "${dracut_compress[@]}" \
    "/boot/initramfs-${KVER}.img" "${KVER}" \
    || { echo "FATAL: dracut initramfs build failed for ${KVER}" >&2; exit 3; }

# Fail-closed module audit (apt-arm parity): the hippius dracut module
# (90hippius-luks legacy, or 95hippius-golden in golden mode) MUST have
# staged the release core, or the guest hangs at unlock/assembly with no
# diagnostics. Catch it at bake time.
if command -v lsinitrd >/dev/null 2>&1; then
    if ! lsinitrd "/boot/initramfs-${KVER}.img" 2>/dev/null | grep -q 'hippius-release-core.sh'; then
        echo "FATAL: initrd for ${KVER} carries NO hippius release core (the hippius dracut module did not run)" >&2
        exit 3
    fi
    # Golden mode: additionally assert the overlay assembly library +
    # the mount runner made it in (the release core alone is not enough
    # to assemble the overlay root).
    if [ "${BAKE_DISK_MODE:-legacy_luks}" = "golden_verity_overlay" ]; then
        if ! lsinitrd "/boot/initramfs-${KVER}.img" 2>/dev/null | grep -q 'hippius-golden-overlay.sh'; then
            echo "FATAL: golden initrd for ${KVER} carries NO golden overlay lib (95hippius-golden did not run)" >&2
            exit 3
        fi
    fi
fi

# Pin the measurement-relevant packages against in-VM dnf churn
# (apt-mark hold parity). Best-effort: the versionlock plugin may not
# be preinstalled and a re-bake re-pins anyway.
${DNF} install python3-dnf-plugin-versionlock 2>/dev/null || \
    ${DNF} install 'dnf-command(versionlock)' 2>/dev/null || true
dnf versionlock add \
    ${DISTRO_KERNEL_PKG} kernel-modules kernel-modules-extra \
    dracut dracut-network cryptsetup netbird 2>/dev/null || true

# SELinux: the bake wrote guest files (release binaries, systemd units,
# the dracut module, crypttab/fstab, netbird) with the baker container's
# (absent) labels. The relabel is done OFFLINE after this chroot exits
# (see the `chroot … setfiles` block below), once the /proc /sys /dev
# binds are torn down — using the GUEST's own `setfiles` + `-c <policy>`
# so it validates against the policy FILE (no selinuxfs) and the guest's
# libsepol reads its own newer policydb. The old `.autorelabel` fallback
# forced a first-boot relabel+REBOOT — fatal under SNP measured boot (the
# reboot re-attests and burns the single-use KBS release nonce, so
# cloud-init/netbird never run). No `.autorelabel`.

# Untrusted miner (M0 hardening): same as the apt arm — no guest agent
# on a miner-attachable virtio channel (the RHEL-family cloud images
# ship qemu-guest-agent WantedBy its virtio port).
dnf -y remove qemu-guest-agent spice-vdagent open-vm-tools 2>/dev/null || true

dnf clean all
CHROOT_RHEL_EOF
sudo chroot "${MNT_ROOT}" /usr/bin/env \
    SOURCE_DATE_EPOCH="${source_date_epoch}" \
    DISTRO_KERNEL_PKG="${DISTRO_KERNEL_PKG}" \
    NETBIRD_VERSION="${netbird_version}" \
    BAKE_DISK_MODE="${disk_mode}" \
    PKG_REFRESH="${package_refresh}" \
    /bin/bash /tmp/hippius-chroot-install.sh
sudo rm -f "${MNT_ROOT}/tmp/hippius-chroot-install.sh"

sudo umount "${MNT_ROOT}/var/cache/libdnf5" || true
fi

# Restore the image's ORIGINAL resolv.conf shape (recorded before the
# chroot DNS swap): Ubuntu = systemd-resolved stub symlink; Debian
# genericcloud = plain file / absent.
sudo rm -f "${MNT_ROOT}/etc/resolv.conf"
case "${RESOLV_WAS}" in
    symlink) sudo ln -s "${RESOLV_LINK_TARGET}" "${MNT_ROOT}/etc/resolv.conf" ;;
    file)    sudo cp "${WORK_DIR}/resolv.conf.orig" "${MNT_ROOT}/etc/resolv.conf" ;;
    absent)  ;; # the image shipped none; leave none
esac
# RHEL family: the restore above wrote the file from THIS (non-SELinux)
# container, so it carries NO security.selinux xattr → `unlabeled_t` in
# the enforcing guest. NetworkManager is then DENIED replacing it
# ("dns-mgr: could not commit DNS changes ... g_rename() Permission
# denied") and the guest boots with EMPTY DNS — cloud-init runcmd
# (NetBird install!) fails on the first curl. The chroot's setfiles ran
# BEFORE this restore, so label it here, directly via the xattr (works
# without SELinux running — same mechanism the rsync -X copy preserves).
# net_conf_t is the file_contexts label for /etc/resolv.conf on every
# RHEL-family policy (targeted).
if [[ "${DISTRO_FAMILY}" == "rhel" && -f "${MNT_ROOT}/etc/resolv.conf" ]]; then
    sudo setfattr -n security.selinux -v "system_u:object_r:net_conf_t:s0" \
        "${MNT_ROOT}/etc/resolv.conf" \
        || die "setfattr net_conf_t on restored resolv.conf failed (install attr) (exit 3)"
    log "rhel: restored resolv.conf labeled net_conf_t"
fi

# SSH key-only by default (every family). sshd keeps the FIRST value it
# reads for a keyword and reads sshd_config.d/*.conf (Included at the top
# of sshd_config on Ubuntu, Debian, CS10 and Fedora) in name order. A seed
# with `ssh_pwauth: true` makes cloud-init write `PasswordAuthentication
# yes` to 50-cloud-init.conf, which beat the cloud image's own
# 60-cloudimg-settings.conf (`no`): password login was on. 00- sorts
# first, so this drop-in wins over cloud-init and the distro drop-ins
# (CS10/Fedora 50-redhat.conf sets X11Forwarding yes and
# GSSAPIAuthentication yes, which offered gssapi-keyex/gssapi-with-mic
# next to publickey). Golden guests get
# the same bytes re-written by the measured initramfs every boot
# (hippius_golden_write_masks; golden-overlay-test pins the two equal),
# which also reaches VMs whose base predates this file. The tenant keeps
# control of their VM: a drop-in sorting before this one, or a `Match`
# block anywhere, overrides it (sshd-key-only-test proves both).
# Create the directory only if the base lacks it: Fedora ships it 0700 and
# `install -d -m` would widen an existing one.
[[ -d "${MNT_ROOT}/etc/ssh/sshd_config.d" ]] || sudo install -d -m 0755 "${MNT_ROOT}/etc/ssh/sshd_config.d"
sudo tee "${MNT_ROOT}/etc/ssh/sshd_config.d/00-hippius-harden.conf" >/dev/null <<'HIPPIUS_SSHD_HARDEN'
# hippius: SSH is key-only by default. sshd keeps the first value it reads
# for each keyword and reads sshd_config.d in name order, so this file wins
# over cloud-init's 50-cloud-init.conf (ssh_pwauth) and the distro defaults.
# On golden images it is re-written at every boot. To change a setting on
# your VM, put it in a drop-in that sorts BEFORE this one (for example
# 00-00-local.conf) or in a `Match` block, which overrides it.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
X11Forwarding no
GSSAPIAuthentication no
GSSAPIKeyExchange no
HIPPIUS_SSHD_HARDEN
sudo chmod 0644 "${MNT_ROOT}/etc/ssh/sshd_config.d/00-hippius-harden.conf"

# The root never grows in place, in either disk mode: a golden root is an
# overlay whose upper is the guest-keyed /dev/mapper/hippius-overlay, and a
# legacy root is LUKS2 --integrity, which `cryptsetup resize` refuses
# (#365). cloud-init's growpart / resizefs could only fail on them and
# leave the run `degraded`.
sudo tee "${MNT_ROOT}/etc/cloud/cloud.cfg.d/99-hippius-noresize.cfg" >/dev/null <<'EOF'
# hippius-bake-managed: the root is an overlay (golden) or LUKS2 with
# dm-integrity (legacy); neither can be grown in place.
growpart:
  mode: 'off'
resize_rootfs: false
EOF

# Headless guest: no modem, no multipath SAN (virtio disks only; the
# initramfs assembles the dm-crypt / dm-verity / overlay root without
# multipathd, which only ever claims `mpath-` maps), no desktop disk
# manager. Masked rather than purged: multipath-tools and udisks2 are
# pulled in by distro meta-packages, and a mask is a no-op on a base
# that does not ship the unit. The socket goes too, or socket activation
# would start the masked multipathd.
for headless_unit in ModemManager.service multipathd.service multipathd.socket udisks2.service; do
    sudo ln -sfn /dev/null "${MNT_ROOT}/etc/systemd/system/${headless_unit}"
done

# Untrusted miner (M0 hardening), every family:
#   - systemd-ssh-generator (systemd >=256) binds sshd to AF_VSOCK when
#     the guest sees a vsock device — which the miner controls — giving
#     a login surface outside NetBird. Masked by a /dev/null generator.
#   - serial-getty@ttyS0: the miner owns the serial console; a login
#     prompt there is a password-guessing surface. Masked.
sudo mkdir -p "${MNT_ROOT}/etc/systemd/system-generators"
sudo ln -sf /dev/null "${MNT_ROOT}/etc/systemd/system-generators/systemd-ssh-generator"
sudo ln -sf /dev/null "${MNT_ROOT}/etc/systemd/system/serial-getty@ttyS0.service"

# Post-customise assertions for the M0 hardening above: a later edit
# that drops one of them fails the bake instead of shipping a guest
# the miner can talk to.
sudo grep -qx '    fs_label: null' "${MNT_ROOT}/etc/cloud/cloud.cfg.d/99-hippius-nocloud.cfg" \
    || { echo "FATAL: 99-hippius-nocloud.cfg lacks 'fs_label: null' (cidata volume probe enabled)" >&2; exit 3; }
sudo grep -qx 'policy: enabled' "${MNT_ROOT}/etc/cloud/ds-identify.cfg" 2>/dev/null \
    || { echo "FATAL: /etc/cloud/ds-identify.cfg missing or not 'policy: enabled'" >&2; exit 3; }
for agent_bin in /usr/bin/qemu-ga /usr/sbin/qemu-ga \
    /usr/bin/spice-vdagent /usr/bin/spice-vdagentd /usr/sbin/spice-vdagentd \
    /usr/bin/vmtoolsd /usr/sbin/vmtoolsd; do
    if sudo test -e "${MNT_ROOT}${agent_bin}"; then
        echo "FATAL: guest agent ${agent_bin} still present after purge" >&2
        exit 3
    fi
done
# Unconditional: we create both masks above, so both must be a symlink to
# /dev/null regardless of whether the vendor generator/unit exists on this
# base image. Gating on the vendor file existing would let a future edit
# that drops the mask pass on any image that happens not to ship it.
for masked in \
    /etc/systemd/system-generators/systemd-ssh-generator \
    /etc/systemd/system/serial-getty@ttyS0.service; do
    [[ "$(sudo readlink "${MNT_ROOT}${masked}")" == /dev/null ]] \
        || { echo "FATAL: ${masked} is not masked to /dev/null" >&2; exit 3; }
done
# The guest network: cloud-init writes none, the family's DHCP profile
# brings the NIC up, and the old netplan merge file (a DHCP-less enp1s0
# definition once cloud-init's is gone) is not shipped.
sudo grep -qx '  config: disabled' "${MNT_ROOT}/etc/cloud/cloud.cfg.d/99-hippius-network.cfg" 2>/dev/null \
    || { echo "FATAL: 99-hippius-network.cfg missing or does not disable cloud-init network config" >&2; exit 3; }
sudo test ! -e "${MNT_ROOT}/etc/netplan/90-hippius-dhcp-identifier.yaml" \
    || { echo "FATAL: /etc/netplan/90-hippius-dhcp-identifier.yaml would shadow the DHCP profile with a DHCP-less enp1s0" >&2; exit 3; }
if [[ "${DISTRO_FAMILY}" == "debian" ]]; then
    { sudo grep -qx 'DHCP=ipv4' "${MNT_ROOT}/etc/systemd/network/50-hippius-dhcp.network" \
        && sudo grep -qx 'ClientIdentifier=mac' "${MNT_ROOT}/etc/systemd/network/50-hippius-dhcp.network"; } 2>/dev/null \
        || { echo "FATAL: /etc/systemd/network/50-hippius-dhcp.network missing or not DHCPv4 with ClientIdentifier=mac" >&2; exit 3; }
else
    [[ "$(sudo stat -c %a "${MNT_ROOT}/etc/NetworkManager/system-connections/hippius-dhcp.nmconnection" 2>/dev/null)" == 600 ]] \
        && sudo grep -qx 'method=auto' "${MNT_ROOT}/etc/NetworkManager/system-connections/hippius-dhcp.nmconnection" \
        || { echo "FATAL: hippius-dhcp.nmconnection missing, not DHCP, or not mode 0600 (NetworkManager ignores it)" >&2; exit 3; }
fi
# SSH key-only: the drop-in carries every keyword and is the FIRST file in
# sshd_config.d (a base drop-in sorting before it would win over it). The
# effective policy is checked against the guest's own sshd further down.
sshd_dropin=/etc/ssh/sshd_config.d/00-hippius-harden.conf
for sshd_kv in 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' \
    'PermitRootLogin no' 'X11Forwarding no' 'GSSAPIAuthentication no' 'GSSAPIKeyExchange no'; do
    sudo grep -qx "${sshd_kv}" "${MNT_ROOT}${sshd_dropin}" 2>/dev/null \
        || { echo "FATAL: ${sshd_dropin} missing or lacks '${sshd_kv}'" >&2; exit 3; }
done
sshd_first="$(sudo find "${MNT_ROOT}/etc/ssh/sshd_config.d" -maxdepth 1 -name '*.conf' -printf '%f\n' | LC_ALL=C sort | head -n1)"
[[ "${sshd_first}" == "${sshd_dropin##*/}" ]] \
    || { echo "FATAL: /etc/ssh/sshd_config.d/${sshd_first} sorts before ${sshd_dropin##*/} and would override it" >&2; exit 3; }
# The root does not grow in place, and the headless masks are in place.
sudo grep -qx "  mode: 'off'" "${MNT_ROOT}/etc/cloud/cloud.cfg.d/99-hippius-noresize.cfg" 2>/dev/null \
    && sudo grep -qx 'resize_rootfs: false' "${MNT_ROOT}/etc/cloud/cloud.cfg.d/99-hippius-noresize.cfg" \
    || { echo "FATAL: 99-hippius-noresize.cfg missing or does not turn growpart + resize_rootfs off" >&2; exit 3; }
for masked in ModemManager.service multipathd.service multipathd.socket udisks2.service; do
    [[ "$(sudo readlink "${MNT_ROOT}/etc/systemd/system/${masked}")" == /dev/null ]] \
        || { echo "FATAL: /etc/systemd/system/${masked} is not masked to /dev/null" >&2; exit 3; }
done
# The shipped initramfs-tools initrd carries no BUILD-HOST state (the
# chroot sees the host's /proc, /sys and /dev): no non-zero
# /.random-seed, no md ARRAY the guest's own mdadm.conf does not list,
# no mkconf leftover, no efivarfs (load line or .ko) the guest's own
# modules list does not ask for. Same selection as the stage-5 initrd extraction. dracut
# (rhel) builds --no-hostonly and ships none of these hooks.
hs_initrd="$(sudo bash -c "ls -d ${MNT_ROOT}/boot/initrd.img-* 2>/dev/null | grep -v -- '-cloud-' | sort -V | tail -1")"
if [[ -n "${hs_initrd}" ]]; then
    hs_dir="$(mktemp -d)"
    sudo unmkinitramfs "${hs_initrd}" "${hs_dir}/x" \
        || { echo "FATAL: cannot unpack ${hs_initrd} to audit it for build-host state" >&2; exit 3; }
    hs_guest_arrays="$(sudo grep -h '^ARRAY' "${MNT_ROOT}/etc/mdadm/mdadm.conf" 2>/dev/null | sort -u || true)"
    while IFS= read -r hs_f; do
        case "${hs_f}" in
            */.random-seed)
                # Count non-zero bytes as root (the unpacked tree is root's);
                # anything but a clean "0" — unreadable included — fails.
                hs_nz="$(sudo bash -c 'set -o pipefail; tr -d "\\000" < "$1" | wc -c' _ "${hs_f}" 2>/dev/null)" || hs_nz="unreadable"
                if [[ "${hs_nz}" != 0 ]]; then
                    echo "FATAL: ${hs_initrd} carries a /.random-seed with ${hs_nz} non-zero bytes (build-host /dev/random)" >&2; exit 3
                fi ;;
            */etc/mdadm/mdadm.conf.tmp)
                echo "FATAL: ${hs_initrd} carries mkconf's /etc/mdadm/mdadm.conf.tmp (build-host md scan)" >&2; exit 3 ;;
            */etc/mdadm/mdadm.conf)
                hs_extra="$(comm -23 <(sudo grep -h '^ARRAY' "${hs_f}" | sort -u) <(printf '%s\n' "${hs_guest_arrays}" | sed '/^$/d'))"
                if [[ -n "${hs_extra}" ]]; then
                    echo "FATAL: ${hs_initrd} mdadm.conf lists md arrays the guest does not (build-host arrays): ${hs_extra}" >&2; exit 3
                fi ;;
            */conf/modules|*/efivarfs.ko*)
                if { [[ "${hs_f}" != */conf/modules ]] || sudo grep -qx 'efivarfs' "${hs_f}"; } \
                    && ! sudo grep -qx 'efivarfs' "${MNT_ROOT}/etc/initramfs-tools/modules" 2>/dev/null; then
                    echo "FATAL: ${hs_initrd} ships efivarfs (${hs_f##*/}) — the build host has EFI; the guest did not ask for it" >&2; exit 3
                fi ;;
        esac
    done < <(sudo find "${hs_dir}/x" -type f \( -name .random-seed -o -path '*/etc/mdadm/mdadm.conf*' \
                -o -path '*/conf/modules' -o -name 'efivarfs.ko*' \))
    # An initramfs dhcpcd (Ubuntu) presents 01:<MAC>, the client-id the
    # booted guest sends (zz-hippius-dhcp-clientid hook, #289 multi-IP).
    # A dhcpcd with no config at all would fall back to its DUID default.
    if [[ -n "$(sudo find "${hs_dir}/x" -type f -path '*/sbin/dhcpcd' -print -quit)" \
        && -z "$(sudo find "${hs_dir}/x" -type f -path '*/etc/dhcpcd.conf' -print -quit)" ]]; then
        echo "FATAL: ${hs_initrd} ships dhcpcd but no etc/dhcpcd.conf: its DHCP client-id would be dhcpcd's DUID default, not the booted guest's 01:<MAC>" >&2; exit 3
    fi
    while IFS= read -r hs_f; do
        { sudo grep -qx 'clientid' "${hs_f}" \
            && ! sudo grep -Eq '^[[:space:]]*(duid([[:space:]]|$)|clientid[[:space:]]+[^[:space:]])' "${hs_f}"; } \
            || { echo "FATAL: ${hs_initrd} ships an initramfs dhcpcd.conf without a bare \`clientid\` (or with a duid / clientid <value> line): its DHCP client-id would differ from the booted guest's 01:<MAC>" >&2; exit 3; }
    done < <(sudo find "${hs_dir}/x" -type f -path '*/etc/dhcpcd.conf')
    sudo rm -r -- "${hs_dir}"
fi

# Effective sshd policy (every family): ask the guest's OWN sshd what it
# will enforce, with a probe drop-in standing in for the worst later file
# (cloud-init's 50-cloud-init.conf for `ssh_pwauth: true`, a distro
# default turning X11 on). The checks above pin the file; this pins the
# result, so a base whose sshd_config sets a keyword before its Include,
# or does not Include sshd_config.d at all, fails the bake instead of
# shipping password login. Runs while /dev, /proc and /run are still
# bound; the probe, the throwaway host key and a /run/sshd it had to
# create (sshd -T refuses to start without its privsep dir) are removed.
sudo tee "${MNT_ROOT}/tmp/hippius-sshd-effective.sh" >/dev/null <<'SSHD_EFFECTIVE_EOF'
set -eu
probe=/etc/ssh/sshd_config.d/50-hippius-bake-probe.conf
work="$(mktemp -d /tmp/hippius-sshd.XXXXXX)"
made_privsep=""
cleanup() {
    rm -f "${probe}"
    rm -f "${work}/hk" "${work}/hk.pub" "${work}/effective"
    rmdir "${work}"
    if [ -n "${made_privsep}" ]; then rmdir /run/sshd; fi
}
trap cleanup EXIT
[ ! -e "${probe}" ] || { echo "sshd -T: ${probe} already exists" >&2; exit 1; }
printf 'PasswordAuthentication yes\nKbdInteractiveAuthentication yes\nPermitRootLogin yes\nX11Forwarding yes\nGSSAPIAuthentication yes\nGSSAPIKeyExchange yes\n' > "${probe}"
ssh-keygen -q -t ed25519 -N '' -f "${work}/hk"
if [ ! -d /run/sshd ]; then mkdir -m 0755 /run/sshd; made_privsep=1; fi
/usr/sbin/sshd -T -h "${work}/hk" > "${work}/effective"
for kv in 'passwordauthentication no' 'kbdinteractiveauthentication no' \
    'permitrootlogin no' 'x11forwarding no' 'gssapiauthentication no' 'gssapikeyexchange no'; do
    grep -qx "${kv}" "${work}/effective" \
        || { echo "sshd -T: want '${kv}', got '$(grep "^${kv%% *} " "${work}/effective")'" >&2; exit 1; }
done
SSHD_EFFECTIVE_EOF
sudo chroot "${MNT_ROOT}" /bin/sh /tmp/hippius-sshd-effective.sh \
    || { echo "FATAL: the guest's sshd does not enforce key-only SSH (sshd -T above)" >&2; exit 3; }
sudo rm -f "${MNT_ROOT}/tmp/hippius-sshd-effective.sh"
sudo test ! -e "${MNT_ROOT}/etc/ssh/sshd_config.d/50-hippius-bake-probe.conf" \
    || { echo "FATAL: the sshd -T probe drop-in was left in the image" >&2; exit 3; }

# ── cdn-node profile (CDN plan I3) ───────────────────────────────────
# A CDN node has no shell for anyone: sshd is purged (the standard gates
# above ran on the base first, so a standard bake is unaffected), then the
# data plane is staged by scripts/cdn-node/install-cdn-node.sh while the
# vfs binds are still up. All of it lands in the dm-verity base, so the
# measurement covers it; none of it comes from user-data.
if [[ "${profile}" == "cdn-node" ]]; then
    log "cdn-node: purging sshd and staging the CDN data plane"
    sudo chroot "${MNT_ROOT}" /usr/bin/env DEBIAN_FRONTEND=noninteractive \
        apt-get purge -y openssh-server openssh-sftp-server \
        || die "cdn-node: could not purge openssh-server (exit 3)"
    # Nothing may change the measured software at runtime: no snaps, no
    # unattended upgrades (the installer masks their units too).
    for pkg in snapd unattended-upgrades; do
        if sudo chroot "${MNT_ROOT}" dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep -q 'ok installed'; then
            sudo chroot "${MNT_ROOT}" /usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get purge -y "${pkg}" \
                || die "cdn-node: could not purge ${pkg} (exit 3)"
        fi
    done
    sudo find "${MNT_ROOT}/etc/ssh" -depth \( -path '*/sshd_config*' -o -name 'ssh_host_*' \) \
        -delete 2>/dev/null || true
    for f in /usr/sbin/sshd /usr/lib/systemd/system/ssh.service /usr/lib/systemd/system/ssh.socket \
             /lib/systemd/system/ssh.service /lib/systemd/system/ssh.socket; do
        sudo test ! -e "${MNT_ROOT}${f}" || die "cdn-node: ${f} still present after the purge (exit 3)"
    done
    sudo test -x "${MNT_ROOT}/usr/sbin/nft" || die "cdn-node: nft missing from the guest (exit 3)"
    sudo test -x "${MNT_ROOT}/usr/bin/openssl" || die "cdn-node: openssl missing from the guest (exit 3)"
    # A child bash does not inherit the root `sudo` shim above: as root
    # (the baker pod, which ships no sudo) the installer writes directly.
    cdn_sudo=sudo
    if [[ ${EUID} -eq 0 ]]; then cdn_sudo=""; fi
    SUDO="${cdn_sudo}" bash "${CDN_INSTALL_SRC}" "${MNT_ROOT}" "${cdn_agent_bin}" \
        "${cdn_openresty_tarball}" "${cdn_config_dir}" "${cdn_backend_url}" "${cdn_fleet_wildcard}" \
        || die "cdn-node: data-plane staging failed (exit 3)"
fi

log "chroot install complete; root partition customised"

# ── 5. Unbind + unmount ─────────────────────────────────────────────

for vfs in run sys proc dev/pts dev; do
    sudo umount -l "${MNT_ROOT}/${vfs}" 2>/dev/null || true
done

# ── SELinux offline relabel (RHEL family) ───────────────────────────
# The bake wrote guest files (release binaries, systemd units, the
# dracut module, crypttab/fstab, netbird) from THIS non-SELinux baker
# container, so they carry no security.selinux xattr → `unlabeled_t` in
# the enforcing guest — and PID1 itself gets AVC-denied, so systemd runs
# a full autorelabel and FORCE-REBOOTS on first boot. Under SNP that
# reboot re-enters the measured boot + re-attest and burns the
# single-use KBS release nonce → the second boot fails → cloud-init
# never runs (no SSH key, no netbird). So relabel the WHOLE tree
# DETERMINISTICALLY here, offline, writing security.selinux xattrs
# directly — the same offline-xattr mechanism used for resolv.conf's
# net_conf_t above. Run the GUEST's own `setfiles` via `chroot`: the
# Debian-trixie baker's libsepol only reads policydb v15-34, but
# CS10/Fedora ship policy.35, so a HOST `setfiles -c policy.35` dies
# "policydb version 35 does not match". The guest's libsepol reads its
# own v35 policy. `-c <policy>` validates against the policy FILE (no
# selinuxfs needed — that was the original in-chroot blocker before the
# `-c` flag). Done AFTER the vfs binds (/proc /sys /dev) are torn down,
# so `/` inside the chroot is just the rootfs; `-m` skips /proc/mounts
# (absent in the chroot anyway). Fail-closed: never ship an unlabeled
# image (an unlabeled enforcing guest force-reboots on autorelabel and
# burns the single-use KBS nonce).
if [[ "${DISTRO_FAMILY}" == "rhel" ]]; then
    _fc="/etc/selinux/targeted/contexts/files/file_contexts"
    _pol="$(ls -1 "${MNT_ROOT}"/etc/selinux/targeted/policy/policy.* 2>/dev/null | sort -V | tail -1)"
    [[ -x "${MNT_ROOT}/usr/sbin/setfiles" ]] \
        || die "setfiles absent in guest rootfs (policycoreutils not installed) — cannot relabel rhel rootfs (exit 3)"
    [[ -f "${MNT_ROOT}${_fc}" ]] \
        || die "guest file_contexts absent (${MNT_ROOT}${_fc}) — cannot relabel rhel rootfs (exit 3)"
    [[ -n "${_pol}" && -f "${_pol}" ]] \
        || die "guest binary policy absent under ${MNT_ROOT}/etc/selinux/targeted/policy/ — cannot relabel rhel rootfs (exit 3)"
    _pol_rel="${_pol#"${MNT_ROOT}"}"
    sudo rm -f "${MNT_ROOT}/.autorelabel"
    sudo chroot "${MNT_ROOT}" /usr/sbin/setfiles -m -c "${_pol_rel}" "${_fc}" / \
        || die "offline SELinux relabel of rhel rootfs failed (chroot setfiles -c $(basename "${_pol}")) (exit 3)"
    log "rhel: offline SELinux relabel complete (guest setfiles, policy $(basename "${_pol}"))"
fi

# -R: also releases a separate /boot mount (Fedora) nested under the root.
sudo umount -R "${MNT_ROOT}" || die "umount root failed (exit 3)"
sudo losetup -d "${LOOP_DEV}" || true
LOOP_DEV=""

# ── 6. Build the LUKS-encrypted output qcow2 ────────────────────────

# The output qcow2 layout: a single LUKS-encrypted partition that
# holds the customised root. Boot path: OVMF → grub (from /boot
# inside the LUKS volume → wait, grub can't read encrypted... we
# need a separate /boot.)
#
# RIGHT — for grub to find the kernel, /boot must be unencrypted OR
# grub must have its `cryptodisk` + `luks2` modules built-in. Modern
# grub2 supports `cryptomount` → see GRUB_ENABLE_CRYPTODISK=y in
# /etc/default/grub. The chroot install above set that up via the
# Debian default. So the output is a fully-encrypted single
# partition + a small unencrypted EFI partition for grub itself.
#
# But cloud images don't ship grub configured that way out of the
# box. For the MVP we ship a simpler layout: the LUKS volume IS the
# qcow2 (no partition table), and the miner-agent attaches it
# alongside the staged `kernel` + `initrd` direct-boot files (the
# legacy Hippius UKI path keeps the measurement chain). The
# keyscript-bearing initramfs is the SAME initramfs that gets
# direct-booted — we have to extract it from the chroot.
#
# This MVP keeps:
#   - existing Hippius UKI direct-boot model (-kernel/-initrd at
#     QEMU)
#   - the initramfs is now THE TENANT's (with udev + cryptsetup-
#     initramfs + Hippius keyscript) — so the mount(2) ENOENT bug
#     is gone (udev is doing its job).
#
# Output:
#   - kernel.vmlinuz — copied from /boot/vmlinuz-*-generic in chroot
#   - initrd.img    — copied from /boot/initrd.img-*-generic in chroot
#   - root.luks.qcow2 — LUKS-encrypted root partition
#
# The miner-agent staging script then attaches the qcow2 as
# /dev/vda + uses kernel.vmlinuz + initrd.img as -kernel/-initrd.

# Re-attach + extract kernel + initramfs from the customised root.
# Re-derive root_part from the new LOOP_DEV (the previous attach was
# closed at the end of stage 4b, so the loop number may have shifted).
log "extracting kernel + initramfs from customised image"
LOOP_DEV="$(sudo losetup --find --show --partscan "${src_raw}")"
sudo partprobe "${LOOP_DEV}" 2>/dev/null || true
sleep 1
ensure_loop_partitions "${LOOP_DEV}"
root_part="${LOOP_DEV}p${root_part_num}"
[[ -b "${root_part}" ]] || die "re-attached source has no ${root_part} (exit 3)"
# Same btrfs-subvol resolution as stage 3. The separate /boot can't be
# rediscovered from fstab here (stage 4 rewrote it to a single `/`), so
# re-mount it by the partition number captured at the stage-3 mount —
# this whole extraction block only runs on a cache MISS, the same branch
# where BOOT_PART_NUM was set.
mount_guest_root "${root_part}" "${MNT_ROOT}" rw
if [[ -n "${BOOT_PART_NUM:-}" ]]; then
    sudo mount "${LOOP_DEV}p${BOOT_PART_NUM}" "${MNT_ROOT}/boot" \
        || die "re-mount separate /boot (${LOOP_DEV}p${BOOT_PART_NUM}) failed (exit 3)"
    log "re-mounted separate /boot partition: ${LOOP_DEV}p${BOOT_PART_NUM}"
fi

# Distro-agnostic kernel + initrd extraction. Pick the highest-versioned
# vmlinuz-*, excluding ".efi.signed" duplicates. The initrd is named
# `initrd.img-<kver>` on the debian family (initramfs-tools) but
# `initramfs-<kver>.img` on the rhel family (dracut) — match both.
# `-cloud-` filter: Debian genericcloud PRE-INSTALLS a -cloud- kernel
# that lacks sev-guest/tsm; the bake installs the full image alongside
# it, and `sort -V` would otherwise pick the -cloud- one ('c' > 'a').
# Ubuntu never names kernels -cloud- → unconditional filter is safe.
# This selection MUST stay semantically identical to the chroot's
# KVER= line (the initrd regenerated there is the one extracted here).
kernel_src=$(sudo bash -c "ls ${MNT_ROOT}/boot/vmlinuz-* 2>/dev/null | grep -v '\.signed$' | grep -v -- '-cloud-' | sort -V | tail -1")
initrd_src=$(sudo bash -c "ls ${MNT_ROOT}/boot/initrd.img-* ${MNT_ROOT}/boot/initramfs-*.img 2>/dev/null | grep -v -- '-cloud-' | sort -V | tail -1")
[[ -n "${kernel_src}" ]] || die "no /boot/vmlinuz-* in image (exit 3)"
[[ -n "${initrd_src}" ]] || die "no /boot/{initrd.img-*,initramfs-*.img} in image (exit 3)"
assert_kernel_initrd_match "${kernel_src}" "${initrd_src}"
log "kernel:  ${kernel_src}"
log "initrd:  ${initrd_src}"
sudo cp "${kernel_src}" "${WORK_DIR}/kernel.vmlinuz"
sudo cp "${initrd_src}" "${WORK_DIR}/initrd.img"

sudo umount -R "${MNT_ROOT}" || true
sudo losetup -d "${LOOP_DEV}" || true
LOOP_DEV=""

# Fail-closed audit on the SHIPPED artifact (not just the in-chroot
# copy): the extracted initrd MUST carry the hippius release core, or
# the guest can never unlock (silent cryptroot hang). The in-chroot
# audit already passed, but this catches any mechanism that ships a
# DIFFERENT initrd than the one the chroot regenerated — e.g. the
# 2026-07-04 stale-loop /boot mount, where a leaked host loop with the
# same LABEL=BOOT absorbed the chroot's /boot writes and the pristine
# hookless preinstalled initrd shipped instead. Also blocks the bake
# from CACHING a bad artifact (runs before stage1_cache_store).
# NOTE: plain `grep >/dev/null`, NOT `grep -q` — this script runs under
# `set -o pipefail`, and `grep -q` exits on the FIRST match, SIGPIPE-ing
# lsinitramfs so the pipeline fails EXACTLY when the file is found (a
# guaranteed false negative; bitten live 2026-07-04). Plain grep reads
# the whole stream, so the pipeline status is honest.
audit_ok=""
if command -v lsinitramfs >/dev/null 2>&1; then
    lsinitramfs "${WORK_DIR}/initrd.img" 2>/dev/null | grep 'hippius-release-core.sh' >/dev/null && audit_ok=1
fi
if [[ -z "${audit_ok}" ]] && command -v lsinitrd >/dev/null 2>&1; then
    sudo lsinitrd "${WORK_DIR}/initrd.img" 2>/dev/null | grep 'hippius-release-core.sh' >/dev/null && audit_ok=1
fi
[[ -n "${audit_ok}" ]] \
    || die "extracted initrd (${initrd_src}) carries NO hippius release core — refusing to ship an unbootable image (exit 3)"
# cdn-node: the shipped initrd must carry the ephemeral-root marker, or the
# node would keep a persistent upper with nothing to say so.
if [[ "${profile}" == "cdn-node" ]]; then
    cdn_initrd_list="$(lsinitramfs "${WORK_DIR}/initrd.img" 2>/dev/null)" \
        || die "cdn-node: could not list the extracted initrd (exit 3)"
    grep -Ex '(\./)?conf/conf\.d/hippius-cdn-ephemeral-upper' <<<"${cdn_initrd_list}" >/dev/null \
        || die "cdn-node: the extracted initrd lacks the ephemeral-root marker (exit 3)"
    # A merged-/usr initrd lists /lib/... under usr/lib/.
    grep -Ex '(\./)?(usr/)?lib/hippius/chown' <<<"${cdn_initrd_list}" >/dev/null \
        || die "cdn-node: the extracted initrd lacks the chown the ephemeral root needs (exit 3)"
fi

stage1_cache_store

# Close of the stage-1 cache-miss branch opened just before
# "── 1. Fetch + verify the base image". On a cache HIT everything
# from there to here was skipped: src_raw + kernel + initrd were
# restored from the cache and root_part_num came from meta.json.
fi

# ── Golden dm-verity base mode: package the SHARED customised root as a
# read-only dm-verity base and exit BEFORE the legacy per-VM luksFormat
# below. Feature-flagged + inert until PR2-PR6 (see build_golden_verity_base).
if [[ "${disk_mode}" == "golden_verity_overlay" ]]; then
    build_golden_verity_base
    exit 0
fi

# ── legacy_luks path (default, unchanged) ────────────────────────────
# Now copy the root partition's used blocks into a fresh
# LUKS-encrypted raw → qcow2 output.
out_qcow2="${output_dir}/tenant-${base_image_sha256:0:12}.qcow2"
out_raw="${WORK_DIR}/out.raw"
qcow2_bytes=$(( output_qcow2_gb * 1024 * 1024 * 1024 ))
log "allocating output raw image: ${output_qcow2_gb} GiB"
qemu-img create -f raw "${out_raw}" "${qcow2_bytes}" >/dev/null

log "luksFormat output raw (with --integrity hmac-sha256 — wipes the device, takes ~2 min/16 GiB on NVMe)"
# --integrity hmac-sha256 — closes the §257 "AES-XTS malleability"
# gap explicitly listed as a MUST-FIX in the issue body. Without it,
# a malicious miner can flip ciphertext bits at known offsets and
# the guest reads back attacker-controlled plaintext. With it,
# dm-integrity stacks under dm-crypt: every 512-byte sector carries
# a 32-byte HMAC-SHA256 tag the guest re-verifies on every read, so
# a tampered sector returns EIO instead of malicious plaintext.
# Cost: ~7 % capacity (the encrypted plaintext device is smaller than
# the raw image), a format-time wipe (cryptsetup zeros the whole
# device to initialise valid HMAC tags), and ~10 % IOPS overhead at
# runtime. Per the issue body: "accept it as default".
#
# The guest side handles integrity transparently — the distro's
# cryptsetup-initramfs hook (this bake injects the
# \`hippius-luks-keyscript\` next to it) calls libcryptsetup's
# \`crypt_load(LUKS2)\` + \`crypt_activate_by_passphrase\`, which auto-
# stacks dm-integrity under dm-crypt when LUKS2's on-disk header
# records \`integrity: hmac(sha256)\` (set here by this flag). The
# legacy agent-initramfs \`RealLuksUnlocker\` path uses the same
# libcryptsetup call and gets integrity transparently too.
# PBKDF: pbkdf2 with the cryptsetup-minimum iteration count, NOT
# argon2id. The keyslot KDF's only job is to make brute-forcing a
# LOW-ENTROPY passphrase expensive; our KEK is 32 random bytes from
# Vault (256-bit entropy), so the KDF adds zero security — guessing
# the KEK is infeasible at ANY iteration count. What argon2id DID
# cost us: ~1-2 s per luksFormat/open benchmark run, and a ~1 GiB
# memory grab during the guest initramfs unlock — a real OOM risk on
# `small`-flavor guests where the initramfs has the whole VM's RAM
# minus the kernel to work with.
sudo cryptsetup luksFormat --type luks2 --batch-mode \
    --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --integrity hmac-sha256 \
    --key-file="${kek_buf}" "${out_raw}" \
    || die "luksFormat failed (exit 3)"

# #296 — compute the SHA-256 of the LUKS2 header bytes the format just
# wrote, so vali can pin it into the kernel cmdline at launch and the
# keyscript can verify before the open. `cryptsetup luksHeaderBackup`
# is the right primitive (per Review of the proposed design):
# it knows the actual on-disk header size (not the 16 MiB default —
# `--luks2-metadata-size` / `--luks2-keyslots-size` make the size
# configurable in principle), so we don't bake a magic constant.
# The backup is written to the bake's WORK_DIR (private to the
# operator workstation; wiped by the cleanup trap on exit) and
# `shred`-deleted as soon as the hash is taken — the digest is the
# only thing that travels with the bake outputs.
HEADER_BACKUP="${WORK_DIR}/luks-header.bin"
sudo cryptsetup luksHeaderBackup "${out_raw}" \
    --header-backup-file "${HEADER_BACKUP}" \
    || die "luksHeaderBackup failed (exit 3)"
LUKS_HEADER_SHA256=$(sha256sum "${HEADER_BACKUP}" | awk '{print $1}')
sudo shred -u "${HEADER_BACKUP}" 2>/dev/null || sudo rm -f -- "${HEADER_BACKUP}"
log "LUKS2 header sha256=${LUKS_HEADER_SHA256} ($(printf '%d MiB' $(($(sudo stat -c%s "${out_raw}" 2>/dev/null || echo 0) / 1024 / 1024)) ) raw)"

# `--integrity-no-journal` — ACTIVATION-time flag only (nothing is
# persisted to the LUKS2 header): the dm-integrity journal double-
# writes every sector to guarantee crash consistency of the
# data+tag pair. The bake's bulk load doesn't need that — a crash
# mid-bake fails the Job and the retry re-formats from scratch — so
# paying 2× writes here is pure latency. The GUEST's boot-time
# `crypt_activate_by_passphrase` (cryptsetup-initramfs) does NOT
# pass this flag, so runtime activation keeps the journal and the
# §257 integrity guarantees are unchanged where they matter.
sudo cryptsetup open --type luks2 --integrity-no-journal \
    --key-file="${kek_buf}" "${out_raw}" hippius-bake \
    || die "cryptsetup open failed (exit 3)"

# Re-attach src_raw to copy from. The loop device number may differ
# from the first attach (the previous /dev/loopN was released between
# chroot + extract phases), so re-discover root_part rather than
# reusing the stale path.
LOOP_DEV="$(sudo losetup --find --show --partscan "${src_raw}")"
sudo partprobe "${LOOP_DEV}" 2>/dev/null || true
sleep 1
ensure_loop_partitions "${LOOP_DEV}"
root_part="${LOOP_DEV}p${root_part_num}"
[[ -b "${root_part}" ]] || die "re-attached source has no ${root_part} (exit 3)"
src_size=$(sudo blockdev --getsize64 "${root_part}")
dst_size=$(sudo blockdev --getsize64 /dev/mapper/hippius-bake)
# Copy mode dispatches on the SOURCE root fs type, RE-PROBED here on
# the re-attached partition so the cache-HIT path (which skipped the
# stage-2 probe) resolves identically (#multi-distro). The output-size
# guard is PER-COPY-MODE because the two copy modes have different
# size bounds (see each arm).
#
# ext4 (Ubuntu/Debian): used-blocks block copy. The luksFormat wipe
# already wrote valid zero-tags over the WHOLE plaintext device, so
# free space needs no copy — `e2image -ra` walks the ext4 allocation
# bitmap and copies only allocated blocks (~2-4 GiB of a 7.5 GiB
# source). Every copied byte still goes through the dm-crypt+
# dm-integrity stack. e2image preserves block GEOMETRY up to the source
# fs size, so the output device must be at least the source partition.
#
# xfs (CentOS) / btrfs (Fedora): neither can be block-copied into a
# smaller device (no shrink) and e2image is ext4-only, so the mapper
# gets a FRESH ext4 and the tree is rsync'd file-by-file: -aHAX
# preserves hardlinks + ACLs + xattrs — `security.selinux` labels
# included, mandatory for enforcing RHEL guests — and --numeric-ids
# keeps uid/gid raw (the baker container's passwd differs from the
# guest's). The guest's root fs therefore CHANGES xfs|btrfs→ext4,
# unifying every downstream assumption (fstab, fsck tooling, the #365
# data disk). For btrfs the mounted tree is Fedora's default `root`
# subvolume — `/home` is a separate subvol left as an empty mountpoint,
# correct for a cloud image, and the rewritten fstab collapses it to a
# single ext4 root. rsync copies FILE DATA, not block geometry, so the
# bound is the source's USED bytes — NOT its partition size. The source
# carries a +HCC_BAKE_SRC_GROW_GB headroom grown in for the dnf chroot
# that is irrelevant to the output, so the e2image-style
# `dst < src_partition` guard would wrongly reject a sized output.
COPY_FSTYPE="$(sudo blkid -s TYPE -o value "${root_part}" 2>/dev/null || echo unknown)"
case "${COPY_FSTYPE}" in
    ext4)
        if (( dst_size < src_size )); then
            die "output LUKS plaintext (${dst_size}) smaller than source ext4 partition (${src_size}) — bump --size-gb (exit 3)"
        fi
        log "e2fsck source before used-blocks copy"
        sudo e2fsck -fy "${root_part}" 2>&1 | tail -2 || true
        log "e2image used-blocks copy root → /dev/mapper/hippius-bake (src ${src_size} bytes)"
        sudo e2image -rap "${root_part}" /dev/mapper/hippius-bake 2>&1 | tail -3 \
            || die "e2image copy failed (exit 3)"
        sudo sync
        sudo e2fsck -fy /dev/mapper/hippius-bake || true
        sudo resize2fs /dev/mapper/hippius-bake || true
        ;;
    xfs|btrfs)
        command -v rsync >/dev/null 2>&1 \
            || die "rsync missing — required for ${COPY_FSTYPE}-rooted images (exit 2)"
        log "${COPY_FSTYPE} source: mkfs.ext4 on the LUKS mapper + rsync -aHAXS tree copy"
        sudo mkfs.ext4 -q -F /dev/mapper/hippius-bake \
            || die "mkfs.ext4 on mapper failed (exit 3)"
        SRC_MNT="${WORK_DIR}/copy-src"
        DST_MNT="${WORK_DIR}/copy-dst"
        mkdir -p "${SRC_MNT}" "${DST_MNT}"
        # btrfs source: resolve the system subvol (top-level mount would
        # rsync `root/`+`home/` as subdirs). ext4/xfs mount straight.
        mount_guest_root "${root_part}" "${SRC_MNT}" ro
        # Size guard against ACTUAL used data (+ ~20% ext4 metadata /
        # safety slack), not the grown source partition.
        used_bytes=$(sudo df -B1 --output=used "${SRC_MNT}" | tail -1 | tr -dc '0-9')
        need_bytes=$(( used_bytes + used_bytes / 5 ))
        if (( dst_size < need_bytes )); then
            sudo umount "${SRC_MNT}"; SRC_MNT=""
            die "output LUKS plaintext (${dst_size}) too small for ${COPY_FSTYPE} used data (${used_bytes} + 20% slack = ${need_bytes}) — bump --size-gb (exit 3)"
        fi
        log "${COPY_FSTYPE} used=${used_bytes} bytes fits output=${dst_size} bytes (need>=${need_bytes})"
        sudo mount /dev/mapper/hippius-bake "${DST_MNT}" \
            || die "mount dest mapper failed (exit 3)"
        # -S sparse keeps the wipe's zero-tagged free space untouched.
        # -x stays on ONE filesystem: for btrfs this prevents descending
        # into any nested subvolume that happens to be mounted under the
        # source tree (we only want the root subvol's contents).
        sudo rsync -aHAXS -x --numeric-ids "${SRC_MNT}/" "${DST_MNT}/" \
            || die "rsync tree copy failed (exit 3)"
        sudo sync
        sudo umount "${DST_MNT}"; DST_MNT=""
        sudo umount "${SRC_MNT}"; SRC_MNT=""
        sudo e2fsck -fy /dev/mapper/hippius-bake || true
        ;;
    *)
        die "unsupported source root fs '${COPY_FSTYPE}' at copy time (exit 3)"
        ;;
esac
sudo cryptsetup close hippius-bake
sudo losetup -d "${LOOP_DEV}" || true
LOOP_DEV=""

# NO `-c` (qcow2 zlib compression): after the integrity wipe every
# sector of out.raw is dm-crypt ciphertext — uniformly random bytes
# that compress to ~100 % of their input size. The old `-c` spent
# 15-25 min of single-threaded zlib per `medium` bake to shave ~0 %
# off the image. Plain convert keeps the qcow2 container (which the
# miner-agent's format probe + libvirt expect) at near-disk-speed.
log "qemu-img convert raw → qcow2 (uncompressed — ciphertext doesn't compress)"
qemu-img convert -O qcow2 "${out_raw}" "${out_qcow2}" \
    || die "qemu-img convert raw → qcow2 failed (exit 3)"

# ── 7. Emit measurement.json + JSON output ──────────────────────────

out_sha=$(sha256sum "${out_qcow2}" | cut -d' ' -f1)
out_bytes=$(stat -c '%s' "${out_qcow2}")
kernel_sha=$(sha256sum "${WORK_DIR}/kernel.vmlinuz" | cut -d' ' -f1)
initrd_sha=$(sha256sum "${WORK_DIR}/initrd.img" | cut -d' ' -f1)

# Copy kernel + initrd into output dir so the operator can stage
# them next to the qcow2.
cp "${WORK_DIR}/kernel.vmlinuz" "${output_dir}/tenant-${base_image_sha256:0:12}.vmlinuz"
cp "${WORK_DIR}/initrd.img"    "${output_dir}/tenant-${base_image_sha256:0:12}.initrd.img"

measurement_json="${output_dir}/tenant-${base_image_sha256:0:12}.measurement.json"
jq -n \
    --arg qcow "${out_qcow2}" \
    --arg qcow_sha "${out_sha}" \
    --argjson qcow_size "${out_bytes}" \
    --arg base_url "${base_image_url}" \
    --arg base_sha "${base_image_sha256}" \
    --arg kbs "${kbs_url}" \
    --arg kernel_sha "${kernel_sha}" \
    --arg initrd_sha "${initrd_sha}" \
    --arg luks_header_sha "${LUKS_HEADER_SHA256}" \
    '{
        qcow2_path: $qcow,
        qcow2_sha256: $qcow_sha,
        qcow2_size_bytes: $qcow_size,
        base_image_url: $base_url,
        base_image_sha256: $base_sha,
        kbs_url: $kbs,
        kernel_sha256: $kernel_sha,
        initrd_sha256: $initrd_sha,
        luks_header_sha256: $luks_header_sha,
        luks_version: 2,
        luks_pbkdf: "pbkdf2"
     }' > "${measurement_json}"

cat "${measurement_json}"
log "qcow2:        ${out_qcow2}"
log "kernel:       ${output_dir}/tenant-${base_image_sha256:0:12}.vmlinuz"
log "initrd:       ${output_dir}/tenant-${base_image_sha256:0:12}.initrd.img"
log "measurement:  ${measurement_json}"
log "BAKE OK — pass these three files to the miner-agent staging step"

exit 0
