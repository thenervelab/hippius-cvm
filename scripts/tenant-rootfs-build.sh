#!/usr/bin/env bash
#
# `tenant-rootfs-build.sh` — Stage 1 of the split bake pipeline
# (`scripts/tenant-image-bake.sh` is the legacy single-stage path).
#
# Produces a SHARED, content-addressable rootfs tarball + kernel +
# initrd + manifest. No tenant secrets. No LUKS. Run ONCE per
# (base-image-sha, flavor, hippius-binary-version). Stage 2
# (`tenant-image-from-rootfs.sh`) consumes the manifest + tarball
# and produces a per-tenant LUKS-encrypted qcow2 in ~5 min (vs.
# the 30-60 min the fused legacy bake takes).
#
# Security: the tarball carries no per-tenant data. Every per-tenant
# launch gets a FRESH LUKS master key (Stage 2's luksFormat). Sharing
# the tarball does NOT leak across tenants.
#
# Output (in --output-dir):
#   rootfs.tar.zst            customised root filesystem
#   vmlinuz                   kernel extracted from /boot/
#   initrd.img                Hippius-keyscript-bearing initramfs
#   manifest.json             SHAs + provenance metadata
#
# Flow mirrors steps 1-5 of `tenant-image-bake.sh` (download +
# verify base, qemu-img convert + grow, mount, stage Hippius tooling,
# chroot apt install + update-initramfs, unmount) — then instead of
# the LUKS-format/dd step it tarballs the customised root + extracts
# kernel + initrd + emits the manifest.

set -Eeuo pipefail

cleanup() {
    local rc=$?
    set +e
    if [[ -n "${LOOP_DEV:-}" ]]; then
        sudo umount -R "${MNT_ROOT:-}" 2>/dev/null || true
        sudo losetup -d "${LOOP_DEV}" 2>/dev/null || true
    fi
    if [[ -n "${WORK_DIR:-}" && -d "${WORK_DIR}" ]]; then
        sudo rm -rf -- "${WORK_DIR}"
    fi
    exit "$rc"
}
trap cleanup EXIT

PROG="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
KEYSCRIPT_SRC="${SCRIPT_DIR}/initramfs/hippius-luks-keyscript"
HOOK_SRC="${SCRIPT_DIR}/initramfs/hippius-luks-hook"
NET_TEARDOWN_SRC="${SCRIPT_DIR}/initramfs/hippius-net-teardown"

base_image_url=""
base_image_sha256=""
output_dir="${HCC_BAKE_OUTPUT_DIR:-./out/rootfs-build}"
flavor=""
# No built-in default: the KBS a guest attests to is deployment
# config. Set $HIPPIUS_KBS_URL or pass --kbs-url.
kbs_url="${HIPPIUS_KBS_URL:-}"
hippius_release_bin=""
hippius_vsock_bin=""
source_date_epoch="${SOURCE_DATE_EPOCH:-86400}"
# NetBird overlay agent — PINNED version pre-installed into the shared
# rootfs during the chroot (see the "NetBird pre-install" block below).
# Pinned (never `latest`) so it is part of the reproducible/measured
# tarball, kept in lock-step with the miner side + legacy bake. WHY
# pre-install: the upstream first-boot installer runs
# `apt-get install -y ca-certificates curl gnupg`, which UPGRADES the
# curl/ca-certificates this bake holds → apt aborts (`E: Held packages
# were changed …`), netbird never installs, the guest never joins the
# overlay. Pre-installing removes the boot-time apt dependency and keeps
# the holds intact. Override for a bump via HCC_BAKE_NETBIRD_VERSION.
netbird_version="${HCC_BAKE_NETBIRD_VERSION:-0.71.3}"
# Audit follow-up (Gemini #2 / Codex #1): the shared rootfs tarball
# + manifest.json sit in S3 indefinitely as a shared artifact, and
# Stage 2 trusts whatever it finds at `--rootfs-dir`. Without a
# signature, a compromised S3 admin can atomically swap the tarball,
# the SHAs in the manifest, and ship a backdoored userspace that
# still passes the §22 allowlist gate (kernel + initrd unchanged).
# `--signing-key` makes Stage 1 emit a detached Ed25519 sig over the
# manifest bytes; Stage 2's `--verify-pubkey-hex` re-verifies before
# trusting any SHA. Default empty (operator opts in for the dev
# pipeline, production posture should require it).
signing_key=""

log() { printf '%s: %s\n' "${PROG}" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

usage() {
    cat >&2 <<EOF
${PROG} — Stage 1: build a shared rootfs tarball (no LUKS, no tenant data).

Usage:
  ${PROG} --base-image-url URL --base-image-sha256 HEX \\
          --hippius-release-bin PATH --hippius-vsock-bin PATH \\
          [--output-dir DIR] [--flavor small|medium|large] \\
          [--kbs-url URL] [--source-date-epoch TS]

Required:
  --base-image-url URL    https:// / s3:// / file:// of the cloud image.
  --base-image-sha256 HEX 64-hex sha256 of the cloud image bytes.
  --hippius-release-bin P Path to \`hippius-guest-release\`.
  --hippius-vsock-bin P   Path to \`hippius-vsock-ticket\`.

Optional:
  --signing-key PATH      Ed25519 seed file (64 lowercase hex chars +
                          optional trailing newline — the shape the
                          existing dev key at
                          \`packer/kbs-uki/keys/dev/provenance-root.dev.ed25519\`
                          uses). When set, emits
                          \`manifest.json.sig\` alongside the
                          manifest. Stage 2 then refuses to extract
                          unless its \`--verify-pubkey-hex\` (or
                          \`--verify-pubkey-file\`) matches.
  --output-dir DIR        Default \$HCC_BAKE_OUTPUT_DIR, else
                          \`./out/rootfs-build\`.
  --flavor NAME           small | medium | large. Affects the flavor
                          label recorded in the manifest only — the
                          rootfs CONTENT does not differ across
                          flavors (vCPU/memory/disk-size are stage 2's
                          concern). Default: medium.
  --kbs-url URL           Default \$HIPPIUS_KBS_URL, else
                          e.g. https://kbs.example.invalid
                          REQUIRED — no built-in default.
  --source-date-epoch TS  Reproducibility epoch. Default 86400.
  -h, --help              Show this header.

Output (in --output-dir):
  rootfs.tar.zst, vmlinuz, initrd.img, manifest.json

Exit codes:
  0  success
  1  usage error
  2  host tooling missing
  3  bake step failed
EOF
}

require_arg() { [[ -n "${2-}" ]] || die "$1 requires a value"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --base-image-url)       require_arg "$1" "${2-}"; base_image_url="$2";       shift 2;;
        --base-image-sha256)    require_arg "$1" "${2-}"; base_image_sha256="$2";    shift 2;;
        --hippius-release-bin)  require_arg "$1" "${2-}"; hippius_release_bin="$2";  shift 2;;
        --hippius-vsock-bin)    require_arg "$1" "${2-}"; hippius_vsock_bin="$2";    shift 2;;
        --output-dir)           require_arg "$1" "${2-}"; output_dir="$2";           shift 2;;
        --flavor)               require_arg "$1" "${2-}"; flavor="$2";               shift 2;;
        --kbs-url)              require_arg "$1" "${2-}"; kbs_url="$2";              shift 2;;
        --source-date-epoch)    require_arg "$1" "${2-}"; source_date_epoch="$2";    shift 2;;
        --signing-key)          require_arg "$1" "${2-}"; signing_key="$2";          shift 2;;
        -h|--help)              usage; exit 0;;
        *) die "unknown argument: $1 (try --help)";;
    esac
done

[[ -n "${flavor}" ]] || flavor="medium"
case "${flavor}" in
    small|medium|large) ;;
    *) die "--flavor must be one of: small, medium, large (got '${flavor}')";;
esac

[[ -n "${kbs_url}" ]]             || { usage; die "--kbs-url is required ""(or export HIPPIUS_KBS_URL) — there is no default KBS"; }
[[ -n "${base_image_url}" ]]      || { usage; die "--base-image-url is required"; }
[[ -n "${base_image_sha256}" ]]   || die "--base-image-sha256 is required"
[[ -n "${hippius_release_bin}" ]] || die "--hippius-release-bin is required"
[[ -n "${hippius_vsock_bin}" ]]   || die "--hippius-vsock-bin is required"
[[ "${base_image_sha256}" =~ ^[0-9a-f]{64}$ ]] \
    || die "--base-image-sha256 must be 64 lowercase hex chars"
case "${base_image_url}" in
    https://*|s3://*|file://*) ;;
    *) die "--base-image-url must be https://, s3://, or file://" ;;
esac
[[ -x "${hippius_release_bin}" ]] || die "${hippius_release_bin}: not executable"
[[ -x "${hippius_vsock_bin}" ]]   || die "${hippius_vsock_bin}: not executable"
if [[ -n "${signing_key}" ]]; then
    [[ -r "${signing_key}" ]] || die "${signing_key}: signing key not readable"
fi
[[ -r "${KEYSCRIPT_SRC}" ]]       || die "${KEYSCRIPT_SRC}: keyscript missing"
[[ -r "${HOOK_SRC}" ]]            || die "${HOOK_SRC}: initramfs hook missing"
[[ -r "${NET_TEARDOWN_SRC}" ]]    || die "${NET_TEARDOWN_SRC}: init-bottom teardown missing"

missing=()
for tool in curl sha256sum qemu-img losetup chroot mount umount jq growpart e2fsck resize2fs tar zstd; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if (( ${#missing[@]} > 0 )); then
    log "missing host tools: ${missing[*]}"
    log "install qemu-utils + cryptsetup-bin + coreutils + jq + cloud-guest-utils + e2fsprogs + zstd"
    exit 2
fi

output_dir="$(cd "$(dirname "${output_dir}")" 2>/dev/null && pwd)/$(basename "${output_dir}")"
mkdir -p "${output_dir}"
WORK_DIR="$(mktemp -d -t hippius-rootfs-build.XXXXXX)"
log "work dir: ${WORK_DIR}"

# ── 1. Fetch + verify base image ────────────────────────────────────

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
        curl -fsSL --retry 3 --retry-delay 2 -o "${src_qcow2}" "${base_image_url}" \
            || die "curl failed (exit 3)"
        ;;
esac

actual="$(sha256sum "${src_qcow2}" | cut -d' ' -f1)"
if [[ "${actual}" != "${base_image_sha256}" ]]; then
    die "sha256 mismatch: expected ${base_image_sha256}, got ${actual} (exit 3)"
fi
log "base image verified (sha256=${base_image_sha256})"

# ── 2. Convert to raw + grow + losetup ─────────────────────────────

HCC_BAKE_SRC_GROW_GB="${HCC_BAKE_SRC_GROW_GB:-4}"

src_raw="${WORK_DIR}/base.raw"
log "qemu-img convert qcow2 → raw"
qemu-img convert -O raw "${src_qcow2}" "${src_raw}" \
    || die "qemu-img convert failed (exit 3)"
log "qemu-img resize +${HCC_BAKE_SRC_GROW_GB} GiB"
qemu-img resize -f raw "${src_raw}" "+${HCC_BAKE_SRC_GROW_GB}G" >/dev/null \
    || die "qemu-img resize failed (exit 3)"

LOOP_DEV="$(sudo losetup --find --show --partscan "${src_raw}")"
log "loop device: ${LOOP_DEV}"
sleep 1

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
log "root partition: ${root_part} (#${root_part_num})"

log "growpart ${LOOP_DEV} ${root_part_num}"
sudo growpart "${LOOP_DEV}" "${root_part_num}" 2>&1 | sed 's/^/growpart: /' || true
sudo partprobe "${LOOP_DEV}" 2>/dev/null || true
sleep 1
sudo e2fsck -fy "${root_part}" 2>&1 | tail -2 || true
sudo resize2fs "${root_part}" 2>&1 | tail -2 || true

# ── 3. Mount + bind virtual filesystems ─────────────────────────────

MNT_ROOT="${WORK_DIR}/mnt"
mkdir -p "${MNT_ROOT}"
sudo mount "${root_part}" "${MNT_ROOT}" || die "mount root failed (exit 3)"
for vfs in dev dev/pts proc sys run; do
    sudo mkdir -p "${MNT_ROOT}/${vfs}"
    sudo mount --bind "/${vfs}" "${MNT_ROOT}/${vfs}" || die "bind /${vfs} failed (exit 3)"
done

# ── 4. Stage Hippius tooling ────────────────────────────────────────

log "staging Hippius tooling into the image"
sudo install -d -m 0755 "${MNT_ROOT}/etc/hippius"
sudo install -m 0644 "${KEYSCRIPT_SRC}" "${MNT_ROOT}/etc/hippius/hippius-luks-keyscript"
sudo install -m 0755 "${NET_TEARDOWN_SRC}" "${MNT_ROOT}/etc/hippius/hippius-net-teardown"
sudo install -d -m 0755 "${MNT_ROOT}/etc/initramfs-tools/hooks"
sudo install -m 0755 "${HOOK_SRC}" "${MNT_ROOT}/etc/initramfs-tools/hooks/hippius-luks"
sudo install -d -m 0755 "${MNT_ROOT}/usr/sbin"
sudo install -m 0755 "${hippius_release_bin}" "${MNT_ROOT}/usr/sbin/hippius-guest-release"
sudo install -m 0755 "${hippius_vsock_bin}" "${MNT_ROOT}/usr/sbin/hippius-vsock-ticket"

sudo tee "${MNT_ROOT}/etc/apt/apt.conf.d/99force-ipv4" >/dev/null <<'EOF'
Acquire::ForceIPv4 "true";
EOF

# `IP=dhcp` only when the keyscript reaches KBS over the network
# (http/https). A `vsock://` KBS transport needs NO initramfs network;
# adding DHCP there just leaves a second lingering lease on the NIC
# (the #289 double-IP), so skip it for vsock images.
case "${kbs_url}" in
    vsock://*)
        printf 'tenant-rootfs-build: kbs_url is vsock — skipping initramfs IP=dhcp\n' >&2
        ;;
    *)
        if [[ -f "${MNT_ROOT}/etc/initramfs-tools/initramfs.conf" ]]; then
            if ! sudo grep -q '^IP=' "${MNT_ROOT}/etc/initramfs-tools/initramfs.conf"; then
                echo 'IP=dhcp' | sudo tee -a "${MNT_ROOT}/etc/initramfs-tools/initramfs.conf" >/dev/null
            fi
        fi
        ;;
esac

sudo tee "${MNT_ROOT}/etc/crypttab" >/dev/null <<'EOF'
# hippius-bake-managed; cryptroot maps /dev/vda → /dev/mapper/cryptroot
cryptroot /dev/vda none luks,discard,header=/run/hippius/luks.header,keyscript=/sbin/hippius-luks-keyscript
EOF

sudo tee "${MNT_ROOT}/etc/fstab" >/dev/null <<'EOF'
/dev/mapper/cryptroot / ext4 errors=remount-ro 0 1
EOF

# ── 4b. Chroot install ──────────────────────────────────────────────

log "chroot: apt install (SOURCE_DATE_EPOCH=${source_date_epoch})"
sudo mkdir -p "${MNT_ROOT}/var/cache/apt/archives"
sudo mount -t tmpfs -o size=2G tmpfs "${MNT_ROOT}/var/cache/apt/archives"
sudo chroot "${MNT_ROOT}" /bin/bash -se <<CHROOT_EOF
set -eu
export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export SOURCE_DATE_EPOCH=${source_date_epoch}
export LC_ALL=C
export LANG=C
export LANGUAGE=C
export TZ=UTC

apt-get update
apt-get install -y --no-install-recommends \
    cryptsetup cryptsetup-initramfs initramfs-tools \
    linux-image-virtual \
    curl ca-certificates \
    udhcpc isc-dhcp-client iproute2

KVER_PKG=\$(dpkg-query -W -f='\${Depends}' linux-image-virtual 2>/dev/null | tr ',' '\\n' | awk '{print \$1}' | grep -E '^linux-image-[0-9]' | sed 's/^linux-image-//' | sort -V | tail -1)
if [ -n "\${KVER_PKG:-}" ]; then
    apt-get install -y --no-install-recommends \
        "linux-modules-extra-\${KVER_PKG}" || true
fi

# NetBird pre-install (held-curl first-boot fix — see tenant-image-bake.sh
# for the full rationale). Installed HERE, in the measured chroot, at the
# PINNED ${netbird_version}; curl/ca-certificates are present but not yet
# held, so apt resolves netbird's deps cleanly. apt accepts an armored
# keyring in signed-by= (no gnupg dependency). First-boot userdata is
# reduced to just \`netbird up\`.
install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://pkgs.netbird.io/debian/public.key -o /etc/apt/keyrings/netbird.asc
chmod 0644 /etc/apt/keyrings/netbird.asc
echo 'deb [signed-by=/etc/apt/keyrings/netbird.asc] https://pkgs.netbird.io/debian stable main' \
    > /etc/apt/sources.list.d/netbird.list
apt-get update
apt-get install -y --no-install-recommends "netbird=${netbird_version}"
# The netbird deb postinst installs AND STARTS the daemon; a running netbird
# holds the build mountpoint and makes teardown umount fail "target is busy".
# Stop the transient build-time daemon (systemd unit stays enabled for boot).
netbird service stop >/dev/null 2>&1 || true
pkill -x netbird 2>/dev/null || true
command -v netbird >/dev/null 2>&1 || { echo "FATAL: netbird binary absent after install (pin ${netbird_version})" >&2; exit 3; }
# Wipe the build-time NetBird identity/state so each guest mints a FRESH
# keypair on first `netbird up` — else every VM from this image collides
# onto ONE NetBird peer/overlay-IP.
rm -rf /var/lib/netbird/* /etc/netbird/*.json 2>/dev/null || true

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
# virtio_net/virtio_pci pinned so the NIC is in the initrd regardless of
# IP=dhcp (see tenant-image-bake.sh for the rationale — the vsock double-IP
# fix removes IP=dhcp, and without pinning that would drop the NIC driver).

mkdir -p /etc/cryptsetup-initramfs
{
    echo 'CRYPTSETUP=y'
    echo 'KEYFILE_PATTERN='
} > /etc/cryptsetup-initramfs/conf-hook

update-initramfs -u -k all

apt-mark hold \\
    cryptsetup cryptsetup-initramfs initramfs-tools \\
    linux-image-virtual \\
    curl ca-certificates \\
    udhcpc isc-dhcp-client iproute2 \\
    netbird \\
    || true
if [ -n "\${KVER_PKG:-}" ]; then
    apt-mark hold "linux-modules-extra-\${KVER_PKG}" || true
fi

apt-get clean
CHROOT_EOF

sudo umount "${MNT_ROOT}/var/cache/apt/archives" || true

log "chroot install complete; root partition customised"

# ── 5. Extract kernel + initrd ──────────────────────────────────────

kernel_src=$(sudo bash -c "ls ${MNT_ROOT}/boot/vmlinuz-* 2>/dev/null | grep -v '\.signed$' | sort -V | tail -1")
initrd_src=$(sudo bash -c "ls ${MNT_ROOT}/boot/initrd.img-* 2>/dev/null | sort -V | tail -1")
[[ -n "${kernel_src}" ]] || die "no /boot/vmlinuz-* in image (exit 3)"
[[ -n "${initrd_src}" ]] || die "no /boot/initrd.img-* in image (exit 3)"
sudo cp "${kernel_src}" "${output_dir}/vmlinuz"
sudo cp "${initrd_src}" "${output_dir}/initrd.img"
sudo chmod 0644 "${output_dir}/vmlinuz" "${output_dir}/initrd.img"
sudo chown "$(id -u):$(id -g)" "${output_dir}/vmlinuz" "${output_dir}/initrd.img"
log "kernel + initrd extracted"

# ── 6. Tarball the customised rootfs ────────────────────────────────
#
# Unbind virtual filesystems FIRST so they don't end up in the tar.
# We re-mount the rootfs alone to be safe.

for vfs in run sys proc dev/pts dev; do
    sudo umount -l "${MNT_ROOT}/${vfs}" 2>/dev/null || true
done

log "tarring customised root → rootfs.tar.zst (reproducible; SOURCE_DATE_EPOCH=${source_date_epoch})"
# `--sort=name` + `--mtime` + zstd's `--no-content-size` keep the
# tarball byte-stable across reproducible bakes.
sudo tar --sort=name \
    --mtime="@${source_date_epoch}" \
    --numeric-owner \
    --xattrs \
    --acls \
    --selinux \
    -C "${MNT_ROOT}" \
    -cf - . \
    | zstd -T0 --no-content-size -19 \
    | sudo tee "${output_dir}/rootfs.tar.zst" >/dev/null
sudo chown "$(id -u):$(id -g)" "${output_dir}/rootfs.tar.zst"

sudo umount "${MNT_ROOT}" || die "umount root failed (exit 3)"
sudo losetup -d "${LOOP_DEV}" || true
LOOP_DEV=""

# ── 7. Manifest ─────────────────────────────────────────────────────

rootfs_sha=$(sha256sum "${output_dir}/rootfs.tar.zst" | cut -d' ' -f1)
rootfs_bytes=$(stat -c '%s' "${output_dir}/rootfs.tar.zst")
kernel_sha=$(sha256sum "${output_dir}/vmlinuz" | cut -d' ' -f1)
initrd_sha=$(sha256sum "${output_dir}/initrd.img" | cut -d' ' -f1)
hippius_release_sha=$(sha256sum "${hippius_release_bin}" | cut -d' ' -f1)
hippius_vsock_sha=$(sha256sum "${hippius_vsock_bin}" | cut -d' ' -f1)

manifest_json="${output_dir}/manifest.json"
jq -n \
    --arg base_url "${base_image_url}" \
    --arg base_sha "${base_image_sha256}" \
    --arg flavor "${flavor}" \
    --arg kbs "${kbs_url}" \
    --arg rootfs_sha "${rootfs_sha}" \
    --argjson rootfs_bytes "${rootfs_bytes}" \
    --arg kernel_sha "${kernel_sha}" \
    --arg initrd_sha "${initrd_sha}" \
    --arg release_sha "${hippius_release_sha}" \
    --arg vsock_sha "${hippius_vsock_sha}" \
    --argjson sde "${source_date_epoch}" \
    '{
        schema_version: 1,
        kind: "hippius-rootfs-build",
        base_image_url: $base_url,
        base_image_sha256: $base_sha,
        flavor: $flavor,
        kbs_url: $kbs,
        rootfs_tar_zst_sha256: $rootfs_sha,
        rootfs_tar_zst_size_bytes: $rootfs_bytes,
        kernel_sha256: $kernel_sha,
        initrd_sha256: $initrd_sha,
        hippius_release_bin_sha256: $release_sha,
        hippius_vsock_bin_sha256: $vsock_sha,
        source_date_epoch: $sde
     }' > "${manifest_json}"

cat "${manifest_json}"

# ── 8. (Optional) Detached Ed25519 signature over manifest.json ────
# Codex / Gemini audit finding #2 — the shared rootfs.tar.zst lives
# in S3 indefinitely as a SHARED artifact across tenants. Without a
# manifest sig, an S3 admin can swap (tarball, kernel, initrd,
# manifest) atomically; Stage 2's SHA check passes against the
# attacker's manifest, so the SEV-SNP measurement still verifies
# (same kernel + initrd), but userspace runs the attacker's rootfs.
# When `--signing-key` is set we emit `manifest.json.sig`; Stage 2's
# `--verify-pubkey-hex` pins the matching public key out-of-band and
# refuses to extract if the sig fails.
if [[ -n "${signing_key}" ]]; then
    manifest_sig="${manifest_json}.sig"
    log "signing manifest with ${signing_key}"
    "${SCRIPT_DIR}/sign-manifest.py" sign \
        --manifest "${manifest_json}" \
        --signing-key "${signing_key}" \
        --out "${manifest_sig}" \
        || die "manifest signing failed (exit 3)"
    log "manifest.sig: ${manifest_sig}"
fi

log "rootfs:       ${output_dir}/rootfs.tar.zst (${rootfs_bytes} bytes)"
log "vmlinuz:      ${output_dir}/vmlinuz"
log "initrd.img:   ${output_dir}/initrd.img"
log "manifest:     ${manifest_json}"
log "STAGE 1 OK — feed manifest + tarball into tenant-image-from-rootfs.sh"
