#!/usr/bin/env bash
#
# REAL dm-integrity end-to-end for the golden per-VM upper — the part
# `golden-upper-init-test.sh` can only mock. Needs root (loop devices,
# device-mapper): run by the `golden-integrity` workflow on a GitHub-hosted
# runner (passwordless sudo), never on a miner.
#
# Drives the SHIPPED `hippius_golden_open_upper` from
# `scripts/initramfs/hippius-golden-overlay.sh` against a loop device with
# the real cryptsetup and the real `hippius-guest-release --integrity-wipe`,
# and checks what the unit tests can only argue:
#
#   1. first boot: LUKS2 + hmac(sha256) integrity, 4096-byte sectors,
#      ready label; a FULL read-back of the mapping succeeds (every sector
#      carries a valid tag) with zero verification failures in the kernel log
#      at ANY point of the init (udev is paused around the wipe);
#   2. reboot: the volume is reopened, not reformatted (a sentinel survives);
#   3. a host-side ciphertext change reads back EILSEQ;
#   4. interrupted first boot (init label, never wiped): expectation 0 ⇒
#      formatted again and fully readable; expectation 1 ⇒ fail-closed and
#      the header is left alone;
#   5. the wiper refuses a mapping that is in use (O_EXCL);
#   6. #1347: the data bind is the guest-keyed ext4 (not overlay), hides
#      the volume root (stamp) from both the merged root and the bind,
#      carries an overlay whose upperdir lives under it (what containerd's
#      snapshotter mounts), and is rebound with its data on reboot.
#
# Usage: sudo WIPE_BIN=/path/to/hippius-guest-release bash golden-integrity-e2e.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LIB="${HERE}/../initramfs/hippius-golden-overlay.sh"
: "${WIPE_BIN:?set WIPE_BIN to the hippius-guest-release binary}"
[ "$(id -u)" -eq 0 ] || { echo "golden-integrity-e2e: needs root" >&2; exit 1; }
# Without a running udevd, "zero verification failures" would pass without
# exercising the udev pause at all.
udevadm control --ping || { echo "golden-integrity-e2e: udevd not running — the udev-pause claim would be untested" >&2; exit 1; }
SIZE_MB="${SIZE_MB:-2048}"

fail=0
ok()  { echo "golden-integrity-e2e: OK — $*"; }
err() { echo "golden-integrity-e2e: FAIL — $*" >&2; fail=1; }

WORK="$(mktemp -d)"
LOOPS=()
MAPPER=hippius-upper
cleanup() {
    # A run killed mid-wipe must not leave the host's udev paused.
    udevadm control --start-exec-queue 2>/dev/null || true
    umount "${WORK}/droot/var/lib/hippius-data/snap/m" "${WORK}/droot/snap/m" 2>/dev/null || true
    umount "${WORK}/droot/var/lib/hippius-data" 2>/dev/null || true
    umount "${WORK}/droot" 2>/dev/null || true
    umount "${WORK}/dv" 2>/dev/null || true
    umount "${WORK}/mnt" 2>/dev/null || true
    cryptsetup close "${MAPPER}" 2>/dev/null || true
    for l in "${LOOPS[@]}"; do losetup -d "$l" 2>/dev/null || true; done
    rm -rf "${WORK}"
}
trap cleanup EXIT

new_loop() {
    truncate -s "${SIZE_MB}M" "${WORK}/$1.img"
    losetup -f --show "${WORK}/$1.img"
}
# Kernel lines that mean a sector failed verification (dm-crypt AEAD /
# dm-integrity checksum). `dmesg` line count is the cursor.
KMSG_ERR='INTEGRITY AEAD ERROR|[Cc]hecksum failed'
dmesg_mark() { dmesg | wc -l; }
dmesg_errors_since() { dmesg | tail -n +"$(( $1 + 1 ))" | grep -E "${KMSG_ERR}" || true; }

# The initramfs environment the library expects.
head -c 32 /dev/urandom > "${WORK}/kek"
chmod 0600 "${WORK}/kek"
export HIPPIUS_GOLDEN_STAMP_EXPECTED="${WORK}/expected"
export HIPPIUS_GOLDEN_WIPE_BIN="${WIPE_BIN}"
export HIPPIUS_GOLDEN_MKFS="${WORK}/no-private-mkfs"   # use mkfs.ext4 from PATH

# Run `hippius_golden_open_upper` in a subshell exactly as the golden driver
# does. $1 = upper device, $2 = KBS expectation. Returns its exit code.
open_upper() {
    printf '%s\n' "$2" > "${HIPPIUS_GOLDEN_STAMP_EXPECTED}"
    (
        hippius_log() { echo "  [lib] $*"; }
        hippius_die() { echo "  [lib] DIE: $*" >&2; exit 1; }
        # shellcheck source=scripts/initramfs/hippius-golden-overlay.sh
        . "${LIB}"
        # shellcheck disable=SC2034  # read by the sourced library
        HIPPIUS_GOLDEN_UPPER="$1"
        # shellcheck disable=SC2034
        HIPPIUS_GOLDEN_DISK_GB=1
        hippius_golden_open_upper "${WORK}/kek"
    )
}
dump() { cryptsetup luksDump "$1"; }
label_of() { dump "$1" | sed -n 's/^Label:[[:space:]]*//p'; }
full_read() { dd if="/dev/mapper/${MAPPER}" of=/dev/null bs=16M iflag=direct status=none 2>"${WORK}/rd"; }

# ── 1. first boot ────────────────────────────────────────────────────
A="$(new_loop a)"; LOOPS+=("$A")
mark0="$(dmesg_mark)"
t0="$(date +%s.%N)"
open_upper "$A" 0 || { err "first boot failed"; exit 1; }
t1="$(date +%s.%N)"
echo "golden-integrity-e2e: first boot of ${SIZE_MB} MiB took $(echo "$t1 - $t0" | bc) s"
[ "$(label_of "$A")" = hippius-upper ] && ok "first boot: ready label" || err "label is '$(label_of "$A")'"
dump "$A" | grep -qE '^[[:space:]]*sector:[[:space:]]*4096' && ok "4096-byte sectors" || err "sector size not 4096: $(dump "$A" | grep -i sector)"
dump "$A" | grep -qE 'integrity:[[:space:]]*hmac\(sha256\)' && ok "hmac(sha256) integrity" || err "integrity not hmac(sha256)"
# Zero verification failures across the WHOLE first boot — including the
# window before the wipe, where udev would probe the fresh mapping if the
# library did not pause it — and the full read-back after it.
if full_read; then ok "full read-back of the whole mapping succeeds"; else err "full read-back failed: $(cat "${WORK}/rd")"; fi
new_errs="$(dmesg_errors_since "${mark0}")"
[ -z "${new_errs}" ] && ok "zero verification failures during first boot and the read-back" || err "the kernel logged verification failures:
$(printf '%s\n' "${new_errs}" | head -n 20)"

mkdir -p "${WORK}/mnt"
mount "/dev/mapper/${MAPPER}" "${WORK}/mnt"
echo sentinel > "${WORK}/mnt/sentinel"
# ── 5. the wiper refuses a mapping in use ────────────────────────────
if "${WIPE_BIN}" --integrity-wipe "/dev/mapper/${MAPPER}" 2>"${WORK}/w"; then
    err "wiper overwrote a MOUNTED mapping"
else
    rc=$?
    [ "${rc}" -eq 4 ] && ok "wiper refuses a mounted mapping (O_EXCL, exit 4)" || err "wiper exit ${rc}: $(cat "${WORK}/w")"
fi
[ "$(cat "${WORK}/mnt/sentinel")" = sentinel ] || err "sentinel damaged by the refused wipe"
umount "${WORK}/mnt"
cryptsetup close "${MAPPER}"

# ── 2. reboot: reopen, not reformat ──────────────────────────────────
open_upper "$A" 1 || err "reopen failed"
mount -o ro "/dev/mapper/${MAPPER}" "${WORK}/mnt"
[ "$(cat "${WORK}/mnt/sentinel" 2>/dev/null)" = sentinel ] && ok "reboot reopens the volume (sentinel intact)" || err "sentinel lost on reopen"
umount "${WORK}/mnt"
cryptsetup close "${MAPPER}"

# ── 6. #1347: the non-overlay data path, on the real kernel ──────────
# The shipped `hippius_golden_bind_data` on the real guest-keyed volume,
# after an overlay root assembled with the SAME options as
# `hippius_golden_mount_overlay` (its dm-verity lower is out of scope here:
# a plain directory with the /var/lib every lower ships stands in).
DV="${WORK}/dv"            # volume root (the library's HIPPIUS_GOLDEN_UPPER_MNT)
DL="${WORK}/dl"            # stand-in lower
DR="${WORK}/droot"         # tenant root (${rootmnt})
DATA="${DR}/var/lib/hippius-data"
mkdir -p "${DV}" "${DL}/var/lib" "${DR}"
data_boot() {
    # Every step `|| return 1`: errexit is off inside an `if` condition.
    open_upper "$A" 1 || return 1
    mount "/dev/mapper/${MAPPER}" "${DV}" || return 1
    printf '1\n' > "${DV}/.hippius-volume-stamp" || return 1
    mkdir -p "${DV}/upper" "${DV}/work" || return 1
    mount -t overlay hippius-overlay \
        -o "lowerdir=${DL},upperdir=${DV}/upper,workdir=${DV}/work" "${DR}" || return 1
    (
        hippius_log() { echo "  [lib] $*"; }
        hippius_die() { echo "  [lib] DIE: $*" >&2; exit 1; }
        # shellcheck source=scripts/initramfs/hippius-golden-overlay.sh
        . "${LIB}"
        # shellcheck disable=SC2034  # read by the sourced library
        HIPPIUS_GOLDEN_UPPER_MNT="${DV}"
        # shellcheck disable=SC2034
        HIPPIUS_GOLDEN_LOWER_MNT="${DL}"
        hippius_golden_bind_data "${DR}"
    )
}
data_shutdown() {
    umount "${DATA}" 2>/dev/null || true
    umount "${DR}" 2>/dev/null || true
    umount "${DV}" 2>/dev/null || true
    cryptsetup close "${MAPPER}" 2>/dev/null || true
}
if data_boot; then
    [ "$(findmnt -no FSTYPE --mountpoint "${DATA}")" = ext4 ] && [ "$(findmnt -no FSTYPE --mountpoint "${DR}")" = overlay ] \
        && ok "data path: ${DATA#"${DR}"} is the guest-keyed ext4 (not overlay) inside the overlay root" \
        || err "data path: fstype '$(findmnt -no FSTYPE --mountpoint "${DATA}")' (root '$(findmnt -no FSTYPE --mountpoint "${DR}")')"
    [ ! -e "${DR}/.hippius-volume-stamp" ] && [ ! -e "${DATA}/.hippius-volume-stamp" ] \
        && [ ! -e "${DATA}/../.hippius-volume-stamp" ] && [ ! -e "${DATA}/../upper" ] \
        && [ "$(cd "${DATA}/.." && pwd -P)" = "${DR}/var/lib" ] \
        && ok "data path: the stamp is reachable neither from the merged root nor through the bind (.. is the tenant's /var/lib)" \
        || err "data path: the volume root leaks through the merged root or the bind"
    # What containerd's overlayfs snapshotter does: an overlay whose
    # upperdir/workdir live under the data path.
    mkdir -p "${DATA}/snap/l" "${DATA}/snap/u" "${DATA}/snap/w" "${DATA}/snap/m"
    echo layer > "${DATA}/snap/l/f"
    if mount -t overlay snap -o "lowerdir=${DATA}/snap/l,upperdir=${DATA}/snap/u,workdir=${DATA}/snap/w" "${DATA}/snap/m"; then
        echo written > "${DATA}/snap/m/f"
        [ "$(cat "${DATA}/snap/u/f")" = written ] \
            && ok "data path: an overlay with its upperdir under ${DATA#"${DR}"} mounts and writes (container snapshots work)" \
            || err "data path: nested overlay write did not land in its upperdir"
        umount "${DATA}/snap/m"
    else
        err "data path: an overlay with its upperdir under ${DATA#"${DR}"} was refused"
    fi
    # Informational: the premise of #1347 on this kernel.
    mkdir -p "${DR}/snap/u" "${DR}/snap/w" "${DR}/snap/m"
    if mount -t overlay snap -o "lowerdir=${DL},upperdir=${DR}/snap/u,workdir=${DR}/snap/w" "${DR}/snap/m" 2>/dev/null; then
        echo "golden-integrity-e2e: note — this kernel accepted an upperdir on the overlay root"
        umount "${DR}/snap/m"
    else
        echo "golden-integrity-e2e: note — this kernel refuses an upperdir on the overlay root (the #1347 premise)"
    fi
    echo kept > "${DATA}/sentinel"
    [ "$(stat -c '%a %u' "${DV}/data")" = "755 0" ] \
        && ok "data path: data/ is 0755 root on the volume root" \
        || err "data path: data/ is '$(stat -c '%a %u' "${DV}/data")'"
else
    err "data path: first boot of the bind failed"
fi
data_shutdown
if data_boot; then
    [ "$(cat "${DATA}/sentinel" 2>/dev/null)" = kept ] && [ "$(findmnt -no FSTYPE --mountpoint "${DATA}")" = ext4 ] \
        && ok "data path: reboot rebinds the same data (sentinel intact)" \
        || err "data path: data lost or not rebound on reboot"
else
    err "data path: second boot of the bind failed"
fi
data_shutdown

# ── 3. host-side tamper ⇒ EILSEQ ─────────────────────────────────────
# 64 KiB of random bytes at 1 GiB into the raw device: data area, far past
# the LUKS2 header and the dm-integrity superblock/journal.
dd if=/dev/urandom of="$A" bs=64K count=1 seek=$((1024 * 16)) conv=notrunc status=none
cryptsetup open "$A" "${MAPPER}" --key-file "${WORK}/kek"
if full_read; then
    err "tampered ciphertext read back as valid"
elif grep -q 'Invalid or incomplete multibyte' "${WORK}/rd"; then
    ok "host-side tamper reads back EILSEQ"
else
    err "tamper read failed, but not with EILSEQ: $(cat "${WORK}/rd")"
fi
cryptsetup close "${MAPPER}"

# ── 4. interrupted first boot ────────────────────────────────────────
# A header with the init label and no wipe — what a reset right after
# luksFormat leaves behind.
interrupted() {
    cryptsetup luksFormat --type luks2 --integrity hmac-sha256 --integrity-no-wipe \
        --sector-size 4096 --label hippius-upper-init --batch-mode "$1" --key-file "${WORK}/kek"
}
B="$(new_loop b)"; LOOPS+=("$B")
interrupted "$B"
uuid_before="$(cryptsetup luksUUID "$B")"
if open_upper "$B" 1; then
    err "init label + expectation 1 was reformatted"
    cryptsetup close "${MAPPER}" 2>/dev/null || true
else
    [ "$(cryptsetup luksUUID "$B")" = "${uuid_before}" ] && [ "$(label_of "$B")" = hippius-upper-init ] \
        && ok "init label + expectation 1: fail-closed, header untouched" \
        || err "init label + expectation 1: header changed"
fi
mark2="$(dmesg_mark)"
if open_upper "$B" 0; then
    [ "$(cryptsetup luksUUID "$B")" != "${uuid_before}" ] && ok "interrupted first boot: formatted again (new header)" || err "re-init kept the old header"
    [ "$(label_of "$B")" = hippius-upper ] || err "re-init did not end with the ready label"
    if full_read; then ok "re-initialised volume fully readable"; else err "re-init read-back failed: $(cat "${WORK}/rd")"; fi
    new_errs="$(dmesg_errors_since "${mark2}")"
    [ -z "${new_errs}" ] && ok "zero verification failures during the re-init" || err "re-init logged verification failures:
$(printf '%s\n' "${new_errs}" | head -n 20)"
    cryptsetup close "${MAPPER}"
else
    err "interrupted first boot with expectation 0 failed"
fi

[ "${fail}" -eq 0 ] && echo "golden-integrity-e2e: OK (all checks passed)" || exit 1
