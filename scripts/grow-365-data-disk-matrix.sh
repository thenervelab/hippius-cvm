#!/usr/bin/env bash
# #365 — regression matrix for the tenant data-disk primitive.
#
# Validates the security-critical operations the guest's first-boot
# `hippius-data-disk-init` (baked by scripts/tenant-image-bake.sh)
# relies on, on a loopback stand-in for /dev/vde:
#
#   fresh `cryptsetup luksFormat --type luks2 --integrity hmac-sha256`
#   → mkfs.ext4 → mount → write → reboot (close/reopen) → fsck + verify
#   → tamper an unwritten region → guest read must EIO (fail-closed).
#
# This is the supported replacement for the abandoned grow-by-resize
# plan: `cryptsetup resize` refuses LUKS2+integrity volumes outright, so
# the data disk is formatted FRESH at the flavor size, never grown. See
# docs/design/grow-at-first-boot-365.md.
#
# Run on a host with cryptsetup 2.x + dm-integrity (root required):
#   sudo bash scripts/grow-365-data-disk-matrix.sh
set -eu
D=$(mktemp -d "${TMPDIR:-/tmp}/grow365.XXXX"); cd "$D"
KEY=$(printf 'data-disk-guest-key-32-bytes!!!!' | head -c32); printf '%s' "$KEY" > key.bin
SZ_MB=1024; truncate -s ${SZ_MB}M data.img; N=grow365d

echo "== full-wipe luksFormat --integrity hmac-sha256 (${SZ_MB} MiB) =="
T0=$(cut -d. -f1 /proc/uptime)
cryptsetup luksFormat --type luks2 --integrity hmac-sha256 \
  --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 -d key.bin data.img
T1=$(cut -d. -f1 /proc/uptime)
DT=$((T1-T0)); [ $DT -lt 1 ] && DT=1
echo "RESULT wipe_seconds=${DT} for ${SZ_MB}MiB -> ~$(( SZ_MB / DT )) MiB/s ; 256GiB wipe ~$(( 262144 * DT / SZ_MB ))s"

cryptsetup open -d key.bin data.img $N
mkfs.ext4 -q -F /dev/mapper/$N
mkdir -p mnt; mount /dev/mapper/$N mnt
echo "FRESH-MOUNT-OK"
echo "tenant-canary" > mnt/canary.txt
dd if=/dev/zero bs=1M count=300 of=mnt/big 2>/dev/null; sync
echo "WROTE-300MB-OK"
umount mnt; cryptsetup close $N

echo "== reboot sim: reopen + fsck + verify =="
cryptsetup open -d key.bin data.img $N
e2fsck -fn /dev/mapper/$N >/dev/null 2>&1 && echo "FSCK-CLEAN-OK" || echo "FSCK-FAILED"
mount /dev/mapper/$N mnt
[ "$(cat mnt/canary.txt)" = "tenant-canary" ] && echo "CANARY-OK" || echo "CANARY-LOST"
[ -s mnt/big ] && echo "PAYLOAD-OK" || echo "PAYLOAD-LOST"
umount mnt; cryptsetup close $N

echo "== tamper unwritten region -> expect EIO (fail-closed) =="
printf '\xde\xad\xbe\xef' | dd of=data.img bs=1 seek=$(( (SZ_MB-20)*1024*1024 )) conv=notrunc 2>/dev/null
cryptsetup open -d key.bin data.img $N
if dd if=/dev/mapper/$N of=/dev/null bs=512 skip=$(( (SZ_MB-15)*1024*1024/512 )) count=8 2>/dev/null; then
  echo "TAMPER-NOT-CAUGHT (read returned) — FAIL"
else
  echo "TAMPER-EIO-OK (fail-closed)"
fi
cryptsetup close $N
cd /; find "$D" -mindepth 1 -delete; rmdir "$D"
echo "==== DONE ===="
