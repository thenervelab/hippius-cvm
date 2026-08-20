#!/bin/sh
# `hippius-golden-mount` — RHEL-family (dracut) GOLDEN-mode root assembler
# (dracut module 95hippius-golden). Invoked by
# `hippius-golden-mount.service` (Before=initrd-root-fs.target); the
# dracut analogue of the Debian-family initramfs-tools `hippius-golden-
# boot::mountroot`.
#
# It drives the SHARED, family-agnostic `hippius-golden-overlay.sh::
# hippius_golden_run /sysroot` — the SAME assembly the proven Debian
# golden boot runs, byte-for-byte:
#   1. verify-BEFORE-network: dm-verity-open the RO golden lower (vdb/vdc)
#      from the MEASURED `dm-verity.root=` + assert VERITY-type AND
#      read-only, BEFORE any KBS/KEK contact — a tampered base fails
#      closed here without ever contacting the KBS;
#   2. the §21 KBS release (net → ticket → anti-rollback → userdata →
#      per-VM KEK) via the audited `hippius_acquire`;
#   3. first-boot `luksFormat --integrity` the blank per-VM `/dev/vda`
#      upper (MK generated in-guest, keyslot = the KBS KEK, size-anchored
#      to the measured `hippius.disk_gb`) → open → mkfs.ext4;
#   4. overlayfs mount (RO verity golden lower + guest-keyed upper) at
#      /sysroot;
#   5. KEK shred on ANY exit path (success or fail-closed).
#
# On dracut, `/sysroot` is the pivot root: once this oneshot completes,
# `initrd-root-fs.target` is satisfied (this unit is Before= it +
# RequiredBy= it) and systemd proceeds to switch-root into the overlay.
#
# §20: the KEK plaintext touches only a tmpfs 0600 keyfile between the
# release and the upper open; the overlay lib shreds it on every path.
# This runner adds nothing security-relevant — all the load-bearing
# logic is in the shared library.

set -eu

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

HIPPIUS_LOG_TAG="hippius-golden-mount"

CORE=/lib/hippius/hippius-release-core.sh
OVERLAY=/lib/hippius/hippius-golden-overlay.sh
for f in "$CORE" "$OVERLAY"; do
    if [ ! -r "$f" ]; then
        printf 'hippius-golden-mount: FATAL: %s not staged (module-setup bug); rebake the image\n' "$f" >&2
        exit 1
    fi
done
# shellcheck source=scripts/initramfs/hippius-release-core.sh
. "$CORE"
# shellcheck source=scripts/initramfs/hippius-golden-overlay.sh
. "$OVERLAY"

# Defense-in-depth: refuse to assemble the overlay if the cmdline does
# NOT actually signal golden (a mis-enabled module on a legacy VM must
# fail closed, never silently overlay-mount over a legacy root).
hippius_is_golden_mode || hippius_die "hippius-golden-mount: boot cmdline is not golden — fail-closed"

# Assemble dm-verity lower + guest-keyed overlay upper at /sysroot; the
# shared driver fails closed (poweroff via the unit's FailureAction) on
# any tamper / KBS denial / size-anchor miss, shredding the KEK.
hippius_golden_run /sysroot

exit 0
