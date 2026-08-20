#!/bin/bash
# dracut module `95hippius-golden` — the RHEL-family (CentOS Stream 10 /
# Fedora) GOLDEN-mode boot module. It is the dracut counterpart of the
# Debian-family initramfs-tools golden pair
# (`hippius-golden-boot` + `hippius-golden-hook`): it OWNS `/sysroot`
# assembly in `disk_mode=golden_verity_overlay` bakes instead of the
# stock `root=`→systemd-cryptsetup path.
#
# Installed into the guest image at
# `/usr/lib/dracut/modules.d/95hippius-golden/` by
# `scripts/tenant-image-bake.sh` (RHEL arm, golden mode only), then baked
# into the initrd by `dracut --force` via the
# `/etc/dracut.conf.d/95-hippius-golden.conf` drop-in
# (`add_dracutmodules+=" hippius-golden "`). In golden mode the legacy
# `90hippius-luks` module is NOT included (see the bake) so the KBS
# release happens EXACTLY once (a second release would spend the
# single-use, nonce-bound §21 ticket and fail closed).
#
# ═══════════════════════════════════════════════════════════════════
# WHY A DRACUT MODULE (the boot-model difference vs initramfs-tools)
# ═══════════════════════════════════════════════════════════════════
# initramfs-tools selects a boot script via the measured `boot=hippius-
# golden` cmdline token and that script's `mountroot` owns root assembly.
# dracut has no `boot=` mechanism, and the golden measured cmdline
# carries NO `root=` (the golden base is an overlay the guest assembles,
# not a block device systemd can mount). So this module:
#
#   1. a `cmdline` hook (`parse-hippius-golden.sh`) sets `rootok=1` when
#      the measured cmdline signals golden — this tells dracut a root
#      handler exists so it does NOT emergency on the (deliberately
#      absent) `root=` token. Same mechanism `90dmsquash-live` uses for
#      `root=live:...`.
#   2. `hippius-golden-mount.service` runs `/sbin/hippius-golden-mount`,
#      which drives the SHARED, family-agnostic
#      `hippius-golden-overlay.sh::hippius_golden_run /sysroot`
#      (verify-before-network: dm-verity-open the RO golden lower + assert
#      VERITY/RO BEFORE any KBS contact → §21 KBS KEK release → first-boot
#      luksFormat --integrity the blank per-VM upper → overlayfs mount at
#      /sysroot). The unit is ordered `Before=initrd-root-fs.target` and
#      enabled `RequiredBy=initrd-root-fs.target`, so systemd pulls it in
#      AND waits for /sysroot before switch-root — exactly the wiring a
#      generated `sysroot.mount` gets.
#   3. `hippius-net-teardown.service` flushes the initrd network + shreds
#      any KEK residue before switch-root.
#
# ALL security-load-bearing logic (fail-closed golden detect, the RO
# dm-verity lower open/assert BEFORE the network, the per-VM KBS KEK
# handling, the in-guest MK, KEK shred-on-any-failure) lives in the
# SHARED `hippius-golden-overlay.sh` + `hippius-release-core.sh` — the
# SAME files the proven Debian golden boot uses, byte-for-byte. This
# module is glue: it cannot weaken an invariant because it does not
# reimplement one.
#
# §20: this module stages binaries + scripts; no secret ever touches the
# module files. The KEK exists only in initrd tmpfs between the release
# and the upper open, then is shredded.

# Only included when the bake explicitly asks for it
# (`add_dracutmodules+=" hippius-golden "`) — never auto-hostonly (the
# bake chroot's "host" has no SNP devices / no golden cmdline).
check() {
    return 255
}

depends() {
    # systemd: our units run in the systemd-driven initrd. dm: device-
    # mapper udev rules + dmsetup so the dm-verity lower and the LUKS
    # upper mapper devices settle. We deliberately do NOT depend on
    # `crypt` — golden writes an EMPTY /etc/crypttab and must not pull in
    # systemd-cryptsetup / rd.luks machinery (root is the overlay, not a
    # crypttab device).
    echo "systemd dm"
    return 0
}

installkernel() {
    # hostonly='' FORCES inclusion — hostonly probing inside the bake
    # chroot would strip the SNP/vsock tree (the build "host" has none of
    # these devices). Mirror hippius-release-core's modprobe chain + the
    # golden overlay stack (dm_verity for the RO lower, overlay for the
    # overlayfs root, squashfs for the golden rootfs.img, dm_crypt +
    # dm_integrity for the guest-keyed upper) + virtio for net/blk.
    # shellcheck disable=SC2086
    hostonly='' instmods \
        configfs tsm sev-guest \
        crypto_null gf128mul ghash-generic gcm xts \
        vsock vmw_vsock_virtio_transport_common vmw_vsock_virtio_transport \
        dm_mod dm_crypt dm_integrity dm_verity \
        overlay squashfs \
        virtio_net virtio_blk \
        ext4 xfs
}

install() {
    # Tools the shared core + overlay lib shell out to. `-o` for optional
    # ones. veritysetup opens the RO golden lower; cryptsetup luksFormats/
    # opens the guest-keyed upper; mkfs.ext4 lays down the first-boot
    # overlay upperdir; blockdev enforces the measured size anchor + the
    # RO assert; overlay/mount assemble the root.
    inst_multiple ip sha256sum awk wc cat mktemp modprobe mount umount sync \
        grep head tr ls blockdev veritysetup cryptsetup mkfs.ext4
    inst_multiple -o shred curl getent ping
    # setfattr/getfattr (attr) — the overlay lib stamps the RO lower's "/"
    # SELinux label onto the per-VM upper's overlay-root dir so the enforcing
    # RHEL guest does not see "/" as `unlabeled_t` (which denies every confined
    # domain `search /`). getfattr reads the real lower label; setfattr writes
    # it. RHEL-only module ⇒ `attr` is installed in the golden chroot.
    inst_multiple setfattr getfattr

    # ── busybox-shadow-proof mkfs.ext4 (parity with #834 / the Debian
    #    golden hook) ─────────────────────────────────────────────────
    # The overlay lib prefers a hippius-private `/lib/hippius/mkfs.ext4`
    # (`HIPPIUS_GOLDEN_MKFS`) and only falls back to `$PATH mkfs.ext4`.
    # RHEL dracut ships the REAL e2fsprogs binary (no busybox shadow), so
    # the PATH copy is already genuine — but staging the private copy too
    # makes BOTH families deterministic and immune to any future busybox
    # inclusion. `inst` (not inst_simple) so the binary's shared-lib deps
    # are resolved into the initrd; mke2fs.conf gives the full ext4
    # feature profile.
    _hg_real_mkfs="$(readlink -f "$(command -v mkfs.ext4 2>/dev/null)" 2>/dev/null || true)"
    if [ -x "${_hg_real_mkfs}" ]; then
        inst "${_hg_real_mkfs}" /lib/hippius/mkfs.ext4
        inst_simple -o /etc/mke2fs.conf /etc/mke2fs.conf
    fi

    # The two static-musl Hippius binaries (zero ldd deps — PR #422).
    inst /usr/sbin/hippius-guest-release
    inst /usr/sbin/hippius-vsock-ticket

    # The SHARED §21 release core + the SHARED golden overlay assembly
    # library, at the SAME `/lib/hippius/` paths the Debian golden boot
    # sources them from. Staged into the chroot at `/etc/hippius/` by the
    # bake (identical bytes to the Debian family).
    inst_simple /etc/hippius/hippius-release-core.sh /lib/hippius/hippius-release-core.sh
    inst_simple /etc/hippius/hippius-golden-overlay.sh /lib/hippius/hippius-golden-overlay.sh

    # The cmdline `rootok=1` claimer (so dracut does not emergency on the
    # absent root=) + the mount runner + the net teardown.
    inst_hook cmdline 30 "$moddir/parse-hippius-golden.sh"
    inst_script "$moddir/hippius-golden-mount.sh" /sbin/hippius-golden-mount
    inst_script "$moddir/hippius-net-teardown.sh" /sbin/hippius-net-teardown

    # Units + enablement. The mount unit is RequiredBy=initrd-root-fs.
    # target (via `enable` → the .requires symlink) so systemd pulls it in
    # AND waits for /sysroot before switch-root. The teardown unit is
    # WantedBy=initrd-switch-root.target so it runs just before the pivot.
    inst_simple "$moddir/hippius-golden-mount.service" \
        "$systemdsystemunitdir/hippius-golden-mount.service"
    inst_simple "$moddir/hippius-net-teardown.service" \
        "$systemdsystemunitdir/hippius-net-teardown.service"
    $SYSTEMCTL -q --root "$initdir" enable hippius-golden-mount.service || true
    $SYSTEMCTL -q --root "$initdir" enable hippius-net-teardown.service || true

    # CA bundle — consumed by the core's curl preflight diagnostics only
    # (hippius-guest-release carries webpki roots compiled in).
    inst_simple -o /etc/pki/tls/certs/ca-bundle.crt /etc/pki/tls/certs/ca-bundle.crt
}
