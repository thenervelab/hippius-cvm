#!/bin/bash
# dracut module `90hippius-luks` — the RHEL-family (CentOS Stream /
# Fedora) counterpart of the Debian-family `hippius-luks-hook` +
# `keyscript=` pair. Installed into the guest image at
# `/usr/lib/dracut/modules.d/90hippius-luks/` by
# `scripts/tenant-image-bake.sh` (RHEL arm), then baked into the initrd
# by `dracut --force`.
#
# Mechanism (dracut has NO crypttab `keyscript=` extension):
#   1. `hippius-release.service` (this module, ordered
#      Before=cryptsetup-pre.target) runs `hippius-release-runner`,
#      which drives the SHARED `hippius-release-core.sh` sequence
#      (#296 header verify → net → vsock ticket → SNP attest → KBS
#      release) and writes the 32-byte KEK to /run/hippius/kek (0600).
#   2. The initrd's /etc/crypttab names that keyfile:
#        cryptroot /dev/vda /run/hippius/kek luks,...,header=/run/hippius/luks.header,x-initrd.attach
#      systemd-cryptsetup (ordered After=cryptsetup-pre.target by the
#      generator) reads the keyfile + the VERIFIED header copy and
#      unlocks — same trust shape as the Debian keyscript path.
#   3. `hippius-net-teardown.service` flushes the initrd network +
#      shreds /run/hippius/{kek,luks.header} before switch-root (#289
#      + secret hygiene).
#
# §20: this module stages binaries + scripts; no secret ever touches
# the module files. The KEK exists only in initrd tmpfs between the
# runner and systemd-cryptsetup, then is shredded pre-pivot.

# Only included when the bake explicitly asks for it
# (`add_dracutmodules+=" hippius-luks "` in a dracut conf.d drop-in) —
# never auto-hostonly (the bake chroot's "host" has no SNP devices).
check() {
    return 255
}

depends() {
    # systemd: our units; crypt: systemd-cryptsetup + the cryptsetup
    # CLI (luksHeaderBackup in the core).
    echo "systemd crypt"
    return 0
}

installkernel() {
    # hostonly='' FORCES inclusion — hostonly probing inside the bake
    # chroot would strip the SNP/vsock tree (the build "host" has none
    # of these devices), exactly the MODULES=auto failure the Debian
    # hook documents. Mirror hippius-release-core's modprobe chain +
    # the unlock stack + virtio_net for the static net bring-up.
    # ext4 covers the Phase 2B state disk AND the (always-ext4, see
    # the bake's copy step) rootfs; xfs is cheap insurance if a future
    # bake arm keeps an xfs root.
    # shellcheck disable=SC2086
    hostonly='' instmods \
        configfs tsm sev-guest \
        crypto_null gf128mul ghash-generic gcm xts \
        vsock vmw_vsock_virtio_transport_common vmw_vsock_virtio_transport \
        dm_crypt dm_integrity \
        virtio_net virtio_blk \
        ext4 xfs
}

install() {
    # Tools the shared core shells out to. `-o` for the optional ones.
    inst_multiple ip sha256sum awk wc cat mktemp modprobe mount umount sync grep head tr ls
    inst_multiple -o shred curl getent ping cryptsetup
    # The two static-musl Hippius binaries (zero ldd deps — PR #422).
    inst /usr/sbin/hippius-guest-release
    inst /usr/sbin/hippius-vsock-ticket
    # The shared release core, at the same path the Debian hook stages
    # it (the runner sources /lib/hippius/hippius-release-core.sh).
    inst_simple /etc/hippius/hippius-release-core.sh /lib/hippius/hippius-release-core.sh
    # The runner + teardown scripts ship inside the module dir.
    inst_script "$moddir/hippius-release-runner.sh" /sbin/hippius-release-runner
    inst_script "$moddir/hippius-net-teardown.sh" /sbin/hippius-net-teardown
    # Units + enablement (initrd.target / initrd-switch-root.target).
    inst_simple "$moddir/hippius-release.service" \
        "$systemdsystemunitdir/hippius-release.service"
    inst_simple "$moddir/hippius-net-teardown.service" \
        "$systemdsystemunitdir/hippius-net-teardown.service"
    $SYSTEMCTL -q --root "$initdir" enable hippius-release.service || true
    $SYSTEMCTL -q --root "$initdir" enable hippius-net-teardown.service || true
    # Force the crypttab into the initrd: systemd-cryptsetup-generator
    # reads the INITRD's /etc/crypttab. Hostonly device-probing inside
    # the bake chroot cannot see /dev/vda, so without this explicit
    # install the 90crypt module may drop the entry.
    inst_simple /etc/crypttab /etc/crypttab
    # CA bundle — consumed by the core's curl preflight diagnostics
    # only (hippius-guest-release carries webpki roots compiled in).
    inst_simple -o /etc/pki/tls/certs/ca-bundle.crt /etc/pki/tls/certs/ca-bundle.crt
}
