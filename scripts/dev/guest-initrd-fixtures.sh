# shellcheck shell=bash
# Fixture golden base initrds for the guest components release tests
# (guest-release-test.sh, guest-initrd-build-test.sh): shaped like the real
# ones — an uncompressed early member, then one compressed member, usrmerge
# symlinks — with OLD Hippius files at the paths the hooks install them.
# Sourced; needs T (a scratch dir) and REPO (the checkout root).
# mkbase <dir> <out> [gzip|zstd]: <dir> is the main member's tree.
mkbase() {
    local tree="$1" out="$2" comp="${3:-gzip}" early="${T}/early-$$-${RANDOM}"
    mkdir -p "${early}/kernel/x86/microcode"
    printf 'ucode' > "${early}/kernel/x86/microcode/AuthenticAMD.bin"
    (cd "${early}" && find . | sort | cpio --quiet -o -H newc -R 0:0) > "${out}"
    case "${comp}" in
        gzip) (cd "${tree}" && find . | sort | cpio --quiet -o -H newc -R 0:0 | gzip -9n) >> "${out}" ;;
        zstd) (cd "${tree}" && find . | sort | cpio --quiet -o -H newc -R 0:0 | zstd -q -19) >> "${out}" ;;
    esac
}
# A usrmerged base tree of one family, with OLD Hippius files.
mktree() {
    local tree="$1" family="$2"
    mkdir -p "${tree}/usr/bin" "${tree}/usr/sbin" "${tree}/usr/lib/hippius" "${tree}/scripts/init-bottom"
    ln -s usr/bin "${tree}/bin"; ln -s usr/lib "${tree}/lib"; ln -s usr/sbin "${tree}/sbin"
    for c in mkdir rm ln readlink setfattr getfattr; do
        printf 'elf' > "${tree}/usr/bin/${c}"; chmod 0755 "${tree}/usr/bin/${c}"
    done
    printf 'elf' > "${tree}/usr/sbin/modprobe"; chmod 0755 "${tree}/usr/sbin/modprobe"
    printf 'old core' > "${tree}/usr/lib/hippius/hippius-release-core.sh"
    printf 'old overlay' > "${tree}/usr/lib/hippius/hippius-golden-overlay.sh"
    printf 'old release bin' > "${tree}/usr/sbin/hippius-guest-release"
    printf 'old ticket bin' > "${tree}/usr/sbin/hippius-vsock-ticket"
    if [[ "${family}" == initramfs-tools ]]; then
        printf 'old boot' > "${tree}/scripts/hippius-golden"
        printf 'old teardown' > "${tree}/scripts/init-bottom/hippius-net-teardown"
    else
        mkdir -p "${tree}/usr/lib/dracut/hooks/cmdline" "${tree}/usr/lib/systemd/system" \
                 "${tree}/etc/systemd/system/initrd-root-fs.target.requires" \
                 "${tree}/etc/systemd/system/initrd-switch-root.target.wants"
        cp "${REPO}/scripts/dracut/95hippius-golden/parse-hippius-golden.sh" \
            "${tree}/usr/lib/dracut/hooks/cmdline/30-parse-hippius-golden.sh"
        printf 'old mount' > "${tree}/usr/sbin/hippius-golden-mount"
        printf 'old teardown' > "${tree}/usr/sbin/hippius-net-teardown"
        printf '[Unit]\n' > "${tree}/usr/lib/systemd/system/hippius-golden-mount.service"
        printf '[Unit]\n' > "${tree}/usr/lib/systemd/system/hippius-net-teardown.service"
        ln -s /usr/lib/systemd/system/hippius-golden-mount.service \
            "${tree}/etc/systemd/system/initrd-root-fs.target.requires/hippius-golden-mount.service"
        ln -s /usr/lib/systemd/system/hippius-net-teardown.service \
            "${tree}/etc/systemd/system/initrd-switch-root.target.wants/hippius-net-teardown.service"
    fi
}
# mkvmlinuz <out> <kver>: a stub bzImage whose setup header carries the
# kernel_version string (all a reader of the version needs).
mkvmlinuz() {
    python3 - "$1" "$2" <<'PYVM'
import struct, sys
out, kver = sys.argv[1], sys.argv[2]
img = bytearray(0x1000)
img[0x202:0x206] = b"HdrS"
ver_off = 0x300  # kernel_version is at this offset + 0x200
struct.pack_into("<H", img, 0x20E, ver_off)
s = (kver + " (fixture) #1 SMP").encode() + b"\0"
img[ver_off + 0x200:ver_off + 0x200 + len(s)] = s
open(out, "wb").write(bytes(img))
PYVM
}
# mkrootfs <out> <kver> <loop: builtin|module|none>: a squashfs base with
# the module metadata the build checks for the loop driver.
mkrootfs() {
    local out="$1" kver="$2" loop="$3" t="${T}/rootfs-$$-${RANDOM}"
    mkdir -p "${t}/usr/lib/modules/${kver}/kernel/drivers/block"
    ln -s usr/lib "${t}/lib"
    : > "${t}/usr/lib/modules/${kver}/modules.builtin"
    : > "${t}/usr/lib/modules/${kver}/modules.dep"
    case "${loop}" in
        builtin) echo "kernel/drivers/block/loop.ko" >> "${t}/usr/lib/modules/${kver}/modules.builtin" ;;
        module)
            printf 'mod' > "${t}/usr/lib/modules/${kver}/kernel/drivers/block/loop.ko.zst"
            echo "kernel/drivers/block/loop.ko.zst:" >> "${t}/usr/lib/modules/${kver}/modules.dep"
            ;;
    esac
    echo "kernel/fs/ext4/ext4.ko" >> "${t}/usr/lib/modules/${kver}/modules.builtin"
    mksquashfs "${t}" "${out}" -noappend -all-root -quiet >/dev/null
}
