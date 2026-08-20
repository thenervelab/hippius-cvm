#!/usr/bin/env bash
# Container gate for the `90hippius-luks` dracut module (multi-OS
# series). For each RHEL-family image (CentOS Stream 10, Fedora):
#   1. install dracut + a kernel + cryptsetup in a container,
#   2. stage the module + stub crypttab + stub binaries/core,
#   3. `dracut --no-hostonly --add hippius-luks`,
#   4. `lsinitrd`-assert: units present + enabled, runner + teardown +
#      core + crypttab + binaries staged, and the REQUIRED KERNEL
#      MODULES (sev-guest / tsm / vsock chain / dm_integrity) made it
#      in — this is the loud gate for "which kernel package carries
#      sev-guest on this distro", answered in CI instead of on a dead
#      serial console.
#
# Needs docker (or podman via DOCKER=podman). Heavier than a unit test
# (~2-4 min/distro) — wired to the dracut-module CI workflow, not the
# per-PR rust job.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "${HERE}/../.." && pwd)"
DOCKER="${DOCKER:-docker}"
IMAGES=(${DRACUT_TEST_IMAGES:-quay.io/centos/centos:stream10 fedora:latest})

run_one() {
    local image="$1"
    echo "=== ${image} ==="
    "${DOCKER}" run --rm -i \
        -v "${REPO}/scripts/dracut/90hippius-luks:/mod:ro" \
        -v "${REPO}/scripts/initramfs/hippius-release-core.sh:/core.sh:ro" \
        "${image}" bash -s <<'INNER'
set -euo pipefail
dnf -y -q install dracut dracut-network kernel-core kernel-modules kernel-modules-extra \
    cryptsetup systemd iproute >/dev/null
KVER=$(ls /lib/modules | sort -V | tail -1)
echo "kernel: ${KVER}"

# Stage what module-setup expects on the "host" being baked:
install -d /etc/hippius /usr/lib/dracut/modules.d/90hippius-luks
cp /core.sh /etc/hippius/hippius-release-core.sh
cp /mod/* /usr/lib/dracut/modules.d/90hippius-luks/
chmod 0755 /usr/lib/dracut/modules.d/90hippius-luks/*.sh
# Stub static binaries (the real ones are musl-static; any executable
# with no ldd deps exercises the same `inst` path).
printf '#!/bin/sh\nexit 0\n' > /usr/sbin/hippius-guest-release
printf '#!/bin/sh\nexit 0\n' > /usr/sbin/hippius-vsock-ticket
chmod 0755 /usr/sbin/hippius-guest-release /usr/sbin/hippius-vsock-ticket
# The crypttab the bake's RHEL arm writes:
cat > /etc/crypttab <<'EOF'
cryptroot /dev/vda /run/hippius/kek luks,discard,header=/run/hippius/luks.header,x-initrd.attach
EOF

dracut --force --no-hostonly --add hippius-luks --kver "${KVER}" /tmp/test-initrd.img
echo "initrd built: $(du -h /tmp/test-initrd.img | cut -f1)"

fail=0
# List ONCE to a file and grep THAT — any `... | grep -q` under
# pipefail dies with SIGPIPE (141) even on a match.
lsinitrd /tmp/test-initrd.img > /tmp/lsinitrd.txt
need() {
    if ! grep -qE "$1" /tmp/lsinitrd.txt; then
        echo "MISSING in initrd: $1" >&2; fail=1
    fi
}
# Units present + enabled.
need 'usr/lib/systemd/system/hippius-release.service'
need 'usr/lib/systemd/system/hippius-net-teardown.service'
need 'initrd.target.wants/hippius-release.service'
need 'initrd-switch-root.target.wants/hippius-net-teardown.service'
# Scripts + core + binaries + crypttab. Path-AGNOSTIC (basename
# match): Fedora 42+ merged /sbin into /usr/bin, CS10 keeps /usr/sbin —
# dracut's merge symlinks make /sbin/<name> resolve either way.
need '/hippius-release-runner'
need '/hippius-net-teardown'
need 'hippius-release-core.sh'
need '/hippius-guest-release'
need '/hippius-vsock-ticket'
need 'etc/crypttab'
# The kernel-module risk gate: the SNP/vsock/integrity chain must be
# IN the initrd (builtin would also satisfy boot, but RHEL ships these
# as modules — absence here means the kernel package set is wrong).
for mod in sev-guest dm-integrity dm-crypt vmw_vsock_virtio_transport vsock; do
    if ! grep -qE "${mod//-/[-_]}\.ko" /tmp/lsinitrd.txt; then
        # tolerate builtin: check modules.builtin for it
        if ! grep -qE "/${mod//-/[-_]}\.ko" "/lib/modules/${KVER}/modules.builtin"; then
            echo "MISSING kernel module in initrd (and not builtin): ${mod}" >&2; fail=1
        fi
    fi
done
[ "${fail}" -eq 0 ] && echo "DRACUT-MODULE-OK" || exit 1
INNER
}

rc=0
for img in "${IMAGES[@]}"; do
    run_one "${img}" || { echo "FAILED for ${img}" >&2; rc=1; }
done
exit "${rc}"
