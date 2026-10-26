#!/usr/bin/env bash
# Stage the ubuntu-runner glue into a mounted guest rootfs.
#
#   install-ubuntu-runner.sh <rootfs>
#
# Called by `tenant-image-bake.sh --profile ubuntu-runner` after the chroot
# has installed Docker (docker-ce, containerd.io, buildx, compose) and the
# GitHub Actions runner's dependencies, while the rootfs is still mounted.
#
# What this adds: Docker's and containerd's state on the golden guest's
# non-overlay data path. A golden root is an overlayfs (dm-verity lower +
# guest-keyed upper), and the kernel refuses an overlay whose upperdir sits
# on an overlay, so overlay2 / the overlayfs snapshotter cannot live under
# `/` (docs/design/golden-data-path.md). The initramfs binds the volume's
# plain-ext4 `data/` at /var/lib/hippius-data; at boot,
# hippius-runner-data.service binds
#   /var/lib/hippius-data/docker     -> /var/lib/docker
#   /var/lib/hippius-data/containerd -> /var/lib/containerd
# before either daemon starts, and both daemons require it. The default
# paths stay what every tool expects, whichever image store Docker uses
# (graph drivers in /var/lib/docker, the containerd store in
# /var/lib/containerd). If /var/lib/hippius-data is not a mount point the
# service fails and neither daemon starts: a loud failure, rather than
# Docker silently falling back to the vfs driver on the overlay root.
#
# Root-free testable: SUDO="" runs every write directly (see
# scripts/dev/ubuntu-runner-profile-test.sh).
set -euo pipefail

SUDO="${SUDO-sudo}"
die() { echo "install-ubuntu-runner: $*" >&2; exit 3; }

[[ $# -eq 1 ]] || die "usage: install-ubuntu-runner.sh <rootfs>"
ROOT="$1"
[[ -d "${ROOT}/etc" && -d "${ROOT}/usr" ]] || die "${ROOT} is not a rootfs"

UNIT_DIR="${ROOT}/etc/systemd/system"

put() { # mode path (content on stdin)
    ${SUDO} install -d -m 0755 "$(dirname -- "$2")"
    ${SUDO} tee "$2" >/dev/null
    ${SUDO} chmod "$1" "$2"
}

put 0755 "${ROOT}/usr/local/sbin/hippius-runner-data" <<'SCRIPT'
#!/bin/sh
# Bind Docker's and containerd's state onto the golden guest's non-overlay
# data path (baked by the ubuntu-runner profile; see
# hippius-runner-data.service).
set -eu
data=/var/lib/hippius-data
mountpoint -q "${data}" || { echo "hippius-runner-data: ${data} is not a mount point" >&2; exit 1; }
for name in docker containerd; do
    src="${data}/${name}"
    dst="/var/lib/${name}"
    if mountpoint -q "${dst}"; then
        continue
    fi
    for p in "${src}" "${dst}"; do
        if [ -L "${p}" ] || { [ -e "${p}" ] && [ ! -d "${p}" ]; }; then
            echo "hippius-runner-data: ${p} is not a plain directory" >&2
            exit 1
        fi
    done
    install -d -m 0711 "${src}" "${dst}"
    mount --bind "${src}" "${dst}"
    echo "hippius-runner-data: ${dst} bound to ${src}"
done
SCRIPT

put 0644 "${UNIT_DIR}/hippius-runner-data.service" <<'UNIT'
[Unit]
Description=Docker and containerd state on the non-overlay data path
RequiresMountsFor=/var/lib/hippius-data
AssertPathIsMountPoint=/var/lib/hippius-data
Before=containerd.service docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/hippius-runner-data

[Install]
WantedBy=multi-user.target
UNIT

for daemon in containerd docker; do
    put 0644 "${UNIT_DIR}/${daemon}.service.d/10-hippius-runner-data.conf" <<'DROPIN'
# ubuntu-runner: the daemon's state lives on the non-overlay data path.
[Unit]
Requires=hippius-runner-data.service
After=hippius-runner-data.service
DROPIN
done

${SUDO} install -d -m 0755 "${UNIT_DIR}/multi-user.target.wants"
${SUDO} ln -sfn ../hippius-runner-data.service \
    "${UNIT_DIR}/multi-user.target.wants/hippius-runner-data.service"
