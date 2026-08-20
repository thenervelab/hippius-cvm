#!/usr/bin/env bash
# `build-initramfs.sh AGENT_BINARY_PATH`
#
# Builds the cpio initramfs that the UKI boots into. The cpio entry
# layout is:
#
#   /init                — symlink to /sbin/hippius-agent-initramfs
#   /sbin/hippius-agent-initramfs   — the binary built upstream
#                                     (cargo build --release).
#   /lib/x86_64-linux-gnu/*         — every `.so` `ldd` reports against
#                                     the staged binary (PR-E1.4 added
#                                     `libcryptsetup-rs`, whose `-sys`
#                                     crate dynamic-links `libcryptsetup`
#                                     and friends — Debian ships no
#                                     `libcryptsetup.a`, so the original
#                                     `+crt-static` PID1 plan is
#                                     infeasible and we bundle).
#   /lib64/ld-linux-x86-64.so.2     — the dynamic linker.
#   /lib/modules/<kver>/kernel/net/vmw_vsock/
#       vsock.ko
#       vmw_vsock_virtio_transport_common.ko
#       vmw_vsock_virtio_transport.ko
#                                   — Debian Trixie ships
#                                     `CONFIG_VSOCKETS=m`; the agent
#                                     `init_module(2)`s these at PID 1
#                                     so `/dev/vsock` exists before
#                                     `stages::ticket_vsock::recv_ticket`
#                                     binds.
#   /lib/modules/<kver>/kernel/net/core/failover.ko
#   /lib/modules/<kver>/kernel/drivers/net/net_failover.ko
#   /lib/modules/<kver>/kernel/drivers/net/virtio_net.ko
#                                   — Debian Trixie ships virtio_net
#                                     as `=m`; the agent
#                                     `init_module(2)`s the dependency
#                                     chain at PID 1 so an `eth0`
#                                     interface exists before
#                                     `stages::network::bring_up_dhcp`
#                                     opens a DHCP socket against the
#                                     libvirt-NAT lease server.
#                                   All `.ko` are decompressed from
#                                   the `.ko.xz` shipped inside the
#                                   same kernel `.deb` `inputs.lock`
#                                   already pins, so no new fetch +
#                                   no new SHA pin.
#
# Reproducibility:
#   - cpio --reproducible (UID/GID/mtime cleared per entry).
#   - `find … | LC_ALL=C sort` so entry order is deterministic.
#   - mtime forced to $SOURCE_DATE_EPOCH on every staged file.
#   - umask 022 + chmod 0755 on the binary so file mode is fixed.
#   - The bundled `.so` bytes come from the pinned-by-digest trixie
#     Docker image, so an identical build produces an identical cpio.
#   - The vsock `.ko` bytes come from the kernel `.deb` whose SHA-256
#     `inputs.lock` already verifies (`fetch-inputs.sh`); `unxz -k` is
#     a pure function of the input bytes, so the staged `.ko` are
#     byte-identical across runs.
#
# Output: /build/work/initramfs.cpio (uncompressed; ukify gzips it
# inside the UKI's `.initrd` section deterministically).

set -euo pipefail
umask 022

if [[ $# -ne 1 ]]; then
    echo "usage: $0 AGENT_BINARY_PATH" >&2
    exit 64
fi

AGENT_BINARY="$1"
if [[ ! -x "$AGENT_BINARY" ]]; then
    echo "build-initramfs: agent binary not executable at $AGENT_BINARY" >&2
    echo "build-initramfs: run \`cargo build -p hippius-agent-initramfs --release\` first." >&2
    exit 65
fi

STAGING=/build/work/initramfs-staging
rm -rf "$STAGING"
mkdir -p "$STAGING/sbin"

install -m 0755 "$AGENT_BINARY" "$STAGING/sbin/hippius-agent-initramfs"
ln -sf /sbin/hippius-agent-initramfs "$STAGING/init"

# ── Bundle the dynamic-linker + every `.so` `ldd` resolves against
#    the staged binary into the cpio's `/lib`/`/lib64` tree. Without
#    these the kernel's execve of `/init` fails ENOENT looking for
#    `/lib64/ld-linux-x86-64.so.2`. The trixie runtime image is pinned
#    by digest, so the resolved `.so` paths and bytes are stable.
LIBS=$(ldd "$STAGING/sbin/hippius-agent-initramfs" \
    | awk '/=> \//{print $3}' \
    | LC_ALL=C sort -u)
if [[ -z "$LIBS" ]]; then
    echo "build-initramfs: ldd produced no shared-library deps for $AGENT_BINARY" >&2
    echo "build-initramfs: this script expects a dynamically-linked agent (see header)." >&2
    exit 66
fi
for lib in $LIBS; do
    # Mirror the absolute path inside $STAGING so the in-binary
    # RUNPATH/RPATH and the dynamic linker's default search dirs both
    # resolve at execve time.
    install -D -m 0644 "$lib" "$STAGING$lib"
done
# The dynamic linker itself — `ldd` lists it as "ld-linux-…" without a
# `=>` arrow, so it must be staged explicitly. The ELF interpreter
# path is baked into the binary header; `readelf -l` will confirm
# `/lib64/ld-linux-x86-64.so.2` on amd64 + glibc Debian.
LINKER=/lib64/ld-linux-x86-64.so.2
if [[ ! -e "$LINKER" ]]; then
    echo "build-initramfs: dynamic linker missing at $LINKER" >&2
    exit 67
fi
install -D -m 0755 "$LINKER" "$STAGING$LINKER"

# ── Bundle measured kernel modules ──────────────────────────────────
#
# Debian Trixie's 6.12 kernel ships several driver families as `=m`
# that the §21 boot pipeline relies on. Each is loaded from PID 1 by
# the agent (`load_kernel_modules` in
# `binaries/agent-initramfs/src/main.rs`); the cpio just has to carry
# the bytes.
#
# Source: `fetch-inputs.sh` already `dpkg-deb -x kernel.deb
# /build/work/kernel-extracted`. The Debian package lays modules
# down under `/usr/lib/modules/<kver>/kernel/...`; we extract the
# ones we need, decompress to raw `.ko`, and stage at the canonical
# `/lib/modules/<kver>/...` the agent reads.
#
# Reproducibility: the source `.deb` SHA is pinned (`inputs.lock`)
# AND `unxz` is deterministic, so the staged `.ko` bytes are stable.
KMOD_SRC_PARENT=/build/work/kernel-extracted/usr/lib/modules
if [[ ! -d "$KMOD_SRC_PARENT" ]]; then
    echo "build-initramfs: kernel modules tree missing at $KMOD_SRC_PARENT" >&2
    echo "build-initramfs: did fetch-inputs.sh run? It dpkg-deb -x's the kernel package here." >&2
    exit 68
fi
# Take the single kernel-version directory present — the .deb ships
# exactly one. `LC_ALL=C sort | head -n1` keeps the pick deterministic
# even on the hypothetical day a future package ships two.
KVER=$(find "$KMOD_SRC_PARENT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' \
    | LC_ALL=C sort | head -n1)
if [[ -z "$KVER" ]]; then
    echo "build-initramfs: no kernel-version dir under $KMOD_SRC_PARENT" >&2
    exit 69
fi
KMOD_SRC_ROOT="$KMOD_SRC_PARENT/$KVER/kernel"
KMOD_DEST_ROOT="$STAGING/lib/modules/$KVER/kernel"

# `stage_kmod <relative .ko path under kernel/>` — extract one
# `.ko.xz` to its mirror path under `$KMOD_DEST_ROOT`, decompress
# in place, and ELF-magic-check. Centralised so adding a new module
# is one line; the per-module rationale stays at the call site.
#
# The ELF-magic sanity check catches the failure mode where
# `init_module(2)` rejects XZ bytes with an opaque "Invalid ELF
# header" errno — the agent would only surface that as the generic
# `*-modules-load-*` class long after the UKI is published. Failing
# the build here is much louder.
stage_kmod() {
    local rel="$1"
    local src_xz="$KMOD_SRC_ROOT/${rel}.ko.xz"
    local dest_dir="$KMOD_DEST_ROOT/$(dirname "$rel")"
    local dest="$KMOD_DEST_ROOT/${rel}.ko"
    if [[ ! -f "$src_xz" ]]; then
        echo "build-initramfs: missing kernel module: $src_xz" >&2
        echo "build-initramfs: kernel.deb layout changed? check inputs.lock + Debian package." >&2
        exit 70
    fi
    install -d -m 0755 "$dest_dir"
    # `unxz -k -c` (keep source / write to stdout) is a pure function
    # of input bytes — reproducible. The agent reads raw `.ko` because
    # `init_module(2)`'s plain form does not handle compressed images,
    # and `finit_module`'s `MODULE_INIT_COMPRESSED_FILE` flag depends
    # on a kernel config we can't reliably assume.
    unxz -k -c "$src_xz" > "$dest"
    chmod 0644 "$dest"
    local magic
    magic=$(head -c 4 "$dest" | od -An -tx1 | tr -d ' \n')
    if [[ "$magic" != "7f454c46" ]]; then
        echo "build-initramfs: $dest is not an uncompressed ELF (magic=$magic)" >&2
        echo "build-initramfs: xz-utils pin missing in Dockerfile? unxz step bypassed?" >&2
        exit 71
    fi
}

# AF_VSOCK family — `stages::ticket_vsock::recv_ticket` calls
# `VsockListener::bind`, which fails closed (`/dev/vsock` does not
# exist) on a kernel where `CONFIG_VSOCKETS=m` and nothing has yet
# `init_module(2)`-ed the module set. Load order (dependency chain)
# is enforced agent-side; the cpio just ships the files. Same set
# (and order) as the per-name list in `load_kernel_modules` — keep
# them in lockstep.
stage_kmod net/vmw_vsock/vsock
stage_kmod net/vmw_vsock/vmw_vsock_virtio_transport_common
stage_kmod net/vmw_vsock/vmw_vsock_virtio_transport

# Network family — `stages::network::bring_up_dhcp` needs an eth0
# (virtio-net) interface before the agent can resolve the KBS hostname
# or POST a request. `virtio_net=m` in Trixie's 6.12 kernel, and the
# pre-#194 initramfs ran with the NIC unbound — `ReqwestHttpClient::
# post_cbor` failed closed at `kbs-connect` ~0.9 s after `/init`
# started (live, 2026-05-25 E2E). Declared `depends:` chain
# (verified via `modinfo` on the staged .deb):
#   failover     — no deps
#   net_failover — depends on failover
#   virtio_net   — depends on net_failover (transitively on failover)
# `virtio` / `virtio_pci` are built-in in Trixie (`modules.builtin`),
# so the device is already on the PCI bus by the time the agent loads
# `virtio_net`. Same lockstep convention as the vsock set.
stage_kmod net/core/failover
stage_kmod drivers/net/net_failover
stage_kmod drivers/net/virtio_net

# Force-set mtime on every staged file/dir/symlink so cpio's
# fallback to filesystem mtime can't leak the build wall-clock into
# the archive. `find -exec touch -h -d` covers symlinks too.
find "$STAGING" -depth -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +

# `cpio -o` reads filenames from stdin; we sort byte-wise (LC_ALL=C)
# so the archive's entry order is stable across runs.
cd "$STAGING"
find . -mindepth 1 -depth \
    | LC_ALL=C sort \
    | cpio --create --format=newc --reproducible --owner=0:0 \
        > /build/work/initramfs.cpio

echo "build-initramfs: OK — /build/work/initramfs.cpio ($(stat -c%s /build/work/initramfs.cpio) bytes)" >&2
