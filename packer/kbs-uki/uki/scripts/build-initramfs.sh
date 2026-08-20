#!/usr/bin/env bash
# `build-initramfs.sh AGENT_BINARY_PATH [STAGED_NAME]`
#
# Builds the cpio initramfs that the UKI boots into. The cpio entry
# layout is (STAGED_NAME defaults to `hippius-agent-initramfs`):
#
#   /init                — symlink to /sbin/<STAGED_NAME>
#   /sbin/<STAGED_NAME>             — the binary built upstream
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
#
# Reproducibility:
#   - cpio --reproducible (UID/GID/mtime cleared per entry).
#   - `find … | LC_ALL=C sort` so entry order is deterministic.
#   - mtime forced to $SOURCE_DATE_EPOCH on every staged file.
#   - umask 022 + chmod 0755 on the binary so file mode is fixed.
#   - The bundled `.so` bytes come from the pinned-by-digest trixie
#     Docker image, so an identical build produces an identical cpio.
#
# Output: /build/work/initramfs.cpio (uncompressed; ukify gzips it
# inside the UKI's `.initrd` section deterministically).

set -euo pipefail
umask 022

if [[ $# -lt 1 || $# -gt 3 ]]; then
    echo "usage: $0 AGENT_BINARY_PATH [STAGED_NAME] [KMOD_SET]" >&2
    exit 64
fi

AGENT_BINARY="$1"
# The in-cpio basename of the agent binary + the `/init` symlink target.
# Defaults to `hippius-agent-initramfs` so the tenant/kbs UKI's cpio
# bytes are unchanged; `make blackbox-uki` passes
# `hippius-agent-host-attestor` to stage the diskless attestor PID1.
STAGED_NAME="${2:-hippius-agent-initramfs}"
# Which kernel-module set to bundle into `/lib/modules/<kver>/...`.
# Empty (default) stages NO modules → the KBS UKI cpio stays byte-
# identical (measurement unchanged). `host-attestor` stages the
# diskless attestor's `sev-guest` + `vsock` families (the guest kernel
# ships both as `=m`; the agent `init_module(2)`s them at PID 1). Only
# `make blackbox-*` passes a non-empty value.
KMOD_SET="${3:-}"
if [[ ! -x "$AGENT_BINARY" ]]; then
    echo "build-initramfs: agent binary not executable at $AGENT_BINARY" >&2
    echo "build-initramfs: run \`cargo build -p hippius-agent-initramfs --release\` (or the host-attestor bin) first." >&2
    exit 65
fi

STAGING=/build/work/initramfs-staging
rm -rf "$STAGING"
mkdir -p "$STAGING/sbin"

install -m 0755 "$AGENT_BINARY" "$STAGING/sbin/${STAGED_NAME}"
ln -sf "/sbin/${STAGED_NAME}" "$STAGING/init"

# ── Bundle the dynamic-linker + every `.so` `ldd` resolves against
#    the staged binary into the cpio's `/lib`/`/lib64` tree. Without
#    these the kernel's execve of `/init` fails ENOENT looking for
#    `/lib64/ld-linux-x86-64.so.2`. The trixie runtime image is pinned
#    by digest, so the resolved `.so` paths and bytes are stable.
LIBS=$(ldd "$STAGING/sbin/${STAGED_NAME}" \
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

# ── Bundle measured kernel modules (blackbox / host-attestor only) ───
#
# The default (empty $KMOD_SET) stages NO modules, so the KBS UKI cpio
# bytes — and its SNP measurement — are byte-identical to before this
# change. `make blackbox-*` passes `host-attestor`, which stages the
# two module families the DISKLESS attestor loads at PID 1
# (`load_kernel_modules` in `binaries/agent-host-attestor/src/main.rs`):
#
#   - sev-guest (+ configfs/tsm + the gcm(aes) crypto chain) — the
#     Debian stock kernel ships `CONFIG_SEV_GUEST=m`, so `/dev/sev-guest`
#     never appears until these load (the live `open-failed` blocker).
#   - vsock (+ virtio transport) — `CONFIG_VSOCKETS=m` /
#     `CONFIG_VIRTIO_VSOCKETS=m`; the challenge/enroll/beacon vsock
#     cannot bind until these load.
#
# Source: `fetch-inputs.sh` already `dpkg-deb -x kernel.deb
# /build/work/kernel-extracted`, laying modules under
# `/usr/lib/modules/<kver>/kernel/...`. We decompress the ones we need
# to raw `.ko` at the canonical `/lib/modules/<kver>/...` the agent reads.
# Reproducibility: the `.deb` SHA is pinned (`inputs.lock`) AND `unxz`
# is deterministic, so the staged `.ko` bytes are stable — and being IN
# the initrd they are a MEASURED input (the blackbox measurement folds
# them; operator re-pins on this change, as expected).
if [[ "$KMOD_SET" == "host-attestor" ]]; then
    KMOD_SRC_PARENT=/build/work/kernel-extracted/usr/lib/modules
    if [[ ! -d "$KMOD_SRC_PARENT" ]]; then
        echo "build-initramfs: kernel modules tree missing at $KMOD_SRC_PARENT" >&2
        echo "build-initramfs: did fetch-inputs.sh run? It dpkg-deb -x's the kernel package here." >&2
        exit 68
    fi
    # The .deb ships exactly one kernel-version dir; keep the pick
    # deterministic even on the hypothetical day it ships two.
    KVER=$(find "$KMOD_SRC_PARENT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' \
        | LC_ALL=C sort | head -n1)
    if [[ -z "$KVER" ]]; then
        echo "build-initramfs: no kernel-version dir under $KMOD_SRC_PARENT" >&2
        exit 69
    fi
    KMOD_SRC_ROOT="$KMOD_SRC_PARENT/$KVER/kernel"
    KMOD_DEST_ROOT="$STAGING/lib/modules/$KVER/kernel"

    # `stage_kmod <relative .ko path under kernel/>` — extract one
    # `.ko.xz` to its mirror path under `$KMOD_DEST_ROOT`, decompress in
    # place, and ELF-magic-check (init_module(2) rejects XZ bytes with an
    # opaque errno; failing here is much louder than at boot).
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
        # `unxz -k -c` is a pure function of input bytes → reproducible.
        # The agent reads raw `.ko` (plain `init_module(2)` does not
        # handle compressed images).
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

    # vsock transport stack — the guest-initiated challenge PULL and the
    # enroll/beacon UP relay bind `AF_VSOCK`. Same set + order as the
    # `vsock` family in the agent's `load_kernel_modules` — keep lockstep.
    stage_kmod net/vmw_vsock/vsock
    stage_kmod net/vmw_vsock/vmw_vsock_virtio_transport_common
    stage_kmod net/vmw_vsock/vmw_vsock_virtio_transport

    # SEV-SNP attestation family — `/dev/sev-guest` is exposed by the
    # `sev-guest` driver, which depends on the CoCo TSM framework (`tsm`
    # → `configfs`) and allocates a `gcm(aes)` AEAD (crypto_null →
    # gf128mul → ghash-generic → gcm) at probe. `aes` is built-in
    # (CONFIG_CRYPTO_AES=y). Same set + order as the `sev_guest` family
    # in the agent's `load_kernel_modules` — keep lockstep.
    stage_kmod fs/configfs/configfs
    stage_kmod crypto/crypto_null
    stage_kmod lib/crypto/gf128mul
    stage_kmod crypto/ghash-generic
    stage_kmod crypto/gcm
    stage_kmod drivers/virt/coco/tsm
    stage_kmod drivers/virt/coco/sev-guest/sev-guest
fi

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
