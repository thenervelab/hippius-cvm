#!/usr/bin/env bash
# `assemble-uki.sh IMAGE_VERSION`
#
# Invokes `ukify build` to assemble the UKI from the staged inputs:
#   - kernel:     /build/work/vmlinuz
#   - initrd:     /build/work/initramfs.cpio
#   - cmdline:    /build/work/cmdline.effective  (composed below)
#   - os-release: /build/work/os-release
#   - stub:       /build/work/linuxx64.efi.stub
#
# Output: /build/output/tenant-<IMAGE_VERSION>.uki (unsigned). The
# `sign-uki.sh` step produces the `.uki.signed` flavour.
#
# ## PR-F3 — dm-verity root hash in the cmdline
#
# The effective kernel cmdline is the pinned base (`uki/cmdline`) plus
# `dm-verity.root=<root_hash>`, where `<root_hash>` is the dm-verity
# root hash `build-rootfs.sh` computed for the read-only rootfs. The
# initramfs agent's `switch_root` stage reads `dm-verity.root=` and
# refuses to boot a rootfs whose device root hash does not match — so
# the rootfs is integrity-anchored in the measured UKI.
#
# Reproducibility:
#   - `ukify` honours SOURCE_DATE_EPOCH for the PE timestamp.
#   - The effective cmdline is a pure function of the pinned base file
#     and the (reproducible) verity root hash — no wall-clock input.
#   - All other inputs are pinned by SHA-256 (fetch-inputs.sh) or built
#     deterministically (build-initramfs.sh / build-rootfs.sh).

set -euo pipefail
umask 022

if [[ $# -ne 1 ]]; then
    echo "usage: $0 IMAGE_VERSION" >&2
    exit 64
fi

IMAGE_VERSION="$1"

# ── Compose the effective cmdline: base + dm-verity root hash ────────
ROOTHASH_FILE=/build/work/rootfs.roothash
if [[ ! -f "$ROOTHASH_FILE" ]]; then
    echo "assemble-uki: missing $ROOTHASH_FILE — run build-rootfs.sh first." >&2
    exit 65
fi
ROOT_HASH=$(cat "$ROOTHASH_FILE")
if [[ ! "$ROOT_HASH" =~ ^[0-9a-f]{64}$ ]]; then
    echo "assemble-uki: rootfs.roothash is not a 64-hex digest: '$ROOT_HASH'" >&2
    exit 66
fi

# Read the pinned base cmdline (one line + a trailing newline).
# REJECT internal newlines — a multi-line base file would silently
# concatenate kernel arguments — and strip the single trailing newline
# so the embedded cmdline is exactly `<base> dm-verity.root=<hash>`.
# The SEV-SNP launch digest hashes this byte-exactly, so
# cmdline.effective IS the measured cmdline.
mapfile -t _cmdline_lines < /repo/packer/tenant-uki-debian/uki/cmdline
if [[ "${#_cmdline_lines[@]}" -gt 1 ]]; then
    echo "assemble-uki: base cmdline file has internal newlines — refusing" >&2
    echo "assemble-uki: (a multi-line cmdline would concatenate kernel args)." >&2
    exit 67
fi
BASE_CMDLINE="${_cmdline_lines[0]:-}"
# Belt-and-suspenders: an empty / blank cmdline file would silently
# compose ` dm-verity.root=…` (leading space, nothing pinned) — the
# launch digest would diverge radically from the test vector. Refuse.
if [[ -z "${BASE_CMDLINE// /}" ]]; then
    echo "assemble-uki: base cmdline file is empty / whitespace-only — refusing" >&2
    exit 68
fi
printf '%s dm-verity.root=%s' "$BASE_CMDLINE" "$ROOT_HASH" \
    > /build/work/cmdline.effective

# Substitute IMAGE_VERSION into os-release so a custom
# `make uki IMAGE_VERSION=foo` doesn't ship a stale VERSION_ID.
sed -e "s|@IMAGE_VERSION@|${IMAGE_VERSION}|g" \
    /repo/packer/tenant-uki-debian/uki/os-release.template \
    > /build/work/os-release

ukify build \
    --linux /build/work/vmlinuz \
    --initrd /build/work/initramfs.cpio \
    --cmdline "@/build/work/cmdline.effective" \
    --os-release "@/build/work/os-release" \
    --stub /build/work/linuxx64.efi.stub \
    --output /build/output/tenant-debian-${IMAGE_VERSION}.uki

echo "assemble-uki: OK — /build/output/tenant-debian-${IMAGE_VERSION}.uki ($(stat -c%s /build/output/tenant-debian-${IMAGE_VERSION}.uki) bytes)" >&2
echo "assemble-uki: cmdline = $(cat /build/work/cmdline.effective)" >&2
