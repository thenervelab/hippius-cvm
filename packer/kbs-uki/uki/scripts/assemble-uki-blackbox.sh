#!/usr/bin/env bash
# `assemble-uki-blackbox.sh IMAGE_VERSION`
#
# Assembles the DISKLESS "blackbox" host-attestor UKI (host-attestor
# chantier PR-6). It reuses the SAME `ukify build` pipeline as the
# tenant/kbs `assemble-uki.sh`, but for the diskless shape:
#
#   - kernel:     /build/work/vmlinuz
#   - initrd:     /build/work/initramfs.cpio   (the ATTESTOR PID1 as /init)
#   - cmdline:    /build/work/cmdline.effective (a FIXED constant — see below)
#   - os-release: /build/work/os-release
#   - stub:       /build/work/linuxx64.efi.stub
#
# Output: /build/output/blackbox-<IMAGE_VERSION>.uki (unsigned). The
# `sign-uki.sh <...> blackbox` step produces the `.uki.signed` flavour.
#
# ## Diskless: initrd-as-root, no dm-verity / LUKS / cloud-init / netbird
#
# The host-attestor boots, derives its measurement-bound SNP key, enrols
# the pubkey with the KBS, and beacons — it mounts NO rootfs and needs
# none of the tenant machinery. So unlike `assemble-uki.sh` this script:
#   - reads NO `rootfs.roothash` and appends NO `dm-verity.root=`;
#   - embeds the cmdline VERBATIM from the pinned `cmdline.blackbox`
#     file, which is a FIXED CONSTANT. That determinism is load-bearing:
#     the SEV-SNP launch digest hashes the cmdline byte-exactly, so a
#     constant cmdline yields an identical measurement per CPU-gen (the
#     property the operator/CI pins the blackbox §22 allowlist entry to).
#
# Reproducibility:
#   - `ukify` honours SOURCE_DATE_EPOCH for the PE timestamp.
#   - The effective cmdline is a pure copy of the pinned constant — no
#     wall-clock, no per-build input.
#   - All other inputs are pinned by SHA-256 (fetch-inputs.sh) or built
#     deterministically (build-initramfs.sh).

set -euo pipefail
umask 022

if [[ $# -ne 1 ]]; then
    echo "usage: $0 IMAGE_VERSION" >&2
    exit 64
fi

IMAGE_VERSION="$1"

# ── Compose the effective cmdline: the FIXED diskless constant ───────
# Read the pinned constant (one line + a trailing newline). REJECT
# internal newlines — a multi-line file would silently concatenate
# kernel arguments — and strip the single trailing newline so the
# embedded cmdline is EXACTLY the constant. The SEV-SNP launch digest
# hashes this byte-exactly, so cmdline.effective IS the measured cmdline.
mapfile -t _cmdline_lines < /repo/packer/kbs-uki/uki/cmdline.blackbox
if [[ "${#_cmdline_lines[@]}" -gt 1 ]]; then
    echo "assemble-uki-blackbox: cmdline.blackbox has internal newlines — refusing" >&2
    echo "assemble-uki-blackbox: (a multi-line cmdline would concatenate kernel args)." >&2
    exit 67
fi
BLACKBOX_CMDLINE="${_cmdline_lines[0]:-}"
if [[ -z "$BLACKBOX_CMDLINE" ]]; then
    echo "assemble-uki-blackbox: cmdline.blackbox is empty — refusing" >&2
    exit 68
fi
# The diskless cmdline MUST NOT carry a dm-verity / root anchor — the
# attestor has no rootfs. Fail closed if one leaked in (a copy-paste
# from the tenant cmdline would otherwise measure a phantom anchor).
if [[ "$BLACKBOX_CMDLINE" == *dm-verity.root=* || "$BLACKBOX_CMDLINE" == *" root="* ]]; then
    echo "assemble-uki-blackbox: diskless cmdline must carry no rootfs anchor — refusing" >&2
    echo "assemble-uki-blackbox: got: $BLACKBOX_CMDLINE" >&2
    exit 69
fi
printf '%s' "$BLACKBOX_CMDLINE" > /build/work/cmdline.effective

# Substitute IMAGE_VERSION into the blackbox os-release template.
sed -e "s|@IMAGE_VERSION@|${IMAGE_VERSION}|g" \
    /repo/packer/kbs-uki/uki/os-release-blackbox.template \
    > /build/work/os-release

ukify build \
    --linux /build/work/vmlinuz \
    --initrd /build/work/initramfs.cpio \
    --cmdline "@/build/work/cmdline.effective" \
    --os-release "@/build/work/os-release" \
    --stub /build/work/linuxx64.efi.stub \
    --output /build/output/blackbox-${IMAGE_VERSION}.uki

echo "assemble-uki-blackbox: OK — /build/output/blackbox-${IMAGE_VERSION}.uki ($(stat -c%s /build/output/blackbox-${IMAGE_VERSION}.uki) bytes)" >&2
echo "assemble-uki-blackbox: cmdline = $(cat /build/work/cmdline.effective)" >&2
