#!/usr/bin/env bash
# `fetch-inputs.sh KERNEL_URL KERNEL_SHA256 STUB_URL STUB_SHA256 \
#                  OVMF_URL OVMF_SHA256`
#
# Downloads each input into `/build/fetched/` and refuses to proceed
# if the SHA-256 doesn't match the pinned value. Runs INSIDE the
# Linux/amd64 Docker image so all hosts hit the same `curl` +
# `sha256sum` versions.
#
# Kernel + systemd-stub arrive as Debian `.deb` archives and are
# unpacked; the OVMF firmware (PR-F3) is fetched as a raw `.fd` file —
# `ovmf.lock` must therefore pin a direct firmware-file URL.
#
# Fail-closed: any digest mismatch removes the offending file before
# exiting non-zero so a partial-download artefact can't trick the
# next step into accepting it.

set -euo pipefail
umask 022

if [[ $# -ne 6 ]]; then
    echo "usage: $0 KERNEL_URL KERNEL_SHA256 STUB_URL STUB_SHA256 OVMF_URL OVMF_SHA256" >&2
    exit 64
fi

KERNEL_URL="$1"
KERNEL_SHA256="$2"
STUB_URL="$3"
STUB_SHA256="$4"
OVMF_URL="$5"
OVMF_SHA256="$6"

ZERO_DIGEST="0000000000000000000000000000000000000000000000000000000000000000"
for d in "$KERNEL_SHA256" "$STUB_SHA256"; do
    if [[ "$d" == "$ZERO_DIGEST" ]]; then
        echo "fetch-inputs: placeholder zero digest in inputs.lock — operator must pin before building." >&2
        echo "fetch-inputs: see packer/kbs-uki/uki/inputs.lock + the README for the pinning procedure." >&2
        exit 65
    fi
done
if [[ "$OVMF_SHA256" == "$ZERO_DIGEST" ]]; then
    echo "fetch-inputs: placeholder zero digest in ovmf.lock — operator must pin before building." >&2
    echo "fetch-inputs: see packer/kbs-uki/ovmf/ovmf.lock + its README for the pinning procedure." >&2
    exit 65
fi

# Clean before extracting — review flagged that stale files
# from a previous run could survive into a new `vmlinuz-*` glob
# pick at the bottom of this script and silently affect the next
# build. The reproducibility check (`make uki-reproducible-check`)
# isolates these dirs PER RUN, but a single-run `make uki` MUST
# also clean.
#
# Clean the CONTENTS of the mounted dirs, not the dirs themselves —
# `/build/fetched` and `/build/work` are Docker bind-mounts, so a
# `rm -rf` on the directory itself trips ENOTEMPTY/EBUSY against the
# mountpoint.
mkdir -p /build/fetched /build/work
find /build/fetched -mindepth 1 -delete
find /build/work    -mindepth 1 -delete
cd /build/fetched

fetch_and_verify() {
    local url="$1"
    local sha="$2"
    local dest="$3"

    echo "fetching $dest from $url" >&2
    curl --fail --silent --show-error --location --output "$dest" "$url"

    local got
    got=$(sha256sum "$dest" | awk '{print $1}')
    if [[ "$got" != "$sha" ]]; then
        rm -f "$dest"
        echo "fetch-inputs: SHA-256 mismatch for $dest" >&2
        echo "  expected: $sha" >&2
        echo "  got:      $got" >&2
        exit 66
    fi
    echo "verified $dest = $sha" >&2
}

fetch_and_verify "$KERNEL_URL" "$KERNEL_SHA256" kernel.deb
fetch_and_verify "$STUB_URL"   "$STUB_SHA256"   systemd-stub.deb
# OVMF firmware — fetched raw (no archive). `measure` passes this file
# straight to `hippius-uki-measure --ovmf`.
fetch_and_verify "$OVMF_URL"   "$OVMF_SHA256"   ovmf.bin

# Both inputs ship as Debian `.deb` archives. We extract the files
# we need into `/build/work/` (deterministic order via `LC_ALL=C` +
# `sort` if needed). `dpkg-deb -x` is repeatable given the same
# `.deb` input.
mkdir -p /build/work/kernel-extracted /build/work/stub-extracted
dpkg-deb -x kernel.deb       /build/work/kernel-extracted
dpkg-deb -x systemd-stub.deb /build/work/stub-extracted

# Locate the vmlinuz binary inside the extracted kernel package.
# Debian layout: /boot/vmlinuz-X.Y.Z-arch. Take the first match in
# byte-sorted order so a kernel `.deb` that legitimately ships two
# (it shouldn't) still produces a deterministic pick.
VMLINUZ=$(find /build/work/kernel-extracted/boot -name 'vmlinuz-*' | LC_ALL=C sort | head -n1)
if [[ -z "$VMLINUZ" ]]; then
    echo "fetch-inputs: no vmlinuz-* found in extracted kernel.deb" >&2
    exit 67
fi
install -m 0644 "$VMLINUZ" /build/work/vmlinuz

# systemd-stub.deb ships `/usr/lib/systemd/boot/efi/linuxx64.efi.stub`.
STUB=/build/work/stub-extracted/usr/lib/systemd/boot/efi/linuxx64.efi.stub
if [[ ! -f "$STUB" ]]; then
    echo "fetch-inputs: linuxx64.efi.stub not found in extracted systemd-boot-efi.deb" >&2
    exit 68
fi
install -m 0644 "$STUB" /build/work/linuxx64.efi.stub

echo "fetch-inputs: OK — vmlinuz + linuxx64.efi.stub staged in /build/work/;" >&2
echo "fetch-inputs:      ovmf.bin staged in /build/fetched/" >&2
