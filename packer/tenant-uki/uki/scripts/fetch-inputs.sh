#!/usr/bin/env bash
# `fetch-inputs.sh KERNEL_URL KERNEL_SHA256 STUB_URL STUB_SHA256 \
#                  OVMF_URL OVMF_SHA256 NETBIRD_URL NETBIRD_SHA256`
#
# Downloads each input into `/build/fetched/` and refuses to proceed
# if the SHA-256 doesn't match the pinned value. Runs INSIDE the
# Linux/amd64 Docker image so all hosts hit the same `curl` +
# `sha256sum` versions.
#
# Tenant-uki vs kbs-uki: takes one extra input pair (the NetBird
# tarball) — `build-rootfs.sh` bundles the extracted `netbird` binary
# into the verity-protected rootfs, so its bytes are a measured input.
#
# Kernel + systemd-stub arrive as Debian `.deb` archives and are
# unpacked; the OVMF firmware is fetched as a raw `.fd` file (so
# `ovmf.lock` must pin a direct firmware-file URL); the NetBird
# release ships as `netbird_<version>_linux_amd64.tar.gz`.
#
# Fail-closed: any digest mismatch removes the offending file before
# exiting non-zero so a partial-download artefact can't trick the
# next step into accepting it.

set -euo pipefail
umask 022

if [[ $# -ne 8 ]]; then
    echo "usage: $0 KERNEL_URL KERNEL_SHA256 STUB_URL STUB_SHA256 OVMF_URL OVMF_SHA256 NETBIRD_URL NETBIRD_SHA256" >&2
    exit 64
fi

KERNEL_URL="$1"
KERNEL_SHA256="$2"
STUB_URL="$3"
STUB_SHA256="$4"
OVMF_URL="$5"
OVMF_SHA256="$6"
NETBIRD_URL="$7"
NETBIRD_SHA256="$8"

ZERO_DIGEST="0000000000000000000000000000000000000000000000000000000000000000"
for d in "$KERNEL_SHA256" "$STUB_SHA256" "$NETBIRD_SHA256"; do
    if [[ "$d" == "$ZERO_DIGEST" ]]; then
        echo "fetch-inputs: placeholder zero digest in inputs.lock — operator must pin before building." >&2
        echo "fetch-inputs: see packer/tenant-uki/uki/inputs.lock + the README for the pinning procedure." >&2
        exit 65
    fi
done
if [[ "$OVMF_SHA256" == "$ZERO_DIGEST" ]]; then
    echo "fetch-inputs: placeholder zero digest in ovmf.lock — operator must pin before building." >&2
    echo "fetch-inputs: see packer/kbs-uki/ovmf/ovmf.lock + its README for the pinning procedure." >&2
    exit 65
fi

# Clean before extracting — stale files from a previous run could
# survive into a new glob pick and silently affect the next build.
# `make uki-reproducible-check` isolates these dirs PER RUN, but a
# single-run `make uki` MUST also clean.
#
# Clean the CONTENTS of the mounted dirs, not the dirs themselves —
# `/build/fetched` and `/build/work` are Docker bind-mounts, so a
# `rm -rf` on the directory itself trips ENOTEMPTY/EBUSY against the
# mountpoint.
mkdir -p /build/fetched /build/work
find /build/fetched -mindepth 1 -delete
find /build/work    -mindepth 1 -delete
cd /build/fetched

# Download with a bounded retry. snapshot.debian.org is a volunteer-run
# archive that answers 504 intermittently; a single `curl` attempt made
# every `tenant-uki-build` on main red for weeks on commits that never
# touched the UKI (the same pinned URLs answered 302 minutes later). So:
# up to 5 attempts, exponential backoff 5/10/20/40 s, retried ONLY on
# what can be transient — HTTP 5xx, 429, and curl transport failures
# (DNS, connect, timeout, reset, short body). Any other 4xx fails on the
# first attempt: a 404 on a pinned snapshot URL is a broken pin, not a
# blip. The digest check below is outside the loop on purpose — a hash
# mismatch is a security signal and is never retried.
#
# An explicit loop rather than curl's `--retry`: curl's own transient
# set skips connection-refused and short-body (exit 18) failures, and
# `--retry-all-errors` would retry a 404 too. The loop also owns the log
# line, so a red build names the input, the attempt, and the code.
#
# `--connect-timeout` / `--max-time` bound a hung connection per attempt
# (the largest input, the kernel .deb, is tens of MB) so a stalled
# mirror cannot hold the job for the runner's full 6 h.
FETCH_ATTEMPTS=5
FETCH_BACKOFF_INITIAL=5
FETCH_CONNECT_TIMEOUT=30
FETCH_MAX_TIME=600

fetch_and_verify() {
    local url="$1"
    local sha="$2"
    local dest="$3"

    echo "fetching $dest from $url" >&2

    local attempt=1 delay="$FETCH_BACKOFF_INITIAL" rc http
    while :; do
        rc=0
        # `--write-out` still prints `%{http_code}` when `--fail` trips
        # (e.g. `504`, exit 22) and `000` when no response arrived.
        http=$(curl --fail --silent --show-error --location \
                    --connect-timeout "$FETCH_CONNECT_TIMEOUT" \
                    --max-time "$FETCH_MAX_TIME" \
                    --write-out '%{http_code}' \
                    --output "$dest" "$url") || rc=$?
        if [[ $rc -eq 0 ]]; then
            break
        fi
        # Never leave a partial body behind between attempts.
        rm -f "$dest"

        # Exit 22 is `--fail` reporting an HTTP error: only 5xx / 429
        # are transient. Every other exit (6 DNS, 7 connect, 18 short
        # body — which carries http_code 200 — 28 timeout, 56 reset, …)
        # is a transport failure and is retried.
        if [[ $rc -eq 22 ]]; then
            case "$http" in
                429|5[0-9][0-9]) ;;
                *)
                    echo "fetch-inputs: $dest failed (HTTP $http, curl exit $rc) — not retrying: a non-transient HTTP error on a pinned URL is a broken pin, not a blip" >&2
                    exit "$rc"
                    ;;
            esac
        fi
        # Some curl exits are permanent whatever the network does: 1
        # unsupported protocol, 3 malformed URL, 23 local write error,
        # 60 certificate verification failed. Retrying them burns the
        # full backoff for nothing — and retrying a certificate failure
        # would paper over the one error that must never be waited out.
        case "$rc" in
            1|3|23|60)
                echo "fetch-inputs: $dest failed (curl exit $rc) — not retrying: this exit code is permanent, not a transient transport error" >&2
                exit "$rc"
                ;;
        esac

        if [[ $attempt -ge $FETCH_ATTEMPTS ]]; then
            echo "fetch-inputs: $dest failed after $attempt attempts (last: HTTP $http, curl exit $rc)" >&2
            exit "$rc"
        fi
        echo "fetch-inputs: $dest attempt $attempt/$FETCH_ATTEMPTS failed (HTTP $http, curl exit $rc) — retrying in ${delay}s" >&2
        sleep "$delay"
        attempt=$((attempt + 1))
        delay=$((delay * 2))
    done

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

fetch_and_verify "$KERNEL_URL"  "$KERNEL_SHA256"  kernel.deb
fetch_and_verify "$STUB_URL"    "$STUB_SHA256"    systemd-stub.deb
# OVMF firmware — fetched raw (no archive). `measure` passes this file
# straight to `hippius-uki-measure --ovmf`.
fetch_and_verify "$OVMF_URL"    "$OVMF_SHA256"    ovmf.bin
# NetBird tarball — `build-rootfs.sh` consumes the extracted binary.
fetch_and_verify "$NETBIRD_URL" "$NETBIRD_SHA256" netbird.tar.gz

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

# ── NetBird: extract the static binary ─────────────────────────────
#
# The NetBird release tarball lays out as `./netbird` at the top
# level — `tar -xzf` is deterministic given the same input. Refuse
# to proceed if the expected binary is absent (a release layout
# change would silently produce a tenant rootfs WITHOUT NetBird).
#
# Defense-in-depth: the tarball SHA is verified above, but a future
# upstream / signing-key compromise could ship a malicious archive
# whose entries are `../sbin/init` or symlinks pointing into the host.
# We extract with `--no-same-owner --no-same-permissions` (drop any
# baked-in uid/gid + mode metadata — the `install -m 0755` below sets
# the only mode that matters), and immediately scrub any symlinks
# and non-regular-file entries from the extraction tree before we
# `find` for the `netbird` ELF.
mkdir -p /build/work/netbird-extracted
tar --no-same-owner --no-same-permissions -xzf netbird.tar.gz \
    -C /build/work/netbird-extracted
# Drop any symlinks / special files — tarballs may carry them. The
# tenant rootfs only consumes a single regular-file ELF.
find /build/work/netbird-extracted \( -type l -o -type b -o -type c \
    -o -type p -o -type s \) -delete
NETBIRD_BIN=$(find /build/work/netbird-extracted -name 'netbird' -type f | LC_ALL=C sort | head -n1)
if [[ -z "$NETBIRD_BIN" ]]; then
    echo "fetch-inputs: no 'netbird' binary found in extracted netbird.tar.gz" >&2
    exit 69
fi
install -m 0755 "$NETBIRD_BIN" /build/work/netbird

echo "fetch-inputs: OK — vmlinuz + linuxx64.efi.stub + netbird staged in /build/work/;" >&2
echo "fetch-inputs:      ovmf.bin staged in /build/fetched/" >&2
