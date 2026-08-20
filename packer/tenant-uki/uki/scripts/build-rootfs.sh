#!/usr/bin/env bash
# `build-rootfs.sh` — build a reproducible, dm-verity-protected tenant rootfs.
#
# Tenant flavour of `packer/kbs-uki/uki/scripts/build-rootfs.sh`.
# Produces, in /build/work/:
#
#   rootfs.img            — read-only squashfs of the userspace tree.
#   rootfs.verity         — the dm-verity hash tree over rootfs.img.
#   rootfs.roothash       — the verity root hash (64 hex chars), the
#                           value `assemble-uki.sh` embeds into the
#                           UKI cmdline as `dm-verity.root=<hash>`.
#
# At boot the initramfs agent (`switch_root` stage) activates dm-verity
# on the rootfs and refuses to continue unless the device's root hash
# equals the `dm-verity.root=` value baked into the *measured* UKI
# cmdline — so the rootfs is integrity-anchored in the launch digest.
#
# ## What the tenant rootfs contains (vs the KBS rootfs)
#
# The KBS-uki rootfs is a §F3 placeholder (`/sbin/init` that `exec
# /bin/sh`); its real KBS userspace is a deferred §F PR. The tenant
# rootfs ships a compiled `/sbin/init` (the `hippius-agent-tenant-
# init` Rust binary built in the agent-builder Docker stage) — the
# prior `#!/bin/sh` placeholder fail-closed at `switch-root-failed:
# execv` once the rest of the chain shipped, because the
# deterministic rootfs intentionally ships no shell binary. The
# tenant rootfs additionally bundles the two binaries the tenant CVM
# needs AFTER `switch_root`:
#
#   /sbin/hippius-agent-tenant-telemetry  — §23 per-VM telemetry-signer
#                                           service (PR-E2.x). Built
#                                           inside the agent-builder
#                                           Docker stage and COPY'd to
#                                           /opt/hippius/tenant-telemetry.
#   /sbin/netbird                          — NetBird agent static binary
#                                           (pinned by SHA in inputs.lock).
#
# Their bytes are inside the squashfs → covered by the dm-verity root
# hash → folded into the launch digest. A version bump for either is
# a §22 allowlist-affecting PR.
#
# The compiled `/sbin/init` (the Rust `hippius-agent-tenant-init`
# binary) is intentionally minimal — announce on serial, defensively
# re-mount /proc + /sys, then block forever on `pause(2)`. The
# post-pivot service launcher (NoCloud seed → cloud-init → NetBird
# setup-key + mesh join → tenant-telemetry signer) is layered on top
# in dedicated follow-up PRs. The two service binaries above are
# present so each follow-up only adds the launcher logic to
# `/sbin/init`, not the payload.
#
# ## Reproducibility — the load-bearing invariant
#
# Two runs MUST produce a byte-identical rootfs.img AND therefore an
# identical root hash. Determinism is pinned by:
#   - a minimal, fixed staging tree (no host files leak in);
#   - mtimes forced to $SOURCE_DATE_EPOCH on every staged entry;
#   - `mksquashfs` with -all-root (uid/gid 0), -no-xattrs, a fixed
#     single-threaded compressor, and an exported SOURCE_DATE_EPOCH
#     (mksquashfs rejects the env var and explicit -mkfs-time/-all-time
#     flags used together);
#   - `veritysetup format` with a PINNED --salt (its default salt is
#     random — that alone would make the root hash non-reproducible);
#   - the tenant-telemetry binary built inside the pinned-by-digest
#     agent-builder Docker stage; the NetBird binary pinned by SHA.

set -euo pipefail
umask 022

# Paths default to the in-container layout; `test-build-rootfs.sh`
# overrides them with temp dirs so the reproducibility check can run
# without Docker.
WORK="${ROOTFS_WORK:-/build/work}"
OUTPUT="${ROOTFS_OUTPUT:-/build/output}"
STAGING="$WORK/rootfs-staging"
ROOTFS_IMG="$WORK/rootfs.img"
VERITY="$WORK/rootfs.verity"
ROOTHASH_FILE="$WORK/rootfs.roothash"

# Bundled-binary sources. The tenant-telemetry + tenant-init binaries
# are COPY'd from the agent-builder Docker stage to
# `/opt/hippius/tenant-telemetry` + `/opt/hippius/tenant-init`; the
# NetBird binary is staged by `fetch-inputs.sh` at
# `/build/work/netbird`.
TENANT_TELEMETRY_BIN="${TENANT_TELEMETRY_BIN:-/opt/hippius/tenant-telemetry}"
TENANT_INIT_BIN="${TENANT_INIT_BIN:-/opt/hippius/tenant-init}"
NETBIRD_BIN="${NETBIRD_BIN:-$WORK/netbird}"

mkdir -p "$WORK"

# Pinned dm-verity salt + superblock UUID. Both `--salt` AND `--uuid`
# default to random — without pinning, `veritysetup format` produces a
# different root hash (salt is folded into the Merkle tree) AND
# different rootfs.verity file bytes (UUID lives in the superblock at
# offset 0x10) on every run. Pinning both makes BOTH reproducible.
# The UUID is non-secret and does not enter the SNP launch digest (the
# digest covers the cmdline-bound root hash, not the verity superblock
# bytes); pinning it is purely so `make uki-reproducible-check` can
# byte-diff the rootfs.verity file too. Changing either is a
# deliberate measurement-affecting PR.
VERITY_SALT="0000000000000000000000000000000000000000000000000000000000000000"
VERITY_UUID="00000000-0000-0000-0000-000000000000"
VERITY_HASH_ALG="sha256"
VERITY_BLOCK_SIZE="4096"

# Exported (not just assigned) so `mksquashfs` reads it from the
# environment for ALL timestamps even when the caller did not set it.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

for tool in mksquashfs veritysetup; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "build-rootfs: required tool '$tool' not found on PATH." >&2
        echo "build-rootfs: this script runs inside the pinned UKI Docker image" >&2
        echo "build-rootfs: (squashfs-tools + cryptsetup-bin) — see uki/Dockerfile." >&2
        exit 69
    fi
done

# ── Stage a minimal, deterministic userspace tree ───────────────────
# Per-PR scope: the binaries the tenant CVM needs after switch_root are
# present (verity-protected), and `/sbin/init` is a placeholder that
# documents the wire-up. A follow-up PR adds the real launcher (config
# + setup-key fetch + supervisor) without re-shaping the rootfs layout.
rm -rf "$STAGING"
mkdir -p "$STAGING"/{sbin,etc,proc,sys,dev,run,tmp,var/lib/hippius-tenant}

# Bundle the tenant-telemetry binary. `install -m 0755` clears any
# stage-1-baked metadata; the bytes are deterministic because the
# agent-builder stage uses pinned-by-digest base images.
if [[ ! -x "$TENANT_TELEMETRY_BIN" ]]; then
    echo "build-rootfs: tenant-telemetry binary missing at $TENANT_TELEMETRY_BIN" >&2
    echo "build-rootfs: this is COPY'd from the agent-builder Docker stage; see uki/Dockerfile." >&2
    exit 70
fi
install -D -m 0755 "$TENANT_TELEMETRY_BIN" "$STAGING/sbin/hippius-agent-tenant-telemetry"

# Bundle the NetBird static binary. `fetch-inputs.sh` SHA-256-verifies
# the upstream tarball and extracts `netbird` to /build/work/netbird —
# a missing file here means the fetch step did not run (a single-run
# `make uki` runs `fetch` first; the reproducibility check isolates
# the WORK dir, so the same fetch runs again per-run).
if [[ ! -x "$NETBIRD_BIN" ]]; then
    echo "build-rootfs: netbird binary missing at $NETBIRD_BIN" >&2
    echo "build-rootfs: run 'make fetch' first; see uki/scripts/fetch-inputs.sh." >&2
    exit 71
fi
install -D -m 0755 "$NETBIRD_BIN" "$STAGING/sbin/netbird"

# Bundle the tenant-init binary AS `/sbin/init` — the PID-1 entry
# point the initramfs agent `execv`s after switch_root. Replaces the
# prior `#!/bin/sh` placeholder, which fail-closed at
# `switch-root-failed:execv` once the rest of the chain shipped
# (the deterministic rootfs ships no `/bin/sh`). Same reproducibility
# envelope as the two binaries above.
if [[ ! -x "$TENANT_INIT_BIN" ]]; then
    echo "build-rootfs: tenant-init binary missing at $TENANT_INIT_BIN" >&2
    echo "build-rootfs: this is COPY'd from the agent-builder Docker stage; see uki/Dockerfile." >&2
    exit 74
fi
install -D -m 0755 "$TENANT_INIT_BIN" "$STAGING/sbin/init"

# Bundle the .so deps both the tenant-telemetry binary AND the
# tenant-init binary dynamically link (same posture as
# `build-initramfs.sh`: the agent-initramfs is also dynamically
# linked and bundles its `ldd` output). The trixie runtime image is
# pinned by digest, so the resolved `.so` paths and bytes are
# stable. NetBird is a static Go binary — no `ldd` output, skipped.
# The two Rust binaries share libc + libgcc_s + libm; merging their
# `ldd` output keeps the staging tree minimal (no duplicate copy).
LIBS=$( {
    ldd "$STAGING/sbin/hippius-agent-tenant-telemetry"
    ldd "$STAGING/sbin/init"
  } | awk '/=> \//{print $3}' \
    | LC_ALL=C sort -u)
if [[ -z "$LIBS" ]]; then
    echo "build-rootfs: ldd produced no shared-library deps for the bundled Rust binaries" >&2
    echo "build-rootfs: this script expects dynamically-linked agents (see header)." >&2
    exit 72
fi
for lib in $LIBS; do
    install -D -m 0644 "$lib" "$STAGING$lib"
done
# The dynamic linker itself — `ldd` lists it without a `=>` arrow,
# so it must be staged explicitly. Path is baked into the ELF header;
# `readelf -l` confirms `/lib64/ld-linux-x86-64.so.2` on amd64 + glibc.
LINKER=/lib64/ld-linux-x86-64.so.2
if [[ ! -e "$LINKER" ]]; then
    echo "build-rootfs: dynamic linker missing at $LINKER" >&2
    exit 73
fi
install -D -m 0755 "$LINKER" "$STAGING$LINKER"

cat > "$STAGING/etc/os-release" <<'OSREL'
NAME="Hippius tenant"
ID=hippius-tenant-rootfs
PRETTY_NAME="Hippius tenant dm-verity rootfs"
OSREL

# Force-set mtime on every entry (files, dirs, symlinks) so squashfs
# cannot leak the build wall-clock. `-h` covers symlinks.
find "$STAGING" -depth -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

# ── squashfs: read-only, reproducible ───────────────────────────────
rm -f "$ROOTFS_IMG"
# Same flags as kbs-uki/build-rootfs.sh (same reproducibility regime):
#   -all-root      : every entry owned by uid/gid 0 (no host-uid leak).
#   -no-xattrs     : xattrs are a non-deterministic surface; drop them.
#   -noappend      : never append to a stale image.
#   -comp gzip     : deterministic compressor; -Xcompression-level fixed.
#   -processors 1  : single-threaded so block packing is run-independent.
mksquashfs "$STAGING" "$ROOTFS_IMG" \
    -all-root \
    -no-xattrs \
    -noappend \
    -comp gzip \
    -Xcompression-level 9 \
    -processors 1 \
    >/dev/null

# ── dm-verity hash tree + root hash ─────────────────────────────────
rm -f "$VERITY"
verity_out=$(veritysetup format "$ROOTFS_IMG" "$VERITY" \
    --salt="$VERITY_SALT" \
    --uuid="$VERITY_UUID" \
    --hash="$VERITY_HASH_ALG" \
    --data-block-size="$VERITY_BLOCK_SIZE" \
    --hash-block-size="$VERITY_BLOCK_SIZE")

ROOT_HASH=$(echo "$verity_out" | awk '/^Root hash:/ {print $NF}')
if [[ ! "$ROOT_HASH" =~ ^[0-9a-f]{64}$ ]]; then
    echo "build-rootfs: could not parse a 64-hex root hash from veritysetup:" >&2
    echo "$verity_out" >&2
    exit 74
fi

printf '%s' "$ROOT_HASH" > "$ROOTHASH_FILE"

# Publish the rootfs artefacts to the output dir alongside the UKI so
# `make uki-reproducible-check` (which diffs the output dir) proves the
# rootfs + its root hash are byte-identical across runs too.
mkdir -p "$OUTPUT"
cp "$ROOTFS_IMG" "$VERITY" "$ROOTHASH_FILE" "$OUTPUT/"

echo "build-rootfs: OK" >&2
echo "  rootfs.img      $(stat -c%s "$ROOTFS_IMG") bytes" >&2
echo "  rootfs.verity   $(stat -c%s "$VERITY") bytes" >&2
echo "  root hash       $ROOT_HASH" >&2
