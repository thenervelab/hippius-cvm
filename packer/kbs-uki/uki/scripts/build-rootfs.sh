#!/usr/bin/env bash
# `build-rootfs.sh` — build a reproducible, dm-verity-protected rootfs.
#
# PR-F3 deliverable A. Produces, in /build/work/:
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
# ## Reproducibility — the load-bearing invariant
#
# Two runs MUST produce a byte-identical rootfs.img AND therefore an
# identical root hash. Determinism is pinned by:
#   - a minimal, fixed staging tree (no host files leak in);
#   - mtimes forced to $SOURCE_DATE_EPOCH on every staged entry;
#   - `mksquashfs` with -all-root (uid/gid 0), -no-xattrs, a fixed
#     single-threaded compressor, and an exported SOURCE_DATE_EPOCH
#     (which mksquashfs reads for every timestamp — it rejects the env
#     var and explicit -mkfs-time/-all-time flags used together);
#   - `veritysetup format` with a PINNED --salt (its default salt is
#     random — that alone would make the root hash non-reproducible).
#
# ## PR-F3 scope
#
# The staged tree is a deterministic MINIMAL placeholder. The real KBS
# userspace (the kbs-server binary + its runtime) is assembled by a
# later §F PR; PR-F3 ships the dm-verity machinery + the root-hash →
# cmdline → launch-digest chain.

set -euo pipefail
umask 022

# Paths default to the in-container layout; `test-build-rootfs.sh`
# overrides them with temp dirs so the reproducibility check can run
# without Docker. build-rootfs.sh reads no repo inputs — it stages its
# own minimal tree — so it is fully relocatable.
WORK="${ROOTFS_WORK:-/build/work}"
OUTPUT="${ROOTFS_OUTPUT:-/build/output}"
STAGING="$WORK/rootfs-staging"
ROOTFS_IMG="$WORK/rootfs.img"
VERITY="$WORK/rootfs.verity"
ROOTHASH_FILE="$WORK/rootfs.roothash"

mkdir -p "$WORK"

# Pinned dm-verity salt + superblock UUID. Both `--salt` AND `--uuid`
# default to random — without pinning, `veritysetup format` produces a
# different root hash (salt is folded into the Merkle tree) AND
# different rootfs.verity file bytes (UUID lives in the superblock at
# offset 0x10) on every run. Pinning both makes BOTH reproducible.
# The UUID is non-secret and does not enter the SNP launch digest (the
# digest covers the cmdline-bound root hash, not the verity superblock
# bytes); pinning it is purely so `make uki-reproducible-check` can
# byte-diff the rootfs.verity file too. Changing either is a deliberate
# measurement-affecting PR. Mirrors `packer/tenant-uki/uki/scripts/
# build-rootfs.sh`.
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
# PR-F3 placeholder: just enough to be a valid, mountable rootfs with a
# pinned /sbin/init. The real userspace lands in a later §F PR.
rm -rf "$STAGING"
mkdir -p "$STAGING"/{sbin,etc,proc,sys,dev,run,tmp}

cat > "$STAGING/sbin/init" <<'INIT'
#!/bin/sh
# PR-F3 placeholder init for the dm-verity rootfs. The real KBS
# userspace init is assembled by a later §F PR. Reaching this means
# the initramfs agent verified dm-verity and switch_root'd correctly.
echo "hippius-kbs: dm-verity rootfs placeholder init (PR-F3)"
exec /bin/sh
INIT
chmod 0755 "$STAGING/sbin/init"

cat > "$STAGING/etc/os-release" <<'OSREL'
NAME="Hippius KBS rootfs"
ID=hippius-kbs-rootfs
PRETTY_NAME="Hippius KBS dm-verity rootfs (PR-F3 placeholder)"
OSREL

# Force-set mtime on every entry (files, dirs, symlinks) so squashfs
# cannot leak the build wall-clock. `-h` covers symlinks.
find "$STAGING" -depth -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

# ── squashfs: read-only, reproducible ───────────────────────────────
rm -f "$ROOTFS_IMG"
# -all-root      : every entry owned by uid/gid 0 (no host-uid leak).
# -no-xattrs     : xattrs are a non-deterministic surface; drop them.
# -noappend      : never append to a stale image.
# -comp gzip     : deterministic compressor; -Xcompression-level fixed.
# -processors 1  : single-threaded so block packing is run-independent.
# All timestamps come from the exported SOURCE_DATE_EPOCH — mksquashfs
# rejects the env var and explicit -mkfs-time/-all-time flags together.
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
# `veritysetup format` over plain files (no block device, no root).
# The PINNED --salt makes the root hash reproducible; the PINNED
# --uuid makes the rootfs.verity FILE bytes reproducible (the UUID
# lives in the verity superblock and defaults to random).
verity_out=$(veritysetup format "$ROOTFS_IMG" "$VERITY" \
    --salt="$VERITY_SALT" \
    --uuid="$VERITY_UUID" \
    --hash="$VERITY_HASH_ALG" \
    --data-block-size="$VERITY_BLOCK_SIZE" \
    --hash-block-size="$VERITY_BLOCK_SIZE")

# veritysetup prints a "Root hash:\t<hex>" line. Extract it exactly.
ROOT_HASH=$(echo "$verity_out" | awk '/^Root hash:/ {print $NF}')
if [[ ! "$ROOT_HASH" =~ ^[0-9a-f]{64}$ ]]; then
    echo "build-rootfs: could not parse a 64-hex root hash from veritysetup:" >&2
    echo "$verity_out" >&2
    exit 70
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
