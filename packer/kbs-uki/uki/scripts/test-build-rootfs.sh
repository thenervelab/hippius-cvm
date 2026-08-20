#!/usr/bin/env bash
# `test-build-rootfs.sh` — shell test for the dm-verity rootfs build.
#
# Always: `bash -n` syntax-checks the dm-verity scripts.
#
# When `mksquashfs` + `veritysetup` are on PATH: runs `build-rootfs.sh`
# twice into isolated dirs and asserts the rootfs image AND the
# dm-verity root hash are byte-identical — the reproducibility contract
# that makes the launch measurement stable.
#
# When the tools are absent (a plain dev box, the cargo-test CI
# runner): it SKIPs the reproducibility run with a clear notice. The
# scripts are exercised end-to-end by an operator inside the pinned UKI
# Docker image (`make rootfs`) — the same review-then-operator-run
# precedent PR-F2 set for this directory.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BUILD_ROOTFS="$SCRIPT_DIR/build-rootfs.sh"

# ── Always: syntax-check ────────────────────────────────────────────
echo "test-build-rootfs: syntax-checking dm-verity scripts..."
for s in build-rootfs.sh assemble-uki.sh; do
    if bash -n "$SCRIPT_DIR/$s"; then
        echo "  OK    $s"
    else
        echo "  FAIL  $s — syntax error"
        exit 1
    fi
done

# ── Conditional: full reproducibility run ───────────────────────────
if ! command -v mksquashfs >/dev/null 2>&1 \
   || ! command -v veritysetup >/dev/null 2>&1; then
    echo "test-build-rootfs: SKIP reproducibility run — mksquashfs/veritysetup"
    echo "test-build-rootfs: not on PATH. Run \`make rootfs\` inside the pinned"
    echo "test-build-rootfs: UKI Docker image for the full byte-identical check."
    echo "test-build-rootfs: PASS (syntax only)"
    exit 0
fi

echo "test-build-rootfs: running build-rootfs.sh twice (reproducibility)..."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
# Pin the clock so the only thing under test is the script's own
# determinism, not the wall time.
export SOURCE_DATE_EPOCH=1700000000

run() {
    local tag="$1"
    if ! ROOTFS_WORK="$TMP/$tag/work" ROOTFS_OUTPUT="$TMP/$tag/out" \
            bash "$BUILD_ROOTFS" >/dev/null 2>"$TMP/$tag.log"; then
        echo "  FAIL  build-rootfs.sh run $tag errored:"
        sed 's/^/    /' "$TMP/$tag.log"
        exit 1
    fi
}
run a
run b

HASH_A=$(cat "$TMP/a/work/rootfs.roothash")
HASH_B=$(cat "$TMP/b/work/rootfs.roothash")

if [[ ! "$HASH_A" =~ ^[0-9a-f]{64}$ ]]; then
    echo "  FAIL  root hash is not a 64-hex digest: '$HASH_A'"
    exit 1
fi
if [[ "$HASH_A" != "$HASH_B" ]]; then
    echo "  FAIL  dm-verity root hash diverged across runs:"
    echo "          run a: $HASH_A"
    echo "          run b: $HASH_B"
    exit 1
fi
if ! cmp -s "$TMP/a/work/rootfs.img" "$TMP/b/work/rootfs.img"; then
    echo "  FAIL  rootfs.img diverged across runs (not byte-identical)"
    exit 1
fi

echo "  OK    rootfs.img byte-identical; dm-verity root hash stable"
echo "  OK    root hash = $HASH_A"
echo "test-build-rootfs: PASS"
