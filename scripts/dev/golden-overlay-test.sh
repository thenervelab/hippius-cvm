#!/usr/bin/env bash
# Unit test for the pure-logic functions of `hippius-golden-overlay.sh`
# (golden-bake PR3) — the GOLDEN-mode detection + parameter validation
# that gates the guest overlay boot. Root-free, no /proc, no devices:
# it sources the library and drives the pure resolvers with cmdline
# STRINGS, so the security-load-bearing branch (golden ⇔ dm-verity.root
# PRESENT and luks_header_sha256 ABSENT; 64-hex root hash; positive
# disk_gb) is pinned in CI without a live boot.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LIB="${HERE}/../initramfs/hippius-golden-overlay.sh"
[[ -r "${LIB}" ]] || { echo "golden-overlay-test: lib not found at ${LIB}" >&2; exit 1; }

# Stubs so the library sources cleanly (the pure functions never call
# these, but a future edit might — fail loud if so).
hippius_log() { :; }
hippius_die() { echo "hippius_die: $*" >&2; return 1; }
# shellcheck source=scripts/initramfs/hippius-golden-overlay.sh
. "${LIB}"

fail=0
ok()  { echo "golden-overlay-test: OK — $*"; }
err() { echo "golden-overlay-test: FAIL — $*" >&2; fail=1; }

GOOD_HASH="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# ── 1. cmdline value extraction ─────────────────────────────────────
v="$(hippius_golden_cmdline_value "ro quiet dm-verity.root=${GOOD_HASH} boot=hippius-golden" "dm-verity.root")"
[[ "${v}" == "${GOOD_HASH}" ]] || err "cmdline_value did not extract dm-verity.root (got '${v}')"
[[ "$(hippius_golden_cmdline_value "ro quiet" "dm-verity.root" || true)" == "" ]] \
    || err "cmdline_value returned a value for an absent key"
ok "cmdline value extraction"

# ── 2. GOLDEN detection: BOTH conditions required ───────────────────
# golden ⇔ dm-verity.root present AND luks_header_sha256 absent.
if hippius_is_golden_cmdline "ro quiet dm-verity.root=${GOOD_HASH} hippius.disk_gb=10 boot=hippius-golden"; then
    ok "golden cmdline detected"
else
    err "golden cmdline NOT detected"
fi
# Legacy: luks header present, no verity root → NOT golden.
if hippius_is_golden_cmdline "ro quiet hippius.luks_header_sha256=${GOOD_HASH} hippius.disk_gb=10"; then
    err "legacy cmdline wrongly detected as golden"
else
    ok "legacy cmdline not golden"
fi
# Half-formed / hostile: BOTH tokens present → fail closed (NOT golden),
# so a miner cannot splice dm-verity.root onto a legacy cmdline to skip
# the LUKS-header gate.
if hippius_is_golden_cmdline "ro dm-verity.root=${GOOD_HASH} hippius.luks_header_sha256=${GOOD_HASH}"; then
    err "both-tokens cmdline wrongly detected as golden (fail-open!)"
else
    ok "both-tokens cmdline fails closed (not golden)"
fi
# Neither token → not golden.
if hippius_is_golden_cmdline "ro quiet console=ttyS0"; then
    err "bare cmdline wrongly detected as golden"
else
    ok "bare cmdline not golden"
fi

# ── 3. root-hash validation (64 lowercase hex) ──────────────────────
hippius_golden_valid_root_hash "${GOOD_HASH}"       || err "valid 64-hex root hash rejected"
! hippius_golden_valid_root_hash ""                 || err "empty root hash accepted"
! hippius_golden_valid_root_hash "abc"              || err "short root hash accepted"
! hippius_golden_valid_root_hash "$(printf 'A%.0s' $(seq 64))" || err "uppercase root hash accepted"
! hippius_golden_valid_root_hash "$(printf 'z%.0s' $(seq 64))" || err "non-hex root hash accepted"
ok "root-hash validation (64 lowercase hex; fail-closed otherwise)"

# ── 4. disk_gb validation (positive integer) ────────────────────────
hippius_golden_valid_disk_gb "10"   || err "valid disk_gb rejected"
hippius_golden_valid_disk_gb "1"    || err "disk_gb=1 rejected"
! hippius_golden_valid_disk_gb "0"  || err "disk_gb=0 accepted"
! hippius_golden_valid_disk_gb ""   || err "empty disk_gb accepted"
! hippius_golden_valid_disk_gb "5x" || err "non-numeric disk_gb accepted"
ok "disk_gb validation (positive integer; the MEASURED size anchor)"

# ── 4b. first-boot mkfs resolver (busybox-shadow-proof) ─────────────
# The upper is formatted with the REAL e2fsprogs mkfs.ext4 the golden hook
# stages at the private HIPPIUS_GOLDEN_MKFS path (some distros' busybox
# ships an `mke2fs` applet that shadows the real binary in $PATH — Debian
# trixie does). Prefer the private copy when present + executable; fall
# back to `$PATH` `mkfs.ext4` otherwise (Ubuntu's busybox omits the applet;
# a dracut-family initrd stages no private copy).
_mkfs_stub="$(mktemp)"; chmod +x "${_mkfs_stub}"
HIPPIUS_GOLDEN_MKFS="${_mkfs_stub}" \
    && [[ "$(HIPPIUS_GOLDEN_MKFS="${_mkfs_stub}" hippius_golden_mkfs_bin)" == "${_mkfs_stub}" ]] \
    && ok "mkfs resolver prefers the private staged binary" \
    || err "mkfs resolver did not prefer the private staged binary"
[[ "$(HIPPIUS_GOLDEN_MKFS="/nonexistent/hippius/mkfs.ext4" hippius_golden_mkfs_bin)" == "mkfs.ext4" ]] \
    && ok "mkfs resolver falls back to \$PATH mkfs.ext4 when the private copy is absent" \
    || err "mkfs resolver did not fall back to \$PATH mkfs.ext4"
rm -f "${_mkfs_stub}"

# ── 5. Driver ordering + KEK shred (golden-bake PR5) ────────────────
# Drive `hippius_golden_run` with STUBBED collaborators that record call
# order + a fake tmpfs KEK, no live boot/devices. Pins two PR5 invariants:
#   (a) the PUBLIC golden lower is opened/verity-verified BEFORE any
#       network / KBS KEK release (validate-before-mutate);
#   (b) the per-VM KEK keyfile is ALWAYS shredded — on success AND on a
#       mid-path hippius_die inside assembly (§20 secret hygiene).
# Section 5 exercises the DRIVER, where hippius_die must model the real
# init's `exit 1` (not the `return 1` the pure-function sections above
# want) — otherwise a mid-path die would fall through to the trailing
# hippius_log and wrongly report success.
hippius_die() { echo "hippius_die: $*" >&2; exit 1; }

ORDER_LOG="$(mktemp)"
KEK_PATH="$(mktemp)"; rm -f "${KEK_PATH}"

# Collaborator stubs (override the real ones the lib just defined).
hippius_parse_cmdline()        { echo parse        >>"${ORDER_LOG}"; }
hippius_golden_modprobe()      { echo modprobe     >>"${ORDER_LOG}"; }
hippius_golden_resolve()       { echo resolve      >>"${ORDER_LOG}"; }
hippius_golden_open_lower()    { echo open_lower   >>"${ORDER_LOG}"; }
hippius_acquire()              { echo acquire      >>"${ORDER_LOG}"; printf 'k' >"$1"; }
hippius_golden_open_upper()    { echo open_upper   >>"${ORDER_LOG}"; }
hippius_golden_mount_overlay() { echo mount_overlay >>"${ORDER_LOG}"; }
# Pin the KEK path so the test can assert it is shredded.
mktemp() {
    case "$*" in
        *hippius-gold-kek*) printf '%s' "${KEK_PATH}"; : >"${KEK_PATH}" ;;
        *) command mktemp "$@" ;;
    esac
}

# 5a. Success path: order + shred.
: >"${ORDER_LOG}"
hippius_golden_run "/fake/rootmnt"
lower_ln="$(grep -n '^open_lower$' "${ORDER_LOG}" | head -1 | cut -d: -f1)"
acq_ln="$(grep -n '^acquire$'    "${ORDER_LOG}" | head -1 | cut -d: -f1)"
if [[ -n "${lower_ln}" && -n "${acq_ln}" && "${lower_ln}" -lt "${acq_ln}" ]]; then
    ok "golden lower verified BEFORE network KBS release (validate-before-mutate)"
else
    err "verity-before-network order violated (open_lower=${lower_ln} acquire=${acq_ln})"
fi
[[ ! -e "${KEK_PATH}" ]] && ok "KEK shredded on the success path" || err "KEK survived the success path"

# 5b. Mid-path failure (open_upper dies AFTER the KEK is released) still
# shreds the KEK and fails the boot closed.
hippius_golden_open_upper() { echo open_upper >>"${ORDER_LOG}"; hippius_die "simulated mid-path failure"; }
: >"${ORDER_LOG}"
if ( hippius_golden_run "/fake/rootmnt" ) 2>/dev/null; then
    err "mid-path failure did NOT fail the golden boot closed (fail-open!)"
else
    ok "mid-path failure fails the golden boot closed"
fi
[[ ! -e "${KEK_PATH}" ]] && ok "KEK shredded even on a mid-path failure (§20)" || err "KEK survived a mid-path failure — secret-hygiene breach"

rm -f "${ORDER_LOG}" "${KEK_PATH}"

if [[ "${fail}" -ne 0 ]]; then
    echo "golden-overlay-test: FAILED" >&2
    exit 1
fi
echo "golden-overlay-test: OK (all checks passed)"
