#!/usr/bin/env bash
#
# Unit test for the GOLDEN anti-rollback gate in
# `scripts/initramfs/hippius-golden-overlay.sh` — the stamp kept INSIDE
# the guest-keyed encrypted volume and compared, after unlock and before
# the overlayfs root is assembled, against the last CONFIRMED stamp the
# KBS reports in its SIGNED release response.
#
# THE ATTACK IT DEFENDS: the miner snapshots the LUKS overlay, lets the
# VM advance, then restores the OLD overlay while leaving the CURRENT
# boot counter on the miner-writable plaintext state disk. The KBS
# compare-and-swap passes (the submitted counter is current) and
# dm-integrity is satisfied (the old image is authentic ciphertext), so
# only this gate can see it.
#
# THE FAILURE MODE THE DESIGN AVOIDS, and which several tests below pin:
# comparing the in-volume stamp against the BOOT COUNTER would be worse
# than the bug. The boot counter advances on every successful RELEASE,
# not every successful BOOT, so every boot that dies after the KEK ships
# widens the gap by one — and the host controls the VM's lifetime, so any
# fixed tolerance is exhausted after a few kill cycles and the disk is
# permanently unopenable. The reference therefore has to be a value that
# moves ONLY when a volume was actually stamped: the KBS's confirmed
# stamp. See `kbs-core/src/volume_stamp.rs`.
#
# Root-free, no devices, no VM: it SOURCES the library and drives
# `hippius_golden_check_stamp` directly against temp directories, with
# `hippius_die` modelling the real init's `exit 1` so a refusal is
# observable as a non-zero subshell exit.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
LIB="${HERE}/../initramfs/hippius-golden-overlay.sh"
[ -r "${LIB}" ] || { echo "golden-stamp-test: lib not found at ${LIB}" >&2; exit 1; }

fail=0
ok()  { echo "golden-stamp-test: OK — $*"; }
err() { echo "golden-stamp-test: FAIL — $*" >&2; fail=1; }

# shellcheck source=scripts/initramfs/hippius-golden-overlay.sh
. "${LIB}"

# The real init's contract: `hippius_die` never returns (the golden
# driver's subshell then falls through to the KEK shred + fail-closed
# abort). `sync` is a no-op here — durability is not the claim under test.
hippius_die() { echo "hippius_die: $*" >&2; exit 1; }
hippius_log() { :; }
sync() { :; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

SF="${HIPPIUS_GOLDEN_STAMP_NAME}"

# Build a fresh fake "mounted guest-keyed volume root".
#   $1 = the in-volume stamp body, or the literal ABSENT.
# Written WITHOUT a trailing newline on purpose: the gate's write-back
# emits `<value>\n`, so "content is exactly <value>\n" afterwards proves
# the stamp was actually REWRITTEN (and kills a skip-the-write-back
# mutant, which would leave the newline-less body in place).
mkvol() {
    rm -rf "${WORK}/vol"
    mkdir -p "${WORK}/vol"
    if [ "$1" != "ABSENT" ]; then
        printf '%s' "$1" > "${WORK}/vol/${SF}"
    fi
}

# Run the gate. Echoes REFUSED or ALLOWED.
run_gate() {
    # $1 = expected stamp ("" = no expectation this boot)
    if ( hippius_golden_check_stamp "${WORK}/vol" "$1" ) >/dev/null 2>&1; then
        echo ALLOWED
    else
        echo REFUSED
    fi
}

expect() {
    # $1 = expected verdict, $2 = expected stamp, $3 = label
    v="$(run_gate "$2")"
    if [ "${v}" = "$1" ]; then ok "$3"; else err "$3 (expected $1, got ${v})"; fi
}

expect_body() {
    # $1 = expected exact stamp body, $2 = label
    if [ ! -e "${WORK}/vol/${SF}" ]; then
        err "$2 — in-volume stamp is MISSING"
        return
    fi
    got="$(cat "${WORK}/vol/${SF}")"
    if [ "${got}" = "$1" ] && [ "$(wc -c < "${WORK}/vol/${SF}")" -eq $(( ${#1} + 1 )) ]; then
        ok "$2"
    else
        err "$2 (stamp='${got}' bytes=$(wc -c < "${WORK}/vol/${SF}"), wanted '$1' + newline)"
    fi
}

# ── 1. Steady state: S == E → boots, stamp advances to E+1 ───────────
mkvol 7
expect ALLOWED 7 "steady state (in_volume=7 == expected=7) boots"
expect_body 8 "steady state advances the in-volume stamp to E+1"

# ── 2. THE ATTACK: overlay rolled far back, expectation current ──────
mkvol 3
expect REFUSED 50 "ROLLBACK REFUSED (in_volume=3 expected=50) — the reproduced attack"

# ── 3. Boundary: rolled back by exactly ONE is REFUSED ───────────────
# The window is {E, E+1}; anything below E is a rollback, however small.
mkvol 7
expect REFUSED 8 "rollback by exactly 1 REFUSED (in_volume=7 expected=8)"

# ── 4. The crash window: S == E+1 boots (confirm did not land) ───────
# The guest writes E+1 and then confirms. If the confirm is lost the
# volume sits one ahead of the KBS; the next boot must converge, not
# brick.
mkvol 8
expect ALLOWED 7 "S == E+1 boots (the previous boot's confirm never landed)"
expect_body 8 "the crash-window boot re-stamps E+1 (idempotent, no drift)"

# ── 5. S > E+1 is impossible for an honest guest → REFUSED ───────────
mkvol 9
expect REFUSED 7 "in_volume AHEAD of E+1 REFUSED (in_volume=9 expected=7)"

# ── 6. NON-ACCUMULATION — the whole point of the redesign ────────────
# Ten consecutive boots whose confirm never lands. The KBS expectation
# stays at E (only a confirm moves it), so every one of those boots must
# still open the volume and the stamp must NOT drift upward. Under the
# rejected design — comparing against the boot counter, which advances
# per RELEASE — the gap would have grown by one per boot and the volume
# would be permanently unopenable after a couple of cycles.
#
# This also pins the write-back VALUE: a gate that stamped `S+1` instead
# of `E+1` would drift past E+1 on the second iteration and refuse.
mkvol 7
drift=0
for i in $(seq 1 10); do
    v="$(run_gate 7)"
    if [ "${v}" != "ALLOWED" ]; then
        err "aborted-boot #${i} of 10 was REFUSED — the gap accumulated (this is the brick the redesign exists to prevent)"
        drift=1
        break
    fi
    body="$(cat "${WORK}/vol/${SF}")"
    if [ "${body}" != "8" ]; then
        err "aborted-boot #${i} of 10 drifted the stamp to '${body}' (expected a stable 8 = E+1)"
        drift=1
        break
    fi
done
[ "${drift}" -eq 0 ] && ok "10 consecutive unconfirmed boots neither accumulate a gap nor drift the stamp"

# ── 7. E == 0: adopt (fresh VM, pre-gate VM, or rebuilt KBS store) ───
mkvol ABSENT
expect ALLOWED 0 "E=0 with no stamp boots (fresh volume)"
expect_body 1 "fresh volume is seeded with stamp 1"
# A rebuilt KBS store reads 0 while the volume still carries an old
# stamp; adopting is what stops a lost store from bricking the fleet.
mkvol 37
expect ALLOWED 0 "E=0 with an existing stamp boots (rebuilt KBS store — self-healing)"
expect_body 1 "adoption re-anchors the stamp to the rebuilt store"

# ── 8. LEGACY MIGRATION: stamp ABSENT with a real expectation ────────
# Every VM alive today has no in-volume stamp. Refusing would brick the
# whole fleet on the first deploy.
mkvol ABSENT
expect ALLOWED 42 "legacy VM (no in-volume stamp) boots"
expect_body 43 "legacy VM gets the stamp CREATED at E+1"
# ...and it is compared from the very next boot: migration is once-only.
expect REFUSED 9999 "the migrated VM is compared on its NEXT boot (migration is once-only)"

# ── 9. Unparseable ⇒ REFUSE, at EVERY expectation including 0 ────────
# Absence is the legacy signal; garbage is not a legacy VM. Sweeping
# E=0 too matters: the adopt branch must not become a laundering route
# for an unreadable stamp.
for garbage in "abc" "" "12x" "-1" "3 4" "99999999999999999999"; do
    for e in 10 1 0; do
        mkvol "${garbage}"
        expect REFUSED "${e}" "unparseable stamp '${garbage}' REFUSED (expected=${e})"
    done
done
rm -rf "${WORK}/vol"; mkdir -p "${WORK}/vol/${SF}"
expect REFUSED 10 "a stamp path that is a DIRECTORY is REFUSED"

# ── 10. No expectation at all ────────────────────────────────────────
# Distinct from E=0. The expected file and the in-volume stamp are
# written by the SAME measured code, so a stamped volume with no
# expectation is incoherent → refuse.
mkvol ABSENT
expect ALLOWED "" "no expectation + no stamp boots (pre-gate image)"
mkvol 7
expect REFUSED "" "no expectation but a STAMPED volume is REFUSED"

# ── 11. The stamp lives OUTSIDE the overlayfs upperdir ───────────────
# `hippius_golden_mount_overlay` uses ${HIPPIUS_GOLDEN_UPPER_MNT}/upper
# as the overlayfs upperdir. The stamp must sit at the VOLUME ROOT, one
# level above — otherwise the tenant's merged "/" exposes it and
# in-guest root could forge it.
mkvol ABSENT
mkdir -p "${WORK}/vol/upper" "${WORK}/vol/work"
expect ALLOWED 5 "stamp written with an overlayfs upperdir present"
if [ -e "${WORK}/vol/${SF}" ] && [ ! -e "${WORK}/vol/upper/${SF}" ]; then
    ok "stamp is at the VOLUME ROOT, not inside the overlayfs upperdir (tenant cannot see or forge it)"
else
    err "stamp landed in the overlayfs upperdir — the tenant root can see/forge it"
fi
if [ -e "${WORK}/vol/${SF}.new" ]; then
    err "the tmp staging file survived the write-back"
else
    ok "write-back leaves no staging file behind"
fi

# ── 12. The parser fail-closes ───────────────────────────────────────
[ "$(hippius_golden_parse_counter 42)" = "42" ]      || err "parse_counter rejected a valid value"
! hippius_golden_parse_counter ""   >/dev/null 2>&1  || err "parse_counter accepted an empty value"
! hippius_golden_parse_counter "1a" >/dev/null 2>&1  || err "parse_counter accepted a non-decimal value"
! hippius_golden_parse_counter "1234567890123456789" >/dev/null 2>&1 \
    || err "parse_counter accepted a 19-digit value (arithmetic overflow risk)"
ok "stamp parser fail-closes on non-decimal / empty / oversized input"

# ── 13. The gate no longer trusts the miner-writable state disk ──────
# The reference must come from the KBS-signed response, never from
# /dev/vdd. Pin that structurally so a future edit cannot quietly
# reintroduce the accumulating-gap design.
# Comments are stripped first: the header deliberately DISCUSSES the
# state disk and the rejected design, and that prose must stay.
if sed 's/[[:space:]]*#.*$//' "${LIB}" | grep -qE '(/dev/vdd|/hippius-state)'; then
    err "the golden library has EXECUTABLE code referencing the miner-writable state disk again — the accumulating-gap design is back"
else
    ok "the gate takes its reference ONLY from the KBS-signed expectation (no live /dev/vdd read)"
fi

# ── 14. INTEGRATION: the gate is wired into the boot path, and a
#       failed confirm does NOT fail the boot ──────────────────────
# Sections 1-13 drive the gate directly, so they all still pass if
# someone deletes the call from `hippius_golden_mount_overlay`. Drive the
# real assembly function with a mocked `mount`.
MO="${WORK}/mo"
OVERLAY_LOG="${MO}/overlay-mounts"
CONFIRM_LOG="${MO}/confirms"
HIPPIUS_GOLDEN_LOWER_MNT="${MO}/lower"
HIPPIUS_GOLDEN_UPPER_MNT="${MO}/uppervol"
HIPPIUS_GOLDEN_STAMP_EXPECTED="${MO}/expected"
HIPPIUS_GOLDEN_STAMP_CTX="${MO}/ctx"
HIPPIUS_KBS_URL="https://kbs.invalid"

mount() {
    for _a in "$@"; do
        [ "${_a}" = "overlay" ] && echo overlay >>"${OVERLAY_LOG}"
    done
    return 0
}
# Stub the confirm binary; CONFIRM_RC controls whether it succeeds.
CONFIRM_RC=0
hippius-guest-release() { echo "$*" >>"${CONFIRM_LOG}"; return "${CONFIRM_RC}"; }

mo_case() {
    # $1 = in-volume stamp (or ABSENT), $2 = expected (or ABSENT)
    rm -rf "${MO}"
    mkdir -p "${HIPPIUS_GOLDEN_LOWER_MNT}" "${HIPPIUS_GOLDEN_UPPER_MNT}"
    : >"${OVERLAY_LOG}"; : >"${CONFIRM_LOG}"
    [ "$2" = "ABSENT" ] || printf '%s\n' "$2" > "${HIPPIUS_GOLDEN_STAMP_EXPECTED}"
    : > "${HIPPIUS_GOLDEN_STAMP_CTX}"
    [ "$1" = "ABSENT" ] || printf '%s\n' "$1" > "${HIPPIUS_GOLDEN_UPPER_MNT}/${SF}"
    if ( hippius_golden_mount_overlay "${MO}/sysroot" ) >/dev/null 2>&1; then
        echo ALLOWED
    else
        echo REFUSED
    fi
}

v="$(mo_case 3 50)"
if [ "${v}" = "REFUSED" ]; then
    ok "hippius_golden_mount_overlay ABORTS on a rolled-back upper (the gate is wired in)"
else
    err "hippius_golden_mount_overlay assembled a rolled-back upper (gate not wired in!)"
fi
if [ -s "${OVERLAY_LOG}" ]; then
    err "the overlayfs was mounted despite the refusal — tenant bytes exposed before the gate"
else
    ok "no overlayfs mount on the refusal path (gate runs before root assembly)"
fi

v="$(mo_case 7 7)"
if [ "${v}" = "ALLOWED" ] && [ -s "${OVERLAY_LOG}" ]; then
    ok "hippius_golden_mount_overlay assembles the overlay on the happy path (positive control)"
else
    err "mount_overlay refused a healthy volume (verdict=${v})"
fi
if grep -q -- "--confirm-volume-stamp" "${CONFIRM_LOG}" 2>/dev/null; then
    ok "the new stamp is CONFIRMED to the KBS (only a confirm may advance the expectation)"
else
    err "mount_overlay did NOT confirm the stamp — the expectation would never advance"
fi

# A FAILING confirm must not fail the boot: otherwise a miner blocks one
# route and denies every boot.
CONFIRM_RC=1
v="$(mo_case 7 7)"
CONFIRM_RC=0
if [ "${v}" = "ALLOWED" ] && [ -s "${OVERLAY_LOG}" ]; then
    ok "a FAILED confirm does not fail the boot (a dropped confirm must not be a denial of service)"
else
    err "a failed confirm bricked the boot (verdict=${v}) — miner-triggerable DoS"
fi

if [ "${fail}" -ne 0 ]; then
    echo "golden-stamp-test: FAILED" >&2
    exit 1
fi
echo "golden-stamp-test: OK (all checks passed)"
