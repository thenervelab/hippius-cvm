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

# ── 10b. Customer keys (M1/M2): no legacy, no pre-gate ──────────────
# M1/M2 volumes are born stamped, so "no stamp, E > 0" is a blanked or
# swapped volume, not a migration; and a boot without an expectation is
# not a pre-gate image. Both fail closed. E == 0 still seeds.
for mode in split customer; do
    HIPPIUS_GOLDEN_KEY_MODE="${mode}"
    mkvol ABSENT
    expect REFUSED 42 "${mode}: no stamp + E=42 REFUSED (no legacy migration in M1/M2)"
    [ ! -e "${WORK}/vol/${SF}" ] && ok "${mode}: the refused volume got no stamp" \
        || err "${mode}: a refused volume was stamped"
    mkvol ABSENT
    expect REFUSED "" "${mode}: no expectation + no stamp REFUSED (no pre-gate M1/M2 image)"
    mkvol ABSENT
    expect ALLOWED 0 "${mode}: E=0 + no stamp still seeds (first boot)"
    expect_body 1 "${mode}: the first boot is stamped 1"
    mkvol 7
    expect ALLOWED 7 "${mode}: steady state unchanged"
done
unset HIPPIUS_GOLDEN_KEY_MODE
mkvol ABSENT
expect ALLOWED 42 "M0: the legacy migration is still accepted once"

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

# ═════════════════════════════════════════════════════════════════════
# STAMP PROTOCOL v2 — the in-volume stamp is the pair (TIMELINE, value).
# The timeline sits in a sidecar next to the stamp; no sidecar = the zero
# timeline (a legacy stamp). The gate accepts only the release's EXPECTED
# timeline, then writes its TARGET timeline and E+1. Closes blocker B1:
# after an authorized rollback (E := E_T, the VM moved to a fresh
# timeline TB) a disk of the ABANDONED timeline TA carries the same
# numbers the restored timeline will write — only the timeline tells
# them apart.
# ═════════════════════════════════════════════════════════════════════
TF="${HIPPIUS_GOLDEN_TIMELINE_NAME}"
Z="${HIPPIUS_GOLDEN_ZERO_TIMELINE}"
TA="$(printf 'a%.0s' $(seq 1 64))"
TB="$(printf 'b%.0s' $(seq 1 64))"
TC="$(printf 'c%.0s' $(seq 1 64))"

# $1 = stamp body or ABSENT, $2 = timeline sidecar body or ABSENT
mkvol2() {
    mkvol "$1"
    if [ "$2" != "ABSENT" ]; then
        printf '%s' "$2" > "${WORK}/vol/${TF}"
    fi
}

# $1 = verdict, $2 = E, $3 = expected timeline, $4 = target timeline, $5 = label
expect2() {
    if ( hippius_golden_check_stamp_v2 "${WORK}/vol" "$2" "$3" "$4" ) >/dev/null 2>&1; then
        _x2=ALLOWED
    else
        _x2=REFUSED
    fi
    if [ "${_x2}" = "$1" ]; then ok "$5"; else err "$5 (expected $1, got ${_x2})"; fi
}

# $1 = exact sidecar body (+ newline), $2 = label
expect_timeline() {
    got="$(cat "${WORK}/vol/${TF}" 2>/dev/null || echo '<absent>')"
    if [ "${got}" = "$1" ] && [ "$(wc -c < "${WORK}/vol/${TF}")" -eq 65 ]; then
        ok "$2"
    else
        err "$2 (timeline='${got}', wanted '$1' + newline)"
    fi
}

# $1 = stamp body, $2 = sidecar body (or ABSENT), $3 = label — the volume
# must be EXACTLY as planted (a refusal writes nothing).
expect_untouched() {
    s="$(cat "${WORK}/vol/${SF}" 2>/dev/null || echo '<absent>')"
    t="$(cat "${WORK}/vol/${TF}" 2>/dev/null || echo ABSENT)"
    if [ "${s}" = "$1" ] && [ "${t}" = "$2" ]; then ok "$3"; else err "$3 (stamp='${s}' timeline='${t}')"; fi
}

# ── 15. Steady state on the zero timeline + the LEGACY UPGRADE ───────
mkvol2 7 ABSENT
expect2 ALLOWED 7 "${Z}" "${Z}" "v2 steady state on a LEGACY stamp (reads as the zero timeline) boots"
expect_body 8 "v2 steady state advances the stamp to E+1"
expect_timeline "${Z}" "a legacy stamp is UPGRADED: the zero-timeline sidecar is written"
expect2 ALLOWED 8 "${Z}" "${Z}" "the upgraded volume boots again on the zero timeline"

# The upgrade happens ONLY under a release that expects the zero
# timeline: a legacy disk is never taken for a timeline-bound one.
mkvol2 7 ABSENT
expect2 REFUSED 7 "${TA}" "${TA}" "a LEGACY stamp is REFUSED by a release bound to a non-zero timeline"
expect_untouched 7 ABSENT "the refused legacy volume is untouched (no sidecar written)"

# ── 16. THE B1 ATTACK: an abandoned-timeline disk after a rollback ───
# The VM was on TA; an authorized rollback restored the point (TA, E_T=5)
# and moved the VM to TB. The miner now presents the ABANDONED disk (TA,
# v) — for EVERY value v, including the ones the restored timeline itself
# writes next — against a release that expects TB. Each must be refused,
# and the disk left as it was.
for v in 4 5 6 7 9; do
    for e in 5 6; do
        mkvol2 "${v}" "${TA}"
        expect2 REFUSED "${e}" "${TB}" "${TB}" "B1: abandoned-timeline disk (TA, ${v}) REFUSED after the rollback (E=${e}, expecting TB)"
        expect_untouched "${v}" "${TA}" "B1: the refused abandoned disk (TA, ${v}) is untouched"
    done
done
# A legacy (pre-v2) disk of the abandoned timeline is refused the same way.
mkvol2 6 ABSENT
expect2 REFUSED 5 "${TB}" "${TB}" "B1: an abandoned LEGACY disk (zero timeline, 6) REFUSED after a rollback to TB"
# Contrast: the v1 gate — value only — ACCEPTS the abandoned disk. That is
# the hole; the sidecar-blind v1 comparison is why v2 exists.
mkvol2 6 "${TA}"
expect ALLOWED 5 "(contrast) the v1 value-only gate accepts the abandoned disk (TA, 6) at E=5"

# ── 17. The authorized-rollback release itself: TA → TB ──────────────
mkvol2 5 "${TA}"
expect2 ALLOWED 5 "${TA}" "${TB}" "the rollback release accepts the restored point (TA, E_T=5)"
expect_timeline "${TB}" "the restored volume MOVES to the fresh timeline TB"
expect_body 6 "…and is stamped E_T+1"
expect2 ALLOWED 5 "${TB}" "${TB}" "the next release (TB → TB) accepts the restored volume"
# The honest limit (documented in kbs-core::rollback): a point of the same
# boot epoch at E_T+1 is admitted too; E_T+2 is not.
mkvol2 6 "${TA}"
expect2 ALLOWED 5 "${TA}" "${TB}" "the rollback release accepts (TA, E_T+1) — the documented {E_T, E_T+1} window"
mkvol2 7 "${TA}"
expect2 REFUSED 5 "${TA}" "${TB}" "the rollback release REFUSES (TA, E_T+2) — ahead of the window"
# A disk of ANOTHER timeline is not the restored point.
mkvol2 5 "${TC}"
expect2 REFUSED 5 "${TA}" "${TB}" "the rollback release REFUSES a disk of another timeline (TC, 5)"

# ── 18. A LOST first rollback response fails CLOSED ──────────────────
# The KBS committed the rollback (the VM is on TB) but the response never
# reached the guest, so the restored disk still says (TA, 5). Every later
# release is a normal TB → TB one: refused — another authorized rollback
# is needed, the disk is never opened on a timeline it was not moved to.
mkvol2 5 "${TA}"
expect2 REFUSED 5 "${TB}" "${TB}" "a lost first rollback response: (TA, 5) REFUSED by the next TB release"
expect_untouched 5 "${TA}" "the unmoved restored disk stays exactly as restored (a re-armed rollback can still take it)"

# ── 19. A crash between the timeline write and the value write ───────
# The gate writes the TARGET timeline FIRST: a crash then leaves (TB,
# E_T), which the next TB release still accepts. (The reverse order
# would strand the restored volume on TA.)
mkvol2 5 "${TB}"
expect2 ALLOWED 5 "${TB}" "${TB}" "a crash after the timeline write (TB, E_T) still boots on TB"
expect_body 6 "…and completes the stamp"

# The ORDER itself: when the value write fails, the timeline has already
# been moved (never the reverse, which strands a restored volume).
mkvol2 5 "${TA}"
mkdir -p "${WORK}/vol/${SF}.new"
expect2 REFUSED 5 "${TA}" "${TB}" "a failed stamp write fails the boot closed"
expect_timeline "${TB}" "…AFTER the timeline was moved (timeline first, value second)"

# ── 20. E == 0: ADOPT (fresh VM or rebuilt KBS store) ────────────────
mkvol2 37 "${TA}"
expect2 ALLOWED 0 "${Z}" "${Z}" "v2 E=0 ADOPTS whatever it finds (rebuilt KBS store — self-healing, as v1)"
expect_timeline "${Z}" "adoption re-anchors the timeline to the target"
expect_body 1 "…and the stamp to 1"
mkvol2 ABSENT ABSENT
expect2 ALLOWED 0 "${Z}" "${Z}" "v2 fresh volume boots"
expect_timeline "${Z}" "the fresh volume gets its timeline sidecar"
expect_body 1 "…and stamp 1"

# ── 21. No in-volume stamp: migration ONLY for a legacy zero-timeline volume
mkvol2 ABSENT ABSENT
expect2 ALLOWED 42 "${Z}" "${Z}" "v2 legacy MIGRATION (no stamp, no sidecar, zero timeline) boots once"
expect_body 43 "the migrated volume is stamped E+1"
mkvol2 ABSENT "${Z}"
expect2 REFUSED 42 "${Z}" "${Z}" "no stamp but a timeline sidecar is REFUSED (not a legacy volume)"
mkvol2 ABSENT ABSENT
expect2 REFUSED 42 "${TA}" "${TA}" "no stamp under a release bound to a non-zero timeline is REFUSED"
mkvol2 ABSENT ABSENT
expect2 REFUSED 42 "${Z}" "${TB}" "no stamp under a ROLLBACK release is REFUSED (a restored point is always stamped)"

# ── 22. Unparseable timeline / stamp ⇒ REFUSE, at every E ────────────
for garbage in "zz" "${TA}0" "$(printf 'A%.0s' $(seq 1 64))" "" "${TA} ${TA}"; do
    for e in 5 0; do
        mkvol2 5 "${garbage}"
        expect2 REFUSED "${e}" "${TA}" "${TA}" "unparseable timeline sidecar '${garbage:0:8}…' REFUSED (E=${e})"
    done
done
mkvol2 "abc" "${TA}"
expect2 REFUSED 5 "${TA}" "${TA}" "an unparseable stamp on the right timeline is REFUSED"
[ "$(hippius_golden_parse_timeline "${TA}")" = "${TA}" ] || err "parse_timeline rejected a valid id"
! hippius_golden_parse_timeline "${TA%a}" >/dev/null 2>&1 || err "parse_timeline accepted 63 chars"
! hippius_golden_parse_timeline "$(printf 'g%.0s' $(seq 1 64))" >/dev/null 2>&1 || err "parse_timeline accepted non-hex"
ok "timeline parser fail-closes on short / non-hex input"

# ── 23. The raw value-only gate leaves the timeline sidecar alone ────
# `hippius_golden_check_stamp` itself never reads the sidecar; the boot
# path wraps it in `hippius_golden_check_stamp_v1` (23b), which refuses
# a timeline-bound volume before this runs.
mkvol2 7 "${TA}"
expect ALLOWED 7 "v1 gate on a v2 volume boots (value-only, as before)"
expect_untouched 8 "${TA}" "the v1 gate stamps E+1 and leaves the timeline sidecar untouched"

# ── 22b. S2: after a KBS restart the E=0 release moves to a FRESH timeline
# The KBS store was wiped (E=0). Its v2 release now carries zero -> TC (a
# fresh timeline). The guest adopts whatever it finds and stamps (TC, 1);
# after the confirm the KBS expects TC, so the disks the VM would
# otherwise have re-accepted once E caught up — the zero-timeline volume
# it counted from before, and a disk a pre-wipe rollback abandoned (TA) —
# are refused whatever their value.
mkvol2 5 "${TB}"
expect2 ALLOWED 0 "${Z}" "${TC}" "S2: E=0 release zero -> fresh TC adopts the current disk"
expect_timeline "${TC}" "S2: …which moves to the fresh timeline"
expect_body 1 "S2: …stamped 1"
expect2 ALLOWED 1 "${TC}" "${TC}" "S2: the next release (TC, E=1) accepts it"
for v in 1 2; do
    for t in "${Z}" ABSENT "${TA}" "${TB}"; do
        mkvol2 "${v}" "${t}"
        expect2 REFUSED 1 "${TC}" "${TC}" "S2: an earlier-timeline disk (${t:0:4}…, ${v}) is REFUSED once the VM is on TC (E=1)"
    done
done

# ── 23b. S1: the v1 gate AS THE BOOT PATH RUNS IT on a timeline-bound
#        volume (hippius_golden_check_stamp_v1): REFUSED at every E ───
# Since R1 only M2 ever reaches this gate (M0/M1 never retry v1 and the
# boot path refuses them a transition-less release — section 24), and an
# honest M2 volume is never timeline-bound; the refusal stays as a
# DEFENCE. The scenario it defends: a VM on a non-zero timeline TA, then
# a KBS restart (E=0, zero timeline), then the v2 attempt is refused — a
# transient 403, or one the MINER FORGED — and a v1 release is served
# anyway. The raw value-only
# gate (23) would adopt and leave TA in the sidecar while the v1 confirm
# lands on the zero timeline: every later v2 release (expecting zero)
# refuses the volume — an honest VM bricked. Resetting the sidecar to
# zero instead would let the forged 403 pin the VM to the zero timeline
# for good (E=1 after that confirm: no fresh-timeline move any more),
# re-opening abandoned zero-timeline disks. So: refuse, write nothing;
# the next boot's v2 release (still E=0) adopts on a fresh timeline.
# $1 = verdict, $2 = E ("" = none), $3 = label
expect_v1() {
    if ( hippius_golden_check_stamp_v1 "${WORK}/vol" "$2" ) >/dev/null 2>&1; then
        _xv1=ALLOWED
    else
        _xv1=REFUSED
    fi
    if [ "${_xv1}" = "$1" ]; then ok "$3"; else err "$3 (expected $1, got ${_xv1})"; fi
}
# The forged-403-then-v1 sequence, end to end on the volume.
mkvol2 7 "${TA}"
expect_v1 REFUSED 0 "S1: forged 403 then a v1 release at E=0 on a non-zero timeline is REFUSED"
expect_untouched 7 "${TA}" "S1: …and NOTHING is written (no adopt, no timeline reset)"
expect2 ALLOWED 0 "${Z}" "${TC}" "S1: the next boot's v2 release (E=0, zero -> fresh TC) adopts the untouched volume"
expect_timeline "${TC}" "S1: …which lands on the fresh timeline, never the zero one"
expect_body 1 "S1: …stamped 1"
for e in 0 1 7 8 ""; do
    mkvol2 7 "${TA}"
    expect_v1 REFUSED "${e}" "S1: a v1 release (E=${e:-<absent>}) REFUSES a volume on a non-zero timeline"
    expect_untouched 7 "${TA}" "S1: the refused volume (E=${e:-<absent>}) is untouched"
done
mkvol2 ABSENT "${TA}"
expect_v1 REFUSED 0 "S1: a non-zero sidecar with no stamp is REFUSED under v1 too"
mkvol2 7 "zz"
expect_v1 REFUSED 0 "S1: an unparseable sidecar under a v1 release is REFUSED"
# A zero-timeline sidecar, or none: exactly the v1 gate as before.
mkvol2 7 "${Z}"
expect_v1 ALLOWED 7 "v1 on a ZERO-timeline volume: value-only, as before"
expect_untouched 8 "${Z}" "…stamps E+1, sidecar kept"
mkvol2 3 "${Z}"
expect_v1 REFUSED 50 "v1 on a zero-timeline volume still refuses a rolled-back stamp"
mkvol2 7 ABSENT
expect_v1 ALLOWED 7 "v1 on a LEGACY volume: value-only, as before"
expect_untouched 8 ABSENT "…no sidecar written"

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

# Sections 14-15 drive the boot path with NO timeline transition — a v1
# release, which only M2 (`customer`, the guardian's stamp) ever gets:
# M0/M1 refuse a release without one (section 24).
HIPPIUS_GOLDEN_KEY_MODE=customer

# The mocked overlay mount leaves the tenant root empty: give it the
# /var/lib every lower ships, under which the #1347 data bind lands.
mo_case() {
    # $1 = in-volume stamp (or ABSENT), $2 = expected (or ABSENT)
    rm -rf "${MO}"
    mkdir -p "${HIPPIUS_GOLDEN_LOWER_MNT}" "${HIPPIUS_GOLDEN_UPPER_MNT}" "${MO}/sysroot/var/lib"
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

# ── 24. INTEGRATION (v2): a transition file selects the v2 gate ─────
HIPPIUS_GOLDEN_STAMP_TRANSITION="${MO}/transition"
HIPPIUS_GOLDEN_KEY_MODE=""
# $1 = stamp, $2 = sidecar (or ABSENT), $3 = expected, $4 = transition body (or ABSENT)
mo_case2() {
    rm -rf "${MO}"
    mkdir -p "${HIPPIUS_GOLDEN_LOWER_MNT}" "${HIPPIUS_GOLDEN_UPPER_MNT}" "${MO}/sysroot/var/lib"
    : >"${OVERLAY_LOG}"; : >"${CONFIRM_LOG}"
    printf '%s\n' "$3" > "${HIPPIUS_GOLDEN_STAMP_EXPECTED}"
    : > "${HIPPIUS_GOLDEN_STAMP_CTX}"
    [ "$4" = "ABSENT" ] || printf '%s\n' "$4" > "${HIPPIUS_GOLDEN_STAMP_TRANSITION}"
    printf '%s\n' "$1" > "${HIPPIUS_GOLDEN_UPPER_MNT}/${SF}"
    [ "$2" = "ABSENT" ] || printf '%s\n' "$2" > "${HIPPIUS_GOLDEN_UPPER_MNT}/${TF}"
    if ( hippius_golden_mount_overlay "${MO}/sysroot" ) >/dev/null 2>&1; then
        echo ALLOWED
    else
        echo REFUSED
    fi
}
v="$(mo_case2 6 "${TA}" 5 "${TB} ${TB}")"
if [ "${v}" = "REFUSED" ] && [ ! -s "${OVERLAY_LOG}" ]; then
    ok "mount_overlay runs the v2 gate when the release carried a transition (abandoned disk refused, no overlay)"
else
    err "mount_overlay did not refuse the abandoned-timeline disk under a v2 release (verdict=${v})"
fi
# R1: M0/M1 NEVER take a v1 release. A forged 403 to the v2 attempt no
# longer buys a v1 retry (hippius-guest-release fails the boot), and a
# release without a transition is refused by the boot path too — at every
# E, on a legacy, zero- or non-zero-timeline volume — with nothing
# written and nothing confirmed. The forged-403 scenario after a KBS
# store wipe (E=0, old zero-timeline disk) is a denial of service only.
for km in "" split; do
    HIPPIUS_GOLDEN_KEY_MODE="${km}"
    for tl in ABSENT "${Z}" "${TA}"; do
        for e in 0 5; do
            v="$(mo_case2 6 "${tl}" "${e}" ABSENT)"
            if [ "${v}" = "REFUSED" ] && [ ! -s "${OVERLAY_LOG}" ] && [ ! -s "${CONFIRM_LOG}" ] \
                && [ "$(cat "${HIPPIUS_GOLDEN_UPPER_MNT}/${SF}")" = "6" ] \
                && { [ "${tl}" = ABSENT ] && [ ! -e "${HIPPIUS_GOLDEN_UPPER_MNT}/${TF}" ] \
                     || [ "$(cat "${HIPPIUS_GOLDEN_UPPER_MNT}/${TF}" 2>/dev/null)" = "${tl}" ]; }; then
                ok "R1: ${km:-M0} without a transition (E=${e}, timeline ${tl:0:4}…) is REFUSED, nothing written or confirmed"
            else
                err "R1: ${km:-M0} without a transition (E=${e}, timeline ${tl:0:4}…) was not refused cleanly (verdict=${v})"
            fi
        done
    done
done
# M2 is unchanged: no transition = the v1 gate.
HIPPIUS_GOLDEN_KEY_MODE=customer
v="$(mo_case2 6 "${Z}" 5 ABSENT)"
if [ "${v}" = "ALLOWED" ]; then
    ok "M2: mount_overlay runs the v1 gate when the release carried NO transition (v1 behaviour unchanged)"
else
    err "an M2 v1 release no longer takes the v1 gate (verdict=${v})"
fi
# S1, wired: the boot path's v1 branch is the timeline-aware v1 gate.
v="$(mo_case2 6 "${TA}" 5 ABSENT)"
if [ "${v}" = "REFUSED" ] && [ ! -s "${OVERLAY_LOG}" ]; then
    ok "S1: mount_overlay's v1 branch REFUSES a timeline-bound volume at E>0"
else
    err "S1: mount_overlay's v1 branch took a timeline-bound volume at E>0 (verdict=${v})"
fi
v="$(mo_case2 6 "${TA}" 0 ABSENT)"
if [ "${v}" = "REFUSED" ] && [ ! -s "${OVERLAY_LOG}" ] && [ ! -s "${CONFIRM_LOG}" ] \
    && [ "$(cat "${HIPPIUS_GOLDEN_UPPER_MNT}/${TF}")" = "${TA}" ] \
    && [ "$(cat "${HIPPIUS_GOLDEN_UPPER_MNT}/${SF}")" = "6" ]; then
    ok "S1: mount_overlay's v1 branch at E=0 REFUSES a timeline-bound volume, writes nothing, confirms nothing"
else
    err "S1: mount_overlay's v1 branch at E=0 (verdict=${v})"
fi
v="$(mo_case2 5 "${TA}" 5 "${TA} ${TB}")"
if [ "${v}" = "ALLOWED" ] && [ "$(cat "${HIPPIUS_GOLDEN_UPPER_MNT}/${TF}")" = "${TB}" ] \
    && grep -q -- "--confirm-volume-stamp" "${CONFIRM_LOG}"; then
    ok "mount_overlay completes an authorized rollback: TA -> TB, then confirms"
else
    err "mount_overlay rollback release (verdict=${v})"
fi
# A malformed transition NEVER falls back to the v1 gate.
for bad in "garbage" "${TA}" "${TA} ${TB} ${TC}" "${TA} zz"; do
    v="$(mo_case2 5 ABSENT 5 "${bad}")"
    if [ "${v}" = "REFUSED" ] && [ ! -s "${OVERLAY_LOG}" ]; then
        ok "a malformed transition '${bad:0:10}...' is REFUSED, never read as a v1 release"
    else
        err "a malformed transition '${bad:0:10}...' was not refused (verdict=${v})"
    fi
done

# ── 25. Customer keys (H5b) under stamp protocol v2 ─────────────────
# M1 attests v2 (KBS stamp + timeline gate); M2 attests v1 (guardian
# stamp, v1 gate). Three H5b rules sit on top of both gates:
#   - no legacy migration in M1/M2 (no stamp under E > 0 ⇒ refuse);
#   - no expectation ⇒ refuse (v2 already refuses; v1 now too for M2);
#   - on the FIRST boot (the version-less, E == 0 format) the confirm is
#     mandatory — retried, then fatal — so a dropped confirm cannot keep
#     E at 0 behind a provisioned volume. Later boots and M0 stay
#     non-fatal.
KV="${WORK}/kvol"
kgate_v2() { # $1 key mode, $2 expected, $3 expected tl, $4 target tl
    rm -rf "${KV}"; mkdir -p "${KV}"
    if ( HIPPIUS_GOLDEN_KEY_MODE="$1" hippius_golden_check_stamp_v2 "${KV}" "$2" "$3" "$4" ) >/dev/null 2>&1
    then echo ALLOWED; else echo REFUSED; fi
}
[ "$(kgate_v2 split 42 "${Z}" "${Z}")" = REFUSED ] && [ ! -e "${KV}/${SF}" ] && [ ! -e "${KV}/${TF}" ] \
    && ok "25a: M1 v2, no stamp + E=42 on the zero timeline: REFUSED (no legacy migration), nothing written" \
    || err "25a: M1 v2 took the legacy migration"
[ "$(kgate_v2 "" 42 "${Z}" "${Z}")" = ALLOWED ] \
    && ok "25a: M0 v2 keeps #1320's one-time legacy migration" \
    || err "25a: M0 v2 lost the legacy migration"
[ "$(kgate_v2 split 0 "${Z}" "${TA}")" = ALLOWED ] && [ "$(cat "${KV}/${TF}")" = "${TA}" ] && [ "$(cat "${KV}/${SF}")" = 1 ] \
    && ok "25b: M1 v2 first boot (E=0): adopts the KBS's fresh timeline and stamps (TA,1)" \
    || err "25b: M1 v2 first boot at E=0"
KV_M2="${WORK}/kvol2"; rm -rf "${KV_M2}"; mkdir -p "${KV_M2}"
( HIPPIUS_GOLDEN_KEY_MODE=customer hippius_golden_check_stamp_v1 "${KV_M2}" 42 ) >/dev/null 2>&1 \
    && err "25c: M2 v1 took the legacy migration" \
    || ok "25c: M2 v1 (guardian stamp), no stamp + E=42: REFUSED"
( HIPPIUS_GOLDEN_KEY_MODE=customer hippius_golden_check_stamp_v1 "${KV_M2}" "" ) >/dev/null 2>&1 \
    && err "25c: M2 v1 booted without an expectation" \
    || ok "25c: M2 v1 without an expectation: REFUSED"
printf '%s\n' "${TA}" > "${KV_M2}/${TF}"
( HIPPIUS_GOLDEN_KEY_MODE=customer hippius_golden_check_stamp_v1 "${KV_M2}" 0 ) >/dev/null 2>&1 \
    && err "25c: M2 v1 took a timeline-bound volume" \
    || ok "25c: M2 v1 still refuses a timeline-bound volume at E=0 (#1320 S1 defence kept)"

# 25d. the mandatory first-boot confirm, through mount_overlay: M1 with
#      a v2 transition (zero → fresh), M2 with a v1 release.
sleep() { echo "sleep $*" >> "${CONFIRM_LOG}.sleeps"; }
hippius-guest-release() { # fails the first $CONFIRM_FAILS confirms
    echo "$*" >>"${CONFIRM_LOG}"
    [ "$(grep -c -- '--confirm-volume-stamp' "${CONFIRM_LOG}")" -gt "${CONFIRM_FAILS}" ]
}
first_case() { # $1 key mode, $2 first-boot flag, $3 confirm failures
    rm -f "${CONFIRM_LOG}.sleeps"
    CONFIRM_FAILS="$3"
    HIPPIUS_GOLDEN_KEY_MODE="$1"
    HIPPIUS_GOLDEN_FIRST_BOOT="$2"
    if [ "$1" = customer ]; then _fc_tr=ABSENT; else _fc_tr="${Z} ${TA}"; fi
    v="$(mo_case2 0 ABSENT 0 "${_fc_tr}")"
    N="$(grep -c -- '--confirm-volume-stamp' "${CONFIRM_LOG}")"
    HIPPIUS_GOLDEN_FIRST_BOOT=""
}
for mode in split customer; do
    first_case "${mode}" yes 99
    [ "${v}" = REFUSED ] && [ "${N}" -eq "${HIPPIUS_GOLDEN_FIRST_CONFIRM_TRIES}" ] \
        && [ "$(tr '\n' ' ' < "${CONFIRM_LOG}.sleeps")" = "sleep 2 sleep 4 sleep 8 sleep 16 " ] \
        || err "25d: ${mode} first boot, confirm never lands: verdict=${v} attempts=${N}"
    first_case "${mode}" yes 2
    [ "${v}" = ALLOWED ] && [ "${N}" -eq 3 ] \
        || err "25d: ${mode} first boot, confirm lands on attempt 3: verdict=${v} attempts=${N}"
    first_case "${mode}" "" 99
    [ "${v}" = ALLOWED ] && [ "${N}" -eq 1 ] \
        || err "25d: ${mode} later boot, confirm fails: verdict=${v} attempts=${N}"
done
first_case "" yes 99
[ "${v}" = ALLOWED ] && [ "${N}" -eq 1 ] || err "25d: M0 first boot, confirm fails: verdict=${v} attempts=${N}"
ok "25d: M1/M2 first boot: confirm retried (${HIPPIUS_GOLDEN_FIRST_CONFIRM_TRIES} attempts, backoff) then FATAL; later boots and M0 stay non-fatal"
# No confirm context on an M1/M2 first boot: fatal too.
CONFIRM_FAILS=0
v="$( mo_case2 0 ABSENT 0 "${Z} ${TA}" >/dev/null; rm -f "${HIPPIUS_GOLDEN_STAMP_CTX}"
      if ( HIPPIUS_GOLDEN_KEY_MODE=split HIPPIUS_GOLDEN_FIRST_BOOT=yes hippius_golden_mount_overlay "${MO}/sysroot" ) >/dev/null 2>&1
      then echo ALLOWED; else echo REFUSED; fi )"
[ "${v}" = REFUSED ] && ok "25d: M1/M2 first boot without a confirm context: fail-closed" \
    || err "25d: M1/M2 first boot without a confirm context booted"
HIPPIUS_GOLDEN_KEY_MODE=""

# ── 26. #1347: the non-overlay data path next to upper/ and work/ ───
# `mount -o bind <src> <dst>` is recorded; the overlay mount too, in the
# same ordered log (the bind must come AFTER it, or the overlay hides it).
MOUNT_ORDER="${MO}/mount-order"
BIND_LOG="${MO}/binds"
mount() {
    _m_bind=0
    for _a in "$@"; do
        [ "${_a}" = overlay ] && { echo overlay >>"${OVERLAY_LOG}"; echo overlay >>"${MOUNT_ORDER}"; }
        [ "${_a}" = bind ] && _m_bind=1
    done
    if [ "${_m_bind}" = 1 ]; then
        printf '%s %s\n' "$3" "$4" >>"${BIND_LOG}"
        echo bind >>"${MOUNT_ORDER}"
    fi
    return 0
}
CONFIRM_FAILS=0
U="${HIPPIUS_GOLDEN_UPPER_MNT}"
DST="${MO}/sysroot${HIPPIUS_GOLDEN_DATA_MOUNT}"
# One boot on the volume AS IT IS (nothing reset): the expectation is the
# volume's own stamp, on timeline TA, so the real gate passes and advances.
data_boot() {
    : >"${OVERLAY_LOG}"; : >"${CONFIRM_LOG}"; : >"${BIND_LOG}"; : >"${MOUNT_ORDER}"
    cat "${U}/${SF}" > "${HIPPIUS_GOLDEN_STAMP_EXPECTED}"
    : > "${HIPPIUS_GOLDEN_STAMP_CTX}"
    printf '%s %s\n' "${TA}" "${TA}" > "${HIPPIUS_GOLDEN_STAMP_TRANSITION}"
    if ( hippius_golden_mount_overlay "${MO}/sysroot" ) >/dev/null 2>&1; then
        echo ALLOWED
    else
        echo REFUSED
    fi
}
# An EXISTING provisioned volume from before #1347: stamp + timeline at
# the root, tenant bytes in upper/, and no data/. The mocked overlay mount
# leaves the tenant root empty, so give it the /var/lib every lower ships.
rm -rf "${MO}"
mkdir -p "${HIPPIUS_GOLDEN_LOWER_MNT}/var/lib" "${U}/upper/etc" "${U}/work" "${MO}/sysroot/var/lib"
echo tenant > "${U}/upper/etc/hostname"
printf '5\n' > "${U}/${SF}"
printf '%s\n' "${TA}" > "${U}/${TF}"
v="$(data_boot)"
[ "${v}" = ALLOWED ] && [ "$(tr '\n' ' ' < "${MOUNT_ORDER}")" = "overlay bind " ] \
    && ok "26: an existing volume without data/ boots; the data bind comes after the overlay root" \
    || err "26: existing volume without data/ (verdict=${v}, order='$(tr '\n' ' ' < "${MOUNT_ORDER}")')"
[ -d "${U}/data" ] && [ ! -L "${U}/data" ] && [ "$(stat -c %a "${U}/data")" = 755 ] \
    && ok "26: data/ created on the volume root as a plain 0755 directory" \
    || err "26: data/ not created as a plain 0755 directory"
[ ! -e "${U}/upper/data" ] && [ ! -e "${U}/work/data" ] \
    && ok "26: data/ sits next to upper/ and work/, never inside them" \
    || err "26: data/ landed under upper/ or work/"
[ "$(cat "${BIND_LOG}")" = "${U}/data ${DST}" ] \
    && ok "26: exactly one bind: the volume's data/ (not its root) at ${HIPPIUS_GOLDEN_DATA_MOUNT} in the tenant root" \
    || err "26: unexpected bind(s): '$(cat "${BIND_LOG}")'"
[ -z "$(find "${U}/data" "${U}/upper" -name '.hippius-volume-*')" ] && [ -e "${U}/${SF}" ] && [ -e "${U}/${TF}" ] \
    && ok "26: stamp + timeline stay at the volume root, outside both the overlay upperdir and the bound data/" \
    || err "26: a stamp/timeline file is reachable from the merged root or the data bind"
[ "$(cat "${U}/upper/etc/hostname")" = tenant ] && [ "$(cat "${U}/${SF}")" = 6 ] \
    && ok "26: the tenant's upper is untouched and the anti-rollback gate still advanced the stamp (5 -> 6)" \
    || err "26: upper bytes or the stamp changed unexpectedly"

# Second boot: idempotent. The tenant's data and their own mode survive.
echo payload > "${U}/data/containerd-root"
chmod 0700 "${U}/data"
v="$(data_boot)"
[ "${v}" = ALLOWED ] && [ "$(cat "${U}/data/containerd-root")" = payload ] \
    && [ "$(stat -c %a "${U}/data")" = 700 ] && [ "$(cat "${BIND_LOG}")" = "${U}/data ${DST}" ] \
    && ok "26: second boot is idempotent: same single bind, data kept, the tenant's mode not reset" \
    || err "26: second boot (verdict=${v}, binds='$(cat "${BIND_LOG}")')"
chmod 0755 "${U}/data"

# Anything but a plain directory at either end SKIPS the bind: the boot
# goes on (refusing would brick a VM only fixable from inside) and nothing
# is bound, since following a symlink could bind the volume root itself.
# Only in-guest root can plant these (the volume is guest-keyed).
data_skips() { # $1 = label
    v="$(data_boot)"
    [ "${v}" = ALLOWED ] && [ -s "${OVERLAY_LOG}" ] && [ ! -s "${BIND_LOG}" ] \
        && ok "26: $1 — boots WITHOUT the data bind, nothing bound" \
        || err "26: $1 — (verdict=${v}, binds='$(cat "${BIND_LOG}")')"
}
mv "${U}/data" "${U}/data.keep"
ln -s . "${U}/data"
data_skips "data -> . (would bind the volume root and expose the stamp)"
rm -f "${U}/data"; : > "${U}/data"
data_skips "data is a regular file"
rm -f "${U}/data"; mv "${U}/data.keep" "${U}/data"
rm -rf "${DST}"; ln -s "${U}" "${DST}"
data_skips "the mount point is a symlink to the volume root"
rm -f "${DST}"
mkdir -p "${WORK}/elsewhere/lib"; rm -rf "${MO}/sysroot/var"; ln -s "${WORK}/elsewhere" "${MO}/sysroot/var"
data_skips "a parent of the mount point (/var) is a symlink out of the tenant root"
[ ! -e "${WORK}/elsewhere/lib/hippius-data" ] \
    && ok "26: a symlinked parent creates nothing outside the tenant root" \
    || err "26: a symlinked parent let the initramfs create the mount point outside the tenant root"
rm -f "${MO}/sysroot/var"; mkdir -p "${MO}/sysroot/var/lib2"; ln -s lib2 "${MO}/sysroot/var/lib"
data_skips "/var/lib is a symlink, even one inside the tenant root"
rm -f "${MO}/sysroot/var/lib"
data_skips "/var/lib is missing"
mkdir -p "${MO}/sysroot/var/lib"
v="$(data_boot)"
[ "${v}" = ALLOWED ] && [ "$(cat "${BIND_LOG}")" = "${U}/data ${DST}" ] && [ -d "${DST}" ] \
    && ok "26: a clean tree binds again, recreating the mount point (positive control after the skips)" \
    || err "26: the positive control after the skips did not bind (verdict=${v})"

# The initramfs does not run bash: busybox ash (initramfs-tools) and dash
# are what source this lib at boot. Run the bind under both, on a clean
# tree (binds) and on a symlinked /var/lib (skips, boot goes on).
SH_ROOT="${WORK}/shroot"
for sh in dash "busybox sh"; do
    if ! command -v "${sh%% *}" >/dev/null 2>&1; then
        err "26: ${sh} is not installed — the non-bash smoke run cannot be skipped"
        continue
    fi
    for tree in clean symlinked; do
        rm -rf "${SH_ROOT}"
        mkdir -p "${SH_ROOT}/vol" "${SH_ROOT}/lower/var/lib" "${SH_ROOT}/root/var"
        if [ "${tree}" = clean ]; then
            mkdir -p "${SH_ROOT}/root/var/lib"
        else
            mkdir -p "${SH_ROOT}/root/var/lib2"; ln -s lib2 "${SH_ROOT}/root/var/lib"
        fi
        # shellcheck disable=SC2016  # expanded by the inner shell
        out="$(${sh} -c '
            set -eu
            hippius_log() { :; }
            hippius_die() { echo DIE; exit 1; }
            mount() { echo "BIND $3 $4"; }
            . "$1"
            HIPPIUS_GOLDEN_UPPER_MNT="$2/vol"
            HIPPIUS_GOLDEN_LOWER_MNT="$2/lower"
            ( true && hippius_golden_bind_data "$2/root" ) && echo RC0
        ' sh "${LIB}" "${SH_ROOT}" 2>&1)"
        if [ "${tree}" = clean ]; then
            want="BIND ${SH_ROOT}/vol/data ${SH_ROOT}/root/var/lib/hippius-data
RC0"
        else
            want="RC0"
        fi
        [ "${out}" = "${want}" ] \
            && ok "26: under ${sh}, a ${tree} tree $( [ "${tree}" = clean ] && echo binds || echo 'skips the bind and boots')" \
            || err "26: under ${sh}, ${tree} tree: got '${out}'"
    done
done

if [ "${fail}" -ne 0 ]; then
    echo "golden-stamp-test: FAILED" >&2
    exit 1
fi
echo "golden-stamp-test: OK (all checks passed)"
