#!/usr/bin/env bash
#
# Unit test for the per-VM upper initialisation in
# `scripts/initramfs/hippius-golden-overlay.sh`:
#
#   - first boot formats with `--integrity-no-wipe --sector-size 4096`
#     and the init label, wipes through a journal-less activation with
#     `hippius-guest-release --integrity-wipe`, reopens journaled, runs
#     mkfs, and only THEN marks the volume initialised;
#   - a failed wipe never gets a filesystem;
#   - an upper whose label says init never finished is formatted again
#     (fresh MK) ONLY when the KBS expectation is exactly 0; with any other
#     expectation it fails closed; every other volume is plainly reopened,
#     with no filesystem probe (a probe mount can write via orphan cleanup).
#
# Root-free, no devices: cryptsetup / mount / umount / blockdev / mkfs /
# the wiper are shell functions that log their argv. The library is
# sourced from a copy with `/dev/kmsg` pointed at a temp file (writing the
# real one needs root).
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${HERE}/../initramfs/hippius-golden-overlay.sh"
[ -r "${SRC}" ] || { echo "golden-upper-init-test: lib not found at ${SRC}" >&2; exit 1; }

fail=0
ok()  { echo "golden-upper-init-test: OK — $*"; }
err() { echo "golden-upper-init-test: FAIL — $*" >&2; fail=1; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

sed "s#/dev/kmsg#${WORK}/kmsg#g" "${SRC}" > "${WORK}/lib.sh"
# shellcheck source=scripts/initramfs/hippius-golden-overlay.sh
. "${WORK}/lib.sh"

hippius_die() { echo "hippius_die: $*" >> "${LOG}"; exit 1; }
hippius_log() { :; }

# ── 1. the pure re-init decision ─────────────────────────────────────
I="${HIPPIUS_GOLDEN_INIT_LABEL}"
R="${HIPPIUS_GOLDEN_READY_LABEL}"
for row in \
    "yes|${I}|0" \
    "yes|${I}|00" \
    "no|${I}|1" \
    "no|${I}|37" \
    "no|${I}|" \
    "no|${I}|junk" \
    "no|${I}|-0" \
    "no|${R}|0" \
    "no|(no label)|0" \
    "no||0"
do
    want="${row%%|*}"; rest="${row#*|}"; label="${rest%|*}"; exp="${rest##*|}"
    if hippius_golden_may_reinit "${label}" "${exp}"; then got=yes; else got=no; fi
    [ "${got}" = "${want}" ] || err "may_reinit label='${label}' expected='${exp}': got ${got}, want ${want}"
done
ok "reformat only for (init label, expectation exactly 0)"

# ── 2. open_upper against mocked tools ───────────────────────────────
# Any block device will do for the `-b` check; the tools are mocked.
BLK="$(find /dev -maxdepth 1 -type b 2>/dev/null | head -n 1)"
if [ -z "${BLK}" ]; then
    # In CI a skip would hide every case below: fail instead.
    [ -z "${CI:-}" ] || { err "no block device visible in CI — the open_upper cases cannot run"; exit 1; }
    echo "golden-upper-init-test: no block device visible — skipping the open_upper cases"
    [ "${fail}" -eq 0 ] && echo "golden-upper-init-test: OK (all checks passed)" || exit 1
    exit 0
fi

HIPPIUS_GOLDEN_UPPER="${BLK}"
HIPPIUS_GOLDEN_DISK_GB=1
HIPPIUS_GOLDEN_MKFS="${WORK}/no-private-mkfs"
HIPPIUS_GOLDEN_STAMP_EXPECTED="${WORK}/expected"
HIPPIUS_GOLDEN_WIPE_BIN=mock_wipe
KEK="${WORK}/kek"
head -c 32 /dev/zero > "${KEK}"

blockdev() { echo 1099511627776; }
# Calls made with libdevmapper's udev support off are tagged `[noudev]`.
cryptsetup() {
    echo "${DM_DISABLE_UDEV:+[noudev] }cryptsetup $*" >> "${LOG}"
    case "$1" in
        isLuks) return "${M_ISLUKS}" ;;
        luksDump)
            [ "${M_LABEL}" != DUMPFAIL ] || return 1
            printf 'LUKS header information\nVersion:       \t2\nLabel:          %s\n' "${M_LABEL}" ;;
        open) return "${M_OPEN_RC}" ;;
    esac
    return 0
}
mount() { echo "mount $*" >> "${LOG}"; }
umount() { echo "umount $*" >> "${LOG}"; }
udevadm() { echo "udevadm $*" >> "${LOG}"; return "${M_UDEV_RC:-0}"; }
mock_wipe() { echo "wipe $*" >> "${LOG}"; return "${M_WIPE_RC}"; }
mkfs.ext4() { echo "mkfs $*" >> "${LOG}"; }

# $1 isLuks rc, $2 label, $3 expectation (ABSENT = no file), $4 wipe rc,
# $5 open rc. Sets LOG and RC.
case_run() {
    M_ISLUKS="$1"; M_LABEL="$2"; M_WIPE_RC="$4"; M_OPEN_RC="$5"
    if [ "$3" = ABSENT ]; then rm -f "${HIPPIUS_GOLDEN_STAMP_EXPECTED}"; else printf '%s\n' "$3" > "${HIPPIUS_GOLDEN_STAMP_EXPECTED}"; fi
    LOG="${WORK}/log.$((++CASE))"
    : > "${LOG}"
    ( hippius_golden_open_upper "${KEK}" ); RC=$?
}
CASE=0
has()    { grep -qE -- "$1" "${LOG}"; }
# First line after line $2 matching $1.
line_after() { grep -nE -- "$1" "${LOG}" | awk -F: -v after="$2" '$1 > after { print $1; exit }'; }
in_order() { # every pattern present, each strictly after the previous match
    _prev=0
    for _p in "$@"; do
        _n="$(line_after "${_p}" "${_prev}")"
        [ -n "${_n}" ] || return 1
        _prev="${_n}"
    done
}
INIT_SEQ=(
    "^udevadm control --stop-exec-queue\$"
    "^\\[noudev\\] cryptsetup open --integrity-no-journal "
    "^wipe --integrity-wipe /dev/mapper/${HIPPIUS_GOLDEN_UPPER_MAPPER}\$"
    "^\\[noudev\\] cryptsetup close ${HIPPIUS_GOLDEN_UPPER_MAPPER}\$"
    "^udevadm control --start-exec-queue\$"
    "^cryptsetup open ${BLK} "
    "^mkfs -q -F /dev/mapper/${HIPPIUS_GOLDEN_UPPER_MAPPER}\$"
    "^cryptsetup config --label ${R} "
)

FORMAT="^cryptsetup luksFormat .*--integrity hmac-sha256 .*--integrity-no-wipe --sector-size 4096 --label ${I} "

# 2a. blank disk → the full first boot, in order.
case_run 1 "" 0 0 0
if [ "${RC}" -eq 0 ] && in_order "${FORMAT}" "${INIT_SEQ[@]}"; then
    ok "first boot: no-wipe 4K luksFormat → journal-less wipe → reopen → mkfs → mark ready"
else
    err "first boot sequence (rc=${RC}): $(cat "${LOG}")"
fi

# 2b. blank disk, the wipe fails → die, no filesystem, not marked ready,
#     and the udev queue is still restarted.
case_run 1 "" 0 1 0
if [ "${RC}" -ne 0 ] && has "^wipe " && ! has "^mkfs" && ! has "config --label" \
    && in_order "^udevadm control --stop-exec-queue\$" "^wipe " \
        "^\\[noudev\\] cryptsetup close ${HIPPIUS_GOLDEN_UPPER_MAPPER}\$" "^udevadm control --start-exec-queue\$"; then
    ok "a failed wipe never gets a filesystem; the mapping is closed before udev resumes"
else
    err "failed wipe (rc=${RC}): $(cat "${LOG}")"
fi

# 2b'. no udevd (the pause is refused) → the wipe still runs, and there is
#      no queue to restart.
M_UDEV_RC=1 case_run 1 "" 0 0 0
if [ "${RC}" -eq 0 ] && has "^wipe " && ! has "start-exec-queue"; then
    ok "no udevd: wipe runs, nothing to resume"
else
    err "no udevd (rc=${RC}): $(cat "${LOG}")"
fi

# 2b''. only the wipe activation runs with udev support off.
case_run 1 "" 0 0 0
if [ "$(grep -c '^\[noudev\]' "${LOG}")" -eq 2 ] && ! grep -q '^\[noudev\] .*\(luksFormat\|config\)' "${LOG}"; then
    ok "DM_DISABLE_UDEV only for the wipe open/close"
else
    err "noudev scope: $(cat "${LOG}")"
fi

# 2c. initialised / pre-change volumes → plain reopen, nothing rewritten,
#     and no probe mount of any kind.
for label in "${R}" "(no label)" ""; do
    case_run 0 "${label}" 5 0 0
    if [ "${RC}" -eq 0 ] && has "^cryptsetup open ${BLK} " \
        && ! has "^wipe|^mkfs|luksFormat|config --label|integrity-no-journal|^mount"; then
        ok "label '${label}': reopened, nothing rewritten, not probed"
    else
        err "reopen with label '${label}' (rc=${RC}): $(cat "${LOG}")"
    fi
done

# 2d. interrupted first boot (init label, expectation 0) → formatted again
#     from scratch, never opened with the old header first.
for exp in 0 00; do
    case_run 0 "${I}" "${exp}" 0 0
    if [ "${RC}" -eq 0 ] && in_order "${FORMAT}" "${INIT_SEQ[@]}" \
        && [ "$(line_after "^cryptsetup open" 0)" -gt "$(line_after "luksFormat" 0)" ]; then
        ok "interrupted first boot (expected=${exp}): fresh format, then the full init"
    else
        err "interrupted first boot expected=${exp} (rc=${RC}): $(cat "${LOG}")"
    fi
done

# 2e. init label with any other expectation fails closed without writing.
for exp in 1 37 ABSENT junk; do
    case_run 0 "${I}" "${exp}" 0 0
    if [ "${RC}" -ne 0 ] && has "^hippius_die: .*refusing to reformat" \
        && ! has "^wipe|^mkfs|luksFormat|config --label|^cryptsetup open"; then
        ok "init label + expectation ${exp}: fail-closed, nothing written"
    else
        err "init label + expectation ${exp} (rc=${RC}): $(cat "${LOG}")"
    fi
done

# 2f. an unreadable header dump is never read as "not the init label".
case_run 0 DUMPFAIL 0 0 0
if [ "${RC}" -ne 0 ] && has "^hippius_die: .*cannot be dumped" \
    && ! has "^wipe|^mkfs|luksFormat|config --label|^cryptsetup open"; then
    ok "luksDump failure: fail-closed, nothing opened or written"
else
    err "luksDump failure (rc=${RC}): $(cat "${LOG}")"
fi

# 2g. a header our KEK does not open → fail closed, nothing rewritten.
case_run 0 "${R}" 0 0 1
if [ "${RC}" -ne 0 ] && ! has "^wipe|^mkfs|luksFormat|config --label"; then
    ok "foreign header: fail-closed, never reformatted"
else
    err "foreign header (rc=${RC}): $(cat "${LOG}")"
fi

# ── 3. customer keys (M1/M2): the upper is opened as keymode_prepare
#       classified it BEFORE the release (HIPPIUS_GOLDEN_UPPER_CLASS),
#       never as the disk looks now. A first-boot format (class blank or
#       init) needs a version-less release AND a signed E of exactly 0.
HIPPIUS_GOLDEN_GUARDIAN_FP="$(printf '%064d' 0)"
HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT="${WORK}/share-c-version"
printf '1\n' > "${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT}"
# $1 class, $2 share version sent ("" = version-less), then case_run args.
keyed_run() {
    _kr_class="$1"; _kr_ver="$2"; shift 2
    HIPPIUS_GOLDEN_KEY_MODE=split HIPPIUS_GOLDEN_UPPER_CLASS="${_kr_class}" \
        HIPPIUS_GOLDEN_SHARE_C_VERSION="${_kr_ver}" case_run "$@"
}
NOWRITE="^wipe|^mkfs|luksFormat|config --label|^cryptsetup open"

# 3a. class blank / init, version-less, E == 0 → format (whatever the disk
#     looks like now: the class decides).
for class in blank init; do
    for isluks in 1 0; do
        keyed_run "${class}" "" "${isluks}" "${I}" 0 0 0
        [ "${RC}" -eq 0 ] && in_order "${FORMAT}" "${INIT_SEQ[@]}" \
            || err "class ${class} (isLuks ${isluks}), version-less, E=0 (rc=${RC}): $(cat "${LOG}")"
    done
done
ok "M1/M2 class blank/init + version-less + E=0: first-boot format"

# 3b. class blank / init with E != 0 (or none) → refuse, nothing written.
#     This is the zeroed upper of a VM that has booted before.
for class in blank init; do
    for exp in 1 37 ABSENT junk -0 ""; do
        keyed_run "${class}" "" 1 "" "${exp}" 0 0
        [ "${RC}" -ne 0 ] && has "^hippius_die: .*a blanked upper is not a first boot" && ! has "${NOWRITE}" \
            || err "class ${class} + expectation '${exp}' (rc=${RC}): $(cat "${LOG}")"
    done
done
ok "M1/M2 class blank/init with an expectation other than 0 (or none): fail-closed, never formatted"

# 3c. class blank / init but a share version WAS sent → refuse.
for class in blank init; do
    keyed_run "${class}" 7 1 "" 0 0 0
    [ "${RC}" -ne 0 ] && has "^hippius_die: .*needs a version-less release" && ! has "${NOWRITE}" \
        || err "class ${class} with version 7 (rc=${RC}): $(cat "${LOG}")"
done
ok "M1/M2: a release that carried a share version never formats"

# 3d. THE TOCTOU: classified ready (token kept, version sent), then the
#     host changes the disk before the open. Every variant fails closed,
#     even under E == 0.
keyed_run ready 7 0 "${I}" 0 0 0
[ "${RC}" -ne 0 ] && has "^hippius_die: .*was ready before the release and now says its init never finished" && ! has "${NOWRITE}" \
    || err "ready → label flipped to init (rc=${RC}): $(cat "${LOG}")"
keyed_run ready 7 1 "" 0 0 0
[ "${RC}" -ne 0 ] && has "^hippius_die: .*has no LUKS header now" && ! has "${NOWRITE}" \
    || err "ready → header blanked (rc=${RC}): $(cat "${LOG}")"
for rc in 2 4 5; do
    keyed_run ready 7 "${rc}" "" 0 0 0
    [ "${RC}" -ne 0 ] && has "^hippius_die: .*cannot tell whether the upper is LUKS \\(cryptsetup isLuks exit ${rc}\\)" && ! has "${NOWRITE}" \
        || err "ready → isLuks exit ${rc} (rc=${RC}): $(cat "${LOG}")"
done
keyed_run ready 7 0 DUMPFAIL 0 0 0
[ "${RC}" -ne 0 ] && ! has "${NOWRITE}" || err "ready → header undumpable (rc=${RC}): $(cat "${LOG}")"
ok "M1/M2 class ready: label flipped to init, header blanked, isLuks error or undumpable header after the release ⇒ fail-closed, never formatted"

# 3e. class ready, disk unchanged → plain reopen, nothing rewritten.
keyed_run ready 7 0 "${R}" 5 0 0
[ "${RC}" -eq 0 ] && has "^cryptsetup open ${BLK} " && ! has "^wipe|^mkfs|luksFormat|config --label|integrity-no-journal" \
    || err "ready reopen (rc=${RC}): $(cat "${LOG}")"
keyed_run ready 7 0 "${R}" 0 0 1
[ "${RC}" -ne 0 ] && ! has "^wipe|^mkfs|luksFormat|config --label" || err "ready, wrong KEK (rc=${RC}): $(cat "${LOG}")"
ok "M1/M2 class ready: reopened, never formatted"

# 3f. no classification (prepare did not run, or an unknown value) → refuse.
for class in "" ready2 BLANK; do
    keyed_run "${class}" "" 1 "" 0 0 0
    [ "${RC}" -ne 0 ] && has "^hippius_die: .*was not classified before the release" && ! has "${NOWRITE}" \
        || err "class '${class}' (rc=${RC}): $(cat "${LOG}")"
done
ok "M1/M2 without a pre-release classification: fail-closed"

# 3g. the E == 0 gate runs BEFORE luksFormat.
eval "real_$(declare -f hippius_golden_keyed_may_format_blank)"
hippius_golden_keyed_may_format_blank() { echo "e-gate $1" >> "${LOG}"; real_hippius_golden_keyed_may_format_blank "$@"; }
keyed_run blank "" 1 "" 0 0 0
[ "${RC}" -eq 0 ] && in_order "^e-gate 0\$" "${FORMAT}" \
    && ok "M1/M2: E == 0 gate → luksFormat, in that order" \
    || err "E-gate ordering (rc=${RC}): $(cat "${LOG}")"
keyed_run init "" 0 "${I}" 7 0 0
[ "${RC}" -ne 0 ] && has "^e-gate 7\$" && ! has "luksFormat" \
    && ok "M1/M2: E = 7 stops at the gate, luksFormat never runs" \
    || err "E-gate refusal (rc=${RC}): $(cat "${LOG}")"
case_run 1 "" 7 0 0
! has "^e-gate" && has "luksFormat" && ok "M0: the E gate is never consulted" \
    || err "M0 consulted the E gate: $(cat "${LOG}")"
eval "$(declare -f real_hippius_golden_keyed_may_format_blank | sed '1s/^real_//')"

# 3h. M0 is unchanged: a blank upper formats whatever the expectation,
#     and an isLuks error still reads as blank.
case_run 1 "" 37 0 0
[ "${RC}" -eq 0 ] && in_order "${FORMAT}" "${INIT_SEQ[@]}" \
    && ok "M0 blank upper + expectation 37: formats, as before" \
    || err "M0 blank upper + expectation 37 (rc=${RC}): $(cat "${LOG}")"
case_run 4 "" 0 0 0
[ "${RC}" -eq 0 ] && has "luksFormat" && ok "M0: isLuks exit 4 still reads as blank (unchanged)" \
    || err "M0 isLuks exit 4 (rc=${RC}): $(cat "${LOG}")"

[ "${fail}" -eq 0 ] && echo "golden-upper-init-test: OK (all checks passed)" || exit 1
