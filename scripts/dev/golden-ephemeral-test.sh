#!/usr/bin/env bash
#
# Unit test for the cdn-node ephemeral root in
# scripts/initramfs/hippius-golden-overlay.sh.
#
# A cdn-node bake stages a marker file in the initrd
# (/conf/conf.d/hippius-cdn-ephemeral-upper). With it, every boot:
#   - discards the golden upper + workdir BEFORE the overlay is assembled,
#     and scrubs data/ down to cdn-agent's billing state (counters.json and
#     the regular files of usage-queue/), symlinks included;
#   - remounts the data directory nosuid,nodev,noexec and verifies it;
#   - sets panic=10 (an initramfs panic reboots, no console shell);
#   - refuses key modes M1/M2.
# Without the marker (every other initrd) none of it runs.
#
# Root-free: `mount` is mocked and keeps a fake /proc/mounts; no devices.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
LIB="${HERE}/../initramfs/hippius-golden-overlay.sh"
[ -r "${LIB}" ] || { echo "golden-ephemeral-test: lib not found at ${LIB}" >&2; exit 1; }

fail=0
ok()  { echo "golden-ephemeral-test: OK — $*"; }
err() { echo "golden-ephemeral-test: FAIL — $*" >&2; fail=1; }

# shellcheck source=scripts/initramfs/hippius-golden-overlay.sh
. "${LIB}"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

HIPPIUS_GOLDEN_LOWER_MNT="${WORK}/lower"
HIPPIUS_GOLDEN_UPPER_MNT="${WORK}/vol"
HIPPIUS_GOLDEN_EPHEMERAL_MARKER="${WORK}/marker"
HIPPIUS_GOLDEN_PROC_MOUNTS="${WORK}/proc-mounts"
SYSROOT="${WORK}/sysroot"
DATA_DST="${SYSROOT}${HIPPIUS_GOLDEN_DATA_MOUNT}"
MOUNT_LOG="${WORK}/mount-log"
VOL="${HIPPIUS_GOLDEN_UPPER_MNT}"

# The mocked mount logs every call and keeps the fake /proc/mounts: a bind
# adds the destination with plain options; a remount sets the requested
# ones, unless REMOUNT_DROPS names one the "kernel" leaves off.
REMOUNT_DROPS=""
REMOUNT_FAILS=0
mount() {
    printf '%s\n' "$*" >>"${MOUNT_LOG}"
    case " $* " in
        *" -t overlay "*)
            [ -e "${VOL}/upper/etc/systemd/system/evil.service" ] && echo stale-upper >>"${MOUNT_LOG}"
            ;;
    esac
    _m_opts=""; _m_prev=""; _m_last=""
    for _a in "$@"; do
        [ "${_m_prev}" = "-o" ] && _m_opts="${_a}"
        _m_prev="${_a}"; _m_last="${_a}"
    done
    case "${_m_opts}" in
        bind)
            printf '/dev/mapper/vol %s ext4 rw,relatime 0 0\n' "${_m_last}" >>"${HIPPIUS_GOLDEN_PROC_MOUNTS}"
            ;;
        remount,*)
            [ "${REMOUNT_FAILS}" = 1 ] && return 1
            _m_new="rw,relatime"
            for _o in nosuid nodev noexec; do
                [ "${_o}" = "${REMOUNT_DROPS}" ] || _m_new="${_m_new},${_o}"
            done
            _m_tmp="${HIPPIUS_GOLDEN_PROC_MOUNTS}.new"
            while read -r _s _d _f _o _r; do
                if [ "${_d}" = "${_m_last}" ]; then _o="${_m_new}"; fi
                printf '%s %s %s %s %s\n' "${_s}" "${_d}" "${_f}" "${_o}" "${_r}"
            done <"${HIPPIUS_GOLDEN_PROC_MOUNTS}" >"${_m_tmp}"
            mv "${_m_tmp}" "${HIPPIUS_GOLDEN_PROC_MOUNTS}"
            ;;
    esac
    return 0
}
# The mocked chown logs its arguments (the real one needs root).
CHOWN_LOG="${WORK}/chown-log"
CHOWN_FAILS=0
mock_chown() {
    printf '%s\n' "$*" >>"${CHOWN_LOG}"
    [ "${CHOWN_FAILS}" = 0 ]
}
HIPPIUS_GOLDEN_CHOWN=mock_chown
hippius_die() { echo "hippius_die: $*" >&2; exit 1; }
hippius_log() { :; }
# The anti-rollback gate is golden-stamp-test.sh's; keep it inert here
# (same stubs as golden-overlay-selinux-test.sh).
HIPPIUS_GOLDEN_STAMP_EXPECTED="${WORK}/no-such-expected"
HIPPIUS_GOLDEN_STAMP_CTX="${WORK}/no-such-ctx"
HIPPIUS_GOLDEN_STAMP_TRANSITION="${WORK}/transition"
hippius_golden_check_stamp_v2() { :; }

NL_NAME="$(printf 'a\nb')"

# A volume as a previous boot (possibly an implant) left it.
seed_volume() {
    rm -rf "${WORK:?}/lower" "${VOL}" "${SYSROOT}"
    mkdir -p "${HIPPIUS_GOLDEN_LOWER_MNT}/var/lib" "${SYSROOT}/var/lib"
    mkdir -p "${VOL}/upper/etc/systemd/system" "${VOL}/work/work" \
        "${VOL}/data/cdn/usage-queue/sub" "${VOL}/data/cache/ab" "${VOL}/data/other"
    echo implant >"${VOL}/upper/etc/systemd/system/evil.service"
    echo '{"epoch":3}' >"${VOL}/data/cdn/counters.json"
    echo report >"${VOL}/data/cdn/usage-queue/0001.json"
    ln -s /etc/shadow "${VOL}/data/cdn/usage-queue/0002.json"
    echo forged >"${VOL}/data/cdn/feed.json"
    ln -s /usr/bin "${VOL}/data/cdn/bin"
    echo poisoned >"${VOL}/data/cache/ab/obj"
    ln -s /etc "${VOL}/data/etc-link"
    echo x >"${VOL}/data/.hidden"
    # Hostile entries in the queue: a fifo, a hardlink to a setuid file,
    # option-like, newline and dot names.
    mkfifo "${VOL}/data/cdn/usage-queue/fifo"
    echo payload >"${VOL}/upper/suid"
    chmod 4755 "${VOL}/upper/suid"
    ln "${VOL}/upper/suid" "${VOL}/data/cdn/usage-queue/hl"
    echo dash >"${VOL}/data/cdn/usage-queue/-rf"
    echo nl >"${VOL}/data/cdn/usage-queue/${NL_NAME}"
    echo dot >"${VOL}/data/cdn/usage-queue/.0003.json"
    # Permissions a previous boot loosened.
    chmod 0777 "${VOL}/data" "${VOL}/data/cdn" "${VOL}/data/cdn/usage-queue"
    echo 1 >"${VOL}/.hippius-volume-stamp"
    : >"${HIPPIUS_GOLDEN_PROC_MOUNTS}"; : >"${MOUNT_LOG}"; : >"${CHOWN_LOG}"
    printf '%s %s\n' "${HIPPIUS_GOLDEN_ZERO_TIMELINE}" "${HIPPIUS_GOLDEN_ZERO_TIMELINE}" \
        >"${HIPPIUS_GOLDEN_STAMP_TRANSITION}"
}

run_overlay() {
    # As hippius_golden_run chains them.
    ( hippius_golden_mount_overlay "${SYSROOT}" \
        && hippius_golden_ephemeral_harden "${SYSROOT}" ) >"${WORK}/out" 2>&1
}

# ── Case 1: no marker → the standard path keeps the upper and data/ ──────
rm -f "${HIPPIUS_GOLDEN_EPHEMERAL_MARKER}"
seed_volume
if run_overlay; then ok "standard boot assembles the overlay"; else err "standard boot failed ($(cat "${WORK}/out"))"; fi
if [ -f "${VOL}/upper/etc/systemd/system/evil.service" ] && [ -f "${VOL}/data/cdn/feed.json" ] \
   && [ -f "${VOL}/data/cache/ab/obj" ] && [ -L "${VOL}/data/etc-link" ]; then
    ok "standard boot leaves the upper and data/ untouched"
else
    err "standard boot touched the upper or data/"
fi
if grep -q '^-o remount' "${MOUNT_LOG}"; then
    err "standard boot remounted the data directory ($(cat "${MOUNT_LOG}"))"
else
    ok "standard boot does not remount the data directory"
fi

# ── Case 2: marker → discard, scrub, harden ──────────────────────────────
: >"${HIPPIUS_GOLDEN_EPHEMERAL_MARKER}"
seed_volume
if run_overlay; then ok "ephemeral boot assembles the overlay"; else err "ephemeral boot failed ($(cat "${WORK}/out"))"; fi
if [ -d "${VOL}/upper" ] && [ -z "$(ls -A "${VOL}/upper")" ] \
   && [ -d "${VOL}/work" ] && [ -z "$(ls -A "${VOL}/work")" ]; then
    ok "upper/ and work/ come back empty"
else
    err "the previous upper survived ($(find "${VOL}/upper" "${VOL}/work" 2>&1 | tr '\n' ' '))"
fi
if [ -f "${VOL}/data/cdn/counters.json" ] && [ -f "${VOL}/data/cdn/usage-queue/0001.json" ] \
   && [ -f "${VOL}/.hippius-volume-stamp" ]; then
    ok "counters.json, queued usage reports and the volume stamp are kept"
else
    err "billing state or the stamp was lost"
fi
if [ -f "${VOL}/data/cdn/usage-queue/${NL_NAME}" ]; then
    ok "a queued report with a newline in its name is kept"
else
    err "the newline-named report was lost"
fi
rm -f "${VOL}/data/cdn/usage-queue/${NL_NAME}"
left="$(cd "${VOL}/data" && find . -mindepth 1 | LC_ALL=C sort | tr '\n' ' ')"
want="./cdn ./cdn/counters.json ./cdn/usage-queue ./cdn/usage-queue/-rf ./cdn/usage-queue/.0003.json ./cdn/usage-queue/0001.json ./cdn/usage-queue/hl "
if [ "${left}" = "${want}" ]; then
    ok "data/ rebuilt: cache, feed, symlinks, fifo, subdirs and other entries gone"
else
    err "data/ rebuild left '${left}' (want '${want}')"
fi
modes="$(cd "${VOL}/data" && stat -c '%a %h %n' . cdn cdn/usage-queue cdn/counters.json cdn/usage-queue/hl | tr '\n' ' ')"
if [ "${modes}" = "755 3 . 700 3 cdn 700 2 cdn/usage-queue 600 1 cdn/counters.json 600 1 cdn/usage-queue/hl " ]; then
    ok "fresh modes, no setuid bit, the hardlink is a new inode"
else
    err "kept entries carry old metadata (${modes})"
fi
if [ "$(cat "${CHOWN_LOG}")" = "-R 61101:61100 ${VOL}/data.new/cdn" ]; then
    ok "the cdn state is handed to cdn-agent:hippius-cdn"
else
    err "chown call unexpected ($(cat "${CHOWN_LOG}"))"
fi
if [ ! -e "${VOL}/data.new" ]; then ok "no data.new left behind"; else err "data.new left behind"; fi
if grep -q "^-o remount,bind,nosuid,nodev,noexec ${DATA_DST}$" "${MOUNT_LOG}"; then
    ok "data directory remounted nosuid,nodev,noexec"
else
    err "no hardening remount ($(cat "${MOUNT_LOG}"))"
fi
# The discard runs before the overlay mount: the old upper is never
# lowered into the root, not even for /init's early fstab read.
if grep -q '^stale-upper$' "${MOUNT_LOG}"; then
    err "the overlay was mounted over the previous upper"
else
    ok "the overlay is mounted over an already-empty upper"
fi
if [ "$(grep -n -- '-t overlay' "${MOUNT_LOG}" | cut -d: -f1)" -lt "$(grep -n -- 'remount' "${MOUNT_LOG}" | cut -d: -f1)" ]; then
    ok "remount follows the overlay + bind"
else
    err "mount order unexpected ($(cat "${MOUNT_LOG}"))"
fi

# A data/ that is itself a symlink is removed and recreated as a directory.
seed_volume
rm -rf "${VOL:?}/data"
ln -s /etc "${VOL}/data"
if run_overlay && [ -d "${VOL}/data" ] && [ ! -L "${VOL}/data" ]; then
    ok "a symlinked data/ is replaced by a plain directory"
else
    err "a symlinked data/ survived ($(cat "${WORK}/out"))"
fi

# A data/ that is a symlink is never read through.
seed_volume
mkdir -p "${WORK}/elsewhere/cdn"
echo outside >"${WORK}/elsewhere/cdn/counters.json"
rm -rf "${VOL:?}/data"
ln -s "${WORK}/elsewhere" "${VOL}/data"
if run_overlay && [ ! -e "${VOL}/data/cdn/counters.json" ] && [ -f "${WORK}/elsewhere/cdn/counters.json" ]; then
    ok "a symlinked data/ is not read through (and its target is untouched)"
else
    err "a symlinked data/ was read through ($(cat "${WORK}/out"))"
fi

# cdn-agent's limits: an oversized file, and reports past the count cap,
# are not kept.
seed_volume
HIPPIUS_GOLDEN_CDN_MAX_FILE=8
HIPPIUS_GOLDEN_CDN_MAX_QUEUED=2
echo 'a very long counter file' >"${VOL}/data/cdn/counters.json"
if run_overlay; then
    kept="$(find "${VOL}/data/cdn/usage-queue" -type f | wc -l)"
    if [ ! -e "${VOL}/data/cdn/counters.json" ] && [ "${kept}" -eq 2 ]; then
        ok "files over the size cap and reports past the count cap are not kept"
    else
        err "caps not applied (counters.json present: $([ -e "${VOL}/data/cdn/counters.json" ] && echo yes || echo no), queue files: ${kept})"
    fi
else
    err "a capped rebuild failed ($(cat "${WORK}/out"))"
fi
HIPPIUS_GOLDEN_CDN_MAX_FILE=67108864
HIPPIUS_GOLDEN_CDN_MAX_QUEUED=1440

# A sparse report far over the cap is sized from its inode, never read,
# and not kept; junk inside cdn/ goes before the copy.
seed_volume
truncate -s 64G "${VOL}/data/cdn/usage-queue/huge.json"
# (A read would take minutes; the whole test runs in seconds.)
if run_overlay \
    && [ ! -e "${VOL}/data/cdn/usage-queue/huge.json" ] && [ -f "${VOL}/data/cdn/usage-queue/0001.json" ]; then
    ok "a 64 GiB sparse report is skipped without being read"
else
    err "the sparse report was kept or the rebuild failed ($(cat "${WORK}/out"))"
fi

# An interrupted swap (data/ moved aside, the fresh one not yet in place)
# takes data.old back; a stale data.old next to data/ is removed.
seed_volume
mv "${VOL}/data" "${VOL}/data.old"
mkdir -p "${VOL}/data.new"
if run_overlay && [ -f "${VOL}/data/cdn/counters.json" ] && [ ! -e "${VOL}/data.old" ] && [ ! -e "${VOL}/data.new" ]; then
    ok "an interrupted swap keeps the billing state from data.old"
else
    err "an interrupted swap lost the billing state ($(cat "${WORK}/out"))"
fi
seed_volume
mkdir -p "${VOL}/data.old/cdn"
echo stale >"${VOL}/data.old/cdn/counters.json"
if run_overlay && [ "$(cat "${VOL}/data/cdn/counters.json")" = '{"epoch":3}' ] && [ ! -e "${VOL}/data.old" ]; then
    ok "a stale data.old beside data/ is discarded"
else
    err "a stale data.old was used or left ($(cat "${WORK}/out"))"
fi

# A planted data.new is discarded, and a fifo named counters.json is not copied.
seed_volume
mkdir -p "${VOL}/data.new/cdn"
echo planted >"${VOL}/data.new/cdn/feed.json"
rm -f "${VOL}/data/cdn/counters.json"
mkfifo "${VOL}/data/cdn/counters.json"
if run_overlay && [ ! -e "${VOL}/data/cdn/feed.json" ] && [ ! -e "${VOL}/data/cdn/counters.json" ]; then
    ok "a planted data.new and a fifo counters.json do not survive"
else
    err "planted data.new or fifo counters.json survived ($(cat "${WORK}/out"))"
fi

# ── Case 3: failures are fail-closed ─────────────────────────────────────
seed_volume
CHOWN_FAILS=1
if run_overlay; then err "a failed chown booted"; else ok "a failed chown fails closed"; fi
CHOWN_FAILS=0
seed_volume
REMOUNT_DROPS=noexec
if run_overlay; then err "a data mount left exec booted"; else ok "a remount that leaves exec fails closed"; fi
REMOUNT_DROPS=""
seed_volume
REMOUNT_FAILS=1
if run_overlay; then err "a failed remount booted"; else ok "a failed remount fails closed"; fi
REMOUNT_FAILS=0
seed_volume
if ( hippius_golden_harden_data "${WORK}/not-bound" ) >/dev/null 2>&1; then
    err "an unbound data directory passed"
else
    ok "an unbound data directory fails closed"
fi

# ── Case 4: hippius_golden_run — panic=10, M0 only ───────────────────────
hippius_parse_cmdline() { :; }
hippius_golden_resolve() { :; }
hippius_golden_open_lower() { :; }
hippius_golden_modprobe() { echo "panic=${panic:-}" >"${WORK}/panic"; }

run_golden() {
    # $1 = key mode the volume names ("" for M0)
    eval "hippius_golden_keymode_prepare() { HIPPIUS_GOLDEN_KEY_MODE='$1'; }"
    : >"${WORK}/panic"
    # Stop the run at the first step after the gates under test (the KEK
    # keyfile's chmod runs in hippius_golden_run's own shell).
    ( unset panic
      mktemp() { echo "${WORK}/kek"; }
      chmod() { exit 7; }
      hippius_golden_run "${SYSROOT}" ) >"${WORK}/out" 2>&1
}

run_golden ""
rc=$?
if [ "${rc}" = 7 ] && [ "$(cat "${WORK}/panic")" = "panic=10" ]; then
    ok "ephemeral M0 boot sets panic=10 and proceeds"
else
    err "ephemeral M0 boot: rc=${rc} $(cat "${WORK}/panic") ($(cat "${WORK}/out"))"
fi
for mode in M1 M2; do
    run_golden "${mode}"
    rc=$?
    if [ "${rc}" = 1 ] && grep -q 'M0 only' "${WORK}/out"; then
        ok "ephemeral boot refuses key mode ${mode}"
    else
        err "ephemeral boot accepted ${mode}: rc=${rc} ($(cat "${WORK}/out"))"
    fi
done
rm -f "${HIPPIUS_GOLDEN_EPHEMERAL_MARKER}"
run_golden "M1"
rc=$?
if [ "${rc}" = 7 ] && [ "$(cat "${WORK}/panic")" = "panic=" ]; then
    ok "standard boot leaves panic unset and accepts M1"
else
    err "standard boot: rc=${rc} $(cat "${WORK}/panic") ($(cat "${WORK}/out"))"
fi

if [ "${fail}" -ne 0 ]; then
    echo "golden-ephemeral-test: FAILED" >&2
    exit 1
fi
echo "golden-ephemeral-test: OK (all checks passed)"
