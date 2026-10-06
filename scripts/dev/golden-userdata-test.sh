#!/usr/bin/env bash
#
# H5b — customer-held keys (M1 `split` / M2 `customer`): the KBS-released
# cloud-init user-data reaches cloud-init on the FIRST boot of the volume
# only (`scripts/initramfs/hippius-golden-overlay.sh`,
# "cloud-init user-data on FIRST BOOT ONLY"):
#
#   - M1/M2 first boot (this boot formatted the upper): the staged
#     user-data is moved into the NoCloud seed, meta-data carries the
#     stable instance-id the release derived from the vm_id;
#   - M1/M2 later boot: the staged user-data is shredded, the seed gets
#     an EMPTY user-data and the SAME instance-id;
#   - anything that is not a positive "formatted this boot" (unset flag,
#     a stray value, a flag inherited from the environment / kernel
#     cmdline, a failed boot) ⇒ the user-data never reaches the seed;
#   - no valid instance-id ⇒ fail closed;
#   - M0 is unchanged: a random instance-id every boot, the user-data in
#     the seed every boot, the release core's command line as before.
#
# Part 1 drives `hippius_golden_install_seed` directly; part 2 runs the
# whole `hippius_golden_run` driver with the REAL release core and a fake
# `hippius-guest-release` on PATH (only devices, network and the upper's
# format are mocked).
#
# The real cloud-init side (what a later boot with the stable iid and an
# empty user-data does) is pinned by cloud-init-first-boot-only-check.sh.
#
# Root-free, temp-dir only.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
LIB="${HERE}/../initramfs/hippius-golden-overlay.sh"
CORE="${HERE}/../initramfs/hippius-release-core.sh"
[ -r "${LIB}" ] && [ -r "${CORE}" ] || { echo "golden-userdata-test: libs not found" >&2; exit 1; }

fail=0
ok()  { echo "golden-userdata-test: OK — $*"; }
err() { echo "golden-userdata-test: FAIL — $*" >&2; fail=1; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
RUN="${WORK}/run"
mkdir -p "${RUN}" "${WORK}/bin"

# Both libraries, with /run, /proc/cmdline and /dev/kmsg pointed into WORK.
for f in "${CORE}:core.sh" "${LIB}:lib.sh"; do
    sed -e "s#/run/#${RUN}/#g" -e "s#/dev/kmsg#${WORK}/kmsg#g" -e "s#/proc/cmdline#${WORK}/cmdline#g" \
        -e "s#-p /run #-p ${RUN} #g" "${f%%:*}" > "${WORK}/${f##*:}"
done

LOG="${WORK}/log"
SEED="${RUN}/cloud-init/seed"
IID="iid-3a693f9c2cd7229cb0d0ee2256270777"
UD='#cloud-config
runcmd: [ [ touch, /tmp/released ] ]'
PK="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
FP="$(printf '%s' "${PK}" | sha256sum | awk '{print $1}')"
BASE="ro quiet systemd.import_credentials=no dm-verity.root=${PK} hippius.disk_gb=10 boot=hippius-golden hippius.kbs_url=vsock://2:19266 ds=nocloud;s=/run/cloud-init/seed/"
keyed() { printf '%s hippius.key_mode=%s hippius.guardian_pk=%s hippius.guardian_ep=3130302e36342e302e393a37343433' "${BASE}" "$1" "${PK}"; }

# Everything a test needs, in a fresh shell each time.
load() {
    # shellcheck source=scripts/initramfs/hippius-release-core.sh
    . "${WORK}/core.sh"
    # shellcheck source=scripts/initramfs/hippius-golden-overlay.sh
    . "${WORK}/lib.sh"
    hippius_die() { echo "hippius_die: $*" >> "${LOG}"; exit 1; }
    hippius_log() { echo "log: $*" >> "${LOG}"; }
}
reset() {
    rm -rf "${RUN}"; mkdir -p "${RUN}/hippius"
    : > "${LOG}"
}
has() { grep -qE -- "$1" "${LOG}"; }
seed_ud() { cat "${SEED}/user-data" 2>/dev/null || printf '<absent>'; }
seed_md() { cat "${SEED}/meta-data" 2>/dev/null || printf '<absent>'; }
# The released bytes must be NOWHERE under /run once the boot is done.
leaked() { grep -rqF 'touch, /tmp/released' "${RUN}" 2>/dev/null; }

# ── 1. pure: the instance-id shape ───────────────────────────────────
(
    load
    hippius_golden_valid_iid "${IID}" || exit 1
    for bad in "" "iid-" "${IID}0" "iid-3A693F9C2CD7229CB0D0EE2256270777" \
        "iid-3a693f9c2cd7229cb0d0ee225627077" "IID-3a693f9c2cd7229cb0d0ee2256270777" \
        "iid-3a693f9c2cd7229cb0d0ee225627077g" "iid-${IID#iid-} x" "$(printf 'iid-%s\n' "${IID#iid-}")x"; do
        ! hippius_golden_valid_iid "${bad}" || { echo "accepted '${bad}'"; exit 1; }
    done
) && ok "instance-id: exactly iid- + 32 lowercase hex" || err "instance-id shape"

# ── 2. hippius_golden_install_seed ───────────────────────────────────
# $1 key mode ("" = M0), $2 first-boot flag, $3 iid-out content (ABSENT =
# no file), $4 staged user-data (ABSENT = no file).
install() {
    reset
    [ "$3" = ABSENT ] || printf '%s\n' "$3" > "${RUN}/hippius/instance-id"
    [ "$4" = ABSENT ] || printf '%s' "$4" > "${RUN}/hippius/userdata.staged"
    RC=0
    ( load; HIPPIUS_GOLDEN_KEY_MODE="$1"; HIPPIUS_GOLDEN_FIRST_BOOT="$2"
      HIPPIUS_GOLDEN_UPPER_CLASS="${CLASS-blank}"; HIPPIUS_GOLDEN_SHARE_C_VERSION="${SENT_VERSION-}"
      hippius_golden_install_seed ) || RC=$?
}

for mode in split customer; do
    install "${mode}" yes "${IID}" "${UD}"
    [ "${RC}" -eq 0 ] && [ "$(seed_ud)" = "${UD}" ] && [ "$(seed_md)" = "instance-id: ${IID}" ] \
        && [ ! -e "${RUN}/hippius/userdata.staged" ] \
        || err "${mode} first boot: rc=${RC} ud='$(seed_ud)' md='$(seed_md)' log=$(cat "${LOG}")"
done
ok "M1/M2 first boot: the released user-data goes to the seed, meta-data = the stable iid"

for mode in split customer; do
    install "${mode}" "" "${IID}" "${UD}"
    [ "${RC}" -eq 0 ] && [ -f "${SEED}/user-data" ] && [ ! -s "${SEED}/user-data" ] \
        && [ "$(seed_md)" = "instance-id: ${IID}" ] && [ ! -e "${RUN}/hippius/userdata.staged" ] && ! leaked \
        || err "${mode} later boot: rc=${RC} ud='$(seed_ud)' md='$(seed_md)'"
done
ok "M1/M2 later boot: EMPTY user-data, the same iid, the released user-data shredded"

# Anything but the exact positive flag is "not the first boot".
for flag in "" 1 true YES "yes " no first-boot; do
    install split "${flag}" "${IID}" "${UD}"
    [ "${RC}" -eq 0 ] && [ ! -s "${SEED}/user-data" ] && ! leaked \
        || err "flag '${flag}' handed the user-data over: rc=${RC} ud='$(seed_ud)'"
done
ok "first-boot state not positively known ⇒ the user-data is ignored"

# The flag alone is not enough: the pre-release class must be blank/init
# and the release version-less (the only path that sets the flag).
for class in ready "" init2; do
    CLASS="${class}" install split yes "${IID}" "${UD}"
    [ "${RC}" -eq 0 ] && [ ! -s "${SEED}/user-data" ] && ! leaked \
        || err "class '${class}' + flag handed the user-data over: rc=${RC} ud='$(seed_ud)'"
done
for class in blank init; do
    CLASS="${class}" SENT_VERSION=7 install split yes "${IID}" "${UD}"
    [ "${RC}" -eq 0 ] && [ ! -s "${SEED}/user-data" ] && ! leaked \
        || err "class ${class} + version 7 handed the user-data over: rc=${RC}"
    CLASS="${class}" install split yes "${IID}" "${UD}"
    [ "${RC}" -eq 0 ] && [ "$(seed_ud)" = "${UD}" ] || err "class ${class} version-less first boot: rc=${RC}"
done
ok "user-data only for class blank/init + version-less + first-boot flag"

for iid in ABSENT "" "iid-nothex" "${IID}x"; do
    install split yes "${iid}" "${UD}"
    [ "${RC}" -ne 0 ] && [ "$(seed_ud)" = "<absent>" ] && has "no valid instance-id" \
        || err "iid '${iid}': rc=${RC} ud='$(seed_ud)'"
done
ok "no valid instance-id ⇒ fail closed, nothing in the seed"

install split yes "${IID}" ABSENT
[ "${RC}" -ne 0 ] && has "first boot but the release left no user-data" \
    || err "first boot without a staged user-data: rc=${RC}"
ok "first boot without the released user-data ⇒ fail closed"

# M0: a no-op — the release core already wrote the seed.
reset
mkdir -p "${SEED}"; printf 'm0-ud' > "${SEED}/user-data"; printf 'instance-id: iid-m0\n' > "${SEED}/meta-data"
RC=0; ( load; HIPPIUS_GOLDEN_KEY_MODE=""; HIPPIUS_GOLDEN_FIRST_BOOT=""; hippius_golden_install_seed ) || RC=$?
[ "${RC}" -eq 0 ] && [ "$(seed_ud)" = m0-ud ] && [ "$(seed_md)" = "instance-id: iid-m0" ] && [ ! -s "${LOG}" ] \
    || err "M0 install_seed touched the seed"
ok "M0: install_seed is a no-op"

# ── 3. only the format path says "first boot" ────────────────────────
(
    load
    cryptsetup() { case "$1 $2" in "token import") cat > /dev/null ;; esac; return 0; }
    hippius_golden_init_upper() { :; }
    printf '3\n' > "${RUN}/hippius/share-c-version"
    HIPPIUS_GOLDEN_KEY_MODE=split; HIPPIUS_GOLDEN_GUARDIAN_FP="${FP}"; HIPPIUS_GOLDEN_FIRST_BOOT=""
    HIPPIUS_GOLDEN_UPPER="${WORK}/upper"
    hippius_golden_format_upper "${WORK}/kek"
    [ "${HIPPIUS_GOLDEN_FIRST_BOOT}" = yes ]
) && ok "format_upper (after init) sets the first-boot flag" || err "format_upper did not set the flag"
# Structural: the flag is set in exactly one place, the format path
# (reached for a blank upper and for an interrupted first boot under
# E == 0, never for a reopen).
[ "$(grep -c 'HIPPIUS_GOLDEN_FIRST_BOOT="yes"' "${LIB}")" -eq 1 ] \
    && awk '/^hippius_golden_format_upper\(\) \{/{f=1} f&&/^}/{exit} f' "${LIB}" | grep -q 'HIPPIUS_GOLDEN_FIRST_BOOT="yes"' \
    && ok "the first-boot flag is set only in hippius_golden_format_upper" \
    || err "the first-boot flag is set outside hippius_golden_format_upper"
( load; [ -z "${HIPPIUS_GOLDEN_FIRST_BOOT}" ] ) || err "sourcing the library left a first-boot flag set"
( export HIPPIUS_GOLDEN_FIRST_BOOT=yes; load; [ -z "${HIPPIUS_GOLDEN_FIRST_BOOT}" ] ) \
    && ok "a first-boot flag in the environment (e.g. from the kernel cmdline) is dropped at source time" \
    || err "sourcing kept an inherited first-boot flag"

# ── 4. the whole driver, real release core, fake release binary ─────
cat > "${WORK}/bin/hippius-guest-release" <<EOF
#!/bin/sh
# Fake: records its argv, writes what the real binary writes.
printf '%s\n' "\$*" >> "${WORK}/release-args"
[ -n "\${FAKE_RELEASE_FAIL:-}" ] && exit 3
# The host may change the upper once the release has happened.
: > "${WORK}/released"
while [ \$# -gt 0 ]; do
    case "\$1" in
        --userdata-out) mkdir -p "\$(dirname "\$2")"; printf '%s' "${UD}" > "\$2"; shift ;;
        --instance-id-out) printf '%s\n' "${IID}" > "\$2"; shift ;;
        --share-c-version-out) printf '1\n' > "\$2"; shift ;;
        --volume-stamp-expected-out) printf '%s\n' "\${FAKE_E:-0}" > "\$2"; shift ;;
        --volume-stamp-ctx-out) printf 'ctx' > "\$2"; shift ;;
        *) : ;;
    esac
    shift
done
head -c 32 /dev/zero
EOF
chmod +x "${WORK}/bin/hippius-guest-release"
export PATH="${WORK}/bin:${PATH}"

# The REAL `hippius_golden_open_upper` runs below; its `-b` check needs a
# block device (the tools are mocked, nothing touches it).
BLK="$(find /dev -maxdepth 1 -type b 2>/dev/null | head -n 1)"
if [ -z "${BLK}" ]; then
    [ -z "${CI:-}" ] || { err "no block device visible in CI — the driver cases cannot run"; exit 1; }
    echo "golden-userdata-test: no block device visible — skipping the driver cases"
    [ "${fail}" -eq 0 ] && echo "golden-userdata-test: OK (all checks passed)" || exit 1
    exit 0
fi
CS_LOG="${WORK}/cryptsetup-log"

# $1 cmdline, $2 upper: zeroed (the WHOLE upper is zeros: no LUKS header,
# no data) | existing | open-fails. FAKE_E = the signed expectation.
boot() {
    reset
    printf '%s\n' "$1" > "${WORK}/cmdline"
    : > "${WORK}/release-args"
    : > "${CS_LOG}"
    rm -f "${WORK}/released"
    RC=0
    (
        load
        UPPER_STATE="$2"
        hippius_golden_modprobe() { :; }
        hippius_golden_resolve() { HIPPIUS_GOLDEN_UPPER="${BLK}"; HIPPIUS_GOLDEN_DISK_GB=1; }
        blockdev() { echo 1099511627776; }
        # Format → wipe → mkfs is golden-upper-init-test's; here only that it ran.
        hippius_golden_init_upper() { echo "init_upper" >> "${CS_LOG}"; }
        hippius_golden_open_lower() { :; }
        hippius_modprobe_chain() { :; }
        hippius_net_up() { :; }
        hippius_kbs_preflight() { :; }
        hippius_fetch_ticket() { HIPPIUS_TICKET_FILE="${WORK}/ticket"; : > "${HIPPIUS_TICKET_FILE}"; }
        hippius_mount_state_disk() { HIPPIUS_STATE_DISK_FLAGS=""; HIPPIUS_STATE_DISK_MOUNTED=no; }
        hippius_golden_mount_overlay() { :; }
        # #1305's M0 guard (tested in golden-overlay-test.sh / its own suite).
        hippius_golden_harden_root() { :; }
        # States: zeroed | existing | open-fails | init (init label, token
        # kept) | flip-init / flip-blank (ready with its token before the
        # release; the host relabels init / zeroes the header after it).
        cryptsetup() {
            echo "cryptsetup $1" >> "${CS_LOG}"
            _st="${UPPER_STATE}"
            if [ -e "${WORK}/released" ]; then
                case "${_st}" in flip-init) _st=init ;; flip-blank) _st=zeroed ;; esac
            fi
            _lbl=hippius-upper
            [ "${_st}" != init ] || _lbl=hippius-upper-init
            case "$1" in
                isLuks) [ "${_st}" != zeroed ] ;;
                luksDump) printf 'Label:          %s\n\nTokens:\n  0: hippius-keymode\nDigests:\n' "${_lbl}" ;;
                token)
                    case "$2" in
                        export) printf '%s' "$(hippius_golden_keymode_token_json "${KM}" "${FP}" 1)" ;;
                        import) cat > /dev/null ;;
                    esac ;;
                open) [ "${UPPER_STATE}" != open-fails ] ;;
                *) return 0 ;;
            esac
        }
        hippius_golden_run "${WORK}/root"
    ) || RC=$?
}

for KM in split customer; do
    export KM
    boot "$(keyed "${KM}")" zeroed
    [ "${RC}" -eq 0 ] && [ "$(seed_ud)" = "${UD}" ] && [ "$(seed_md)" = "instance-id: ${IID}" ] \
        && [ ! -e "${RUN}/hippius/userdata.staged" ] \
        && grep -q -- "--userdata-out ${RUN}/hippius/userdata.staged" "${WORK}/release-args" \
        && grep -q -- "--instance-id-out ${RUN}/hippius/instance-id" "${WORK}/release-args" \
        || err "driver ${KM} first boot: rc=${RC} ud='$(seed_ud)' md='$(seed_md)' args=$(cat "${WORK}/release-args") log=$(cat "${LOG}")"

    boot "$(keyed "${KM}")" existing
    [ "${RC}" -eq 0 ] && [ -f "${SEED}/user-data" ] && [ ! -s "${SEED}/user-data" ] \
        && [ "$(seed_md)" = "instance-id: ${IID}" ] && ! leaked \
        || err "driver ${KM} later boot: rc=${RC} ud='$(seed_ud)' md='$(seed_md)' log=$(cat "${LOG}")"

    # A first-boot flag handed in through the environment changes nothing.
    ( export HIPPIUS_GOLDEN_FIRST_BOOT=yes; boot "$(keyed "${KM}")" existing
      [ "${RC}" -eq 0 ] && [ ! -s "${SEED}/user-data" ] && ! leaked ) \
        || err "driver ${KM}: an inherited first-boot flag handed the user-data over"
    # Nor does a cmdline/environment attempt to point the release at the seed.
    ( export HIPPIUS_USERDATA_OUT="${SEED}/user-data"
      boot "$(keyed "${KM}")" existing
      [ "${RC}" -eq 0 ] && [ ! -s "${SEED}/user-data" ] && ! leaked ) \
        || err "driver ${KM}: an inherited HIPPIUS_USERDATA_OUT reached the seed"

    # B1: the WHOLE upper of a VM that has booted before is zeroed (signed
    # expectation > 0): the guest refuses before luksFormat — no format,
    # no seed, the released user-data gone.
    for e in 1 5; do
        FAKE_E="${e}" boot "$(keyed "${KM}")" zeroed
        [ "${RC}" -ne 0 ] && has "a blanked upper is not a first boot" \
            && ! grep -q "cryptsetup luksFormat" "${CS_LOG}" \
            && [ "$(seed_ud)" = "<absent>" ] && ! leaked \
            || err "driver ${KM} zeroed upper, E=${e}: rc=${RC} ud='$(seed_ud)' cs=$(tr '\n' ' ' < "${CS_LOG}") log=$(cat "${LOG}")"
    done
    # THE TOCTOU (Review HIGH): ready with its token before the release (so
    # a share version is sent), then relabelled init / zeroed before the
    # open — even under E == 0 nothing is formatted and nothing seeded.
    for st in flip-init flip-blank; do
        FAKE_E=0 boot "$(keyed "${KM}")" "${st}"
        [ "${RC}" -ne 0 ] && grep -q -- "--share-c-version 1" "${WORK}/release-args" \
            && ! grep -q "cryptsetup luksFormat" "${CS_LOG}" \
            && [ "$(seed_ud)" = "<absent>" ] && ! leaked \
            || err "driver ${KM} ${st}: rc=${RC} ud='$(seed_ud)' args=$(cat "${WORK}/release-args") cs=$(tr '\n' ' ' < "${CS_LOG}") log=$(cat "${LOG}")"
    done
    # An init-labelled upper (interrupted first boot) carrying a token: the
    # request is version-less; it formats only under E == 0.
    FAKE_E=0 boot "$(keyed "${KM}")" init
    [ "${RC}" -eq 0 ] && ! grep -q -- "--share-c-version " "${WORK}/release-args" \
        && grep -q "cryptsetup luksFormat" "${CS_LOG}" && [ "$(seed_ud)" = "${UD}" ] \
        || err "driver ${KM} init, E=0: rc=${RC} args=$(cat "${WORK}/release-args") cs=$(tr '\n' ' ' < "${CS_LOG}")"
    FAKE_E=3 boot "$(keyed "${KM}")" init
    [ "${RC}" -ne 0 ] && ! grep -q "cryptsetup luksFormat" "${CS_LOG}" && [ "$(seed_ud)" = "<absent>" ] \
        || err "driver ${KM} init, E=3: rc=${RC} cs=$(tr '\n' ' ' < "${CS_LOG}")"

    # ... and with E == 0 (a genuine first boot) it formats.
    FAKE_E=0 boot "$(keyed "${KM}")" zeroed
    [ "${RC}" -eq 0 ] && grep -q "cryptsetup luksFormat" "${CS_LOG}" && [ "$(seed_ud)" = "${UD}" ] \
        || err "driver ${KM} zeroed upper, E=0: rc=${RC} cs=$(tr '\n' ' ' < "${CS_LOG}")"

    boot "$(keyed "${KM}")" open-fails
    [ "${RC}" -ne 0 ] && [ "$(seed_ud)" = "<absent>" ] && ! leaked \
        || err "driver ${KM} failed boot: rc=${RC} ud='$(seed_ud)'"
    FAKE_RELEASE_FAIL=1 boot "$(keyed "${KM}")" zeroed
    [ "${RC}" -ne 0 ] && [ "$(seed_ud)" = "<absent>" ] && ! leaked \
        || err "driver ${KM} failed release: rc=${RC} ud='$(seed_ud)'"
done
ok "driver M1/M2: TOCTOU — ready before the release, then relabelled init or zeroed: refused under any E, version was sent, no format, no seed"
ok "driver M1/M2: init-labelled upper with a token → version-less release; formats only under E == 0"
ok "driver M1/M2: a zeroed upper under E > 0 is refused before luksFormat (no seed); under E == 0 it formats"
ok "driver M1/M2: first boot hands the user-data over with the stable iid; later boots get an empty one with the same iid; env overrides and failed boots expose nothing"

# M0: the release core writes the user-data straight into the seed with a
# random iid, every boot; no H5b flag reaches the release — whatever the
# environment (the kernel cmdline) says.
KM=""
( export HIPPIUS_USERDATA_OUT="${RUN}/elsewhere"
  boot "${BASE}" existing
  [ "${RC}" -eq 0 ] && [ "$(seed_ud)" = "${UD}" ] && [ ! -e "${RUN}/elsewhere" ] ) \
    || err "driver M0: an inherited HIPPIUS_USERDATA_OUT moved the user-data"
boot "${BASE}" existing
M0_MD1="$(seed_md)"
[ "${RC}" -eq 0 ] && [ "$(seed_ud)" = "${UD}" ] \
    && grep -q -- "--userdata-out ${SEED}/user-data" "${WORK}/release-args" \
    && ! grep -q -- "--instance-id-out" "${WORK}/release-args" \
    && [ ! -e "${RUN}/hippius/userdata.staged" ] \
    || err "driver M0: rc=${RC} ud='$(seed_ud)' args=$(cat "${WORK}/release-args")"
case "${M0_MD1}" in
    "instance-id: iid-"????????-????-????-????-????????????) : ;;
    *) err "driver M0: meta-data is not a per-boot uuid iid: '${M0_MD1}'" ;;
esac
FAKE_E=5 boot "${BASE}" zeroed
[ "${RC}" -eq 0 ] && grep -q "cryptsetup luksFormat" "${CS_LOG}" \
    && [ "$(seed_ud)" = "${UD}" ] && [ "$(seed_md)" != "${M0_MD1}" ] \
    || err "driver M0 second boot: rc=${RC} md='$(seed_md)' (was '${M0_MD1}')"
ok "driver M0: user-data in the seed every boot, a fresh random iid every boot, no H5b flag"

[ "${fail}" -eq 0 ] && echo "golden-userdata-test: OK (all checks passed)" || exit 1
