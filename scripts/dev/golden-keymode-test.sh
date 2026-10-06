#!/usr/bin/env bash
#
# Unit test for the customer-held-keys (M1 `split` / M2 `customer`)
# additions to `scripts/initramfs/hippius-golden-overlay.sh`:
#
#   - M0 (no `hippius.key_mode`, or `hippius`): no token is read or
#     written, no extra release flag — the M0 boot is unchanged;
#   - first boot (blank upper): no `--share-c-version`, and right after
#     `luksFormat` (before the wipe and the ready relabel) the
#     `hippius-keymode` LUKS2 token records mode, guardian fingerprint
#     and the share version the release left on tmpfs;
#   - later boots: the token's version is passed as `--share-c-version`;
#     a token whose mode or guardian disagrees with the measured cmdline,
#     a malformed token, two tokens, or no token on a volume past init
#     all fail closed BEFORE any KBS or guardian contact;
#   - with a real `cryptsetup` on a file image (when one is installed):
#     the token this script writes is the token it reads back.
#
# Root-free, no devices. The library is sourced from a copy with
# `/proc/cmdline` and `/dev/kmsg` pointed at temp files.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${HERE}/../initramfs/hippius-golden-overlay.sh"
[ -r "${SRC}" ] || { echo "golden-keymode-test: lib not found at ${SRC}" >&2; exit 1; }

fail=0
ok()  { echo "golden-keymode-test: OK — $*"; }
err() { echo "golden-keymode-test: FAIL — $*" >&2; fail=1; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

sed -e "s#/dev/kmsg#${WORK}/kmsg#g" -e "s#/proc/cmdline#${WORK}/cmdline#g" "${SRC}" > "${WORK}/lib.sh"
# shellcheck source=scripts/initramfs/hippius-golden-overlay.sh
. "${WORK}/lib.sh"

LOG="${WORK}/log"
hippius_die() { echo "hippius_die: $*" >> "${LOG}"; exit 1; }
hippius_log() { :; }

PK="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
FP="$(printf '%s' "${PK}" | sha256sum | awk '{print $1}')"
OTHER_FP="$(printf '%s' "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100" | sha256sum | awk '{print $1}')"
BASE="ro quiet dm-verity.root=${PK} hippius.disk_gb=10 boot=hippius-golden"
keyed() { printf '%s hippius.key_mode=%s hippius.guardian_pk=%s hippius.guardian_ep=3130302e36342e302e393a37343433' "${BASE}" "$1" "${PK}"; }

# ── 1. pure helpers ──────────────────────────────────────────────────
for row in "1|${BASE}|" "1|${BASE} hippius.key_mode=hippius|" \
    "0|$(keyed split)|split" "0|$(keyed customer)|customer" \
    "2|${BASE} hippius.key_mode=bogus|"; do
    want_rc="${row%%|*}"; rest="${row#*|}"; cl="${rest%|*}"; want="${rest##*|}"
    got_rc=0; got="$(hippius_golden_key_mode_of "${cl}")" || got_rc=$?
    [ "${got_rc}" = "${want_rc}" ] && [ "${got}" = "${want}" ] \
        || err "key_mode_of '${cl}': rc=${got_rc} got='${got}', want rc=${want_rc} '${want}'"
done
ok "key mode: absent/hippius = M0, split/customer = keyed, anything else refused"

[ "$(hippius_golden_guardian_fp_of "$(keyed split)")" = "${FP}" ] \
    || err "guardian_fp is not sha256 of the guardian_pk hex"
! hippius_golden_guardian_fp_of "${BASE} hippius.key_mode=split hippius.guardian_pk=ABC" >/dev/null \
    || err "a malformed guardian_pk yielded a fingerprint"
ok "guardian fingerprint = sha256(guardian_pk hex)"

for v in 1 7 4294967295; do
    [ "$(hippius_golden_valid_share_version "${v}")" = "${v}" ] || err "share version ${v} refused"
done
for v in "" 0 01 4294967296 12345678901 1a -1; do
    ! hippius_golden_valid_share_version "${v}" >/dev/null || err "share version '${v}' accepted"
done
ok "share version: u32, never 0, one spelling"

JSON="$(hippius_golden_keymode_token_json split "${FP}" 3)"
[ "${JSON}" = "{\"type\":\"hippius-keymode\",\"keyslots\":[],\"mode\":\"split\",\"guardian_fp\":\"${FP}\",\"share_c_version\":3}" ] \
    || err "token JSON shape: ${JSON}"
hippius_golden_parse_keymode_token "${JSON}" \
    && [ "${_HGKT_MODE}" = split ] && [ "${_HGKT_FP}" = "${FP}" ] && [ "${_HGKT_VERSION}" = 3 ] \
    || err "token JSON does not parse back"
# cryptsetup may print spaces around ':'.
hippius_golden_parse_keymode_token "{ \"type\": \"hippius-keymode\", \"keyslots\": [ ], \"mode\": \"customer\", \"guardian_fp\": \"${FP}\", \"share_c_version\": 12 }" \
    && [ "${_HGKT_MODE}" = customer ] && [ "${_HGKT_VERSION}" = 12 ] \
    || err "spaced token JSON does not parse"
for bad in \
    "{\"type\":\"luks2-keyring\",\"keyslots\":[],\"mode\":\"split\",\"guardian_fp\":\"${FP}\",\"share_c_version\":3}" \
    "{\"type\":\"hippius-keymode\",\"keyslots\":[],\"mode\":\"hippius\",\"guardian_fp\":\"${FP}\",\"share_c_version\":3}" \
    "{\"type\":\"hippius-keymode\",\"keyslots\":[],\"mode\":\"split\",\"guardian_fp\":\"abc\",\"share_c_version\":3}" \
    "{\"type\":\"hippius-keymode\",\"keyslots\":[],\"mode\":\"split\",\"guardian_fp\":\"${FP}\",\"share_c_version\":0}" \
    "{\"type\":\"hippius-keymode\",\"keyslots\":[],\"mode\":\"split\",\"guardian_fp\":\"${FP}\"}" \
    "garbage"; do
    ! hippius_golden_parse_keymode_token "${bad}" || err "malformed token accepted: ${bad}"
done
ok "token JSON round-trips; every malformed shape is refused"

# ── 2. prepare / write against a mocked cryptsetup ───────────────────
HIPPIUS_GOLDEN_UPPER="${WORK}/upper"
HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT="${WORK}/share-c-version"
# M_TOKENS: token lines for luksDump; M_TOKEN_JSON: what export prints.
cryptsetup() {
    echo "cryptsetup $*" >> "${LOG}"
    case "$1" in
        isLuks) return "${M_ISLUKS}" ;;
        luksDump)
            printf 'LUKS header information\nVersion:       \t2\nLabel:          %s\n\nTokens:\n%sDigests:\n' \
                "${M_LABEL}" "${M_TOKENS}" ;;
        token)
            case "$2" in
                export) printf '%s' "${M_TOKEN_JSON}" ;;
                import) cat > "${WORK}/imported" ;;
            esac ;;
    esac
    return 0
}

# $1 cmdline, $2 isLuks rc, $3 label, $4 luksDump token lines, $5 export JSON.
prep() {
    printf '%s\n' "$1" > "${WORK}/cmdline"
    M_ISLUKS="$2"; M_LABEL="$3"; M_TOKENS="$4"; M_TOKEN_JSON="$5"
    : > "${LOG}"
    RC=0
    OUT="$( hippius_golden_keymode_prepare
            printf '%s|%s|%s|%s' "${HIPPIUS_GOLDEN_KEY_MODE}" "${HIPPIUS_GOLDEN_GUARDIAN_FP}" \
                "${HIPPIUS_GOLDEN_SHARE_C_VERSION}" "$(hippius_golden_keymode_release_flags)" > "${WORK}/out"
            printf '%s' "${HIPPIUS_GOLDEN_UPPER_CLASS}" > "${WORK}/class" )" || RC=$?
    OUT="$(cat "${WORK}/out" 2>/dev/null)"; CLASS="$(cat "${WORK}/class" 2>/dev/null)"
    rm -f "${WORK}/out" "${WORK}/class"
}
has() { grep -qE -- "$1" "${LOG}"; }
ONE_TOKEN="  0: hippius-keymode
"

# 2a. M0: nothing read, no flags.
for cl in "${BASE}" "${BASE} hippius.key_mode=hippius"; do
    prep "${cl}" 0 hippius-upper "${ONE_TOKEN}" "$(hippius_golden_keymode_token_json split "${FP}" 3)"
    [ "${RC}" -eq 0 ] && [ "${OUT}" = "|||" ] && [ -z "${CLASS}" ] && [ ! -s "${LOG}" ] \
        || err "M0 '${cl}': rc=${RC} out='${OUT}' log=$(cat "${LOG}")"
done
( HIPPIUS_GOLDEN_KEY_MODE=""; : > "${LOG}"; hippius_golden_write_keymode_token ) && [ ! -s "${LOG}" ] \
    || err "M0 wrote a token"
ok "M0: no token read or written, no extra release flag"

# 2b. keyed first boot (blank upper): no version, the out flag only.
prep "$(keyed split)" 1 "" "" ""
[ "${RC}" -eq 0 ] && [ "${CLASS}" = blank ] \
    && [ "${OUT}" = "split|${FP}|| --share-c-version-out ${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT} --instance-id-out ${HIPPIUS_GOLDEN_IID_OUT}" ] \
    || err "first boot: rc=${RC} out='${OUT}'"
ok "keyed first boot: no share version, --share-c-version-out + --instance-id-out only"

# 2c. later boot: the token's version is passed through.
for mode in split customer; do
    prep "$(keyed "${mode}")" 0 hippius-upper "${ONE_TOKEN}" "$(hippius_golden_keymode_token_json "${mode}" "${FP}" 7)"
    [ "${RC}" -eq 0 ] \
        && [ "${CLASS}" = ready ] \
        && [ "${OUT}" = "${mode}|${FP}|7| --share-c-version-out ${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT} --share-c-version 7 --instance-id-out ${HIPPIUS_GOLDEN_IID_OUT}" ] \
        || err "later boot ${mode}: rc=${RC} out='${OUT}'"
done
ok "later boot: the token's share version reaches --share-c-version"

# 2d. every disagreement fails closed.
fails() { # $1 label for the message, $2 expected die pattern; prep already ran
    [ "${RC}" -ne 0 ] && has "^hippius_die: .*$2" || err "$1: rc=${RC} log=$(cat "${LOG}")"
}
prep "$(keyed split)" 0 hippius-upper "${ONE_TOKEN}" "$(hippius_golden_keymode_token_json customer "${FP}" 7)"
fails "mode mismatch" "formatted in mode customer but this boot measures split"
prep "$(keyed split)" 0 hippius-upper "${ONE_TOKEN}" "$(hippius_golden_keymode_token_json split "${OTHER_FP}" 7)"
fails "guardian mismatch" "formatted for guardian"
prep "$(keyed split)" 0 hippius-upper "${ONE_TOKEN}" '{"type":"hippius-keymode","mode":"split"}'
fails "malformed token" "token is malformed"
prep "$(keyed split)" 0 hippius-upper "  0: hippius-keymode
  1: hippius-keymode
" "$(hippius_golden_keymode_token_json split "${FP}" 7)"
fails "two tokens" "more than one hippius-keymode token"
prep "$(keyed split)" 0 hippius-upper "" ""
fails "no token past init" "carries no hippius-keymode token"
prep "$(keyed split)" 0 hippius-upper "  0: luks2-keyring
" ""
fails "only a foreign token" "carries no hippius-keymode token"
prep "${BASE} hippius.key_mode=bogus" 0 hippius-upper "" ""
fails "unknown mode" "unknown value"
prep "${BASE} hippius.key_mode=split hippius.guardian_pk=zz hippius.guardian_ep=312e322e332e343a35" 1 "" "" ""
fails "malformed guardian_pk" "guardian_pk= missing/malformed"
ok "mode / guardian mismatch, malformed or duplicate token, token missing past init: fail-closed"

# 2d'. an isLuks answer that is neither LUKS nor "not LUKS" is not a
#      blank upper (B1): fail closed before any contact.
for rc in 2 4; do
    prep "$(keyed split)" "${rc}" "" "" ""
    fails "isLuks exit ${rc}" "cannot tell whether the upper is LUKS"
done
ok "isLuks error: fail-closed, never read as a blank upper"

# 2e. no token yet on an upper whose init never finished: no version.
prep "$(keyed customer)" 0 "${HIPPIUS_GOLDEN_INIT_LABEL}" "" ""
[ "${RC}" -eq 0 ] && [ "${CLASS}" = init ] \
    && [ "${OUT}" = "customer|${FP}|| --share-c-version-out ${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT} --instance-id-out ${HIPPIUS_GOLDEN_IID_OUT}" ] \
    || err "interrupted first boot without a token: rc=${RC} out='${OUT}'"
ok "interrupted first boot with no token: class init, version-less"

# 2e'. an init-labelled volume WITH a valid token is still class init and
#      the request is VERSION-LESS: the unauthenticated label can only
#      lead to a format through the guardian's once-only gate.
for mode in split customer; do
    prep "$(keyed "${mode}")" 0 "${HIPPIUS_GOLDEN_INIT_LABEL}" "${ONE_TOKEN}" \
        "$(hippius_golden_keymode_token_json "${mode}" "${FP}" 7)"
    [ "${RC}" -eq 0 ] && [ "${CLASS}" = init ] \
        && [ "${OUT}" = "${mode}|${FP}|| --share-c-version-out ${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT} --instance-id-out ${HIPPIUS_GOLDEN_IID_OUT}" ] \
        || err "init label + token (${mode}): rc=${RC} class='${CLASS}' out='${OUT}'"
done
ok "init label + a valid token: class init, NO share version sent (token ignored)"
# ... and the class is not taken from the environment.
( export HIPPIUS_GOLDEN_UPPER_CLASS=ready
  prep "$(keyed split)" 1 "" "" ""
  [ "${CLASS}" = blank ] ) || err "an inherited HIPPIUS_GOLDEN_UPPER_CLASS survived prepare"
( export HIPPIUS_GOLDEN_UPPER_CLASS=blank
  prep "${BASE}" 1 "" "" ""
  [ -z "${CLASS}" ] ) || err "M0 prepare left an inherited HIPPIUS_GOLDEN_UPPER_CLASS in place"
( . "${WORK}/lib.sh"; [ -z "${HIPPIUS_GOLDEN_UPPER_CLASS}" ] ) \
    || err "sourcing the library kept a class"
( export HIPPIUS_GOLDEN_UPPER_CLASS=init; . "${WORK}/lib.sh"; [ -z "${HIPPIUS_GOLDEN_UPPER_CLASS}" ] ) \
    || err "sourcing the library kept an inherited class"
ok "HIPPIUS_GOLDEN_UPPER_CLASS is set by prepare, never inherited"

# 2f. the first-boot write records what the release sealed.
write_case() { # $1 share-c-version-out content (ABSENT = no file)
    if [ "$1" = ABSENT ]; then rm -f "${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT}"; else printf '%s' "$1" > "${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT}"; fi
    rm -f "${WORK}/imported"; : > "${LOG}"; RC=0
    ( HIPPIUS_GOLDEN_KEY_MODE=split; HIPPIUS_GOLDEN_GUARDIAN_FP="${FP}"; hippius_golden_write_keymode_token ) || RC=$?
}
write_case "5
"
[ "${RC}" -eq 0 ] && [ "$(cat "${WORK}/imported")" = "$(hippius_golden_keymode_token_json split "${FP}" 5)" ] \
    && has "^cryptsetup token import ${HIPPIUS_GOLDEN_UPPER}\$" \
    || err "token write: rc=${RC} imported=$(cat "${WORK}/imported" 2>/dev/null)"
for bad in ABSENT "" "0
" "x
"; do
    write_case "${bad}"
    [ "${RC}" -ne 0 ] && [ ! -e "${WORK}/imported" ] && has "^hippius_die: .*no valid share version" \
        || err "token write with share version '${bad}': rc=${RC}"
done
ok "first-boot token = mode + guardian fp + the version the release sealed; no version ⇒ fail-closed"

# 2g. in the format path the token lands right after luksFormat, before
#     the wipe and the ready relabel.
LOG_FMT="${WORK}/fmt"
: > "${LOG_FMT}"
(
    cryptsetup() { echo "cryptsetup $1 $2" >> "${LOG_FMT}"; [ "$1 $2" != "token import" ] || cat > /dev/null; }
    hippius_golden_init_upper() { echo "init_upper" >> "${LOG_FMT}"; }
    printf '9\n' > "${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT}"
    HIPPIUS_GOLDEN_KEY_MODE=customer; HIPPIUS_GOLDEN_GUARDIAN_FP="${FP}"
    hippius_golden_format_upper "${WORK}/kek"
)
[ "$(tr '\n' ',' < "${LOG_FMT}")" = "cryptsetup luksFormat --type,cryptsetup token import,init_upper," ] \
    || err "format order: $(tr '\n' ',' < "${LOG_FMT}")"
: > "${LOG_FMT}"
(
    cryptsetup() { echo "cryptsetup $1 $2" >> "${LOG_FMT}"; }
    hippius_golden_init_upper() { echo "init_upper" >> "${LOG_FMT}"; }
    HIPPIUS_GOLDEN_KEY_MODE=""
    hippius_golden_format_upper "${WORK}/kek"
)
[ "$(tr '\n' ',' < "${LOG_FMT}")" = "cryptsetup luksFormat --type,init_upper," ] \
    || err "M0 format order: $(tr '\n' ',' < "${LOG_FMT}")"
ok "format: keyed ⇒ luksFormat → token → init; M0 ⇒ luksFormat → init"

# ── 2h. no KBS contact before the guardian: the release core's
#        diagnostic KBS preflight is skipped when the golden overlay says
#        the guardian goes first, and runs as before otherwise. ─────────
CORE="${HERE}/../initramfs/hippius-release-core.sh"
sed "s#/dev/kmsg#${WORK}/kmsg#g" "${CORE}" > "${WORK}/core.sh"
(
    # shellcheck source=scripts/initramfs/hippius-release-core.sh
    . "${WORK}/core.sh"
    hippius_log() { :; }
    curl() { echo "curl $*" >> "${LOG}"; }
    HIPPIUS_KBS_URL="https://kbs.test"
    : > "${LOG}"
    hippius_kbs_preflight
    grep -q "^curl .*https://kbs.test/v1/kbs/nonce" "${LOG}" || { echo "M0 preflight no longer probes the KBS"; exit 1; }
    : > "${LOG}"
    HIPPIUS_GUARDIAN_FIRST=1 hippius_kbs_preflight
    [ ! -s "${LOG}" ] || { echo "keyed preflight contacted the KBS: $(cat "${LOG}")"; exit 1; }
) && ok "guardian-first boots skip the KBS preflight; M0 still probes" \
    || err "KBS preflight gating"

# ── 3. real cryptsetup on a file image ───────────────────────────────
unset -f cryptsetup
REAL="$(command -v cryptsetup || true)"
if [ -z "${REAL}" ]; then
    echo "golden-keymode-test: cryptsetup not installed — skipping the real-header round trip"
else
    IMG="${WORK}/upper.img"
    truncate -s 32M "${IMG}"
    head -c 32 /dev/urandom > "${WORK}/kek"
    if cryptsetup luksFormat --type luks2 --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
        --label "${HIPPIUS_GOLDEN_INIT_LABEL}" "${IMG}" --key-file "${WORK}/kek" >/dev/null 2>&1; then
        HIPPIUS_GOLDEN_UPPER="${IMG}"
        printf '11\n' > "${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT}"
        : > "${LOG}"
        ( HIPPIUS_GOLDEN_KEY_MODE=split; HIPPIUS_GOLDEN_GUARDIAN_FP="${FP}"; hippius_golden_write_keymode_token ) \
            || err "real token import: $(cat "${LOG}")"
        cryptsetup config --label "${HIPPIUS_GOLDEN_READY_LABEL}" "${IMG}" >/dev/null 2>&1
        printf '%s\n' "$(keyed split)" > "${WORK}/cmdline"
        : > "${LOG}"
        OUT="$( hippius_golden_keymode_prepare; printf '%s' "${HIPPIUS_GOLDEN_SHARE_C_VERSION}" )" \
            && [ "${OUT}" = 11 ] || err "real token read back: out='${OUT}' log=$(cat "${LOG}")"
        printf '%s\n' "$(keyed customer)" > "${WORK}/cmdline"
        : > "${LOG}"
        ! ( hippius_golden_keymode_prepare ) && has "formatted in mode split" \
            || err "real token, other mode: $(cat "${LOG}")"
        # A second token of the same type (a header we never write).
        hippius_golden_keymode_token_json split "${FP}" 12 | cryptsetup token import "${IMG}" >/dev/null 2>&1
        printf '%s\n' "$(keyed split)" > "${WORK}/cmdline"
        : > "${LOG}"
        ! ( hippius_golden_keymode_prepare ) && has "more than one" \
            || err "real header, two tokens: $(cat "${LOG}")"
        ok "real cryptsetup: the token written is the token read; mismatch and duplicates fail closed"
    else
        echo "golden-keymode-test: cryptsetup cannot format a file image here — skipping the real-header round trip"
    fi
fi

[ "${fail}" -eq 0 ] && echo "golden-keymode-test: OK (all checks passed)" || exit 1
