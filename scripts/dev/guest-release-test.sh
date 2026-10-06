#!/usr/bin/env bash
# Guest components release (docs/design/guest-component-rollout.md):
#
#   A. the release record parser `hippius_golden_parse_release`;
#   B. the boot step `_hippius_golden_components_run` against temp roots —
#      no record = strict no-op, the unit links + .wants links + retired
#      masks, links written even when the image does not mount (and then
#      NO agent: never the base's), fail-closed link writes, the strict
#      SELinux label on an SELinux base;
#   C. the same boot step under the shells the initramfs really runs
#      (busybox ash, dash) when they are installed;
#   D. scripts/guest/build-guest-release.sh: two runs give the same bytes,
#      the record it writes is the one the boot step accepts, the members
#      carry only the expected entries, every image entry is labelled, and
#      its refusals.
#
# Root-free. The loop mount is the one thing a test cannot do without
# root: the busybox handed to the boot step is a stub that forwards
# cp/sha256sum to the real tools and "mounts" by copying a tree.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "${HERE}/../.." && pwd)"
LIB="${REPO}/scripts/initramfs/hippius-golden-overlay.sh"
BUILD="${REPO}/scripts/guest/build-guest-release.sh"

fail=0
ok()  { echo "guest-release-test: OK — $*"; }
err() { echo "guest-release-test: FAIL — $*" >&2; fail=1; }
# A skipped section is a failure in CI (CI=true), where every tool is
# installed on purpose.
skip() {
    if [[ "${CI:-}" == true ]]; then err "SKIPPED in CI: $*"; else echo "guest-release-test: SKIP — $*"; fi
}

T="$(mktemp -d)"
trap 'chmod -R u+w "${T}" 2>/dev/null; rm -r "${T}"' EXIT

SHA_A="$(printf 'a%.0s' $(seq 64))"
COMMIT="$(printf 'c%.0s' $(seq 40))"

# A shell snippet sourcing the library with test stubs. hippius_die exits
# the (sub)shell with 42 so a test can tell a fail-closed die from any
# other failure.
prelude() {
    cat <<EOF
hippius_log() { printf '%s\n' "\$*" >> "${T}/log"; }
hippius_die() { printf 'DIE %s\n' "\$*" >> "${T}/log"; exit 42; }
. "${LIB}"
EOF
}
run_sh() {
    # run_sh <shell> <script>, under `set -eu` like the dracut caller
    # (hippius-golden-mount.sh): an unguarded failing command or an unset
    # variable in the step must show here.
    "$1" -c "set -eu
$(prelude)
$2"
}

# ── A. record parser ────────────────────────────────────────────────
rec() { printf '%s\n' "$@" > "${T}/rec"; }
parse() { run_sh sh "hippius_golden_parse_release '${T}/rec'"; }
good=(version=3 security_epoch=2 "commit=${COMMIT}" "squashfs_sha256=${SHA_A}"
      enable=hippius-keepalive.service:multi-user.target retire=hippius-old.service)
rec "${good[@]}"
want="$(printf 'version 3\nsecurity_epoch 2\ncommit %s\nsquashfs_sha256 %s\nenable hippius-keepalive.service multi-user.target\nretire hippius-old.service' "${COMMIT}" "${SHA_A}")"
got="$(parse)" || err "a valid record was refused"
[[ "${got}" == "${want}" ]] || err "parser output: '${got}'"
ok "a valid record parses to its normalised form"
rec "# comment" "" "${good[@]}"
parse >/dev/null || err "comments/blank lines refused"
rec "${good[@]}" health_mask=15
got="$(parse)" || err "a record with health_mask was refused"
[[ "${got}" == "${want}" ]] || err "health_mask changed the parser output: '${got}'"
ok "health_mask is accepted and not part of what the boot uses"
bad_cases=(
    "missing version|security_epoch=1 commit=${COMMIT} squashfs_sha256=${SHA_A}"
    "missing epoch|version=1 commit=${COMMIT} squashfs_sha256=${SHA_A}"
    "missing commit|version=1 security_epoch=1 squashfs_sha256=${SHA_A}"
    "missing sha|version=1 security_epoch=1 commit=${COMMIT}"
    "repeated version|version=1 version=2 security_epoch=1 commit=${COMMIT} squashfs_sha256=${SHA_A}"
    "short commit|version=1 security_epoch=1 commit=abc squashfs_sha256=${SHA_A}"
    "uppercase sha|version=1 security_epoch=1 commit=${COMMIT} squashfs_sha256=$(printf 'A%.0s' $(seq 64))"
    "non-numeric version|version=1a security_epoch=1 commit=${COMMIT} squashfs_sha256=${SHA_A}"
    "unknown key|version=1 security_epoch=1 commit=${COMMIT} squashfs_sha256=${SHA_A} path=/x"
    "non-numeric health_mask|version=1 security_epoch=1 commit=${COMMIT} squashfs_sha256=${SHA_A} health_mask=0xf"
    "repeated health_mask|version=1 security_epoch=1 commit=${COMMIT} squashfs_sha256=${SHA_A} health_mask=15 health_mask=15"
    "line without =|version=1 security_epoch=1 commit=${COMMIT} squashfs_sha256=${SHA_A} enable"
    "enable without target|version=1 security_epoch=1 commit=${COMMIT} squashfs_sha256=${SHA_A} enable=a.service"
    "enable target not a target|version=1 security_epoch=1 commit=${COMMIT} squashfs_sha256=${SHA_A} enable=a.service:b.service"
    "enable a target|version=1 security_epoch=1 commit=${COMMIT} squashfs_sha256=${SHA_A} enable=a.target:multi-user.target"
    "unit with a slash|version=1 security_epoch=1 commit=${COMMIT} squashfs_sha256=${SHA_A} enable=../x.service:multi-user.target"
    "dot unit|version=1 security_epoch=1 commit=${COMMIT} squashfs_sha256=${SHA_A} retire=.service"
    "unit without suffix|version=1 security_epoch=1 commit=${COMMIT} squashfs_sha256=${SHA_A} retire=sshd"
    "glob unit|version=1 security_epoch=1 commit=${COMMIT} squashfs_sha256=${SHA_A} retire=*.service"
)
for c in "${bad_cases[@]}"; do
    # shellcheck disable=SC2086  # split the case's lines on purpose
    rec ${c#*|}
    if parse >/dev/null 2>&1; then err "parser accepted: ${c%%|*}"; fi
done
ok "the parser refuses ${#bad_cases[@]} malformed records"

# ── B. boot step ────────────────────────────────────────────────────
# A fake busybox: cp/sha256sum/umount forward to the host tools, `mount`
# copies the image's source tree (FAKE_IMAGE_TREE) to the mountpoint, or
# fails when FAKE_MOUNT_FAIL=1.
make_fake_bb() {
    cat > "$1" <<'BB'
#!/bin/sh
applet="$1"; shift
case "${applet}" in
    cp) exec cp "$@" ;;
    sha256sum) exec sha256sum "$@" ;;
    umount) exit 0 ;;
    mount)
        [ "${FAKE_MOUNT_FAIL:-0}" = 1 ] && exit 1
        for last; do :; done
        printf '%s\n' "$*" > "${FAKE_MOUNT_LOG}"
        cp -R "${FAKE_IMAGE_TREE}/." "${last}/"
        ;;
    *) exit 127 ;;
esac
BB
    chmod 0755 "$1"
}
# A case: fresh root, release dir, run dir, image tree.
new_case() {
    C="${T}/case-$1"
    mkdir -p "${C}/root/etc/systemd/system/multi-user.target.wants" "${C}/rel" "${C}/run" \
             "${C}/tree/units" "${C}/lower"
    for u in hippius-keepalive.service hippius-eol-sign.service; do
        printf '[Unit]\n' > "${C}/tree/units/${u}"
    done
    printf 'image-bytes-%s\n' "$1" > "${C}/rel/components.squashfs"
    make_fake_bb "${C}/rel/busybox"
    : > "${T}/log"
}
write_record() {
    # write_record <sha> [extra lines...]
    local sha="$1"; shift
    printf '%s\n' version=7 security_epoch=2 "commit=${COMMIT}" "squashfs_sha256=${sha}" \
        enable=hippius-keepalive.service:multi-user.target \
        enable=hippius-eol-sign.service:multi-user.target "$@" > "${C}/rel/release"
}
boot() {
    # boot [shell]
    FAKE_IMAGE_TREE="${C}/tree" FAKE_MOUNT_LOG="${C}/mountlog" \
        run_sh "${1:-sh}" "HIPPIUS_GOLDEN_LOWER_MNT='${C}/lower'
_hippius_golden_components_run '${C}/root' '${C}/rel' '${C}/run'"
}
img_sha() { sha256sum "${C}/rel/components.squashfs" | cut -d' ' -f1; }
link_is() { [[ -L "$1" && "$(readlink "$1")" == "$2" ]]; }

# B1. No record: nothing written, nothing mounted.
new_case norec
printf 'base unit\n' > "${C}/root/etc/systemd/system/hippius-keepalive.service"
boot || err "no-record boot failed"
[[ "$(cat "${C}/root/etc/systemd/system/hippius-keepalive.service")" == "base unit" ]] \
    || err "no-record boot touched the base unit"
[[ ! -e "${C}/run/guest-components" && ! -e "${C}/mountlog" ]] || err "no-record boot mounted or reported"
grep -q "no release in this initrd" "${T}/log" || err "no-record boot did not say so"
ok "no record: strict no-op (base units untouched, nothing mounted)"

# B2. Happy path: mounted, links over the base's units, .wants links,
# status file, mount options.
new_case happy
printf 'base unit\n' > "${C}/root/etc/systemd/system/hippius-keepalive.service"
mkdir -p "${C}/root/etc/systemd/system/hippius-eol-sign.service"   # a tenant dir in the way
write_record "$(img_sha)" retire=hippius-old.service
boot || err "happy boot failed: $(cat "${T}/log")"
S="${C}/root/etc/systemd/system"
link_is "${S}/hippius-keepalive.service" /run/hippius/guest/units/hippius-keepalive.service \
    || err "keepalive unit not linked into the image"
link_is "${S}/hippius-eol-sign.service" /run/hippius/guest/units/hippius-eol-sign.service \
    || err "a directory at the unit path was not replaced by the link"
link_is "${S}/multi-user.target.wants/hippius-keepalive.service" ../hippius-keepalive.service \
    || err "keepalive .wants link missing"
link_is "${S}/multi-user.target.wants/hippius-eol-sign.service" ../hippius-eol-sign.service \
    || err "eol .wants link missing"
link_is "${S}/hippius-old.service" /dev/null || err "retired unit not masked"
grep -q 'mounted=yes' "${C}/run/guest-components" || err "status does not say mounted"
grep -q 'version=7' "${C}/run/guest-components" || err "status lacks the version"
grep -q -- '-t squashfs -o ro,nosuid,nodev,loop' "${C}/mountlog" || err "mount options: $(cat "${C}/mountlog")"
grep -q "${C}/run/guest.squashfs ${C}/run/guest" "${C}/mountlog" \
    || err "the image was not mounted from its RAM copy"
[[ -f "${C}/run/guest/units/hippius-keepalive.service" ]] || err "image content not at the mountpoint"
ok "record: image mounted from its /run copy, units linked over the base's, .wants + retire masks"

# B3. Idempotent: a second boot over the same root gives the same tree.
before="$(cd "${C}/root" && find . -printf '%p %y %l\n' | sort)"
rm -r "${C}/run"; mkdir -p "${C}/run"
boot || err "second boot failed"
after="$(cd "${C}/root" && find . -printf '%p %y %l\n' | sort)"
[[ "${before}" == "${after}" ]] || err "second boot changed the root"
ok "a second boot leaves the same tree"

# B4. Image sha mismatch: NOT mounted, links still written, WARN.
new_case badsha
printf 'base unit\n' > "${C}/root/etc/systemd/system/hippius-keepalive.service"
write_record "${SHA_A}"
boot || err "bad-sha boot died (must boot without agents)"
link_is "${C}/root/etc/systemd/system/hippius-keepalive.service" /run/hippius/guest/units/hippius-keepalive.service \
    || err "bad sha: the base unit was left in place (old agent would run)"
[[ ! -e "${C}/mountlog" ]] || err "bad sha: the image was mounted anyway"
[[ ! -e "${C}/run/guest.squashfs" ]] || err "bad sha: the rejected copy was left in /run"
grep -q 'mounted=no' "${C}/run/guest-components" || err "bad sha: status says mounted"
grep -q 'sha256 mismatch' "${T}/log" || err "bad sha: no WARN"
ok "image sha mismatch: not mounted, links still written (no agent, never the base's)"

# B5. Mount fails / image missing / busybox missing: same outcome.
for what in mount image busybox; do
    new_case "miss-${what}"
    write_record "$(img_sha)"
    case "${what}" in
        mount) export FAKE_MOUNT_FAIL=1 ;;
        image) rm "${C}/rel/components.squashfs" ;;
        busybox) rm "${C}/rel/busybox" ;;
    esac
    boot || err "${what} missing: boot died"
    unset FAKE_MOUNT_FAIL
    link_is "${C}/root/etc/systemd/system/hippius-keepalive.service" /run/hippius/guest/units/hippius-keepalive.service \
        || err "${what} missing: unit not linked"
    grep -q 'mounted=no' "${C}/run/guest-components" || err "${what} missing: status says mounted"
done
ok "mount failure, missing image, missing busybox: boot goes on, links written, nothing mounted"

# B6. An image without units/ is not used.
new_case nounits
rm -r "${C}/tree/units"; mkdir -p "${C}/tree/bin"
write_record "$(img_sha)"
boot || err "no-units boot died"
grep -q 'mounted=no' "${C}/run/guest-components" || err "an image without units/ counted as mounted"
ok "an image without units/ is unmounted and reported"

# B7. Fail-closed: a malformed record, an unwritable unit dir.
new_case malformed
printf 'version=1\n' > "${C}/rel/release"
set +e; boot; rc=$?; set -e
[[ ${rc} -eq 42 ]] || err "malformed record did not fail closed (rc=${rc})"
new_case rofs
write_record "$(img_sha)"
chmod 0555 "${C}/root/etc/systemd/system"
set +e; boot; rc=$?; set -e
chmod 0755 "${C}/root/etc/systemd/system"
[[ ${rc} -eq 42 ]] || err "an unwritable unit dir did not fail closed (rc=${rc})"
ok "fail-closed: malformed record, unit links that cannot be written"

# B8. SELinux base: links take the label of their directory, strictly.
selinux_stubs() {
    # getfattr/setfattr over a label table (`<path> <label>` lines, last
    # wins). FAKE_SETFATTR_FAIL=1: setfattr fails; FAKE_SETFATTR_NOOP=1:
    # it "succeeds" without effect.
    cat <<EOF
LABELS='${T}/labels'
getfattr() {
    for _p; do :; done
    _v="\$(grep -F "\${_p} " "\${LABELS}" | tail -n1 | cut -d' ' -f2)"
    [ -n "\${_v}" ] || return 1
    printf '%s' "\${_v}"
}
setfattr() {
    [ "\${FAKE_SETFATTR_FAIL:-0}" = 1 ] && return 1
    [ "\${FAKE_SETFATTR_NOOP:-0}" = 1 ] && return 0
    _v=""; _prev=""
    for _a; do [ "\${_prev}" = -v ] && _v="\${_a}"; _prev="\${_a}"; done
    printf '%s %s\n' "\${_a}" "\${_v}" >> "\${LABELS}"
}
EOF
}
boot_selinux() {
    # boot_selinux [VAR=value...]: extra environment for the boot.
    env FAKE_IMAGE_TREE="${C}/tree" FAKE_MOUNT_LOG="${C}/mountlog" "$@" \
        sh -c "set -eu
$(prelude)
$(selinux_stubs)
HIPPIUS_GOLDEN_LOWER_MNT='${C}/lower'
_hippius_golden_components_run '${C}/root' '${C}/rel' '${C}/run'"
}
UNIT_CTX="system_u:object_r:systemd_unit_file_t:s0"
selinux_case() {
    new_case "$1"
    mkdir -p "${C}/lower/etc/selinux" "${C}/lower/etc/systemd/system"
    : > "${C}/lower/etc/selinux/config"
    write_record "$(img_sha)"
    S="${C}/root/etc/systemd/system"
    L="${C}/lower/etc/systemd/system"
}
selinux_case selinux
# The upper's own labels are forged: they must not be copied.
printf '%s %s\n' "${L}" "${UNIT_CTX}" "${S}" "system_u:object_r:tmp_t:s0" \
    "${S}/multi-user.target.wants" "system_u:object_r:tmp_t:s0" > "${T}/labels"
boot_selinux || err "SELinux boot failed: $(cat "${T}/log")"
label_of() { grep -F "$1 " "${T}/labels" | tail -n1 | cut -d' ' -f2; }
for p in "${S}" "${S}/multi-user.target.wants" "${S}/hippius-keepalive.service" \
         "${S}/multi-user.target.wants/hippius-keepalive.service"; do
    [[ "$(label_of "${p}")" == "${UNIT_CTX}" ]] || err "SELinux: ${p#"${C}"/} labelled '$(label_of "${p}")', want the lower's"
done
for mode in FAIL NOOP; do
    selinux_case "selinux-${mode}"
    printf '%s %s\n' "${L}" "${UNIT_CTX}" > "${T}/labels"
    set +e; boot_selinux "FAKE_SETFATTR_${mode}=1"; rc=$?; set -e
    [[ ${rc} -eq 42 ]] || err "SELinux: setfattr ${mode} did not fail closed (rc=${rc})"
done
selinux_case selinux-noref
printf '%s %s\n' "${S}" "${UNIT_CTX}" > "${T}/labels"   # only the UPPER has one
set +e; boot_selinux; rc=$?; set -e
[[ ${rc} -eq 42 ]] || err "SELinux: an unlabelled LOWER unit dir did not fail closed (rc=${rc})"
ok "SELinux base: links + unit dirs get the LOWER's label (forged upper labels ignored); a label that does not take is fatal"

# B8b. Symlinked parents in the upper are never followed: they would
# resolve against the initramfs, outside the guest root.
for which in etc etc/systemd etc/systemd/system; do
    new_case "symlink-${which//\//-}"
    write_record "$(img_sha)"
    outside="${C}/outside"
    mkdir -p "${outside}/systemd/system" "${outside}/system"
    : > "${outside}/sentinel"
    victim="${C}/root/${which}"
    rm -r "${victim}"
    mkdir -p "$(dirname "${victim}")"
    case "${which}" in
        etc) ln -s "${outside}" "${victim}" ;;
        etc/systemd) ln -s "${outside}" "${victim}" ;;
        etc/systemd/system) ln -s "${outside}/system" "${victim}" ;;
    esac
    before="$(cd "${outside}" && find . | sort)"
    set +e; boot; rc=$?; set -e
    [[ ${rc} -eq 42 ]] || err "symlinked ${which}: the boot did not fail closed (rc=${rc})"
    [[ "$(cd "${outside}" && find . | sort)" == "${before}" ]] \
        || err "symlinked ${which}: the step wrote outside the guest root"
done
new_case symlink-wants
write_record "$(img_sha)"
mkdir -p "${C}/outside"; : > "${C}/outside/sentinel"
rm -r "${C}/root/etc/systemd/system/multi-user.target.wants"
ln -s "${C}/outside" "${C}/root/etc/systemd/system/multi-user.target.wants"
boot || err "symlinked .wants: boot died"
[[ "$(ls "${C}/outside")" == sentinel ]] || err "symlinked .wants: the step wrote through it"
[[ -d "${C}/root/etc/systemd/system/multi-user.target.wants" && ! -L "${C}/root/etc/systemd/system/multi-user.target.wants" ]] \
    || err "symlinked .wants: not replaced by a real directory"
link_is "${C}/root/etc/systemd/system/multi-user.target.wants/hippius-keepalive.service" ../hippius-keepalive.service \
    || err "symlinked .wants: no .wants link"
ok "symlinked /etc, /etc/systemd, /etc/systemd/system: never followed, the boot fails closed; a symlinked .wants is replaced"

# B9. Wired into the golden boot: after the M0 hardening, before the
# boot hands control back for switch_root.
run_body="$(sed -n '/^hippius_golden_run() {/,/^}/p' "${LIB}")"
harden_at="$(grep -n 'hippius_golden_harden_root "${_hgrun_rootmnt}"' <<<"${run_body}" | cut -d: -f1)"
step_at="$(grep -n 'hippius_golden_mount_components "${_hgrun_rootmnt}"' <<<"${run_body}" | cut -d: -f1)"
done_at="$(grep -n 'boot assembled' <<<"${run_body}" | cut -d: -f1)"
[[ -n "${harden_at}" && -n "${step_at}" && -n "${done_at}" ]] \
    && (( harden_at < step_at && step_at < done_at )) \
    || err "hippius_golden_run does not call the components step after the M0 hardening"
ok "hippius_golden_run runs the components step after the M0 hardening"

# ── C. the initramfs shells ─────────────────────────────────────────
shells=()
command -v dash >/dev/null 2>&1 && shells+=(dash)
if command -v busybox >/dev/null 2>&1; then
    printf '#!/bin/sh\nexec busybox ash "$@"\n' > "${T}/ash"; chmod +x "${T}/ash"; shells+=("${T}/ash")
fi
for shell in "${shells[@]}"; do
    new_case "shell-$(basename "${shell}")"
    write_record "$(img_sha)" retire=hippius-old.service
    boot "${shell}" || err "${shell}: boot failed: $(cat "${T}/log")"
    link_is "${C}/root/etc/systemd/system/hippius-keepalive.service" /run/hippius/guest/units/hippius-keepalive.service \
        || err "${shell}: unit not linked"
    grep -q 'mounted=yes' "${C}/run/guest-components" || err "${shell}: not mounted"
    rec "${good[@]}"
    [[ "$(run_sh "${shell}" "hippius_golden_parse_release '${T}/rec'")" == "${want}" ]] \
        || err "${shell}: parser output differs"
    ok "boot step + parser under ${shell}"
done
(( ${#shells[@]} == 2 )) || skip "C (initramfs shells) — have: ${shells[*]:-none}"

# ── D. the builder ──────────────────────────────────────────────────
missing=()
for tool in mksquashfs rdsquashfs cpio; do command -v "${tool}" >/dev/null 2>&1 || missing+=("${tool}"); done
STATIC_BB="${GUEST_RELEASE_TEST_STATIC_BUSYBOX:-}"
[[ -n "${STATIC_BB}" ]] || missing+=("GUEST_RELEASE_TEST_STATIC_BUSYBOX")
if (( ${#missing[@]} > 0 )); then
    skip "D (builder) — missing ${missing[*]}"
else
    B="${T}/bins"
    mkdir -p "${B}"
    for b in hippius-agent-keepalive hippius-agent-tenant-telemetry hippius-agent-initramfs \
             hippius-guest-release hippius-vsock-ticket; do
        printf '#!/bin/sh\necho %s --attest-components\n' "${b}" > "${B}/${b}"; chmod 0755 "${B}/${b}"
    done
    build() { "${BUILD}" --bin-dir "${B}" --busybox "${STATIC_BB}" --commit "${COMMIT}" \
        --source-date-epoch 1700000000 --out "$1"; }
    build "${T}/out1" 2>"${T}/build1.err" || err "builder failed: $(tail -3 "${T}/build1.err")"
    build "${T}/out2" 2>"${T}/build2.err" || err "builder failed (2nd run): $(tail -3 "${T}/build2.err")"
    for f in components.squashfs release release-initramfs-tools.cpio release-dracut.cpio \
             release-initramfs-tools.manifest release-dracut.manifest release.json; do
        cmp -s "${T}/out1/${f}" "${T}/out2/${f}" || err "builder not reproducible: ${f}"
    done
    ok "builder: two runs, same bytes"

    # The health leg: declared in release.conf, carried into release.json,
    # and switched on in keepalive.env — a mismatch is refused.
    [[ "$(sed -n 's/^health_mask=//p' "${T}/out1/release")" == 15 ]] || err "record health_mask"
    grep -q '"health_mask": 15,' "${T}/out1/release.json" || err "release.json health_mask"
    cp -r "${HERE}/../guest/components" "${T}/comp-noswitch"
    sed -i '/^HIPPIUS_KEEPALIVE_ATTEST_COMPONENTS=/d' "${T}/comp-noswitch/etc/keepalive.env"
    if HIPPIUS_GUEST_COMPONENTS_DIR="${T}/comp-noswitch" build "${T}/out-noswitch" 2>"${T}/b.err"; then
        err "the builder accepted a health_mask without the keepalive switch"
    fi
    cp -r "${HERE}/../guest/components" "${T}/comp-nomask"
    sed -i '/^health_mask=/d' "${T}/comp-nomask/release.conf"
    if HIPPIUS_GUEST_COMPONENTS_DIR="${T}/comp-nomask" build "${T}/out-nomask" 2>"${T}/b.err"; then
        err "the builder accepted the keepalive switch without a health_mask"
    fi
    cp -r "${B}" "${T}/bins-old"
    printf '#!/bin/sh\necho hippius-agent-keepalive\n' > "${T}/bins-old/hippius-agent-keepalive"
    if "${BUILD}" --bin-dir "${T}/bins-old" --busybox "${STATIC_BB}" --commit "${COMMIT}" \
        --source-date-epoch 1700000000 --out "${T}/out-old" 2>"${T}/b.err"; then
        err "the builder shipped a keepalive that does not know --attest-components"
    fi
    ok "builder: health_mask and the keepalive switch must agree"

    # The record it writes is one the boot step accepts and mounts.
    new_case built
    cp "${T}/out1/release" "${C}/rel/release"
    cp "${T}/out1/components.squashfs" "${C}/rel/components.squashfs"
    boot || err "the boot step refused the builder's record: $(cat "${T}/log")"
    grep -q 'mounted=yes' "${C}/run/guest-components" || err "the builder's image did not pass the sha check"
    for u in hippius-keepalive.service hippius-tenant-telemetry.service hippius-eol-sign.service; do
        link_is "${C}/root/etc/systemd/system/${u}" "/run/hippius/guest/units/${u}" \
            || err "the builder's record does not enable ${u}"
    done
    ok "builder: its record is accepted by the boot step and enables the three units"

    # Member contents: exactly the expected leaves + the one new dir.
    want_common="lib/hippius/guest
lib/hippius/guest/busybox
lib/hippius/guest/components.squashfs
lib/hippius/guest/release
lib/hippius/hippius-golden-overlay.sh
lib/hippius/hippius-release-core.sh"
    want_it="${want_common}
scripts/hippius-golden
scripts/init-bottom/hippius-net-teardown
usr/sbin/hippius-guest-release
usr/sbin/hippius-vsock-ticket"
    want_dr="${want_common}
sbin/hippius-golden-mount
sbin/hippius-net-teardown
usr/lib/systemd/system/hippius-golden-mount.service
usr/lib/systemd/system/hippius-net-teardown.service
usr/sbin/hippius-guest-release
usr/sbin/hippius-vsock-ticket"
    [[ "$(cpio --quiet -it < "${T}/out1/release-initramfs-tools.cpio" | sort)" == "$(sort <<<"${want_it}")" ]] \
        || err "initramfs-tools member entries: $(cpio --quiet -it < "${T}/out1/release-initramfs-tools.cpio")"
    [[ "$(cpio --quiet -it < "${T}/out1/release-dracut.cpio" | sort)" == "$(sort <<<"${want_dr}")" ]] \
        || err "dracut member entries: $(cpio --quiet -it < "${T}/out1/release-dracut.cpio")"
    # The member's overlay library is THIS one, byte for byte.
    (cd "${T}" && mkdir -p x && cd x && cpio --quiet -id lib/hippius/hippius-golden-overlay.sh \
        < "${T}/out1/release-initramfs-tools.cpio")
    cmp -s "${T}/x/lib/hippius/hippius-golden-overlay.sh" "${LIB}" || err "member carries another overlay library"
    # Owner root, fixed mtime (newc header fields), 4-byte aligned size.
    python3 - "${T}/out1/release-initramfs-tools.cpio" "${T}/out1/release-dracut.cpio" <<'PY' || err "cpio headers"
import sys
for path in sys.argv[1:]:
    data = open(path, "rb").read()
    assert len(data) % 4 == 0, "member length not 4-aligned"
    off = 0
    while True:
        h = data[off:off + 110]
        assert h[:6] == b"070701", "not newc"
        f = [int(h[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
        mode, uid, gid, mtime, size, namesize = f[1], f[2], f[3], f[5], f[6], f[11]
        name = data[off + 110:off + 110 + namesize - 1].decode()
        if name == "TRAILER!!!":
            break
        assert uid == 0 and gid == 0, f"{name}: uid/gid {uid}/{gid}"
        assert mtime == 1700000000, f"{name}: mtime {mtime}"
        off = (off + 110 + namesize + 3) & ~3
        off = (off + size + 3) & ~3
PY
    ok "builder: members carry only the expected entries, root-owned, fixed mtime, 4-aligned"

    # Every image entry labelled (the builder checks it too; check here
    # from the outside).
    while read -r p; do
        l="$(rdsquashfs -x "${p}" "${T}/out1/components.squashfs" | sed -n 's/^security\.selinux=//p')"
        [[ -n "${l}" ]] || err "image entry ${p} is unlabelled"
    done < <(printf '/\n/bin\n/units\n/etc\n/bin/hippius-agent-keepalive\n/units/hippius-eol-sign.service\n/etc/keepalive.env\n')
    [[ "$(rdsquashfs -x /bin/hippius-agent-keepalive "${T}/out1/components.squashfs")" == "security.selinux=system_u:object_r:bin_t:s0" ]] \
        || err "agent label"
    ok "builder: image entries carry their SELinux labels"

    # Refusals.
    refuse() {
        local what="$1"; shift
        set +e; "$@" >/dev/null 2>&1; local rc=$?; set -e
        [[ ${rc} -ne 0 ]] || err "builder accepted: ${what}"
    }
    refuse "a dynamic busybox" "${BUILD}" --bin-dir "${B}" --busybox "$(command -v sh)" \
        --commit "${COMMIT}" --source-date-epoch 1 --out "${T}/r1"
    mv "${B}/hippius-agent-keepalive" "${T}/ka"
    refuse "a missing agent" "${BUILD}" --bin-dir "${B}" --busybox "${STATIC_BB}" \
        --commit "${COMMIT}" --source-date-epoch 1 --out "${T}/r2"
    mv "${T}/ka" "${B}/hippius-agent-keepalive"
    refuse "a short commit" "${BUILD}" --bin-dir "${B}" --busybox "${STATIC_BB}" \
        --commit abc --source-date-epoch 1 --out "${T}/r3"
    mkdir -p "${T}/r4"; : > "${T}/r4/x"
    refuse "a non-empty --out" "${BUILD}" --bin-dir "${B}" --busybox "${STATIC_BB}" \
        --commit "${COMMIT}" --source-date-epoch 1 --out "${T}/r4"
    ok "builder: refuses a dynamic busybox, a missing agent, a bad commit, a non-empty --out"

    # ── F. appended to a base initrd: the merged-tree check ───────────
    # Fixture base initrds shaped like the real ones (an uncompressed early
    # member, then one compressed member; usrmerge symlinks), the release
    # appended, unpacked with the kernel's rules by initrd-merge-check.py.
    CHECK="${REPO}/scripts/guest/initrd-merge-check.py"
    # shellcheck source=scripts/dev/guest-initrd-fixtures.sh
    . "${HERE}/guest-initrd-fixtures.sh"
    merge_ok() {
        # merge_ok <family> <base> <out>
        python3 "${CHECK}" --base "$2" --release "${T}/out1/release-$1.cpio" \
            --manifest "${T}/out1/release-$1.manifest" --out "$3" >/dev/null 2>"${T}/merge.err"
    }
    merge_refused() {
        # merge_refused <what> <family> <base> <pattern>: refused, saying <pattern>
        set +e; merge_ok "$2" "$3" "${T}/never"; local rc=$?; set -e
        if [[ ${rc} -ne 3 ]]; then
            err "merge check accepted: $1 (rc=${rc})"
        elif ! grep -q -- "$4" "${T}/merge.err"; then
            err "merge check refused $1 for another reason: $(cat "${T}/merge.err")"
        fi
        [[ ! -e "${T}/never" ]] || err "merge check wrote an initrd it refused ($1)"
    }
    # The unpack emulation itself, against init/initramfs.c's rules.
    PYTHONDONTWRITEBYTECODE=1 python3 - "${CHECK}" <<'PYEMU' || err "initramfs unpack emulation"
import importlib.util, sys
spec = importlib.util.spec_from_file_location("mc", sys.argv[1])
mc = importlib.util.module_from_spec(spec); sys.modules["mc"] = mc; spec.loader.exec_module(mc)
D, F, L = mc.S_IFDIR | 0o755, mc.S_IFREG | 0o644, mc.S_IFLNK | 0o777
E = mc.Entry
t = mc.Tree()
for e in [E("usr", D, b""), E("usr/lib", D, b""), E("lib", L, b"usr/lib"),
          E("usr/lib/x", D, b""), E("usr/lib/x/f", F, b"1"), E("s", L, b"a")]:
    t.apply(e)
# A file entry through an intermediate usrmerge symlink lands in usr/lib.
assert t.apply(E("lib/x/g", F, b"2")) == "usr/lib/x/g"
# A symlink entry replaces an existing symlink; a non-empty dir stays.
t.apply(E("s", L, b"b")); assert t.nodes["s"].target == "b", "symlink not replaced"
assert t.apply(E("usr/lib/x", L, b"y")) == "", "symlink over a non-empty dir was created"
# A file entry over a NON-empty directory is dropped (rmdir fails).
assert t.apply(E("usr/lib/x", F, b"3")) == "", "file over a non-empty dir was created"
assert t.nodes["usr/lib/x"].kind == "dir"
# Hard links share an inode within one archive; a later same-type write
# rewrites both names; the link table is forgotten at the trailer.
k = (0, 0, 42)
t.apply(E("usr/lib/x/h1", F, b"", 2, k)); t.apply(E("usr/lib/x/h2", F, b"same", 2, k))
assert t.nodes["usr/lib/x/h1"].inode is t.nodes["usr/lib/x/h2"].inode
assert t.aliases("usr/lib/x/h1") == ["usr/lib/x/h2"]
t.apply(E("usr/lib/x/h1", F, b"new"))
assert t.nodes["usr/lib/x/h2"].inode.sha256 == t.nodes["usr/lib/x/h1"].inode.sha256
t.apply(E(mc.TRAILER, 0, b"")); assert not t.links
t.apply(E("usr/lib/x/h3", F, b"other", 2, k))
assert t.nodes["usr/lib/x/h3"].inode is not t.nodes["usr/lib/x/h1"].inode, "link table survived the trailer"
# A directory entry for a usrmerge parent replaces the symlink: the hazard
# the release's leaf-only rule exists for.
t.apply(E("lib", D, b"")); assert t.nodes["lib"].kind == "dir"
assert t.resolve_dir("lib/x") is None, "lib/x must be gone once lib is a real dir"
PYEMU
    ok "unpack emulation: intermediate symlinks, symlink replacement, rmdir of a non-empty dir, hard links, the usrmerge hazard"
    comps=(gzip)
    command -v zstd >/dev/null 2>&1 && comps+=(zstd)
    for family in initramfs-tools dracut; do
        for comp in "${comps[@]}"; do
            tree="${T}/base-${family}-${comp}"
            mktree "${tree}" "${family}"
            mkbase "${tree}" "${T}/base-${family}-${comp}.img" "${comp}"
            merge_ok "${family}" "${T}/base-${family}-${comp}.img" "${T}/merged-${family}-${comp}.img" \
                || err "${family}/${comp}: merge refused: $(cat "${T}/merge.err")"
            base_len="$(stat -c %s "${T}/base-${family}-${comp}.img")"
            pad=$(( (4 - base_len % 4) % 4 ))
            cmp -s <(head -c "${base_len}" "${T}/merged-${family}-${comp}.img") "${T}/base-${family}-${comp}.img" \
                || err "${family}/${comp}: merged initrd does not start with the base"
            [[ "$(tail -c +$((base_len + 1)) "${T}/merged-${family}-${comp}.img" | head -c "${pad}" | tr -d '\0' | wc -c)" -eq 0 ]] \
                || err "${family}/${comp}: padding is not zeros"
            cmp -s <(tail -c +$((base_len + pad + 1)) "${T}/merged-${family}-${comp}.img") "${T}/out1/release-${family}.cpio" \
                || err "${family}/${comp}: merged initrd does not end with the release member"
        done
    done
    ok "merge check: the release appended to usrmerged ${comps[*]} bases of both families lands as its manifest says"

    # Refusals, each on an otherwise good initramfs-tools / dracut base.
    refusal_case() {
        # refusal_case <name> <family> <mutation…>: fresh tree, mutated.
        local tree="${T}/neg-$1"
        mktree "${tree}" "$2"
        (cd "${tree}" && eval "$3")
        mkbase "${tree}" "${T}/neg-$1.img"
    }
    refusal_case guest-file initramfs-tools 'printf x > usr/lib/hippius/guest'
    merge_refused "a base where lib/hippius/guest is a file" initramfs-tools "${T}/neg-guest-file.img" "directory entry over an existing file"
    refusal_case no-hippius-dir initramfs-tools 'rm -r usr/lib/hippius'
    merge_refused "a base without lib/hippius/" initramfs-tools "${T}/neg-no-hippius-dir.img" "parent is not a directory"
    refusal_case boot-is-dir initramfs-tools 'rm scripts/hippius-golden; mkdir -p scripts/hippius-golden/x'
    merge_refused "a base where the boot script is a directory" initramfs-tools "${T}/neg-boot-is-dir.img" "replaces a dir with a file"
    refusal_case no-readlink initramfs-tools 'rm usr/bin/readlink'
    merge_refused "a base without readlink" initramfs-tools "${T}/neg-no-readlink.img" "command readlink"
    refusal_case noexec-readlink initramfs-tools 'chmod 0644 usr/bin/readlink'
    merge_refused "a base whose readlink is not executable" initramfs-tools "${T}/neg-noexec-readlink.img" "command readlink"
    refusal_case old-hook dracut 'printf changed > usr/lib/dracut/hooks/cmdline/30-parse-hippius-golden.sh'
    merge_refused "a dracut base whose cmdline hook differs" dracut "${T}/neg-old-hook.img" "expected base file"
    refusal_case no-link dracut 'rm etc/systemd/system/initrd-root-fs.target.requires/hippius-golden-mount.service'
    merge_refused "a dracut base without the mount unit's .requires link" dracut "${T}/neg-no-link.img" "expected base link"
    refusal_case no-getfattr dracut 'rm usr/bin/getfattr'
    merge_refused "a dracut base without getfattr" dracut "${T}/neg-no-getfattr.img" "command getfattr"
    # A base with no compressed member is not a distro initrd.
    mkdir -p "${T}/flat/usr/lib/hippius"
    (cd "${T}/flat" && find . | sort | cpio --quiet -o -H newc -R 0:0) > "${T}/neg-flat.img"
    merge_refused "an uncompressed-only base" initramfs-tools "${T}/neg-flat.img" "no compressed member"
    # A release member that does not match its manifest.
    cp "${T}/out1/release-initramfs-tools.cpio" "${T}/tampered.cpio"
    python3 - "${T}/tampered.cpio" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
i = b.find(b"old") if b.find(b"old") >= 0 else b.find(b"hippius_golden_run")
b[i] ^= 0x20
open(p, "wb").write(bytes(b))
PY
    set +e
    python3 "${CHECK}" --base "${T}/base-initramfs-tools-gzip.img" --release "${T}/tampered.cpio" \
        --manifest "${T}/out1/release-initramfs-tools.manifest" >/dev/null 2>"${T}/merge.err"
    rc=$?
    set -e
    [[ ${rc} -eq 3 ]] && grep -q "content differs" "${T}/merge.err" \
        || err "merge check accepted a member that does not match its manifest: $(cat "${T}/merge.err")"
    # A base whose files sit in TWO compressed members (gzip then xz): the
    # second must be read too (readlink lives only there).
    tree="${T}/two-members"
    mktree "${tree}" initramfs-tools
    mkdir -p "${T}/two-members-b/usr/bin"
    mv "${tree}/usr/bin/readlink" "${T}/two-members-b/usr/bin/readlink"
    mkbase "${tree}" "${T}/two-members.img"
    (cd "${T}/two-members-b" && find . | sort | cpio --quiet -o -H newc -R 0:0 | xz -9 --check=crc32) \
        >> "${T}/two-members.img"
    merge_ok initramfs-tools "${T}/two-members.img" "${T}/two-members-merged.img" \
        || err "a gzip+xz base was refused: $(cat "${T}/merge.err")"
    # An uncompressed member followed by a compressed one at an unaligned
    # offset: the kernel stops on "broken padding".
    mktree "${T}/misaligned" initramfs-tools
    early="${T}/misaligned-early"; mkdir -p "${early}/kernel"; printf 'u' > "${early}/kernel/u"
    (cd "${early}" && find . | sort | cpio --quiet -o -H newc -R 0:0) > "${T}/misaligned.img"
    printf '\0\0' >> "${T}/misaligned.img"
    (cd "${T}/misaligned" && find . | sort | cpio --quiet -o -H newc -R 0:0 | gzip -9n) >> "${T}/misaligned.img"
    merge_refused "a compressed member at an unaligned offset" initramfs-tools "${T}/misaligned.img" "broken padding"
    # A base where a file the release overwrites is hard-linked elsewhere:
    # the kernel would rewrite the other name too.
    refusal_case hardlink initramfs-tools 'ln usr/sbin/hippius-guest-release usr/bin/other-tool'
    merge_refused "a base hard link on a release path" initramfs-tools "${T}/neg-hardlink.img" "hard-linked"
    ok "merge check: reads every compressed member; refuses broken padding, a base hard link on a release path, type changes, a missing parent, a missing command, a changed dracut hook, a missing enablement link, an uncompressed base, a tampered member"
fi

# ── E. the release units = the bake's units, paths aside ────────────
# The release's units replace the ones the bake installs into the base, so
# every directive but the ones naming a path must stay the bake's (the
# ordering edges took incidents to get right: #1322).
directives() {
    grep -vE '^[[:space:]]*(#|$)' \
        | grep -vE '^(ExecStart|ExecStop|EnvironmentFile|Environment|RequiresMountsFor)=' \
        | sort
}
BAKE="${REPO}/scripts/tenant-image-bake.sh"
for pair in hippius-keepalive.service:KEEPALIVEUNIT_EOF \
            hippius-tenant-telemetry.service:TELEMUNIT_EOF \
            hippius-eol-sign.service:EOLUNIT_EOF; do
    unit="${pair%%:*}"; tag="${pair#*:}"
    bake_unit="$(sed -n "/<<'${tag}'\$/,/^${tag}\$/p" "${BAKE}" | sed '1d;$d')"
    [[ -n "${bake_unit}" ]] || { err "could not extract ${unit} from the bake (${tag})"; continue; }
    if [[ "$(directives <<<"${bake_unit}")" != "$(directives < "${REPO}/scripts/guest/components/units/${unit}")" ]]; then
        err "${unit}: directives differ from the bake's: $(diff <(directives <<<"${bake_unit}") <(directives < "${REPO}/scripts/guest/components/units/${unit}") | tr '\n' ' ')"
    fi
    for p in $(grep -hoE '/run/hippius/guest/[A-Za-z0-9/._-]+' "${REPO}/scripts/guest/components/units/${unit}"); do
        rel="${p#/run/hippius/guest/}"
        case "${rel}" in
            bin/hippius-keepalive-start) src="${REPO}/scripts/guest/hippius-keepalive-start" ;;
            bin/*) src="" ;;  # an agent from --bin-dir
            *) src="${REPO}/scripts/guest/components/${rel}" ;;
        esac
        [[ -z "${src}" || -e "${src}" ]] || err "${unit} names ${p}, which the release does not ship"
    done
done
# Each unit runs from the image, so each must order itself after its mount
# (and the eol unit's ExecStop BEFORE its unmount at shutdown): exactly one
# RequiresMountsFor=/run/hippius/guest — the line the comparison above
# leaves out.
for u in "${REPO}"/scripts/guest/components/units/*.service; do
    [[ "$(grep -c '^RequiresMountsFor=/run/hippius/guest$' "${u}")" -eq 1 ]] \
        || err "$(basename "${u}"): needs exactly one RequiresMountsFor=/run/hippius/guest"
    if grep -E '^(ExecStart|ExecStop|ExecStartPre|ExecStopPost)=' "${u}" | grep -vqE '=/run/hippius/guest/|=/bin/true$'; then
        err "$(basename "${u}"): runs something from outside the image"
    fi
done
ok "release units: same directives as the bake's, paths into the image only, ordered on the image mount"

if [[ ${fail} -ne 0 ]]; then
    echo "guest-release-test: FAILED" >&2
    exit 1
fi
echo "guest-release-test: all passed"

