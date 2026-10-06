#!/usr/bin/env bash
# Unit test for the kernel-hold logic inside the apt chroot heredoc of
# `scripts/tenant-image-bake.sh` (the production tenant-image bake).
#
# WHY this exists: on Debian the base image (genericcloud) PRE-INSTALLS
# linux-image-cloud-amd64 + a concrete -cloud- kernel, and the bake
# installs the FULL linux-image-amd64 on top — two kernels. The hold
# used to name only ${DISTRO_KERNEL_PKG}, behind `|| true`, and
# KVER_PKG was derived on Ubuntu only. So the -cloud- meta-package and
# EVERY concrete kernel version stayed unheld, a tenant `apt upgrade`
# pulled the next linux-image-*-cloud-amd64, and its grub/initramfs
# postinst hooks (which cannot resolve the live dm-crypt root inside a
# CVM) left dpkg half-configured.
#
# HOW: root-free, no chroot, no apt. The chroot script is a QUOTED
# heredoc in the bake (outer values ride env(1)), so the body is lifted
# VERBATIM — no expansion step — and the two kernel-related sections
# are sliced out, the absolute /etc paths rewritten into a temp dir,
# and run with the same env the bake passes (DISTRO_ID,
# DISTRO_KERNEL_PKG) against PATH-shimmed `dpkg-query` / `apt-mark` /
# `apt-get` driven by a fixture "dpkg db". It never restructures the
# bake script: if the section anchors move, the test fails loudly
# rather than silently testing nothing.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BAKE="${HERE}/../tenant-image-bake.sh"
[[ -r "${BAKE}" ]] || { echo "tenant-image-bake-kernel-hold-test: bake script not found at ${BAKE}" >&2; exit 1; }

fail=0
ok()  { echo "tenant-image-bake-kernel-hold-test: OK — $*"; }
err() { echo "tenant-image-bake-kernel-hold-test: FAIL — $*" >&2; fail=1; }

WORK="$(mktemp -d -t hippius-bake-kernel-hold-test.XXXXXX)"
trap 'rm -rf -- "${WORK}"' EXIT

# ── 1. Shims ────────────────────────────────────────────────────────
# Fixture db: one package per line, TAB-separated:
#   <Package>\t<Status>\t<Depends>
SHIM="${WORK}/bin"
mkdir -p "${SHIM}"

# dpkg-query -W -f=FMT PATTERN... — supports ${Package} ${Status}
# ${Depends} and a trailing \n, glob patterns, and the real tool's
# "exit 1 if any pattern matched nothing" (stderr noise included).
cat > "${SHIM}/dpkg-query" <<'SHIM_EOF'
#!/usr/bin/env bash
set -eu
fmt='${Package}\t${Version}\n'
pats=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -W) shift ;;
        -f=*) fmt="${1#-f=}"; shift ;;
        -f) fmt="$2"; shift 2 ;;
        *) pats+=("$1"); shift ;;
    esac
done
rc=0
for pat in "${pats[@]}"; do
    hit=0
    while IFS=$'\t' read -r pkg status depends; do
        [[ -n "${pkg}" ]] || continue
        # shellcheck disable=SC2053
        [[ "${pkg}" == ${pat} ]] || continue
        hit=1
        out="${fmt//\$\{Package\}/${pkg}}"
        out="${out//\$\{Status\}/${status}}"
        out="${out//\$\{Depends\}/${depends}}"
        printf "%b" "${out}"
    done < "${FAKE_DPKG_DB}"
    if [[ ${hit} -eq 0 ]]; then
        echo "dpkg-query: no packages found matching ${pat}" >&2
        rc=1
    fi
done
exit "${rc}"
SHIM_EOF

# apt-mark hold PKG... / showhold — holds are recorded in a file; an
# unknown package makes the whole invocation fail (as the real tool
# does), which is exactly what the old `|| true` used to swallow.
cat > "${SHIM}/apt-mark" <<'SHIM_EOF'
#!/usr/bin/env bash
set -eu
cmd="$1"; shift
case "${cmd}" in
    hold)
        rc=0
        for pkg in "$@"; do
            if cut -f1 "${FAKE_DPKG_DB}" | grep -qxF -- "${pkg}"; then
                echo "${pkg}" >> "${FAKE_HOLDS}"
                echo "${pkg} set on hold."
            else
                echo "E: Unable to locate package ${pkg}" >&2
                rc=1
            fi
        done
        exit "${rc}" ;;
    showhold)
        [[ -e "${FAKE_HOLDS}" ]] && sort -u "${FAKE_HOLDS}"
        exit 0 ;;
    *) echo "apt-mark shim: unsupported ${cmd}" >&2; exit 2 ;;
esac
SHIM_EOF

# apt-get: record and succeed (the modules-extra install in the sliced
# section is `|| true` in the bake; we only need it not to explode).
cat > "${SHIM}/apt-get" <<'SHIM_EOF'
#!/usr/bin/env bash
echo "apt-get $*" >> "${FAKE_APTGET_LOG}"
exit 0
SHIM_EOF
chmod +x "${SHIM}"/*

# ── 2. Lift the chroot body verbatim, slice the kernel sections ─────
# The apt arm's chroot script is `<<'CHROOT_EOF'` (QUOTED): nothing in
# the body is expanded by the outer shell, so what is between the
# opener and the terminator is byte-for-byte what runs in the chroot.
body="${WORK}/body.sh"
awk "/^sudo tee .* <<'CHROOT_EOF'\$/{f=1; next} /^CHROOT_EOF\$/{f=0} f" "${BAKE}" > "${body}"
[[ -s "${body}" ]] || { echo "tenant-image-bake-kernel-hold-test: could not find the <<'CHROOT_EOF' body in ${BAKE}" >&2; exit 1; }
grep -q "^sudo tee .* <<'CHROOT_EOF'\$" "${BAKE}" \
    || { echo "tenant-image-bake-kernel-hold-test: the CHROOT_EOF heredoc is no longer QUOTED — this test lifts the body verbatim; re-check the guard" >&2; exit 1; }

# Section A: KVER_PKG derivation (+ the Ubuntu-only modules-extra
# install that consumes it).
# Section B: the hold block through to (not including) apt-get clean.
sect_a="$(awk '/^KVER_PKG=/{f=1} /^# ── NetBird pre-install/{f=0} f' "${body}")"
sect_b="$(awk '/^apt-mark hold/{f=1} /^apt-get clean/{f=0} f' "${body}")"
[[ -n "${sect_a}" ]] || { echo "tenant-image-bake-kernel-hold-test: section A anchor (^KVER_PKG= … ^# ── NetBird pre-install) not found — bake script moved?" >&2; exit 1; }
[[ -n "${sect_b}" ]] || { echo "tenant-image-bake-kernel-hold-test: section B anchor (^apt-mark hold … ^apt-get clean) not found — bake script moved?" >&2; exit 1; }
grep -q 'apt-mark showhold' <<<"${sect_b}" \
    || { echo "tenant-image-bake-kernel-hold-test: section B has no showhold check — wrong slice" >&2; exit 1; }

# Rewrite the absolute paths the sections touch into the fixture dir.
# Only these two prefixes; anything else absolute would be a test bug.
# A trailing line exposes KVER_PKG so (c) can assert on it directly.
under_test="${WORK}/under-test.sh"
{
    echo 'set -eu'
    printf '%s\n' "${sect_a}" "${sect_b}" \
        | sed -e 's|/etc/kernel/|${FAKE_ROOT}/etc/kernel/|g' \
              -e 's|/etc/apt/apt.conf.d/|${FAKE_ROOT}/etc/apt/apt.conf.d/|g'
    echo 'printf "TEST_KVER_PKG=%s\n" "${KVER_PKG:-}"'
} > "${under_test}"
bash -n "${under_test}" || { echo "tenant-image-bake-kernel-hold-test: sliced sections do not parse" >&2; exit 1; }

# ── 3. Runner ───────────────────────────────────────────────────────
# run_case NAME DISTRO_ID DISTRO_KERNEL_PKG DB_CONTENT → sets CASE_RC,
# CASE_OUT, CASE_ERR, CASE_HOLDS, CASE_ROOT for the assertions.
run_case() {
    local name="$1" distro_id="$2" kernel_pkg="$3" db="$4"
    CASE_ROOT="${WORK}/case-${name}"
    rm -rf -- "${CASE_ROOT}"
    mkdir -p "${CASE_ROOT}/etc/kernel/postinst.d" "${CASE_ROOT}/etc/kernel/postrm.d" "${CASE_ROOT}/etc/apt/apt.conf.d"
    printf '%b' "${db}" > "${CASE_ROOT}/dpkg.db"
    printf '#!/bin/sh\nexit 0\n' > "${CASE_ROOT}/etc/kernel/postinst.d/zz-update-grub"
    printf '#!/bin/sh\nexit 0\n' > "${CASE_ROOT}/etc/kernel/postrm.d/zz-update-grub"
    chmod +x "${CASE_ROOT}/etc/kernel/postinst.d/zz-update-grub" "${CASE_ROOT}/etc/kernel/postrm.d/zz-update-grub"
    : > "${CASE_ROOT}/holds"
    : > "${CASE_ROOT}/apt-get.log"
    set +e
    PATH="${SHIM}:/usr/bin:/bin" \
    DISTRO_ID="${distro_id}" \
    DISTRO_KERNEL_PKG="${kernel_pkg}" \
    FAKE_ROOT="${CASE_ROOT}" \
    FAKE_DPKG_DB="${CASE_ROOT}/dpkg.db" \
    FAKE_HOLDS="${CASE_ROOT}/holds" \
    FAKE_APTGET_LOG="${CASE_ROOT}/apt-get.log" \
        bash "${under_test}" >"${CASE_ROOT}/stdout" 2>"${CASE_ROOT}/stderr"
    CASE_RC=$?
    set -e
    CASE_OUT="$(cat "${CASE_ROOT}/stdout")"
    CASE_ERR="$(cat "${CASE_ROOT}/stderr")"
    CASE_HOLDS="$(sort -u "${CASE_ROOT}/holds")"
}
held()     { grep -qxF -- "$1" <<<"${CASE_HOLDS}"; }
not_held() { ! held "$1"; }
kver_of()  { sed -n 's/^TEST_KVER_PKG=//p' <<<"${CASE_OUT}"; }

BASE_DB='cryptsetup\tinstall ok installed\t\ncryptsetup-initramfs\tinstall ok installed\t\ninitramfs-tools\tinstall ok installed\t\ncurl\tinstall ok installed\t\nca-certificates\tinstall ok installed\t\nudhcpc\tinstall ok installed\t\nisc-dhcp-client\tinstall ok installed\t\niproute2\tinstall ok installed\t\nnetbird\tinstall ok installed\t\n'

# ── 4. (a)(b)(c)(d) Debian genericcloud: full kernel baked on top of
#       the pre-installed cloud kernel — BOTH metas + BOTH concretes
#       held, KVER_PKG derived, removed / never-installed kernels not
#       held, no modules-extra install attempted.
DEB_FULL_KVER="6.12.48+deb13-amd64"
DEB_CLOUD_KVER="6.12.107+deb13-cloud-amd64"
run_case debian debian linux-image-amd64 \
"${BASE_DB}linux-image-amd64\tinstall ok installed\tlinux-image-${DEB_FULL_KVER} (= 6.12.48-1)\nlinux-image-${DEB_FULL_KVER}\tinstall ok installed\tkmod, linux-base\nlinux-image-cloud-amd64\tinstall ok installed\tlinux-image-${DEB_CLOUD_KVER} (= 6.12.107-1)\nlinux-image-${DEB_CLOUD_KVER}\tinstall ok installed\tkmod, linux-base\nlinux-image-6.12.41+deb13-cloud-amd64\tdeinstall ok config-files\t\nlinux-headers-6.12.48+deb13-amd64\tunknown ok not-installed\t\nlinux-image-virtual\tunknown ok not-installed\t\n"
[[ ${CASE_RC} -eq 0 ]] || err "debian: sections exited ${CASE_RC}: ${CASE_ERR}"
held "linux-image-amd64"                       || err "debian: baked meta-package linux-image-amd64 not held (held: ${CASE_HOLDS//$'\n'/ })"
held "linux-image-cloud-amd64"                 || err "debian: pre-installed meta-package linux-image-cloud-amd64 not held (held: ${CASE_HOLDS//$'\n'/ })"
held "linux-image-${DEB_FULL_KVER}"            || err "debian: concrete full kernel linux-image-${DEB_FULL_KVER} not held"
held "linux-image-${DEB_CLOUD_KVER}"           || err "debian: concrete cloud kernel linux-image-${DEB_CLOUD_KVER} not held"
not_held "linux-image-6.12.41+deb13-cloud-amd64" || err "debian: removed (config-files) kernel wrongly held"
not_held "linux-headers-6.12.48+deb13-amd64"   || err "debian: not-installed headers wrongly held"
not_held "linux-image-virtual"                 || err "debian: not-installed Ubuntu meta-package wrongly held"
[[ "$(kver_of)" == "${DEB_FULL_KVER}" ]]       || err "debian: KVER_PKG='$(kver_of)', expected ${DEB_FULL_KVER} (derived from linux-image-amd64)"
grep -q "kernel hold: meta=.*linux-image-cloud-amd64.* kver=${DEB_FULL_KVER} " <<<"${CASE_OUT}" \
    || err "debian: summary line missing or wrong: ${CASE_OUT}"
grep -q 'linux-modules-extra' "${CASE_ROOT}/apt-get.log" && err "debian: linux-modules-extra install attempted (Debian has no such package): $(cat "${CASE_ROOT}/apt-get.log")"
grep -q '^WARNING:' <<<"${CASE_ERR}"           && err "debian: unexpected WARNING: ${CASE_ERR}"
[[ ! -x "${CASE_ROOT}/etc/kernel/postinst.d/zz-update-grub" ]] || err "debian: postinst.d/zz-update-grub still executable"
[[ ! -x "${CASE_ROOT}/etc/kernel/postrm.d/zz-update-grub" ]]   || err "debian: postrm.d/zz-update-grub still executable"
note="${CASE_ROOT}/etc/apt/apt.conf.d/99-hippius-kernel-hold"
[[ -s "${note}" ]] || err "debian: ${note} not written"
if [[ -s "${note}" ]] && grep -qvE '^\s*(//|#|$)' "${note}"; then
    err "debian: 99-hippius-kernel-hold contains a non-comment line (apt would parse it)"
fi
[[ ${fail} -eq 0 ]] && ok "(a)(b)(c)(d) debian: both meta-packages + both concrete kernels held, KVER_PKG=${DEB_FULL_KVER}, removed/not-installed not held, grub hooks disabled, note written"

# Symmetric: a plan that picked the -cloud- meta on a base that also
# carries the full one — both still held, KVER derived from the plan's.
run_case debian-cloudplan debian linux-image-cloud-amd64 \
"${BASE_DB}linux-image-cloud-amd64\tinstall ok installed\tlinux-image-${DEB_CLOUD_KVER} (= 6.12.107-1)\nlinux-image-${DEB_CLOUD_KVER}\tinstall ok installed\t\nlinux-image-amd64\tinstall ok installed\tlinux-image-${DEB_FULL_KVER} (= 6.12.48-1)\nlinux-image-${DEB_FULL_KVER}\tinstall ok installed\t\n"
[[ ${CASE_RC} -eq 0 ]] || err "debian-cloudplan: sections exited ${CASE_RC}: ${CASE_ERR}"
held "linux-image-cloud-amd64"           || err "debian-cloudplan: plan meta-package not held"
held "linux-image-amd64"                 || err "debian-cloudplan: other installed meta-package linux-image-amd64 not held"
held "linux-image-${DEB_CLOUD_KVER}"     || err "debian-cloudplan: concrete cloud kernel not held"
held "linux-image-${DEB_FULL_KVER}"      || err "debian-cloudplan: concrete full kernel not held"
[[ "$(kver_of)" == "${DEB_CLOUD_KVER}" ]] || err "debian-cloudplan: KVER_PKG='$(kver_of)', expected ${DEB_CLOUD_KVER}"
grep -q '^WARNING:' <<<"${CASE_ERR}"     && err "debian-cloudplan: unexpected WARNING: ${CASE_ERR}"
[[ ${fail} -eq 0 ]] && ok "debian (plan=cloud): both meta-packages + both concretes held, KVER from the plan's meta"

# Ubuntu: only linux-image-virtual present; concrete image/modules/
# modules-extra held; modules-extra installed; removed kernel not held.
UBU_KVER="6.8.0-31-generic"
run_case ubuntu ubuntu linux-image-virtual \
"${BASE_DB}linux-image-virtual\tinstall ok installed\tlinux-image-${UBU_KVER}\nlinux-image-${UBU_KVER}\tinstall ok installed\tlinux-modules-${UBU_KVER}\nlinux-modules-${UBU_KVER}\tinstall ok installed\t\nlinux-modules-extra-${UBU_KVER}\tinstall ok installed\t\nlinux-image-6.8.0-25-generic\tdeinstall ok config-files\t\n"
[[ ${CASE_RC} -eq 0 ]] || err "ubuntu: sections exited ${CASE_RC}: ${CASE_ERR}"
held "linux-image-virtual"                 || err "ubuntu: meta-package linux-image-virtual not held (held: ${CASE_HOLDS//$'\n'/ })"
not_held "linux-image-amd64"               || err "ubuntu: absent Debian meta-package wrongly held"
not_held "linux-image-cloud-amd64"         || err "ubuntu: absent Debian cloud meta-package wrongly held"
held "linux-image-${UBU_KVER}"             || err "ubuntu: concrete linux-image-${UBU_KVER} not held"
held "linux-modules-${UBU_KVER}"           || err "ubuntu: linux-modules-${UBU_KVER} not held"
held "linux-modules-extra-${UBU_KVER}"     || err "ubuntu: linux-modules-extra-${UBU_KVER} not held"
not_held "linux-image-6.8.0-25-generic"    || err "ubuntu: removed (config-files) kernel wrongly held"
[[ "$(kver_of)" == "${UBU_KVER}" ]]        || err "ubuntu: KVER_PKG='$(kver_of)', expected ${UBU_KVER}"
grep -q "linux-modules-extra-${UBU_KVER}" "${CASE_ROOT}/apt-get.log" \
    || err "ubuntu: linux-modules-extra-${UBU_KVER} not installed (apt-get log: $(cat "${CASE_ROOT}/apt-get.log"))"
grep -q '^WARNING:' <<<"${CASE_ERR}"       && err "ubuntu: unexpected WARNING: ${CASE_ERR}"
[[ ${fail} -eq 0 ]] && ok "ubuntu: linux-image-virtual + linux-image/-modules/-modules-extra ${UBU_KVER} held; removed kernel not held; modules-extra installed"

# ── 5. (e) Nothing held → loud WARNING naming distro + packages ─────
run_case nokernel debian linux-image-amd64 "${BASE_DB}"
[[ ${CASE_RC} -eq 0 ]] || err "nokernel: sections exited ${CASE_RC} (the check must warn, not abort): ${CASE_ERR}"
if grep -q '^WARNING: no linux-image-\* package is on hold' <<<"${CASE_ERR}"; then
    grep -q "ID='debian'" <<<"${CASE_ERR}"       || err "nokernel: WARNING does not name the distro: ${CASE_ERR}"
    grep -q 'linux-image-amd64' <<<"${CASE_ERR}" || err "nokernel: WARNING does not name the plan's meta-package: ${CASE_ERR}"
else
    err "nokernel: expected 'WARNING: no linux-image-* package is on hold', got: ${CASE_ERR:-<empty>}"
fi
grep -q '^linux-' <<<"${CASE_HOLDS}" && err "nokernel: something kernel-ish got held from an empty db: ${CASE_HOLDS}"
[[ -z "$(kver_of)" ]] || err "nokernel: KVER_PKG='$(kver_of)' from a db without the meta-package"
[[ ${fail} -eq 0 ]] && ok "(e) no kernel package held → WARNING names distro + meta-package looked for"

# The non-kernel holds keep their own `|| true` and never abort the
# chroot even when a package is absent (netbird missing here).
NO_NETBIRD_DB="${BASE_DB/netbird\\tinstall ok installed\\t\\n/}"
[[ "${NO_NETBIRD_DB}" != "${BASE_DB}" ]] || { echo "tenant-image-bake-kernel-hold-test: fixture bug — netbird not removed from BASE_DB" >&2; exit 1; }
run_case nonetbird debian linux-image-amd64 \
"${NO_NETBIRD_DB}linux-image-amd64\tinstall ok installed\tlinux-image-${DEB_FULL_KVER}\nlinux-image-${DEB_FULL_KVER}\tinstall ok installed\t\n"
[[ ${CASE_RC} -eq 0 ]] || err "nonetbird: a missing NON-kernel package aborted the sections: ${CASE_ERR}"
grep -q 'Unable to locate package netbird' <<<"${CASE_ERR}" || err "nonetbird: fixture did not exercise a failing non-kernel hold: ${CASE_ERR}"
held "linux-image-amd64" || err "nonetbird: kernel meta not held when a non-kernel hold failed"
grep -q '^WARNING:' <<<"${CASE_ERR}" && err "nonetbird: unexpected kernel WARNING: ${CASE_ERR}"
[[ ${fail} -eq 0 ]] && ok "non-kernel hold failure stays best-effort; kernel holds unaffected"

if [[ ${fail} -eq 0 ]]; then
    echo "tenant-image-bake-kernel-hold-test: ALL OK"
else
    echo "tenant-image-bake-kernel-hold-test: FAILURES" >&2
    exit 1
fi
