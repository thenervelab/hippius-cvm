#!/usr/bin/env bash
# Unit test for the kernel-hold logic inside the chroot heredoc of
# `scripts/tenant-rootfs-build.sh` (Stage 1 shared-rootfs bake).
#
# WHY this exists: the hold used to name Ubuntu's `linux-image-virtual`
# unconditionally, behind `|| true`. On a Debian base that held nothing,
# a tenant `apt upgrade` pulled a new concrete kernel, and the grub
# postinst hook (which cannot resolve the live dm-crypt root inside a
# CVM) left dpkg half-configured. Holding the meta-package alone is not
# enough either — apt still installs a new concrete linux-image-<ver>.
#
# The first fix of that hold was itself unreachable on Debian: the
# `apt-get install` that PRECEDES it still named `linux-image-virtual`,
# which does not exist there, so the chroot's `set -e` died before the
# hold logic ran. This test missed it because its slice started AFTER
# the install and its `apt-get` shim always succeeded. Both are fixed
# here: the slice starts at the first apt-get call, and the shim fails
# an install of a package the fixture's distro does not have.
#
# HOW: root-free, no chroot, no apt. The test lifts the chroot BODY out
# of the bake script, expands it through an unquoted heredoc exactly as
# the bake does (so the `\$` / `\\` escaping is exercised for real),
# slices out the two kernel-related sections, rewrites the absolute
# /etc paths into a temp dir, and runs them against PATH-shimmed
# `dpkg-query` / `apt-mark` / `apt-get` driven by a fixture "dpkg db"
# plus a per-distro "archive" of installable names.
# It never restructures the bake script: if the section anchors move,
# the test fails loudly rather than silently testing nothing.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BAKE="${HERE}/../tenant-rootfs-build.sh"
[[ -r "${BAKE}" ]] || { echo "tenant-rootfs-kernel-hold-test: bake script not found at ${BAKE}" >&2; exit 1; }

fail=0
ok()  { echo "tenant-rootfs-kernel-hold-test: OK — $*"; }
err() { echo "tenant-rootfs-kernel-hold-test: FAIL — $*" >&2; fail=1; }

WORK="$(mktemp -d -t hippius-kernel-hold-test.XXXXXX)"
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

# apt-get: record every call; `install` FAILS (exit 100, like the real
# tool) when asked for a package that neither the fixture db nor the
# fixture "archive" (FAKE_APT_ARCHIVE: the distro's installable names,
# one per line) knows. This is what a hard-coded Ubuntu kernel name does
# on a Debian base — and an always-succeeding shim is exactly how the
# previous version of this test missed it. The db is NOT mutated by an
# install: each case states the post-install package state explicitly.
cat > "${SHIM}/apt-get" <<'SHIM_EOF'
#!/usr/bin/env bash
set -eu
echo "apt-get $*" >> "${FAKE_APTGET_LOG}"
cmd=""
pkgs=()
for a in "$@"; do
    case "${a}" in
        -*) ;;
        *) if [[ -z "${cmd}" ]]; then cmd="${a}"; else pkgs+=("${a}"); fi ;;
    esac
done
[[ "${cmd}" == install ]] || exit 0
rc=0
for pkg in "${pkgs[@]}"; do
    if cut -f1 "${FAKE_DPKG_DB}" | grep -qxF -- "${pkg}"; then continue; fi
    if [[ -r "${FAKE_APT_ARCHIVE}" ]] && grep -qxF -- "${pkg}" "${FAKE_APT_ARCHIVE}"; then continue; fi
    echo "E: Unable to locate package ${pkg}" >&2
    rc=100
done
exit "${rc}"
SHIM_EOF

# The chroot body carries a pre-existing backtick in a comment that the
# outer shell command-substitutes at expansion time; a no-op keeps the
# expansion quiet here (it is not what this test is about).
printf '#!/usr/bin/env bash\nexit 0\n' > "${SHIM}/netbird"
chmod +x "${SHIM}"/*

# ── 2. Lift + expand the chroot body, slice the kernel sections ─────
body_raw="${WORK}/body.raw"
awk '/^sudo chroot .* <<CHROOT_EOF$/{f=1; next} /^CHROOT_EOF$/{f=0} f' "${BAKE}" > "${body_raw}"
[[ -s "${body_raw}" ]] || { echo "tenant-rootfs-kernel-hold-test: could not find the <<CHROOT_EOF body in ${BAKE}" >&2; exit 1; }

# Expand exactly like the bake: an UNQUOTED heredoc with the two outer
# variables the body references. This is what turns `\${X}` into `${X}`
# and `\\n` into `\n`.
body_expanded="${WORK}/body.sh"
PATH="${SHIM}:${PATH}" netbird_version="0.0.0-test" source_date_epoch="86400" \
    bash -c "cat <<CHROOT_EOF
$(cat "${body_raw}")
CHROOT_EOF" > "${body_expanded}"

# Section A: from the distro detection up to the NetBird block: DISTRO_ID
# + KERNEL_PKG/KERNEL_META, the apt-get install that names the kernel
# meta-package, KERNEL_META_INSTALLED, KVER_PKG (+ the modules-extra
# install that consumes KVER_PKG). The install MUST be inside this slice:
# a slice that starts at the hold logic can never see a distro-wrong
# install, and if the install ever moves back ABOVE the detection it
# falls out of the slice and the check below fails loudly.
# Section B: the hold block through to (not including) apt-get clean.
sect_a="$(awk '/^DISTRO_ID=/{f=1} /^# NetBird pre-install/{f=0} f' "${body_expanded}")"
sect_b="$(awk '/^apt-mark hold/{f=1} /^apt-get clean/{f=0} f' "${body_expanded}")"
[[ -n "${sect_a}" ]] || { echo "tenant-rootfs-kernel-hold-test: section A anchor (^DISTRO_ID= … ^# NetBird pre-install) not found — bake script moved?" >&2; exit 1; }
[[ -n "${sect_b}" ]] || { echo "tenant-rootfs-kernel-hold-test: section B anchor (^apt-mark hold … ^apt-get clean) not found — bake script moved?" >&2; exit 1; }
grep -q '^apt-get install ' <<<"${sect_a}" \
    || { echo "tenant-rootfs-kernel-hold-test: section A has no apt-get install AFTER DISTRO_ID= — the kernel package cannot be per-distro (install precedes detection, or bake script moved?)" >&2; exit 1; }
grep -q 'apt-mark showhold' <<<"${sect_b}" \
    || { echo "tenant-rootfs-kernel-hold-test: section B has no showhold check — wrong slice" >&2; exit 1; }

# Rewrite the absolute paths the sections touch into the fixture dir.
# Only these three prefixes; anything else absolute would be a test bug.
under_test="${WORK}/under-test.sh"
{
    echo 'set -eu'
    printf '%s\n' "${sect_a}" "${sect_b}" \
        | sed -e 's|/etc/os-release|${FAKE_ROOT}/etc/os-release|g' \
              -e 's|/etc/kernel/|${FAKE_ROOT}/etc/kernel/|g' \
              -e 's|/etc/apt/apt.conf.d/|${FAKE_ROOT}/etc/apt/apt.conf.d/|g'
} > "${under_test}"
bash -n "${under_test}" || { echo "tenant-rootfs-kernel-hold-test: sliced sections do not parse" >&2; exit 1; }

# ── 3. Runner ───────────────────────────────────────────────────────
# run_case NAME OS_RELEASE_CONTENT DB_CONTENT ARCHIVE → sets CASE_RC,
# CASE_ERR, CASE_HOLDS, CASE_ROOT, CASE_APTGET for the assertions.
# ARCHIVE = the package names apt-get install may fetch for this
# distro (one per line); db packages are always installable.
run_case() {
    local name="$1" osr="$2" db="$3" archive="$4"
    CASE_ROOT="${WORK}/case-${name}"
    rm -rf -- "${CASE_ROOT}"
    mkdir -p "${CASE_ROOT}/etc/kernel/postinst.d" "${CASE_ROOT}/etc/kernel/postrm.d" "${CASE_ROOT}/etc/apt/apt.conf.d"
    printf '%s\n' "${osr}" > "${CASE_ROOT}/etc/os-release"
    printf '%b' "${db}" > "${CASE_ROOT}/dpkg.db"
    printf '%s\n' "${archive}" > "${CASE_ROOT}/archive"
    printf '#!/bin/sh\nexit 0\n' > "${CASE_ROOT}/etc/kernel/postinst.d/zz-update-grub"
    printf '#!/bin/sh\nexit 0\n' > "${CASE_ROOT}/etc/kernel/postrm.d/zz-update-grub"
    chmod +x "${CASE_ROOT}/etc/kernel/postinst.d/zz-update-grub" "${CASE_ROOT}/etc/kernel/postrm.d/zz-update-grub"
    : > "${CASE_ROOT}/holds"
    : > "${CASE_ROOT}/apt-get.log"
    set +e
    PATH="${SHIM}:/usr/bin:/bin" \
    FAKE_ROOT="${CASE_ROOT}" \
    FAKE_DPKG_DB="${CASE_ROOT}/dpkg.db" \
    FAKE_HOLDS="${CASE_ROOT}/holds" \
    FAKE_APTGET_LOG="${CASE_ROOT}/apt-get.log" \
    FAKE_APT_ARCHIVE="${CASE_ROOT}/archive" \
        bash "${under_test}" >"${CASE_ROOT}/stdout" 2>"${CASE_ROOT}/stderr"
    CASE_RC=$?
    set -e
    CASE_ERR="$(cat "${CASE_ROOT}/stderr")"
    CASE_HOLDS="$(sort -u "${CASE_ROOT}/holds")"
    CASE_APTGET="$(cat "${CASE_ROOT}/apt-get.log")"
}
held()     { grep -qxF -- "$1" <<<"${CASE_HOLDS}"; }
not_held() { ! held "$1"; }
# The base install line (not the `|| true` modules-extra one) named PKG.
install_requested() {
    grep -E '^apt-get install ' <<<"${CASE_APTGET}" | grep -v 'linux-modules-extra-' | grep -qw -- "$1"
}

# Per-distro "archive": what apt could fetch. Ubuntu has no
# linux-image-amd64 and Debian has no linux-image-virtual — that is the
# whole point: the wrong meta-package must FAIL the install.
UBU_ARCHIVE=$'linux-image-virtual'
DEB_ARCHIVE=$'linux-image-amd64\nlinux-image-cloud-amd64'

BASE_DB='cryptsetup\tinstall ok installed\t\ncryptsetup-initramfs\tinstall ok installed\t\ninitramfs-tools\tinstall ok installed\t\ncurl\tinstall ok installed\t\nca-certificates\tinstall ok installed\t\nudhcpc\tinstall ok installed\t\nisc-dhcp-client\tinstall ok installed\t\niproute2\tinstall ok installed\t\nnetbird\tinstall ok installed\t\n'

# ── 4. (a)+(b) Debian: cloud meta-package + concrete kernel held ────
DEB_KVER="6.12.107+deb13-cloud-amd64"
run_case debian 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
ID=debian
VERSION_ID="13"' \
"${BASE_DB}linux-image-cloud-amd64\tinstall ok installed\tlinux-image-${DEB_KVER} (= 6.12.107-1)\nlinux-image-${DEB_KVER}\tinstall ok installed\tkmod, linux-base\n" \
"${DEB_ARCHIVE}"
[[ ${CASE_RC} -eq 0 ]] || err "debian: sections exited ${CASE_RC}: ${CASE_ERR}"
install_requested "linux-image-amd64"     || err "debian: install did not request linux-image-amd64 (apt-get log: ${CASE_APTGET//$'\n'/ | })"
install_requested "linux-image-virtual"   && err "debian: install requested the Ubuntu meta-package linux-image-virtual (apt-get log: ${CASE_APTGET//$'\n'/ | })"
held "linux-image-cloud-amd64"          || err "debian: meta-package linux-image-cloud-amd64 not held (held: ${CASE_HOLDS//$'\n'/ })"
not_held "linux-image-virtual"          || err "debian: Ubuntu meta-package linux-image-virtual wrongly held"
held "linux-image-${DEB_KVER}"          || err "debian: concrete linux-image-${DEB_KVER} not held (held: ${CASE_HOLDS//$'\n'/ })"
grep -q '^WARNING:' <<<"${CASE_ERR}"    && err "debian: unexpected WARNING: ${CASE_ERR}"
[[ ! -x "${CASE_ROOT}/etc/kernel/postinst.d/zz-update-grub" ]] || err "debian: postinst.d/zz-update-grub still executable"
[[ ! -x "${CASE_ROOT}/etc/kernel/postrm.d/zz-update-grub" ]]   || err "debian: postrm.d/zz-update-grub still executable"
note="${CASE_ROOT}/etc/apt/apt.conf.d/99-hippius-kernel-hold"
[[ -s "${note}" ]] || err "debian: ${note} not written"
if [[ -s "${note}" ]] && grep -qvE '^\s*(//|#|$)' "${note}"; then
    err "debian: 99-hippius-kernel-hold contains a non-comment line (apt would parse it)"
fi
grep -q "linux-modules-extra-${DEB_KVER}" "${CASE_ROOT}/apt-get.log" \
    || err "debian: KVER_PKG not derived from linux-image-cloud-amd64 (apt-get log: $(cat "${CASE_ROOT}/apt-get.log"))"
[[ ${fail} -eq 0 ]] && ok "(a)(b) debian: installs linux-image-amd64; linux-image-cloud-amd64 + linux-image-${DEB_KVER} held, grub hooks disabled, note written"

# Debian with the FULL kernel (linux-image-amd64) instead of -cloud-.
run_case debian-full 'ID=debian' \
"${BASE_DB}linux-image-amd64\tinstall ok installed\tlinux-image-6.12.107+deb13-amd64 (= 6.12.107-1)\nlinux-image-6.12.107+deb13-amd64\tinstall ok installed\t\n" \
"${DEB_ARCHIVE}"
[[ ${CASE_RC} -eq 0 ]] || err "debian-full: sections exited ${CASE_RC}: ${CASE_ERR}"
install_requested "linux-image-amd64"     || err "debian-full: install did not request linux-image-amd64"
held "linux-image-amd64"                  || err "debian-full: linux-image-amd64 not held"
held "linux-image-6.12.107+deb13-amd64"   || err "debian-full: concrete kernel not held"
not_held "linux-image-cloud-amd64"        || err "debian-full: absent -cloud- meta wrongly held"
grep -q '^WARNING:' <<<"${CASE_ERR}"      && err "debian-full: unexpected WARNING: ${CASE_ERR}"
[[ ${fail} -eq 0 ]] && ok "debian (full kernel): linux-image-amd64 + concrete held"

# ── 5. (c) Ubuntu: linux-image-virtual + concrete set held ──────────
UBU_KVER="6.8.0-31-generic"
run_case ubuntu 'NAME="Ubuntu"
ID="ubuntu"
ID_LIKE=debian' \
"${BASE_DB}linux-image-virtual\tinstall ok installed\tlinux-image-${UBU_KVER}\nlinux-image-${UBU_KVER}\tinstall ok installed\tlinux-modules-${UBU_KVER}\nlinux-modules-${UBU_KVER}\tinstall ok installed\t\nlinux-modules-extra-${UBU_KVER}\tinstall ok installed\t\nlinux-image-6.8.0-25-generic\tdeinstall ok config-files\t\n" \
"${UBU_ARCHIVE}"
[[ ${CASE_RC} -eq 0 ]] || err "ubuntu: sections exited ${CASE_RC}: ${CASE_ERR}"
install_requested "linux-image-virtual"   || err "ubuntu: install did not request linux-image-virtual (apt-get log: ${CASE_APTGET//$'\n'/ | })"
install_requested "linux-image-amd64"     && err "ubuntu: install requested the Debian meta-package linux-image-amd64 (apt-get log: ${CASE_APTGET//$'\n'/ | })"
held "linux-image-virtual"                 || err "ubuntu: meta-package linux-image-virtual not held (held: ${CASE_HOLDS//$'\n'/ })"
not_held "linux-image-cloud-amd64"         || err "ubuntu: Debian meta-package wrongly held"
held "linux-image-${UBU_KVER}"             || err "ubuntu: concrete linux-image-${UBU_KVER} not held"
held "linux-modules-${UBU_KVER}"           || err "ubuntu: linux-modules-${UBU_KVER} not held"
held "linux-modules-extra-${UBU_KVER}"     || err "ubuntu: linux-modules-extra-${UBU_KVER} not held"
not_held "linux-image-6.8.0-25-generic"    || err "ubuntu: removed (config-files) kernel wrongly held"
grep -q '^WARNING:' <<<"${CASE_ERR}"       && err "ubuntu: unexpected WARNING: ${CASE_ERR}"
grep -q "linux-modules-extra-${UBU_KVER}" "${CASE_ROOT}/apt-get.log" \
    || err "ubuntu: KVER_PKG not derived from linux-image-virtual"
[[ ${fail} -eq 0 ]] && ok "(c) ubuntu: installs linux-image-virtual; linux-image-virtual + linux-image/-modules/-modules-extra ${UBU_KVER} held; removed kernel not held"

# ── 6. (d) Nothing held → loud WARNING naming distro + packages ─────
run_case nokernel 'ID=debian' "${BASE_DB}" "${DEB_ARCHIVE}"
[[ ${CASE_RC} -eq 0 ]] || err "nokernel: sections exited ${CASE_RC} (the check must warn, not abort): ${CASE_ERR}"
if grep -q '^WARNING: no linux-image-\* package is on hold' <<<"${CASE_ERR}"; then
    grep -q "ID='debian'" <<<"${CASE_ERR}"          || err "nokernel: WARNING does not name the distro: ${CASE_ERR}"
    grep -q 'linux-image-cloud-amd64' <<<"${CASE_ERR}" || err "nokernel: WARNING does not name the meta-package looked for: ${CASE_ERR}"
else
    err "nokernel: expected 'WARNING: no linux-image-* package is on hold', got: ${CASE_ERR:-<empty>}"
fi
grep -q '^linux-' <<<"${CASE_HOLDS}" && err "nokernel: something kernel-ish got held from an empty db: ${CASE_HOLDS}"
[[ ${fail} -eq 0 ]] && ok "(d) no kernel package held → WARNING names distro + packages looked for"

# ── 7. (e) Unknown distro: fails loudly BEFORE any install, names the ID
# There is no kernel meta-package to guess for an ID the bake does not
# know; guessing is how the Ubuntu name ended up on a Debian base.
run_case unknown 'ID=frobnix' \
"${BASE_DB}linux-image-virtual\tinstall ok installed\tlinux-image-${UBU_KVER}\nlinux-image-${UBU_KVER}\tinstall ok installed\t\n" \
"${UBU_ARCHIVE}"$'\n'"${DEB_ARCHIVE}"
[[ ${CASE_RC} -ne 0 ]] || err "unknown: sections exited 0 for ID=frobnix — an unknown distro must abort the bake"
grep -q "^ERROR: unsupported distro ID='frobnix'" <<<"${CASE_ERR}" || err "unknown: no ERROR naming the ID: ${CASE_ERR:-<empty>}"
grep -q '^apt-get install ' <<<"${CASE_APTGET}" && err "unknown: apt-get install was attempted for an unknown distro: ${CASE_APTGET//$'\n'/ | }"
[[ -z "${CASE_HOLDS}" ]] || err "unknown: something got held after the abort: ${CASE_HOLDS//$'\n'/ }"
[[ ${fail} -eq 0 ]] && ok "(e) unknown distro: ERROR names ID='frobnix', no install attempted, nothing held"

# ── 8. Guard the guard: the wrong meta-package must make the shim fail ─
# If a fixture's archive accepted the other distro's name, the two
# install assertions above would pass against a hard-coded package too.
set +e
FAKE_APTGET_LOG=/dev/null FAKE_DPKG_DB=/dev/null FAKE_APT_ARCHIVE=<(printf '%s\n' "${DEB_ARCHIVE}") \
    "${SHIM}/apt-get" install -y --no-install-recommends linux-image-virtual >/dev/null 2>&1
shim_deb_rc=$?
FAKE_APTGET_LOG=/dev/null FAKE_DPKG_DB=/dev/null FAKE_APT_ARCHIVE=<(printf '%s\n' "${UBU_ARCHIVE}") \
    "${SHIM}/apt-get" install -y --no-install-recommends linux-image-amd64 >/dev/null 2>&1
shim_ubu_rc=$?
set -e
[[ ${shim_deb_rc} -ne 0 ]] || err "shim: apt-get install linux-image-virtual succeeded against the Debian archive"
[[ ${shim_ubu_rc} -ne 0 ]] || err "shim: apt-get install linux-image-amd64 succeeded against the Ubuntu archive"
[[ ${fail} -eq 0 ]] && ok "shim: linux-image-virtual fails on debian, linux-image-amd64 fails on ubuntu"

if [[ ${fail} -eq 0 ]]; then
    echo "tenant-rootfs-kernel-hold-test: ALL OK"
else
    echo "tenant-rootfs-kernel-hold-test: FAILURES" >&2
    exit 1
fi
