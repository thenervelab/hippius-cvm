#!/usr/bin/env bash
# `build-guest-release.sh` — build a Hippius guest components release
# (docs/design/guest-component-rollout.md, "The components release").
#
# A release is what gets APPENDED to a golden base's initrd:
#
#   initrd(base, R) = base_initrd ‖ zeros((-len) mod 4) ‖ release-<family>.cpio
#
# It carries every Hippius file the guest runs:
#   - the initramfs scripts + static release binaries, at the paths the
#     golden initrds already use, so they replace the base initrd's copies;
#   - /lib/hippius/guest/components.squashfs: the rootfs agents and their
#     units, SELinux-labelled, mounted from guest RAM at /run/hippius/guest
#     by `hippius_golden_mount_components` (hippius-golden-overlay.sh);
#   - /lib/hippius/guest/release: the record that step reads;
#   - /lib/hippius/guest/busybox: a static busybox for that step.
#
# Outputs (in --out, which must not exist or be empty):
#   components.squashfs          the rootfs components image
#   release                      the release record (as staged in the initrd)
#   release-initramfs-tools.cpio Ubuntu/Debian member (uncompressed newc)
#   release-dracut.cpio          CentOS Stream/Fedora member
#   release-<family>.manifest    every entry of that member:
#                                `<path> <type> <mode> <sha256|->`
#   release.json                 version, epoch, commit, shas
#
# Reproducible: the same inputs and --source-date-epoch give the same
# bytes (sorted entries, root-owned, fixed mtimes, cpio --reproducible,
# mksquashfs single-threaded with fixed times). The cpio members carry
# LEAF entries only (files) plus a directory entry for the one directory
# no golden initrd has (lib/hippius/guest): the kernel's initramfs unpacker
# replaces a same-type entry but a directory entry for an existing parent
# could replace a usrmerge symlink (`lib -> usr/lib`) with a directory.
#
# Exit: 0 ok, 2 usage, 3 refused (an input check failed), 4 build failure.
set -euo pipefail

PROG="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

die() { printf '%s: FATAL: %s\n' "${PROG}" "$*" >&2; exit 3; }
usage_die() { printf '%s: %s\n' "${PROG}" "$*" >&2; exit 2; }
build_die() { printf '%s: BUILD FAILED: %s\n' "${PROG}" "$*" >&2; exit 4; }
log() { printf '%s: %s\n' "${PROG}" "$*" >&2; }

usage() {
    cat <<EOF
Usage: ${PROG} --bin-dir DIR --busybox PATH --commit SHA
               --source-date-epoch N --out DIR

  --bin-dir DIR            holds hippius-agent-keepalive,
                           hippius-agent-tenant-telemetry,
                           hippius-agent-initramfs, hippius-guest-release,
                           hippius-vsock-ticket (the baker image: /usr/sbin)
  --busybox PATH           a STATIC busybox (Debian busybox-static)
  --commit SHA             the 40-hex repo commit the release is cut from
  --source-date-epoch N    timestamp for every entry (the commit time)
  --out DIR                output directory (absent or empty)
EOF
}

bin_dir=""
busybox=""
commit=""
sde=""
out=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin-dir) bin_dir="${2:?}"; shift 2 ;;
        --busybox) busybox="${2:?}"; shift 2 ;;
        --commit) commit="${2:?}"; shift 2 ;;
        --source-date-epoch) sde="${2:?}"; shift 2 ;;
        --out) out="${2:?}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; usage_die "unknown argument: $1" ;;
    esac
done
[[ -n "${bin_dir}" && -n "${busybox}" && -n "${commit}" && -n "${sde}" && -n "${out}" ]] \
    || { usage >&2; usage_die "missing a required argument"; }
[[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || usage_die "--commit must be 40 lowercase hex"
[[ "${sde}" =~ ^[0-9]+$ ]] || usage_die "--source-date-epoch must be an integer"

# Test seam: the tests point it at a modified copy.
COMPONENTS="${HIPPIUS_GUEST_COMPONENTS_DIR:-${SCRIPT_DIR}/components}"
INITRAMFS="${SCRIPT_DIR}/../initramfs"
DRACUT="${SCRIPT_DIR}/../dracut/95hippius-golden"
SHIM="${SCRIPT_DIR}/hippius-keepalive-start"

for tool in mksquashfs rdsquashfs cpio sha256sum python3; do
    command -v "${tool}" >/dev/null 2>&1 || die "missing host tool: ${tool}"
done
AGENTS=(hippius-agent-keepalive hippius-agent-tenant-telemetry hippius-agent-initramfs)
INITRD_BINS=(hippius-guest-release hippius-vsock-ticket)
for b in "${AGENTS[@]}" "${INITRD_BINS[@]}"; do
    [[ -f "${bin_dir}/${b}" && -x "${bin_dir}/${b}" ]] || die "--bin-dir: missing executable ${b}"
done
for f in "${COMPONENTS}/release.conf" "${COMPONENTS}/selinux-labels" \
         "${COMPONENTS}/etc/keepalive.env" "${SHIM}" \
         "${INITRAMFS}/hippius-release-core.sh" "${INITRAMFS}/hippius-golden-overlay.sh" \
         "${INITRAMFS}/hippius-golden-boot" "${INITRAMFS}/hippius-net-teardown" \
         "${DRACUT}/hippius-golden-mount.sh" "${DRACUT}/hippius-net-teardown.sh" \
         "${DRACUT}/hippius-golden-mount.service" "${DRACUT}/hippius-net-teardown.service" \
         "${DRACUT}/parse-hippius-golden.sh"; do
    [[ -r "${f}" ]] || die "missing input ${f}"
done
[[ -f "${busybox}" && -x "${busybox}" ]] || die "--busybox: not an executable file"
# The applets the boot step uses, and nothing dynamic: the base initrd's
# libc is not ours to rely on.
# (The list is read whole first: `--list | grep -q` under pipefail fails
# whenever grep exits early and busybox takes the SIGPIPE.)
applets="$("${busybox}" --list 2>/dev/null)" || die "--busybox --list failed"
for applet in sha256sum cp mount umount; do
    grep -qx "${applet}" <<<"${applets}" || die "--busybox lacks the ${applet} applet"
done
# Static = an ELF with no PT_INTERP program header.
python3 - "${busybox}" <<'PY' || die "--busybox is not a static x86-64 ELF; use busybox-static"
import struct, sys
with open(sys.argv[1], "rb") as f:
    data = f.read()
if data[:4] != b"\x7fELF" or data[4] != 2:
    sys.exit(1)
phoff, = struct.unpack_from("<Q", data, 0x20)
phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
for i in range(phnum):
    p_type, = struct.unpack_from("<I", data, phoff + i * phentsize)
    if p_type == 3:  # PT_INTERP
        sys.exit(1)
PY

if [[ -e "${out}" ]]; then
    [[ -d "${out}" && -z "$(ls -A "${out}")" ]] || usage_die "--out must not exist or be empty"
fi
mkdir -p "${out}"
out="$(cd "${out}" && pwd)"
work="$(mktemp -d)"
trap 'chmod -R u+w "${work}" 2>/dev/null; rm -r "${work}"' EXIT

export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="${sde}"

# ── 1. The components image ─────────────────────────────────────────
img="${work}/img"
install -d -m 0755 "${img}" "${img}/bin" "${img}/units" "${img}/etc"
for b in "${AGENTS[@]}"; do
    install -m 0755 "${bin_dir}/${b}" "${img}/bin/${b}"
done
install -m 0755 "${SHIM}" "${img}/bin/hippius-keepalive-start"
install -m 0644 "${COMPONENTS}/etc/keepalive.env" "${img}/etc/keepalive.env"
units=()
while IFS= read -r line; do
    case "${line}" in enable=*) ;; *) continue ;; esac
    unit="${line#enable=}"
    unit="${unit%%:*}"
    [[ -r "${COMPONENTS}/units/${unit}" ]] || die "release.conf enables ${unit} but units/${unit} is missing"
    install -m 0644 "${COMPONENTS}/units/${unit}" "${img}/units/${unit}"
    units+=("${unit}")
done < "${COMPONENTS}/release.conf"
(( ${#units[@]} > 0 )) || die "release.conf enables no unit"
for f in "${COMPONENTS}"/units/*; do
    name="$(basename "${f}")"
    [[ -e "${img}/units/${name}" ]] || die "units/${name} is not enabled by release.conf (ship nothing unused)"
done

# Every entry gets a label from its top-level directory; none may lack one.
declare -A label=()
while read -r key ctx _; do
    [[ -z "${key}" || "${key}" == \#* ]] && continue
    [[ "${ctx}" =~ ^[a-z0-9_]+:[a-z0-9_]+:[a-z0-9_]+:s0$ ]] || die "selinux-labels: bad context '${ctx}'"
    label["${key}"]="${ctx}"
done < "${COMPONENTS}/selinux-labels"
[[ -n "${label[/]:-}" ]] || die "selinux-labels: no label for the image root"
pseudo="${work}/labels.pf"
printf '/ x security.selinux=%s\n' "${label[/]}" > "${pseudo}"
while IFS= read -r rel; do
    top="${rel%%/*}"
    [[ -n "${label[${top}]:-}" ]] || die "no SELinux label for ${rel} (selinux-labels has none for ${top})"
    printf '%s x security.selinux=%s\n' "${rel}" "${label[${top}]}" >> "${pseudo}"
done < <(cd "${img}" && find . -mindepth 1 | sed 's|^\./||' | sort)

squashfs="${out}/components.squashfs"
# SOURCE_DATE_EPOCH (exported above) sets the mkfs time and every entry's
# mtime; mksquashfs refuses it together with -mkfs-time/-all-time.
mksquashfs "${img}" "${squashfs}" -noappend -comp gzip -Xcompression-level 9 \
    -processors 1 -all-root \
    -pf "${pseudo}" -quiet >/dev/null \
    || build_die "mksquashfs"
# Read every label back out of the image: the bytes we ship, not the
# pseudo file we asked for.
while read -r rel _ ctx; do
    path="/${rel}"
    [[ "${rel}" == "/" ]] && path="/"
    got="$(rdsquashfs -x "${path}" "${squashfs}" 2>/dev/null | sed -n 's/^security\.selinux=//p')"
    [[ "${got}" == "${ctx#security.selinux=}" ]] \
        || build_die "label of ${path} in the image is '${got}', want '${ctx#security.selinux=}'"
done < "${pseudo}"
squashfs_sha="$(sha256sum "${squashfs}" | cut -d' ' -f1)"

# ── 2. The release record ───────────────────────────────────────────
record="${out}/release"
{
    printf '# Hippius guest components release (build-guest-release.sh)\n'
    grep -E '^(version|security_epoch|health_mask|enable|retire)=' "${COMPONENTS}/release.conf"
    printf 'commit=%s\n' "${commit}"
    printf 'squashfs_sha256=%s\n' "${squashfs_sha}"
} > "${record}"
# The record must parse with the SAME parser the initramfs runs.
(
    hippius_log() { :; }
    hippius_die() { echo "$*" >&2; exit 1; }
    # shellcheck source=scripts/initramfs/hippius-golden-overlay.sh
    . "${INITRAMFS}/hippius-golden-overlay.sh"
    hippius_golden_parse_release "${record}" >/dev/null
) || die "the release record does not parse with hippius_golden_parse_release"
version="$(sed -n 's/^version=//p' "${record}")"
epoch="$(sed -n 's/^security_epoch=//p' "${record}")"
health_mask="$(sed -n 's/^health_mask=//p' "${record}")"
health_mask="${health_mask:-0}"
(( health_mask <= 4294967295 )) || die "health_mask ${health_mask} does not fit a u32"
# The keepalive attests the health leg iff the release declares checks:
# a release that declares them without the switch would never pass vali's
# gate; one that switches it on without declaring them would send a leg
# vali does not judge.
attest="$(sed -n 's/^HIPPIUS_KEEPALIVE_ATTEST_COMPONENTS=//p' "${COMPONENTS}/etc/keepalive.env")"
if (( health_mask != 0 )); then
    [[ "${attest}" == 1 ]] \
        || die "release.conf declares health_mask=${health_mask} but etc/keepalive.env does not set HIPPIUS_KEEPALIVE_ATTEST_COMPONENTS=1"
    # …and the keepalive this release ships understands the switch: an
    # older binary exits on the unknown flag (status 2, which the unit
    # never restarts), which would take the uptime leg down with it.
    ka_help="$("${bin_dir}/hippius-agent-keepalive" --help 2>&1 || true)"
    [[ "${ka_help}" == *--attest-components* ]] \
        || die "--bin-dir: hippius-agent-keepalive does not know --attest-components (built from another commit?)"
else
    [[ -z "${attest}" || "${attest}" == 0 ]] \
        || die "etc/keepalive.env sets HIPPIUS_KEEPALIVE_ATTEST_COMPONENTS=${attest} but release.conf declares no health_mask"
fi

# ── 3. One cpio member per initramfs family ─────────────────────────
# `stage <family> <dest> <mode> <src>`: a leaf at <dest> (relative to the
# initrd root). Paths are where the golden hooks / dracut module put them.
build_member() {
    local family="$1"
    local root="${work}/member-${family}"
    local list="${work}/list-${family}"
    install -d -m 0755 "${root}"
    : > "${list}"
    stage() {
        install -D -m "$2" "$3" "${root}/$1"
        printf '%s\n' "$1" >> "${list}"
    }
    stage lib/hippius/guest/release 0644 "${record}"
    stage lib/hippius/guest/components.squashfs 0644 "${squashfs}"
    stage lib/hippius/guest/busybox 0755 "${busybox}"
    stage lib/hippius/hippius-release-core.sh 0644 "${INITRAMFS}/hippius-release-core.sh"
    stage lib/hippius/hippius-golden-overlay.sh 0644 "${INITRAMFS}/hippius-golden-overlay.sh"
    stage usr/sbin/hippius-guest-release 0755 "${bin_dir}/hippius-guest-release"
    stage usr/sbin/hippius-vsock-ticket 0755 "${bin_dir}/hippius-vsock-ticket"
    case "${family}" in
        initramfs-tools)
            stage scripts/hippius-golden 0755 "${INITRAMFS}/hippius-golden-boot"
            stage scripts/init-bottom/hippius-net-teardown 0755 "${INITRAMFS}/hippius-net-teardown"
            ;;
        dracut)
            stage sbin/hippius-golden-mount 0755 "${DRACUT}/hippius-golden-mount.sh"
            stage sbin/hippius-net-teardown 0755 "${DRACUT}/hippius-net-teardown.sh"
            stage usr/lib/systemd/system/hippius-golden-mount.service 0644 "${DRACUT}/hippius-golden-mount.service"
            stage usr/lib/systemd/system/hippius-net-teardown.service 0644 "${DRACUT}/hippius-net-teardown.service"
            ;;
    esac
    # The one new directory, before its files (the unpacker does not
    # create parents).
    chmod 0755 "${root}/lib/hippius/guest"
    printf 'lib/hippius/guest\n' >> "${list}"
    find "${root}" -exec touch -h -d "@${sde}" {} +
    sort -o "${list}" "${list}"
    (cd "${root}" && cpio --quiet -o -H newc -R 0:0 --reproducible < "${list}") \
        > "${out}/release-${family}.cpio" \
        || build_die "cpio (${family})"
    # The manifest: what the member puts where, for the build Job's
    # merged-tree check.
    while IFS= read -r rel; do
        if [[ -d "${root}/${rel}" ]]; then
            printf '%s dir 0755 -\n' "${rel}"
        else
            printf '%s file %s %s\n' "${rel}" "$(stat -c '%04a' "${root}/${rel}")" \
                "$(sha256sum "${root}/${rel}" | cut -d' ' -f1)"
        fi
    done < "${list}" > "${out}/release-${family}.manifest"
    # What the member does NOT replace but relies on, checked against the
    # base initrd by the build Job (scripts/guest/initrd-merge-check.py):
    #   expect <sha256> <path>[|<path>...]  a base file with this content
    #                                       (any one of the paths)
    #   expect-link <resolves-to> <path>    a base symlink resolving there
    #   needs <command>                     on the initrd's PATH
    # The dracut cmdline hook's directory depends on the dracut version and
    # the units' enablement links were made by `systemctl enable` at bake
    # time, so they are checked, not shipped.
    {
        for cmd in mkdir rm ln readlink; do
            printf 'needs %s\n' "${cmd}"
        done
        if [[ "${family}" == dracut ]]; then
            local hook=30-parse-hippius-golden.sh
            printf 'expect %s lib/dracut/hooks/cmdline/%s|usr/lib/dracut/hooks/cmdline/%s|var/lib/dracut/hooks/cmdline/%s\n' \
                "$(sha256sum "${DRACUT}/parse-hippius-golden.sh" | cut -d' ' -f1)" "${hook}" "${hook}" "${hook}"
            printf 'expect-link usr/lib/systemd/system/hippius-golden-mount.service etc/systemd/system/initrd-root-fs.target.requires/hippius-golden-mount.service\n'
            printf 'expect-link usr/lib/systemd/system/hippius-net-teardown.service etc/systemd/system/initrd-switch-root.target.wants/hippius-net-teardown.service\n'
            printf 'needs setfattr\nneeds getfattr\n'
        fi
    } >> "${out}/release-${family}.manifest"
}
build_member initramfs-tools
build_member dracut

# A member's entries must be leaves or the one new directory, nothing else.
for family in initramfs-tools dracut; do
    bad="$(cpio --quiet -it < "${out}/release-${family}.cpio" \
        | grep -vxE 'lib/hippius/guest(/[^/]+)?|lib/hippius/[^/]+\.sh|usr/sbin/hippius-[a-z-]+|scripts/hippius-golden|scripts/init-bottom/hippius-net-teardown|sbin/hippius-(golden-mount|net-teardown)|usr/lib/systemd/system/hippius-(golden-mount|net-teardown)\.service' || true)"
    [[ -z "${bad}" ]] || build_die "unexpected entries in release-${family}.cpio: ${bad}"
done

# ── 4. Summary ──────────────────────────────────────────────────────
sha() { sha256sum "$1" | cut -d' ' -f1; }
cat > "${out}/release.json" <<JSON
{
  "version": ${version},
  "security_epoch": ${epoch},
  "health_mask": ${health_mask},
  "commit": "${commit}",
  "source_date_epoch": ${sde},
  "squashfs_sha256": "${squashfs_sha}",
  "cpio_sha256": {
    "initramfs-tools": "$(sha "${out}/release-initramfs-tools.cpio")",
    "dracut": "$(sha "${out}/release-dracut.cpio")"
  }
}
JSON
log "RELEASE OK version=${version} security_epoch=${epoch} health_mask=${health_mask} commit=${commit} squashfs_sha256=${squashfs_sha}"
