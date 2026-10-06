#!/usr/bin/env bash
# `guest-initrd-build.sh` — build the initrd a golden base boots for a
# guest components release (docs/design/guest-component-rollout.md):
#
#   initrd(base, R) = base_initrd ‖ zeros((-len) mod 4) ‖ release-<family>.cpio
#
# and publish it, with the base's own kernel + dm-verity base, as a NEW
# prefix that `vali_swap_vm_initrd` (and later the guest-upgrade job) can
# point a VM's launch record at. Nothing of the base changes: same kernel,
# same rootfs.img + rootfs.verity, same verity root hash; the base initrd's
# bytes are the prefix of the new one.
#
# What it does:
#   1. fetch the source set (tenant.vmlinuz, tenant.initrd.img, rootfs.img,
#      rootfs.verity, golden.measurement.json) from an S3 prefix or a local
#      dir and REFUSE unless every sha matches its measurement.json (and the
#      optional --expect-* pins, e.g. the vali TenantBake row); the source
#      must be golden and its initrd one built by the base's own
#      mkinitramfs/dracut (a bake or an initrd-only rebuild), never an
#      earlier release build: releases are appended to the base, never
#      chained;
#   2. take the release (--release-dir, the output of
#      build-guest-release.sh), or build it here (--build-release, from the
#      baker image's own binaries);
#   3. detect the base initrd's family and run initrd-merge-check.py: the
#      release member is unpacked over the base with the kernel's rules and
#      the merged tree must match the release manifest, else REFUSE;
#   4. write the output set (reused kernel/rootfs/verity + the appended
#      initrd + golden.measurement.json: the source's, initrd_sha256
#      replaced, plus `initrd_rebuild` provenance — the shape
#      vali_swap_vm_initrd reads — and a `guest_release` object) to
#      --output-dir, and with --output-prefix upload it to a NEW, EMPTY S3
#      prefix (read back after upload). The source prefix is never written.
#
# Exit: 0 ok, 2 usage, 3 refused (a check failed), 4 build failure.
#
# ── Operator note: one-off k8s Job (control-plane cluster, namespace vali)
# Same shape as the initrd-rebuild Job in scripts/tenant-initrd-rebuild.sh
# (baker image built from the release COMMIT, the vali-s3 creds, an
# emptyDir work volume), with:
#   command: ["/usr/local/bin/guest/guest-initrd-build.sh"]
#   args: ["--source-prefix", "s3://hippius-compute-images/tenant/<base prefix>/",
#          "--source-bake-id", "<TenantBake.bake_id>",
#          "--expect-initrd-sha256", "<the base initrd sha>",
#          "--build-release", "--commit", "<COMMIT>", "--source-date-epoch", "<commit time>",
#          "--output-dir", "/work/out",
#          "--output-prefix", "s3://hippius-compute-images/tenant/<base prefix>-gr<version>-<short>/"]
# It needs no privilege, no loop device and no network beyond S3. Read the
# result from the log (`GUEST INITRD OK initrd_sha256=...`) or the
# uploaded golden.measurement.json. Re-running the Job with the same source
# + image prints the same sha.
# Hand the RELATIVE prefix to vali:
#   vali_swap_vm_initrd --vm-id <vm> --from-s3-prefix tenant/<base prefix>-gr<version>-<short>
#
# CI: scripts/dev/guest-initrd-build-test.sh (fixtures, root-free).
set -euo pipefail

PROG="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/${PROG}"

log() { printf '%s: %s\n' "${PROG}" "$*" >&2; }
die() { printf '%s: FATAL: %s\n' "${PROG}" "$*" >&2; exit 3; }
usage_die() { printf '%s: %s\n' "${PROG}" "$*" >&2; exit 2; }
build_die() { printf '%s: BUILD FAILED: %s\n' "${PROG}" "$*" >&2; exit 4; }

usage() {
    cat <<EOF
Usage: ${PROG} (--source-prefix s3://B/P/ | --source-dir DIR) --source-bake-id ID
               (--release-dir DIR | --build-release --commit SHA --source-date-epoch N
                                    [--bin-dir DIR] [--busybox PATH])
               --output-dir DIR [--output-prefix s3://B/P2/] [options]

  --source-prefix URI        S3 prefix of the base set (read only)
  --source-dir DIR           local dir holding the same five files instead
  --source-bake-id ID        vali TenantBake.bake_id of the base (recorded)
  --release-dir DIR          a build-guest-release.sh output directory
  --build-release            build the release here (build-guest-release.sh)
    --commit SHA             ... the 40-hex commit it is cut from
    --source-date-epoch N    ... its timestamp (the commit time)
    --bin-dir DIR            ... agents + release binaries (default /usr/sbin)
    --busybox PATH           ... a static busybox (default /usr/bin/busybox)
  --family F                 initramfs-tools | dracut (default: detected)
  --output-dir DIR           where the output set is written (absent or empty)
  --output-prefix URI        upload it here: a NEW, EMPTY prefix, disjoint
                             from the source prefix
  --expect-kernel-sha256 H / --expect-initrd-sha256 H /
  --expect-rootfs-img-sha256 H / --expect-rootfs-verity-sha256 H
                             pin the source artifacts beyond its measurement
  --work-dir DIR             scratch (default: mktemp under \$TMPDIR)
EOF
}

source_prefix=""
source_dir=""
source_bake_id=""
release_dir=""
build_release=0
commit=""
sde=""
bin_dir="/usr/sbin"
busybox="/usr/bin/busybox"
family=""
output_dir=""
output_prefix=""
expect_kernel=""
expect_initrd=""
expect_rootfs_img=""
expect_rootfs_verity=""
work_dir=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --source-prefix) source_prefix="${2:?}"; shift 2 ;;
        --source-dir) source_dir="${2:?}"; shift 2 ;;
        --source-bake-id) source_bake_id="${2:?}"; shift 2 ;;
        --release-dir) release_dir="${2:?}"; shift 2 ;;
        --build-release) build_release=1; shift ;;
        --commit) commit="${2:?}"; shift 2 ;;
        --source-date-epoch) sde="${2:?}"; shift 2 ;;
        --bin-dir) bin_dir="${2:?}"; shift 2 ;;
        --busybox) busybox="${2:?}"; shift 2 ;;
        --family) family="${2:?}"; shift 2 ;;
        --output-dir) output_dir="${2:?}"; shift 2 ;;
        --output-prefix) output_prefix="${2:?}"; shift 2 ;;
        --expect-kernel-sha256) expect_kernel="${2:?}"; shift 2 ;;
        --expect-initrd-sha256) expect_initrd="${2:?}"; shift 2 ;;
        --expect-rootfs-img-sha256) expect_rootfs_img="${2:?}"; shift 2 ;;
        --expect-rootfs-verity-sha256) expect_rootfs_verity="${2:?}"; shift 2 ;;
        --work-dir) work_dir="${2:?}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; usage_die "unknown argument: $1" ;;
    esac
done

[[ -n "${source_prefix}" || -n "${source_dir}" ]] || usage_die "one of --source-prefix / --source-dir is required"
[[ -z "${source_prefix}" || -z "${source_dir}" ]] || usage_die "--source-prefix and --source-dir are mutually exclusive"
[[ -n "${source_bake_id}" ]] || usage_die "--source-bake-id is required"
[[ -n "${output_dir}" ]] || usage_die "--output-dir is required"
if [[ ${build_release} -eq 1 ]]; then
    [[ -z "${release_dir}" ]] || usage_die "--release-dir and --build-release are mutually exclusive"
    [[ -n "${commit}" && -n "${sde}" ]] || usage_die "--build-release needs --commit and --source-date-epoch"
else
    [[ -n "${release_dir}" ]] || usage_die "one of --release-dir / --build-release is required"
fi
[[ -z "${family}" || "${family}" == initramfs-tools || "${family}" == dracut ]] \
    || usage_die "--family must be initramfs-tools or dracut"
for h in "${expect_kernel}" "${expect_initrd}" "${expect_rootfs_img}" "${expect_rootfs_verity}"; do
    [[ -z "${h}" || "${h}" =~ ^[0-9a-f]{64}$ ]] || usage_die "--expect-*-sha256 must be 64 lowercase hex: ${h}"
done

norm_prefix() {
    local p="$1"
    [[ "${p}" =~ ^s3://[^/]+/.+ ]] || usage_die "not an s3://bucket/prefix URI: ${p}"
    printf '%s/\n' "${p%/}"
}
[[ -z "${source_prefix}" ]] || source_prefix="$(norm_prefix "${source_prefix}")"
[[ -z "${output_prefix}" ]] || output_prefix="$(norm_prefix "${output_prefix}")"
out_bucket=""
out_key=""
if [[ -n "${output_prefix}" ]]; then
    [[ -n "${source_prefix}" ]] || usage_die "--output-prefix needs --source-prefix (the source location is recorded)"
    case "${output_prefix}" in "${source_prefix}"*) die "--output-prefix ${output_prefix} is inside the source prefix ${source_prefix}" ;; esac
    case "${source_prefix}" in "${output_prefix}"*) die "--output-prefix ${output_prefix} contains the source prefix ${source_prefix}" ;; esac
    out_bucket="${output_prefix#s3://}"; out_bucket="${out_bucket%%/*}"
    out_key="${output_prefix#s3://"${out_bucket}"/}"; out_key="${out_key%/}"
    src_bucket="${source_prefix#s3://}"; src_bucket="${src_bucket%%/*}"
    # A VM's launch record keeps its bucket; a swap only moves its prefix.
    [[ "${out_bucket}" == "${src_bucket}" ]] \
        || die "--output-prefix is in bucket ${out_bucket}, the base in ${src_bucket}: a swap cannot change a VM's bucket"
fi
for tool in sha256sum jq python3; do
    command -v "${tool}" >/dev/null 2>&1 || usage_die "${tool} not on PATH"
done
if [[ -n "${source_prefix}${output_prefix}" ]]; then
    command -v aws >/dev/null 2>&1 || usage_die "aws not on PATH (needed for S3)"
fi
if [[ -e "${output_dir}" ]]; then
    [[ -d "${output_dir}" && -z "$(ls -A "${output_dir}")" ]] || usage_die "--output-dir must not exist or be empty"
fi

if [[ -z "${work_dir}" ]]; then
    work_dir="$(mktemp -d "${TMPDIR:-/tmp}/guest-initrd-build.XXXXXX")"
else
    [[ ! -e "${work_dir}" || -z "$(ls -A "${work_dir}" 2>/dev/null)" ]] \
        || usage_die "--work-dir ${work_dir} is not empty — use a fresh one"
    mkdir -p "${work_dir}"
fi
SRC="${work_dir}/src"
mkdir -p "${SRC}" "${output_dir}"
output_dir="$(cd "${output_dir}" && pwd)"
if [[ -z "${AWS_CONFIG_FILE:-}" ]]; then
    printf '[default]\ns3 =\n    addressing_style = path\n' > "${work_dir}/aws-config"
    export AWS_CONFIG_FILE="${work_dir}/aws-config"
fi
sha_of() { sha256sum "$1" | cut -d' ' -f1; }
CHECK="${SCRIPT_DIR}/initrd-merge-check.py"
[[ -r "${CHECK}" ]] || die "missing ${CHECK}"

# ── 1. Fetch + verify the source set ────────────────────────────────
ARTIFACTS=(tenant.vmlinuz tenant.initrd.img rootfs.img rootfs.verity golden.measurement.json)
if [[ -n "${source_prefix}" ]]; then
    log "fetching the base set ${source_prefix} (read-only)"
    for a in "${ARTIFACTS[@]}"; do
        fetched=0
        for attempt in 1 2 3; do
            if aws s3 cp --only-show-errors "${source_prefix}${a}" "${SRC}/${a}"; then
                fetched=1; break
            fi
            log "fetch ${a} failed (attempt ${attempt}/3)"
            sleep $((attempt * 5))
        done
        [[ ${fetched} -eq 1 ]] || die "could not fetch ${source_prefix}${a}"
    done
    source_location="${source_prefix}"
else
    for a in "${ARTIFACTS[@]}"; do
        [[ -f "${source_dir}/${a}" ]] || die "source dir ${source_dir} has no ${a}"
        cp "${source_dir}/${a}" "${SRC}/${a}"
    done
    source_location="$(cd "${source_dir}" && pwd)"
fi
M_SRC="${SRC}/golden.measurement.json"
jq -e 'type == "object"' "${M_SRC}" >/dev/null 2>&1 || die "source golden.measurement.json is not a JSON object"
[[ "$(jq -r '.disk_mode // empty' "${M_SRC}")" == golden_verity_overlay ]] \
    || die "the source is not a golden_verity_overlay set"
if jq -e 'has("guest_release") or (.initrd_rebuild.method? == "append-guest-release")' "${M_SRC}" >/dev/null; then
    die "the source initrd is itself a guest release build — releases are appended to the base initrd, never chained (use the base's own set)"
fi
check_artifact() {
    local file="$1" key="$2" pin="$3" want got
    want="$(jq -r --arg k "${key}" '.[$k] // empty' "${M_SRC}")"
    [[ "${want}" =~ ^[0-9a-f]{64}$ ]] || die "source measurement.json has no 64-hex ${key}"
    got="$(sha_of "${SRC}/${file}")"
    [[ "${got}" == "${want}" ]] || die "${file}: sha256 ${got} does not match the source measurement ${key}=${want}"
    [[ -z "${pin}" || "${got}" == "${pin}" ]] || die "${file}: sha256 ${got} does not match the pinned --expect value ${pin}"
    printf '%s' "${got}"
}
kernel_sha="$(check_artifact tenant.vmlinuz kernel_sha256 "${expect_kernel}")"
src_initrd_sha="$(check_artifact tenant.initrd.img initrd_sha256 "${expect_initrd}")"
rootfs_img_sha="$(check_artifact rootfs.img rootfs_img_sha256 "${expect_rootfs_img}")"
rootfs_verity_sha="$(check_artifact rootfs.verity rootfs_verity_sha256 "${expect_rootfs_verity}")"
src_measurement_sha="$(sha_of "${M_SRC}")"
log "base set matches its measurement: kernel=${kernel_sha} initrd=${src_initrd_sha}"

# ── 2. The release ──────────────────────────────────────────────────
if [[ ${build_release} -eq 1 ]]; then
    release_dir="${work_dir}/release"
    "${SCRIPT_DIR}/build-guest-release.sh" --bin-dir "${bin_dir}" --busybox "${busybox}" \
        --commit "${commit}" --source-date-epoch "${sde}" --out "${release_dir}" \
        || build_die "build-guest-release.sh"
fi
for f in release.json release-initramfs-tools.cpio release-initramfs-tools.manifest \
         release-dracut.cpio release-dracut.manifest; do
    [[ -r "${release_dir}/${f}" ]] || die "--release-dir ${release_dir} has no ${f}"
done
R_JSON="${release_dir}/release.json"
for fam in initramfs-tools dracut; do
    want="$(jq -r --arg f "${fam}" '.cpio_sha256[$f] // empty' "${R_JSON}")"
    [[ "$(sha_of "${release_dir}/release-${fam}.cpio")" == "${want}" ]] \
        || die "release-${fam}.cpio does not match release.json"
done

# ── 3. The boot step needs the loop driver ──────────────────────────
# The components image is loop-mounted. `loop` must be built into the
# base's kernel or be a module the base ships (the step loads it from the
# verity-checked lower when the initrd lacks it). Read from the base's own
# module metadata for the kernel the set boots.
kver="$(python3 - "${SRC}/tenant.vmlinuz" <<'PY_KVER'
import re, struct, sys
d = open(sys.argv[1], "rb").read()
if len(d) < 0x210 or d[0x202:0x206] != b"HdrS":
    sys.exit("tenant.vmlinuz is not a bzImage")
off = struct.unpack("<H", d[0x20E:0x210])[0]
s = d[off + 0x200:off + 0x200 + 256].split(b"\0", 1)[0].decode("ascii", "replace")
kver = s.split(" ", 1)[0]
if not off or not re.fullmatch(r"[0-9][0-9A-Za-z.+_~-]*", kver):
    sys.exit("tenant.vmlinuz carries no kernel version")
print(kver)
PY_KVER
)" || die "cannot read the kernel version from tenant.vmlinuz"
command -v unsquashfs >/dev/null 2>&1 || usage_die "unsquashfs not on PATH"
MODS="${work_dir}/modules"
loop_ok=""
for d in "usr/lib/modules/${kver}" "lib/modules/${kver}"; do
    unsquashfs -no-xattrs -q -d "${MODS}" "${SRC}/rootfs.img" "${d}/modules.builtin" "${d}/modules.dep"         >/dev/null 2>&1 || true
    [[ -f "${MODS}/${d}/modules.builtin" ]] || continue
    if grep -qE '(^|/)loop\.ko$' "${MODS}/${d}/modules.builtin"; then
        loop_ok="built-in"
    elif [[ -f "${MODS}/${d}/modules.dep" ]]; then
        # A module: listed in modules.dep AND present in the base (the
        # boot step's `modprobe -d <lower> loop` loads it from there).
        mod="$(grep -oE '^kernel/drivers/block/loop\.ko(\.(xz|zst|gz))?:' "${MODS}/${d}/modules.dep" | head -n1 || true)"
        mod="${mod%:}"
        if [[ -n "${mod}" ]] && unsquashfs -no-xattrs -q -d "${MODS}/m" "${SRC}/rootfs.img" "${d}/${mod}" \
            >/dev/null 2>&1 && [[ -s "${MODS}/m/${d}/${mod}" ]]; then
            loop_ok="module"
        fi
    fi
    break
done
[[ -n "${loop_ok}" ]] \
    || die "the base kernel ${kver} has no loop driver (neither built in nor a module in the base) — the components image could not be mounted"
log "base kernel ${kver}: loop driver ${loop_ok}"

# ── 4. Family + merge check ─────────────────────────────────────────
detected="$(python3 "${CHECK}" --base "${SRC}/tenant.initrd.img" --detect-family)" \
    || die "cannot tell the base initrd's family"
if [[ -n "${family}" && "${family}" != "${detected}" ]]; then
    die "--family ${family} but the base initrd is ${detected}"
fi
family="${detected}"
log "base initrd family: ${family}"
NEW_INITRD="${output_dir}/tenant.initrd.img"
# A loop MODULE is loaded by the initrd's own modprobe: it must have one.
extra_needs=()
[[ "${loop_ok}" == module ]] && extra_needs=(--need modprobe)
python3 "${CHECK}" --base "${SRC}/tenant.initrd.img" \
    --release "${release_dir}/release-${family}.cpio" \
    --manifest "${release_dir}/release-${family}.manifest" "${extra_needs[@]}" \
    --out "${NEW_INITRD}" >&2 \
    || die "the release does not merge cleanly over this base initrd (see above)"
new_initrd_sha="$(sha_of "${NEW_INITRD}")"
# The appended layout, byte for byte.
base_len="$(stat -c '%s' "${SRC}/tenant.initrd.img")"
pad=$(( (4 - base_len % 4) % 4 ))
cmp -s <(head -c "${base_len}" "${NEW_INITRD}") "${SRC}/tenant.initrd.img" || die "the new initrd does not start with the base initrd"
cmp -s <(tail -c +$((base_len + pad + 1)) "${NEW_INITRD}") "${release_dir}/release-${family}.cpio" \
    || die "the new initrd does not end with the release member"

# ── 5. Output set ───────────────────────────────────────────────────
for a in tenant.vmlinuz rootfs.img rootfs.verity; do
    cp "${SRC}/${a}" "${output_dir}/${a}"
done
jq \
    --arg initrd_sha "${new_initrd_sha}" \
    --arg bake_id "${source_bake_id}" \
    --arg src "${source_location}" \
    --arg src_initrd "${src_initrd_sha}" \
    --arg src_meas "${src_measurement_sha}" \
    --arg family "${family}" \
    --arg tool_sha "$(sha_of "${SCRIPT_PATH}")" \
    --argjson pad "${pad}" \
    --arg out_bucket "${out_bucket}" \
    --arg out_key "${out_key}" \
    --slurpfile rel "${R_JSON}" \
    '.initrd_sha256 = $initrd_sha
     | .initrd_rebuild = {
         source_bake_id: $bake_id,
         source_location: $src,
         source_initrd_sha256: $src_initrd,
         source_measurement_sha256: $src_meas,
         repo_commit: $rel[0].commit,
         family: $family,
         method: "append-guest-release",
         tool: "scripts/guest/guest-initrd-build.sh",
         tool_sha256: $tool_sha
       }
     | .guest_release = {
         version: $rel[0].version,
         security_epoch: $rel[0].security_epoch,
         health_mask: ($rel[0].health_mask // 0),
         commit: $rel[0].commit,
         squashfs_sha256: $rel[0].squashfs_sha256,
         release_cpio_sha256: $rel[0].cpio_sha256[$family],
         family: $family,
         pad_bytes: $pad
       }
     # Where THIS set lives (vali_swap_vm_initrd checks it against the
     # prefix it reads): the output, never the base it was built from.
     | del(.s3_bucket, .s3_key_prefix)
     | if $out_key != "" then .s3_bucket = $out_bucket | .s3_key_prefix = $out_key else . end
    ' "${M_SRC}" > "${output_dir}/golden.measurement.json"
[[ "$(sha_of "${output_dir}/tenant.vmlinuz")" == "${kernel_sha}" ]] || die "output tenant.vmlinuz is not the base kernel"
[[ "$(sha_of "${output_dir}/rootfs.img")" == "${rootfs_img_sha}" ]] || die "output rootfs.img is not the base rootfs.img"
[[ "$(sha_of "${output_dir}/rootfs.verity")" == "${rootfs_verity_sha}" ]] || die "output rootfs.verity is not the base rootfs.verity"
[[ "$(sha_of "${NEW_INITRD}")" == "${new_initrd_sha}" ]] || die "output tenant.initrd.img changed after the check"
log "output set in ${output_dir}:"
(cd "${output_dir}" && sha256sum "${ARTIFACTS[@]}") | sed 's/^/    /' >&2

# ── 6. Upload to a NEW prefix ───────────────────────────────────────
# One writer per prefix: a claim object created with If-None-Match: *
# (an atomic create) before anything else, so two builds aimed at the same
# prefix cannot both pass the emptiness check and overwrite each other.
# Every payload is read back and its sha compared BEFORE the measurement
# is written; the measurement — what makes the prefix usable — goes last
# (also a conditional create) and is read back too. A failure anywhere
# leaves a prefix without a measurement, which nothing consumes.
if [[ -n "${output_prefix}" ]]; then
    put_new() {
        # put_new <local file> <key>: create <key>, refused if it exists.
        aws s3api put-object --bucket "${out_bucket}" --key "$2" --body "$1" --if-none-match '*' >/dev/null
    }
    readback_sha() {
        # readback_sha <key> <local file>: the remote bytes' sha == local's.
        rm -f "${work_dir}/readback.tmp"
        aws s3 cp --only-show-errors "s3://${out_bucket}/$1" "${work_dir}/readback.tmp" \
            || die "read-back of s3://${out_bucket}/$1 failed"
        [[ "$(sha_of "${work_dir}/readback.tmp")" == "$(sha_of "$2")" ]] \
            || die "s3://${out_bucket}/$1: read-back sha differs from the uploaded file"
        rm -f "${work_dir}/readback.tmp"
    }
    nkeys="$(aws s3api list-objects-v2 --bucket "${out_bucket}" --prefix "${out_key}/" --max-keys 1 \
        --query 'KeyCount' --output text)" \
        || die "cannot list ${output_prefix} — refusing to write to a prefix whose emptiness is unknown"
    [[ "${nkeys}" == "0" ]] || die "--output-prefix ${output_prefix} is not empty — never overwrite a prefix"
    printf 'guest-initrd-build claim\nsource=%s\nrelease=%s\n' "${source_location}" "$(jq -r .commit "${R_JSON}")" \
        > "${work_dir}/claim"
    put_new "${work_dir}/claim" "${out_key}/.claim" \
        || die "could not claim ${output_prefix} (another build holds it, or the store refused a conditional create)"
    for a in tenant.vmlinuz rootfs.img rootfs.verity tenant.initrd.img; do
        log "upload ${output_prefix}${a}"
        aws s3 cp --only-show-errors "${output_dir}/${a}" "${output_prefix}${a}" || die "upload of ${a} failed"
        readback_sha "${out_key}/${a}" "${output_dir}/${a}"
    done
    log "upload ${output_prefix}golden.measurement.json (last)"
    put_new "${output_dir}/golden.measurement.json" "${out_key}/golden.measurement.json" \
        || die "could not create ${output_prefix}golden.measurement.json"
    readback_sha "${out_key}/golden.measurement.json" "${output_dir}/golden.measurement.json"
    log "uploaded to ${output_prefix} (every object read back)"
fi

echo "GUEST INITRD OK initrd_sha256=${new_initrd_sha} source_initrd_sha256=${src_initrd_sha} family=${family} release_version=$(jq -r .version "${R_JSON}") security_epoch=$(jq -r .security_epoch "${R_JSON}") commit=$(jq -r .commit "${R_JSON}") source_bake_id=${source_bake_id}"
