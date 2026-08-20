#!/usr/bin/env bash
#
# `tenant-image-from-rootfs.sh` — Stage 2 of the split bake pipeline
# (`scripts/tenant-rootfs-build.sh` is Stage 1).
#
# Consumes a `(rootfs.tar.zst, vmlinuz, initrd.img, manifest.json)`
# produced by Stage 1 plus a per-tenant LUKS KEK, and produces a
# fresh LUKS-encrypted qcow2 + measurement.json.
#
# Security model:
#   - Stage 1's manifest is content-addressable. This script verifies
#     the SHAs of rootfs.tar.zst + vmlinuz + initrd.img against the
#     manifest BEFORE touching them. A tampered tarball that doesn't
#     match the manifest is rejected here. (Signing the manifest with
#     an offline operator key is a follow-up.)
#   - Every per-tenant launch gets a FRESH LUKS master key via
#     `luksFormat --integrity hmac-sha256`. Two tenants sharing the
#     same Stage 1 manifest do NOT share encryption material — the
#     LUKS volume key is independent per tenant.
#   - The KEK never lands in a file the bake writes (same §20
#     discipline as the legacy `tenant-image-bake.sh`).
#
# Output (in --output-dir):
#   tenant-<vm_id>-<base12>.qcow2           per-tenant LUKS-encrypted qcow2
#   tenant-<vm_id>-<base12>.vmlinuz         copy from manifest
#   tenant-<vm_id>-<base12>.initrd.img      copy from manifest
#   tenant-<vm_id>-<base12>.measurement.json   SHAs + LUKS header digest
#
# The `<vm_id>` infix is required (audit follow-up Gemini #5 /
# Codex #3) so two operators baking different tenants in parallel
# can't overwrite each other's outputs.

set -Eeuo pipefail

cleanup() {
    local rc=$?
    set +e
    if [[ -n "${MAPPER_OPEN:-}" ]]; then
        sudo cryptsetup close ${mapper_name} 2>/dev/null || true
    fi
    if [[ -n "${LOOP_DEV:-}" ]]; then
        sudo umount -R "${MNT_ROOT:-}" 2>/dev/null || true
        sudo losetup -d "${LOOP_DEV}" 2>/dev/null || true
    fi
    if [[ -n "${WORK_DIR:-}" && -d "${WORK_DIR}" ]]; then
        sudo rm -rf -- "${WORK_DIR}"
    fi
    if [[ -n "${KEK_TMPFS_DIR:-}" && -d "${KEK_TMPFS_DIR}" ]]; then
        sudo shred -u -- "${KEK_TMPFS_DIR}"/* 2>/dev/null || true
        sudo rm -rf -- "${KEK_TMPFS_DIR}"
    fi
    exit "$rc"
}
trap cleanup EXIT

PROG="$(basename "$0")"

rootfs_dir=""
manifest=""
output_dir="${HCC_BAKE_OUTPUT_DIR:-./out/tenant-bake}"
output_qcow2_gb=""
flavor=""
kek_source="stdin"
kek_file=""
vm_id=""
# Audit follow-up (Gemini #2 / Codex #1): pin the manifest's
# detached Ed25519 signature against an operator-supplied verifying
# key BEFORE trusting any SHA in the manifest. Either flag is
# accepted; supplying both is rejected. Production posture: required.
# Dev posture: optional (legacy bake produced unsigned manifests).
verify_pubkey_hex=""
verify_pubkey_file=""
# Unique mapper-device name suffix. Two operators running Stage 2 in
# parallel on the same host collide on a hardcoded /dev/mapper/<name>
# (Gemini audit finding #5), so the mapper name embeds a per-bake
# random suffix. `$$` is the PID, $(date +%s%N) is nanosecond epoch —
# combined collision risk is astronomical.
mapper_name="hippius-bake-$$-$(date +%s%N 2>/dev/null || echo $$)"

log() { printf '%s: %s\n' "${PROG}" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

usage() {
    cat >&2 <<EOF
${PROG} — Stage 2: fresh per-tenant LUKS qcow2 from a Stage 1 rootfs.

Usage:
  ${PROG} --rootfs-dir DIR --vm-id ID \\
          [--output-dir DIR] [--output-qcow2-gb N | --flavor NAME] \\
          [--kek-source stdin|file] [--kek-file PATH]

Required:
  --vm-id ID              Per-tenant identifier embedded into every
                          output filename so parallel bakes on the
                          same workstation do not overwrite each
                          other (Gemini / Codex audit finding #5).
                          Restricted to [a-z0-9_-]{1,64} to keep the
                          filename safe.
  --rootfs-dir DIR        Stage 1 output directory containing:
                            rootfs.tar.zst
                            vmlinuz
                            initrd.img
                            manifest.json

Optional:
  --output-dir DIR        Default \$HCC_BAKE_OUTPUT_DIR, else
                          \`./out/tenant-bake\`. Same default as the
                          legacy bake.
  --output-qcow2-gb N     Final qcow2 virtual size in GiB. Either
                          this or --flavor is required. Must be large
                          enough to fit the rootfs tarball expanded
                          plus the LUKS2 header + integrity overhead
                          (~7 % under \`--integrity hmac-sha256\`).
  --flavor NAME           small | medium | large. Resolves --output-
                          qcow2-gb from the catalogue (matches
                          \`hippius_types::flavor::Flavor::disk_gb()\`):
                            small  → 8  GiB
                            medium → 16 GiB
                            large  → 32 GiB
                          Must agree with the manifest's flavor field
                          (Stage 1 records what it built for; Stage 2
                          refuses to bake a small qcow2 from a large
                          manifest, etc.).
  --kek-source SRC        stdin (default) or file.
  --kek-file PATH         Required with --kek-source=file.
  --verify-pubkey-hex HEX 64 lowercase hex chars — the Ed25519
                          verifying key pinned out-of-band by the
                          operator. When set, the script reads
                          \`manifest.json.sig\` from --rootfs-dir
                          and verifies the detached signature BEFORE
                          trusting any SHA from the manifest. Audit
                          follow-up (Gemini #2 / Codex #1).
  --verify-pubkey-file P  Same as --verify-pubkey-hex but the hex is
                          read from a file (matches the
                          \`.pub\` shape next to the signing seed).
                          Mutually exclusive with --verify-pubkey-hex.
  -h, --help              Show this header.

Output (in --output-dir):
  tenant-<vm_id>-<base12>.qcow2, .vmlinuz, .initrd.img, .measurement.json

Exit codes:
  0  success
  1  usage error
  2  host tooling missing
  3  bake step failed
  4  manifest verification failed
EOF
}

require_arg() { [[ -n "${2-}" ]] || die "$1 requires a value"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rootfs-dir)           require_arg "$1" "${2-}"; rootfs_dir="$2";           shift 2;;
        --vm-id)                require_arg "$1" "${2-}"; vm_id="$2";                shift 2;;
        --verify-pubkey-hex)    require_arg "$1" "${2-}"; verify_pubkey_hex="$2";    shift 2;;
        --verify-pubkey-file)   require_arg "$1" "${2-}"; verify_pubkey_file="$2";   shift 2;;
        --output-dir)           require_arg "$1" "${2-}"; output_dir="$2";           shift 2;;
        --output-qcow2-gb)      require_arg "$1" "${2-}"; output_qcow2_gb="$2";      shift 2;;
        --flavor)               require_arg "$1" "${2-}"; flavor="$2";               shift 2;;
        --kek-source)           require_arg "$1" "${2-}"; kek_source="$2";           shift 2;;
        --kek-file)             require_arg "$1" "${2-}"; kek_file="$2";             shift 2;;
        -h|--help)              usage; exit 0;;
        *) die "unknown argument: $1 (try --help)";;
    esac
done

[[ -n "${rootfs_dir}" ]] || { usage; die "--rootfs-dir is required"; }
[[ -n "${vm_id}" ]] || { usage; die "--vm-id is required (audit follow-up — parallel bakes collide on shared output names)"; }
# Restrict vm_id to a safe shape so it can ride into filenames + libvirt
# domain names without escaping concerns. Mirrors the miner-agent's
# `VmId::new` validator: lowercase ASCII alphanumeric + dash/underscore,
# 1-64 chars.
if [[ ! "${vm_id}" =~ ^[a-z0-9_-]{1,64}$ ]]; then
    die "--vm-id must match ^[a-z0-9_-]{1,64}\$ (got '${vm_id}')"
fi
[[ -d "${rootfs_dir}" ]] || die "${rootfs_dir}: not a directory"
manifest="${rootfs_dir}/manifest.json"
rootfs_tar="${rootfs_dir}/rootfs.tar.zst"
src_kernel="${rootfs_dir}/vmlinuz"
src_initrd="${rootfs_dir}/initrd.img"
[[ -r "${manifest}" ]]    || die "${manifest}: not readable"
[[ -r "${rootfs_tar}" ]]  || die "${rootfs_tar}: not readable"
[[ -r "${src_kernel}" ]]  || die "${src_kernel}: not readable"
[[ -r "${src_initrd}" ]]  || die "${src_initrd}: not readable"

case "${flavor}" in
    "")        ;;
    small)     output_qcow2_gb="${output_qcow2_gb:-8}"  ;;
    medium)    output_qcow2_gb="${output_qcow2_gb:-16}" ;;
    large)     output_qcow2_gb="${output_qcow2_gb:-32}" ;;
    *) die "--flavor must be one of: small, medium, large (got '${flavor}')";;
esac
[[ -n "${output_qcow2_gb}" ]] || die "either --output-qcow2-gb or --flavor is required"
[[ "${output_qcow2_gb}" =~ ^[1-9][0-9]*$ ]] || die "--output-qcow2-gb must be a positive integer"

case "${kek_source}" in
    stdin|file) ;;
    *) die "--kek-source must be stdin or file (got '${kek_source}')";;
esac
if [[ "${kek_source}" == "file" ]]; then
    [[ -n "${kek_file}" && -r "${kek_file}" ]] \
        || die "--kek-source=file needs --kek-file PATH (readable)"
fi

missing=()
for tool in jq sha256sum qemu-img cryptsetup losetup mount umount dd e2fsck resize2fs mkfs.ext4 tar zstd shred findmnt openssl; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if (( ${#missing[@]} > 0 )); then
    log "missing host tools: ${missing[*]}"
    log "install qemu-utils + cryptsetup-bin + coreutils + jq + e2fsprogs + zstd"
    exit 2
fi

# ── 1. Verify manifest signature (audit follow-up Gemini #2 / Codex #1) ─
#
# The manifest's SHAs only protect against silent S3 corruption — an
# attacker who can write the bucket can swap the tarball AND the
# manifest atomically and Stage 2 would happily extract the malicious
# rootfs. Without this gate, the SEV-SNP measurement still verifies
# (kernel + initrd are the same) but the userspace running inside
# the LUKS volume is whatever the attacker chose.
#
# `--verify-pubkey-hex` / `--verify-pubkey-file` pin the operator's
# Ed25519 verifying key out-of-band. The matching signing key is
# offline. When neither flag is supplied (dev posture), the script
# logs a loud warning and falls through to the legacy SHA-only path;
# production deployments should make these flags mandatory in their
# operator runbook + CI gate.
if [[ -n "${verify_pubkey_hex}" && -n "${verify_pubkey_file}" ]]; then
    die "--verify-pubkey-hex and --verify-pubkey-file are mutually exclusive (exit 1)"
fi
manifest_sig="${rootfs_dir}/manifest.json.sig"
if [[ -n "${verify_pubkey_hex}" || -n "${verify_pubkey_file}" ]]; then
    [[ -r "${manifest_sig}" ]] || die "${manifest_sig}: not readable — Stage 1 must have been run with --signing-key (exit 4)"
    log "verifying manifest signature against the pinned operator key"
    SCRIPT_DIR_S2="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -n "${verify_pubkey_hex}" ]]; then
        "${SCRIPT_DIR_S2}/sign-manifest.py" verify \
            --manifest "${manifest}" \
            --sig "${manifest_sig}" \
            --verify-pubkey-hex "${verify_pubkey_hex}" \
            || die "manifest signature verification failed (exit 4)"
    else
        "${SCRIPT_DIR_S2}/sign-manifest.py" verify \
            --manifest "${manifest}" \
            --sig "${manifest_sig}" \
            --verify-pubkey-file "${verify_pubkey_file}" \
            || die "manifest signature verification failed (exit 4)"
    fi
    log "manifest signature verified"
else
    log "WARN: no --verify-pubkey-{hex,file} supplied — dev posture, manifest signature NOT verified (see audit Gemini #2 / Codex #1)"
fi

# ── 2. Verify manifest SHAs ─────────────────────────────────────────

want_rootfs_sha=$(jq -r '.rootfs_tar_zst_sha256' "${manifest}")
want_kernel_sha=$(jq -r '.kernel_sha256'         "${manifest}")
want_initrd_sha=$(jq -r '.initrd_sha256'         "${manifest}")
want_flavor=$(jq -r '.flavor // ""'              "${manifest}")
base_image_sha256=$(jq -r '.base_image_sha256'   "${manifest}")
base_image_url=$(jq -r '.base_image_url'         "${manifest}")
kbs_url=$(jq -r '.kbs_url'                       "${manifest}")
schema_version=$(jq -r '.schema_version // 0'    "${manifest}")
[[ "${schema_version}" == "1" ]] || die "manifest schema_version=${schema_version} (expected 1) (exit 4)"
[[ "${want_rootfs_sha}" =~ ^[0-9a-f]{64}$ ]] || die "manifest missing rootfs_tar_zst_sha256 (exit 4)"
[[ "${want_kernel_sha}" =~ ^[0-9a-f]{64}$ ]] || die "manifest missing kernel_sha256 (exit 4)"
[[ "${want_initrd_sha}" =~ ^[0-9a-f]{64}$ ]] || die "manifest missing initrd_sha256 (exit 4)"

have_rootfs_sha=$(sha256sum "${rootfs_tar}" | cut -d' ' -f1)
have_kernel_sha=$(sha256sum "${src_kernel}" | cut -d' ' -f1)
have_initrd_sha=$(sha256sum "${src_initrd}" | cut -d' ' -f1)
[[ "${have_rootfs_sha}" == "${want_rootfs_sha}" ]] \
    || die "rootfs.tar.zst sha mismatch: want=${want_rootfs_sha} have=${have_rootfs_sha} (exit 4)"
[[ "${have_kernel_sha}" == "${want_kernel_sha}" ]] \
    || die "vmlinuz sha mismatch: want=${want_kernel_sha} have=${have_kernel_sha} (exit 4)"
[[ "${have_initrd_sha}" == "${want_initrd_sha}" ]] \
    || die "initrd.img sha mismatch: want=${want_initrd_sha} have=${have_initrd_sha} (exit 4)"

if [[ -n "${flavor}" && -n "${want_flavor}" && "${flavor}" != "${want_flavor}" ]]; then
    die "--flavor ${flavor} disagrees with manifest flavor ${want_flavor} (exit 4)"
fi
log "manifest verified (base_image_sha256=${base_image_sha256:0:12}, flavor=${want_flavor:-unset})"

# ── 3. Stage KEK on tmpfs ───────────────────────────────────────────

WORK_DIR="$(mktemp -d -t hippius-bake-s2.XXXXXX)"
# §20 secret discipline: the KEK staging dir MUST be on tmpfs so a
# crash/oom-kill doesn't strand 32 bytes of LUKS-unlock material on
# the operator workstation's persistent storage. The legacy script's
# `mktemp -p /dev/shm ... || mktemp -t ...` silently fell back to /tmp
# when /dev/shm was unmounted or noexec (Codex audit finding #6) —
# fail-closed here is the right posture: no /dev/shm, no bake.
if [[ ! -d /dev/shm ]]; then
    die "/dev/shm is unavailable; refusing to stage the KEK on persistent storage (exit 1)"
fi
KEK_TMPFS_DIR="$(mktemp -d -p /dev/shm hippius-bake-kek.XXXXXX)" \
    || die "mktemp under /dev/shm failed; refusing the /tmp fallback (exit 1)"
chmod 0700 "${KEK_TMPFS_DIR}"
# Belt-and-suspenders: even if /dev/shm exists, confirm it's a tmpfs
# (could be a regular dir on a misconfigured host). `findmnt -T` walks
# up the mount tree until it finds the containing FS; we want tmpfs.
fstype="$(findmnt -T "${KEK_TMPFS_DIR}" -no FSTYPE 2>/dev/null || true)"
if [[ "${fstype}" != "tmpfs" ]]; then
    die "KEK staging dir ${KEK_TMPFS_DIR} is not on tmpfs (fstype=${fstype:-unknown}); refusing to write KEK bytes (exit 1)"
fi
kek_buf="${KEK_TMPFS_DIR}/kek.bin"
case "${kek_source}" in
    stdin) cat > "${kek_buf}" ;;
    file)  cp -- "${kek_file}" "${kek_buf}" ;;
esac
chmod 0400 "${kek_buf}"
kek_len=$(stat -c '%s' "${kek_buf}")
if (( kek_len != 32 )); then
    die "KEK must be exactly 32 bytes (got ${kek_len}) (exit 1)"
fi
log "KEK buffered (${kek_len} bytes, tmpfs)"

# ── 4. Fresh LUKS-formatted raw image ───────────────────────────────

output_dir="$(cd "$(dirname "${output_dir}")" 2>/dev/null && pwd)/$(basename "${output_dir}")"
mkdir -p "${output_dir}"

out_qcow2="${output_dir}/tenant-${vm_id}-${base_image_sha256:0:12}.qcow2"
out_raw="${WORK_DIR}/out.raw"
qcow2_bytes=$(( output_qcow2_gb * 1024 * 1024 * 1024 ))
log "allocating output raw image: ${output_qcow2_gb} GiB"
qemu-img create -f raw "${out_raw}" "${qcow2_bytes}" >/dev/null

log "luksFormat output raw (--integrity hmac-sha256; ~2 min/16 GiB on NVMe)"
sudo cryptsetup luksFormat --type luks2 --batch-mode --pbkdf argon2id \
    --integrity hmac-sha256 \
    --key-file="${kek_buf}" "${out_raw}" \
    || die "luksFormat failed (exit 3)"

HEADER_BACKUP="${WORK_DIR}/luks-header.bin"
sudo cryptsetup luksHeaderBackup "${out_raw}" \
    --header-backup-file "${HEADER_BACKUP}" \
    || die "luksHeaderBackup failed (exit 3)"
LUKS_HEADER_SHA256=$(sha256sum "${HEADER_BACKUP}" | awk '{print $1}')
sudo shred -u "${HEADER_BACKUP}" 2>/dev/null || sudo rm -f -- "${HEADER_BACKUP}"
log "LUKS2 header sha256=${LUKS_HEADER_SHA256}"

sudo cryptsetup open --type luks2 --key-file="${kek_buf}" "${out_raw}" ${mapper_name} \
    || die "cryptsetup open failed (exit 3)"
MAPPER_OPEN=1

# ── 5. mkfs ext4 + extract rootfs tarball ───────────────────────────

log "mkfs.ext4 /dev/mapper/${mapper_name}"
sudo mkfs.ext4 -F -q -L cryptroot /dev/mapper/${mapper_name} \
    || die "mkfs.ext4 failed (exit 3)"

MNT_ROOT="${WORK_DIR}/mnt"
mkdir -p "${MNT_ROOT}"
sudo mount /dev/mapper/${mapper_name} "${MNT_ROOT}" \
    || die "mount cryptroot failed (exit 3)"

log "extracting rootfs.tar.zst into cryptroot"
# `sudo zstd -dc <path> | sudo tar -xf -` instead of the legacy
# `sudo bash -c "zstd ... | tar ..."`. The legacy form embedded
# `${rootfs_tar}` + `${MNT_ROOT}` into a SHELL STRING the privileged
# bash interpreted — a path containing a single quote (or `$()`,
# `;`, etc.) became privilege-escalated command injection on the
# operator workstation (Codex audit finding #4). The new form passes
# the paths as ARGV entries to two separately-sudo'd binaries, so
# the shell never sees them as code. `pipefail` is set at the script
# top so a zstd error propagates and `||die` catches it.
sudo zstd -dc -- "${rootfs_tar}" \
    | sudo tar --numeric-owner --xattrs --acls -xf - -C "${MNT_ROOT}" \
    || die "tar extract failed (exit 3)"

sudo umount "${MNT_ROOT}" || die "umount cryptroot failed (exit 3)"
sudo cryptsetup close ${mapper_name}
MAPPER_OPEN=""

# ── 6. Convert raw → qcow2 ──────────────────────────────────────────

# `qemu-img convert` WITHOUT `-c`: the LUKS ciphertext is high-entropy
# so compression saves nothing while slowing the bake substantially,
# and the on-disk size of compressed clusters is an oracle for the
# plaintext's compressibility (Gemini audit finding #10). The legacy
# bake had `-c`; this fix-up drops it.
log "qemu-img convert raw → qcow2"
qemu-img convert -O qcow2 "${out_raw}" "${out_qcow2}" \
    || die "qemu-img convert raw → qcow2 failed (exit 3)"

# ── 7. Copy kernel + initrd into output dir ─────────────────────────

cp "${src_kernel}" "${output_dir}/tenant-${vm_id}-${base_image_sha256:0:12}.vmlinuz"
cp "${src_initrd}" "${output_dir}/tenant-${vm_id}-${base_image_sha256:0:12}.initrd.img"

# ── 8. Emit measurement.json ────────────────────────────────────────

out_sha=$(sha256sum "${out_qcow2}" | cut -d' ' -f1)
out_bytes=$(stat -c '%s' "${out_qcow2}")
kernel_sha=$(sha256sum "${output_dir}/tenant-${vm_id}-${base_image_sha256:0:12}.vmlinuz" | cut -d' ' -f1)
initrd_sha=$(sha256sum "${output_dir}/tenant-${vm_id}-${base_image_sha256:0:12}.initrd.img" | cut -d' ' -f1)

measurement_json="${output_dir}/tenant-${vm_id}-${base_image_sha256:0:12}.measurement.json"
jq -n \
    --arg qcow "${out_qcow2}" \
    --arg qcow_sha "${out_sha}" \
    --argjson qcow_size "${out_bytes}" \
    --arg base_url "${base_image_url}" \
    --arg base_sha "${base_image_sha256}" \
    --arg kbs "${kbs_url}" \
    --arg kernel_sha "${kernel_sha}" \
    --arg initrd_sha "${initrd_sha}" \
    --arg luks_header_sha "${LUKS_HEADER_SHA256}" \
    --arg rootfs_sha "${want_rootfs_sha}" \
    '{
        qcow2_path: $qcow,
        qcow2_sha256: $qcow_sha,
        qcow2_size_bytes: $qcow_size,
        base_image_url: $base_url,
        base_image_sha256: $base_sha,
        kbs_url: $kbs,
        kernel_sha256: $kernel_sha,
        initrd_sha256: $initrd_sha,
        luks_header_sha256: $luks_header_sha,
        luks_version: 2,
        luks_pbkdf: "argon2id",
        rootfs_tar_zst_sha256: $rootfs_sha
     }' > "${measurement_json}"

cat "${measurement_json}"
log "qcow2:        ${out_qcow2}"
log "kernel:       ${output_dir}/tenant-${vm_id}-${base_image_sha256:0:12}.vmlinuz"
log "initrd:       ${output_dir}/tenant-${vm_id}-${base_image_sha256:0:12}.initrd.img"
log "measurement:  ${measurement_json}"
log "STAGE 2 OK — stage the three files to the miner-agent"
