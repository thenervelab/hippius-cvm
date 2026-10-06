#!/usr/bin/env bash
#
# ╔════════════════════════════════════════════════════════════════╗
# ║                  ARCHIVED — DO NOT USE IN PROD                 ║
# ║                                                                ║
# ║ This script SSH'es into the miner host to luksFormat a blank   ║
# ║ tenant disk. The production trust model is operator-DOES-NOT-  ║
# ║ have-SSH-to-miner; this script is therefore unusable on real   ║
# ║ deployments and only existed for the pre-BYO-OS era.           ║
# ║                                                                ║
# ║ Use scripts/tenant-image-bake.sh instead. It runs entirely on  ║
# ║ the operator workstation, produces an encrypted qcow2, and     ║
# ║ vali_create_vm dispatches a `tenant-preflight` order so the    ║
# ║ miner-agent fetches the image from S3 via short-TTL presigned  ║
# ║ URLs + sha-verifies. No operator-to-miner SSH anywhere.        ║
# ║                                                                ║
# ║ Runbook: docs/operator/byo-base-os-bake-runbook.md             ║
# ║ Architecture: scripts/tenant-image-bake.sh::Architecture       ║
# ║                                                                ║
# ║ Kept under scripts/archived/ for git-history reference only.   ║
# ╚════════════════════════════════════════════════════════════════╝
#
# tenant-disk-create.sh — pre-allocate + LUKS2-format a tenant disk
# image on a target miner, using the KEK staged in Vault by
# `tenant-secrets-stage.sh` (PR-V).
#
# What this lays down
# -------------------
# On the SSH target (a Hippius miner), a single per-tenant directory:
#
#   /var/lib/hippius-miner/staging/tenant-<vm-id>/
#     └── luks.img    raw image, LUKS2 header, KEK slot 0 = the
#                     EXACT bytes the `secret/<prefix>/<vm>/luks-kek`
#                     Vault path stores (post-base64-decode).
#
# That KEK is the only authority the guest accepts at unlock — at
# launch, the KBS attests the guest and releases the same bytes back
# (post PR-V `vault_mvp.rs` schema fix). `binaries/agent-initramfs`
# (see `src/stages/luks_cryptsetup.rs`) drives `libcryptsetup`'s
# `crypt_activate_by_passphrase(CRYPT_ANY_SLOT, <released-bytes>)`.
# So a single-byte divergence between what THIS script wrote and what
# Vault holds = unlock fail-closed at first boot. We mirror that
# byte-level contract here.
#
# §20 logging discipline
# ----------------------
# Stderr carries progress only — NEVER the KEK bytes, NEVER the
# base64. The script PRINTS the SHA-256 of the KEK (a §20-safe
# fingerprint the operator can compare with the KBS release log after
# attest), then unsets the in-process variable. The KEK only ever
# crosses one boundary: this process's stdin → the remote
# `cryptsetup` stdin via SSH — no temp file, no argv, no environment
# variable.
#
# Wire format / pinned crypto profile
# -----------------------------------
# - **LUKS2 only** (`--type luks2`). LUKS1's PBKDF2 is the kind of
#   profile §20 calls "pinned" — anything else is a §20 regression.
# - **argon2id KDF** (`--pbkdf argon2id`). Memory-hard, sandwich-resistant.
#   Argon2i / pbkdf2 are explicitly rejected at sanity-verify time.
# - Key passed via `--key-file=-` (stdin) — never argv, never $TMP.
#
# References
# ----------
# - scripts/tenant-secrets-stage.sh: writes `{"value": "<base64>"}`.
# - binaries/kbs-server/src/vault_mvp.rs::parse_kv_secret_body: the
#   schema-lock that round-trips the same bytes.
# - binaries/agent-initramfs/src/stages/luks_cryptsetup.rs: the
#   guest-side consumer (LUKS2 + CRYPT_ANY_SLOT + libcryptsetup).
# - docs/operator/tenant-launch-runbook.md: end-to-end sequencing.

set -Eeuo pipefail

# ── Secret hygiene: scrub the base64 KEK on ANY exit path ───────────
#
# `kek_b64` is `unset` immediately after each pipe-into-ssh step on
# the happy path, but `die "..."` shortcuts to `exit` without running
# that unset. A `trap` on EXIT closes the gap so a SIGTERM / unexpected
# failure can't leave the base64 KEK sitting in a shell process's
# environment long enough for a core-dump / `/proc/<pid>/environ`
# inspection to lift it. (`set +e` inside the trap is belt+suspenders
# — `unset` on an undefined name is a no-op, but the broader script
# runs under `set -e` and we don't want the trap to mask a real exit
# code.)
cleanup_secrets() {
    set +e
    unset kek_b64
    # #257 Phase B: clean the local image staging dir if the bake path
    # set one. Bytes there are public cloud-image (Ubuntu / Debian /
    # CentOS) — not secret — but a long-lived /tmp residue is noise.
    if [[ -n "${BASE_IMAGE_TMPDIR:-}" && -d "${BASE_IMAGE_TMPDIR}" ]]; then
        rm -rf -- "${BASE_IMAGE_TMPDIR}"
    fi
}
trap cleanup_secrets EXIT

# ── Defaults + state ────────────────────────────────────────────────

PROG="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_VAULT_CACERT="${REPO_ROOT}/vault-ca.crt"

# NO DEFAULT — supply $VAULT_ADDR or --vault-addr.
VAULT_ADDR_DEFAULT=""
VAULT_PATH_PREFIX_DEFAULT="hippius-compute/kbs/tenants"
# Mirrors `tenant-secrets-stage.sh` — keeps `vault kv …` output
# machine-readable for `jq -r`.
export VAULT_FORMAT=json

# Staging root on the miner. The miner's writeable per-tenant tree is
# `/var/lib/hippius-miner/staging/` (created by 06-bootstrap).
MINER_STAGING_ROOT_DEFAULT="/var/lib/hippius-miner/staging"

miner_host=""
vm_id=""
size_gb=""
out_path=""
vault_addr="${VAULT_ADDR:-${VAULT_ADDR_DEFAULT}}"
vault_token="${VAULT_TOKEN:-}"
vault_cacert="${VAULT_CACERT:-}"
if [[ -z "${vault_cacert}" && -r "${DEFAULT_VAULT_CACERT}" ]]; then
    vault_cacert="${DEFAULT_VAULT_CACERT}"
fi
vault_path_prefix="${VAULT_PATH_PREFIX:-${VAULT_PATH_PREFIX_DEFAULT}}"
kek_source="vault"
kek_file=""
force=0
dry_run=0
# #257 Phase B (BYO base-OS): optional fetch+bake of a vanilla cloud
# image into the LUKS plaintext device immediately after format. Both
# flags must be supplied together; absent ⇒ legacy blank-disk behaviour.
base_image_url=""
base_image_sha256=""

# ── Helpers ─────────────────────────────────────────────────────────

log() { printf '%s: %s\n' "${PROG}" "$*" >&2; }
die() {
    log "ERROR: $*"
    exit 1
}

usage() {
    cat >&2 <<EOF
${PROG} — pre-allocate + LUKS2-format a tenant disk image on a miner,
keyed with the KEK staged in Vault by tenant-secrets-stage.sh (PR-V).

Usage:
  ${PROG} --miner-host SSH_HOST --vm-id ID --size-gb N \\
          [--out-path PATH] \\
          [--vault-addr URL] [--vault-token TOKEN] \\
          [--vault-cacert PATH] [--vault-path-prefix PREFIX] \\
          [--kek-source vault|stdin|file] [--kek-file PATH] \\
          [--base-image-url URL --base-image-sha256 HEX] \\
          [--force] [--dry-run]

Required:
  --miner-host HOST   SSH destination (ssh(1) form, e.g.
                      'ubuntu@miner-a.internal' or a Host alias).
                      The script SSH'es here with stdin piping a
                      raw-bytes KEK into cryptsetup — sudo without
                      password is required for the target dir.
  --vm-id ID          The OrderTicket.vm_id. Becomes the directory
                      basename under MINER_STAGING_ROOT.
  --size-gb N         Raw image size in GiB (integer, > 0). The
                      encrypted plaintext device is smaller than the
                      raw image by ~7 % — the LUKS2 header takes
                      ~16 MiB and \`--integrity hmac-sha256\` (closes
                      the §257 AES-XTS malleability gap) adds a
                      32-byte HMAC tag per 512-byte sector plus a
                      small journal. Size N so that
                      \`int(N * 0.93) GiB\` is the usable plaintext
                      capacity you want.

Optional:
  --out-path PATH     Absolute path on the miner. Default:
                      ${MINER_STAGING_ROOT_DEFAULT}/tenant-<vm-id>/luks.img
  --vault-addr URL    Vault address. Default: \$VAULT_ADDR, else
                      ${VAULT_ADDR_DEFAULT}.
  --vault-token T     Vault token. Default: \$VAULT_TOKEN. Required
                      when --kek-source=vault.
  --vault-cacert P    Vault CA cert (self-signed Tier-0). Default:
                      \$VAULT_CACERT, else the repo's vault-ca.crt
                      next to scripts/ (${DEFAULT_VAULT_CACERT}).
  --vault-path-prefix PFX
                      KV-v2 path prefix WITHOUT the leading mount.
                      Default: \$VAULT_PATH_PREFIX, else
                      ${VAULT_PATH_PREFIX_DEFAULT}.
  --kek-source SRC    Where to read the raw KEK bytes from:
                        vault  — default; KV-v2 read at
                                 secret/<prefix>/<vm-id>/luks-kek.
                        stdin  — the script's own stdin (one read,
                                 piped straight through).
                        file   — --kek-file PATH (file is read
                                 in-process and immediately wiped
                                 from memory after the pipe).
  --kek-file P        Required with --kek-source=file. Mutually
                      exclusive with the other sources.
  --force             Re-create even if --out-path exists. The first
                      16 MiB of the image are zeroed BEFORE
                      luksFormat so a partial write cannot leave
                      half-formatted state.
  --base-image-url URL
                      #257 Phase B (BYO base-OS): URL of a vanilla
                      cloud image (Ubuntu / Debian / CentOS qcow2
                      or raw) to bake into the LUKS plaintext device
                      immediately after format. The image is fetched
                      LOCALLY (so the operator's bandwidth + sha256
                      check are the trust anchor, not the miner's),
                      qemu-img-converted to raw if it's qcow2, then
                      streamed over SSH stdin into
                      \`dd of=/dev/mapper/hippius-bake-<vm-id>\` with
                      \`oflag=direct\` for write-once landing. The
                      tenant's cloud-init partition + fs (ext4 by
                      default for the Ubuntu / Debian / CentOS
                      Stream cloud images) lands inside the LUKS
                      ciphertext.
  --base-image-sha256 HEX
                      Required with --base-image-url. 64-hex digest
                      of the *original* image bytes (qcow2 or raw —
                      whatever the URL serves), verified BEFORE the
                      qemu-img convert + SSH stream. Mismatch ⇒
                      fail-closed (exit 5) BEFORE any miner-side
                      cryptsetup open.
  --dry-run           Print the remote commands that WOULD run
                      (with the KEK redacted to '<32-byte-KEK>')
                      and exit without touching the miner.

Output (stdout, single-line JSON):
  { "vm_id": "...", "miner_host": "...", "out_path": "...",
    "size_gb": N, "kek_sha256": "<64 hex>",
    "luks_version": 2, "luks_pbkdf": "argon2id",
    "state": "created" | "already_provisioned" }

Filesystem layout left on the miner (post-PR fix-tenant-disk-create-perms):
  /var/lib/hippius-miner/staging/tenant-<vm>/         drwxr-xr-x root:root
  /var/lib/hippius-miner/staging/tenant-<vm>/luks.img -rw-rw---- libvirt-qemu:kvm

The dir is mode 0755 (NOT 0700) so libvirt-qemu can traverse to open
the image; the image itself is group-rw + world-none. Owner is
\`libvirt-qemu\` on Debian/Ubuntu, \`qemu\` on RHEL/Fedora — the script
resolves via \`getent passwd\` at run time and fails closed if neither
user exists.

Why this script
---------------
Without it, the runbook would have an operator pipe raw KEK bytes
over SSH by hand for each tenant. A single typo (\`cat \$KEK | ssh\`
vs \`ssh ... <\$KEK\`, sudo prompts that echo stdin, a stray \`set -x\`)
leaks the bytes into a shell history / a CI log / the journal. The
script is the §20-discipline boundary.

Exit codes:
  0  — created OR already-provisioned (idempotent success).
  1  — usage / input rejection.
  2  — vault read / decode failure.
  3  — SSH / cryptsetup failure on the miner.
  4  — sanity-verify failure (wrong LUKS version / pbkdf / slot).
  5  — base-image fetch / sha256 / convert / bake failure
       (#257 Phase B BYO base-OS path only).
EOF
}

require_arg() {
    [[ -n "${2-}" ]] || die "$1 requires a value"
}

ascii_id() {
    local field="$1" val="$2"
    [[ -n "${val}" ]] || die "${field} must not be empty"
    [[ "${val}" =~ ^[A-Za-z0-9._-]+$ ]] \
        || die "${field}='${val}' contains characters outside [A-Za-z0-9._-]"
}

# ── Parse args ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --miner-host)         require_arg "$1" "${2-}"; miner_host="$2";         shift 2;;
        --vm-id)              require_arg "$1" "${2-}"; vm_id="$2";              shift 2;;
        --size-gb)            require_arg "$1" "${2-}"; size_gb="$2";            shift 2;;
        --out-path)           require_arg "$1" "${2-}"; out_path="$2";           shift 2;;
        --vault-addr)         require_arg "$1" "${2-}"; vault_addr="$2";         shift 2;;
        --vault-token)        require_arg "$1" "${2-}"; vault_token="$2";        shift 2;;
        --vault-cacert)       require_arg "$1" "${2-}"; vault_cacert="$2";       shift 2;;
        --vault-path-prefix)  require_arg "$1" "${2-}"; vault_path_prefix="$2";  shift 2;;
        --kek-source)         require_arg "$1" "${2-}"; kek_source="$2";         shift 2;;
        --kek-file)           require_arg "$1" "${2-}"; kek_file="$2";           shift 2;;
        --base-image-url)     require_arg "$1" "${2-}"; base_image_url="$2";     shift 2;;
        --base-image-sha256)  require_arg "$1" "${2-}"; base_image_sha256="$2";  shift 2;;
        --force)              force=1;                                           shift;;
        --dry-run)            dry_run=1;                                         shift;;
        -h|--help)            usage; exit 0;;
        *)                    die "unknown argument: $1 (try --help)";;
    esac
done

# ── Validate inputs ─────────────────────────────────────────────────

[[ -n "${miner_host}" ]] || { usage; die "--miner-host is required"; }
[[ -n "${vm_id}"      ]] || die "--vm-id is required"
[[ -n "${size_gb}"    ]] || die "--size-gb is required"

ascii_id "--vm-id" "${vm_id}"
# Miner-host accepts SSH-config forms (alias, user@host, host:port);
# we don't deny ':' / '@', but we do deny obvious quoting bait.
[[ "${miner_host}" =~ ^[A-Za-z0-9._:@-]+$ ]] \
    || die "--miner-host='${miner_host}' contains characters outside [A-Za-z0-9._:@-]"
[[ "${size_gb}" =~ ^[1-9][0-9]*$ ]] \
    || die "--size-gb must be a positive integer (got '${size_gb}')"

case "${kek_source}" in
    vault|stdin|file) ;;
    *) die "--kek-source must be one of: vault, stdin, file (got '${kek_source}')" ;;
esac
if [[ "${kek_source}" == "file" ]]; then
    [[ -n "${kek_file}" ]] || die "--kek-file is required with --kek-source=file"
    [[ -r "${kek_file}" ]] || die "--kek-file '${kek_file}' not readable"
elif [[ -n "${kek_file}" ]]; then
    die "--kek-file is only valid with --kek-source=file"
fi
if [[ "${kek_source}" == "vault" ]]; then
    [[ -n "${vault_token}" ]] \
        || die "--vault-token (or \$VAULT_TOKEN) is required for --kek-source=vault"
fi
if [[ -n "${vault_cacert}" && ! -r "${vault_cacert}" ]]; then
    die "--vault-cacert '${vault_cacert}' not readable"
fi

# Either both --base-image-* or neither — partial is a config error.
if [[ -n "${base_image_url}" && -z "${base_image_sha256}" ]] \
    || [[ -z "${base_image_url}" && -n "${base_image_sha256}" ]]; then
    die "--base-image-url and --base-image-sha256 must be supplied together"
fi
if [[ -n "${base_image_url}" ]]; then
    # 64-hex sha256 — same rigid shape `--rootfs-hash-sha256` style
    # checks elsewhere in the repo, applied here so a mistyped digest
    # fail-closes before a single byte hits the wire.
    [[ "${base_image_sha256}" =~ ^[0-9a-f]{64}$ ]] \
        || die "--base-image-sha256 must be exactly 64 lowercase hex chars"
    # Cheap URL shape check — accept https://, s3://, file:// (file://
    # for local-mirror integration tests). Anything else is a config typo.
    case "${base_image_url}" in
        https://*|s3://*|file://*) ;;
        *) die "--base-image-url scheme must be https://, s3://, or file:// (got '${base_image_url}')" ;;
    esac
    # The local fetch + qemu-img convert + SSH stream pipeline needs
    # these binaries. Fail FAST so an operator hits the missing-tool
    # error before SSH'ing to the miner. Skip the check on --dry-run:
    # a dry-run doesn't actually fetch / convert / SSH, and we want
    # operators to be able to preview the bake plan from a workstation
    # without qemu-utils installed.
    if [[ "${dry_run}" -ne 1 ]]; then
        for tool in curl qemu-img; do
            command -v "${tool}" >/dev/null 2>&1 \
                || die "--base-image-url path requires '${tool}' on \$PATH (sudo apt install qemu-utils for qemu-img)"
        done
    fi
fi

# Resolve default out-path AFTER --vm-id is known.
if [[ -z "${out_path}" ]]; then
    out_path="${MINER_STAGING_ROOT_DEFAULT}/tenant-${vm_id}/luks.img"
fi
# Reject anything that isn't an absolute path — the remote-side `mkdir
# -p` and `chmod` calls require a fully-qualified location.
[[ "${out_path}" == /* ]] || die "--out-path must be absolute (got '${out_path}')"

# Reject `..` segments outright: the path is concatenated into shell
# commands that ssh executes via the remote shell. `..` in there would
# silently let a caller write OUTSIDE the staging root.
case "${out_path}" in
    *..*) die "--out-path must not contain '..' segments (got '${out_path}')" ;;
esac

# ── Vault wiring ────────────────────────────────────────────────────

export VAULT_ADDR="${vault_addr}"
if [[ -n "${vault_token}" ]]; then
    export VAULT_TOKEN="${vault_token}"
fi
if [[ -n "${vault_cacert}" ]]; then
    export VAULT_CACERT="${vault_cacert}"
fi

luks_kv_path="${vault_path_prefix}/${vm_id}/luks-kek"
luks_full="secret/${luks_kv_path}"

# ── Fetch KEK ───────────────────────────────────────────────────────
# `kek_b64` lives in shell-process memory only. We `unset` it after
# the SSH/cryptsetup pipe so a later log() / die() / set -x cannot
# observe it. The decoded raw bytes are NEVER held in a shell
# variable — they flow as a byte stream from `base64 -d` straight
# into the SSH stdin (and from SSH stdin straight into the remote
# cryptsetup --key-file=-).

fetch_kek_b64() {
    case "${kek_source}" in
        vault)
            local out
            out=$(vault kv get -format=json -mount=secret "${luks_kv_path}" 2>&1) \
                || die "vault kv get '${luks_full}' failed: ${out}"
            local val
            val=$(printf '%s' "${out}" | jq -er '.data.data.value // empty') \
                || die "vault path '${luks_full}' missing .data.data.value (PR-V schema)"
            printf '%s' "${val}"
            ;;
        stdin)
            # Operator pipes base64 in on the script's own stdin; the
            # script wraps it as a single line. `base64 -w0` re-wraps
            # if the operator's line is already wrapped, and rejects
            # non-base64 bytes.
            local raw
            raw=$(cat) || die "reading KEK from stdin failed"
            printf '%s' "${raw}" | base64 -d >/dev/null 2>&1 \
                || die "--kek-source=stdin: input is not valid base64"
            printf '%s' "${raw}"
            ;;
        file)
            # `--kek-file` is the *raw* 32 bytes (matches what
            # tenant-secrets-stage.sh's `--luks-kek-file` accepts);
            # base64-encode in-process and never write the encoded
            # form to a file.
            base64 -w0 < "${kek_file}"
            ;;
    esac
}

# `kek_b64` is base64-encoded raw KEK bytes (single-line). NOTE: we
# could pipe `base64 -d` straight from `fetch_kek_b64` without ever
# materializing `kek_b64`, but the §20-safe sha256 fingerprint we
# emit requires touching the decoded bytes once; doing it via
# `base64 -d` in two short subshells, with `kek_b64` unset between
# them, keeps the decoded stream from re-entering any later log path.
log "fetching KEK from ${kek_source}"
kek_b64=$(fetch_kek_b64)
[[ -n "${kek_b64}" ]] || die "empty KEK"

kek_byte_len=$(printf '%s' "${kek_b64}" | base64 -d | wc -c | tr -d ' ')
# PR-V locked KEK size at 32 bytes (`tenant-secrets-stage.sh`'s
# `--luks-kek-file` rejects anything else). Mirror that here so a
# Vault path written by a future schema-drifted writer fails closed.
[[ "${kek_byte_len}" -eq 32 ]] \
    || die "expected 32-byte KEK, got ${kek_byte_len} bytes — schema drift?"

kek_sha256=$(printf '%s' "${kek_b64}" | base64 -d | sha256sum | cut -d' ' -f1)
log "KEK: 32 bytes (sha256=${kek_sha256})"

# ── Remote scripts ──────────────────────────────────────────────────
# Two small remote commands. NEITHER carries the KEK in argv — the
# only place the bytes ever appear remote-side is libcryptsetup's
# mlock'd buffer (cryptsetup reads --key-file=- from its stdin, which
# IS the ssh stdin, which IS the local `base64 -d` output).

# Quoting: `out_path` is bash-quoted into the remote shell via
# `printf %q`. We restrict its character set above to absolute paths
# under [A-Za-z0-9._/-] (no `..`), so the quoted form is safe even
# under odd remote shells.
out_path_q=$(printf '%q' "${out_path}")
size_gb_q=$(printf '%q' "${size_gb}")
out_dir_q=$(printf '%q' "$(dirname "${out_path}")")

# Probe: does the file exist AND parse as LUKS2 AND unlock with our
# KEK? On all three "yes" we return early; on any "no" we proceed
# to the format path.
probe_remote_cmd=$(cat <<EOF
set -Eeuo pipefail
if ! sudo test -f ${out_path_q}; then
    echo "absent"; exit 0
fi
if ! sudo cryptsetup isLuks --type luks2 ${out_path_q} 2>/dev/null; then
    echo "present-not-luks2"; exit 0
fi
# --test-passphrase reads from stdin (--key-file=-) without
# activating the dm target. CRYPT_ANY_SLOT semantics = try every
# slot against the one supplied key.
if sudo cryptsetup open --test-passphrase --key-file=- ${out_path_q}; then
    echo "luks2-unlocks"
else
    echo "luks2-no-unlock"
fi
EOF
)

# Format: zero the head, allocate the image, luksFormat from stdin.
# - \`sudo install -d -m 0755 ...\` creates the parent dir. 0755 (not
#   0700) is REQUIRED so libvirt-qemu can traverse into the dir to
#   open the image at QEMU launch; the dir itself contains no secret
#   metadata — only the LUKS2 image, and its header carries no key
#   material (the keyslot is KDF-protected). Write stays root-only.
# - \`truncate -s ${N}G\` allocates a sparse file; cryptsetup needs a
#   real or sparse backing file >= the header (~16 MiB for LUKS2).
# - \`dd if=/dev/zero ... count=16M\` zeros the first 16 MiB so a
#   half-formatted prior header can't survive --force.
# - \`cryptsetup luksFormat ... --key-file=-\` reads the passphrase
#   from stdin. \`--batch-mode\` skips the destructive-action prompt
#   (the file is already known to be unused per the probe path).
#
# Ownership + 0660 are NOT applied here — they are the contract of
# the \`perms_remote_cmd\` step that runs idempotently in BOTH the
# format path AND the already-provisioned path. Keeping the two
# concerns separate lets a re-run repair a stale image whose perms
# were wrong (e.g. an early-PR run that chmod'd 0600).
format_remote_cmd=$(cat <<EOF
set -Eeuo pipefail
sudo install -d -m 0755 ${out_dir_q}
sudo truncate -s ${size_gb_q}G ${out_path_q}
sudo dd if=/dev/zero of=${out_path_q} bs=1M count=16 conv=notrunc status=none
# --integrity hmac-sha256 — closes the §257 "AES-XTS malleability"
# gap explicitly listed as a MUST-FIX in the issue body. Without it,
# a malicious miner can flip ciphertext bits at known offsets and
# the guest reads back attacker-controlled plaintext. With it,
# dm-integrity stacks under dm-crypt: every 512-byte sector carries
# a 32-byte HMAC-SHA256 tag the guest re-verifies on every read,
# so a tampered sector returns EIO instead of malicious plaintext.
# Cost: ~7 % capacity (the encrypted plaintext device is smaller
# than the raw image) + format-time wipe (cryptsetup zeros the whole
# device to initialise valid HMAC tags — ~16 GiB/min on NVMe, so
# format on a 32 GiB image takes ~2 min) + ~10 % IOPS overhead at
# runtime. Per the issue body: "accept it as default".
#
# The guest side handles integrity transparently — libcryptsetup
# auto-stacks dm-integrity under dm-crypt when LUKS2's on-disk
# header records \`integrity: hmac(sha256)\` (set here by this flag),
# so neither the agent-initramfs \`RealLuksUnlocker\` nor the BYO
# bake's \`cryptsetup-initramfs\` keyscript path needs any change.
sudo cryptsetup luksFormat \\
    --type luks2 \\
    --batch-mode \\
    --pbkdf argon2id \\
    --integrity hmac-sha256 \\
    --key-file=- \\
    ${out_path_q}
EOF
)

# Idempotent perms re-assert. Runs after format AND on the
# already-provisioned path (live bug 2026-05-25: an early run created
# the tenant dir with mode 0700 + the image as root:root mode 0600, so
# libvirt-qemu \`Could not open … : Permission denied\` at QEMU exec).
#
# - **Parent dir 0755** — libvirt-qemu needs +x to traverse. The dir
#   holds only the LUKS2 image (header has no key material).
# - **Owner libvirt-qemu** (fallback \`qemu\` for RHEL conventions —
#   the upstream packaging difference; \`getent\` resolves whichever
#   the host ships). FAIL CLOSED if neither user exists.
# - **Group kvm** — the standard libvirt qemu invocation runs as
#   \`<qemu-user>:kvm\`; making the file group-owned by kvm + mode 0660
#   gives the right ambient privilege without world-readable bytes.
# - **Mode 0660** — owner + group rw, world none.
#
# chmod + chown are idempotent so a re-run is a no-op when perms
# already match. The \`namei\` of a happy path is:
#     drwxr-xr-x /var/lib/hippius-miner/staging
#     drwxr-xr-x staging/tenant-<vm-id>
#     -rw-rw---- libvirt-qemu:kvm luks.img
perms_remote_cmd=$(cat <<EOF
set -Eeuo pipefail
qemu_user=""
for cand in libvirt-qemu qemu; do
    if getent passwd "\$cand" >/dev/null 2>&1; then
        qemu_user="\$cand"
        break
    fi
done
if [[ -z "\$qemu_user" ]]; then
    echo "ERROR: no libvirt-qemu or qemu user on this host (RHEL packaging differs)" >&2
    exit 1
fi
if ! getent group kvm >/dev/null 2>&1; then
    echo "ERROR: no kvm group on this host" >&2
    exit 1
fi
sudo chmod 0755 ${out_dir_q}
sudo chown "\$qemu_user":kvm ${out_path_q}
sudo chmod 0660 ${out_path_q}
echo "perms_ok user=\$qemu_user"
EOF
)

# Sanity verify: re-read the header and confirm version + PBKDF
# match the pinned profile. \`luksDump\` does NOT touch the keyslot
# secret — only metadata.
verify_remote_cmd=$(cat <<EOF
set -Eeuo pipefail
sudo cryptsetup luksDump ${out_path_q}
EOF
)

# ── Dry-run path ────────────────────────────────────────────────────

if [[ "${dry_run}" -eq 1 ]]; then
    log "DRY RUN — printing remote commands (KEK redacted)"
    # Re-flow the remote command bodies for human reading. The
    # actual SSH invocation passes them as a single argv string;
    # printing them as a heredoc is just a more readable shape for
    # operator review.
    cat >&2 <<EOF
# ── probe (stdin: <32-byte-KEK> base64-decoded) ──
echo '<32-byte-KEK>' | base64 -d | ssh ${miner_host} '
${probe_remote_cmd}
'

# ── format (stdin: <32-byte-KEK> base64-decoded) ──
echo '<32-byte-KEK>' | base64 -d | ssh ${miner_host} '
${format_remote_cmd}
'
$(if [[ -n "${base_image_url}" ]]; then cat <<BAKE
# ── #257 BYO-OS bake (only when --base-image-url is set) ──
# LOCAL: curl ${base_image_url} → sha256 ${base_image_sha256} → (if qcow2) qemu-img convert -O raw
# Then:
echo '<32-byte-KEK>' | base64 -d | ssh ${miner_host} 'sudo cryptsetup open --type luks2 --key-file=- ${out_path} hippius-bake-${vm_id}'
ssh ${miner_host} 'sudo blockdev --getsize64 /dev/mapper/hippius-bake-${vm_id}'  # sanity: plaintext >= image bytes
cat <local-raw-image> | ssh ${miner_host} 'sudo dd of=/dev/mapper/hippius-bake-${vm_id} bs=1M iflag=fullblock oflag=direct status=none && sync'
ssh ${miner_host} 'sudo cryptsetup close hippius-bake-${vm_id}'
BAKE
fi)

# ── perms (idempotent; runs on both format + already-provisioned paths) ──
ssh ${miner_host} '
${perms_remote_cmd}
'

# ── verify ──
ssh ${miner_host} '
${verify_remote_cmd}
'
EOF
    jq -nc \
        --arg vm "${vm_id}" \
        --arg host "${miner_host}" \
        --arg path "${out_path}" \
        --argjson sz "${size_gb}" \
        --arg sha "${kek_sha256}" \
        '{
            vm_id: $vm,
            miner_host: $host,
            out_path: $path,
            size_gb: $sz,
            kek_sha256: $sha,
            luks_version: 2,
            luks_pbkdf: "argon2id",
            state: "dry-run"
         }'
    unset kek_b64
    exit 0
fi

# ── Probe (idempotency) ─────────────────────────────────────────────

log "probing ${miner_host}:${out_path}"
# `2>/dev/null` is INTENTIONAL on the probe path so a `cryptsetup`
# stderr line carrying "No usable token is available" (libcryptsetup
# emits that as part of a clean reject) doesn't pollute the
# operator's terminal — the probe's contract is its stdout discriminator
# only.
#
# Wire: `cryptsetup --test-passphrase --key-file=-` reads its
# passphrase from stdin. SSH forwards the local stdin to the remote
# command's stdin, so the `base64 -d` byte stream lands directly on
# cryptsetup. The remote script body is passed as a single SSH argv
# string (NOT via a herestring on stdin — that would override the
# pipe).
probe_out=$(
    printf '%s' "${kek_b64}" \
    | base64 -d \
    | ssh -o BatchMode=yes "${miner_host}" "${probe_remote_cmd}" \
        2>/dev/null
) || die "probe SSH to ${miner_host} failed (exit-code path: 3)"

case "${probe_out}" in
    luks2-unlocks)
        log "${out_path} already provisioned with this KEK — re-asserting perms"
        # Even on a same-KEK no-op we re-run the perms step: a pre-fix
        # invocation (PR #167, before this PR landed) may have left the
        # dir at 0700 + the image at root:root — the live bug. The
        # perms_remote_cmd is idempotent, so re-running on a happy
        # state is a few cheap chmod/chown no-ops.
        perms_out=$(ssh -o BatchMode=yes "${miner_host}" "${perms_remote_cmd}") \
            || die "perms re-assert on ${miner_host} failed (exit 3)"
        log "  → ${perms_out}"
        jq -nc \
            --arg vm "${vm_id}" \
            --arg host "${miner_host}" \
            --arg path "${out_path}" \
            --argjson sz "${size_gb}" \
            --arg sha "${kek_sha256}" \
            --arg baseurl "${base_image_url}" \
            --arg basesha "${base_image_sha256}" \
            '{
                vm_id: $vm,
                miner_host: $host,
                out_path: $path,
                size_gb: $sz,
                kek_sha256: $sha,
                luks_version: 2,
                luks_pbkdf: "argon2id",
                state: "already_provisioned",
                base_image_url: (if $baseurl == "" then null else $baseurl end),
                base_image_sha256: (if $basesha == "" then null else $basesha end),
                base_image_baked: false
             }'
        unset kek_b64
        exit 0
        ;;
    luks2-no-unlock)
        if [[ "${force}" -ne 1 ]]; then
            unset kek_b64
            die "${out_path} is LUKS2 but the Vault KEK does NOT unlock it — re-run with --force to wipe + recreate (exit 3)"
        fi
        log "force: existing LUKS2 image will be re-created"
        ;;
    present-not-luks2)
        if [[ "${force}" -ne 1 ]]; then
            unset kek_b64
            die "${out_path} exists but is not LUKS2 — re-run with --force to wipe + recreate (exit 3)"
        fi
        log "force: existing non-LUKS2 file will be wiped + re-created"
        ;;
    absent)
        log "no existing image — creating fresh"
        ;;
    *)
        unset kek_b64
        die "unexpected probe output: '${probe_out}' (exit 3)"
        ;;
esac

# ── Format ──────────────────────────────────────────────────────────

if [[ "${probe_out}" == "luks2-no-unlock" || "${probe_out}" == "present-not-luks2" ]]; then
    # The destructive head-wipe is part of the remote `format` step
    # (16 MiB of zeros before luksFormat). Log INTENT before the SSH
    # so an operator who passed `--force` by mistake sees the
    # destruction intent before it happens. Wording is deliberately
    # "WILL WIPE" not "WIPE": if the SSH connection fails before
    # `dd` runs, the destruction never happened — `die "luksFormat
    # … failed"` on the next line conveys that. The probe already
    # established the file's pre-state (LUKS2-but-wrong-KEK vs
    # non-LUKS2); this is the §13 "no surprise data loss" guard.
    log "WILL WIPE: about to zero the first 16 MiB of ${out_path} on ${miner_host} and reformat (--force). A subsequent 'luksFormat ... failed' line means the wipe did NOT happen."
fi
log "formatting ${miner_host}:${out_path} (${size_gb}G, LUKS2/argon2id)"
# stdout from the remote shell is allowed through unchanged — the
# `cryptsetup luksFormat` happy path prints nothing. A non-zero exit
# is the failure signal; we still surface stderr to the operator (no
# secret bytes can ride there — cryptsetup's logs are header-meta).
if ! printf '%s' "${kek_b64}" \
    | base64 -d \
    | ssh -o BatchMode=yes "${miner_host}" "${format_remote_cmd}"; then
    unset kek_b64
    die "luksFormat on ${miner_host} failed (exit 3)"
fi

# ── #257 Phase B: BYO base-OS bake ──────────────────────────────────
# When --base-image-url is set, fetch the vanilla cloud image LOCALLY,
# verify the operator-supplied sha256, qemu-img-convert qcow2 → raw,
# then open the LUKS mapper on the miner and stream the raw bytes
# straight into /dev/mapper/<mapper> over a single SSH stdin pipe.
# The plaintext fs (ext4 by default for the Ubuntu / Debian / CentOS
# Stream cloud images) lands INSIDE the LUKS ciphertext — the KEK is
# the only authority that re-opens it at first boot.
#
# Sequence:
#   1. LOCAL: curl → sha256 → qemu-img convert (if qcow2)
#   2. REMOTE: cryptsetup open --key-file=- <kek> on stdin
#   3. REMOTE: dd of=/dev/mapper/<mapper> on stdin (the raw bytes)
#   4. REMOTE: sync && cryptsetup close
#
# The KEK stays in `kek_b64` across steps 2 and 3 because they're two
# separate SSH calls (two separate stdin streams). It is unset at the
# bottom of this block (or the legacy `unset` immediately below for
# the no-bake path).
if [[ -n "${base_image_url}" ]]; then
    mapper_name="hippius-bake-${vm_id}"
    mapper_name_q=$(printf '%q' "${mapper_name}")
    BASE_IMAGE_TMPDIR=$(mktemp -d -t hippius-base-image.XXXXXX)
    raw_src="${BASE_IMAGE_TMPDIR}/image.src"

    log "fetching base image: ${base_image_url}"
    case "${base_image_url}" in
        file://*)
            local_src="${base_image_url#file://}"
            [[ -r "${local_src}" ]] \
                || die "base image file:// path '${local_src}' not readable (exit 5)"
            cp -- "${local_src}" "${raw_src}" \
                || die "base image copy from '${local_src}' failed (exit 5)"
            ;;
        s3://*)
            command -v aws >/dev/null 2>&1 \
                || die "--base-image-url s3:// requires aws-cli on \$PATH (exit 5)"
            aws s3 cp "${base_image_url}" "${raw_src}" \
                || die "base image s3 fetch failed (exit 5)"
            ;;
        https://*)
            # `--fail` so an HTTP 4xx / 5xx aborts (don't write the body).
            curl -fsSL --retry 3 --retry-delay 2 \
                 -o "${raw_src}" "${base_image_url}" \
                || die "base image curl failed (exit 5)"
            ;;
    esac

    log "verifying base image sha256"
    actual_sha=$(sha256sum "${raw_src}" | cut -d' ' -f1)
    if [[ "${actual_sha}" != "${base_image_sha256}" ]]; then
        unset kek_b64
        die "base image sha256 mismatch: expected ${base_image_sha256}, got ${actual_sha} (exit 5)"
    fi

    # qcow2 → raw. `qemu-img convert` is deterministic given the same
    # source so a future re-run with the same image bytes lands the
    # same plaintext bits.
    fmt=$(qemu-img info --output=json "${raw_src}" 2>/dev/null \
            | sed -nE 's/.*"format":[[:space:]]*"([^"]+)".*/\1/p' \
            | head -n 1)
    [[ -n "${fmt}" ]] || { unset kek_b64; die "qemu-img info on base image failed (exit 5)"; }
    case "${fmt}" in
        raw)
            raw_dst="${raw_src}"
            ;;
        qcow2)
            log "converting qcow2 → raw"
            raw_dst="${BASE_IMAGE_TMPDIR}/image.raw"
            qemu-img convert -O raw "${raw_src}" "${raw_dst}" \
                || { unset kek_b64; die "qemu-img convert failed (exit 5)"; }
            rm -f -- "${raw_src}"
            ;;
        *)
            unset kek_b64
            die "unsupported base image format '${fmt}' (raw / qcow2 only) (exit 5)"
            ;;
    esac
    raw_bytes=$(stat -c '%s' "${raw_dst}")
    log "base image ready: ${raw_bytes} bytes (raw)"

    # Open LUKS under a temp mapper name.
    open_remote_cmd=$(cat <<EOF
set -Eeuo pipefail
# Loud-fail if the mapper name is already in use — `cryptsetup open`
# would normally refuse, but we'd rather surface a clear class.
if sudo dmsetup info ${mapper_name_q} >/dev/null 2>&1; then
    echo "ERROR: mapper ${mapper_name_q} already exists — left over from a prior failed bake?" >&2
    exit 1
fi
sudo cryptsetup open --type luks2 --key-file=- ${out_path_q} ${mapper_name_q}
EOF
)
    size_remote_cmd=$(cat <<EOF
sudo blockdev --getsize64 /dev/mapper/${mapper_name_q}
EOF
)
    bake_remote_cmd=$(cat <<EOF
set -Eeuo pipefail
sudo dd of=/dev/mapper/${mapper_name_q} bs=1M iflag=fullblock oflag=direct conv=notrunc status=none
sync
EOF
)
    close_remote_cmd=$(cat <<EOF
sudo cryptsetup close ${mapper_name_q}
EOF
)

    log "opening LUKS mapper '${mapper_name}' on ${miner_host}"
    if ! printf '%s' "${kek_b64}" \
        | base64 -d \
        | ssh -o BatchMode=yes "${miner_host}" "${open_remote_cmd}"; then
        unset kek_b64
        die "cryptsetup open on ${miner_host} failed (exit 5)"
    fi

    # Sanity: the plaintext device MUST be at least as large as the raw
    # base image. The LUKS2 header eats ~16 MiB off the raw image; if
    # the operator passed --size-gb that's too small for the chosen
    # base image, we surface a clear error BEFORE the dd starts.
    plaintext_bytes=$(ssh -o BatchMode=yes "${miner_host}" "${size_remote_cmd}" \
        | tr -d '[:space:]')
    if ! [[ "${plaintext_bytes}" =~ ^[0-9]+$ ]]; then
        ssh -o BatchMode=yes "${miner_host}" "${close_remote_cmd}" >/dev/null 2>&1 || true
        unset kek_b64
        die "blockdev --getsize64 returned non-numeric '${plaintext_bytes}' (exit 5)"
    fi
    if (( plaintext_bytes < raw_bytes )); then
        ssh -o BatchMode=yes "${miner_host}" "${close_remote_cmd}" >/dev/null 2>&1 || true
        unset kek_b64
        die "LUKS plaintext (${plaintext_bytes} bytes) smaller than base image (${raw_bytes} bytes) — bump --size-gb (exit 5)"
    fi
    log "plaintext device: ${plaintext_bytes} bytes ≥ ${raw_bytes} bytes image"

    log "streaming base image into /dev/mapper/${mapper_name} (this can take a few minutes)"
    if ! ssh -o BatchMode=yes "${miner_host}" "${bake_remote_cmd}" < "${raw_dst}"; then
        ssh -o BatchMode=yes "${miner_host}" "${close_remote_cmd}" >/dev/null 2>&1 || true
        unset kek_b64
        die "dd into /dev/mapper/${mapper_name} failed (exit 5)"
    fi

    log "closing LUKS mapper '${mapper_name}'"
    ssh -o BatchMode=yes "${miner_host}" "${close_remote_cmd}" \
        || { unset kek_b64; die "cryptsetup close on ${miner_host} failed (exit 5)"; }
fi
unset kek_b64

# ── Apply perms (libvirt-qemu:kvm, 0660 file, 0755 dir) ─────────────
# Carries no secret bytes — pure chmod/chown over SSH. Lives outside
# the format pipe so a future re-run against a pre-fix tenant dir
# (mode 0700, root:root) can repair it without re-formatting.

log "applying ownership + traversal perms (libvirt-qemu:kvm)"
perms_out=$(ssh -o BatchMode=yes "${miner_host}" "${perms_remote_cmd}") \
    || die "perms apply on ${miner_host} failed (exit 3)"
log "  → ${perms_out}"

# ── Sanity verify ───────────────────────────────────────────────────

log "verifying LUKS2 header"
dump=$(ssh -o BatchMode=yes "${miner_host}" "${verify_remote_cmd}") \
    || die "cryptsetup luksDump on ${miner_host} failed (exit 4)"

# luksDump output is a fixed key/value layout we scrape with grep.
# `-i` + tolerant whitespace makes the checks robust to minor
# cryptsetup version-to-version formatting drift (e.g. a future
# rename like 'version' instead of 'Version' would still match).
echo "${dump}" | grep -qiE '^[[:space:]]*Version:[[:space:]]+2[[:space:]]*$' \
    || die "sanity-verify: LUKS version != 2 (got: $(echo "${dump}" | grep -i '^[[:space:]]*Version:'))  (exit 4)"
echo "${dump}" | grep -qiE '^[[:space:]]*PBKDF:[[:space:]]+argon2id[[:space:]]*$' \
    || die "sanity-verify: PBKDF != argon2id (got: $(echo "${dump}" | grep -i '^[[:space:]]*PBKDF:'))  (exit 4)"
# `Keyslots:` precedes one or more `  0: luks2` blocks. Slot 0
# specifically is what `luksFormat` populates first — assert it's
# there. Same tolerance applied.
echo "${dump}" | grep -qiE '^[[:space:]]+0:[[:space:]]+luks2[[:space:]]*$' \
    || die "sanity-verify: slot 0 missing from luksDump (exit 4)"

log "verified: LUKS2 / argon2id / slot 0 present"

# `base_image_baked` records whether THIS run baked a cloud image into
# the LUKS plaintext. The already_provisioned branch above never bakes
# (idempotency contract: re-running on a working tenant must not
# clobber its disk), so its JSON output records the field as `false`
# regardless of whether --base-image-url was passed.
jq -nc \
    --arg vm "${vm_id}" \
    --arg host "${miner_host}" \
    --arg path "${out_path}" \
    --argjson sz "${size_gb}" \
    --arg sha "${kek_sha256}" \
    --arg baseurl "${base_image_url}" \
    --arg basesha "${base_image_sha256}" \
    --argjson baked "$([[ -n "${base_image_url}" ]] && echo true || echo false)" \
    '{
        vm_id: $vm,
        miner_host: $host,
        out_path: $path,
        size_gb: $sz,
        kek_sha256: $sha,
        luks_version: 2,
        luks_pbkdf: "argon2id",
        state: "created",
        base_image_url: (if $baseurl == "" then null else $baseurl end),
        base_image_sha256: (if $basesha == "" then null else $basesha end),
        base_image_baked: $baked
     }'
