#!/usr/bin/env bash
# tenant-uki-stage-miner.sh — pre-stage a signed tenant UKI on a miner.
#
# What this does
# --------------
# Pulls the content-addressed tenant `.uki.signed` from
# `s3://hippius-compute-images/images/<sha>/…` (auth-only — the
# `.uki.signed` ACL is private, even though the sibling
# `provenance.cbor` is anon-readable), sha-gates the bytes, ships them
# to the target miner over SSH, sha-gates again on the miner, then
# splits the EFI PE into the four ingredients the miner-agent dispatch
# path consumes separately (`--kernel-path`, `--initrd-path`,
# `--cmdline`, `--ovmf-path`) plus the original `.uki.signed` for the
# audit trail.
#
# Final layout on the miner (atomic — partial failures leave the prior
# stage dir untouched):
#
#     <out-dir>/
#       ├── tenant-<sha>.uki.signed   — original EFI PE (audit trail)
#       ├── kernel                    — `.linux`   PE section
#       ├── initrd                    — `.initrd`  PE section
#       ├── cmdline                   — `.cmdline` PE section (text)
#       └── ovmf.fd                   — symlink to the shared cluster
#                                       OVMF (only if present on miner)
#
# Idempotency
# -----------
# A re-run with the same `--tenant-uki-sha` against an existing stage
# dir whose `.uki.signed` already hashes to the requested sha is a
# no-op. `--force` overrides — the existing stage dir is replaced
# atomically.
#
# §20 logging discipline
# ----------------------
# Stderr carries progress only — never UKI bytes, never the operator's
# S3 secret key, never the Vault token. The diagnostic surface is
# limited to: the sha (which IS the content address), the version, the
# stage-dir path, byte counts, and per-section sha256 fingerprints.
#
# References
# ----------
# - scripts/tenant-secrets-stage.sh        — bash/Vault template (PR-V).
# - packer/tenant-uki/uki/Makefile         — UKI assembly + section layout.
# - .github/workflows/tenant-uki-build.yml — S3 publish path
#                                            (`images/<sha>/<basename>`).
# - binaries/miner-uki-fetch/              — the alternative on-miner Rust
#                                            fetch (§22-verified) — preferred
#                                            once an operator-friendly
#                                            wrapper around it exists; this
#                                            script is the pre-flight tool.
# - docs/operator/byo-base-os-bake-runbook.md — invocation order.
#   (NOTE: this script is the legacy SSH-to-miner path; the BYO bake
#   flow is the production-recommended replacement.)

set -Eeuo pipefail

# ── Defaults + state ────────────────────────────────────────────────

PROG="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_VAULT_CACERT="${REPO_ROOT}/vault-ca.crt"

# NO DEFAULT — supply $VAULT_ADDR or --vault-addr (see the check
# below). e.g. https://vault.example.invalid:8200
DEFAULT_VAULT_ADDR=""
DEFAULT_VAULT_S3_PATH="hippius-compute/s3/operator"
# Object-store endpoint holding the published UKIs — deployment
# config, e.g. https://s3.example.invalid
DEFAULT_S3_ENDPOINT="${S3_ENDPOINT:-}"
DEFAULT_S3_BUCKET="hippius-compute-images"
DEFAULT_MINER_STAGING_ROOT="/var/lib/hippius-miner/staging"
# Cluster-wide OVMF location on every miner (one fleet-wide pin, see
# packer/kbs-uki/ovmf/ovmf.lock). The script SYMLINKS this from each
# tenant stage dir if it is present; it does NOT fetch+install OVMF
# itself — that is a separate, one-time-per-host operator step.
DEFAULT_OVMF_PATH_ON_MINER="/var/lib/hippius-miner/ovmf.fd"

# `VAULT_FORMAT=json` makes `vault kv get` emit a parseable envelope
# we can `jq -r` out of without touching the operator's shell config.
export VAULT_FORMAT=json

miner_host=""
tenant_uki_sha=""
tenant_uki_version=""
out_dir=""
vault_addr="${VAULT_ADDR:-${DEFAULT_VAULT_ADDR}}"
# The Vault token is NEVER accepted on argv (audit
# M-drop-vault-token-argv): argv is world-readable via ps/proc. It comes
# from `$VAULT_TOKEN` (env) or, preferred, a file via `--vault-token-file`
# / `$VAULT_TOKEN_FILE` (never in argv nor env).
vault_token="${VAULT_TOKEN:-}"
vault_token_file="${VAULT_TOKEN_FILE:-}"
vault_cacert="${VAULT_CACERT:-}"
vault_s3_path="${VAULT_S3_PATH:-${DEFAULT_VAULT_S3_PATH}}"
ovmf_path_on_miner="${OVMF_PATH:-${DEFAULT_OVMF_PATH_ON_MINER}}"
force=0
dry_run=0

if [[ -z "${vault_cacert}" && -r "${DEFAULT_VAULT_CACERT}" ]]; then
    vault_cacert="${DEFAULT_VAULT_CACERT}"
fi

# ── Helpers ─────────────────────────────────────────────────────────

# All progress goes to stderr; stdout is reserved for the trailing
# JSON summary the runbook copies into the next step.
log() { printf '%s: %s\n' "${PROG}" "$*" >&2; }
die() {
    log "ERROR: $*"
    exit 1
}

usage() {
    cat >&2 <<EOF
${PROG} — pre-stage a signed tenant UKI on a miner host.

Usage:
  ${PROG} --miner-host HOST --tenant-uki-sha SHA256_HEX \\
          [--tenant-uki-version V] [--out-dir PATH] \\
          [--vault-addr URL] [--vault-token-file PATH] [--vault-cacert PATH] \\
          [--vault-s3-path PATH] [--ovmf-path PATH] \\
          [--force] [--dry-run]

Required:
  --miner-host HOST       SSH target (any value 'ssh' accepts —
                          'ubuntu@1.2.3.4', a ~/.ssh/config alias, etc.).
  --tenant-uki-sha HEX    Content-addressed SHA-256 of the UKI to stage
                          (64 lowercase hex chars).

Optional:
  --tenant-uki-version V  The UKI's image-version tag — a HINT used
                          to short-circuit the bucket listing on the
                          happy path. The file in the bucket is named
                          'tenant-<V>.uki.signed'. If the explicit
                          object does not exist (e.g. the operator
                          passed '0.0.1' but the build emitted
                          '0.0.1-tenant'), the script falls back to
                          listing s3://<bucket>/images/<sha>/ and
                          picks the single .uki.signed it finds.
                          If unset, the listing path runs directly.
  --out-dir PATH          Stage destination on the miner. Default:
                          ${DEFAULT_MINER_STAGING_ROOT}/tenant-<sha8>.
  --vault-addr URL        Vault address, e.g.
                          https://vault.example.invalid:8200
                          Default: \$VAULT_ADDR. REQUIRED — no built-in
                          default.
  --vault-token-file P    File holding the Vault token (read once, never
                          on argv/env). Default: \$VAULT_TOKEN_FILE; if
                          unset, \$VAULT_TOKEN (env). Required (no
                          anonymous reads). Passing the token on the
                          command line is deliberately NOT supported —
                          argv is world-readable via ps.
  --vault-cacert PATH     Vault self-signed CA. Default: \$VAULT_CACERT,
                          else the repo-local ${DEFAULT_VAULT_CACERT}
                          (if readable), else defers to system trust.
  --vault-s3-path PATH    KV-v2 path under 'secret/' holding the S3
                          operator credentials. The body MUST include
                          'access_key' and 'secret_key'; 'endpoint' and
                          'bucket' are optional; when absent the
                          fallbacks are \$S3_ENDPOINT / ${DEFAULT_S3_BUCKET}.
                          There is no built-in endpoint default — the
                          Vault body or --s3-endpoint must supply it.
                          Default: \$VAULT_S3_PATH, else
                          ${DEFAULT_VAULT_S3_PATH}.
  --ovmf-path PATH        Cluster-wide OVMF location ON the miner. The
                          script symlinks <out-dir>/ovmf.fd → this path
                          if it exists; otherwise warns and leaves
                          ovmf.fd unstaged (operator handles OVMF
                          one-time-per-host out-of-band). Default:
                          \$OVMF_PATH, else ${DEFAULT_OVMF_PATH_ON_MINER}.
  --force                 Replace an existing stage dir atomically. The
                          default is to refuse if the existing UKI
                          sha matches (no-op) AND to refuse if it does
                          not (avoid silent overwrite).
  --dry-run               Print the planned actions and exit 0 without
                          touching Vault, S3, or the miner.

Output (stdout, single-line JSON on success):
  { "miner_host":..., "tenant_uki_sha":..., "tenant_uki_version":...,
    "out_dir":..., "ovmf_staged": true|false,
    "kernel_sha256":..., "initrd_sha256":..., "cmdline_sha256":... }
EOF
}

require_arg() {
    [[ -n "${2-}" ]] || die "$1 requires a value"
}

# ── Parse args ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --miner-host)         require_arg "$1" "${2-}"; miner_host="$2";         shift 2;;
        --tenant-uki-sha)     require_arg "$1" "${2-}"; tenant_uki_sha="$2";     shift 2;;
        --tenant-uki-version) require_arg "$1" "${2-}"; tenant_uki_version="$2"; shift 2;;
        --out-dir)            require_arg "$1" "${2-}"; out_dir="$2";            shift 2;;
        --vault-addr)         require_arg "$1" "${2-}"; vault_addr="$2";         shift 2;;
        --vault-token-file)   require_arg "$1" "${2-}"; vault_token_file="$2";   shift 2;;
        --vault-token)        die "--vault-token is not supported (argv is world-readable via ps); use --vault-token-file or \$VAULT_TOKEN";;
        --vault-cacert)       require_arg "$1" "${2-}"; vault_cacert="$2";       shift 2;;
        --vault-s3-path)      require_arg "$1" "${2-}"; vault_s3_path="$2";      shift 2;;
        --ovmf-path)          require_arg "$1" "${2-}"; ovmf_path_on_miner="$2"; shift 2;;
        --force)              force=1;                                           shift;;
        --dry-run)            dry_run=1;                                         shift;;
        -h|--help)            usage; exit 0;;
        *)                    die "unknown argument: $1 (try --help)";;
    esac
done

# ── Validate inputs ─────────────────────────────────────────────────

[[ -n "${miner_host}"     ]] || { usage; die "--miner-host is required"; }
[[ -n "${tenant_uki_sha}" ]] || die "--tenant-uki-sha is required"

# Content address: lowercase-hex SHA-256, exactly 64 chars. Rejected
# uppercase to keep the on-miner basename and the S3 key in canonical
# form (both content-addressed by lowercase-hex by upstream tooling).
[[ "${tenant_uki_sha}" =~ ^[0-9a-f]{64}$ ]] \
    || die "--tenant-uki-sha must be 64 lowercase-hex chars (got '${tenant_uki_sha}')"

if [[ -n "${tenant_uki_version}" ]]; then
    # The version string lands inside an S3 object key + a filename;
    # restrict to the same charset the build pipeline already enforces
    # (alphanum + - . _) so a hostile-looking value can't be passed
    # through to ssh / aws / scp.
    [[ "${tenant_uki_version}" =~ ^[A-Za-z0-9._-]+$ ]] \
        || die "--tenant-uki-version contains characters outside [A-Za-z0-9._-]"
fi

if [[ "${dry_run}" -ne 1 ]]; then
    # Resolve the token from a file if given (preferred — never argv/env),
    # else $VAULT_TOKEN (env). Strip a trailing newline.
    if [[ -n "${vault_token_file}" ]]; then
        [[ -r "${vault_token_file}" ]] \
            || die "--vault-token-file '${vault_token_file}' not readable"
        vault_token="$(tr -d '\r\n' < "${vault_token_file}")"
    fi
    [[ -n "${vault_token}" ]] \
        || die "a Vault token is required (--vault-token-file PATH or \$VAULT_TOKEN; --dry-run skips this)"
fi
if [[ -n "${vault_cacert}" && ! -r "${vault_cacert}" ]]; then
    die "--vault-cacert '${vault_cacert}' not readable"
fi

# Tools we hard-require — fail upfront with a clear message rather
# than mid-pipeline with a `command not found` from a subshell.
for bin in aws vault jq ssh scp sha256sum; do
    command -v "${bin}" >/dev/null 2>&1 \
        || die "missing required tool: ${bin}"
done

sha8="${tenant_uki_sha:0:8}"
if [[ -z "${out_dir}" ]]; then
    out_dir="${DEFAULT_MINER_STAGING_ROOT}/tenant-${sha8}"
fi
# Refuse a leading-tilde out-dir (it would NOT be expanded by the
# remote shell after `ssh "${miner_host}" "mkdir -p '${out_dir}'"`)
# and a relative out-dir (ambiguous on the miner).
[[ "${out_dir}" == /* ]] \
    || die "--out-dir must be an absolute path (got '${out_dir}')"

uki_basename="tenant-${tenant_uki_sha}.uki.signed"

# ── SSH wrappers ────────────────────────────────────────────────────
#
# `BatchMode=yes` refuses any interactive password / key-passphrase
# prompt — the only auth path is the operator's pre-installed key (set
# up out-of-band, see runbook). A miner that does not key-accept this
# operator fails the very first ssh call with a clear error rather
# than hanging.
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new)
# SC2029: the snippets we send through `ssh_run` deliberately
# interpolate variables on the CLIENT side (sha, version, out_dir,
# remote_staging). Every interpolated value is pre-validated at parse:
# sha = 64 hex chars, version = [A-Za-z0-9._-], out_dir is an absolute
# path. The remote command-line cannot be hijacked through any of these.
# shellcheck disable=SC2029
ssh_run() { ssh "${ssh_opts[@]}" "${miner_host}" "$@"; }
scp_to()  { scp "${ssh_opts[@]}" "$1" "${miner_host}:$2"; }

# ── Vault wiring + S3 creds ─────────────────────────────────────────

read_s3_creds_from_vault() {
    [[ -n "${vault_addr}" ]] \
        || die "Vault address is not set — pass --vault-addr URL or export VAULT_ADDR"
    export VAULT_ADDR="${vault_addr}"
    export VAULT_TOKEN="${vault_token}"
    if [[ -n "${vault_cacert}" ]]; then
        export VAULT_CACERT="${vault_cacert}"
    fi

    local full_path body
    full_path="secret/${vault_s3_path}"
    log "reading S3 creds from vault: ${full_path}"

    # `vault kv get -format=json` returns `{data:{data:{...}, metadata:{...}}}`.
    # Trap the entire envelope so a missing path / 403 / wrong format
    # fails closed BEFORE we try to extract a value (`jq -r` would
    # otherwise silently emit `null`).
    body=$(vault kv get -format=json "${full_path}") \
        || die "vault kv get ${full_path} failed (token expired / path missing / policy?)"

    s3_access_key=$(echo "${body}" | jq -er '.data.data.access_key') \
        || die "${full_path}: missing field 'access_key'"
    s3_secret_key=$(echo "${body}" | jq -er '.data.data.secret_key') \
        || die "${full_path}: missing field 'secret_key'"
    s3_endpoint=$(echo "${body}" | jq -r ".data.data.endpoint // \"${DEFAULT_S3_ENDPOINT}\"")
    [[ -n "${s3_endpoint}" ]] \
        || die "no S3 endpoint: set 'endpoint' in ${full_path} or export S3_ENDPOINT"
    s3_bucket=$(echo "${body}" | jq -r ".data.data.bucket // \"${DEFAULT_S3_BUCKET}\"")
    # Audit fingerprint of the access-key (last 4 chars only, not the
    # secret) — confirms WHICH credential the script picked up without
    # leaking the key itself.
    local ak_tail="${s3_access_key: -4}"
    log "  endpoint=${s3_endpoint} bucket=${s3_bucket} access_key=…${ak_tail}"

    export AWS_ACCESS_KEY_ID="${s3_access_key}"
    export AWS_SECRET_ACCESS_KEY="${s3_secret_key}"
    # Belt-and-braces: scrub the locals so a future `set -x` in the
    # same shell would not echo them.
    unset s3_access_key s3_secret_key
}

# ── Resolve UKI S3 key (version is optional) ────────────────────────

resolve_uki_s3_key() {
    # `--tenant-uki-version` is a HINT, not a hard contract. The
    # Packer build emits `tenant-<IMAGE_VERSION>.uki.signed` where
    # `IMAGE_VERSION` is the Makefile's `0.0.1-tenant` (suffix and
    # all). An operator who passes `--tenant-uki-version 0.0.1`
    # — the natural reading of "the version" — would otherwise 404
    # on `tenant-0.0.1.uki.signed`. We `head-object` the explicit
    # key first; on 404 we fall through to listing, which is the
    # same auto-discovery path that fires when the flag is omitted.
    # Net effect: the hint short-circuits the LIST round-trip when
    # it matches; an off-by-suffix hint still resolves.
    if [[ -n "${tenant_uki_version}" ]]; then
        local explicit_key="images/${tenant_uki_sha}/tenant-${tenant_uki_version}.uki.signed"
        log "probing explicit --tenant-uki-version='${tenant_uki_version}' → s3 key='${explicit_key}'"
        if aws s3api head-object \
                --bucket "${s3_bucket}" \
                --key "${explicit_key}" \
                --endpoint-url "${s3_endpoint}" \
                >/dev/null 2>&1; then
            uki_s3_key="${explicit_key}"
            log "  → found (used as-is)"
            return 0
        fi
        log "  → not found, falling back to bucket listing"
        # Drop the unmatched hint so the JSON summary's `version`
        # field carries the ACTUAL version the listing finds (parsed
        # from the basename below) rather than the wrong hint.
        tenant_uki_version=""
    fi

    log "listing s3://${s3_bucket}/images/${tenant_uki_sha}/ to discover .uki.signed"
    local listing
    listing=$(aws s3 ls "s3://${s3_bucket}/images/${tenant_uki_sha}/" \
                    --endpoint-url "${s3_endpoint}") \
        || die "aws s3 ls failed — wrong creds, wrong endpoint, or empty prefix?"

    # Pick out *.uki.signed names from the `aws s3 ls` output (last
    # column = key basename). Refuse 0 / 2+ — an ambiguous prefix is
    # never silently disambiguated.
    local matches name count
    matches=$(echo "${listing}" | awk '{print $NF}' \
              | grep -E '\.uki\.signed$' || true)
    count=$(printf '%s\n' "${matches}" | grep -c . || true)
    case "${count}" in
        0) die "no *.uki.signed under images/${tenant_uki_sha}/ — wrong sha?";;
        1) :;;
        *) die "ambiguous: ${count} *.uki.signed found at the prefix — pass --tenant-uki-version explicitly";;
    esac
    name=$(printf '%s' "${matches}")
    uki_s3_key="images/${tenant_uki_sha}/${name}"
    # Pull the version out of `tenant-<v>.uki.signed` for the JSON
    # summary; falls back to "" if the name doesn't match (still
    # functional, just no version in the summary).
    if [[ "${name}" =~ ^tenant-(.+)\.uki\.signed$ ]]; then
        tenant_uki_version="${BASH_REMATCH[1]}"
    fi
    log "  → s3 key='${uki_s3_key}' (version='${tenant_uki_version:-?}')"
}

# ── Remote idempotency probe ────────────────────────────────────────

remote_already_staged() {
    # The probe is a single ssh round-trip: presence + sha256 in one
    # shot. A missing file / wrong sha / unreadable dir all just print
    # 'MISSING' and the caller proceeds to a fresh stage.
    local out
    out=$(ssh_run "
        if [[ -r '${out_dir}/${uki_basename}' ]]; then
            sha256sum '${out_dir}/${uki_basename}' | awk '{print \$1}'
        else
            echo MISSING
        fi
    " 2>/dev/null) || return 1
    [[ "${out}" == "${tenant_uki_sha}" ]]
}

# ── Pipeline ────────────────────────────────────────────────────────

if [[ "${dry_run}" -eq 1 ]]; then
    cat >&2 <<EOF
${PROG}: --dry-run — actions that WOULD be taken:
  1. read S3 creds from vault: secret/${vault_s3_path}
  2. resolve UKI key: images/${tenant_uki_sha}/tenant-${tenant_uki_version:-<auto>}.uki.signed
  3. probe ${miner_host}:${out_dir}/${uki_basename} for idempotency
  4. if absent or --force:
       a. aws s3 cp s3://${DEFAULT_S3_BUCKET}/images/${tenant_uki_sha}/<file> → local tmp
       b. sha256 verify local against ${tenant_uki_sha}
       c. ssh ${miner_host} mkdir -p ${out_dir}.staging
       d. scp local tmp → ${miner_host}:${out_dir}.staging/${uki_basename}
       e. ssh ${miner_host} sha256 verify
       f. ssh ${miner_host} objcopy --dump-section .linux/.initrd/.cmdline
       g. ssh ${miner_host} symlink ovmf.fd → ${ovmf_path_on_miner} (if present)
       h. ssh ${miner_host} atomic rename ${out_dir}.staging → ${out_dir}
EOF
    exit 0
fi

read_s3_creds_from_vault
resolve_uki_s3_key

if remote_already_staged; then
    if [[ "${force}" -ne 1 ]]; then
        log "${miner_host}:${out_dir}/${uki_basename} already at sha=${tenant_uki_sha} — no-op (use --force to re-stage)"
        jq -nc \
            --arg host "${miner_host}" \
            --arg sha "${tenant_uki_sha}" \
            --arg ver "${tenant_uki_version}" \
            --arg out "${out_dir}" \
            '{miner_host:$host,tenant_uki_sha:$sha,tenant_uki_version:$ver,out_dir:$out,staged:"already"}'
        exit 0
    fi
    log "stage dir already at the requested sha — --force given, re-staging"
fi

# ── Local fetch + sha gate ──────────────────────────────────────────

local_tmp=$(mktemp -d -t tenant-uki-stage.XXXXXX)
trap 'rm -rf "${local_tmp}"' EXIT
local_uki="${local_tmp}/${uki_basename}"

log "fetching s3://${s3_bucket}/${uki_s3_key} → local tmp"
aws s3 cp "s3://${s3_bucket}/${uki_s3_key}" "${local_uki}" \
        --endpoint-url "${s3_endpoint}" >/dev/null \
    || die "aws s3 cp failed (private ACL? wrong creds? wrong key?)"

local_sha=$(sha256sum "${local_uki}" | awk '{print $1}')
local_size=$(wc -c < "${local_uki}" | tr -d ' ')
[[ "${local_sha}" == "${tenant_uki_sha}" ]] \
    || die "local sha mismatch: got ${local_sha}, expected ${tenant_uki_sha}"
log "  size=${local_size} sha=${local_sha} (matches)"

# ── Push to miner — stage in a temp dir, atomic-rename on success ───
#
# Atomicity strategy: the new stage materializes at `<out>.staging.<pid>`
# entirely; only the last step renames it to `<out>`. A failure anywhere
# upstream leaves the prior `<out>` untouched (still bootable), and
# `<out>.staging.*` as visible debris (cleaned by a successful retry,
# or by an operator).

remote_staging="${out_dir}.staging.$$"
# Resolve `<out-dir>`'s parent CLIENT-side so the ssh_run snippet
# gets a literal, pre-validated path (out_dir is already constrained
# to absolute via the earlier `[[ "${out_dir}" == /* ]]` check).
out_dir_parent="$(dirname "${out_dir}")"
log "preparing ${miner_host}:${remote_staging}"
# Auto-chown is bounded to the designated staging root only (review r2
# P2). An operator who points --out-dir at /etc, /root, or any other
# application path is responsible for the perms themselves — we
# refuse to silently rewrite ownership on a path the bootstrap does
# not own.
expected_staging_root="${DEFAULT_MINER_STAGING_ROOT}"
ssh_run "
    set -e
    parent='${out_dir_parent}'
    expected_staging_root='${expected_staging_root}'
    # Two distinct conditions to handle (both observed live):
    #   1. parent absent  — early bootstrap; create + take ownership.
    #   2. parent present but NOT writable by us — the miner-bootstrap
    #      Ansible role creates the designated root as root:root mode
    #      755. The original guard \`if [[ ! -d ]]\` missed this case:
    #      the mkdir below silently failed with 'Permission denied'
    #      (live 2026-05-25 19:09 UTC+4).
    if [[ ! -d \"\$parent\" ]]; then
        if [[ \"\$parent\" == \"\$expected_staging_root\" ]]; then
            sudo mkdir -p \"\$parent\"
            sudo chown \"\$(id -un):\$(id -gn)\" \"\$parent\"
        else
            echo \"parent \$parent does not exist and is outside the designated staging root \$expected_staging_root — refusing to mkdir+chown\" >&2
            exit 1
        fi
    elif [[ ! -w \"\$parent\" ]]; then
        if [[ \"\$parent\" == \"\$expected_staging_root\" ]]; then
            # Idempotent: \`chown\` to the SAME owner is a no-op, so a
            # subsequent run that already owns the dir does not re-sudo.
            sudo chown \"\$(id -un):\$(id -gn)\" \"\$parent\"
        else
            echo \"parent \$parent is not writable and is outside the designated staging root \$expected_staging_root — refusing to chown (operator must prepare perms manually)\" >&2
            exit 1
        fi
    fi
    rm -rf '${remote_staging}'
    mkdir -p '${remote_staging}'
"

log "scp → ${miner_host}:${remote_staging}/${uki_basename}"
scp_to "${local_uki}" "${remote_staging}/${uki_basename}" >/dev/null \
    || die "scp failed"

log "verifying remote sha"
remote_sha=$(ssh_run "sha256sum '${remote_staging}/${uki_basename}' | awk '{print \$1}'")
[[ "${remote_sha}" == "${tenant_uki_sha}" ]] \
    || die "remote sha mismatch after scp: got ${remote_sha}, expected ${tenant_uki_sha}"
log "  → sha=${remote_sha} (matches)"

# ── Extract PE sections on the miner ────────────────────────────────
#
# A UKI is a single EFI PE binary with the kernel / initrd / cmdline /
# os-release embedded as named PE sections (`.linux`, `.initrd`,
# `.cmdline`, `.osrel`). `objcopy --dump-section` writes the bytes of
# each section to a file. We avoid `ukify --extract` because it
# requires a recent systemd-ukify (not present on every miner host),
# while `objcopy` is in the binutils baseline.
#
# `objcopy --dump-section .X=out in [out2]` writes the named section
# to `out`, AND (per the binutils manual) writes a transformed copy
# of the whole `in` to the trailing positional arg. We only want the
# section bytes; the transformed-copy arg is mandatory in the
# `--dump-section` invocation we're using, so we route it to a
# throwaway tempfile.
#
# WHY NOT `/dev/null`: binutils 2.45 (Ubuntu 24.04 Noble, a miner host)
# refuses to write to `/dev/null` with `objcopy: /dev/null: file
# truncated` (exit 1) — even though the named section IS written
# correctly first. Binutils 2.42 (Debian Trixie, what the Packer
# builder runs) silently tolerates this. The version skew was the
# `EXTRACT_FAILED:.linux` observed live 2026-05-25 19:09 UTC+4.
# A per-loop tempfile is the portable fix; the binutils maintainers
# moved to this stricter behaviour deliberately.
#
# The kernel / initrd are binary — the throwaway tempfile is never
# echoed, never logged, and is removed by a trap before the remote
# shell exits.

log "extracting PE sections on miner (objcopy --dump-section)"
ssh_run "
    set -e
    cd '${remote_staging}'
    # Co-locate the objcopy throwaway with the stage dir (which is
    # under /var/lib/hippius-miner — a real disk) rather than the
    # default \`mktemp -t\` location (/tmp, typically tmpfs on miner
    # hosts). The transformed-copy can run to a few hundred MiB on a
    # tenant UKI and would otherwise risk exhausting a small tmpfs
    # (review r1 Medium). The file lives only for this one ssh_run;
    # the trap removes it before the remote shell exits, and the
    # parent stage dir is itself renamed away on the happy path's
    # atomic flip below.
    objcopy_throwaway=\$(mktemp -p . hippius-objcopy.XXXXXX)
    trap 'rm -f \"\$objcopy_throwaway\"' EXIT
    for sect in linux:kernel initrd:initrd cmdline:cmdline; do
        s=\${sect%%:*}; out=\${sect##*:}
        if ! objcopy --dump-section \".\${s}=\${out}\" \\
                     '${uki_basename}' \"\$objcopy_throwaway\" 2>/dev/null; then
            echo \"EXTRACT_FAILED:.\${s}\" >&2
            exit 1
        fi
        [[ -s \"\${out}\" ]] || { echo \"EMPTY_SECTION:.\${s}\" >&2; exit 1; }
    done
    # The cmdline section is text — strip a trailing NUL byte the UKI
    # builder pads with (the miner-agent passes the cmdline as a Rust
    # String; a trailing NUL would break that). Idempotent: a cmdline
    # without a trailing NUL is untouched.
    if [[ \$(tail -c 1 cmdline | wc -c) -gt 0 ]] && \\
       [[ \$(tail -c 1 cmdline | od -An -tx1 | tr -d ' ') == 00 ]]; then
        truncate -s -1 cmdline
    fi
"

# Pull per-section sha + sizes for the operator-facing summary. These
# are content fingerprints (the §22 launch_digest covers the same
# bytes), so logging them here adds no exposure beyond what the §22
# allowlist already publishes.
read_remote_meta() {
    ssh_run "
        cd '${remote_staging}'
        for f in kernel initrd cmdline; do
            sha=\$(sha256sum \"\$f\" | awk '{print \$1}')
            sz=\$(wc -c < \"\$f\" | tr -d ' ')
            printf '%s %s %s\n' \"\$f\" \"\$sha\" \"\$sz\"
        done
    "
}

declare -A sec_sha sec_sz
while read -r name sha sz; do
    sec_sha[$name]="${sha}"
    sec_sz[$name]="${sz}"
done < <(read_remote_meta)
log "  kernel  size=${sec_sz[kernel]}  sha=${sec_sha[kernel]}"
log "  initrd  size=${sec_sz[initrd]}  sha=${sec_sha[initrd]}"
log "  cmdline size=${sec_sz[cmdline]} sha=${sec_sha[cmdline]}"

# ── dm-verity rootfs disks: fetch + stage alongside the UKI ─────────
#
# `tenant-uki-build.yml` publishes `rootfs.img` (the squashfs) and
# `rootfs.verity` (the hash tree) into the SAME content-addressed S3
# prefix as the UKI — `s3://<bucket>/images/<uki_sha>/{rootfs.img,
# rootfs.verity}`. The miner-agent's libvirt XML attaches these as
# read-only virtio-blk disks at `/dev/vdb` + `/dev/vdc`, and the in-
# guest agent-initramfs verity stage pairs them with the
# `dm-verity.root=` cmdline token to create
# `/dev/mapper/hippius-rootfs`.
#
# These files carry no secrets — the launch_digest covers the verity
# root hash on the cmdline, which integrity-binds the bytes. The
# rootfs.img bytes are deterministic across CI runs by build-rootfs.sh
# discipline; we still sha-gate locally + on the miner because a
# transport corruption would surface here, not at boot time inside
# the SNP guest where diagnostics are intentionally minimal.
for art in rootfs.img rootfs.verity; do
    art_local="${local_tmp}/${art}"
    art_key="images/${tenant_uki_sha}/${art}"
    log "fetching s3://${s3_bucket}/${art_key} → local tmp"
    aws s3 cp "s3://${s3_bucket}/${art_key}" "${art_local}" \
            --endpoint-url "${s3_endpoint}" >/dev/null \
        || die "aws s3 cp failed for ${art} (was the tenant-uki-build publish step skipped? wrong creds?)"
    art_sha=$(sha256sum "${art_local}" | awk '{print $1}')
    art_size=$(wc -c < "${art_local}" | tr -d ' ')
    log "  ${art} size=${art_size} sha=${art_sha}"

    log "scp → ${miner_host}:${remote_staging}/${art}"
    scp_to "${art_local}" "${remote_staging}/${art}" >/dev/null \
        || die "scp failed for ${art}"
    remote_art_sha=$(ssh_run "sha256sum '${remote_staging}/${art}' | awk '{print \$1}'")
    [[ "${remote_art_sha}" == "${art_sha}" ]] \
        || die "remote sha mismatch after scp ${art}: got ${remote_art_sha}, expected ${art_sha}"

    if [[ "${art}" == "rootfs.img" ]]; then
        sec_sha[rootfs_data]="${art_sha}"; sec_sz[rootfs_data]="${art_size}"
    else
        sec_sha[rootfs_hash]="${art_sha}"; sec_sz[rootfs_hash]="${art_size}"
    fi
done

# ── OVMF: symlink cluster-wide pin if present ───────────────────────

ovmf_staged=false
log "checking OVMF at ${miner_host}:${ovmf_path_on_miner}"
if ssh_run "test -r '${ovmf_path_on_miner}'"; then
    ssh_run "ln -sfn '${ovmf_path_on_miner}' '${remote_staging}/ovmf.fd'"
    ovmf_staged=true
    log "  → ovmf.fd symlink → ${ovmf_path_on_miner}"
else
    log "  → MISSING — stage dir will not carry ovmf.fd. Install OVMF once per host (see runbook)."
fi

# ── Atomic flip ─────────────────────────────────────────────────────
#
# `mv -T` makes the rename atomic at the directory level: if `<out>`
# exists as a directory, the rename FAILS by default (refusing a
# clobber). We handle the clobber explicitly: rotate the existing dir
# to a `.prev` sibling and then mv. On the cleanup `rm -rf .prev` —
# best-effort, a leftover .prev is benign (next `--force` reuses it).

ssh_run "
    set -e
    if [[ -e '${out_dir}' ]]; then
        rm -rf '${out_dir}.prev'
        mv -T '${out_dir}' '${out_dir}.prev'
    fi
    mv -T '${remote_staging}' '${out_dir}'
    rm -rf '${out_dir}.prev' || true
"

# ── Final summary ───────────────────────────────────────────────────

log "staged ${miner_host}:${out_dir}/"
jq -nc \
    --arg host "${miner_host}" \
    --arg sha "${tenant_uki_sha}" \
    --arg ver "${tenant_uki_version}" \
    --arg out "${out_dir}" \
    --arg ks "${sec_sha[kernel]}"      --argjson kz "${sec_sz[kernel]}" \
    --arg is "${sec_sha[initrd]}"      --argjson iz "${sec_sz[initrd]}" \
    --arg cs "${sec_sha[cmdline]}"     --argjson cz "${sec_sz[cmdline]}" \
    --arg rds "${sec_sha[rootfs_data]}" --argjson rdz "${sec_sz[rootfs_data]}" \
    --arg rhs "${sec_sha[rootfs_hash]}" --argjson rhz "${sec_sz[rootfs_hash]}" \
    --argjson ovmf "${ovmf_staged}" \
    '{
        miner_host: $host,
        tenant_uki_sha: $sha,
        tenant_uki_version: $ver,
        out_dir: $out,
        kernel:      { sha256: $ks,  size: $kz  },
        initrd:      { sha256: $is,  size: $iz  },
        cmdline:     { sha256: $cs,  size: $cz  },
        rootfs_data: { sha256: $rds, size: $rdz },
        rootfs_hash: { sha256: $rhs, size: $rhz },
        ovmf_staged: $ovmf,
        staged: "fresh"
     }'
