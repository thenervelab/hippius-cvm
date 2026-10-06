#!/usr/bin/env bash
# tenant-secrets-stage.sh — stage per-tenant KBS release secrets in
# Vault to the PR-V schema (`binaries/kbs-server/src/vault_mvp.rs`).
#
# What this stages
# ---------------
# Two KV-v2 secrets per tenant, both rooted under
# `<--vault-path-prefix>/<vm-id>/`:
#
#   <prefix>/<vm>/luks-kek    body = {"value": "<base64(vault:v1:… Transit ct)>"}
#   <prefix>/<vm>/userdata    body = {"value": "<base64(vault:v1:… Transit ct)>"}
#
# KEK-HSM (RA-08a/F1): the luks-kek value is the KEK WRAPPED with its per-VM
# Vault Transit key (ciphertext, never plaintext at rest). The attested KBS
# `read_exact` → base64-decode → detects the `vault:` prefix →
# `transit_decrypt` inside its CVM → HPKE-wraps the recovered secret to the
# guest.
#
# The user-data goes through the SAME wrap, under the SAME per-VM key. It
# used to be staged as raw bytes — and a tenant's cloud-init routinely
# carries SSH keys, API tokens and the NetBird enrolment secret, so this
# script was writing exactly the material the KEK wrapping exists to
# protect in the clear, right next to the wrapped KEK. Wrapping it under
# `kek-<vm>` also means §24's Transit destroy crypto-erases it.
#
# What this prints (stdout, JSON)
# -------------------------------
# Single-line JSON the PR-B `order-ticket-mint` binary feeds straight
# into the `OrderTicket`:
#   { "vm_id":..., "tenant_id":..., "ticket_id":...,
#     "luks_vault_ref": { "path": "...", "version": N },
#     "userdata_vault_ref": { "path": "...", "version": M },
#     "allowed_userdata_digest_hex": "<64 hex>" }
#
# §20 logging discipline
# ----------------------
# Stderr carries progress only — never the LUKS KEK, never the user-
# data plaintext, never the base64 of either. Diagnostics are limited
# to: file length, sha256 of the staged bytes (which is also the
# digest the script prints anyway for user-data), Vault HTTP status,
# version number.
#
# References
# ----------
# - vault_mvp.rs: `parse_kv_secret_body` and the schema-lock module doc.
# - kbs-core/src/release.rs::run: how the digest binds to the bytes.
# - hippius-types/src/digest.rs::userdata_digest: canonical preimage.
# - docs/operator/byo-base-os-bake-runbook.md: end-to-end runbook.

set -Eeuo pipefail

# ── Defaults + state ────────────────────────────────────────────────

PROG="$(basename "$0")"
# Resolve the repo's vault-ca.crt next to this script (../vault-ca.crt
# from `scripts/`). If the script is invoked from outside the repo,
# the operator passes `--vault-cacert`.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_VAULT_CACERT="${REPO_ROOT}/vault-ca.crt"

# NO DEFAULT, deliberately: this script WRITES tenant secrets. A
# baked-in address would send another deployment's LUKS KEKs
# somewhere its operator never chose. Supply $VAULT_ADDR or
# --vault-addr; unset is a hard error below.
VAULT_ADDR_DEFAULT=""
VAULT_PATH_PREFIX_DEFAULT="hippius-compute/kbs/tenants"
# `VAULT_FORMAT=json` makes `vault kv put` emit a parseable envelope
# we can `jq -r '.data.version'` out of — without changing the user's
# global shell config.
export VAULT_FORMAT=json

vm_id=""
tenant_id=""
ticket_id=""
luks_kek_file=""
userdata_file=""
vault_addr="${VAULT_ADDR:-${VAULT_ADDR_DEFAULT}}"
# The Vault token is NEVER accepted on the command line (audit
# M-drop-vault-token-argv): an argv token is world-readable via
# `ps`/`/proc/<pid>/cmdline` for the process lifetime. It comes from
# `$VAULT_TOKEN` (env — not in argv) or, preferred, a file via
# `--vault-token-file` / `$VAULT_TOKEN_FILE` (never in argv nor env).
vault_token="${VAULT_TOKEN:-}"
vault_token_file="${VAULT_TOKEN_FILE:-}"
# CA precedence: explicit --vault-cacert / $VAULT_CACERT > repo-local
# vault-ca.crt (if present) > unset (defer to vault CLI's system trust,
# which is the right answer once the prod CA is a trusted issuer).
vault_cacert="${VAULT_CACERT:-}"
if [[ -z "${vault_cacert}" && -r "${DEFAULT_VAULT_CACERT}" ]]; then
    vault_cacert="${DEFAULT_VAULT_CACERT}"
fi
vault_path_prefix="${VAULT_PATH_PREFIX:-${VAULT_PATH_PREFIX_DEFAULT}}"
force=0

# ── Helpers ─────────────────────────────────────────────────────────

# All progress lines go to stderr; stdout is reserved for the final
# JSON output the caller (PR-B mint binary, runbook copy/paste) parses.
log() { printf '%s: %s\n' "${PROG}" "$*" >&2; }
die() {
    log "ERROR: $*"
    exit 1
}

usage() {
    cat >&2 <<EOF
${PROG} — stage per-tenant KBS release secrets in Vault.

Usage:
  ${PROG} --vm-id ID --tenant-id ID --ticket-id ID \\
          --luks-kek-file PATH --userdata-file PATH \\
          [--vault-addr URL] [--vault-token-file PATH] \\
          [--vault-cacert PATH] [--vault-path-prefix PREFIX] \\
          [--force]

Required:
  --vm-id ID          OrderTicket.vm_id. Becomes the per-tenant
                      sub-path under <vault-path-prefix>.
  --tenant-id ID      OrderTicket.tenant_id. Binds the user-data
                      digest preimage (kbs-core/src/release.rs::run).
  --ticket-id ID      OrderTicket.ticket_id. Same binding.
  --luks-kek-file P   Binary file (exactly 32 bytes) holding the LUKS
                      slot passphrase. Same bytes that the tenant
                      disk image's LUKS keyslot accepts.
  --userdata-file P   Cloud-init NoCloud user-data plaintext bytes
                      (typically a #cloud-config YAML carrying the
                      NetBird setup-key + first-boot config).

Optional:
  --vault-addr URL    Vault address, e.g. https://vault.example.invalid:8200
                      Default: \$VAULT_ADDR. REQUIRED — there is no
                      built-in default.
  --vault-token-file P  File holding the Vault token (read once, never
                      placed on argv/env). Default: \$VAULT_TOKEN_FILE.
                      If unset, \$VAULT_TOKEN (env) is used. A token is
                      required (no anonymous writes). NOTE: passing the
                      token on the command line is deliberately NOT
                      supported — argv is world-readable via ps.
  --vault-cacert P    Vault CA cert (self-signed Tier-0). Default:
                      \$VAULT_CACERT, else the repo's vault-ca.crt
                      next to scripts/ (${DEFAULT_VAULT_CACERT}).
  --vault-path-prefix PFX
                      KV-v2 path prefix WITHOUT the leading mount
                      (Vault prepends 'secret/data/'). Default:
                      \$VAULT_PATH_PREFIX, else
                      ${VAULT_PATH_PREFIX_DEFAULT}.
  --force             Allow overwriting an existing path (Vault
                      creates a new KV-v2 version; metadata persists).
                      Without --force, an existing path aborts.

Output (stdout, single-line JSON):
  { "vm_id": ..., "tenant_id": ..., "ticket_id": ...,
    "luks_vault_ref":     { "path": ..., "version": N },
    "userdata_vault_ref": { "path": ..., "version": M },
    "allowed_userdata_digest_hex": "<64 hex chars>" }

Schema (matches binaries/kbs-server/src/vault_mvp.rs PR-V lock):
  <prefix>/<vm>/luks-kek   ← {"value": "<base64(vault:v1:… Transit ciphertext)>"}
  <prefix>/<vm>/userdata   ← {"value": "<base64(vault:v1:… Transit ciphertext)>"}
EOF
}

require_arg() {
    [[ -n "${2-}" ]] || die "$1 requires a value"
}

ascii_id() {
    # Match the kbs-core / ticket-validator ID character set:
    # alphanumeric + - + _ . Reject anything else upfront so a bad
    # vm-id can't slip into a Vault path and break the §19 exact-read
    # path contract.
    local field="$1" val="$2"
    [[ -n "${val}" ]] || die "${field} must not be empty"
    [[ "${val}" =~ ^[A-Za-z0-9._-]+$ ]] \
        || die "${field}='${val}' contains characters outside [A-Za-z0-9._-]"
}

reject_placeholder() {
    # The script must never silently stage a `REPLACE_ME_*` placeholder
    # (e.g. operator forgot to substitute a setup key in a template).
    local field="$1" path="$2"
    if LC_ALL=C grep -q -F 'REPLACE_ME_' "${path}"; then
        die "${field} (${path}) contains literal 'REPLACE_ME_' — refusing to stage"
    fi
}

# Compute hippius_types::digest::userdata_digest in Python, matching
# the framed-LE encoding in hippius-types/src/digest.rs::userdata_digest.
# The file path is passed as the LAST argv so Python reads it directly —
# heredoc-stdin is already taken by the Python source. Stdout: 64-char
# lowercase hex (sha256).
#
# The bytes digested are the PLAINTEXT, even though what is STAGED is the
# ciphertext: the KBS unwraps before it recomputes, and the guest re-derives
# the same digest a third time over the plaintext it receives
# (hippius-guest/src/release.rs) and refuses the release on a mismatch.
# Digesting the stored ciphertext would deny every launch.
compute_userdata_digest_hex() {
    local tenant="$1" vm="$2" ticket="$3" path="$4" version="$5" plaintext_path="$6"
    python3 - \
        "${tenant}" "${vm}" "${ticket}" "userdata" "${path}" "${version}" "${plaintext_path}" \
        <<'PY'
import hashlib
import sys

DOMAIN = b"HIPPIUS_USERDATA_DIGEST_V1"


def put_framed(h, s: bytes) -> None:
    h.update(len(s).to_bytes(8, "little"))
    h.update(s)


def main() -> int:
    tenant_id, vm_id, ticket_id, secret_type, path, version_s, ud_path = sys.argv[1:8]
    version = int(version_s)
    with open(ud_path, "rb") as f:
        plaintext = f.read()
    h = hashlib.sha256()
    put_framed(h, DOMAIN)
    put_framed(h, tenant_id.encode("utf-8"))
    put_framed(h, vm_id.encode("utf-8"))
    put_framed(h, ticket_id.encode("utf-8"))
    put_framed(h, secret_type.encode("utf-8"))
    put_framed(h, path.encode("utf-8"))
    h.update(version.to_bytes(8, "little"))
    put_framed(h, plaintext)
    sys.stdout.write(h.hexdigest())
    return 0


sys.exit(main())
PY
}

# ── Parse args ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --vm-id)              require_arg "$1" "${2-}"; vm_id="$2";              shift 2;;
        --tenant-id)          require_arg "$1" "${2-}"; tenant_id="$2";          shift 2;;
        --ticket-id)          require_arg "$1" "${2-}"; ticket_id="$2";          shift 2;;
        --luks-kek-file)      require_arg "$1" "${2-}"; luks_kek_file="$2";      shift 2;;
        --userdata-file)      require_arg "$1" "${2-}"; userdata_file="$2";      shift 2;;
        --vault-addr)         require_arg "$1" "${2-}"; vault_addr="$2";         shift 2;;
        --vault-token-file)   require_arg "$1" "${2-}"; vault_token_file="$2";   shift 2;;
        --vault-token)        die "--vault-token is not supported (argv is world-readable via ps); use --vault-token-file or \$VAULT_TOKEN";;
        --vault-cacert)       require_arg "$1" "${2-}"; vault_cacert="$2";       shift 2;;
        --vault-path-prefix)  require_arg "$1" "${2-}"; vault_path_prefix="$2";  shift 2;;
        --force)              force=1;                                           shift;;
        -h|--help)            usage; exit 0;;
        *)                    die "unknown argument: $1 (try --help)";;
    esac
done

# ── Validate inputs ─────────────────────────────────────────────────

[[ -n "${vm_id}"          ]] || { usage; die "--vm-id is required"; }
[[ -n "${tenant_id}"      ]] || die "--tenant-id is required"
[[ -n "${ticket_id}"      ]] || die "--ticket-id is required"
[[ -n "${luks_kek_file}"  ]] || die "--luks-kek-file is required"
[[ -n "${userdata_file}"  ]] || die "--userdata-file is required"
# Resolve the token from a file if given (preferred — never argv/env),
# else fall back to $VAULT_TOKEN (env). Strip a trailing newline.
if [[ -n "${vault_token_file}" ]]; then
    [[ -r "${vault_token_file}" ]] || die "--vault-token-file '${vault_token_file}' not readable"
    vault_token="$(tr -d '\r\n' < "${vault_token_file}")"
fi
[[ -n "${vault_token}"    ]] || die "a Vault token is required (--vault-token-file PATH or \$VAULT_TOKEN)"

ascii_id "--vm-id" "${vm_id}"
ascii_id "--tenant-id" "${tenant_id}"
ascii_id "--ticket-id" "${ticket_id}"

[[ -r "${luks_kek_file}"  ]] || die "--luks-kek-file '${luks_kek_file}' not readable"
[[ -r "${userdata_file}"  ]] || die "--userdata-file '${userdata_file}' not readable"

luks_size=$(wc -c < "${luks_kek_file}" | tr -d ' ')
[[ "${luks_size}" -eq 32 ]] \
    || die "--luks-kek-file must be exactly 32 bytes (got ${luks_size})"

ud_size=$(wc -c < "${userdata_file}" | tr -d ' ')
[[ "${ud_size}" -gt 0 ]] || die "--userdata-file '${userdata_file}' is empty"

reject_placeholder "--luks-kek-file" "${luks_kek_file}"
reject_placeholder "--userdata-file" "${userdata_file}"

# `vault:` is the discriminator that says "this stored value is Transit
# ciphertext". A cloud-config never starts with it, and staging one that
# does produces a blob the KBS unwraps into something still prefixed
# `vault:` — which it refuses as a double wrap, two systems away from the
# typo. The launch API and `vali_create_vm` reject the same shape.
if LC_ALL=C head -c 6 "${userdata_file}" | grep -q '^vault:'; then
    die "--userdata-file starts with 'vault:', which is reserved for Transit ciphertext — pass cloud-init plaintext"
fi

if [[ -n "${vault_cacert}" && ! -r "${vault_cacert}" ]]; then
    die "--vault-cacert '${vault_cacert}' not readable"
fi

[[ -n "${vault_addr}" ]] \
    || die "Vault address is not set — pass --vault-addr URL or export VAULT_ADDR"


# ── Vault wiring ────────────────────────────────────────────────────

export VAULT_ADDR="${vault_addr}"
export VAULT_TOKEN="${vault_token}"
if [[ -n "${vault_cacert}" ]]; then
    export VAULT_CACERT="${vault_cacert}"
fi

luks_kv_path="${vault_path_prefix}/${vm_id}/luks-kek"
ud_kv_path="${vault_path_prefix}/${vm_id}/userdata"
ud_work_kv_path="${vault_path_prefix}/${vm_id}/userdata-pending"

# `secret/<path>` is the KV-v2 mount-rooted address vault CLI expects.
luks_full="secret/${luks_kv_path}"
ud_full="secret/${ud_kv_path}"
ud_work_full="secret/${ud_work_kv_path}"

# Vault metadata read returns the current_version (or fails if the
# path doesn't exist). We don't want stderr leaking 'no value found'
# into the operator's terminal when a path is fresh — squelch and
# branch on exit code.
path_exists() {
    local mount_path="$1"
    vault kv metadata get -format=json "${mount_path}" >/dev/null 2>&1
}

if [[ "${force}" -ne 1 ]]; then
    if path_exists "${luks_full}"; then
        die "${luks_full} already exists — re-run with --force to roll the KEK (new KV version)"
    fi
    if path_exists "${ud_full}"; then
        die "${ud_full} already exists — re-run with --force to roll the user-data"
    fi
fi

# ── Stage secrets ───────────────────────────────────────────────────

log "vault-addr=${VAULT_ADDR} cacert=${VAULT_CACERT:-<system>}"
log "vm_id=${vm_id} tenant_id=${tenant_id} ticket_id=${ticket_id}"

# `base64 -w0` keeps the line unwrapped (single-line value) — Vault
# stores whatever string we pass, but a wrapped \n would round-trip
# back through `parse_kv_secret_body`'s STANDARD decoder and would
# decode fine, while needlessly enlarging the stored body. The
# resulting variable holds the base64 string only in the script's
# process memory and is never logged.
luks_b64=$(base64 -w0 < "${luks_kek_file}")
ud_b64=$(base64 -w0 < "${userdata_file}")

# Trace fingerprints, not the bytes. Deliberately NOT the sha256 of the
# user-data PLAINTEXT: that is a fingerprint of the secret itself (it
# confirms a guess), and now that the digest printed on stdout is taken
# over the ciphertext, logging it would be a fresh exposure rather than a
# restatement of something already emitted. Size only.
log "luks-kek: 32 bytes (sha256=$(sha256sum "${luks_kek_file}" | cut -d' ' -f1))"
log "userdata: ${ud_size} bytes"

# KEK-HSM (RA-08a / F1): WRAP the KEK with its per-VM Vault Transit key so it is
# CIPHERTEXT (`vault:v1:…`) at rest — never plaintext. Mirrors the baker
# (`binaries/tenant-baker/entrypoint.sh`) + `vali_stage_tenant_kek`; the attested
# KBS transit-decrypts it inside its CVM on release (`kbs-core/src/release.rs`
# detects the `vault:` prefix). So a Vault storage / etcd-snapshot compromise
# yields ciphertext, not a usable tenant KEK. The staging token needs
# `transit/keys/kek-*` (create) + `transit/encrypt/kek-*` — NOT decrypt.
log "wrapping luks-kek with Transit key kek-${vm_id}"
vault write -f "transit/keys/kek-${vm_id}" >/dev/null \
    || die "could not create Transit key kek-${vm_id} (token needs transit/keys/kek-* create)"
luks_ct=$(vault write -field=ciphertext "transit/encrypt/kek-${vm_id}" "plaintext=${luks_b64}") \
    || die "transit/encrypt of luks-kek failed (token needs transit/encrypt/kek-* + transit/keys/kek-* create)"
unset luks_b64
[[ "${luks_ct}" == vault:* ]] || die "transit/encrypt did not return a vault: ciphertext"
# Store base64(ciphertext): the KBS reads .data.value → base64-decode → `vault:v1:…`
# → transit-decrypt. Same at-rest shape the baker + vali produce.
luks_store_b64=$(printf '%s' "${luks_ct}" | base64 -w0)
unset luks_ct

log "staging ${luks_full} (Transit ciphertext — never plaintext at rest)"
luks_put_out=$(vault kv put "${luks_full}" "value=${luks_store_b64}")
unset luks_store_b64
luks_version=$(echo "${luks_put_out}" | jq -er '.data.version // empty') \
    || die "could not parse luks-kek version from vault put output"
log "  → version=${luks_version}"

# Same wrap for the user-data, same per-VM key (so §24's Transit destroy
# covers both). The KBS unwraps it on release exactly like the KEK.
log "wrapping userdata with Transit key kek-${vm_id}"
ud_ct=$(vault write -field=ciphertext "transit/encrypt/kek-${vm_id}" "plaintext=${ud_b64}") \
    || die "transit/encrypt of userdata failed (token needs transit/encrypt/kek-* + transit/keys/kek-* create)"
unset ud_b64
[[ "${ud_ct}" == vault:* ]] || die "transit/encrypt did not return a vault: ciphertext"
ud_store_b64=$(printf '%s' "${ud_ct}" | base64 -w0)
unset ud_ct

log "staging ${ud_full} (Transit ciphertext — never plaintext at rest)"
ud_put_out=$(vault kv put "${ud_full}" "value=${ud_store_b64}")
unset ud_store_b64
ud_version=$(echo "${ud_put_out}" | jq -er '.data.version // empty') \
    || die "could not parse user-data version from vault put output"
log "  → version=${ud_version}"

# vali's WORKING COPY of the same bytes, wrapped under `ud-<vm>` — the
# per-VM key vali may decrypt. Without it a hand-staged VM cannot be §25
# migrated or KBS-state recovered: those re-mint under a fresh ticket_id,
# the §6 digest binds it, and re-deriving the digest needs the cloud-init
# plaintext — which the canonical copy above no longer yields (it is
# wrapped under the KBS-only key). §24 destroys BOTH keys and deletes
# both blobs, so this copy does not outlive the VM.
#
# STAMPED, inside the wrapped blob, with the canonical KV version it
# corresponds to — the exact form `launch.stage_userdata_working_copy`
# writes (`hippius-userdata-for-canonical-v<N>\n` + plaintext). The
# reader (`launch.open_userdata_working_copy`) REFUSES an unstamped copy
# and one stamped for another version, at §25 intake and at the re-mint:
# the two KV writes are not atomic, so the stamp is what proves this copy
# holds the bytes canonical version N holds. An unstamped copy here made
# every hand-staged VM unmigratable and unrecoverable.
log "wrapping userdata working copy with Transit key ud-${vm_id} (stamped for canonical v${ud_version})"
ud_b64_for_work=$(
    { printf 'hippius-userdata-for-canonical-v%s\n' "${ud_version}"; cat "${userdata_file}"; } \
        | base64 -w0
)
vault write -f "transit/keys/ud-${vm_id}" >/dev/null \
    || die "could not create Transit key ud-${vm_id} (token needs transit/keys/ud-* create)"
ud_work_ct=$(vault write -field=ciphertext "transit/encrypt/ud-${vm_id}" "plaintext=${ud_b64_for_work}") \
    || die "transit/encrypt of the userdata working copy failed (token needs transit/encrypt/ud-* + transit/keys/ud-* create)"
unset ud_b64_for_work
[[ "${ud_work_ct}" == vault:* ]] || die "transit/encrypt did not return a vault: ciphertext"
ud_work_store_b64=$(printf '%s' "${ud_work_ct}" | base64 -w0)
unset ud_work_ct
log "staging ${ud_work_full} (vali working copy — Transit ciphertext)"
vault kv put "${ud_work_full}" "value=${ud_work_store_b64}" >/dev/null \
    || die "could not stage the userdata working copy"
unset ud_work_store_b64

# ── Compute digest + emit JSON ──────────────────────────────────────

log "computing allowed_userdata_digest"
ud_digest_hex=$(
    compute_userdata_digest_hex \
        "${tenant_id}" "${vm_id}" "${ticket_id}" \
        "${ud_kv_path}" "${ud_version}" "${userdata_file}"
)
[[ "${ud_digest_hex}" =~ ^[0-9a-f]{64}$ ]] \
    || die "digest computation returned malformed output"
log "  → ${ud_digest_hex}"

jq -nc \
    --arg vm "${vm_id}" \
    --arg tenant "${tenant_id}" \
    --arg ticket "${ticket_id}" \
    --arg lp "${luks_kv_path}" --argjson lv "${luks_version}" \
    --arg up "${ud_kv_path}"   --argjson uv "${ud_version}" \
    --arg digest "${ud_digest_hex}" \
    '{
        vm_id: $vm,
        tenant_id: $tenant,
        ticket_id: $ticket,
        luks_vault_ref:     { path: $lp, version: $lv },
        userdata_vault_ref: { path: $up, version: $uv },
        allowed_userdata_digest_hex: $digest
     }'
