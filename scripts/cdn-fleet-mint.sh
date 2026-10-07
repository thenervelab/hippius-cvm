#!/usr/bin/env bash
# cdn-fleet-mint.sh — mint cdn-fleet key version N, then have the KBS
# derive, sign and return its public half (CDN K2, kbs-core/src/cdn_fleet.rs).
#
# What it does
# ------------
#   1. checks the Transit key `cdn-fleet` exists, is aes256-gcm96 and is
#      NOT exportable (with --init-transit-key: creates it that way first);
#   2. asks Transit to GENERATE a 256-bit key and return only its
#      ciphertext:  transit/datakey/wrapped/cdn-fleet bits=256
#      Nobody — not this script, not the operator — sees the plaintext;
#   3. stores that ciphertext ONCE (cas=0) at
#        secret/hippius-compute/kbs/cdn-fleet/v<N>  {"value": base64(ct)}
#      and checks it landed as KV version 1 (the KBS reads exactly that);
#   4. calls `hippius-kbs-admin-client cdn-fleet-public`, which makes the
#      KBS unwrap it inside its CVM, derive the X25519 public key and sign
#      it, and verifies that signature against the pinned KBS response key.
#
# stdout: the verified fleet_keys[] entry (JSON) from step 4.
# stderr: progress only. The ciphertext is never printed either.
#
# Prerequisites
# -------------
# - `vault` CLI with VAULT_ADDR / VAULT_CACERT and a token that may use
#   transit/datakey/wrapped/cdn-fleet and create the KV entry (vali's
#   orchestrator policy grants exactly that; step 1 also needs read on
#   transit/keys/cdn-fleet, --init-transit-key needs create on it).
# - The KBS running with `[cdn_fleet] enabled = true`, the broker with
#   `vault.cdn_fleet_policy`, policy kbs-cap-cdn-fleet in Vault.
# - `hippius-kbs-admin-client` plus its mTLS material
#   (KBS_ADMIN_URL, KBS_ADMIN_CLIENT_CERT/KEY, KBS_ADMIN_CA_CERT).
#
# Usage
# -----
#   scripts/cdn-fleet-mint.sh --version 1 --kbs-vk-hex <64 hex> \
#       [--init-transit-key] [--admin-client PATH] [--skip-kbs]
#
# A version that already exists is refused (cas=0): versions are
# immutable. `--skip-kbs` stops after step 3 (re-run the client later).

set -Eeuo pipefail

PROG="$(basename "$0")"
TRANSIT_KEY="cdn-fleet"
KV_MOUNT="secret"
KV_PREFIX="hippius-compute/kbs/cdn-fleet"

version=""
kbs_vk_hex="${KBS_RESPONSE_VK_HEX:-}"
admin_client="hippius-kbs-admin-client"
init_transit_key=0
skip_kbs=0

die() { echo "${PROG}: ERROR: $*" >&2; exit 1; }
log() { echo "${PROG}: $*" >&2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --kbs-vk-hex) kbs_vk_hex="${2:-}"; shift 2 ;;
    --admin-client) admin_client="${2:-}"; shift 2 ;;
    --init-transit-key) init_transit_key=1; shift ;;
    --skip-kbs) skip_kbs=1; shift ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if ! [[ "$version" =~ ^[1-9][0-9]{0,9}$ ]] || (( version > 4294967295 )); then
  die "--version must be an integer in 1..=4294967295"
fi
if (( ! skip_kbs )); then
  [[ "$kbs_vk_hex" =~ ^[0-9a-f]{64}$ ]] \
    || die "--kbs-vk-hex must be the pinned KBS response key (64 lower-case hex)"
fi
command -v vault >/dev/null || die "vault CLI not found"
command -v jq >/dev/null || die "jq not found"

# 1. The Transit key: exists, right type, never exportable.
if ! key_json="$(vault read -format=json "transit/keys/${TRANSIT_KEY}" 2>/dev/null)"; then
  (( init_transit_key )) || die "transit/keys/${TRANSIT_KEY} not found (or not readable); \
re-run with --init-transit-key to create it"
  log "creating transit/keys/${TRANSIT_KEY} (aes256-gcm96, exportable=false)"
  vault write -f "transit/keys/${TRANSIT_KEY}" type=aes256-gcm96 exportable=false \
    allow_plaintext_backup=false >/dev/null
  key_json="$(vault read -format=json "transit/keys/${TRANSIT_KEY}")"
fi
[[ "$(jq -r '.data.type' <<<"$key_json")" == "aes256-gcm96" ]] \
  || die "transit/keys/${TRANSIT_KEY} is not aes256-gcm96"
[[ "$(jq -r '.data.exportable' <<<"$key_json")" == "false" ]] \
  || die "transit/keys/${TRANSIT_KEY} is EXPORTABLE — refusing to mint under it"
[[ "$(jq -r '.data.allow_plaintext_backup' <<<"$key_json")" == "false" ]] \
  || die "transit/keys/${TRANSIT_KEY} allows plaintext backup — refusing to mint under it"
[[ "$(jq -r '.data.deletion_allowed' <<<"$key_json")" == "false" ]] \
  || log "WARNING: transit/keys/${TRANSIT_KEY} has deletion_allowed=true (one call from losing every fleet key)"

path="${KV_PREFIX}/v${version}"

# 2 + 3. Generate wrapped, store once. The ciphertext only ever lives in
# this shell variable and on Vault's stdin.
ct="$(vault write -field=ciphertext -f "transit/datakey/wrapped/${TRANSIT_KEY}" bits=256)"
[[ "$ct" == vault:v* ]] || die "transit/datakey/wrapped did not return Transit ciphertext"
if ! printf '%s' "$ct" | base64 -w0 | vault kv put -mount="${KV_MOUNT}" -cas=0 "${path}" value=- >/dev/null; then
  unset ct
  die "could not create ${KV_MOUNT}/${path} — it may already exist (versions are immutable)"
fi
unset ct
kv_version="$(vault kv metadata get -mount="${KV_MOUNT}" -format=json "${path}" 2>/dev/null \
  | jq -r '.data.current_version' || true)"
if [[ -n "$kv_version" && "$kv_version" != "1" ]]; then
  die "${KV_MOUNT}/${path} is at KV version ${kv_version}, not 1 — the KBS will not read it"
fi
log "stored ${KV_MOUNT}/${path} (KV version 1, Transit-wrapped)"

(( skip_kbs )) && { log "--skip-kbs: not asking the KBS for the public key"; exit 0; }

# 4. KBS-derived, KBS-signed, verified against the pinned key.
"${admin_client}" cdn-fleet-public --version "${version}" --kbs-vk-hex "${kbs_vk_hex}"
