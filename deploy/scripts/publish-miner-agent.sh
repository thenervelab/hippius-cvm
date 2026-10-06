#!/usr/bin/env bash
# =============================================================================
# publish-miner-agent.sh — Publish a hippius-miner-agent build to Hippius S3
#
# The PUBLISH side of the miner auto-update channel (operator/CI runs this).
# It takes a built `hippius-miner-agent` binary + a tag, computes sha256,
# (optionally Ed25519-signs the sha256), uploads the binary + a `latest.json`
# manifest to S3, and makes both public-read. Each miner's systemd timer then
# pulls latest.json, sha256-verifies, installs, and rolls back on failure.
#
#   s3://<bucket>/miner-agent/<tag>/hippius-miner-agent   (the binary)
#   s3://<bucket>/miner-agent/latest.json                 ({tag, sha256, url[, sig]})
#
# The fleet timer is DISARMED by default (miner_auto_update_enabled: false in
# deploy/ansible/group_vars/miner_nodes.yml). On a disarmed miner a publish
# changes nothing: agent rollouts are a manual canary, host by host (the
# SIGKILL swap in deploy/ansible/playbooks/miner-tasks/AUTO_UPDATE.md).
#
# On any miner still ARMED, publishing restarts its agent within ~15 min, at
# the same time as every other armed miner, with no canary. A real upload
# therefore requires --fleet-roll, an explicit acknowledgement of that.
#
# Usage:
#   publish-miner-agent.sh \
#       --binary target/release/hippius-miner-agent \
#       --tag    sha-<gitsha>                         \
#       --fleet-roll                                  \
#       [--sign-key /path/to/ed25519-private.pem]      \
#       [--bucket hippius-compute-images]              \
#       [--prefix miner-agent]                         \
#       [--endpoint https://s3.hippius.com]            \
#       [--dry-run]
#
# Required env (S3 write creds for the Hippius endpoint — the writable
# operator creds, see Vault secret/hippius-compute/s3/operator):
#   AWS_ACCESS_KEY_ID
#   AWS_SECRET_ACCESS_KEY
# Optional env (override defaults):
#   MINER_AGENT_BUCKET    (default: hippius-compute-images)
#   MINER_AGENT_PREFIX    (default: miner-agent)
#   S3_ENDPOINT_URL       (default: https://s3.hippius.com)
#
# Path-style + SigV4 is forced (Hippius S3 requires path-style addressing —
# see deploy/terraform/providers.tf `s3_use_path_style`).
# =============================================================================
set -euo pipefail

BINARY=""
TAG=""
SIGN_KEY=""
BUCKET="${MINER_AGENT_BUCKET:-hippius-compute-images}"
PREFIX="${MINER_AGENT_PREFIX:-miner-agent}"
ENDPOINT="${S3_ENDPOINT_URL:-https://s3.hippius.com}"
DRY_RUN=false
FLEET_ROLL=false

die() { echo "ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --binary)   BINARY="$2"; shift 2 ;;
        --tag)      TAG="$2"; shift 2 ;;
        --sign-key) SIGN_KEY="$2"; shift 2 ;;
        --bucket)   BUCKET="$2"; shift 2 ;;
        --prefix)   PREFIX="$2"; shift 2 ;;
        --endpoint) ENDPOINT="$2"; shift 2 ;;
        --dry-run)  DRY_RUN=true; shift ;;
        --fleet-roll) FLEET_ROLL=true; shift ;;
        -h|--help)  grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)          die "unknown argument: $1" ;;
    esac
done

[ -n "$BINARY" ] || die "--binary is required"
[ -n "$TAG" ]    || die "--tag is required"
[ -f "$BINARY" ] || die "binary not found: $BINARY"
command -v aws >/dev/null 2>&1 || die "aws CLI not found on PATH"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found on PATH"

if [ "$DRY_RUN" != "true" ] && [ "$FLEET_ROLL" != "true" ]; then
    die "refusing to publish without --fleet-roll: every miner with an ARMED
       hippius-miner-update.timer restarts its agent within ~15 min, all at
       once, no canary. The fleet default is disarmed
       (miner_auto_update_enabled: false) and rollouts are a manual canary
       (SIGKILL swap, deploy/ansible/playbooks/miner-tasks/AUTO_UPDATE.md)."
fi

if [ "$DRY_RUN" != "true" ]; then
    [ -n "${AWS_ACCESS_KEY_ID:-}" ]     || die "AWS_ACCESS_KEY_ID is not set"
    [ -n "${AWS_SECRET_ACCESS_KEY:-}" ] || die "AWS_SECRET_ACCESS_KEY is not set"
fi

# Force path-style addressing for the Hippius endpoint.
export AWS_S3_ADDRESSING_STYLE=path

SHA256="$(sha256sum "$BINARY" | awk '{print $1}')"
BINARY_KEY="${PREFIX}/${TAG}/hippius-miner-agent"
MANIFEST_KEY="${PREFIX}/latest.json"
BINARY_URL="${ENDPOINT%/}/${BUCKET}/${BINARY_KEY}"

echo "binary   : $BINARY"
echo "tag      : $TAG"
echo "sha256   : $SHA256"
echo "bucket   : $BUCKET"
echo "endpoint : $ENDPOINT"
echo "binary url: $BINARY_URL"

# ── Optional Ed25519 signature over the sha256-hex string ───────────────────
# Matches the updater's verify: Ed25519 over the lowercase sha256 hex,
# base64-encoded into the manifest `sig` field. The updater pins the matching
# public key (miner_auto_update_pubkey) and enforces it when both are present.
SIG_FIELD=""
if [ -n "$SIGN_KEY" ]; then
    [ -f "$SIGN_KEY" ] || die "--sign-key file not found: $SIGN_KEY"
    command -v openssl >/dev/null 2>&1 || die "openssl required for --sign-key"
    TMP_SIG="$(mktemp)"
    TMP_MSG="$(mktemp)"
    trap 'rm -f "$TMP_SIG" "$TMP_MSG"' EXIT
    printf '%s' "$SHA256" > "$TMP_MSG"
    openssl pkeyutl -sign -inkey "$SIGN_KEY" -rawin -in "$TMP_MSG" -out "$TMP_SIG" \
        || die "Ed25519 signing failed (is --sign-key an Ed25519 private PEM?)"
    SIG_B64="$(base64 -w0 < "$TMP_SIG" 2>/dev/null || base64 < "$TMP_SIG" | tr -d '\n')"
    SIG_FIELD="$SIG_B64"
    echo "sig      : ${SIG_B64:0:24}... (Ed25519 over sha256-hex, base64)"
fi

# ── Build manifest JSON ─────────────────────────────────────────────────────
MANIFEST_FILE="$(mktemp)"
trap 'rm -f "$MANIFEST_FILE" "${TMP_SIG:-}" "${TMP_MSG:-}"' EXIT
if [ -n "$SIG_FIELD" ]; then
    SIG_FIELD="$SIG_FIELD" TAG="$TAG" SHA256="$SHA256" BINARY_URL="$BINARY_URL" \
        python3 -c "
import json, os
print(json.dumps({
    'tag': os.environ['TAG'],
    'sha256': os.environ['SHA256'],
    'url': os.environ['BINARY_URL'],
    'sig': os.environ['SIG_FIELD'],
}, indent=2))" > "$MANIFEST_FILE"
else
    TAG="$TAG" SHA256="$SHA256" BINARY_URL="$BINARY_URL" \
        python3 -c "
import json, os
print(json.dumps({
    'tag': os.environ['TAG'],
    'sha256': os.environ['SHA256'],
    'url': os.environ['BINARY_URL'],
}, indent=2))" > "$MANIFEST_FILE"
fi

echo "--- latest.json ---"
cat "$MANIFEST_FILE"
echo "-------------------"

if [ "$DRY_RUN" = "true" ]; then
    echo "[dry-run] would upload binary  -> s3://${BUCKET}/${BINARY_KEY}"
    echo "[dry-run] would upload manifest -> s3://${BUCKET}/${MANIFEST_KEY}"
    exit 0
fi

# ── Upload (public-read) ────────────────────────────────────────────────────
# Binary first, THEN the manifest — so latest.json never points at an object
# that is not yet uploaded (avoids a window where miners 404 the binary).
echo "Uploading binary -> s3://${BUCKET}/${BINARY_KEY}"
aws s3 cp "$BINARY" "s3://${BUCKET}/${BINARY_KEY}" \
    --endpoint-url "$ENDPOINT" \
    --acl public-read \
    --content-type application/octet-stream \
    --no-progress

echo "Uploading manifest -> s3://${BUCKET}/${MANIFEST_KEY}"
aws s3 cp "$MANIFEST_FILE" "s3://${BUCKET}/${MANIFEST_KEY}" \
    --endpoint-url "$ENDPOINT" \
    --acl public-read \
    --content-type application/json \
    --cache-control "no-cache, max-age=0" \
    --no-progress

echo "Published miner-agent tag=${TAG} sha256=${SHA256}"
echo "Miners with an armed timer pick it up within ~15 min; disarmed miners are untouched."
