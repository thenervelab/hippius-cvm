#!/usr/bin/env bash
# =============================================================================
# hippius-miner-update.sh — Auto-update hippius-miner-agent from Hippius S3
#
# Modelled on arion's `arion-miner-update.sh` (GitHub-release driven), but
# adapted to Hippius S3 as the distribution channel. A systemd timer fires
# this oneshot every ~15 min.
#
# Flow:
#   1. Fetch ${S3_BASE}/latest.json  → { "tag", "sha256", "url" }
#   2. Compare manifest sha256 with the INSTALLED binary's sha256.
#      Equal → already up to date, exit 0.
#      (We compare sha256, NOT `--version`: `hippius-miner-agent --version`
#       prints a STATIC `hippius-miner-agent 0.0.1` — the Cargo crate
#       version, which is never bumped — so a version compare can't detect
#       a fresh build. The sha256 changes on every new build, so it is the
#       real change-detection signal. `tag` is for human-readable logging.)
#   3. Download the binary, recompute sha256, REQUIRE it to equal the
#      manifest sha256 before installing (integrity, MANDATORY).
#   4. OPTIONAL Ed25519 signature verify if UPDATE_PUBKEY is configured and
#      the manifest ships a `sig` — otherwise skip (sha256-over-HTTPS is the
#      baseline, matching arion's simplicity).
#   5. Sanity-run the new binary (`--help`), stop the service, back up the
#      old binary, atomic install, restart, health-check (is-active AND a
#      fresh heartbeat delivered). ROLL BACK to the backup on any failure.
#
# Install (handled by the Ansible miner-tasks role):
#   install -m 0755 hippius-miner-update.sh /usr/local/bin/hippius-miner-update
#   # renders /etc/hippius-miner/auto-update.env with S3_BASE (+ UPDATE_PUBKEY)
#   systemctl enable --now hippius-miner-update.timer
#
# To disable auto-update on a specific miner (e.g. a dev box):
#   touch /var/lib/hippius-miner/.no-auto-update
#   # or set AUTO_UPDATE_DISABLED=true in /etc/hippius-miner/auto-update.env
# =============================================================================
set -euo pipefail

# ── Config (env file rendered by Ansible) ───────────────────────────────────
ENV_FILE="${HIPPIUS_MINER_UPDATE_ENV:-/etc/hippius-miner/auto-update.env}"
# shellcheck source=/dev/null
[ -f "$ENV_FILE" ] && . "$ENV_FILE"

BINARY_PATH="${MINER_BINARY:-/usr/local/bin/hippius-miner-agent}"
SERVICE_NAME="${MINER_SERVICE:-hippius-miner-agent}"
STATE_DIR="${MINER_STATE_DIR:-/var/lib/hippius-miner}"
NO_UPDATE_FLAG="${STATE_DIR}/.no-auto-update"
# S3_BASE e.g. https://s3.hippius.com/<bucket>/miner-agent  (no trailing slash)
S3_BASE="${S3_BASE:-}"
# Optional pinned operator Ed25519 public key (PEM path or 64-hex). Empty = skip sig.
UPDATE_PUBKEY="${UPDATE_PUBKEY:-}"
AUTO_UPDATE_DISABLED="${AUTO_UPDATE_DISABLED:-false}"

LOG_TAG="hippius-miner-update"
TMP_DIR="$(mktemp -d)"

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

log() { echo "[$LOG_TAG] $*" | systemd-cat -t "$LOG_TAG" -p info 2>/dev/null || echo "[$LOG_TAG] $*"; }
err() { echo "[$LOG_TAG] ERROR: $*" | systemd-cat -t "$LOG_TAG" -p err 2>/dev/null || echo "[$LOG_TAG] ERROR: $*" >&2; }

# ── Pre-flight ──────────────────────────────────────────────────────────────
if [ -f "$NO_UPDATE_FLAG" ]; then
    log "Auto-update disabled (.no-auto-update flag present at $NO_UPDATE_FLAG)"
    exit 0
fi
if [ "$AUTO_UPDATE_DISABLED" = "true" ]; then
    log "Auto-update disabled (AUTO_UPDATE_DISABLED=true)"
    exit 0
fi
if [ -z "$S3_BASE" ]; then
    err "S3_BASE is not configured (expected in $ENV_FILE) — refusing to run"
    exit 1
fi
if [ ! -x "$BINARY_PATH" ]; then
    err "Installed binary not found at $BINARY_PATH"
    exit 1
fi

sha256_of() { sha256sum "$1" | awk '{print $1}'; }

# ── Fetch the manifest ──────────────────────────────────────────────────────
MANIFEST="${TMP_DIR}/latest.json"
MANIFEST_URL="${S3_BASE%/}/latest.json"
log "Fetching manifest: $MANIFEST_URL"
if ! curl -sfL --max-time 30 -o "$MANIFEST" "$MANIFEST_URL"; then
    err "Failed to fetch manifest from $MANIFEST_URL"
    exit 1
fi
if [ ! -s "$MANIFEST" ]; then
    err "Manifest is empty"
    exit 1
fi

# Parse manifest with python3 (always present on the miner image; same
# approach arion uses for the GitHub asset list).
read_manifest_field() {
    MANIFEST="$MANIFEST" python3 -c "
import json, os, sys
d = json.load(open(os.environ['MANIFEST']))
print(d.get(sys.argv[1], ''))
" "$1" 2>/dev/null || echo ""
}

MANIFEST_SHA="$(read_manifest_field sha256)"
MANIFEST_TAG="$(read_manifest_field tag)"
MANIFEST_URL_FIELD="$(read_manifest_field url)"
MANIFEST_SIG="$(read_manifest_field sig)"

if [ -z "$MANIFEST_SHA" ]; then
    err "Manifest is missing the required 'sha256' field"
    exit 1
fi
# Normalise to lowercase hex for the comparison.
MANIFEST_SHA="$(echo "$MANIFEST_SHA" | tr '[:upper:]' '[:lower:]')"
log "Manifest tag=${MANIFEST_TAG:-<none>} sha256=${MANIFEST_SHA}"

# ── Change detection: manifest sha256 vs installed binary sha256 ────────────
INSTALLED_SHA="$(sha256_of "$BINARY_PATH" | tr '[:upper:]' '[:lower:]')"
log "Installed binary sha256=${INSTALLED_SHA}"
if [ "$MANIFEST_SHA" = "$INSTALLED_SHA" ]; then
    log "Already up to date (sha256 match)"
    exit 0
fi
log "New build published — updating (installed ${INSTALLED_SHA:0:12} -> published ${MANIFEST_SHA:0:12}, tag ${MANIFEST_TAG:-<none>})"

# ── Download the new binary ─────────────────────────────────────────────────
if [ -n "$MANIFEST_URL_FIELD" ]; then
    DOWNLOAD_URL="$MANIFEST_URL_FIELD"
elif [ -n "$MANIFEST_TAG" ]; then
    DOWNLOAD_URL="${S3_BASE%/}/${MANIFEST_TAG}/hippius-miner-agent"
else
    err "Manifest has neither 'url' nor 'tag' — cannot locate the binary"
    exit 1
fi

NEW_BINARY="${TMP_DIR}/hippius-miner-agent"
log "Downloading binary: $DOWNLOAD_URL"
if ! curl -sfL --max-time 180 -o "$NEW_BINARY" "$DOWNLOAD_URL"; then
    err "Failed to download binary from $DOWNLOAD_URL"
    exit 1
fi
if [ ! -s "$NEW_BINARY" ]; then
    err "Downloaded binary is empty"
    exit 1
fi

# ── Integrity: recompute sha256, REQUIRE match (MANDATORY) ──────────────────
DOWNLOAD_SHA="$(sha256_of "$NEW_BINARY" | tr '[:upper:]' '[:lower:]')"
if [ "$DOWNLOAD_SHA" != "$MANIFEST_SHA" ]; then
    err "sha256 mismatch: manifest=${MANIFEST_SHA} download=${DOWNLOAD_SHA} — refusing to install"
    exit 1
fi
log "sha256 verified: ${DOWNLOAD_SHA}"

# ── Signature (OPTIONAL): Ed25519 over the sha256 hex, if pubkey configured ──
# We sign the lowercase sha256 hex string (compact, deterministic, and the
# sha256 already binds the full binary). publish-miner-agent.sh signs the
# same string. Only enforced when BOTH a pubkey is pinned AND the manifest
# ships a `sig`; otherwise the sha256-over-HTTPS baseline stands.
if [ -n "$UPDATE_PUBKEY" ]; then
    if [ -z "$MANIFEST_SIG" ]; then
        err "UPDATE_PUBKEY is configured but the manifest carries no 'sig' — refusing (signing required once a key is pinned)"
        exit 1
    fi
    # Resolve the pubkey to a PEM file usable by `openssl pkeyutl`.
    PUBKEY_PEM="${TMP_DIR}/update.pub.pem"
    if [ -f "$UPDATE_PUBKEY" ]; then
        cp "$UPDATE_PUBKEY" "$PUBKEY_PEM"
    else
        # Treat as 64-hex raw Ed25519 public key → wrap into a DER/PEM
        # SubjectPublicKeyInfo (the 12-byte Ed25519 SPKI prefix + the 32 key bytes).
        if ! printf '%s' "$UPDATE_PUBKEY" | grep -Eq '^[0-9a-fA-F]{64}$'; then
            err "UPDATE_PUBKEY is neither a readable PEM file nor 64-hex — cannot verify signature"
            exit 1
        fi
        if ! printf '302a300506032b6570032100%s' "$(echo "$UPDATE_PUBKEY" | tr '[:upper:]' '[:lower:]')" \
                | xxd -r -p \
                | openssl pkey -pubin -inform DER -out "$PUBKEY_PEM" 2>/dev/null; then
            err "Failed to materialise Ed25519 pubkey from hex (need openssl + xxd)"
            exit 1
        fi
    fi
    # The signature is base64 of the raw 64-byte Ed25519 signature over the
    # sha256-hex string.
    SIG_BIN="${TMP_DIR}/update.sig"
    if ! printf '%s' "$MANIFEST_SIG" | base64 -d > "$SIG_BIN" 2>/dev/null; then
        err "Manifest 'sig' is not valid base64"
        exit 1
    fi
    SHA_MSG="${TMP_DIR}/sha.msg"
    printf '%s' "$MANIFEST_SHA" > "$SHA_MSG"
    if openssl pkeyutl -verify -pubin -inkey "$PUBKEY_PEM" \
            -rawin -in "$SHA_MSG" -sigfile "$SIG_BIN" >/dev/null 2>&1; then
        log "Ed25519 signature verified against pinned pubkey"
    else
        err "Ed25519 signature verification FAILED — refusing to install"
        exit 1
    fi
else
    log "No UPDATE_PUBKEY configured — skipping signature check (sha256-over-HTTPS baseline)"
fi

# ── Binary sanity: must run --help before we touch the live service ─────────
chmod +x "$NEW_BINARY"
if ! "$NEW_BINARY" --help >/dev/null 2>&1; then
    # `--version` as a fallback (some builds may gate --help differently).
    if ! "$NEW_BINARY" --version >/dev/null 2>&1; then
        err "Downloaded binary failed to run (--help and --version both errored) — refusing to install"
        exit 1
    fi
fi
log "New binary sanity check passed"

# ── Atomic install with backup + rollback ───────────────────────────────────
BACKUP_PATH="${BINARY_PATH}.bak"
RESTART_REF="$(date '+%Y-%m-%d %H:%M:%S')"

log "Stopping $SERVICE_NAME"
systemctl stop "$SERVICE_NAME" 2>/dev/null || true

cp -p "$BINARY_PATH" "$BACKUP_PATH"
install -m 0755 "$NEW_BINARY" "$BINARY_PATH"

log "Starting $SERVICE_NAME (tag ${MANIFEST_TAG:-<none>})"
systemctl start "$SERVICE_NAME"

rollback() {
    err "Update unhealthy — rolling back to the previous binary"
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    if [ -f "$BACKUP_PATH" ]; then
        install -m 0755 "$BACKUP_PATH" "$BINARY_PATH"
    fi
    systemctl start "$SERVICE_NAME" 2>/dev/null || true
}

# Give the agent time to boot and push its first heartbeat.
sleep 6

# Health check 1: the unit is active.
if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    rollback
    exit 1
fi

# Health check 2: a fresh heartbeat was delivered since the restart. The
# agent logs `hippius-miner-agent: heartbeat-pusher: ... outcome=delivered`
# to the journal. Poll for up to ~30s (heartbeat cadence may exceed 6s).
HEARTBEAT_OK=false
for _ in 1 2 3 4 5; do
    if journalctl -u "$SERVICE_NAME" --since "$RESTART_REF" --no-pager 2>/dev/null \
            | grep -q 'heartbeat-pusher:.*outcome=delivered'; then
        HEARTBEAT_OK=true
        break
    fi
    sleep 6
done

if [ "$HEARTBEAT_OK" != "true" ]; then
    err "No delivered heartbeat observed since restart ($RESTART_REF)"
    rollback
    exit 1
fi

log "Update complete: tag ${MANIFEST_TAG:-<none>} sha256 ${MANIFEST_SHA} — service healthy, heartbeat delivered"
rm -f "$BACKUP_PATH"
