#!/usr/bin/env bash
#
# hippius-tenant-baker entrypoint — #334 Phase 2.
#
# Drives one bake from "claim Queued" to "finalize Succeeded /
# Failed" via vali's per-tenant-bake API. Invoked by the k8s Job
# the `apps.tenant_bake` POST endpoint spawned; reads every input
# from BAKE_* env vars + the secret-mounted tokens (VAULT_TOKEN,
# AWS_*, BAKE_VALI_WORKER_TOKEN).
#
# Inputs (every var REQUIRED — fail-closed if any is empty):
#   BAKE_BAKE_ID                vali's stable bake identifier (32 hex)
#   BAKE_VM_ID                  tenant VM the bake produces an image for
#   BAKE_BASE_IMAGE_URL         vanilla cloud image URL
#   BAKE_BASE_IMAGE_SHA256      expected sha of the base image
#   BAKE_SIZE_GB                target raw image size (GiB)
#   BAKE_KEK_VAULT_PATH         KV-v2 path holding the LUKS KEK
#   BAKE_S3_OUTPUT_BUCKET       S3 bucket the outputs land in
#   BAKE_S3_OUTPUT_PREFIX       per-VM S3 key prefix
#   BAKE_VALI_INTERNAL_URL      vali Service URL (in-cluster DNS)
#   BAKE_VALI_WORKER_TOKEN      Bearer token for /finalize
#
# Optional:
#   BAKE_KBS_URL                KBS transport the guest will use — passed
#                               to `tenant-image-bake.sh --kbs-url`. A
#                               `vsock://…` value (the fleet default) tells
#                               the bake the initramfs needs NO network, so
#                               it does NOT add `IP=dhcp` (which otherwise
#                               yields a lingering second DHCP lease, the
#                               #289 double-IP). Defaults to
#                               `vsock://2:19266`; set an `https://…` value
#                               only for a legacy network-KBS image.
#   VAULT_ADDR                  Vault address
#   VAULT_TOKEN                 Vault token on the `tenant-baker` policy:
#                               transit/datakey/plaintext/kek-* + transit/keys +
#                               write tenants/* — NO transit/decrypt, NO luks-kek
#                               read (KEK-HSM Phase 4 part 2). The baker GENERATES
#                               the KEK, it never reads/decrypts an existing one.
#   AWS_ACCESS_KEY_ID           S3 write creds
#   AWS_SECRET_ACCESS_KEY       S3 write creds
#
# Outputs on success: POSTs `succeeded` with the 3 sha256s + the
# 96-hex SNP launch digest, then exits 0.
#
# Outputs on failure: tries to POST `failed` with the last stderr
# tail as `failure_reason`, then exits non-zero so the k8s Job is
# observable as Failed.

set -Eeuo pipefail

# ── Secret + log discipline ─────────────────────────────────────────
#
# Inherits the §20 posture from `scripts/tenant-image-bake.sh`: no
# KEK / userdata / Vault response is ever written to stdout/stderr
# verbatim; only structural classifiers + sha fingerprints.

PROG="$(basename "$0")"
log() { printf '%s: %s\n' "${PROG}" "$*" >&2; }

# Capture stderr to a tmpfile so we can ship the last lines back to
# vali as `failure_reason` on the failure path. The file lives in
# /tmp (tmpfs in the pod) so it's automatically destroyed when the
# Job's pod exits.
STDERR_TAIL_FILE="$(mktemp)"
# `exec 2> >(tee -a "${STDERR_TAIL_FILE}" >&2)` would mirror stderr
# into both the original fd AND the tail file — but the subshell's
# lifecycle makes the tail-file race the failure-finalize call.
# Simpler: append to the file at every classifier emit + use
# `tail -c` on it before the failure-finalize call.
classify() { printf '%s\n' "$1" >> "${STDERR_TAIL_FILE}"; log "$1"; }

cleanup() {
    # Best-effort wipe of any tmp KEK file the bake script might
    # have left behind on a kill -9 path. The script's own cleanup
    # trap covers the happy + ordinary-failure paths; this is the
    # belt+suspenders for SIGKILL.
    rm -f /tmp/luks-kek.bin /tmp/userdata.bin 2>/dev/null || true
}
trap cleanup EXIT

# ── Input validation ────────────────────────────────────────────────

REQUIRED_VARS=(
    BAKE_BAKE_ID
    BAKE_VM_ID
    BAKE_BASE_IMAGE_URL
    BAKE_BASE_IMAGE_SHA256
    BAKE_SIZE_GB
    BAKE_KEK_VAULT_PATH
    BAKE_S3_OUTPUT_BUCKET
    BAKE_S3_OUTPUT_PREFIX
    BAKE_VALI_INTERNAL_URL
    BAKE_VALI_WORKER_TOKEN
    VAULT_ADDR
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
)
# VAULT_TOKEN is required ONLY when there is no jwt role to log in with
# (M-k8sauth, #94). This check runs long before the login block below, so
# demanding it unconditionally would kill a correctly-configured jwt Job
# before it ever got the chance to authenticate.
if [[ -z "${VAULT_JWT_ROLE:-}" ]]; then
    REQUIRED_VARS+=(VAULT_TOKEN)
fi
missing=()
for var in "${REQUIRED_VARS[@]}"; do
    if [[ -z "${!var:-}" ]]; then
        missing+=("${var}")
    fi
done
if (( ${#missing[@]} > 0 )); then
    log "FATAL: missing required env vars: ${missing[*]}"
    # Cannot POST finalize without BAKE_VALI_WORKER_TOKEN; the k8s
    # Job will surface this as a non-zero exit + the operator
    # diagnoses via `kubectl logs`.
    exit 64
fi

# ── Boot-disk packaging mode (golden-bake PR6) ─────────────────────
#
# BAKE_DISK_MODE selects how the customised root is packaged + which
# artifacts are uploaded/finalized. Absent ⇒ `legacy_luks` (the
# pre-golden per-VM LUKS qcow2 path — byte-identical). In
# `golden_verity_overlay` the bake produces a SHARED, non-confidential
# dm-verity base (rootfs.img + rootfs.verity, no qcow2) and consumes NO
# KEK — so step-2 (Vault KEK gen) is skipped and the golden artifacts
# are uploaded under the FIXED keys the launch/preflight fetch
# (rootfs.img / rootfs.verity / tenant.vmlinuz / tenant.initrd.img).
BAKE_DISK_MODE="${BAKE_DISK_MODE:-legacy_luks}"
case "${BAKE_DISK_MODE}" in
    legacy_luks|golden_verity_overlay) ;;
    *)
        log "FATAL: BAKE_DISK_MODE must be legacy_luks or golden_verity_overlay (got '${BAKE_DISK_MODE}')"
        exit 64
        ;;
esac

# ── Bake profile (CDN plan I3) ─────────────────────────────────────
#
# BAKE_PROFILE absent or `standard` ⇒ every existing bake, unchanged (no
# flag passed). `cdn-node` bakes the CDN cache-node image from the data
# plane this image carries (/usr/sbin/hippius-cdn-agent and
# /usr/local/share/hippius/cdn-node/), and needs BAKE_CDN_BACKEND_URL
# (vali's VALI_CDN_BACKEND_URL) and the golden disk mode.
BAKE_PROFILE="${BAKE_PROFILE:-standard}"
case "${BAKE_PROFILE}" in
    standard) ;;
    cdn-node)
        if [[ "${BAKE_DISK_MODE}" != "golden_verity_overlay" || -z "${BAKE_CDN_BACKEND_URL:-}" ]]; then
            log "FATAL: BAKE_PROFILE=cdn-node needs BAKE_DISK_MODE=golden_verity_overlay and BAKE_CDN_BACKEND_URL"
            exit 64
        fi
        ;;
    *)
        log "FATAL: BAKE_PROFILE must be standard or cdn-node (got '${BAKE_PROFILE}')"
        exit 64
        ;;
esac

# ── helpers: vali /finalize call wrappers ──────────────────────────

VALI_FINALIZE_URL="${BAKE_VALI_INTERNAL_URL%/}/v1/tenant-bakes/${BAKE_BAKE_ID}/finalize"

post_finalize() {
    local payload="$1"
    local resp
    if ! resp="$(curl -sS \
        -H "Authorization: Bearer ${BAKE_VALI_WORKER_TOKEN}" \
        -H "Content-Type: application/json" \
        -X POST \
        --data "${payload}" \
        --max-time 30 \
        "${VALI_FINALIZE_URL}")"; then
        log "FATAL: vali POST /finalize transport failed: ${VALI_FINALIZE_URL}"
        return 64
    fi
    # Echo the new version + state — useful in logs for matching the
    # progression against `kubectl get tenantbake/<bake_id>`.
    echo "${resp}" | jq -r '"finalize ok: state=\(.state) version=\(.version)"' >&2
}

post_failed() {
    local reason="$1"
    # Bound the reason to 256 chars (the model's max_length).
    local trimmed
    trimmed="$(printf '%s' "${reason}" | head -c 256)"
    local payload
    payload="$(jq -nc \
        --arg to_state failed \
        --argjson if_version "${VERSION:-1}" \
        --arg failure_reason "${trimmed}" \
        '{to_state:$to_state, if_version:$if_version, failure_reason:$failure_reason}')"
    post_finalize "${payload}" || log "WARN: best-effort failure post also failed"
}

# Global error trap — fires on any unset/cmd-non-zero. Tries to
# post failed before exiting.
error_trap() {
    local exit_code=$?
    local last_line tail_text
    tail_text="$(tail -c 256 "${STDERR_TAIL_FILE}" 2>/dev/null || echo "unknown")"
    classify "FATAL: bake errored at line ${BASH_LINENO[0]}; rc=${exit_code}; tail=${tail_text}"
    post_failed "${tail_text}"
    exit "${exit_code}"
}
trap error_trap ERR

# ── 1. claim → Running ─────────────────────────────────────────────

VERSION=1
classify "step-1/6: claim → Running"
CLAIM_PAYLOAD="$(jq -nc \
    --arg to_state running \
    --argjson if_version 1 \
    '{to_state:$to_state, if_version:$if_version}')"
CLAIM_RESP="$(curl -sS \
    -H "Authorization: Bearer ${BAKE_VALI_WORKER_TOKEN}" \
    -H "Content-Type: application/json" \
    -X POST \
    --data "${CLAIM_PAYLOAD}" \
    --max-time 30 \
    "${VALI_FINALIZE_URL}")"
NEW_VERSION="$(echo "${CLAIM_RESP}" | jq -r '.version // empty')"
if [[ -z "${NEW_VERSION}" ]]; then
    classify "FATAL: claim response missing version: ${CLAIM_RESP}"
    exit 65
fi
VERSION="${NEW_VERSION}"
log "claimed: bake_id=${BAKE_BAKE_ID} version=${VERSION}"

# ── 2. fetch KEK from Vault (LEGACY only) ──────────────────────────
#
# GOLDEN: the shared dm-verity base is UNKEYED (non-confidential public
# distro) — it consumes no KEK and the bake script dispatches BEFORE any
# luksFormat. Skip the whole Vault KEK generation/staging so a golden
# bake needs no `luks-kek` Vault write (KEK-HSM: fewer paths that ever
# touch a plaintext key). The per-VM overlay-upper KEK is a LAUNCH-time
# per-VM concern, not a bake-time one.
if [[ "${BAKE_DISK_MODE}" == "golden_verity_overlay" ]]; then
    classify "step-2/6: golden dm-verity base is non-confidential — no KEK"
else

classify "step-2/6: fetch LUKS KEK from Vault"
KEK_BIN=/tmp/luks-kek.bin
# NOTE: do NOT `chmod 0600 /dev/null` here. It is NOT a noop — it
# changes the shared /dev/null device to mode 0600, and the bake's
# chroot bind-mounts /dev. apt's download/verify sandbox runs gpgv as
# the unprivileged `_apt` user (uid 42), which then cannot open the
# 0600 root-owned /dev/null → `apt-get update`/`install` fail with
# "gpgv ... not installed" and the bake dies at step 3 (rc 100). This
# only bites the COLD path (a warm stage-1 cache skips the chroot apt),
# which is why it was masked until a bake-script change invalidated the
# cache. /dev/null must stay 0666. (Confirmed live 2026-06-11.)
# Vault fronts a private CA; the Job mounts the same `vault-ca`
# ConfigMap the vali pod uses. Without --cacert, curl exits 60
# (TLS verify) and the bake dies at this step (observed live
# 2026-06-10). The conditional keeps the entrypoint working in
# environments where Vault carries a public cert and no CA is
# mounted.
VAULT_CA_ARGS=()
if [[ -r /etc/hippius/vault-ca/ca.crt ]]; then
    VAULT_CA_ARGS=(--cacert /etc/hippius/vault-ca/ca.crt)
fi

# ── Vault auth: exchange this Job's ServiceAccount token for a short
#    Vault token (M-k8sauth, #94) ─────────────────────────────────────
#
# A bake Job is short-lived, so one login at start covers the whole run —
# no caching or renewal needed, unlike the long-running vali processes.
#
# When VAULT_JWT_ROLE is set AND the projected token is mounted, this
# REPLACES the injected static VAULT_TOKEN. The credential is a projected
# token with audience `vault` (not the default API-audience one), so it
# cannot be replayed against the Kubernetes API.
#
# Fail-CLOSED when a role is configured but the login fails AND no static
# token was injected — a bake that continued would fail later at the
# Transit call anyway, with a far more confusing error.
if [[ -n "${VAULT_JWT_ROLE:-}" ]]; then
    _jwt_path="${VAULT_JWT_TOKEN_PATH:-/var/run/secrets/vault/token}"
    _jwt_mount="${VAULT_JWT_AUTH_PATH:-jwt}"
    if [[ -r "${_jwt_path}" ]]; then
        # The response carries the token; never log the body.
        _login_resp="$(curl -sS "${VAULT_CA_ARGS[@]}" --max-time 30 \
            -X POST -d "{\"role\":\"${VAULT_JWT_ROLE}\",\"jwt\":\"$(cat "${_jwt_path}")\"}" \
            "${VAULT_ADDR%/}/v1/auth/${_jwt_mount}/login" 2>/dev/null || true)"
        _jwt_token="$(printf '%s' "${_login_resp}" \
            | sed -n 's/.*"client_token":"\([^"]*\)".*/\1/p')"
        unset _login_resp
        if [[ -n "${_jwt_token}" ]]; then
            VAULT_TOKEN="${_jwt_token}"
            export VAULT_TOKEN
            unset _jwt_token
            log "vault-auth: logged in via ${_jwt_mount}/${VAULT_JWT_ROLE} (short-lived token)"
        elif [[ -z "${VAULT_TOKEN:-}" ]]; then
            log "FATAL: vault jwt login failed and no static VAULT_TOKEN to fall back to"
            exit 64
        else
            log "WARN: vault jwt login failed — falling back to the injected static VAULT_TOKEN"
        fi
    elif [[ -z "${VAULT_TOKEN:-}" ]]; then
        log "FATAL: VAULT_JWT_ROLE is set but ${_jwt_path} is not readable, and no static VAULT_TOKEN"
        exit 64
    fi
fi
# KEK-HSM Phase 4 part 2 — the baker GENERATES the KEK inside Vault Transit
# (`transit/datakey/plaintext/kek-<vm>`) instead of reading a pre-staged
# plaintext. It uses the returned plaintext ONLY to `luksFormat` and stages the
# WRAPPED ciphertext at the luks-kek path — so the KEK is NEVER plaintext at
# rest. CRITICAL: `datakey/plaintext` MINTS a fresh key; it can NEVER DECRYPT an
# existing tenant KEK (only `transit/decrypt` does), so this token — and any
# node RCE that steals it — cannot recover any tenant disk key. The `tenant-baker`
# policy therefore grants NO `transit/decrypt` and NO `luks-kek` read.
TRANSIT_KEY="kek-${BAKE_VM_ID}"

# (a) ensure the per-VM Transit key exists (idempotent — 204 new-or-existing).
if ! curl -fsS "${VAULT_CA_ARGS[@]}" -H "X-Vault-Token: ${VAULT_TOKEN}" \
        --max-time 30 -X POST -d '{}' \
        "${VAULT_ADDR%/}/v1/transit/keys/${TRANSIT_KEY}" >/dev/null; then
    classify "FATAL: could not ensure Transit key ${TRANSIT_KEY}"
    exit 68
fi

# (b) generate a fresh KEK: plaintext (to format) + ciphertext (to stage).
DK_RESP="$(curl -sS "${VAULT_CA_ARGS[@]}" -H "X-Vault-Token: ${VAULT_TOKEN}" \
    --max-time 30 -X POST -d '{}' \
    "${VAULT_ADDR%/}/v1/transit/datakey/plaintext/${TRANSIT_KEY}")"
KEK_PT_B64="$(printf '%s' "${DK_RESP}" | jq -re '.data.plaintext' 2>/dev/null || true)"
KEK_CT="$(printf '%s' "${DK_RESP}" | jq -re '.data.ciphertext' 2>/dev/null || true)"
if [[ -z "${KEK_PT_B64}" || "${KEK_CT}" != vault:* ]]; then
    classify "FATAL: transit datakey generation failed for ${TRANSIT_KEY}"
    exit 68
fi
printf '%s' "${KEK_PT_B64}" | base64 -d > "${KEK_BIN}"
unset KEK_PT_B64 DK_RESP  # §20 — drop the plaintext-bearing datakey response
chmod 0400 "${KEK_BIN}"
if [[ "$(stat -c '%s' "${KEK_BIN}")" -ne 32 ]]; then
    classify "FATAL: generated KEK is not 32 bytes"
    exit 68
fi

# (c) stage the WRAPPED ciphertext at the luks-kek path — same
#     `{"value": base64(...)}` KV-v2 shape the KBS reads + transit-decrypts on
#     release. NEVER plaintext at rest.
KEK_CT_B64="$(printf '%s' "${KEK_CT}" | base64 -w0)"
STAGE_RESP="$(curl -sS "${VAULT_CA_ARGS[@]}" -H "X-Vault-Token: ${VAULT_TOKEN}" \
    --max-time 30 -X POST \
    --data "$(jq -nc --arg v "${KEK_CT_B64}" '{data:{value:$v}}')" \
    "${VAULT_ADDR%/}/v1/${BAKE_KEK_VAULT_PATH}")"
if ! printf '%s' "${STAGE_RESP}" | jq -e '.data.version' >/dev/null 2>&1; then
    classify "FATAL: wrapped KEK stage failed: ${STAGE_RESP}"
    exit 68
fi
unset KEK_CT KEK_CT_B64
log "kek-generated: wrapped ciphertext staged at ${BAKE_KEK_VAULT_PATH} (32-byte plaintext held only to luksFormat)"

fi  # end LEGACY-only KEK generation

# ── 3. run tenant-image-bake.sh ────────────────────────────────────

classify "step-3/6: run tenant-image-bake.sh"
OUTPUT_DIR=/work/out
mkdir -p "${OUTPUT_DIR}"
# `--output-qcow2-gb` carries the flavor's disk size end-to-end. A
# previous revision omitted it, so every in-cluster bake silently
# produced the script's 10 GiB default regardless of BAKE_SIZE_GB.
#
# `HCC_BAKE_STAGE1_CACHE_DIR` (optional, set by the Job manifest when
# `VALI_TENANT_BAKE_CACHE_PVC` is configured) points the bake script
# at the stage-1 cache PVC; the script handles hit/miss/verify
# itself. Exported explicitly so a future `env -i`-style hardening
# of this entrypoint doesn't silently sever the knob.
export HCC_BAKE_STAGE1_CACHE_DIR="${HCC_BAKE_STAGE1_CACHE_DIR:-}"
# `--hippius-eol-bin` stages the §24/§25 guest shutdown-sign binary
# (hippius-agent-initramfs, built dynamic-glibc in the baker image's
# eol-builder stage) into the tenant rootfs + installs
# hippius-eol-sign.service (Before=shutdown.target → `eol --sign-only`).
# WITHOUT this, a clean §25 quiesce shutdown produces NO signed
# StoppedAck → vali's poll_source_ack sees count=0 → the migration
# stalls forever at awaiting_source_ack (fail-closed). The companion
# §7 lifecycle key is materialised at BOOT by the keyscript (which
# passes `--lifecycle-key-out` to hippius-guest-release, driven by the
# launch-baked `hippius.lifecycle_key_path` cmdline token) — NOT a
# bake-time flag.
#
# `--hippius-keepalive-bin` stages the §23 SNP live-attestation keepalive
# agent (hippius-agent-keepalive, same glibc `eol-builder` stage) into the
# tenant rootfs + installs AND ENABLES hippius-keepalive.service, which
# runs it from boot for the VM's lifetime. This is what makes the served
# receipts above worth anything: the telemetry signing key is readable by
# root inside the CVM, so a miner could lift it, kill the VM and keep
# billing — a red team did exactly that. The keepalive agent's proof
# cannot be forged that way (a fresh `/dev/sev-guest` report, KBS-verified
# VCEK→ASK→ARK against AMD silicon, bound to a single-use KBS nonce), and
# a dead VM cannot produce one at all. WITHOUT this flag no guest emits a
# liveness proof, vali's `VmLiveAttestation` table stays empty, and
# `uptimeLiveness.requireAttestation` can never be armed — arming it would
# zero the whole fleet's uptime credit. This IS step 2 of the arming
# sequence documented in deploy/gitops/apps/vali/values.yaml. The cadence
# defaults (300 s tick, vsock relay port 5000) live in the bake script and
# are gated there against vali's `uptimeLiveness.coverageSeconds`.
# The bake args are identical for both modes EXCEPT: golden consumes no
# KEK (no stdin pipe, no `--kek-source`) and passes `--disk-mode
# golden_verity_overlay` so the script packages the shared dm-verity
# base and dispatches before the legacy per-VM luksFormat.
BAKE_ARGS=(
    --base-image-url "${BAKE_BASE_IMAGE_URL}"
    --base-image-sha256 "${BAKE_BASE_IMAGE_SHA256}"
    --hippius-release-bin /usr/sbin/hippius-guest-release
    --hippius-vsock-bin /usr/sbin/hippius-vsock-ticket
    --hippius-eol-bin /usr/sbin/hippius-agent-initramfs
    --hippius-telemetry-bin /usr/sbin/hippius-agent-tenant-telemetry
    --hippius-keepalive-bin /usr/sbin/hippius-agent-keepalive
    --kbs-url "${BAKE_KBS_URL:-vsock://2:19266}"
    --output-dir "${OUTPUT_DIR}"
    --output-qcow2-gb "${BAKE_SIZE_GB}"
    --disk-mode "${BAKE_DISK_MODE}"
)
# F6 scheduled golden re-bake: a non-empty BAKE_PACKAGE_REFRESH (vali's
# `TenantBake.package_refresh`) makes the bake apply every pending distro
# update and keys the stage-1 cache on it. Absent ⇒ no flag ⇒ the bake is
# unchanged.
if [[ -n "${BAKE_PACKAGE_REFRESH:-}" ]]; then
    BAKE_ARGS+=(--package-refresh "${BAKE_PACKAGE_REFRESH}")
fi
if [[ "${BAKE_PROFILE}" == "cdn-node" ]]; then
    BAKE_ARGS+=(
        --profile cdn-node
        --cdn-agent-bin /usr/sbin/hippius-cdn-agent
        --cdn-openresty-tarball /usr/local/share/hippius/cdn-node/openresty.tar.gz
        --cdn-config-dir /usr/local/share/hippius/cdn-node/openresty-config
        --cdn-backend-url "${BAKE_CDN_BACKEND_URL}"
    )
    # Optional: the bake defaults the fleet wildcard (*.c.hipcdn.net).
    if [[ -n "${BAKE_CDN_FLEET_WILDCARD:-}" ]]; then
        BAKE_ARGS+=(--cdn-fleet-wildcard "${BAKE_CDN_FLEET_WILDCARD}")
    fi
fi
if [[ "${BAKE_DISK_MODE}" == "golden_verity_overlay" ]]; then
    /usr/local/bin/tenant-image-bake.sh "${BAKE_ARGS[@]}"
else
    cat "${KEK_BIN}" | /usr/local/bin/tenant-image-bake.sh \
        "${BAKE_ARGS[@]}" \
        --kek-source stdin
    # Wipe KEK immediately after the bake step.
    shred -u "${KEK_BIN}" || rm -f "${KEK_BIN}"
fi

# ══ GOLDEN branch (golden-bake PR6): detect → sha → upload fixed keys →
#    finalize with the dm-verity artifacts, then exit. ═════════════════
if [[ "${BAKE_DISK_MODE}" == "golden_verity_overlay" ]]; then
    # ── 4g. locate golden outputs + read measurement.json ──────────
    classify "step-4/6: locate golden dm-verity outputs + read measurement.json"
    G_ROOTFS_IMG="$(find "${OUTPUT_DIR}" -maxdepth 1 -name 'golden-*.rootfs.img' | head -1)"
    G_ROOTFS_VERITY="$(find "${OUTPUT_DIR}" -maxdepth 1 -name 'golden-*.rootfs.verity' | head -1)"
    G_KERNEL="$(find "${OUTPUT_DIR}" -maxdepth 1 -name 'golden-*.vmlinuz' | head -1)"
    G_INITRD="$(find "${OUTPUT_DIR}" -maxdepth 1 -name 'golden-*.initrd.img' | head -1)"
    G_MEASUREMENT="$(find "${OUTPUT_DIR}" -maxdepth 1 -name 'golden-*.measurement.json' | head -1)"
    for path in "${G_ROOTFS_IMG}" "${G_ROOTFS_VERITY}" "${G_KERNEL}" "${G_INITRD}" "${G_MEASUREMENT}"; do
        if [[ -z "${path}" || ! -f "${path}" ]]; then
            classify "FATAL: golden bake output missing: ${path:-<none>}"
            exit 66
        fi
    done
    # SHAs the launch fetches by (cache-keyed) + folds into the measured
    # cmdline. Recompute from the bytes we UPLOAD (not merely trust the
    # measurement.json) so the finalize digests describe the exact objects.
    G_ROOTFS_IMG_SHA="$(sha256sum "${G_ROOTFS_IMG}" | awk '{print $1}')"
    G_ROOTFS_VERITY_SHA="$(sha256sum "${G_ROOTFS_VERITY}" | awk '{print $1}')"
    G_KERNEL_SHA="$(sha256sum "${G_KERNEL}" | awk '{print $1}')"
    G_INITRD_SHA="$(sha256sum "${G_INITRD}" | awk '{print $1}')"
    # The UNKEYED dm-verity root hash is produced by veritysetup, NOT a
    # sha of a file — read it from the measurement.json the bake emitted.
    G_VERITY_ROOT_HASH="$(jq -r '.verity_root_hash // empty' < "${G_MEASUREMENT}")"
    if [[ ! "${G_VERITY_ROOT_HASH}" =~ ^[0-9a-f]{64}$ ]]; then
        classify "FATAL: golden measurement.json has no 64-hex verity_root_hash"
        exit 67
    fi
    log "golden sha-summary: rootfs_img=${G_ROOTFS_IMG_SHA} rootfs_verity=${G_ROOTFS_VERITY_SHA} kernel=${G_KERNEL_SHA} initrd=${G_INITRD_SHA} verity_root=${G_VERITY_ROOT_HASH}"

    # ── 5g. upload golden artifacts under the FIXED launch keys ─────
    #
    # The launch/preflight fetch immutable object keys at the bake prefix:
    #   rootfs.img          ← golden squashfs base  (preflight `luks_disk`)
    #   rootfs.verity       ← golden dm-verity tree  (preflight `rootfs_hash`)
    #   tenant.vmlinuz      ← guest kernel  (SAME key as legacy — measured)
    #   tenant.initrd.img   ← guest initrd  (SAME key as legacy — measured)
    # The golden bake writes `golden-<sha>.*` locally; we RENAME on upload
    # so the MEASURED + fetched + booted bytes are byte-identical (the
    # kernel/initrd land at the exact keys `launch.py` + the C2 digest
    # recompute expect).
    classify "step-5/6: aws s3 cp golden artifacts (fixed keys)"
    aws configure set default.s3.addressing_style path
    S3_PREFIX="s3://${BAKE_S3_OUTPUT_BUCKET}/${BAKE_S3_OUTPUT_PREFIX%/}"
    aws s3 cp "${G_ROOTFS_IMG}"     "${S3_PREFIX}/rootfs.img"
    aws s3 cp "${G_ROOTFS_VERITY}"  "${S3_PREFIX}/rootfs.verity"
    aws s3 cp "${G_KERNEL}"         "${S3_PREFIX}/tenant.vmlinuz"
    aws s3 cp "${G_INITRD}"         "${S3_PREFIX}/tenant.initrd.img"
    # Public-safe metadata (no secret bytes; the base is non-confidential).
    aws s3 cp "${G_MEASUREMENT}"    "${S3_PREFIX}/golden.measurement.json"

    # ── 6g. finalize → Succeeded (golden fields, NO qcow2) ─────────
    classify "step-6/6: finalize → Succeeded (golden)"
    G_SUCCESS_PAYLOAD="$(jq -nc \
        --arg to_state succeeded \
        --argjson if_version "${VERSION}" \
        --arg rootfs_img_sha256 "${G_ROOTFS_IMG_SHA}" \
        --arg rootfs_verity_sha256 "${G_ROOTFS_VERITY_SHA}" \
        --arg verity_root_hash "${G_VERITY_ROOT_HASH}" \
        --arg kernel_sha256 "${G_KERNEL_SHA}" \
        --arg initrd_sha256 "${G_INITRD_SHA}" \
        '{to_state:$to_state, if_version:$if_version,
          rootfs_img_sha256:$rootfs_img_sha256,
          rootfs_verity_sha256:$rootfs_verity_sha256,
          verity_root_hash:$verity_root_hash,
          kernel_sha256:$kernel_sha256,
          initrd_sha256:$initrd_sha256}')"
    post_finalize "${G_SUCCESS_PAYLOAD}"
    classify "DONE: bake_id=${BAKE_BAKE_ID} vm_id=${BAKE_VM_ID} mode=golden OK"
    exit 0
fi

# ── 4. sha256 the outputs + extract measurement_hex (LEGACY) ───────

classify "step-4/6: sha256 outputs + extract measurement_hex"
QCOW2_PATH="$(find "${OUTPUT_DIR}" -maxdepth 1 -name 'tenant-*.qcow2' | head -1)"
KERNEL_PATH="$(find "${OUTPUT_DIR}" -maxdepth 1 -name 'tenant-*.vmlinuz' | head -1)"
INITRD_PATH="$(find "${OUTPUT_DIR}" -maxdepth 1 -name 'tenant-*.initrd.img' | head -1)"
MEASUREMENT_JSON="$(find "${OUTPUT_DIR}" -maxdepth 1 -name 'tenant-*.measurement.json' | head -1)"
for path in "${QCOW2_PATH}" "${KERNEL_PATH}" "${INITRD_PATH}" "${MEASUREMENT_JSON}"; do
    if [[ -z "${path}" || ! -f "${path}" ]]; then
        classify "FATAL: bake output missing: ${path:-<none>}"
        exit 66
    fi
done
QCOW2_SHA="$(sha256sum "${QCOW2_PATH}" | awk '{print $1}')"
KERNEL_SHA="$(sha256sum "${KERNEL_PATH}" | awk '{print $1}')"
INITRD_SHA="$(sha256sum "${INITRD_PATH}" | awk '{print $1}')"
# measurement_hex is OPTIONAL: the SNP launch digest folds OVMF +
# vcpus — launch-time inputs this bake flow cannot know (the miner
# preflight computes the authoritative value; vali pins it). The
# BYO-OS bake's measurement.json deliberately omits the field; a
# future UKI-style bake may emit it and it will be forwarded.
MEASUREMENT_HEX="$(jq -r '.measurement_hex // empty' < "${MEASUREMENT_JSON}")"
if [[ -n "${MEASUREMENT_HEX}" && ${#MEASUREMENT_HEX} -ne 96 ]]; then
    classify "FATAL: measurement_hex present but not 96 chars (got ${#MEASUREMENT_HEX})"
    exit 67
fi
# #587 Phase 1C — forward the LUKS2-header MAC (#296) to vali so the
# bake→launch resolver can fill it into the launch spec (vali pins it
# into the measured `hippius.luks_header_sha256` cmdline at launch).
# OPTIONAL: a base-OS bake whose measurement.json omits it leaves the
# field empty and the launch intent must supply it.
LUKS_HEADER_SHA="$(jq -r '.luks_header_sha256 // empty' < "${MEASUREMENT_JSON}")"
if [[ -n "${LUKS_HEADER_SHA}" && ${#LUKS_HEADER_SHA} -ne 64 ]]; then
    classify "FATAL: luks_header_sha256 present but not 64 chars (got ${#LUKS_HEADER_SHA})"
    exit 67
fi
log "sha-summary: qcow2=${QCOW2_SHA} kernel=${KERNEL_SHA} initrd=${INITRD_SHA} luks_header=${LUKS_HEADER_SHA}"
log "measurement_hex=${MEASUREMENT_HEX}"

# ── 5. upload to S3 ────────────────────────────────────────────────

classify "step-5/6: aws s3 cp outputs"
# Hippius S3 is endpoint + PATH-style only: the Job env carries
# AWS_ENDPOINT_URL (awscli ≥2.13 honors it), but addressing style
# has no env knob — without this `aws s3 cp` builds
# `https://<bucket>.s3.hippius.com/...` vhost URLs whose wildcard
# DNS doesn't exist (NXDOMAIN, verified 2026-06-10).
aws configure set default.s3.addressing_style path
S3_PREFIX="s3://${BAKE_S3_OUTPUT_BUCKET}/${BAKE_S3_OUTPUT_PREFIX%/}"
aws s3 cp "${QCOW2_PATH}" "${S3_PREFIX}/tenant.qcow2"
aws s3 cp "${KERNEL_PATH}" "${S3_PREFIX}/tenant.vmlinuz"
aws s3 cp "${INITRD_PATH}" "${S3_PREFIX}/tenant.initrd.img"
# measurement.json carries luks_header_sha256 (#296 — vali pins it
# into the measured cmdline at launch) + pbkdf/provenance metadata.
# Public-safe: no secret bytes, only digests + URLs.
aws s3 cp "${MEASUREMENT_JSON}" "${S3_PREFIX}/tenant.measurement.json"

# ── 6. finalize → Succeeded ────────────────────────────────────────

classify "step-6/6: finalize → Succeeded"
SUCCESS_PAYLOAD="$(jq -nc \
    --arg to_state succeeded \
    --argjson if_version "${VERSION}" \
    --arg qcow2_sha256 "${QCOW2_SHA}" \
    --arg kernel_sha256 "${KERNEL_SHA}" \
    --arg initrd_sha256 "${INITRD_SHA}" \
    --arg luks_header_sha256 "${LUKS_HEADER_SHA}" \
    --arg measurement_hex "${MEASUREMENT_HEX}" \
    '{to_state:$to_state, if_version:$if_version,
      qcow2_sha256:$qcow2_sha256,
      kernel_sha256:$kernel_sha256,
      initrd_sha256:$initrd_sha256}
     + (if $luks_header_sha256 != "" then {luks_header_sha256:$luks_header_sha256} else {} end)
     + (if $measurement_hex != "" then {measurement_hex:$measurement_hex} else {} end)')"
post_finalize "${SUCCESS_PAYLOAD}"
classify "DONE: bake_id=${BAKE_BAKE_ID} vm_id=${BAKE_VM_ID} OK"
