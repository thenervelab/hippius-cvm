#!/usr/bin/env bash
# tenant-secrets-stage-test.sh — run `scripts/tenant-secrets-stage.sh`
# against a STUBBED `vault` CLI and assert the two properties an operator
# stage has to get right, neither of which any test executed before:
#
#   1. both user-data copies are staged Transit-WRAPPED, under the two
#      DIFFERENT per-VM keys — the canonical copy under `kek-<vm>` (which
#      only the attested KBS opens) and vali's working copy under
#      `ud-<vm>` (which vali may open, and without which the VM cannot be
#      §25 migrated or KBS-state recovered). The script used to write the
#      cloud-init plaintext — SSH keys, API tokens, the NetBird enrolment
#      secret — right next to the carefully-wrapped KEK;
#   2. the `allowed_userdata_digest_hex` it prints is taken over the
#      PLAINTEXT, not over the ciphertext it staged. The KBS unwraps
#      before it recomputes, and the guest re-derives the same digest a
#      third time over what it receives — digest the stored form and
#      every release denies, a failure that surfaces two systems away.
#
# No network, no real Vault: the stub records what it was asked to store
# and answers in the CLI's own shapes.
#
# Usage: scripts/dev/tenant-secrets-stage-test.sh

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
UNDER_TEST="${REPO_ROOT}/scripts/tenant-secrets-stage.sh"

err() {
    printf 'tenant-secrets-stage-test: FAIL: %s\n' "$*" >&2
    exit 1
}

WORK="$(mktemp -d)"
cleanup() { rm -rf -- "${WORK}"; }
trap cleanup EXIT

mkdir -p "${WORK}/bin"

# ── the `vault` stub ────────────────────────────────────────────────
#
# `transit/encrypt` is modelled as a REVERSIBLE transform
# (`vault:v1:<hex>`) so the test can assert both that what was staged is
# ciphertext AND exactly which plaintext it wraps. `kv put` records the
# stored value per path.
cat > "${WORK}/bin/vault" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
STORE="${STUB_STORE:?}"
case "$1" in
  kv)
    case "$2" in
      metadata) exit 1 ;;                    # nothing staged yet
      put)
        path="$3"; kv="$4"
        # Injected failure, so the test can assert the script DIES rather
        # than emitting a valid-looking result with a copy missing.
        [[ "${STUB_FAIL_PUT:-}" != "$(basename "${path}")" ]] || exit 2
        printf '%s\n' "${kv#value=}" > "${STORE}/$(basename "${path}").b64"
        printf '{"data":{"version":3}}\n'
        ;;
      *) exit 64 ;;
    esac
    ;;
  write)
    # `-f transit/keys/<name>` (ensure) or
    # `-field=ciphertext transit/encrypt/<name> plaintext=<b64>`
    for arg in "$@"; do
      case "${arg}" in
        plaintext=*) b64="${arg#plaintext=}" ;;
      esac
    done
    case "$*" in
      *transit/keys/*)
        # Record the key as CREATED. Vault refuses `transit/encrypt` on a
        # key that does not exist, so the stub does too — otherwise a
        # dropped key-creation call is invisible here and fails on the
        # first real stage.
        for arg in "$@"; do
          case "${arg}" in transit/keys/*) printf '%s\n' "${arg#transit/keys/}" >> "${STORE}/created-keys" ;; esac
        done
        exit 0
        ;;
      *transit/encrypt/*)
        for arg in "$@"; do
          case "${arg}" in
            transit/encrypt/*)
              grep -qx "${arg#transit/encrypt/}" "${STORE}/created-keys" 2>/dev/null \
                || { echo "encryption key not found" >&2; exit 2; }
              ;;
          esac
        done
        # Record WHICH key each wrap used — the separation between the
        # KBS-only `kek-<vm>` and vali's `ud-<vm>` is the point.
        for arg in "$@"; do
          case "${arg}" in transit/encrypt/*) printf '%s\n' "${arg#transit/encrypt/}" >> "${STORE}/encrypt-keys" ;; esac
        done
        printf 'vault:v1:%s\n' "$(printf '%s' "${b64}" | base64 -d | xxd -p | tr -d '\n')"
        ;;
      *) exit 64 ;;
    esac
    ;;
  *) exit 64 ;;
esac
STUB
chmod +x "${WORK}/bin/vault"

printf 'test-token\n' > "${WORK}/token"
printf '#cloud-config\nssh_authorized_keys: [ssh-ed25519 AAAA-SECRET]\n' > "${WORK}/userdata.yaml"
head -c 32 /dev/zero > "${WORK}/kek.bin"

export STUB_STORE="${WORK}"
out="$(
    PATH="${WORK}/bin:${PATH}" \
    VAULT_CACERT="" \
    "${UNDER_TEST}" \
        --vm-id vm-stage-test \
        --tenant-id t-1 \
        --ticket-id tk-1 \
        --luks-kek-file "${WORK}/kek.bin" \
        --userdata-file "${WORK}/userdata.yaml" \
        --vault-addr https://vault.invalid:8200 \
        --vault-token-file "${WORK}/token" \
        --vault-path-prefix p/tenants \
        2>"${WORK}/stderr"
)" || { cat "${WORK}/stderr" >&2; err "the script exited non-zero"; }

# ── 1. what was STAGED for the user-data is ciphertext ──────────────
[[ -r "${WORK}/userdata.b64" ]] || err "the script staged no userdata"
stored="$(base64 -d < "${WORK}/userdata.b64")"
case "${stored}" in
    vault:v1:*) ;;
    *) err "userdata staged UNWRAPPED (starts with: ${stored:0:24})" ;;
esac
if grep -q 'AAAA-SECRET' "${WORK}/userdata.b64"; then
    err "the cloud-init plaintext reached the staged value"
fi
# …and it wraps exactly the file we passed, nothing else.
unwrapped="$(printf '%s' "${stored#vault:v1:}" | xxd -r -p)"
[[ "${unwrapped}" == "$(cat "${WORK}/userdata.yaml")" ]] \
    || err "the staged ciphertext does not wrap the supplied user-data"

# ── 1b. vali's working copy is staged too, under the OTHER key ──────
[[ -r "${WORK}/userdata-pending.b64" ]] \
    || err "no userdata working copy staged — the VM could never be migrated or recovered"
work="$(base64 -d < "${WORK}/userdata-pending.b64")"
case "${work}" in
    vault:v1:*) ;;
    *) err "the working copy was staged UNWRAPPED (starts with: ${work:0:24})" ;;
esac
# …and what it wraps is the STAMPED form the vali reader requires:
# `hippius-userdata-for-canonical-v<N>\n` + the plaintext, N being the
# version the canonical `kv put` returned (the stub answers 3). The
# reader refuses an unstamped copy and one stamped for another version
# — at §25 intake and at the re-mint — so a script that wrote the bare
# plaintext here produced VMs that could be launched and never migrated
# or recovered. Asserted byte-exact, stamp included.
work_plain="$(printf '%s' "${work#vault:v1:}" | xxd -r -p)"
expect_work="$(printf 'hippius-userdata-for-canonical-v3\n'; cat "${WORK}/userdata.yaml")"
[[ "${work_plain}" == "${expect_work}" ]] \
    || err "the working copy is not the stamped plaintext (starts with: ${work_plain:0:48})"
# The EXACT key each wrap used, in order: the KEK and the canonical
# user-data under `kek-<vm_id>` (KBS-only), the working copy under
# `ud-<vm_id>` (vali-openable). Asserted as a whole sequence, not as
# "kek appears somewhere": the KBS decrypts with `kek-<vm_id>` and
# nothing else, so a wrap under a neighbouring key — another VM's, the
# tenant's, the wrong one of this VM's two — yields a blob nobody can
# open, and the failure surfaces at guest boot.
printf 'kek-vm-stage-test\nkek-vm-stage-test\nud-vm-stage-test\n' > "${WORK}/expect-keys"
diff -u "${WORK}/expect-keys" "${WORK}/encrypt-keys" >/dev/null \
    || err "wrong Transit keys used: $(tr '\n' ' ' < "${WORK}/encrypt-keys")"

# ── 2. the printed digest is over the PLAINTEXT ─────────────────────
digest="$(printf '%s' "${out}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["allowed_userdata_digest_hex"])')"
version="$(printf '%s' "${out}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["userdata_vault_ref"]["version"])')"
expected="$(
    PLAINFILE="${WORK}/userdata.yaml" VERSION="${version}" python3 - <<'PY'
import hashlib
import os

DOMAIN = b"HIPPIUS_USERDATA_DIGEST_V1"


def framed(h, b):
    h.update(len(b).to_bytes(8, "little"))
    h.update(b)


h = hashlib.sha256()
framed(h, DOMAIN)
for field in ("t-1", "vm-stage-test", "tk-1", "userdata", "p/tenants/vm-stage-test/userdata"):
    framed(h, field.encode())
h.update(int(os.environ["VERSION"]).to_bytes(8, "little"))
with open(os.environ["PLAINFILE"], "rb") as f:
    framed(h, f.read())
print(h.hexdigest())
PY
)"
[[ "${digest}" == "${expected}" ]] \
    || err "digest is not over the plaintext (got ${digest}, want ${expected})"

# The ciphertext-derived digest MUST NOT match: the KBS unwraps before it
# recomputes, and the guest re-derives the same digest over the plaintext
# it receives. Digesting the stored form denies every release.
wrapped_digest="$(
    STAGED="${stored}" VERSION="${version}" python3 - <<'PY'
import hashlib
import os

DOMAIN = b"HIPPIUS_USERDATA_DIGEST_V1"


def framed(h, b):
    h.update(len(b).to_bytes(8, "little"))
    h.update(b)


h = hashlib.sha256()
framed(h, DOMAIN)
for field in ("t-1", "vm-stage-test", "tk-1", "userdata", "p/tenants/vm-stage-test/userdata"):
    framed(h, field.encode())
h.update(int(os.environ["VERSION"]).to_bytes(8, "little"))
framed(h, os.environ["STAGED"].encode())
print(h.hexdigest())
PY
)"
[[ "${digest}" != "${wrapped_digest}" ]] \
    || err "digest is over the STAGED CIPHERTEXT — the KBS and the guest both hash the plaintext"

# ── 3. failure modes: the script must DIE, not emit a partial stage ──
#
# A stage that reports success with one copy missing is worse than a
# failed stage: the VM launches and only stops being migratable later.
for target in userdata userdata-pending; do
    if PATH="${WORK}/bin:${PATH}" STUB_FAIL_PUT="${target}" \
        "${UNDER_TEST}" \
            --vm-id vm-stage-test --tenant-id t-1 --ticket-id tk-1 \
            --luks-kek-file "${WORK}/kek.bin" \
            --userdata-file "${WORK}/userdata.yaml" \
            --vault-addr https://vault.invalid:8200 \
            --vault-token-file "${WORK}/token" \
            --vault-path-prefix p/tenants >/dev/null 2>&1
    then
        err "a failed ${target} write did not fail the stage"
    fi
done

# A `vault:`-prefixed user-data is reserved (it is the ciphertext
# discriminator) and must be refused at input, not staged and then
# rejected by the KBS as a double wrap.
printf 'vault:v1:not-cloud-init\n' > "${WORK}/reserved.yaml"
if PATH="${WORK}/bin:${PATH}" "${UNDER_TEST}" \
    --vm-id vm-stage-test --tenant-id t-1 --ticket-id tk-1 \
    --luks-kek-file "${WORK}/kek.bin" \
    --userdata-file "${WORK}/reserved.yaml" \
    --vault-addr https://vault.invalid:8200 \
    --vault-token-file "${WORK}/token" \
    --vault-path-prefix p/tenants >/dev/null 2>&1
then
    err "a vault:-prefixed user-data was accepted"
fi

# ── 4. no plaintext fingerprint on stderr ───────────────────────────
if grep -q 'AAAA-SECRET' "${WORK}/stderr"; then
    err "the cloud-init plaintext appeared on stderr"
fi

echo "tenant-secrets-stage-test: OK (both copies wrapped, under their own keys; digest over the plaintext)"
