# Trust-anchor key rotation (allowlist-root + L1 order-ticket)

Two Ed25519 seeds are the control-plane trust anchors:

| Seed | Signs | Vault path (KV v2, mount `secret`) | KBS pin |
| --- | --- | --- | --- |
| allowlist-root | the §22 measurement allowlist (COSE) | `hippius-compute/vali/allowlist-root`, field `seed` | `[allowlist] root_pubkey_hex` in `kbs-config` |
| L1 order-ticket | KEK-release OrderTickets | `hippius-compute/vali/l1-order-ticket`, field `seed` | a `[[l1_keys]] pubkey_hex` entry in `kbs-config` |

**Production source of truth is Vault.** vali reads each seed at runtime with
its scoped Vault token (`vali-orchestrator` policy) via
`allowlist_pin._resolve_seed_hex()` / `ticket_mint._resolve_l1_seed()`, wired
by `VALI_KBS_ALLOWLIST_ROOT_SEED_VAULT_PATH` /
`VALI_L1_SIGNING_KEY_VAULT_PATH` in the `vali-config` ConfigMap. The Vault
path takes precedence over the DEV-only `*_PATH` file affordance. There is NO
plaintext k8s Secret copy in prod (the vestigial `vali-allowlist-root-seed` /
`vali-l1-signing-key` dev-CLI Secrets were removed — audit H2). etcd is also
encrypted at rest (audit H1).

Rotation is a deliberate, human-gated break-glass procedure — it is
intentionally NOT automated (an online rotation robot for a trust anchor is
itself an attack surface). Keep the allowlist-root seed generation offline /
HSM-backed where possible (see the M-of-N / offline-signer hardening item).

## L1 order-ticket rotation (overlap — zero downtime)

KBS trusts a SET of L1 kids, so a new key can be introduced with overlap:

1. Generate a fresh seed offline: `openssl rand -hex 32` (or an HSM export of
   the raw 32-byte seed as hex). Derive its pubkey + kid.
2. `vault kv put -mount=secret hippius-compute/vali/l1-order-ticket seed=<new-hex>`
   (KV v2 keeps the prior version — instant rollback with `vault kv rollback`).
3. Add the NEW `{kid_hex, pubkey_hex}` to `kbs-config`'s `[[l1_keys]]`
   (gitops `deploy/gitops/apps/kbs/values.yaml` → `l1Keys`), keeping the OLD
   entry. Bump the kbs-server digest / let ArgoCD roll. Now KBS accepts
   tickets from BOTH keys.
4. Confirm vali mints with the new seed (a launch succeeds → KEK released).
5. After all in-flight OLD-signed tickets have expired, REMOVE the old
   `[[l1_keys]]` entry and roll KBS again.

## allowlist-root rotation (single pin — schedule a window)

There is ONE `root_pubkey_hex`, so this is disruptive; schedule a maintenance
window (no launches / no allowlist pins in flight):

1. Generate a fresh seed offline (HSM-backed if available).
2. Re-sign the CURRENT allowlist manifest with the new seed using
   `hippius-kbs-allowlist-tool` (same epoch, new signature) and stage the new
   COSE to S3 (`VALI_KBS_ALLOWLIST_S3_URL`).
3. Update `kbs-config`'s `[allowlist] root_pubkey_hex` to the new pubkey
   (gitops), bump the kbs-server digest, let ArgoCD roll. KBS now verifies the
   allowlist against the new root.
4. `vault kv put -mount=secret hippius-compute/vali/allowlist-root seed=<new-hex>`
   so vali's future auto-pins sign with the new root.
5. Verify: a fresh launch auto-pins a measurement, KBS accepts the newly
   root-signed allowlist, KEK releases. Roll back via `vault kv rollback` +
   revert the `root_pubkey_hex` if verification fails.

## Verifying the live wiring (no rotation)

Confirm vali reads each anchor from Vault and it matches the KBS pin:

```bash
kubectl -n vali exec deploy/vali -c vali -- python - <<'PY'
import django, os; os.environ.setdefault("DJANGO_SETTINGS_MODULE","vali.settings"); django.setup()
from apps.orchestration.services.allowlist_pin import _resolve_seed_hex
from apps.orchestration.services.ticket_mint import _resolve_l1_seed
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
def pub(h):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(h)).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
print("allowlist-root pub:", pub(_resolve_seed_hex()))
print("l1 pub           :", pub(_resolve_l1_seed()))
PY
```

Each printed pubkey MUST equal the corresponding `kbs-config` pin
(`root_pubkey_hex` / `l1Keys[].pubkey_hex`).
