# `packer/keys/dev/` — DEV-ONLY L1 OrderTicket signing key

**⚠️ DEV PLACEHOLDER. NEVER USE IN PRODUCTION. ⚠️**

This directory ships one committed **dev placeholder** keypair: the
Ed25519 signing key used to mint dev `OrderTicket` COSE_Sign1
envelopes against a dev cluster.

| File | Contents | Status |
|---|---|---|
| `l1-order-ticket.dev.ed25519`     | Ed25519 private seed, 64 hex chars. | **PUBLIC** — committed to git. |
| `l1-order-ticket.dev.ed25519.pub` | Ed25519 public key, 64 hex chars.   | **PUBLIC** — committed to git. |

| Field            | Value                                                                |
|---|---|
| `kid` (ASCII)    | `l1-order-ticket-dev-v1`                                             |
| `kid` (hex)      | `6c312d6f726465722d7469636b65742d6465762d7631`                       |
| `pubkey_hex`     | `611ed9f2d689c8ba965f353b146309fb559a419b3247a33aa4a9d2781dd39159`   |

The pubkey lands in `deploy/gitops/apps/kbs/values.yaml::l1Keys` and
is rendered into the KBS `[[l1_keys]]` config by
`templates/configmap-kbs.yaml`. The §22 dev allowlist
(`test_vectors/allowlist/dev-manifest.toml`) lists this kid under
the tenant UKI measurement entry.

## Three-belt defense against prod use

A DEV key in a public repo is dangerous IF a placeholder ever escapes
into the production L1 → KBS trust path. Three independent gates
must ALL fail before a dev-signed OrderTicket becomes a prod release
grant:

1. **kid string**: `l1-order-ticket-dev-v1` is visually obvious in
   any KBS log line / audit dump. Prod kids carry no `-dev-` segment.
2. **Allowlist root**: the dev §22 allowlist root pubkey
   (`provenance-root.dev.ed25519.pub` under `packer/kbs-uki/keys/dev/`)
   is itself dev-only. The KBS verifies every allowlist artifact
   against `config.allowlistRootPubkeyHex`, which in the dev chart
   takes the dev root value; in production it takes the offline
   ceremony root pubkey (whose seed is never in this repo). A dev
   allowlist won't load against a prod KBS.
3. **Prod KBS config**: `deploy/gitops/apps/kbs/values.yaml::l1Keys`
   in prod ships the real L1 ticket-signing pubkey(s), not this one.

## Why commit a private key

Same rationale as `packer/kbs-uki/keys/dev/README.md`: a deterministic
in-repo dev keypair lets every developer + CI run mint byte-equivalent
test vectors against the same KBS without per-machine key rotation.
The production L1 OrderTicket-signing key lives offline; this seed
exists exclusively to exercise the dev cluster end-to-end.

## Regenerating

Don't, unless intentionally rolling the dev cluster's L1 trust root.
Rotating this key requires (in lockstep, one PR):

1. Replace this seed + pubkey file.
2. Update `deploy/gitops/apps/kbs/values.yaml::l1Keys[0].pubkeyHex`.
3. Re-mint `test_vectors/allowlist/dev.cose` (bump epoch).
4. Bump `deploy/gitops/apps/kbs/values.yaml::allowlist.sha256` to
   the new artifact bytes.
