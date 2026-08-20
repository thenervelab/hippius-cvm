# vali-orchestrator — LEAST PRIVILEGE (replaces the root token, audit C1).
#
# KEK-HSM Phase 1 (deny the standing luks-kek READ): the confidential-
# compute promise is that ONLY the SNP-attested guest ever obtains a
# plaintext tenant disk KEK (the KBS HPKE-releases it after a double
# measurement gate). vali only STAGES secrets; it must not be able to read
# a `luks-kek` back, so a vali/node RCE cannot exfil every tenant's disk
# key from Vault.
#
# Runtime Vault use audited by grep of vali/apps (KEK-HSM Phase 1, fire
# after #771): the ONLY data-path `get_kv` reads under tenants/* are
# `userdata`, `userdata-pending`, and `lifecycle-key` (version 1). The
# `luks-kek` is NEVER read on the data path — the async launch worker was
# refactored to leave the KEK where the caller staged it (the launch API
# enforces `kek_vault_path == {prefix}/{vm_id}/luks-kek`) and to read only
# its KV VERSION from the metadata endpoint. The sync/CLI path generates +
# writes the KEK but does not read it.

# Per-VM tenant secrets, DATA path.
#
# Default for EVERYTHING under tenants/* (incl. luks-kek): stage-only —
# create (first write) + update (overwrite), NO read. A more-specific rule
# below re-grants read on exactly the three leaves vali legitimately reads
# back. (Vault resolves the most specific matching path, so a `+`-templated
# leaf rule wins over this trailing-glob for that leaf.)
path "secret/data/hippius-compute/kbs/tenants/*" {
  capabilities = ["create", "update"]
}

# cloud-init userdata — read back by the §6 migration-ticket re-derivation.
path "secret/data/hippius-compute/kbs/tenants/+/userdata" {
  capabilities = ["create", "update", "read"]
}

# userdata transport staging (§20) — read back by the async launch worker
# to template NetBird keys + re-stage to the canonical `userdata`.
path "secret/data/hippius-compute/kbs/tenants/+/userdata-pending" {
  capabilities = ["create", "update", "read"]
}

# §7 lifecycle seed — read back (version 1) for first-write-wins reuse on
# re-launch (the per-VM-lifetime signing identity). NOT a disk KEK.
path "secret/data/hippius-compute/kbs/tenants/+/lifecycle-key" {
  capabilities = ["create", "update", "read"]
}

# Per-VM tenant secrets, METADATA path — read the current KV VERSION
# (non-secret: no plaintext) AND delete (§24 golden crypto-erase). The
# async launch path reads the luks-kek version here to bind it into the
# attested ticket without ever touching the plaintext KEK; the §24
# decommission DELETEs a golden VM's wrapped-KEK KV secret (all versions +
# metadata) as part of crypto-erase. `delete` on the metadata endpoint
# removes only ciphertext (the wrapped KEK) — vali still cannot READ a
# plaintext luks-kek (the data-path read stays denied by the trailing glob).
path "secret/metadata/hippius-compute/kbs/tenants/*" {
  capabilities = ["read", "delete"]
}

# L1 OrderTicket signing seed (mints KEK-release tickets) — read-only.
path "secret/data/hippius-compute/vali/l1-order-ticket" {
  capabilities = ["read"]
}

# §22 allowlist root signing seed (signs the measurement allowlist) — read-only.
path "secret/data/hippius-compute/vali/allowlist-root" {
  capabilities = ["read"]
}

# Registry-feed signing seed (signs the Edge admission feed, audit
# M-registry-mTLS) — read-only.
path "secret/data/hippius-compute/vali/registry-feed" {
  capabilities = ["read"]
}

# KEK-HSM Phase 2 — vali WRAPS each tenant KEK with its per-VM Vault
# Transit key (`kek-<vm_id>`) before staging, so the KEK is stored as
# ciphertext (never plaintext). vali may create the per-VM key + encrypt,
# but is DELIBERATELY NOT granted `transit/decrypt` — only the attested SNP
# KBS (via the broker-minted per-VM cap token) can unwrap. So a vali/node
# RCE can overwrite a KEK (a DoS) but can NEVER recover a plaintext KEK.
#
# §24 golden crypto-erase: vali must also DESTROY a golden VM's Transit key
# `kek-<vm_id>` at decommission — once destroyed, the wrapped per-VM KEK can
# never be unwrapped, so the golden overlay's in-guest LUKS master key is
# cryptographically unrecoverable (the data-death guarantee, since a golden
# KEK has NO KBS record to `crypto-erase`). Vault refuses a Transit key
# delete unless `deletion_allowed=true` is set on the key's config first, so
# grant `update` on `…/config` too. This is DESTROY-only — it still cannot
# `decrypt` (recover a plaintext KEK), so the confidentiality property holds.
path "transit/keys/kek-*" {
  capabilities = ["create", "update", "delete"]
}
path "transit/keys/kek-*/config" {
  capabilities = ["update"]
}
path "transit/encrypt/kek-*" {
  capabilities = ["update"]
}

# KEK-HSM Phase 4 — vali may ask Transit to GENERATE a fresh KEK and return
# ONLY the wrapped ciphertext (`transit/datakey/wrapped/kek-*`), so vali never
# holds a plaintext KEK even at generation. DELIBERATELY NOT granted
# `transit/datakey/plaintext/*` (that returns the raw key) — the
# never-plaintext property is enforced by Vault here, not just by vali's code.
path "transit/datakey/wrapped/kek-*" {
  capabilities = ["update"]
}
