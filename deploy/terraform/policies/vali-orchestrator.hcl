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

# cloud-init userdata, CANONICAL — the copy the minted ticket binds and
# the attested KBS releases. Wrapped under `kek-<vm_id>`, which this
# policy does NOT grant decrypt on, so a read returns ciphertext vali
# cannot open. `read` stays for one legacy case: a VM staged before the
# wrapping holds plaintext here and the §6 re-mint still hashes it.
path "secret/data/hippius-compute/kbs/tenants/+/userdata" {
  capabilities = ["create", "update", "read"]
}

# userdata WORKING COPY (§20) — vali's copy of the SUBSTITUTED bytes the
# canonical path holds, wrapped under `ud-<vm_id>` (decrypt granted
# below) and stamped with the canonical KV version it corresponds to.
# Read by the §6 digest re-derivation on a §25 migration / KBS-state
# recovery: that mint binds a fresh ticket_id, so it must hash the
# plaintext again, and the canonical copy is not openable by vali.
path "secret/data/hippius-compute/kbs/tenants/+/userdata-pending" {
  capabilities = ["create", "update", "read"]
}

# userdata INTAKE copy — the TEMPLATE the caller POSTed, wrapped under the
# same `ud-<vm_id>`. Read by the async launch worker and by
# reboot-recovery, which each substitute a FRESH NetBird setup key into it
# before staging. Without `read` here every async launch fails at
# `secret-fetch` — the trailing-glob default above is create/update only.
path "secret/data/hippius-compute/kbs/tenants/+/userdata-intake" {
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

# The userdata WORKING-COPY key. Separate from `kek-*` because the two
# copies answer to different readers, and the separation is the whole
# point: `kek-<vm_id>` wraps the disk KEK and the canonical userdata the
# KBS releases, and vali is DENIED decrypt on it; `ud-<vm_id>` wraps only
# vali's own working copy of the userdata, and vali MAY decrypt it —
# because the NetBird substitution at launch and the §6 digest
# re-derivation on a §25 migration / KBS-state recovery genuinely need the
# cloud-init plaintext (the digest is over the plaintext and binds a fresh
# ticket_id each time, so it cannot be precomputed once).
#
# What this grant does NOT do is give vali any path to a KEK or to the
# canonical userdata: `transit/decrypt/kek-*` remains ungranted. What it
# costs is stated plainly: an RCE holding vali's credentials can read a
# tenant's cloud-init. Removing that would mean removing the ticket_id
# from the digest preimage — which the GUEST also computes — i.e. a
# fleet-wide image re-bake, tracked separately.
#
# `delete` + `…/config` update: §24 DESTROYS this key at decommission,
# which is what makes the wrapped working copy cryptographically dead.
path "transit/keys/ud-*" {
  capabilities = ["create", "update", "delete"]
}
path "transit/keys/ud-*/config" {
  capabilities = ["update"]
}
path "transit/encrypt/ud-*" {
  capabilities = ["update"]
}
path "transit/decrypt/ud-*" {
  capabilities = ["update"]
}
# The erase PROBE for `ud-*`, same route and same reason as `kek-*` below:
# `transit/datakey/wrapped/<name>` is a stateless derive that answers 400
# "encryption key not found" once the key is destroyed and 2xx while it is
# alive, so it is the one call that can tell a dead key from a live one
# without `read` on `transit/keys/*`. The full-tier synthetic monitor asserts
# BOTH per-VM keys are dead after §24; without this grant its `ud-*` probe
# 403s and the monitor fails closed on a decommission that actually erased
# (first seen 2026-09-21, the run right after #1068 rolled). vali still
# cannot unwrap what the route returns for `ud-*` any more than for
# `kek-*` — the result is discarded inside `transit_key_gone`.
path "transit/datakey/wrapped/ud-*" {
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
