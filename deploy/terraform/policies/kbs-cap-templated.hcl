# kbs-cap-templated — the FIXED, TEMPLATED per-VM KEK-release capability
# (KEK-HSM Phase 3, closes RA-KBS-M2).
#
# BEFORE: the broker WROTE a fresh `sys/policies/acl/kbs-cap-<vm_id>` ACL
# per release, with arbitrary HCL, under its own token — so a broker RCE
# could author `read secret/*` + mint a token on it = read every secret
# (all tenant KEKs AND the L1/allowlist signing seeds = forge everything).
#
# NOW: this ONE policy is operator-created (never broker-written). The
# broker mints the per-VM cap via `auth/token/create/kbs-vault-broker-cap`
# with `entity_alias=<vm_id>` — Vault binds the token to an entity whose
# token-mount alias name IS the vm_id, and this policy's ACL templates
# resolve `{{identity.entity.aliases.<token_accessor>.name}}` to that
# vm_id. So the cap is scoped to EXACTLY one VM's release secrets, the
# broker holds NO `sys/policies/acl` write, and a broker RCE is bounded to
# minting tenant-KEK-scoped caps (never arbitrary-secret ACLs).
#
# NOTE: `auth_token_b0d7c32e` is THIS Vault's token-auth mount accessor
# (`vault auth list`). Stable unless the token backend is remounted (it
# is not). Re-derive + re-pin here if the accessor ever changes.

# The wrapped KEK ciphertext (read) — the KBS transit-decrypts it.
path "secret/data/hippius-compute/kbs/tenants/{{identity.entity.aliases.auth_token_b0d7c32e.name}}/luks-kek" {
  capabilities = ["read"]
}
# cloud-init userdata (read).
path "secret/data/hippius-compute/kbs/tenants/{{identity.entity.aliases.auth_token_b0d7c32e.name}}/userdata" {
  capabilities = ["read"]
}
# §7 lifecycle signing seed (read; 404 tolerated for pre-§7 VMs).
path "secret/data/hippius-compute/kbs/tenants/{{identity.entity.aliases.auth_token_b0d7c32e.name}}/lifecycle-key" {
  capabilities = ["read"]
}
# KEK-HSM Phase 2 — transit-decrypt THIS VM's per-VM Transit key.
path "transit/decrypt/kek-{{identity.entity.aliases.auth_token_b0d7c32e.name}}" {
  capabilities = ["update"]
}
