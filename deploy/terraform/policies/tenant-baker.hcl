# `tenant-baker` — Vault policy for the tenant-image bake Job (KEK-HSM Phase 4
# part 2/2).
#
# The bake Job pre-formats the tenant rootfs (`cryptsetup luksFormat`), which
# fundamentally needs a plaintext KEK. Instead of reading a pre-staged plaintext
# KEK (the old plaintext-at-rest hole) or being able to decrypt one, the baker
# GENERATES the KEK entirely inside Vault Transit with
# `transit/datakey/plaintext/kek-<vm>`, uses the returned plaintext transiently
# to format, and stages ONLY the wrapped ciphertext.
#
# CRITICAL SECURITY PROPERTY: `transit/datakey/plaintext` MINTS NEW key material
# — it does NOT decrypt existing ciphertext (only `transit/decrypt` does). So a
# baker/node RCE holding this token can generate fresh, useless keys but CANNOT
# recover ANY existing tenant disk KEK. This policy therefore deliberately grants
# NO `transit/decrypt` and NO `luks-kek` READ. It is a SEPARATE token from
# vali's (`vali-orchestrator`), so vali never gains `datakey/plaintext` either.
#
# This is why the bake path meets the KEK-HSM objective: no online component
# (vali, this baker, a node) can decrypt a tenant disk; only the attested SNP
# KBS unwraps the KEK on release. The baker holds the NEW KEK's plaintext only
# transiently to format a disk that carries no tenant runtime data yet.

# Generate a fresh KEK (wrapped by the per-VM key) — returns the plaintext to
# luksFormat with; does NOT decrypt anything existing.
path "transit/datakey/plaintext/kek-*" {
  capabilities = ["update"]
}

# Create the per-VM Transit key on first bake (idempotent).
path "transit/keys/kek-*" {
  capabilities = ["create", "update"]
}

# Stage the WRAPPED KEK ciphertext + the userdata under the VM's namespace.
# Write-only shape mirrors vali-orchestrator: create/update, NO standing read of
# the luks-kek plaintext path (there is none — it holds ciphertext now anyway).
path "secret/data/hippius-compute/kbs/tenants/*" {
  capabilities = ["create", "update"]
}

# Read userdata/lifecycle-key back only where the bake legitimately needs it
# (first-write-wins / idempotent re-bake); NOT luks-kek.
path "secret/data/hippius-compute/kbs/tenants/+/userdata" {
  capabilities = ["create", "update", "read"]
}
path "secret/metadata/hippius-compute/kbs/tenants/*" {
  capabilities = ["read"]
}
