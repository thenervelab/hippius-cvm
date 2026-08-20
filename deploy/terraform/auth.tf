# AppRole auth — one role per NON-KBS Vault policy (issue #54 locked
# Q6/Q7).
#
# Each control-plane component authenticates with its OWN AppRole role,
# carrying ITS OWN single policy. A component holds no role but its
# own, so a compromise can never widen into another responsibility's
# Vault path.
#
# The KBS is the deliberate exception — it gets NO AppRole. Per
# ARCHITECTURE.md §8 the KBS Vault credential is SNP-attestation-bound:
# "there is no static KBS AppRole secret anywhere". The
# `kbs-response-signing` policy still exists (vault_policies.tf); it
# binds to the SNP-attestation auth method (a later §K PR). Minting a
# KBS AppRole here would create exactly the static secret the v1
# security model forbids — so only 3 of the 4 policies get a role.
#
# `role_id` is non-secret (it behaves like a username) and is exported
# in outputs.tf. The matching `secret_id` is the actual credential: it
# is minted out of band (`vault write -f auth/approle/role/<r>/secret-id`)
# per the README and delivered to each component via the External
# Secrets Operator — it is never created or stored by Terraform.

resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "approle"
}

locals {
  # AppRole role name → the single policy it carries. `kbs-response-
  # signing` is intentionally absent — see the header comment.
  approle_roles = {
    "packer-write-only"       = vault_policy.packer_write_only.name
    "l1-ticket-signing"       = vault_policy.l1_ticket_signing.name
    "sentinel-anchor-signing" = vault_policy.sentinel_anchor_signing.name
  }
}

resource "vault_approle_auth_backend_role" "this" {
  for_each = local.approle_roles

  backend        = vault_auth_backend.approle.path
  role_name      = each.key
  token_policies = [each.value]

  # The token carries EXACTLY its one responsibility policy. Vault
  # otherwise also attaches the built-in `default` policy (token
  # self-management + cubbyhole paths), which would break the
  # "exactly its own one policy" model — disable it.
  token_no_default_policy = true

  # A leaked secret_id is bounded: login REQUIRES the secret_id
  # (`bind_secret_id`), the secret_id itself expires, and the issued
  # token is short-lived with a hard max TTL.
  bind_secret_id = true
  secret_id_ttl  = 3600 # 1 h  — secret_id must be used within the hour
  token_ttl      = 1200 # 20 m — issued-token lease
  token_max_ttl  = 3600 # 1 h  — hard ceiling, no renewal past this
}
