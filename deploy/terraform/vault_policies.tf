# Vault policies — one per responsibility, never cross-domain
# (issue #54 locked Q6/Q7).
#
# Each policy is rendered from a standalone `.hcl` file in `policies/`
# so the exact capability grant is reviewable as its own artifact.
# Every policy is write-only: no `read`, no `list`, no `delete`, and no
# path wider than the single resource that responsibility owns. A
# component that is compromised can, at worst, write to its own one
# transit key / KV subtree — never read a secret, never reach another
# domain's path.
#
# NOTE: the `transit` and `secret` (KV-v2) secret engines, and the
# named keys (`kbs-response`, `l1-ticket`, `sentinel`), are provisioned
# out of band on the Tier-0 Vault (a Vault-setup step, not PR-K1). A
# `vault_policy` is just a path-string grant — it is accepted whether
# or not the engine exists yet, so these policies are forward-declared.

# kbs-response-signing binds to the SNP-attestation auth method
# (ARCHITECTURE.md §8), NOT an AppRole — the KBS deliberately has no
# AppRole role (see auth.tf). The policy is provisioned here regardless.
resource "vault_policy" "kbs_response_signing" {
  name   = "kbs-response-signing"
  policy = file("${path.module}/policies/kbs-response-signing.hcl")
}

resource "vault_policy" "packer_write_only" {
  name   = "packer-write-only"
  policy = file("${path.module}/policies/packer-write-only.hcl")
}

resource "vault_policy" "l1_ticket_signing" {
  name   = "l1-ticket-signing"
  policy = file("${path.module}/policies/l1-ticket-signing.hcl")
}

resource "vault_policy" "sentinel_anchor_signing" {
  name   = "sentinel-anchor-signing"
  policy = file("${path.module}/policies/sentinel-anchor-signing.hcl")
}

# hippius-compute-eso-read — the External-Secrets-Operator sync token
# (audit RA-N1). Unlike the write-only signing policies above this is a
# READ policy by necessity (ESO mirrors Vault KV leaves into k8s Secrets),
# but scoped to EXACTLY the ~12 leaves ESO syncs — NOT the wildcard
# `secret/data/hippius-compute/*` it previously held, which re-exposed the
# H2 trust-anchor seeds + every tenant KEK + s3/operator via a second
# token. Any new ExternalSecret leaf must be added to the .hcl. Previously
# provisioned out-of-band on the Tier-0 Vault; committed here so the scope
# is review-gated.
resource "vault_policy" "hippius_compute_eso_read" {
  name   = "hippius-compute-eso-read"
  policy = file("${path.module}/policies/hippius-compute-eso-read.hcl")
}
