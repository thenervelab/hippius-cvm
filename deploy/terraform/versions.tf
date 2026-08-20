# Terraform core + provider version pins.
#
# Every provider is pinned to an EXACT version (no `~>`, no `latest`) so
# a `terraform init` on any machine, at any time, resolves the identical
# provider build. `.terraform.lock.hcl` (committed) additionally pins the
# per-platform hashes.
#
# PR-K1 has no hosting-provider-managed resource — the bare-metal box is
# bootstrapped by `deploy/ansible/` (PR-K2), not Terraform — so no
# bare-metal provider is
# deliberately NOT declared here. Add it in a later §K PR if/when an
# provider-API resource (private networking, IP failover, …) becomes
# Terraform-managed.

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    # S3 buckets on Hippius S3 (S3-API-compatible — the AWS provider is
    # pointed at the Hippius endpoint in providers.tf; no real AWS).
    aws = {
      source  = "hashicorp/aws"
      version = "5.82.2"
    }
    # Cloudflare DNS records for the public-facing service hostnames.
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "4.52.0"
    }
    # Vault policies + AppRole auth for the Tier-0 broker secrets.
    vault = {
      source  = "hashicorp/vault"
      version = "4.5.0"
    }
  }
}
