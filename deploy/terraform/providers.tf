# Provider configuration.

# ─── Hippius S3, via the AWS provider ───────────────────────────────
#
# Hippius S3 is S3-API-compatible, so the AWS provider drives it — but
# it is NOT AWS. The `skip_*` flags below disable every AWS-only control
# path (STS credential validation, the IMDS metadata endpoint, the
# account-id lookup, region validation); `endpoints.s3` retargets the
# S3 API at the Hippius endpoint and `s3_use_path_style` forces
# path-style addressing (`endpoint/bucket`, not `bucket.endpoint` —
# required for a custom-domain S3-compatible store).
provider "aws" {
  region     = var.hippius_s3_region
  access_key = var.hippius_s3_access_key
  secret_key = var.hippius_s3_secret_key

  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true

  endpoints {
    s3 = var.hippius_s3_endpoint
  }

  # Applied to every taggable AWS resource. Per-resource `tags` blocks
  # add resource-specific keys (`purpose`, `signer`) on top.
  default_tags {
    tags = var.common_tags
  }
}

# ─── Cloudflare DNS ─────────────────────────────────────────────────
provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# ─── HashiCorp Vault (Tier-0) ───────────────────────────────────────
#
# Manages policies + AppRole auth only. The token is admin-scoped and
# short-TTL; it is never persisted to the repo (tfvars are git-ignored).
provider "vault" {
  address         = var.vault_address
  token           = var.vault_token
  ca_cert_file    = var.vault_ca_cert_file
  skip_tls_verify = var.vault_skip_tls_verify
}
