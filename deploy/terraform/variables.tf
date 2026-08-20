# Input variables.
#
# No secret has a default. Secret-bearing variables are `sensitive` so
# Terraform redacts them from plan/apply output. Concrete values go in
# `terraform.tfvars` (git-ignored) — see `terraform.tfvars.example`.

# ─── common tagging ─────────────────────────────────────────────────

variable "common_tags" {
  description = <<-EOT
    Tags applied to every taggable resource. The two mandatory keys
    (`app.kubernetes.io/part-of`, `managed-by`) MUST stay — overriding
    this variable should only ADD keys.
  EOT
  type        = map(string)
  default = {
    "app.kubernetes.io/part-of" = "hippius-compute"
    "managed-by"                = "terraform"
  }
}

# ─── Hippius S3 (S3-API-compatible object store) ────────────────────

variable "hippius_s3_endpoint" {
  description = "Hippius S3 API endpoint (dogfooded object store — no AWS/R2/B2 fallback)."
  type        = string
  default     = "https://s3.hippius.com"
}

variable "hippius_s3_region" {
  description = <<-EOT
    Region string the S3 client sends. Hippius S3 is S3-compatible;
    `us-east-1` is the safe S3-compat default (no LocationConstraint on
    bucket create). Override if Hippius S3 pins a specific region.
  EOT
  type        = string
  default     = "us-east-1"
}

variable "hippius_s3_access_key" {
  description = "Hippius S3 access key id. Terraform uses it only to create the buckets."
  type        = string
  sensitive   = true
}

variable "hippius_s3_secret_key" {
  description = "Hippius S3 secret access key."
  type        = string
  sensitive   = true
}

variable "backups_retention_days" {
  description = "Lifecycle retention for the Postgres backup bucket (days)."
  type        = number
  default     = 30
}

# ─── Cloudflare DNS ─────────────────────────────────────────────────

variable "cloudflare_api_token" {
  description = "Cloudflare API token scoped to DNS edit on the hippius.network zone."
  type        = string
  sensitive   = true
}

variable "cloudflare_zone_id" {
  description = <<-EOT
    Zone id of `hippius.network`. Supplied directly (not looked up via a
    data source) so `terraform plan` needs no live Cloudflare API call.
  EOT
  type        = string
}

variable "dns_zone_name" {
  description = "DNS zone the service records live under."
  type        = string
  default     = "hippius.network"
}

# Public-facing service IPs. ALL of these default to the RFC 5737
# TEST-NET-1 documentation range (`192.0.2.0/24`) so an un-filled value
# is obviously a placeholder and never a real host. Set every one of
# them in `terraform.tfvars` before a real apply.

variable "kbs_public_ip" {
  description = "Public IP for kbs.hippius.network — fill after PR-K6 + Edge GW public exposure."
  type        = string
  default     = "192.0.2.1"
}

variable "vali_public_ip" {
  description = "Public IP for vali.hippius.network — fill after PR-K7."
  type        = string
  default     = "192.0.2.2"
}

# `edge` — the Edge gateway's MetalLB LoadBalancer IP (PR-H7). This is
# NOT a public IP: it is the private address MetalLB assigns out of the
# `lbPool.addresses` range (deploy/gitops/addons/metallb/values.yaml).
# `edge.hippius.network` is a NetBird-mesh-internal convenience record
# (`proxied = false`) — miners reach it over the mesh, never the public
# internet. See dns.tf. Must match
# `deploy/gitops/apps/edge-gateway/values.yaml::service.loadBalancerIP`.
variable "edge_loadbalancer_ip" {
  description = "Edge gateway MetalLB LoadBalancer IP (private address, NetBird-mesh-reachable)."
  type        = string
  default     = "192.0.2.10"
}

variable "argocd_public_ip" {
  description = "Public IP of the control-plane ingress-nginx LoadBalancer."
  type        = string
  default     = "192.0.2.3"
}

# ─── HashiCorp Vault (Tier-0) ───────────────────────────────────────

variable "vault_address" {
  description = "Vault API endpoint. RFC 2606 `.invalid` placeholder — set it in terraform.tfvars."
  type        = string
  default     = "https://vault.example.invalid:8200"
}

variable "vault_token" {
  description = "Vault token Terraform uses to manage policies + AppRole roles. Short-TTL, admin-scoped."
  type        = string
  sensitive   = true
}

variable "vault_ca_cert_file" {
  description = <<-EOT
    Path to the Vault server's CA certificate (`vault-ca.crt`, fetched
    from the Vault host — see README). Empty ("") falls back to
    the system trust store, which will fail TLS against the self-signed
    cert: set this for any real plan/apply.
  EOT
  type        = string
  default     = ""
}

variable "vault_skip_tls_verify" {
  description = "Skip Vault TLS verification. Dev-only escape hatch — keep false; set vault_ca_cert_file instead."
  type        = bool
  default     = false
}
