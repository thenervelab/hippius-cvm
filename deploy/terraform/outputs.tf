# Outputs — non-secret references downstream §K PRs consume.

output "s3_bucket_names" {
  description = "Provisioned Hippius S3 bucket names, keyed by role."
  value       = { for k, b in aws_s3_bucket.this : k => b.id }
}

output "s3_endpoint" {
  description = "Hippius S3 API endpoint the buckets live behind."
  value       = var.hippius_s3_endpoint
}

output "dns_record_fqdns" {
  description = "FQDNs of the managed Cloudflare DNS records."
  value       = { for k, _ in cloudflare_record.service : k => "${k}.${var.dns_zone_name}" }
}

output "vault_policy_names" {
  description = "Vault policy names provisioned — one per responsibility."
  value = [
    vault_policy.kbs_response_signing.name,
    vault_policy.packer_write_only.name,
    vault_policy.l1_ticket_signing.name,
    vault_policy.sentinel_anchor_signing.name,
  ]
}

output "vault_approle_backend_path" {
  description = "Mount path of the AppRole auth backend."
  value       = vault_auth_backend.approle.path
}

output "vault_approle_role_ids" {
  description = <<-EOT
    AppRole role_id per role. Non-secret (role_id is a public
    identifier); the matching secret_id is minted out of band — see
    README — and is never produced by Terraform.
  EOT
  value       = { for k, r in vault_approle_auth_backend_role.this : k => r.role_id }
}
