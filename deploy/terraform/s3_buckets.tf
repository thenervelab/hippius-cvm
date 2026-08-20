# Hippius S3 buckets (ARCHITECTURE.md §11/§22; issue #54 Hippius-S3 Q4).
#
# ── Writer-only / immutability model ────────────────────────────────
#
# Issue #54 Q4: Hippius S3 does NOT support Object Lock today. The
# "writer-only ACL" substitution is realised by three layers, only the
# first of which Terraform owns:
#
#   1. Bucket posture (HERE) — every bucket is `private` (canned ACL:
#      owner-only, no anonymous, no cross-account) AND has all four
#      public-access-block flags set, AND has versioning enabled.
#      Versioning makes an UNVERSIONED delete recoverable (it writes a
#      delete-marker, prior versions retained); it does NOT stop a
#      principal holding version-delete rights from permanently
#      purging a version. Terraform owns the posture — not the harder
#      "writer ≠ delete" guarantee, which is layer 2 (the out-of-band
#      writer credential must exclude version-delete) and, in future,
#      Object Lock.
#   2. Writer-key distribution (OUT OF BAND) — only the §22 ceremony
#      key (offline, 3× age-encrypted USB) holds write credentials to
#      `allowlist`/`images`; only the sentinel key (lives inside the
#      attested sentinel CVM, never exported) holds them for
#      `audit-anchors`/`backups`. An attacker cannot obtain the key, so
#      cannot write or delete. The AWS provider against an S3-compatible
#      store cannot manage these per-key grants — they are a Hippius S3
#      console step (see README).
#   3. Content-addressing + signatures (APPLICATION) — object keys are
#      the SHA-256 of their content and every object carries a §22-root
#      signature, so any tamper is caught at read by a digest/signature
#      mismatch. The §22 ceremony procedure has no delete op → de-facto
#      immutable.
#
# When Hippius S3 gains Object Lock, enable the commented
# `aws_s3_bucket_object_lock_configuration` blocks below — that is the
# real, enforced "writer ≠ delete"; no application code changes.

locals {
  # Each bucket: its name + the resource-specific tags merged on top of
  # the provider `default_tags` (part-of + managed-by).
  s3_buckets = {
    allowlist = {
      name = "hippius-compute-allowlist"
      tags = {
        purpose = "allowlist"
        # §22 root — ASCII tag value (`§` is not an S3 tag-safe char).
        signer = "section-22-root"
      }
    }
    images = {
      name = "hippius-compute-images"
      tags = {
        purpose = "images"
        signer  = "section-22-root"
      }
    }
    audit-anchors = {
      name = "hippius-compute-audit-anchors"
      tags = { purpose = "audit-anchors" }
    }
    backups = {
      name = "hippius-compute-backups"
      tags = { purpose = "backups" }
    }
  }
}

resource "aws_s3_bucket" "this" {
  for_each = local.s3_buckets
  bucket   = each.value.name
  tags     = each.value.tags

  # TODO: enable when Hippius S3 supports Object Lock (issue #54 Q4).
  # Object Lock must be turned on at bucket-CREATE time; flipping it on
  # later requires Hippius S3 support + recreating the bucket.
  # object_lock_enabled = true
}

# Versioning — enabled everywhere. An unversioned delete becomes
# recoverable (delete-marker written, prior versions retained); this
# does NOT block a version-delete by a principal that holds
# version-delete rights — see the header comment for how "writer ≠
# delete" is actually obtained. The allowlist additionally relies on
# versioning for monotonic-epoch reads.
resource "aws_s3_bucket_versioning" "this" {
  for_each = local.s3_buckets
  bucket   = aws_s3_bucket.this[each.key].id

  versioning_configuration {
    status = "Enabled"
  }
}

# Block every public-access path — no public ACLs, no public bucket
# policy, on existing or future objects. The strong "never public"
# control, universally supported by S3-compatible stores.
resource "aws_s3_bucket_public_access_block" "this" {
  for_each = local.s3_buckets
  bucket   = aws_s3_bucket.this[each.key].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Keep ACLs enabled (BucketOwnerPreferred, not BucketOwnerEnforced) so
# the explicit `private` canned ACL below is honoured.
resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = local.s3_buckets
  bucket   = aws_s3_bucket.this[each.key].id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Private / no-public ACL: the `private` canned ACL grants the bucket
# owner full control and nothing to anyone else — no anonymous, no
# cross-account, no public. This is a public-EXPOSURE control, not a
# writer-vs-delete control (the owner keeps delete). "Writer ≠ delete"
# comes from layers 2-3 above — credential scoping + future Object
# Lock — never from this ACL.
resource "aws_s3_bucket_acl" "this" {
  for_each   = local.s3_buckets
  bucket     = aws_s3_bucket.this[each.key].id
  acl        = "private"
  depends_on = [aws_s3_bucket_ownership_controls.this]
}

# Postgres backups bucket — retention lifecycle (issue #54: pg_dump →
# Hippius S3, consumed by the PR-K4 backup CronJob). Current objects
# AND non-current versions expire after the retention window.
resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  bucket = aws_s3_bucket.this["backups"].id

  rule {
    id     = "expire-after-retention"
    status = "Enabled"

    # Empty filter ⇒ the rule applies to every object in the bucket.
    filter {}

    expiration {
      days = var.backups_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.backups_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

# TODO: enable when Hippius S3 supports Object Lock (issue #54 Q4).
# This is the real enforced "writer ≠ delete" — a COMPLIANCE-mode
# retention lock no principal (not even the writer key) can shorten.
#
# resource "aws_s3_bucket_object_lock_configuration" "immutable" {
#   for_each = toset(["allowlist", "images", "audit-anchors"])
#   bucket   = aws_s3_bucket.this[each.value].id
#   rule {
#     default_retention {
#       mode = "COMPLIANCE"
#       days = 3650
#     }
#   }
# }
