# `deploy/terraform/` — cloud resources

Terraform for the hippius-compute control-plane **cloud resources**:
Hippius S3 buckets, Cloudflare DNS records, and HashiCorp Vault
policies + AppRole auth. This is **PR-K1** of §K
([issue #54](https://github.com/thenervelab/hippius-compute/issues/54));
the locked infrastructure topology is
[issue #1 → comment](https://github.com/thenervelab/hippius-compute/issues/1#issuecomment-4505904116).

Cluster-internal resources (CNI, ingress, runtimes, apps) are **not**
here — those are GitOps (`deploy/gitops/`, Argo CD). Terraform owns
only what lives outside the cluster.

## What this provisions

| Resource | Detail |
|---|---|
| `hippius-compute-allowlist` | §22 measurement allowlist. Versioned, private, public-access blocked. |
| `hippius-compute-images` | UKI artifacts + signed provenance maps. Versioned, private. |
| `hippius-compute-audit-anchors` | Sentinel hash-chain head snapshots. Versioned, private. |
| `hippius-compute-backups` | Postgres `pg_dump` backups. Versioned, private, **30-day** lifecycle. |
| 4× Cloudflare A records | `kbs` / `vali` / `edge` / `argocd` `.hippius.network`, Cloudflare-proxied. |
| 4× Vault policies | `kbs-response-signing`, `packer-write-only`, `l1-ticket-signing`, `sentinel-anchor-signing` — write-only, one per responsibility. |
| 3× Vault AppRole roles | One per **non-KBS** policy — no component holds another's role. The KBS authenticates by SNP attestation (ARCHITECTURE.md §8), so it gets no AppRole. |

## Workflow

```
edit *.tf  ──►  PR  ──►  review + merge  ──►  operator runs `terraform apply`
```

Unlike the GitOps tree, Terraform is **not** auto-reconciled — an
operator applies it deliberately. `terraform plan` is part of PR review.

### Bootstrap (one-time)

```sh
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars   # then fill in the secrets
terraform init
terraform plan        # review
terraform apply       # deliberate
```

`terraform.tfvars`, `*.tfstate*` and `.terraform/` are git-ignored
(`deploy/.gitignore`). `.terraform.lock.hcl` **is** committed — it pins
the provider hashes.

### Vault CA certificate

The Tier-0 Vault serves a self-signed certificate. Fetch its CA
(`vault-ca.crt`) from the Vault CVM and point `vault_ca_cert_file` at
it. It is a **public** certificate — safe to keep on disk — but it is
not committed to this repo; obtain it from the operator who runs the
Vault infrastructure.

## State backend

MVP uses the **local** backend — `terraform.tfstate` in this directory,
git-ignored. State holds resolved secrets in plaintext, so it must
never be committed. Migrate to the GCS backend (encrypted at rest +
state locking) once the team is multi-operator — see `backend.tf`.

## Design notes

### S3 writer-only / immutability

Hippius S3 does **not** support Object Lock today (issue #54 Q4). The
"writer-only ACL" is realised in three layers — Terraform owns only
the first:

1. **Bucket posture** (this code) — every bucket is `private` (canned
   ACL, owner-only) with all four public-access-block flags set, and
   versioning enabled. Versioning makes an *unversioned* delete
   recoverable (delete-marker written, prior versions kept); it does
   **not** stop a principal with version-delete rights from purging a
   version — that depends on layer 2 scoping the writer credential to
   exclude version-delete, and ultimately on Object Lock. Terraform
   owns the posture, not the "writer ≠ delete" guarantee.
2. **Writer-key distribution** (out of band) — only the §22 ceremony
   key (offline, air-gapped) can write `allowlist`/`images`; only the
   sentinel key (inside the attested sentinel CVM) can write
   `audit-anchors`/`backups`. The AWS provider against an S3-compatible
   store cannot manage these per-key grants — set them in the Hippius
   S3 console.
3. **Content-addressing** (application) — object keys are the SHA-256
   of their content + every object carries a §22-root signature, so a
   tamper is caught at read.

`s3_buckets.tf` carries commented `aws_s3_bucket_object_lock_configuration`
blocks — the real enforced "writer ≠ delete" — to enable the day
Hippius S3 supports Object Lock (a bucket-config change, no app code).

### DNS — MVP vs final

The 4 A records are the **MVP** posture: services fronted by
ingress-nginx on the control-plane node, Cloudflare-proxied
(`proxied = true`).
The **locked final design** is Edge-via-NetBird — `kbs`/`vali` traffic
over the NetBird mesh, not the public internet — so `kbs`/`vali` here
are transitional and will narrow to mesh-only once the Edge GW lands
(PR-K8). `kbs`/`vali`/`edge` default to RFC 5737 placeholder IPs; fill
the real values in `terraform.tfvars` as each service is deployed.

### Vault — out-of-band prerequisites

PR-K1 provisions the **4 policies + 3 AppRole roles** only. It assumes
the `transit` and `secret` (KV-v2) secret engines, and the named
transit keys (`kbs-response`, `l1-ticket`, `sentinel`), are already
mounted on the Tier-0 Vault — a Vault-setup step outside this PR. Each
AppRole `secret_id` is minted out of band and delivered via the
External Secrets Operator (PR-K11); Terraform never creates or stores
a `secret_id`.

**The KBS gets a policy but no AppRole.** Per ARCHITECTURE.md §8 the
KBS Vault credential is SNP-attestation-bound — there is *no static
KBS AppRole secret anywhere*. The `kbs-response-signing` policy is
provisioned here, but it binds to the SNP-attestation auth method (a
later §K PR), never to an AppRole — so only 3 of the 4 policies get a
role. Minting a KBS AppRole would reintroduce exactly the static
secret the v1 model forbids.

### Bare-metal hosting provider

PR-K1 has **no** provider-managed bare-metal resource — the box is
bootstrapped by `deploy/ansible/` (PR-K2). No bare-metal Terraform
provider is therefore declared; add yours in a later §K PR if a
provider-API resource (private networking, IP failover) ever becomes
Terraform-managed.

## Secret hygiene

- No secret value is ever committed. `terraform.tfvars` and `*.tfstate`
  are git-ignored; secret variables are marked `sensitive`.
- Providers are pinned to **exact** versions (`versions.tf`).
- Every taggable resource carries `app.kubernetes.io/part-of=hippius-compute`
  + `managed-by=terraform` (AWS `default_tags`; Cloudflare records carry
  it in `comment`, since DNS records have no key=value tag map).
