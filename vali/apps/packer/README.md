# apps.packer — Packer trigger surface + S3 presigning

vali's HTTP surface for kicking off image builds (the Packer factory
ships in §F / issue #41) and for handing out presigned GET URLs once
an artifact lands in the Hippius S3 images bucket.

## Endpoints (auth via `apps.identity`)

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `POST` | `/v1/packer/build` | any `ServiceClient` | request a build (one in-flight row per `image_kind`) |
| `GET`  | `/v1/packer/build/<build_id>` | any `ServiceClient` | poll state |
| `POST` | `/v1/packer/build/<build_id>/finalize` | **worker only** (`VALI_PACKER_WORKER_PRINCIPAL`) | close out a Queued/Running build with `Running`/`Succeeded`/`Failed` |
| `POST` | `/v1/packer/build/<build_id>/presign-image-get` | any `ServiceClient` | presigned GET URL for the artifact (Succeeded builds only) |

State machine: `Queued → Running → {Succeeded | Failed}`. Terminal
states are immutable; retry = new row. Optimistic concurrency via
the `version` field — mirrors `apps.lifecycle` (PR-G2).

## Hippius S3 wiring

Locked decision Q12 (issue #1 comment 4496539510): vali distributes
images via **Hippius S3** (dogfooding). Four operational details are
still **tracked open in issue #54** (Hippius S3 follow-ups):

1. **Object Lock** — does Hippius S3 support it (needed for §22
   allowlist OOB delivery + provenance WORM storage)?
2. **Endpoint URL** — real prod / staging value once the cluster
   stands up.
3. **Credential path** — env vars now; Vault transit STS once the
   Vault path lands (Q6 follow-up).
4. **Presign support** — does the Hippius S3 implementation correctly
   emit + accept SigV4 presigned URLs?

Until those resolve, vali ships with:

- `apps.storage.s3.HippiusS3Client` — abstract base, the only
  surface `apps.packer` consumes.
- `apps.storage.s3.MockHippiusS3Client` — default factory; emits
  `mock-s3://…` URLs deterministically. **Wired by default** so dev
  + tests + first deploys don't blow up on an unreachable endpoint.
- `apps.storage.s3.BotoHippiusS3Client` — boto3-backed, ready to
  flip on once the four answers above land.

Switching to the real wiring is a single env-var flip:

```bash
export VALI_S3_CLIENT_FACTORY=apps.storage.s3.boto_factory
export HIPPIUS_S3_ENDPOINT_URL=https://s3.hippius.example.com
export HIPPIUS_S3_REGION_NAME=us-east-1  # optional
# AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY via boto3 default chain
```

No code change in `apps.packer`, the views, or the tests.

## Settings

| Setting | Default | Purpose |
| --- | --- | --- |
| `VALI_PACKER_WORKER_PRINCIPAL` | `""` (fails closed) | `ServiceClient.name` allowed to call `/finalize` |
| `VALI_PACKER_IMAGES_BUCKET` | `hippius-compute-images` | S3 bucket for artifacts |
| `VALI_PACKER_PRESIGN_TTL_SECS` | `3600` (1 h) | default TTL for `presign-image-get` |
| `VALI_S3_CLIENT_FACTORY` | `apps.storage.s3.mock_factory` | DI for the S3 client |
| `HIPPIUS_S3_ENDPOINT_URL` | `""` | required when using `boto_factory` |
| `HIPPIUS_S3_REGION_NAME` | `""` | optional region override |

## What's NOT here

- Bucket creation / Object Lock configuration — that's an ops
  responsibility tracked in #54.
- The actual Packer Job (Kubernetes) that consumes `Queued` rows —
  ships in PR-F* (issue #41).
- §22 allowlist signing pipeline — separate (Q8) and pulled by the
  KBS, not by vali.
