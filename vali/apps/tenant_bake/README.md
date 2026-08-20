# apps.tenant_bake — per-tenant encrypted-qcow2 bake trigger

vali's HTTP surface for kicking off **per-tenant** image bakes. Mirrors
[`apps.packer`](../packer/README.md) — same state machine, same CAS
discipline, same worker-only `/finalize` permission gate — but where
`apps.packer` builds shared fleet images (KBS / Edge / Guest /
Audit-VM, one in flight per kind), `apps.tenant_bake` builds
per-tenant encrypted qcow2s (many in flight in parallel, at most one
per `vm_id`).

Spec of record: [issue #334](https://github.com/thenervelab/hippius-compute/issues/334).

## Why

The legacy bake script `scripts/tenant-image-bake.sh` runs on the
operator workstation as root, requires `qemu-img + cryptsetup +
losetup + chroot`, and produces the encrypted qcow2 the operator then
uploads to S3. The production trust + ops model is **every tenant-
launch operation originates from vali in k8s, no operator workstation
steps**.

PR #332 already closed the operator-SSH-to-miner side by archiving
`scripts/archived/tenant-disk-create.sh`. This app closes the
operator-workstation-bake side: a vali-triggered k8s Job replaces the
manual script. Phase 2 will then archive `tenant-image-bake.sh` the
same way.

## Endpoints (auth via `apps.identity`)

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `POST` | `/v1/tenant-bakes` | any `ServiceClient` | request a bake — body carries vm_id + base_image_url + base_image_sha256 + size_gb + kek_vault_path + s3 output bucket/prefix |
| `GET`  | `/v1/tenant-bakes/<bake_id>` | any `ServiceClient` | poll state |
| `POST` | `/v1/tenant-bakes/<bake_id>/finalize` | **baker worker only** (`VALI_TENANT_BAKE_WORKER_PRINCIPAL`) | close out a Queued/Running bake with `Running`/`Succeeded`/`Failed` |

State machine: `Queued → Running → {Succeeded | Failed}`. Terminal
states are immutable; retry = new row (with a fresh `bake_id`).
Optimistic concurrency via the `version` field, identical to
`apps.lifecycle` (PR-G2) and `apps.packer`.

## Constraints

- One **active** (Queued or Running) bake per `vm_id` — partial unique
  index. Concurrent `POST /v1/tenant-bakes` for the same `vm_id`
  surfaces as 409 with the conflicting row attached. Terminal rows
  (Succeeded / Failed) don't gate a fresh bake — a re-bake is a new
  row.
- `Succeeded` requires ALL FOUR fields: `qcow2_sha256`,
  `kernel_sha256`, `initrd_sha256` (each 64-hex lowercase) and
  `measurement_hex` (96-hex lowercase — the 48-byte SNP launch
  digest). DB CHECK constraints enforce this in addition to the view
  validation, so even a manual `UPDATE` outside the view cannot leave
  a Succeeded row in an under-populated state.
- `Failed` requires `failure_reason` (non-empty, ≤ 256 chars).

## Phase 2 follow-up

- `hippius-tenant-baker` container image — Dockerfile + entrypoint
  that wraps the existing `tenant-image-bake.sh` logic, reads bake
  params from env vars, finalizes via `POST /finalize`.
- k8s Job spec template in the vali Helm chart, triggered by a
  vali-side reconciler observing Queued rows.
- `vali_create_vm --in-cluster-bake` flag chains a bake request →
  poll → tenant-preflight → mint → dispatch in one operator
  invocation.

Tracking: [issue #334](https://github.com/thenervelab/hippius-compute/issues/334).
