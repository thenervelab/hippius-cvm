# Tenant launch runbook (ARCHIVED — pre-BYO-OS flow)

> ⚠️ **This runbook is archived.** It documents the legacy
> operator-SSH-to-miner provisioning flow which is incompatible
> with the production trust model (the operator does NOT have SSH
> to miner hosts).
>
> **Use [`byo-base-os-bake-runbook.md`](../byo-base-os-bake-runbook.md)
> instead.** That runbook covers the modern BYO base-OS path:
> the operator bakes an encrypted qcow2 on their own workstation,
> uploads to S3, and `vali_create_vm` dispatches a `tenant-preflight`
> order so the miner-agent fetches the image via short-TTL
> presigned URLs + sha-verifies. No operator-to-miner SSH
> anywhere.
>
> Kept under `docs/operator/archived/` for git-history reference
> only — invocations of `tenant-disk-create.sh` /
> `tenant-uki-stage-miner.sh` below will not work on production
> deployments.

End-to-end operator procedure to bring a single tenant CVM up on
a miner host under SEV-SNP attestation: stage release secrets,
mint a signed `OrderTicket`, submit it to vali, watch the chain
`vali → Edge → <miner> → KBS → guest`, confirm the tenant joins the
NetBird mesh.

This is the post-PR-V slice. Each step links to the binary / chart /
README that owns the behaviour; this document only sequences them.

## 0. Prerequisites

| Need | Where |
|---|---|
| Cluster access (`kubectl`) | `<PATH_TO_YOUR_KUBECONFIG>` |
| Vault Tier-0 token w/ tenant write capability | see §1 below |
| Vault CA cert (self-signed) | `vault-ca.crt` (copy locally, or pass `--vault-cacert`) |
| Dev L1 OrderTicket signing key | `packer/keys/dev/l1-order-ticket.dev.ed25519` (PR #161) |
| Tenant UKI in §22 allowlist | epoch ≥ 2 (PR #161 – allowlist published to `s3://hippius-compute-images/allowlist/v1/dev.cose`) |
| PR-B `order-ticket-mint` binary | parallel PR – path `binaries/order-ticket-mint/` (consume the JSON this runbook produces) |
| KBS pod healthy | `kubectl -n kbs get deploy/kbs-server` reports `READY 1/1` |
| Tenant LUKS disk image | pre-built with passphrase = exact bytes of `--luks-kek-file` (see §3) |
| Cloud-init user-data file | YAML / JSON containing the NetBird `setup-key` + first-boot config (see §4) |
| Tenant UKI staged on the miner | see §0a below — `scripts/tenant-uki-stage-miner.sh` |

## 0a. Pre-flight: stage the tenant UKI on the target miner

The miner-agent dispatch path expects `kernel`, `initrd`, `cmdline`,
and `ovmf.fd` as four SEPARATE files (`vali_dispatch_launch.py`
hands them to `--kernel-path` / `--initrd-path` / `--cmdline` /
`--ovmf-path`, alongside the now-required `--cpu-count` and
`--memory-mb` — `vcpus` feeds the SNP launch digest, so the value
MUST equal `test_vectors/uki/tenant-measurement.json::
snp_launch_config.vcpus` for the deployed UKI, currently `1`).
The build pipeline publishes a single signed UKI EFI PE
(`tenant-<v>.uki.signed`) carrying the kernel/initrd/cmdline as
named PE sections; OVMF is a separate shared fleet pin.

`scripts/tenant-uki-stage-miner.sh` does the pre-flight in one shot:
auth-fetch from S3 → SHA-gate locally → scp to the miner → SHA-gate
remotely → `objcopy --dump-section` to split the four ingredients →
atomic rename into place. The script is idempotent: a re-run against
an already-staged sha is a no-op (use `--force` to re-stage).

```bash
# One-time per host: install OVMF at the cluster-wide path the
# script symlinks from each stage dir. (URL + SHA pinned in
# packer/kbs-uki/ovmf/ovmf.lock; this script does NOT fetch OVMF —
# the operator runs the fetch once per miner host.)
ssh <user>@<miner> 'sudo install -m 0644 ovmf.fd /var/lib/hippius-miner/ovmf.fd'

# Per tenant launch: stage the signed UKI by content address.
export VAULT_TOKEN=$(cat ~/.vault-token)    # operator token, S3-read policy
scripts/tenant-uki-stage-miner.sh \
    --miner-host <user>@<miner-ip> \
    --tenant-uki-sha <64-hex>
```

Output (single-line JSON on stdout) lists the staged paths and
per-section sha256s — the kernel / initrd / cmdline sha is also what
the §22 `launch_digest` covers, so logging it here adds no exposure.

Run this BEFORE §5 ("Stage the release secrets"): a launch dispatch
to a miner without a staged UKI fails at `cvm-launch-failed/domain-error`
(the new `dispatch-failed-detail` log line — PR #164 — surfaces that
classifier). The §22 allowlist (epoch ≥ 2) gates which UKI shas are
accepted; this script only stages, it does not verify the allowlist.

| Flag | Purpose |
|---|---|
| `--miner-host` | Anything `ssh` accepts (`user@host`, alias, …). Operator key only — `BatchMode=yes`. |
| `--tenant-uki-sha` | 64-char lowercase-hex SHA-256, the bucket's content address. |
| `--tenant-uki-version` | Optional. If omitted, the script lists `s3://hippius-compute-images/images/<sha>/` and picks the single `*.uki.signed`. |
| `--out-dir` | Default `/var/lib/hippius-miner/staging/tenant-<sha8>` on the miner. |
| `--vault-s3-path` | KV-v2 path holding `{access_key, secret_key, endpoint?, bucket?}`. Default `hippius-compute/s3/operator`. |
| `--ovmf-path` | Cluster-wide OVMF location on the miner. Default `/var/lib/hippius-miner/ovmf.fd`. |
| `--force` | Replace an existing stage dir even when the sha already matches. |
| `--dry-run` | Print the planned actions; no Vault / S3 / SSH side-effects. |

§20 discipline: the script never logs UKI bytes, never echoes the S3
secret key or the Vault token. Diagnostic surface = sha + sizes +
paths only.

## 1. Vault writer policy (one-time)

The KBS read policy `hippius-compute-kbs-read` (see
`deploy/gitops/apps/kbs/README.md`) already covers
`secret/data/hippius-compute/kbs/*`, which includes the tenant
sub-tree `hippius-compute/kbs/tenants/<vm>/...`. That is what KBS
reads at release time — no chart change needed.

What is missing is the operator-side WRITER policy. Create it once
on the Tier-0 Vault (Terraform follow-up will fold this in):

```hcl
# hippius-compute-tenant-stage.hcl
path "secret/data/hippius-compute/kbs/tenants/+/luks-kek" {
  capabilities = ["create", "update"]
}
path "secret/data/hippius-compute/kbs/tenants/+/userdata" {
  capabilities = ["create", "update"]
}
# Idempotency probe in tenant-secrets-stage.sh — needs to detect
# "does this path already exist?" so it refuses to silently roll a
# KEK without --force.
path "secret/metadata/hippius-compute/kbs/tenants/+/luks-kek" {
  capabilities = ["read"]
}
path "secret/metadata/hippius-compute/kbs/tenants/+/userdata" {
  capabilities = ["read"]
}
```

```bash
vault policy write hippius-compute-tenant-stage \
  hippius-compute-tenant-stage.hcl

# Operator token bound to the policy. -period for renewable, no expiry
# semantics — `vault token revoke` is the off switch.
OPERATOR_TOKEN=$(vault token create \
  -policy=hippius-compute-tenant-stage \
  -period=768h -orphan -display-name=tenant-stage-operator \
  -format=json | jq -r '.auth.client_token')
```

Use `OPERATOR_TOKEN` as `--vault-token` in §2 below.

## 2. Pick a `vm_id` and the matching tenant / ticket / lease ids

The script binds `(tenant_id, vm_id, ticket_id, userdata_path,
userdata_version, plaintext)` into the `allowed_userdata_digest`. The
ids it stages against MUST be byte-identical to what the PR-B
`order-ticket-mint` binary writes into the `OrderTicket` it signs.

Naming convention (dev):

| Field | Example | Notes |
|---|---|---|
| `vm_id` | `tenant-1` | persists across `vm_generation` bumps |
| `tenant_id` | `t-1` | logical account |
| `ticket_id` | `tk-2026-05-25-001` | per-mint, single-use; binds the KBS release-once cell |
| `lease_id` | `lease-2026q2` | not staged; set on the ticket directly |
| `vm_generation` | `1` | starts at 1 for a fresh `vm_id` |
| `platform_id` | hex(CHIP_ID) of the target miner | attested at release time |

Smoke-test ids the dev cluster expects:

```bash
VM=smoke-vault-staging-test
TENANT=t-smoke
TICKET=tk-smoke-001
```

## 3. Prepare the LUKS KEK + tenant disk image

The KBS hands the guest exactly the bytes the operator staged
(PR-V `vault_mvp.rs` schema lock — `{"value": "<base64>"}` decoded
on read). So the LUKS image's slot passphrase MUST be the same 32
bytes the script stages.

```bash
# 1. Generate the KEK.
openssl rand 32 > /run/user/$(id -u)/luks-kek-${VM}.bin
chmod 600   /run/user/$(id -u)/luks-kek-${VM}.bin

# 2. Keep the KEK file readable to the staging script in §5.
#    Do NOT commit it, do NOT copy it off this host. tmpfs is the
#    intended home; the script reads it once then it can be wiped.
```

The LUKS-formatted disk image on the miner is laid down by §5.5,
**after** the KEK has been staged in Vault — that flow guarantees the
disk and Vault share the same byte-exact key without an operator ever
copy-pasting the bytes through a shell.

## 4. Author the cloud-init user-data

Single file, NoCloud format. cloud-init reads it from
`/run/cloud-init-seed/user-data` (initramfs writes there after KBS
unwrap). The bytes are the PLAINTEXT — no base64, no JSON envelope.

Minimum to join the mesh:

```yaml
#cloud-config
write_files:
  - path: /etc/netbird/setup-key
    permissions: '0600'
    encoding: text/plain
    content: |
      DE772700-6715-4377-9CB3-FD6B887D2FE8

runcmd:
  - curl -fsSL https://pkgs.netbird.io/install.sh | sh
  - systemctl enable --now netbird
  - netbird up --setup-key "$(cat /etc/netbird/setup-key)"
```

Write it to a tmpfs path:

```bash
cat > /run/user/$(id -u)/userdata-${VM}.yaml <<'YAML'
#cloud-config
...
YAML
chmod 600 /run/user/$(id -u)/userdata-${VM}.yaml
```

The script `--reject-placeholder` gate fails closed if the file
still contains literal `REPLACE_ME_` — useful when templating.

## 5. Stage the release secrets

Run from the repository root:

```bash
export VAULT_ADDR=https://<YOUR_VAULT_HOST>:8200
export VAULT_TOKEN="${OPERATOR_TOKEN}"   # from §1
export VAULT_CACERT=$PWD/vault-ca.crt    # if you keep a local copy

STAGED=$(scripts/tenant-secrets-stage.sh \
  --vm-id "${VM}" \
  --tenant-id "${TENANT}" \
  --ticket-id "${TICKET}" \
  --luks-kek-file /run/user/$(id -u)/luks-kek-${VM}.bin \
  --userdata-file /run/user/$(id -u)/userdata-${VM}.yaml)

# Stdout is a single-line JSON envelope. Sample (real values vary):
#   {
#     "vm_id": "smoke-vault-staging-test",
#     "tenant_id": "t-smoke",
#     "ticket_id": "tk-smoke-001",
#     "luks_vault_ref":     { "path": ".../luks-kek", "version": 1 },
#     "userdata_vault_ref": { "path": ".../userdata", "version": 1 },
#     "allowed_userdata_digest_hex": "<64 hex>"
#   }

echo "${STAGED}" | jq .
```

`tenant-secrets-stage.sh` refuses to overwrite an existing path
unless `--force`. The first mint of a tenant uses `--version 1`; a
roll re-runs with `--force` and yields `version 2` (KV-v2 metadata
preserves history).

Once `STAGED` is captured, the in-memory KEK file can be wiped:

```bash
shred -u /run/user/$(id -u)/luks-kek-${VM}.bin
shred -u /run/user/$(id -u)/userdata-${VM}.yaml
```

## 5.5. Pre-flight: create the tenant LUKS image on the target miner

`scripts/archived/tenant-disk-create.sh` reads the KEK back out of Vault (the
single source of truth post §5), pipes the raw bytes STRAIGHT
through SSH into `cryptsetup luksFormat --key-file=-` on the miner,
and never materialises them as a file or argv anywhere along the way.
The result is `/var/lib/hippius-miner/staging/tenant-<vm-id>/luks.img`
— LUKS2 + argon2id, the only profile
`binaries/agent-initramfs/src/stages/luks_cryptsetup.rs` accepts.

```bash
# Re-uses VAULT_ADDR / VAULT_TOKEN / VAULT_CACERT from §5.
scripts/archived/tenant-disk-create.sh \
  --miner-host <user>@<miner> \
  --vm-id "${VM}" \
  --size-gb 10
```

What it does, in order:

1. **Fetch KEK from Vault** — `vault kv get -format=json
   secret/${VAULT_PATH_PREFIX:-hippius-compute/kbs/tenants}/${VM}/luks-kek`,
   `jq -r .data.data.value`, `base64 -d` — yields the same 32 bytes
   §5 staged.
2. **Print the SHA-256 fingerprint** to stderr so the operator can
   cross-reference against the KBS release log once the guest
   attests. The bytes themselves NEVER appear in stderr / a log /
   an argv (§20).
3. **Probe** `<out-path>` on the miner. If the image already exists
   AND is LUKS2 AND unlocks with this KEK → exit 0 with
   `"state": "already_provisioned"`. Mismatched LUKS or different
   KEK fails with exit 3 unless `--force` is passed.
4. **Format**: `sudo install -d -m 0700 ...`, `truncate -s ${N}G ...`,
   zero the first 16 MiB (kill any prior LUKS header on `--force`),
   then `cryptsetup luksFormat --type luks2 --batch-mode --pbkdf
   argon2id --key-file=-` — passphrase piped through the SSH stdin.
5. **Sanity-verify** with `cryptsetup luksDump`. Refuses the result
   unless version=2, PBKDF=argon2id, slot 0 present.

Output (single-line JSON on stdout — chainable):

```json
{
  "vm_id": "...", "miner_host": "...", "out_path": "...",
  "size_gb": N, "kek_sha256": "<64 hex>",
  "luks_version": 2, "luks_pbkdf": "argon2id",
  "state": "created" | "already_provisioned"
}
```

§20 boundary: the bytes flow `Vault HTTP → in-process base64 → ssh
stdin → cryptsetup stdin`. The script's process holds the base64
string for ~50 ms (long enough to print the sha256), then
`unset`s it (and a `trap … EXIT` re-runs the unset on any failure
path). The remote `cryptsetup` reads `--key-file=-` and copies into
libcryptsetup's mlock'd buffer; nothing on the miner ever
materialises the key outside that buffer. When `--kek-source=file`
is used, the input file already exists on the operator's machine;
the script reads it once into a process-memory base64 string and
never creates any new file (local or remote) that holds the key.

> **`--kek-file` path discipline**: pass an ABSOLUTE path. The script
> reads the file directly (`< "${kek_file}"`), so a relative path
> resolves against the operator's current working directory — under
> a CI / cron / automation harness, the CWD is unpredictable and a
> wrong-CWD run could silently read the wrong file (or fail-loud if
> none exists at the relative path). The runbook always uses
> `/run/user/$(id -u)/luks-kek-${VM}.bin`, which is absolute.

Re-running on a healthy disk is safe:

```bash
$ scripts/archived/tenant-disk-create.sh --miner-host ... --vm-id "${VM}" --size-gb 10
tenant-disk-create.sh: probing ...
tenant-disk-create.sh: ... already provisioned with this KEK — no-op
{"vm_id":"...", ..., "state":"already_provisioned"}
```

The `state` discriminator is the script's contract — chain on it
(don't grep stderr).

## 6. Mint the OrderTicket (PR-B `order-ticket-mint`)

The mint binary lives at `binaries/order-ticket-mint/` (parallel
PR-B). It consumes the JSON from §5 plus the per-tenant inputs that
DON'T touch Vault (allowed_measurements, lease_id, vm_generation,
platform_id, expiry, lifecycle_perms, …) and emits a COSE_Sign1
envelope.

See `binaries/order-ticket-mint/README.md` for the full CLI. The
short form:

```bash
order-ticket-mint \
  --seed packer/keys/dev/l1-order-ticket.dev.ed25519 \
  --kid l1-order-ticket-dev-v1 \
  --schema-v 1 \
  --tenant-id  "${TENANT}" \
  --vm-id      "${VM}" \
  --ticket-id  "${TICKET}" \
  --lease-id   lease-2026q2 \
  --vm-generation 1 \
  --node-id    <MINER_ID> \
  --platform-id <hex-CHIP_ID-of-miner> \
  --allowed-measurement f89f6a20e1e985e483c0b25abbf9d157d7f3e2302baefbe90c5af00e880ccb5ff26f0fd06bc10f1fe99e8c17972fd928 \
  --resource-class standard \
  --lifecycle-perms start,stop \
  --issue-time $(date -u +%s) \
  --expiry     $(($(date -u +%s) + 86400)) \
  --luks-vault-path     "$(echo "${STAGED}" | jq -r .luks_vault_ref.path)" \
  --luks-vault-version  "$(echo "${STAGED}" | jq -r .luks_vault_ref.version)" \
  --userdata-vault-path    "$(echo "${STAGED}" | jq -r .userdata_vault_ref.path)" \
  --userdata-vault-version "$(echo "${STAGED}" | jq -r .userdata_vault_ref.version)" \
  --allowed-userdata-digest-hex "$(echo "${STAGED}" | jq -r .allowed_userdata_digest_hex)" \
  --out /tmp/${TICKET}.cose
```

The measurement above is the §F tenant UKI (PR #146 KAT,
`test_vectors/uki/tenant-measurement.json`). When the UKI is rebuilt,
re-mint §22 allowlist + this measurement in lockstep.

## 7. Submit to vali

vali ingests the COSE blob opaquely (§3 / §4 of `ARCHITECTURE.md`)
and persists it in `OrderTicketIntake`. The transport endpoint is
`vali/apps/orders/urls.py` → `POST /v1/order_ticket`.

```bash
curl -fsSL --cacert "${VAULT_CACERT:-/etc/ssl/certs/ca-certificates.crt}" \
  -H "Authorization: Bearer ${VALI_SERVICE_TOKEN}" \
  -H "Content-Type: application/cbor" \
  --data-binary @/tmp/${TICKET}.cose \
  https://vali.hippius.network/v1/order_ticket
```

Expected: `201 Created` on first intake (idempotent `200 OK` on a
byte-identical replay). Body is minimal JSON — never echoes the
ticket bytes.

If `vali.hippius.network` isn't routable from outside the cluster
yet, port-forward:

```bash
kubectl -n vali port-forward svc/vali 8000:80
# then POST to http://127.0.0.1:8000/v1/order_ticket
```

## 8. Watch the chain

The OrderTicket COSE bytes travel through every layer **byte-identical**:
vali stores the blob (`OrderTicketIntake.cose_blob`) → vali's launch
dispatch attaches it to the `LaunchOrder.cose_ticket` JSON field (base64)
→ Edge signs the whole `OrderBody` and forwards → miner-agent receives,
extracts the bytes from `LaunchOrder.cose_ticket: ByteBuf` → after the
libvirt domain reaches `Running`, miner-agent **pushes the bytes over
AF_VSOCK to the guest** at `(guest_cid, hippius_types::ticket_vsock::PORT)`
→ guest `/init` (`hippius-agent-initramfs`) accepts on
`(VMADDR_CID_ANY, PORT)` and reads them as its first §21 stage. The
operator never pre-stages a ticket file on the miner — the dispatch
itself carries the bytes (no audit hole where a staged-vs-dispatched
mismatch could go silent).

```bash
# vali — scheduler placement + orchestration dispatch
kubectl -n vali logs deploy/vali -f | grep -E "ticket|Vm|placement|dispatch"

# Edge — order forward to the miner over NetBird
kubectl -n edge-gateway logs deploy/edge-gateway-inner -f | grep order

# miner-agent — libvirt define + launch + ticket push (run on the miner itself)
ssh <user>@<miner> 'sudo journalctl -u hippius-miner-agent -f'
# A successful push is silent; a failure surfaces as outcome class
# `ticket-delivery-failed` (with a sub-class `connect-timeout` /
# `oversize` / `no-cid` / `empty` / `write-failed`). See
# `binaries/miner-agent/src/error.rs::MinerAgentError::TicketDelivery`.

# guest libvirt domain
ssh <user>@<miner> 'sudo virsh list --all'

# guest console — early-boot log; the agent-initramfs prints
# `fail-closed: ticket/vsock-…` on a ticket-load failure
ssh <user>@<miner> 'sudo virsh console tenant-1'   # ^] to exit
```

KBS release path (the load-bearing log to confirm):

```bash
kubectl -n kbs logs deploy/kbs-server -f | grep -E "release|denied|granted|SevChainVerifier"
```

A successful release prints `granted` with the ticket-id; a denied
release prints the structured reason (kid not in allowlist,
measurement mismatch, digest mismatch, …). Both paths are also in
the hash-chained audit log (PV-mounted at `/var/lib/kbs/audit`).

## 9. Verify the tenant joined the mesh

NetBird side:

```bash
# Operator-Mac, ping by mesh IP (allocated dynamically; check the
# NetBird dashboard at https://vpn.hippius.network/peers — the new
# peer's hostname is the cloud-init `hostname` from §4).
ping -c 3 <tenant-mesh-ip>
```

vali side:

```bash
# apps.lifecycle.Vm row reaches Active{gen=1, host=<chip-id>,
# lease_id=lease-2026q2}.
kubectl -n vali exec deploy/vali -- python manage.py shell -c \
  "from apps.lifecycle.models import Vm; \
   print(Vm.objects.get(vm_id='${VM}').state)"
```

Acceptance:

- KBS audit log: one `granted` entry for `(ticket_id, vm_id) =
  (${TICKET}, ${VM})`, no preceding `denied`.
- `virsh list` on the miner shows the guest `running`.
- NetBird dashboard lists the new peer with `Connected`.
- vali `Vm.state = Active{gen=1}`.

## 10. Rollback / teardown

```bash
# Stop the guest (vali emits a stop OrderBody to the miner)
kubectl -n vali exec deploy/vali -- python manage.py shell -c \
  "from apps.lifecycle.service import stop; stop('${VM}')"

# Destroy (next gen will start at 2 if you reuse the vm_id)
kubectl -n vali exec deploy/vali -- python manage.py shell -c \
  "from apps.lifecycle.service import destroy; destroy('${VM}')"

# Revoke the staged secrets (KV-v2 metadata destroy — irreversible)
vault kv metadata delete secret/hippius-compute/kbs/tenants/${VM}/luks-kek
vault kv metadata delete secret/hippius-compute/kbs/tenants/${VM}/userdata
```

## Schema cross-references

| Concept | Source of truth |
|---|---|
| `OrderTicket` CBOR shape | `hippius-types/src/ticket.rs::OrderTicket` |
| `allowed_userdata_digest` preimage | `hippius-types/src/digest.rs::userdata_digest` |
| KBS release flow | `kbs-core/src/release.rs::run` |
| Vault read JSON schema | `binaries/kbs-server/src/vault_mvp.rs` (PR-V schema lock) |
| §22 allowlist artifact | `test_vectors/allowlist/dev.cose`, `binaries/kbs-allowlist-tool/` |
| Guest unwrap + binding gates | `hippius-guest/src/release.rs::verify_and_unwrap_release` |
| NoCloud seed write | `binaries/agent-initramfs/src/stages/seed.rs` |
| LUKS unlock | `binaries/agent-initramfs/src/stages/luks_cryptsetup.rs` |

