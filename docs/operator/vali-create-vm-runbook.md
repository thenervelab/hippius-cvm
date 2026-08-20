# `vali_create_vm` runbook (DEV ONLY)

Single-command end-to-end automation that folds every operator step
between "I have a baked image + a cloud-init YAML" and "the guest is
running, NetBird-joined, SSH-accessible" into one `manage.py`
invocation.

## What this command refuses to do

- Run when `VALI_ALLOW_PROD=true` — the §22 allowlist re-pin signs
  with the committed `packer/kbs-uki/keys/dev/provenance-root.dev.ed25519`
  seed. Running against a production KBS is a sign-anything backdoor.
- Auto-pin the allowlist when `VALI_KBS_ALLOWLIST_DEV_PIN` is unset —
  belt-and-suspenders for the previous point.
- Bake the image. Run `scripts/tenant-image-bake.sh` first (see
  `docs/operator/byo-base-os-bake-runbook.md`).
- Upload the baked `{qcow2, vmlinuz, initrd.img}` triple to S3 at
  `s3://<bucket>/<prefix>/tenant.{qcow2,vmlinuz,initrd.img}` —
  vali generates the presigned URLs for these exact object names.

The `--measurement-hex` flag is now OPTIONAL — when omitted, vali
dispatches a `tenant-preflight` order first, the miner fetches the
artifacts via the presigned URLs, sha-verifies them, computes the
SNP launch_digest, and returns it. Vali pins THAT digest into the
ticket + the allowlist (if `--auto-pin-allowlist` is set).

## What it does

```
┌── vali_create_vm internals ──────────────────────────────────────┐
│                                                                  │
│  1. Generate random 32-byte LUKS KEK (or read from --kek-file).  │
│  2. PUT KEK + user-data to Vault KV v2 at                        │
│       secret/<prefix>/<vm-id>/{luks-kek,userdata}.               │
│     Record the integer versions Vault assigns.                   │
│  3. Compute allowed_userdata_digest_hex                          │
│       = sha256( framed DOMAIN ‖ tenant_id ‖ vm_id ‖ ticket_id    │
│                ‖ "userdata" ‖ vault_path ‖ ud_ver_LE ‖ user-data )│
│  3b. Subprocess `aws s3 presign` for {qcow2, vmlinuz, initrd}    │
│      (short-TTL, single-object).                                 │
│  3c. Dispatch `tenant-preflight` order via the existing Edge     │
│      sign + miner-verify chain. The miner:                       │
│        - Downloads the 3 artifacts via the presigned URLs.       │
│        - sha256-verifies the bytes against the bake's pin.       │
│        - Stages under /var/lib/hippius-miner/staging/<vm-id>/.   │
│        - Computes the SNP launch_digest.                         │
│        - Returns JSON { classifier, launch_digest_hex,           │
│                         {luks_disk,kernel,initrd}_path }.        │
│      Vali parses the digest; pins it as `measurement_hex` for    │
│      both the allowlist (if --auto-pin-allowlist) and the ticket.│
│  4. (if --auto-pin-allowlist) Read the in-cluster manifest,      │
│     bump epoch, append [[entries]] with the preflight digest,    │
│     subprocess hippius-kbs-allowlist-tool → signed COSE,         │
│     subprocess aws s3 cp → S3 dev.cose (so init-container path   │
│       sees the same bytes on next pod restart),                  │
│     POST signed COSE → kbs-admin /v1/admin/allowlist/reload      │
│       (atomic in-memory swap; no pod restart).                   │
│  5. Subprocess hippius-order-ticket-mint with the L1 seed →      │
│     COSE_Sign1 OrderTicket bytes (tmpfs-buffered, never on disk).│
│  6. Call kbs-admin /v1/admin/vm/<vm-id>/register-vm via the      │
│     existing hippius-kbs-admin-client wrapper.                   │
│  7. Build the launch payload + dispatch via the existing         │
│     order_dispatch.dispatch_order (vali → Edge → miner).         │
│  8. Settle the durable ledger: `lifecycle.Vm` row (created in    │
│     step 0, before any Vault work) + `scheduler.Placement`       │
│     Pending → Bound on accept / Failed otherwise.                │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## The ledger (P9/#18) — why this is not optional

The ONLY thing this command does differently from `POST /v1/vm/launch`
is CHOOSE THE MINER. It used to differ in a second, invisible way: it
called `launch_on_miner` directly and wrote no `lifecycle.Vm` row and no
`scheduler.Placement`. The result was a real, attested, RUNNING CVM that
the control plane did not know about:

- **It could never be crypto-erased.** `DecommissionJob.vm` is a non-null
  FK and `POST /v1/vm/<id>/decommission` 404s without the row, so §24
  never ran: the VM's Vault-Transit KEK stayed live and its overlay was
  never unlinked. (Production still carries exactly this for `nbproof-3`.)
- **It did not count against capacity.** The #668 fit gate sums load and
  committed RAM/CPU over ACTIVE `Placement` rows only, so the miner was
  oversubscribed by exactly the forced VMs and nothing noticed. The
  miner's own heartbeat cannot compensate — `reported_free_mib` is a
  DOWN-ONLY throttle capped by vali's (understated) trusted math.
- **It was outside every sweep** — `sweep_guest_liveness`,
  `reboot_recovery_once`, `verify_netbird_enrolments` and
  `reclaim_migrated_sources` all iterate `Vm` — and §25 could not migrate
  it.

Both rows are now written. The `Vm` row is created inside
`launch_on_miner` itself, so no future caller can reintroduce the hole;
the `Placement` is written by `launch_on_named_miner`, which is what this
command calls.

`--decided-by <ServiceClient name>` attributes the placement (§15 audit).
It defaults to the well-known `operator-cli` principal, auto-created with
`is_active=False` so it can never authenticate — it exists only to own
the row. An unknown name is REFUSED, never created.

A vm_id that already holds a Pending/Bound placement is refused with
`{"outcome": "placement-conflict"}` (exit 8) instead of being launched a
second time — decommission it or fail its placement first.

Any VM left unbound from before this fix is surfaced every orchestration
tick by `sweep_unbound_launches` (`unbound_launches=N` on the tick log
line, plus a throttled WARNING naming each vm_id). That sweep DETECTS
ONLY. It never adopts: creating the `Vm` row is precisely what makes a VM
eligible for crypto-erase, so adoption is an operator decision, not a
heuristic's.

The output is one JSON object on stdout summarising the outcome:

```json
{
  "ok": true,
  "outcome": "miner-accepted",
  "status": 200,
  "classifier": "launched",
  "miner_id": "<MINER_ID>",
  "target_addr": "<MINER_NETBIRD_IP>:9700",
  "ticket_id": "tk-<vm>-<rand>",
  "order_id": "ord-<vm>-<rand>",
  "vault_luks_version": 7,
  "vault_userdata_version": 9,
  "allowed_userdata_digest_hex": "<64 hex>",
  "allowlist_epoch": 65,
  "allowlist_sha256": "<64 hex>"
}
```

## Required runtime context

The command relies on:

| What | Where | Why |
|---|---|---|
| `VAULT_TOKEN` env | process env at invocation time | The operator's KV v2 writer token. Vali holds NO long-lived Vault credential — the token must be supplied per invocation. |
| `VALI_VAULT_ADDR` + `VALI_VAULT_CACERT` | settings (env) | KV v2 endpoint + self-signed CA bundle path. The CA path is settings-pinned so a tampered token cannot disable cert verification. |
| `VALI_L1_SIGNING_KEY_PATH` | settings (env) | File path to the 32-byte Ed25519 seed. The Rust `hippius-order-ticket-mint` binary opens it; vali NEVER reads the bytes. |
| `VALI_KBS_ALLOWLIST_ROOT_SEED_PATH` | settings (env) | File path to the §22 root seed. Same byte-shape as L1 seed; same "binary opens it" rule. |
| `VALI_KBS_ALLOWLIST_S3_URL` | settings (env) | The S3 URL the KBS init container fetches. MUST equal `deploy/gitops/apps/kbs/values.yaml::allowlist.url`. |
| `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` env | process env at invocation | Operator-tier S3 writer creds (Vault path `secret/hippius-compute/s3/operator`). |
| `VALI_KBS_ADMIN_URL` + (optional) `VALI_KBS_ADMIN_CACERT` | settings (env) | The auto-pin POSTs the signed COSE bytes to `${VALI_KBS_ADMIN_URL}/v1/admin/allowlist/reload`. The handler runs the SAME `InstalledAllowlist::install` the file-fed startup path uses — signature verify + epoch HWM CAS + atomic in-memory swap. No kubectl, no pod restart, no concentrated RBAC in vali. |
| `hippius-order-ticket-mint`, `hippius-kbs-allowlist-tool`, `aws` binaries | image PATH | Subprocessed; absent ⇒ command fails with a static-classifier error. `kubectl` is NO LONGER required — the auto-pin swaps the allowlist via HTTP. |

## Example invocation

```bash
export VAULT_TOKEN=$(cat ~/.vault-token)
export AWS_ACCESS_KEY_ID=hip_xxx
export AWS_SECRET_ACCESS_KEY=xxx

# Pre-compute the launch digest ONCE on the miner with the cmdline
# you intend to dispatch.
ssh ubuntu@miner-1 "
  echo -n 'console=ttyS0,115200 console=tty0 earlyprintk=ttyS0 loglevel=7 \\
    ro root=/dev/mapper/cryptroot \\
    cryptopts=target=cryptroot,source=/dev/vda,luks,keyfile-size=32,keyscript=/sbin/hippius-luks-keyscript \\
    ds=nocloud;s=/run/cloud-init/seed/ \\
    hippius.kbs_url=https://kbs.hippius.network \\
    hippius.luks_device=/dev/vda' > /tmp/cmdline.txt
  sudo /usr/local/bin/hippius-miner-agent launch-test \\
    --ovmf /var/lib/hippius-miner/ovmf.fd \\
    --kernel /var/lib/hippius-miner/staging/myvm-1/tenant-53fdde898fee.vmlinuz \\
    --initrd /var/lib/hippius-miner/staging/myvm-1/tenant-53fdde898fee.initrd.img \\
    --cmdline /tmp/cmdline.txt --vm-id myvm-1 --cpus 1 --digest-only"
# → prints 96-hex MEASUREMENT

# Then:
kubectl exec -n vali deploy/vali -- python manage.py vali_create_vm \\
    --tenant-id t-smoke --vm-id myvm-1 \\
    --user-id u-smoke --lease-id lease-smoke \\
    --miner-id <MINER_ID> \\
    --platform-id <AMD_CHIP_ID_HEX> \\
    --userdata-file /tmp/my-cloud-init.yaml \\
    --measurement-hex 502ed26c662932f2cb2f2942cd684de47313b352443f66e1e49e193333f218627289f7d21047f0e98639e7c1e34c8635 \\
    --image-base-sha 53fdde898fee \\
    --cmdline 'console=ttyS0,115200 console=tty0 earlyprintk=ttyS0 loglevel=7 ro root=/dev/mapper/cryptroot cryptopts=target=cryptroot,source=/dev/vda,luks,keyfile-size=32,keyscript=/sbin/hippius-luks-keyscript ds=nocloud;s=/run/cloud-init/seed/ hippius.kbs_url=https://kbs.hippius.network hippius.luks_device=/dev/vda' \\
    --cpu-count 1 --memory-mb 2048 \\
    --auto-pin-allowlist
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Miner accepted, launch dispatched. |
| 2 | Miner rejected (4xx) — see `classifier` in the JSON output. |
| 3 | Edge transport / misconfig failure. |
| 4 | KBS admin (pre-registration) failure. |
| 5 | Vault stage failure. |
| 6 | §22 allowlist auto-pin failure. |
| 7 | Order-ticket mint subprocess failure. |
| 8 | Operator config / input-validation error (`CommandError`), incl. `placement-conflict` (this vm_id already holds an active placement). |
| 9 | `tenant-preflight` order failure (presign / fetch / sha / digest). |

## Follow-ups out of scope here

- Per-tenant cloud-init network config (`network: ... dhcp4: true`) —
  default cloud image already DHCPs; explicit config is documented
  defence-in-depth, not required.
