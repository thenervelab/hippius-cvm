# Launching a confidential VM

Two ways to launch a tenant confidential VM (CVM), sharing one
choreography (`apps.orchestration.services.launch`):

| Path | Who | Miner chosen by | Entry point |
|------|-----|-----------------|-------------|
| **API** (recommended) | admin / orchestrator | the §23 **scheduler** | `POST /v1/vm/launch` |
| **CLI** (dev) | operator on the box | `--miner-id` (forced) | `manage.py vali_create_vm` |

Both end the same way: a baked image boots under AMD SEV-SNP on a
miner, the guest attests, the KBS releases the LUKS KEK against the
attested measurement, and the rootfs unlocks. The **miner is
untrusted** — see *Security model* below.

---

## Security model (why a launch is safe on an untrusted miner)

The launch pipeline does **not** trust the miner and does not weaken the
attestation chain. The trust anchors live OUTSIDE the miner:

- **The KEK is released by the KBS, not vali, and only against an
  attested measurement that is in the §22 offline allowlist.** A miner
  that swaps the kernel/initrd/rootfs/cmdline produces a different
  SEV-SNP launch digest → not allowlisted → no KEK → the rootfs never
  unlocks. (`kbs-core/src/release.rs`.)
- **The data disk is `luksFormat`ed with a guest-held key generated
  INSIDE the SNP boundary** — the host only ever sees ciphertext, and
  any tampered byte makes the guest read-fault (`#365`).
- **The ticket binds the miner.** vali mints the L1 `OrderTicket` with
  `node_id = <human miner_id>` and the AMD `platform_id`; the order body
  binds `target_miner_id`. A ticket can't be replayed to a different
  miner, and the KBS checks the attested `chip_id == ticket.platform_id`.
- **The miner can only DoS, never extract.** It can reject or fail a
  launch (fail-closed, vali re-places — see limits below), but it cannot
  obtain a releasable KEK or read tenant data.

`POST /v1/vm/launch` is therefore an **operator-root** action (it mints
with the dev L1 key, stages Vault secrets, and dispatches): the endpoint
requires the orchestration-root principal, exactly like
`/v1/vm/<id>/migrate` and `/decommission`.

---

## Prerequisites (both paths)

1. **A baked image in S3.** Run `scripts/tenant-image-bake.sh` (see
   `byo-base-os-bake-runbook.md`) and upload the triple to
   `s3://<bucket>/<prefix>/tenant.{qcow2,vmlinuz,initrd.img}`. Keep the
   `measurement.json` — it carries the `{qcow2,kernel,initrd,luks_header}`
   SHAs you pass below.
2. **The LUKS KEK staged in Vault**, at a path under
   `${VALI_VAULT_KV_PREFIX}/<vm_id>/…` — the same KEK the bake's
   `luksFormat` used. (A mismatch = `cryptsetup` "Digest verify failed"
   loop at boot, `#304`.)
3. **A registered miner** (`POST /v1/admin/miner/register`) with a
   `netbird_ip`. For the **API path**, also set its **`chain_node_id`**
   (the 64-hex on-chain compute key) so the scheduler can bridge its
   placement decision back to the dispatchable identity (`#463`).
4. **`VAULT_TOKEN` + `AWS_*`** in the environment of whatever process
   does the launch (the CLI process, or the `vali_launch_tick` worker).
5. Dev only: `VALI_ALLOW_PROD=false` and (for `--auto-pin-allowlist`)
   `VALI_KBS_ALLOWLIST_DEV_PIN=true`.

---

## API path — `POST /v1/vm/launch`

Async: the POST enqueues a `LaunchJob`; the **`vali_launch_tick`** worker
drives the (up-to-30-min) preflight + dispatch; you poll for the result.

### 1. POST the launch intent

## Before you sell it: `GET /v1/scheduler/feasibility`

A launch that cannot place fails *after* the customer has paid. Ask
first:

```
GET /v1/scheduler/feasibility?flavor=2xlarge&tenant_id=t-acme
Authorization: Bearer <service-token>
```

Omit `flavor` for the whole catalogue — the "what can I sell right now"
board. In the SDK: `client.can_place("2xlarge", tenant_id=...)`, or
`client.feasibility()` for the board.

Branch on `verdict`, and treat the two negatives differently:

| verdict | meaning | what to do |
|---|---|---|
| `yes` | a miner would be chosen and the flavor fits it | sell it |
| `not-now` | the fleet CAN run this flavor but has no room / no eligible host right now | retry later — the hardware is fine |
| `never` | no reachable host is big enough | **do not take the money**; retrying cannot help |

`never` is the one that matters commercially, and it is not
hypothetical: on hardware of 125 GB / 24 cores, `4xlarge` asks 128 GiB
and 32 vCPU and can never place.

⚠️ **`never` is only returned when vali actually knows every reachable
host's size.** That size is the operator-registered anchor
(`MinerCapacity.total_memory_mb` / `total_cpus`). A miner without it
answers `not-now` with reason `host-size-unknown` for every flavor, and
its admission runs on the flat `capacity_slots` fallback rather than
dynamic capacity. The fleet operator seeds it from their own reading of the hardware (`nproc`, and
`MemTotal` kB / 1024 from `/proc/meminfo`):

```sh
python manage.py vali_set_miner_capacity --miner-id <MINER_ID> \
    --cpus <NPROC> --memory-mb <MEMTOTAL_MB> --dry-run          # check first
python manage.py vali_set_miner_capacity --miner-id <MINER_ID> \
    --cpus <NPROC> --memory-mb <MEMTOTAL_MB> --by <you>
```

`--node-id <64-hex>` works in place of `--miner-id`, and `--clear` removes
the anchor. The command refuses an anchor smaller than the VMs vali has
already placed on the miner. It warns when a fresh heartbeat's free-memory
report looks inconsistent with the anchor. It prints an audit record
(who, node, before, after) as its last line of output. Keep that line: with
`kubectl exec` it does not reach the pod log. The numbers must be your own
reading of the hardware, never the miner operator's claim. See
[onboarding a miner §6b](onboarding-a-miner.md#6b-register-the-hosts-size-fleet-operator).

Two limits worth knowing, both reported rather than hidden:

- **`headroom` is advisory, not a reservation.** It is a snapshot; a
  concurrent launch consumes it. The authoritative admission is still
  the launch itself.
- **`disk_checked` is always `false`.** Miner heartbeats report memory
  and CPU but never disk, so vali cannot evaluate the DATA-disk
  dimension — it stays gated by the miner at dispatch (503
  `insufficient-resources`, and vali re-places).

This is distinct from `GET /v1/scheduler/capacity`, which answers in
admission *slots*. A slot is sized by the reference flavor and one
placement costs one slot whatever its size, so `capacity` cannot tell
you whether a *particular* flavor fits.

```
POST /v1/vm/launch          Authorization: Bearer <root-service-token>
Content-Type: application/json
{
  "tenant_id": "t-acme", "user_id": "u-1",
  "vm_id": "acme-web-1",            // [a-z0-9-]{1,64} — interpolated into Vault paths
  "lease_id": "lease-42",
  "flavor": "xlarge",              // small|medium|large|xlarge|2xlarge|4xlarge, or unlisted runner-small|runner-medium|runner-large
  "cmdline": "console=ttyS0,115200 ... ds=nocloud;s=/run/cloud-init/seed/",
  "s3_bucket": "hippius-compute-images",
  "s3_key_prefix": "tenant/acme-web-1/",
  "luks_disk_sha256_hex":   "<64-hex from measurement.json>",
  "kernel_sha256_hex":      "<64-hex>",
  "initrd_sha256_hex":      "<64-hex>",
  "luks_header_sha256_hex": "<64-hex>",
  "kek_vault_path": "hippius-compute/kbs/tenants/acme-web-1/luks-kek",  // MUST be under {prefix}/{vm_id}/
  "userdata": "#cloud-config\n...{{NETBIRD_SETUP_KEY}}...",  // cloud-init plaintext in the REQUEST only — vali Transit-wraps it before staging; never in the DB, never plaintext at rest
  "auto_pin_allowlist": true,   // see note below — NOT optional in practice
  // optional: platform_id, measurement_hex,
  //           netbird_group, ovmf_path, ... (see launch_jobs._OPTIONAL)
}
→ 202 { "job_id": "...", "vm_id": "...", "state": "queued", ... }
```

The `runner-*` flavors (1/4 GB/20 GB, 2/8 GB/20 GB, 4/16 GB/30 GB) are for
single-use CI VMs: the compute of `small`/`medium`/`large` with a small data
disk, so the first-boot integrity wipe is short. They are not in the
feasibility board, fleet views or resize targets, and the OrderTicket carries
their compute class (`small`/`medium`/`large`), so they need no KBS, guest or
miner-agent change (`apps/orchestration/services/flavors.py`).

`auto_pin_allowlist` is listed as optional in `launch_jobs._OPTIONAL` and
defaults to `false`, but in practice every launch needs it: each one bakes
per-launch nonces into the MEASURED cmdline, so every VM has its own launch
measurement and the KBS refuses (`403`) an unpinned one. Omitting it yields a
`succeeded` job and a guest that never unlocks. (It was labelled "(dev)" here
until 2026-07-28 — stale since #587 Phase 1A made pinning a normal
authenticated production operation.)

> **NetBird is ON by default** for every VM (overlay reachability). The
> `userdata` therefore MUST carry the literal `{{NETBIRD_SETUP_KEY}}`
> placeholder (vali mints a one-off setup-key and substitutes it in
> memory) — shipped template:
> `docs/operator/userdata-templates/netbird-enabled.yaml.example`. To
> launch a VM WITHOUT NetBird, POST `"enable_netbird": false` (API) or
> pass `--no-enable-netbird` (CLI); then a plain userdata is accepted.

Validation refuses, with 400, a missing field, a `vm_id` with path
separators, a `kek_vault_path` outside `{prefix}/{vm_id}/` (cross-tenant
KEK guard), an empty/large userdata, or — with NetBird enabled (the
default) — a userdata missing `{{NETBIRD_SETUP_KEY}}`. 401 unauth,
**403 non-root**, 409 if the VM already has an in-flight launch.

**§20:** `userdata` is staged to Vault immediately; the KEK is referenced
by `kek_vault_path` (read by the worker). Neither plaintext ever lands in
the `LaunchJob` row.

### 2. The worker runs

Deploy `vali_launch_tick` as a single daemon (or run `--once` for a
batch). It CAS-claims the queued job, reads the secrets back from Vault,
and drives `launch_vm`: the §23 scheduler picks an eligible miner
(admission slots, anti-affinity, epoch-freshness), bridges its chain
`node_id` → `MinerIdentity`, runs the choreography (stage → preflight →
allowlist-pin → mint → KBS register → dispatch), and **re-places onto
another miner** if one rejects.

```
python manage.py vali_launch_tick           # daemon
python manage.py vali_launch_tick --once     # one cycle (cron / batch)
```

### 3. Poll

```
GET /v1/vm/launch/<job_id>     Authorization: Bearer <any-service-token>
→ 200 { "state": "succeeded", "miner_id": "...", "result": { "ticket_id": ..., "attempts": [...] } }
     | { "state": "failed", "reason": "no-eligible-miner" | ... }
```

---

## CLI path — `vali_create_vm` (dev, forced miner)

When you want to pin the miner yourself and watch a single launch
synchronously. **The miner choice is the ONLY difference from the API
path**: it calls `launch_on_named_miner`, which runs the same
choreography and writes the same durable ledger (`lifecycle.Vm` row +
an active `scheduler.Placement`) — it just skips the scheduler's
*decision*. Full reference: **`vali-create-vm-runbook.md`**.

> **P9/#18.** Until this was fixed the CLI called `launch_on_miner`
> directly and wrote NEITHER row, so it produced a real, attested,
> RUNNING CVM the control plane knew nothing about: §24 decommission
> could never crypto-erase it (`DecommissionJob.vm` is a non-null FK, and
> `POST /v1/vm/<id>/decommission` 404s), so its Vault-Transit KEK stayed
> live forever; and the #668 fit gate — which counts ACTIVE `Placement`
> rows — never counted the RAM/CPU it consumed, so the miner was
> silently oversubscribed. Any such VM left over from before the fix is
> now surfaced every orchestration tick by `sweep_unbound_launches`
> (`unbound_launches=N` in the tick log). That sweep DETECTS ONLY — it
> never adopts, because creating the `Vm` row is exactly what makes a VM
> eligible for crypto-erase, and that is not a heuristic's call.

The `Placement` is attributed to `--decided-by <ServiceClient name>`,
defaulting to the well-known `operator-cli` principal (auto-created with
`is_active=False`, so it can never authenticate — it exists only to own
the audit row). An unknown name is refused, never created.

A vm_id that already holds a Pending/Bound placement is REFUSED
(`outcome: placement-conflict`, exit 8) rather than force-launched a
second time.

```
python manage.py vali_create_vm \
  --tenant-id t-acme --user-id u-1 --vm-id acme-web-1 --lease-id lease-42 \
  --miner-id <MINER_ID> --platform-id <amd-chip-id-hex> \
  --userdata-file ./cloud-init.yaml --kek-file ./luks.kek \
  --s3-bucket hippius-compute-images --s3-key-prefix tenant/acme-web-1/ \
  --luks-disk-sha256-hex <…> --kernel-sha256-hex <…> \
  --initrd-sha256-hex <…> --luks-header-sha256-hex <…> \
  --cmdline 'console=ttyS0,115200 … ds=nocloud;s=/run/cloud-init/seed/' \
  --flavor xlarge --enable-netbird --auto-pin-allowlist
```

---

## Customer-held keys (M1 `split` / M2 `customer`) — operator notes

- **Guardian on NetBird.** `PUT /v1/guardian/<tenant>/netbird/policy` and
  `POST …/setup-key` (root principal) create a policy that lets the miners
  reach the tenant's guardian on its TCP port, and nothing else. That only
  holds if (1) NetBird's `Default` All↔All policy is **disabled** (vali
  refuses `409 guardian-netbird-open-policy` while any enabled policy reaches
  `All` or the guardian group), and (2) `VALI_NETBIRD_MINERS_GROUP` names a
  group holding **only miner peers** (vali cannot check this; audit it before
  enabling). `DELETE /v1/guardian/<tenant>/netbird` revokes everything.
- **Userdata `netbird up` shapes.** For an M1/M2 VM with NetBird, vali inserts
  `--disable-dns --disable-client-routes --disable-server-routes` after
  `up`. Supported: an unquoted flow list (`[ netbird, up, … ]`), a block list
  (`- netbird` / `- up`), or a shell string containing `netbird up` (also
  `/usr/bin/netbird up`). NOT supported — refused
  `customer-keys-netbird-up-not-found`: a quoted flow list
  (`[ "netbird", "up" ]`), a `netbird up` only in a comment, or none at all.
- **Restore.** An M2 restore to an earlier boot is the customer's
  (`guardian authorize-rollback`) and is refused today (the KBS boot counter
  has no M2 rollback). An M2 current-boot (A1) restore works, but once it has
  committed it **cannot be undone** (`…/revert` is a KBS rollback, which M2
  never gets).
- **§24.** An M2 decommission reports `data_death: customer-erase-required`:
  tell the customer to run `guardian erase <vm>` for a cryptographic erase.

---

## Capacity & re-placement

- The miner declares its disk capacity via `[host].cvm_disk_gb_budget`
  and **reserves** it per launch (`check_capacity`), so concurrent
  launches can't over-commit; a per-create `statvfs` backstop rejects a
  genuinely full mount (physical free space can't be faked) — `#461`/`#464`.
- On a rejection, `launch_vm` **re-places** onto the next-ranked miner
  (`excluded += miner`), bounded by `VALI_LAUNCH_MAX_REPLACE`.

> **Known limitation (tracked).** Re-place currently works for
> **preflight-level** rejections (the miner can't fetch/verify the
> artefacts). A **dispatch-level** rejection (e.g. the disk-budget check
> at launch) lands *after* the KBS `register` step, whose host-bound
> `Active` state makes the next miner's register conflict — so that
> attempt dead-ends instead of re-placing. Fix in progress: move the
> miner's capacity check to preflight (pre-register), or add a KBS-clear
> fence on retriable.

---

## Deployment prerequisites for the in-cluster API

The HTTP surface (auth, validation, routing, job intake) is live as soon
as the vali image ships. For the **worker** to complete a launch the
deployment must additionally provide:

- **`VAULT_TOKEN`** in the `vali_launch_tick` process env — vali talks to
  Vault via a static token (`vault_kv`); the default in-cluster pod runs
  SNP-auth with no static token, so the worker needs one wired in.
- **`VALI_THEBRAIN_RPC_URL`** — the scheduler reads on-chain miner status
  (`pallet-compute-scoring`) to place; without it `launch_vm` fails
  closed with `chain-unavailable`.

Until both are configured, `POST /v1/vm/launch` returns **503
`vault stage failed`** at the staging step (verified live, 2026-06-15) —
a clean fail, not a code bug. The forced-miner CLI path works wherever
`VAULT_TOKEN` + `AWS_*` are exported (it doesn't touch the chain).
