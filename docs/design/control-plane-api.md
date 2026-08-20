# Design: Unified vali control-plane API ("everything through the API")

**Status:** ✅ Implemented + deployed + live-verified (2026-06-30) — see §12 · **Author:** Codex · **Date:** 2026-06-30

## 1. Goal & principles

Today a VM launch is a patchwork of SSH + dev CLI (`vali_create_vm`), hand-run
Vault writes, manual `gitops allowlist.sha256` bumps, and SSH miner-agent
restarts. A single launch took ~22 min of operator wrangling in the 2026-06-30
session — **none of it actual VM boot** (real boot is ~1–2 min); all of it
orchestration friction.

**Target:** every lifecycle action — launch, status, migrate, decommission,
attestation, fleet/miner control, bake — is a **vali (Django/DRF) API call**.
No SSH, no manual Vault writes, no manual gitops lockstep. One control plane.

**Principles**

1. **API-first, CLI-thin.** `vali_create_vm` stays only as a thin dev wrapper
   that POSTs the same API. No orchestration logic lives in CLI commands.
2. **Idempotent + async.** Every mutating action enqueues a CAS-guarded job
   (the existing `LaunchJob`/`MigrationJob`/`DecommissionJob` substrate) and is
   safe to retry. Callers poll a job, or (Phase 3) receive a webhook.
3. **Self-healing, no manual lockstep.** The recurring `allowlist.sha256`
   crashloop dance (≈10 manual bumps this session, incl. #530/#543/#544/#554/
   #562/#568/#584/#586) must be **designed out**, not papered over.
4. **Trust boundary unchanged.** The miner stays 100% untrusted. No API may
   weaken the §7/§8/§20/§22 release gates (HPKE-to-attested-guest, measurement
   double-gate, chip_id binding, anti-rollback, launch-policy allowlist).

**Who calls this API (important scoping).** vali's control-plane API is
**NOT** the end-user-facing API. End users go through a separate **upstream
product API that already owns authentication, tenant ACLs, quotas, and
billing**. vali is consumed by exactly two kinds of caller:

- **the upstream product API** — a trusted backend service that has *already*
  authorized the end user and resolved their `tenant_id`/`user_id`/`lease_id`;
  it calls vali service-to-service to actually launch/migrate/inspect VMs;
- **operators / vali's own daemons** — root-scoped fleet + lifecycle control.

So vali authenticates **service principals** (`ServiceClient` via mTLS or
bearer `ServiceToken`), **not end users**. It does **not** re-implement
per-end-user access control — that lives upstream. vali's job is to (a) treat
the upstream-supplied `tenant_id`/`user_id`/`lease_id` as authoritative *input*
(the caller already vouched for it), (b) **cryptographically bind** it into the
artifacts that matter (the L1 OrderTicket's `tenant_id`, the per-VM KEK, the
`lease_id` on `Vm`), and (c) record it for audit. This removes a whole layer of
work (no tenant-token/JWT system inside vali) and keeps one clear boundary.

## 2. Current state (what already exists)

The control plane is **~70% built** — see the full inventory in the 2026-06-30
codebase mapping. Highlights:

- **Launch IS already an API:** `POST /v1/vm/launch` enqueues a `LaunchJob`;
  the `vali_launch_tick` worker runs `launch.launch_vm` (scheduler place →
  preflight → mint ticket → KBS pre-register → dispatch → create `Vm` row).
  `vali_create_vm` is just the **dev CLI shortcut** we were using instead.
- **Lifecycle/migrate/decommission/fleet/bake** all have endpoints
  (`/v1/vm/<id>/{state,transition,attestation,migrate,decommission}`,
  `/v1/admin/miner/{register,list,quarantine}`, `/v1/tenant-bakes`,
  `/v1/packer/build`).
- **Solid async substrate:** `LaunchJob`/`MigrationJob`/`DecommissionJob` with
  `(id, version, state)` CAS + §14 idempotency store + tick workers.
- **Auth:** `ServiceClient` principals via mTLS CN or bearer `ServiceToken`;
  `IsOrchestrationRoot` / `IsMinerAdmin` permission classes. **No per-tenant
  scope yet** (`lifecycle/views.py:88`).

So this is a **gap-closing** effort, not a greenfield build.

## 3. The gaps that force manual scripting

| # | Gap | Today | Bit us this session |
|---|-----|-------|---------------------|
| G1 | **Allowlist sha lockstep** | every auto-pin overwrites S3 `dev.cose`; gitops `allowlist.sha256` must be hand-bumped or KBS crashloops on restart | ≈10 manual bumps + a near-crashloop |
| G2 | **Miner-agent stale "already-launched"** | no miner-control API → SSH + agent restart | the 22-min relaunch |
| G3 | **LUKS KEK staging** | `vault kv put` by hand / `--kek-file` | every launch |
| G4 | **Bake→launch not chained** | launch assumes artifacts present; no wait | manual sequencing |
| G5 | **Upstream-API integration is incomplete** | the upstream product API can't drive a full launch in one call (KEK/bake/pin still manual) | forces operators to fill the gaps by hand |
| G6 | **Poll-only** | no webhooks/events | operator + upstream polling loops |

> Note: an earlier draft listed "no per-tenant auth" as a gap. That is **not**
> vali's concern — end-user ACLs/quotas live in the upstream product API.
> vali only needs clean **service-to-service** auth (it has it: `ServiceClient`
> + `ServiceToken` + `IsOrchestrationRoot`). G5 is therefore about the
> *integration contract*, not an auth system.

## 4. Phase 1 — kill the manual scripting

### Phase 1A — decouple the KBS allowlist gate from the auto-pin (the big one)

**Root cause of G1.** Two mechanisms are in direct tension:

- the KBS init-container pins **one frozen `sha256`** (gitops) and refuses to
  boot unless the S3 `dev.cose` byte-matches it — a static supply-chain pin;
- the vali §22 auto-pin **rewrites** `dev.cose` on *every* launch (new
  measurement → new signed allowlist → S3 overwrite + in-memory KBS reload).

So every launch invalidates the frozen sha; the running pod survives (in-memory
reload) but any restart/resync crashloops until an operator hand-bumps the
gitops sha. This is unfixable as long as the gate is "byte-equals a frozen
artifact" while the artifact is dynamic.

**Fix — verify by signature + monotonic epoch, not by frozen sha.** The
allowlist `dev.cose` is *already* a COSE_Sign1 signed by the §22 allowlist root
seed. Replace the sha gate with:

1. **Signature gate:** the KBS verifies `dev.cose`'s COSE_Sign1 against a
   **pinned allowlist-root public key** (gitops pins the *pubkey*, which is
   static, instead of the *artifact sha*, which is dynamic). Integrity comes
   from "only the root key can sign an allowlist", exactly like the L1 ticket
   and KBS-L0 keys.
2. **Monotonic-epoch anti-rollback:** the KBS durably stores the last-accepted
   allowlist `epoch` and **rejects any artifact with `epoch <= last_accepted`**.
   This is what stops a malicious S3 write from rolling the allowlist *back* to
   one that still admits a since-revoked measurement. (Forward pins — adding a
   new measurement — are always allowed; that's the whole point of auto-pin.)
3. **Optional operator sha pin (advisory, non-fatal):** keep an *optional*
   `allowlist.sha256` for operators who want to freeze a specific artifact in a
   locked-down environment, but it is **off by default** and never the cause of
   a crashloop.

**Effect:** launches auto-pin freely; every KBS restart fetches the latest
*signed, epoch-monotonic* allowlist and boots; **the manual gitops lockstep and
the entire crashloop class disappear.** This is the production trust model
(root key vouches for the allowlist) replacing the dev supply-chain crutch.

**Code touch points**
- `kbs-server` init/startup allowlist load (`binaries/kbs-server` + the
  init-container that fetches `dev.cose`): add COSE-sig verify against
  `allowlist.root_pubkey`; add durable `last_accepted_epoch` (a small
  persisted value next to the boot-counter store) + the monotonicity check;
  demote the sha check to optional.
- `kbs-core` allowlist replay/verify path (`allowlist.rs` / the §22 verifier):
  the epoch-monotonicity rule lives here so the in-memory `reload` admin path
  enforces the *same* rule as startup (no drift between the two).
- gitops `deploy/gitops/apps/kbs/values.yaml`: replace `allowlist.sha256` with
  `allowlist.rootPubkeyHex` (static, set once at the §22 ceremony); drop the
  per-launch bump.
- `vali` auto-pin (`apps/orchestration/services/allowlist_pin.py`): unchanged
  except it no longer needs an operator to follow up — it already signs +
  bumps the epoch + uploads + reloads.

**Security review required** (touches §22 trust boundary): the signature gate
must pin the *root* key (not accept any key), the epoch store must be durable +
fail-closed (a missing/lower epoch denies), and the in-memory reload + startup
paths must share one verifier so they cannot diverge.

### Phase 1B — miner-control API (kills G2, the SSH restart)

The miner-agent keeps an in-memory VM table; a failed/partial dispatch leaves a
stale "already-launched" record that blocks relaunch until an SSH agent restart.

**Fix (two parts):**
1. **Make miner-side launch idempotent** (preferred): the agent's launch
   handler treats "VM with this `vm_id` + measurement already present" as a
   success/no-op replay, and a launch with a *new* generation/measurement
   supersedes the stale record. This removes the need to clear state at all.
2. **Add an operator escape hatch** — `POST /v1/admin/miner/<miner_id>/control`
   `{action: "clear-vm-state"|"status"|"restart-agent", vm_id?}`. vali dispatches
   it to the miner over the existing Edge → miner-agent `:9700` signed-order
   channel (a new `OrderKind::AgentControl`), so operators never SSH. Root-only.

This also gives a `status` probe (what does the agent think is running?) which
the launch tick can use to self-diagnose instead of timing out.

### Phase 1C — KEK staging API + bake→launch chaining (kills G3, G4)

- **KEK staging:** `POST /v1/admin/kek` `{vm_id|tenant scope}` → vali generates
  a 32-byte KEK, writes it to the §20 Vault path the launch path already reads
  (`secret/data/.../tenants/<vm>/luks-kek`), returns only a handle (never the
  bytes). For BYO-KEK, accept an encrypted-to-vali envelope, never plaintext
  over the wire. The launch intent then just references the staged handle.
- **Bake→launch chaining:** the `LaunchJob` intent gains an optional
  `bake_id`; the launch tick, before dispatch, polls the `TenantBake` job to
  `succeeded` and resolves its S3 artifact location + measurement SHAs
  automatically (today the operator copies them by hand from `measurement.json`).
  One `POST /v1/vm/launch {bake_id, tenant, flavor, userdata}` then does
  bake-wait → KEK → pin → mint → dispatch → boot with zero manual steps.

**End of Phase 1:** a single `POST /v1/vm/launch` launches a VM end-to-end with
no SSH, no Vault CLI, no gitops bump.

## 5. Phase 2 — the upstream-API integration contract

End-user auth/ACLs/quotas live in the **upstream product API**, not vali (see
§1). So Phase 2 is **not** a per-tenant auth system inside vali — it is making
vali a clean, complete *service API* the upstream product can drive in one call,
with the tenant context flowing through as authoritative data.

- **Service auth (already have it):** the upstream API authenticates to vali as
  a dedicated `ServiceClient` (mTLS CN or scoped `ServiceToken`). A new
  `IsUpstreamProduct` principal (or reuse `IsOrchestrationRoot` if the upstream
  *is* the orchestration root) gates the launch/lifecycle endpoints. No JWT /
  per-end-user token machinery in vali.
- **Tenant context as data, cryptographically bound:** the upstream call passes
  `{tenant_id, user_id, lease_id, ...}` (it already authorized the user). vali
  treats it as authoritative, binds it into the L1 OrderTicket (`tenant_id`),
  the per-VM KEK path, and `Vm.lease_id`, and records it for audit — but does
  **not** re-check "may this user touch this VM" (the upstream already did).
- **Complete, idempotent verbs:** the upstream needs the full set returning
  clean job handles + terminal states: `launch` (Phase 1C one-shot),
  `status`/`list` (filter by the upstream-supplied `tenant_id`/`lease_id` for
  *display*, not authz), `migrate`, `decommission`, `attestation` (so the
  upstream can surface "your VM is genuinely SNP-attested" to its users). These
  mostly exist; Phase 2 hardens the contract: consistent error envelopes,
  idempotency keys on every POST, and a stable `tenant_id`/`lease_id` filter on
  the list/read endpoints.

> If the product later wants a thin end-user-direct path, the access control
> still belongs upstream (or an API-gateway in front of vali) — vali stays the
> service layer. This keeps the trust boundary single and auditable.

## 6. Phase 3 — operator ergonomics

- **Webhooks/events:** per-job state-transition callbacks (`succeeded`,
  `failed`, `timeout`) so automation is event-driven, not poll-driven.
- **Migration cancel:** `POST /v1/vm/<id>/migrate/<job_id>/cancel` (root) →
  graceful `Failed` with reason, where the state machine allows it.
- **Measurement / attestation audit ledger:** `GET /v1/admin/audit/measurements`
  — every pinned `launch_digest` + `platform_id` + epoch + timestamp, for fleet
  audit and the "which firmware emits what" diagnostics (cf. the Turin v4 /
  reported-tcb investigation).
- **Capacity query:** `GET /v1/scheduler/capacity` — candidate miners + price
  for a flavor, so placement can be inspected/overridden via API.

## 7. New API surface (summary)

| Phase | Method + path | Auth | Purpose |
|-------|---------------|------|---------|
| 1B | `POST /v1/admin/miner/<id>/control` | root | clear-vm-state / status / restart-agent |
| 1C | `POST /v1/admin/kek` | root | stage a LUKS KEK to Vault, return handle |
| 1C | (extend) `POST /v1/vm/launch` `{bake_id}` | service/root | bake-wait + auto-resolve artifacts |
| 2 | `GET /v1/vm?tenant_id=&lease_id=` | service/root | list VMs (filter for display) |
| 3 | `POST /v1/vm/<id>/migrate/<job_id>/cancel` | root | abort migration |
| 3 | `GET /v1/admin/audit/measurements` | root | measurement ledger |
| 3 | `GET /v1/scheduler/capacity` | root | placement candidates |

No public/guest/end-user endpoints — every caller is a service principal
(upstream product API or operator). The end-user-facing surface + ACLs live in
the upstream product API.

## 8. New / changed models

- `ServiceClient`/`ServiceToken`: `+ role` for the upstream-product principal
  (or reuse the orchestration-root principal) — service-to-service only, **no**
  per-end-user fields (Phase 2).
- `LaunchJob`: `+ bake_id (nullable FK)`, `+ kek_handle`, `+ idempotency_key`
  (Phase 1C/2).
- KBS side (not Django): a durable `last_accepted_allowlist_epoch` store
  (Phase 1A) co-located with the boot-counter persistence.
- Optional `MeasurementLedger` append-only table (Phase 3).

All migrations are additive/nullable → no backfill, no downtime.

## 9. Security considerations

- **Phase 1A is a §22 trust-boundary change** — root-pubkey-pinned signature +
  monotonic epoch *replaces* a frozen sha. Must be security-reviewed: pin the
  exact root key, fail-closed on a missing/older epoch, single shared verifier
  for startup + reload. Net effect is *stronger* (anti-rollback on the
  allowlist itself, which the sha pin never provided) and removes operator
  toil. Pairs with the existing untrusted-miner review
  (`docs/...` / memory `kbs-untrusted-miner-security-review`).
- **Phase 1B** miner-control orders ride the existing signed Edge→miner channel
  — no new trust surface; `clear-vm-state` cannot release secrets, only reset
  agent bookkeeping.
- **Phase 1C** KEK staging never returns key bytes; BYO-KEK only via an
  encrypted envelope. §20 zeroize discipline applies.
- **Phase 2** adds **no** end-user authz to vali (that stays upstream) — it
  only adds a service principal for the upstream API. The security property to
  preserve: the upstream-supplied `tenant_id` is *bound* (into the OrderTicket +
  KEK path) but never used as an *authz* decision inside vali; vali trusts the
  caller is the (mutually-authenticated) upstream service. The list/read filters
  are for display, not access control, and must be documented as such so nobody
  later mistakes them for a tenant gate.

## 10. Phasing & sequencing

1. **Phase 1A** (allowlist decouple) — highest leverage; removes the #1
   recurring failure + unblocks unattended launches. *Ship first.*
2. **Phase 1B** (miner-control / idempotent launch) — removes the SSH restart.
3. **Phase 1C** (KEK staging + bake chaining) — closes the last manual inputs.
4. **Phase 2** (tenant auth) — opens self-service.
5. **Phase 3** (webhooks, cancel, ledger, capacity) — ergonomics.

Each phase is independently shippable and leaves the system in a working state.
Phase 1 alone delivers the headline outcome: **one `POST /v1/vm/launch` does
everything, no manual scripting.**

## 11. Open questions for review

1. **Phase 1A epoch store:** co-locate with the boot-counter `FileBootCounter`
   persistence, or a dedicated small KV? (Leaning: same volume, new key.)
2. **Dev allowlist root key:** dev currently uses a committed seed. Keep the
   signature gate meaningful in dev (the epoch-monotonicity already helps), or
   accept that dev integrity rests on the epoch rule alone?
3. **Upstream-product principal (Phase 2):** is the upstream product API the
   existing `orchestration-root` principal, or does it get its own dedicated
   `ServiceClient` + permission class (cleaner separation, recommended)? And:
   does the upstream call vali directly, or through an API-gateway?
4. **BYO-KEK envelope format (Phase 1C):** reuse the HPKE-to-vali primitive, or
   a simpler sealed-box?

## 12. Implementation status (as-built, 2026-06-30)

Fully implemented, deployed to prod, and live-verified — **production-direct
(no dev bypass: prod §22/L1 signing keys from Vault, no committed dev seeds,
no dev gates)**. 20 PRs (#604–#618). The vali control plane is now CI
test+lint gated (`vali` job in ci.yml; ~835 tests).

| Phase | Item | PR(s) | State |
|-------|------|-------|-------|
| 1A | Allowlist gate decoupled from auto-pin (signature + monotonic-epoch; prod root key from Vault; multi-root rotation) | #588–#600 (prior) | ✅ deployed |
| 1B | Idempotent miner-side launch (stale-handle reclaim) | #599 | ✅ deployed |
| 1C | Bake→launch chaining (`LaunchJob.bake_id` → spec) + `luks_header_sha256` | #601 | ✅ deployed |
| — | `vali_launch_tick` worker — makes `POST /v1/vm/launch` async path live | #602 | ✅ deployed |
| — | `VALI_ORCHESTRATION_ROOT_PRINCIPAL` wiring; edge CNP allows the launch worker | #604, #606 | ✅ deployed |
| 2 | `GET /v1/vm` list + `Vm.tenant_id` (display filter, not authz); launch-worker hardening | #605, #607 | ✅ deployed + verified |
| 3 | Capacity query `GET /v1/scheduler/capacity` | #609 | ✅ deployed + live-verified |
| 3 | Migrate-cancel `POST /v1/vm/<id>/migrate/<job_id>/cancel` (pre-Fencing → Failed; past-fence 409) | #615 | ✅ deployed (404-wiring verified) |
| 3 | Measurement audit ledger `GET /v1/admin/audit/measurements` + `MeasurementLedger` | #616 | ✅ deployed + live-verified (write+read+filter) |
| 3 | Outbound job-event webhooks (HMAC-signed, retry/backoff) + `vali_webhook_tick` | #617 | ✅ code deployed; worker gated until an upstream URL/secret exists |

**End-to-end proof (no CLI):** `POST /v1/vm/launch` (202) → `vali_launch_tick`
worker → §23 placement → preflight → §22 auto-pin (writes the audit ledger:
real measurement + CHIP_ID + epoch) → L1 mint → KBS admin register → dispatch
→ guest boots → `POST /v1/kbs/release → 200` → **`granted=true`** (running,
pingable SEV-SNP CVM with a DHCP lease). Verified on three launches across two
prod images.

### Resolved open questions (§11)
1. **Epoch store:** durable monotonic-epoch HWM (`FileHighWaterStore`), KBS-side.
2. **Dev allowlist root:** removed — the prod root key lives in Vault; dev seeds
   are gone from the prod signing path entirely.
3. **Upstream principal:** the upstream is authenticated as a `ServiceClient`;
   vali authenticates the service principal only and never re-implements
   end-user authz (the upstream owns ACLs). `tenant_id`/`lease_id` are display
   filters, not authz boundaries.
4. **BYO-KEK envelope:** KEK staged in Vault under `{prefix}/{vm_id}/` and read
   back by the worker; the launch ticket binds it (no new envelope needed).

### To activate webhooks later
Set `webhookTick.enabled=true` + `webhookTick.url=<callback>` and provision the
`vali-webhook` Secret (ExternalSecret from Vault, key `secret`). The code +
worker template already ship; this only turns on the delivery loop.

## 13. Current API reference (as-built)

Grounded in the DRF serializers/views/urls (`vali/apps/{tenant_bake,orchestration,lifecycle}/`).
Every caller is a service principal — `Authorization: Bearer <ServiceToken>`.
`launch` / `migrate` / `decommission` / `transition` are `IsOrchestrationRoot`;
bake create/get + VM state/list accept any authenticated `ServiceClient`. The
Python SDK (`clients/python/`) wraps all of these.

### 13.1 Tenant bake — `POST /v1/tenant-bakes` (→ 202)

Request (`TenantBakeCreateSerializer`). All required except `disk_mode`:

| field | type | notes |
|---|---|---|
| `vm_id` | str `[a-z0-9-]{1,64}` | target VM (KEK is scoped to it) |
| `base_image_url` | url | vanilla cloud image, SSRF-guarded, fetched + sha-verified server-side |
| `base_image_sha256` | 64 hex | expected digest of `base_image_url` |
| `size_gb` | int > 0 | target raw image size |
| `kek_vault_path` | str | KV-v2 path the baker reads the disk KEK from |
| `s3_output_bucket` | str | artefact output bucket |
| `s3_output_prefix` | str | artefact key prefix |
| `disk_mode` | `legacy_luks` \| `golden_verity_overlay` | **optional; absent ⇒ `legacy_luks`** (golden-bake PR6) |

`GET /v1/tenant-bakes/<bake_id>` → the bake row (`TenantBakeSerializer`, 200):
`bake_id, vm_id, base_image_url, base_image_sha256, size_gb, kek_vault_path,
s3_output_bucket, s3_output_prefix, disk_mode, state` (`queued|running|
succeeded|failed`), `requested_by, requested_at, started_at, finished_at,
version`, plus the artefact digests (null until succeeded):

- **legacy** (`disk_mode == legacy_luks`): `qcow2_sha256` set; the golden trio
  null.
- **golden** (`disk_mode == golden_verity_overlay`): `rootfs_img_sha256`,
  `rootfs_verity_sha256`, `verity_root_hash` set; **`qcow2_sha256` null.**
- both: `kernel_sha256`, `initrd_sha256`, `measurement_hex`, `failure_reason`.

(`POST /v1/tenant-bakes/<bake_id>/finalize` is worker-only CAS ingress, not a
tenant path.)

### 13.2 Launch — `POST /v1/vm/launch` (→ 202)

Request (`LaunchIntentSerializer`). `userdata` + the intent fields are required
*unless resolved from an `image` or a `bake_id`*. There are three ways to name
the disk artefacts, in order of convenience:

1. **`image`** (launch-by-image, the **fast default path**) — an
   operator-blessed golden image NAME (e.g. `ubuntu`; discover via
   `GET /v1/images`). vali resolves it to the CURRENT blessed golden `bake_id`
   for that image, so every fresh launch reuses the shared golden base
   (cache-HIT on the miner → ~2-3 min boot).
2. **`bake_id`** — a Succeeded `TenantBake` you baked yourself.
3. the raw artefact fields (`s3_bucket` / `*_sha256_hex` / `kek_vault_path` / …).

`image` and `bake_id` are **mutually exclusive** (supplying both → 400
`bad-field`); an **unknown `image` is rejected** (fail closed — it never falls
through to a launch). Supplying a resolved `image`/`bake_id` fills the artefact
SHAs / LUKS-header MAC / KEK Vault path / S3 location (caller-supplied values
win). Key fields: `userdata` (cloud-init plaintext, staged to Vault — carry the
`{{NETBIRD_SETUP_KEY}}` placeholder when NetBird is on), `tenant_id`, `user_id`,
`vm_id`, `lease_id`, `flavor`, `cmdline`, `image` **or** `bake_id`, and the
resolved `s3_bucket` / `s3_key_prefix` / `*_sha256_hex` / `kek_vault_path`;
optional `platform_id`, `auto_pin_allowlist` (default false), `enable_netbird`
(default true), `netbird_group`/`netbird_key_ttl_seconds`/
`netbird_hostname_template`, `max_price_per_unit`.

> **Golden-ness is transparent at launch.** There is **no** tenant-set
> `disk_mode` on the launch intent — the server resolves the disk mode (and the
> matching artefacts/cmdline) from the `image`/`bake_id`. A tenant launches a
> golden VM exactly like a legacy one.
>
> **The `image` catalog is operator-controlled.** A tenant supplies only the
> image NAME; vali maps it — through the `GoldenImage` catalog written **only**
> by the `vali_bless_golden_image` command — to the operator-blessed golden
> `bake_id`. A tenant can therefore NEVER cause a launch off an un-blessed or
> arbitrary bake.

#### 13.2.1 Images — `GET /v1/images` (→ 200)

Any authenticated ServiceClient. Lists the launchable golden images
(`GoldenImageListSerializer`): `{ "images": [ { image_name, distro, bake_id,
is_golden, blessed_at, blessed_by } ], "total" }`. Read-only discovery — the
catalog is set only by the operator (`vali_bless_golden_image <image> <bake_id>`,
or `--seed-defaults` to bless the current 4: ubuntu / debian / cs10 / fedora).
`is_golden` is `true` when the referenced bake is a Succeeded
`golden_verity_overlay` bake (diagnostic; never an authz signal).

`GET /v1/vm/launch/<job_id>` → the launch job (`LaunchJobSerializer`, 200):
`job_id, vm_id, tenant_id, flavor, state` (`queued|running|succeeded|failed`),
`phase` (`queued→staging→placing→dispatching→launched|failed`, nullable),
`miner_id, placement_id, reason, result, decided_by, started_at, finished_at,
version`.

### 13.3 Lifecycle / boot / NetBird

- `GET /v1/vm/<vm_id>/state` → the `Vm` row incl. `boot_phase`
  (`""→booting→kek_released→running`) and `netbird_ip` (`""` until the overlay
  peer resolves, then `100.x.y.z` — the SSH-reachable guest IP).
- **`guest_liveness`** (`alive|wedged|unknown`) + `guest_signal_at` /
  `guest_signal_age_s` / `guest_signal_kind` on the same payload. Read this,
  NOT `state`/`boot_phase`, to answer "is the guest actually up?": `state` is
  vali's lifecycle intent, `boot_phase` is monotonic (permanently `running`
  once reached), and the underlying libvirt domain stays `running` for a guest
  hung in its initramfs. `guest_liveness` is derived from the freshest signal
  that can only originate INSIDE the guest (a §23 served receipt or a §322
  live attestation) against `VALI_GUEST_LIVENESS_STALE_S`. `wedged` = it used
  to emit and has gone silent; `unknown` = it never emitted one (an image with
  no telemetry agent, or a VM still on its first boot) and is explicitly NOT a
  statement that the VM is dead.
- `GET /v1/vm?tenant_id=&lease_id=&limit=&offset=` → paginated list (display
  filter, **not** an authz boundary — see §5/§9).
- `GET /v1/vm/<vm_id>/attestation` → the raw SNP attestation bundle.

### 13.4 Decommission (§24) — `POST /v1/vm/<vm_id>/decommission` (→ 202)

Enqueues a `DecommissionJob`; the **crypto-erase happens server-side** (the
guest's disk KEK is destroyed and the NetBird peer revoked). Poll
`GET /v1/vm/<vm_id>/decommission/<job_id>` (`DecommissionJobSerializer`, 200):
`job_id, vm_id, state` (`draining→awaiting_eol_ack→crypto_erasing→
revoking_netbird→done|failed`; terminal = `done|failed`), `eol_ack_verified,
forced, quarantine_node_id, reason, decided_by, phase_started_at, started_at,
finished_at, version`. Migration (`POST /v1/vm/<vm_id>/migrate` + poll/cancel)
follows the same job shape (`MigrationJobSerializer`).

### 13.5 Worked example (Python SDK — the full tenant flow)

**Fast path — launch by image (no bake).** Reuse the shared operator-blessed
golden base; every fresh launch is a cache-HIT (~2-3 min):

```python
images = client.list_images()                      # discover launchable names
job = client.launch_vm(LaunchRequest(
    tenant_id="tenant-1", user_id="user-1", vm_id="tenant-vm-1",
    lease_id="lease-1", flavor="small", cmdline="console=ttyS0 root=/dev/vda",
    image="ubuntu",                                # ← resolves the blessed golden bake
    userdata="#cloud-config\nssh_authorized_keys: [ssh-ed25519 AAAA... ]\n",
))
job = client.wait_for_launch(job.job_id)           # → succeeded
```

**Full path — bake your own image, then launch:**

```python
from hippius_validator_client import (
    HippiusValidatorClient, BakeRequest, LaunchRequest,
)

client = HippiusValidatorClient(
    base_url="https://127.0.0.1:8443",
    token="<orchestration-root service token>",
    host_header="vali.vali.svc.cluster.local",
    verify="/etc/hippius/vali-ca.pem",
)

# 1. Bake (golden dm-verity overlay; drop disk_mode for legacy LUKS).
bake = client.create_bake(BakeRequest(
    vm_id="tenant-vm-1",
    base_image_url="https://images.example/ubuntu-24.04.qcow2",
    base_image_sha256="<64 hex>",
    size_gb=20,
    kek_vault_path="secret/data/hippius-compute/vms/tenant-vm-1/luks-kek",
    s3_output_bucket="hippius-bakes",
    s3_output_prefix="tenant/tenant-vm-1/",
    disk_mode="golden_verity_overlay",
))
bake = client.wait_for_bake(bake.bake_id)          # → succeeded

# 2. Launch (bake_id resolves artefacts/KEK/S3; golden-ness is transparent).
job = client.launch_vm(LaunchRequest(
    tenant_id="tenant-1", user_id="user-1", vm_id="tenant-vm-1",
    lease_id="lease-1", flavor="small", cmdline="console=ttyS0 root=/dev/vda",
    bake_id=bake.bake_id,
    userdata="#cloud-config\nssh_authorized_keys: [ssh-ed25519 AAAA... ]\n",
))
job = client.wait_for_launch(job.job_id)           # → succeeded

# 3. Boot + SSH-reachable overlay IP.
for step in client.wait_for_boot(job.vm_id):       # booting→kek_released→running
    print(step.phase.value, step.detail)
print("ssh IP:", client.wait_for_netbird_ip(job.vm_id))

# 4. Decommission (server-side crypto-erase + NetBird revoke).
dec = client.decommission_vm(job.vm_id)
dec = client.wait_for_decommission(job.vm_id, dec.job_id)   # → done
assert dec.is_done
```

`provision_vm(bake=..., launch=...)` chains steps 1–3 (create → wait → launch →
wait → boot) in one call; `iter_provision(...)` yields a `ProvisionStep` per
poll for an SSE/websocket bridge. Both have async twins.
