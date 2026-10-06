# Restoring §23 epoch close

Epoch closing has been dead since **2026-08-03**. This is the runbook for
bringing it back, and the order matters: steps 2–5 are what stop a resumed
closer from paying miners for work nobody proved.

Nothing here is speculative. Every claim was verified live on the testnet and
every fix referenced is merged.

## What actually happened

The testnet was upgraded to a runtime built from thebrain `main`, which has
**never** contained `pallet-compute-scoring`. `main`'s `construct_runtime` has
zero occurrences of it; `dev` additionally has
`ComputeScoring: pallet_compute_scoring = 79`.

A runtime upgrade does not delete storage, so the pallet's twox-128 prefix keeps
answering reads. `state_getStorage` on `ComputeScoring.CurrentEpoch` still
returns the last epoch — but `api.tx.computeScoring` is gone, so `close-epoch.mjs` dies
at its first chain call. vali reports `read-miner-status ok: current_epoch=<N>`
every 30 s off a **fossil**.

Two consequences that are easy to miss:

- the §23 **stale-epoch gate is disarmed**. `placement.py` and `service.py` both
  gate on `current_epoch - data_epoch > max_epoch_lag`; with the chain frozen
  both operands freeze together at a lag of 0, so no miner can ever be excluded
  as stale. It fails **open**;
- **on-chain revocation of a compromised miner is impossible** — nothing can
  transition `MinerStatuses` any more.

Resuming the CronJob today is harmless (it exits 3 with an explanatory message)
and useless.

## Step 1 — port the pallet onto thebrain `main`

`main` does not merely lack the wiring: **`pallets/compute-scoring/` does not
exist on `main` at all**. It lives only on `dev`.

This recipe was **executed and compiled** against thebrain `main` at
`5c15ec98` — it is not a sketch. Every step below is a step that was actually
needed; the two marked ⚠️ were missing from the first draft and would each have
stopped the port dead.

1. Vendor `pallets/compute-scoring/` — from **hippius-compute**, not from `dev`.
   The two copies are identical apart from the #901 genesis price bounds
   (whole-file diff: 40 lines added, 0 removed, 0 changed) and the storage layout
   is byte-identical, so the frozen epoch state decodes either way — but only ours
   carries the bounds.
2. ⚠️ **Vendor `hippius-types` too.** The pallet does
   `hippius-types = { path = "../../hippius-types" }`, and that crate lives in
   hippius-compute. A git dependency is **not** an option: thebrain is **public**
   and hippius-compute is **private**, so a git dep would make a public repo
   unbuildable outside the org.

   It does not need the whole 10,196-line crate. The pallet touches exactly two
   modules (`audit_vm`, `live_attestation`) and their only intra-crate dependency
   is `cbor`, which pulls in nothing further — **3 modules, 1,349 lines**. Keep
   `Cargo.toml` as-is and trim `lib.rs` to those three `pub mod` lines.

   (thebrain `dev` already vendors a **stale 19-module snapshot** of this crate —
   it predates `kbs_vsock.rs`, `host_attestor*`, `graceful_exit`, `vm_progress`.
   Do not copy that one forward; take the trimmed current source.)
3. ⚠️ **Reconcile the manifests with thebrain's workspace.** Our crates inherit
   `publish.workspace = true` and `[lints] workspace = true`; thebrain's root
   defines **neither**, and cargo fails to even load the workspace
   (`workspace.package.publish was not defined`). Replace with `publish = false`
   and drop the `[lints]` block. Also convert the pallet's `pallet-registration`
   / `pallet-proxy` **git** deps (rev `11226860`) into **path** deps
   (`../registration`, `../proxy`) — in-tree they must not resolve through git.
4. `runtime/mainnet/Cargo.toml` —
   `pallet-compute-scoring = { path = "../../pallets/compute-scoring", default-features = false }`
   plus `"pallet-compute-scoring/std"` in the `std` feature.
5. `runtime/mainnet/src/lib.rs` — the `ComputeScoringAuthorityMembers`
   `SortedMembers` impl, the `ComputePalletInstance` / `ComputeChainGenesis`
   `parameter_types!`, and the `impl pallet_compute_scoring::Config for Runtime`.
   Lift the block verbatim from `dev` (it sits just before
   `#[cfg(feature = "std")] use sp_version::NativeVersion;`). The authority is
   `<COMPUTE_SCORING_AUTHORITY_SS58>` — the account already in
   `metagraph.whitelistedValidators`. `main` already defines every supporting
   const the impl references (`BaseChildDeposit`,
   `GlobalDepositHalvingPeriodBlocks`, `UnregisterCooldownBlocks`,
   `UnbondingPeriodBlocks`) and already uses `from_ss58check` + `hex_literal`, so
   nothing else has to be added.
6. `construct_runtime` — `ComputeScoring: pallet_compute_scoring = 79,`.
   Verified free on `main`: index 79 is unused and no index is duplicated.
7. Bump `spec_version` — and mind the **renumbering**. On 2026-08-11 the live
   testnet went `9199` → **`92001`**, a jump of five orders of magnitude, while
   thebrain `main` still reads `spec_version: 9198`. So the next value must beat
   **92001**, not 9199: a runtime whose `spec_version` does not strictly increase
   is rejected, and `main`'s number is now far *behind* the chain rather than one
   ahead of it.

   That upgrade changed **nothing else**. Diffing the metadata blob before and
   after: same 380,255 bytes, **15 differing bytes**, every one of them the
   little-endian spec version (`ef230000` → `61670100`) at the `System.Version`
   constant and four type/doc sites. Same pallet set, `ComputeScoring` still 0.
   It was a version-scheme change, not a functional release — worth knowing
   before anyone reads a five-digit jump as "the port landed".

> **Preserve the pallet NAME and index 79.** Storage lives under the twox-128 of
> the *name*, so the existing frozen epoch state is picked up again only if the
> name matches. The index governs call encoding.
>
> ⚠️ There is a `pallets/compute` on `main` already — that is `pallet-compute`,
> *"managing compute resources and tasks"*, a **different** pallet. Do not
> conflate them.

**Verification actually run** (thebrain `main` @ `5c15ec98`, all four steps
applied):

```
cargo check -p pallet-compute-scoring --no-default-features --target wasm32-unknown-unknown   → exit 0
cargo check -p hippius-mainnet-runtime --no-default-features --features std                   → exit 0
```

The pallet also builds against `main`'s current `pallet-registration` /
`pallet-proxy` (138 commits past our pinned rev) with **89/89 tests passing** and
no source change, so those two APIs have not drifted.

> ⚠️ hippius-compute PR **#910** is a prerequisite. Before it, `hippius-types`
> did not compile for `wasm32-unknown-unknown` at all — `kbs_vsock.rs` used
> `String` without importing it from `alloc`, which a host-target build hides
> because `String` is in the std prelude. Vendoring an older snapshot of the
> crate would have failed at exactly this step.

**Merge it into `main`, do not ship a one-off build.** `dev` is behind `main`,
and the live chain went 9196 → 9198 without the pallet while this was being
written. Every `main`-lineage deploy is another chance to drop it — which is
exactly how the outage started.

## Step 2 — set the price bounds in the chain spec

The pallet has always had `PriceFloor` / `PriceCeiling` and
`announce_price_change` has always enforced them. They were simply never set, so
the chain ran unbounded: miners carried self-set prices with no cap, and a
`small` VM billed ~7,950 USD/hour.

Genesis now takes them (hippius-compute #901) — **but that only helps a fresh
chain.** `GenesisConfig` runs at chain genesis only, and the pallet has no
`Hooks` impl and therefore no `on_runtime_upgrade` migration. Re-adding the
pallet by runtime upgrade picks the existing storage back up with
`PriceFloor = 0` / `PriceCeiling = None` intact.

On the live testnet the bounds must therefore be set by extrinsic:
**`set_price_bounds` (call_index 52)**, whose origin is
`ComputeScoringAdminOrigin = EnsureSignedBy<ComputeScoringAuthorityMembers>` —
the `<COMPUTE_SCORING_AUTHORITY_SS58>` account, **not sudo**.

The *values* are an economic decision, not a technical one. What the arithmetic
says: `MinerPrice` is µUSD per **real** resource-unit per hour, and a flavor's
real units are `cpu×1.0 + ramGB×0.25 + (dataGB+10)×0.005` — so `small` = 1.59
units, `4xlarge` = 49.33. At the live test price of 5e6 µUSD a `small` VM bills
**5,804 USD/month**; a sane band for a confidential small VM (15-40 USD/month) is
roughly **10,000-35,000 µUSD/unit-hour**.

⚠️ Setting bounds does **not** re-validate prices already in storage:
`set_price_bounds` writes the two values and stops, and `within_price_bounds` is
consulted only on the propose path. A tight ceiling therefore strands the
existing prices above it, and a miner can only walk down through the magnitude
limiter (default `3/2` ⇒ ÷1.5 per step, each gated by
`MinPriceChangeIntervalBlocks` and delayed by `PriceChangeNoticeBlocks`) —
5e6 → 5e4 is 12 gated steps. Either open wide first and tighten later, or raise
`MaxPriceChangeNumer/Denom` for the re-pricing window.

## Step 3 — arm the SNP liveness gate (needs a tenant re-bake)

Served receipts are signed by the guest alone. The telemetry key is HKDF-derived
from the lifecycle key, readable by in-CVM root. So a miner could launch a VM on
its own node, extract the key, kill the VM, and keep signing uptime — reproduced
live: one fabricated receipt credited 5,716,050 unit_seconds.

hippius-compute #904 makes credit require an SNP-attested liveness proof
covering the window. It ships **disabled**
(`VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION`).

Arming order:

1. deploy vali and the miner-agent/Edge relay;
2. **re-bake the tenant images** — a hardware liveness proof needs the guest to
   produce SNP reports post-boot, so the measured image changes;
3. confirm `VmLiveAttestation` rows are arriving for live VMs;
4. only then set the flag.

Armed before step 3 and every accrual stops, fleet-wide.

## Step 4 — check the migrations actually ran

Migrations run from a `vali-django-migrations` Job. **Deploying a new vali image
does not re-run it.**

```
kubectl -n vali exec deploy/vali -- python manage.py showmigrations | grep '\[ \]'
```

Any output means the running code and the schema disagree. The light synthetic
monitor now fails on this (#905), but check it by hand before arming anything.

## Step 5 — verify the semantics, then dry-run

Once the pallet is live:

```
# the fossil check should go green on its own within 15 min
kubectl -n vali create job epochverify --from=cronjob/synthetic-monitor-light
kubectl -n vali logs job/epochverify | grep epoch_close
```

Confirm the shape has not drifted — `vali_submit_epoch_close(epoch, status_updates)`
still takes `BoundedVec<MinerStatusUpdate>` and still enforces `epoch > cur`,
and `EpochWeights[epoch][node_id]` is still `u128`. `hippius-onchain-registry`
derives its storage keys from the pallet name and reads them raw; a changed
storage layout would be read as garbage rather than refused.

Then, **before** touching `suspend`:

```
kubectl -n vali create job epochdry --from=cronjob/epoch-close
kubectl -n vali set env job/epochdry EPOCH_CLOSE_DRY_RUN=1
kubectl -n vali logs job/epochdry
```

`EPOCH_CLOSE_DRY_RUN` runs every step for real — chain reads, vali weights
fetch, epoch arithmetic, per-node mapping — and stops immediately before the
call is built. Nothing is signed, nothing is sent. Read the per-node weights and
decide whether they are what you expect.

## Step 6 — resume

`deploy/gitops/apps/vali/values.yaml`, `epochClose.suspend: false`, then apply.
The first close submits the **entire** accumulated bucket for the frozen epoch as one
epoch's weights — the ledger has been filling since 2026-08-03 and cannot roll
over until an epoch closes. Expect that first submission to be large and
lopsided; it is not a bug, but look at the dry run before accepting it.

## Already fixed, for the record

| | |
| --- | --- |
| a stalled ledger was re-paid at every close | #896 — weights key off the CHAIN epoch |
| the ×1000 ranking scale leaked into the bill | #902 — 1,092,682 USD → 1,180 USD on the same data |
| a frozen epoch reported OK for a week | #898 — the monitor fails on a fossil pallet |
| the closer died with a bare `TypeError` | #900 — it now names the runtime and the decision |
| "what would it submit?" needed a throwaway script | #906 — `EPOCH_CLOSE_DRY_RUN` |
| an image could ship a model with no table | #905 — the monitor fails on pending migrations |

## Still open, and NOT technical

**Self-dealing.** Nothing prevents a miner hosting its own tenant VMs and
collecting the hosting weight. Note that the reward pot is
`pallet_balances::free_balance(pallet_account)` — an **emission** pot, not the
tenant's payment — so "the VM is billed more than the miner earns" does not hold
as a defence: the two flows are unrelated. What decides it is the ratio between
the emission share per unit of hosted capacity and the price of that capacity.
Both are parameters you control.

This only becomes the binding constraint once step 3 is armed. Until then a
miner does not need to run a VM at all.
