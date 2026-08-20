# Marketplace, Stake & Slashing — design

Status: **DRAFT for review** · Owner: scheduler/pallet · Repo: `hippius-compute`
Pallet of record: `pallets/compute-scoring/` (runtime name `ComputeScoring`).

This extends the §23 scoring pallet with three interlocking economic layers:
a **$-denominated stake** (so a miner has skin-in-the-game proportional to
what it hosts), a **marketplace** (miners set their own capped prices with
announced changes), and **slashing** (with a global kill-switch). It also
fixes the **cold-start** trap surfaced in review.

It is written against what already exists in the pallet — it reuses the
deposit/lockup machinery, the `MinerStatus` state machine, the live-attestation
liveness signal, and the `LockupEnabled` toggle pattern — and adds only the
genuinely new storage + extrinsics.

---

## 0. The problem (from review)

1. **Reward ≠ selection.** `EpochWeights` (PR #472) correctly rewards a miner
   for what it **hosts** (Σ reserved cpu/ram/disk of its bound VMs), not
   advertised capacity. But the scheduler also *selects* by that same weight
   (`placement.py:132` sorts `(-quality, -free_slots, node_id)`), so a
   **weight-0 miner is starved**: no VMs → no hosting → weight stays 0.
   Rich-get-richer / cold-start death spiral.

2. **Stake alone ≠ stability.** Making stake a selection priority lets a whale
   concentrate VMs then go dark → large correlated outage. Slashing repays the
   tenant but does **not** prevent the outage.

The fix is to **separate the reward signal from the selection signal**, and to
make selection a **composite** (stake + merit + free-capacity + newcomer-grace
+ anti-affinity) bounded by **concentration caps**, with stake **proportional
to hosting** so monopolising is expensive and going dark is self-punishing.

---

## 1. Layers & where each lives

| Layer | Signal | Where computed | Where enforced |
|-------|--------|----------------|----------------|
| **Reward** | Σ hosted units → `EpochWeights` | vali (`scoring.py`, #472) | pallet `vali_submit_epoch_close` |
| **Selection** | composite score → which miner wins the next VM | vali (`scheduler.placement`) | vali scheduler |
| **Stake** | required native-coin reserve = value-at-risk($) ÷ `AlphaPerUsd_ema` | pallet | pallet (reserve) + vali (eligibility) |
| **Marketplace** | per-miner price (capped, rate-limited, announced) | pallet (set/announce) | vali (selection input + migration trigger) |
| **Slashing** | liveness/SLA breach → burn part of stake | pallet | pallet (toggle-gated) |

Principle: **the pallet is the source of economic truth** (stake, prices,
slashing, status); **vali is the producer/consumer** (computes hosting,
selects, migrates). Money rules are on-chain; placement policy is off-chain.

---

## 2. Stake — $-denominated, hosting-proportional

Today `register_child` reserves a **fixed** native deposit (`BaseChildDeposit`,
halving curve). We add a **$-denominated, hosting-proportional** stake on top
of (or replacing) the flat deposit.

### 2.1 Price oracle + asymmetric EMA

- `AlphaPerUsdSpot: StorageValue<u128>` — fixed-point `alpha_per_usd × 1e6`
  (how many native units = 1 USD). Set by `set_alpha_per_usd(origin, spot)`,
  `ComputeScoringAdminOrigin` (sudo/council). **No floats on-chain.**
- `AlphaPerUsdEma: StorageValue<u128>` — the value the stake math uses.
  Updated on every `set_alpha_per_usd` post by an **asymmetric EMA**:

  ```
  // alpha_per_usd RISES when the native coin DUMPS (more alpha buys $1).
  if spot > ema:  ema += (alpha_down * (spot - ema)) / 1000   // dump → fast
  else:           ema -= (alpha_up   * (ema - spot)) / 1000   // pump → slow
  ```

  `EmaAlphaDownPermille` (e.g. 300 = react fast to dumps) and
  `EmaAlphaUpPermille` (e.g. 50 = react slow to pumps) are admin constants.
  This encodes the reviewer's intent — **"lock more fast on a dump, release
  slowly on a pump"** — *without* a hard ratchet that would freeze a miner's
  capital forever (which would make staking capital-inefficient and scare
  miners off). The asymmetry lives in the EMA, not in an irreversible lock.

  > Sourcing the spot: phase-1 = admin posts it (a trusted relayer off a DEX
  > TWAP). A later phase can replace `set_alpha_per_usd` with an on-chain
  > oracle median without touching the consumers.

### 2.2 Required stake

```
required_alpha(miner) = value_at_risk_usd(miner) × AlphaPerUsdEma / 1e6
value_at_risk_usd(miner) = Σ  vm_value_usd(flavor(vm))      // bound VMs
                          vm ∈ placements on miner
```

`vm_value_usd(flavor)` is the same hosting blend `scoring.resource_units`
already produces, re-expressed in USD (one shared coefficient table). So the
stake a miner must lock **tracks exactly what it hosts** — host more → lock
more; host nothing → lock only a base floor.

- `RequiredStake: StorageMap<[u8;32], BalanceOf>` — cached per node, refreshed
  on `vali_submit_epoch_close` (vali already reports per-miner hosting there;
  it can carry the per-miner value-at-risk in the same call) and on every
  `set_alpha_per_usd`.
- `StakeFloor: BalanceOf` (admin) — the minimum to be **eligible at all** (a
  staked newcomer hosting nothing still posts the floor; this is the
  cold-start entry ticket + anti-Sybil).

### 2.3 Top-up / unlock (the asymmetry, enforced)

- **Under-collateralised** (`reserved < required` after a dump): the miner is
  marked **`StakeDeficient`** and gets a grace window `StakeTopUpGraceBlocks`
  to `top_up_stake`. While deficient it is **ineligible for NEW placements**
  (vali selection filter) but keeps its current VMs. Past grace →
  `set_miner_status(Quarantined)` → §13 drain (migrate VMs) → optional slash.
- **Over-collateralised** (`reserved > required` after a pump): the miner may
  `request_unstake(amount)` down to `required`; the freed amount enters the
  existing **`UnbondingPeriodBlocks`** queue (stays slashable during unbond)
  and is released via the existing `claim_unbonded`. Because `required` uses
  the **slow-up EMA**, the unlockable amount grows only gradually → exactly
  the conservative behaviour the reviewer wanted, reusing machinery that's
  already there.

---

## 3. Marketplace — miner-set, capped, announced

Miners price their own capacity; price is **one input** to selection, never
the only one. Anti-gaming via stake/slashing/reputation, not price alone.

### 3.1 Price storage

- `MinerPrice: StorageMap<[u8;32], PricePerUnit>` — the miner's **current
  effective** USD price per resource-unit (fixed-point `× 1e6`).
- `PriceCeiling: StorageValue<PricePerUnit>` (admin) — anti-gouging cap.
- `PriceFloor: StorageValue<PricePerUnit>` (admin) — anti-dumping floor (a
  price absurdly low is the "win-then-disappear" attack; the floor + stake
  blunt it).

### 3.2 Announced changes (rate-limited, magnitude-bounded)

A price change does **not** take effect immediately — it is **announced
on-chain N blocks ahead** so vali can migrate VMs that no longer fit a
tenant's budget *before* the new price bites.

- `announce_price_change(origin, node_id, new_price)`:
  - **frequency**: reject if `now < LastPriceChangeBlock[node] +
    MinPriceChangeIntervalBlocks` (can't change too often).
  - **magnitude**: reject if `new_price > current × MaxPriceChangeNumer /
    MaxPriceChangeDenom` or `< current × Denom / Numer` (e.g. 3/2 ⇒ at most
    ±50% per change — **no "simple au double"**).
  - **bounds**: clamp to `[PriceFloor, PriceCeiling]`.
  - writes `PendingPriceChange[node] = { new_price, effective_block: now +
    PriceChangeNoticeBlocks }` and emits `PriceChangeAnnounced`.
- A `on_initialize` hook (or lazy-apply on read) promotes
  `PendingPriceChange` → `MinerPrice` once `now >= effective_block`, emits
  `PriceChangeApplied`, stamps `LastPriceChangeBlock`.
- vali watches `PriceChangeAnnounced`: if a bound tenant's policy would be
  violated by the new price, it schedules a **migration** within the notice
  window (reuses the §25 migration / §13 drain path).

### 3.3 Selection input (vali)

`scheduler` folds price into the composite as a **cheaper-is-better** factor,
bounded so it can't dominate trust:

```
selection_score(miner) =
      w_stake  * normalized_stake          // skin-in-the-game (cold-start key)
    + w_merit  * normalized_reward_weight  // proven hosting (anti rich-get-richer: capped)
    + w_free   * free_capacity_ratio       // load-balance → empties win
    + w_grace  * newcomer_grace(age)       // first N epochs boost → bootstrap
    + w_price  * (1 - normalized_price)     // cheaper bids rank up, within floor/ceiling
    , gated by: status==Active, !StakeDeficient, anti-affinity, free_slots>0,
                concentration_cap (no miner > MaxHostShare of active VMs)
```

`w_merit` is deliberately **not dominant** — merit breaks ties among
trusted miners, it does not starve newcomers (fixes §0.1). The
**concentration cap** + anti-affinity bound the blast radius of any single
miner going dark (fixes §0.2).

---

## 4. Slashing — with a global kill-switch

Mirrors the existing `LockupEnabled` / `set_lockup_enabled` precedent.

- `SlashingEnabled: StorageValue<bool, ValueQuery>` (default **false**).
  `set_slashing_enabled(origin, bool)` — `ComputeScoringAdminOrigin`. When
  **false**, breaches are detected + an event is emitted + (optionally) a
  `SlashRecord` is written, but **no balance is burned** — a safety switch
  for early phases / incident response.
- `slash(node_id, reason, amount)` — internal, called from the breach paths:
  - **liveness**: `submit_live_attestation` gap > `MaxLivenessGapBlocks`
    (miner went dark) → slash ∝ value-at-risk of its hosted VMs.
  - **SLA / quarantine**: `set_miner_status(Quarantined)` for cause.
  - **deficiency timeout**: stayed `StakeDeficient` past grace.
  - amount = `min(reserved, SlashNumer/SlashDenom × required)`; routed to a
    treasury / tenant-compensation account (`SlashBeneficiary`).
- `Slashed`, `SlashSkippedDisabled` events; a `SlashRecord` map for audit.

Because stake is **hosting-proportional**, a whale that goes dark loses a
slash sized to the damage it caused — "take all then disappear" is
economically irrational, which is what gives the system stability (§0.2).

---

## 5. Cold-start, restated (what makes a 0-weight miner viable)

A brand-new miner: `EpochWeights = 0`, but it **posts `StakeFloor`** →
`w_stake` term > 0 **and** `w_grace` boost for its first
`NewcomerGraceEpochs` → it **wins early placements** despite zero merit →
accrues real `EpochWeights` → graduates to competing on merit. Selection is
never pure `-quality`, so the death spiral is broken. The stake it posted is
slashable, so this is not a free lunch (anti-Sybil).

---

## 6. New storage / constants (summary)

Storage: `AlphaPerUsdSpot`, `AlphaPerUsdEma`, `RequiredStake`, `MinerPrice`,
`PendingPriceChange`, `LastPriceChangeBlock`, `PriceCeiling`, `PriceFloor`,
`SlashingEnabled`, `SlashRecord` (+ reuse `MinerStatuses`, the reserve/unbond
queues, `LiveAttestationCount`).

Admin constants: `EmaAlphaDownPermille`, `EmaAlphaUpPermille`, `StakeFloor`,
`StakeTopUpGraceBlocks`, `MinPriceChangeIntervalBlocks`,
`PriceChangeNoticeBlocks`, `MaxPriceChangeNumer/Denom`, `MaxLivenessGapBlocks`,
`SlashNumer/Denom`, `SlashBeneficiary`, `MaxHostShare`, `NewcomerGraceEpochs`.

New extrinsics: `set_alpha_per_usd`, `top_up_stake`, `request_unstake`,
`announce_price_change`, `set_slashing_enabled`, plus admin setters for the
caps. (Reuse `claim_unbonded`, `set_miner_status`, `vali_submit_epoch_close`.)

vali changes: selection composite in `scheduler.placement`; carry per-miner
value-at-risk in `submit_epoch_close`; watch `PriceChangeAnnounced` →
migration trigger; eligibility filter on `StakeDeficient`/status/concentration.

---

## 7. Invariants

1. A miner with `reserved < required` is **never** selected for a new VM.
2. `MinerPrice ∈ [PriceFloor, PriceCeiling]` always; a pending change is
   already clamped at announce time.
3. A price change is visible on-chain ≥ `PriceChangeNoticeBlocks` before it
   bites — vali always has the migration window.
4. No miner hosts > `MaxHostShare` of active VMs (blast-radius bound).
5. `SlashingEnabled == false` ⇒ no balance is ever burned (only events).
6. Unstake only reduces reserve via the unbonding queue (slashable until
   released) — never an instant drop.

---

## 8. Phasing (proposed PRs, after this doc is approved)

- **PR-1 (pallet, stake core)**: oracle + asymmetric EMA + `RequiredStake` +
  top-up/unstake + `StakeFloor`/eligibility. Tests + benches.
- **PR-2 (pallet, slashing)**: `SlashingEnabled` toggle + breach paths +
  `SlashRecord`. Tests (toggle-off = no burn).
- **PR-3 (pallet, marketplace)**: price storage + caps + announced changes +
  apply hook. Tests (frequency/magnitude/notice).
- **PR-4 (vali, selection)**: composite score + cold-start grace +
  concentration cap + `StakeDeficient` filter. Tests on `placement`.
- **PR-5 (vali, migration on price change)**: watch `PriceChangeAnnounced` →
  §25/§13 migration within the notice window.

Each pallet PR ships behind a default-off / conservative-constant posture so
mainnet behaviour is unchanged until ops flips the toggles.

---

## 9. Open decisions (for sign-off)

- **D1 — unlock policy.** Recommend **asymmetric EMA + unbonding** (§2.1/2.3)
  over a hard ratchet. *Confirm.*
- **D2 — stake replaces or stacks on `BaseChildDeposit`?** Recommend the
  $-denominated stake **subsumes** the flat deposit (one reserve, one
  unbond), with `BaseChildDeposit` retired to avoid double-locking. *Confirm.*
- **D3 — price units.** Per resource-unit (the `resource_units` blend) vs per
  flavor. Recommend **per resource-unit** (consistent with reward). *Confirm.*
- **D4 — spot source.** Phase-1 admin-posted vs oracle now. Recommend
  **admin-posted**, oracle later (consumers unchanged). *Confirm.*
- **D5 — slash beneficiary.** Treasury vs direct tenant-compensation escrow.
  *Decide.*
