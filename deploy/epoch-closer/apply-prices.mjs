// hippius price keeper — §23 marketplace: materialise due price changes.
//
// A miner announces a price with `ComputeScoring.announcePriceChange`; the
// pallet parks it in `PendingPriceChange{new_price, effective_block}`. Once
// the notice window has elapsed, ANYONE may call the permissionless
// `ComputeScoring.applyPriceChange(node_id)` to write it into `MinerPrice`.
// Nobody did, so a due change never reached `MinerPrice` — the raw value
// vali reads. This worker lists the due entries and applies them.
//
// Same image as the epoch closer (one @polkadot/api build, one signature
// pipeline), different entrypoint and a DIFFERENT key: a dedicated,
// low-funded keeper account. Never the audit authority / sudo key, never a
// miner's key — the guards below refuse both rather than trusting the chart.
//
// Env:
//   THEBRAIN_RPC_URL                wss:// endpoint (required)
//   PRICE_KEEPER_KEY_FILE           file holding the KEEPER mnemonic (required)
//   PRICE_KEEPER_MAX_PER_RUN        at most this many applies per run (default 10)
//   PRICE_KEEPER_FEE_BUDGET_PLANCK  total estimated fees per run (default 1e18)
//   PRICE_KEEPER_MIN_BALANCE_PLANCK reserve the keeper never spends below
//                                   (default 2e18); also the low-balance alert line
//   PRICE_KEEPER_PUSHGATEWAY_URL    optional; result gauges are PUT there
//   PRICE_KEEPER_FORBIDDEN_ACCOUNTS comma-separated SS58 / 0x-hex accounts the
//                                   keeper must never sign as (the audit
//                                   authority: on production it is NOT sudo,
//                                   so the sudo guard alone cannot see it)
//   PRICE_KEEPER_INCLUSION_TIMEOUT_S an apply not in a block after this
//                                   counts as failed (default 60)
//   PRICE_KEEPER_RUN_TIMEOUT_S      the whole run gives up (pushing success=0)
//                                   after this (default 600, under the Job
//                                   deadline so the failure is reported)
//   PRICE_KEEPER_DRY_RUN            any non-empty value ⇒ list what WOULD be
//                                   applied, sign, send and push nothing
//
// Idempotent: each entry is re-read right before it is submitted, and a
// change that is gone (applied by someone else, or the node deregistered)
// or no longer due (the miner re-announced) is skipped, not failed. A run
// that loses that race at dispatch (`NoPriceChangeDue`) counts it the same.
// A change the pallet DISCARDS at apply (out of the current price bounds; it
// emits `PendingPriceDiscarded` and returns Ok) is counted as discarded, not
// applied: `MinerPrice` did not move.
//
// Exit codes:
//   0  every due change attempted was applied (or skipped as already applied)
//   1  at least one submission failed, a chain read failed, or the run timed out
//   2  required env missing / malformed
//   3  pallet-compute-scoring (or applyPriceChange) is not in the runtime
//   5  stopped at the balance reserve with due changes left
//   6  the signer is the sudo key, a registered miner or a forbidden account
//      — refused, nothing sent
import { ApiPromise, WsProvider } from '@polkadot/api';
import { Keyring } from '@polkadot/keyring';
import { cryptoWaitReady, decodeAddress } from '@polkadot/util-crypto';
import fs from 'fs';

// ── configuration: parsed in full before anything connects ────────────────
function envBigInt(name, dflt) {
  const raw = (process.env[name] || '').trim();
  if (!raw) return dflt;
  if (!/^[0-9]+$/.test(raw)) { console.error(`${name} must be a non-negative integer, got ${JSON.stringify(raw)}`); process.exit(2); }
  return BigInt(raw);
}

const RPC = process.env.THEBRAIN_RPC_URL;
const KEY_FILE = process.env.PRICE_KEEPER_KEY_FILE;
if (!RPC || !KEY_FILE) { console.error('THEBRAIN_RPC_URL + PRICE_KEEPER_KEY_FILE required'); process.exit(2); }
const MAX_PER_RUN = Number(envBigInt('PRICE_KEEPER_MAX_PER_RUN', 10n));
const FEE_BUDGET = envBigInt('PRICE_KEEPER_FEE_BUDGET_PLANCK', 1_000_000_000_000_000_000n);
const MIN_BALANCE = envBigInt('PRICE_KEEPER_MIN_BALANCE_PLANCK', 2_000_000_000_000_000_000n);
const INCLUSION_TIMEOUT_MS = Number(envBigInt('PRICE_KEEPER_INCLUSION_TIMEOUT_S', 60n)) * 1000;
const RUN_TIMEOUT_MS = Number(envBigInt('PRICE_KEEPER_RUN_TIMEOUT_S', 600n)) * 1000;
const PUSHGATEWAY = (process.env.PRICE_KEEPER_PUSHGATEWAY_URL || '').trim().replace(/\/+$/, '');
const DRY_RUN = !!(process.env.PRICE_KEEPER_DRY_RUN || '').trim();
const u8aHex = (u8a) => '0x' + Buffer.from(u8a).toString('hex');
let FORBIDDEN;
try {
  FORBIDDEN = (process.env.PRICE_KEEPER_FORBIDDEN_ACCOUNTS || '')
    .split(',').map((a) => a.trim()).filter(Boolean).map((a) => u8aHex(decodeAddress(a)));
} catch (e) {
  console.error(`PRICE_KEEPER_FORBIDDEN_ACCOUNTS holds an undecodable account (${e.message})`);
  process.exit(2);
}

const metrics = {
  due: 0, applied: 0, discarded: 0, skipped: 0, failed: 0, remaining: 0,
  free_balance_planck: null, success: 0,
};

// Pushgateway text format. A push failure is logged and never changes the
// exit code: the chain work already happened (or did not) either way.
async function pushMetrics() {
  if (!PUSHGATEWAY || DRY_RUN) return; // a dry run must not overwrite the armed job's gauges
  const lines = [];
  const g = (name, help, value) => {
    if (value === null || value === undefined) return;
    lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} gauge`, `${name} ${value}`);
  };
  g('hippius_price_keeper_last_run_timestamp_seconds', 'End of the last price-keeper run.', Math.floor(Date.now() / 1000));
  g('hippius_price_keeper_success', '1 if the last run finished with no failure or refusal.', metrics.success);
  g('hippius_price_keeper_due', 'Due price changes seen by the last run.', metrics.due);
  g('hippius_price_keeper_applied', 'Price changes applied by the last run.', metrics.applied);
  g('hippius_price_keeper_discarded', 'Due changes the pallet discarded as out of bounds in the last run.', metrics.discarded);
  g('hippius_price_keeper_skipped', 'Due changes the last run found already resolved.', metrics.skipped);
  g('hippius_price_keeper_failed', 'Apply submissions that failed in the last run.', metrics.failed);
  g('hippius_price_keeper_remaining', 'Due changes left unattempted (cap, fee budget or reserve).', metrics.remaining);
  g('hippius_price_keeper_free_balance_planck', 'Keeper account free balance.', metrics.free_balance_planck?.toString());
  g('hippius_price_keeper_min_balance_planck', 'Reserve the keeper never spends below.', MIN_BALANCE.toString());
  try {
    const r = await fetch(`${PUSHGATEWAY}/metrics/job/price-keeper`, {
      method: 'PUT', body: lines.join('\n') + '\n', signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) console.error(`price-keeper: metrics push HTTP ${r.status}`);
  } catch (e) {
    console.error(`price-keeper: metrics push failed (${e.message})`);
  }
}

let api = null;
let finishing = false;
// Every exit after configuration goes through here, so every outcome —
// including a crash or a hang — is pushed (success=0 unless main() set it).
async function finish(code) {
  if (finishing) return;
  finishing = true;
  await pushMetrics();
  if (api) await Promise.race([api.disconnect(), new Promise((r) => setTimeout(r, 2000))]);
  process.exit(code);
}

// A hung RPC (the provider reconnects forever) must still end in a pushed
// failure, before the Job deadline kills the pod silently.
setTimeout(() => {
  console.error(`price-keeper: run exceeded ${RUN_TIMEOUT_MS / 1000}s — giving up`);
  metrics.success = 0;
  finish(1);
}, RUN_TIMEOUT_MS);

// OptionQuery storage comes back as an Option codec; unwrap to the value or null.
const unwrap = (v) => (v && typeof v.isSome === 'boolean' ? (v.isSome ? v.unwrap() : null) : v);

async function main() {
  await cryptoWaitReady();
  const signer = new Keyring({ type: 'sr25519' }).addFromMnemonic(fs.readFileSync(KEY_FILE, 'utf8').trim());
  const signerHex = u8aHex(signer.publicKey);
  // throwOnConnect: an unreachable RPC fails this run now instead of
  // retrying until the deadline.
  api = await ApiPromise.create({ provider: new WsProvider(RPC), throwOnConnect: true });

  if (!api.query.computeScoring?.pendingPriceChange || !api.tx.computeScoring?.applyPriceChange) {
    const rt = api.runtimeVersion;
    console.error(
      `price-keeper: computeScoring.pendingPriceChange / applyPriceChange is NOT in the runtime ` +
      `(${rt.specName.toString()} spec ${rt.specVersion.toString()}) — nothing can be applied.`
    );
    return 3;
  }

  // ── signer guards ────────────────────────────────────────────────────────
  // The call is permissionless, so the cheapest key on the chain is the right
  // one. A powerful key here turns a cron job into a standing hot wallet for
  // the chain's most privileged account; a miner's key lets that miner's fee
  // budget be drained by everyone else's price changes. Refuse both.
  if (FORBIDDEN.includes(signerHex)) {
    console.error('price-keeper: the signer is in PRICE_KEEPER_FORBIDDEN_ACCOUNTS — refusing. Use the dedicated keeper key.');
    return 6;
  }
  const sudoKey = api.query.sudo?.key ? unwrap(await api.query.sudo.key()) : null;
  if (sudoKey && sudoKey.toHex() === signerHex) {
    console.error('price-keeper: the signer is the chain sudo key — refusing. Use the dedicated keeper key.');
    return 6;
  }
  const children = await api.query.computeScoring.nodeIdToChild.entries();
  if (children.some(([, v]) => unwrap(v)?.toHex() === signerHex)) {
    console.error('price-keeper: the signer is a registered miner account — refusing. Use the dedicated keeper key.');
    return 6;
  }

  // ── due changes ──────────────────────────────────────────────────────────
  // The pallet admits an apply once `now >= effective_block`; the extrinsic
  // executes in a block after `head`, so `effective_block <= head` is due.
  const head = (await api.query.system.number()).toBigInt();
  const due = (await api.query.computeScoring.pendingPriceChange.entries())
    .map(([k, v]) => {
      const p = unwrap(v);
      return p && { nodeId: k.args[0].toHex(), newPrice: p.newPrice.toBigInt(), effectiveBlock: p.effectiveBlock.toBigInt() };
    })
    .filter((c) => c && c.effectiveBlock <= head)
    // Oldest first, then node id: deterministic, and the longest-overdue
    // change is never starved by the per-run cap.
    .sort((a, b) => (a.effectiveBlock === b.effectiveBlock
      ? (a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0)
      : (a.effectiveBlock < b.effectiveBlock ? -1 : 1)));
  metrics.due = due.length;

  const balance = async () => (await api.query.system.account(signer.address)).data.free.toBigInt();
  const startFree = await balance();
  metrics.free_balance_planck = startFree;
  console.log(`price-keeper: head=${head} due=${due.length} free=${startFree} reserve=${MIN_BALANCE} cap=${MAX_PER_RUN} budget=${FEE_BUDGET}`);

  if (DRY_RUN) {
    console.log('DRY RUN — would apply (in order); NOTHING signed, NOTHING sent');
    for (const c of due.slice(0, MAX_PER_RUN)) {
      console.log(`    ${c.nodeId}  new_price=${c.newPrice}  effective_block=${c.effectiveBlock}`);
    }
    return 0;
  }

  const discardedEvent = api.events.computeScoring?.PendingPriceDiscarded;
  async function submit(tx) {
    let timer;
    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => resolve({ ok: false, why: `not in a block after ${INCLUSION_TIMEOUT_MS / 1000}s` }), INCLUSION_TIMEOUT_MS);
    });
    const included = new Promise((resolve, reject) => {
      tx.signAndSend(signer, ({ status, dispatchError, events = [] }) => {
        // Never going to be included: fail now, not at the timeout.
        if (status.isInvalid || status.isDropped || status.isUsurped) return resolve({ ok: false, why: `transaction ${status.type}` });
        if (!status.isInBlock) return;
        if (!dispatchError) {
          const discarded = !!discardedEvent && events.some(({ event }) => discardedEvent.is(event));
          return resolve({ ok: true, discarded });
        }
        let name = dispatchError.toString();
        if (dispatchError.isModule) {
          try {
            const d = api.registry.findMetaError(dispatchError.asModule);
            name = `${d.section}.${d.name}`;
          } catch (e) {
            name = `undecodable module error ${dispatchError.asModule.toString()} (${e})`;
          }
        }
        resolve({ ok: false, why: name });
      }).catch(reject);
    });
    try {
      return await Promise.race([included, timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  let stop = null;
  for (let i = 0; i < due.length; i++) {
    const c = due[i];
    if (metrics.applied + metrics.discarded + metrics.failed >= MAX_PER_RUN) { stop = 'per-run cap'; metrics.remaining = due.length - i; break; }

    // Re-read: another keeper (or a second run) may have applied it, the node
    // may have deregistered, or the miner re-announced a later change.
    const now = unwrap(await api.query.computeScoring.pendingPriceChange(c.nodeId));
    if (!now || now.effectiveBlock.toBigInt() > head) {
      console.log(`    ${c.nodeId}  already resolved — skipped`);
      metrics.skipped++;
      continue;
    }

    // `spent` is the real balance drop so far, not a sum of estimates; only
    // the NEXT call's fee is an estimate.
    const free = await balance();
    const spent = startFree > free ? startFree - free : 0n;
    const tx = api.tx.computeScoring.applyPriceChange(c.nodeId);
    const fee = (await tx.paymentInfo(signer)).partialFee.toBigInt();
    if (spent + fee > FEE_BUDGET) { stop = 'fee budget'; metrics.remaining = due.length - i; break; }
    if (free - fee < MIN_BALANCE) { stop = 'balance reserve'; metrics.remaining = due.length - i; break; }

    let res;
    try {
      res = await submit(tx);
    } catch (e) {
      res = { ok: false, why: `rpc: ${e.message}` };
    }
    if (res.ok && res.discarded) {
      // The pallet resolved it by dropping it (out of the current bounds);
      // MinerPrice did not move and the miner has to re-announce.
      console.log(`    ${c.nodeId}  DISCARDED by the pallet (new_price=${now.newPrice.toBigInt()} out of bounds)`);
      metrics.discarded++;
    } else if (res.ok) {
      console.log(`    ${c.nodeId}  applied new_price=${now.newPrice.toBigInt()} fee~${fee}`);
      metrics.applied++;
    } else if (res.why === 'computeScoring.NoPriceChangeDue') {
      // Lost the race between the re-read and dispatch: resolved by someone else.
      console.log(`    ${c.nodeId}  resolved before dispatch — skipped`);
      metrics.skipped++;
    } else {
      console.error(`    ${c.nodeId}  apply REFUSED: ${res.why}`);
      metrics.failed++;
    }
  }

  const free = await balance();
  metrics.free_balance_planck = free;
  if (stop) console.log(`price-keeper: stopped at the ${stop}, ${metrics.remaining} due change(s) left for the next run`);
  console.log(
    `price-keeper: applied=${metrics.applied} discarded=${metrics.discarded} skipped=${metrics.skipped} ` +
    `failed=${metrics.failed} remaining=${metrics.remaining} spent=${startFree > free ? startFree - free : 0n} free=${free}`
  );

  if (metrics.failed > 0) return 1;
  if (stop === 'balance reserve') return 5;
  metrics.success = 1;
  return 0;
}

let code;
try {
  code = await main();
} catch (e) {
  console.error(`price-keeper: run failed: ${e?.stack || e}`);
  metrics.success = 0;
  code = 1;
}
await finish(code);
