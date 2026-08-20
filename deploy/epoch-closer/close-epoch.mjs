// hippius-epoch-closer — §23 periodic epoch-close worker.
//
// Advances pallet-compute-scoring's CurrentEpoch by submitting
// `ComputeScoring.valiSubmitEpochClose(epoch, status_updates)` for every
// on-chain-registered node — submitted DIRECTLY by the pallet's configured
// audit authority, NOT via `Sudo.sudo`. Without this, CurrentEpoch stays 0,
// every miner scores quality=0, and vali's §23 scheduler stale-gates.
//
// Env:
//   THEBRAIN_RPC_URL      wss:// endpoint (required)
//   EPOCH_CLOSE_KEY_FILE  file holding the AUDIT AUTHORITY mnemonic (required).
//                         It does NOT need to be the chain's sudo key.
//   VALI_EPOCH_WEIGHTS_URL  vali GET /v1/admin/epoch-weights (optional) — the
//                         REAL §23 merit weights {node_id_hex: weight}. When
//                         set + reachable, each node's weight is its bound-
//                         placement merit (0 if it hosts nothing). When unset
//                         or unreachable, falls back to EPOCH_DEFAULT_WEIGHT
//                         (so a vali outage never stops the epoch advancing).
//   VALI_TOKEN_FILE       file with the ServiceToken bearer for that GET.
//   EPOCH_DEFAULT_WEIGHT  fallback per-node weight (default 1).
//   EPOCH_CLOSE_DRY_RUN   any non-empty value ⇒ resolve + PRINT the exact
//                         payload and STOP, signing and submitting nothing.
//                         Exists because "what would a resumed run submit
//                         today?" was asked repeatedly and could only be
//                         answered by hand-rolling a throwaway probe that
//                         reimplemented these same steps — which is a
//                         reimplementation that can drift from the real
//                         worker precisely when you are relying on it.
//
// Exit codes:
//   0  closed (or dry-ran, or nothing to close)
//   1  submission failed (ExtrinsicFailed / RPC error)
//   2  required env missing
//   3  pallet-compute-scoring is not in the runtime (orphaned storage only)
//   4  the fleet outgrew MaxMinerStatusUpdatesPerCall — see the guard below
import { ApiPromise, WsProvider } from '@polkadot/api';
import { Keyring } from '@polkadot/keyring';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import fs from 'fs';

const RPC = process.env.THEBRAIN_RPC_URL;
const KEY_FILE = process.env.EPOCH_CLOSE_KEY_FILE;
const DEFAULT_WEIGHT = BigInt(process.env.EPOCH_DEFAULT_WEIGHT || '1');
const WEIGHTS_URL = process.env.VALI_EPOCH_WEIGHTS_URL || '';
const DRY_RUN = !!(process.env.EPOCH_CLOSE_DRY_RUN || '').trim();
const TOKEN_FILE = process.env.VALI_TOKEN_FILE || '';
if (!RPC || !KEY_FILE) { console.error('THEBRAIN_RPC_URL + EPOCH_CLOSE_KEY_FILE required'); process.exit(2); }

// Pull vali's real per-miner merit weights; null ⇒ caller uses the flat
// fallback (so a vali outage never stops the epoch from advancing).
async function fetchValiWeights() {
  if (!WEIGHTS_URL) return null;
  const headers = {};
  if (TOKEN_FILE) {
    try { headers['Authorization'] = 'Bearer ' + fs.readFileSync(TOKEN_FILE, 'utf8').trim(); } catch {}
  }
  // Retry — a freshly-scheduled Job pod's CiliumNetworkPolicy identity can
  // take a few seconds to converge, so the first in-cluster fetch may be
  // dropped. 4 tries × 5s rides that window; if it still fails the caller
  // uses the flat fallback (so a vali outage never stops the epoch).
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      const r = await fetch(WEIGHTS_URL, { headers, signal: AbortSignal.timeout(8000) });
      if (!r.ok) { console.log('vali weights HTTP ' + r.status + ' — flat fallback'); return null; }
      const body = await r.json();
      console.log('vali weights: ' + body.miners + ' miner(s), total ' + body.total_weight);
      return body.weights || {};
    } catch (e) {
      console.log('vali weights attempt ' + attempt + '/4 failed (' + e.message + ')');
      if (attempt < 4) await new Promise((r) => setTimeout(r, 5000));
    }
  }
  console.log('vali weights unreachable — flat fallback');
  return null;
}

await cryptoWaitReady();
const signer = new Keyring({ type: 'sr25519' }).addFromMnemonic(fs.readFileSync(KEY_FILE, 'utf8').trim());
const api = await ApiPromise.create({ provider: new WsProvider(RPC) });

// The pallet must actually be IN the runtime, not merely have storage.
// A runtime upgrade does not delete a removed pallet's storage prefix, so
// `state_getStorage` keeps answering with its last-written bytes forever
// while `api.tx`/`api.query` — which come from the metadata — are gone.
// That is exactly what happened on 2026-08-03: the testnet moved to a
// runtime lineage that never carried pallet-compute-scoring, and this
// worker began dying here every 10 minutes with a bare
// `TypeError: Cannot read properties of undefined (reading 'nodeIdToChild')`
// — a message that says nothing about the cause. Fail with one that does.
if (!api.query.computeScoring || !api.tx.computeScoring) {
  const rt = api.runtimeVersion;
  console.error(
    `epoch-close: pallet 'computeScoring' is NOT in the runtime ` +
    `(${rt.specName.toString()} spec ${rt.specVersion.toString()}). ` +
    `Its storage prefix may still answer reads — that is an ORPHANED ` +
    `snapshot, not a live pallet, and no epoch can be closed against it. ` +
    `Unsuspending this CronJob cannot help. See deploy/gitops/apps/vali/` +
    `values.yaml \`epochClose\` part 1 for the decision this is blocked on ` +
    `(restore the pallet upstream, or rewire vali onto ` +
    `rankingCompute.updateRankings).`
  );
  await api.disconnect();
  process.exit(3);
}

const nodes = (await api.query.computeScoring.nodeIdToChild.entries()).map(([k]) => k.args[0].toHex());
if (nodes.length === 0) { console.log('no registered nodes — nothing to close'); await api.disconnect(); process.exit(0); }

// A close is ONE extrinsic and the pallet bounds it: `status_updates` is a
// `BoundedVec<_, MaxMinerStatusUpdatesPerCall>`. The registry, meanwhile, is
// bounded by `MaxChildrenTotal` — a much larger number (128 vs 1000 in the
// runtime Config as written). So a fleet that outgrows the per-call bound
// cannot close an epoch AT ALL.
//
// And it cannot be worked around by splitting the batch: the call ends with
// `CurrentEpoch::put(epoch)` and begins with
// `ensure!(epoch > cur, EpochRegression)`, so a second call for the same
// epoch is refused. One call or nothing.
//
// Left unchecked this surfaces as an opaque codec/BoundedVec failure at
// submission time, on the reward path, the first time the fleet crosses the
// bound — with rewards silently stopped fleet-wide until someone reads the
// pallet source. Read the bound out of metadata (it is a
// `#[pallet::constant]`) and refuse with something an operator can act on.
const maxBatch = api.consts?.computeScoring?.maxMinerStatusUpdatesPerCall;
if (maxBatch && nodes.length > maxBatch.toNumber()) {
  console.error(
    `epoch-close: ${nodes.length} registered node(s) exceeds the pallet's ` +
    `MaxMinerStatusUpdatesPerCall=${maxBatch.toNumber()}. A close is a single ` +
    `extrinsic and CANNOT be split — the call advances CurrentEpoch, so a ` +
    `second batch for the same epoch fails with EpochRegression. Nothing was ` +
    `submitted and NO epoch can close until this is resolved. Fix: raise ` +
    `MaxMinerStatusUpdatesPerCall in the runtime's ` +
    `pallet_compute_scoring::Config (at least to MaxChildrenTotal, so the ` +
    `per-call bound can never be tighter than the registry it must cover), ` +
    `or teach the pallet to accept partial batches and advance CurrentEpoch ` +
    `only on the final one.`
  );
  await api.disconnect();
  process.exit(4);
}

const valiWeights = await fetchValiWeights();
const epoch = (await api.query.computeScoring.currentEpoch()).toNumber() + 1;
// Chain node_ids come 0x-prefixed (toHex); vali keys them as raw hex — strip.
const weightFor = (n) =>
  valiWeights ? BigInt(valiWeights[n.replace(/^0x/, '')] ?? 0) : DEFAULT_WEIGHT;
const updates = nodes.map((nodeId) => ({ nodeId, newStatus: 'Active', weight: weightFor(nodeId) }));
const src = valiWeights ? 'vali (real merit)' : ('flat default=' + DEFAULT_WEIGHT);
console.log(`closing epoch ${epoch} for ${nodes.length} node(s) [weights: ${src}]`);

if (DRY_RUN) {
  // Everything above ran for real — the chain reads, the vali weights
  // fetch, the epoch arithmetic, the per-node mapping. Only the signature
  // and the submission are skipped, so what is printed is what WOULD go
  // on-chain rather than a second implementation's opinion of it.
  const total = updates.reduce((a, u) => a + u.weight, 0n);
  console.log(`DRY RUN — would submit valiSubmitEpochClose(${epoch}, …); NOTHING signed, NOTHING sent`);
  console.log(`  nodes=${updates.length}  total_weight=${total}  weights_source=${src}`);
  for (const u of updates) {
    console.log(`    ${u.nodeId}  status=${u.newStatus}  weight=${u.weight}`);
  }
  await api.disconnect();
  process.exit(0);
}

// Submitted DIRECTLY, not wrapped in `sudo.sudo(...)`.
//
// The wrapper was correct while `valiSubmitEpochClose` was `ensure_root` and
// this key held sudo on the chain we targeted. Neither is true on the
// production chain: the call is gated on the pallet's `AuditAuthorityOrigin`,
// and this key is the pinned authority there but NOT sudo. So the wrapper made
// every close fail `sudo.RequireSudo` — included in a block, then rejected at
// dispatch, which reads like a chain problem rather than a caller one.
const call = api.tx.computeScoring.valiSubmitEpochClose(epoch, updates);
await new Promise((resolve, reject) => {
  call.signAndSend(signer, ({ status, dispatchError }) => {
    if (!status.isInBlock) return;
    console.log(`epoch ${epoch} close included ${status.hash.toHex()} success=${!dispatchError}`);
    if (!dispatchError) return resolve();

    // Decode the refusal into a pallet + error NAME before throwing. The
    // previous `new Error('ExtrinsicFailed')` discarded exactly the field
    // that says WHY, which left a production crash-loop diagnosable only by
    // hand-decoding the event out of the block.
    let why = dispatchError.toString();
    if (dispatchError.isModule) {
      try {
        const d = api.registry.findMetaError(dispatchError.asModule);
        why = `${d.section}.${d.name}${d.docs?.length ? ` — ${d.docs.join(' ').trim()}` : ''}`;
      } catch (e) {
        why = `undecodable module error ${dispatchError.asModule.toString()} (${e})`;
      }
    }
    console.error(`epoch ${epoch} close REFUSED: ${why}`);
    reject(new Error(`ExtrinsicFailed: ${why}`));
  }).catch(reject);
});
await api.disconnect();
process.exit(0);
