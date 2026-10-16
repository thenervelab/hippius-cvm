#!/usr/bin/env bash
# price-keeper-test.sh — run the REAL apply-prices.mjs against a stubbed
# @polkadot/api and assert what it submits, skips, refuses and reports.
#
# Same method as epoch-close-guard-test.sh: copy the shipped script into a
# temp tree whose node_modules holds stub @polkadot packages (Node resolves
# bare specifiers relative to the importing file), so the code under test is
# byte-identical to what the image runs. The fake chain is a JSON file
# (STUB_STATE); every signAndSend appends the node id to STUB_SUBMIT_LOG, and
# a throwaway HTTP server stands in for the Pushgateway.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${HERE}/../.."
SCRIPT="${ROOT}/deploy/epoch-closer/apply-prices.mjs"
[[ -f "${SCRIPT}" ]] || { echo "price-keeper-test: missing ${SCRIPT}"; exit 1; }

FAILED=0
ok()  { echo "price-keeper-test: OK — $1"; }
bad() { echo "price-keeper-test: FAIL — $1"; FAILED=1; }

WORK="$(mktemp -d)"
PGW_PID=""
cleanup() {
  if [[ -n "${PGW_PID}" ]]; then kill "${PGW_PID}" 2>/dev/null || true; fi
  rm -rf "${WORK}"
}
trap cleanup EXIT

# ── the image must ship the script the CronJob runs ─────────────────────────
grep -Eq '^COPY .*\bapply-prices\.mjs\b' "${ROOT}/deploy/epoch-closer/Dockerfile" \
  && ok "the epoch-closer Dockerfile ships apply-prices.mjs" \
  || bad "the epoch-closer Dockerfile does not COPY apply-prices.mjs"

# ── stub @polkadot/* ────────────────────────────────────────────────────────
mkdir -p "${WORK}/node_modules/@polkadot/api" \
         "${WORK}/node_modules/@polkadot/keyring" \
         "${WORK}/node_modules/@polkadot/util-crypto"
for pkg in api keyring util-crypto; do
  cat > "${WORK}/node_modules/@polkadot/${pkg}/package.json" <<EOF
{ "name": "@polkadot/${pkg}", "version": "0.0.0-stub", "type": "module", "main": "index.js" }
EOF
done

cat > "${WORK}/node_modules/@polkadot/api/index.js" <<'STUB'
import fs from 'fs';
// STUB_STATE: { head, free, fee, pallet, sudo, children[], pending[{node,price,eff}],
//               hang[] (never included), dropped[] (dropped from the pool),
//               discard[] (pallet emits PendingPriceDiscarded), crashOnReread,
//               hangRead (system.number never answers), vanish[] (gone at the re-read), reannounce{node: eff} (a later
//               change at the re-read), errors{node: "section.Name"} }
const S = JSON.parse(fs.readFileSync(process.env.STUB_STATE, 'utf8'));
const LOG = process.env.STUB_SUBMIT_LOG;
const big = (n) => ({ toBigInt: () => BigInt(n) });
const hex = (h) => ({ toHex: () => h });
const some = (v) => ({ isSome: true, unwrap: () => v });
const none = { isSome: false, unwrap: () => { throw new Error('none'); } };
const id = (n) => '0x' + String(n).padStart(64, '0');
let free = BigInt(S.free ?? '10000000000000000000');
const fee = BigInt(S.fee ?? '1000');
const pending = (S.pending || []).map((p) => ({ node: id(p.node), price: p.price, eff: p.eff }));
const change = (p) => some({ newPrice: big(p.price), effectiveBlock: big(p.eff) });

const computeScoring = {
  nodeIdToChild: { entries: async () => (S.children || []).map((c, i) => [{ args: [hex(id(900 + i))] }, some(hex(c))]) },
  pendingPriceChange: Object.assign(
    async (node) => {
      if (S.crashOnReread) throw new Error('stub: RPC connection lost');
      if ((S.vanish || []).map(id).includes(node)) return none;
      const re = (S.reannounce || {})[String(BigInt(node))];
      if (re !== undefined) return change({ price: '1', eff: re });
      const p = pending.find((x) => x.node === node);
      return p ? change(p) : none;
    },
    { entries: async () => pending.map((p) => [{ args: [hex(p.node)] }, change(p)]) },
  ),
};

const api = {
  runtimeVersion: { specName: { toString: () => 'hippius' }, specVersion: { toString: () => '92019' } },
  query: {
    system: {
      number: () => (S.hangRead ? new Promise(() => {}) : Promise.resolve(big(S.head))),
      account: async () => ({ data: { free: big(free) } }),
    },
    ...(S.sudo ? { sudo: { key: async () => some(hex(S.sudo)) } } : {}),
    ...(S.pallet === false ? {} : { computeScoring }),
  },
  tx: S.pallet === false ? {} : {
    computeScoring: {
      applyPriceChange: (node) => ({
        paymentInfo: async () => ({ partialFee: big(fee) }),
        signAndSend: (_signer, cb) => {
          fs.appendFileSync(LOG, node + '\n');
          if ((S.hang || []).map(id).includes(node)) return Promise.resolve(() => {});
          if ((S.dropped || []).map(id).includes(node)) {
            cb({ status: { isDropped: true, type: 'Dropped' } });
            return Promise.resolve(() => {});
          }
          free -= fee;
          const err = (S.errors || {})[String(BigInt(node))];
          const dispatchError = err
            ? { isModule: true, asModule: { toString: () => err }, toString: () => err }
            : undefined;
          cb({ status: { isInBlock: false } });
          const events = (S.discard || []).map(id).includes(node) ? [{ event: { discarded: true } }] : [{ event: {} }];
          cb({ status: { isInBlock: true, asInBlock: hex('0xb10c') }, dispatchError, events });
          return Promise.resolve(() => {});
        },
      }),
    },
  },
  events: { computeScoring: { PendingPriceDiscarded: { is: (e) => e.discarded === true } } },
  registry: {
    findMetaError: (m) => {
      const [section, name] = m.toString().split('.');
      return { section, name, docs: [] };
    },
  },
  disconnect: async () => {},
};

export class WsProvider { constructor() {} }
export const ApiPromise = { create: async () => api };
STUB

cat > "${WORK}/node_modules/@polkadot/keyring/index.js" <<'STUB'
export class Keyring {
  constructor() {}
  addFromMnemonic() { return { address: '5Stub', publicKey: new Uint8Array(32).fill(0xaa) }; }
}
STUB
cat > "${WORK}/node_modules/@polkadot/util-crypto/index.js" <<'STUB'
export const cryptoWaitReady = async () => true;
// Hex only: the tests pass forbidden accounts as 0x public keys.
export const decodeAddress = (a) => {
  if (!/^0x[0-9a-f]{64}$/.test(a)) throw new Error(`stub cannot decode ${a}`);
  return Uint8Array.from(Buffer.from(a.slice(2), 'hex'));
};
STUB

cp "${SCRIPT}" "${WORK}/apply-prices.mjs"
printf '{ "type": "module" }\n' > "${WORK}/package.json"
echo "//stub-mnemonic" > "${WORK}/key"
SIGNER="0x$(printf 'aa%.0s' $(seq 32))"

# ── a Pushgateway stand-in: each request is written to PUSHED ───────────────
PUSHED="${WORK}/pushed"
cat > "${WORK}/pgw.cjs" <<'PGW'
const http = require('http'); const fs = require('fs');
const srv = http.createServer((req, res) => {
  let b = ''; req.on('data', (c) => { b += c; });
  req.on('end', () => { fs.writeFileSync(process.argv[2], req.method + ' ' + req.url + '\n' + b); res.end(); });
});
srv.listen(0, '127.0.0.1', () => fs.writeFileSync(process.argv[3], String(srv.address().port)));
PGW
node "${WORK}/pgw.cjs" "${PUSHED}" "${WORK}/port" & PGW_PID=$!
for _ in $(seq 50); do [[ -s "${WORK}/port" ]] && break; sleep 0.1; done
[[ -s "${WORK}/port" ]] || { echo "price-keeper-test: Pushgateway stand-in did not start"; exit 1; }
PGW_URL="http://127.0.0.1:$(cat "${WORK}/port")"

LOG="${WORK}/submitted"
# run <state-json> [ENV=VAL ...] -> RC, OUT; resets the submit log + push file
run() {
  local state="$1"; shift
  printf '%s' "${state}" > "${WORK}/state.json"
  rm -f "${LOG}" "${PUSHED}"; touch "${LOG}"
  set +e
  OUT="$(cd "${WORK}" && env \
    THEBRAIN_RPC_URL="ws://stub" \
    PRICE_KEEPER_KEY_FILE="${WORK}/key" \
    PRICE_KEEPER_PUSHGATEWAY_URL="${PGW_URL}" \
    STUB_STATE="${WORK}/state.json" \
    STUB_SUBMIT_LOG="${LOG}" \
    "$@" node apply-prices.mjs 2>&1)"
  RC=$?
  set -e
}
# Submitted node ids in order, as plain integers ("2 1").
submitted() { sed 's/^0x0*//' "${LOG}" | tr '\n' ' ' | sed 's/ $//'; }
metric() { awk -v m="$1" '$1 == m { print $2 }' "${PUSHED}" 2>/dev/null || true; }

TWO_DUE='{"head":100,"pending":[{"node":2,"price":"7","eff":90},{"node":1,"price":"5","eff":95},{"node":3,"price":"9","eff":150}]}'

# ── 1. due changes are applied oldest-first; a future one is left alone ─────
run "${TWO_DUE}"
[[ "${RC}" == "0" ]] && ok "two due changes ⇒ exit 0" || bad "expected exit 0, got ${RC}: ${OUT}"
[[ "$(submitted)" == "2 1" ]] \
  && ok "applied exactly the due nodes, oldest effective block first" \
  || bad "expected submissions '2 1', got '$(submitted)'"
[[ "$(metric hippius_price_keeper_applied)" == "2" && "$(metric hippius_price_keeper_due)" == "2" && "$(metric hippius_price_keeper_success)" == "1" ]] \
  && ok "pushed applied=2 due=2 success=1" \
  || bad "metrics wrong: $(cat "${PUSHED}" 2>/dev/null)"
head -1 "${PUSHED}" | grep -q '^PUT /metrics/job/price-keeper$' \
  && ok "metrics PUT to job=price-keeper" \
  || bad "unexpected push target: $(head -1 "${PUSHED}" 2>/dev/null)"
[[ "$(metric hippius_price_keeper_free_balance_planck)" == "9999999999999998000" && "$(metric hippius_price_keeper_min_balance_planck)" == "2000000000000000000" ]] \
  && ok "post-run balance and reserve gauges pushed" \
  || bad "balance/reserve gauges wrong: $(cat "${PUSHED}")"

# ── 2. effective_block == head is due (the pallet admits now >= effective) ──
run '{"head":100,"pending":[{"node":4,"price":"3","eff":100},{"node":5,"price":"3","eff":101}]}'
[[ "$(submitted)" == "4" ]] \
  && ok "effective_block == head is applied, head+1 is not" \
  || bad "boundary wrong: submitted '$(submitted)'"

# ── 3. per-run cap ──────────────────────────────────────────────────────────
run "${TWO_DUE}" PRICE_KEEPER_MAX_PER_RUN=1
[[ "${RC}" == "0" && "$(submitted)" == "2" && "$(metric hippius_price_keeper_remaining)" == "1" ]] \
  && ok "cap 1 ⇒ one applied, remaining=1, exit 0" \
  || bad "cap: rc=${RC} submitted='$(submitted)' remaining=$(metric hippius_price_keeper_remaining)"

# ── 4. gone at the re-read ⇒ skipped, never submitted ───────────────────────
run '{"head":100,"pending":[{"node":2,"price":"7","eff":90},{"node":1,"price":"5","eff":95}],"vanish":[2]}'
[[ "${RC}" == "0" && "$(submitted)" == "1" && "$(metric hippius_price_keeper_skipped)" == "1" ]] \
  && ok "a change resolved before the re-read is skipped, not submitted" \
  || bad "vanish: rc=${RC} submitted='$(submitted)' skipped=$(metric hippius_price_keeper_skipped)"

# ── 4b. re-announced with a later effective block ⇒ no longer due, skipped ──
run '{"head":100,"pending":[{"node":2,"price":"7","eff":90},{"node":1,"price":"5","eff":95}],"reannounce":{"2":180}}'
[[ "${RC}" == "0" && "$(submitted)" == "1" && "$(metric hippius_price_keeper_skipped)" == "1" ]] \
  && ok "a change re-announced past head at the re-read is skipped" \
  || bad "reannounce: rc=${RC} submitted='$(submitted)' ${OUT}"

# ── 5. lost the race at dispatch (NoPriceChangeDue) ⇒ skipped, exit 0 ───────
run '{"head":100,"pending":[{"node":2,"price":"7","eff":90}],"errors":{"2":"computeScoring.NoPriceChangeDue"}}'
[[ "${RC}" == "0" && "$(metric hippius_price_keeper_skipped)" == "1" && "$(metric hippius_price_keeper_failed)" == "0" && "$(metric hippius_price_keeper_success)" == "1" ]] \
  && ok "NoPriceChangeDue at dispatch counts as already applied" \
  || bad "race: rc=${RC} ${OUT}"

# ── 6. any other refusal ⇒ failed, exit 1, success=0, the rest still tried ──
run '{"head":100,"pending":[{"node":2,"price":"7","eff":90},{"node":1,"price":"5","eff":95}],"errors":{"2":"balances.InsufficientBalance"}}'
[[ "${RC}" == "1" && "$(submitted)" == "2 1" && "$(metric hippius_price_keeper_failed)" == "1" && "$(metric hippius_price_keeper_success)" == "0" ]] \
  && ok "a refused apply ⇒ exit 1, failed=1, success=0, later nodes still applied" \
  || bad "refusal: rc=${RC} submitted='$(submitted)' ${OUT}"
grep -q 'balances.InsufficientBalance' <<<"${OUT}" \
  && ok "the refusal is decoded to pallet.error" \
  || bad "refusal not named: ${OUT}"

# ── 6b. never included ⇒ failed after the inclusion timeout, run continues ──
run '{"head":100,"pending":[{"node":2,"price":"7","eff":90},{"node":1,"price":"5","eff":95}],"hang":[2]}' PRICE_KEEPER_INCLUSION_TIMEOUT_S=1
[[ "${RC}" == "1" && "$(submitted)" == "2 1" && "$(metric hippius_price_keeper_failed)" == "1" && "$(metric hippius_price_keeper_applied)" == "1" ]] \
  && ok "an apply never included times out as failed; the next one still runs" \
  || bad "hang: rc=${RC} submitted='$(submitted)' ${OUT}"

# ── 6c. dropped from the pool ⇒ failed at once, not after the timeout ──────
SECONDS=0
run '{"head":100,"pending":[{"node":2,"price":"7","eff":90}],"dropped":[2]}' PRICE_KEEPER_INCLUSION_TIMEOUT_S=30
[[ "${RC}" == "1" && "$(metric hippius_price_keeper_failed)" == "1" && "${SECONDS}" -lt 20 ]] && grep -q 'transaction Dropped' <<<"${OUT}" \
  && ok "a dropped transaction fails immediately" \
  || bad "dropped: rc=${RC} after ${SECONDS}s ${OUT}"

# ── 6d. the pallet discards an out-of-bounds change ⇒ discarded, not applied ─
run '{"head":100,"pending":[{"node":2,"price":"7","eff":90},{"node":1,"price":"5","eff":95}],"discard":[2]}'
[[ "${RC}" == "0" && "$(metric hippius_price_keeper_discarded)" == "1" && "$(metric hippius_price_keeper_applied)" == "1" ]] && grep -q 'DISCARDED' <<<"${OUT}" \
  && ok "PendingPriceDiscarded is reported as discarded, not applied" \
  || bad "discard: rc=${RC} ${OUT}"

# ── 6e. a chain read failing mid-run still pushes success=0 ─────────────────
run '{"head":100,"pending":[{"node":2,"price":"7","eff":90}],"crashOnReread":true}'
[[ "${RC}" == "1" && "$(metric hippius_price_keeper_success)" == "0" && -z "$(submitted)" ]] \
  && ok "a crash mid-run exits 1 and pushes success=0" \
  || bad "crash: rc=${RC} success=$(metric hippius_price_keeper_success) ${OUT}"

# ── 6f. a hung RPC ends at the run timeout with success=0 pushed ────────────
run '{"head":100,"hangRead":true}' PRICE_KEEPER_RUN_TIMEOUT_S=1
[[ "${RC}" == "1" && "$(metric hippius_price_keeper_success)" == "0" ]] \
  && ok "a hung run times out, exits 1 and pushes success=0" \
  || bad "run timeout: rc=${RC} ${OUT}"

# ── 7. balance reserve ⇒ nothing submitted, exit 5 ──────────────────────────
run '{"head":100,"free":"2000000000000000500","fee":"1000","pending":[{"node":2,"price":"7","eff":90}]}'
[[ "${RC}" == "5" && -z "$(submitted)" && "$(metric hippius_price_keeper_remaining)" == "1" && "$(metric hippius_price_keeper_success)" == "0" ]] \
  && ok "a fee that would dip under the reserve ⇒ nothing sent, exit 5" \
  || bad "reserve: rc=${RC} submitted='$(submitted)' ${OUT}"

# ── 8. fee budget ⇒ stop, exit 0, backlog reported ──────────────────────────
run "${TWO_DUE}" PRICE_KEEPER_FEE_BUDGET_PLANCK=1500
[[ "${RC}" == "0" && "$(submitted)" == "2" && "$(metric hippius_price_keeper_remaining)" == "1" ]] \
  && ok "fee budget for one apply ⇒ one sent, remaining=1" \
  || bad "budget: rc=${RC} submitted='$(submitted)' ${OUT}"

# ── 9. the signer is the sudo key ⇒ refuse, nothing sent ────────────────────
run "{\"head\":100,\"sudo\":\"${SIGNER}\",\"pending\":[{\"node\":2,\"price\":\"7\",\"eff\":90}]}"
[[ "${RC}" == "6" && -z "$(submitted)" ]] \
  && ok "sudo key as signer ⇒ exit 6, nothing sent" \
  || bad "sudo guard: rc=${RC} submitted='$(submitted)' ${OUT}"

# ── 10. the signer is a registered miner ⇒ refuse, nothing sent ─────────────
run "{\"head\":100,\"children\":[\"0x01\",\"${SIGNER}\"],\"pending\":[{\"node\":2,\"price\":\"7\",\"eff\":90}]}"
[[ "${RC}" == "6" && -z "$(submitted)" ]] \
  && ok "a miner key as signer ⇒ exit 6, nothing sent" \
  || bad "miner guard: rc=${RC} submitted='$(submitted)' ${OUT}"

# ── 10b. the signer is a forbidden account (the audit authority) ⇒ refuse ──
OTHER="0x$(printf 'bb%.0s' $(seq 32))"
run "${TWO_DUE}" PRICE_KEEPER_FORBIDDEN_ACCOUNTS="${OTHER}, ${SIGNER}"
[[ "${RC}" == "6" && -z "$(submitted)" ]] \
  && ok "a forbidden account as signer ⇒ exit 6, nothing sent" \
  || bad "forbidden guard: rc=${RC} submitted='$(submitted)' ${OUT}"
run "${TWO_DUE}" PRICE_KEEPER_FORBIDDEN_ACCOUNTS="${OTHER}"
[[ "${RC}" == "0" && "$(submitted)" == "2 1" ]] \
  && ok "a forbidden list without the signer ⇒ the keeper runs" \
  || bad "forbidden false refusal: rc=${RC} ${OUT}"
run "${TWO_DUE}" PRICE_KEEPER_FORBIDDEN_ACCOUNTS="not-an-account"
[[ "${RC}" == "2" && -z "$(submitted)" ]] \
  && ok "an undecodable forbidden account ⇒ exit 2" \
  || bad "forbidden decode: rc=${RC} ${OUT}"

# ── 11. unrelated sudo / miner keys do not trip the guards ──────────────────
run '{"head":100,"sudo":"0x01","children":["0x02"],"pending":[{"node":2,"price":"7","eff":90}]}'
[[ "${RC}" == "0" && "$(submitted)" == "2" ]] \
  && ok "unrelated sudo/miner keys ⇒ the keeper runs" \
  || bad "false refusal: rc=${RC} ${OUT}"

# ── 12. pallet absent ⇒ exit 3 ──────────────────────────────────────────────
run '{"head":100,"pallet":false}'
[[ "${RC}" == "3" && -z "$(submitted)" ]] \
  && ok "pallet absent ⇒ exit 3" \
  || bad "pallet absent: rc=${RC} ${OUT}"

# ── 13. dry run ⇒ lists, sends nothing, pushes nothing ──────────────────────
run "${TWO_DUE}" PRICE_KEEPER_DRY_RUN=1
[[ "${RC}" == "0" && -z "$(submitted)" && ! -e "${PUSHED}" ]] && grep -q 'DRY RUN' <<<"${OUT}" \
  && ok "dry run ⇒ nothing signed, sent or pushed" \
  || bad "dry run: rc=${RC} submitted='$(submitted)' ${OUT}"

# ── 14. env errors ⇒ exit 2 ─────────────────────────────────────────────────
run "${TWO_DUE}" PRICE_KEEPER_MAX_PER_RUN=ten
[[ "${RC}" == "2" && -z "$(submitted)" ]] \
  && ok "malformed number ⇒ exit 2" \
  || bad "malformed env: rc=${RC} ${OUT}"
run "${TWO_DUE}" PRICE_KEEPER_KEY_FILE=
[[ "${RC}" == "2" ]] \
  && ok "missing key file env ⇒ exit 2" \
  || bad "missing env: rc=${RC} ${OUT}"

[[ "${FAILED}" == "0" ]] && echo "price-keeper-test: ALL OK" || echo "price-keeper-test: FAILURES"
exit "${FAILED}"
