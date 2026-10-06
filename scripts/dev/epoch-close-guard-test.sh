#!/usr/bin/env bash
# epoch-close-guard-test.sh — run the REAL close-epoch.mjs against a stubbed
# @polkadot/api and assert its refusal gates.
#
# The closer had no tests at all, and it sits on the reward path: everything it
# decides is decided once, in production, with a sudo key loaded. The two gates
# that matter are both refusals — "the pallet is gone" (exit 3) and "the fleet
# outgrew the per-call batch bound" (exit 4) — and a refusal that silently stops
# refusing is invisible until the day it was supposed to fire.
#
# Method: copy the real script into a temp tree whose node_modules holds stub
# @polkadot packages, then run it. Node resolves bare specifiers relative to the
# importing FILE, so the copy picks up the stubs. Nothing is mocked inside the
# script itself — the code under test is byte-identical to what ships.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/../../deploy/epoch-closer/close-epoch.mjs"
[[ -f "${SCRIPT}" ]] || { echo "epoch-close-guard-test: missing ${SCRIPT}"; exit 1; }

FAILED=0
ok()  { echo "epoch-close-guard-test: OK — $1"; }
bad() { echo "epoch-close-guard-test: FAIL — $1"; FAILED=1; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# ── stub @polkadot/* ────────────────────────────────────────────────────────
# NODE_COUNT / MAX_BATCH / PALLET_PRESENT drive the fake chain. `signAndSend`
# writes a marker file: any test that reaches it has let a submission through,
# which for a refusal test is the whole failure.
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
const NODES = Number(process.env.STUB_NODE_COUNT || '3');
const MAX = process.env.STUB_MAX_BATCH;           // unset ⇒ const absent
const PRESENT = process.env.STUB_PALLET_PRESENT !== '0';
const MARKER = process.env.STUB_SUBMIT_MARKER;

const entries = Array.from({ length: NODES }, (_, i) => {
  const hex = '0x' + i.toString(16).padStart(64, '0');
  return [{ args: [{ toHex: () => hex }] }];
});

const computeScoringQuery = {
  nodeIdToChild: { entries: async () => entries },
  currentEpoch: async () => ({ toNumber: () => 5002 }),
};

const api = {
  runtimeVersion: { specName: { toString: () => 'hippius' }, specVersion: { toString: () => '9199' } },
  query: PRESENT ? { computeScoring: computeScoringQuery } : {},
  tx: PRESENT ? {
    computeScoring: { valiSubmitEpochClose: (...a) => ({ kind: 'close', a }) },
    sudo: {
      sudo: (inner) => ({
        signAndSend: async () => {
          if (MARKER) fs.writeFileSync(MARKER, 'SUBMITTED');
          throw new Error('stub: submission attempted');
        },
      }),
    },
  } : {},
  consts: MAX === undefined ? {} : {
    computeScoring: { maxMinerStatusUpdatesPerCall: { toNumber: () => Number(MAX) } },
  },
  events: { system: { ExtrinsicFailed: { is: () => false } } },
  disconnect: async () => {},
};

export class WsProvider { constructor() {} }
export const ApiPromise = { create: async () => api };
STUB

cat > "${WORK}/node_modules/@polkadot/keyring/index.js" <<'STUB'
export class Keyring { constructor() {} addFromMnemonic() { return { address: '5Stub' }; } }
STUB

cat > "${WORK}/node_modules/@polkadot/util-crypto/index.js" <<'STUB'
export const cryptoWaitReady = async () => true;
STUB

cp "${SCRIPT}" "${WORK}/close-epoch.mjs"
printf '{ "type": "module" }\n' > "${WORK}/package.json"
echo "//stub-mnemonic" > "${WORK}/key"

# run <name> -> sets RC and OUT
run() {
  set +e
  OUT="$(cd "${WORK}" && env \
    THEBRAIN_RPC_URL="ws://stub" \
    EPOCH_CLOSE_KEY_FILE="${WORK}/key" \
    "$@" node close-epoch.mjs 2>&1)"
  RC=$?
  set -e
}

MARKER="${WORK}/submitted"

# ── 1. over the bound ⇒ refuse, exit 4, NOTHING submitted ───────────────────
rm -f "${MARKER}"
run STUB_NODE_COUNT=200 STUB_MAX_BATCH=128 STUB_SUBMIT_MARKER="${MARKER}"
[[ "${RC}" == "4" ]] \
  && ok "200 nodes vs bound 128 ⇒ exit 4" \
  || bad "200 nodes vs bound 128 should exit 4, got ${RC}: ${OUT}"
[[ -f "${MARKER}" ]] \
  && bad "a submission was attempted despite exceeding the bound" \
  || ok "nothing was submitted when the bound was exceeded"
grep -q 'MaxMinerStatusUpdatesPerCall=128' <<<"${OUT}" \
  && ok "the refusal names the actual bound" \
  || bad "the refusal does not name the bound: ${OUT}"
grep -q 'CANNOT be split' <<<"${OUT}" \
  && ok "the refusal says splitting is impossible (EpochRegression)" \
  || bad "the refusal omits why splitting cannot work: ${OUT}"

# ── 2. exactly AT the bound ⇒ allowed (off-by-one) ──────────────────────────
run STUB_NODE_COUNT=128 STUB_MAX_BATCH=128 EPOCH_CLOSE_DRY_RUN=1
[[ "${RC}" == "0" ]] \
  && ok "exactly 128 nodes at bound 128 is allowed (not off-by-one)" \
  || bad "128 == bound should be allowed, got ${RC}: ${OUT}"

# ── 3. under the bound ⇒ proceeds ───────────────────────────────────────────
run STUB_NODE_COUNT=3 STUB_MAX_BATCH=128 EPOCH_CLOSE_DRY_RUN=1
[[ "${RC}" == "0" ]] && grep -q 'DRY RUN' <<<"${OUT}" \
  && ok "3 nodes under bound 128 proceeds to the dry run" \
  || bad "3 nodes should proceed, got ${RC}: ${OUT}"

# ── 4. the guard fires in DRY RUN too ───────────────────────────────────────
# A dry run is what an operator uses to decide whether to resume. If it reports
# a clean payload the real run cannot submit, it has actively misled them.
run STUB_NODE_COUNT=200 STUB_MAX_BATCH=128 EPOCH_CLOSE_DRY_RUN=1
[[ "${RC}" == "4" ]] \
  && ok "the dry run refuses too, rather than printing a payload that cannot submit" \
  || bad "dry run should also exit 4, got ${RC}: ${OUT}"

# ── 5. no constant in metadata ⇒ do NOT invent a bound ──────────────────────
# An older runtime may not expose it. Guessing a limit would stop a close that
# would have succeeded; the guard must simply not fire.
run STUB_NODE_COUNT=200 EPOCH_CLOSE_DRY_RUN=1
[[ "${RC}" == "0" ]] \
  && ok "absent constant ⇒ the guard stays out of the way" \
  || bad "absent constant should not block, got ${RC}: ${OUT}"

# ── 6. the pre-existing exit-3 gate still fires ─────────────────────────────
run STUB_PALLET_PRESENT=0
[[ "${RC}" == "3" ]] \
  && ok "pallet absent from the runtime still exits 3" \
  || bad "missing pallet should exit 3, got ${RC}: ${OUT}"

[[ "${FAILED}" == "0" ]] && echo "epoch-close-guard-test: ALL OK" || echo "epoch-close-guard-test: FAILURES"
exit "${FAILED}"
