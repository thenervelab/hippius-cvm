# hippius-sentinel

Read-only LLM observability + security agent for the hippius-compute
control plane. Full §S scope is tracked in
[issue #57](https://github.com/thenervelab/hippius-compute/issues/57)
— **read it first**. This README only covers what PR-S1 actually ships.

## What's shipped so far

### PR-S1 — skeleton

- Python 3.12 package using
  [`claude-agent-sdk`](https://github.com/anthropics/claude-agent-sdk-python).
- Dummy MCP tool `hello_kbs`, asyncio agent loop in `sentinel.main`,
  stdlib `/healthz` on `:8080` for the k8s liveness probe.
- Locked-down `ClaudeAgentOptions`: only sentinel MCP tools are
  pre-approved (`allowed_tools`) and every Claude Code built-in that
  could mutate state is explicitly denied (`disallowed_tools`).
- Dockerfile + Kustomize base at `deploy/kustomize/base/sentinel/`.

### PR-S2 — KBS audit reader + external attestation anchor

- `sentinel/tools/kbs_audit.py`: Python re-implementation of
  `kbs_core::audit::walk_log`. Two MCP tools — `verify_kbs_audit_chain`
  (walks + reconciles `head.sha256`) and `read_kbs_audit_tail(n=100)`
  (verifies first, then returns the last N decoded records). Refuses
  to return data on any tamper detection.
- `sentinel/tools/anchor.py`: MCP tool `publish_audit_anchor` (and
  background `_anchor_loop` task in `sentinel.main`) that signs the
  `(timestamp, record_count, head)` tuple via Vault transit
  (`/transit/keys/sentinel-anchor`, Ed25519, key never leaves Vault)
  and PUTs an immutable artefact into the Hippius S3 `audit-anchors`
  bucket under Object Lock COMPLIANCE retention. Closes the §15
  external-attestation gap documented in `kbs-core/src/audit.rs`.
- Cross-impl witness fixture: `cargo run --example audit_fixture --` emits
  a real Rust-produced `audit.log` + `head.sha256` under
  `sentinel/tests/fixtures/audit_known_good/`. The Python verifier is
  tested against that fixture so any drift between the Rust producer
  and the Python consumer is caught immediately.

Reader tools for Vault audit, analytics rules, output channels
(GitHub issues / Slack / daily summary), and prompt engineering all
land in PR-S4..PR-S6 per the breakdown in #57.

### PR-S3 — vali Postgres + thebrain RPC + NetBird readers

- `sentinel/tools/vali_postgres.py`: read-only Postgres reader. Three
  MCP tools — `query_vm_state(vm_id)`, `count_pending_tickets()`,
  `list_recent_state_transitions(limit=50)`. Connection is opened with
  `default_transaction_read_only=on` as a belt-and-suspenders against
  a misconfigured DSN. Pending-tickets proxy = OrderTicketIntake rows
  whose `vm_id` has no `lifecycle_vm` row and whose `expiry` is in the
  future, until PR-G5+ adds an explicit ticket-state column.
- `sentinel/tools/thebrain_rpc.py`: hand-rolled Substrate JSON-RPC
  reader (no `py-substrate-interface` dependency). Three MCP tools —
  `read_current_epoch()`, `read_miner_status(node_id)`,
  `read_epoch_weights(epoch)`. Uses `state_getStorage` +
  `state_getKeysPaged`; `xxhash` for `twox128` and `hashlib.blake2b`
  for `Blake2_128Concat`. BlockNumber width configurable via
  `THEBRAIN_BLOCK_NUMBER_BITS` (default 32).
- `sentinel/tools/netbird.py`: NetBird API reader. Two MCP tools —
  `list_peers()`, `get_peer_status(peer_id)`. PAT auth via
  `NETBIRD_API_TOKEN`, base URL configurable via `NETBIRD_API_BASE`.
  Each peer is projected down to a small allowlist of fields to keep
  the LLM prompt window small.

## Posture (locked decisions, see #57)

- **Anthropic API direct** (posture 1, locked 2026-05-20). Accepts
  Anthropic's SOC2 + zero-retention as adequate for the operational IDs
  we ship. No plaintext secrets ever leave the control plane.
- **Strict read-only**. The agent has zero write paths to KBS, vali,
  the chain, Vault, NetBird, or the allowlist. Outputs in PR-S5 will
  be limited to GitHub Issues, Slack, and the Hippius S3
  `audit-anchors` bucket — never back into the systems it observes.
- **No service-account token mount** on the pod. The sentinel does not
  need kube-apiserver access for PR-S1.

## Layout

```
sentinel/
├── sentinel/
│   ├── agent.py        # ClaudeAgentOptions + MCP server wiring
│   ├── healthz.py      # stdlib HTTP /healthz on :8080
│   ├── main.py         # console-script entrypoint, loop driver
│   └── tools/
│       ├── __init__.py
│       ├── hello.py    # dummy hello_kbs tool (PR-S1 smoke test)
│       ├── kbs_audit.py      # walk_log / verify_chain / read_tail (PR-S2)
│       ├── anchor.py         # publish_anchor → Vault sign → S3 Object Lock (PR-S2)
│       ├── vali_postgres.py  # vm state + pending tickets + transitions (PR-S3)
│       ├── thebrain_rpc.py   # CurrentEpoch + MinerStatuses + EpochWeights (PR-S3)
│       └── netbird.py        # list_peers + get_peer_status (PR-S3)
├── tests/
│   ├── _audit_builder.py
│   ├── fixtures/audit_known_good/   # committed Rust-produced chain
│   ├── test_agent_loop.py
│   ├── test_anchor.py
│   ├── test_kbs_audit.py
│   ├── test_netbird.py
│   ├── test_thebrain_rpc.py
│   └── test_vali_postgres.py
├── conftest.py
├── pyproject.toml
├── Dockerfile
└── README.md           # you are here
```

## Local dev

```sh
cd sentinel
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Tests run offline — the SDK client is stubbed.
.venv/bin/pytest

# Optional: live smoke against the Anthropic API.
export SENTINEL_ANTHROPIC_API_KEY=sk-ant-...
.venv/bin/hippius-sentinel
```

## Container

Built for `linux/amd64` to match the RKE2 cluster (see global infra
notes in `~/.claude/CLAUDE.md`):

```sh
docker buildx build \
  --platform linux/amd64 \
  -t <YOUR_REGISTRY>/hippius-sentinel:pr-s1-skeleton \
  sentinel/
```

## Deploy

The following secrets must exist in the `hippius-sentinel` namespace
before applying the base manifest — the sentinel pod refuses to boot
without them:

- `sentinel-anthropic-api-key` (key `api-key`) — Anthropic API key.
- `sentinel-vault` (keys `addr`, `token`, optional `transit-mount`) —
  Vault transit endpoint for the `sentinel-anchor` Ed25519 signing key.
- `sentinel-s3` (keys `bucket`, `access-key-id`, `secret-access-key`,
  optional `endpoint-url`, optional `region`) — Hippius S3 audit-anchors
  bucket credentials. The bucket MUST have Object Lock enabled at
  creation time (S3 cannot enable Object Lock post-hoc).

And one shared volume:

- A `kbs-audit-log` PVC backed by `ceph-filesystem` (RWX) bound by the
  KBS pod's audit-log writer. Sentinel mounts it read-only at
  `/var/lib/kbs/audit`.

```sh
kubectl kustomize deploy/kustomize/base/sentinel | kubectl apply -f -
```

## Regenerating the Rust audit fixture

The committed `sentinel/tests/fixtures/audit_known_good/` is the
cross-implementation witness between `kbs-core::audit` and the Python
verifier. Regenerate it any time the audit-record schema changes
(which means the Python verifier also changes):

```sh
cargo run --example audit_fixture -- sentinel/tests/fixtures/audit_known_good
rm sentinel/tests/fixtures/audit_known_good/audit.lock  # transient
```

The Python tests then need their expected head hex constant
(`KNOWN_GOOD_HEAD_HEX` in `tests/test_kbs_audit.py`) updated to match
the new output.
