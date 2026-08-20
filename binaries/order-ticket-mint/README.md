# `hippius-order-ticket-mint`

Operator tool that mints L1-signed `OrderTicket` COSE_Sign1 envelopes
(ARCHITECTURE.md §6).

Counterpart to the KBS verifier `kbs_core::ticket::verify_order_ticket`
— the two MUST agree byte-exactly on the wire shape. This binary
takes the verifier's constraints as its source of truth and emits
envelopes the KBS will accept.

## Wire shape

- **Body**: canonical-CBOR map per RFC 8949 §4.2.1 — sorted-by-encoded-
  key, no duplicate keys, built via `hippius_types::cbor::to_canonical_vec`.
  Schema: `hippius_types::ticket::OrderTicket` (`SCHEMA_V = 1`,
  `deny_unknown_fields`).
- **Envelope**: COSE_Sign1 with `alg = EdDSA` + the operator-supplied
  `kid` in the (canonically-encoded) protected header. Signature is
  Ed25519 over the COSE `Sig_structure`.
- **Output**: raw bytes — `--out FILE` writes to disk, no flag streams
  to stdout.

## Constraints (refuse-at-mint mirroring the verifier)

The verifier already rejects an out-of-shape ticket; we re-check the
same invariants at mint time so a typo'd flag fails locally with a
clear message before the operator pipes bytes into vali.

- `v == 1` (set automatically — `SCHEMA_V`)
- `nonce.len() == 32` (default: 32 fresh random bytes from `OsRng`)
- `allowed_userdata_digest.len() == 32`
- every `allowed_measurement.len() == 48`
- `allowed_measurements` non-empty
- `luks_vault_ref.path != userdata_vault_ref.path`
- `luks_vault_ref.version > 0` AND `userdata_vault_ref.version > 0`
- `expiry > issue_time`

Free-form text fields (`vm_id`, `tenant_id`, `node_id`, …) are NOT
validated here — they must match the §22 allowlist entry the KBS
gates against. A mismatch surfaces at the KBS, not the minter.

## CLI

```text
hippius-order-ticket-mint \
  --signing-key <FILE> \
  --kid <STR> \
  --tenant-id <STR> --user-id <STR> \
  --vm-id <STR> --lease-id <STR> [--vm-generation <U64>] \
  --node-id <STR> --platform-id <STR> \
  --allowed-measurement-hex <HEX>  [--allowed-measurement-hex <HEX> ...] \
  --userdata-vault-path <PATH> --userdata-vault-version <U64> \
  --luks-vault-path     <PATH> --luks-vault-version     <U64> \
  --allowed-userdata-digest-hex <HEX> \
  --resource-class <STR> \
  --lifecycle-perm <STR> [--lifecycle-perm <STR> ...] \
  [--ticket-id <STR>] [--issue-time <EPOCH>] [--expiry-seconds <SECS>] \
  [--nonce-hex <HEX>] \
  [--out <FILE>]
```

Run `hippius-order-ticket-mint --help` for the canonical option list.

## Defaults

| Flag                  | Default                                                       |
|---|---|
| `--ticket-id`         | Fresh UUIDv4.                                                 |
| `--issue-time`        | Wall-clock `now()` (Unix seconds).                            |
| `--expiry-seconds`    | `3600` (1 hour validity window).                              |
| `--nonce-hex`         | 32 fresh random bytes from `OsRng`.                           |
| `--vm-generation`     | `1`.                                                          |

## Exit codes

| Code | Meaning                                                            |
|---|---|
| `0`  | Mint succeeded, envelope written.                                 |
| `2`  | Structured input rejection (bad hex, wrong length, vault collision, empty kid, ...). |
| `1`  | I/O or crypto failure (signing-key file unreadable, COSE encode error, ...).        |

Stderr carries a one-line human diagnostic. Stderr NEVER contains the
signing seed and NEVER contains the ticket body (§20).

## Concrete example — first tenant CVM mint

The tenant UKI's launch measurement is in
[`test_vectors/uki/tenant-measurement.json`](../../test_vectors/uki/tenant-measurement.json)
and currently reads
`f89f6a20e1e985e483c0b25abbf9d157d7f3e2302baefbe90c5af00e880ccb5ff26f0fd06bc10f1fe99e8c17972fd928`.
The dev L1 signer is checked into
[`packer/keys/dev/l1-order-ticket.dev.ed25519`](../../packer/keys/dev/l1-order-ticket.dev.ed25519)
under kid `l1-order-ticket-dev-v1` — the §22 dev allowlist epoch 2
binds that kid to the tenant UKI measurement (see PR #161).

The `--allowed-userdata-digest-hex` value below is a placeholder —
replace with the real digest once the PR-V Vault staging lands the
sealed user-data blob + the operator runs the §20 binder.

```bash
# Re-grep the live tenant UKI measurement
TENANT_MEASUREMENT_HEX=$(
  python3 -c '
import json, pathlib
print(json.loads(pathlib.Path("test_vectors/uki/tenant-measurement.json").read_text())["measurement_hex"])
'
)

cargo run --release -p hippius-order-ticket-mint -- \
  --signing-key packer/keys/dev/l1-order-ticket.dev.ed25519 \
  --kid l1-order-ticket-dev-v1 \
  --tenant-id tenant-dev-1 \
  --user-id   user-dev-1 \
  --vm-id     tenant-dev-1-vm-0 \
  --lease-id  lease-dev-1-0 \
  --vm-generation 1 \
  --node-id   miner-a \
  --platform-id CHIP-PLACEHOLDER \
  --allowed-measurement-hex "${TENANT_MEASUREMENT_HEX}" \
  --userdata-vault-path secret/hippius-compute/tenants/tenant-dev-1-vm-0/userdata \
  --userdata-vault-version 1 \
  --luks-vault-path     secret/hippius-compute/tenants/tenant-dev-1-vm-0/luks-kek \
  --luks-vault-version  1 \
  --allowed-userdata-digest-hex 0000000000000000000000000000000000000000000000000000000000000000 \
  --resource-class small \
  --lifecycle-perm launch \
  --expiry-seconds 3600 \
  --out tenant-dev-1-vm-0.ticket.cose
```

Then sanity-check the envelope before handing it to vali:

```bash
# Same parse the vali intake view shells out to — no signature check
# here, that's the KBS's job.
cargo run --release -p hippius-ticket-validator -- \
    verify-ticket < tenant-dev-1-vm-0.ticket.cose
# expected: {"tag":"ok","ticket":{…}}
```

## Out of scope (per PR-B brief)

- Vault staging (LUKS KEK + sealed user-data plaintexts) — that is
  PR-V, in parallel.
- Submission to vali (`POST /v1/order_ticket`) — separate E2E session
  after PR-V merges.
- Production L1 signer / rotation flow — future PR. The dev key in
  `packer/keys/dev/` is the only signer this binary is wired against
  today.
- Modifications to `kbs_core::ticket::verify_order_ticket` — the
  verifier path stays untouched. This binary's wire shape is locked
  to whatever the verifier accepts.

## Security envelope

- Signing key is read from a file path (CLI flag, not env) — operators
  are responsible for the file's filesystem ACL.
- The decoded `SigningKey` is zero-on-drop via the standard
  `ed25519-dalek` `Drop` impl.
- `Debug` is never derived on any struct that carries the seed.
- Output is the raw COSE_Sign1 bytes; stderr carries operator-facing
  diagnostics only — never the seed, never the ticket body (§20).
