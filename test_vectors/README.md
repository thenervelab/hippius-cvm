# Conformance test vectors (`v1`)

Cross-implementation source of truth for every deterministic-CBOR wire
format in the Hippius DePIN compute stack (ARCHITECTURE.md §N).

This directory holds **no binary data** — the vectors live in Rust
test code at
[`hippius-types/tests/conformance_vectors.rs`](../hippius-types/tests/conformance_vectors.rs)
so the inputs (struct fields) and the expected outputs (SHA-256 hex
hashes of the canonical CBOR body) stay in lockstep in one file.

If you are writing a parallel implementation (TypeScript, Python, the
on-chain pallet, an audit tool) you MUST:

1. Construct the same input struct with the same fixed bytes.
2. Encode it with your impl's deterministic-CBOR encoder.
3. SHA-256 the encoded body.
4. Verify the hex hash matches the value the Rust test asserts.

If it doesn't, your impl's CBOR encoder is drifting — fix it, do not
update the Rust constant.

## Schema version

`v1` covers every signed wire format on `main` as of PR #35. Bumping to
`v2` requires:

- a deliberate schema change in `hippius-types` (new field, removed
  field, renamed key) AND
- this README updated with the diff AND
- every external consumer notified before merge.

A `v1`-vector test failure means **drift** — never silently update the
constant. The CI gate catches it before merge.

## Coverage

| Vector | Type | Inputs |
| --- | --- | --- |
| `release_context.luks` | `ReleaseContext` | LUKS secret release context |
| `release_context.userdata` | `ReleaseContext` | user-data secret release context |
| `userdata_digest` | 32-byte SHA-256 | the §6 ticket-pinned user-data digest preimage |
| `stopped_ack.basic` | `StoppedAck` | guest-signed §24/§25 EOL ack |
| `served_delivery_receipt.basic` | `ServedDeliveryReceipt` | §23 tenant-signed receipt |
| `served_delivery_aggregate.basic` | `ServedDeliveryAggregate` | §23 Audit-VM-signed aggregate |
| `map_root.single_entry` | 32-byte SHA-256 | single-entry receipt set root |
| `totals_root.boundary` | 32-byte SHA-256 | u64::MAX + 1 boundary case for u128 served_units |

## Implementing a parallel encoder

The deterministic-CBOR rules every encoder MUST satisfy are:

1. **Map keys sorted by encoded-key bytes** (RFC 8949 §4.2.1).
2. **Duplicate map keys rejected** during canonicalize.
3. **Map array uses definite length** (no indefinite encoding).
4. **Integer 0–u64::MAX uses major type 0** (preferred serialization).
5. **u128 values > u64::MAX use tag-2 bignum, big-endian, leading zero
   bytes stripped** (RFC 8949 §3.4.3).

See [`hippius-types/src/cbor.rs`](../hippius-types/src/cbor.rs) for the
Rust reference encoder and the per-schema `canonical()` methods in
[`hippius-types/src/*.rs`](../hippius-types/src/) for field layouts.
