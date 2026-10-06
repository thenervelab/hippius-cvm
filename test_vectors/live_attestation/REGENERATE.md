# `test_vectors/live_attestation/` — tenant-CVM live-attestation vector

Pinned input tuple + frozen output for the §23 KBS-L0-signed
`LiveAttestation` — the proof a tenant SEV-SNP CVM was genuinely ALIVE,
which the uptime meter requires before it credits a served receipt.

The vector is a **real** signed envelope: the inner body is signed by a
fixed test Ed25519 key standing in for the KBS L0 key. Ed25519 signing
is deterministic, so a fixed key + fixed body yields a byte-exact
envelope.

## Files

| File | Provenance |
|---|---|
| `signed_live_attestation.cbor` | **Frozen output** — `SignedLiveAttestation::encode()`: the `{body, sig}` envelope, `sig` = Ed25519 over `LiveAttestation::canonical()` by the pinned test key. |
| `signed_live_attestation_v2.cbor` | **Frozen output** — the same, for `kat_attestation_v2()`: schema v2 with a release-time guest binding (`chip_id = [0x5E; 64]`, `report_id = [0x7A; 32]`). |
| `signed_live_attestation_v3.cbor` | **Frozen output** — the same, for `kat_attestation_v3()`: the v2 body plus attested guest resources (`vcpus_online = 4`, `mem_firmware_kib = 16776164`, `mem_total_kib = 15337812`, `mem_unaccepted_kib = 1024`). |
| `signed_live_attestation_v4.cbor` | **Frozen output** — the same, for `kat_attestation_v4()`: the v3 body plus the attested guest components (`components_release_version = 2`, `components_security_epoch = 1`, `components_health = 15`, `components_instance = 0x12345678`, `components_unhealthy_ticks = 1`). |

## Pinned inputs

In `hippius-types/tests/live_attestation_kat.rs`: `KAT_SEED =
[0x5A; 32]` and `kat_attestation()` (`vm_id = "tn-kat-live-1"`,
`attestation_seq = 7`, `verified_at_unix = 1_800_000_005`, …).

The matching PUBLIC key — what a verifier pins — is

```
0d7550754e0800a5d237eef5826035766b9b3e5a15868a940ab289958788e3b0
```

## Who depends on these exact bytes

- `binaries/ticket-validator` `verify-live-attestation` — the Rust
  decode + L0-signature gate.
- vali `apps.telemetry.tests.test_vm_liveness_e2e` — pipes THIS FILE
  through the real built binary into `vm_liveness.ingest_live_attestation`.
  It is the only test that checks the Rust→JSON→Python field contract
  against real cryptography instead of a mock, so this vector must stay
  a real signed envelope.

A mismatch is **drift** — fix the implementation, do not update the
vector to match.

## Regenerating

Only for a deliberate change (a canonical-encoding change in
`hippius_types::live_attestation`, an intentional fixture edit, or a
rotation of the test seed):

```bash
cargo test -p hippius-types --test live_attestation_kat \
    regenerate_committed_vectors -- --ignored --exact --nocapture
```

Then review the `.cbor` diff **and** re-check vali's end-to-end fixture
expectations (`vm_id`, `attestation_seq`, `verified_at_unix`, and the
pinned public key above).
