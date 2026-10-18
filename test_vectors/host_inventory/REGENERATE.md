# `test_vectors/host_inventory/` — host inventory known-answer vectors

Frozen outputs of the §18.10 host inventory wire format
(the `hippius-host-inventory` crate), checked by
`cargo test -p hippius-host-inventory --test kat`. vali's
`verify-host-inventory` tests reuse them.

| File | Provenance |
|---|---|
| `host_inventory_body_full.cbor` | `HostInventory::canonical()` of `kat_full()`: a `full` report, every section. |
| `signed_host_inventory_full.cbor` | `SignedHostInventory::canonical()`: that body + an Ed25519 signature by the pinned test key. |
| `host_inventory_body_counters.cbor` | the `counters` report `kat_counters()` (memory, storage, sensors, software). |
| `signed_host_inventory_counters.cbor` | its signed envelope, same key. |
| `kat_vk.hex` | the test key's verifying key (hex), what vali resolves for the miner. |

The inputs are pinned in the test (`kat_full()`, `kat_counters()`,
`KAT_SEED`). Every value is synthetic: no real serial, by-id name or host.

A parallel encoder must reproduce these bytes for the same inputs. A
mismatch is drift: fix the encoder, never the vector.

## Regenerating

Only for a deliberate change (an encoding change in the module, an
intentional fixture edit, a new test seed):

```bash
cargo test -p hippius-host-inventory --test kat \
    regenerate_committed_vectors -- --ignored --exact
```
