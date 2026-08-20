# `test_vectors/allowlist/` — pinned dev §22 allowlist KAT

`dev.cose` is the committed dev §22 allowlist artifact — the COSE_Sign1
EdDSA-signed output of `hippius-kbs-allowlist-tool` run against
`dev-manifest.toml` + `packer/kbs-uki/keys/dev/
provenance-root.dev.ed25519` (the dev §22 root seed).

Canonical-CBOR encoding (`hippius_types::cbor::to_canonical_vec`) plus
EdDSA's RFC 8032 §5.1.6 determinism means the artifact is byte-identical
across hosts, so the committed file is a known-answer test: drift any
input (manifest, seed, schema) and the byte diff fires loudly.

## What's pinned

| Input | Source |
|---|---|
| Schema version | `kbs_core::allowlist::ALLOWLIST_V = 1` |
| Epoch | `dev-manifest.toml::epoch = 1` |
| Measurement | `test_vectors/uki/measurement.json::measurement_hex` (the current §F UKI launch digest) |
| `accepted_l1_kids_hex` | placeholder — locked into a real kid in lockstep with the §I pallet-arion vendoring |
| `accepted_kbs_response_kids_hex` | hex of `kbs-cc-1-response-v1` (matches `deploy/gitops/apps/kbs/values.yaml::config.kidHex`) |
| Root seed | `packer/kbs-uki/keys/dev/provenance-root.dev.ed25519` (dev placeholder, committed) |

## Regenerating after an intentional change

A change to ANY pinned input (manifest, UKI measurement, dev seed,
canonical-CBOR encoder) shifts the artifact bytes; the regen flow:

```bash
# 1. Bump whichever input is changing (e.g. the UKI measurement,
#    epoch, or a kid).
# 2. Re-mint:
cargo run -p hippius-kbs-allowlist-tool -- \
    --manifest test_vectors/allowlist/dev-manifest.toml \
    --seed packer/kbs-uki/keys/dev/provenance-root.dev.ed25519 \
    --out test_vectors/allowlist/dev.cose

# 3. Verify reproducibility:
cargo run -p hippius-kbs-allowlist-tool -- \
    --manifest test_vectors/allowlist/dev-manifest.toml \
    --seed packer/kbs-uki/keys/dev/provenance-root.dev.ed25519 \
    --out /tmp/dev.cose.check
diff -q test_vectors/allowlist/dev.cose /tmp/dev.cose.check

# 4. The §22 epoch in the manifest MUST be strictly greater than the
#    epoch currently installed in any target KBS — otherwise the
#    InstalledAllowlist HWM CAS rejects the install.
```

## NOT a secret

The dev seed under `packer/kbs-uki/keys/dev/` is publicly committed —
see that directory's README. The signed allowlist therefore conveys
no confidentiality; it's pinned for **integrity** (deterministic
launch-digest gating). Production rolls in a different §22 root seed
that never enters the repo.
