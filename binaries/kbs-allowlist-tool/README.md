# `hippius-kbs-allowlist-tool` — offline §22 allowlist minter

Builds + signs the COSE_Sign1 EdDSA artifact `hippius-kbs-server` ingests
via `[allowlist].signed_path` (§22 of `ARCHITECTURE.md`). Operates on
exactly the same `kbs_core::allowlist::AllowlistBody` schema the KBS
runtime verifies against, then re-runs `parse_and_verify` against the
matching public key before writing — an artifact the runtime would
reject never reaches disk.

## Inputs

| Flag | Meaning |
|---|---|
| `--manifest <FILE>` | TOML manifest — epoch + list of `(measurement, l1 kids, KBS kids)` tuples. |
| `--seed <FILE>` | 32-byte Ed25519 seed (the §22 root signing key). Held in `Zeroizing`, wiped on drop. |
| `--out <FILE>` | Output path for the signed `.cose` artifact (atomic rename from `<out>.tmp`). |

## Manifest schema

```toml
# Monotonic anti-rollback counter (§22 HWM). Strictly greater than the
# epoch currently installed in any target KBS.
epoch = 1

# At least one entry — an empty allowlist is a footgun (denies
# everything, same as having no allowlist installed, which the KBS
# already fails closed on).
[[entries]]
# 48-byte SNP launch digest, hex.
measurement_hex = "bcbd16c…"
# L1 OrderTicket-signing kid(s) accepted for THIS measurement, hex.
accepted_l1_kids_hex     = ["6c312d…"]
# KBS response-signing kid(s) accepted for THIS measurement, hex.
accepted_kbs_response_kids_hex = ["6b62732d63632d312d726573706f6e73652d7631"]
```

All fields are `deny_unknown_fields`; a typo fails fast.

## Dev key

`packer/kbs-uki/keys/dev/provenance-root.dev.ed25519` is the committed
dev root — the SAME key the §F UKI provenance signer uses. It is
**dev-only**: production §22 ceremony runs against an offline ceremony
host whose key is never in this repo.

The matching pubkey is `e6fec6b20e2a6848537e70c195e99dce63a09f6d175518
45e6eda126be53adab` — that's the value `[allowlist].root_pubkey_hex`
takes in the dev cluster.

## Mint the dev artifact

```sh
cargo run -p hippius-kbs-allowlist-tool -- \
    --manifest test_vectors/allowlist/dev-manifest.toml \
    --seed packer/kbs-uki/keys/dev/provenance-root.dev.ed25519 \
    --out test_vectors/allowlist/dev.cose
```

The committed `test_vectors/allowlist/dev.cose` is byte-identical to
what a fresh run produces — the canonical-CBOR encoding is deterministic
and the COSE_Sign1 signature over the canonical payload is too (EdDSA
is deterministic by RFC 8032 §5.1.6).

## Publishing

Out of scope for this tool — `aws s3 cp ... s3.hippius.com/...` is a
deliberately separate operator step so the credential surface stays
bounded.
