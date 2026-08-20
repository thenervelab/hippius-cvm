# `test_vectors/snp/` — SEV-SNP launch-digest known-answer vector

Pinned inputs for `hippius-uki-measure`'s SNP known-answer test
(`cargo test -p hippius-uki-measure --features snp`). The test freezes
the `snp_launch_digest_v1` value for this exact tuple so a `sev`-crate
bump — or an accidental fixture edit — that shifts the digest fails CI
loudly instead of silently changing every production measurement.

## Files

| File | Provenance |
|---|---|
| `ovmf.bin` | `ovmf_AmdSev_suffix.bin` from the `sev` crate's test corpus (sev 7.1.0, Apache-2.0). A known-good SEV-SNP OVMF metadata suffix — the canonical fixture `sev`'s own `snp_calc_launch_digest` tests use, so it is guaranteed to parse. NOT a production firmware. |
| `kernel.bin` | Synthetic — fixed ASCII bytes. `snp_calc_launch_digest` only hashes the kernel into the SEV hashes table, so a synthetic blob is sufficient and keeps the fixture tiny. |
| `initrd.bin` | Synthetic — fixed ASCII bytes. |
| `uki.bin` | Synthetic — fixed ASCII bytes. The SNP path reads it only for `uki_size_bytes` / `uki_basename`; the measurement is the launch digest, not a hash of the UKI. |
| `cmdline` | Fixed kernel cmdline, including a sample `dm-verity.root=` value. |

The launch config is pinned in the test itself (`snp_fixture()` in
`binaries/uki-measure/src/main.rs`): `vcpus = 1`, `vcpu_type =
EpycGenoa`, `guest_features = 0x1` (SNPActive). The `sev` crate is
our in-tree vendor copy (`vendor/sev/`, 7.1.0 with the `EpycGenoa`
stepping=1 patch — see `vendor/sev/HIPPIUS_PATCH.md`), so the KAT
freezes the post-patch digest.

## Regenerating the known answer

The frozen digest lives in `EXPECTED_SNP_DIGEST` in
`binaries/uki-measure/src/main.rs`. Regenerate it ONLY for a
deliberate change — **any `sev` version change, including a patch
release** (`7.1.x` → `7.1.y` can touch the measurement code), or an
intentional fixture / launch-config edit:

```sh
# On Linux (the sev measurement module is Linux-only):
cargo test -p hippius-uki-measure --features snp --locked
```

If `snp_digest_matches_known_answer` fails, the panic message prints
the newly-computed digest as `left:`. Copy it into
`EXPECTED_SNP_DIGEST`, commit, and — because the production launch
measurement has moved — **re-attest the §22 offline allowlist** with
the new value via the Q12 out-of-band path.

A digest change that is NOT accompanied by a deliberate `sev` bump or
fixture edit is a regression — investigate before touching the
constant.

## Not a secret

Every file here is non-secret: public firmware metadata + synthetic
blobs. They are pinned for *integrity* (a stable known-answer), not
confidentiality.

## `genoa-vek.pem` — Genoa VEK known-answer

Fetched 2026-05-24 from AMD's KDS endpoint
`https://kdsintf.amd.com/vcek/v1/Genoa/<CHIP_ID>?blSPL=12&teeSPL=00&snpSPL=28&ucodeSPL=88`
for an EPYC 9254 (Genoa) host, via `snphost fetch vek`
(virtee/snphost v0.7.0). `<CHIP_ID>` is whatever
`snphost show identifier` returns on the host you fetch for.

This is a **public** AMD-signed certificate — VEKs convey no secrets
and are designed to be distributed widely. But a VEK is issued
per-chip: it carries the 64-byte CHIP_ID of the machine it was fetched
for, in X.509 extension `1.3.6.1.4.1.3704.1.4`. It names one physical
host, and this repository is meant to be publishable.

So **it is not committed.** Supply it out of band:

```sh
sudo snphost fetch vek pem /tmp/vek        # on YOUR Genoa host
export HIPPIUS_VEK_FIXTURE=/tmp/vek/vek.pem
cargo test -p hippius-kbs-server --lib attest::
```

Seven `attest::tests` consume it, including
`forged_genoa_report_signature_denied` and
`turin_report_denied_when_no_turin_vek_source` — the anti-forgery
boundary. Without `HIPPIUS_VEK_FIXTURE` they SKIP, printing why. That
is correct for someone who owns no Genoa hardware and unacceptable for
this project's own CI, which supplies the fixture from a secret and
FAILS if that secret is missing (`.github/workflows/ci.yml`).

The chain test only asserts AMD-signature consistency — no real SNP
report is needed, so any valid Genoa VEK works, not specifically ours.
