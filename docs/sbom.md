# SBOM generation + verification

PR-F6 added [`.github/workflows/sbom.yml`](../.github/workflows/sbom.yml),
which — on every push to `main` and every `v*` tag — produces a
[CycloneDX](https://cyclonedx.org/) Software Bill of Materials for each
security-critical Rust binary and signs it with a **keyless cosign**
attestation recorded in the [Sigstore](https://www.sigstore.dev/) Rekor
transparency log.

This closes the §F "SBOM/SLSA provenance" scope item (issue #41): the
SBOM lets a downstream consumer enumerate the exact dependency tree of a
shipped binary, and the cosign attestation lets them prove the SBOM was
produced by this repository's CI and not tampered with afterwards.

## What is produced

`cargo-cyclonedx` generates one `*.cdx.json` SBOM per crate. The
workflow signs + publishes the SBOMs for the §E/§F trusted-computing-base
binaries:

| Binary | Crate | SBOM artifact |
| --- | --- | --- |
| KBS server | `kbs-server` | `kbs-server.cdx.json` |
| Initramfs agent | `hippius-agent-initramfs` | `hippius-agent-initramfs.cdx.json` |
| UKI measurement tool | `hippius-uki-measure` | `hippius-uki-measure.cdx.json` |
| Image-provenance CLI | `hippius-image-provenance` | `hippius-image-provenance.cdx.json` |

> The miner-side image-fetch binary (`miner-uki-fetch`, PR-F5) is not
> merged yet; add it to the `sign_sbom` list in `sbom.yml` when it lands.

Each SBOM ships with a companion `<name>.cdx.json.cosign.bundle` — the
Sigstore bundle (signature + Fulcio certificate + Rekor inclusion
proof) needed to verify it offline.

## Where to get them

- **Every `main` push** — as the `sbom-cyclonedx` workflow artifact on
  the `sbom` workflow run (Actions tab → the run → Artifacts).
- **Tagged releases (`v*`)** — also attached as assets on the GitHub
  Release for that tag.

## Why keyless

The cosign attestation is **keyless** (Sigstore "Fulcio" flow): the
`sbom` job mints a short-lived GitHub OIDC token (`id-token: write`),
exchanges it for a short-lived signing certificate, signs, and discards
the key. There is **no long-lived cosign private key** to store, rotate,
or leak — the identity proven is the GitHub Actions workflow itself.

## Verifying an SBOM downstream

You need [`cosign`](https://docs.sigstore.dev/cosign/installation/)
(v3.x), the SBOM file, and its `.cosign.bundle`.

```sh
cosign verify-blob \
  --bundle hippius-agent-initramfs.cdx.json.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/thenervelab/hippius-compute/\.github/workflows/sbom\.yml@refs/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  hippius-agent-initramfs.cdx.json
```

`cosign` exits `0` and prints `Verified OK` only if **all** of:

1. the signature matches the SBOM bytes,
2. the signing certificate was issued by Sigstore Fulcio to the GitHub
   OIDC identity of **this** repo's `sbom.yml` workflow
   (`--certificate-identity-regexp` — pin it to a single tag with
   `--certificate-identity` for a release artifact), and
3. the signing event is present in the Rekor transparency log.

A failure on any of these means the SBOM is not the one this CI
produced — **do not trust it**.

To inspect the dependency tree itself, any CycloneDX-aware tool works,
e.g. `cyclonedx` CLI or:

```sh
jq '.components[] | "\(.name) \(.version)"' hippius-agent-initramfs.cdx.json
```

## Regenerating locally

```sh
cargo install cargo-cyclonedx --version 0.5.9 --locked
cargo cyclonedx --format json
```

This writes `<crate>.cdx.json` next to each crate's `Cargo.toml`. These
files are build artifacts — they are git-ignored and must not be
committed (the canonical, signed copies come from CI only).
