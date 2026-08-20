# `packer/kbs-uki/` — KBS-image Packer factory

This directory builds the **measured UKI** that the KBS Confidential
VM boots inside. Spec of record: `ARCHITECTURE.md` §11 (Supply chain
& measured boot) and §17.7 (Packer factory). PR-F1 is the structural
skeleton — `packer validate` passes, `packer build` is deliberately
deferred to PR-F2.

## Why this dir exists

The §22 offline allowlist gates which UKI launch measurements the
KBS will release secrets to. For that to be meaningful, the
measurement has to be:

1. **reproducible** — two builders on different machines must
   produce byte-identical UKIs (and therefore byte-identical
   measurements). PR-F1 pins this by:
   - Pinning the base ISO **by SHA-256 digest** (not just URL).
   - Pinning the **Packer CLI** AND **every plugin** to an
     **exact** version (`= X.Y.Z`, never `~> X.Y` or `< 2.0`).
     Both pins are bump-and-re-attest PRs; never transitive.
   - Treating `qemu_accelerator` as **dev-only** for anything
     other than `tcg` until PR-F6's two-builder gate proves
     KVM/HVF bytes match. The accelerator value is included in
     the PR-F4 provenance map so any divergence is auditable.
2. **traceable** — the artifact ships with a signed provenance map
   `{launch_measurement, verity_root_hash, artifact_sha256,
   bucket, key, version_id}` (PR-F4).
3. **non-secret** — the base image contains no tenant data, no
   private keys, no Vault credentials, no static host identity.
   CI enforcement (secret-scan + SBOM) lands in PR-F6; PR-F1
   sets the structural contract.

## Locked decisions this skeleton honours

Per the §B / custody Q&A logged in **issue #1, comment 4496539510**
(2026-05-20):

- **Q12 — allowlist OOB delivery**: `build pipeline → S3 bucket
  Object Lock → signed by §22 root → KBS pull`. PR-F1 leaves the
  S3 upload + signing post-processor block intentionally empty in
  `build.pkr.hcl` (PR-F4 fills it). PR-F1 already pins the
  expectation that the build emits **inputs** to that pipeline
  (image_version + the eventually-computed launch_measurement +
  verity_root_hash); the **delivery** mechanism lives in the
  vali/CI layer that consumes Packer's manifest.
- **B22 — §22 root lives offline**: nothing in this directory ever
  touches the §22 signing key. PR-F4's S3 upload writes
  unsigned bytes; the signing ceremony (on the offline machine)
  consumes the upload manifest, signs it, and the signed
  artifact comes back through the Q12 path.

## What PR-F1 ships

| File | Purpose |
|---|---|
| `plugins.pkr.hcl` | Pinned Packer CLI range + exact-version qemu plugin. |
| `variables.pkr.hcl` | Typed inputs (ISO URL/digest/release, image_version, output dir, accelerator, VM shape). |
| `build.pkr.hcl` | qemu source block + non-empty `build {}` with a single shell-local stub provisioner. |
| `scripts/provision-stub.sh` | Documented placeholder for the PR-F2 in-guest provisioner. |
| `kbs-uki.auto.pkrvars.hcl.example` | Operator-supplied secret-store template (gitignored once filled). |
| `.gitignore` | Excludes Packer caches, qcow2 outputs, and any filled-in `*.pkrvars.hcl`. |

## What PR-F2 ships (in `uki/`)

| File / target | Purpose |
|---|---|
| `uki/Dockerfile` | Pinned-by-digest `debian:bookworm-slim` build env with `ukify`, `sbsigntool`, `cpio`, `binutils`. `--platform linux/amd64` so macOS Apple Silicon dev reproduces CI byte-for-byte. |
| `uki/Makefile` | Orchestrator: `make uki` → fetch → initramfs → assemble → sign → measure. `make uki-reproducible-check` → runs the build twice + diffs (CI gates here). |
| `uki/inputs.lock` | Pinned kernel + systemd-stub URLs + SHA-256 digests (placeholder zero — operator pins). |
| `uki/cmdline` | Locked kernel cmdline (PR-F3 adds `root=/dev/mapper/verity-rootfs`). |
| `uki/os-release` | UKI metadata baked into the `.osrel` PE section. |
| `uki/scripts/*` | Fetch, build-initramfs, assemble (`ukify`), sign (`sbsign`), measure, verify. All scripts respect `SOURCE_DATE_EPOCH` + `LC_ALL=C` + `umask 022`. |
| `keys/dev/{db.key, db.crt}` | **DEV ONLY** committed RSA-2048 + self-signed cert. See `keys/dev/README.md` for the three-belt defense against prod leakage. |
| `binaries/uki-measure/` | Rust binary emitting `{measurement_kind: "uki_sha384", measurement_hex, components, …}`. Stable wire shape; PR-F3 swaps the calculator without breaking consumers. |

## What PR-F1 does NOT ship (still deferred)

| Concern | PR |
|---|---|
| ✅ `dm-verity` rootfs + verity root hash embedded in the UKI's cmdline. | PR-F3 (shipped) |
| ✅ Real `sev::measurement::snp::snp_calc_launch_digest` (OVMF pinned by SHA-256, IDBLOCK placeholder) — `measurement_kind = "snp_launch_digest_v1"`. | PR-F3 (shipped) |
| Signed provenance map (`launch_measurement, verity_root_hash, …`) + S3 Object Lock upload (Q12 source side). | PR-F4 |
| Miner-side image fetch tool (Rust binary calling `hippius-types` for provenance verify). | PR-F5 |
| CI: `make uki-reproducible-check` job + secret-scan + SBOM. | PR-F6 |
| Real `iso_checksum` value (PR-F1 ships a placeholder zero digest, see "Validate vs build" below). | PR-F2 turn-up (operator's first real build). |
| Pinned `inputs.lock` digests for a specific kernel / systemd-stub release (PR-F2 ships zero placeholders). | PR-F3 turn-up. |
| Pinned Docker base digest + apt package versions in `uki/Dockerfile`. | PR-F2 turn-up via `make pin-base` + `make pin-apt`. |

## How to validate locally

```bash
cd packer/kbs-uki/
packer init .       # downloads the exact-pinned qemu plugin
packer validate .   # structural check; does not fetch the ISO
```

`packer validate` is the contract PR-F1 commits to passing. It runs
without network for the ISO (the digest is checked at fetch time,
not validate time), so the placeholder
`sha256:0000…0000` in `variables.pkr.hcl` is fine here.

## How to (NOT) build locally

`packer build .` will **fail closed** in this PR for two reasons:

1. The placeholder ISO digest will not match any real bytes Debian
   ever published, so Packer aborts on the SHA-256 mismatch BEFORE
   touching qemu.
2. There is no preseed, no SSH key, no in-guest packages — even if
   the ISO were correct, the build would time out on
   `ssh_wait_timeout`.

This is deliberate. The PR-F2 turn-up procedure is:

1. Verify `debian-cd/<release>/amd64/iso-cd/SHA256SUMS.sign`
   against a trusted Debian release key.
2. Copy `kbs-uki.auto.pkrvars.hcl.example` →
   `kbs-uki.auto.pkrvars.hcl` and paste the verified hex digest.
3. Add the preseed + the real provisioning chain (apt install,
   UKI assembly, etc.).
4. `packer build .`.
5. Record the new launch_measurement in the §22 allowlist via the
   Q12 OOB path.

## Threat model PR-F1 explicitly addresses

- **TLS-only mirror pinning is not enough.** The `iso_url` over
  HTTPS protects transport integrity, but the §22 allowlist
  ultimately trusts the measurement of what booted — not the URL
  it came from. Pinning the ISO by SHA-256 makes a poisoned
  mirror irrelevant.
- **Plugin transitive drift.** Packer plugin behaviour can change
  between minor versions (e.g. default firmware paths, default
  qemuargs). Exact-version pins close that drift channel.
- **Implicit non-determinism.** PR-F1 keeps `qemuargs = []`
  intentionally so PR-F3 can document each `-smbios`, `-bios`,
  `-machine` addition as a deliberate measurement-affecting
  change.

## Threat model PR-F1 does NOT yet address

- **Reproducibility check.** Two builders producing the same bytes
  is asserted by `plugins.pkr.hcl` + `variables.pkr.hcl`, but
  PR-F6 will *prove* it via a CI matrix (Linux/KVM and
  Linux/TCG runs that diff their `artifact_sha256`s).
- **Secret-in-base-image scan.** PR-F6 ships the CI gate; PR-F1
  documents the contract but does not enforce it.
- **Provenance signing.** PR-F4's job, on the §22 offline path.
