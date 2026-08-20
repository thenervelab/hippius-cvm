# `packer/kbs-uki/uki/` — UKI build pipeline (PR-F2)

Assembles the **measured Unified Kernel Image** that the KBS
SEV-SNP guest boots. Spec: `ARCHITECTURE.md` §11 (measured boot) +
§17.7 (Packer factory).

PR-F1 shipped the structural skeleton (pinned Packer + qemu plugin,
pinned base ISO). **PR-F2 (this dir) ships the UKI assembly +
signing + measurement extraction**. PR-F3 will add dm-verity root
hash embedding + the real SEV-SNP launch-digest calculation.

## End-to-end flow

```
hippius-agent-initramfs                  inputs.lock
  (Rust binary, from PR-E1.1)              (kernel + systemd-stub
        │                                   pinned by SHA-256)
        │                                   │
        ▼                                   ▼
   build-initramfs.sh  ───────►  fetch-inputs.sh
        │                                   │
        │  (cpio --reproducible)             │  (curl + sha256sum)
        ▼                                   ▼
   /build/work/initramfs.cpio        /build/work/{vmlinuz,
                                              linuxx64.efi.stub}
                              │
                              ▼
                       assemble-uki.sh
                       (ukify build, honours SOURCE_DATE_EPOCH)
                              │
                              ▼
                  /build/output/kbs-<version>.uki
                              │
                              ▼
                        sign-uki.sh
                        (sbsign with dev key OR prod override)
                              │
                              ▼
              /build/output/kbs-<version>.uki.signed
                              │
                              ▼
                       hippius-uki-measure
                              │
                              ▼
              /build/output/measurement.json
              {measurement_kind: "uki_sha384",
               measurement_hex: "<96 hex>",
               components: { kernel_sha256, initrd_sha256,
                             cmdline_sha256 },
               ...}
```

## Reproducibility contract

The single load-bearing invariant: **two back-to-back `make uki`
runs produce byte-identical outputs**. `make uki-reproducible-check`
enforces it.

Discipline that keeps this true:

| Source of non-determinism | How PR-F2 closes it |
|---|---|
| Wall-clock timestamps inside cpio / PE / signing | `SOURCE_DATE_EPOCH` = repo HEAD commit time (`git log -1 --format=%ct`). Every tool downstream reads it. |
| File-system entry order | `find … \| LC_ALL=C sort` before `cpio`. |
| File mode / uid / gid drift | `umask 022`, explicit `chmod 0755`, `cpio --owner=0:0 --reproducible`. |
| Hostname / user baked into archives | `LC_ALL=C` + `TZ=UTC`. cpio is `--reproducible` (no user info). ukify honours `SOURCE_DATE_EPOCH`. |
| Host CPU architecture | `docker buildx --platform linux/amd64` so macOS Apple Silicon dev hits the same binaries as CI. The `hippius-agent-initramfs` binary is built INSIDE the Docker image (multi-stage Dockerfile, `rust:1.93-bookworm-slim` first stage) — the host's `cargo target/` is NOT consumed. |
| Base image drift | Dockerfile `ARG DEBIAN_BASE_DIGEST` + `ARG RUST_BUILDER_DIGEST` pinned by SHA-256 (PR-F2 ships placeholders; operator pins via `make pin-base`). |
| Apt package drift | Each `apt-get install` line carries a `=PLACEHOLDER-PIN-VIA-MAKE-PIN-APT` suffix so the build fails closed until the operator pastes exact versions from `make pin-apt`. |
| Plugin / Rust toolchain drift | Toolchain pinned in `rust-toolchain.toml` (workspace). `cargo run` is invoked from the host so the Rust measure-tool produces identical bytes regardless of build host. |
| Signing key drift across machines | Dev key COMMITTED at `../keys/dev/{db.key, db.crt}`. Prod overrides via `SBSIGN_KEY`/`SBSIGN_CRT` env (Vault transit / offline ceremony). |

## PR-F3 — dm-verity rootfs + real SEV-SNP launch digest

PR-F3 turns the placeholder measurement into the real thing:

- **dm-verity rootfs** — `scripts/build-rootfs.sh` builds a
  reproducible read-only squashfs, runs `veritysetup format` (with a
  pinned salt) to get the verity root hash, and `assemble-uki.sh`
  embeds `dm-verity.root=<hash>` into the UKI cmdline. The rootfs is
  thereby integrity-anchored in the launch measurement.
- **Real launch digest** — built `--features snp`,
  `hippius-uki-measure` computes
  `sev::measurement::snp::snp_calc_launch_digest` over the pinned
  OVMF (`../ovmf/ovmf.lock`) + kernel + initrd + the verity-bearing
  cmdline, and emits `measurement_kind = "snp_launch_digest_v1"`.
  `make measure` runs it inside this Docker image (the `sev`
  measurement crate is Linux-only).

## Three-belt defense — placeholder ≠ trust anchor

PR-F2's `measurement_kind = "uki_sha384"` was itself the "not for
prod" signal. PR-F3 legitimately reaches `snp_launch_digest_v1`, so
the belts are now:

1. **`measurement_kind` tag**: the §22 ceremony signer MUST refuse to
   sign any allowlist entry where `measurement_kind !=
   "snp_launch_digest_v1"`. A default (`uki_sha384`) build reaching
   the signer is a hard reject.
2. **IDBLOCK marker**: while `../idblock/DO-NOT-TRUST-IN-PROD` exists
   next to an all-zero `idblock.bin`, the SEV-SNP launch policy is
   unauthenticated — dev-only. A production turn-up replaces the
   blocks and deletes the marker in one visible diff.
3. **Dev signing key**: dev key CN is `hippius-uki-dev-placeholder`,
   under `keys/dev/` — obvious in any `openssl x509 -text`. Prod
   overrides via `SBSIGN_KEY`/`SBSIGN_CRT`.

All three independent. Bypassing one without the others shows in code
review as a load-bearing comment removed; bypassing all three is a
deliberate, visible diff.

## Blackbox host-attestor UKI (chantier PR-6)

The same pipeline builds a second, **diskless** UKI: the measured
"blackbox" host-attestor. It packages `hippius-agent-host-attestor`
(the PR-4 crate — a measured guest PID1) instead of
`hippius-agent-initramfs`, and boots **initrd-as-root** with NO
dm-verity rootfs, LUKS, cloud-init, or netbird token.

```bash
make blackbox-uki                    # → output/blackbox-<ver>.uki.signed
                                     #   + output/blackbox-measurement.json
make blackbox-uki-reproducible-check # double-build byte-identical gate
```

How it reuses the pipeline:

| Knob | Default UKI | Blackbox UKI |
|---|---|---|
| `/init` binary | `AGENT_BINARY=/opt/hippius/agent-initramfs` | `/opt/hippius/agent-host-attestor` (both COPY'd by the Dockerfile) |
| rootfs | dm-verity squashfs (`rootfs` step) | **none** — diskless, `blackbox-assemble` skips it |
| cmdline | `uki/cmdline` + `dm-verity.root=<hash>` | `uki/cmdline.blackbox` **verbatim** — a FIXED constant (`quiet panic=0 console=ttyS0`), so the digest is deterministic per CPU-gen |
| measurement | `snp_launch_digest_v1` with `rootfs_verity_root` | `snp_launch_digest_v1`, same shape **minus** `rootfs_verity_root` (`hippius-uki-measure --diskless`) |
| SNP launch config | `SNP_VCPUS` / `SNP_VCPU_TYPE` / `SNP_GUEST_FEATURES` | **identical** |

The blackbox measurement is operator/CI-pinned on the first CI build —
NEVER auto-pinned from a miner. See
`test_vectors/uki/blackbox-REGENERATE.md` for the pinning flow and
`.github/workflows/blackbox-uki-build.yml` for the CI build + keyless
cosign `sign-blob` provenance (verified by PR-9's vali admin-release).
Ships **inert** — nothing bakes or launches it yet (PR-7).

## Operator workflows

### First-time setup

```bash
# Resolve the current debian:bookworm-slim digest + paste it into
# the Dockerfile's DEBIAN_BASE_DIGEST ARG.
cd packer/kbs-uki/uki/
make pin-base

# Record the verified kernel + systemd-stub SHA-256s into
# inputs.lock. URLs should target snapshot.debian.org so the
# digest pin is stable forever.
$EDITOR inputs.lock
```

### Build the UKI

```bash
# From the repo root. `hippius-uki-measure` is built on the host
# (pure-CPU, byte-stable regardless of arch). `hippius-agent-
# initramfs` is built INSIDE the Docker image (multi-stage
# Dockerfile, `rust:1.93-bookworm-slim` builder) so macOS Apple
# Silicon dev and CI Linux/amd64 produce byte-identical agent
# bytes.
cargo build -p hippius-uki-measure --release
cd packer/kbs-uki/uki/
make uki
```

Output: `output/kbs-<image-version>.uki.signed` +
`output/measurement.json`.

### Verify reproducibility

```bash
make uki-reproducible-check
```

Runs `make uki` twice into isolated output dirs; exits 0 iff every
emitted byte is byte-identical. CI gates on this.

### Production signing key override

```bash
make uki \
  SBSIGN_KEY=/path/to/prod/db.key \
  SBSIGN_CRT=/path/to/prod/db.crt
```

Both files MUST live OUTSIDE the repo (`.gitignore` blocks `*.key`
outside the dev allowlist). Prod typically stages from Vault
transit or an offline ceremony machine.

## Still deferred (post-PR-F3)

| Concern | PR |
|---|---|
| Signed provenance map + S3 Object Lock upload (`launch_measurement, verity_root_hash, artifact_sha256, …`). | PR-F4 |
| Miner-side image fetch tool (verifies SHA-256 vs signed provenance before boot). | PR-F5 |
| CI: `make uki-reproducible-check` job + secret-scan + SBOM. | PR-F6 |
| Real signed SEV-SNP ID block (replaces the `idblock/` all-zero placeholder); author-key custody. | future |
| Pinned `inputs.lock` + `ovmf.lock` digests for a specific kernel / systemd-stub / OVMF release (currently zero-digest placeholders). | operator turn-up |
