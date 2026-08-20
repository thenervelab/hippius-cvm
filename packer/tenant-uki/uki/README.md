# `packer/tenant-uki/uki/` — tenant UKI build pipeline

Assembles the **measured Unified Kernel Image** that a Hippius
**tenant CVM** boots. Spec: `ARCHITECTURE.md` §11 (measured boot) +
§17.7 (Packer factory). Sibling of `packer/kbs-uki/` (which builds
the KBS pod image); same reproducibility regime, different rootfs
payload + cmdline contract.

## What the tenant UKI is

A signed UKI (kernel + initramfs + cmdline, packed into one PE the
SEV-SNP firmware measures) whose:

- **initramfs** is the SHARED `hippius-agent-initramfs` (PR-E1.x) —
  runs the §21 boot pipeline (KBS release → LUKS unlock → switch_root);
- **rootfs** (PR-F3 dm-verity squashfs, integrity-anchored by the
  `dm-verity.root=` token in the measured cmdline) bundles the two
  binaries the tenant CVM needs after `switch_root`:
    - `/sbin/hippius-agent-tenant-telemetry` — §23 per-VM
      telemetry-signer service (PR-E2.x);
    - `/sbin/netbird` — NetBird agent static binary (pinned by SHA in
      `inputs.lock`);
- **cmdline** carries the §E1.5 hardened profile
  (`assert_hardened_cmdline`) — `panic=1 panic_on_oops=1 ds=nocloud
  init=/sbin/init-hippius` — plus `hippius.kbs_url=` baked at
  measurement time so a tenant CVM cannot be redirected to a hostile
  KBS without changing the launch digest;
- **measurement** is the real `snp_launch_digest_v1` over the pinned
  OVMF (shared with kbs-uki) + kernel + initrd + cmdline.

## End-to-end flow

```
hippius-agent-initramfs            inputs.lock                  agent-tenant-telemetry
  (built in Dockerfile)              (kernel + stub +              (built in Dockerfile)
        │                             OVMF + NetBird,                      │
        │                             pinned by SHA-256)                   │
        ▼                                     ▼                            ▼
  build-initramfs.sh                  fetch-inputs.sh              build-rootfs.sh
        │                                     │                            │
        │  (cpio --reproducible)               │ (curl + sha256sum +        │ (squashfs --all-root,
        │                                     │  dpkg-deb -x + tar -xzf)   │  veritysetup --salt=pinned,
        ▼                                     ▼                            ▼  bundles tenant-telemetry + netbird)
   /build/work/initramfs.cpio   /build/work/{vmlinuz, linuxx64.efi.stub, netbird}
                              \                |                            |
                               \   /build/fetched/ovmf.bin                  ▼
                                \              |                  /build/work/rootfs.{img,verity,roothash}
                                 \             |                            |
                                  \            ▼                            |
                                   assemble-uki.sh ◄──────────────── dm-verity.root=<hash>
                                   (ukify build, honours
                                    SOURCE_DATE_EPOCH)
                                              │
                                              ▼
                            /build/output/tenant-<version>.uki
                                              │
                                              ▼
                                        sign-uki.sh
                                        (sbsign with the shared dev
                                         key from packer/kbs-uki/)
                                              │
                                              ▼
                          /build/output/tenant-<version>.uki.signed
                                              │
                                              ▼
                                  hippius-uki-measure --features snp
                                  (pinned OVMF + kernel + initrd +
                                   cmdline.effective → SNP launch digest)
                                              │
                                              ▼
                            /build/output/measurement.json
                            {measurement_kind: "snp_launch_digest_v1",
                             measurement_hex: "<96 hex>",
                             components: { kernel_sha256, initrd_sha256,
                                           cmdline_sha256, ovmf_sha256,
                                           rootfs_verity_root, snp_launch_config },
                             ...}
```

## Shared with `packer/kbs-uki/`

One §22 trust anchor and one OVMF firmware pin for both UKI flavours
— there is exactly one fleet root and exactly one measured firmware,
never duplicated:

- **dev signing key** (`sbsign` + the `hippius-image-provenance` §22
  root) — `packer/kbs-uki/keys/dev/{db.key, db.crt,
  provenance-root.dev.ed25519}`. The tenant Makefile defaults
  `SBSIGN_KEY`/`SBSIGN_CRT` there and the CI workflow signs provenance
  with the same `provenance-root.dev.ed25519`.
- **OVMF firmware pin** — `packer/kbs-uki/ovmf/ovmf.lock`. The tenant
  Makefile reads it directly; a change there affects BOTH UKIs'
  launch measurements in lockstep (intentional — the firmware is
  fleet-wide).
- **Kernel + systemd-stub pins** — duplicated values in
  `inputs.lock` (must stay equal to `packer/kbs-uki/uki/inputs.lock`).
  The duplication is deliberate per the §F discipline: each file
  is independently audit-grep-able for its pinned SHA.

## Reproducibility contract

The single load-bearing invariant: **two back-to-back `make uki` runs
produce byte-identical outputs**. `make uki-reproducible-check`
enforces it.

Discipline that keeps this true is identical to kbs-uki's — see
`packer/kbs-uki/uki/README.md` "Reproducibility contract". The tenant
flavour adds one extra surface (the NetBird tarball) and pins it
the same way: `inputs.lock` carries the SHA-256, `fetch-inputs.sh`
refuses to proceed on a mismatch, and the extracted binary's bytes
are inside the verity-protected squashfs.

## Three-belt defense — placeholder ≠ trust anchor

Same three belts as kbs-uki (`measurement_kind` tag, `idblock`
marker, dev signing key CN). The tenant build runs on the SAME §22
ceremony — bypassing belts shows up as a load-bearing comment
removed across BOTH UKI flavours in the same review.

## Operator workflows

### Build the tenant UKI

```bash
# From the repo root. The full pipeline runs inside the pinned
# Linux/amd64 Docker image (macOS Apple Silicon dev reproduces CI
# byte-for-byte).
cd packer/tenant-uki/uki/
make uki
```

Output: `output/tenant-<image-version>.uki.signed` +
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

Both files MUST live OUTSIDE the repo. Prod typically stages from
Vault transit or an offline ceremony machine.

## Still deferred

| Concern | PR |
|---|---|
| Real tenant-rootfs init: KBS-released NetBird setup key + vsock CID config + supervisor that starts `hippius-agent-tenant-telemetry` and `netbird up`. The current `/sbin/init` is a placeholder that mounts pseudo-fs and waits. | follow-up tenant-rootfs-init PR |
| Pinned signed SEV-SNP ID block (replaces the shared `packer/kbs-uki/idblock/` all-zero placeholder); author-key custody. | future |
| Tenant-specific test vectors beyond the launch-measurement KAT (rootfs verity-root KAT, cmdline-hash KAT). | as the launcher matures |
