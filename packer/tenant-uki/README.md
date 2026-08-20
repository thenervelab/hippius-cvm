# `packer/tenant-uki/` — tenant UKI Packer factory

Builds the **measured UKI a Hippius tenant CVM boots into** — the
sibling artefact to `packer/kbs-uki/` (which builds the KBS pod
image). Spec of record: `ARCHITECTURE.md` §11 (Supply chain &
measured boot), §17.7 (Packer factory), §E1.5 (hardened guest
cmdline). The §22 trust anchor + the OVMF firmware pin are SHARED
with `packer/kbs-uki/` — one fleet-wide root.

## What the tenant UKI is

A signed UKI whose:

- **initramfs** is the SHARED `hippius-agent-initramfs` (PR-E1.x) —
  decides its KBS endpoint / LUKS device / EOL semantics from
  `hippius.*=` kernel-cmdline tokens (and / or `HIPPIUS_*` env vars
  the miner-agent passes per-VM);
- **rootfs** is a dm-verity-protected squashfs that bundles the §23
  `hippius-agent-tenant-telemetry` service + the NetBird agent
  static binary;
- **cmdline** carries the §E1.5 hardened profile
  (`assert_hardened_cmdline`) AND the tenant-specific
  `hippius.kbs_url=` pin so a tenant CVM cannot be re-pointed at a
  hostile KBS without a new measurement.

The directory layout mirrors `packer/kbs-uki/`; the substantive
deltas — and what is SHARED vs duplicated — are documented in
`uki/README.md`.

## What this dir ships

| File | Purpose |
|---|---|
| `plugins.pkr.hcl` | Pinned Packer CLI range + exact-version qemu plugin (identical pins to kbs-uki — fleet-wide reproducibility). |
| `variables.pkr.hcl` | Typed Packer inputs (ISO URL/digest/release, image_version, output dir, accelerator, VM shape). |
| `build.pkr.hcl` | qemu source block + skeleton `build {}` provisioner — `packer validate` passes; the real install path is `uki/Makefile`. |
| `scripts/provision-stub.sh` | Placeholder for an in-guest Packer provisioner; current builds drive `uki/Makefile` directly. |
| `tenant-uki.auto.pkrvars.hcl.example` | Operator-supplied template (gitignored once filled). |
| `uki/` | The real build pipeline — Dockerfile + Makefile + scripts + pinned `inputs.lock`. See `uki/README.md`. |
| `.gitignore` | Excludes Packer caches, qcow2 outputs, `*.auto.pkrvars.hcl`. |

## What's NOT here (shared from `packer/kbs-uki/`)

| Shared input | Why |
|---|---|
| `keys/dev/{db.key, db.crt, provenance-root.dev.ed25519}` | One §22 dev key for the whole fleet — both UKIs sign with it. The tenant Makefile defaults `SBSIGN_KEY`/`SBSIGN_CRT` at `packer/kbs-uki/keys/dev/`. |
| `ovmf/ovmf.lock` | One OVMF firmware pin for the whole fleet — both UKIs measure the same `OvmfPkg/AmdSev/AmdSevX64.dsc` build. The tenant Makefile reads the kbs-uki lockfile directly. |
| `idblock/` | Same placeholder; production replaces it once for both flavours. |

A future refactor that promotes `keys/`, `ovmf/`, and `idblock/` to
`packer/{keys,ovmf,idblock}/` (the top level) is a separate PR; this
PR keeps the trust anchors in their current `kbs-uki` home so the
diff stays focused.

## How to validate locally

```bash
cd packer/tenant-uki/
packer init .       # downloads the exact-pinned qemu plugin
packer validate .   # structural check; does not fetch the ISO
```

## How to build the UKI

The real build path is the Makefile under `uki/`, NOT `packer build`
(see `uki/README.md`):

```bash
cd packer/tenant-uki/uki/
make uki                    # fetch → initramfs → rootfs → assemble → sign → measure
make uki-reproducible-check # double-build + byte-diff
```

Output: `uki/output/tenant-<image-version>.uki.signed` +
`uki/output/measurement.json`.
