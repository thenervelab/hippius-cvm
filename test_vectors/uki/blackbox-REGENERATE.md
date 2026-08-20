# `test_vectors/uki/blackbox-measurement.json` — pin-on-first-CI-build

The diskless **blackbox host-attestor** UKI (host-attestor chantier
PR-6) has its own launch measurement, produced by:

```bash
make -C packer/kbs-uki/uki blackbox-uki
# → packer/kbs-uki/uki/output/blackbox-measurement.json
```

It is the same `snp_launch_digest_v1` envelope shape as the tenant/kbs
`measurement.json`, MINUS the `rootfs_verity_root` component: the
blackbox UKI is diskless (initrd-as-root), so there is no dm-verity
rootfs to anchor. The measured cmdline is the FIXED constant
`packer/kbs-uki/uki/cmdline.blackbox` (`quiet panic=0 console=ttyS0`) —
no `dm-verity.root=`, no LUKS, no cloud-init, no netbird token — so the
digest is deterministic per CPU-generation.

## Why this KAT is NOT committed in the PR that added the target

This PR ships the build target + wiring INERT. The real launch digest
can only be produced by the full silicon-parity build (the pinned
snapshot.debian.org kernel + systemd-stub, the content-addressed OVMF
from s3.hippius.com, and `hippius-uki-measure --features snp` inside
the pinned Linux/amd64 Docker image). That runs on CI, not in the PR
author's environment, and a **faked** measurement value would be a
silent trust-anchor forgery — so none is committed here.

## Security must-have — operator/CI pins it, NEVER a miner

The host-attestor measurement is the value vali's §22 allowlist gates
the admin-release on (PR-9). It MUST be pinned by the operator/CI from
a reproducible build, and is **NEVER auto-pinned from a miner-reported
measurement** (a miner could report an attacker-controlled digest).
This mirrors the three-belt discipline in `packer/kbs-uki/uki/README.md`
and `test_vectors/uki/REGENERATE.md`.

## Pinning flow (first CI build, coupled to a §22 allowlist epoch)

```bash
# 1. Build the blackbox UKI on CI (or an operator's Linux/amd64 box).
make -C packer/kbs-uki/uki blackbox-uki

# 2. Verify reproducibility — the build is bit-for-bit deterministic.
make -C packer/kbs-uki/uki blackbox-uki-reproducible-check

# 3. Publish the pinned known-answer.
cp packer/kbs-uki/uki/output/blackbox-measurement.json \
   test_vectors/uki/blackbox-measurement.json

# 4. Add the digest to the §22 allowlist (AllowlistClass = host-attestor)
#    + bump the allowlist epoch, and commit both in the same PR.
```

Once `test_vectors/uki/blackbox-measurement.json` exists, the
`blackbox-uki-build` workflow (`.github/workflows/blackbox-uki-build.yml`)
diffs every build against it and fails loudly on any drift — identical
discipline to `uki-build.yml` for the tenant/kbs KAT. Until it is
pinned, that workflow emits a NOTICE and skips the comparison rather
than failing red.

## Per-CPU-generation note

`SNP_VCPU_TYPE` folds the host silicon's `cpu_sig` into the VMSA, so
the digest is per-generation. Build `make blackbox-uki` (Genoa default)
and `make blackbox-uki SNP_VCPU_TYPE=EpycTurin` produce distinct
digests; pin whichever generation(s) the fleet runs, re-attesting the
§22 allowlist per generation — exactly as the tenant/kbs KAT does.
