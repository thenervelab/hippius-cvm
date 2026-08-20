# `packer/ovmf/` — reproducible AmdSevX64 OVMF build

Debian's stock `ovmf` package ships `OvmfPkgX64` — the standard OVMF
build, which has no SEV-SNP guest metadata table. The `sev` crate's
`snp_calc_launch_digest` (called by `hippius-uki-measure --features
snp`) refuses to bind the kernel/initrd/cmdline into the SEV-SNP launch
digest unless the OVMF includes the `SNP_KERNEL_HASHES` section —
which only the `OvmfPkg/AmdSev/AmdSevX64.dsc` build target emits.

This directory builds that target from a pinned edk2 source, uploads
the resulting `OVMF.fd` to `s3://hippius-compute-images/firmware/ovmf/
<sha>.fd`, and produces the URL + sha256 the `packer/kbs-uki/` UKI
build pins in its `ovmf.lock`.

## Why a separate workflow

`make uki` (the UKI build) is on the `push @ main` hot path; the edk2
build is 20–40 minutes on `linux/amd64`. We run the edk2 build only
when the operator deliberately bumps the pin (`packer/ovmf/inputs.lock`
or the builder `Dockerfile`) and re-host the resulting blob on
`s3.hippius.com`. The UKI build `curl`s + sha256-verifies that blob
like every other pinned input.

## Layout

| File | Purpose |
|---|---|
| `inputs.lock` | Pinned `EDK2_TAG` + `EDK2_COMMIT`. |
| `Dockerfile` | Trixie-based edk2 builder with all apt tools pinned by `=<version>`. |
| `Makefile` | `make ovmf` (single build) + `make ovmf-reproducible-check` (double-build + byte-diff). |
| `scripts/build-ovmf.sh` | Runs inside the builder image: clone edk2, verify commit sha, build `OvmfPkg/AmdSev/AmdSevX64.dsc`, drop `OVMF.fd` in `/out/`. |
| `output/` | Build outputs (git-ignored). |

## Operator flow — bump the pinned OVMF

1. Bump `EDK2_COMMIT` in `inputs.lock` to the new pinned stable tag's
   commit sha (verify against `tianocore/edk2`'s tag list).
2. Locally — or via `.github/workflows/ovmf-build.yml`'s
   `workflow_dispatch` — run:

   ```bash
   make -C packer/ovmf ovmf-reproducible-check
   ```

   This builds twice into isolated dirs and refuses to exit 0 unless
   `OVMF.fd` is byte-identical across runs.

3. Compute the sha + upload:

   ```bash
   SHA=$(sha256sum packer/ovmf/output-run-a/OVMF.fd | awk '{print $1}')
   aws s3 cp packer/ovmf/output-run-a/OVMF.fd \
       "s3://hippius-compute-images/firmware/ovmf/${SHA}.fd" \
       --endpoint-url https://s3.hippius.com \
       --content-type application/octet-stream \
       --acl public-read
   ```

4. Paste the URL + sha into `packer/kbs-uki/ovmf/ovmf.lock`:

   ```
   OVMF_URL    = https://s3.hippius.com/hippius-compute-images/firmware/ovmf/<SHA>.fd
   OVMF_SHA256 = <SHA>
   ```

5. The §22 allowlist epoch MUST be bumped in lockstep — a new OVMF
   changes the SEV-SNP launch digest, and the allowlist would otherwise
   refuse to release secrets to the new measurement.

## NOT a secret

The OVMF is public firmware — published as anonymous-readable on the
content-addressed s3 URL. It is pinned for *integrity* (reproducible
measurement), not confidentiality.

## Why the AmdSevX64 target specifically

- `OvmfPkg/OvmfPkgX64.dsc` (Debian's default) — no SEV-SNP metadata.
- `OvmfPkg/AmdSev/AmdSevX64.dsc` — emits the SEV-SNP guest metadata
  table at the reset-vector address, including:
    - the SEV-secret page descriptor;
    - the CPUID page descriptor;
    - **`SNP_KERNEL_HASHES`** — the section the `sev` crate folds the
      kernel / initrd / cmdline measurements into when computing the
      launch digest. Without it the digest covers only the OVMF blob
      and the `--kernel` flag is rejected.
- Other AMD-SEV targets (`AmdSev.dsc`, the legacy 32-bit SEV target)
  are not relevant — modern SEV-SNP guests are 64-bit X64 only.

## Reproducibility

The build is deterministic under:

- the pinned `debian:trixie-slim` digest (gcc / nasm / iasl / python3
  / uuid-dev / git all pinned by `=<version>` in the builder Dockerfile);
- the pinned `EDK2_COMMIT` (full sha, verified by `git rev-parse HEAD`);
- `SOURCE_DATE_EPOCH` (from the HEAD commit's `--format=%ct`);
- `LC_ALL=C`, `TZ=UTC`, `LANG=C` baked into the builder image.

`make ovmf-reproducible-check` enforces this by double-building into
isolated dirs and refusing to exit 0 on any byte drift.
