# `test_vectors/uki/` — pinned UKI measurement KAT

`measurement.json` here is the **known-answer** for the §F UKI build:
`uki-build.yml` (`.github/workflows/uki-build.yml`) runs `make uki`,
emits its own `packer/kbs-uki/uki/output/measurement.json`, and `diff`s
it against this file. Any drift — a canonical-encoding change, a
fixture edit, a pinned-input swap, a non-reproducible build — fails CI
loudly instead of silently moving every production launch measurement.

## What's pinned here

The committed `measurement.json` is the output of one byte-for-byte
build with every input pinned:

| Input | Source |
|---|---|
| Linux kernel | `packer/kbs-uki/uki/inputs.lock::KERNEL_URL` (snapshot.debian.org) |
| systemd-boot stub | `packer/kbs-uki/uki/inputs.lock::SYSTEMD_STUB_URL` (snapshot.debian.org) |
| OVMF (AmdSevX64) | `packer/kbs-uki/ovmf/ovmf.lock::OVMF_URL` (built reproducibly by `packer/ovmf/`) |
| Builder image | `packer/kbs-uki/uki/Dockerfile` (trixie base + rust + apt all pinned) |
| Agent binary | Built from the workspace at the same commit |
| SNP launch config | `packer/kbs-uki/uki/Makefile` (`SNP_VCPUS=1`, `SNP_VCPU_TYPE=EpycV4`, `SNP_GUEST_FEATURES=0x1`) |
| Image version | `IMAGE_VERSION=0.0.3-pr-f3` |

The `measurement_kind` is `snp_launch_digest_v1` — the real AMD SEV-SNP
launch digest over OVMF + kernel + initrd + cmdline (bound through the
OVMF's `SNP_KERNEL_HASHES` metadata section, which the AmdSevX64 build
target emits).

## Regenerating after an intentional change

A change to ANY pinned input (kernel, OVMF, Dockerfile, agent code,
SNP launch config) shifts the launch digest → the §22 allowlist gates
release on it, so this is a measurement-affecting PR and must land in
lockstep with the §22 allowlist epoch bump.

The regen flow:

```bash
# 1. Bump whichever input is changing (e.g. `inputs.lock`).
# 2. Run the full build.
make -C packer/kbs-uki/uki uki

# 3. Verify reproducibility — the build is bit-for-bit deterministic.
make -C packer/kbs-uki/uki uki-reproducible-check

# 4. Re-publish the pinned-input KAT.
cp packer/kbs-uki/uki/output/measurement.json test_vectors/uki/measurement.json

# 5. Bump the §22 allowlist epoch + commit both in the same PR.
```

`uki-build.yml` enforces the KAT on every push to `main`:

```yaml
# .github/workflows/uki-build.yml
- name: Compare the measurement against test_vectors/uki/
  run: diff -u test_vectors/uki/measurement.json packer/kbs-uki/uki/output/measurement.json
```

A reviewer **must** sanity-check that the committed `measurement.json`
matches the output of a fresh `make uki` run before merging.
