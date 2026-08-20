# `packer/kbs-uki/ovmf/` — pinned OVMF firmware

The OVMF (Open Virtual Machine Firmware) binary is the guest firmware
the KBS SEV-SNP VM executes first. PR-F3 makes it a **measured input**
to the launch digest.

## Why it is pinned

`hippius-uki-measure --features snp` calls
`sev::measurement::snp::snp_calc_launch_digest`, which parses the OVMF
and folds its pages into the measurement an SEV-SNP hypervisor will
reproduce at launch. The §22 offline allowlist gates secret release on
that measurement, so the OVMF bytes are as load-bearing as the kernel:
a silently-swapped OVMF would silently change every measurement.

`ovmf.lock` pins the firmware by SHA-256. `../uki/scripts/fetch-inputs.sh`
downloads it and fails closed on any digest mismatch — identical
discipline to `../uki/inputs.lock` for the kernel + systemd-stub.

## SEV-SNP capability requirement

The OVMF must be built from an edk2 release that emits the SEV-SNP
guest metadata table. The `sev` crate's OVMF parser reads that table
for the reset vector and the measured page layout; a non-SNP OVMF will
fail to parse. A recent Debian `ovmf` package or an AMD edk2 build
both qualify.

## What PR-F3 ships

`ovmf.lock` with a **placeholder zero digest**. `make uki` /
`packer build` fails closed at fetch until an operator pins a real,
verified OVMF release. See the pinning procedure in `ovmf.lock`.

## NOT a secret

The OVMF is public firmware — no keys, no tenant data. It is pinned
for *integrity* (reproducible measurement), not confidentiality. The
PR-F6 secret-scan applies here as everywhere in this directory.
