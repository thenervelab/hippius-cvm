# `packer/ovmf/Dockerfile` — reproducible edk2 AmdSevX64 OVMF build.
#
# Why a dedicated builder image:
#   Debian's stock `ovmf` package ships `OvmfPkgX64` (no SEV-SNP guest
#   metadata). The `sev` crate's `snp_calc_launch_digest` needs the
#   `SNP_KERNEL_HASHES` section that ONLY the `OvmfPkg/AmdSev/AmdSevX64`
#   build target emits. Debian has no such package — we build it here
#   from a pinned edk2 commit and re-host the `OVMF.fd` on
#   `s3.hippius.com/firmware/ovmf/<sha>.fd`, which `packer/kbs-uki`
#   then pulls + sha256-verifies via `fetch-inputs.sh`.
#
# Why a separate workflow (not inline in the UKI build):
#   The edk2 build is heavy (20–40 min on linux/amd64 emulation).
#   Doing it on every `make uki` is unacceptable — and unnecessary,
#   because the OVMF only shifts when the §22 allowlist epoch shifts.
#   This image is built by `.github/workflows/ovmf-build.yml`
#   (manual / on-change of `packer/ovmf/`), the resulting `.fd` is
#   uploaded once to s3, and the kbs-uki build references the URL +
#   sha256 like every other pinned input.
#
# Reproducibility:
#   - Trixie base + all apt packages pinned by `=<version>`.
#   - edk2 commit pinned by full sha (see `inputs.lock`).
#   - SOURCE_DATE_EPOCH baked in from the operator (CI sets it from
#     the HEAD commit's `--format=%ct`).
#   - Locale + tz fixed (LC_ALL=C, TZ=UTC).
#   - The build orchestration (`build-ovmf.sh`) runs the build twice
#     into isolated `Build/` trees and refuses to ship a non-byte-
#     identical OVMF.

# syntax=docker/dockerfile:1.7

ARG DEBIAN_BASE_DIGEST=sha256:b6e2a152f22a40ff69d92cb397223c906017e1391a73c952b588e51af8883bf8

FROM --platform=linux/amd64 debian:trixie-slim@${DEBIAN_BASE_DIGEST}

ENV LC_ALL=C
ENV LANG=C
ENV TZ=UTC
ENV DEBIAN_FRONTEND=noninteractive

# edk2 build deps:
#   `build-essential` — gcc + make + binutils + libc-dev.
#   `nasm` — x86 assembler (edk2 ResetVector).
#   `acpica-tools` — `iasl`, the ACPI compiler edk2 uses.
#   `python3` + `python3-setuptools` — edk2 BaseTools + the `build` script.
#   `uuid-dev` — `libuuid` headers, linked by BaseTools.
#   `git` + `ca-certificates` — clone tianocore/edk2 over HTTPS.
#   `grub-common` + `grub-pc-bin` — `grub-mkimage` for
#     `OvmfPkg/AmdSev/Grub/grub.sh` (the AmdSev prebuild step bundles a
#     measured `grub.efi` into OVMF for the SEV-SNP boot chain).
RUN umask 022 && apt-get update && apt-get install --no-install-recommends -y \
        build-essential=12.12 \
        nasm=2.16.03-1 \
        acpica-tools=20250404-1 \
        python3=3.13.5-1 \
        python3-setuptools=78.1.1-0.1 \
        uuid-dev=2.41-5 \
        git=1:2.47.3-0+deb13u1 \
        ca-certificates=20250419 \
        grub-common=2.12-9+deb13u2 \
        grub-pc-bin=2.12-9+deb13u2 \
        grub-efi-amd64-bin=2.12-9+deb13u2 \
        dosfstools=4.2-1.2 \
        mtools=4.0.48-1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
ENTRYPOINT ["/bin/bash"]
