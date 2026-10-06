# `packer/tenant-uki-debian/uki/Makefile` — Debian 13 tenant UKI
# build orchestrator (EPIC #186 Phase 1).
#
# Sibling factory to `packer/tenant-uki/uki/Makefile`. Same
# reproducibility regime; the deltas are:
#   - output artefacts are named `tenant-debian-${IMAGE_VERSION}.uki
#     [.signed]` (the placeholder names them `tenant-…`);
#   - `rootfs` invokes `debootstrap`-based `build-rootfs.sh` which
#     stands up a FULL Debian 13 userspace (systemd + sshd +
#     cloud-init + netbird + telemetry) — measurement-affecting, so a
#     §22 allowlist epoch covers it separately from the placeholder;
#   - `fetch` passes the extra DEBIAN_BOOTSTRAP_URL pair (for the
#     chroot apt repository) to `fetch-inputs.sh` alongside the
#     kernel + stub + ovmf + netbird pins.
#
# Reproducibility discipline (review convergent review pre-merge):
#   - SOURCE_DATE_EPOCH derived from the path-scoped commit timestamp
#     of `packer/tenant-uki-debian/` (NOT repo HEAD — same posture as
#     `packer/tenant-uki/uki/Makefile`'s SDE pin: a KAT-only commit
#     at `test_vectors/uki/tenant-debian-measurement.json` ships
#     without shifting the basis, so `uki-reproducible-check`
#     continues to PASS post-merge).
#   - Docker --platform=linux/amd64 with the agent binaries BUILT
#     INSIDE the container.
#   - SBSIGN_KEY + SBSIGN_CRT default to the shared §F dev key
#     (`packer/kbs-uki/keys/dev/`); prod overrides via env var.
#
# Public targets:
#   make uki                      — full pipeline: fetch → initramfs
#                                   → rootfs → assemble → sign → measure.
#   make uki-reproducible-check   — runs `make uki` twice into
#                                   ISOLATED output/fetched/build
#                                   dirs and refuses to exit 0
#                                   unless every emitted byte is
#                                   byte-identical. THE SHIPPING
#                                   GATE — debootstrap-based rootfs
#                                   reproducibility is the load-
#                                   bearing claim of this PR.
#   make pin-base                 — resolves `debian:trixie-slim` +
#                                   `rust:1.93-slim-trixie` to their
#                                   current registry digests.
#   make pin-apt                  — boots the runtime stage at the
#                                   pinned digest and dumps
#                                   `apt-cache policy` for each
#                                   pinned package.
#   make clean                    — wipes output / fetched / build.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# ── Reproducibility env ─────────────────────────────────────────────
# SOURCE_DATE_EPOCH = the commit timestamp of the LAST change to
# `packer/tenant-uki-debian/`. Pinning to the *directory's* last
# touch (NOT repo HEAD) lets a KAT-only commit at `test_vectors/uki/
# tenant-debian-measurement.json` ship the measurement the SAME
# pipeline state produces — the SDE stays stable across the KAT-
# update commit, so `make uki-reproducible-check` continues to PASS.
# Any change under `packer/tenant-uki-debian/` shifts the SDE
# deliberately (a measurement-affecting PR re-attests the §22
# allowlist).
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct -- $(abspath $(HERE)/..) 2>/dev/null || echo 0)
export SOURCE_DATE_EPOCH
export LC_ALL := C
export LANG := C
export TZ := UTC

# ── Paths ───────────────────────────────────────────────────────────
HERE        := $(abspath $(dir $(firstword $(MAKEFILE_LIST))))
REPO_ROOT   := $(abspath $(HERE)/../../..)
# Shared §22 dev key + OVMF anchor live under `packer/kbs-uki/`. They
# are NOT duplicated under `packer/tenant-uki-debian/` — there is one
# fleet trust anchor for every UKI flavour; the kbs-uki Makefile owns
# the rotation procedure.
KBS_UKI_DIR := $(abspath $(HERE)/../../kbs-uki)
KEYS_DIR    := $(abspath $(KBS_UKI_DIR)/keys/dev)
OUTPUT_DIR  := $(HERE)/output
FETCHED_DIR := $(HERE)/fetched
BUILD_DIR   := $(HERE)/build

# Inputs the Makefile reads from `inputs.lock`. NETBIRD_* is the same
# tarball the placeholder bundles; DEBIAN_BOOTSTRAP_* is the snapshot
# the in-chroot apt resolves against (NEW vs placeholder).
KERNEL_URL                    := $(shell awk -F'= ' '/^KERNEL_URL/{print $$2}' $(HERE)/inputs.lock)
KERNEL_SHA256                 := $(shell awk -F'= ' '/^KERNEL_SHA256/{print $$2}' $(HERE)/inputs.lock)
SYSTEMD_STUB_URL              := $(shell awk -F'= ' '/^SYSTEMD_STUB_URL/{print $$2}' $(HERE)/inputs.lock)
SYSTEMD_STUB_SHA256           := $(shell awk -F'= ' '/^SYSTEMD_STUB_SHA256/{print $$2}' $(HERE)/inputs.lock)
NETBIRD_URL                   := $(shell awk -F'= ' '/^NETBIRD_URL/{print $$2}' $(HERE)/inputs.lock)
NETBIRD_SHA256                := $(shell awk -F'= ' '/^NETBIRD_SHA256/{print $$2}' $(HERE)/inputs.lock)
DEBIAN_BOOTSTRAP_URL          := $(shell awk -F'= ' '/^DEBIAN_BOOTSTRAP_URL/{print $$2}' $(HERE)/inputs.lock)
DEBIAN_BOOTSTRAP_SECURITY_URL := $(shell awk -F'= ' '/^DEBIAN_BOOTSTRAP_SECURITY_URL/{print $$2}' $(HERE)/inputs.lock)

# OVMF firmware — pinned by SHA-256 in the SHARED `packer/kbs-uki/
# ovmf/ovmf.lock`.
OVMF_LOCK   := $(abspath $(KBS_UKI_DIR)/ovmf/ovmf.lock)
ifeq ($(wildcard $(OVMF_LOCK)),)
$(error tenant-uki-debian Makefile: shared OVMF lock $(OVMF_LOCK) is missing — \
    a kbs-uki refactor probably moved it. Update KBS_UKI_DIR.)
endif
OVMF_URL    := $(shell awk -F'= ' '/^OVMF_URL/{print $$2}' $(OVMF_LOCK))
OVMF_SHA256 := $(shell awk -F'= ' '/^OVMF_SHA256/{print $$2}' $(OVMF_LOCK))

# SEV-SNP launch parameters measured by `hippius-uki-measure --features
# snp`. Identical to the kbs-uki and placeholder defaults — same vcpu
# count / VMM type across UKI flavours.
#
# SNP_VCPU_TYPE folds the host silicon's cpu_sig into the VMSA, so it is
# PER-GENERATION: the default `EpycGenoa` measures a Genoa host
# digest; for a Turin host (e.g. EPYC 9255) build with
# `make SNP_VCPU_TYPE=EpycTurin`. The launch-time authority is the
# miner-agent (host-CPUID-derived); this only pre-pins the matching §22
# allowlist measurement (re-attest per generation).
SNP_VCPUS          ?= 1
SNP_VCPU_TYPE      ?= EpycGenoa
SNP_GUEST_FEATURES ?= 0x1

# Signing material. Resolve to absolute paths so docker `-v` mounts
# work regardless of cwd. Prod override via env var pointing to a
# path OUTSIDE the repo.
SBSIGN_KEY ?= $(KEYS_DIR)/db.key
SBSIGN_CRT ?= $(KEYS_DIR)/db.crt
SBSIGN_KEY_ABS := $(abspath $(SBSIGN_KEY))
SBSIGN_CRT_ABS := $(abspath $(SBSIGN_CRT))
ifeq ($(SBSIGN_KEY),$(KEYS_DIR)/db.key)
ifeq ($(wildcard $(SBSIGN_KEY)),)
$(error tenant-uki-debian Makefile: shared dev SBSIGN key $(SBSIGN_KEY) is missing — \
    a kbs-uki refactor probably moved it. Update KBS_UKI_DIR or set SBSIGN_KEY.)
endif
endif

# Image stamp baked into the UKI's `.osrel` section and the output
# filename. The basename prefix `tenant-debian-` (set in
# `assemble-uki.sh` / `sign-uki.sh`) already encodes the flavour, so
# the version itself is a clean SemVer-shape — the resulting artefact
# is `tenant-debian-0.0.1.uki.signed`, distinct from the placeholder's
# `tenant-0.0.1-tenant.uki.signed` so the two UKIs coexist on S3
# without an overwrite.
IMAGE_VERSION ?= 0.0.1

# Docker image tag for the build environment. Distinct from the
# placeholder's tag so a parallel docker host doesn't conflate the
# two stage caches.
DOCKER_TAG ?= hippius-tenant-uki-debian-builder:$(IMAGE_VERSION)

# ── Phony targets ───────────────────────────────────────────────────
.PHONY: uki uki-reproducible-check fetch initramfs rootfs assemble sign \
        measure docker-build pin-base pin-apt clean

# Each pipeline step is a `docker run` mutating shared mounted dirs
# (/build/work, /build/fetched, /build/output); they are NOT safe to
# interleave. `.NOTPARALLEL` forces serial execution even under a
# `make -j` invoked from a parent build.
.NOTPARALLEL:

uki: docker-build measure

# Run the build twice into ISOLATED output / fetched / build dirs and
# refuse to exit 0 unless every emitted byte is identical. THIS IS
# THE SHIPPING GATE for the Debian rootfs reproducibility claim —
# debootstrap + apt + cleanup must produce a byte-identical squashfs
# across runs. If this fails, the rootfs has unidentified
# non-determinism (mtime drift, UID drift, dpkg log leakage,
# /etc/machine-id randomness, ssh_host key generation, etc.).
uki-reproducible-check: docker-build
	@set -e; \
	rm -rf $(OUTPUT_DIR)-run-a $(OUTPUT_DIR)-run-b \
	       $(FETCHED_DIR)-run-a $(FETCHED_DIR)-run-b \
	       $(BUILD_DIR)-run-a   $(BUILD_DIR)-run-b; \
	$(MAKE) uki \
	    OUTPUT_DIR=$(OUTPUT_DIR)-run-a \
	    FETCHED_DIR=$(FETCHED_DIR)-run-a \
	    BUILD_DIR=$(BUILD_DIR)-run-a >/dev/null; \
	$(MAKE) uki \
	    OUTPUT_DIR=$(OUTPUT_DIR)-run-b \
	    FETCHED_DIR=$(FETCHED_DIR)-run-b \
	    BUILD_DIR=$(BUILD_DIR)-run-b >/dev/null; \
	if diff -r --exclude='*.uki.signed' $(OUTPUT_DIR)-run-a $(OUTPUT_DIR)-run-b; then \
		echo "uki-reproducible-check: PASS — outputs are byte-identical."; \
		echo "uki-reproducible-check: (the *.uki.signed bytes are excluded —"; \
		echo "  sbsign 0.9.4 embeds a wall-clock signing timestamp with no"; \
		echo "  --no-timestamp flag, so two signatures over IDENTICAL input"; \
		echo "  bytes differ. The launch_digest is computed over the UNSIGNED"; \
		echo "  UKI + kernel + initrd + cmdline + ovmf — none of which carry"; \
		echo "  the signature — so the §22 measurement IS reproducible. The"; \
		echo "  measurement.json file itself is included in the diff above.)"; \
	else \
		echo "uki-reproducible-check: FAIL — outputs diverged. Check"; \
		echo "  $(OUTPUT_DIR)-run-a vs $(OUTPUT_DIR)-run-b"; \
		exit 1; \
	fi

# Build the multi-stage Docker image. Build context = repo root so
# the `agent-builder` stage's `COPY . /src` sees the workspace.
docker-build:
	docker buildx build \
		--platform linux/amd64 \
		--load \
		-f $(HERE)/Dockerfile \
		-t $(DOCKER_TAG) \
		$(REPO_ROOT)

# Each pipeline step runs INSIDE the docker image so dev (macOS) and
# CI (Linux) execute the exact same binaries. The chroot step
# additionally needs `--privileged` because debootstrap mounts
# /proc + /sys + /dev/pts inside the bootstrap target — without
# CAP_SYS_ADMIN the bootstrap fails on the post-install hooks (the
# `--no-merged-usr` posture is unrelated; modern Debian uses
# merged-/usr unconditionally).
#
# We keep `--privileged` SCOPED to the rootfs step only (the other
# steps don't need it). The placeholder factory's DOCKER_RUN works
# unmodified for fetch/initramfs/assemble.
DOCKER_RUN := docker run --rm \
	--platform linux/amd64 \
	-e SOURCE_DATE_EPOCH \
	-e LC_ALL -e LANG -e TZ \
	-v $(REPO_ROOT):/repo:ro \
	-v $(OUTPUT_DIR):/build/output \
	-v $(FETCHED_DIR):/build/fetched \
	-v $(BUILD_DIR):/build/work \
	-w /build \
	$(DOCKER_TAG)

# Privileged variant — used ONLY by the `rootfs` step. `debootstrap`
# mounts /proc + /sys + /dev/pts inside the bootstrap target via
# `mount(2)` (CAP_SYS_ADMIN); without `--privileged` (or at minimum
# `--cap-add=SYS_ADMIN --security-opt apparmor=unconfined`) the
# bootstrap fails partway with `mount: permission denied`. The
# Docker container is itself isolated; the privileged escalation is
# scoped to the bootstrap chroot inside /build/work, and the
# resulting squashfs is verity-protected at boot.
DOCKER_RUN_PRIV := docker run --rm \
	--platform linux/amd64 \
	--privileged \
	-e SOURCE_DATE_EPOCH \
	-e LC_ALL -e LANG -e TZ \
	-v $(REPO_ROOT):/repo:ro \
	-v $(OUTPUT_DIR):/build/output \
	-v $(FETCHED_DIR):/build/fetched \
	-v $(BUILD_DIR):/build/work \
	-w /build \
	$(DOCKER_TAG)

fetch:
	@mkdir -p $(FETCHED_DIR) $(BUILD_DIR)
	$(DOCKER_RUN) /repo/packer/tenant-uki-debian/uki/scripts/fetch-inputs.sh \
		"$(KERNEL_URL)" "$(KERNEL_SHA256)" \
		"$(SYSTEMD_STUB_URL)" "$(SYSTEMD_STUB_SHA256)" \
		"$(OVMF_URL)" "$(OVMF_SHA256)" \
		"$(NETBIRD_URL)" "$(NETBIRD_SHA256)"

initramfs: fetch
	@mkdir -p $(BUILD_DIR)
	$(DOCKER_RUN) /repo/packer/tenant-uki-debian/uki/scripts/build-initramfs.sh \
		/opt/hippius/agent-initramfs

# dm-verity rootfs — the Debian flavour debootstraps a FULL trixie
# userspace inside /build/work/rootfs-staging, applies the
# reproducibility scrub (mtime / UID / machine-id / dpkg log / ssh
# host keys / resolv.conf / dbus machine-id), then `mksquashfs`'s
# the tree into rootfs.img and `veritysetup format`'s the hash tree.
# `--privileged` is REQUIRED — see DOCKER_RUN_PRIV comment above.
rootfs: fetch
	@mkdir -p $(BUILD_DIR) $(OUTPUT_DIR)
	$(DOCKER_RUN_PRIV) \
		/repo/packer/tenant-uki-debian/uki/scripts/build-rootfs.sh \
		"$(DEBIAN_BOOTSTRAP_URL)" "$(DEBIAN_BOOTSTRAP_SECURITY_URL)"

# `assemble` needs the initramfs AND the dm-verity root hash.
assemble: initramfs rootfs
	@mkdir -p $(OUTPUT_DIR)
	$(DOCKER_RUN) /repo/packer/tenant-uki-debian/uki/scripts/assemble-uki.sh \
		$(IMAGE_VERSION)

sign: assemble
	docker run --rm \
		--platform linux/amd64 \
		-e SOURCE_DATE_EPOCH -e LC_ALL -e LANG -e TZ \
		-v $(REPO_ROOT):/repo:ro \
		-v $(OUTPUT_DIR):/build/output \
		-v $(BUILD_DIR):/build/work \
		-v $(SBSIGN_KEY_ABS):/run/signing/db.key:ro \
		-v $(SBSIGN_CRT_ABS):/run/signing/db.crt:ro \
		-w /build \
		$(DOCKER_TAG) \
		/repo/packer/tenant-uki-debian/uki/scripts/sign-uki.sh \
		/run/signing/db.key /run/signing/db.crt $(IMAGE_VERSION)

measure: sign
	docker run --rm \
		--platform linux/amd64 \
		-e SOURCE_DATE_EPOCH -e LC_ALL -e LANG -e TZ \
		-v $(REPO_ROOT):/repo:ro \
		-v $(OUTPUT_DIR):/build/output \
		-v $(FETCHED_DIR):/build/fetched \
		-v $(BUILD_DIR):/build/work \
		-w /build \
		--entrypoint /opt/hippius/uki-measure \
		$(DOCKER_TAG) \
		--uki                /build/output/tenant-debian-$(IMAGE_VERSION).uki.signed \
		--kernel             /build/work/vmlinuz \
		--initrd             /build/work/initramfs.cpio \
		--cmdline            /build/work/cmdline.effective \
		--ovmf               /build/fetched/ovmf.bin \
		--rootfs-verity-root "$$(cat $(BUILD_DIR)/rootfs.roothash)" \
		--vcpus              $(SNP_VCPUS) \
		--vcpu-type          $(SNP_VCPU_TYPE) \
		--guest-features     $(SNP_GUEST_FEATURES) \
		--out                /build/output/measurement.json

pin-base:
	@echo "Resolving current digest for debian:trixie-slim..."
	@docker buildx imagetools inspect debian:trixie-slim \
		--format '{{json .Manifest.Digest}}' \
		| tr -d '"' \
		| xargs -I{} echo "  Dockerfile DEBIAN_BASE_DIGEST={}"
	@echo
	@echo "Resolving current digest for rust:1.93-slim-trixie..."
	@docker buildx imagetools inspect rust:1.93-slim-trixie \
		--format '{{json .Manifest.Digest}}' \
		| tr -d '"' \
		| xargs -I{} echo "  Dockerfile RUST_BUILDER_DIGEST={}"
	@echo
	@echo "Paste both into packer/tenant-uki-debian/uki/Dockerfile ARGs, then re-run \`make uki\`."

DEBIAN_BASE_DIGEST := $(shell awk -F'=' '/^ARG DEBIAN_BASE_DIGEST=/{print $$2}' \
                                $(HERE)/Dockerfile | head -n 1 | tr -d ' ')

pin-apt:
	@echo "Boots the runtime base AT THE PINNED DIGEST + dumps"
	@echo "apt-cache policy for each pinned package. Operator pastes"
	@echo "the EXACT VERSIONS into Dockerfile REPLACING the previous"
	@echo "pinned suffixes."
	@echo "  base = debian:trixie-slim@$(DEBIAN_BASE_DIGEST)"
	@docker run --rm --platform linux/amd64 \
		debian:trixie-slim@$(DEBIAN_BASE_DIGEST) \
		bash -lc 'apt-get update >/dev/null 2>&1 && \
		  for pkg in ca-certificates curl cpio dpkg binutils sbsigntool systemd-boot-efi systemd-ukify squashfs-tools cryptsetup-bin libssl3t64 xz-utils debootstrap mmdebstrap gnupg debian-archive-keyring; do \
		    v=$$(apt-cache policy "$$pkg" | awk "/Candidate:/{print \$$2}"); \
		    echo "  $${pkg}=$${v}"; \
		  done'

clean:
	rm -rf $(OUTPUT_DIR) $(FETCHED_DIR) $(BUILD_DIR)
	rm -rf $(OUTPUT_DIR)-run-a $(OUTPUT_DIR)-run-b
	rm -rf $(FETCHED_DIR)-run-a $(FETCHED_DIR)-run-b
	rm -rf $(BUILD_DIR)-run-a $(BUILD_DIR)-run-b
