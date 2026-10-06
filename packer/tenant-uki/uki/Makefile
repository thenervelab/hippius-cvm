# `packer/tenant-uki/uki/Makefile` — tenant UKI build orchestrator.
#
# Mirror of `packer/kbs-uki/uki/Makefile`. The reproducibility regime
# is identical; the deltas are:
#   - output artefacts are named `tenant-${IMAGE_VERSION}.uki[.signed]`
#     (the kbs-flavour names them `kbs-…`);
#   - `fetch` passes the extra NETBIRD URL/SHA pair to `fetch-inputs.sh`
#     (tenant-rootfs bundles the NetBird static binary, kbs-rootfs
#     doesn't);
#   - the SBSIGN dev key and the OVMF pin are READ from
#     `packer/kbs-uki/` — one fleet-wide §22 dev key + one OVMF anchor
#     for both UKI flavours, never duplicated.
#
# Reproducibility discipline (review applied):
#   - SOURCE_DATE_EPOCH derived from the repo HEAD commit date
#     (`git log -1 --format=%ct`).
#   - Docker --platform=linux/amd64 with the agent binaries BUILT
#     INSIDE the container (multi-stage Dockerfile) so macOS Apple
#     Silicon dev reproduces CI Linux/amd64 byte-for-byte. The host's
#     `target/release/*` is NOT consumed.
#   - SBSIGN_KEY + SBSIGN_CRT default to the shared committed dev key
#     (`packer/kbs-uki/keys/dev/`); prod overrides via env var with
#     arbitrary absolute paths — the `sign` target mounts the file at
#     a stable inner path so paths outside the repo work.
#
# Public targets:
#   make uki                      — full pipeline: fetch → initramfs
#                                   → rootfs → assemble → sign → measure.
#   make uki-reproducible-check   — runs `make uki` twice into
#                                   ISOLATED output/fetched/build
#                                   dirs and refuses to exit 0
#                                   unless every emitted byte is
#                                   byte-identical.
#   make pin-base                 — resolves `debian:trixie-slim`
#                                   + `rust:1.93-slim-trixie` to
#                                   their current registry digests
#                                   for paste into the Dockerfile.
#   make pin-apt                  — boots the runtime stage at the
#                                   pinned digest and dumps
#                                   `apt-cache policy` for each
#                                   pinned package.
#   make clean                    — wipes output / fetched / build.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# ── Reproducibility env ─────────────────────────────────────────────
# SOURCE_DATE_EPOCH = the commit timestamp of the LAST change to
# `packer/tenant-uki/`. Pinning to the *directory's* last touch (NOT
# repo HEAD) lets a KAT-only commit at `test_vectors/uki/
# tenant-measurement.json` ship the measurement the SAME pipeline
# state produces — the SDE stays stable across the KAT-update commit,
# so `make uki-reproducible-check` continues to PASS. Any change under
# `packer/tenant-uki/` shifts the SDE deliberately (a measurement-
# affecting PR re-attests the §22 allowlist).
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct -- $(abspath $(HERE)/..) 2>/dev/null || echo 0)
export SOURCE_DATE_EPOCH
export LC_ALL := C
export LANG := C
export TZ := UTC

# ── Paths ───────────────────────────────────────────────────────────
HERE        := $(abspath $(dir $(firstword $(MAKEFILE_LIST))))
REPO_ROOT   := $(abspath $(HERE)/../../..)
# Shared §22 dev key + OVMF anchor live under `packer/kbs-uki/`. They
# are NOT duplicated under `packer/tenant-uki/` — there is one fleet
# trust anchor for both UKI flavours; the kbs-uki Makefile is the
# single owner of the rotation procedure. A future move to
# `packer/keys/dev/` + `packer/ovmf/` is a separate refactor.
KBS_UKI_DIR := $(abspath $(HERE)/../../kbs-uki)
KEYS_DIR    := $(abspath $(KBS_UKI_DIR)/keys/dev)
OUTPUT_DIR  := $(HERE)/output
FETCHED_DIR := $(HERE)/fetched
BUILD_DIR   := $(HERE)/build

# Inputs the Makefile reads from `inputs.lock`. NETBIRD_* are tenant-
# specific (the rootfs bundles the NetBird static binary).
KERNEL_URL          := $(shell awk -F'= ' '/^KERNEL_URL/{print $$2}' $(HERE)/inputs.lock)
KERNEL_SHA256       := $(shell awk -F'= ' '/^KERNEL_SHA256/{print $$2}' $(HERE)/inputs.lock)
SYSTEMD_STUB_URL    := $(shell awk -F'= ' '/^SYSTEMD_STUB_URL/{print $$2}' $(HERE)/inputs.lock)
SYSTEMD_STUB_SHA256 := $(shell awk -F'= ' '/^SYSTEMD_STUB_SHA256/{print $$2}' $(HERE)/inputs.lock)
NETBIRD_URL         := $(shell awk -F'= ' '/^NETBIRD_URL/{print $$2}' $(HERE)/inputs.lock)
NETBIRD_SHA256      := $(shell awk -F'= ' '/^NETBIRD_SHA256/{print $$2}' $(HERE)/inputs.lock)

# OVMF firmware — pinned by SHA-256 in the SHARED `packer/kbs-uki/
# ovmf/ovmf.lock`. It is a measured input to the SEV-SNP launch digest
# AND it is the same firmware kbs-uki measures, so the pin must NOT
# diverge — there is one §22 OVMF anchor for the whole fleet.
OVMF_LOCK   := $(abspath $(KBS_UKI_DIR)/ovmf/ovmf.lock)
# Fail LOUD if the shared OVMF lockfile (or the shared dev SBSIGN key
# below) is missing — a future kbs-uki refactor that moves these would
# otherwise silently produce empty OVMF_URL / OVMF_SHA256 here and
# surface only as an opaque `curl: no URL specified` at fetch time.
ifeq ($(wildcard $(OVMF_LOCK)),)
$(error tenant-uki Makefile: shared OVMF lock $(OVMF_LOCK) is missing — \
    a kbs-uki refactor probably moved it. Update KBS_UKI_DIR.)
endif
OVMF_URL    := $(shell awk -F'= ' '/^OVMF_URL/{print $$2}' $(OVMF_LOCK))
OVMF_SHA256 := $(shell awk -F'= ' '/^OVMF_SHA256/{print $$2}' $(OVMF_LOCK))

# SEV-SNP launch parameters measured by `hippius-uki-measure --features
# snp`. Identical to the kbs-uki defaults — the tenant CVM launches
# with the same vcpu count / VMM type as the kbs CVM, so the SNP
# `snp_calc_launch_digest` is comparable across UKI flavours.
#
# SNP_VCPU_TYPE folds the host silicon's cpu_sig into the VMSA, so it is
# PER-GENERATION: the default `EpycGenoa` measures the digest a Genoa
# host produces; for a Turin host (e.g. EPYC 9255)
# build the allowlist entry with `make SNP_VCPU_TYPE=EpycTurin`. The
# launch-time authority is the miner-agent, which derives the model from
# the host's own CPUID; this build-time value only pre-pins the matching
# §22 allowlist measurement (re-attest per generation).
SNP_VCPUS          ?= 1
SNP_VCPU_TYPE      ?= EpycGenoa
SNP_GUEST_FEATURES ?= 0x1

# Signing material. Resolve to absolute paths so docker `-v` mounts
# work regardless of cwd. Prod override via env var pointing to a
# path OUTSIDE the repo — the docker run command mounts the file at
# a stable inner path so the script doesn't need to know.
SBSIGN_KEY ?= $(KEYS_DIR)/db.key
SBSIGN_CRT ?= $(KEYS_DIR)/db.crt
SBSIGN_KEY_ABS := $(abspath $(SBSIGN_KEY))
SBSIGN_CRT_ABS := $(abspath $(SBSIGN_CRT))
# Fail LOUD when the DEFAULT (shared kbs-uki) signing key path is
# selected but the file is missing — same rationale as the OVMF
# lockfile check above. A prod override via env var routes through a
# different path and skips this check.
ifeq ($(SBSIGN_KEY),$(KEYS_DIR)/db.key)
ifeq ($(wildcard $(SBSIGN_KEY)),)
$(error tenant-uki Makefile: shared dev SBSIGN key $(SBSIGN_KEY) is missing — \
    a kbs-uki refactor probably moved it. Update KBS_UKI_DIR or set SBSIGN_KEY.)
endif
endif

# Image stamp baked into the UKI's `.osrel` section and the output
# filename. PR-F UKI tenant first publish defaults to `0.0.1-tenant`;
# bump on every measurement-affecting change.
IMAGE_VERSION ?= 0.0.1-tenant

# Docker image tag for the build environment. Distinct from kbs-uki's
# tag so a parallel docker host doesn't conflate the two stage caches.
DOCKER_TAG ?= hippius-tenant-uki-builder:$(IMAGE_VERSION)

# ── Phony targets ───────────────────────────────────────────────────
.PHONY: uki uki-reproducible-check fetch initramfs rootfs assemble sign \
        measure test-rootfs docker-build pin-base pin-apt clean

# Each pipeline step is a `docker run` mutating shared mounted dirs
# (/build/work, /build/fetched, /build/output); they are NOT safe to
# interleave. `.NOTPARALLEL` forces serial execution even under a
# `make -j` invoked from a parent build.
.NOTPARALLEL:

uki: docker-build measure

# Run the build twice into ISOLATED output / fetched / build dirs and
# refuse to exit 0 unless every emitted byte is identical.
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
		echo "  measurement.json file itself is included in the diff above."; \
		echo "  When sbsign gains a --no-timestamp flag, drop the --exclude.)"; \
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
# CI (Linux) execute the exact same binaries. The agent binaries live
# at `/opt/hippius/{agent-initramfs,tenant-telemetry}` inside the
# image (COPY'd from the agent-builder stage); the repo is mounted
# read-only for the scripts + inputs.lock + cmdline + os-release
# template only.
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

fetch:
	@mkdir -p $(FETCHED_DIR) $(BUILD_DIR)
	$(DOCKER_RUN) /repo/packer/tenant-uki/uki/scripts/fetch-inputs.sh \
		"$(KERNEL_URL)" "$(KERNEL_SHA256)" \
		"$(SYSTEMD_STUB_URL)" "$(SYSTEMD_STUB_SHA256)" \
		"$(OVMF_URL)" "$(OVMF_SHA256)" \
		"$(NETBIRD_URL)" "$(NETBIRD_SHA256)"

initramfs: fetch
	@mkdir -p $(BUILD_DIR)
	$(DOCKER_RUN) /repo/packer/tenant-uki/uki/scripts/build-initramfs.sh \
		/opt/hippius/agent-initramfs

# dm-verity rootfs — tenant variant bundles the tenant-telemetry
# binary + the NetBird static. `fetch` is the dependency: it both
# wipes /build/work (so this must come after) AND drops the NetBird
# binary at /build/work/netbird (which build-rootfs.sh consumes).
rootfs: fetch
	@mkdir -p $(BUILD_DIR) $(OUTPUT_DIR)
	$(DOCKER_RUN) /repo/packer/tenant-uki/uki/scripts/build-rootfs.sh

# `assemble` needs the initramfs AND the dm-verity root hash (the
# effective cmdline embeds `dm-verity.root=<hash>`).
assemble: initramfs rootfs
	@mkdir -p $(OUTPUT_DIR)
	$(DOCKER_RUN) /repo/packer/tenant-uki/uki/scripts/assemble-uki.sh \
		$(IMAGE_VERSION)

# Mount the signing key + cert at fixed inner paths so the script
# doesn't need to translate host paths.
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
		/repo/packer/tenant-uki/uki/scripts/sign-uki.sh \
		/run/signing/db.key /run/signing/db.crt $(IMAGE_VERSION)

measure: sign
	# Runs INSIDE the Docker image. `hippius-uki-measure` is COPY'd at
	# /opt/hippius/uki-measure, built `--features snp` so it emits the
	# real `snp_launch_digest_v1` over the pinned OVMF + kernel +
	# initrd + the effective (verity-bearing) cmdline.
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
		--uki                /build/output/tenant-$(IMAGE_VERSION).uki.signed \
		--kernel             /build/work/vmlinuz \
		--initrd             /build/work/initramfs.cpio \
		--cmdline            /build/work/cmdline.effective \
		--ovmf               /build/fetched/ovmf.bin \
		--rootfs-verity-root "$$(cat $(BUILD_DIR)/rootfs.roothash)" \
		--vcpus              $(SNP_VCPUS) \
		--vcpu-type          $(SNP_VCPU_TYPE) \
		--guest-features     $(SNP_GUEST_FEATURES) \
		--out                /build/output/measurement.json

# Shell test for the dm-verity rootfs build: runs `build-rootfs.sh`
# twice and diffs the rootfs image + verity root hash. Self-skips the
# heavy run when mksquashfs / veritysetup are not on PATH, so it is
# safe to invoke on any host (and from CI).
test-rootfs:
	bash $(HERE)/scripts/test-build-rootfs.sh

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
	@echo "Paste both into packer/tenant-uki/uki/Dockerfile ARGs, then re-run \`make uki\`."

# Pin against the EXACT digest the Dockerfile pins, not the floating
# `debian:trixie-slim` tag. Otherwise a registry-side tag move yields
# `pin-apt` output that disagrees with what the Docker build actually
# bases on — silently producing a non-reproducible `=<version>` set.
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
		  for pkg in ca-certificates curl cpio dpkg binutils sbsigntool systemd-boot-efi systemd-ukify squashfs-tools cryptsetup-bin libssl3t64 pkg-config libssl-dev libcryptsetup-dev libclang-19-dev; do \
		    v=$$(apt-cache policy "$$pkg" | awk "/Candidate:/{print \$$2}"); \
		    echo "  $${pkg}=$${v}"; \
		  done'

clean:
	rm -rf $(OUTPUT_DIR) $(FETCHED_DIR) $(BUILD_DIR)
	rm -rf $(OUTPUT_DIR)-run-a $(OUTPUT_DIR)-run-b
	rm -rf $(FETCHED_DIR)-run-a $(FETCHED_DIR)-run-b
	rm -rf $(BUILD_DIR)-run-a $(BUILD_DIR)-run-b
