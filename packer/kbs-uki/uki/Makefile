# `packer/kbs-uki/uki/Makefile` — UKI build orchestrator.
#
# Reproducibility discipline (review applied):
#   - SOURCE_DATE_EPOCH derived from the LAST commit timestamp under
#     `packer/kbs-uki/` (path-scoped — see the `SOURCE_DATE_EPOCH ?=`
#     line below for the rationale).
#   - Docker --platform=linux/amd64 with the agent binary BUILT
#     INSIDE the container (multi-stage Dockerfile) so macOS Apple
#     Silicon dev reproduces CI Linux/amd64 byte-for-byte. The host's
#     `target/release/hippius-agent-initramfs` is NOT consumed.
#   - SBSIGN_KEY + SBSIGN_CRT default to the committed dev key
#     (see `../keys/dev/README.md` for the three-belt prod-use
#     defense); prod overrides via env var with arbitrary absolute
#     paths — the `sign` target mounts the file at a stable inner
#     path so paths outside the repo work.
#
# Public targets:
#   make uki                      — full pipeline: fetch → initramfs
#                                   → assemble → sign → measure.
#   make uki-reproducible-check   — runs `make uki` twice into
#                                   ISOLATED output/fetched/build
#                                   dirs and refuses to exit 0
#                                   unless every emitted byte is
#                                   byte-identical.
#   make blackbox-uki             — the DISKLESS host-attestor UKI
#                                   (chantier PR-6): same pipeline,
#                                   staging agent-host-attestor as
#                                   /init, no dm-verity rootfs, a
#                                   FIXED constant cmdline. Emits
#                                   blackbox-<ver>.uki.signed +
#                                   blackbox-measurement.json. INERT.
#   make blackbox-uki-reproducible-check
#                                 — the blackbox double-build byte-
#                                   identical gate.
#   make pin-base                 — resolves `debian:bookworm-slim`
#                                   + `rust:1.93-bookworm-slim` to
#                                   their current registry digests
#                                   for paste into the Dockerfile.
#   make pin-apt                  — boots the runtime stage with the
#                                   placeholder versions stripped,
#                                   dumps `apt-cache policy` for each
#                                   pinned package so the operator
#                                   can record the snapshot baseline.
#   make clean                    — wipes output / fetched / build.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# ── Reproducibility env ─────────────────────────────────────────────
# SOURCE_DATE_EPOCH = the commit timestamp of the LAST change to
# `packer/kbs-uki/`. Pinning to the *directory's* last touch (NOT
# repo HEAD) lets a KAT-only commit at `test_vectors/uki/
# measurement.json` — or any other unrelated push — ship without
# shifting the SDE, so the post-merge `make uki` continues to match
# the pinned KAT. Any change under `packer/kbs-uki/` shifts the SDE
# deliberately (a measurement-affecting commit re-attests the §22
# allowlist). Mirrors `packer/tenant-uki/uki/Makefile`'s SDE line
# (the original of this pattern, PR #146 round 1 + #150 + #155/#156).
# REQUIRES `fetch-depth: 0` on the workflow checkout, otherwise the
# path-scoped `git log` on a shallow clone returns empty and the
# fallback `echo 0` would clamp every cpio/squashfs mtime to
# 1970-01-01 → measurement collapse.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct -- $(abspath $(HERE)/..) 2>/dev/null || echo 0)
export SOURCE_DATE_EPOCH
export LC_ALL := C
export LANG := C
export TZ := UTC

# ── Paths ───────────────────────────────────────────────────────────
HERE        := $(abspath $(dir $(firstword $(MAKEFILE_LIST))))
REPO_ROOT   := $(abspath $(HERE)/../../..)
KEYS_DIR    := $(abspath $(HERE)/../keys/dev)
OUTPUT_DIR  := $(HERE)/output
FETCHED_DIR := $(HERE)/fetched
BUILD_DIR   := $(HERE)/build

# Inputs the Makefile reads from `inputs.lock`.
KERNEL_URL          := $(shell awk -F'= ' '/^KERNEL_URL/{print $$2}' $(HERE)/inputs.lock)
KERNEL_SHA256       := $(shell awk -F'= ' '/^KERNEL_SHA256/{print $$2}' $(HERE)/inputs.lock)
SYSTEMD_STUB_URL    := $(shell awk -F'= ' '/^SYSTEMD_STUB_URL/{print $$2}' $(HERE)/inputs.lock)
SYSTEMD_STUB_SHA256 := $(shell awk -F'= ' '/^SYSTEMD_STUB_SHA256/{print $$2}' $(HERE)/inputs.lock)

# OVMF firmware — pinned by SHA-256 in `../ovmf/ovmf.lock` (PR-F3). It
# is a measured input to the SEV-SNP launch digest.
OVMF_LOCK   := $(abspath $(HERE)/../ovmf/ovmf.lock)
OVMF_URL    := $(shell awk -F'= ' '/^OVMF_URL/{print $$2}' $(OVMF_LOCK))
OVMF_SHA256 := $(shell awk -F'= ' '/^OVMF_SHA256/{print $$2}' $(OVMF_LOCK))

# SEV-SNP launch parameters measured by `hippius-uki-measure --features
# snp` (PR-F3). They are part of the launch config and feed the launch
# digest, so changing one is a measurement-affecting PR — re-attest the
# §22 allowlist in lockstep.
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
# path OUTSIDE the repo — the docker run command mounts the file at
# a stable inner path so the script doesn't need to know.
SBSIGN_KEY ?= $(KEYS_DIR)/db.key
SBSIGN_CRT ?= $(KEYS_DIR)/db.crt
SBSIGN_KEY_ABS := $(abspath $(SBSIGN_KEY))
SBSIGN_CRT_ABS := $(abspath $(SBSIGN_CRT))

# ── Embedded agent selection (host-attestor chantier PR-6) ──────────
# WHICH binary the UKI stages into its initramfs `/init` slot. The
# Dockerfile builds BOTH agent-initramfs and agent-host-attestor and
# COPYs them to fixed in-container paths; these knobs pick one.
#   - default (this file)      → the tenant/kbs `agent-initramfs`.
#   - `make blackbox-*`        → the diskless `agent-host-attestor`
#                                (overrides below).
# AGENT_BINARY is the in-container path build-initramfs.sh installs;
# AGENT_STAGED_NAME is its in-cpio basename + the `/init` symlink
# target (kept as `hippius-agent-initramfs` by default so the tenant
# cpio bytes are unchanged).
AGENT_BINARY      ?= /opt/hippius/agent-initramfs
AGENT_STAGED_NAME ?= hippius-agent-initramfs

# Image stamp baked into the UKI's `.osrel` section and the output
# filename. Match Packer's `image_version` variable so PR-F4
# provenance correlates artefacts. The Makefile substitutes this
# into `os-release.template` at build time so a custom IMAGE_VERSION
# doesn't ship a stale VERSION_ID.
IMAGE_VERSION ?= 0.0.3-pr-f3

# ── Blackbox host-attestor UKI (host-attestor chantier PR-6) ────────
# The diskless measured UKI that packages `hippius-agent-host-attestor`
# (PR-4). It reuses the SAME pipeline as the tenant/kbs UKI but boots
# initrd-as-root with a FIXED constant cmdline (no dm-verity/LUKS/
# cloud-init/netbird), so the measurement is deterministic per CPU-gen.
# Ships INERT — nothing bakes or launches it (PR-7 wires the launch).
BLACKBOX_IMAGE_VERSION     ?= 0.0.1-blackbox
BLACKBOX_ARTIFACT_PREFIX   := blackbox
BLACKBOX_AGENT_BINARY      := /opt/hippius/agent-host-attestor
BLACKBOX_AGENT_STAGED_NAME := hippius-agent-host-attestor

# Docker image tag for the build environment.
DOCKER_TAG ?= hippius-uki-builder:$(IMAGE_VERSION)

# ── Phony targets ───────────────────────────────────────────────────
.PHONY: uki uki-reproducible-check fetch initramfs rootfs assemble sign \
        measure test-rootfs docker-build pin-base pin-apt clean \
        blackbox-uki blackbox-uki-reproducible-check blackbox-initramfs \
        blackbox-assemble blackbox-sign blackbox-measure

# Each pipeline step is a `docker run` mutating shared mounted dirs
# (/build/work, /build/fetched, /build/output); they are NOT safe to
# interleave. `.NOTPARALLEL` forces serial execution even under a
# `make -j` invoked from a parent build.
.NOTPARALLEL:

uki: docker-build measure

# Run the build twice into ISOLATED output / fetched / build dirs
# and refuse to exit 0 unless every emitted byte is identical. PR-F2
# review (review) flagged that sharing FETCHED/BUILD between runs
# would weaken the audit; full isolation is the only honest check.
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
# `.dockerignore` (repo root + here) trims `target/` etc.
docker-build:
	docker buildx build \
		--platform linux/amd64 \
		--load \
		-f $(HERE)/Dockerfile \
		-t $(DOCKER_TAG) \
		$(REPO_ROOT)

# Each pipeline step runs INSIDE the docker image so dev (macOS) and
# CI (Linux) execute the exact same binaries. The agent binary lives
# at `/opt/hippius/agent-initramfs` inside the image (COPY'd from
# the agent-builder stage); the repo is mounted read-only for the
# scripts + inputs.lock + cmdline + os-release.template only.
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
	$(DOCKER_RUN) /repo/packer/kbs-uki/uki/scripts/fetch-inputs.sh \
		"$(KERNEL_URL)" "$(KERNEL_SHA256)" \
		"$(SYSTEMD_STUB_URL)" "$(SYSTEMD_STUB_SHA256)" \
		"$(OVMF_URL)" "$(OVMF_SHA256)"

initramfs: fetch
	@mkdir -p $(BUILD_DIR)
	$(DOCKER_RUN) /repo/packer/kbs-uki/uki/scripts/build-initramfs.sh \
		$(AGENT_BINARY) $(AGENT_STAGED_NAME)

# dm-verity rootfs (PR-F3). Depends on `fetch` only for ordering —
# `fetch-inputs.sh` wipes /build/work, so `rootfs` must run after it,
# never before. build-rootfs.sh stages its own minimal tree and reads
# no fetched input.
rootfs: fetch
	@mkdir -p $(BUILD_DIR) $(OUTPUT_DIR)
	$(DOCKER_RUN) /repo/packer/kbs-uki/uki/scripts/build-rootfs.sh

# `assemble` needs the initramfs AND the dm-verity root hash (the
# effective cmdline embeds `dm-verity.root=<hash>`).
assemble: initramfs rootfs
	@mkdir -p $(OUTPUT_DIR)
	$(DOCKER_RUN) /repo/packer/kbs-uki/uki/scripts/assemble-uki.sh \
		$(IMAGE_VERSION)

# Mount the signing key + cert at fixed inner paths so the script
# doesn't need to translate host paths. This is the review-review fix
# for the `/repo/$(patsubst …)` bug that broke external prod-key
# overrides.
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
		/repo/packer/kbs-uki/uki/scripts/sign-uki.sh \
		/run/signing/db.key /run/signing/db.crt $(IMAGE_VERSION)

measure: sign
	# Runs INSIDE the Docker image (PR-F3). `hippius-uki-measure` is
	# COPY'd into the image at /opt/hippius/uki-measure, built
	# `--features snp` in the agent-builder stage — so it emits the
	# real `snp_launch_digest_v1` over the pinned OVMF + kernel +
	# initrd + the effective (verity-bearing) cmdline. The `sev`
	# measurement crate is Linux-only, hence the move into Docker.
	#
	# `--entrypoint` overrides the image's `/bin/bash` ENTRYPOINT (the
	# other steps run shell scripts; this one runs an ELF binary, which
	# bash would otherwise try to interpret as a script).
	#
	# --rootfs-verity-root is read on the HOST from the mounted build
	# dir (the value is also already inside cmdline.effective, so it
	# feeds the digest regardless; this records it in the audit trail).
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
		--uki                /build/output/kbs-$(IMAGE_VERSION).uki.signed \
		--kernel             /build/work/vmlinuz \
		--initrd             /build/work/initramfs.cpio \
		--cmdline            /build/work/cmdline.effective \
		--ovmf               /build/fetched/ovmf.bin \
		--rootfs-verity-root "$$(cat $(BUILD_DIR)/rootfs.roothash)" \
		--vcpus              $(SNP_VCPUS) \
		--vcpu-type          $(SNP_VCPU_TYPE) \
		--guest-features     $(SNP_GUEST_FEATURES) \
		--out                /build/output/measurement.json

# ── Blackbox host-attestor UKI pipeline (host-attestor chantier PR-6)
#
# The DISKLESS measured UKI. It reuses every stage of the pipeline
# above EXCEPT the dm-verity rootfs: the attestor boots initrd-as-root,
# so there is no `rootfs` step, no `dm-verity.root=` in the cmdline, and
# no `--rootfs-verity-root` in the measurement. The cmdline is the
# FIXED constant `uki/cmdline.blackbox` → the launch digest is identical
# per CPU-gen. Output: `blackbox-<version>.uki.signed` + a same-shape
# `blackbox-measurement.json` (minus the rootfs anchor field).
#
# Ships INERT — no bake / launch consumes it yet (PR-7).
blackbox-uki: docker-build blackbox-measure

# Stage the ATTESTOR binary as `/init` (AGENT_BINARY override → the
# COPY'd /opt/hippius/agent-host-attestor, staged name
# hippius-agent-host-attestor). Reuses the shared `initramfs` target
# via variable override so there is ONE initramfs build path.
blackbox-initramfs: fetch
	@mkdir -p $(BUILD_DIR)
	$(DOCKER_RUN) /repo/packer/kbs-uki/uki/scripts/build-initramfs.sh \
		$(BLACKBOX_AGENT_BINARY) $(BLACKBOX_AGENT_STAGED_NAME) host-attestor

# Diskless assemble — NO `rootfs` dependency (the diskless UKI has no
# dm-verity rootfs). `assemble-uki-blackbox.sh` embeds the fixed
# constant cmdline verbatim.
blackbox-assemble: blackbox-initramfs
	@mkdir -p $(OUTPUT_DIR)
	$(DOCKER_RUN) /repo/packer/kbs-uki/uki/scripts/assemble-uki-blackbox.sh \
		$(BLACKBOX_IMAGE_VERSION)

# Sign the blackbox artifact (prefix `blackbox`). Same key-mount recipe
# as `sign` — prod overrides via SBSIGN_KEY/SBSIGN_CRT identically.
blackbox-sign: blackbox-assemble
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
		/repo/packer/kbs-uki/uki/scripts/sign-uki.sh \
		/run/signing/db.key /run/signing/db.crt \
		$(BLACKBOX_IMAGE_VERSION) $(BLACKBOX_ARTIFACT_PREFIX)

# Measure the diskless launch. Identical SNP launch config to the
# tenant/kbs UKI (SNP_VCPUS / SNP_VCPU_TYPE / SNP_GUEST_FEATURES); the
# ONLY differences are `--diskless` (no rootfs anchor) and the fixed
# cmdline written by blackbox-assemble. Emits `blackbox-measurement.json`.
blackbox-measure: blackbox-sign
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
		--uki            /build/output/blackbox-$(BLACKBOX_IMAGE_VERSION).uki.signed \
		--kernel         /build/work/vmlinuz \
		--initrd         /build/work/initramfs.cpio \
		--cmdline        /build/work/cmdline.effective \
		--ovmf           /build/fetched/ovmf.bin \
		--diskless \
		--vcpus          $(SNP_VCPUS) \
		--vcpu-type      $(SNP_VCPU_TYPE) \
		--guest-features $(SNP_GUEST_FEATURES) \
		--out            /build/output/blackbox-measurement.json

# Double-build the blackbox UKI into isolated dirs; refuse exit 0
# unless every emitted byte is identical (the `.uki.signed` bytes are
# excluded for the same sbsign-timestamp reason as `uki-reproducible-
# check`; the measurement.json IS included in the diff).
blackbox-uki-reproducible-check: docker-build
	@set -e; \
	rm -rf $(OUTPUT_DIR)-bb-a $(OUTPUT_DIR)-bb-b \
	       $(FETCHED_DIR)-bb-a $(FETCHED_DIR)-bb-b \
	       $(BUILD_DIR)-bb-a   $(BUILD_DIR)-bb-b; \
	$(MAKE) blackbox-uki \
	    OUTPUT_DIR=$(OUTPUT_DIR)-bb-a \
	    FETCHED_DIR=$(FETCHED_DIR)-bb-a \
	    BUILD_DIR=$(BUILD_DIR)-bb-a >/dev/null; \
	$(MAKE) blackbox-uki \
	    OUTPUT_DIR=$(OUTPUT_DIR)-bb-b \
	    FETCHED_DIR=$(FETCHED_DIR)-bb-b \
	    BUILD_DIR=$(BUILD_DIR)-bb-b >/dev/null; \
	if diff -r --exclude='*.uki.signed' $(OUTPUT_DIR)-bb-a $(OUTPUT_DIR)-bb-b; then \
		echo "blackbox-uki-reproducible-check: PASS — outputs are byte-identical."; \
	else \
		echo "blackbox-uki-reproducible-check: FAIL — outputs diverged. Check"; \
		echo "  $(OUTPUT_DIR)-bb-a vs $(OUTPUT_DIR)-bb-b"; \
		exit 1; \
	fi

# Shell test for the dm-verity rootfs build (PR-F3): runs
# `build-rootfs.sh` twice and diffs the rootfs image + verity root
# hash. Self-skips the heavy run when mksquashfs / veritysetup are not
# on PATH, so it is safe to invoke on any host (and from CI).
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
	@echo "Paste both into packer/kbs-uki/uki/Dockerfile ARGs, then re-run \`make uki\`."

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
	rm -rf $(OUTPUT_DIR)-bb-a $(OUTPUT_DIR)-bb-b
	rm -rf $(FETCHED_DIR)-bb-a $(FETCHED_DIR)-bb-b
	rm -rf $(BUILD_DIR)-bb-a $(BUILD_DIR)-bb-b
