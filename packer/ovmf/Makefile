# `packer/ovmf/Makefile` — orchestrator for the AmdSevX64 OVMF build.
#
# Public targets:
#   make ovmf                 — single build → `output/OVMF.fd`.
#   make ovmf-reproducible-check
#                             — runs `make ovmf` twice into ISOLATED
#                               dirs and refuses to exit 0 unless the
#                               two `OVMF.fd` files are byte-identical.
#   make docker-build         — build the edk2 builder image.
#   make pin-base             — print the current digest for
#                               `debian:trixie-slim` so the operator
#                               can paste it into the Dockerfile.
#   make clean                — wipe output / work.
#
# The operator runs `make ovmf` (or pushes a `packer/ovmf/` change to
# trigger `.github/workflows/ovmf-build.yml`), uploads the resulting
# `OVMF.fd` to `s3://hippius-compute-images/firmware/ovmf/<sha>.fd`,
# and pastes the URL + sha256 into `packer/kbs-uki/ovmf/ovmf.lock`.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
export SOURCE_DATE_EPOCH
export LC_ALL := C
export LANG := C
export TZ := UTC

HERE       := $(abspath $(dir $(firstword $(MAKEFILE_LIST))))
REPO_ROOT  := $(abspath $(HERE)/../..)
OUTPUT_DIR := $(HERE)/output
WORK_DIR   := $(HERE)/work

EDK2_TAG    := $(shell awk -F'= ' '/^EDK2_TAG/{print $$2}'    $(HERE)/inputs.lock)
EDK2_COMMIT := $(shell awk -F'= ' '/^EDK2_COMMIT/{print $$2}' $(HERE)/inputs.lock)

DOCKER_TAG ?= hippius-ovmf-builder:latest

.PHONY: ovmf ovmf-reproducible-check docker-build pin-base clean

.NOTPARALLEL:

ovmf: docker-build
	@mkdir -p $(OUTPUT_DIR) $(WORK_DIR)
	docker run --rm \
	    --platform linux/amd64 \
	    -e SOURCE_DATE_EPOCH \
	    -e LC_ALL -e LANG -e TZ \
	    -v $(REPO_ROOT):/repo:ro \
	    -v $(OUTPUT_DIR):/out \
	    -v $(WORK_DIR):/build/work \
	    -w /build \
	    $(DOCKER_TAG) \
	    /repo/packer/ovmf/scripts/build-ovmf.sh "$(EDK2_TAG)" "$(EDK2_COMMIT)"

# Run the build twice into ISOLATED output / work dirs and refuse to
# exit 0 unless every emitted byte is identical. The operator runs
# this BEFORE uploading to s3 so a non-deterministic build is caught
# locally instead of fingerprinting the §22 allowlist epoch.
ovmf-reproducible-check: docker-build
	@set -e; \
	rm -rf $(OUTPUT_DIR)-run-a $(OUTPUT_DIR)-run-b \
	       $(WORK_DIR)-run-a $(WORK_DIR)-run-b; \
	$(MAKE) ovmf OUTPUT_DIR=$(OUTPUT_DIR)-run-a WORK_DIR=$(WORK_DIR)-run-a; \
	$(MAKE) ovmf OUTPUT_DIR=$(OUTPUT_DIR)-run-b WORK_DIR=$(WORK_DIR)-run-b; \
	if diff -q $(OUTPUT_DIR)-run-a/OVMF.fd $(OUTPUT_DIR)-run-b/OVMF.fd >/dev/null; then \
		echo "ovmf-reproducible-check: PASS — OVMF.fd is byte-identical."; \
	else \
		echo "ovmf-reproducible-check: FAIL — runs diverged at"; \
		echo "  $(OUTPUT_DIR)-run-a/OVMF.fd vs $(OUTPUT_DIR)-run-b/OVMF.fd"; \
		exit 1; \
	fi

docker-build:
	docker buildx build \
	    --platform linux/amd64 \
	    --load \
	    -f $(HERE)/Dockerfile \
	    -t $(DOCKER_TAG) \
	    $(HERE)

pin-base:
	@echo "Resolving current digest for debian:trixie-slim..."
	@docker buildx imagetools inspect debian:trixie-slim \
	    --format '{{json .Manifest.Digest}}' \
	    | tr -d '"' \
	    | xargs -I{} echo "  Dockerfile DEBIAN_BASE_DIGEST={}"

clean:
	rm -rf $(OUTPUT_DIR) $(WORK_DIR) \
	       $(OUTPUT_DIR)-run-a $(OUTPUT_DIR)-run-b \
	       $(WORK_DIR)-run-a $(WORK_DIR)-run-b
