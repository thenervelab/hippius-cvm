#!/usr/bin/env bash
# `sign-uki.sh KEY_PATH CRT_PATH IMAGE_VERSION`
#
# Signs ONLY the `tenant-${IMAGE_VERSION}.uki` under /build/output/.
# Codex review flagged that an earlier `*.uki` glob signed stale
# artefacts from previous builds; the explicit version eliminates
# that.
#
# Signing is deterministic given the same key+cert+input — sbsign
# uses Authenticode (PE/COFF), which has no embedded timestamp by
# default.
#
# Key + cert are passed by ABSOLUTE in-container path; the Makefile
# mounts the operator-supplied files at `/run/signing/db.{key,crt}`
# so paths outside the repo (Vault transit cache, offline ceremony
# machine) work. The dev override defaults stay inside the repo.

set -euo pipefail
umask 022

if [[ $# -ne 3 ]]; then
    echo "usage: $0 KEY_PATH CRT_PATH IMAGE_VERSION" >&2
    exit 64
fi

KEY="$1"
CRT="$2"
IMAGE_VERSION="$3"

if [[ ! -f "$KEY" ]]; then
    echo "sign-uki: signing key not found at $KEY" >&2
    exit 65
fi
if [[ ! -f "$CRT" ]]; then
    echo "sign-uki: signing cert not found at $CRT" >&2
    exit 66
fi

UKI="/build/output/tenant-${IMAGE_VERSION}.uki"
if [[ ! -f "$UKI" ]]; then
    echo "sign-uki: $UKI not found — did assemble-uki.sh run?" >&2
    exit 67
fi

sbsign \
    --key "$KEY" \
    --cert "$CRT" \
    --output "${UKI}.signed" \
    "$UKI"

echo "sign-uki: signed $UKI → ${UKI}.signed" >&2
