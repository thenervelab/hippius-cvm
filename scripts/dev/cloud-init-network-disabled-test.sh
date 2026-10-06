#!/usr/bin/env bash
# cloud-init writes no network config on the golden distros: with the
# bake's cloud.cfg.d/99-hippius-network.cfg (`network: {config: disabled}`),
# each distro's REAL cloud-init must stop at system_cfg and never reach
# generate_fallback_config(), which raced udev's eth0 → enp1s0 rename on
# Fedora 43 (cloud-init 25.2: read_sys_net_safe(...).lower() on a bool, 1
# boot in 5 with no cloud-init network). Control: without the drop-in the
# fallback IS generated, or this test sees nothing.
#
# That the network still comes up without cloud-init (the bake's
# per-family DHCP profile) needs a booted VM:
# guest-network-without-cloud-init-boot.sh. The bake's static checks are in
# tenant-image-bake-m0-harden-test.sh. Needs docker.
#
#   scripts/dev/cloud-init-network-disabled-test.sh [IMAGE ...]
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BAKE="${HERE}/../tenant-image-bake.sh"
GUEST="${HERE}/cloud-init-network-disabled-guest.sh"
NAME="cloud-init-network-disabled-test"
[[ -r "${BAKE}" && -r "${GUEST}" ]] || { echo "${NAME}: ${BAKE} or ${GUEST} missing" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "${NAME}: docker is required" >&2; exit 1; }

T="$(mktemp -d)"
trap 'rm -rf -- "${T}"' EXIT
awk "/<<'HIPPIUS_CI_NETWORK'\$/{f=1; next} /^HIPPIUS_CI_NETWORK\$/{f=0} f" "${BAKE}" > "${T}/99-hippius-network.cfg"
grep -qx '  config: disabled' "${T}/99-hippius-network.cfg" \
    || { echo "${NAME}: could not lift the <<'HIPPIUS_CI_NETWORK' drop-in from ${BAKE}" >&2; exit 1; }
chmod 0755 "${T}"
chmod 0644 "${T}"/*

[[ "$#" -gt 0 ]] || set -- ubuntu:24.04 debian:13 quay.io/centos/centos:stream10 fedora:43
rc=0
for image in "$@"; do
    echo "== ${image}"
    docker run --rm -v "${GUEST}:/guest.sh:ro" -v "${T}:/t:ro" "${image}" bash /guest.sh || rc=1
done
if [[ ${rc} -eq 0 ]]; then
    echo "${NAME}: ALL OK"
else
    echo "${NAME}: FAILURES" >&2
    exit 1
fi
