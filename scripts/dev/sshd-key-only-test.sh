#!/usr/bin/env bash
# SSH key-only on every golden distro, against the distro's REAL sshd and
# cloud-init. A tenant seed with `ssh_pwauth: true` made cloud-init write
# `PasswordAuthentication yes` to sshd_config.d/50-cloud-init.conf, which
# sshd reads before the cloud image's own `no` (first value wins), so
# `sshd -T` said passwordauthentication yes. The bake now ships
# sshd_config.d/00-hippius-harden.conf; this test lifts that drop-in and
# the bake's own `sshd -T` check out of scripts/tenant-image-bake.sh and,
# in a throwaway container per distro (sshd-key-only-guest.sh):
#   - reproduces the bug with cloud-init's own writer (control: the bake's
#     check must FAIL without the drop-in);
#   - proves the effective policy with the drop-in: passwords,
#     kbd-interactive, root login and X11 forwarding all off;
#   - runs the bake's check with and without /run/sshd, and checks it
#     leaves no probe drop-in behind;
#   - proves the tenant can still override it (an earlier-sorting drop-in,
#     or a Match block anywhere).
# Needs docker.
#
#   scripts/dev/sshd-key-only-test.sh [IMAGE ...]
#
# Default images: the four golden bases (Ubuntu 24.04, Debian 13,
# CentOS Stream 10, Fedora 43).
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BAKE="${HERE}/../tenant-image-bake.sh"
GUEST="${HERE}/sshd-key-only-guest.sh"
NAME="sshd-key-only-test"
[[ -r "${BAKE}" && -r "${GUEST}" ]] || { echo "${NAME}: ${BAKE} or ${GUEST} missing" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "${NAME}: docker is required" >&2; exit 1; }

T="$(mktemp -d)"
trap 'rm -rf -- "${T}"' EXIT
# Both are QUOTED heredocs, so the lifted text is byte-for-byte what the
# bake writes / feeds to the guest's shell.
awk "/<<'HIPPIUS_SSHD_HARDEN'\$/{f=1; next} /^HIPPIUS_SSHD_HARDEN\$/{f=0} f" "${BAKE}" > "${T}/00-hippius-harden.conf"
awk "/<<'SSHD_EFFECTIVE_EOF'\$/{f=1; next} /^SSHD_EFFECTIVE_EOF\$/{f=0} f" "${BAKE}" > "${T}/effective.sh"
grep -qx 'PasswordAuthentication no' "${T}/00-hippius-harden.conf" \
    || { echo "${NAME}: could not lift the <<'HIPPIUS_SSHD_HARDEN' drop-in from ${BAKE}" >&2; exit 1; }
grep -q 'sshd -T' "${T}/effective.sh" \
    || { echo "${NAME}: could not lift the <<'SSHD_EFFECTIVE_EOF' check from ${BAKE}" >&2; exit 1; }
chmod 0755 "${T}"
chmod 0644 "${T}"/*

[[ "$#" -gt 0 ]] || set -- mirror.gcr.io/library/ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55 mirror.gcr.io/library/debian:13@sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5 quay.io/centos/centos:stream10 mirror.gcr.io/library/fedora:43@sha256:a651ddf48ea28a06ed4e1e6519f51c9f47e7a5a138722ade87369b8fbb7e5b42
rc=0
# CentOS Stream 10 images from 2026-10-20 on are built for x86-64-v3 and
# die at exec ("Fatal glibc error: CPU does not support x86-64-v3") on a
# runner without AVX2/BMI2/FMA/MOVBE; quay garbage-collects the older
# manifests, so the leg cannot be pinned back. Skip it, loudly, on such a
# host: the tenant images themselves only ever boot on EPYC (v3 and up).
x86_64_v3() {
    local flags
    flags="$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null)"
    for f in avx2 bmi2 fma movbe; do
        [[ " ${flags} " == *" ${f} "* ]] || return 1
    done
}
for image in "$@"; do
    echo "== ${image}"
    if [[ "${image}" == *centos*stream10* ]] && ! x86_64_v3; then
        echo "${NAME}: SKIP ${image} — this CPU lacks x86-64-v3, which CentOS Stream 10 now requires"
        continue
    fi
    docker run --rm -v "${GUEST}:/sshd-key-only-guest.sh:ro" -v "${T}:/t:ro" "${image}" \
        bash /sshd-key-only-guest.sh || rc=1
done
if [[ ${rc} -eq 0 ]]; then
    echo "${NAME}: ALL OK"
else
    echo "${NAME}: FAILURES" >&2
    exit 1
fi
