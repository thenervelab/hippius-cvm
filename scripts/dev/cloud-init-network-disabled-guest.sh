#!/usr/bin/env bash
# Runs INSIDE a throwaway distro container (see
# cloud-init-network-disabled-test.sh). /t/99-hippius-network.cfg is the
# bake's cloud.cfg.d drop-in, byte for byte.
set -euo pipefail

NAME="cloud-init-network-disabled-guest"
fail=0
ok()  { echo "${NAME}: OK — $*"; }
err() { echo "${NAME}: FAIL — $*" >&2; fail=1; }

if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends cloud-init >/dev/null 2>&1
else
    dnf -y -q install cloud-init >/dev/null 2>&1
fi
DISTRO="$(. /etc/os-release && echo "${ID}-${VERSION_ID}")"
CI_VER="$(python3 -c 'from cloudinit.version import version_string; print(version_string())')"

# What cloud-init's init-local does to find the network config: the seed
# carries no network-config, so without our drop-in it falls back to
# generate_fallback_config() — the call that raced udev's eth0 → enp1s0
# rename on Fedora 43. Stubbed here to record whether it is reached.
probe() {
    python3 - <<'PY'
from cloudinit import stages
init = stages.Init(ds_deps=[])
calls = []
def fallback(*args, **kwargs):
    calls.append(1)
    return {"version": 2, "ethernets": {}}
init.distro.generate_fallback_config = fallback
cfg, src = init._find_networking_config()
print(f"cfg={cfg} src={getattr(src, 'value', src)} fallback_calls={len(calls)}")
PY
}

ctl="$(probe)"
[[ "${ctl}" == *"src=fallback fallback_calls=1"* ]] \
    && ok "${DISTRO} (cloud-init ${CI_VER}): control — no drop-in, cloud-init generates the fallback network config (${ctl})" \
    || err "${DISTRO}: control — expected the fallback path without the drop-in, got: ${ctl}"

install -m 0644 /t/99-hippius-network.cfg /etc/cloud/cloud.cfg.d/99-hippius-network.cfg
got="$(probe)"
[[ "${got}" == "cfg=None src=system_cfg fallback_calls=0" ]] \
    && ok "${DISTRO} (cloud-init ${CI_VER}): with the drop-in, network config is disabled by system_cfg and no fallback is generated" \
    || err "${DISTRO}: with the drop-in, expected 'cfg=None src=system_cfg fallback_calls=0', got: ${got}"

if [[ ${fail} -eq 0 ]]; then
    echo "${NAME}: ${DISTRO}: ALL OK"
else
    echo "${NAME}: ${DISTRO}: FAILURES" >&2
    exit 1
fi
