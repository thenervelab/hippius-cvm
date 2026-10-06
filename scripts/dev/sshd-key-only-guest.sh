#!/usr/bin/env bash
# Runs INSIDE a throwaway distro container (see sshd-key-only-test.sh).
# /t holds what the host lifted from scripts/tenant-image-bake.sh:
#   00-hippius-harden.conf  the bake's drop-in, byte for byte
#   effective.sh            the bake's `sshd -T` check, as fed to the
#                           guest's /bin/sh (the bake runs it in a chroot)
set -euo pipefail

NAME="sshd-key-only-guest"
fail=0
ok()  { echo "${NAME}: OK — $*"; }
err() { echo "${NAME}: FAIL — $*" >&2; fail=1; }

# The distro's own openssh-server and cloud-init.
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        openssh-server cloud-init >/dev/null 2>&1
else
    dnf -y -q install openssh-server openssh-clients cloud-init >/dev/null 2>&1
fi
DISTRO="$(. /etc/os-release && echo "${ID}-${VERSION_ID}")"

D=/etc/ssh/sshd_config.d
DROPIN="${D}/00-hippius-harden.conf"
KEY="$(mktemp -d)/hk"
ssh-keygen -q -t ed25519 -N '' -f "${KEY}"
mkdir -p /run/sshd
# offered — the auth methods a running sshd offers a client that tries none
# (`Permission denied (publickey).` → `publickey`): the tenant-test check.
offered() {
    local pid out
    /usr/sbin/sshd -D -e -h "${KEY}" -p 2222 -o ListenAddress=127.0.0.1 2>/tmp/sshd-live.log &
    pid=$!
    for _ in $(seq 1 50); do
        out="$(ssh -p 2222 -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PubkeyAuthentication=no \
            -o PreferredAuthentications=none hippius-probe@127.0.0.1 true 2>&1 || true)"
        [[ "${out}" == *"Permission denied"* ]] && break
        sleep 0.2
    done
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
    tr -d '\r' <<<"${out}" | sed -n 's/.*Permission denied (\(.*\))\.*$/\1/p' | tail -n1
}
# eff KEYWORD [sshd -T args] — the value sshd will enforce.
eff() { local kw="$1"; shift; /usr/sbin/sshd -T -h "${KEY}" "$@" | sed -n "s/^${kw} //p"; }

grep -Eq '^Include /etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config \
    || err "${DISTRO}: sshd_config does not Include sshd_config.d — the drop-in would be ignored"

# What a seed with `ssh_pwauth: true` does: cloud-init's own writer.
python3 -c 'from cloudinit import ssh_util; ssh_util.update_ssh_config({"PasswordAuthentication": "yes"})'
grep -qx 'PasswordAuthentication yes' "${D}/50-cloud-init.conf" 2>/dev/null \
    || err "${DISTRO}: cloud-init did not write PasswordAuthentication yes to ${D}/50-cloud-init.conf: $(ls "${D}")"

# Control: without the drop-in, cloud-init's file turns passwords on — the
# bake's check must see it, or it proves nothing.
if sh /t/effective.sh >/tmp/ctl.out 2>&1; then
    err "${DISTRO}: control — the bake's sshd -T check PASSED without the drop-in (blind)"
else
    grep -q "^sshd -T: want 'passwordauthentication no', got 'passwordauthentication yes'" /tmp/ctl.out \
        && [[ "$(eff passwordauthentication)" == yes ]] \
        && [[ ",$(offered)," == *,password,* ]] \
        && ok "${DISTRO}: control — cloud-init's 50-cloud-init.conf turns password login on (a running sshd offers password), and the bake's check fails it" \
        || err "${DISTRO}: control — the bake's check did not fail on passwordauthentication yes: $(cat /tmp/ctl.out)"
fi

install -m 0644 /t/00-hippius-harden.conf "${DROPIN}"
run_was="$(ls -d /run/sshd)"
if sh /t/effective.sh >/tmp/eff.out 2>&1; then
    ok "${DISTRO}: the bake's sshd -T check passes with the drop-in over cloud-init's file"
else
    err "${DISTRO}: the bake's sshd -T check fails with the drop-in: $(cat /tmp/eff.out)"
fi
[[ ! -e "${D}/50-hippius-bake-probe.conf" ]] || err "${DISTRO}: the bake's check left its probe drop-in"
[[ "$(ls -d /run/sshd)" == "${run_was}" ]] || err "${DISTRO}: the bake's check removed a /run/sshd it did not create"
for kv in 'passwordauthentication no' 'kbdinteractiveauthentication no' 'permitrootlogin no' 'x11forwarding no' 'gssapiauthentication no' 'gssapikeyexchange no'; do
    [[ "$(eff "${kv%% *}")" == "${kv#* }" ]] || err "${DISTRO}: sshd -T ${kv%% *} = '$(eff "${kv%% *}")', want '${kv#* }'"
done
[[ "$(LC_ALL=C ls "${D}" | head -n1)" == 00-hippius-harden.conf ]] \
    || err "${DISTRO}: 00-hippius-harden.conf is not the first drop-in: $(LC_ALL=C ls "${D}")"
methods="$(offered)"
[[ "${methods}" == publickey ]] \
    || err "${DISTRO}: a running sshd offers '${methods}', want 'publickey' only ($(tail -n3 /tmp/sshd-live.log))"
[[ ${fail} -eq 0 ]] && ok "${DISTRO}: a running sshd offers (publickey) only"
[[ ${fail} -eq 0 ]] && ok "${DISTRO}: sshd -T = key-only (passwords, kbd-interactive, root, X11, GSSAPI off) over $(LC_ALL=C ls "${D}" | tr '\n' ' ')"

# The bake's check also runs on a base without /run/sshd (Ubuntu's
# package does not create it) and leaves none behind.
rmdir /run/sshd
if sh /t/effective.sh >/tmp/eff2.out 2>&1 && [[ ! -e /run/sshd ]]; then
    ok "${DISTRO}: the bake's check creates and removes a missing /run/sshd"
else
    err "${DISTRO}: the bake's check without /run/sshd: rc/out $(cat /tmp/eff2.out); /run/sshd $(ls -d /run/sshd 2>&1)"
fi
mkdir -p /run/sshd

# The tenant keeps control: a drop-in sorting first, or a Match block in
# any file, overrides the default.
printf 'PasswordAuthentication yes\n' > "${D}/00-00-local.conf"
[[ "$(eff passwordauthentication)" == yes ]] \
    && ok "${DISTRO}: a tenant drop-in sorting before 00-hippius-harden.conf overrides it" \
    || err "${DISTRO}: a tenant 00-00-local.conf does not override the default"
rm -f "${D}/00-00-local.conf"
printf 'Match all\n    PasswordAuthentication yes\n' > "${D}/90-local.conf"
[[ "$(eff passwordauthentication -C user=tenant,host=client,addr=203.0.113.7)" == yes ]] \
    && ok "${DISTRO}: a tenant Match block in a later drop-in overrides it" \
    || err "${DISTRO}: a tenant Match block does not override the default"
rm -f "${D}/90-local.conf"

if [[ ${fail} -eq 0 ]]; then
    echo "${NAME}: ${DISTRO}: ALL OK"
else
    echo "${NAME}: ${DISTRO}: FAILURES" >&2
    exit 1
fi
