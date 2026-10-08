#!/usr/bin/env bash
# cdn-node bake profile (CDN plan I3), root-free:
#   1. tenant-image-bake.sh's --profile gate refuses what it must, before
#      any root / network / image step;
#   2. scripts/cdn-node/install-cdn-node.sh, run against a throwaway
#      rootfs (SUDO=""), writes the users, units, rendered configs, guard,
#      firewall and SSH masks the image needs, and refuses bad inputs.
# Same tier as disk-mode-test.sh (per-PR CI gate).
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "${HERE}/../.." && pwd)"
BAKE="${REPO}/scripts/tenant-image-bake.sh"
INSTALL="${REPO}/scripts/cdn-node/install-cdn-node.sh"
CFG="${REPO}/packer/cdn-node/openresty"

fail=0
ok() { echo "cdn-node-profile-test: OK — $*"; }
bad() { echo "cdn-node-profile-test: FAIL — $*" >&2; fail=1; }

TMP="$(mktemp -d)"
trap 'find "${TMP}" -mindepth 1 -delete; rmdir "${TMP}"' EXIT

# ── 1. bake-script gate ──────────────────────────────────────────────
run_bake() {
    set +e
    bash "${BAKE}" "$@" </dev/null 2>"${TMP}/err" >/dev/null
    RC=$?
    set -e
}
expect_die() { # message args...
    local want="$1"; shift
    run_bake "$@"
    if (( RC == 0 )) || ! grep -qF -- "${want}" "${TMP}/err"; then
        bad "bake $* did not die with '${want}' (rc=${RC}): $(cat "${TMP}/err")"
    else
        ok "bake refuses: ${want}"
    fi
}
printf '#!/bin/sh\nexit 0\n' > "${TMP}/agent"; chmod 0755 "${TMP}/agent"
mkdir -p "${TMP}/or/opt/openresty/nginx/sbin"
printf '#!/bin/sh\nexit 0\n' > "${TMP}/or/opt/openresty/nginx/sbin/nginx"
chmod 0755 "${TMP}/or/opt/openresty/nginx/sbin/nginx"
tar -czf "${TMP}/openresty.tar.gz" -C "${TMP}/or" opt
sha256sum "${TMP}/openresty.tar.gz" | awk '{print $1}' > "${TMP}/openresty.tar.gz.sha256"
CDN_OK=(--cdn-agent-bin "${TMP}/agent" --cdn-openresty-tarball "${TMP}/openresty.tar.gz"
        --cdn-config-dir "${CFG}" --cdn-backend-url https://api.example.invalid)

expect_die "--profile must be standard or cdn-node" --profile bogus
expect_die "--cdn-* flags need --profile cdn-node" --cdn-backend-url https://api.example.invalid
expect_die "needs --disk-mode golden_verity_overlay" --profile cdn-node "${CDN_OK[@]}"
expect_die "needs an executable --cdn-agent-bin" --profile cdn-node --disk-mode golden_verity_overlay \
    --cdn-openresty-tarball "${TMP}/openresty.tar.gz" --cdn-config-dir "${CFG}" --cdn-backend-url https://x.invalid
expect_die "needs --cdn-backend-url https" --profile cdn-node --disk-mode golden_verity_overlay \
    --cdn-agent-bin "${TMP}/agent" --cdn-openresty-tarball "${TMP}/openresty.tar.gz" \
    --cdn-config-dir "${CFG}" --cdn-backend-url http://plain.invalid
expect_die "needs --cdn-openresty-tarball" --profile cdn-node --disk-mode golden_verity_overlay \
    --cdn-agent-bin "${TMP}/agent" --cdn-openresty-tarball "${TMP}/absent.tar.gz" \
    --cdn-config-dir "${CFG}" --cdn-backend-url https://x.invalid
expect_die "--cdn-fleet-wildcard must be" --profile cdn-node --disk-mode golden_verity_overlay \
    "${CDN_OK[@]}" --cdn-fleet-wildcard cdn.example.test
expect_die "--cdn-fleet-wildcard must be" --profile cdn-node --disk-mode golden_verity_overlay \
    "${CDN_OK[@]}" --cdn-fleet-wildcard '*.Upper.example'
expect_die "--cdn-* flags need --profile cdn-node" --cdn-fleet-wildcard '*.c.example.test'
# A complete cdn-node request passes the gate and dies at the next check.
run_bake --profile cdn-node --disk-mode golden_verity_overlay "${CDN_OK[@]}"
if grep -qE 'profile (must|cdn-node needs)|cdn-\* flags' "${TMP}/err" \
    || ! grep -qF 'base-image-url is required' "${TMP}/err"; then
    bad "a complete cdn-node request did not pass the gate: $(cat "${TMP}/err")"
else
    ok "a complete cdn-node request passes the gate"
fi
# The default stays standard.
run_bake
grep -qF 'base-image-url is required' "${TMP}/err" && ok "default profile is valid" || bad "default profile"

# ── 2. installer against a throwaway rootfs ──────────────────────────
new_root() {
    local r="$1"
    mkdir -p "${r}/etc/systemd/system" "${r}/usr/sbin" "${r}/usr/bin"
    printf 'root:x:0:0:root:/root:/bin/bash\nsystemd-network:x:998:998::/:/usr/sbin/nologin\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n' > "${r}/etc/passwd"
    printf 'root:x:0:\nsystemd-network:x:998:\nubuntu:x:1000:\n' > "${r}/etc/group"
    printf 'root:*:1::::::\nubuntu:!:1::::::\n' > "${r}/etc/shadow"
    printf 'root:*::\nubuntu:!::\n' > "${r}/etc/gshadow"
}
R="${TMP}/root"
new_root "${R}"
SUDO="" bash "${INSTALL}" "${R}" "${TMP}/agent" "${TMP}/openresty.tar.gz" "${CFG}" \
    https://api.example.invalid >/dev/null

has() { # file pattern description
    if grep -qE -- "$2" "${R}$1"; then ok "$3"; else bad "$3 ($1 lacks /$2/)"; fi
}
has /etc/passwd '^cdn-agent:x:61101:61100:' "cdn-agent uid 61101"
has /etc/passwd '^openresty:x:61102:61100:.*:/usr/sbin/nologin$' "openresty uid 61102, no shell"
has /etc/group '^hippius-cdn:x:61100:cdn-agent,openresty$' "shared group hippius-cdn"
has /etc/group '^hippius-snp:x:61103:cdn-agent$' "hippius-snp for /dev/sev-guest"
has /etc/shadow '^cdn-agent:!\*:' "cdn-agent password locked"
[[ -x "${R}/opt/openresty/nginx/sbin/nginx" ]] && ok "OpenResty tree unpacked" || bad "OpenResty tree"
[[ -x "${R}/usr/sbin/hippius-cdn-agent" ]] && ok "agent installed" || bad "agent installed"
[[ -r "${R}/opt/hippius-cdn/lua/hippius_cdn/router.lua" && -x "${R}/opt/hippius-cdn/render.sh" ]] \
    && ok "Lua + render.sh installed" || bad "Lua + render.sh"

conf=/etc/hippius/cdn/nginx.conf
if grep -qE '@[A-Z0-9_]+@' "${R}${conf}"; then bad "nginx.conf has unrendered placeholders"; else ok "nginx.conf fully rendered"; fi
has "${conf}" 'listen unix:/run/cdn/ctl.sock;' "control socket in /run/cdn"
has "${conf}" 'meter_socket = "/run/cdn-agent/meter.sock"' "metering socket in /run/cdn-agent"
has "${conf}" 'include /opt/hippius-cdn/origin.conf;' "baked origin endpoint"
has "${conf}" 'listen 443 ssl default_server;' "TLS on 443"

toml=/etc/hippius/cdn-agent.toml
python3 -I - "${R}${toml}" <<'PY' && ok "agent config is valid TOML with the baked owner uid" || bad "agent config"
import sys, tomllib
c = tomllib.load(open(sys.argv[1], "rb"))
assert c["backend"]["url"] == "https://api.example.invalid"
assert c["backend"]["request_signatures"] is True
assert c["paths"]["control_socket_uid"] == 61102
assert c["paths"]["metering_socket"] == "/run/cdn-agent/meter.sock"
assert c["data_plane"]["attestation"] is True
assert c["identity"]["fleet_wildcard_hostname"] == "*.c.hipcdn.net"
assert set(c) == {"backend", "identity", "paths", "data_plane"}
PY

t=/etc/tmpfiles.d/hippius-cdn.conf
has "$t" '^d /var/lib/hippius-data/cache 0750 openresty hippius-cdn -$' "cache dir created at boot"
has "$t" '^d /var/lib/hippius-data/cdn 0700 cdn-agent hippius-cdn -$' "agent state dir created at boot"
if grep -q 'install -d .*/var/lib/hippius-data' "${R}"/etc/systemd/system/hippius-cdn-*.service; then
    bad "a unit creates a ReadWritePaths= directory in ExecStartPre (its namespace needs it first)"
else
    ok "no unit creates its ReadWritePaths= directory itself"
fi

u=/etc/systemd/system/hippius-cdn-openresty.service
has "$u" '^User=openresty$' "OpenResty runs as openresty"
has "$u" '^Group=hippius-cdn$' "OpenResty group hippius-cdn"
has "$u" '^UMask=0007$' "OpenResty UMask 0007"
has "$u" '^AmbientCapabilities=CAP_NET_BIND_SERVICE$' "only CAP_NET_BIND_SERVICE"
has "$u" '^CapabilityBoundingSet=CAP_NET_BIND_SERVICE$' "bounding set limited"
has "$u" '^RuntimeDirectory=cdn$' "RuntimeDirectory=cdn"
has "$u" '^RequiresMountsFor=/var/lib/hippius-data$' "OpenResty needs the data volume"
has "$u" '^ConditionPathIsMountPoint=/var/lib/hippius-data$' "OpenResty refuses the overlay fallback"
has "$u" 'render.sh placeholder /run/cdn/placeholder.pem' "placeholder pair at each start"
has "$u" 'render.sh cache-auto /run/cdn/cache.conf /var/lib/hippius-data/cache 75' "cache size at each start"
u=/etc/systemd/system/hippius-cdn-agent.service
has "$u" '^User=cdn-agent$' "agent runs as cdn-agent"
has "$u" '^SupplementaryGroups=hippius-snp$' "agent reaches /dev/sev-guest"
has "$u" '^LoadCredential=lifecycle.key:/run/hippius/lifecycle.key$' "lifecycle key via LoadCredential"
has "$u" '^LoadCredential=cdn-fleet:/run/hippius/cdn-fleet$' "fleet keys via LoadCredential"
has "$u" '^RuntimeDirectory=cdn-agent$' "agent-owned metering directory"
has "$u" '^RuntimeDirectoryMode=0750$' "metering directory not writable by OpenResty"
has "$u" '^CapabilityBoundingSet=$' "agent has no capabilities"
has "$u" '^ConditionPathIsMountPoint=/var/lib/hippius-data$' "agent refuses the overlay fallback"

for unit in hippius-cdn-openresty.service hippius-cdn-agent.service; do
    u=/etc/systemd/system/${unit}
    has "$u" '^InaccessiblePaths=.*-/run/netbird.sock .*-/var/run/netbird.sock.*-/run/hippius$' "${unit}: NetBird socket and release tmpfs unreachable"
    has "$u" '^LimitCORE=0$' "${unit}: no core dumps"
done
has /etc/systemd/system/hippius-cdn-openresty.service '^Requires=hippius-cdn-firewall.service$' "no listener without the firewall"
has /etc/systemd/system/hippius-cdn-openresty.service '^LimitNOFILE=1048576$' "OpenResty fd limit"
has /etc/systemd/system/hippius-cdn-agent.service '^LoadCredential=cdn-node.json:/run/hippius/cdn-node.json$' "identity via LoadCredential"
has /etc/hippius/cdn-agent.toml '^node_file = "/run/credentials/hippius-cdn-agent.service/cdn-node.json"$' "agent reads its identity credential"
has /etc/hippius/cdn-input.nft 'type filter hook prerouting priority -150' "wt0 restricted before input"
has /etc/systemd/network/50-hippius-dhcp.network.d/10-hippius-cdn.conf '^UseRoutes=no$' "no DHCP classless routes"
has /etc/systemd/network/50-hippius-dhcp.network.d/10-hippius-cdn.conf '^IPv6AcceptRA=no$' "no router advertisements"
has /etc/sysctl.d/60-hippius-cdn.conf '^net.ipv4.conf.all.accept_redirects = 0$' "no ICMP redirects"
for m in apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service snapd.service \
         hippius-public-ip-inbound.service hippius-public-ip-inbound.timer; do
    [[ "$(readlink "${R}/etc/systemd/system/${m}")" == /dev/null ]] && ok "masked ${m}" || bad "not masked: ${m}"
done
for link in sysinit.target.wants/hippius-cdn-firewall.service multi-user.target.wants/hippius-cdn-openresty.service \
            multi-user.target.wants/hippius-cdn-agent.service timers.target.wants/hippius-cdn-inbound.timer; do
    [[ -L "${R}/etc/systemd/system/${link}" && -f "${R}/etc/systemd/system/${link##*/}" ]] \
        && ok "enabled: ${link}" || bad "not enabled: ${link}"
done
for m in ssh.service ssh.socket sshd.service ssh@.service; do
    [[ "$(readlink "${R}/etc/systemd/system/${m}")" == /dev/null ]] && ok "masked ${m}" || bad "not masked: ${m}"
done
sh -n "${R}/usr/sbin/hippius-cdn-inbound" && ok "inbound guard parses" || bad "inbound guard syntax"
has /usr/sbin/hippius-cdn-inbound "tcp dport '\\{ 80, 443 \\}' accept" "guard opens 80/443 only (nft)"
has /usr/sbin/hippius-cdn-inbound '--dports 80,443' "guard opens 80/443 only (iptables)"
has /etc/hippius/cdn-input.nft '^        drop$' "input firewall drops the rest"
has /etc/udev/rules.d/60-hippius-cdn-sev-guest.rules 'GROUP="hippius-snp", MODE="0660"' "sev-guest group rule"

# ── 3. installer refusals ────────────────────────────────────────────
expect_install_die() { # message rootfs agent tarball cfg url
    local want="$1"; shift
    set +e
    SUDO="" bash "${INSTALL}" "$@" >/dev/null 2>"${TMP}/ierr"
    local rc=$?
    set -e
    if (( rc == 0 )) || ! grep -qF -- "${want}" "${TMP}/ierr"; then
        bad "installer did not refuse with '${want}' (rc=${rc}): $(cat "${TMP}/ierr")"
    else
        ok "installer refuses: ${want}"
    fi
}
expect_install_die "already exists in the base image" "${R}" "${TMP}/agent" "${TMP}/openresty.tar.gz" "${CFG}" https://api.example.invalid
R2="${TMP}/root2"; new_root "${R2}"
echo 0000 > "${TMP}/bad.sha"; cp "${TMP}/openresty.tar.gz" "${TMP}/badsum.tar.gz"; cp "${TMP}/bad.sha" "${TMP}/badsum.tar.gz.sha256"
expect_install_die "sha256 does not match" "${R2}" "${TMP}/agent" "${TMP}/badsum.tar.gz" "${CFG}" https://api.example.invalid
mkdir -p "${TMP}/evil/etc"; echo x > "${TMP}/evil/etc/evil"
tar -czf "${TMP}/evil.tar.gz" -C "${TMP}/or" opt -C "${TMP}/evil" etc
sha256sum "${TMP}/evil.tar.gz" | awk '{print $1}' > "${TMP}/evil.tar.gz.sha256"
expect_install_die "entry outside opt/openresty" "${R2}" "${TMP}/agent" "${TMP}/evil.tar.gz" "${CFG}" https://api.example.invalid
mkdir -p "${TMP}/lnk/opt/openresty"; ln -s /etc "${TMP}/lnk/opt/openresty/escape"
tar -czf "${TMP}/lnk.tar.gz" -C "${TMP}/lnk" opt
sha256sum "${TMP}/lnk.tar.gz" | awk '{print $1}' > "${TMP}/lnk.tar.gz.sha256"
expect_install_die "symlink opt/openresty/escape -> /etc" "${R2}" "${TMP}/agent" "${TMP}/lnk.tar.gz" "${CFG}" https://api.example.invalid
expect_install_die "backend url must be https" "${R2}" "${TMP}/agent" "${TMP}/openresty.tar.gz" "${CFG}" 'https://x.invalid/a b'
expect_install_die "fleet wildcard must be" "${R2}" "${TMP}/agent" "${TMP}/openresty.tar.gz" "${CFG}" \
    https://api.example.invalid 'c.example.test'
# An explicit wildcard is baked as given.
R4="${TMP}/root4"; new_root "${R4}"
SUDO="" bash "${INSTALL}" "${R4}" "${TMP}/agent" "${TMP}/openresty.tar.gz" "${CFG}" \
    https://api.example.invalid '*.cdn.example.test' >/dev/null
grep -qx 'fleet_wildcard_hostname = "\*.cdn.example.test"' "${R4}${toml}" \
    && ok "an explicit fleet wildcard is baked" || bad "explicit fleet wildcard"
R3="${TMP}/root3"; new_root "${R3}"; echo 'intruder:x:61102:61102::/:/bin/sh' >> "${R3}/etc/passwd"
expect_install_die "already exists in the base image" "${R3}" "${TMP}/agent" "${TMP}/openresty.tar.gz" "${CFG}" https://api.example.invalid

if (( fail )); then
    echo "cdn-node-profile-test: FAIL" >&2
    exit 1
fi
echo "cdn-node-profile-test: OK"
