#!/usr/bin/env bash
# Stage the cdn-node data plane into a mounted guest rootfs (CDN plan I3).
#
#   install-cdn-node.sh <rootfs> <cdn-agent-bin> <openresty.tar.gz> <config-dir> <backend-url>
#
# Called by `tenant-image-bake.sh --profile cdn-node` after the standard
# customise (and after the sshd gates), while the rootfs is still mounted.
# Everything written here lands in the dm-verity base and so in the SNP
# launch measurement; nothing depends on user-data:
#   - fixed-id system users and groups (cdn-agent, openresty, hippius-cdn,
#     hippius-snp), so `control_socket_uid` can be baked;
#   - the OpenResty tree (/opt/openresty), its Lua and the config rendered
#     with the production values (/etc/hippius/cdn/nginx.conf);
#   - the agent (/usr/sbin/hippius-cdn-agent) and its config;
#   - the systemd units, enabled;
#   - the public-IP inbound guard (80/443 only), baked rather than in
#     user-data, and a guest input firewall;
#   - sshd masked (the bake purges the package before calling this).
#
# Root-free testable: SUDO="" runs every write directly (see
# scripts/dev/cdn-node-profile-test.sh).
set -euo pipefail

SUDO="${SUDO-sudo}"
die() { echo "install-cdn-node: $*" >&2; exit 3; }

[[ $# -eq 5 ]] || die "usage: install-cdn-node.sh <rootfs> <cdn-agent-bin> <openresty.tar.gz> <config-dir> <backend-url>"
ROOT="$1"; AGENT_BIN="$2"; OR_TARBALL="$3"; CFG_DIR="$4"; BACKEND_URL="$5"

# Fixed ids, outside Debian's dynamic system range (100-999) and its user
# range, inside the block Debian leaves for global allocation. Fixed so
# the agent's `control_socket_uid` can be baked and the image stays
# reproducible.
GID_CDN=61100   # hippius-cdn: shared by the agent and OpenResty (sockets)
UID_AGENT=61101 # cdn-agent
UID_OPENRESTY=61102 # openresty
GID_SNP=61103   # hippius-snp: /dev/sev-guest for the agent's attestation

# Production values of the data-plane template (packer/cdn-node/openresty).
# Constants of this (hashed) script: an environment override would escape
# the bake's stage-1 cache key. Change them here, after spike S1.
S3_REGION="us-east-1"
RATE_PER_IP="200r/s"
BURST_PER_IP="400"
CONN_PER_IP="256"

# ── inputs ───────────────────────────────────────────────────────────
[[ -d "${ROOT}/etc" && -d "${ROOT}/usr" ]] || die "${ROOT} is not a rootfs"
[[ -x "${AGENT_BIN}" ]] || die "${AGENT_BIN}: not executable"
[[ -r "${OR_TARBALL}" && -r "${OR_TARBALL}.sha256" ]] || die "${OR_TARBALL}(.sha256) missing"
[[ "$(sha256sum "${OR_TARBALL}" | awk '{print $1}')" == "$(tr -d '[:space:]' < "${OR_TARBALL}.sha256")" ]] \
    || die "${OR_TARBALL}: sha256 does not match its .sha256"
for f in render.sh nginx.conf.in origin.conf lua/hippius_cdn/router.lua; do
    [[ -r "${CFG_DIR}/${f}" ]] || die "${CFG_DIR}/${f} missing"
done
[[ "${BACKEND_URL}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$ ]] \
    || die "backend url must be https://host[:port][/path] (got '${BACKEND_URL}')"

# ── the OpenResty tarball, checked before anything is written ────────
# Every member is a directory, a regular file or a symlink under
# opt/openresty/ (plus the opt/ directory itself); no absolute or ".."
# path, no hard link or device, no member below a symlink (an extract as
# root would follow it), and every symlink target is a bare name in the
# same directory or an absolute path under /opt/openresty/.
python3 -I - "${OR_TARBALL}" <<'PY' || die "${OR_TARBALL}: refused (see above)"
import posixpath, re, sys, tarfile
bad = []
with tarfile.open(sys.argv[1], "r:gz") as t:
    members = t.getmembers()
links = {m.name.rstrip("/") for m in members if m.issym()}
for m in members:
    n = m.name.rstrip("/")
    parts = n.split("/")
    if n.startswith("/") or ".." in parts or not (n == "opt" or n.startswith("opt/openresty")):
        bad.append(f"entry outside opt/openresty: {m.name!r}")
    elif not (m.isdir() or m.isreg() or m.issym()):
        bad.append(f"entry type not allowed: {m.name!r}")
    elif any("/".join(parts[:k]) in links for k in range(1, len(parts))):
        bad.append(f"entry below a symlink: {m.name!r}")
    if m.issym():
        tgt = m.linkname
        ok = re.fullmatch(r"[A-Za-z0-9._-]+", tgt) or (
            re.fullmatch(r"/opt/openresty/[A-Za-z0-9._/-]+", tgt)
            and posixpath.normpath(tgt) == tgt
        )
        if not ok or tgt in (".", ".."):
            bad.append(f"symlink {m.name} -> {tgt}")
for b in bad:
    print("install-cdn-node: " + b, file=sys.stderr)
sys.exit(1 if bad else 0)
PY

w() { # write stdin to ROOT/$1 with mode $2
    ${SUDO} install -d -m 0755 "$(dirname "${ROOT}$1")"
    ${SUDO} tee "${ROOT}$1" >/dev/null
    ${SUDO} chmod "$2" "${ROOT}$1"
}
enable() { # enable unit $1 for target $2 (no systemctl in a chroot-less bake)
    ${SUDO} install -d -m 0755 "${ROOT}/etc/systemd/system/$2.wants"
    ${SUDO} ln -sfn "../$1" "${ROOT}/etc/systemd/system/$2.wants/$1"
}
mask() {
    ${SUDO} ln -sfn /dev/null "${ROOT}/etc/systemd/system/$1"
}

# ── users and groups (fixed ids, collision-checked) ──────────────────
id_free() { # file name id: neither the name nor the id may exist
    ! ${SUDO} awk -F: -v n="$2" -v i="$3" '$1 == n || $3 == i { found = 1 } END { exit !found }' "${ROOT}/etc/$1"
}
add_group() { # name gid members
    id_free group "$1" "$2" || die "group $1 or gid $2 already exists in the base image"
    echo "$1:x:$2:$3" | ${SUDO} tee -a "${ROOT}/etc/group" >/dev/null
    if [[ -f "${ROOT}/etc/gshadow" ]]; then
        echo "$1:!::$3" | ${SUDO} tee -a "${ROOT}/etc/gshadow" >/dev/null
    fi
}
add_user() { # name uid gid gecos
    id_free passwd "$1" "$2" || die "user $1 or uid $2 already exists in the base image"
    echo "$1:x:$2:$3:$4:/nonexistent:/usr/sbin/nologin" | ${SUDO} tee -a "${ROOT}/etc/passwd" >/dev/null
    if [[ -f "${ROOT}/etc/shadow" ]]; then
        echo "$1:!*:1::::::" | ${SUDO} tee -a "${ROOT}/etc/shadow" >/dev/null
    fi
}
add_group hippius-cdn "${GID_CDN}" "cdn-agent,openresty"
add_group hippius-snp "${GID_SNP}" "cdn-agent"
add_user cdn-agent "${UID_AGENT}" "${GID_CDN}" "Hippius CDN agent"
add_user openresty "${UID_OPENRESTY}" "${GID_CDN}" "Hippius CDN data plane"

# ── OpenResty tree ───────────────────────────────────────────────────
${SUDO} tar -xzf "${OR_TARBALL}" -C "${ROOT}" --no-same-permissions --numeric-owner
[[ -x "${ROOT}/opt/openresty/nginx/sbin/nginx" ]] || die "OpenResty binary missing after extract"

# Lua, render.sh, the origin endpoint: root-owned, read-only to services.
${SUDO} install -d -m 0755 "${ROOT}/opt/hippius-cdn" "${ROOT}/opt/hippius-cdn/lua/hippius_cdn"
for f in "${CFG_DIR}"/lua/hippius_cdn/*.lua; do
    ${SUDO} install -m 0644 "$f" "${ROOT}/opt/hippius-cdn/lua/hippius_cdn/"
done
${SUDO} install -m 0755 "${CFG_DIR}/render.sh" "${ROOT}/opt/hippius-cdn/render.sh"
${SUDO} install -m 0644 "${CFG_DIR}/origin.conf" "${ROOT}/opt/hippius-cdn/origin.conf"

# The config, rendered once here with the production values.
${SUDO} install -d -m 0755 "${ROOT}/etc/hippius/cdn"
rendered="$(mktemp)"
"${CFG_DIR}/render.sh" conf "${CFG_DIR}/nginx.conf.in" "${rendered}" \
    PREFIX=/opt/openresty PID=/run/cdn/nginx.pid TEMP_DIR=/run/cdn/tmp \
    LUA_DIR=/opt/hippius-cdn/lua DOCS_DICT_SIZE=512m \
    METER_SOCKET=/run/cdn-agent/meter.sock CACHE_DIR=/var/lib/hippius-data/cache \
    S3_REGION="${S3_REGION}" RESOLVER=127.0.0.53 CACHE_CONF=/run/cdn/cache.conf \
    ORIGIN_CONF=/opt/hippius-cdn/origin.conf RATE_PER_IP="${RATE_PER_IP}" \
    CTL_SOCKET=/run/cdn/ctl.sock CTL_MAX_BODY=256m LISTEN_HTTP=80 LISTEN_HTTPS=443 \
    PLACEHOLDER_CERT=/run/cdn/placeholder.pem PLACEHOLDER_KEY=/run/cdn/placeholder.key \
    BURST_PER_IP="${BURST_PER_IP}" CONN_PER_IP="${CONN_PER_IP}" \
    CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
w /etc/hippius/cdn/nginx.conf 0644 < "${rendered}"
rm -f "${rendered}"

# ── agent ────────────────────────────────────────────────────────────
${SUDO} install -m 0755 "${AGENT_BIN}" "${ROOT}/usr/sbin/hippius-cdn-agent"
w /etc/hippius/cdn-agent.toml 0644 <<EOF
# hippius-bake-managed (cdn-node profile). Measured with the image.
[backend]
url = "${BACKEND_URL}"
request_signatures = true

[identity]
node_file = "/run/credentials/hippius-cdn-agent.service/cdn-node.json"
lifecycle_key = "/run/credentials/hippius-cdn-agent.service/lifecycle.key"
fleet_key_dir = "/run/credentials/hippius-cdn-agent.service"

[paths]
state_dir = "/var/lib/hippius-data/cdn"
data_mount = "/var/lib/hippius-data"
cache_dir = "/var/lib/hippius-data/cache"
control_socket = "/run/cdn/ctl.sock"
control_socket_uid = ${UID_OPENRESTY}
metering_socket = "/run/cdn-agent/meter.sock"

[data_plane]
compression = ["gzip"]
attestation = true
EOF

# The agent's attestation reads /dev/sev-guest without root.
w /etc/udev/rules.d/60-hippius-cdn-sev-guest.rules 0644 <<'EOF'
# hippius-bake-managed: the CDN agent (group hippius-snp) requests the
# TLS-bound SNP report; every other user keeps no access.
SUBSYSTEM=="misc", KERNEL=="sev-guest", GROUP="hippius-snp", MODE="0660"
EOF

# ── data directories ─────────────────────────────────────────────────
# Created at boot by systemd-tmpfiles (before the services, which order
# after sysinit.target), not by an ExecStartPre: a unit's ReadWritePaths=
# must exist when its namespace is set up, and that setup also runs for a
# `+` ExecStartPre, so the start would fail on a fresh data volume.
w /etc/tmpfiles.d/hippius-cdn.conf 0644 <<'EOF'
# hippius-bake-managed (cdn-node profile): the cache and the agent's
# state on the guest-keyed data volume.
d /var/lib/hippius-data/cache 0750 openresty hippius-cdn -
d /var/lib/hippius-data/cdn 0700 cdn-agent hippius-cdn -
EOF

# ── units ────────────────────────────────────────────────────────────
w /etc/systemd/system/hippius-cdn-openresty.service 0644 <<'EOF'
# hippius-bake-managed (cdn-node profile).
[Unit]
Description=Hippius CDN data plane (OpenResty)
# The cache lives on the guest-keyed data volume. Without the bind the
# unit does not start rather than fall back to the overlay root.
RequiresMountsFor=/var/lib/hippius-data
ConditionPathIsMountPoint=/var/lib/hippius-data
# No public listener without the input firewall.
Requires=hippius-cdn-firewall.service
# The cache directory comes from tmpfiles (hippius-cdn.conf above), on the
# data volume the initramfs binds before switch-root.
After=network-online.target systemd-resolved.service hippius-cdn-firewall.service systemd-tmpfiles-setup.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
# The whole process, master included, runs unprivileged; only binding
# 80/443 is granted. The control socket it creates is therefore owned by
# openresty (the agent checks the owner before pushing secrets). nginx
# chmods a unix listener to 0666 whatever the umask: what keeps everyone
# but the agent out is /run/cdn itself, 0750 openresty:hippius-cdn
# (RuntimeDirectoryMode below). Do not loosen it.
User=openresty
Group=hippius-cdn
UMask=0007
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
RuntimeDirectory=cdn
RuntimeDirectoryMode=0750
ExecStartPre=/usr/bin/install -d -m 0700 /run/cdn/tmp
ExecStartPre=/opt/hippius-cdn/render.sh placeholder /run/cdn/placeholder.pem /run/cdn/placeholder.key
ExecStartPre=/opt/hippius-cdn/render.sh cache-auto /run/cdn/cache.conf /var/lib/hippius-data/cache 75
ExecStart=/opt/openresty/nginx/sbin/nginx -e stderr -c /etc/hippius/cdn/nginx.conf -g "daemon off;"
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
LimitNOFILE=1048576
# Nothing else on the node is reachable: NetBird's daemon socket (0666,
# unauthenticated gRPC that can re-point the daemon and enable root SSH),
# cloud-init's state and seed, NetBird's state, the KBS release tmpfs.
InaccessiblePaths=-/run/netbird.sock -/var/run/netbird.sock -/var/lib/netbird -/etc/netbird -/run/cloud-init -/var/lib/cloud -/run/hippius
LimitCORE=0
ProtectSystem=strict
ReadWritePaths=/var/lib/hippius-data/cache
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

w /etc/systemd/system/hippius-cdn-agent.service 0644 <<'EOF'
# hippius-bake-managed (cdn-node profile).
[Unit]
Description=Hippius CDN node agent
RequiresMountsFor=/var/lib/hippius-data
ConditionPathIsMountPoint=/var/lib/hippius-data
After=network-online.target hippius-cdn-openresty.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=cdn-agent
Group=hippius-cdn
SupplementaryGroups=hippius-snp
UMask=0077
# /run/cdn-agent: the metering socket's directory, owned by the agent and
# not writable by OpenResty (the agent refuses anything else).
RuntimeDirectory=cdn-agent
RuntimeDirectoryMode=0750
# The KBS-released lifecycle key and fleet keys (guest-release writes them
# to tmpfs as root); systemd copies them into this unit's private
# credentials directory. A missing one fails the start: no keys, no agent.
LoadCredential=lifecycle.key:/run/hippius/lifecycle.key
LoadCredential=cdn-fleet:/run/hippius/cdn-fleet
LoadCredential=cdn-node.json:/run/hippius/cdn-node.json
ExecStart=/usr/sbin/hippius-cdn-agent --config /etc/hippius/cdn-agent.toml run
# The node identity arrives with the KBS-released user-data; until it is
# there the agent exits and is restarted.
Restart=always
RestartSec=10
# Nothing else on the node is reachable: NetBird's daemon socket (0666,
# unauthenticated gRPC that can re-point the daemon and enable root SSH),
# cloud-init's state and seed, NetBird's state, the KBS release tmpfs.
InaccessiblePaths=-/run/netbird.sock -/var/run/netbird.sock -/var/lib/netbird -/etc/netbird -/run/cloud-init -/var/lib/cloud -/run/hippius
LimitCORE=0
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ReadWritePaths=/var/lib/hippius-data/cdn
ProtectHome=yes
PrivateTmp=yes
DevicePolicy=closed
DeviceAllow=/dev/sev-guest rw
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

# ── public-IP inbound guard (baked; the tenant version lives in user-data)
# The ingress edge DNATs the node's public IP to its overlay IP and
# forwards over wt0 with the internet source intact. NetBird's guest
# firewall drops non-overlay sources on wt0; this admits them, for TCP
# 80/443 only, and only while the edge's metadata server says this VM
# holds a public IP. Re-applied every 30 s (NetBird rebuilds its chains).
w /usr/sbin/hippius-cdn-inbound 0755 <<'EOF'
#!/bin/sh
# hippius-bake-managed (cdn-node profile): admit public-IP HTTP/HTTPS
# through NetBird's guest firewall.
set -eu
TAG=hippius-cdn-inbound
ip link show wt0 >/dev/null 2>&1 || exit 0  # not enrolled yet
# Only an answer over wt0 is the edge's; off it, the host could answer.
if ip route get 169.254.169.254 2>/dev/null | grep -q ' dev wt0 '; then
  code=$(curl -s -o /dev/null -m 3 -w '%{http_code}' \
    http://169.254.169.254/metadata/public-ip) || exit 0
  case $code in 200) want=1 ;; 404) want=0 ;; *) exit 0 ;; esac
else
  want=0
fi
T="ip netbird netbird-acl-input-filter"
if command -v nft >/dev/null 2>&1 && nft list chain $T >/dev/null 2>&1; then
  rules=$(nft -a list chain $T | grep '# handle' | grep -v 'chain ' || true)
  n=$(printf '%s\n' "$rules" | grep -c "$TAG" || true)
  if [ $want = 1 ] && [ "$n" = 1 ] &&
     printf '%s\n' "$rules" | head -n1 | grep -q "$TAG"; then exit 0; fi
  for h in $(printf '%s\n' "$rules" | grep "$TAG" | sed 's/.*# handle //'); do
    nft delete rule $T handle "$h"
  done
  [ $want = 1 ] || exit 0
  exec nft insert rule $T iifname wt0 ip saddr != 100.64.0.0/10 tcp dport '{ 80, 443 }' accept comment "\"$TAG\""
fi
R="-i wt0 ! -s 100.64.0.0/10 -p tcp -m multiport --dports 80,443 -m comment --comment $TAG -j ACCEPT"
if command -v iptables >/dev/null 2>&1 &&
   iptables -w -S INPUT | grep -q NETBIRD-ACL-INPUT; then
  n=$(iptables -w -S INPUT | grep -c "$TAG" || true)
  if [ $want = 1 ] && [ "$n" = 1 ] &&
     iptables -w -S INPUT 1 | grep -q "$TAG"; then exit 0; fi
  while iptables -w -D INPUT $R 2>/dev/null; do :; done
  [ $want = 1 ] || exit 0
  exec iptables -w -I INPUT 1 $R
fi
echo "NetBird input filter not found (yet); nothing to open" >&2
EOF
w /etc/systemd/system/hippius-cdn-inbound.service 0644 <<'EOF'
# hippius-bake-managed (cdn-node profile).
[Unit]
Description=Admit public-IP HTTP/HTTPS through NetBird's guest firewall
After=netbird.service
[Service]
Type=oneshot
ExecStart=/usr/sbin/hippius-cdn-inbound
EOF
w /etc/systemd/system/hippius-cdn-inbound.timer 0644 <<'EOF'
# hippius-bake-managed (cdn-node profile).
[Unit]
Description=Keep the CDN public-IP inbound rule in place
[Timer]
OnBootSec=10s
OnUnitActiveSec=30s
AccuracySec=1s
[Install]
WantedBy=timers.target
EOF

# ── guest input firewall ─────────────────────────────────────────────
# Off the overlay, a node takes nothing new: the miner's network reaches
# the VM's own NIC, and only DHCP, NetBird's WireGuard port and ICMP are
# admitted there. wt0 is left to NetBird's chains and the guard above (an
# accept in this table never overrides a drop in NetBird's).
w /etc/hippius/cdn-input.nft 0644 <<'EOF'
# hippius-bake-managed (cdn-node profile).
table inet hippius_cdn_input
delete table inet hippius_cdn_input
table inet hippius_cdn_input {
    # On the overlay, only HTTP/HTTPS (the edge's DNAT of the public IP),
    # replies and ICMP reach the node, whatever accept NetBird puts in its
    # own input chains: this hook runs before input.
    chain wt0_in {
        type filter hook prerouting priority -150; policy accept;
        iifname != "wt0" accept
        ct state established,related accept
        ct state invalid drop
        meta l4proto { icmp, ipv6-icmp } accept
        tcp dport { 80, 443 } accept
        drop
    }
    chain input {
        type filter hook input priority filter; policy accept;
        iifname "lo" accept
        ct state established,related accept
        ct state invalid drop
        iifname "wt0" accept
        meta l4proto { icmp, ipv6-icmp } accept
        udp dport { 68, 546 } accept
        udp dport 51820 accept
        drop
    }
}
EOF
w /etc/systemd/system/hippius-cdn-firewall.service 0644 <<'EOF'
# hippius-bake-managed (cdn-node profile).
[Unit]
Description=Hippius CDN guest input firewall
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
After=local-fs.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/hippius/cdn-input.nft
[Install]
WantedBy=sysinit.target
EOF

enable hippius-cdn-firewall.service sysinit.target
enable hippius-cdn-openresty.service multi-user.target
enable hippius-cdn-agent.service multi-user.target
enable hippius-cdn-inbound.timer timers.target

# ── DHCP and redirects from the miner's network ──────────────────────
# eth0 is the miner's. Take only an address, a gateway and resolvers from
# its DHCP server: no classless routes (they would beat NetBird's exit
# default), no NTP, MTU, hostname or domains, no IPv6 router
# advertisements, no ICMP redirects.
w /etc/systemd/network/50-hippius-dhcp.network.d/10-hippius-cdn.conf 0644 <<'EOF'
# hippius-bake-managed (cdn-node profile).
[Network]
IPv6AcceptRA=no
LinkLocalAddressing=ipv4

[DHCPv4]
UseRoutes=no
UseGateway=yes
UseNTP=no
UseMTU=no
UseHostname=no
UseDomains=no
EOF
w /etc/sysctl.d/60-hippius-cdn.conf 0644 <<'EOF'
# hippius-bake-managed (cdn-node profile).
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
kernel.core_pattern = |/bin/false
fs.suid_dumpable = 0
EOF

# ── nothing changes the measured software at runtime ─────────────────
# Updates are a new bake and a node replacement (CDN plan A.10).
for u in apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service \
         unattended-upgrades.service snapd.service snapd.socket snapd.seeded.service \
         motd-news.timer; do
    mask "$u"
done
# The tenant user-data's public-IP guard opens every port; a CDN node has
# its own (80/443). Masked so a tenant template written to this image can
# never be enabled.
for u in hippius-public-ip-inbound.service hippius-public-ip-inbound.timer; do
    mask "$u"
done

# ── no SSH, at all ───────────────────────────────────────────────────
# The bake purged openssh-server; masking keeps a later package or a
# socket unit from bringing a listener back.
for u in ssh.service ssh.socket sshd.service sshd.socket ssh@.service sshd@.service; do
    mask "$u"
done

echo "install-cdn-node: staged (agent uid ${UID_AGENT}, openresty uid ${UID_OPENRESTY}, backend ${BACKEND_URL})"
