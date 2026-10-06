#!/usr/bin/env bash
# Regression test for the untrusted-miner (M0) hardening in
# `scripts/tenant-image-bake.sh`.
#
# WHY this exists: the miner writes the libvirt domain XML, and nothing
# it attaches beyond OVMF + kernel + initrd + cmdline is in the SNP
# launch measurement. Two holes were proven live on throwaway golden
# VMs:
#   C2 — a miner-attached disk labelled `cidata` was consumed by
#        cloud-init's NoCloud datasource (default `fs_label: cidata`):
#        attacker instance-id + ssh key merged into meta-data, and the
#        KEK still released.
#   C3 — qemu-guest-agent on the RHEL-family images answered a
#        miner-hotplugged virtio channel (guest-exec as root).
# Plus the adjacent surfaces: systemd-ssh-generator (sshd on AF_VSOCK)
# and a serial-getty on the miner-owned console.
# The bake's own `exit 3` assertions only run inside a real bake (root,
# loop devices, network), so without this test a regression surfaces at
# the next golden bake at best — or ships.
#
# HOW: root-free. The hardening sections are lifted VERBATIM from the
# bake by their anchors and run against a temp rootfs with a PATH shim
# for `sudo` (runs the command as-is) and for `apt-get` / `dnf` (a
# purge/remove deletes that package's binaries from the fixture rootfs).
# The bake's post-customise assertion block is run as-is too, both on
# the hardened tree (must pass) and on trees missing one item each
# (must `exit 3`). The written cloud-init config is then fed to the REAL
# cloud-init `DataSourceNoCloud` (nocloud-seed-precedence-check.py)
# against an attacker `cidata` disk and SMBIOS serial. If an anchor
# moves the test fails loudly rather than silently testing nothing.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BAKE="${HERE}/../tenant-image-bake.sh"
PRECEDENCE="${HERE}/nocloud-seed-precedence-check.py"
NAME="tenant-image-bake-m0-harden-test"
[[ -r "${BAKE}" ]] || { echo "${NAME}: bake script not found at ${BAKE}" >&2; exit 1; }

fail=0
ok()  { echo "${NAME}: OK — $*"; }
err() { echo "${NAME}: FAIL — $*" >&2; fail=1; }
die() { echo "${NAME}: $*" >&2; exit 1; }

WORK="$(mktemp -d -t hippius-bake-m0-harden-test.XXXXXX)"
trap 'rm -rf -- "${WORK}"' EXIT

# ── 1. Lift the sections ────────────────────────────────────────────
# slice FILE START_ERE STOP_ERE — START line included, STOP excluded.
# Patterns ride ENVIRON, not -v (which would eat their backslashes).
slice() { S_RE="$2" E_RE="$3" awk '$0 ~ ENVIRON["S_RE"] {f=1} f && $0 ~ ENVIRON["E_RE"] {exit} f' "$1"; }
# The two chroot bodies are QUOTED heredocs, so the text between opener
# and terminator is byte-for-byte what runs inside the chroot.
apt_body="${WORK}/apt-body.sh"
rhel_body="${WORK}/rhel-body.sh"
awk "/^sudo tee .* <<'CHROOT_EOF'\$/{f=1; next} /^CHROOT_EOF\$/{f=0} f" "${BAKE}" > "${apt_body}"
awk "/^sudo tee .* <<'CHROOT_RHEL_EOF'\$/{f=1; next} /^CHROOT_RHEL_EOF\$/{f=0} f" "${BAKE}" > "${rhel_body}"
[[ -s "${apt_body}" ]]  || die "could not find the quoted <<'CHROOT_EOF' body in ${BAKE}"
[[ -s "${rhel_body}" ]] || die "could not find the quoted <<'CHROOT_RHEL_EOF' body in ${BAKE}"

# A: cloud-init NoCloud pin + ds-identify policy (outer script, MNT_ROOT).
sect_cloud="$(slice "${BAKE}" '^sudo tee "\$\{MNT_ROOT\}/etc/cloud/cloud\.cfg\.d/99-hippius-nocloud\.cfg"' '^# Single guest IP')"
# B: apt-arm guest-agent purge (inside the chroot).
sect_apt="$(slice "${apt_body}" '^# Untrusted miner \(M0 hardening\): the miner can attach' '^# Tell cryptsetup-initramfs')"
# C: dnf-arm guest-agent removal (inside the chroot).
sect_dnf="$(slice "${rhel_body}" '^# Untrusted miner \(M0 hardening\): same as the apt arm' '^dnf clean all')"
# D: generator / getty masks (outer script, every family).
sect_mask="$(slice "${BAKE}" '^# Untrusted miner \(M0 hardening\), every family:' '^# Post-customise assertions for the M0 hardening')"
# E: the bake's own post-customise assertions (up to the sshd -T block,
# which needs the guest's own sshd: sshd-key-only-test runs it per distro).
sect_assert="$(slice "${BAKE}" '^# Post-customise assertions for the M0 hardening' '^# Effective sshd policy')"
# F: sshd key-only drop-in, no in-place root growth, headless masks
# (outer script, every family).
sect_sshd="$(slice "${BAKE}" '^# SSH key-only by default \(every family\)' '^# Untrusted miner \(M0 hardening\), every family:')"
# G: guest network without cloud-init (outer script, per family).
sect_net="$(slice "${BAKE}" '^# The guest network does NOT come from cloud-init' '^if \[\[ "\$\{DISTRO_FAMILY\}" == "debian" \]\]; then$')"

[[ -n "${sect_cloud}" ]]  || die "section A anchor (99-hippius-nocloud.cfg tee … # Single guest IP) not found — bake script moved?"
[[ -n "${sect_apt}" ]]    || die "section B anchor (apt-arm M0 purge … # Tell cryptsetup-initramfs) not found — bake script moved?"
[[ -n "${sect_dnf}" ]]    || die "section C anchor (dnf-arm M0 removal … dnf clean all) not found — bake script moved?"
[[ -n "${sect_mask}" ]]   || die "section D anchor (M0 every-family masks … # Post-customise assertions) not found — bake script moved?"
[[ -n "${sect_assert}" ]] || die "section E anchor (# Post-customise assertions … # Effective sshd policy) not found — bake script moved?"
[[ -n "${sect_net}" ]]    || die "section G anchor (# The guest network does NOT come from cloud-init … if DISTRO_FAMILY == debian) not found — bake script moved?"
[[ -n "${sect_sshd}" ]]   || die "section F anchor (# SSH key-only by default … # Untrusted miner (M0 hardening), every family:) not found — bake script moved?"
grep -q 'ds-identify.cfg' <<<"${sect_cloud}"   || die "section A does not write ds-identify.cfg — wrong slice"
grep -q 'apt-get purge' <<<"${sect_apt}"       || die "section B has no apt-get purge — wrong slice"
grep -q 'dnf .*remove' <<<"${sect_dnf}"        || die "section C has no dnf remove — wrong slice"
grep -q 'exit 3' <<<"${sect_assert}"           || die "section E has no 'exit 3' — wrong slice"
grep -q '00-hippius-harden.conf' <<<"${sect_sshd}" || die "section F does not write 00-hippius-harden.conf — wrong slice"
grep -q 'hippius-dhcp.nmconnection' <<<"${sect_net}" || die "section G does not write the NetworkManager profile — wrong slice"
if grep -Eq '(^|[^_[:alnum:]])log[[:space:]]' <<<"${sect_cloud}${sect_mask}${sect_assert}${sect_sshd}${sect_net}"; then
    die "a lifted outer section calls the bake's log(); extend the harness"
fi

write_section() {
    { echo 'set -euo pipefail'; printf '%s\n' "$2"; } > "${WORK}/$1.sh"
    bash -n "${WORK}/$1.sh" || die "lifted section $1 does not parse"
}
write_section cloud  "${sect_cloud}"
write_section apt    "${sect_apt}"
write_section dnf    "${sect_dnf}"
write_section mask   "${sect_mask}"
write_section assert "${sect_assert}"
write_section sshd   "${sect_sshd}"
# The bake's die() (exit 3), for the sections that call it.
write_section net    "die() { echo \"FATAL: \$*\" >&2; exit 3; }
${sect_net}"

# ── 2. Shims ────────────────────────────────────────────────────────
SHIM="${WORK}/bin"
mkdir -p "${SHIM}"
cat > "${SHIM}/sudo" <<'SHIM_EOF'
#!/usr/bin/env bash
exec "$@"
SHIM_EOF
# Package → the binaries the bake's assertion looks for. A purge/remove
# deletes them from the fixture rootfs; anything else is a no-op.
cat > "${SHIM}/pkg-remove" <<'SHIM_EOF'
#!/usr/bin/env bash
set -eu
for arg in "$@"; do
    case "${arg}" in
        qemu-guest-agent) rm -f -- "${FAKE_ROOT:?}/usr/bin/qemu-ga" "${FAKE_ROOT:?}/usr/sbin/qemu-ga" ;;
        spice-vdagent)    rm -f -- "${FAKE_ROOT:?}/usr/bin/spice-vdagent" ;;
        open-vm-tools)    rm -f -- "${FAKE_ROOT:?}/usr/bin/vmtoolsd" "${FAKE_ROOT:?}/usr/sbin/vmtoolsd" ;;
    esac
    echo "${arg}" >> "${FAKE_ROOT:?}/.pkg-removed"
done
SHIM_EOF
# unmkinitramfs <initrd> <dir>: the fixture initrd's unpacked tree lives
# at <root>/.initrd-trees/<initrd name> (laid out like the real tool's main/).
cat > "${SHIM}/unmkinitramfs" <<'SHIM_EOF'
t="$(dirname "$(dirname "$1")")/.initrd-trees/$(basename "$1")"
[[ -d "${t}" ]] || { echo "unmkinitramfs shim: no ${t}" >&2; exit 1; }
mkdir -p "$2" && cp -a "${t}/." "$2/"
# .unreadable-after-unpack: the unpacked seed is then unreadable to the
# auditor (as a root-only file is to a non-root reader).
if [[ -e "${t}/.unreadable-after-unpack" ]]; then find "$2" -name .random-seed -exec chmod 000 {} +; fi
SHIM_EOF
cat > "${SHIM}/apt-get" <<'SHIM_EOF'
#!/usr/bin/env bash
[[ "$1" == purge ]] || { echo "apt-get shim: unexpected $*" >&2; exit 2; }
shift; exec pkg-remove "$@"
SHIM_EOF
cat > "${SHIM}/dnf" <<'SHIM_EOF'
#!/usr/bin/env bash
[[ "$1" == -y && "$2" == remove ]] || { echo "dnf shim: unexpected $*" >&2; exit 2; }
shift 2; exec pkg-remove "$@"
SHIM_EOF
chmod +x "${SHIM}"/*

# ── 3. Fixture rootfs + runners ─────────────────────────────────────
# A cloud image as it arrives: every guest agent installed, and a
# systemd >=256 ssh generator (Fedora / CS10 ship one).
new_root() {
    local root="${WORK}/root-$1"
    rm -rf -- "${root:?}"
    mkdir -p "${root}/etc/cloud/cloud.cfg.d" "${root}/etc/systemd/system" \
             "${root}/usr/bin" "${root}/usr/sbin" "${root}/usr/lib/systemd/system-generators"
    local bin
    for bin in usr/bin/qemu-ga usr/sbin/qemu-ga usr/bin/spice-vdagent usr/bin/vmtoolsd \
               usr/lib/systemd/system-generators/systemd-ssh-generator usr/sbin/NetworkManager; do
        printf '#!/bin/sh\n' > "${root}/${bin}"
        chmod +x "${root}/${bin}"
    done
    # systemd-networkd enabled, as on the Ubuntu and Debian cloud images.
    mkdir -p "${root}/etc/systemd/system/multi-user.target.wants" "${root}/usr/lib/systemd/system"
    : > "${root}/usr/lib/systemd/system/systemd-networkd.service"
    ln -s /usr/lib/systemd/system/systemd-networkd.service \
        "${root}/etc/systemd/system/multi-user.target.wants/systemd-networkd.service"
    echo "${root}"
}
# run_in ROOT SECTION — outer sections see MNT_ROOT; chroot sections run
# with FAKE_ROOT for the package shims (their paths are chroot-relative
# and never touch the filesystem themselves).
run_in() {
    PATH="${SHIM}:/usr/bin:/bin" MNT_ROOT="$1" FAKE_ROOT="$1" DISTRO_FAMILY="${FAMILY:-debian}" \
        bash "${WORK}/$2.sh" >"$1/.out-$2" 2>&1
}

# bake_family FAMILY — the M0 steps in bake order for that family.
bake_family() {
    local family="$1" root pkg_section
    root="$(new_root "${family}")"
    [[ "${family}" == apt ]] && pkg_section=apt || pkg_section=dnf
    [[ "${family}" == apt ]] && FAMILY=debian || FAMILY=rhel
    # Fedora/CS10 ship sshd_config.d 0700: the bake must not widen it.
    [[ "${family}" == apt ]] || install -d -m 0700 "${root}/etc/ssh/sshd_config.d"
    local s
    for s in cloud net "${pkg_section}" sshd mask; do
        run_in "${root}" "${s}" || { err "${family}: lifted section '${s}' exited $?: $(cat "${root}/.out-${s}")"; return; }
    done
    set +e; run_in "${root}" assert; local rc=$?; set -e
    [[ ${rc} -eq 0 ]] || err "${family}: the bake's own M0 assertions fail on the hardened tree (rc=${rc}): $(cat "${root}/.out-assert")"

    # Independent end-state checks (the assertion block does not cover
    # everything — serial-getty, the NoCloud pin, qemu-ga per path).
    local cfg="${root}/etc/cloud/cloud.cfg.d/99-hippius-nocloud.cfg"
    grep -qx '    fs_label: null' "${cfg}" || err "${family}: 99-hippius-nocloud.cfg has no 'fs_label: null'"
    grep -qx 'datasource_list: \[ NoCloud, None \]' "${cfg}" || err "${family}: datasource_list no longer pinned to [ NoCloud, None ]"
    grep -qx '    seedfrom: /run/cloud-init/seed/' "${cfg}" || err "${family}: NoCloud seedfrom no longer pinned to the tmpfs seed"
    local dsid="${root}/etc/cloud/ds-identify.cfg"
    if [[ -f "${dsid}" ]]; then
        [[ "$(grep -v '^#' "${dsid}")" == 'policy: enabled' ]] \
            || err "${family}: ds-identify.cfg is not exactly 'policy: enabled' ('disabled' turns cloud-init off): $(grep -v '^#' "${dsid}")"
    else
        err "${family}: /etc/cloud/ds-identify.cfg not written"
    fi
    local bin
    for bin in usr/bin/qemu-ga usr/sbin/qemu-ga usr/bin/spice-vdagent usr/bin/vmtoolsd; do
        [[ ! -e "${root}/${bin}" ]] || err "${family}: guest agent /${bin} survived the ${pkg_section} arm's purge"
    done
    for pkg in qemu-guest-agent spice-vdagent open-vm-tools; do
        grep -qx "${pkg}" "${root}/.pkg-removed" 2>/dev/null || err "${family}: ${pkg} not in the ${pkg_section} arm's purge list"
    done
    [[ "$(readlink "${root}/etc/systemd/system-generators/systemd-ssh-generator" 2>/dev/null)" == /dev/null ]] \
        || err "${family}: systemd-ssh-generator not masked to /dev/null (sshd on a miner-controlled AF_VSOCK)"
    [[ "$(readlink "${root}/etc/systemd/system/serial-getty@ttyS0.service" 2>/dev/null)" == /dev/null ]] \
        || err "${family}: serial-getty@ttyS0.service not masked to /dev/null (login prompt on the miner-owned console)"
    local sshd="${root}/etc/ssh/sshd_config.d/00-hippius-harden.conf" kv
    for kv in 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'PermitRootLogin no' 'X11Forwarding no' 'GSSAPIAuthentication no' 'GSSAPIKeyExchange no'; do
        grep -qxF "${kv}" "${sshd}" 2>/dev/null || err "${family}: 00-hippius-harden.conf lacks '${kv}'"
    done
    [[ "$(stat -c %a "${sshd}" 2>/dev/null)" == 644 ]] || err "${family}: 00-hippius-harden.conf is not mode 0644"
    local want_dir=755
    [[ "${family}" == apt ]] || want_dir=700
    [[ "$(stat -c %a "${root}/etc/ssh/sshd_config.d")" == "${want_dir}" ]] \
        || err "${family}: sshd_config.d mode changed to $(stat -c %a "${root}/etc/ssh/sshd_config.d") (want ${want_dir})"
    [[ "$(python3 -c 'import sys, yaml; print(yaml.safe_load(open(sys.argv[1]))["network"]["config"])' "${root}/etc/cloud/cloud.cfg.d/99-hippius-network.cfg" 2>&1)" == disabled ]] \
        || err "${family}: 99-hippius-network.cfg does not parse to network.config=disabled"
    if [[ "${family}" == apt ]]; then
        [[ -f "${root}/etc/systemd/network/50-hippius-dhcp.network" && ! -e "${root}/etc/NetworkManager/system-connections/hippius-dhcp.nmconnection" ]] \
            || err "${family}: expected the systemd-networkd DHCP profile only"
    else
        [[ -f "${root}/etc/NetworkManager/system-connections/hippius-dhcp.nmconnection" && ! -e "${root}/etc/systemd/network/50-hippius-dhcp.network" ]] \
            || err "${family}: expected the NetworkManager DHCP profile only"
    fi
    [[ ! -e "${root}/etc/netplan/90-hippius-dhcp-identifier.yaml" ]] || err "${family}: the old netplan merge file is still written"
    local noresize="${root}/etc/cloud/cloud.cfg.d/99-hippius-noresize.cfg"
    [[ "$(python3 -c 'import sys, yaml; c = yaml.safe_load(open(sys.argv[1])); print(c["growpart"]["mode"], c["resize_rootfs"])' "${noresize}" 2>&1)" == "off False" ]] \
        || err "${family}: 99-hippius-noresize.cfg does not parse to growpart.mode=off, resize_rootfs=false"
    local unit
    for unit in ModemManager.service multipathd.service multipathd.socket udisks2.service; do
        [[ "$(readlink "${root}/etc/systemd/system/${unit}" 2>/dev/null)" == /dev/null ]] \
            || err "${family}: ${unit} not masked to /dev/null"
    done
    LAST_CFG="${cfg}"
}

# ── 4. Both families end hardened ───────────────────────────────────
for family in apt rhel; do
    before=${fail}
    bake_family "${family}"
    [[ ${fail} -eq ${before} ]] && ok "${family}: NoCloud pinned (fs_label null), ds-identify enabled, no guest agent, ssh-generator + serial-getty masked, sshd key-only drop-in, no root growth, headless masks, cloud-init network off + DHCP profile, bake assertions pass"
done
FAMILY=debian

# ── 5. The bake's assertions reject each missing item (exit 3) ──────
# Built from the hardened apt tree, then one item undone per case; only
# the assertion block runs, so this pins the bake's own fail-closed net.
assert_rejects() {
    local name="$1" breaker="$2" root
    root="$(new_root "neg-${name}")"
    run_in "${root}" cloud && run_in "${root}" net && run_in "${root}" apt && run_in "${root}" sshd && run_in "${root}" mask \
        || { err "neg-${name}: could not build the hardened base tree"; return; }
    ( cd "${root}" && eval "${breaker}" ) || { err "neg-${name}: breaker failed"; return; }
    set +e; run_in "${root}" assert; local rc=$?; set -e
    if [[ ${rc} -eq 3 ]]; then
        ok "bake assertions exit 3 on: ${name} ($(grep -m1 FATAL "${root}/.out-assert"))"
    else
        err "bake assertions did not exit 3 on '${name}' (rc=${rc}): $(cat "${root}/.out-assert")"
    fi
}
assert_rejects "fs_label unset (cidata probe on)" "sed -i '/fs_label: null/d' etc/cloud/cloud.cfg.d/99-hippius-nocloud.cfg"
assert_rejects "ds-identify policy disabled"      "sed -i 's/^policy: enabled\$/policy: disabled/' etc/cloud/ds-identify.cfg"
assert_rejects "ds-identify.cfg missing"          "rm -f etc/cloud/ds-identify.cfg"
assert_rejects "qemu-ga still installed"          "printf '#!/bin/sh\n' > usr/bin/qemu-ga"
assert_rejects "vmtoolsd still installed"         "printf '#!/bin/sh\n' > usr/sbin/vmtoolsd"
assert_rejects "ssh-generator unmasked"           "rm -f etc/systemd/system-generators/systemd-ssh-generator"
assert_rejects "sshd drop-in missing"             "rm -f etc/ssh/sshd_config.d/00-hippius-harden.conf"
assert_rejects "sshd drop-in allows passwords"    "sed -i 's/^PasswordAuthentication no\$/PasswordAuthentication yes/' etc/ssh/sshd_config.d/00-hippius-harden.conf"
assert_rejects "sshd drop-in lost PermitRootLogin" "sed -i '/^PermitRootLogin no\$/d' etc/ssh/sshd_config.d/00-hippius-harden.conf"
assert_rejects "a base drop-in sorts before ours" "printf 'PasswordAuthentication yes\\n' > etc/ssh/sshd_config.d/00-aaa.conf"
assert_rejects "growpart left on"                 "sed -i \"s/^  mode: 'off'\$/  mode: auto/\" etc/cloud/cloud.cfg.d/99-hippius-noresize.cfg"
assert_rejects "multipathd.socket unmasked"       "rm -f etc/systemd/system/multipathd.socket"
assert_rejects "cloud-init network re-enabled"    "sed -i 's/^  config: disabled\$/  config: enabled/' etc/cloud/cloud.cfg.d/99-hippius-network.cfg"
assert_rejects "networkd DHCP profile missing"    "rm -f etc/systemd/network/50-hippius-dhcp.network"
assert_rejects "netplan DHCP-less enp1s0 merge"   "mkdir -p etc/netplan && printf 'network: {version: 2, ethernets: {enp1s0: {dhcp-identifier: mac}}}\\n' > etc/netplan/90-hippius-dhcp-identifier.yaml"
# Enabled-looking link, but the unit only exists on the BAKER's filesystem
# (the absolute link resolves there): still refused.
root="$(new_root "netd-host-only")"
rm -f "${root}/usr/lib/systemd/system/systemd-networkd.service"
set +e; FAMILY=debian run_in "${root}" net; rc=$?; set -e
[[ ${rc} -eq 3 ]] && ok "debian: a networkd link whose unit is missing from the guest fails the bake" \
    || err "debian: a dangling networkd link passed (rc=${rc}) — test -e followed it onto the host"
# A base without systemd-networkd (apt) / NetworkManager (rhel) would boot
# with no network at all: the bake refuses it (exit 3) instead.
for fam in debian rhel; do
    root="$(new_root "no-netd-${fam}")"
    rm -f "${root}/etc/systemd/system/multi-user.target.wants/systemd-networkd.service" "${root}/usr/sbin/NetworkManager"
    set +e; FAMILY="${fam}" run_in "${root}" net; rc=$?; set -e
    if [[ ${rc} -eq 3 ]]; then
        ok "${fam}: a base without its network daemon fails the bake ($(grep -m1 FATAL "${root}/.out-net"))"
    else
        err "${fam}: a base without its network daemon did not exit 3 (rc=${rc}): $(cat "${root}/.out-net")"
    fi
done

# ── 5b. Build-host state in the shipped initrd (exit 3) ─────────────
# A hardened apt tree plus a /boot/initrd.img-* whose unpacked content
# (<root>/.initrd-trees/<initrd>/main/…) and the guest's own config are set per case.
HOOK="${HERE}/../initramfs/hippius-host-state-hook"
KV="6.8.0-1-generic"
host_state_tree() {
    local root
    root="$(new_root "hs-$(tr -c 'a-z0-9\n' '-' <<< "$1")")"
    run_in "${root}" cloud && run_in "${root}" net && run_in "${root}" apt && run_in "${root}" sshd && run_in "${root}" mask \
        || { err "hs-$1: could not build the hardened base tree"; return 1; }
    mkdir -p "${root}/boot" "${root}/.initrd-trees/initrd.img-${KV}/main/conf" "${root}/.initrd-trees/initrd.img-${KV}/main/etc/mdadm" \
             "${root}/etc/mdadm" "${root}/etc/initramfs-tools"
    : > "${root}/boot/initrd.img-${KV}"
    printf 'HOMEHOST <system>\nMAILADDR root\n' > "${root}/etc/mdadm/mdadm.conf"
    printf 'virtio_net\nvirtio_pci\n' > "${root}/etc/initramfs-tools/modules"
    cp "${root}/etc/mdadm/mdadm.conf" "${root}/.initrd-trees/initrd.img-${KV}/main/etc/mdadm/mdadm.conf"
    printf 'virtio_net\nvirtio_pci\n' > "${root}/.initrd-trees/initrd.img-${KV}/main/conf/modules"
    echo "${root}"
}
host_state_case() {  # <name> <want rc> <breaker run in the tree root; I = the initrd's main/>
    local name="$1" want="$2" breaker="$3" root rc
    root="$(host_state_tree "${name}")" || return
    ( cd "${root}" && export I=".initrd-trees/initrd.img-${KV}/main" && eval "${breaker}" ) || { err "hs-${name}: breaker failed"; return; }
    set +e; run_in "${root}" assert; rc=$?; set -e
    if [[ ${rc} -eq ${want} ]]; then
        ok "host-state audit rc=${want}: ${name}$([[ ${rc} -eq 3 ]] && echo " ($(grep -m1 FATAL "${root}/.out-assert"))")"
    else
        err "host-state audit on '${name}': rc=${rc}, want ${want}: $(cat "${root}/.out-assert")"
    fi
}
host_state_case "clean initrd"                          0 ":"
host_state_case "zeroed /.random-seed"                  0 "head -c 4096 /dev/zero > \${I}/.random-seed"
host_state_case "array the guest itself declares"       0 "echo 'ARRAY /dev/md0 UUID=1:2:3:4' | tee -a etc/mdadm/mdadm.conf >> \${I}/etc/mdadm/mdadm.conf"
host_state_case "efivarfs the guest asks for"           0 "echo efivarfs | tee -a etc/initramfs-tools/modules >> \${I}/conf/modules"
host_state_case "build-host /dev/random seed"           3 "printf 'rnd' > \${I}/.random-seed"
host_state_case "build-host md array"                   3 "echo 'ARRAY /dev/md/md2 metadata=1.2 UUID=53e6cfcf:5153c59f:5de1720d:8702ae25' >> \${I}/etc/mdadm/mdadm.conf"
host_state_case "mkconf leftover mdadm.conf.tmp"        3 ": > \${I}/etc/mdadm/mdadm.conf.tmp"
host_state_case "build-host efivarfs in conf/modules"   3 "echo efivarfs >> \${I}/conf/modules"
host_state_case "seed whose first non-zero byte is a newline" 3 "printf '\\000\\n' > \${I}/.random-seed"
host_state_case "a seed the audit cannot read fails closed" 3 "head -c 16 /dev/zero > \${I}/.random-seed && : > \${I}/../.unreadable-after-unpack"
host_state_case "build-host efivarfs.ko payload"        3 "mkdir -p \${I}/usr/lib/modules/${KV}/kernel/fs/efivarfs && : > \${I}/usr/lib/modules/${KV}/kernel/fs/efivarfs/efivarfs.ko.zst"
host_state_case "leak in an early/ segment too"         3 "mkdir -p .initrd-trees/initrd.img-${KV}/early && printf 'rnd' > .initrd-trees/initrd.img-${KV}/early/.random-seed"
host_state_case "initramfs dhcpcd with clientid"       0 "printf 'persistent\\nclientid\\n' > \${I}/etc/dhcpcd.conf"
host_state_case "initramfs dhcpcd still duid ll"        3 "printf 'persistent\\nduid ll\\n' > \${I}/etc/dhcpcd.conf"
host_state_case "initramfs dhcpcd clientid AND duid"    3 "printf 'clientid\\nduid\\n' > \${I}/etc/dhcpcd.conf"
host_state_case "initramfs dhcpcd clientid <value>"     3 "printf 'clientid\\nclientid deadbeef\\n' > \${I}/etc/dhcpcd.conf"
host_state_case "initramfs dhcpcd binary, no config"    3 "mkdir -p \${I}/usr/sbin && : > \${I}/usr/sbin/dhcpcd"
host_state_case "initramfs dhcpcd binary + clientid"    0 "mkdir -p \${I}/usr/sbin && : > \${I}/usr/sbin/dhcpcd && printf 'clientid\\n' > \${I}/etc/dhcpcd.conf"

# ── 5c. The hook itself turns a leaky DESTDIR into one the audit passes
# DESTDIR = what the stock hooks leave on a build host with md arrays +
# EFI; the guest's own config says no arrays, no efivarfs.
root="$(host_state_tree hook)"
if [[ -n "${root}" ]]; then
    D="${root}/.initrd-trees/initrd.img-${KV}/main"
    printf 'rnd' > "${D}/.random-seed"
    printf '# This configuration was auto-generated on Fri, 02 Jan 1970 by mkconf\nCREATE owner=root\nARRAY /dev/md/md2 metadata=1.2 UUID=53e6cfcf:5153c59f:5de1720d:8702ae25\n' > "${D}/etc/mdadm/mdadm.conf"
    : > "${D}/etc/mdadm/mdadm.conf.tmp"
    echo efivarfs >> "${D}/conf/modules"
    mkdir -p "${D}/usr/lib/modules/${KV}/kernel/fs/efivarfs" && : > "${D}/usr/lib/modules/${KV}/kernel/fs/efivarfs/efivarfs.ko.zst"
    echo 'CREATE owner=root group=disk mode=0660' >> "${root}/etc/mdadm/mdadm.conf"
    set +e; run_in "${root}" assert; rc=$?; set -e
    [[ ${rc} -eq 3 ]] || err "hook: the leaky fixture is not rejected before the hook runs (rc=${rc}) — the check is blind"
    if DESTDIR="${D}" HIPPIUS_HOST_STATE_ROOT="${root}" sh "${HOOK}" >"${WORK}/hook.out" 2>&1; then
        set +e; run_in "${root}" assert; rc=$?; set -e
        [[ ${rc} -eq 0 ]] || err "hook: the audit still rejects the scrubbed initrd (rc=${rc}): $(cat "${root}/.out-assert")"
        [[ ! -e "${D}/.random-seed" && ! -e "${D}/etc/mdadm/mdadm.conf.tmp" ]] || err "hook: seed or mkconf leftover survived"
        [[ -z "$(find "${D}" -name 'efivarfs.ko*')" ]] || err "hook: the efivarfs module payload survived"
        [[ "$(cat "${D}/etc/mdadm/mdadm.conf")" == $'HOMEHOST <system>\nMAILADDR root\n#CREATE owner=root group=disk mode=0660' ]] \
            || err "hook: initrd mdadm.conf is not the guest's own (CREATE commented): $(cat "${D}/etc/mdadm/mdadm.conf")"
        [[ "$(cat "${D}/conf/modules")" == $'virtio_net\nvirtio_pci' ]] || err "hook: conf/modules not restored: $(cat "${D}/conf/modules")"
        [[ ${fail} -eq 0 ]] && ok "hippius-host-state hook: seed, host arrays, mkconf leftover, efivarfs dropped; the audit passes"
    else
        err "hook failed: $(cat "${WORK}/hook.out")"
    fi
    E="${WORK}/hook-noop"; mkdir -p "${E}/conf"; printf 'virtio_net\n' > "${E}/conf/modules"
    DESTDIR="${E}" HIPPIUS_HOST_STATE_ROOT="${WORK}/nonexistent" sh "${HOOK}" \
        && [[ ! -e "${E}/etc/mdadm" && "$(cat "${E}/conf/modules")" == virtio_net ]] \
        && ok "hippius-host-state hook: no-op on a base without mdadm/overlayroot" \
        || err "hook: not a no-op on a base without mdadm/overlayroot"
    [[ -z "$(sh "${HOOK}" prereqs)" ]] && ok "hippius-host-state hook: answers prereqs" || err "hook: prereqs output not empty"
fi

# ── 5d. The DHCP client-id hook on the stock dhcpcd hook's config ───────
# The config initramfs-tools' hooks/dhcpcd writes (Ubuntu 24.04,
# 0.142ubuntu25.8); the real one is exercised against dnsmasq in
# initramfs-dhcp-clientid-test.sh.
CHOOK="${HERE}/../initramfs/hippius-dhcp-clientid-hook"
C="${WORK}/dhcp-hook"; mkdir -p "${C}/etc"
printf '# Options from default configuration\npersistent\nvendorclassid\nslaac private\n\n# initramfs-tools specific options\nduid ll\nenv hostname_fqdn=no\n' > "${C}/etc/dhcpcd.conf"
if DESTDIR="${C}" sh "${CHOOK}" && DESTDIR="${C}" sh "${CHOOK}"; then
    if [[ "$(grep -cx clientid "${C}/etc/dhcpcd.conf")" == 1 ]] && ! grep -q '^duid' "${C}/etc/dhcpcd.conf" \
        && grep -qx 'persistent' "${C}/etc/dhcpcd.conf" && grep -qx 'env hostname_fqdn=no' "${C}/etc/dhcpcd.conf"; then
        ok "dhcp-clientid hook: duid ll → clientid (once, idempotent), the rest of the config untouched"
    else
        err "dhcp-clientid hook: unexpected result: $(cat "${C}/etc/dhcpcd.conf")"
    fi
else
    err "dhcp-clientid hook failed on the stock config"
fi
E="${WORK}/dhcp-hook-noop"; mkdir -p "${E}"
DESTDIR="${E}" sh "${CHOOK}" && [[ ! -e "${E}/etc/dhcpcd.conf" ]] \
    && ok "dhcp-clientid hook: no-op on an initramfs without dhcpcd (Debian klibc ipconfig)" \
    || err "dhcp-clientid hook: not a no-op without dhcpcd.conf"
[[ -z "$(sh "${CHOOK}" prereqs)" ]] && ok "dhcp-clientid hook: answers prereqs" || err "dhcp-clientid hook: prereqs output not empty"

# ── 6. cloud-init itself ignores the attacker (real DataSourceNoCloud)
# Feed the config the bake wrote to cloud-init's own NoCloud code with
# an attacker `cidata` disk and an attacker SMBIOS serial present. The
# negative control (fs_label line removed) MUST let the attacker in —
# otherwise this harness could not see the attack and proves nothing.
if python3 -c 'import cloudinit, yaml' 2>/dev/null; then
    ci_ver="$(python3 -c 'from cloudinit.version import version_string; print(version_string())')"
    precedence() { python3 "${PRECEDENCE}" "$1" 2>"${WORK}/precedence.err"; }
    field() { python3 -c 'import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$1" "$2"; }

    hard="$(precedence "${LAST_CFG}")" || err "cloud-init harness crashed on the hardened config: $(cat "${WORK}/precedence.err")"
    if [[ -n "${hard}" ]]; then
        [[ "$(field "${hard}" claimed)" == True ]]              || err "cloud-init: NoCloud did not claim the legit tmpfs seed: ${hard}"
        [[ "$(field "${hard}" attacker_in_metadata)" == False ]] || err "cloud-init: attacker cidata/DMI meta-data (ssh key / instance-id) reached the hardened guest: ${hard}"
        [[ "$(field "${hard}" attacker_in_userdata)" == False ]] || err "cloud-init: attacker user-data reached the hardened guest: ${hard}"
        [[ "$(field "${hard}" legit_userdata)" == True ]]        || err "cloud-init: tenant user-data not the tmpfs seed's: ${hard}"
        [[ "$(field "${hard}" cidata_probed)" == '[]' ]]         || err "cloud-init: still scans block devices for a seed label: ${hard}"
        [[ "$(field "${hard}" seedfrom_read)" == "['/run/cloud-init/seed/']" ]] \
            || err "cloud-init: seedfrom read something other than the pinned tmpfs seed (SMBIOS serial redirect?): ${hard}"
        [[ ${fail} -eq 0 ]] && ok "cloud-init ${ci_ver}: hardened config ignores the attacker cidata disk + SMBIOS serial; tenant seed only"
    fi

    soft_cfg="${WORK}/soft-99-hippius-nocloud.cfg"
    grep -v 'fs_label: null' "${LAST_CFG}" > "${soft_cfg}"
    soft="$(precedence "${soft_cfg}")" || err "cloud-init harness crashed on the control config: $(cat "${WORK}/precedence.err")"
    if [[ -n "${soft}" && "$(field "${soft}" attacker_in_metadata)" == True ]]; then
        ok "cloud-init ${ci_ver}: control (fs_label removed) lets the attacker's cidata meta-data in — the harness sees C2"
    else
        err "cloud-init: negative control did not reproduce the cidata merge — harness is blind: ${soft}"
    fi
else
    err "python3 cannot import cloudinit + yaml; install cloud-init (the CI step does) — this check does not skip"
fi

# ── hippius-eol-sign.service must not build an ordering cycle ────────
# The unit is DefaultDependencies=no, After=network-online.target (LATE).
# Any Before= on an EARLY boot target closes a cycle
# (early-target -> eol-sign -> network-online -> ... -> early-target).
# systemd then deletes one job per boot to break it, and on the RHEL
# family it picked cloud-init-network.service: cloud-init never finished
# and the guest never enrolled in NetBird. Shutdown ordering only needs
# shutdown.target + umount.target.
eol_before="$(sed -n '/^Description=Hippius .24\/.25 guest EOL/,/^\[Service\]/p' "${BAKE}" \
    | sed -n 's/^Before=//p' | tr ' ' '\n' | sed '/^$/d')"
[[ -n "${eol_before}" ]] \
    || err "eol-sign: no Before= found in the unit — did the heredoc move?"
for t in ${eol_before}; do
    case "${t}" in
        shutdown.target | umount.target) ;;
        *) err "eol-sign: Before=${t} is an early-boot target — ordering cycle with After=network-online.target (broke cloud-init on RHEL)" ;;
    esac
done
[[ "${eol_before}" == *shutdown.target* ]] \
    || err "eol-sign: Before= lost shutdown.target — ExecStop would not fire on the shutdown transition"
[[ "${eol_before}" == *umount.target* ]] \
    || err "eol-sign: Before= lost umount.target — the ack push could race the storage teardown"
# The rest of the contract the ExecStop depends on. Before= alone can be
# right while the unit still fails to fire, or fires too late.
eol_unit="$(sed -n '/^Description=Hippius .24\/.25 guest EOL/,/^\[Install\]/p' "${BAKE}")"
for need in \
    'DefaultDependencies=no' \
    'After=network-online.target' \
    'Conflicts=shutdown.target' \
    'RemainAfterExit=yes' \
    'After=systemd-cryptsetup@cryptroot.service'; do
    grep -qxF "${need}" <<<"${eol_unit}" \
        || err "eol-sign: unit lost '${need}' — the shutdown ack is no longer guaranteed"
done
grep -q '^ExecStop=.*eol --sign-only' <<<"${eol_unit}" \
    || err "eol-sign: ExecStop no longer runs 'eol --sign-only'"
[[ ${fail} -eq 0 ]] && ok "eol-sign: no early-boot Before= (no cycle), and the shutdown-ack contract is intact"

if [[ ${fail} -eq 0 ]]; then
    echo "${NAME}: ALL OK"
else
    echo "${NAME}: FAILURES" >&2
    exit 1
fi
