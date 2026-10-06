#!/usr/bin/env bash
# Boot each golden distro's STOCK cloud image with the bake's network files
# (cloud-init network disabled + the per-family DHCP profile) and check the
# guest still gets its DHCP lease and DNS — i.e. that nothing but cloud-init
# configured the network before, and that the bake's profile replaces it.
#
# Manual / pre-bless check, not CI: it boots full VMs under QEMU (KVM if
# /dev/kvm is there, else TCG — ~5-15 min per distro). Everything runs in a
# throwaway container (libguestfs + qemu); the base images are only read
# (each boot writes to a qcow2 overlay).
#
#   scripts/dev/guest-network-without-cloud-init-boot.sh WORKDIR [DISTRO ...]
#
# WORKDIR holds (or receives) ubuntu.qcow2, debian.qcow2, cs10.qcow2,
# fedora.qcow2 — the bake's pinned base images. DISTRO: ubuntu debian cs10
# fedora, plus `ubuntu-control` (cloud-init network disabled, NO DHCP
# profile: must come up WITHOUT an address, or the check proves nothing).
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BAKE="${HERE}/../tenant-image-bake.sh"
NAME="guest-network-without-cloud-init-boot"
W="${1:?usage: $0 WORKDIR [DISTRO ...]}"
shift
[[ "$#" -gt 0 ]] || set -- ubuntu-control ubuntu debian cs10 fedora
command -v docker >/dev/null 2>&1 || { echo "${NAME}: docker is required" >&2; exit 1; }
mkdir -p "${W}/files"

# The bake's own bytes (quoted heredocs, lifted verbatim).
lift() { awk "/<<'$1'\$/{f=1; next} /^$1\$/{f=0} f" "${BAKE}"; }
lift HIPPIUS_CI_NETWORK    > "${W}/files/99-hippius-network.cfg"
lift HIPPIUS_NETWORKD_DHCP > "${W}/files/50-hippius-dhcp.network"
lift HIPPIUS_NM_DHCP       > "${W}/files/hippius-dhcp.nmconnection"
for f in 99-hippius-network.cfg 50-hippius-dhcp.network hippius-dhcp.nmconnection; do
    [[ -s "${W}/files/${f}" ]] || { echo "${NAME}: could not lift ${f} from ${BAKE}" >&2; exit 1; }
done

declare -A URL=(
    [ubuntu]=https://cloud-images.ubuntu.com/noble/20260801/noble-server-cloudimg-amd64.img
    [debian]=https://gemmei.ftp.acc.umu.se/images/cloud/trixie/20260712-2537/debian-13-genericcloud-amd64-20260712-2537.qcow2
    [cs10]=https://cloud.centos.org/centos/10-stream/x86_64/images/CentOS-Stream-GenericCloud-10-latest.x86_64.qcow2
    [fedora]=https://dl.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2
)

cat > "${W}/files/Dockerfile" <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    libguestfs-tools qemu-system-x86 qemu-utils linux-image-generic genisoimage curl ca-certificates >/dev/null
EOF
docker build -q -t hippius-guest-net-check "${W}/files" >/dev/null

# Runs in the container: customise an overlay (files root-owned, as the
# bake's `sudo tee` writes them: NetworkManager refuses a keyfile owned by
# anyone else), boot it, read the verdict the guest prints on its serial
# console.
cat > "${W}/files/boot-one.sh" <<'EOF'
#!/bin/bash
set -euo pipefail
case_="$1"; distro="${case_%-control}"; url="$2"
cd /w
[[ -s "${distro}.qcow2" ]] || { curl -fsSL -o "${distro}.qcow2.part" "${url}"; mv "${distro}.qcow2.part" "${distro}.qcow2"; }
d="/w/run-${case_}"; rm -rf "${d}"; mkdir -p "${d}"
qemu-img create -q -f qcow2 -F qcow2 -b "/w/${distro}.qcow2" "${d}/disk.qcow2" 20G
export LIBGUESTFS_BACKEND=direct
args=(--no-network -a "${d}/disk.qcow2"
      --mkdir /etc/cloud/cloud.cfg.d
      # TCG is slow enough for udev to miss systemd's 90 s device timeout
      # (/boot by-label → emergency mode); a test-only allowance.
      --mkdir /etc/systemd/system.conf.d
      --write $'/etc/systemd/system.conf.d/90-net-check-slow.conf:[Manager]\nDefaultDeviceTimeoutSec=900s\nDefaultTimeoutStartSec=900s\n'
      --upload /w/files/99-hippius-network.cfg:/etc/cloud/cloud.cfg.d/99-hippius-network.cfg)
if [[ "${case_}" != *-control ]]; then
    case "${distro}" in
        ubuntu|debian)
            args+=(--mkdir /etc/systemd/network
                   --upload /w/files/50-hippius-dhcp.network:/etc/systemd/network/50-hippius-dhcp.network) ;;
        *)
            args+=(--mkdir /etc/NetworkManager/system-connections
                   --upload /w/files/hippius-dhcp.nmconnection:/etc/NetworkManager/system-connections/hippius-dhcp.nmconnection
                   --chmod 0600:/etc/NetworkManager/system-connections/hippius-dhcp.nmconnection) ;;
    esac
fi
# Root-owned, as the bake's `sudo tee` writes them (virt-customize keeps
# the uploader's uid; its --chown rejects `0:0:PATH` in 1.52).
args+=(--run-command 'chown -R root:root /etc/cloud/cloud.cfg.d /etc/systemd/network /etc/NetworkManager/system-connections 2>/dev/null || true')
case "${distro}" in cs10|fedora) args+=(--selinux-relabel) ;; esac
virt-customize "${args[@]}" >"${d}/customize.log" 2>&1 || { echo "RESULT ${case_} customize-failed"; tail -5 "${d}/customize.log"; exit 1; }
mkdir -p "${d}/seed"
printf 'instance-id: iid-net-check\n' > "${d}/seed/meta-data"
cat > "${d}/seed/user-data" <<'UD'
#cloud-config
runcmd:
  # Through a file and pipes: on SELinux distros ip(8) runs confined and
  # may not write to the serial tty or a cloud-init file itself.
  - [ sh, -c, 'sleep 5; { echo HIPPIUS-NET-BEGIN; ip -4 -o addr show scope global | cat; ip -4 route show default | cat; getent hosts example.com || echo DNS-FAIL; ls /etc/netplan /run/systemd/network 2>&1; networkctl list --no-pager 2>&1; nmcli -t -f NAME,DEVICE connection show --active 2>&1; ls -lZ /etc/NetworkManager/system-connections 2>&1; journalctl -b -u NetworkManager --no-pager 2>/dev/null | grep -iE "keyfile|hippius|warn" | head -8; grep -h "network config disabled\|generate_fallback\|Traceback" /var/log/cloud-init.log | head -5; cloud-init status --long 2>&1 | head -8; echo HIPPIUS-NET-END; } > /run/hippius-net-check.txt 2>&1; cat /run/hippius-net-check.txt > /dev/ttyS0' ]
UD
genisoimage -quiet -output "${d}/seed.iso" -volid cidata -joliet -rock "${d}/seed/user-data" "${d}/seed/meta-data"
accel=tcg; [[ -w /dev/kvm ]] && accel=kvm
timeout 1800 qemu-system-x86_64 -machine q35,accel="${accel}" -cpu max -smp 4 -m 3072 -nographic \
    -drive file="${d}/disk.qcow2",if=virtio -drive file="${d}/seed.iso",media=cdrom \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    -serial file:"${d}/serial.log" -monitor none -display none >/dev/null 2>&1 &
qpid=$!
for _ in $(seq 1 360); do
    grep -q HIPPIUS-NET-END "${d}/serial.log" 2>/dev/null && break
    kill -0 "${qpid}" 2>/dev/null || break
    sleep 5
done
kill "${qpid}" 2>/dev/null || true
# Serial output carries colour escapes (ip(8) colours by default on a tty).
sed -n '/HIPPIUS-NET-BEGIN/,/HIPPIUS-NET-END/p' "${d}/serial.log" | tr -d '\r' \
    | sed 's/\x1b\[[0-9;]*[A-Za-z]//g' > "${d}/verdict.txt"
if [[ ! -s "${d}/verdict.txt" ]]; then echo "RESULT ${case_} no-verdict"; tail -20 "${d}/serial.log" | tr -d '\r'; exit 1; fi
cat "${d}/verdict.txt"
# Exactly one global IPv4 (#289: no stacked second lease), the slirp one.
if [[ "$(grep -c ' inet ' "${d}/verdict.txt")" -eq 1 ]] && grep -Eq 'inet 10\.0\.2\.15/' "${d}/verdict.txt" \
    && ! grep -q DNS-FAIL "${d}/verdict.txt"; then
    # RHEL family: the lease must come from the bake's profile, not from
    # NetworkManager's implicit "Wired connection 1".
    if [[ "${distro}" == cs10 || "${distro}" == fedora ]] && ! grep -q '^hippius-dhcp:' "${d}/verdict.txt"; then
        echo "RESULT ${case_} lease-from-other-profile"
    else
        echo "RESULT ${case_} lease+dns"
    fi
else
    echo "RESULT ${case_} no-lease"
fi
EOF
chmod 0755 "${W}/files/boot-one.sh"

kvm=()
[[ -e /dev/kvm ]] && kvm=(--device /dev/kvm)
pids=()
for c in "$@"; do
    docker run --rm "${kvm[@]}" -v "${W}:/w" hippius-guest-net-check \
        /w/files/boot-one.sh "${c}" "${URL[${c%-control}]}" > "${W}/${c}.out" 2>&1 &
    pids+=($!)
done
for p in "${pids[@]}"; do wait "${p}" || true; done

fail=0
for c in "$@"; do
    r="$(sed -n 's/^RESULT [^ ]* //p' "${W}/${c}.out" | tail -n1)"
    want="lease+dns"; [[ "${c}" == *-control ]] && want="no-lease"
    if [[ "${r}" == "${want}" ]]; then
        echo "${NAME}: OK — ${c}: ${r}"
    else
        echo "${NAME}: FAIL — ${c}: got '${r:-nothing}', want '${want}' (see ${W}/${c}.out)" >&2
        fail=1
    fi
done
[[ ${fail} -eq 0 ]] && echo "${NAME}: ALL OK" || { echo "${NAME}: FAILURES" >&2; exit 1; }
