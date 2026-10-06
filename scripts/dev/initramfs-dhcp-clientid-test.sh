#!/usr/bin/env bash
# The initramfs DHCP client and the booted guest present the SAME client-id,
# so the miner's dnsmasq hands userspace the initramfs lease instead of a
# second one (#289 multi-IP). Real clients against a real dnsmasq on a
# throwaway docker network:
#
#   ubuntu (24.04, initramfs dhcpcd): the STOCK initramfs-tools dhcpcd hook
#     writes DESTDIR/etc/dhcpcd.conf, scripts/initramfs/hippius-dhcp-clientid-hook
#     runs after it (as /etc/initramfs-tools/hooks does), dhcpcd leases with
#     that config, then a second client sends 01:<MAC> — what systemd-networkd's
#     ClientIdentifier=mac (50-hippius-dhcp.network) sends — on the same NIC.
#     Want: ONE lease, the same address. Control: without the hook (stock
#     `duid ll`) the same sequence gets TWO leases, or the test sees nothing.
#   debian (13, initramfs klibc ipconfig): ipconfig sends no client-id; a
#     01:<MAC> client afterwards must still get the same lease (dnsmasq falls
#     back to the MAC for a lease without one), so the hook is a no-op there.
#
# Needs docker; nothing privileged (CAP_NET_ADMIN inside the containers'
# own network namespace: klibc ipconfig configures its eth0).
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HOOK="${HERE}/../initramfs/hippius-dhcp-clientid-hook"
NAME="initramfs-dhcp-clientid-test"
[[ -r "${HOOK}" ]] || { echo "${NAME}: ${HOOK} missing" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "${NAME}: docker is required" >&2; exit 1; }

fail=0
ok()  { echo "${NAME}: OK — $*"; }
err() { echo "${NAME}: FAIL — $*" >&2; fail=1; }

T="$(mktemp -d)"
NET="hippius-dhcp-clientid-$$"
SRV="${NET}-dnsmasq"
cleanup() {
    docker rm -f "${SRV}" >/dev/null 2>&1 || true
    docker network rm "${NET}" >/dev/null 2>&1 || true
    rm -rf -- "${T}"
}
trap cleanup EXIT
cp "${HOOK}" "${T}/hook"

# A /24 docker is unlikely to have in use; dnsmasq leases from .100-.200.
SUBNET_PREFIX="172.31.$(( ($$ % 200) + 20 ))"
docker network create --subnet "${SUBNET_PREFIX}.0/24" "${NET}" >/dev/null
docker run -d --name "${SRV}" --network "${NET}" --ip "${SUBNET_PREFIX}.2" --cap-add NET_ADMIN debian:13 \
    bash -c "apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dnsmasq-base >/dev/null 2>&1 && touch /tmp/ready && exec dnsmasq -d --port=0 --log-dhcp --dhcp-authoritative --dhcp-range=${SUBNET_PREFIX}.100,${SUBNET_PREFIX}.200,1h --dhcp-leasefile=/tmp/leases" >/dev/null
for _ in $(seq 1 120); do docker exec "${SRV}" test -e /tmp/ready 2>/dev/null && break; sleep 1; done
sleep 2

# The initramfs client, then the booted guest's client, on one NIC. The
# booted guest is played by busybox udhcpc, whose default client-id is
# 01:<MAC> — exactly systemd-networkd's ClientIdentifier=mac. dhcpcd itself
# cannot take a lease in a container (its if_init writes the read-only
# /proc/sys), so on Ubuntu dhcpcd computes its client-id in test mode (-T,
# real config, real hooks) and udhcpc presents those exact bytes.
cat > "${T}/client.sh" <<'EOF'
#!/bin/bash
set -euo pipefail
mode="$1"
pkgs=(busybox)
if [[ "${mode}" == klibc ]]; then pkgs+=(klibc-utils); else pkgs+=(initramfs-tools-core dhcpcd-base); fi
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${pkgs[@]}" >/dev/null 2>&1
mac="$(cat /sys/class/net/eth0/address)"
echo "MAC ${mac}"
lease() { busybox udhcpc -i eth0 -n -q -f -s /bin/true "$@" 2>&1 | sed -n 's/.*lease of \([0-9.]*\) obtained.*/\1/p'; }
case "${mode}" in
    klibc)
        echo "INITRAMFS-ADDR $(/usr/lib/klibc/bin/ipconfig -t 10 eth0 | sed -n 's/^ *address: *\([0-9.]*\).*/\1/p')" ;;
    stock|hooked)
        D="$(mktemp -d)"
        DESTDIR="${D}" verbose=n sh /usr/share/initramfs-tools/hooks/dhcpcd
        grep -qx 'duid ll' "${D}/etc/dhcpcd.conf" || { echo "STOCK-CHANGED $(cat "${D}/etc/dhcpcd.conf")"; exit 1; }
        [[ "${mode}" == stock ]] || DESTDIR="${D}" sh /t/hook
        echo "CONF $(grep -E '^(duid|clientid)' "${D}/etc/dhcpcd.conf" | tr '\n' ' ')"
        dbg="$(timeout 30 dhcpcd -d -1 -4 -T -f "${D}/etc/dhcpcd.conf" eth0 2>&1 || true)"
        cid="$(sed -n 's/.*using ClientID \([0-9a-f:]*\).*/\1/p' <<<"${dbg}" | head -n1)"
        if [[ -z "${cid}" ]]; then
            # RFC 4361: 0xff, IAID, DUID.
            iaid="$(sed -n 's/.*IAID \([0-9a-f:]*\).*/\1/p' <<<"${dbg}" | head -n1)"
            duid="$(sed -n 's/^DUID \([0-9a-f:]*\).*/\1/p' <<<"${dbg}" | head -n1)"
            [[ -n "${iaid}" && -n "${duid}" ]] || { echo "NO-CLIENTID ${dbg}"; exit 1; }
            cid="ff:${iaid}:${duid}"
        fi
        echo "INITRAMFS-CLIENTID ${cid}"
        echo "INITRAMFS-ADDR $(lease -C -x "0x3d:$(tr -d : <<<"${cid}")")" ;;
esac
echo "USERSPACE-CLIENTID 01:${mac}"
echo "USERSPACE-ADDR $(lease)"
EOF
chmod 0755 "${T}/client.sh"
chmod 0755 "${T}"; chmod 0644 "${T}/hook"

# run_case MODE IMAGE WANT_LEASES
run_case() {
    local mode="$1" image="$2" want="$3" out mac n a1 a2
    out="$(docker run --rm --network "${NET}" --cap-add NET_ADMIN -v "${T}:/t:ro" "${image}" /t/client.sh "${mode}" 2>&1)" \
        || { err "${mode}: client failed: ${out}"; return; }
    mac="$(sed -n 's/^MAC //p' <<<"${out}")"
    a1="$(sed -n 's/^INITRAMFS-ADDR //p' <<<"${out}")"
    a2="$(sed -n 's/^USERSPACE-ADDR //p' <<<"${out}")"
    n="$(docker exec "${SRV}" cat /tmp/leases | grep -c " ${mac} " || true)"
    local detail
    detail="$(grep -E '^(CONF|INITRAMFS-CLIENTID|USERSPACE-CLIENTID) ' <<<"${out}" | tr '\n' ';')"
    local cid
    cid="$(sed -n 's/^INITRAMFS-CLIENTID //p' <<<"${out}")"
    case "${mode}" in
        hooked) [[ "${cid}" == "01:${mac}" ]] || err "hooked: initramfs dhcpcd client-id ${cid}, want 01:${mac}" ;;
        stock)  [[ "${cid}" == ff:* ]] || err "stock: initramfs dhcpcd client-id ${cid} is not the RFC 4361 DUID form — control is blind" ;;
    esac
    if [[ -z "${a1}" || -z "${a2}" ]]; then
        err "${mode}: no lease (initramfs '${a1}', userspace '${a2}'): ${out}"
    elif [[ "${n}" == "${want}" ]]; then
        ok "${mode} (${image}): ${n} lease(s) for ${mac}; initramfs ${a1}, userspace ${a2} [${detail}]"
    else
        err "${mode} (${image}): ${n} lease(s) for ${mac}, want ${want}; initramfs ${a1}, userspace ${a2} [${detail}]"
    fi
}

run_case stock  ubuntu:24.04 2   # control: duid ll ≠ 01:<MAC> → a second lease
run_case hooked ubuntu:24.04 1
run_case klibc  debian:13    1

if [[ ${fail} -eq 0 ]]; then
    echo "${NAME}: ALL OK"
else
    echo "${NAME}: FAILURES" >&2
    exit 1
fi
