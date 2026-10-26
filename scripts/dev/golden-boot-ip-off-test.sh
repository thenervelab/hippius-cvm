#!/usr/bin/env bash
#
# Unit test for the end of `mountroot` in scripts/initramfs/hippius-golden-boot:
#
#   - after a successful golden assembly, IP=off, so initramfs-tools' /init
#     skips its post-mountroot `configure_networking` (Ubuntu: settle 10 s +
#     dhcpcd with an ARP probe; Debian: klibc ipconfig). Checked against the
#     REAL /init's `case "$IP"` block (lifted verbatim, configure_networking
#     stubbed), with IP=dhcp as the control;
#   - a failed assembly exits before that line: IP stays dhcp;
#   - the `hippius-trace` lines: mountroot-done (boot script),
#     net-teardown-start (init-bottom/hippius-net-teardown), after-udev
#     (init-bottom/hippius-trace-after-udev, ordered after udev), and the
#     dhcpcd hook the zz-hippius-dhcp-clientid hook writes.
#
# Root-free: the libraries the boot script sources are stubs, /dev/kmsg is
# a temp file. INIT_FILES (space-separated) overrides the /init files to
# check; default: this host's /usr/share/initramfs-tools/init (required in
# CI, skipped with a note elsewhere).
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
BOOT="${HERE}/../initramfs/hippius-golden-boot"
TEARDOWN="${HERE}/../initramfs/hippius-net-teardown"
AFTER_UDEV="${HERE}/../initramfs/hippius-trace-after-udev"
CHOOK="${HERE}/../initramfs/hippius-dhcp-clientid-hook"
NAME="golden-boot-ip-off-test"
for f in "${BOOT}" "${TEARDOWN}" "${AFTER_UDEV}" "${CHOOK}"; do
    [ -r "${f}" ] || { echo "${NAME}: ${f} missing" >&2; exit 1; }
done

fail=0
ok()  { echo "${NAME}: OK — $*"; }
err() { echo "${NAME}: FAIL — $*" >&2; fail=1; }

WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK}"' EXIT
KMSG="${WORK}/kmsg"

# ── 1. mountroot with stubbed libraries ──────────────────────────────
mkdir -p "${WORK}/lib"
cat > "${WORK}/lib/hippius-release-core.sh" <<'EOF'
hippius_die() { echo "DIE: $*" >&2; exit 1; }
EOF
cat > "${WORK}/lib/hippius-golden-overlay.sh" <<'EOF'
hippius_is_golden_mode() { return 0; }
hippius_golden_run() {
    echo "run $1" >> "${CALLS}"
    [ "${RUN_MODE}" = ok ] || hippius_die "golden: KBS release / overlay assembly failed"
}
EOF
sed -e "s#^HIPPIUS_LIB_DIR=.*#HIPPIUS_LIB_DIR=\"${WORK}/lib\"#" -e "s#/dev/kmsg#${KMSG}#g" "${BOOT}" > "${WORK}/boot.sh"
grep -q "HIPPIUS_LIB_DIR=\"${WORK}/lib\"" "${WORK}/boot.sh" || { echo "${NAME}: could not repoint HIPPIUS_LIB_DIR" >&2; exit 1; }

# Runs mountroot as /init does (sourced, same shell) and prints IP after.
# $1 = ok|fail.
run_mountroot() {
    : > "${KMSG}"; : > "${WORK}/calls"
    (
        IP=dhcp
        rootmnt=/root
        CALLS="${WORK}/calls" RUN_MODE="$1"
        export CALLS RUN_MODE
        # shellcheck disable=SC1090,SC1091
        . "${WORK}/boot.sh"
        mountroot
        echo "IP=${IP}"
    ) 2>/dev/null
}

out="$(run_mountroot ok)"
[ "${out}" = "IP=off" ] && ok "after a successful assembly, mountroot leaves IP=off" \
    || err "successful assembly: got '${out}', want IP=off"
grep -qx 'run /root' "${WORK}/calls" || err "hippius_golden_run was not called with \${rootmnt}"
grep -Eq '^hippius-trace: mountroot-done up=[0-9]+\.[0-9]+$' "${KMSG}" \
    && ok "mountroot-done trace line with the uptime" \
    || err "mountroot-done trace: $(cat "${KMSG}")"

out="$(run_mountroot fail)"
[ -z "${out}" ] && [ ! -s "${KMSG}" ] \
    && ok "a failed assembly exits before IP=off (IP untouched, no trace line)" \
    || err "failed assembly: got '${out}', kmsg '$(cat "${KMSG}")'"

# ── 2. the real /init skips configure_networking on IP=off ───────────
# The block between `mountroot`'s cleanup and init-bottom, verbatim: from
# `case "$IP" in` (column 0) to the next `esac` in column 0.
INIT_FILES="${INIT_FILES:-/usr/share/initramfs-tools/init}"
checked=0
for init in ${INIT_FILES}; do
    if [ ! -r "${init}" ]; then
        [ -z "${CI:-}" ] || { err "${init} not found in CI — the /init check cannot run"; continue; }
        echo "${NAME}: note — ${init} not found, skipping the real /init check"
        continue
    fi
    awk '/^case "\$IP" in$/{f=1} f{print} f && /^esac$/{exit}' "${init}" > "${WORK}/case.sh"
    grep -q configure_networking "${WORK}/case.sh" \
        || { err "${init}: no post-mountroot configure_networking block found — /init changed?"; continue; }
    for row in "off|no" "dhcp|yes" "|no"; do
        ip="${row%|*}"; want="${row#*|}"
        got="$(IP="${ip}" IP6="" bash -c 'configure_networking() { echo yes; }; . "$1"' _ "${WORK}/case.sh")"
        [ "${got:-no}" = "${want}" ] || err "${init}: IP='${ip}' → configure_networking ran: ${got:-no}, want ${want}"
    done
    checked=$((checked + 1))
    ok "${init}: IP=off skips configure_networking (control: IP=dhcp runs it)"
done

# ── 3. the init-bottom trace lines ───────────────────────────────────
[ "$(sh "${AFTER_UDEV}" prereqs)" = udev ] && ok "hippius-trace-after-udev is ordered after the udev init-bottom script" \
    || err "hippius-trace-after-udev prereqs: '$(sh "${AFTER_UDEV}" prereqs)', want udev"
sed "s#/dev/kmsg#${KMSG}#g" "${AFTER_UDEV}" > "${WORK}/after-udev"
: > "${KMSG}"
sh "${WORK}/after-udev" && grep -Eq '^hippius-trace: after-udev up=[0-9]+\.[0-9]+$' "${KMSG}" \
    && ok "after-udev trace line with the uptime" || err "after-udev trace: $(cat "${KMSG}")"
# hippius-net-teardown sources /scripts/functions: check the line itself.
grep -q '^echo "hippius-trace: net-teardown-start up=' "${TEARDOWN}" \
    && [ "$(grep -n 'hippius-trace' "${TEARDOWN}" | head -n1 | cut -d: -f1)" -lt "$(grep -n 'for iface in' "${TEARDOWN}" | cut -d: -f1)" ] \
    && ok "net-teardown-start trace line comes before the flush" || err "net-teardown trace line missing or after the flush"

# ── 4. the dhcpcd trace hook ─────────────────────────────────────────
D="${WORK}/destdir"; mkdir -p "${D}/etc"
printf 'persistent\nduid ll\n' > "${D}/etc/dhcpcd.conf"
if DESTDIR="${D}" sh "${CHOOK}"; then
    h="${D}/usr/lib/dhcpcd/dhcpcd-hooks/01-hippius-trace"
    sed "s#/dev/kmsg#${KMSG}#g" "${h}" > "${WORK}/dhcpcd-hook"
    : > "${KMSG}"
    # dhcpcd-run-hooks sources each hook with reason/interface set.
    reason=BOUND interface=enp1s0 sh -c '. "$1"' _ "${WORK}/dhcpcd-hook"
    [ "$(stat -c %a "${h}")" = 644 ] && grep -Eq '^hippius-trace: dhcpcd BOUND enp1s0 up=[0-9]+\.[0-9]+$' "${KMSG}" \
        && ok "dhcpcd hook: one trace line per event (reason, interface, uptime)" \
        || err "dhcpcd hook: mode $(stat -c %a "${h}"), kmsg '$(cat "${KMSG}")'"
else
    err "dhcp-clientid hook failed"
fi
E="${WORK}/destdir-noop"; mkdir -p "${E}"
DESTDIR="${E}" sh "${CHOOK}" && [ ! -e "${E}/usr" ] \
    && ok "no dhcpcd in the initramfs (Debian klibc): no trace hook written" \
    || err "dhcp-clientid hook wrote a trace hook without dhcpcd"

[ "${fail}" -eq 0 ] && echo "${NAME}: OK (all checks passed; real /init files checked: ${checked})" || exit 1
