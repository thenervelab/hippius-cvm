#!/usr/bin/env bash
# Step-order golden for `hippius-release-core.sh` (multi-OS series).
#
# The §21 unlock sequence's ORDER is security-load-bearing (audit
# Codex #8: the #296 header gate MUST precede any network activity;
# userdata MUST land before the KEK; the state disk MUST be mounted
# before the release). Both family wrappers delegate to the core's
# drivers, so pinning the drivers' call order here protects both.
# A structural (not behavioral) test: it parses the function bodies.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CORE="${HERE}/../initramfs/hippius-release-core.sh"
[[ -r "${CORE}" ]] || { echo "core not found at ${CORE}" >&2; exit 1; }

fail=0
err() { echo "release-core-order-test: FAIL: $*" >&2; fail=1; }

# Extract a function body (from `name() {` to the closing `}` at col 1).
body() {
    awk -v fn="$1() {" '
        $0 == fn {grab=1; next}
        grab && /^}/ {exit}
        grab {print}
    ' "${CORE}"
}

# 1. hippius_prepare = parse_cmdline THEN verify_header, nothing else.
prep="$(body hippius_prepare | grep -E 'hippius_' | sed 's/^ *//')"
expected_prep='hippius_parse_cmdline
hippius_verify_header'
[[ "${prep}" == "${expected_prep}" ]] \
    || err "hippius_prepare order drifted: $(echo "${prep}" | tr '\n' ' ')"

# 2. hippius_acquire order: modprobe → net → preflight → ticket →
#    state-disk → seed-meta → release → umount. `hippius_net_up` +
#    `hippius_kbs_preflight` are UNCONDITIONAL (gating them for vsock
#    hung boot twice — #670/#673, reverted); strip comments + drop the
#    non-step helpers (`hippius_log`/`hippius_die`) before pinning the
#    order of the actual drivers — the security-load-bearing sequence
#    (net BEFORE ticket, header gate BEFORE net) is unchanged.
acq="$(body hippius_acquire | sed 's/#.*$//' \
    | grep -oE 'hippius_[a-z_]+' | grep -vE '^hippius_(log|die)$' | head -8)"
expected_acq='hippius_modprobe_chain
hippius_net_up
hippius_kbs_preflight
hippius_fetch_ticket
hippius_mount_state_disk
hippius_write_seed_meta
hippius_run_release
hippius_umount_state_disk'
[[ "${acq}" == "${expected_acq}" ]] \
    || err "hippius_acquire order drifted: $(echo "${acq}" | tr '\n' ' ')"

# 3. hippius_release_run = prepare THEN acquire (header gate before any
#    network, structurally).
run="$(body hippius_release_run | grep -oE 'hippius_(prepare|acquire)' | head -2)"
expected_run='hippius_prepare
hippius_acquire'
[[ "${run}" == "${expected_run}" ]] \
    || err "hippius_release_run order drifted: $(echo "${run}" | tr '\n' ' ')"

# 4. No network verbs inside the prepare half (the #296 gate is
#    network-free by construction).
if body hippius_parse_cmdline | grep -qE '\b(ip|curl|udhcpc|dhclient)\b'; then
    err "hippius_parse_cmdline touches the network"
fi
if body hippius_verify_header | grep -qE '\b(ip |curl|udhcpc|dhclient)\b'; then
    err "hippius_verify_header touches the network (#296 must stay network-free)"
fi

# 5. userdata-before-KEK: the release invocation must carry
#    --userdata-out (the binary enforces write-before-KEK; the flag
#    being present is the script-side contract).
body hippius_run_release | grep -q -- '--userdata-out /run/cloud-init/seed/user-data' \
    || err "hippius_run_release lost --userdata-out (fail-closed userdata ordering)"

# 6. Both wrappers source the core and use only the drivers.
for wrapper in "${HERE}/../initramfs/hippius-luks-keyscript" \
               "${HERE}/../dracut/90hippius-luks/hippius-release-runner.sh"; do
    [[ -r "${wrapper}" ]] || { err "wrapper missing: ${wrapper}"; continue; }
    grep -q 'hippius-release-core.sh' "${wrapper}" \
        || err "$(basename "${wrapper}") does not source the core"
    # Wrappers may call drivers + log/die; never the inner steps.
    # (comments stripped — doc references to step names are fine).
    if sed 's/#.*$//' "${wrapper}" | grep -nE 'hippius_(parse_cmdline|verify_header|net_up|fetch_ticket|mount_state_disk|write_seed_meta|run_release|modprobe_chain|kbs_preflight)\b'; then
        err "$(basename "${wrapper}") calls core steps directly (must use the drivers)"
    fi
done

if [[ ${fail} -eq 0 ]]; then
    echo "release-core-order-test: OK (sequence pinned: header-gate→net→ticket→state→userdata→KEK)"
else
    exit 1
fi
