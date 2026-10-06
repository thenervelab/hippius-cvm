#!/usr/bin/env bash
# Unit test for the §23 SNP live-attestation keepalive staging in
# `tenant-image-bake.sh` + the guest shim it installs.
#
# PR #904 built the whole liveness gate — vali, the Edge, the miner-agent
# relay, the guest binary — and then nobody ran it in a guest, so
# `VmLiveAttestation` stayed empty and the gate could never be armed. The
# failure mode this file exists to prevent is the codebase's recurring
# one: a unit DECLARED but not WIRED. So the assertions here are about
# what actually lands in the rootfs and what the shim actually execs, not
# about the presence of a flag.
#
# Root-free and network-free: the staging block is EXTRACTED VERBATIM from
# the bake script (between its `keepalive-staging-block` sentinels) and
# executed against a temp directory with `sudo` stubbed to a passthrough,
# so the bytes under test are the bytes the bake installs. The shim is
# likewise executed for real, against a fixture `/proc/cmdline` and a stub
# agent binary that prints its argv.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BAKE="${HERE}/../tenant-image-bake.sh"
SHIM="${HERE}/../guest/hippius-keepalive-start"
VALUES="${HERE}/../../deploy/gitops/apps/vali/values.yaml"
BAKER_ENTRYPOINT="${HERE}/../../binaries/tenant-baker/entrypoint.sh"

for f in "${BAKE}" "${SHIM}" "${VALUES}" "${BAKER_ENTRYPOINT}"; do
    [[ -r "${f}" ]] || { echo "keepalive-unit-test: missing ${f}" >&2; exit 1; }
done

fail=0
ok()   { echo "keepalive-unit-test: OK — $1"; }
bad()  { echo "keepalive-unit-test: FAIL — $1" >&2; fail=1; }

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

# ── 0. The staging block is reachable and delimited ──────────────────
BEGIN_LINE="$(grep -n '>>> BEGIN keepalive-staging-block' "${BAKE}" | cut -d: -f1 || true)"
END_LINE="$(grep -n '<<< END keepalive-staging-block' "${BAKE}" | cut -d: -f1 || true)"
if [[ -z "${BEGIN_LINE}" || -z "${END_LINE}" ]]; then
    echo "keepalive-unit-test: FAIL — staging-block sentinels missing from ${BAKE}" >&2
    exit 1
fi
sed -n "$((BEGIN_LINE + 1)),$((END_LINE - 1))p" "${BAKE}" > "${TMP}/staging-block.sh"

# ── 1. Execute the extracted staging block against a temp rootfs ─────
ROOTFS="${TMP}/rootfs"
mkdir -p "${ROOTFS}/usr/sbin" "${ROOTFS}/etc/systemd/system"
printf '#!/bin/sh\nexit 0\n' > "${TMP}/fake-keepalive-bin"
chmod 0755 "${TMP}/fake-keepalive-bin"

cat > "${TMP}/run-staging.sh" <<'HARNESS'
set -euo pipefail
# `sudo` is not available (and not needed) in CI: the block writes only
# into the temp rootfs.
sudo() { "$@"; }
log() { :; }
source "${STAGING_BLOCK}"
HARNESS

STAGING_BLOCK="${TMP}/staging-block.sh" \
MNT_ROOT="${ROOTFS}" \
hippius_keepalive_bin="${TMP}/fake-keepalive-bin" \
KEEPALIVE_SHIM_SRC="${SHIM}" \
keepalive_interval_secs=300 \
keepalive_relay_port=5000 \
KEEPALIVE_MAX_INTERVAL_SECS=900 \
    bash "${TMP}/run-staging.sh"

BIN_DST="${ROOTFS}/usr/sbin/hippius-agent-keepalive"
SHIM_DST="${ROOTFS}/usr/sbin/hippius-keepalive-start"
UNIT_DST="${ROOTFS}/etc/systemd/system/hippius-keepalive.service"
WANTS_DST="${ROOTFS}/etc/systemd/system/multi-user.target.wants/hippius-keepalive.service"
ENV_DST="${ROOTFS}/etc/hippius/keepalive.env"

# 1a. The binary is staged at the expected path with the expected mode.
if [[ ! -f "${BIN_DST}" ]]; then
    bad "the keepalive binary was not staged at /usr/sbin/hippius-agent-keepalive"
elif [[ "$(stat -c '%a' "${BIN_DST}")" != "755" ]]; then
    bad "keepalive binary mode is $(stat -c '%a' "${BIN_DST}"), expected 755 (systemd cannot exec a non-executable)"
else
    ok "keepalive binary staged 0755 at /usr/sbin/hippius-agent-keepalive"
fi

# 1b. The shim likewise — it is the unit's ExecStart.
if [[ ! -f "${SHIM_DST}" ]]; then
    bad "the cmdline shim was not staged at /usr/sbin/hippius-keepalive-start"
elif [[ "$(stat -c '%a' "${SHIM_DST}")" != "755" ]]; then
    bad "shim mode is $(stat -c '%a' "${SHIM_DST}"), expected 755"
elif ! cmp -s "${SHIM}" "${SHIM_DST}"; then
    bad "the staged shim differs from ${SHIM} (the bake must install the committed bytes verbatim)"
else
    ok "cmdline shim staged 0755, byte-identical to the committed source"
fi

# 1c. INSTALLED **and** ENABLED. An installed-but-not-enabled unit is the
#     "declared but not wired" failure this codebase has shipped three
#     times: `systemctl status` looks fine and the unit never runs.
if [[ ! -f "${UNIT_DST}" ]]; then
    bad "hippius-keepalive.service was not installed"
else
    ok "hippius-keepalive.service installed"
fi
if [[ ! -L "${WANTS_DST}" ]]; then
    bad "hippius-keepalive.service is INSTALLED BUT NOT ENABLED (no multi-user.target.wants symlink) — it would never start"
elif [[ "$(readlink "${WANTS_DST}")" != "../hippius-keepalive.service" ]]; then
    bad "the enable symlink points at $(readlink "${WANTS_DST}"), not ../hippius-keepalive.service"
else
    ok "hippius-keepalive.service ENABLED via the multi-user.target.wants symlink"
fi

# 1d. The unit's failure posture: it must be incapable of holding up or
#     failing the boot. `Type=simple` (systemd does not wait for it) and
#     — the load-bearing one — NO `Before=` ordering at all, so a KBS a
#     hostile miner has blocked costs that miner uncredited uptime and
#     costs the tenant nothing.
if grep -qE '^[[:space:]]*Before=' "${UNIT_DST}"; then
    bad "the unit declares Before= — a blocked KBS could then delay or wedge the boot"
else
    ok "the unit orders Before= nothing (a KBS outage cannot hold up the boot)"
fi
if grep -qE '^[[:space:]]*(Requires|Requisite|BindsTo)=' "${UNIT_DST}"; then
    bad "the unit declares a hard dependency — a failure would propagate to the boot transaction"
else
    ok "the unit declares no hard dependency (Wants= semantics only)"
fi
for want in 'Type=simple' 'Restart=always' 'StartLimitIntervalSec=0' 'WantedBy=multi-user.target'; do
    if grep -qF "${want}" "${UNIT_DST}"; then
        ok "unit declares ${want}"
    else
        bad "unit is missing ${want}"
    fi
done
# A long KBS outage must not leave the unit permanently failed, but the
# two TERMINAL conditions must not restart-loop either.
if grep -qE '^RestartPreventExitStatus=.*\<2\>.*\<78\>' "${UNIT_DST}"; then
    ok "unit treats 2 (no /dev/sev-guest) and 78 (no Hippius cmdline) as terminal"
else
    bad "unit does not stop on the terminal exit codes 2 and 78 — it would restart-loop forever"
fi
if grep -qF 'ExecStart=/usr/sbin/hippius-keepalive-start' "${UNIT_DST}"; then
    ok "unit ExecStart is the staged shim"
else
    bad "unit ExecStart does not point at /usr/sbin/hippius-keepalive-start"
fi

# 1e. The cadence file the unit sources.
if [[ ! -f "${ENV_DST}" ]]; then
    bad "/etc/hippius/keepalive.env was not staged"
elif grep -qxF 'HIPPIUS_KEEPALIVE_INTERVAL_SECS=300' "${ENV_DST}" \
  && grep -qxF 'HIPPIUS_KEEPALIVE_RELAY_PORT=5000' "${ENV_DST}"; then
    ok "/etc/hippius/keepalive.env carries the bake's cadence + relay port"
else
    bad "/etc/hippius/keepalive.env does not carry the bake's values: $(grep -v '^#' "${ENV_DST}" | tr '\n' ' ')"
fi

# ── 2. Cadence vs the CHART's coverage window ────────────────────────
# One liveness sample vouches BACKWARD for `coverageSeconds` and no
# further. A cadence wider than that leaves gaps of genuinely-live time
# that the armed gate credits as ZERO. Pinned against the chart so that
# LOWERING coverageSeconds fails CI instead of silently un-crediting the
# fleet — the reason this is not just a hardcoded constant.
COVERAGE="$(awk '/^uptimeLiveness:/{f=1} f && /^[[:space:]]+coverageSeconds:/{print $2; exit}' "${VALUES}")"
CEILING="$(awk -F= '/^KEEPALIVE_MAX_INTERVAL_SECS=/{print $2; exit}' "${BAKE}")"
INTERVAL="$(awk -F= '/^keepalive_interval_secs=/{print $2; exit}' "${BAKE}")"
if [[ -z "${COVERAGE}" || -z "${CEILING}" || -z "${INTERVAL}" ]]; then
    bad "could not read coverageSeconds=${COVERAGE:-?} / ceiling=${CEILING:-?} / interval=${INTERVAL:-?}"
else
    if (( CEILING == COVERAGE )); then
        ok "the bake's cadence ceiling (${CEILING}) tracks the chart's coverageSeconds (${COVERAGE})"
    else
        bad "the bake's cadence ceiling (${CEILING}) has drifted from the chart's coverageSeconds (${COVERAGE}) — update KEEPALIVE_MAX_INTERVAL_SECS in ${BAKE}"
    fi
    if (( INTERVAL <= COVERAGE )); then
        ok "the default cadence (${INTERVAL}s) is <= the coverage window (${COVERAGE}s)"
    else
        bad "the default cadence (${INTERVAL}s) EXCEEDS the coverage window (${COVERAGE}s): honest uptime would fall into the gaps between samples and go uncredited"
    fi
fi

# ── 3. The bake's own gates reject cadences that violate the relation ─
run_bake() {
    set +e
    bash "${BAKE}" "$@" </dev/null 2>"${TMP}/err" >/dev/null
    RC=$?
    set -e
}
run_bake --keepalive-interval-secs 901
if grep -qF 'exceeds vali' "${TMP}/err"; then
    ok "the bake refuses a cadence above the coverage window"
else
    bad "the bake accepted --keepalive-interval-secs 901 (rc=${RC})"
fi
run_bake --keepalive-interval-secs 0
if grep -qF 'must be a positive integer' "${TMP}/err"; then
    ok "the bake refuses a zero cadence"
else
    bad "the bake accepted --keepalive-interval-secs 0 (rc=${RC})"
fi
# Port 0 mints attestations that are archived KBS-side and NEVER reach
# vali — the exact "looks armed, credits nothing" shape.
run_bake --keepalive-relay-port 0
if grep -qF 'never reach vali' "${TMP}/err"; then
    ok "the bake refuses relay port 0 (attestations that never reach vali)"
else
    bad "the bake accepted --keepalive-relay-port 0 (rc=${RC})"
fi
run_bake --keepalive-interval-secs 900
if grep -qF 'exceeds vali' "${TMP}/err"; then
    bad "the bake refused a cadence exactly AT the coverage window (contiguous coverage, must be allowed)"
else
    ok "the bake accepts a cadence exactly at the coverage window"
fi

# ── 4. The shim: what it execs, and what it does when things are absent ─
STUB="${TMP}/stub-agent"
cat > "${STUB}" <<'STUBEOF'
#!/bin/sh
for a in "$@"; do printf '%s\n' "${a}"; done
STUBEOF
chmod 0755 "${STUB}"

# Full production-shaped cmdline (vsock KBS URL, as a real tenant boots).
cat > "${TMP}/cmdline.full" <<'EOF'
BOOT_IMAGE=/vmlinuz root=/dev/mapper/hippius hippius.vm_id=vm-abc hippius.node_id=aa11bb22 hippius.kbs_url=vsock://2:19266 hippius.telemetry_epoch=4242 console=ttyS0
EOF

run_shim() {
    set +e
    env HIPPIUS_KEEPALIVE_CMDLINE_FILE="$1" \
        HIPPIUS_KEEPALIVE_AGENT_BIN="${STUB}" \
        HIPPIUS_KEEPALIVE_EPOCH_FILE="$2" \
        sh "${SHIM}" >"${TMP}/argv" 2>"${TMP}/shimerr"
    SRC=$?
    set -e
}

run_shim "${TMP}/cmdline.full" "${TMP}/epoch.1"
if (( SRC != 0 )); then
    bad "the shim failed on a well-formed cmdline (rc=${SRC}): $(cat "${TMP}/shimerr")"
else
    ok "the shim execs the agent on a well-formed cmdline"
fi
argv="$(cat "${TMP}/argv")"
expect_pair() {
    if grep -qxF -- "$1" "${TMP}/argv" && grep -A1 -xF -- "$1" "${TMP}/argv" | tail -1 | grep -qxF -- "$2"; then
        ok "shim passes $1 $2"
    else
        bad "shim did not pass '$1 $2' (argv: $(tr '\n' ' ' <"${TMP}/argv"))"
    fi
}
expect_pair --kbs-url vsock://2:19266
expect_pair --vm-id vm-abc
expect_pair --node-id-hex aa11bb22
expect_pair --interval-secs 300
# `expiry_unix = now + 2*interval`: an attestation survives one missed
# tick but cannot be replayed long after. The agent REQUIRES
# expiry_offset > interval, and deriving it keeps that true for any
# cadence rather than pairing a tuned interval with a stale constant.
expect_pair --expiry-offset-secs 600
# Non-zero is the whole point: port 0 disables the push, so vali would
# never learn this VM was alive.
expect_pair --relay-vsock-port 5000
if grep -qxF -- '--relay-vsock-port' "${TMP}/argv" && grep -A1 -xF -- '--relay-vsock-port' "${TMP}/argv" | tail -1 | grep -qxF -- '0'; then
    bad "the shim disabled the relay push (port 0) — attestations would never reach vali"
fi
[[ -n "${argv}" ]] || bad "the shim exec'd with no argv"
if grep -qxF -- '--attest-resources' "${TMP}/argv"; then
    bad "the shim attests resources without hippius.attest_resources=1 — an older KBS would refuse every keepalive"
else
    ok "no hippius.attest_resources=1 ⇒ the resource-less keepalive"
fi

# The MEASURED opt-in turns the resource attestation on; any other value
# leaves it off.
sed 's/console=ttyS0/hippius.attest_resources=1 console=ttyS0/' "${TMP}/cmdline.full" > "${TMP}/cmdline.res"
run_shim "${TMP}/cmdline.res" "${TMP}/epoch.res"
if (( SRC == 0 )) && grep -qxF -- '--attest-resources' "${TMP}/argv"; then
    ok "hippius.attest_resources=1 ⇒ the shim passes --attest-resources"
else
    bad "hippius.attest_resources=1 did not pass --attest-resources (rc=${SRC}, argv: $(tr '\n' ' ' <"${TMP}/argv"))"
fi
expect_pair --vm-id vm-abc
sed 's/console=ttyS0/hippius.attest_resources=yes console=ttyS0/' "${TMP}/cmdline.full" > "${TMP}/cmdline.res2"
run_shim "${TMP}/cmdline.res2" "${TMP}/epoch.res2"
if (( SRC == 0 )) && ! grep -qxF -- '--attest-resources' "${TMP}/argv"; then
    ok "hippius.attest_resources=<not 1> leaves the resource attestation off"
else
    bad "hippius.attest_resources=yes changed the argv (rc=${SRC})"
fi

# The components health leg follows the RELEASE's own switch (its
# keepalive.env, read by the unit's EnvironmentFile), never the cmdline.
if grep -qxF -- '--attest-components' "${TMP}/argv"; then
    bad "the shim attests components without HIPPIUS_KEEPALIVE_ATTEST_COMPONENTS=1"
else
    ok "no HIPPIUS_KEEPALIVE_ATTEST_COMPONENTS=1 ⇒ no components leg"
fi
HIPPIUS_KEEPALIVE_ATTEST_COMPONENTS=1 run_shim "${TMP}/cmdline.full" "${TMP}/epoch.comp"
if (( SRC == 0 )) && grep -qxF -- '--attest-components' "${TMP}/argv"; then
    ok "HIPPIUS_KEEPALIVE_ATTEST_COMPONENTS=1 ⇒ the shim passes --attest-components"
else
    bad "HIPPIUS_KEEPALIVE_ATTEST_COMPONENTS=1 did not pass --attest-components (rc=${SRC})"
fi
HIPPIUS_KEEPALIVE_ATTEST_COMPONENTS=yes run_shim "${TMP}/cmdline.full" "${TMP}/epoch.comp2"
if (( SRC == 0 )) && ! grep -qxF -- '--attest-components' "${TMP}/argv"; then
    ok "HIPPIUS_KEEPALIVE_ATTEST_COMPONENTS=<not 1> leaves the components leg off"
else
    bad "HIPPIUS_KEEPALIVE_ATTEST_COMPONENTS=yes changed the argv (rc=${SRC})"
fi

# The epoch file is seeded from the measured cmdline (the guest has no
# chain access of its own).
if [[ "$(cat "${TMP}/epoch.1")" == "4242" ]]; then
    ok "the shim seeds the epoch file from hippius.telemetry_epoch"
else
    bad "the epoch file holds '$(cat "${TMP}/epoch.1")', expected 4242"
fi

# An existing epoch file is NOT clobbered — a host-side refresher must be
# able to keep it current across a unit restart.
printf '99\n' > "${TMP}/epoch.2"
run_shim "${TMP}/cmdline.full" "${TMP}/epoch.2"
if [[ "$(cat "${TMP}/epoch.2")" == "99" ]]; then
    ok "the shim does not clobber an existing epoch file"
else
    bad "the shim overwrote a pre-existing epoch file"
fi

# No telemetry_epoch token ⇒ 0, not a crash. vali's coverage meter does
# not gate on epoch, so 0 costs no coverage.
cat > "${TMP}/cmdline.noepoch" <<'EOF'
hippius.vm_id=vm-abc hippius.node_id=aa11bb22 hippius.kbs_url=vsock://2:19266
EOF
run_shim "${TMP}/cmdline.noepoch" "${TMP}/epoch.3"
if (( SRC == 0 )) && [[ "$(cat "${TMP}/epoch.3")" == "0" ]]; then
    ok "an absent hippius.telemetry_epoch defaults to 0 rather than failing"
else
    bad "an absent hippius.telemetry_epoch was not defaulted (rc=${SRC}, epoch=$(cat "${TMP}/epoch.3" 2>/dev/null))"
fi

# ── 5. A non-Hippius / KBS-less boot must be INERT, never fatal ──────
# 78 = EX_CONFIG, which the unit's RestartPreventExitStatus treats as
# terminal: systemd stops the unit and the guest boots and serves exactly
# as it would have. Nothing here can fail the boot.
for missing in vm_id node_id kbs_url; do
    grep -v "hippius.${missing}=" <<'EOF' > "${TMP}/cmdline.partial"
hippius.vm_id=vm-abc
hippius.node_id=aa11bb22
hippius.kbs_url=vsock://2:19266
EOF
    run_shim "${TMP}/cmdline.partial" "${TMP}/epoch.miss.${missing}"
    if (( SRC == 78 )) && grep -qF "cmdline-missing:hippius.${missing}" "${TMP}/shimerr"; then
        ok "a cmdline without hippius.${missing} exits 78 (inert), not fatally"
    else
        bad "a cmdline without hippius.${missing} gave rc=${SRC}: $(cat "${TMP}/shimerr")"
    fi
done
# No /proc/cmdline at all — the shim must still exit cleanly-terminal.
run_shim "${TMP}/does-not-exist" "${TMP}/epoch.nocmdline"
if (( SRC == 78 )); then
    ok "an unreadable cmdline exits 78 (inert)"
else
    bad "an unreadable cmdline gave rc=${SRC}"
fi
# An UNREACHABLE KBS is the miner's lever. It must not surface here at
# all: the shim execs, and the agent's own loop logs `tick-err` and
# sleeps to the next tick. Proven by the agent never being handed a
# "fail if unreachable" flag and the shim never probing the KBS.
if grep -qE 'curl|wget|nc |ping|getent hosts' "${SHIM}"; then
    bad "the shim probes the KBS at start — an unreachable KBS could then keep the unit from ever starting"
else
    ok "the shim never probes the KBS (reachability is the agent loop's problem, retried forever)"
fi

# ── 6. The layer above: the baker must actually PASS the flag ────────
# The bake supporting a flag nobody passes is precisely the #904 gap.
if grep -qF -- '--hippius-keepalive-bin /usr/sbin/hippius-agent-keepalive' "${BAKER_ENTRYPOINT}"; then
    ok "the in-cluster baker passes --hippius-keepalive-bin"
else
    bad "binaries/tenant-baker/entrypoint.sh does not pass --hippius-keepalive-bin — every in-cluster bake would produce an image with no keepalive"
fi

# vali's guest report grants a keepalive in flight at a hand-over the KBS
# nonce lifetime before it calls a refusal T4: the two charts must agree.
KBS_VALUES="${HERE}/../../deploy/gitops/apps/kbs/values.yaml"
KBS_TTL="$(awk '/^[[:space:]]+nonceTtlSecs:/{print $2; exit}' "${KBS_VALUES}")"
VALI_TTL="$(awk '/^[[:space:]]+kbsNonceTtlSecs:/{gsub(/"/, "", $2); print $2; exit}' "${VALUES}")"
if [[ -n "${KBS_TTL}" && "${KBS_TTL}" == "${VALI_TTL}" ]]; then
    ok "vali's guestReport.kbsNonceTtlSecs (${VALI_TTL}) tracks the KBS nonceTtlSecs (${KBS_TTL})"
else
    bad "guestReport.kbsNonceTtlSecs (${VALI_TTL:-?}) != the KBS nonceTtlSecs (${KBS_TTL:-?}) — align ${VALUES}"
fi

if [[ ${fail} -eq 0 ]]; then
    echo "keepalive-unit-test: ALL OK"
else
    exit 1
fi
