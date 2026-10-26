#!/usr/bin/env bash
# ubuntu-runner bake profile, root-free:
#   1. tenant-image-bake.sh's --profile gate refuses what it must, before
#      any root / network / image step, and a complete request passes it;
#   2. the chroot block pins Docker's key by fingerprint (its fingerprint
#      filter is run against fixtures), installs the Docker + runner set
#      and leaves no policy-rc.d behind; the post-install gate checks it;
#      the pinned runner tarball keys the cache, its fetch retries and
#      refuses a sha256 mismatch (run against a fake curl), and it is
#      installed root-owned at the exact path the consumer looks for;
#      Docker's daemon.json (containerd image store off) is pinned once,
#      keys the cache, is written by the chroot and gated after it;
#   3. scripts/ubuntu-runner/install-ubuntu-runner.sh, run against a
#      throwaway rootfs (SUDO=""), writes the data-path unit, script and
#      daemon drop-ins, and the script binds Docker's and containerd's state
#      onto /var/lib/hippius-data (mount/mountpoint shimmed).
# Same tier as cdn-node-profile-test.sh (per-PR CI gate).
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "${HERE}/../.." && pwd)"
BAKE="${REPO}/scripts/tenant-image-bake.sh"
INSTALL="${REPO}/scripts/ubuntu-runner/install-ubuntu-runner.sh"
ENTRY="${REPO}/binaries/tenant-baker/entrypoint.sh"

fail=0
ok() { echo "ubuntu-runner-profile-test: OK — $*"; }
bad() { echo "ubuntu-runner-profile-test: FAIL — $*" >&2; fail=1; }

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
expect_die "--profile must be standard, cdn-node or ubuntu-runner" --profile runner
expect_die "--profile ubuntu-runner needs --disk-mode golden_verity_overlay" --profile ubuntu-runner
expect_die "--profile ubuntu-runner needs --disk-mode golden_verity_overlay" \
    --profile ubuntu-runner --disk-mode legacy_luks
expect_die "--profile ubuntu-runner needs an Ubuntu base" \
    --profile ubuntu-runner --disk-mode golden_verity_overlay --distro debian
expect_die "--cdn-* flags need --profile cdn-node" \
    --profile ubuntu-runner --disk-mode golden_verity_overlay --cdn-backend-url https://api.example.invalid
for d in auto ubuntu; do
    run_bake --profile ubuntu-runner --disk-mode golden_verity_overlay --distro "${d}"
    if grep -qE 'profile (must|ubuntu-runner needs)|cdn-\* flags' "${TMP}/err" \
        || ! grep -qF 'base-image-url is required' "${TMP}/err"; then
        bad "a complete ubuntu-runner request (--distro ${d}) did not pass the gate: $(cat "${TMP}/err")"
    else
        ok "a complete ubuntu-runner request passes the gate (--distro ${d})"
    fi
done
HCC_BAKE_PROFILE=ubuntu-runner HCC_BAKE_DISK_MODE=golden_verity_overlay run_bake
grep -qF 'base-image-url is required' "${TMP}/err" \
    && ok "the profile is taken from HCC_BAKE_PROFILE" || bad "HCC_BAKE_PROFILE: $(cat "${TMP}/err")"

# The detected base must be Ubuntu, after the os-release read.
grep -qF 'if [[ "${profile}" == "ubuntu-runner" && "${DISTRO_ID}" != "ubuntu" ]]; then' "${BAKE}" \
    && ok "a non-Ubuntu base is refused once detected" || bad "no detected-distro check"
# The installer's bytes key the stage-1 cache.
grep -qF "sha256sum \"\${RUNNER_INSTALL_SRC}\" | awk '{print \"ubuntu-runner=\"\$1}'" "${BAKE}" \
    && ok "the installer keys the stage-1 cache" || bad "the installer is not in the stage-1 cache key"

# ── 2. chroot block ──────────────────────────────────────────────────
block="$(awk '/^if \[ "\$\{HIPPIUS_PROFILE:-standard\}" = "ubuntu-runner" \]; then$/{on=1} on{print} on && /^fi$/{exit}' "${BAKE}")"
[[ -n "${block}" ]] || { bad "chroot ubuntu-runner block not found"; block=""; }
inblock() { # pattern description
    if grep -qE -- "$1" <<<"${block}"; then ok "$2"; else bad "$2 (chroot block lacks /$1/)"; fi
}
inblock '^    DOCKER_KEY_FPR=9DC858229FC7DD38854AE2D88D81803C0EBFCD88$' "Docker key pinned by fingerprint"
inblock 'https://download.docker.com/linux/ubuntu/gpg' "key from Docker's ubuntu repo"
inblock 'signed-by=/etc/apt/keyrings/docker.asc\] https://download.docker.com/linux/ubuntu \$\{DOCKER_SUITE\} stable' "repo signed by the pinned key only"
for pkg in docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
           libkrb5-3 zlib1g git jq curl ca-certificates; do
    inblock "(^| )${pkg//./\\.}( |$)" "installs ${pkg}"
done
inblock 'pick_pkg liblttng-ust1t64 liblttng-ust1 liblttng-ust0' "lttng-ust per release"
inblock 'pick_pkg libssl3t64 libssl3' "libssl per release"
inblock "grep -E '\^libicu\[0-9\]\+\(t64\)\?\\$'" "versioned libicu"
inblock '^    rm -f /usr/sbin/policy-rc.d$' "policy-rc.d removed after the install"
inblock '^    systemctl enable containerd.service docker.service docker.socket$' "daemons enabled"
if grep -qE 'actions-runner|actions/runner/releases' <<<"${block}"; then
    bad "the chroot fetches or extracts the runner (only the host stages its tarball)"
else
    ok "the chroot neither fetches nor extracts the runner"
fi
if grep -qE 'unattended-upgrades|purge' <<<"${block}"; then
    bad "the runner block touches unattended-upgrades or purges a package"
else
    ok "unattended-upgrades and the rest of the image left alone"
fi

# The key check (docker_key_primary_fpr, extracted from the chroot block and
# run as-is under the chroot's `set -eu`, no pipefail) against a fake gpg that
# prints --with-colons fixtures and exits with a chosen status: only the
# primary key's fingerprint counts, anything but one primary key is refused,
# and a gpg failure fails even after gpg printed the pinned fingerprint.
fn="$(awk '/^    docker_key_primary_fpr\(\) \{$/{on=1} on{print} on && /^    \}$/{exit}' "${BAKE}")"
[[ -n "${fn}" ]] || bad "docker_key_primary_fpr not found in the chroot block"
# shellcheck disable=SC2016 # literal source line
grep -qxF '    DOCKER_KEY_FPRS=$(docker_key_primary_fpr /tmp/docker.asc) || exit 3' "${BAKE}" \
    && ok "the chroot block exits when the key check fails" || bad "the key check's failure is not fatal"
K="${TMP}/key"; mkdir -p "${K}/bin"
cat > "${K}/one" <<'FIX'
pub:-:4096:1:8D81803C0EBFCD88:1487788586:::-:::scESA::::::23::0:
fpr:::::::::9DC858229FC7DD38854AE2D88D81803C0EBFCD88:
uid:-::::1487792064::B5A08F01796E7F521861B449372D1FF271F2DD50::Docker Release (CE deb) <docker@docker.com>::::::::::0:
sub:-:4096:1:7EA0A9C3F273FCD8:1487788586::::::s::::::23:
fpr:::::::::D3306A018370199E527AE7317EA0A9C3F273FCD8:
FIX
{ cat "${K}/one"; printf '%s\n' 'pub:-:4096:1:AAAAAAAAAAAAAAAA:1487788586:::-:::scESA::::::23::0:' \
    'fpr:::::::::0123456789ABCDEF0123456789ABCDEFAAAAAAAA:'; } > "${K}/two"
: > "${K}/none"
cat > "${K}/bin/gpg" <<'SHIM'
#!/bin/sh
# Fake gpg: print the fixture named by FAKE_GPG_OUT, exit FAKE_GPG_RC.
[ -n "${FAKE_GPG_OUT:-}" ] && cat "${FAKE_GPG_OUT}"
exit "${FAKE_GPG_RC:-0}"
SHIM
chmod 0755 "${K}/bin/gpg"
{
    echo 'set -eu'
    printf '%s\n' "${fn}"
    # shellcheck disable=SC2016 # written verbatim into the check script
    echo 'FPR=$(docker_key_primary_fpr /tmp/docker.asc) || exit 3'
    # shellcheck disable=SC2016
    echo 'echo "${FPR}"'
} > "${K}/check.sh"
key_check() { # fixture rc -> sets KRC, KOUT, KERR
    set +e
    KOUT="$(FAKE_GPG_OUT="$1" FAKE_GPG_RC="$2" PATH="${K}/bin:${PATH}" bash "${K}/check.sh" 2>"${K}/err")"
    KRC=$?
    set -e
    KERR="$(cat "${K}/err")"
}
key_check "${K}/one" 0
[[ ${KRC} -eq 0 && "${KOUT}" == "9DC858229FC7DD38854AE2D88D81803C0EBFCD88" ]] \
    && ok "key check: the primary key's fingerprint only (subkey ignored)" \
    || bad "key check, one key: rc=${KRC} out='${KOUT}' ${KERR}"
key_check "${K}/one" 2
[[ ${KRC} -eq 3 ]] && grep -qF 'gpg --show-keys failed' <<<"${KERR}" \
    && ok "key check: gpg failing after printing the pinned fingerprint fails the bake" \
    || bad "key check passed a gpg failure: rc=${KRC} out='${KOUT}' ${KERR}"
key_check "" 2
[[ ${KRC} -eq 3 ]] && ok "key check: gpg failing with no output fails the bake" \
    || bad "key check, gpg failure without output: rc=${KRC}"
key_check "${K}/two" 0
[[ ${KRC} -eq 3 ]] && grep -qF 'holds 2 primary keys' <<<"${KERR}" \
    && ok "key check: a file with two primary keys is refused" \
    || bad "key check, two keys: rc=${KRC} out='${KOUT}' ${KERR}"
key_check "${K}/none" 0
[[ ${KRC} -eq 3 ]] && grep -qF 'holds 0 primary keys' <<<"${KERR}" \
    && ok "key check: a file with no key is refused" || bad "key check, no key: rc=${KRC} ${KERR}"

# Post-install gate.
for want in '/usr/bin/dockerd /usr/bin/containerd' 'multi-user.target.wants/docker.service' \
            'sockets.target.wants/docker.socket' 'policy-rc.d was left in the image'; do
    grep -qF -- "${want}" "${BAKE}" && ok "post-install gate: ${want}" || bad "post-install gate lacks ${want}"
done

# ── runner tarball ───────────────────────────────────────────────────
# Pinned once, at the exact path the consumer (hippius-backend's runner
# bootstrap) looks for.
pin() { sed -n "s/^$1=\"\(.*\)\"$/\1/p" "${BAKE}"; }
RV="$(pin RUNNER_TARBALL_VERSION)"; RU="$(pin RUNNER_TARBALL_URL)"
RS="$(pin RUNNER_TARBALL_SHA256)"; RD="$(pin RUNNER_TARBALL_DEST)"
for v in RUNNER_TARBALL_VERSION RUNNER_TARBALL_URL RUNNER_TARBALL_SHA256 RUNNER_TARBALL_DEST; do
    n="$(grep -cE "^${v}=" "${BAKE}")"
    (( n == 1 )) && ok "${v} pinned once" || bad "${v} assigned ${n} times"
done
[[ "${RV}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && ok "runner version ${RV}" || bad "runner version '${RV}'"
[[ "${RU}" == "https://github.com/actions/runner/releases/download/v${RV}/actions-runner-linux-x64-${RV}.tar.gz" ]] \
    && ok "runner URL matches the version" || bad "runner URL '${RU}' does not match version ${RV}"
[[ "${RS}" =~ ^[0-9a-f]{64}$ ]] && ok "runner sha256 is 64 hex" || bad "runner sha256 '${RS}'"
# shellcheck disable=SC2016 # literal source text
[[ "${RD}" == '/opt/actions-runner/actions-runner-linux-x64-${RUNNER_TARBALL_VERSION}.tar.gz' ]] \
    && ok "runner tarball lands at /opt/actions-runner/actions-runner-linux-x64-<version>.tar.gz" \
    || bad "runner tarball destination '${RD}'"
# shellcheck disable=SC2016 # literal source line
grep -qxF '                echo "runner-tarball=${RUNNER_TARBALL_VERSION} ${RUNNER_TARBALL_SHA256} ${RUNNER_TARBALL_URL}"' "${BAKE}" \
    && ok "the runner version, sha256 and URL key the stage-1 cache" || bad "the runner pin is not in the stage-1 cache key"

# runner_tarball_fetch, extracted and run against a fake curl that writes a
# fixture body to -o and fails the first FAKE_CURL_FAILS calls.
rfn="$(awk '/^runner_tarball_fetch\(\) \{$/{on=1} on{print} on && /^\}$/{exit}' "${BAKE}")"
[[ -n "${rfn}" ]] || bad "runner_tarball_fetch not found"
C="${TMP}/curl"; mkdir -p "${C}/bin"
printf 'runner tarball fixture\n' > "${C}/body"
C_SHA="$(sha256sum "${C}/body" | awk '{print $1}')"
cat > "${C}/bin/curl" <<SHIM
#!/bin/sh
# Fake curl: count the call, fail the first FAKE_CURL_FAILS ones (exit 18,
# after writing a truncated body), otherwise write the fixture to -o.
n=\$(( \$(cat "${C}/calls" 2>/dev/null || echo 0) + 1 )); echo "\${n}" > "${C}/calls"
echo "\$*" > "${C}/args"
out=""; while [ \$# -gt 0 ]; do [ "\$1" = -o ] && out="\$2"; shift; done
if [ "\${n}" -le "\${FAKE_CURL_FAILS:-0}" ]; then printf 'trunc' > "\${out}"; exit 18; fi
cat "${C}/body" > "\${out}"
SHIM
chmod 0755 "${C}/bin/curl"
{
    echo 'set -euo pipefail'
    echo 'log() { echo "$*" >&2; }'
    printf '%s\n' "${rfn}"
    # shellcheck disable=SC2016 # written verbatim into the check script
    echo 'runner_tarball_fetch "$1"'
} > "${C}/fetch.sh"
fetch_check() { # want_sha fails -> sets FRC, FERR, FCALLS
    rm -f "${C}/calls" "${C}/out"
    set +e
    PATH="${C}/bin:${PATH}" RUNNER_TARBALL_RETRY_SLEEP=0 RUNNER_TARBALL_VERSION="${RV}" \
        RUNNER_TARBALL_URL="${RU}" RUNNER_TARBALL_SHA256="$1" FAKE_CURL_FAILS="$2" \
        bash "${C}/fetch.sh" "${C}/out" 2>"${C}/err"
    FRC=$?
    set -e
    FERR="$(cat "${C}/err")"; FCALLS="$(cat "${C}/calls" 2>/dev/null || echo 0)"
}
fetch_check "${C_SHA}" 0
[[ ${FRC} -eq 0 && ${FCALLS} -eq 1 ]] && cmp -s "${C}/body" "${C}/out" \
    && ok "runner fetch: a matching download is kept" || bad "runner fetch, good bytes: rc=${FRC} calls=${FCALLS} ${FERR}"
grep -qF -- "--proto =https" "${C}/args" && grep -qF -- "${RU}" "${C}/args" \
    && ok "runner fetch: https-only, from the pinned URL" || bad "runner fetch args: $(cat "${C}/args")"
fetch_check "${C_SHA}" 2
[[ ${FRC} -eq 0 && ${FCALLS} -eq 3 ]] && cmp -s "${C}/body" "${C}/out" \
    && ok "runner fetch: two failed (truncated) attempts are retried from scratch" \
    || bad "runner fetch, retry: rc=${FRC} calls=${FCALLS} ${FERR}"
fetch_check "${C_SHA}" 3
[[ ${FRC} -eq 3 && ${FCALLS} -eq 3 && ! -e "${C}/out" ]] && grep -qF 'could not download' <<<"${FERR}" \
    && ok "runner fetch: three failed attempts fail the bake, no partial file left" \
    || bad "runner fetch, all failed: rc=${FRC} calls=${FCALLS} ${FERR}"
fetch_check "${RS}" 0
[[ ${FRC} -eq 3 && ${FCALLS} -eq 1 && ! -e "${C}/out" ]] && grep -qF "has sha256 ${C_SHA}, want ${RS}" <<<"${FERR}" \
    && ok "runner fetch: a sha256 mismatch fails the bake, is not retried, leaves no file" \
    || bad "runner fetch, mismatch: rc=${FRC} calls=${FCALLS} ${FERR}"

# Post-install staging and assertion, in the ubuntu-runner host block.
hblock="$(awk '/^if \[\[ "\$\{profile\}" == "ubuntu-runner" \]\]; then$/{on=1} on{print} on && /^fi$/{exit}' "${BAKE}")"
[[ -n "${hblock}" ]] || bad "ubuntu-runner host block not found"
for want in \
    'runner_tarball_fetch "${runner_tarball}" || die' \
    'sudo install -d -m 0755 -o root -g root "${MNT_ROOT}${runner_dest_dir}"' \
    'sudo install -m 0644 -o root -g root "${runner_tarball}" "${MNT_ROOT}${RUNNER_TARBALL_DEST}"' \
    '== "0:0 755" ]]' '== "0:0 644" ]]' \
    '[[ "${runner_got}" == "${RUNNER_TARBALL_SHA256}" ]]'; do
    grep -qF -- "${want}" <<<"${hblock}" && ok "runner staging: ${want}" || bad "runner staging lacks: ${want}"
done
if grep -qE 'tar (-|x)|tar --extract' <<<"${hblock}"; then
    bad "the runner tarball is extracted in the image"
else
    ok "the runner tarball is staged as-is, not extracted"
fi

# ── Docker daemon.json ───────────────────────────────────────────────
n="$(grep -cE '^RUNNER_DOCKER_DAEMON_JSON=' "${BAKE}")"
(( n == 1 )) && ok "RUNNER_DOCKER_DAEMON_JSON pinned once" || bad "RUNNER_DOCKER_DAEMON_JSON assigned ${n} times"
dj_assign="$(awk '/^RUNNER_DOCKER_DAEMON_JSON=/{on=1} on{print} on && /'"'"'$/ && !/=.$/{exit}' "${BAKE}")"
DJ="$(eval "${dj_assign}"; printf '%s\n' "${RUNNER_DOCKER_DAEMON_JSON:-}")"
DJ_WANT='{
  "features": {
    "containerd-snapshotter": false
  },
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "2"
  }
}'
[[ "${DJ}" == "${DJ_WANT}" ]] && ok "daemon.json content is exactly the backend bootstrap's document" \
    || bad "daemon.json content: '${DJ}'"
[[ "$(jq . <<<"${DJ}")" == "${DJ}" ]] && ok "daemon.json is pretty-printed consistently (jq's 2-space form)" \
    || bad "daemon.json is not in jq's pretty-printed form"
jq -e '.features["containerd-snapshotter"] == false and ."log-driver" == "json-file"
       and ."log-opts"["max-size"] == "50m" and ."log-opts"["max-file"] == "2"
       and (has("data-root") | not) and (keys == ["features", "log-driver", "log-opts"])
       and (.features | keys == ["containerd-snapshotter"]) and (."log-opts" | keys == ["max-file", "max-size"])' \
    <<<"${DJ}" >/dev/null && ok "daemon.json: snapshotter false, json-file, 50m/2 as strings, no data-root, nothing else" \
    || bad "daemon.json does not parse to the expected document"
# shellcheck disable=SC2016 # literal source line
grep -qxF "                printf '%s\\n' \"\${RUNNER_DOCKER_DAEMON_JSON}\" | sha256sum | awk '{print \"runner-daemon-json=\"\$1}'" "${BAKE}" \
    && ok "daemon.json content keys the stage-1 cache" || bad "daemon.json is not in the stage-1 cache key"
# shellcheck disable=SC2016 # literal source line
grep -qxF '    RUNNER_DOCKER_DAEMON_JSON="${RUNNER_DOCKER_DAEMON_JSON}" \' "${BAKE}" \
    && ok "daemon.json content is passed into the chroot" || bad "daemon.json content not passed into the chroot"
inblock '^    printf .%s\\n. "\$\{RUNNER_DOCKER_DAEMON_JSON\}" > /etc/docker/daemon\.json$' "chroot writes /etc/docker/daemon.json"
inblock '^    chown root:root /etc/docker/daemon\.json$' "daemon.json root:root"
inblock '^    chmod 0644 /etc/docker/daemon\.json$' "daemon.json 0644"
inblock 'RUNNER_DOCKER_DAEMON_JSON not passed to the chroot' "chroot fails without the daemon.json content"
# Written after the Docker packages are installed (they would not overwrite
# it, but the order is the one asked for), before the daemons are enabled.
order="$(grep -nE 'docker-ce docker-ce-cli containerd.io|> /etc/docker/daemon\.json$|systemctl enable containerd.service' <<<"${block}" | cut -d: -f1 | tr '\n' ' ')"
read -r o1 o2 o3 <<<"${order}"
[[ -n "${o3:-}" ]] && (( o1 < o2 && o2 < o3 )) && ok "daemon.json written after the Docker install" \
    || bad "daemon.json write order: ${order}"
# Post-install gate, run against fixtures (jq expression extracted as-is).
for want in "== \"0:0 644\" ]]" 'daemon.json missing or not root:root 0644' \
            "is not the backend bootstrap's document (snapshotter false, json-file, 50m/2, no data-root) (exit 3)"; do
    grep -qF -- "${want}" <<<"${hblock}" && ok "daemon.json gate: ${want}" || bad "daemon.json gate lacks: ${want}"
done
gate_expr="$(sed -n "s/.*| jq -e '\(.*\)' >\/dev\/null.*/\1/p" <<<"${hblock}")"
[[ -n "${gate_expr}" ]] || bad "daemon.json gate jq expression not found"
gate() { jq -e "${gate_expr}" >/dev/null 2>&1 <<<"$1"; }
gate "${DJ}" && ok "daemon.json gate passes the baked document" || bad "daemon.json gate refuses the baked document"
DJ_COMPACT="$(jq -c . <<<"${DJ}")"
gate "${DJ_COMPACT}" && ok "daemon.json gate passes the document compacted (semantic match)" \
    || bad "daemon.json gate refuses the compacted document"
gate '{"log-opts":{"max-file":"2","max-size":"50m"},"log-driver":"json-file","features":{"containerd-snapshotter":false}}' \
    && ok "daemon.json gate ignores key order" || bad "daemon.json gate depends on key order"
for badj in \
    "$(jq -c '. + {"data-root": "/var/lib/hippius-data/docker"}' <<<"${DJ}")" \
    "$(jq -c 'del(."log-opts")' <<<"${DJ}")" \
    "$(jq -c 'del(."log-driver")' <<<"${DJ}")" \
    "$(jq -c '."log-driver" = "journald"' <<<"${DJ}")" \
    "$(jq -c '."log-opts"["max-file"] = 2' <<<"${DJ}")" \
    "$(jq -c '."log-opts"["max-size"] = "100m"' <<<"${DJ}")" \
    "$(jq -c '."log-opts" += {"compress": "true"}' <<<"${DJ}")" \
    "$(jq -c '.features["containerd-snapshotter"] = true' <<<"${DJ}")" \
    "$(jq -c '.features["containerd-snapshotter"] = "false"' <<<"${DJ}")" \
    "$(jq -c 'del(.features)' <<<"${DJ}")" \
    '{"features":{"containerd-snapshotter":false}}' '{}' '[]' 'not json'; do
    gate "${badj}" && bad "daemon.json gate accepts ${badj}" || ok "daemon.json gate refuses ${badj}"
done

# Baker entrypoint: the profile reaches the bake.
grep -qE '^    ubuntu-runner\)$' "${ENTRY}" && grep -qF 'BAKE_ARGS+=(--profile ubuntu-runner)' "${ENTRY}" \
    && ok "entrypoint passes --profile ubuntu-runner" || bad "entrypoint does not pass the profile"

# ── 3. installer against a throwaway rootfs ──────────────────────────
R="${TMP}/root"
mkdir -p "${R}/etc/systemd/system" "${R}/usr/sbin" "${R}/usr/local"
SUDO="" bash "${INSTALL}" "${R}" >/dev/null
has() { # file pattern description
    if grep -qE -- "$2" "${R}$1"; then ok "$3"; else bad "$3 ($1 lacks /$2/)"; fi
}
u=/etc/systemd/system/hippius-runner-data.service
has "$u" '^RequiresMountsFor=/var/lib/hippius-data$' "data unit waits for the data path"
has "$u" '^AssertPathIsMountPoint=/var/lib/hippius-data$' "data unit fails without the data path"
has "$u" '^Before=containerd.service docker.service$' "data unit runs before the daemons"
has "$u" '^ExecStart=/usr/local/sbin/hippius-runner-data$' "data unit runs the bind script"
for d in docker containerd; do
    has "/etc/systemd/system/${d}.service.d/10-hippius-runner-data.conf" '^Requires=hippius-runner-data.service$' "${d} requires the data path"
    has "/etc/systemd/system/${d}.service.d/10-hippius-runner-data.conf" '^After=hippius-runner-data.service$' "${d} ordered after it"
done
link="${R}/etc/systemd/system/multi-user.target.wants/hippius-runner-data.service"
[[ -L "${link}" && "$(readlink "${link}")" == ../hippius-runner-data.service ]] \
    && ok "data unit enabled" || bad "data unit not enabled"
[[ "$(stat -c %a "${R}/usr/local/sbin/hippius-runner-data")" == 755 ]] && ok "bind script 0755" || bad "bind script mode"
sh -n "${R}/usr/local/sbin/hippius-runner-data" && ok "bind script parses" || bad "bind script syntax"
set +e
SUDO="" bash "${INSTALL}" "${TMP}/absent" 2>/dev/null; rc=$?
set -e
(( rc == 3 )) && ok "installer refuses a non-rootfs" || bad "installer accepted a non-rootfs (rc=${rc})"

# Run the bind script on a fake tree: mountpoint/mount shimmed, paths moved.
F="${TMP}/fake"; mkdir -p "${F}/bin" "${F}/var/lib/hippius-data"
cat > "${F}/bin/mountpoint" <<SHIM
#!/bin/sh
# mounted: the data path, and anything already bound (recorded by the mount shim)
[ "\$2" = "${F}/var/lib/hippius-data" ] && exit 0
grep -qxF "\$2" "${F}/mounted" 2>/dev/null
SHIM
cat > "${F}/bin/mount" <<SHIM
#!/bin/sh
[ "\$1" = --bind ] || exit 9
echo "\$2 \$3" >> "${F}/binds"
echo "\$3" >> "${F}/mounted"
SHIM
chmod 0755 "${F}/bin/mountpoint" "${F}/bin/mount"
sed "s#/var/lib/#${F}/var/lib/#g" "${R}/usr/local/sbin/hippius-runner-data" > "${F}/bind.sh"
run_bind() { set +e; PATH="${F}/bin:${PATH}" sh "${F}/bind.sh" >/dev/null 2>"${TMP}/berr"; RC=$?; set -e; }
run_bind
want="${F}/var/lib/hippius-data/docker ${F}/var/lib/docker
${F}/var/lib/hippius-data/containerd ${F}/var/lib/containerd"
[[ ${RC} -eq 0 && "$(cat "${F}/binds")" == "${want}" ]] \
    && ok "binds docker and containerd state onto the data path" || bad "binds: rc=${RC} $(cat "${F}/binds" 2>/dev/null) $(cat "${TMP}/berr")"
[[ -d "${F}/var/lib/hippius-data/docker" && -d "${F}/var/lib/containerd" ]] \
    && ok "creates the source and target directories" || bad "directories not created"
run_bind
[[ ${RC} -eq 0 && "$(wc -l < "${F}/binds")" -eq 2 ]] && ok "a second run binds nothing twice" || bad "re-run rebound (rc=${RC})"
# A symlinked source is refused.
: > "${F}/binds"; : > "${F}/mounted"
rmdir "${F}/var/lib/hippius-data/docker"; ln -s /etc "${F}/var/lib/hippius-data/docker"
run_bind
[[ ${RC} -ne 0 && ! -s "${F}/binds" ]] && grep -qF 'is not a plain directory' "${TMP}/berr" \
    && ok "refuses a symlinked source" || bad "symlinked source: rc=${RC} $(cat "${F}/binds")"
rm "${F}/var/lib/hippius-data/docker"
# No data path mounted: refuses, binds nothing.
sed "s#\"${F}/var/lib/hippius-data\" ] && exit 0#\"/nowhere\" ] \&\& exit 0#" "${F}/bin/mountpoint" > "${F}/mp"
cp "${F}/mp" "${F}/bin/mountpoint"
run_bind
[[ ${RC} -ne 0 && ! -s "${F}/binds" ]] && grep -qF 'is not a mount point' "${TMP}/berr" \
    && ok "refuses when the data path is not mounted" || bad "no data path: rc=${RC} $(cat "${F}/binds")"

if (( fail )); then
    echo "ubuntu-runner-profile-test: FAILED" >&2
    exit 1
fi
echo "ubuntu-runner-profile-test: all checks passed"
