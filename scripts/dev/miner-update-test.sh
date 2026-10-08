#!/usr/bin/env bash
# Hermetic tests for the miner-agent auto-updater
# (deploy/ansible/playbooks/miner-tasks/files/hippius-miner-update.sh).
#
# The GitHub API, the downloads, cosign, systemd, journald and virsh are
# PATH mocks; everything else (python3, sha256sum, install, flock) is real.
# The systemctl mock FAILS the run on `stop`/`restart` and friends: a
# graceful stop of the agent destroys every domain on a miner, so the
# updater must only ever SIGKILL it.
#
#   bash scripts/dev/miner-update-test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UPDATER="$ROOT/deploy/ansible/playbooks/miner-tasks/files/hippius-miner-update.sh"
UNIT_DIR="$ROOT/deploy/ansible/playbooks/miner-tasks/templates"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

PASS=0
FAIL=0
SB=""
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; if [ -n "$SB" ] && [ -f "$SB/out" ]; then sed 's/^/     | /' "$SB/out"; fi; }
check() { local name="$1"; shift; if "$@"; then ok "$name"; else ko "$name"; fi; }

iso_hours_ago() { date -u -d "@$(( $(date +%s) - $1 * 3600 ))" +%Y-%m-%dT%H:%M:%SZ; }

# A fake agent: prints the --version line of a given release tag.
fake_agent() {
    printf '#!/bin/sh\necho "hippius-miner-agent 0.0.1 (%s)"\n' "$2" >"$1"
    chmod 0755 "$1"
}

# setup <installed tag> <latest tag> <published hours ago>
setup() {
    SB="$(mktemp -d "$WORK/case.XXXXXX")"
    mkdir -p "$SB/bin" "$SB/state" "$SB/remote" "$SB/sysd" "$SB/cgroup/system.slice/hippius-miner-agent.service"
    : >"$SB/cgroup/system.slice/hippius-miner-agent.service/cgroup.procs"
    fake_agent "$SB/hippius-miner-agent" "$1"
    printf '[host]\ncvm_cpu_budget = 8\nskip_shutdown_teardown = true\n\n[heartbeat]\ninterval_secs = 60\n' >"$SB/config.toml"
    echo 4242 >"$SB/sysd/pid"
    echo active >"$SB/sysd/state"
    echo on-failure >"$SB/sysd/restart"
    : >"$SB/calls"
    printf 'aaaa-1\nbbbb-2\n' >"$SB/domains"

    fake_agent "$SB/remote/hippius-miner-agent-x86_64-linux-gnu" "$2"
    (cd "$SB/remote" && sha256sum hippius-miner-agent-x86_64-linux-gnu >SHA256SUMS)
    echo '{"fake":"bundle"}' >"$SB/remote/hippius-miner-agent-x86_64-linux-gnu.sigstore.json"
    write_release "$2" "$(iso_hours_ago "$3")"

    cat >"$SB/env" <<EOF
MINER_BINARY=$SB/hippius-miner-agent
MINER_STATE_DIR=$SB/state
MINER_CONFIG=$SB/config.toml
COSIGN_BIN=$SB/bin/cosign
CGROUP_ROOT=$SB/cgroup
RELEASES_API=https://api.github.test/releases/latest
HEALTH_TIMEOUT_S=3
RELAUNCH_TIMEOUT_S=3
POLL_INTERVAL_S=0
EOF
    write_mocks
}

# release_json <tag> <published_at> [<assets updated_at>] — one release
# object, as the GitHub API returns it.
release_json() {
    local base="https://github.test/dl/$1" up="${3:-$2}"
    cat <<EOF
{"tag_name": "$1", "published_at": "$2", "draft": false, "prerelease": false,
 "assets": [
  {"name": "hippius-miner-agent-x86_64-linux-gnu", "updated_at": "$up", "browser_download_url": "$base/hippius-miner-agent-x86_64-linux-gnu"},
  {"name": "SHA256SUMS", "updated_at": "$up", "browser_download_url": "$base/SHA256SUMS"},
  {"name": "hippius-miner-agent-x86_64-linux-gnu.sigstore.json", "updated_at": "$up", "browser_download_url": "$base/hippius-miner-agent-x86_64-linux-gnu.sigstore.json"},
  {"name": "BUILD-INFO.txt", "updated_at": "$up", "browser_download_url": "$base/BUILD-INFO.txt"}
 ]}
EOF
}

write_release() { release_json "$@" >"$SB/remote/latest"; }

write_mocks() {
    # curl: serve $SB/remote/<basename of the URL> to -o.
    cat >"$SB/bin/curl" <<EOF
#!/usr/bin/env bash
out=""; url=""
while [ \$# -gt 0 ]; do
  case "\$1" in -o) out="\$2"; shift 2 ;; -H|--proto|--proto-redir|--retry|--connect-timeout|--max-time) shift 2 ;; -*) shift ;; *) url="\$1"; shift ;; esac
done
echo "curl \$url" >>"$SB/calls"
src="$SB/remote/\${url##*/}"
[ -f "\$src" ] || exit 22
cp "\$src" "\$out"
EOF
    # systemctl: a tiny state machine. stop/restart = test failure.
    cat >"$SB/bin/systemctl" <<EOF
#!/usr/bin/env bash
echo "systemctl \$*" >>"$SB/calls"
case "\$1" in
  stop|restart|try-restart|reload-or-restart|try-reload-or-restart|condrestart|force-reload|isolate|disable|mask)
    echo "systemctl \$*" >>"$SB/forbidden"; exit 97 ;;
  show)
    case "\$3" in
      MainPID) cat "$SB/sysd/pid" ;;
      ActiveState) cat "$SB/sysd/state" ;;
      Restart) cat "$SB/sysd/restart" ;;
      ControlGroup) echo /system.slice/hippius-miner-agent.service ;;
    esac ;;
  kill)
    [ "\$2" = "--signal=SIGKILL" ] || { echo "systemctl \$*" >>"$SB/forbidden"; exit 97; }
    sha256sum "$SB/hippius-miner-agent" | cut -d' ' -f1 >>"$SB/kills"
    if [ -f "$SB/no-relaunch" ]; then echo 0 >"$SB/sysd/pid"; echo activating >"$SB/sysd/state"; rm -f "$SB/no-relaunch"
    else echo \$(( \$(cat "$SB/sysd/pid") + 1 )) >"$SB/sysd/pid"; echo active >"$SB/sysd/state"; fi ;;
  start)
    echo \$(( \$(cat "$SB/sysd/pid") + 100 )) >"$SB/sysd/pid"; echo active >"$SB/sysd/state" ;;
  reset-failed) ;;
  *) echo "systemctl \$*" >>"$SB/forbidden"; exit 97 ;;
esac
EOF
    # journalctl: the running binary "delivers" unless its tag is in bad-tag.
    cat >"$SB/bin/journalctl" <<EOF
#!/usr/bin/env bash
echo "journalctl \$*" >>"$SB/calls"
if [ -f "$SB/bad-tag" ] && "$SB/hippius-miner-agent" --version | grep -qF "(\$(cat "$SB/bad-tag"))"; then exit 0; fi
echo "hippius-miner-agent: heartbeat-pusher: kind=heartbeat body_hash=00 outcome=delivered"
EOF
    cat >"$SB/bin/cosign" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$@" >"$SB/cosign-args"
[ -f "$SB/cosign-fail" ] && { echo "error: no matching CertificateIdentity found" >&2; exit 1; }
echo "Verified OK"
EOF
    cat >"$SB/bin/virsh" <<EOF
#!/usr/bin/env bash
cat "$SB/domains"
EOF
    printf '#!/bin/sh\ncat >>"%s/journal"\n' "$SB" >"$SB/bin/systemd-cat"
    printf '#!/bin/sh\nexit 0\n' >"$SB/bin/sleep"
    chmod 0755 "$SB/bin/"*
}

run_update() {
    set +e
    env -i PATH="$SB/bin:/usr/bin:/bin" HIPPIUS_MINER_UPDATE_ENV="$SB/env" "$@" bash "$UPDATER" >"$SB/out" 2>&1
    RC=$?
    set -e
    cat "$SB/journal" >>"$SB/out" 2>/dev/null || true
}

journal_has() { grep -qF -- "$1" "$SB/journal"; }
installed_tag_is() { "$SB/hippius-miner-agent" --version | grep -qF "($1)"; }
kills() { [ -f "$SB/kills" ] && wc -l <"$SB/kills" | tr -d ' ' || echo 0; }
no_forbidden() { [ ! -e "$SB/forbidden" ]; }
downloaded_binary() { grep -q 'curl .*/hippius-miner-agent-x86_64-linux-gnu$' "$SB/calls"; }

# ── Static: the updater never stops or restarts the agent ────────────────────
static_no_stop_restart() {
    # Executable lines only (comments stripped).
    ! sed 's/^[[:space:]]*#.*//' "$UPDATER" "$UNIT_DIR/hippius-miner-update.service.j2" \
        | grep -nE '(^|[^[:alnum:]_-])systemctl([^#]*[^[:alnum:]_-])?(stop|restart|try-restart|reload-or-restart|isolate)([^[:alnum:]_-]|$)'
}
check "static: no systemctl stop/restart anywhere in the updater or its unit" static_no_stop_restart
static_only_sigkill() {
    [ "$(sed 's/^[[:space:]]*#.*//' "$UPDATER" | grep -c 'systemctl kill')" = 1 ] &&
        grep -qF 'systemctl kill --signal=SIGKILL "$SERVICE_NAME"' "$UPDATER"
}
check "static: the only signal is systemctl kill --signal=SIGKILL" static_only_sigkill

# ── Tag ordering ─────────────────────────────────────────────────────────────
tag_order() {
    # shellcheck source=/dev/null
    ( . "$UPDATER"
      [ "$(tag_cmp v2026.10.08 v2026.10.08)" = 0 ] &&
      [ "$(tag_cmp v2026.10.08 v2026.10.09)" = -1 ] &&
      [ "$(tag_cmp v2026.10.08.1 v2026.10.08)" = 1 ] &&
      [ "$(tag_cmp v2026.10.08.2 v2026.10.08.10)" = -1 ] &&
      [ "$(tag_cmp v2026.09.30 v2026.10.01)" = -1 ] &&
      [ "$(tag_cmp v2027.01.01 v2026.12.31.999)" = 1 ] &&
      [ "$(tag_cmp v2026.08.09 v2026.08.08)" = 1 ] &&
      valid_tag v2026.10.08 && valid_tag v2026.10.08.1 &&
      ! valid_tag v2026.10.8 && ! valid_tag 2026.10.08 && ! valid_tag v2026.10.08.0 &&
      ! valid_tag v2026.10.08-rc1 && ! valid_tag 'v2026.10.08;id' && ! valid_tag dev && ! valid_tag "" )
}
check "tags: vYYYY.MM.DD[.N] order numerically, anything else is invalid" tag_order

# ── Behaviour ────────────────────────────────────────────────────────────────
setup v2025.01.09 v2025.01.09 48; echo v2025.01.09 >"$SB/state/installed-release"; run_update
check "no update: same tag => exit 0, nothing downloaded, agent untouched" \
    bash -c "[ $RC = 0 ] && grep -qF 'up to date (v2025.01.09)' '$SB/journal'"
check "no update: no binary download, no kill" bash -c "! grep -q 'curl .*/hippius-miner-agent-x86_64-linux-gnu$' '$SB/calls' && [ ! -e '$SB/kills' ]"

setup v2025.01.08 v2025.01.09 48; run_update
check "newer: exit 0" test "$RC" = 0
check "newer: new binary installed" installed_tag_is v2025.01.09
check "newer: installed-release records the tag" test "$(cat "$SB/state/installed-release" 2>/dev/null)" = v2025.01.09
check "newer: exactly one SIGKILL, with the NEW binary already in place" \
    bash -c "[ \$(wc -l <'$SB/kills') = 1 ] && [ \"\$(cat '$SB/kills')\" = \"\$(sha256sum '$SB/remote/hippius-miner-agent-x86_64-linux-gnu' | cut -d' ' -f1)\" ]"
check "newer: previous binary kept as .bak" bash -c "'$SB/hippius-miner-agent.bak' --version | grep -qF '(v2025.01.08)'"
check "newer: never stop/restart" no_forbidden
check "newer: cosign pinned to the hippius-cvm release workflow at that tag" bash -c "
    a='$SB/cosign-args'
    grep -qx 'verify-blob-attestation' \$a &&
    grep -qx 'https://github.com/thenervelab/hippius-cvm/.github/workflows/miner-agent-release.yml@refs/tags/v2025.01.09' \$a &&
    grep -qx 'https://token.actions.githubusercontent.com' \$a &&
    grep -qx 'thenervelab/hippius-cvm' \$a && grep -qx 'refs/tags/v2025.01.09' \$a &&
    grep -qx 'https://slsa.dev/provenance/v1' \$a && grep -qx 'push' \$a &&
    ! grep -q 'regexp' \$a && ! grep -q 'hippius-compute' \$a"
check "newer: health read from the relaunched PID only" grep -q 'journalctl .*_PID=4243' "$SB/calls"

setup "" v2025.01.09 48; fake_agent "$SB/hippius-miner-agent" dev; run_update
check "unknown installed release (dev build): latest counts as an upgrade" \
    bash -c "[ $RC = 0 ] && '$SB/hippius-miner-agent' --version | grep -qF '(v2025.01.09)'"

setup v2025.01.08 v2025.01.09 2; run_update
check "too recent: exit 0, waiting, nothing downloaded or killed" \
    bash -c "[ $RC = 0 ] && grep -q 'MIN_RELEASE_AGE_H=24' '$SB/journal' && ! grep -q 'curl .*/hippius-miner-agent-x86_64-linux-gnu$' '$SB/calls' && [ ! -e '$SB/kills' ]"
check "too recent: binary untouched" installed_tag_is v2025.01.08

setup v2025.01.08 v2025.01.09 2; echo MIN_RELEASE_AGE_H=0 >>"$SB/env"; run_update
check "too recent + MIN_RELEASE_AGE_H=0 (canary): updates" bash -c "[ $RC = 0 ] && '$SB/hippius-miner-agent' --version | grep -qF '(v2025.01.09)'"

setup v2025.01.08 v2025.01.09 -3; echo MIN_RELEASE_AGE_H=0 >>"$SB/env"; run_update
check "published_at in the future is never old enough" bash -c "[ $RC = 0 ] && [ ! -e '$SB/kills' ]"

setup v2025.01.09 v2025.01.08 48; run_update
check "downgrade refused (binary tag newer): exit 0, warning, nothing downloaded" \
    bash -c "[ $RC = 0 ] && grep -q 'downgrade refused' '$SB/journal' && ! grep -q 'curl .*/hippius-miner-agent-x86_64-linux-gnu$' '$SB/calls' && [ ! -e '$SB/kills' ]"

setup dev v2025.01.08 48; echo v2025.01.09 >"$SB/state/installed-release"; run_update
check "downgrade refused (recorded tag newer, binary says dev)" bash -c "[ $RC = 0 ] && grep -q 'downgrade refused' '$SB/journal' && [ ! -e '$SB/kills' ]"

setup v2025.01.09.1 v2025.01.09 48; echo v2025.01.08 >"$SB/state/installed-release"; run_update
check "downgrade refused (binary tag newer than a stale recorded tag)" bash -c "[ $RC = 0 ] && grep -q 'downgrade refused' '$SB/journal'"

setup v2025.01.08 v2025.01.09 48; echo "0000000000000000000000000000000000000000000000000000000000000000  hippius-miner-agent-x86_64-linux-gnu" >"$SB/remote/SHA256SUMS"; run_update
check "bad sha: exit 1, refused before cosign, agent untouched" \
    bash -c "[ $RC = 1 ] && grep -q 'sha256 mismatch' '$SB/journal' && [ ! -e '$SB/cosign-args' ] && [ ! -e '$SB/kills' ]"
check "bad sha: binary untouched" installed_tag_is v2025.01.08

setup v2025.01.08 v2025.01.09 48; (cd "$SB/remote" && sha256sum hippius-miner-agent-x86_64-linux-gnu >>SHA256SUMS); run_update
check "SHA256SUMS listing the asset twice is refused" bash -c "[ $RC = 1 ] && grep -q 'exactly once' '$SB/journal' && [ ! -e '$SB/kills' ]"

setup v2025.01.08 v2025.01.09 48; touch "$SB/cosign-fail"; run_update
check "attestation refused: exit 1, agent untouched" \
    bash -c "[ $RC = 1 ] && grep -q 'attestation of v2025.01.09 does not verify' '$SB/journal' && [ ! -e '$SB/kills' ]"
check "attestation refused: binary untouched" installed_tag_is v2025.01.08

setup v2025.01.08 v2025.01.09 48; sed -i '/sigstore.json"}/d' "$SB/remote/latest"; run_update
check "missing attestation bundle: release passed over, nothing installed" bash -c "[ $RC = 0 ] && grep -q 'is incomplete' '$SB/journal' && [ ! -e '$SB/cosign-args' ] && [ ! -e '$SB/kills' ]"

setup v2025.01.08 v2025.01.09 48; rm "$SB/remote/hippius-miner-agent-x86_64-linux-gnu.sigstore.json"; run_update
check "attestation bundle listed but not downloadable: refused" bash -c "[ $RC = 1 ] && [ ! -e '$SB/cosign-args' ] && [ ! -e '$SB/kills' ]"

setup v2025.01.08 v2025.01.09 48; echo RELEASE_REPO=thenervelab/hippius-compute >>"$SB/env"; run_update
check "old repository name thenervelab/hippius-compute refused outright" \
    bash -c "[ $RC = 1 ] && ! grep -q curl '$SB/calls' && [ ! -e '$SB/kills' ]"

setup v2025.01.08 v2025.01.09 48; echo RELEASE_REPO=TheNerveLab/Hippius-Compute >>"$SB/env"; run_update
check "old repository name refused case-insensitively" test "$RC" = 1

setup v2025.01.08 v2025.01.09 48; rm "$SB/bin/cosign"; run_update
check "no cosign: refuse to update at all" bash -c "[ $RC = 1 ] && ! grep -q curl '$SB/calls'"

setup v2025.01.08 v2025.01.09 48
fake_agent "$SB/remote/hippius-miner-agent-x86_64-linux-gnu" v2025.01.10
(cd "$SB/remote" && sha256sum hippius-miner-agent-x86_64-linux-gnu >SHA256SUMS); run_update
check "wrong version: binary reports another tag => exit 1, untouched" \
    bash -c "[ $RC = 1 ] && grep -q \"reports release 'v2025.01.10', expected 'v2025.01.09'\" '$SB/journal' && [ ! -e '$SB/kills' ]"
check "wrong version: binary untouched" installed_tag_is v2025.01.08

setup v2025.01.08 v2025.01.09 48; sed -i '/skip_shutdown_teardown/d' "$SB/config.toml"; run_update
check "skip_shutdown_teardown missing: refused with an ERROR, agent untouched" \
    bash -c "[ $RC = 1 ] && grep -q 'ERROR: refusing to swap: \[host\] skip_shutdown_teardown = true' '$SB/journal' && [ ! -e '$SB/kills' ]"
check "skip_shutdown_teardown missing: binary untouched" installed_tag_is v2025.01.08

setup v2025.01.08 v2025.01.09 48; sed -i 's/skip_shutdown_teardown = true/skip_shutdown_teardown = false/' "$SB/config.toml"; run_update
check "skip_shutdown_teardown = false: refused" bash -c "[ $RC = 1 ] && [ ! -e '$SB/kills' ]"

setup v2025.01.08 v2025.01.09 48; printf '[heartbeat]\nskip_shutdown_teardown = true\n[host]\ncvm_cpu_budget = 8\n' >"$SB/config.toml"; run_update
check "skip_shutdown_teardown outside [host]: refused" bash -c "[ $RC = 1 ] && [ ! -e '$SB/kills' ]"

setup v2025.01.08 v2025.01.09 48; echo no >"$SB/sysd/restart"; run_update
check "Restart=no: refused (systemd would not relaunch)" bash -c "[ $RC = 1 ] && [ ! -e '$SB/kills' ] && grep -q 'Restart=no' '$SB/journal'"

setup v2025.01.08 v2025.01.09 48; echo inactive >"$SB/sysd/state"; echo 0 >"$SB/sysd/pid"; run_update
check "agent stopped by an operator: refused, not started" bash -c "[ $RC = 1 ] && [ ! -e '$SB/kills' ] && ! grep -q 'systemctl start' '$SB/calls'"

setup v2025.01.08 v2025.01.09 48
cp /bin/sleep "$SB/qemu-system-x86_64"; "$SB/qemu-system-x86_64" 30 & QPID=$!
echo "$QPID" >"$SB/cgroup/system.slice/hippius-miner-agent.service/cgroup.procs"; run_update; kill "$QPID" 2>/dev/null || true
check "QEMU inside the agent's cgroup: refused" bash -c "[ $RC = 1 ] && grep -q 'QEMU pid' '$SB/journal' && [ ! -e '$SB/kills' ]"

setup v2025.01.08 v2025.01.09 48; echo v2025.01.09 >"$SB/bad-tag"; run_update
check "health KO: exit 1" test "$RC" = 1
check "health KO: rolled back to the previous binary" installed_tag_is v2025.01.08
check "health KO: .update-failed-v2025.01.09 marker left" test -f "$SB/state/.update-failed-v2025.01.09"
check "health KO: installed-release not advanced" test ! -e "$SB/state/installed-release"
check "health KO: rollback is a second SIGKILL swap, never stop/restart" \
    bash -c "[ \$(wc -l <'$SB/kills') = 2 ] && [ \"\$(sed -n 2p '$SB/kills')\" = \"\$(sha256sum '$SB/hippius-miner-agent' | cut -d' ' -f1)\" ] && [ ! -e '$SB/forbidden' ]"
check "health KO: rollback health confirmed" grep -q 'rolled back: hippius-miner-agent healthy again' "$SB/journal"
run_update
check "health KO: the failed tag is not retried on the next run" \
    bash -c "[ $RC = 0 ] && grep -q 'failed its health check here before' '$SB/journal' && [ \$(wc -l <'$SB/kills') = 2 ]"

setup v2025.01.08 v2025.01.09 48; touch "$SB/no-relaunch"; run_update
check "no relaunch after SIGKILL (start limit): started by hand, then health decides" \
    bash -c "[ $RC = 0 ] && '$SB/hippius-miner-agent' --version | grep -qF '(v2025.01.09)' && grep -q 'systemctl start hippius-miner-agent' '$SB/calls' && [ ! -e '$SB/forbidden' ]"

setup v2025.01.08 v2025.01.09 48; touch "$SB/no-relaunch"; echo v2025.01.09 >"$SB/bad-tag"; run_update
check "no relaunch + unhealthy: rolled back by SIGKILL, previous binary healthy, marker" \
    bash -c "[ $RC = 1 ] && '$SB/hippius-miner-agent' --version | grep -qF '(v2025.01.08)' && [ -f '$SB/state/.update-failed-v2025.01.09' ] && [ ! -e '$SB/forbidden' ] && grep -q 'rolled back: hippius-miner-agent healthy again' '$SB/journal'"

# An earlier run was killed mid-swap (unit timeout, power loss): the new
# binary is on disk, the previous one in .bak, the in-progress file says so.
setup v2025.01.09 v2025.01.09 48; fake_agent "$SB/hippius-miner-agent.bak" v2025.01.08; echo v2025.01.09 >"$SB/state/update-in-progress"; run_update
check "interrupted swap: next run restores .bak first, marks the tag, clears the in-progress file" \
    bash -c "[ $RC = 1 ] && '$SB/hippius-miner-agent' --version | grep -qF '(v2025.01.08)' && [ -f '$SB/state/.update-failed-v2025.01.09' ] && [ ! -e '$SB/state/update-in-progress' ] && ! grep -q 'curl .*/hippius-miner-agent-x86_64-linux-gnu$' '$SB/calls' && [ ! -e '$SB/forbidden' ]"
run_update
check "interrupted swap: the run after that is clean (marker holds, nothing retried)" \
    bash -c "[ $RC = 0 ] && grep -q 'failed its health check here before' '$SB/journal' && [ \$(wc -l <'$SB/kills') = 1 ]"

setup v2025.01.08 v2025.01.09 48; echo inactive >"$SB/sysd/state"; echo 0 >"$SB/sysd/pid"
fake_agent "$SB/hippius-miner-agent.bak" v2025.01.07; echo v2025.01.09 >"$SB/state/update-in-progress"; run_update
check "interrupted swap with the agent down: rollback STARTS it (no kill), never stop/restart" \
    bash -c "[ $RC = 1 ] && '$SB/hippius-miner-agent' --version | grep -qF '(v2025.01.07)' && [ ! -e '$SB/kills' ] && grep -q 'systemctl start hippius-miner-agent' '$SB/calls' && [ ! -e '$SB/forbidden' ]"

setup v2025.01.08 v2025.01.09 48; printf '#!/bin/sh\nexit 1\n' >"$SB/bin/virsh"; run_update
check "virsh cannot list domains: refused before the swap" bash -c "[ $RC = 1 ] && grep -q 'cannot list the running domains' '$SB/journal' && [ ! -e '$SB/kills' ]"

setup v2025.01.08 v2025.01.09 48
mkdir -p "$SB/cgroup/system.slice/hippius-miner-agent.service/nested"
cp /bin/sleep "$SB/qemu-system-x86_64"; "$SB/qemu-system-x86_64" 30 & QPID=$!
echo "$QPID" >"$SB/cgroup/system.slice/hippius-miner-agent.service/nested/cgroup.procs"; run_update; kill "$QPID" 2>/dev/null || true
check "QEMU in a NESTED cgroup of the agent: refused" bash -c "[ $RC = 1 ] && grep -q 'QEMU pid' '$SB/journal' && [ ! -e '$SB/kills' ]"

setup v2025.01.08 v2025.01.09 48; touch "$SB/state/.no-auto-update"; run_update
check "opt-out file: exit 0, no network" bash -c "[ $RC = 0 ] && ! grep -q curl '$SB/calls'"

setup v2025.01.08 v2025.01.09 48; echo AUTO_UPDATE_DISABLED=true >>"$SB/env"; run_update
check "AUTO_UPDATE_DISABLED=true: exit 0, no network" bash -c "[ $RC = 0 ] && ! grep -q curl '$SB/calls'"

setup v2025.01.08 v2025.01.09 48; write_release v2025.01.09-rc1 "$(iso_hours_ago 48)"; run_update
check "non-conforming tag ignored" bash -c "[ $RC = 0 ] && grep -q 'no complete release' '$SB/journal' && [ ! -e '$SB/kills' ]"

setup v2025.01.08 v2025.01.09 48; sed -i 's/"draft": false/"draft": true/' "$SB/remote/latest"; run_update
check "draft release ignored" bash -c "[ $RC = 0 ] && [ ! -e '$SB/kills' ]"

setup v2025.01.08 v2025.01.09 48; printf 'aaaa-1\n' >"$SB/domains.after"
sed -i "s|cat \"$SB/domains\"|if [ -f \"$SB/kills\" ]; then cat \"$SB/domains.after\"; else cat \"$SB/domains\"; fi|" "$SB/bin/virsh"; run_update
check "a domain lost across the swap: ERROR, rolled back, marker" \
    bash -c "grep -q 'ERROR: domain(s) running before the swap are no longer running: bbbb-2' '$SB/journal' && [ $RC = 1 ] && '$SB/hippius-miner-agent' --version | grep -qF '(v2025.01.08)' && [ -f '$SB/state/.update-failed-v2025.01.09' ]"

# The release list (the default endpoint): pick the highest complete one.
release_list() { printf '[%s]\n' "$(IFS=,; echo "$*")" >"$SB/remote/latest"; }
incomplete_json() {
    printf '{"tag_name": "%s", "published_at": "%s", "draft": false, "prerelease": false, "assets": [{"name": "SBOM.cdx.json", "updated_at": "%s", "browser_download_url": "https://github.test/dl/x/SBOM.cdx.json"}]}' "$1" "$2" "$2"
}

setup v2025.01.08 v2025.01.09 48
release_list "$(incomplete_json v2025.01.10 "$(iso_hours_ago 30)")" "$(release_json v2025.01.09 "$(iso_hours_ago 48)")" "$(release_json v2025.01.07 "$(iso_hours_ago 90)")"
run_update
check "list: a newer release without the binary is passed over, the highest complete one installed" \
    bash -c "[ $RC = 0 ] && '$SB/hippius-miner-agent' --version | grep -qF '(v2025.01.09)' && grep -q 'release v2025.01.10 is incomplete' '$SB/journal'"

setup v2025.01.09 v2025.01.09 48
release_list "$(incomplete_json v2025.01.10 "$(iso_hours_ago 30)")" "$(release_json v2025.01.09 "$(iso_hours_ago 48)")"
run_update
check "list: only an incomplete newer release => up to date, no failure" \
    bash -c "[ $RC = 0 ] && grep -q 'up to date (v2025.01.09)' '$SB/journal' && [ ! -e '$SB/kills' ]"

setup v2025.01.08 v2025.01.09 48
release_list "$(release_json v2099.01.01 "$(iso_hours_ago 48)")" "$(release_json v2025.01.09 "$(iso_hours_ago 48)")"
run_update
check "list: a tag dated after its publication (v2099) is passed over" \
    bash -c "[ $RC = 0 ] && grep -q 'v2099.01.01 is dated after its publication' '$SB/journal' && '$SB/hippius-miner-agent' --version | grep -qF '(v2025.01.09)'"

setup v2025.01.08 v2025.01.09 48
release_list "$(release_json v2025.13.01 "$(iso_hours_ago 48)")" "$(release_json v2025.01.09 "$(iso_hours_ago 48)")"
run_update
check "list: an impossible date (month 13) is passed over, not fatal" \
    bash -c "[ $RC = 0 ] && '$SB/hippius-miner-agent' --version | grep -qF '(v2025.01.09)'"

setup v2025.01.08 v2025.01.09 48; write_release v2025.01.09 "$(iso_hours_ago 48)" "$(iso_hours_ago 3)"
run_update
check "soak counts from the last asset upload, not the release creation" \
    bash -c "[ $RC = 0 ] && grep -q 'complete for 3h' '$SB/journal' && [ ! -e '$SB/kills' ]"

setup v2025.01.08 v2025.01.09 48; echo v2025.01.09 >"$SB/bad-tag"; chmod 0555 "$SB/state"; run_update; chmod 0755 "$SB/state"
check "health KO with an unwritable state dir: still rolls back" \
    bash -c "[ $RC = 1 ] && '$SB/hippius-miner-agent' --version | grep -qF '(v2025.01.08)'"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
