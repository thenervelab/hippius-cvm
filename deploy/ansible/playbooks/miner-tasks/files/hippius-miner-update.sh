#!/usr/bin/env bash
# =============================================================================
# hippius-miner-update — auto-update hippius-miner-agent from GitHub Releases
#
# Modelled on arion's `arion-miner-update.sh`, with three differences that
# matter on a host carrying tenant CVMs:
#
#   - The agent is NEVER stopped or restarted. A graceful stop of
#     hippius-miner-agent destroys every domain on the host unless the
#     running process started with `skip_shutdown_teardown = true`. The swap
#     is: atomic install, then `systemctl kill --signal=SIGKILL`, and
#     `Restart=` brings the agent back to re-adopt the running CVMs. QEMU
#     runs in machine.slice, outside the agent's cgroup.
#   - Every release is verified before it runs: sha256 against SHA256SUMS,
#     the GitHub build-provenance attestation (cosign, pinned to the release
#     workflow of thenervelab/hippius-cvm at that exact tag), then the
#     binary's own `--version` must name the tag.
#   - The fleet does not move at once: a release younger than
#     MIN_RELEASE_AGE_H hours is ignored, the timer adds a large random
#     delay, a tag that failed its health check is never retried, and an
#     older tag is never installed over a newer one.
#
# Flow (one run, fired by hippius-miner-update.timer):
#   1. opt-outs: /var/lib/hippius-miner/.no-auto-update, AUTO_UPDATE_DISABLED
#   2. GET ${RELEASES_API} (default: the last 20 hippius-cvm releases) and
#      pick the highest tag among complete releases (binary, SHA256SUMS and
#      attestation all attached; not a draft or prerelease)
#   3. tag newer than the installed one? (/var/lib/hippius-miner/installed-
#      release, or the tag the running binary was built as)
#   4. no .update-failed-<tag> marker, and the last of its three files was
#      uploaded at least MIN_RELEASE_AGE_H hours ago
#   5. download binary + SHA256SUMS + <binary>.sigstore.json
#   6. sha256 -> cosign verify-blob-attestation -> `--version` == tag
#   7. preflight: skip_shutdown_teardown = true, Restart= set, agent active,
#      no QEMU process in the agent's cgroup
#   8. backup to .bak, atomic install, SIGKILL, wait for the relaunch
#   9. health: the relaunched process stays up AND logs
#      `heartbeat-pusher: ... outcome=delivered` within HEALTH_TIMEOUT_S
#  10. unhealthy -> same SIGKILL swap back to .bak, .update-failed-<tag>
#      marker, exit 1. Healthy -> record the tag in installed-release.
#
# Release tags are `vYYYY.MM.DD` or `vYYYY.MM.DD.N` (N = 1..999, a second
# release the same day). They compare as the integer tuple
# (YYYY, MM, DD, N), with N = 0 when absent: v2026.10.08 < v2026.10.08.1
# < v2026.10.09. Anything else is refused.
#
# Installed by deploy/ansible/playbooks/miner-tasks/miner-agent-install.yml
# (tag `miner_auto_update`), configured by /etc/hippius-miner/auto-update.env.
# See miner-tasks/AUTO_UPDATE.md.
# =============================================================================
set -euo pipefail

ENV_FILE="${HIPPIUS_MINER_UPDATE_ENV:-/etc/hippius-miner/auto-update.env}"
# shellcheck source=/dev/null
[ -f "$ENV_FILE" ] && . "$ENV_FILE"

BINARY_PATH="${MINER_BINARY:-/usr/local/bin/hippius-miner-agent}"
SERVICE_NAME="${MINER_SERVICE:-hippius-miner-agent}"
STATE_DIR="${MINER_STATE_DIR:-/var/lib/hippius-miner}"
MINER_CONFIG="${MINER_CONFIG:-/etc/hippius-miner/config.toml}"
RELEASE_REPO="${RELEASE_REPO:-thenervelab/hippius-cvm}"
RELEASES_API="${RELEASES_API:-https://api.github.com/repos/${RELEASE_REPO}/releases?per_page=20}"
ASSET_NAME="${ASSET_NAME:-hippius-miner-agent-x86_64-linux-gnu}"
MIN_RELEASE_AGE_H="${MIN_RELEASE_AGE_H:-24}"
HEALTH_TIMEOUT_S="${HEALTH_TIMEOUT_S:-300}"
RELAUNCH_TIMEOUT_S="${RELAUNCH_TIMEOUT_S:-120}"
POLL_INTERVAL_S="${POLL_INTERVAL_S:-5}"
COSIGN_BIN="${COSIGN_BIN:-/usr/local/libexec/hippius-miner/cosign}"
CGROUP_ROOT="${CGROUP_ROOT:-/sys/fs/cgroup}"
AUTO_UPDATE_DISABLED="${AUTO_UPDATE_DISABLED:-false}"
export TUF_ROOT="${TUF_ROOT:-${STATE_DIR}/sigstore-tuf}"

# Not configurable: the attestation must come from GitHub Actions, from the
# release workflow, built from the tag being installed.
readonly OIDC_ISSUER="https://token.actions.githubusercontent.com"
readonly WORKFLOW_PATH=".github/workflows/miner-agent-release.yml"
readonly PROVENANCE_TYPE="https://slsa.dev/provenance/v1"
readonly TAG_RE='^v([0-9]{4})\.([0-9]{2})\.([0-9]{2})(\.([1-9][0-9]{0,2}))?$'

NO_UPDATE_FLAG="${STATE_DIR}/.no-auto-update"
INSTALLED_FILE="${STATE_DIR}/installed-release"
# Present from just before the new binary is installed until the update is
# confirmed healthy or rolled back. Found at startup = an earlier run was
# cut short (timeout, power loss): roll back before anything else.
TXN_FILE="${STATE_DIR}/update-in-progress"
# Exists once THIS run has SIGKILLed the agent (cleared when the run takes
# the lock). After our own kill, an "inactive" unit is a binary that exited
# cleanly; without one, "inactive" is an operator stop.
KILLED_FLAG="${STATE_DIR}/.update-killed"
BACKUP_PATH="${BINARY_PATH}.bak"
LOG_TAG="hippius-miner-update"

# Fallbacks go to stderr: stdout of some functions is captured (a PID).
log() { printf '%s\n' "$*" | systemd-cat -t "$LOG_TAG" -p info 2>/dev/null || printf '[%s] %s\n' "$LOG_TAG" "$*" >&2; }
warn() { printf '%s\n' "WARNING: $*" | systemd-cat -t "$LOG_TAG" -p warning 2>/dev/null || printf '[%s] WARNING: %s\n' "$LOG_TAG" "$*" >&2; }
err() { printf '%s\n' "ERROR: $*" | systemd-cat -t "$LOG_TAG" -p err 2>/dev/null || printf '[%s] ERROR: %s\n' "$LOG_TAG" "$*" >&2; }
die() { err "$*"; exit 1; }

# ── Tags ─────────────────────────────────────────────────────────────────────

valid_tag() { [[ "$1" =~ $TAG_RE ]]; }

# "YYYY MM DD N" with base-10 integers (no octal surprise on "08").
tag_key() {
    [[ "$1" =~ $TAG_RE ]] || return 1
    printf '%d %d %d %d\n' "$((10#${BASH_REMATCH[1]}))" "$((10#${BASH_REMATCH[2]}))" \
        "$((10#${BASH_REMATCH[3]}))" "$((10#${BASH_REMATCH[5]:-0}))"
}

# Prints -1, 0 or 1 for a < b, a == b, a > b. Both must be valid tags.
tag_cmp() {
    local a b i
    read -r -a a <<<"$(tag_key "$1")"
    read -r -a b <<<"$(tag_key "$2")"
    for i in 0 1 2 3; do
        if [ "${a[i]}" -lt "${b[i]}" ]; then echo -1; return; fi
        if [ "${a[i]}" -gt "${b[i]}" ]; then echo 1; return; fi
    done
    echo 0
}

# The tag inside `hippius-miner-agent <crate version> (<tag>)`, if any.
binary_tag() {
    local line
    line="$(timeout 10 "$1" --version 2>/dev/null | head -n1)" || return 0
    if [[ "$line" =~ ^hippius-miner-agent\ [^\ ]+\ \(([^\)]+)\)$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    fi
}

# The highest release this host is known to run: the recorded tag or the
# tag compiled into the installed binary. Empty when neither is a release
# (a source build, or v2026.10.07 which predates the embedded tag).
installed_tag() {
    local recorded="" embedded best="" t
    [ -f "$INSTALLED_FILE" ] && recorded="$(head -n1 "$INSTALLED_FILE" | tr -d '[:space:]')"
    embedded="$(binary_tag "$BINARY_PATH")"
    for t in "$recorded" "$embedded"; do
        valid_tag "$t" || continue
        if [ -z "$best" ] || [ "$(tag_cmp "$t" "$best")" = 1 ]; then best="$t"; fi
    done
    printf '%s\n' "$best"
}

# ── systemd ──────────────────────────────────────────────────────────────────

unit_prop() { systemctl show -p "$1" --value "$SERVICE_NAME"; }

# Prints the first QEMU process found anywhere in the agent's cgroup tree
# (nested cgroups included); returns 1 when there is none. `systemctl kill`
# signals every process of the unit, so a QEMU in there would die with it.
# QEMU belongs in machine.slice. Returns 2 when the tree cannot be read.
qemu_in_agent_cgroup() {
    local cg dir procs pid pname
    cg="$(unit_prop ControlGroup)"
    dir="${CGROUP_ROOT}${cg}"
    [ -n "$cg" ] && [ -r "$dir/cgroup.procs" ] || return 2
    while read -r procs; do
        while read -r pid; do
            [ -n "$pid" ] || continue
            pname="$(cat "/proc/${pid}/comm" 2>/dev/null || true)"
            case "$pname" in
                qemu* | *qemu-system* | *kvm*) printf '%s (%s) in %s\n' "$pid" "$pname" "${procs%/cgroup.procs}"; return 0 ;;
            esac
        done <"$procs"
    done < <(find "$dir" -name cgroup.procs 2>/dev/null)
    return 1
}

# The only signal this script ever sends the agent. Never `stop`/`restart`:
# a graceful shutdown is what tears the domains down. Checked right before
# every kill, rollback included.
sigkill_agent() {
    local found rc=0
    found="$(qemu_in_agent_cgroup)" || rc=$?
    case "$rc" in
        0) err "not sending SIGKILL: QEMU pid $found, inside $SERVICE_NAME's cgroup"; return 1 ;;
        2) err "not sending SIGKILL: cannot read the cgroup of $SERVICE_NAME"; return 1 ;;
    esac
    systemctl kill --signal=SIGKILL "$SERVICE_NAME" || return 1
    : >"$KILLED_FLAG"
}

# Waits for systemd to bring the agent back under a PID other than $1.
# Prints the new PID.
wait_relaunch() {
    local old_pid="$1" deadline pid state
    deadline=$(( $(date +%s) + RELAUNCH_TIMEOUT_S ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        sleep "$POLL_INTERVAL_S"
        pid="$(unit_prop MainPID)"
        state="$(unit_prop ActiveState)"
        if [ "$state" = active ] && [ -n "$pid" ] && [ "$pid" != 0 ] && [ "$pid" != "$old_pid" ]; then
            printf '%s\n' "$pid"
            return 0
        fi
    done
    return 1
}

# Healthy = the process systemd relaunched is still the main PID and has
# delivered a heartbeat since the swap began ($2, epoch seconds). Only lines
# that PID wrote after $2 count: a heartbeat the old process logged just
# before the kill, or an earlier process that had the same PID, cannot pass.
wait_healthy() {
    local pid="$1" since="$2" deadline
    deadline=$(( $(date +%s) + HEALTH_TIMEOUT_S ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        sleep "$POLL_INTERVAL_S"
        if [ "$(unit_prop ActiveState)" != active ] || [ "$(unit_prop MainPID)" != "$pid" ]; then
            err "agent pid $pid is gone (crashed or restarted by systemd)"
            return 1
        fi
        if journalctl -b --since "@${since}" "_SYSTEMD_UNIT=${SERVICE_NAME}.service" "_PID=${pid}" -o cat --no-pager 2>/dev/null \
                | grep -q 'heartbeat-pusher:.*outcome=delivered'; then
            if [ "$(unit_prop ActiveState)" = active ] && [ "$(unit_prop MainPID)" = "$pid" ]; then
                return 0
            fi
        fi
    done
    err "no delivered heartbeat from pid $pid within ${HEALTH_TIMEOUT_S}s"
    return 1
}

# Running domain UUIDs, sorted. Fails if libvirt cannot be asked.
running_domains() {
    local out
    out="$(virsh -c qemu:///system list --uuid)" || return 1
    printf '%s\n' "$out" | sed '/^$/d' | sort
}

# ── Preflight: refuse anything that could take the domains down ─────────────

preflight_swap() {
    if ! python3 -I -c '
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    cfg = tomllib.load(f)
sys.exit(0 if cfg.get("host", {}).get("skip_shutdown_teardown") is True else 1)
' "$MINER_CONFIG" 2>/dev/null; then
        die "refusing to swap: [host] skip_shutdown_teardown = true is not set in $MINER_CONFIG. Without it any later graceful stop of $SERVICE_NAME (netbird stop, host shutdown) destroys every domain. Re-render the config with play 05, then SIGKILL-swap the agent by hand once (AUTO_UPDATE.md)."
    fi
    case "$(unit_prop Restart)" in
        always | on-failure | on-abnormal | on-abort) ;;
        *) die "refusing to swap: $SERVICE_NAME has Restart=$(unit_prop Restart); systemd would not relaunch it after SIGKILL" ;;
    esac
    if [ "$(unit_prop ActiveState)" != active ]; then
        die "refusing to swap: $SERVICE_NAME is not active ($(unit_prop ActiveState)); an operator stopped it, leave it alone"
    fi
    local found rc=0
    found="$(qemu_in_agent_cgroup)" || rc=$?
    case "$rc" in
        0) die "refusing to swap: QEMU pid $found, inside $SERVICE_NAME's cgroup; SIGKILL would kill it" ;;
        2) die "refusing to swap: cannot read the cgroup of $SERVICE_NAME" ;;
    esac
}

# Installs $1 over the agent binary atomically: a verified, fsynced copy
# renamed in the same directory. Explicit returns: callers run it in an `||`
# context, where errexit is off.
install_binary() {
    install -m 0755 "$1" "${BINARY_PATH}.new" || return 1
    sync -- "${BINARY_PATH}.new" || return 1
    cmp -s "$1" "${BINARY_PATH}.new" || return 1
    mv -f "${BINARY_PATH}.new" "$BINARY_PATH" || return 1
    sync -- "$(dirname -- "$BINARY_PATH")"
}

# Brings the agent up on whatever binary is installed: SIGKILL if it is
# running; `start` if systemd gave up on it after a crash ("failed") or is
# still between restarts ("activating"). Starting such a unit tears nothing
# down. Prints the new PID.
#
# Returns 3, touching nothing, in any other state: "deactivating" (or
# "inactive" when resuming) means an operator stopped, or is stopping, the
# agent on purpose, and a `start` would even replace a pending stop job. It
# stays stopped.
relaunch() {
    local old_pid
    old_pid="$(unit_prop MainPID)"
    if [ "$(unit_prop ActiveState)" = active ] && [ -n "$old_pid" ] && [ "$old_pid" != 0 ]; then
        sigkill_agent || return 1
        # The flag only covers the stretch from our kill until the agent is
        # back up: after that, a later "inactive" is someone else's stop.
        wait_relaunch "$old_pid" && { rm -f -- "$KILLED_FLAG"; return 0; }
        [ "$(unit_prop ActiveState)" = active ] && return 1
    fi
    case "$(unit_prop ActiveState)" in
        failed | activating) ;;
        # After this run's own kill (the preflight saw the agent active),
        # "inactive" is the new or restored binary exiting cleanly, which
        # Restart=on-failure does not cover: start it once. Only when the
        # prior state is unknown (resuming a cut-short run) is it taken as
        # an operator stop.
        inactive) [ -f "$KILLED_FLAG" ] || return 3 ;;
        *) return 3 ;;
    esac
    systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
    systemctl start "$SERVICE_NAME" || return 1
    wait_relaunch "$old_pid" && { rm -f -- "$KILLED_FLAG"; return 0; }
    return 1
}

# Puts the previous binary back and relaunches the agent on it, then marks
# $1 failed so it is not retried. The in-progress file is cleared only once
# the previous binary runs again: if this dies half way, the next run
# starts over from here before doing anything else. An agent an operator
# stopped is left stopped, on the previous binary, and $1 is not marked.
rollback() {
    local tag="$1" reason="$2" pid since rc=0
    mark_failed() {
        printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >"${STATE_DIR}/.update-failed-${tag}" \
            || err "cannot write ${STATE_DIR}/.update-failed-${tag}; $tag may be retried"
    }
    err "release $tag not kept ($reason): rolling back to the previous binary"
    if [ ! -f "$BACKUP_PATH" ]; then
        mark_failed "$reason; no backup to roll back to"
        die "ROLLBACK FAILED: no $BACKUP_PATH to roll back to; $tag is marked failed. Manual intervention needed; never stop or restart $SERVICE_NAME while it hosts domains."
    fi
    if ! install_binary "$BACKUP_PATH"; then
        mark_failed "$reason; cannot reinstall the backup"
        die "ROLLBACK FAILED: cannot reinstall $BACKUP_PATH over $BINARY_PATH; $tag is marked failed and the next run retries the rollback. Never stop or restart $SERVICE_NAME while it hosts domains."
    fi
    since="$(date +%s)"
    pid="$(relaunch)" || rc=$?
    if [ "$rc" = 3 ]; then
        rm -f -- "$TXN_FILE"
        warn "$SERVICE_NAME was stopped by an operator: previous binary restored, agent left stopped"
        exit 1
    fi
    mark_failed "$reason"
    if [ "$rc" != 0 ]; then
        die "ROLLBACK FAILED: $SERVICE_NAME did not come back on the previous binary (installed from $BACKUP_PATH); $tag is marked failed and the next run retries the rollback. Never stop or restart it while it hosts domains."
    fi
    if wait_healthy "$pid" "$since"; then
        rm -f -- "$TXN_FILE"
        log "rolled back: $SERVICE_NAME healthy again on the previous binary (pid $pid); $tag will not be retried (remove ${STATE_DIR}/.update-failed-${tag} to retry it)"
    elif [ "$(unit_prop ActiveState)" = active ] && [ "$(unit_prop MainPID)" = "$pid" ]; then
        # Up but silent (an Edge or network outage looks the same): done
        # here, a later rollback would only SIGKILL it again.
        rm -f -- "$TXN_FILE"
        err "rolled back: the previous binary runs (pid $pid) but delivered no heartbeat. Check the Edge and the agent log."
    else
        # Down or crash-looping: keep the in-progress file so the next run
        # retries the rollback.
        err "ROLLBACK FAILED: the previous binary is not staying up (pid $pid gone); the next run retries the rollback. Manual intervention needed; never stop or restart $SERVICE_NAME while it hosts domains."
    fi
    exit 1
}

# Marks $1 installed, then drops the in-progress file. A crash between the
# two is harmless: the next run resumes, finds $1 running and healthy, and
# finishes here again.
commit_release() {
    printf '%s\n' "$1" >"${INSTALLED_FILE}.new"
    mv -f "${INSTALLED_FILE}.new" "$INSTALLED_FILE"
    rm -f -- "$TXN_FILE"
}

# An earlier run was cut short after writing the in-progress file for $1.
# If $1 is on disk, the running agent was started from it (after the file
# was installed) and it delivers heartbeats, the swap had in fact worked:
# finish it. Anything else: roll back.
resume_interrupted() {
    local tag="$1" pid started_s mtime_s
    if valid_tag "$tag" && [ "$(binary_tag "$BINARY_PATH")" = "$tag" ] \
            && [ "$(unit_prop ActiveState)" = active ]; then
        pid="$(unit_prop MainPID)"
        started_s="$(date -d "$(unit_prop ExecMainStartTimestamp)" +%s 2>/dev/null || echo 0)"
        mtime_s="$(stat -c %Y "$BINARY_PATH")"
        if [ "$started_s" -ge "$mtime_s" ] && wait_healthy "$pid" "$started_s"; then
            commit_release "$tag"
            log "an earlier run was cut short after swapping to $tag; it is running and healthy (pid $pid): update finished"
            exit 0
        fi
    fi
    err "an earlier run was cut short while swapping to $tag; restoring the previous binary"
    rollback "$tag" "interrupted mid-swap"
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    if [ -f "$NO_UPDATE_FLAG" ]; then
        log "auto-update disabled ($NO_UPDATE_FLAG present)"
        exit 0
    fi
    if [ "$AUTO_UPDATE_DISABLED" = true ]; then
        log "auto-update disabled (AUTO_UPDATE_DISABLED=true in $ENV_FILE)"
        exit 0
    fi
    # The repository this host trusts. Its old name still redirects to a
    # different repository, so an attestation minted under it proves nothing.
    case "${RELEASE_REPO,,}" in
        thenervelab/hippius-compute | thenervelab/hippius-compute-internal)
            die "RELEASE_REPO=$RELEASE_REPO is not the public release repository; refusing" ;;
    esac
    [[ "$RELEASE_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "RELEASE_REPO '$RELEASE_REPO' is not <owner>/<repo>"
    [[ "$MIN_RELEASE_AGE_H" =~ ^[0-9]+$ ]] || die "MIN_RELEASE_AGE_H must be a whole number of hours, got '$MIN_RELEASE_AGE_H'"

    mkdir -p "$STATE_DIR"
    exec 9>"${STATE_DIR}/.update.lock"
    flock -n 9 || { log "another update run holds the lock; exiting"; exit 0; }
    rm -f -- "$KILLED_FLAG"

    if [ -f "$TXN_FILE" ]; then
        local stuck
        stuck="$(head -n1 "$TXN_FILE" | tr -d '[:space:]')"
        valid_tag "$stuck" || stuck=unknown
        resume_interrupted "$stuck"
    fi

    [ -x "$BINARY_PATH" ] || die "installed binary not found at $BINARY_PATH"
    [ -x "$COSIGN_BIN" ] || die "cosign not found at $COSIGN_BIN; cannot verify a release, refusing to update"

    local tmp
    tmp="$(mktemp -d "${STATE_DIR}/.update.XXXXXX")"
    # shellcheck disable=SC2064 # expand now: $tmp is local
    trap "rm -rf -- '$tmp'" EXIT

    # Every network step is bounded, so a run always ends well inside the
    # unit's TimeoutStartSec. (A run killed anyway before the swap changes
    # nothing; one killed during it is recovered by the in-progress file.)
    fetch() { # <seconds> <out> <url> [curl args]
        local t="$1" out="$2" url="$3"
        shift 3
        curl -fsSL --proto "=https" --proto-redir "=https" --connect-timeout 20 \
            --retry 2 --max-time "$t" --retry-max-time "$t" "$@" -o "$out" "$url"
    }
    fetch 30 "$tmp/release.json" "$RELEASES_API" \
        -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' \
        || die "cannot fetch $RELEASES_API"

    local installed
    installed="$(installed_tag)"

    # The newest ELIGIBLE release: complete (a valid tag, not a draft or
    # prerelease, carrying the binary, SHA256SUMS and the attestation),
    # newer than the installed one, past the soak, and not marked failed
    # here. A top tag that is too young or failed does not hide an older
    # eligible one. A tag dated more than one day after its UTC publication
    # day is passed over (one day of slack for UTC+ time zones):
    # anti-downgrade would otherwise pin the host to a mistyped far-future
    # tag. The soak counts from when the last of the three files landed,
    # not from when the release object was created (v2026.10.08 was
    # published empty before releases had a single creator).
    local fields
    fields="$(python3 -I -c '
import json, os, re, sys, time
from datetime import datetime, timezone

def ts(s):
    return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())

def say(level, msg):
    print(f"{level}: {msg}", file=sys.stderr)

data = json.load(open(sys.argv[1]))
releases = data if isinstance(data, list) else [data]
asset, tag_re, installed, min_age_h, state_dir = sys.argv[2], re.compile(sys.argv[3]), sys.argv[4], int(sys.argv[5]), sys.argv[6]
need = (asset, "SHA256SUMS", asset + ".sigstore.json")

def key(m):
    return (int(m[1]), int(m[2]), int(m[3]), int(m[5] or 0))

cands = []
for rel in releases:
    tag = rel.get("tag_name") or ""
    m = tag_re.fullmatch(tag)
    if rel.get("draft") or rel.get("prerelease") or not m:
        continue
    assets = {a.get("name"): a for a in rel.get("assets", [])}
    if not all(n in assets for n in need):
        say("warn", f"release {tag} is incomplete (needs " + " + ".join(need) + "); passed over")
        continue
    try:
        published = ts(rel["published_at"])
        tag_day = int(datetime(int(m[1]), int(m[2]), int(m[3]), tzinfo=timezone.utc).timestamp())
        ready = max([published] + [ts(assets[n].get("updated_at") or rel["published_at"]) for n in need])
    except (KeyError, TypeError, ValueError):
        say("warn", f"release {tag} has an unreadable date; passed over")
        continue
    if tag_day > published + 86400:
        say("warn", f"release {tag} is dated after its publication; passed over")
        continue
    cands.append((key(m), tag, ready, [assets[n].get("browser_download_url") or "" for n in need]))

cands.sort(reverse=True)
if not cands:
    say("info", "no complete release yet; nothing to do")
    sys.exit(0)
im = tag_re.fullmatch(installed)
inst = key(im) if im else None
if inst is not None and cands[0][0] < inst:
    say("warn", f"newest release {cands[0][1]} is OLDER than installed {installed}; downgrade refused")
    sys.exit(0)
now = int(time.time())
for k, tag, ready, urls in cands:
    if inst is not None and k <= inst:
        say("info", f"up to date ({installed})")
        sys.exit(0)
    marker = os.path.join(state_dir, ".update-failed-" + tag)
    if os.path.exists(marker):
        say("info", f"release {tag} failed its health check here before; skipping it (remove {marker} to retry)")
        continue
    age = now - ready
    if age < min_age_h * 3600:
        say("info", f"release {tag} has been complete for {age // 3600}h (< MIN_RELEASE_AGE_H={min_age_h}h); waiting")
        continue
    print(tag)
    for u in urls:
        print(u)
    sys.exit(0)
say("info", "no eligible release; nothing to do")
' "$tmp/release.json" "$ASSET_NAME" "$TAG_RE" "$installed" "$MIN_RELEASE_AGE_H" "$STATE_DIR" 2>"$tmp/select.log")" \
        || die "cannot parse the release metadata from $RELEASES_API: $(tail -n 1 "$tmp/select.log")"
    local line
    while read -r line; do
        case "$line" in
            warn:*) warn "${line#warn: }" ;;
            info:*) log "${line#info: }" ;;
            ?*) err "$line" ;;
        esac
    done <"$tmp/select.log"

    # mapfile, not a chain of `read`s: a short answer (no release) must not
    # trip errexit on EOF.
    local f tag url_bin url_sums url_bundle
    mapfile -t f <<<"$fields"
    tag="${f[0]:-}" url_bin="${f[1]:-}" url_sums="${f[2]:-}" url_bundle="${f[3]:-}"
    [ -n "$tag" ] || exit 0

    # Re-checked here, independently of the selection above.
    valid_tag "$tag" || die "selected release tag '$tag' is not vYYYY.MM.DD[.N]; refusing"
    [ ! -f "${STATE_DIR}/.update-failed-${tag}" ] || die "selected release $tag is marked failed; refusing"
    if [ -n "$installed" ]; then
        [ "$(tag_cmp "$tag" "$installed")" = 1 ] || die "selected release $tag is not newer than installed $installed; refusing"
        log "release $tag is newer than installed $installed"
    else
        log "installed release unknown (source build or a release without an embedded tag); $tag counts as an upgrade"
    fi

    local u
    for u in "$url_bin" "$url_sums" "$url_bundle"; do
        [[ "$u" == https://* ]] || die "release $tag has a non-https download URL '$u'; refusing"
    done
    local new="$tmp/$ASSET_NAME"
    fetch 600 "$new" "$url_bin" || die "cannot download $url_bin"
    fetch 60 "$tmp/SHA256SUMS" "$url_sums" || die "cannot download $url_sums"
    fetch 60 "$tmp/bundle.json" "$url_bundle" || die "cannot download $url_bundle"

    # 1. sha256: exactly one SHA256SUMS line for the asset, and it matches.
    local want got
    want="$(awk -v n="$ASSET_NAME" '{ f = $2; sub(/^\*/, "", f) } f == n { print tolower($1) }' "$tmp/SHA256SUMS")"
    [ "$(printf '%s' "$want" | grep -c .)" = 1 ] || die "SHA256SUMS of $tag must list $ASSET_NAME exactly once"
    [[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "SHA256SUMS of $tag has a malformed digest for $ASSET_NAME"
    got="$(sha256sum "$new" | awk '{ print $1 }')"
    [ "$got" = "$want" ] || die "sha256 mismatch for $tag: SHA256SUMS=$want download=$got; refusing"
    log "sha256 OK for $tag: $got"

    # 2. Build provenance: signed by GitHub Actions for the release workflow
    #    of $RELEASE_REPO, run on a push of exactly this tag, and its subject
    #    is this binary.
    local identity="https://github.com/${RELEASE_REPO}/${WORKFLOW_PATH}@refs/tags/${tag}"
    if ! timeout 300 "$COSIGN_BIN" verify-blob-attestation \
            --bundle "$tmp/bundle.json" \
            --type "$PROVENANCE_TYPE" \
            --certificate-identity "$identity" \
            --certificate-oidc-issuer "$OIDC_ISSUER" \
            --certificate-github-workflow-repository "$RELEASE_REPO" \
            --certificate-github-workflow-ref "refs/tags/${tag}" \
            --certificate-github-workflow-trigger push \
            "$new" >"$tmp/cosign.log" 2>&1; then
        err "cosign: $(tail -n 3 "$tmp/cosign.log" | tr '\n' ' ')"
        die "build-provenance attestation of $tag does not verify for $identity; refusing"
    fi
    log "attestation OK for $tag ($identity)"

    # 3. The binary names the tag it was released as.
    chmod 0755 "$new"
    local new_tag
    new_tag="$(binary_tag "$new")"
    [ "$new_tag" = "$tag" ] || die "downloaded binary reports release '${new_tag}', expected '$tag'; refusing"
    log "binary reports $tag"

    preflight_swap

    local domains_before pid since
    domains_before="$(running_domains)" || die "refusing to swap: cannot list the running domains (virsh)"
    if ! { cp -p "$BINARY_PATH" "${BACKUP_PATH}.new" && sync -- "${BACKUP_PATH}.new" && mv -f "${BACKUP_PATH}.new" "$BACKUP_PATH"; }; then
        die "cannot back up $BINARY_PATH to $BACKUP_PATH; the running agent was not touched"
    fi
    if ! { printf '%s\n' "$tag" >"$TXN_FILE" && sync -- "$TXN_FILE"; }; then
        die "cannot write $TXN_FILE; the running agent was not touched"
    fi
    log "swapping $SERVICE_NAME to $tag (backup $BACKUP_PATH, $(printf '%s' "$domains_before" | grep -c .) running domain(s))"
    install_binary "$new" || rollback "$tag" "cannot install the new binary"
    since="$(date +%s)"
    local rc=0
    pid="$(relaunch)" || rc=$?
    case "$rc" in
        0) ;;
        3) rollback "$tag" "agent stopped by an operator during the swap" ;;
        *) rollback "$tag" "agent did not relaunch within ${RELAUNCH_TIMEOUT_S}s" ;;
    esac
    if ! wait_healthy "$pid" "$since"; then
        rollback "$tag" "health check failed"
    fi

    # Domains outlive the agent, so one that stopped across the swap is
    # worth a loud line, but not a rollback: tenants stop, orders destroy,
    # guests crash, and a rollback would only SIGKILL the agent again.
    local after lost
    if after="$(running_domains)"; then
        lost="$(comm -23 <(printf '%s\n' "$domains_before" | sed '/^$/d') <(printf '%s\n' "$after" | sed '/^$/d'))"
        if [ -n "$lost" ]; then
            warn "DOMAIN-LOSS: domain(s) running before the swap to $tag are no longer running: $(printf '%s' "$lost" | tr '\n' ' ')(check them; the update is kept)"
        fi
    else
        warn "DOMAIN-LOSS: cannot list the running domains after the swap to $tag; check them by hand"
    fi

    commit_release "$tag"
    log "updated to $tag: $SERVICE_NAME pid $pid healthy, heartbeat delivered"
}

# Sourced by the tests for the tag helpers; executed for real otherwise.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
