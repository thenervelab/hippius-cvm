#!/usr/bin/env bash
# uki-fetch-retry-test.sh — the tenant-UKI input fetch must survive a
# transient mirror error without retrying anything that is not one.
#
# Why this exists. `tenant-uki-build` was red on every push to main from
# 2026-09-10 on, across commits that never touched the UKI, always with:
#
#   fetching systemd-stub.deb from http://snapshot.debian.org/…
#   curl: (22) The requested URL returned error: 504
#   make: *** [Makefile:217: fetch] Error 22
#
# snapshot.debian.org 504s intermittently; the same pinned URL answered
# 302 minutes later. `fetch-inputs.sh` did ONE `curl` per input, so one
# 504 killed the build, the pinned KAT went unverified for weeks, and a
# scheduled rebake on that path would not have been a pipeline.
#
# What must hold, and what must NOT change with the fix:
#   (a) HTTP 504, 504, 200 → the fetch succeeds, exactly 3 attempts, each
#       retry logged with the input name, the attempt and the code, and
#       the backoff is 5 s then 10 s.
#   (b) HTTP 404 → fails on the FIRST attempt. A 404 on a pinned snapshot
#       URL is a broken pin; retrying it hides the real problem.
#   (c) HTTP 200 with the wrong bytes → the SHA-256 check fails and there
#       is NO retry. A mismatch is a security signal, not a network blip.
#   (d) five failures → non-zero exit; the log names the input and the
#       last code, so a red build is readable without the whole log.
#   (e) a curl transport failure (no HTTP response) is transient too.
#
# How it tests the REAL script, not a copy. `fetch-inputs.sh` is run
# unsliced, with its normal 8 URL/SHA arguments, against a PATH-shimmed
# `curl` driven by a per-input plan (one response per attempt), a `sleep`
# that records the delay instead of waiting, and a `dpkg-deb` that
# unpacks the fixture "debs" (gzipped tars — the extraction step is not
# under test; the fetch is). sha256sum, awk, find, install and tar are
# the real ones. Inputs are all `http://` on a reserved `.invalid` name:
# the shim never touches the network.
#
# /build. The script hardcodes `/build/fetched` + `/build/work` (Docker
# bind-mounts, see the Makefile's DOCKER_RUN) and deliberately has NO
# environment override — a build input path that depends on the caller's
# env is a reproducibility hole. So this test needs a real, EMPTY
# `/build`: it uses one that is already ours and empty, creates it with
# `sudo -n` when absent (CI runners) and removes it afterwards, and
# otherwise SKIPs locally / FAILs in CI. It refuses to run against a
# `/build` that holds anything, because the script wipes its contents.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-${HERE}/../../packer/tenant-uki/uki/scripts/fetch-inputs.sh}"
[[ -r "${TARGET}" ]] || { echo "uki-fetch-retry-test: fetch script not found at ${TARGET}" >&2; exit 1; }

FAILED=0
CHECKS=0
ok()  { CHECKS=$((CHECKS + 1)); echo "uki-fetch-retry-test: OK — $*"; }
err() { CHECKS=$((CHECKS + 1)); echo "uki-fetch-retry-test: FAIL — $*" >&2; FAILED=1; }

# ── 0. /build ───────────────────────────────────────────────────────
CREATED_BUILD=0
if [[ -d /build ]]; then
    if [[ ! -w /build ]]; then
        echo "uki-fetch-retry-test: /build exists but is not writable — SKIP (the script hardcodes it)" >&2
        [[ -n "${CI:-}" ]] && exit 1
        exit 0
    fi
    for d in /build/fetched /build/work; do
        if [[ -e "${d}" ]] && [[ -n "$(find "${d}" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
            echo "uki-fetch-retry-test: ${d} is not empty — refusing to run (the script wipes it)" >&2
            exit 1
        fi
    done
elif sudo -n install -d -m 0755 -o "$(id -u)" -g "$(id -g)" /build 2>/dev/null; then
    CREATED_BUILD=1
else
    if [[ -n "${CI:-}" ]]; then
        echo "uki-fetch-retry-test: cannot create /build and CI is set — FAIL (the check cannot be vacuous in CI)" >&2
        exit 1
    fi
    echo "uki-fetch-retry-test: /build absent and no passwordless sudo — SKIP (local)"
    exit 0
fi

WORK="$(mktemp -d -t hippius-uki-fetch-retry-test.XXXXXX)"
cleanup() {
    rm -rf -- "${WORK}"
    if [[ ${CREATED_BUILD} -eq 1 ]]; then
        rm -rf -- /build/fetched /build/work
        rmdir /build 2>/dev/null || sudo -n rmdir /build 2>/dev/null || true
    else
        rm -rf -- /build/fetched /build/work
    fi
}
trap cleanup EXIT

# ── 1. Fixture payloads (what a 200 delivers) ───────────────────────
# The "debs" are gzipped tars laid out like the real packages, so the
# script's post-fetch steps (dpkg-deb shim → find vmlinuz / the stub,
# tar the NetBird binary) run to its final "OK" line.
PAYLOAD="${WORK}/payload"
mkdir -p "${PAYLOAD}/kernel/boot" "${PAYLOAD}/stub/usr/lib/systemd/boot/efi" "${PAYLOAD}/netbird"
printf 'fake vmlinuz\n' > "${PAYLOAD}/kernel/boot/vmlinuz-6.12.0-fixture-amd64"
printf 'fake stub\n'    > "${PAYLOAD}/stub/usr/lib/systemd/boot/efi/linuxx64.efi.stub"
printf 'fake netbird\n' > "${PAYLOAD}/netbird/netbird"
tar -C "${PAYLOAD}/kernel"  -czf "${PAYLOAD}/kernel.deb"        boot
tar -C "${PAYLOAD}/stub"    -czf "${PAYLOAD}/systemd-stub.deb"  usr
tar -C "${PAYLOAD}/netbird" -czf "${PAYLOAD}/netbird.tar.gz"    ./netbird
head -c 4096 /dev/urandom > "${PAYLOAD}/ovmf.bin"
printf 'not the kernel\n' > "${PAYLOAD}/kernel.deb.wrong"

sha_of() { sha256sum "$1" | awk '{print $1}'; }
KERNEL_SHA="$(sha_of "${PAYLOAD}/kernel.deb")"
STUB_SHA="$(sha_of "${PAYLOAD}/systemd-stub.deb")"
OVMF_SHA="$(sha_of "${PAYLOAD}/ovmf.bin")"
NETBIRD_SHA="$(sha_of "${PAYLOAD}/netbird.tar.gz")"

BASE="http://mirror.invalid/pool"
KERNEL_URL="${BASE}/kernel.deb"
STUB_URL="${BASE}/systemd-stub.deb"
OVMF_URL="${BASE}/ovmf.bin"
NETBIRD_URL="${BASE}/netbird.tar.gz"

# ── 2. Shims ────────────────────────────────────────────────────────
SHIM="${WORK}/bin"
mkdir -p "${SHIM}"

# curl: keyed by the URL's basename. `${FAKE_PLAN}/<name>` lists one
# response per attempt (last line repeats): `200`, `200:<payload-file>`,
# an HTTP status, `curl:<exit>` for a transport failure with no HTTP
# response (http_code 000, like the real tool), or `curl:<exit>@<code>`
# for a transport failure AFTER a response — exit 18 (short body) with
# http_code 200 is the real-world shape. Mirrors real curl's contract
# that matters here: `--write-out %{http_code}` is printed even when
# `--fail` trips (exit 22), `--output` is written only on success.
# Every call is appended to `${FAKE_LOG}` as `<name> <argv…>`.
cat > "${SHIM}/curl" <<'SHIM_EOF'
#!/usr/bin/env bash
set -eu
out=""; wout=""; url=""
args=("$@")
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output|-o) out="$2"; shift 2 ;;
        --write-out|-w) wout="$2"; shift 2 ;;
        --connect-timeout|--max-time|--retry|--retry-delay|--retry-max-time) shift 2 ;;
        -*) shift ;;
        *) url="$1"; shift ;;
    esac
done
name="${url##*/}"
printf '%s %s\n' "${name}" "${args[*]}" >> "${FAKE_LOG}"
plan="${FAKE_PLAN}/${name}"
[[ -r "${plan}" ]] || { echo "curl shim: no plan for ${name}" >&2; exit 99; }
count="${FAKE_PLAN}/${name}.count"
n=$(( $(cat "${count}" 2>/dev/null || echo 0) + 1 ))
echo "${n}" > "${count}"
total=$(wc -l < "${plan}")
[[ ${n} -le ${total} ]] || n=${total}
step="$(sed -n "${n}p" "${plan}")"
case "${step}" in
    200|200:*)
        src="${FAKE_PAYLOAD}/${name}"
        [[ "${step}" == 200:* ]] && src="${step#200:}"
        cp -- "${src}" "${out}"
        [[ -n "${wout}" ]] && printf '200'
        exit 0 ;;
    curl:*)
        spec="${step#curl:}"
        code="000"
        [[ "${spec}" == *@* ]] && code="${spec#*@}"
        spec="${spec%@*}"
        # A short body leaves a partial file behind, as the real tool does.
        [[ "${code}" == "200" ]] && printf 'partial' > "${out}"
        [[ -n "${wout}" ]] && printf '%s' "${code}"
        echo "curl: (${spec}) simulated transport failure" >&2
        exit "${spec}" ;;
    [0-9][0-9][0-9])
        [[ -n "${wout}" ]] && printf '%s' "${step}"
        echo "curl: (22) The requested URL returned error: ${step}" >&2
        exit 22 ;;
    *) echo "curl shim: bad plan step '${step}' for ${name}" >&2; exit 99 ;;
esac
SHIM_EOF

# sleep: record the requested delay, return at once (the backoff
# sequence becomes an assertion instead of a 75 s wait).
cat > "${SHIM}/sleep" <<'SHIM_EOF'
#!/usr/bin/env bash
echo "$1" >> "${FAKE_SLEEP_LOG}"
exit 0
SHIM_EOF

# dpkg-deb -x DEB DIR: the fixture debs are gzipped tars.
cat > "${SHIM}/dpkg-deb" <<'SHIM_EOF'
#!/usr/bin/env bash
set -eu
[[ "$1" == "-x" ]] || { echo "dpkg-deb shim: only -x is supported" >&2; exit 2; }
tar -xzf "$2" -C "$3"
SHIM_EOF
chmod +x "${SHIM}"/*

# ── 3. Runner ───────────────────────────────────────────────────────
# run_case NAME then `plan <input> <line>...` calls before it, via
# CASE_PLAN. Sets CASE_RC, CASE_ERR, CASE_LOG, CASE_SLEEPS.
CASE_PLAN=""
new_case() {
    CASE_PLAN="${WORK}/case-$1"
    rm -rf -- "${CASE_PLAN}"
    mkdir -p "${CASE_PLAN}/plan"
    : > "${CASE_PLAN}/curl.log"
    : > "${CASE_PLAN}/sleep.log"
    # Defaults: every input answers 200 on the first attempt.
    for n in kernel.deb systemd-stub.deb ovmf.bin netbird.tar.gz; do
        echo 200 > "${CASE_PLAN}/plan/${n}"
    done
}
plan() { printf '%s\n' "${@:2}" > "${CASE_PLAN}/plan/$1"; }
run_case() {
    rm -rf -- /build/fetched /build/work
    set +e
    PATH="${SHIM}:/usr/bin:/bin" \
    FAKE_PLAN="${CASE_PLAN}/plan" \
    FAKE_PAYLOAD="${PAYLOAD}" \
    FAKE_LOG="${CASE_PLAN}/curl.log" \
    FAKE_SLEEP_LOG="${CASE_PLAN}/sleep.log" \
        bash "${TARGET}" \
            "${KERNEL_URL}" "${KERNEL_SHA}" \
            "${STUB_URL}" "${STUB_SHA}" \
            "${OVMF_URL}" "${OVMF_SHA}" \
            "${NETBIRD_URL}" "${NETBIRD_SHA}" \
            >"${CASE_PLAN}/stdout" 2>"${CASE_PLAN}/stderr"
    CASE_RC=$?
    set -e
    CASE_ERR="$(cat "${CASE_PLAN}/stderr")"
    CASE_LOG="$(cat "${CASE_PLAN}/curl.log")"
    CASE_SLEEPS="$(tr '\n' ' ' < "${CASE_PLAN}/sleep.log" | sed 's/ $//')"
}
attempts_for() { grep -c "^$1 " <<<"${CASE_LOG}" || true; }
retry_lines_for() { grep -c "^fetch-inputs: $1 attempt [0-9]*/[0-9]* failed" <<<"${CASE_ERR}" || true; }

# ── 4. Baseline: every input 200 first time → whole script succeeds ──
new_case baseline
run_case
[[ ${CASE_RC} -eq 0 ]] || err "baseline: script exited ${CASE_RC}: ${CASE_ERR}"
grep -q '^fetch-inputs: OK' <<<"${CASE_ERR}" || err "baseline: final OK line missing: ${CASE_ERR}"
[[ "$(attempts_for kernel.deb)" -eq 1 ]] || err "baseline: kernel.deb fetched $(attempts_for kernel.deb) times, expected 1"
[[ -z "${CASE_SLEEPS}" ]] || err "baseline: slept (${CASE_SLEEPS}) although nothing failed"
[[ -f /build/work/vmlinuz && -f /build/work/linuxx64.efi.stub && -x /build/work/netbird && -f /build/fetched/ovmf.bin ]] \
    || err "baseline: staged outputs missing under /build/work + /build/fetched"
# Every curl call carries the per-attempt timeouts (requirement: a hung
# connection must not hold the job for the runner's full 6 h).
while read -r line; do
    grep -q -- '--connect-timeout [0-9]' <<<"${line}" || err "baseline: curl call without --connect-timeout: ${line}"
    grep -q -- '--max-time [0-9]'        <<<"${line}" || err "baseline: curl call without --max-time: ${line}"
    grep -q -- '--fail'                  <<<"${line}" || err "baseline: curl call without --fail (an HTTP error would be saved as the artefact): ${line}"
done <<<"${CASE_LOG}"
[[ ${FAILED} -eq 0 ]] && ok "baseline: 4 inputs, 1 attempt each, timeouts on every call, outputs staged, exit 0"

# ── 5. (a) 504, 504, 200 → success on the 3rd attempt ───────────────
new_case a
plan kernel.deb 504 504 200
run_case
[[ ${CASE_RC} -eq 0 ]] || err "(a): script exited ${CASE_RC} — two 504s then a 200 must succeed: ${CASE_ERR}"
[[ "$(attempts_for kernel.deb)" -eq 3 ]] || err "(a): kernel.deb fetched $(attempts_for kernel.deb) times, expected exactly 3"
[[ "$(attempts_for systemd-stub.deb)" -eq 1 ]] || err "(a): systemd-stub.deb fetched $(attempts_for systemd-stub.deb) times — the retry leaked to another input"
[[ "$(retry_lines_for kernel.deb)" -eq 2 ]] || err "(a): expected 2 retry log lines for kernel.deb, got $(retry_lines_for kernel.deb): ${CASE_ERR}"
grep -q '^fetch-inputs: kernel.deb attempt 1/5 failed (HTTP 504, curl exit 22)' <<<"${CASE_ERR}" \
    || err "(a): first retry line must name the input, attempt 1/5 and HTTP 504: ${CASE_ERR}"
grep -q '^fetch-inputs: kernel.deb attempt 2/5 failed (HTTP 504, curl exit 22)' <<<"${CASE_ERR}" \
    || err "(a): second retry line must name the input, attempt 2/5 and HTTP 504: ${CASE_ERR}"
grep -q "^verified kernel.deb = ${KERNEL_SHA}\$" <<<"${CASE_ERR}" || err "(a): kernel.deb not verified after the successful attempt"
[[ "${CASE_SLEEPS}" == "5 10" ]] || err "(a): backoff was '${CASE_SLEEPS}', expected '5 10'"
[[ ${FAILED} -eq 0 ]] && ok "(a) 504,504,200 → success, exactly 3 attempts, 2 retry lines naming kernel.deb + code, backoff 5 10"

# ── 6. (b) 404 → fail on the FIRST attempt, no retry ────────────────
new_case b
plan systemd-stub.deb 404 200 200 200 200
run_case
[[ ${CASE_RC} -ne 0 ]] || err "(b): a 404 on a pinned URL must fail the build"
[[ "$(attempts_for systemd-stub.deb)" -eq 1 ]] || err "(b): systemd-stub.deb fetched $(attempts_for systemd-stub.deb) times — a 404 must NOT be retried"
[[ "$(attempts_for ovmf.bin)" -eq 0 ]] || err "(b): the script went on to ovmf.bin after a failed input"
grep -q '^fetch-inputs: systemd-stub.deb failed (HTTP 404' <<<"${CASE_ERR}" || err "(b): failure line must name the input and HTTP 404: ${CASE_ERR}"
[[ -z "${CASE_SLEEPS}" ]] || err "(b): slept (${CASE_SLEEPS}) on a non-retryable 404"
[[ ! -e /build/fetched/systemd-stub.deb ]] || err "(b): a file was left behind for the failed input"
[[ ${FAILED} -eq 0 ]] && ok "(b) 404 → fails on attempt 1, no retry, no sleep, input + code in the log"

# ── 7. (c) 200 with the wrong bytes → SHA mismatch, NO retry ────────
new_case c
plan kernel.deb "200:${PAYLOAD}/kernel.deb.wrong" 200 200
run_case
[[ ${CASE_RC} -eq 66 ]] || err "(c): expected exit 66 (SHA-256 mismatch), got ${CASE_RC}: ${CASE_ERR}"
grep -q '^fetch-inputs: SHA-256 mismatch for kernel.deb' <<<"${CASE_ERR}" || err "(c): mismatch line missing: ${CASE_ERR}"
[[ "$(attempts_for kernel.deb)" -eq 1 ]] || err "(c): kernel.deb fetched $(attempts_for kernel.deb) times — a hash mismatch must NEVER be retried (the plan's next attempt would have delivered the right bytes)"
[[ "$(retry_lines_for kernel.deb)" -eq 0 ]] || err "(c): retry line logged on a hash mismatch: ${CASE_ERR}"
[[ -z "${CASE_SLEEPS}" ]] || err "(c): slept (${CASE_SLEEPS}) on a hash mismatch"
[[ ! -e /build/fetched/kernel.deb ]] || err "(c): mismatching file left in /build/fetched (fail-closed removal broken)"
[[ ${FAILED} -eq 0 ]] && ok "(c) 200 with wrong bytes → exit 66, 1 attempt, no retry, offending file removed"

# ── 8. (d) five failures → non-zero, log names input + last code ────
# Attempt 3 is a short body (exit 18) that leaves a partial file; the
# later HTTP errors write nothing, so a partial that is not removed
# between attempts would be what the build finds after giving up.
new_case d
plan systemd-stub.deb 504 503 curl:18@200 502 504 200
run_case
[[ ${CASE_RC} -ne 0 ]] || err "(d): five failures must fail the build"
[[ "$(attempts_for systemd-stub.deb)" -eq 5 ]] || err "(d): systemd-stub.deb fetched $(attempts_for systemd-stub.deb) times, expected exactly 5 (the 6th would have succeeded)"
[[ "$(retry_lines_for systemd-stub.deb)" -eq 4 ]] || err "(d): expected 4 retry lines, got $(retry_lines_for systemd-stub.deb): ${CASE_ERR}"
grep -q '^fetch-inputs: systemd-stub.deb failed after 5 attempts (last: HTTP 504, curl exit 22)' <<<"${CASE_ERR}" \
    || err "(d): final line must name the input, the attempt count and the LAST code: ${CASE_ERR}"
[[ "${CASE_SLEEPS}" == "5 10 20 40" ]] || err "(d): backoff was '${CASE_SLEEPS}', expected '5 10 20 40'"
[[ "$(attempts_for ovmf.bin)" -eq 0 ]] || err "(d): the script went on to ovmf.bin after giving up"
[[ ! -e /build/fetched/systemd-stub.deb ]] || err "(d): a partial body was left behind after giving up (fail-closed: nothing may survive a failed fetch)"
[[ ${FAILED} -eq 0 ]] && ok "(d) 5×5xx → non-zero, exactly 5 attempts, backoff 5 10 20 40, final line names systemd-stub.deb + HTTP 504"

# ── 8b. (f) permanent curl exits fail fast, never retried ──────────
# Exit 60 is a certificate-verification failure. Retrying it would wait
# out the one error that must never be waited out; exits 1/3/23 are the
# same class (protocol, URL, local write). One attempt, no sleep, the
# log names the exit code, and nothing is left behind.
new_case f
plan systemd-stub.deb curl:60@0 200
run_case
[[ ${CASE_RC} -eq 60 ]] || err "(f): a certificate failure must exit with curl's code 60, got ${CASE_RC}"
[[ "$(attempts_for systemd-stub.deb)" -eq 1 ]] || err "(f): curl exit 60 was retried ($(attempts_for systemd-stub.deb) attempts) — it is permanent"
[[ -z "${CASE_SLEEPS}" ]] || err "(f): no backoff may run on a permanent exit, slept '${CASE_SLEEPS}'"
grep -q '^fetch-inputs: systemd-stub.deb failed (curl exit 60) — not retrying' <<<"${CASE_ERR}" \
    || err "(f): the log must name the input and the permanent exit code: ${CASE_ERR}"
[[ "$(attempts_for ovmf.bin)" -eq 0 ]] || err "(f): the script went on to ovmf.bin after a permanent failure"
[[ ! -e /build/fetched/systemd-stub.deb ]] || err "(f): a partial body survived a permanent failure"
[[ ${FAILED} -eq 0 ]] && ok "(f) curl exit 60 → fail-fast, 1 attempt, no backoff, log names the code"

# ── 9. (e) transport failures + 429 are transient too ───────────────
# Includes exit 18 with http_code 200 — a truncated body — which curl's
# own `--retry` does NOT cover and which a classifier keyed on the HTTP
# code alone would wrongly treat as a non-retryable 2xx. Success lands on
# the 5th and last permitted attempt.
new_case e
plan ovmf.bin curl:56 curl:28 curl:18@200 429 200
run_case
[[ ${CASE_RC} -eq 0 ]] || err "(e): reset, timeout, short body, 429 then 200 must succeed: ${CASE_ERR}"
[[ "$(attempts_for ovmf.bin)" -eq 5 ]] || err "(e): ovmf.bin fetched $(attempts_for ovmf.bin) times, expected 5"
grep -q '^fetch-inputs: ovmf.bin attempt 1/5 failed (HTTP 000, curl exit 56)' <<<"${CASE_ERR}" || err "(e): curl exit 56 retry line missing: ${CASE_ERR}"
grep -q '^fetch-inputs: ovmf.bin attempt 2/5 failed (HTTP 000, curl exit 28)' <<<"${CASE_ERR}" || err "(e): curl exit 28 retry line missing: ${CASE_ERR}"
grep -q '^fetch-inputs: ovmf.bin attempt 3/5 failed (HTTP 200, curl exit 18)' <<<"${CASE_ERR}" || err "(e): curl exit 18 (short body, HTTP 200) must be retried: ${CASE_ERR}"
grep -q '^fetch-inputs: ovmf.bin attempt 4/5 failed (HTTP 429, curl exit 22)' <<<"${CASE_ERR}" || err "(e): HTTP 429 retry line missing: ${CASE_ERR}"
grep -q "^verified ovmf.bin = ${OVMF_SHA}\$" <<<"${CASE_ERR}" || err "(e): ovmf.bin not verified — the partial body from attempt 3 must not survive into the digest check"
[[ "${CASE_SLEEPS}" == "5 10 20 40" ]] || err "(e): backoff was '${CASE_SLEEPS}', expected '5 10 20 40'"
[[ ${FAILED} -eq 0 ]] && ok "(e) curl 56, curl 28, curl 18 (HTTP 200), HTTP 429, 200 → success on attempt 5/5, each retry names the code"

# ── 10. Vacuity floor ───────────────────────────────────────────────
[[ ${CHECKS} -ge 6 ]] || { echo "uki-fetch-retry-test: only ${CHECKS} checks ran — harness bug" >&2; exit 1; }

if [[ ${FAILED} -eq 0 ]]; then
    echo "uki-fetch-retry-test: ALL OK (${CHECKS} checks)"
else
    echo "uki-fetch-retry-test: FAILURES" >&2
    exit 1
fi
