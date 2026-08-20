#!/usr/bin/env bash
# ssrf-fetch-test.sh — the baker's base-image fetch must survive a
# TRUNCATED transfer without the SSRF guard (audit RA-M1) being weakened.
#
# Why this exists. Bake c08e520e05044c9a894214e250bf950e (golden fedora)
# died in production with:
#
#   fetch: pinned dl.fedoraproject.org:443 -> 38.145.32.24 (no-redirect)
#   curl: (18) end of response with 402721299 bytes missing
#   ERROR: base image fetch failed (ssrf-guard or curl) (exit 3)
#
# Three defects in one line. `--retry 3` was ON the command and did not
# retry, because curl only retries the classes it calls transient
# (timeouts, 408, 429, 5xx) and a short body is exit 18. The guard had
# resolved SIX addresses for that host and VALIDATED every one of them,
# then pinned only the FIRST — two healthy public IPv4s sat unused while
# ~1.6 GB of a ~2 GB download was thrown away. And the single conflated
# error message sent the on-call down a guard/upstream rabbit hole when
# the guard had done nothing wrong.
#
# The fix must not become the OTHER bug. The tempting shape — "walk the
# resolved addresses, skip the ones that fail the policy, use a good one"
# — silently deletes the DNS-rebinding defence, because a rebinding
# answer set is exactly "one public + one internal". So the load-bearing
# assertion here is the REFUSAL: a non-public address ANYWHERE in the
# resolution set must abort the WHOLE fetch, not be skipped.
#
# How it tests the REAL code, not a copy:
#   * the resolver's policy runs verbatim — the test extracts
#     `ssrf_resolve_public_addrs` from the bake script, evals it, and
#     shadows `python3` so the script's own quoted heredoc is executed
#     with only `socket.getaddrinfo` faked. Nothing about the policy is
#     re-implemented here.
#   * the transfer loop runs against REAL curl and REAL HTTP servers on
#     loopback aliases (127.0.0.1/2/3), one truncating and one complete.
#     It is driven directly with explicit addresses — the guard's
#     public-only policy makes loopback unreachable through the resolver,
#     which is exactly why the policy is a separately testable predicate
#     instead of something that had to be loosened for tests. There is no
#     bypass env var, and this test asserts there is none.
#   * the WIRING between the two halves is asserted separately (all
#     validated addresses forwarded, refusal short-circuits), because
#     "declared in one place, never wired in the other" is this repo's
#     most repeated defect.
#
# Vacuity floor (borrowed from addons-digest-pin-test.sh): the counts of
# executed checks and of intercepted policy invocations are themselves
# assertions, so this cannot pass while examining nothing.
#
# Root-free; temp dirs + loopback only. Takes an optional path to the bake
# script so mutants can be driven through it (mutation testing).
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-${HERE}/../tenant-image-bake.sh}"
[[ -r "${TARGET}" ]] || { echo "ssrf-fetch-test: bake script not found at ${TARGET}" >&2; exit 1; }

if ! command -v curl >/dev/null 2>&1; then
    if [[ -n "${CI:-}" ]]; then
        echo "ssrf-fetch-test: curl is not installed and CI is set — FAIL (the check cannot be vacuous in CI)"
        exit 1
    fi
    echo "ssrf-fetch-test: curl not installed — SKIP (local)"
    exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"; [[ -n "${SERVER_PID:-}" ]] && kill "${SERVER_PID}" 2>/dev/null || true' EXIT

FAILED=0
CHECKS=0
ok()  { CHECKS=$((CHECKS + 1)); echo "ssrf-fetch-test: OK — $*"; }
err() { CHECKS=$((CHECKS + 1)); echo "ssrf-fetch-test: FAIL — $*" >&2; FAILED=1; }

# ── Extract the three functions under test from the REAL bake script ──
# Each is written with if/fi + for/done only, so the sole line starting
# with `}` at column 0 is the closing brace.
extract_func() {
    awk -v f="$1" 'index($0, f "() {") == 1 {p = 1} p {print} p && /^\}/ {exit}' "${TARGET}"
}

for fn in ssrf_resolve_public_addrs ssrf_pinned_fetch_rounds ssrf_safe_https_fetch; do
    src="$(extract_func "${fn}")"
    if [[ -z "${src}" ]]; then
        echo "ssrf-fetch-test: could not extract ${fn}() from ${TARGET} — the fetch was refactored without updating this test" >&2
        exit 1
    fi
    # shellcheck disable=SC1090
    eval "${src}"
done

LOGFILE="${TMP}/bake.log"
: > "${LOGFILE}"
log() { printf 'bake: %s\n' "$*" >> "${LOGFILE}"; }

# ── Policy driver: run the bake's OWN heredoc with faked DNS ──────────
cat > "${TMP}/driver.py" <<'DRIVER'
import ipaddress
import os
import socket
import sys

prog = os.environ["SSRF_TEST_PROG"]
fake = [a for a in os.environ.get("SSRF_TEST_ADDRS", "").split(",") if a]


def fake_getaddrinfo(host, port, *args, **kwargs):
    if os.environ.get("SSRF_TEST_RESOLVE_FAIL"):
        raise OSError("simulated resolution failure")
    out = []
    for s in fake:
        ip = ipaddress.ip_address(s)
        if ip.version == 4:
            out.append((socket.AF_INET, socket.SOCK_STREAM,
                        socket.IPPROTO_TCP, "", (s, int(port))))
        else:
            out.append((socket.AF_INET6, socket.SOCK_STREAM,
                        socket.IPPROTO_TCP, "", (s, int(port), 0, 0)))
    return out


socket.getaddrinfo = fake_getaddrinfo
sys.argv = [prog] + sys.argv[1:]
with open(prog) as fh:
    source = fh.read()
exec(compile(source, prog, "exec"), {"__name__": "__main__"})
DRIVER

POLICY_CALLS_FILE="${TMP}/policy-calls"
: > "${POLICY_CALLS_FILE}"
# Shadow python3 for the duration of the policy tests: the bake script's
# quoted heredoc arrives on stdin and is executed VERBATIM by the driver.
python3() {
    local prog="${TMP}/policy-prog.py" rc=0
    cat > "${prog}"
    if [[ "${1:-}" != "-" ]]; then
        echo "ssrf-fetch-test: unexpected python3 invocation: $*" >&2
        return 99
    fi
    shift
    # Counted in a FILE: every policy call below runs inside a process
    # substitution, so a shell variable would be incremented in a subshell
    # and the vacuity floor would read 0 forever.
    echo x >> "${POLICY_CALLS_FILE}"
    SSRF_TEST_PROG="${prog}" command python3 "${TMP}/driver.py" "$@" || rc=$?
    return "${rc}"
}

URL="https://mirror.example.net/base/img.qcow2"

# addrs -> "rc<TAB>stdout"; stderr lands in ${TMP}/policy.err
run_policy() {
    local rc=0 out
    SSRF_TEST_ADDRS="$1" SSRF_TEST_RESOLVE_FAIL="${2:-}"
    export SSRF_TEST_ADDRS SSRF_TEST_RESOLVE_FAIL
    out="$(ssrf_resolve_public_addrs "${URL}" 2>"${TMP}/policy.err")" || rc=$?
    printf '%s\t%s\n' "${rc}" "${out}"
}

echo "── 1. address policy (fail-closed) ──────────────────────────────"

# 1a. Every address public → ALL of them are emitted, IPv4 first.
IFS=$'\t' read -r rc out < <(run_policy "38.145.32.24,152.19.134.198,8.43.85.73")
if [[ "${rc}" == "0" && "${out}" == "mirror.example.net 443 38.145.32.24 152.19.134.198 8.43.85.73" ]]; then
    ok "all-public set: every validated address is emitted (\"${out}\")"
else
    err "all-public set: expected all three addresses, got rc=${rc} out=\"${out}\" — a single-address guard leaves healthy mirrors unused (the live c08e520e defect)"
fi

# 1b. THE regression assertion. A private address anywhere in the set must
#     abort the WHOLE fetch. "Skip the bad one, use a good one" is the
#     DNS-rebinding no-op, and it would show up here as rc=0 + addresses.
IFS=$'\t' read -r rc out < <(run_policy "38.145.32.24,10.0.0.5,8.43.85.73")
if [[ "${rc}" != "0" && -z "${out}" ]]; then
    ok "public+PRIVATE set: refused outright, no address emitted (rebinding defence intact)"
else
    err "public+PRIVATE set: rc=${rc} out=\"${out}\" — the guard SKIPPED the non-public address instead of failing closed; a DNS-rebinding answer set (one public + one internal) would now be fetched from"
fi
if grep -q "10.0.0.5" "${TMP}/policy.err"; then
    ok "refusal names the offending address on stderr"
else
    err "refusal does not name the offending address — diagnosability regression"
fi

# 1c. Order must not matter (a loop that returns on the first PUBLIC hit
#     passes 1b by accident when the private address is last).
IFS=$'\t' read -r rc out < <(run_policy "10.0.0.5,38.145.32.24")
if [[ "${rc}" != "0" && -z "${out}" ]]; then
    ok "PRIVATE-first set: refused outright"
else
    err "PRIVATE-first set: rc=${rc} out=\"${out}\" — expected refusal"
fi

# 1d. The classic SSRF targets, one per policy clause.
for bad in 169.254.169.254 127.0.0.1 ::1 224.0.0.1 0.0.0.0 192.168.1.10 172.16.5.5; do
    IFS=$'\t' read -r rc out < <(run_policy "38.145.32.24,${bad}")
    if [[ "${rc}" != "0" && -z "${out}" ]]; then
        ok "refused resolution set containing ${bad}"
    else
        err "resolution set containing ${bad} was ACCEPTED (rc=${rc} out=\"${out}\")"
    fi
done

# 1e. IPv6 is kept but ordered after IPv4 (baker pod egress is IPv4).
IFS=$'\t' read -r rc out < <(run_policy "2606:2800:220:1:248:1893:25c8:1946,38.145.32.24")
if [[ "${rc}" == "0" && "${out}" == "mirror.example.net 443 38.145.32.24 2606:2800:220:1:248:1893:25c8:1946" ]]; then
    ok "IPv4 ordered before IPv6, IPv6 retained (not dropped)"
else
    err "IPv4/IPv6 ordering wrong: rc=${rc} out=\"${out}\""
fi

# 1f. Unresolvable host → refusal, not an empty success.
IFS=$'\t' read -r rc out < <(run_policy "38.145.32.24" 1)
if [[ "${rc}" != "0" && -z "${out}" ]]; then
    ok "unresolvable host refused"
else
    err "unresolvable host: rc=${rc} out=\"${out}\" — expected refusal"
fi

# Vacuity: the policy tests must actually have gone through the bake
# script's heredoc. If `python3` were never shadowed (function renamed,
# heredoc replaced by a file) this count stays 0 while everything above
# could still be green against a stale binary.
POLICY_CALLS="$(wc -l < "${POLICY_CALLS_FILE}")"
if (( POLICY_CALLS >= 12 )); then
    ok "policy heredoc intercepted ${POLICY_CALLS} times (the bake script's own code ran)"
else
    err "policy heredoc only intercepted ${POLICY_CALLS} times — the tests are not driving the real resolver"
fi
unset -f python3
unset SSRF_TEST_ADDRS SSRF_TEST_RESOLVE_FAIL

echo "── 2. wiring: resolver → transfer ───────────────────────────────"

# The half that keeps getting missed: the resolver may emit N addresses
# and the fetch still use only the first. Record what the transfer loop
# is actually handed.
RECORD="${TMP}/handed.txt"
: > "${RECORD}"
(
    python3() {
        cat > /dev/null
        shift
        printf 'mirror.example.net 443 38.145.32.24 152.19.134.198 8.43.85.73\n'
    }
    ssrf_pinned_fetch_rounds() { printf '%s\n' "$*" > "${RECORD}"; return 0; }
    ssrf_safe_https_fetch "${URL}" "${TMP}/out.bin"
)
handed="$(cat "${RECORD}")"
if [[ "${handed}" == "${URL} ${TMP}/out.bin mirror.example.net 443 38.145.32.24 152.19.134.198 8.43.85.73" ]]; then
    ok "all 3 validated addresses forwarded to the transfer loop"
else
    err "transfer loop received \"${handed}\" — the resolver validated 3 addresses and the fetch did not carry them all"
fi

: > "${RECORD}"
rc=0
(
    python3() { cat > /dev/null; shift; echo "non-public address in resolution set: 10.0.0.5" >&2; exit 1; }
    ssrf_pinned_fetch_rounds() { printf 'CALLED\n' > "${RECORD}"; return 0; }
    ssrf_safe_https_fetch "${URL}" "${TMP}/out.bin"
) 2>/dev/null || rc=$?
if [[ "${rc}" == "2" && ! -s "${RECORD}" ]]; then
    ok "guard refusal short-circuits: rc=2 (distinct from a transfer failure) and NOTHING was fetched"
else
    err "guard refusal: rc=${rc} transfer-called=\"$(cat "${RECORD}")\" — expected rc=2 and no transfer"
fi

echo "── 3. transfer loop against real curl + real sockets ────────────"

# Three HTTP servers on loopback aliases, same port:
#   127.0.0.1 truncates (Content-Length promises N, sends N/4, closes)
#   127.0.0.2 serves the payload completely
#   127.0.0.3 truncates
#   127.0.0.4 answers 302 (must be refused by --max-redirs 0)
cat > "${TMP}/server.py" <<'SERVER'
import hashlib
import os
import socket
import sys
import threading

TMP = sys.argv[1]
PAYLOAD = (b"hippius-ssrf-fetch-test-payload-block\n" * 30000)
with open(os.path.join(TMP, "payload.bin"), "wb") as fh:
    fh.write(PAYLOAD)

MODES = {
    "127.0.0.1": "truncate",
    "127.0.0.2": "full",
    "127.0.0.3": "truncate",
    "127.0.0.4": "redirect",
}


def serve(sock, mode):
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=handle, args=(conn, mode), daemon=True).start()


def handle(conn, mode):
    try:
        conn.recv(65536)
        if mode == "redirect":
            conn.sendall(b"HTTP/1.1 302 Found\r\n"
                         b"Location: http://169.254.169.254/latest/meta-data/\r\n"
                         b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            return
        conn.sendall(b"HTTP/1.1 200 OK\r\n"
                     b"Content-Type: application/octet-stream\r\n"
                     b"Content-Length: %d\r\nConnection: close\r\n\r\n"
                     % len(PAYLOAD))
        if mode == "full":
            conn.sendall(PAYLOAD)
        else:
            # Promise N bytes, deliver N/4, hang up: this is curl exit 18,
            # the class `--retry` does NOT cover.
            conn.sendall(PAYLOAD[: len(PAYLOAD) // 4])
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


port = 0
socks = {}
for attempt in range(40):
    socks = {}
    try:
        for addr in MODES:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((addr, port))
            if port == 0:
                port = s.getsockname()[1]
            s.listen(16)
            socks[addr] = s
        break
    except OSError:
        for s in socks.values():
            s.close()
        socks = {}
        port = 0
else:
    sys.exit("could not bind all loopback aliases on a common port")

for addr, s in socks.items():
    threading.Thread(target=serve, args=(s, MODES[addr]), daemon=True).start()

with open(os.path.join(TMP, "sha256"), "w") as fh:
    fh.write(hashlib.sha256(PAYLOAD).hexdigest())
with open(os.path.join(TMP, "port"), "w") as fh:
    fh.write(str(port))
threading.Event().wait()
SERVER

python3 "${TMP}/server.py" "${TMP}" &
SERVER_PID=$!
for _ in $(seq 1 100); do
    [[ -s "${TMP}/port" ]] && break
    sleep 0.1
done
[[ -s "${TMP}/port" ]] || { echo "ssrf-fetch-test: test server never came up" >&2; exit 1; }
PORT="$(cat "${TMP}/port")"
WANT_SHA="$(cat "${TMP}/sha256")"
HOSTNAME_PIN="baker-fetch-test.invalid"
TEST_URL="http://${HOSTNAME_PIN}:${PORT}/base.qcow2"
OUT="${TMP}/base.qcow2"

attempt_fetch() {
    local rc=0
    : > "${LOGFILE}"
    rm -f -- "${OUT}"
    ssrf_pinned_fetch_rounds "${TEST_URL}" "${OUT}" "${HOSTNAME_PIN}" "${PORT}" "$@" || rc=$?
    return "${rc}"
}

# 3a. Control: the harness itself works against a healthy address.
rc=0; attempt_fetch 127.0.0.2 || rc=$?
if [[ "${rc}" == "0" && -f "${OUT}" && "$(sha256sum "${OUT}" | cut -d' ' -f1)" == "${WANT_SHA}" ]]; then
    ok "single healthy address: complete, byte-correct file"
else
    err "single healthy address failed (rc=${rc}) — the test harness is broken, not the code"
fi

# 3b. THE fix. First address truncates; the second must produce a
#     COMPLETE, byte-correct file. With one-address-only behaviour this
#     is exactly the live c08e520e failure.
rc=0; attempt_fetch 127.0.0.1 127.0.0.2 || rc=$?
got=""
[[ -f "${OUT}" ]] && got="$(sha256sum "${OUT}" | cut -d' ' -f1)"
if [[ "${rc}" == "0" && "${got}" == "${WANT_SHA}" ]]; then
    ok "truncating first address → healthy second address yields a complete, correct file"
else
    err "fallback failed: rc=${rc} sha=${got:-<no file>} want=${WANT_SHA} — a truncated mirror still kills the bake"
fi
if grep -q "127.0.0.1" "${LOGFILE}" && grep -q "127.0.0.2" "${LOGFILE}"; then
    ok "both addresses appear in the attempt log"
else
    err "attempt log does not show both addresses being tried: $(cat "${LOGFILE}")"
fi
if grep -q "curl exit 18" "${LOGFILE}"; then
    ok "the truncation surfaced as curl exit 18 in the log (the class --retry does not cover)"
else
    err "curl's exit code is not surfaced per attempt — the misleading-message defect is back: $(cat "${LOGFILE}")"
fi

# 3c. Every address truncates: must fail NON-ZERO and leave NO short file
#     behind for a later step to treat as the image.
rc=0; attempt_fetch 127.0.0.1 127.0.0.3 || rc=$?
if [[ "${rc}" != "0" ]]; then
    ok "all-truncating address set fails non-zero (rc=${rc})"
else
    err "all-truncating address set returned success"
fi
if [[ ! -e "${OUT}" ]]; then
    ok "no partial file left behind after total failure"
else
    err "a $(stat -c %s "${OUT}") byte PARTIAL file survived the failed fetch — a later step would sha256 it as if it were the image"
fi
if grep -q "attempt 2/2" "${LOGFILE}"; then
    ok "the bounded round loop actually re-ran the address list (attempt 2/2 seen)"
else
    err "no second round observed — the rounds bound is not wired: $(cat "${LOGFILE}")"
fi
if grep -q "TRANSFER failed from every validated public address" "${LOGFILE}"; then
    ok "final error names the failure class (TRANSFER, not the guard) and the addresses tried"
else
    err "final error does not distinguish a transfer failure from a guard refusal: $(cat "${LOGFILE}")"
fi

# 3d. Redirects stay forbidden — behaviourally, not by grep. The server
#     redirects at the cloud metadata endpoint, the canonical SSRF target.
rc=0; attempt_fetch 127.0.0.4 || rc=$?
if [[ "${rc}" != "0" && ! -e "${OUT}" ]]; then
    ok "a 302 toward 169.254.169.254 is refused and leaves no file (--max-redirs 0 intact)"
else
    err "the fetch FOLLOWED a redirect (rc=${rc}) — --max-redirs 0 was lost"
fi

kill "${SERVER_PID}" 2>/dev/null || true
SERVER_PID=""

echo "── 4. source invariants that behaviour cannot show ──────────────"

CURL_LINE="$(extract_func ssrf_pinned_fetch_rounds)"
if grep -q -- '--resolve' <<<"${CURL_LINE}"; then
    ok "the transfer still pins with --resolve (curl never re-resolves ⇒ no rebind window)"
else
    err "--resolve is gone from the transfer — curl would re-resolve mid-fetch"
fi
if grep -qE -- '-C[[:space:]]+-' <<<"${CURL_LINE}"; then
    err "the transfer uses \`-C -\` resume: switching mirrors mid-file would concatenate bytes from two sources"
else
    ok "no \`-C -\` resume (each attempt re-fetches from scratch)"
fi
if grep -qE 'rm -f -- "\$\{out\}"' <<<"${CURL_LINE}"; then
    ok "the partial output is deleted around attempts"
else
    err "nothing deletes the partial output between attempts"
fi

# No dev bypass may exist for the guard, ever.
if grep -nEi '(SSRF|GUARD).*(DISABLE|SKIP|BYPASS|ALLOW_PRIVATE)|(DISABLE|SKIP|BYPASS)_?SSRF' "${TARGET}" >/dev/null; then
    err "the bake script contains something that looks like an SSRF-guard bypass switch"
else
    ok "no SSRF-guard bypass switch in the bake script"
fi

# The caller must tell the two failure classes apart — the misdiagnosis
# that cost a live debugging cycle.
CALLER="$(grep -A 14 'https://\*)' "${TARGET}")"
if grep -qE 'die .*ssrf-guard or curl' "${TARGET}"; then
    err "the conflated \"(ssrf-guard or curl)\" message is back — it is why a curl-18 truncation was first blamed on the guard"
else
    ok "the conflated \"(ssrf-guard or curl)\" message is gone"
fi
if grep -q 'REFUSED BY THE SSRF GUARD' <<<"${CALLER}" && grep -q 'TRANSFER failed' <<<"${CALLER}"; then
    ok "the caller reports guard-refusal and transfer-failure as distinct outcomes"
else
    err "the caller does not distinguish a guard refusal from a transfer failure"
fi

# ── Vacuity floor ────────────────────────────────────────────────────
MIN_CHECKS=25
echo "ssrf-fetch-test: ${CHECKS} checks executed"
if (( CHECKS < MIN_CHECKS )); then
    echo "ssrf-fetch-test: only ${CHECKS} checks ran (expected >= ${MIN_CHECKS}) — FAIL, the test is not seeing the code"
    FAILED=1
fi

[[ "${FAILED}" == "0" ]] && echo "ssrf-fetch-test: ALL OK" || echo "ssrf-fetch-test: FAILURES"
exit "${FAILED}"
