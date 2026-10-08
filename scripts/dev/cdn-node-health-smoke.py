#!/usr/bin/env python3
"""Stand in for the cdn-agent on a booted cdn-node root and require health 200.

Run INSIDE the guest (the nightly nspawn smoke, as root, with the real agent
stopped): it pushes what the agent pushes once the backend has answered
(secrets, a throwaway fleet-wildcard certificate, an empty config, a ready
health document) over OpenResty's control socket, keeps the health document
fresh, and polls https://127.0.0.1/__hippius/health with the fleet SNI.

    cdn-node-health-smoke.py <min-seconds-since-openresty-start> <timeout-seconds>

nginx's cache loader runs a minute after nginx starts (a canary inside the
cache tree used to be deleted then, and a rewrite only hides that for a few
seconds), so it succeeds only on an UNBROKEN run of 200s that starts before
LOADER_AT seconds of OpenResty uptime and lasts past the given minimum. It
restarts OpenResty first if it has already been up too long for that.
"""
import http.client
import json
import socket
import ssl
import subprocess
import sys
import time

CTL = "/run/cdn/ctl.sock"
# Seconds after nginx's start at which its cache loader process runs.
LOADER_AT = 60
UNIT = "hippius-cdn-openresty.service"
WILDCARD = "*.c.hipcdn.net"
WORK = "/run/cdn-health-smoke"


def put(name: str, doc: dict) -> int:
    body = json.dumps(doc).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(CTL)
    s.sendall(
        f"PUT /v1/{name} HTTP/1.1\r\nHost: ctl\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
    )
    r = http.client.HTTPResponse(s)
    r.begin()
    r.read()
    s.close()
    return r.status


def health() -> tuple[int, str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", 443), 5)
    s = ctx.wrap_socket(raw, server_hostname="health.c.hipcdn.net")
    s.sendall(b"GET /__hippius/health HTTP/1.1\r\nHost: health.c.hipcdn.net\r\nConnection: close\r\n\r\n")
    r = http.client.HTTPResponse(s)
    r.begin()
    body = r.read().decode(errors="replace").strip()
    s.close()
    return r.status, body


def openresty_uptime() -> float:
    out = subprocess.run(
        ["systemctl", "show", "-p", "ActiveEnterTimestampMonotonic", "--value",
         UNIT],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    started_us = int(out or "0")
    if started_us == 0:
        return 0.0
    return time.clock_gettime(time.CLOCK_MONOTONIC) - started_us / 1e6


def push_all() -> None:
    subprocess.run(["install", "-d", "-m", "0700", WORK], check=True)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-days", "2", "-subj", f"/CN={WILDCARD}",
         "-addext", f"subjectAltName=DNS:{WILDCARD}",
         "-keyout", f"{WORK}/w.key", "-out", f"{WORK}/w.pem"],
        check=True, capture_output=True,
    )
    with open(f"{WORK}/w.pem") as c, open(f"{WORK}/w.key") as k:
        chain, key = c.read(), k.read()
    statuses = {
        "secrets": put("secrets", {"zones": {}}),
        "certs": put("certs", {"default": WILDCARD, "certs": {
            WILDCARD: {"chain_pem": chain, "key_pem": key, "not_after": 0}}}),
        "config": put("config", {
            "revision": 1, "compression": ["gzip"], "fleet_wildcard": WILDCARD,
            "draining": False, "zones": {}, "hostnames": {}, "purges": {},
            "blocks": [], "acme_http01": {}, "peers": []}),
        "health": put("health", {"ready": True, "at": int(time.time())}),
    }
    print(f"control pushes: {statuses}", flush=True)
    if any(v != 204 for v in statuses.values()):
        sys.exit("a control push was refused")


def restart_openresty() -> None:
    print("restarting OpenResty so the run spans its cache loader", flush=True)
    subprocess.run(["systemctl", "restart", UNIT], check=True)
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            put("health", {"ready": True, "at": int(time.time())})
            return
        except OSError:
            time.sleep(0.5)
    sys.exit("OpenResty's control socket did not come back")


def main() -> None:
    min_uptime, timeout = float(sys.argv[1]), float(sys.argv[2])
    if openresty_uptime() > LOADER_AT - 30:
        restart_openresty()
    push_all()
    deadline = time.time() + timeout
    streak_from = None  # uptime of the first 200 of the current run
    last = (0, "no answer")
    while time.time() < deadline:
        put("health", {"ready": True, "at": int(time.time())})
        try:
            last = health()
        except OSError as e:
            last = (0, f"{type(e).__name__}: {e}")
        up = openresty_uptime()
        if last[0] != 200:
            if streak_from is not None:
                sys.exit(f"health went {last[0]} at {up:.0f} s of uptime after 200s since "
                         f"{streak_from:.0f} s: {last[1]}")
        elif streak_from is None:
            if up >= LOADER_AT:
                sys.exit(f"first 200 only at {up:.0f} s of uptime: the run cannot span the "
                         "cache loader")
            streak_from = up
        elif up >= min_uptime:
            print(f"HEALTH 200 unbroken from {streak_from:.0f} s to {up:.0f} s of OpenResty "
                  f"uptime: {last[1]}", flush=True)
            return
        time.sleep(2)
    sys.exit(f"health never 200 through {min_uptime:.0f} s of uptime; last: {last[0]} {last[1]}")


if __name__ == "__main__":
    main()
