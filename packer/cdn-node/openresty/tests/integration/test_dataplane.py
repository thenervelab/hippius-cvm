#!/usr/bin/env python3
"""Integration tests: the real OpenResty build against a mock agent and a
mock S3 origin (CDN plan I2).

    OPENRESTY_PREFIX=/opt/openresty python3 -I test_dataplane.py

The mock agent pushes control documents over the Unix control socket and
collects metering datagrams; the mock origin serves objects and checks
every request: method, headers, path and an independent SigV4
verification. Standard library only (plus the `openssl` CLI for test
certificates).
"""

import base64
import datetime
import gzip
import hashlib
import hmac
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
PREFIX = os.environ.get("OPENRESTY_PREFIX", "/opt/openresty")
NGINX = os.path.join(PREFIX, "nginx", "sbin", "nginx")

ACCESS = "AKTESTCDNNODE"
# A test-only value for the mock origin; not a credential anywhere.
SIGNING_MATERIAL = "test-signing-material-for-the-mock-origin"
REGION = "us-east-1"
# settings.canary_interval: how often worker 0 re-checks the canary.
CANARY_TICK = 10
EMPTY = hashlib.sha256(b"").hexdigest()

TEXT = ("hello from the origin\n" * 64).encode()
OBJECTS = {
    "/media/site/a/b.txt": (TEXT, "text/plain"),
    "/media/site/a/c.txt": (b"c-object", "text/plain"),
    "/media/site/img/x.png": (b"\x89PNG-bytes", "image/png"),
    "/media/site/img/x.png.bak": (b"backup", "image/png"),
    "/media/site/bad.bin": (b"blocked", "application/octet-stream"),
    "/private/k/doc.txt": (b"private-object", "text/plain"),
    "/private/sub.txt": (b"private-subtoken-object", "text/plain"),
    "/media/site/a%20b.txt": (b"spaced", "text/plain"),
    "/media/site/cookie.txt": (b"with-cookie", "text/plain"),
    "/media/site/accel.txt": (b"accel-object", "text/plain"),
    "/media/site/big.bin": (bytes(range(256)) * (3 * 4096 + 7), "application/octet-stream"),
    "/media/site/empty.txt": (b"", "text/plain"),
    "/media/site/bw.bin": (bytes(range(256)) * 1200, "application/octet-stream"),
    "/media/site/bw-big.bin": (bytes(range(256)) * 16384, "application/octet-stream"),
    # Answered like the production S3 gateway answers a private object
    # (GATEWAY_HEADERS), with the declared type below (None: no header).
    "/media/site/gw/cdn-test.html": (b"<p>hi</p>", "text/html"),
    "/media/site/gw/page.html": (b"<p>no type</p>", None),
    "/media/site/gw/style.css": (b"p{}", "binary/octet-stream"),
    "/media/site/gw/app.js": (b"1;", None),
    "/media/site/gw/data.json": (b"{}", "application/octet-stream"),
    "/media/site/gw/logo.png": (b"\x89PNG", "application/octet-stream"),
    "/media/site/gw/logo.svg": (b"<svg/>", "application/octet-stream"),
    "/media/site/gw/blob.unknownext": (b"??", None),
    "/media/site/gw/x.xhtml": (b"<html/>", "application/xhtml+xml"),
    "/media/site/gw/declared.svg": (b"<svg/>", "image/svg+xml"),
    "/media/site/gw/t.xml": (b"<a/>", "text/xml"),
    "/media/site/gw/a.xml": (b"<a/>", "application/xml"),
}
# Zone z1's cache rules (feed `settings.rules`), in order: the first
# matching rule wins, whole (contract C.4). The last one is unusable and
# must be ignored without failing anything.
RULES = [
    {"match": {"path_prefix": "/r/short/"}, "actions": {"edge_ttl": 2, "browser_ttl": 30}},
    {"match": {"glob": "*.nocache"}, "actions": {"edge_ttl": 0}},
    {"match": {"extensions": ["dat"]}, "actions": {"bypass": True}},
    {"match": {"path_prefix": "/r/qs/"}, "actions": {"query_string": {"whitelist": ["v"]}}},
    {"match": {"path_prefix": "/r/origin/"}, "actions": {"edge_ttl": "origin"}},
    {"match": {"path_prefix": "/r/"}, "actions": {"edge_ttl": 600, "browser_ttl": None}},
    {"match": {"regex": ".*"}, "actions": {"edge_ttl": 1}},
]
# Objects of the cache-rule test, and the Cache-Control the origin sends
# (default: max-age=3600).
for _p in ("short/a.txt", "x.nocache", "clip.dat", "qs/a.txt", "origin/two.txt",
           "origin/private.txt", "origin/nostore.txt", "other.txt"):
    OBJECTS["/media/site/r/" + _p] = (b"rule-" + _p.encode(), "text/plain")
# The origin tries to set its own edge TTL: ignored (the default hour stands).
OBJECTS["/media/site/accel-expires.txt"] = (b"origin-ttl", "text/plain")
ORIGIN_CACHE_CONTROL = {
    "/media/site/r/origin/two.txt": "max-age=2",
    "/media/site/r/origin/private.txt": "private, no-store",
    "/media/site/r/origin/nostore.txt": "no-store",
}
GATEWAY_HEADERS = [
    ("Cache-Control", "private, no-store"), ("Expires", "Thu, 01 Jan 1970 00:00:00 GMT"),
    ("Vary", "Origin"), ("Server", "hippius-s3"), ("Set-Cookie", "gw=1"),
    ("ETag", '"0123abcd"'), ("Last-Modified", "Wed, 07 Oct 2026 10:00:00 GMT"),
    ("Accept-Ranges", "bytes"), ("Content-Disposition", "inline"),
    ("x-hippius-source", "pipeline"), ("x-hippius-api-time-ms", "12"),
    ("x-hippius-ray-id", "ray-1"), ("x-hippius-body-blake3", "b3"),
    ("x-hippius-body-blake3-chunk", "b3c"), ("x-amz-meta-original-name", "cdn-test.html"),
    ("Age", "5000"),
]
MOVED_PATH = "/media/site/gw/moved.txt"
# What a client may see on a 200 (lower case).
CLIENT_HEADERS = {"content-type", "content-length", "content-range", "content-encoding",
                  "content-language", "content-disposition", "etag", "last-modified",
                  "accept-ranges", "x-cache", "cache-control", "x-content-type-options",
                  "content-security-policy",
                  "date", "connection", "vary"}
ERROR_PATH = "/media/site/err.txt"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── mock S3 origin ───────────────────────────────────────────────────


def _hmac(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _q(v):
    return urllib.parse.quote(v, safe="-_.~")


def verify_presigned(method, path, query, headers):
    """Independent check of a presigned (query-string) SigV4 GET; returns a
    reason string on failure, None on success."""
    params = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
    sig = params.pop("X-Amz-Signature", None)
    if not sig or params.get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256":
        return "no-signature"
    cred = params.get("X-Amz-Credential", "").split("/")
    if len(cred) != 5 or cred[0] != ACCESS or cred[2] != REGION or cred[3] != "s3":
        return "credential"
    if params.get("X-Amz-SignedHeaders") != "host":
        return "signed-headers"
    amz_date = params.get("X-Amz-Date", "")
    signed_at = datetime.datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
    if datetime.datetime.now(datetime.timezone.utc) > signed_at + datetime.timedelta(seconds=int(params["X-Amz-Expires"])):
        return "expired"
    canon_q = "&".join(f"{_q(k)}={_q(v)}" for k, v in sorted(params.items()))
    creq = "\n".join([method, path, canon_q, f"host:{headers.get('host', '')}\n", "host", "UNSIGNED-PAYLOAD"])
    scope = f"{amz_date[:8]}/{REGION}/s3/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = _hmac(("AWS4" + SIGNING_MATERIAL).encode(), amz_date[:8])
    for part in (REGION, "s3", "aws4_request"):
        k = _hmac(k, part)
    want = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, sig):
        return "signature"
    return None


class Origin(BaseHTTPRequestHandler):
    log = []
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        path, _, query = self.path.partition("?")
        headers = {k.lower(): v for k, v in self.headers.items()}
        entry = {"method": self.command, "path": path, "query": query, "headers": headers}
        bucket = path.split("/")[1] if path.count("/") >= 1 else ""
        if query:
            entry["sig"] = verify_presigned("GET", path, query, headers)
        elif bucket == "private":
            entry["sig"] = "missing"
        Origin.log.append(entry)
        if entry.get("sig"):
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path.endswith("/reset.txt"):
            # Drop the connection without an answer: nginx logs an
            # upstream error naming the upstream URL.
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        if path == MOVED_PATH:
            body = b"<Error><Code>PermanentRedirect</Code><Endpoint>s3.internal.example</Endpoint></Error>"
            self.send_response(301)
            self.send_header("Location", "https://elsewhere.example/steal")
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == ERROR_PATH:
            body = b"<Error><Code>AccessDenied</Code><BucketName>media</BucketName></Error>"
            self.send_response(403)
            self.send_header("Cache-Control", "max-age=3600")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        obj = OBJECTS.get(path)
        if obj is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body, ctype = obj
        rng = self.headers.get("Range")
        if rng and not body:
            # S3: a ranged GET on an empty object is 416.
            self.send_response(416)
            self.send_header("Content-Range", "bytes */0")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if rng and rng.startswith("bytes="):
            start, _, end = rng[6:].partition("-")
            start = int(start)
            end = min(int(end) if end else len(body) - 1, len(body) - 1)
            total = len(body)
            body = body[start:end + 1]
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{total}")
        else:
            self.send_response(200)
        if ctype is not None:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if "/gw/" in path:
            for k, v in GATEWAY_HEADERS:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
            return
        if path.endswith("/accel.txt"):
            self.send_header("X-Accel-Redirect", "/.well-known/hippius-attestation")
        if path.endswith("/accel-expires.txt"):
            self.send_header("X-Accel-Expires", "1")
            self.send_header("X-Hippius-TTL", "5")
        self.send_header("Cache-Control", ORIGIN_CACHE_CONTROL.get(path, "max-age=3600"))
        if path.endswith("/cookie.txt"):
            self.send_header("Set-Cookie", "origin=1")
        self.send_header("x-amz-request-id", "REQ123")
        self.end_headers()
        self.wfile.write(body)


# ── harness ──────────────────────────────────────────────────────────


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self.unix_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.unix_path)


def openssl_cert(work, name, sans):
    cert = os.path.join(work, f"{name}.pem")
    key = os.path.join(work, f"{name}.key")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-days", "30", "-subj", f"/CN={sans[0]}", "-keyout", key, "-out", cert,
         "-addext", "subjectAltName=" + ",".join("DNS:" + s for s in sans)],
        check=True, capture_output=True)
    with open(cert) as c, open(key) as k:
        return c.read(), k.read(), cert


class DataPlane(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.mkdtemp(prefix="cdn-dataplane-")
        w = cls.work
        for d in ("tmp", "cache", "run", "agent"):
            os.makedirs(os.path.join(w, d))
        # The generated test database (tests/geoip/make_test_mmdb.py), copied
        # so a test can corrupt it.
        cls.geoip_src = os.path.join(os.environ["HIPPIUS_TEST_GEOIP_DIR"], "geo-24.mmdb")
        shutil.copy(cls.geoip_src, os.path.join(w, "geoip.mmdb"))

        cls.origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        threading.Thread(target=cls.origin.serve_forever, daemon=True).start()
        origin_host = f"127.0.0.1:{cls.origin.server_address[1]}"

        cls.wild_chain, cls.wild_key, wild_file = openssl_cert(w, "wild", ["*.cdn.hippius.com"])
        cls.img_chain, cls.img_key, img_file = openssl_cert(w, "img", ["img.example.com", "dl.example.com"])
        cls.cafile = os.path.join(w, "ca.pem")
        with open(cls.cafile, "w") as f:
            f.write(cls.wild_chain + cls.img_chain)

        cls.http_port, cls.https_port = free_port(), free_port()
        cls.ctl = os.path.join(w, "run", "ctl.sock")
        cls.meter_path = os.path.join(w, "agent", "meter.sock")
        cls.meter = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        cls.meter.bind(cls.meter_path)
        cls.meter.settimeout(0.2)
        cls.records = []
        cls.stop = threading.Event()
        threading.Thread(target=cls._collect, daemon=True).start()

        with open(os.path.join(w, "origin.conf"), "w") as f:
            f.write(f'map $host $hippius_s3_scheme {{ default "http"; }}\n'
                    f'map $host $hippius_s3_host {{ default "{origin_host}"; }}\n')
        render = os.path.join(ROOT, "render.sh")
        subprocess.run([render, "cache", os.path.join(w, "cache.conf"), os.path.join(w, "cache"), "64m", "8m"], check=True)
        subprocess.run([render, "placeholder", os.path.join(w, "run", "ph.pem"), os.path.join(w, "run", "ph.key")], check=True)
        subprocess.run([
            render, "conf", os.path.join(ROOT, "nginx.conf.in"), os.path.join(w, "nginx.conf"),
            f"PREFIX={PREFIX}", f"PID={w}/nginx.pid", f"TEMP_DIR={w}/tmp",
            f"LUA_DIR={ROOT}/lua", "DOCS_DICT_SIZE=32m", f"METER_SOCKET={cls.meter_path}",
            f"CACHE_DIR={w}/cache", f"S3_REGION={REGION}", "RESOLVER=127.0.0.1",
            f"CACHE_CONF={w}/cache.conf", f"ORIGIN_CONF={w}/origin.conf", "RATE_PER_IP=1000r/s",
            f"CTL_SOCKET={cls.ctl}", "CTL_MAX_BODY=16m", f"LISTEN_HTTP=127.0.0.1:{cls.http_port}",
            f"LISTEN_HTTPS=127.0.0.1:{cls.https_port}", f"PLACEHOLDER_CERT={w}/run/ph.pem",
            f"PLACEHOLDER_KEY={w}/run/ph.key", "BURST_PER_IP=2000", "CONN_PER_IP=512",
            f"CA_BUNDLE={cls.cafile}", f"GEOIP_DB={w}/geoip.mmdb",
            f"ORIGIN_SOCKET={w}/run/origin.sock",
        ], check=True)
        cls.start_nginx()

    @classmethod
    def start_nginx(cls):
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = os.path.join(PREFIX, "luajit", "lib")
        cls.err_path = os.path.join(cls.work, "nginx.err")
        cls.err = open(cls.err_path, "ab")
        cls.nginx = subprocess.Popen(
            [NGINX, "-e", "stderr", "-p", cls.work, "-c", os.path.join(cls.work, "nginx.conf"),
             "-g", "daemon off;"], env=env, stderr=cls.err)
        for _ in range(100):
            if os.path.exists(cls.ctl):
                try:
                    socket.create_connection(("127.0.0.1", cls.https_port), 1).close()
                    return
                except OSError:
                    pass
            time.sleep(0.05)
        raise RuntimeError("nginx did not start")

    @classmethod
    def stop_nginx(cls):
        cls.nginx.terminate()
        cls.nginx.wait(10)

    @classmethod
    def tearDownClass(cls):
        cls.stop.set()
        cls.stop_nginx()
        cls.origin.shutdown()
        shutil.rmtree(cls.work, ignore_errors=True)

    @classmethod
    def _collect(cls):
        while not cls.stop.is_set():
            try:
                cls.records.append(json.loads(cls.meter.recv(4096)))
            except socket.timeout:
                continue
            except OSError:
                return

    # ── helpers ──

    def put(self, name, doc):
        conn = UnixHTTPConnection(self.ctl)
        body = doc if isinstance(doc, (bytes, str)) else json.dumps(doc)
        conn.request("PUT", f"/v1/{name}", body=body, headers={"Content-Type": "application/json"})
        r = conn.getresponse()
        r.read()
        conn.close()
        return r.status

    def config(self, **over):
        c = {
            "revision": 10, "compression": ["gzip"], "fleet_wildcard": "*.cdn.hippius.com",
            "draining": False,
            "zones": {
                "z1": {"state": "active", "serving": True, "refusal": None,
                       "origin": {"type": "s3", "bucket": "media", "prefix": "site/"},
                       "shield_region": "FR", "settings": {"rules": RULES}, "secrets": []},
                "z2": {"state": "paused", "serving": True, "refusal": None,
                       "origin": {"type": "s3", "bucket": "media"}, "shield_region": None,
                       "settings": {}, "secrets": []},
                "z3": {"state": "active", "serving": False, "refusal": "origin-kind-not-supported",
                       "origin": {"type": "http", "host": "169.254.169.254"}, "shield_region": None,
                       "settings": {}, "secrets": []},
                "z4": {"state": "suspended", "serving": True, "refusal": None,
                       "origin": {"type": "s3", "bucket": "media"}, "shield_region": None,
                       "settings": {}, "secrets": []},
                "zp": {"state": "active", "serving": True, "refusal": None,
                       "origin": {"type": "s3", "bucket": "private", "prefix": "k/"},
                       "shield_region": None, "settings": {}, "secrets": ["s3_credentials"]},
                # The prod shape: a private bucket at its root.
                "zq": {"state": "active", "serving": True, "refusal": None,
                       "origin": {"type": "s3", "bucket": "private", "prefix": ""},
                       "shield_region": None, "settings": {}, "secrets": ["s3_credentials"]},
                # Ceilings (settings.limits): 3 requests a second; 1 Mbit/s; none.
                "zl": {"state": "active", "serving": True, "refusal": None,
                       "origin": {"type": "s3", "bucket": "media", "prefix": "site/"}, "shield_region": None,
                       "settings": {"limits": {"max_mbps": 2000, "max_rps": 3}}, "secrets": []},
                "zb": {"state": "active", "serving": True, "refusal": None,
                       "origin": {"type": "s3", "bucket": "media", "prefix": "site/"}, "shield_region": None,
                       "settings": {"limits": {"max_mbps": 1, "max_rps": 20000}}, "secrets": []},
                # 12 Mbit/s = 1.5 MB/s: above one 1 MiB slice, below 4 MiB.
                "zs": {"state": "active", "serving": True, "refusal": None,
                       "origin": {"type": "s3", "bucket": "media", "prefix": "site/"}, "shield_region": None,
                       "settings": {"limits": {"max_mbps": 9, "max_rps": 20000}}, "secrets": []},
                "z0": {"state": "active", "serving": True, "refusal": None,
                       "origin": {"type": "s3", "bucket": "media", "prefix": "site/"}, "shield_region": None,
                       "settings": {"limits": {"max_mbps": 2000, "max_rps": 0}}, "secrets": []},
                "zr": {"state": "active", "serving": True, "refusal": None,
                       "origin": {"type": "s3", "bucket": "media"}, "shield_region": None,
                       "settings": {}, "secrets": []},
            },
            "hostnames": {
                "img.example.com": "z1", "z1.cdn.hippius.com": "z1", "dl.example.com": "zp",
                "paused.cdn.hippius.com": "z2", "refused.cdn.hippius.com": "z3",
                "susp.cdn.hippius.com": "z4", "root.cdn.hippius.com": "zr",
                "priv.cdn.hippius.com": "zq",
                "lim.cdn.hippius.com": "zl", "bw.cdn.hippius.com": "zb", "zero.cdn.hippius.com": "z0",
                "slices.cdn.hippius.com": "zs",
            },
            "purges": {"z1": {"zone_generation": 1, "prefixes": {}}},
            "blocks": [{"kind": "path", "value": "/bad.bin", "zone_id": "z1"},
                       {"kind": "prefix", "value": "/forbidden/"}],
            "acme_http01": {"tok_ABC-1": "tok_ABC-1.thumbprint_x"},
            "peers": [],
        }
        c.update(over)
        return c

    def push_all(self, health_ready=True, **over):
        self.assertEqual(self.put("secrets", {"zones": {"zp": {"s3_credentials": json.dumps(
            {"access_key_id": ACCESS, "secret_access_key": SIGNING_MATERIAL})}}}), 204)
        self.assertEqual(self.put("certs", {"default": "*.cdn.hippius.com", "certs": {
            "*.cdn.hippius.com": {"chain_pem": self.wild_chain, "key_pem": self.wild_key, "not_after": 0},
            "img.example.com": {"chain_pem": self.img_chain, "key_pem": self.img_key, "not_after": 0},
            "dl.example.com": {"chain_pem": self.img_chain, "key_pem": self.img_key, "not_after": 0},
        }}), 204)
        self.assertEqual(self.put("config", self.config(**over)), 204)
        self.assertEqual(self.put("health", {"ready": health_ready, "at": int(time.time())}), 204)

    def log_count(self, needle):
        with open(self.err_path, "rb") as f:
            return f.read().count(needle.encode())

    def wait_log(self, needle, count, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.log_count(needle) >= count:
                return True
            time.sleep(0.2)
        return False

    def wait_health(self, status, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.put("health", {"ready": True, "at": int(time.time())})
            if self.https("health.cdn.hippius.com", "/__hippius/health")[0] == status:
                return True
            time.sleep(0.5)
        return False

    def https(self, sni, path, host=None, headers=None, method="GET"):
        ctx = ssl.create_default_context(cafile=self.cafile)
        raw = socket.create_connection(("127.0.0.1", self.https_port), 5)
        s = ctx.wrap_socket(raw, server_hostname=sni)
        hdrs = {"Host": host or sni, "Connection": "close"}
        hdrs.update(headers or {})
        req = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        s.sendall(req.encode())
        r = http.client.HTTPResponse(s)
        r.begin()
        body = r.read()
        s.close()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, body

    def http(self, host, path, method="GET"):
        conn = http.client.HTTPConnection("127.0.0.1", self.http_port, timeout=5)
        conn.request(method, path, headers={"Host": host})
        r = conn.getresponse()
        body = r.read()
        conn.close()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, body

    def origin_hits(self, path):
        return [e for e in Origin.log if e["path"] == path]

    def records_for(self, status, zone=None, wait=1.0):
        deadline = time.time() + wait
        while time.time() < deadline:
            found = [r for r in self.records if r["status"] == status and r.get("zone") == zone]
            if found:
                return found
            time.sleep(0.05)
        return []

    # ── tests (run in name order; the "a" test seeds the documents) ──

    def test_a_control_socket_contract(self):
        self.assertEqual(self.put("health", {"ready": True, "at": int(time.time())}), 409,
                         "empty shared memory asks for a resync")
        self.assertEqual(self.put("config", "{not json"), 400)
        self.assertEqual(self.put("config", self.config(revision="x")), 400)
        self.assertEqual(self.put("nonsense", "{}"), 404)
        conn = UnixHTTPConnection(self.ctl)
        conn.request("GET", "/v1/config")
        self.assertEqual(conn.getresponse().status, 405)
        conn.close()
        self.push_all()

    def test_b_cache_miss_then_hit_and_clean_origin_request(self):
        st, h, body = self.https("img.example.com", "/a/b.txt?x=1&evil=2",
                                 headers={"X-Evil": "1", "Cookie": "s=1", "Authorization": "Basic Zm9v"})
        self.assertEqual(st, 200)
        self.assertEqual(body, TEXT)
        self.assertEqual(h.get("x-cache"), "MISS")
        self.assertNotIn("x-amz-request-id", h)
        st, h, body = self.https("img.example.com", "/a/b.txt?other=3")
        self.assertEqual((st, h.get("x-cache"), body), (200, "HIT", TEXT), "query is not part of the key")
        hits = self.origin_hits("/media/site/a/b.txt")
        self.assertEqual(len(hits), 1)
        sent = hits[0]["headers"]
        self.assertEqual(hits[0]["method"], "GET")
        self.assertEqual(hits[0]["query"], "", "the client query string reached the origin")
        for forbidden in ("x-evil", "cookie", "authorization", "accept-encoding", "user-agent"):
            self.assertNotIn(forbidden, sent, f"client header {forbidden} reached the origin")
        # Set-Cookie never reaches the client, so the response is cached
        # like any other.
        for want in ("MISS", "HIT"):
            st, h, _ = self.https("img.example.com", "/cookie.txt")
            self.assertEqual((st, h.get("x-cache")), (200, want))
            self.assertNotIn("set-cookie", h)
        # Another hostname of the same zone shares the cached object.
        st, h, _ = self.https("z1.cdn.hippius.com", "/a/b.txt")
        self.assertEqual((st, h.get("x-cache")), (200, "HIT"))

    def test_bb_gateway_headers_cache_and_types(self):
        # The gateway's "private, no-store" does not stop caching: the
        # lifetime is the zone's.
        for want in ("MISS", "HIT"):
            st, h, body = self.https("img.example.com", "/gw/cdn-test.html")
            self.assertEqual((st, body, h.get("x-cache")), (200, b"<p>hi</p>", want))
        self.assertEqual(len(self.origin_hits("/media/site/gw/cdn-test.html")), 1)
        # Only the allowlist reaches the client.
        self.assertLessEqual(set(h), CLIENT_HEADERS, set(h) - CLIENT_HEADERS)
        for gone in ("server", "set-cookie", "expires", "age", "x-hippius-source", "x-hippius-api-time-ms",
                     "x-hippius-ray-id", "x-hippius-body-blake3", "x-hippius-body-blake3-chunk",
                     "x-amz-meta-original-name"):
            self.assertNotIn(gone, h)
        self.assertNotIn("origin", h.get("vary", "").lower())
        self.assertEqual(h["cache-control"], "public, max-age=3600")
        self.assertEqual(h["x-content-type-options"], "nosniff")
        self.assertEqual((h["etag"], h["accept-ranges"], h["content-disposition"]),
                         ('"0123abcd"', "bytes", "inline"))
        # Declared HTML is the origin's choice and is kept.
        self.assertEqual(h["content-type"], "text/html")
        # No type, or a generic one: by extension, never to HTML or SVG.
        for path, want in (("/gw/style.css", "text/css"), ("/gw/app.js", "application/javascript"),
                           ("/gw/data.json", "application/json"), ("/gw/logo.png", "image/png"),
                           ("/gw/page.html", "application/octet-stream"),
                           ("/gw/logo.svg", "application/octet-stream"),
                           ("/gw/blob.unknownext", "application/octet-stream")):
            st, h, _ = self.https("img.example.com", path)
            self.assertEqual((st, h.get("content-type")), (200, want), path)
            self.assertEqual(h.get("x-content-type-options"), "nosniff", path)
        # nosniff on everything else too: errors, refusals, our endpoints.
        for host, path in (("img.example.com", "/gw/missing.txt"), ("nope.example.org", "/x"),
                           ("health.cdn.hippius.com", "/__hippius/health"),
                           ("img.example.com", "/.well-known/acme-challenge/nope")):
            st, h, _ = self.https(host, path) if not host.startswith("nope") else self.https(
                "img.example.com", path, host=host)
            self.assertEqual(h.get("x-content-type-options"), "nosniff", (host, path, st))
        st, h, _ = self.http("img.example.com", "/gw/style.css")
        self.assertEqual((st, h.get("x-content-type-options")), (301, "nosniff"))
        self.assertTrue(h["location"].startswith("https://img.example.com/"))
        self.assertNotIn("server", h)
        # nginx's own error pages (here: no Host) carry nosniff too.
        with socket.create_connection(("127.0.0.1", self.http_port), 5) as s:
            s.sendall(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
            raw = b""
            while chunk := s.recv(4096):
                raw += chunk
        head = raw.split(b"\r\n\r\n", 1)[0].lower()
        self.assertTrue(head.startswith(b"http/1.1 400"), head)
        self.assertIn(b"x-content-type-options: nosniff", head)
        self.assertNotIn(b"server:", head)

    def test_bd_script_capable_types_are_sandboxed(self):
        # On the fleet's domain, declared HTML, XHTML, SVG and XML run in an
        # opaque origin.
        for path, ctype in (("/gw/cdn-test.html", "text/html"), ("/gw/x.xhtml", "application/xhtml+xml"),
                            ("/gw/declared.svg", "image/svg+xml"), ("/gw/t.xml", "text/xml"),
                            ("/gw/a.xml", "application/xml")):
            st, h, _ = self.https("z1.cdn.hippius.com", path)
            self.assertEqual((st, h.get("content-type")), (200, ctype), path)
            self.assertEqual(h.get("content-security-policy"), "sandbox allow-scripts", path)
        # Anything else carries no policy, the fallback's octet-stream included.
        for path in ("/gw/style.css", "/gw/app.js", "/gw/logo.png", "/gw/page.html"):
            st, h, _ = self.https("z1.cdn.hippius.com", path)
            self.assertEqual(st, 200, path)
            self.assertNotIn("content-security-policy", h, path)
        # A custom domain is the customer's own site: not sandboxed.
        st, h, _ = self.https("img.example.com", "/gw/cdn-test.html")
        self.assertEqual((st, h.get("content-type")), (200, "text/html"))
        self.assertNotIn("content-security-policy", h)

    def test_bc_origin_redirect_is_generic_and_never_cached(self):
        for _ in range(2):
            st, h, body = self.https("img.example.com", "/gw/moved.txt")
            self.assertEqual((st, body), (301, b"301\n"))
            self.assertNotIn("location", h)
            self.assertEqual(h.get("cache-control"), "no-store")
            self.assertEqual(h.get("content-type"), "text/plain")
        self.assertEqual(len(self.origin_hits(MOVED_PATH)), 2, "an origin redirect was cached")

    def test_be_zone_cache_rules(self):
        def get(path):
            st, h, body = self.https("img.example.com", path)
            self.assertEqual(st, 200, (path, body))
            return h.get("x-cache"), h.get("cache-control")

        def hits(path):
            return len(self.origin_hits("/media/site" + path))

        # The origin's own X-Accel-Expires (and X-Hippius-TTL) is ignored:
        # still a HIT after its 1 s, with the default hour.
        self.assertEqual(get("/accel-expires.txt"), ("MISS", "public, max-age=3600"))
        # edge_ttl 2 + browser_ttl 30: cached, then expired at the edge.
        self.assertEqual(get("/r/short/a.txt"), ("MISS", "public, max-age=30"))
        self.assertEqual(get("/r/short/a.txt"), ("HIT", "public, max-age=30"))
        # The HIT never went through the internal origin server: it fetches
        # from the origin on every request it handles, and the origin saw one.
        self.assertEqual(hits("/r/short/a.txt"), 1, "a HIT reached the internal origin server")
        # Rules see the decoded path, like the cache key: an encoded spelling
        # gets the same rule and the same entry.
        self.assertEqual(get("/r/sh%6Frt/a.txt"), ("HIT", "public, max-age=30"))
        time.sleep(3)
        # Expired: served stale while a background update refetches it
        # (proxy_cache_background_update), or refetched outright.
        self.assertIn(get("/r/short/a.txt")[0], ("STALE", "UPDATING", "EXPIRED", "MISS"),
                      "the edge TTL of 2 s was not applied")
        deadline = time.time() + 3
        while hits("/r/short/a.txt") < 2 and time.time() < deadline:
            time.sleep(0.1)
        self.assertEqual(hits("/r/short/a.txt"), 2)
        # edge_ttl 0 (file-name glob) and bypass (extension): every request
        # goes to the origin, no-store.
        for path in ("/r/x.nocache", "/r/clip.dat"):
            for _ in range(2):
                cache, cc = get(path)
                self.assertIn(cache, ("BYPASS", "MISS"), path)
                self.assertEqual(cc, "no-store", path)
            self.assertEqual(hits(path), 2, path)
        # Query whitelist ["v"]: v is in the key, other parameters are not;
        # the origin never sees the query.
        # The /r/qs/ rule wins whole: its query whitelist, and the default
        # edge TTL (not the later /r/ rule's 600).
        self.assertEqual(get("/r/qs/a.txt?v=1"), ("MISS", "public, max-age=3600"))
        self.assertEqual(get("/r/qs/a.txt?x=9&v=1")[0], "HIT")
        self.assertEqual(get("/r/qs/a.txt?v=2")[0], "MISS")
        self.assertEqual(hits("/r/qs/a.txt"), 2)
        self.assertTrue(all(e["query"] == "" for e in self.origin_hits("/media/site/r/qs/a.txt")))
        # edge_ttl "origin": the origin's max-age=2 is the edge TTL, and the
        # client's max-age follows it; "private, no-store" is never cached.
        self.assertEqual(get("/r/origin/two.txt"), ("MISS", "public, max-age=2"))
        self.assertEqual(get("/r/origin/two.txt"), ("HIT", "public, max-age=2"))
        time.sleep(3)
        self.assertIn(get("/r/origin/two.txt")[0], ("STALE", "UPDATING", "EXPIRED", "MISS"))
        # The S3 gateway's blanket "private, no-store" counts as no header:
        # the default hour. Any other no-store is honoured.
        self.assertEqual(get("/r/origin/private.txt"), ("MISS", "public, max-age=3600"))
        self.assertEqual(get("/r/origin/private.txt"), ("HIT", "public, max-age=3600"))
        for _ in range(2):
            self.assertEqual(get("/r/origin/nostore.txt"), ("MISS", "no-store"))
        self.assertEqual(hits("/r/origin/nostore.txt"), 2)
        self.assertEqual(get("/accel-expires.txt"), ("HIT", "public, max-age=3600"))
        # A later, broader rule: edge_ttl 600, browser_ttl null follows it.
        self.assertEqual(get("/r/other.txt"), ("MISS", "public, max-age=600"))
        self.assertEqual(get("/r/other.txt"), ("HIT", "public, max-age=600"))
        # The unusable rule was ignored (logged), and nothing else changed:
        # a path no rule matches keeps the defaults.
        with open(self.err_path, "rb") as f:
            self.assertIn(b"zone z1: 1 cache rules ignored", f.read())
        self.assertEqual(get("/a/c.txt")[1], "public, max-age=3600")

    def test_bf_zone_limits_per_node(self):
        # max_rps 0: no allowance at all, so no Retry-After either.
        st, h, body = self.https("zero.cdn.hippius.com", "/a/b.txt")
        self.assertEqual((st, body, h.get("cache-control"), h.get("retry-after")),
                         (503, b"503\n", "no-store", None))
        # max_rps 3: a burst of 10 within a second or two gets some 503s,
        # and never more than 3 per second through.
        answers = [self.https("lim.cdn.hippius.com", "/a/b.txt") for _ in range(10)]
        statuses = [a[0] for a in answers]
        self.assertIn(503, statuses)
        self.assertLessEqual(statuses.count(200), 6, statuses)
        refused = next(a for a in answers if a[0] == 503)
        self.assertEqual((refused[2], refused[1].get("cache-control"), refused[1].get("retry-after")),
                         (b"503\n", "no-store", "1"))
        time.sleep(2.1)
        self.assertEqual(self.https("lim.cdn.hippius.com", "/a/b.txt")[0], 200, "a new second")
        # max_mbps 1 (125 kB/s): a 300 kB object goes through (in flight
        # finishes), then new requests get 503 until the window has passed.
        st, _, body = self.https("bw.cdn.hippius.com", "/bw.bin")
        self.assertEqual((st, len(body)), (200, len(OBJECTS["/media/site/bw.bin"][0])))
        st, h, _ = self.https("bw.cdn.hippius.com", "/a/b.txt")
        self.assertEqual((st, h.get("retry-after")), (503, "2"))
        time.sleep(2.1)
        self.assertEqual(self.https("bw.cdn.hippius.com", "/a/b.txt")[0], 200)
        # Every slice counts, not only the main request's first one: 4 MiB
        # in 1 MiB slices is over 1.125 MB/s in this second or the last
        # (even spread over three seconds), where the first slice alone
        # (1 MiB) would not be.
        st, _, body = self.https("slices.cdn.hippius.com", "/bw-big.bin")
        self.assertEqual((st, len(body)), (200, 4 * 1024 * 1024))
        self.assertEqual(self.https("slices.cdn.hippius.com", "/a/b.txt")[0], 503,
                         "slice subrequests are not counted against the ceiling")
        # The refusals are not billable and are logged once.
        for zone in ("zl", "zb", "zs", "z0"):
            refused = self.records_for(503, zone=zone)
            self.assertTrue(refused, zone)
            self.assertFalse(any(r["billable"] for r in refused), zone)
        with open(self.err_path, "rb") as f:
            log = f.read()
        self.assertIn(b"zone zl over its rps ceiling: 503", log)
        self.assertIn(b"zone zb over its mbps ceiling: 503", log)

    def test_bg_zone_limits_change_live(self):
        # A new value through the feed applies to the next request, no reload.
        z = self.config()["zones"]
        z["zl"]["settings"]["limits"] = {"max_mbps": 2000, "max_rps": 0}
        self.assertEqual(self.put("config", self.config(zones=z)), 204)
        self.assertEqual(self.https("lim.cdn.hippius.com", "/a/b.txt")[0], 503)
        z["zl"]["settings"]["limits"] = {"max_mbps": 2000, "max_rps": 20000}
        self.assertEqual(self.put("config", self.config(zones=z)), 204)
        self.assertEqual([self.https("lim.cdn.hippius.com", "/a/b.txt")[0] for _ in range(8)], [200] * 8)
        # No limits object at all: the defaults, far above this test.
        del z["zl"]["settings"]["limits"]
        self.assertEqual(self.put("config", self.config(zones=z)), 204)
        self.assertEqual([self.https("lim.cdn.hippius.com", "/a/b.txt")[0] for _ in range(8)], [200] * 8)
        self.push_all()

    def test_c_private_bucket_is_sigv4_signed(self):
        st, _, body = self.https("dl.example.com", "/doc.txt")
        self.assertEqual((st, body), (200, b"private-object"))
        hit = self.origin_hits("/private/k/doc.txt")[0]
        self.assertIsNone(hit.get("sig"), hit.get("sig"))
        self.assertIn("X-Amz-Signature=", hit["query"])
        self.assertIn("X-Amz-Expires=86400", hit["query"])
        self.assertNotIn("authorization", hit["headers"])

    def test_cb_backend_credential_shape(self):
        zp = {"s3_credentials": json.dumps({"access_key_id": ACCESS, "secret_access_key": SIGNING_MATERIAL})}
        # The backend seals the SubToken as {"access_key_id", "secret"};
        # zone zq is the prod shape (a private bucket, empty prefix).
        backend = json.dumps({"access_key_id": ACCESS, "secret": SIGNING_MATERIAL})
        self.assertEqual(self.put("secrets", {"zones": {"zp": zp, "zq": {"s3_credentials": backend}}}), 204)
        st, _, body = self.https("priv.cdn.hippius.com", "/sub.txt")
        self.assertEqual((st, body), (200, b"private-subtoken-object"))
        hit = self.origin_hits("/private/sub.txt")[0]
        self.assertIsNone(hit.get("sig"), hit.get("sig"))
        # Unusable credentials: 503 before the origin, and the CRIT line
        # names the field without printing any credential.
        broken = json.dumps({"access_key_id": ACCESS, "secret_key": SIGNING_MATERIAL})
        self.assertEqual(self.put("secrets", {"zones": {"zp": zp, "zq": {"s3_credentials": broken}}}), 204)
        with open(self.err_path, "rb") as f:
            f.seek(0, 2)
            offset = f.tell()
        before = len(Origin.log)
        for _ in range(3):
            self.assertEqual(self.https("priv.cdn.hippius.com", "/never.txt")[0], 503)
        self.assertEqual(len(Origin.log), before)
        time.sleep(0.2)
        with open(self.err_path, "rb") as f:
            f.seek(offset)
            log = f.read()
        line = b"zone zq has unusable s3 credentials: secret missing or invalid"
        self.assertIn(line, log)
        self.assertNotIn(SIGNING_MATERIAL.encode(), log)
        self.assertNotIn(ACCESS.encode(), log)
        self.push_all()

    def test_d_gzip(self):
        st, h, body = self.https("img.example.com", "/a/b.txt", headers={"Accept-Encoding": "gzip"})
        self.assertEqual(st, 200)
        self.assertEqual(h.get("content-encoding"), "gzip")
        self.assertEqual(gzip.decompress(body), TEXT)
        self.assertEqual(h.get("vary"), "Accept-Encoding")
        # Compression off for the node: identity even when asked.
        self.push_all(compression=[])
        st, h, body = self.https("img.example.com", "/a/b.txt", headers={"Accept-Encoding": "gzip"})
        self.assertNotIn("content-encoding", h)
        self.assertEqual(body, TEXT)
        self.push_all()

    def test_e_purge_generations(self):
        self.https("img.example.com", "/a/c.txt")
        self.https("img.example.com", "/img/x.png")
        self.assertEqual(self.https("img.example.com", "/a/c.txt")[1].get("x-cache"), "HIT")
        # Prefix purge of /a/ misses /a/c.txt but leaves /img/x.png cached.
        self.push_all(purges={"z1": {"zone_generation": 1, "prefixes": {"/a/": 1}}})
        self.assertEqual(self.https("img.example.com", "/a/c.txt")[1].get("x-cache"), "MISS")
        self.assertEqual(self.https("img.example.com", "/img/x.png")[1].get("x-cache"), "HIT")
        # An exact-path purge is exact: a sibling sharing the prefix keeps
        # its cached copy.
        self.https("img.example.com", "/img/x.png.bak")
        self.push_all(purges={"z1": {"zone_generation": 1, "prefixes": {"/a/": 1}, "paths": {"/img/x.png": 1}}})
        self.assertEqual(self.https("img.example.com", "/img/x.png")[1].get("x-cache"), "MISS")
        self.assertEqual(self.https("img.example.com", "/img/x.png.bak")[1].get("x-cache"), "HIT")
        # Zone purge.
        self.push_all(purges={"z1": {"zone_generation": 2, "prefixes": {"/a/": 1}, "paths": {"/img/x.png": 1}}})
        self.assertEqual(self.https("img.example.com", "/a/c.txt")[1].get("x-cache"), "MISS")
        self.assertEqual(self.https("img.example.com", "/a/c.txt")[1].get("x-cache"), "HIT")
        # The backend's interim form: an exact path sent in `prefixes`
        # (no trailing "/") purges that path.
        self.push_all(purges={"z1": {"zone_generation": 2, "prefixes": {"/a/": 1, "/a/c.txt": 4},
                                     "paths": {"/img/x.png": 1}}})
        self.assertEqual(self.https("img.example.com", "/a/c.txt")[1].get("x-cache"), "MISS")

    def test_f_refusals_never_reach_the_origin(self):
        before = len(Origin.log)
        cases = [
            (self.https("paused.cdn.hippius.com", "/a/b.txt"), 503),
            (self.https("refused.cdn.hippius.com", "/latest/meta-data/"), 503),
            (self.https("susp.cdn.hippius.com", "/a/b.txt"), 403),
            (self.https("img.example.com", "/bad.bin"), 451),
            (self.https("img.example.com", "/forbidden/x"), 451),
            (self.https("img.example.com", "/a/b.txt", method="POST"), 405),
            (self.https("root.cdn.hippius.com", "/"), 404),
            (self.https("img.example.com", "/a/b.txt", host="dl.example.com"), 421),
            (self.https("nowhere.cdn.hippius.com", "/a/b.txt"), 421),
            (self.http("unknown.example.net", "/a/b.txt"), 421),
            (self.http("127.0.0.1", "/a/b.txt"), 400),
        ]
        for (st, _, _), want in cases:
            self.assertEqual(st, want)
        for path in ("/a/%2e%2e/%2e%2e/private/k/doc.txt", "/a/..%2f..%2fprivate/k/doc.txt",
                     "/a%5c..%5cb", "/a/%00b"):
            st, _, _ = self.https("img.example.com", path)
            self.assertNotEqual(st, 200, path)
        self.assertEqual([e["path"] for e in Origin.log[before:]], [],
                         "a refused request contacted the origin")
        # Encoded names still work.
        st, _, body = self.https("img.example.com", "/a%20b.txt")
        self.assertEqual((st, body), (200, b"spaced"))

    def test_fa_encoded_feed_paths_block_and_purge(self):
        self.assertEqual(self.https("img.example.com", "/a%20b.txt")[0], 200)
        self.assertEqual(self.https("img.example.com", "/a%20b.txt")[1].get("x-cache"), "HIT")
        self.push_all(purges={"z1": {"zone_generation": 1, "paths": {"/a%20b.txt": 7}}})
        self.assertEqual(self.https("img.example.com", "/a%20b.txt")[1].get("x-cache"), "MISS",
                         "an encoded purge key purges the decoded path")
        blocks = self.config()["blocks"] + [{"kind": "path", "value": "/a%20b.txt", "zone_id": "z1"}]
        self.push_all(blocks=blocks)
        self.assertEqual(self.https("img.example.com", "/a%20b.txt")[0], 451)
        # A prefix block must be directory-aligned, and an origin prefix
        # must end with "/": both documents are refused whole.
        # A block or purge key that is not a request path is skipped, not
        # fatal: the rest of the document still applies.
        odd = self.config(blocks=[{"kind": "prefix", "value": "/a"},
                                  {"kind": "path", "value": "/%2e%2e/x"},
                                  {"kind": "path", "value": "/bad.bin", "zone_id": "z1"}],
                          purges={"z1": {"zone_generation": 1, "prefixes": {"/a%00/": 9, "/no-slash": 9},
                                         "paths": {"/a%5cb": 9, "/%2e%2e/x": 9}}})
        self.assertEqual(self.put("config", odd), 204)
        self.assertEqual(self.https("img.example.com", "/bad.bin")[0], 451)
        z = self.config()["zones"]
        z["z1"]["origin"]["prefix"] = "site"
        self.assertEqual(self.put("config", self.config(zones=z)), 400)
        self.push_all()

    def test_fb_origin_errors_are_generic_and_never_cached(self):
        for _ in range(2):
            st, h, body = self.https("img.example.com", "/err.txt")
            self.assertEqual(st, 403)
            self.assertEqual(body, b"403\n")
            self.assertNotEqual(h.get("x-cache"), "HIT")
        self.assertEqual(len(self.origin_hits(ERROR_PATH)), 2)

    def test_fc_origin_cannot_steer_nginx(self):
        st, h, body = self.https("img.example.com", "/accel.txt")
        self.assertEqual((st, body), (200, b"accel-object"))
        self.assertNotIn("x-accel-redirect", h)

    def test_fd_ranges_fill_only_the_slices_they_cover(self):
        big = OBJECTS["/media/site/big.bin"][0]
        time.sleep(0.5)
        n0 = len(self.records)
        st, h, body = self.https("img.example.com", "/big.bin", headers={"Range": "bytes=0-0"})
        self.assertEqual((st, body), (206, big[:1]))
        hits = self.origin_hits("/media/site/big.bin")
        self.assertEqual([e["headers"].get("range") for e in hits], ["bytes=0-1048575"])
        deadline = time.time() + 2
        while len(self.records) == n0 and time.time() < deadline:
            time.sleep(0.05)
        rec = self.records[n0:][0]
        self.assertLess(rec["bytes_out"], 2048, "a one-byte range is not billed as the object")
        st, _, body = self.https("img.example.com", "/big.bin")
        self.assertEqual((st, body), (200, big))

    def test_ff_empty_objects_are_served(self):
        st, h, body = self.https("img.example.com", "/empty.txt")
        self.assertEqual((st, body), (200, b""))
        self.assertEqual(h.get("content-length"), "0")
        self.assertEqual(h.get("content-type"), "text/plain", "S3's 416 type is not passed on")
        # With a client Range, 416 is the right answer.
        self.assertEqual(self.https("img.example.com", "/empty.txt", headers={"Range": "bytes=0-0"})[0], 416)

    def test_fg_every_slice_carries_a_valid_presigned_url(self):
        # Slice subrequests skip the Lua phases, so they reuse the main
        # request's signature: it is a presigned URL valid for a day, not a
        # header signature bound to a clock-skew window.
        OBJECTS["/private/k/big.bin"] = OBJECTS["/media/site/big.bin"]
        time.sleep(0.5)
        n0 = len(self.records)
        st, _, body = self.https("dl.example.com", "/big.bin")
        self.assertEqual((st, body), (200, OBJECTS["/media/site/big.bin"][0]))
        hits = self.origin_hits("/private/k/big.bin")
        self.assertEqual(len(hits), 4, [e["headers"].get("range") for e in hits])
        self.assertTrue(all(e.get("sig") is None for e in hits), [e.get("sig") for e in hits])
        # bytes_from_origin counts every slice, not just the first.
        deadline = time.time() + 2
        while len(self.records) == n0 and time.time() < deadline:
            time.sleep(0.05)
        rec = [r for r in self.records[n0:] if r.get("zone") == "zp"][0]
        self.assertGreaterEqual(rec["bytes_from_origin"], len(OBJECTS["/media/site/big.bin"][0]))
        self.assertEqual(rec["cache"], "miss")

    def test_fh_presigned_urls_never_reach_a_log(self):
        before = os.path.getsize(self.err_path)
        st, _, body = self.https("dl.example.com", "/reset.txt")
        self.assertEqual(st, 502)
        self.assertEqual(body, b"502\n")
        self.assertIn("X-Amz-Signature=", self.origin_hits("/private/k/reset.txt")[0]["query"])
        time.sleep(0.3)
        with open(self.err_path, "rb") as f:
            f.seek(before)
            logged = f.read()
        for secret in (b"X-Amz-Signature", b"X-Amz-Credential", b"reset.txt?"):
            self.assertNotIn(secret, logged)

    def test_fe_bad_credentials_never_reach_a_header(self):
        self.assertEqual(self.put("secrets", {"zones": {"zp": {"s3_credentials": json.dumps(
            {"access_key_id": ACCESS, "secret_access_key": SIGNING_MATERIAL,
             "session_token": "tok\r\nX-Injected: 1"})}}}), 204)
        before = len(Origin.log)
        self.assertEqual(self.https("dl.example.com", "/doc.txt")[0], 503)
        self.assertEqual(len(Origin.log), before)
        self.push_all()

    def test_g_http_redirects_and_acme(self):
        st, h, _ = self.http("img.example.com", "/a/b.txt?q=1")
        self.assertEqual(st, 301)
        self.assertEqual(h["location"], "https://img.example.com/a/b.txt?q=1")
        st, h, body = self.http("anything.example.org", "/.well-known/acme-challenge/tok_ABC-1")
        self.assertEqual((st, body), (200, b"tok_ABC-1.thumbprint_x"))
        self.assertEqual(self.http("img.example.com", "/.well-known/acme-challenge/nope")[0], 404)

    def test_h_tls_selection(self):
        # Unknown name: the fleet wildcard default.
        ctx = ssl.create_default_context(cafile=self.cafile)
        ctx.check_hostname = False
        with ctx.wrap_socket(socket.create_connection(("127.0.0.1", self.https_port), 5),
                             server_hostname="other.test") as s:
            der = s.getpeercert(binary_form=True)
        self.assertIn(b"cdn.hippius.com", der)
        # No default and no match: the handshake is refused.
        self.assertEqual(self.put("certs", {"default": None, "certs": {
            "img.example.com": {"chain_pem": self.img_chain, "key_pem": self.img_key, "not_after": 0}}}), 204)
        with self.assertRaises(ssl.SSLError):
            ctx.wrap_socket(socket.create_connection(("127.0.0.1", self.https_port), 5),
                            server_hostname="other.test").close()
        self.push_all()

    def test_i_health(self):
        self.assertEqual(self.https("health.cdn.hippius.com", "/__hippius/health")[0], 200)
        self.put("health", {"ready": False, "at": int(time.time())})
        st, _, body = self.https("health.cdn.hippius.com", "/__hippius/health")
        self.assertEqual(st, 503)
        self.assertFalse(json.loads(body)["agent_ready"])
        self.put("health", {"ready": True, "at": int(time.time()) - 120})
        self.assertEqual(self.https("health.cdn.hippius.com", "/__hippius/health")[0], 503, "stale")
        # Something in the canary's way (here a directory): health fails,
        # worker 0 logs it once however many checks fail.
        canary = os.path.join(self.work, "cache", ".hippius-canary")
        os.remove(canary)
        os.mkdir(canary)
        self.put("health", {"ready": True, "at": int(time.time())})
        st, _, body = self.https("health.cdn.hippius.com", "/__hippius/health")
        self.assertEqual(st, 503)
        self.assertFalse(json.loads(body)["canary"])
        self.assertTrue(self.wait_log("canary write failed", 1, CANARY_TICK + 3))
        time.sleep(CANARY_TICK + 1)
        self.assertEqual(self.log_count("canary write failed"), 1, "logged once")
        # Out of the way again: rewritten within one check, recovery logged.
        os.rmdir(canary)
        self.assertTrue(self.wait_health(200, CANARY_TICK + 3))
        self.assertEqual(self.log_count("canary written again"), 1)
        # Deleted under a healthy node (what nginx's cache loader did when the
        # canary sat inside the cache tree): back within one check.
        os.remove(canary)
        self.assertTrue(self.wait_health(200, CANARY_TICK + 3))
        with open(canary) as f:
            self.assertEqual(f.read(), "hippius-canary\n")

    def test_j_attestation(self):
        self.assertEqual(self.put("attestation", {"format": "sev-snp-report-v1",
                                                  "spki_sha256_hex": "ab" * 32, "report_b64": "AAAA"}), 204)
        st, _, body = self.https("z1.cdn.hippius.com", "/.well-known/hippius-attestation")
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["spki_sha256_hex"], "ab" * 32)

    def test_k_metering(self):
        time.sleep(0.5)  # let earlier datagrams drain (100 ms sender timer)
        n0 = len(self.records)
        self.https("img.example.com", "/a/b.txt")
        deadline = time.time() + 2
        while len(self.records) == n0 and time.time() < deadline:
            time.sleep(0.05)
        new = self.records[n0:]
        self.assertEqual(len(new), 1, new)
        r = new[0]
        self.assertEqual((r["zone"], r["status"], r["cache"]), ("z1", 200, "hit"))
        self.assertTrue(r["billable"])
        self.assertGreater(r["bytes_out"], len(TEXT))
        self.assertEqual(r["client_region"], "XX")
        self.assertEqual(set(r), {"zone", "client_region", "billable", "bytes_out", "cache",
                                  "bytes_from_origin", "bytes_from_shield", "status"})
        paused = self.records_for(503, "z2")
        self.assertTrue(paused and not paused[-1]["billable"])
        unknown = self.records_for(421, None)
        self.assertTrue(unknown and not unknown[-1]["billable"])
        misses = [r for r in self.records if r.get("cache") == "miss" and r.get("zone") == "z1"]
        self.assertTrue(misses and misses[0]["bytes_from_origin"] > 0)

    def test_x_no_cache_directory_no_start(self):
        # Without its cache directory nginx does not start (it creates
        # objects/ there), so systemd's Restart= retries until the volume is
        # there; it never runs on a half-present cache.
        cache = os.path.join(self.work, "cache")
        type(self).stop_nginx()
        os.rename(cache, cache + ".away")
        env = dict(os.environ, LD_LIBRARY_PATH=os.path.join(PREFIX, "luajit", "lib"))
        err_path = os.path.join(self.work, "nocache.err")
        with open(err_path, "wb") as err:
            p = subprocess.Popen([NGINX, "-e", "stderr", "-p", self.work, "-c",
                                  os.path.join(self.work, "nginx.conf"), "-g", "daemon off;"],
                                 env=env, stderr=err)
        started = True
        try:
            p.wait(timeout=10)
            started = False
        except subprocess.TimeoutExpired:
            p.terminate()  # the master takes its workers down
            p.wait(10)
        finally:
            shutil.rmtree(cache, ignore_errors=True)  # if nginx made one
            os.rename(cache + ".away", cache)
            type(self).start_nginx()
        self.assertFalse(started, "nginx started without its cache directory")
        self.assertNotEqual(p.returncode, 0)
        with open(err_path, "rb") as f:
            self.assertIn(b"objects", f.read())

    def test_y_canary_survives_the_cache_loader(self):
        # The canary is written at start and left alone by the cache loader
        # (it starts a minute after nginx and deletes every non-cache file
        # in the cache tree): same file, same inode, after the loader ran.
        cache = os.path.join(self.work, "cache")
        type(self).stop_nginx()
        os.remove(os.path.join(cache, ".hippius-canary"))
        type(self).start_nginx()
        started = time.time()
        canary = os.path.join(cache, ".hippius-canary")
        deadline = time.time() + 5
        while not os.path.exists(canary) and time.time() < deadline:
            time.sleep(0.05)
        st = os.stat(canary)
        first = (st.st_ino, st.st_mtime_ns)
        self.push_all()
        self.assertEqual(self.https("img.example.com", "/a/b.txt")[0], 200)
        time.sleep(max(0.0, started + 70 - time.time()))
        st = os.stat(canary)
        self.assertEqual((st.st_ino, st.st_mtime_ns), first, "the canary was deleted and rewritten")
        self.assertEqual(sorted(os.listdir(cache)), [".hippius-canary", "objects"])
        self.put("health", {"ready": True, "at": int(time.time())})
        self.assertEqual(self.https("health.cdn.hippius.com", "/__hippius/health")[0], 200)

    def test_ya_geoip_loaded_and_never_fails_a_request(self):
        def log_has(needle):
            with open(self.err_path, "rb") as f:
                return needle in f.read()

        def region_of_next_request():
            time.sleep(0.3)
            n0 = len(self.records)
            self.assertEqual(self.https("img.example.com", "/a/b.txt")[0], 200)
            deadline = time.time() + 2
            while len(self.records) == n0 and time.time() < deadline:
                time.sleep(0.05)
            return self.records[n0:][-1]["client_region"]

        def median_ms(n=150):
            times = []
            for _ in range(n):
                t0 = time.perf_counter()
                self.https("img.example.com", "/a/b.txt")
                times.append((time.perf_counter() - t0) * 1000)
            return sorted(times)[n // 2]

        self.assertTrue(log_has(b"hippius-cdn: geoip database loaded: DBIP-Country-Lite"))
        # The test client is loopback: private, so XX (unit tests cover the
        # country mapping).
        self.assertEqual(region_of_next_request(), "XX")
        with_db = median_ms()

        # A corrupt database: nginx still starts, requests are served, XX.
        db = os.path.join(self.work, "geoip.mmdb")

        def restore():
            shutil.copy(self.geoip_src, db)
            type(self).stop_nginx()
            type(self).start_nginx()
            self.push_all()
        self.addCleanup(restore)
        with open(db, "wb") as f:
            f.write(bytes(range(256)) * 8)
        type(self).stop_nginx()
        type(self).start_nginx()
        self.push_all()
        self.assertTrue(log_has(b"geoip database unavailable, every client region is XX"))
        self.assertEqual(region_of_next_request(), "XX")
        without_db = median_ms()
        # A missing one: the same.
        os.remove(db)
        type(self).stop_nginx()
        type(self).start_nginx()
        self.push_all()
        self.assertEqual(region_of_next_request(), "XX")

        print(f"\n     geoip overhead: median {with_db:.3f} ms per request with the database, "
              f"{without_db:.3f} ms without", file=sys.stderr)
        # Loose on purpose: request latency on a shared runner is noisy, and the
        # lookup itself (~2 us) is measured in the Lua unit tests.
        self.assertLess(with_db, without_db * 1.5 + 2.0, "the GeoIP lookup slows requests down")

    def test_z_restart_empties_shared_memory(self):
        type(self).stop_nginx()
        type(self).start_nginx()
        self.assertEqual(self.put("health", {"ready": True, "at": int(time.time())}), 409)
        self.push_all()
        self.assertEqual(self.https("img.example.com", "/a/b.txt")[0], 200)


if __name__ == "__main__":
    if not os.path.exists(NGINX):
        sys.exit(f"no OpenResty at {PREFIX}")
    unittest.main(verbosity=2)
