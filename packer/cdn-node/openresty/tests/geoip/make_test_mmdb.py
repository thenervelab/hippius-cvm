#!/usr/bin/env python3
"""Write small MaxMind DB files for the GeoIP tests (no binary is committed).

    make_test_mmdb.py <out-dir>

Writes, in <out-dir>:
  geo-24.mmdb, geo-28.mmdb, geo-32.mmdb  the same networks at each record size
  truncated.mmdb                         geo-24 cut in half (no metadata)
  garbage.mmdb                           sequential bytes, no MaxMind marker
  badtree.mmdb                           metadata claims more nodes than fit
  fanout.mmdb                            metadata whose pointers fan out (each
                                         level points 4 times at the next)

Networks (IPv6 tree; IPv4 at ::/96 as MaxMind writes it):
  2.16.0.0/13   FR
  1.0.0.0/8     AU
  9.9.0.0/16    "nl"   (lower case: read as NL)
  8.8.8.0/24    "ZZ"   (unknown: read as XX)
  7.7.0.0/16    "EUR"  (not alpha-2: read as XX)
  6.6.0.0/16    a record without a country (read as XX)
  2a01::/16     DE
  10.0.0.0/8, 100.64.0.0/10, 192.168.0.0/16  FR (private: the reader must
                answer XX before looking them up)
Keys are written once and referenced through pointers (1-, 2- and 3-byte
pointers: the data section is padded so the later keys sit past 2 KiB and
512 KiB), and every record carries a continent map before the country, as
DB-IP's do.
"""
import ipaddress
import os
import struct
import sys

T_POINTER, T_STRING, T_U16, T_U32, T_MAP, T_U64, T_ARRAY, T_BOOL = 1, 2, 5, 6, 7, 9, 11, 14


def ctrl(t: int, size: int) -> bytes:
    first, ext = (t << 5, b"") if t <= 7 else (0, bytes([t - 7]))
    if size < 29:
        return bytes([first | size]) + ext
    if size < 285:
        return bytes([first | 29]) + ext + bytes([size - 29])
    if size < 65821:
        return bytes([first | 30]) + ext + (size - 285).to_bytes(2, "big")
    return bytes([first | 31]) + ext + (size - 65821).to_bytes(3, "big")


def enc_str(s: str) -> bytes:
    b = s.encode()
    return ctrl(T_STRING, len(b)) + b


def enc_uint(v: int, t: int = T_U32) -> bytes:
    b = v.to_bytes((v.bit_length() + 7) // 8, "big") if v else b""
    return ctrl(t, len(b)) + b


def enc_ptr(off: int) -> bytes:
    if off < 2048:
        return bytes([(T_POINTER << 5) | (off >> 8), off & 0xFF])
    if off < 526336:
        off -= 2048
        return bytes([(T_POINTER << 5) | (1 << 3) | (off >> 16), (off >> 8) & 0xFF, off & 0xFF])
    off -= 526336
    return bytes([(T_POINTER << 5) | (2 << 3) | (off >> 24), (off >> 16) & 0xFF,
                  (off >> 8) & 0xFF, off & 0xFF])


def enc(v) -> bytes:
    if isinstance(v, bytes):  # pre-encoded (pointers)
        return v
    if isinstance(v, bool):
        return ctrl(T_BOOL, 1 if v else 0)
    if isinstance(v, str):
        return enc_str(v)
    if isinstance(v, int):
        return enc_uint(v, T_U64 if v >= 1 << 32 else T_U32)
    if isinstance(v, list):
        return ctrl(T_ARRAY, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        return ctrl(T_MAP, len(v)) + b"".join(enc(k) + enc(x) for k, x in v.items())
    raise TypeError(type(v))


NETWORKS = [
    ("2.16.0.0/13", "FR"),
    ("1.0.0.0/8", "AU"),
    ("9.9.0.0/16", "nl"),
    ("8.8.8.0/24", "ZZ"),
    ("7.7.0.0/16", "EUR"),
    ("6.6.0.0/16", None),
    ("2a01::/16", "DE"),
    ("10.0.0.0/8", "FR"),
    ("100.64.0.0/10", "FR"),
    ("192.168.0.0/16", "FR"),
]


def build(record_size: int) -> bytes:
    # Data section: shared keys first, then one record per network.
    data = bytearray()
    keys = {}
    for k in ("country", "iso_code", "continent", "code", "names", "en"):
        if k == "iso_code":
            data += enc_str("p" * 3000)      # the next keys need 2-byte pointers
        if k == "names":
            data += enc_str("p" * 530000)    # and these 3-byte ones
        keys[k] = len(data)
        data += enc_str(k)
    records = []
    for _, iso in NETWORKS:
        off = len(data)
        rec = {enc_ptr(keys["continent"]): {enc_ptr(keys["code"]): "EU",
                                            enc_ptr(keys["names"]): {enc_ptr(keys["en"]): "Somewhere"}}}
        if iso is not None:
            rec[enc_ptr(keys["country"])] = {"geoname_id": 3017382,
                                             enc_ptr(keys["iso_code"]): iso,
                                             "is_in_european_union": True}
        data += enc(rec)
        records.append(off)

    # Search tree over 128 bits.
    root: list = [None, None]
    for (net, _), off in zip(NETWORKS, records):
        n = ipaddress.ip_network(net)
        if n.version == 4:
            bits = [0] * 96 + [int(c) for c in format(int(n.network_address), "032b")][: n.prefixlen]
        else:
            bits = [int(c) for c in format(int(n.network_address), "0128b")][: n.prefixlen]
        node = root
        for b in bits[:-1]:
            if not isinstance(node[b], list):
                node[b] = [None, None]
            node = node[b]
        node[bits[-1]] = ("data", off)
    order = []
    queue = [root]
    while queue:
        n = queue.pop(0)
        order.append(n)
        queue += [c for c in n if isinstance(c, list)]
    index = {id(n): i for i, n in enumerate(order)}
    count = len(order)

    def value(c) -> int:
        if c is None:
            return count
        if isinstance(c, tuple):
            return count + 16 + c[1]
        return index[id(c)]

    tree = bytearray()
    for n in order:
        left, right = value(n[0]), value(n[1])
        if record_size == 24:
            tree += left.to_bytes(3, "big") + right.to_bytes(3, "big")
        elif record_size == 28:
            tree += (left & 0xFFFFFF).to_bytes(3, "big")
            tree += bytes([((left >> 24) << 4) | (right >> 24)])
            tree += (right & 0xFFFFFF).to_bytes(3, "big")
        else:
            tree += struct.pack(">II", left, right)

    meta = {
        "binary_format_major_version": 2, "binary_format_minor_version": 0,
        "build_epoch": 1790812800, "database_type": "DBIP-Country-Lite",
        "description": {"en": "hippius-cdn test database"},
        "ip_version": 6, "languages": ["en"], "node_count": count,
        "record_size": record_size,
    }
    return bytes(tree) + b"\x00" * 16 + bytes(data) + b"\xab\xcd\xefMaxMind.com" + enc(meta)


def main() -> None:
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for rs in (24, 28, 32):
        with open(os.path.join(out, f"geo-{rs}.mmdb"), "wb") as f:
            f.write(build(rs))
    good = build(24)
    with open(os.path.join(out, "truncated.mmdb"), "wb") as f:
        f.write(good[: len(good) // 2])
    with open(os.path.join(out, "garbage.mmdb"), "wb") as f:
        f.write(bytes(i % 256 for i in range(4096)))
    # Valid metadata, but a node count whose tree would not fit the file.
    meta_off = good.rfind(b"\xab\xcd\xefMaxMind.com") + 14
    meta = {"binary_format_major_version": 2, "ip_version": 6, "record_size": 24,
            "node_count": len(good) * 4, "build_epoch": 1, "database_type": "x"}
    bad = good[:meta_off] + enc(meta)
    with open(os.path.join(out, "badtree.mmdb"), "wb") as f:
        f.write(bad)
    # Metadata fan-out: 14 levels of arrays, each holding 4 pointers to the
    # next (relative to the metadata start). Decoding it naively is 4^14.
    level = enc("leaf")
    body = bytearray()
    offs = []
    for _ in range(14):
        offs.append(len(body))
        body += level
        level = ctrl(T_ARRAY, 4) + enc_ptr(offs[-1]) * 4
    meta_body = ctrl(T_MAP, 1) + enc_str("x") + level
    with open(os.path.join(out, "fanout.mmdb"), "wb") as f:
        f.write(b"\xab\xcd\xefMaxMind.com" + bytes(body) + meta_body)


if __name__ == "__main__":
    main()
