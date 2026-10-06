"""Customer-held disk keys (M1 `split` / M2 `customer`) — vali's half.

Design: `docs`-level plan "customer-held disk keys", §1.1 / §5.5. vali is
the OPERATOR surface only (no tenant API here): the launch intent may carry
`key_mode` + `guardian_endpoint` + `guardian_pubkey`, and vali

- validates them with the SAME grammar the guest and the guardian use
  (`hippius_types::guardian::GuardianBinding::from_cmdline` is the source
  of truth — this module mirrors it byte for byte, and
  `tests/test_customer_keys_grammar.py` diffs the two over a fixture corpus
  through `hippius-ticket-validator parse-guardian-binding`);
- bakes three MEASURED cmdline tokens (`hippius.key_mode`,
  `hippius.guardian_pk`, `hippius.guardian_ep`) before the launch digest is
  recomputed, so they are C2-cross-checked and auto-pinned;
- signs `key_mode` into the OrderTicket (split/customer only — an M0
  ticket carries no key, byte-identical to before), and the LaunchOrder
  carries `guardian_ep` (derived from the measured cmdline itself, see
  `order_dispatch`);
- pins the mode on the `Vm` row at first launch. It is IMMUTABLE: every
  relaunch / re-mint path compares against the pin and against the binding
  the measured cmdline actually carries, and refuses on any difference —
  an M1/M2 VM is never silently re-minted as M0.

M0 (`hippius`, the default) changes nothing: no token, no ticket key, no
order key.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

# ── wire constants (mirror `hippius_types::guardian`) ──────────────────

KEY_MODE_HIPPIUS = "hippius"
KEY_MODE_SPLIT = "split"
KEY_MODE_CUSTOMER = "customer"
KEY_MODES: tuple[str, ...] = (KEY_MODE_HIPPIUS, KEY_MODE_SPLIT, KEY_MODE_CUSTOMER)

KEY_MODE_TOKEN = "hippius.key_mode"
GUARDIAN_PK_TOKEN = "hippius.guardian_pk"
GUARDIAN_EP_TOKEN = "hippius.guardian_ep"
_GRAMMAR_KEYS: tuple[str, ...] = (KEY_MODE_TOKEN, GUARDIAN_PK_TOKEN, GUARDIAN_EP_TOKEN)

#: `hippius_types::guardian::MAX_CMDLINE_LEN`: the longest `/proc/cmdline`
#: the guest kernel keeps. x86 `COMMAND_LINE_SIZE` is 2048 INCLUDING the
#: NUL; a longer cmdline is cut silently (the EFI stub at the last
#: whitespace, the kernel bytewise) while SEV measures the whole string.
MAX_CMDLINE_LEN = 2047

#: `hippius_types::guardian::OVMF_INITRD_PREFIX`. OVMF's direct-kernel
#: loader (edk2 `GenericQemuLoadImageLib`, pinned OVMF 162aa41b) puts this
#: IN FRONT of the measured cmdline whenever an initrd is present, so the
#: guest's `/proc/cmdline` is `OVMF_INITRD_PREFIX + measured` (confirmed
#: live 2026-09-28). The kernel-hashes check covers the fw_cfg blob only:
#: SEV measures the cmdline WITHOUT it.
OVMF_INITRD_PREFIX = "initrd=initrd "

#: `hippius_types::guardian::MAX_MEASURED_CMDLINE_LEN` = 2047 − 14 = 2033:
#: the longest MEASURED cmdline that reaches `/proc/cmdline` whole. vali
#: refuses a longer one in EVERY mode (M0 included): a token past it would
#: be measured — and recomputed by vali, the KBS and the guardian — yet cut
#: before the guest reads it.
MAX_MEASURED_CMDLINE_LEN = MAX_CMDLINE_LEN - len(OVMF_INITRD_PREFIX)

#: The longest key-mode token the guest looks for.
_LONGEST_KEY_MODE_TOKEN = f"{KEY_MODE_TOKEN}={KEY_MODE_CUSTOMER}"
#: `guest-release::KEY_MODE_TRUNCATION_FLOOR` (H5b, #1316), in
#: `/proc/cmdline` bytes: 2047 − 25 = 2022. The EFI stub cuts an over-long
#: cmdline at the last whitespace before byte 2048, so a cut-off key-mode
#: token still leaves at least this many bytes. The guest therefore
#: REFUSES TO BOOT any `/proc/cmdline` this long that has no
#: `hippius.key_mode` token, in every mode.
KEY_MODE_TRUNCATION_FLOOR = MAX_CMDLINE_LEN - len(_LONGEST_KEY_MODE_TOKEN)
#: `guest-release::KEY_MODE_TRUNCATION_FLOOR_MEASURED`: the same floor in
#: MEASURED bytes, 2022 − 14 = 2008. vali refuses a token-less measured
#: cmdline of 2008..=2033 bytes (only M0 can be token-less): it would mint
#: and dispatch fine and then never boot.
KEY_MODE_TRUNCATION_FLOOR_MEASURED = KEY_MODE_TRUNCATION_FLOOR - len(OVMF_INITRD_PREFIX)

#: M2 (`customer`) has NO disk KEK: vali stages nothing at `…/luks-kek`
#: and the KBS never reads it (H3: `releases_kek(Customer) == false`, the
#: scope keeps the path only so the broker wire is unchanged). The ticket
#: schema still requires a `luks_vault_ref` with `version > 0`, and the KBS
#: derives the lifecycle-key path from that ref's `…/luks-kek` segment, so
#: an M2 ticket names the canonical path at this constant version. It is a
#: NAME, not a secret: nothing exists at that path, and an M2 ticket misread
#: as M0 would hit a 404 at the KBS — fail closed.
M2_LUKS_REF_VERSION = 1

#: `hippius_types::guardian::MAX_ENDPOINT_LEN`: a 253-byte DNS name, `:`
#: and a 5-digit port.
MAX_ENDPOINT_LEN = 253 + 1 + 5

#: `hippius_types::guardian::ALLOWED_DS_VALUES` — the only `ds=` values a
#: customer-keys cmdline may carry.
ALLOWED_DS_VALUES: tuple[str, ...] = (
    "nocloud",
    "nocloud-net",
    "nocloud;s=/run/cloud-init/seed/",
    "nocloud-net;s=/run/cloud-init/seed/",
)

#: What an M1/M2 `lease_id` may be made of. It is baked into the measured
#: cmdline (`hippius.lease_id=`), where anything outside this set is at
#: best a second reading of the cmdline and at worst a cloud-init
#: directive; refused before the `Vm` row pins the mode.
LEASE_ID_RE = re.compile(r"[A-Za-z0-9._-]+")

_PK_RE = re.compile(r"^[0-9a-f]{64}$")
_LOWER_HEX = frozenset(b"0123456789abcdef")
_ASCII_WS = frozenset(b" \t\n\x0c\r")  # Rust `u8::is_ascii_whitespace`
_DIGITS = frozenset("0123456789")
_LDH = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_IPV6_CHARS = frozenset("0123456789abcdef:.")


class CustomerKeysError(ValueError):
    """A customer-keys input or state that must refuse the operation.

    `classifier` is a stable machine tag (the grammar's own
    `guardian-cmdline-*` classifiers where they apply)."""

    def __init__(self, classifier: str, message: str) -> None:
        super().__init__(f"{classifier}: {message}")
        self.classifier = classifier


@dataclass(frozen=True)
class GuardianBinding:
    """The guardian half of an M1/M2 VM's measured cmdline. M0 has none
    (represented as `None` everywhere in this module)."""

    mode: str  # KEY_MODE_SPLIT | KEY_MODE_CUSTOMER — never hippius
    guardian_pk: str  # 64 lowercase hex
    endpoint: str  # canonical host:port — DECODED, never the hex token

    def tokens(self) -> tuple[tuple[str, str], ...]:
        """The three measured `(key, value)` tokens, in append order. The
        endpoint is measured HEX-ENCODED (`encode_ep_token`)."""
        return (
            (KEY_MODE_TOKEN, self.mode),
            (GUARDIAN_PK_TOKEN, self.guardian_pk),
            (GUARDIAN_EP_TOKEN, encode_ep_token(self.endpoint)),
        )


# ── grammar mirror ──────────────────────────────────────────────────────


def _canonical_ipv6(addr: ipaddress.IPv6Address) -> str:
    """Rust's `Display for Ipv6Addr` (RFC 5952): an IPv4-MAPPED address as
    `::ffff:a.b.c.d`; otherwise lowercase hex groups with the FIRST longest
    run (length > 1) of zero groups compressed to `::`. Written out rather
    than delegated to `str(addr)`, whose mapped-address spelling changed
    between CPython versions."""
    packed = addr.packed
    segs = [int.from_bytes(packed[i : i + 2], "big") for i in range(0, 16, 2)]
    if segs[:5] == [0, 0, 0, 0, 0] and segs[5] == 0xFFFF:
        return "::ffff:" + str(ipaddress.IPv4Address(packed[12:]))
    best_start, best_len, cur_start, cur_len = 0, 0, 0, 0
    for i, seg in enumerate(segs):
        if seg == 0:
            if cur_len == 0:
                cur_start = i
            cur_len += 1
            if cur_len > best_len:
                best_start, best_len = cur_start, cur_len
        else:
            cur_len = 0
    if best_len > 1:
        left = ":".join(f"{s:x}" for s in segs[:best_start])
        right = ":".join(f"{s:x}" for s in segs[best_start + best_len :])
        return f"{left}::{right}"
    return ":".join(f"{s:x}" for s in segs)


def _parse_port(p: str) -> int | None:
    # Rust: a leading `0` (incl. port 0) is a second spelling; the digit
    # check stops `u16::from_str`'s leading `+`; empty / >65535 fail.
    if not p or p.startswith("0") or not all(c in _DIGITS for c in p):
        return None
    value = int(p)
    return value if value <= 0xFFFF else None


def _parse_ipv4(host: str) -> str | None:
    parts = host.split(".")
    if len(parts) != 4:
        return None
    for part in parts:
        # Canonical dotted-quad only: no empty octet, no leading zero, ≤255.
        if not part or not all(c in _DIGITS for c in part) or str(int(part)) != part:
            return None
        if int(part) > 255:
            return None
    return host


def _host_is_name_or_ipv4(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if all(c in _DIGITS or c == "." for c in host):
        return _parse_ipv4(host) is not None
    last = ""
    for label in host.split("."):
        if not label or len(label) > 63:
            return False
        if not all(c in _LDH for c in label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        last = label
    # An all-digit last label is not a real name.
    return not all(c in _DIGITS for c in last)


def parse_endpoint(s: str) -> str | None:
    """`GuardianEndpoint::parse` — the canonical `host:port`, or `None`.
    Accepts exactly one spelling per endpoint, so a valid input is returned
    unchanged."""
    if s.startswith("["):
        inner, sep, after = s[1:].partition("]")
        if not sep or not after.startswith(":"):
            return None
        port = after[1:]
        if not inner or not all(c in _IPV6_CHARS for c in inner):
            return None
        try:
            addr = ipaddress.IPv6Address(inner)
        except ValueError:
            return None
        if _canonical_ipv6(addr) != inner:
            return None
    else:
        host, sep, port = s.rpartition(":")
        if not sep or not _host_is_name_or_ipv4(host):
            return None
    if _parse_port(port) is None:
        return None
    return s


def encode_ep_token(endpoint: str) -> str:
    """`hippius_types::guardian::encode_guardian_ep_token`: the measured
    `hippius.guardian_ep=` value is the lowercase hex of the canonical
    endpoint string. Hex has no `:` and no `_`, so no endpoint
    (`guardian.example.cc:443`, `[2001:db8::cc:1]:443`) can spell
    cloud-init's `cc:` / `end_cc` in the measured cmdline. Total: any str
    encodes (UTF-8, as Rust's `&str`); only a canonical endpoint decodes."""
    return endpoint.encode("utf-8").hex()


def decode_ep_token(value: bytes) -> str | None:
    """`parse_guardian_ep_token`, mirrored: exactly one spelling per
    endpoint — non-empty, even-length, lowercase hex only; decodes to UTF-8
    that is a canonical endpoint (`parse_endpoint`); and that endpoint
    re-encodes to the very same value. `None` otherwise."""
    if not value or len(value) % 2 or len(value) > 2 * MAX_ENDPOINT_LEN:
        return None
    if not all(b in _LOWER_HEX for b in value):
        return None
    try:
        endpoint = bytes.fromhex(value.decode("ascii")).decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None
    if parse_endpoint(endpoint) is None:
        return None
    if encode_ep_token(endpoint).encode("ascii") != value:
        return None
    return endpoint


def carries_cloud_init_directive(raw: bytes) -> bool:
    """`hippius_types::guardian::carries_cloud_init_directive`, mirrored
    (H5b): `cc:` / `end_cc` anywhere, or a token whose key (split on the
    first `=`) is `url`, `cloud-config-url`, `network-config`, `ci.*`, or
    `ds` with a value outside `ALLOWED_DS_VALUES`. `raw` is already
    printable ASCII with no `"`."""
    if b"cc:" in raw or b"end_cc" in raw:
        return True
    for token in _split_ascii_whitespace(raw):
        key, eq, value = token.partition(b"=")
        if key in (b"url", b"cloud-config-url", b"network-config"):
            return True
        if key == b"ds":
            if not eq or value.decode("ascii") not in ALLOWED_DS_VALUES:
                return True
        elif key.startswith(b"ci."):
            return True
    return False


def check_lease_id(binding: GuardianBinding | None, lease_id: Any) -> None:
    """M1/M2: refuse a `lease_id` outside `[A-Za-z0-9._-]+` (it is baked
    into the measured cmdline). Run before the `Vm` pin. No-op for M0 —
    byte-identical to before."""
    if binding is None:
        return
    # `fullmatch`: `re.match(...$)` would also accept a trailing `\n`.
    if not isinstance(lease_id, str) or not LEASE_ID_RE.fullmatch(lease_id):
        raise CustomerKeysError(
            "customer-keys-bad-lease-id",
            f"key_mode={binding.mode} requires a lease_id of [A-Za-z0-9._-] only",
        )


def _normalize_key(raw: bytes) -> bytes:
    """The kernel compares parameter names with `-` ≡ `_`; ASCII case is
    folded too, to catch lookalikes."""
    return raw.replace(b"-", b"_").lower()


def _split_ascii_whitespace(raw: bytes) -> list[bytes]:
    out: list[bytes] = []
    cur = bytearray()
    for b in raw:
        if b in _ASCII_WS:
            if cur:
                out.append(bytes(cur))
                cur = bytearray()
        else:
            cur.append(b)
    if cur:
        out.append(bytes(cur))
    return out


def parse_cmdline(cmdline: str) -> GuardianBinding | None:
    """`GuardianBinding::from_cmdline`, mirrored. `None` ⇒ M0; raises
    `CustomerKeysError` with the Rust `CmdlineError` classifier."""
    raw = cmdline.encode("utf-8")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    keys = tuple(k.encode() for k in _GRAMMAR_KEYS)
    norm = _normalize_key(raw)
    if any(k in norm for k in keys):
        if not all(0x20 <= b <= 0x7E for b in raw):
            raise CustomerKeysError(
                "guardian-cmdline-non-printable", "a guardian cmdline must be printable ASCII"
            )
        if b'"' in raw:
            raise CustomerKeysError("guardian-cmdline-quoted", "a guardian cmdline must not quote")
        if carries_cloud_init_directive(raw):
            raise CustomerKeysError(
                "guardian-cmdline-cloud-init-directive",
                "a guardian cmdline must carry nothing cloud-init reads from it",
            )
    found: list[bytes | None] = [None, None, None]
    for token in _split_ascii_whitespace(raw):
        key, eq, value = token.partition(b"=")
        norm_key = _normalize_key(key)
        if norm_key not in keys:
            continue
        idx = keys.index(norm_key)
        if key != keys[idx]:
            raise CustomerKeysError(
                "guardian-cmdline-lookalike-token", key.decode("ascii", "replace")
            )
        if found[idx] is not None:
            raise CustomerKeysError("guardian-cmdline-duplicate-token", _GRAMMAR_KEYS[idx])
        if not eq or not value:
            raise CustomerKeysError("guardian-cmdline-empty-token", _GRAMMAR_KEYS[idx])
        found[idx] = value
    mode_b, pk_b, ep_b = found
    if mode_b is None:
        mode = KEY_MODE_HIPPIUS
    else:
        mode = mode_b.decode("ascii")
        if mode not in KEY_MODES:
            raise CustomerKeysError("guardian-cmdline-unknown-mode", mode)
    if mode == KEY_MODE_HIPPIUS:
        if pk_b is not None or ep_b is not None:
            raise CustomerKeysError(
                "guardian-cmdline-orphan-guardian-token", "guardian token without a key mode"
            )
        return None
    if pk_b is None:
        raise CustomerKeysError("guardian-cmdline-missing-guardian-pk", mode)
    if ep_b is None:
        raise CustomerKeysError("guardian-cmdline-missing-guardian-ep", mode)
    pk = pk_b.decode("ascii")
    if not _PK_RE.match(pk):
        raise CustomerKeysError("guardian-cmdline-bad-guardian-pk", "want 64 lowercase hex")
    ep = decode_ep_token(ep_b)
    if ep is None:
        raise CustomerKeysError(
            "guardian-cmdline-bad-guardian-ep",
            "want the lowercase hex of a canonical host:port",
        )
    return GuardianBinding(mode=mode, guardian_pk=pk, endpoint=ep)


def cmdline_may_hide_key_mode(measured_cmdline: str) -> bool:
    """`guest-release::cmdline_may_hide_key_mode` (H5b), mirrored, for a
    MEASURED cmdline: `True` when the guest would refuse to boot it — its
    `/proc/cmdline` (`OVMF_INITRD_PREFIX` + the measured bytes) has no
    `hippius.key_mode` token (exact key) and is at least
    [`KEY_MODE_TRUNCATION_FLOOR`] bytes long, i.e. the measured cmdline is
    at least [`KEY_MODE_TRUNCATION_FLOOR_MEASURED`] (one trailing `\\n`
    ignored, as the guest ignores `/proc/cmdline`'s)."""
    raw = (OVMF_INITRD_PREFIX + measured_cmdline).encode("utf-8")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if len(raw) < KEY_MODE_TRUNCATION_FLOOR:
        return False
    key = KEY_MODE_TOKEN.encode()
    return not any(t.partition(b"=")[0] == key for t in _split_ascii_whitespace(raw))


# ── launch intent / spec ────────────────────────────────────────────────


def binding_from_fields(key_mode: Any, endpoint: Any, pubkey: Any) -> GuardianBinding | None:
    """Validate the three launch fields; `None` for M0.

    A field is valid iff the measured tokens built from it parse back —
    through the grammar above — to exactly the same binding. So nothing the
    guest or guardian would read differently (a space, a quote, a second
    spelling of the endpoint, uppercase hex) can get in. `endpoint` is the
    PLAIN canonical `host:port`; only the measured token is hex.
    """
    mode = KEY_MODE_HIPPIUS if key_mode in (None, "") else key_mode
    if not isinstance(mode, str) or mode not in KEY_MODES:
        raise CustomerKeysError(
            "bad-key-mode", f"key_mode must be one of {', '.join(KEY_MODES)}"
        )
    ep = "" if endpoint is None else endpoint
    pk = "" if pubkey is None else pubkey
    if not isinstance(ep, str) or not isinstance(pk, str):
        raise CustomerKeysError(
            "bad-guardian-field", "guardian_endpoint / guardian_pubkey must be strings"
        )
    if mode == KEY_MODE_HIPPIUS:
        if ep or pk:
            # A guardian without a customer-keys mode would be measured and
            # never read — the grammar's orphan rule, refused up front.
            raise CustomerKeysError(
                "guardian-cmdline-orphan-guardian-token",
                "guardian_endpoint / guardian_pubkey need key_mode split or customer",
            )
        return None
    if not pk:
        raise CustomerKeysError(
            "guardian-cmdline-missing-guardian-pk", "guardian_pubkey is required"
        )
    if not ep:
        raise CustomerKeysError(
            "guardian-cmdline-missing-guardian-ep", "guardian_endpoint is required"
        )
    if parse_endpoint(ep) is None:
        # The field is the PLAIN endpoint; refused here, by name, before it
        # is hex-encoded into a token (whose decode would refuse it too).
        raise CustomerKeysError(
            "guardian-cmdline-bad-guardian-ep", "guardian_endpoint must be a canonical host:port"
        )
    expected = GuardianBinding(mode=mode, guardian_pk=pk, endpoint=ep)
    fragment = " ".join(f"{k}={v}" for k, v in expected.tokens())
    parsed = parse_cmdline(fragment)
    if parsed != expected:
        # Parses, but to something else: a field smuggled a separator.
        field = "pk" if parsed is None or parsed.guardian_pk != pk else "ep"
        raise CustomerKeysError(
            f"guardian-cmdline-bad-guardian-{field}", "guardian fields must each be one token"
        )
    return expected


def binding_of(obj: Any) -> GuardianBinding | None:
    """The binding a `LaunchSpec` / intent dict / `Vm` row declares, via
    its `key_mode` / `guardian_endpoint` / `guardian_pubkey` fields."""
    if isinstance(obj, dict):
        get = obj.get
    else:

        def get(name: str, default: Any = None) -> Any:
            return getattr(obj, name, default)

    return binding_from_fields(
        get("key_mode", None), get("guardian_endpoint", None), get("guardian_pubkey", None)
    )


def spec_fields(binding: GuardianBinding | None) -> dict[str, str]:
    """The `spec_json` / `LaunchSpec` / `Vm` field values for `binding`."""
    if binding is None:
        return {"key_mode": KEY_MODE_HIPPIUS, "guardian_endpoint": "", "guardian_pubkey": ""}
    return {
        "key_mode": binding.mode,
        "guardian_endpoint": binding.endpoint,
        "guardian_pubkey": binding.guardian_pk,
    }


def augment_cmdline(cmdline: str, binding: GuardianBinding | None) -> str:
    """Append the measured guardian tokens. M0: `cmdline` returned as is
    (byte-identical). Idempotent in the `_augment_cmdline_with_token` sense
    (an existing `key=` is left alone) — the caller then verifies the FINAL
    cmdline parses back to exactly `binding` ([`check_cmdline`])."""
    if binding is None:
        return cmdline
    for key, value in binding.tokens():
        if f"{key}=" not in cmdline:
            cmdline = f"{cmdline.rstrip()} {key}={value}"
    return cmdline


def check_cmdline(cmdline: str, expected: GuardianBinding | None) -> None:
    """Refuse unless the (final, measured) `cmdline` carries exactly
    `expected` — an operator-baked token disagreeing with the spec, a
    guardian token on an M0 cmdline, or a token the guest would parse
    differently are all refusals."""
    actual = parse_cmdline(cmdline)
    if actual != expected:
        raise CustomerKeysError(
            "key-mode-cmdline-mismatch",
            f"measured cmdline carries {_describe(actual)}, the VM is {_describe(expected)}",
        )


def _describe(binding: GuardianBinding | None) -> str:
    if binding is None:
        return "key_mode=hippius"
    return (
        f"key_mode={binding.mode} guardian_ep={binding.endpoint} "
        f"guardian_pk={binding.guardian_pk[:16]}…"
    )


# ── guardian address policy (mirror of the miner relay) ─────────────────

#: `miner-agent::lifecycle::guardian::NETBIRD_SERVICE_ADDRS` — NetBird's
#: own in-mesh resolver and companion: inside the allowed CGNAT range, but
#: from a miner they are the miner's own NetBird agent.
_NETBIRD_SERVICE_ADDRS = frozenset(
    {ipaddress.IPv4Address("100.100.100.100"), ipaddress.IPv4Address("100.100.100.200")}
)
#: Rust `Ipv4Addr::is_private` — exactly RFC 1918 (Python's `is_private`
#: is much broader, so the ranges are spelled out).
_RFC1918 = tuple(
    ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_V4_LOOPBACK = ipaddress.IPv4Network("127.0.0.0/8")
_V4_LINK_LOCAL = ipaddress.IPv4Network("169.254.0.0/16")
_V4_MULTICAST = ipaddress.IPv4Network("224.0.0.0/4")
_V4_BROADCAST = ipaddress.IPv4Address("255.255.255.255")
_V6_LOOPBACK = ipaddress.IPv6Address("::1")
_V6_UNSPECIFIED = ipaddress.IPv6Address("::")
_V6_LINK_LOCAL = ipaddress.IPv6Network("fe80::/10")
_V6_UNIQUE_LOCAL = ipaddress.IPv6Network("fc00::/7")
_V6_MULTICAST = ipaddress.IPv6Network("ff00::/8")


def _ipv4_allowed(a: ipaddress.IPv4Address) -> bool:
    return not (
        a in _V4_LOOPBACK
        or a.packed[0] == 0  # 0.0.0.0/8, incl. unspecified
        or a in _V4_LINK_LOCAL
        or a in _V4_MULTICAST
        or a == _V4_BROADCAST
        or any(a in n for n in _RFC1918)
        or a in _NETBIRD_SERVICE_ADDRS
    )


def _ipv6_allowed(a: ipaddress.IPv6Address) -> bool:
    if a.ipv4_mapped is not None:  # Rust `to_ipv4_mapped`: ::ffff:a.b.c.d only
        return _ipv4_allowed(a.ipv4_mapped)
    return not (
        a == _V6_LOOPBACK
        or a == _V6_UNSPECIFIED
        or a in _V6_MULTICAST
        or a in _V6_LINK_LOCAL
        or a in _V6_UNIQUE_LOCAL
    )


def endpoint_host_allowed(endpoint: str) -> bool:
    """`miner-agent::lifecycle::guardian::endpoint_host_allowed`, mirrored,
    for a CANONICAL endpoint (`parse_endpoint` already accepted it).

    The relay refuses these at launch (`guardian-ep-forbidden-address`),
    AFTER vali has pinned the mode on the `Vm` row, which would burn the
    vm_id. So vali refuses them first. IP literals: loopback, 0.0.0.0/8,
    link-local, multicast, broadcast, RFC 1918, IPv6 ULA, NetBird's
    service addresses (and the IPv4-mapped forms of all of those). A DNS
    name: only the `localhost` names; its addresses are checked by the
    relay at dial time. CGNAT 100.64.0.0/10 (a NetBird guardian) and
    public addresses are allowed."""
    if endpoint.startswith("["):
        host = endpoint[1 : endpoint.index("]")]
    else:
        host = endpoint.rpartition(":")[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host != "localhost" and not host.endswith(".localhost")
    if isinstance(ip, ipaddress.IPv4Address):
        return _ipv4_allowed(ip)
    return _ipv6_allowed(ip)


def check_endpoint_allowed(binding: GuardianBinding | None) -> None:
    """Refuse a guardian endpoint the miner relay would refuse. No-op M0."""
    if binding is not None and not endpoint_host_allowed(binding.endpoint):
        raise CustomerKeysError(
            "guardian-ep-forbidden-address",
            f"guardian_endpoint {binding.endpoint!r} is a loopback / private / "
            "link-local / NetBird-service address the miner relay will not dial",
        )


# ── cloud-init cmdline markers ───────────────────────────────────────────

#: cloud-init (22.4.2 on Debian 12) reads `cc: … end_cc` from ANYWHERE in
#: the kernel cmdline (`util.read_cc_from_cmdline`: plain, case-sensitive
#: substring search), even from inside another token's value. On an M1/M2
#: VM that is cloud-config injected past the customer's user-data, so the
#: measured cmdline must contain neither marker.
CLOUD_INIT_CMDLINE_MARKERS: tuple[str, ...] = ("cc:", "end_cc")


def check_cloud_init_markers(binding: GuardianBinding | None, **values: str | None) -> None:
    """Refuse an M1/M2 launch whose cmdline inputs carry a cloud-init
    marker. `values` are named cmdline inputs (`cmdline=`, `vm_id=`,
    `lease_id=`, or the final measured cmdline); the binding's own tokens
    are checked too. No-op for M0."""
    if binding is None:
        return
    fields = dict(values)
    fields["guardian tokens"] = " ".join(f"{k}={v}" for k, v in binding.tokens())
    for name, value in fields.items():
        for marker in CLOUD_INIT_CMDLINE_MARKERS:
            if value and marker in value:
                raise CustomerKeysError(
                    "customer-keys-cloud-init-marker",
                    f"{name} contains {marker!r}: cloud-init reads cc: … end_cc from "
                    f"anywhere in the kernel cmdline, so key_mode={binding.mode} refuses it",
                )


# ── NetBird hardening of the M1/M2 guest ─────────────────────────────────

#: Added to every `netbird up` of an M1/M2 VM's userdata when vali fills in
#: its NetBird setup key. The NetBird management plane is Hippius', so on a
#: customer-keys VM it must not be able to steer the guest's DNS or install
#: routes into it (client routes it accepts, server routes it serves) — the
#: overlay stays a plain peer-to-peer link. All three exist in the pinned
#: netbird 0.71.3 CLI (`client/cmd/system.go`: `disable-dns`,
#: `disable-client-routes`, `disable-server-routes`, persistent flags of
#: `up`). M0 is left byte-identical.
NETBIRD_UP_HARDENING: tuple[bytes, ...] = (
    b"--disable-dns",
    b"--disable-client-routes",
    b"--disable-server-routes",
)

#: A `netbird up` invocation in the three shapes a cloud-config carries it:
#: a flow sequence (`[ netbird, up, … ]`), a shell string (`netbird up …`),
#: or a block sequence (`- netbird` / `- up` on the next line). `sep` is the
#: separator between `netbird` and `up`, reused between the added flags so
#: they land as elements of the same list / words of the same command.
_NETBIRD_UP_RE = re.compile(
    rb"(?<![A-Za-z0-9_.-])netbird"
    rb"(?P<sep>[ \t]*,[ \t]*|[ \t]+|[ \t]*\n[ \t]*-[ \t]+)"
    rb"up(?=[ \t]*[,\]\n;&|\"']|[ \t]|$)"
)


def harden_netbird_up(binding: GuardianBinding | None, userdata: bytes) -> bytes:
    """M1/M2: `userdata` with [`NETBIRD_UP_HARDENING`] inserted right after
    every `netbird up` that is not in a comment line. M0: `userdata`
    unchanged (byte-identical).

    Supported shapes: an UNQUOTED flow sequence (`[ netbird, up, … ]`), a
    block sequence (`- netbird` then `- up`), or a shell string containing
    `netbird up` (`/usr/bin/netbird up` too). Not recognised: a quoted flow
    sequence (`[ "netbird", "up" ]`) — such a userdata refuses as below.

    Refuses (`customer-keys-netbird-up-not-found`) an M1/M2 userdata that
    enables NetBird but carries no `netbird up` vali can recognise: an
    unhardened enrolment would be silently accepted otherwise. Run BEFORE
    the `Vm` pin (and at intake) on the template, and at the substitution
    on the bytes that are staged — so the §6 userdata digest covers the
    hardened invocation."""
    if binding is None:
        return userdata
    out = bytearray()
    last = 0
    found = 0
    for m in _NETBIRD_UP_RE.finditer(userdata):
        line_start = userdata.rfind(b"\n", 0, m.start()) + 1
        if userdata[line_start : m.start()].lstrip(b" \t").startswith(b"#"):
            continue  # a comment that mentions `netbird up`
        sep = m.group("sep")
        out += userdata[last : m.end()]
        out += sep + sep.join(NETBIRD_UP_HARDENING)
        last = m.end()
        found += 1
    if not found:
        raise CustomerKeysError(
            "customer-keys-netbird-up-not-found",
            f"key_mode={binding.mode} with NetBird needs a userdata whose `netbird up` "
            "vali can harden (--disable-dns --disable-client-routes "
            "--disable-server-routes); none was found",
        )
    out += userdata[last:]
    return bytes(out)


# ── immutability ────────────────────────────────────────────────────────


def check_pinned(vm: Any, binding: GuardianBinding | None) -> None:
    """Refuse unless `binding` is exactly the mode pinned on the `Vm` row
    at first launch. Mode switching is launch-time only (design §3.5)."""
    pinned = binding_of(vm)
    if pinned != binding:
        raise CustomerKeysError(
            "key-mode-immutable",
            f"vm {getattr(vm, 'vm_id', '?')!r} is pinned to {_describe(pinned)}; "
            f"refusing {_describe(binding)} — the key mode is fixed at launch",
        )


def resolve_for_remint(vm: Any, measured_cmdline: str | None) -> GuardianBinding | None:
    """The binding a re-mint / re-dispatch of `vm` must carry.

    The `Vm` pin is authoritative; the measured cmdline the VM actually
    boots must agree with it. A record with no measured cmdline is only
    acceptable for an M0 pin (VMs launched before `measured_cmdline` was
    recorded — all M0). Anything else raises: an M1/M2 VM is never
    re-minted as M0, and an M0 pin never adopts a guardian from a record.
    """
    pinned = binding_of(vm)
    if measured_cmdline:
        # The same rule the launch applied: a recorded M1/M2 cmdline that
        # carries a cloud-init marker is never re-minted. Checked first so
        # the refusal names the marker (the grammar refuses it too, as a
        # `guardian-cmdline-cloud-init-directive`).
        check_cloud_init_markers(pinned, measured_cmdline=measured_cmdline)
        check_cmdline(measured_cmdline, pinned)
    elif pinned is not None:
        raise CustomerKeysError(
            "key-mode-unprovable",
            f"vm {getattr(vm, 'vm_id', '?')!r} is {_describe(pinned)} but its launch "
            "record has no measured cmdline to check it against",
        )
    return pinned


def ticket_key_mode(binding: GuardianBinding | None) -> str:
    """The ticket's `key_mode` (`hippius` ⇒ the mint omits the key)."""
    return KEY_MODE_HIPPIUS if binding is None else binding.mode


def assert_no_provider_kek(mount: str, luks_path: str) -> None:
    """M2's defining property is that Hippius holds NO disk key material.
    vali never stages one for M2, but an earlier attempt under the same
    vm_id (an M1 request that failed after its KEK was provisioned) can
    have left one at the canonical path. Refuse rather than launch an
    "M2" VM with a provider-held KEK beside it. Metadata read only — the
    value is never fetched. Vault errors propagate (`EffectError`)."""
    from . import vault_kv

    if vault_kv.kv_exists(mount, luks_path):
        raise CustomerKeysError(
            "customer-keys-kek-present",
            f"{luks_path} holds a provider disk KEK (left by an earlier launch "
            "attempt?) — a customer-mode VM must have none; launch under a fresh vm_id",
        )


def releases_kek(binding: GuardianBinding | None) -> bool:
    """Whether this VM has a Hippius-held disk KEK (M0 KEK, M1 `share_H`).
    M2 has none: nothing is generated, wrapped or staged."""
    return binding is None or binding.mode != KEY_MODE_CUSTOMER


def data_death_for(vm: Any) -> str:
    """`DecommissionJob.data_death` of `vm`'s §24 erase (design §3.4).

    The erase step itself is the SAME for every mode: it destroys the
    per-VM Transit keys (`kek-<vm>` also wraps the userdata the KBS
    releases, so M2 has one too) and deletes the KV copies, and §24 still
    deletes the disks and backups. What differs is what that does to the
    DISK: for M0/M1 the destroyed key is the one the disk needs (the M0 KEK,
    M1's `share_H`), so the data is crypto-erased; an M2 disk key never
    existed at Hippius, so only the customer's `guardian erase <vm>`
    crypto-erases it."""
    from apps.orchestration.models import DataDeath

    if getattr(vm, "key_mode", KEY_MODE_HIPPIUS) == KEY_MODE_CUSTOMER:
        return DataDeath.CUSTOMER_ERASE_REQUIRED.value
    return DataDeath.CRYPTO_ERASED.value


# ── new-launch gates (intake) ───────────────────────────────────────────

_BAKE_BOUND_FIELDS: tuple[tuple[str, str], ...] = (
    ("s3_bucket", "s3_output_bucket"),
    ("s3_key_prefix", "s3_output_prefix"),
    ("kernel_sha256_hex", "kernel_sha256"),
    ("initrd_sha256_hex", "initrd_sha256"),
    ("rootfs_img_sha256_hex", "rootfs_img_sha256"),
    ("rootfs_verity_sha256_hex", "rootfs_verity_sha256"),
    ("verity_root_hash_hex", "verity_root_hash"),
)


def enabled() -> bool:
    from django.conf import settings

    return bool(getattr(settings, "VALI_CUSTOMER_KEYS_ENABLED", False))


def check_new_launch(intent: dict[str, Any], binding: GuardianBinding | None) -> None:
    """The gates an M1/M2 FIRST launch must pass (no-op for M0):

    1. `VALI_CUSTOMER_KEYS_ENABLED` is on;
    2. `disk_mode` is golden (a legacy rootfs is `luksFormat`ted by the
       online baker, which holds that KEK — finding 5);
    3. the launch names a golden `bake_id` the operator marked
       `supports_customer_keys` (its initramfs carries the guest leg), and
       every artifact the measurement covers is THAT bake's — a
       caller-supplied kernel/initrd/base would otherwise ride a capable
       bake's name.

    Relaunches do not re-run these (a flag flip must not strand running
    M1/M2 VMs); they are held to the `Vm` pin instead.
    """
    if binding is None:
        return
    if not enabled():
        raise CustomerKeysError(
            "customer-keys-disabled",
            "customer-held keys are not enabled (VALI_CUSTOMER_KEYS_ENABLED)",
        )
    from apps.tenant_bake.models import TenantBake, TenantBakeDiskMode

    golden = TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY.value
    if intent.get("disk_mode") != golden:
        raise CustomerKeysError(
            "customer-keys-golden-only", f"key_mode={binding.mode} requires disk_mode={golden}"
        )
    bake_id = intent.get("bake_id")
    if not isinstance(bake_id, str) or not bake_id:
        raise CustomerKeysError(
            "customer-keys-bake-required",
            f"key_mode={binding.mode} requires a golden image/bake_id marked "
            "supports_customer_keys",
        )
    bake = TenantBake.objects.filter(bake_id=bake_id).first()
    if bake is None or bake.disk_mode != golden or not bake.supports_customer_keys:
        raise CustomerKeysError(
            "customer-keys-bake-not-capable",
            f"bake {bake_id!r} is not a golden bake marked supports_customer_keys",
        )
    build = _guest_build_of(bake, intent)
    for spec_key, bake_attr in _BAKE_BOUND_FIELDS:
        want = str(getattr(bake, bake_attr) or "")
        if build is not None and spec_key in _BUILD_BOUND_FIELDS:
            # A launch by image of a blessed guest release: the build of
            # THIS bake's initrd (same kernel, same dm-verity base).
            want = str(getattr(build, _BUILD_BOUND_FIELDS[spec_key]) or "")
        if not want or str(intent.get(spec_key) or "") != want:
            raise CustomerKeysError(
                "customer-keys-artifact-mismatch",
                f"{spec_key} must be bake {bake_id!r}'s own value for key_mode={binding.mode}",
            )


#: The fields a guest release build of a bake replaces in its launch spec.
_BUILD_BOUND_FIELDS: dict[str, str] = {
    "s3_bucket": "s3_bucket",
    "s3_key_prefix": "s3_key_prefix",
    "initrd_sha256_hex": "initrd_sha256",
}


def _guest_build_of(bake: Any, intent: dict[str, Any]) -> Any:
    """The registered, usable guest release build of `bake`'s initrd the
    intent names (prefix + initrd), or `None`."""
    from apps.orchestration.models import GuestInitrdBuild

    initrd = str(intent.get("initrd_sha256_hex") or "").lower()
    if not initrd or initrd == bake.initrd_sha256:
        return None
    return GuestInitrdBuild.objects.filter(
        initrd_sha256=initrd,
        s3_key_prefix=str(intent.get("s3_key_prefix") or ""),
        base_initrd_sha256=bake.initrd_sha256,
        kernel_sha256=bake.kernel_sha256,
        rootfs_img_sha256=bake.rootfs_img_sha256,
        rootfs_verity_sha256=bake.rootfs_verity_sha256,
        verity_root_hash=bake.verity_root_hash,
        withdrawn_at__isnull=True,
        release__withdrawn_at__isnull=True,
    ).first()
