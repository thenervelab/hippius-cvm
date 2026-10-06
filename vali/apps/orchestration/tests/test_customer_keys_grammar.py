"""Customer-held keys — vali's mirror of the guardian cmdline grammar.

`hippius_types::guardian::GuardianBinding::from_cmdline` is the source of
truth: the guest and the guardian both read the measured cmdline with it.
vali validates launch fields and every re-minted cmdline with a Python
mirror (`services.customer_keys.parse_cmdline`); the differential test at the
bottom runs the SAME corpus through the Rust parser
(`hippius-ticket-validator parse-guardian-binding`) and requires identical
verdicts, classifier for classifier. CI builds the binary; locally the
differential test skips without it.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from django.conf import settings

from apps.orchestration.services import customer_keys as ck

PK = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
EP = "100.64.3.7:7443"
BASE = "console=hvc0 ro boot=hippius-golden"


def _hex(s: str) -> str:
    return s.encode("utf-8").hex()


def _bound_raw(mode: str = "split", pk: str = PK, ep_token: str = "", base: str = BASE) -> str:
    """A keyed cmdline whose `hippius.guardian_ep=` value is `ep_token` AS IS."""
    ep_token = ep_token or _hex(EP)
    return (
        f"{base} hippius.key_mode={mode} hippius.guardian_pk={pk} "
        f"hippius.guardian_ep={ep_token}"
    )


def _bound(mode: str = "split", pk: str = PK, ep: str = EP, base: str = BASE) -> str:
    """A keyed cmdline measuring `ep` the way vali mints it: hex-encoded."""
    return _bound_raw(mode, pk, _hex(ep), base)


def _err(cmdline: str) -> str:
    with pytest.raises(ck.CustomerKeysError) as exc:
        ck.parse_cmdline(cmdline)
    return exc.value.classifier


# ── the grammar ─────────────────────────────────────────────────────────


def test_an_m0_cmdline_has_no_binding() -> None:
    assert ck.parse_cmdline(BASE) is None
    assert ck.parse_cmdline(f"{BASE} hippius.key_mode=hippius") is None
    # `/proc/cmdline`'s trailing newline reads the same.
    assert ck.parse_cmdline(BASE + "\n") is None


@pytest.mark.parametrize("mode", ["split", "customer"])
def test_a_customer_keys_cmdline_parses_to_its_binding(mode: str) -> None:
    assert ck.parse_cmdline(_bound(mode)) == ck.GuardianBinding(mode, PK, EP)


@pytest.mark.parametrize(
    ("cmdline", "classifier"),
    [
        (_bound() + " hippius.key_mode=split", "guardian-cmdline-duplicate-token"),
        (f"{BASE} hippius.key_mode=", "guardian-cmdline-empty-token"),
        (f"{BASE} hippius.key_mode", "guardian-cmdline-empty-token"),
        (f"{BASE} hippius.key-mode=split", "guardian-cmdline-lookalike-token"),
        (f"{BASE} HIPPIUS.key_mode=split", "guardian-cmdline-lookalike-token"),
        (_bound(base='console="a b"'), "guardian-cmdline-quoted"),
        (_bound().replace(" ", "\t", 1), "guardian-cmdline-non-printable"),
        (_bound() + " x=é", "guardian-cmdline-non-printable"),
        (_bound("m1"), "guardian-cmdline-unknown-mode"),
        (f"{BASE} hippius.guardian_ep={_hex(EP)}", "guardian-cmdline-orphan-guardian-token"),
        (
            f"{BASE} hippius.key_mode=hippius hippius.guardian_pk={PK}",
            "guardian-cmdline-orphan-guardian-token",
        ),
        (f"{BASE} hippius.key_mode=split hippius.guardian_ep={_hex(EP)}",
         "guardian-cmdline-missing-guardian-pk"),
        (f"{BASE} hippius.key_mode=split hippius.guardian_pk={PK}",
         "guardian-cmdline-missing-guardian-ep"),
        (_bound(pk=PK.upper()), "guardian-cmdline-bad-guardian-pk"),
        (_bound(pk=PK[:-2]), "guardian-cmdline-bad-guardian-pk"),
        (_bound(ep="100.64.3.7:07443"), "guardian-cmdline-bad-guardian-ep"),
        # H1b: the plain endpoint is no longer the token.
        (_bound_raw(ep_token=EP), "guardian-cmdline-bad-guardian-ep"),
        (_bound_raw(ep_token=_hex(EP).upper()), "guardian-cmdline-bad-guardian-ep"),
        (_bound(base=f"{BASE} url=http://x"), "guardian-cmdline-cloud-init-directive"),
    ],
)
def test_every_grammar_refusal_has_its_classifier(cmdline: str, classifier: str) -> None:
    assert _err(cmdline) == classifier


@pytest.mark.parametrize(
    "ep",
    [
        "100.64.3.7:7443",
        "0.0.0.0:1",
        "255.255.255.255:65535",
        "guardian.example.com:7443",
        "a-b.c1:80",
        "[2001:db8::1]:7443",
        "[::1]:1",
        "[::]:9",
        "[::ffff:1.2.3.4]:443",
        "[1::]:5",
        "[1:0:1:0:1:0:1:0]:5",
    ],
)
def test_canonical_endpoints_are_accepted_unchanged(ep: str) -> None:
    assert ck.parse_endpoint(ep) == ep


@pytest.mark.parametrize(
    "ep",
    [
        "",
        "100.64.3.7",
        "100.64.3.7:",
        "100.64.3.7:0",
        "100.64.3.7:65536",
        "100.64.3.7:+80",
        "100.064.3.7:80",
        "1.2.3:80",
        "256.1.1.1:80",
        "Guardian.example.com:80",
        "-a.example:80",
        "a..b:80",
        "a.1:80",
        "a_b.example:80",
        "[2001:DB8::1]:80",
        "[2001:db8:0:0:0:0:0:1]:80",
        "[::ffff:102:304]:443",
        "[2001:db8::1]",
        "2001:db8::1:80",
        "user@host.example:80",
        "http://host.example:80",
        "host.example:80/x",
        "höst.example:80",
        "host.example:١٢",
        "[fe80::1%eth0]:80",
    ],
)
def test_non_canonical_endpoints_are_refused(ep: str) -> None:
    assert ck.parse_endpoint(ep) is None


# ── launch fields ───────────────────────────────────────────────────────


def test_m0_fields_are_no_binding() -> None:
    assert ck.binding_from_fields(None, None, None) is None
    assert ck.binding_from_fields("hippius", "", "") is None
    assert ck.binding_from_fields("", None, None) is None


@pytest.mark.parametrize(
    ("mode", "ep", "pk", "classifier"),
    [
        ("Split", EP, PK, "bad-key-mode"),
        ("m2", EP, PK, "bad-key-mode"),
        (1, EP, PK, "bad-key-mode"),
        ("hippius", EP, "", "guardian-cmdline-orphan-guardian-token"),
        ("hippius", "", PK, "guardian-cmdline-orphan-guardian-token"),
        ("split", EP, "", "guardian-cmdline-missing-guardian-pk"),
        ("customer", "", PK, "guardian-cmdline-missing-guardian-ep"),
        ("split", EP, PK.upper(), "guardian-cmdline-bad-guardian-pk"),
        ("split", "100.64.3.7:07443", PK, "guardian-cmdline-bad-guardian-ep"),
        # a separator smuggled into a field would be a second token
        ("split", f"{EP} init=/bin/sh", PK, "guardian-cmdline-bad-guardian-ep"),
        ("split", EP, f"{PK} rd.break", "guardian-cmdline-bad-guardian-pk"),
        ("split", 7443, PK, "bad-guardian-field"),
        # a non-ASCII endpoint is a clean refusal, never an encode crash
        ("split", "g\u00fc.example:1", PK, "guardian-cmdline-bad-guardian-ep"),
        ("customer", "h\u00f6st.example:1", PK, "guardian-cmdline-bad-guardian-ep"),
        ("split", EP + "\n", PK, "guardian-cmdline-bad-guardian-ep"),
    ],
)
def test_bad_launch_fields_are_refused(mode, ep, pk, classifier) -> None:
    with pytest.raises(ck.CustomerKeysError) as exc:
        ck.binding_from_fields(mode, ep, pk)
    assert exc.value.classifier == classifier


def test_m0_augmentation_is_the_identity() -> None:
    assert ck.augment_cmdline(BASE, None) == BASE


def test_augmented_tokens_parse_back_to_the_binding() -> None:
    binding = ck.binding_from_fields("customer", EP, PK)
    out = ck.augment_cmdline(BASE, binding)
    assert out == _bound("customer")
    ck.check_cmdline(out, binding)
    # an operator-baked token that disagrees is left alone by the append —
    # and then refused by the final check
    baked = ck.augment_cmdline(f"{BASE} hippius.guardian_ep={_hex('10.0.0.1:1')}", binding)
    with pytest.raises(ck.CustomerKeysError, match="key-mode-cmdline-mismatch"):
        ck.check_cmdline(baked, binding)
    # a guardian token on an M0 cmdline is refused too
    with pytest.raises(ck.CustomerKeysError):
        ck.check_cmdline(out, None)


def test_the_length_limit_is_the_rust_one() -> None:
    from apps.orchestration.services import launch

    # `hippius_types::guardian::{MAX_CMDLINE_LEN, OVMF_INITRD_PREFIX,
    # MAX_MEASURED_CMDLINE_LEN}`; `launch_on_miner` refuses a longer
    # MEASURED cmdline for every mode (M0 included).
    assert ck.MAX_CMDLINE_LEN == 2047
    assert ck.OVMF_INITRD_PREFIX == "initrd=initrd "
    assert ck.MAX_MEASURED_CMDLINE_LEN == launch._MAX_CMDLINE_BYTES == 2033
    assert ck.KEY_MODE_TRUNCATION_FLOOR == 2022
    assert ck.KEY_MODE_TRUNCATION_FLOOR_MEASURED == 2008


_TYPES_GUARDIAN_RS = Path(settings.BASE_DIR).parent / "hippius-types" / "src" / "guardian.rs"
_GUEST_MAIN_RS = Path(settings.BASE_DIR).parent / "binaries" / "guest-release" / "src" / "main.rs"


def test_the_cmdline_constants_mirror_the_rust_source() -> None:
    """Parity with the Rust source of truth, read from the checkout (the
    vali job runs in the full repo): the kernel limit, OVMF's prefix, the
    measured cap derived from both, and the guest's key-mode floor."""
    import re

    rs = _TYPES_GUARDIAN_RS.read_text()
    m = re.search(r"pub const MAX_CMDLINE_LEN: usize = (\d+);", rs)
    assert m is not None and int(m.group(1)) == ck.MAX_CMDLINE_LEN
    m = re.search(r'pub const OVMF_INITRD_PREFIX: &str = "([^"]*)";', rs)
    assert m is not None and m.group(1) == ck.OVMF_INITRD_PREFIX
    assert (
        "pub const MAX_MEASURED_CMDLINE_LEN: usize = MAX_CMDLINE_LEN - OVMF_INITRD_PREFIX.len();"
        in rs
    )
    guest = _GUEST_MAIN_RS.read_text()
    assert (
        "const KEY_MODE_TRUNCATION_FLOOR: usize = MAX_CMDLINE_LEN - LONGEST_KEY_MODE_TOKEN.len();"
        in guest
    )
    m = re.search(r'const LONGEST_KEY_MODE_TOKEN: &str = "([^"]*)";', guest)
    assert m is not None and m.group(1) == f"{ck.KEY_MODE_TOKEN}={ck.KEY_MODE_CUSTOMER}"
    assert "KEY_MODE_TRUNCATION_FLOOR - OVMF_INITRD_PREFIX.len();" in guest


# ── H5b truncation band: `guest-release::cmdline_may_hide_key_mode` ──────


def _pad(n: int, tail: str = "") -> str:
    """A MEASURED cmdline of exactly `n` bytes (the guest sees it behind
    OVMF's 14-byte `initrd=initrd `)."""
    return BASE + " " + "x" * (n - len(BASE) - 1 - len(tail)) + tail


@pytest.mark.parametrize(
    ("cmdline", "hides"),
    [
        (_pad(900), False),  # a normal M0 cmdline
        (_pad(2007), False),  # below the measured floor
        (_pad(2008), True),  # at the floor (/proc/cmdline 2022), no token
        (_pad(2033), True),
        (_pad(2007) + "\n", False),  # one trailing newline is not counted
        (_pad(2008) + "\n", True),
        (_pad(2030, " hippius.key_mode=hippius"), False),  # explicit M0 token
        (_pad(2030, " hippius.key_mode=split"), False),
        (_pad(2030, " hippius.key_mode"), False),  # bare key counts (Rust map_or)
        (_pad(2030, " hippius-key_mode=split"), True),  # exact key only
        (_pad(2030, " hippius.key-mode=split"), True),  # no kernel `-`/`_` folding
        (_pad(2030, " HIPPIUS.key_mode=split"), True),  # no case folding
        (_pad(2030, " hippius.key_mode_x=split"), True),
        (_pad(2030, " xhippius.key_mode=split"), True),
    ],
)
def test_the_truncation_band_mirrors_the_guest(cmdline: str, hides: bool) -> None:
    assert ck.cmdline_may_hide_key_mode(cmdline) is hides


def test_the_band_is_the_guest_rule_applied_to_proc_cmdline() -> None:
    """The mirror IS the guest's rule on `/proc/cmdline` = OVMF's prefix +
    the measured bytes: the measured floor is the /proc floor less 14."""
    for n in (2006, 2007, 2008, 2009):
        proc_len = len(ck.OVMF_INITRD_PREFIX) + n
        want = proc_len >= ck.KEY_MODE_TRUNCATION_FLOOR
        assert ck.cmdline_may_hide_key_mode(_pad(n)) is want


# ── guardian address policy: `miner-agent::…::endpoint_host_allowed` ──────


@pytest.mark.parametrize(
    "ep",
    [
        "127.0.0.1:1", "127.255.255.255:1", "0.0.0.0:1", "0.1.2.3:1",
        "10.0.0.1:1", "10.255.255.255:1", "172.16.0.1:1", "172.31.255.255:1",
        "192.168.0.1:1", "192.168.255.255:1", "169.254.0.1:1", "169.254.169.254:80",
        "224.0.0.1:1", "239.255.255.255:1", "255.255.255.255:1",
        "100.100.100.100:53", "100.100.100.200:1",
        "[::1]:1", "[::]:1", "[fe80::1]:1", "[febf::1]:1", "[fc00::1]:1", "[fd12::1]:1",
        "[ff02::1]:1", "[::ffff:10.0.0.1]:1", "[::ffff:127.0.0.1]:1",
        "[::ffff:100.100.100.100]:1", "[::ffff:169.254.169.254]:1",
        "localhost:1", "a.localhost:1", "x.y.localhost:1",
    ],
)
def test_forbidden_guardian_addresses_are_refused(ep: str) -> None:
    assert ck.parse_endpoint(ep) == ep  # canonical, so only the policy refuses
    assert ck.endpoint_host_allowed(ep) is False
    with pytest.raises(ck.CustomerKeysError, match="guardian-ep-forbidden-address"):
        ck.check_endpoint_allowed(ck.GuardianBinding("split", PK, ep))


@pytest.mark.parametrize(
    "ep",
    [
        EP, "100.64.0.1:1", "100.127.255.255:1", "100.100.100.101:1", "100.100.100.199:1",
        "1.0.0.0:1", "8.8.8.8:443", "9.255.255.255:1", "11.0.0.0:1",
        "172.15.255.255:1", "172.32.0.0:1", "192.167.255.255:1", "192.169.0.0:1",
        "169.253.255.255:1", "169.255.0.0:1", "223.255.255.255:1", "255.255.255.254:1",
        "[2001:db8::1]:1", "[fec0::1]:1", "[fbff::1]:1", "[fe00::1]:1",
        "[::ffff:8.8.8.8]:1", "[::2]:1",
        "guardian.example.com:7443", "localhost.example.com:1", "localhostx:1", "mylocalhost:1",
    ],
)
def test_allowed_guardian_addresses_pass(ep: str) -> None:
    assert ck.parse_endpoint(ep) == ep
    assert ck.endpoint_host_allowed(ep) is True
    ck.check_endpoint_allowed(ck.GuardianBinding("customer", PK, ep))


def test_m0_has_no_address_to_check() -> None:
    ck.check_endpoint_allowed(None)


# ── differential: the Rust grammar is the source of truth ────────────────

_REAL_BIN = Path(settings.VALI_TICKET_VALIDATOR_BIN)

_CORPUS: list[str] = [
    BASE,
    BASE + "\n",
    "",
    _bound("split"),
    _bound("customer"),
    _bound("split") + "\n",
    f"{BASE} hippius.key_mode=hippius",
    _bound("hippius"),
    _bound() + " hippius.key_mode=split",
    _bound() + f" -- hippius.guardian_ep={_hex('1.2.3.4:5')}",
    f"{BASE} hippius.key_mode=",
    f"{BASE} hippius.key_mode",
    f"{BASE} hippius.key-mode=split",
    f"{BASE} Hippius.Guardian_EP={_hex('1.2.3.4:5')}",
    _bound(base='console="a b"'),
    _bound().replace(" ", "\t", 1),
    _bound().replace(" ", "\x0b", 1),
    _bound() + " x=é",
    "x=é console=hvc0",
    _bound("m1"),
    _bound("Split"),
    f"{BASE} hippius.guardian_ep={_hex(EP)}",
    f"{BASE} hippius.guardian_ep={EP}",
    f"{BASE} hippius.key_mode=split hippius.guardian_ep={_hex(EP)}",
    f"{BASE} hippius.key_mode=split hippius.guardian_pk={PK}",
    _bound(pk=PK.upper()),
    _bound(pk=PK[:-1]),
    _bound(pk=PK + "0"),
    "foo=hippius.guardian_ep console=hvc0",
    "hippius.key_mode_x=1 hippius.guardian_epoch=2",
    "hippius.key_mode=split=x hippius.guardian_pk=" + PK + " hippius.guardian_ep=" + _hex(EP),
]
for _ep in (
    "100.64.3.7:7443", "0.0.0.0:1", "255.255.255.255:65535", "256.1.1.1:80", "1.2.3:80",
    "100.064.3.7:80", "100.64.3.7:0", "100.64.3.7:65536", "100.64.3.7:+80",
    "guardian.example.com:7443", "Guardian.example.com:80", "a..b:80", "a.1:80",
    "-a.b:80", "a-.b:80", "a_b.example:80", "x" * 63 + ".io:1", "x" * 64 + ".io:1",
    ".".join(["a" * 63] * 4)[:253] + ":1", "[2001:db8::1]:7443", "[2001:DB8::1]:1",
    "[2001:db8:0:0:0:0:0:1]:1", "[2001:db8::0:1]:1", "[::1]:1", "[::]:9", "[1::]:5",
    "[1:0:1:0:1:0:1:0]:5", "[1:0:0:1:0:0:1:1]:5", "[1:0:0:1:1:0:0:1]:5",
    "[::ffff:1.2.3.4]:443", "[::ffff:102:304]:443", "[::1.2.3.4]:443", "[::102:304]:443",
    "[64:ff9b::1.2.3.4]:1", "[64:ff9b::102:304]:1", "[fe80::1%eth0]:80",
    "[2001:db8::1]", "[2001:db8::1]:", "[2001:db8::1]x:1", "2001:db8::1:80",
    "user@h.example:80", "h.example:80/x", "h.example:80:81",
    # H1b: endpoints that spell cloud-init markers in the clear — fine
    # once hex-encoded.
    "guardian.example.cc:443", "cc.example.com:1", "end-cc.example.com:1",
    "[2001:db8::cc:1]:443", "[cc::1]:443", "[::cc]:1", "h\u00f6st.example:1",
):
    _CORPUS.append(_bound(ep=_ep))
    # The same endpoint in the clear (the pre-H1b spelling) — refused,
    # as a marker or as a non-hex token.
    _CORPUS.append(_bound_raw(ep_token=_ep))

# H1b: every other spelling of the hex token.
_GOOD_TOK = _hex(EP)
for _tok in (
    _GOOD_TOK.upper(),  # uppercase hex
    _GOOD_TOK[:2] + _GOOD_TOK[2:].upper(),  # one uppercase digit
    _GOOD_TOK[:-1],  # odd length
    "3",
    "0x" + _GOOD_TOK,
    _GOOD_TOK + "g0",  # non-hex digit
    "ff",  # not UTF-8
    "c328",  # invalid UTF-8 sequence
    "e282ac",  # valid UTF-8 (the euro sign), no endpoint
    _GOOD_TOK + "00",  # decoded NUL suffix
    _GOOD_TOK + "20",  # decoded space suffix
    _hex(EP) + _hex(" init=/bin/sh"),  # a smuggled token, decoded
    _hex("100.64.3.7:07443"),  # non-canonical re-encoding: port
    _hex("100.064.3.7:7443"),  # … octet
    _hex("[2001:DB8::CC:1]:443"),  # … IPv6 case
    _hex("[2001:db8:0:0:0:0:cc:1]:443"),  # … IPv6 compression
    _hex("Guardian.Example.CC:443"),  # … DNS case
    _hex(f"{'a' * 256}:1"),  # decoded over MAX_ENDPOINT_LEN
    "3" * (2 * 259 + 2),  # encoded over the cap
    _hex(f"{'a' * 63}.{'a' * 63}.{'a' * 63}.{'a' * 61}:65535"),  # the longest good one
):
    _CORPUS.append(_bound_raw(ep_token=_tok))

# H5b (#1316): the Rust cloud-init directive refusals, on a keyed cmdline
# (refused) and on an M0 one (not our business: M0 is byte-identical).
for _extra in (
    "hippius.vm_id=acc:datasource:end_cc",
    "x=cc:runcmd:[[id]]",
    "cc: ssh_import_id: [x]",
    "y=end_cc",
    "hippius.lease_id=Xcc:",
    "url=http://x/cfg",
    "url",
    "xurl=1",
    "hippius.kbs_url=vsock://2:19266",
    "cloud-config-url=file:///run/x",
    "network-config=e30K",
    "ci.ds=Ec2",
    "ci.datasource=OpenStack",
    "ci.di.policy=search",
    "ci.datasource.ec2.strict_id=false",
    "rd.ci.ds=1",
    "ds=Ec2",
    "ds=",
    "ds",
    "xds=Ec2",
    "ds=nocloud",
    "ds=nocloud-net",
    "ds=nocloud;s=/run/cloud-init/seed/",
    "ds=nocloud-net;s=/run/cloud-init/seed/",
    "ds=nocloud;i=iid-evil",
    "ds=nocloud;h=evil",
    "ds=nocloud;s=http://evil/",
    "ds=nocloud;s=/run/cloud-init/seed/;i=iid-evil",
    "ds=nocloudx",
    "ds=nocloud;",
):
    _CORPUS.append(f"{_bound()} {_extra}")
    _CORPUS.append(f"{BASE} {_extra}")
_CORPUS.append(f"{BASE} hippius.key_mode=hippius url=http://x")


def _rust(cmdline: str) -> tuple[str, object]:
    proc = subprocess.run(  # noqa: S603 — fixed argv, test-only
        [str(_REAL_BIN), "parse-guardian-binding"],
        input=cmdline.encode("utf-8"),
        capture_output=True,
        timeout=30,
        check=False,
    )
    out = json.loads(proc.stdout)
    if out["tag"] == "err":
        return ("err", out["error"])
    b = out["binding"]
    return ("ok", None if b is None else (b["mode"], b["guardian_pk_hex"], b["guardian_ep"]))


def _python(cmdline: str) -> tuple[str, object]:
    try:
        b = ck.parse_cmdline(cmdline)
    except ck.CustomerKeysError as exc:
        return ("err", exc.classifier)
    return ("ok", None if b is None else (b.mode, b.guardian_pk, b.endpoint))


@pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=f"Rust validator not built at {_REAL_BIN}: cargo build -p hippius-ticket-validator",
)
@pytest.mark.parametrize("cmdline", _CORPUS)
def test_the_python_grammar_agrees_with_the_rust_grammar(cmdline: str) -> None:
    assert _python(cmdline) == _rust(cmdline)


def test_the_corpus_exercises_every_verdict() -> None:
    """Guard against a corpus that silently stops covering a branch."""
    verdicts = {_python(c)[1] if _python(c)[0] == "err" else "ok" for c in _CORPUS}
    assert {
        "ok",
        "guardian-cmdline-duplicate-token",
        "guardian-cmdline-empty-token",
        "guardian-cmdline-lookalike-token",
        "guardian-cmdline-quoted",
        "guardian-cmdline-non-printable",
        "guardian-cmdline-unknown-mode",
        "guardian-cmdline-orphan-guardian-token",
        "guardian-cmdline-missing-guardian-pk",
        "guardian-cmdline-missing-guardian-ep",
        "guardian-cmdline-bad-guardian-pk",
        "guardian-cmdline-bad-guardian-ep",
        "guardian-cmdline-cloud-init-directive",
    } <= verdicts


# ── H1b: the hex-encoded endpoint token ──────────────────────────────────


def test_the_ep_token_is_the_lowercase_hex_of_the_endpoint() -> None:
    # Pinned independently of the code (the same KATs as the Rust tests).
    assert ck.encode_ep_token("100.64.3.7:7443") == "3130302e36342e332e373a37343433"
    assert (
        ck.encode_ep_token("guardian.example.cc:443")
        == "677561726469616e2e6578616d706c652e63633a343433"
    )
    assert ck.encode_ep_token("[2001:db8::cc:1]:443") == "5b323030313a6462383a3a63633a315d3a343433"


@pytest.mark.parametrize(
    "ep", [EP, "guardian.example.cc:443", "[2001:db8::cc:1]:443", "[::ffff:1.2.3.4]:443"]
)
def test_the_binding_carries_the_decoded_endpoint_and_measures_the_hex(ep: str) -> None:
    binding = ck.binding_from_fields("customer", ep, PK)
    assert binding is not None and binding.endpoint == ep
    tokens = dict(binding.tokens())
    assert tokens[ck.GUARDIAN_EP_TOKEN] == ep.encode().hex()
    out = ck.augment_cmdline(BASE, binding)
    assert "cc:" not in out and "end_cc" not in out
    assert ck.parse_cmdline(out) == binding
    ck.check_cmdline(out, binding)
    ck.check_cloud_init_markers(binding, measured_cmdline=out)


@pytest.mark.parametrize(
    "value",
    [
        b"",
        EP.encode(),
        _hex(EP).upper().encode(),
        _hex(EP)[:-1].encode(),
        b"0x" + _hex(EP).encode(),
        b"ff",
        b"c328",
        (_hex(EP) + "00").encode(),
        _hex("100.64.3.7:07443").encode(),
        _hex("[2001:DB8::1]:1").encode(),
        _hex("a" * 256 + ":1").encode(),
        b"3" * 520,
    ],
)
def test_every_other_token_spelling_decodes_to_nothing(value: bytes) -> None:
    assert ck.decode_ep_token(value) is None


def test_a_smuggled_endpoint_field_cannot_become_a_token() -> None:
    # Hex-encoding makes a space in the field data, not a separator; the
    # decoded value is then no endpoint.
    with pytest.raises(ck.CustomerKeysError) as exc:
        ck.binding_from_fields("split", f"{EP} url=http://x", PK)
    assert exc.value.classifier == "guardian-cmdline-bad-guardian-ep"


# ── H1b: the M1/M2 lease_id charset ─────────────────────────────────────


@pytest.mark.parametrize("lease_id", ["lease-1", "L.1_a-B", "0", "a" * 200])
def test_a_lease_id_in_the_charset_passes(lease_id: str) -> None:
    ck.check_lease_id(ck.GuardianBinding("split", PK, EP), lease_id)


@pytest.mark.parametrize(
    "lease_id", ["", "lease 1", "lease:1", "lease=1", "l/1", "l;1", 'l"1', "lé", "l\n", None, 7]
)
def test_a_lease_id_outside_the_charset_is_refused_for_m1_m2(lease_id) -> None:
    for mode in ("split", "customer"):
        with pytest.raises(ck.CustomerKeysError) as exc:
            ck.check_lease_id(ck.GuardianBinding(mode, PK, EP), lease_id)
        assert exc.value.classifier == "customer-keys-bad-lease-id"


def test_m0_lease_ids_are_none_of_our_business() -> None:
    ck.check_lease_id(None, "lease:1 x=y")


def test_m0_is_byte_identical() -> None:
    assert ck.augment_cmdline(BASE, None) == BASE
    assert ck.binding_from_fields(None, None, None) is None
    assert ck.spec_fields(None) == {
        "key_mode": "hippius", "guardian_endpoint": "", "guardian_pubkey": ""
    }
