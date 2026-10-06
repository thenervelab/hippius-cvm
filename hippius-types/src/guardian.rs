//! Wire contract for **customer-held disk keys** — the key guardian.
//!
//! ## What it is
//!
//! A golden VM's disk KEK is only the LUKS *keyslot* key of its per-VM
//! overlay upper; the volume master key is generated in-guest and never
//! leaves SEV-SNP. Customer-held keys change who takes part in producing
//! that 32-byte keyslot key:
//!
//! | mode | wire | KEK |
//! |---|---|---|
//! | M0 | `hippius` (or no token) | `share_H` — today's KBS-released `luks-kek`, byte-identical |
//! | M1 | `split` | `HKDF(share_H ‖ share_C)` — Hippius AND the customer |
//! | M2 | `customer` | `HKDF(share_C)` — the customer only |
//!
//! `share_C` is held by the customer's **key guardian** (a customer-run
//! app in its own public repo). The guest asks the guardian FIRST — over
//! a miner-agent vsock relay on [`GUARDIAN_VSOCK_PORT`] that only ever
//! dials the endpoint named in the signed launch order — and only then
//! runs the unchanged KBS leg. Asking the KBS first would spend an
//! unconfirmed release (`max_unconfirmed_releases`) on every boot that
//! then stalls on a dead guardian, locking the VM out.
//!
//! Hippius never calls the guardian. The relay (the miner) and the
//! transport (NetBird, the internet) are untrusted and can only drop
//! traffic: the request carries an SNP report bound to a guardian-issued
//! nonce ([`crate::report_data::guardian`]), the share comes back
//! HPKE-sealed to a guest key that lives only in SNP RAM, and every
//! decision is signed by the guardian identity key `GK` whose public half
//! is in the **measured** cmdline ([`GUARDIAN_PK_TOKEN`]).
//!
//! ## What this module owns
//!
//! - the measured cmdline grammar ([`GuardianBinding::from_cmdline`]) —
//!   the guest, the guardian and the tests must read the same three
//!   tokens out of the same cmdline, so there is exactly one parser;
//! - the canonical-CBOR wire types of the three guardian endpoints;
//! - the signing *inputs* and domains (this crate stays signature-free,
//!   like [`crate::custody`]: Ed25519 lives with the guardian and the
//!   guest);
//! - [`combine_kek`], the one function that turns the shares into the
//!   keyslot key, with frozen known-answer tests shared by every party.
//!
//! ## Domain separation
//!
//! All three signature domains (response, denial, stamp ack) are
//! NUL-terminated ASCII tags whose first byte is `h` (`0x68`), a CBOR
//! *text-string* head — the same trick as the custody domains: a guardian
//! signing input can never parse as the CBOR map every other signed body
//! in the stack starts with, and no guardian domain is a prefix of
//! another or of any custody domain. The share and the M2 stamp token
//! are sealed under two distinct HPKE `info` strings, so neither
//! ciphertext opens as the other.

#[allow(unused_imports)]
// per-module slice of the alloc prelude — not every module needs every item
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::cbor::{assert_canonical, to_canonical_vec};
use crate::{HippiusTypesError, Result};
use ciborium::value::Value;
use hkdf::Hkdf;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The only wire version this build speaks.
pub const GUARDIAN_WIRE_V: u32 = 1;

/// Signing domain of a [`GuardianResponse`], signed by the guardian
/// identity key `GK`: `sig = Ed25519(GK, RESP_SIG_DOMAIN ‖ body)`.
pub const RESP_SIG_DOMAIN: &[u8] = b"hippius-guardian-resp-v1\0";
/// Signing domain of a [`GuardianDenial`], signed by the same `GK`.
pub const DENY_SIG_DOMAIN: &[u8] = b"hippius-guardian-deny-v1\0";
/// Signing domain of a [`GuardianStampAck`] (the M2 stamp-confirm
/// answer), signed by the same `GK`.
pub const STAMP_ACK_SIG_DOMAIN: &[u8] = b"hippius-guardian-stamp-ack-v1\0";

/// HPKE `info` of the wrapped `share_C` (the §20 suite:
/// X25519-HKDF-SHA256 / HKDF-SHA256 / ChaCha20-Poly1305). `aad` is
/// [`GuardianResponse::wrap_aad`].
pub const SHARE_HPKE_INFO: &[u8] = b"hippius-guardian-share-v1";
/// HPKE `info` of the wrapped M2 stamp token. Distinct from
/// [`SHARE_HPKE_INFO`] so a stamp-token ciphertext can never be opened as
/// a key share, or the reverse.
pub const STAMP_TOKEN_HPKE_INFO: &[u8] = b"hippius-guardian-stamp-token-v1";

/// HKDF salt of the M1 (split) combine. See [`combine_kek`].
pub const KEK_SPLIT_SALT: &[u8] = b"hippius-kek-split-v1";
/// HKDF salt of the M2 (customer) combine. See [`combine_kek`].
pub const KEK_CUSTOMER_SALT: &[u8] = b"hippius-kek-customer-v1";

/// Share, nonce, X25519 key and SHA-256 length.
pub const KEY_LEN: usize = 32;
/// SHA-384 length (the OVMF digest).
pub const SHA384_LEN: usize = 48;
/// Ed25519 signature length.
pub const SIG_LEN: usize = 64;
/// HPKE `enc` (X25519 encapsulated key) length.
pub const HPKE_ENC_LEN: usize = 32;
/// ChaCha20-Poly1305 tag length.
pub const AEAD_TAG_LEN: usize = 16;
/// Exact ciphertext length of a sealed 32-byte share or stamp token.
/// Both plaintexts are fixed-size, so anything else is a malformed or
/// foreign ciphertext and is refused before any HPKE work.
pub const WRAPPED_CT_LEN: usize = KEY_LEN + AEAD_TAG_LEN;
/// Upper bound on a `vm_id` — vali's `lifecycle.Vm.vm_id` column and the
/// KBS evidence bound (256), so every VM that can exist can use a
/// guardian.
pub const MAX_VM_ID_LEN: usize = 256;
/// Upper bound on the SNP report (the real one is 1184 bytes; the
/// guardian's verifier checks the exact layout).
pub const MAX_SNP_REPORT_LEN: usize = 4096;
/// Upper bound on the supplied VCEK/ASK(/ARK) DER chain.
pub const MAX_VCEK_CHAIN_LEN: usize = 16 * 1024;
/// The longest cmdline the guest kernel keeps: x86's `COMMAND_LINE_SIZE`
/// is 2048 bytes INCLUDING the NUL, and a longer one is truncated
/// silently (by the EFI stub at the last whitespace, or by the kernel
/// bytewise). This bounds the guest's `/proc/cmdline`, which is NOT the
/// measured string: see [`OVMF_INITRD_PREFIX`] and
/// [`MAX_MEASURED_CMDLINE_LEN`].
pub const MAX_CMDLINE_LEN: usize = 2047;
/// What OVMF's QEMU direct-kernel loader puts IN FRONT of the measured
/// cmdline whenever an initrd is present (edk2 `GenericQemuLoadImageLib`,
/// the `QemuLoadImageLib` of `OvmfPkg/AmdSev/AmdSevX64.dsc`, at our
/// pinned edk2-stable202511: `"%a%a%a", "", "initrd=initrd ",
/// CommandLine`). The kernel-hashes check covers the fw_cfg cmdline blob
/// only, so SEV measures the cmdline WITHOUT this prefix while the kernel
/// — and `/proc/cmdline` — see it with.
pub const OVMF_INITRD_PREFIX: &str = "initrd=initrd ";
/// Upper bound on the measured cmdline carried in a [`LaunchRecipe`]:
/// [`MAX_CMDLINE_LEN`] minus [`OVMF_INITRD_PREFIX`] = 2033. A token past
/// it would be measured (and so seen by the guardian when it recomputes
/// the digest) but cut before it reaches the guest: guest and guardian
/// would read different cmdlines under one valid measurement.
pub const MAX_MEASURED_CMDLINE_LEN: usize = MAX_CMDLINE_LEN - OVMF_INITRD_PREFIX.len();
/// Upper bound on a [`LaunchRecipe::vcpu_type`] (`EpycGenoa`, …).
pub const MAX_VCPU_TYPE_LEN: usize = 32;
/// Upper bound on a [`LaunchRecipe::vcpus`].
pub const MAX_VCPUS: u32 = 512;
/// Upper bound on a guardian endpoint string (a 253-byte DNS name, `:`
/// and a 5-digit port).
pub const MAX_ENDPOINT_LEN: usize = 253 + 1 + 5;

// ---------------------------------------------------------------------
// vsock relay
// ---------------------------------------------------------------------

/// AF_VSOCK port the miner-agent listens on for the guardian relay.
/// Distinct from [`crate::kbs_vsock::PORT`] (`0x4B42`, "KB") and every
/// other host port. `0x4B47` spells "KG" (key guardian).
pub const GUARDIAN_VSOCK_PORT: u32 = 0x4B47;

/// `POST` [`GuardianNonceRequest`] → [`GuardianNonceResponse`].
pub const GUARDIAN_NONCE_PATH: &str = "/v1/guardian/nonce";
/// `POST` [`GuardianReleaseRequest`] → [`SignedGuardianResponse`] or
/// [`SignedGuardianDenial`].
pub const GUARDIAN_RELEASE_PATH: &str = "/v1/guardian/release";
/// `POST` [`GuardianStampConfirm`] → [`SignedGuardianStampAck`]
/// (M2 only).
pub const GUARDIAN_STAMP_CONFIRM_PATH: &str = "/v1/guardian/stamp/confirm";

/// The only paths the guardian relay forwards. Unlike the KBS relay no
/// guardian path takes a query, so the match is on the WHOLE string:
/// `?anything` is refused rather than stripped (see
/// [`is_guardian_allowed_path`]). Keeping this closed is what stops the
/// relay from being an SSRF into the customer's guardian host.
pub const GUARDIAN_ALLOWED_PATHS: &[&str] = &[
    GUARDIAN_NONCE_PATH,
    GUARDIAN_RELEASE_PATH,
    GUARDIAN_STAMP_CONFIRM_PATH,
];

/// Hard cap on one relayed request body. The release request (report
/// 1184 B + chain ≤ 16 KiB + cmdline ≤ 4 KiB) is the largest; this
/// bounds a hostile guest's allocation before any work.
pub const GUARDIAN_MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Hard cap on one relayed response body (a signed response with two
/// 80-byte sealed blobs is well under 1 KiB).
pub const GUARDIAN_MAX_RESPONSE_BYTES: usize = 16 * 1024;

/// `true` iff `path` is exactly one of [`GUARDIAN_ALLOWED_PATHS`].
pub fn is_guardian_allowed_path(path: &str) -> bool {
    GUARDIAN_ALLOWED_PATHS.contains(&path)
}

/// Relay-LOCAL path: the miner-agent answers it itself and NEVER forwards
/// it to the guardian (it is deliberately not in
/// [`GUARDIAN_ALLOWED_PATHS`]). The response body is the canonical CBOR
/// ([`encode_canonical`]) of the [`LaunchRecipe`] the miner launched the
/// connecting CID's VM with — the exact OVMF / kernel / initrd digests,
/// measured cmdline, vCPU count + model and guest features its launch
/// digest was computed over. The guest copies it into
/// [`GuardianReleaseRequest::launch_recipe`].
///
/// Untrusted by design: the guardian resolves the digests against its
/// pinned release set, recomputes the launch digest and compares it with
/// the SNP report's `MEASUREMENT`, so a lying miner only earns a
/// `measurement-mismatch` denial. The request body is ignored.
pub const GUARDIAN_RECIPE_PATH: &str = "/v1/guardian/recipe";

/// Status + body classes the guardian relay answers with ITSELF (never a
/// guardian answer), on the same framing as the KBS relay:
/// guest → host [`crate::kbs_vsock::KbsProxyRequest`] `{path, body}`,
/// host → guest [`crate::kbs_vsock::KbsProxyResponse`] `{status, body}`,
/// each a `u32` big-endian length-prefixed CBOR value, one exchange per
/// connection.
///
/// A local answer's `body` is one of these ASCII class strings. They are
/// display / retry hints only: the relay is untrusted, so the guest keeps
/// waiting (with backoff) on every one of them — none is terminal.
pub mod relay_answer {
    /// The path is neither forwarded nor relay-local.
    pub const PATH_FORBIDDEN: (u16, &str) = (403, "guardian-path-forbidden");
    /// The connecting CID's VM was launched without a `guardian_ep`
    /// (or the relay cannot attribute the CID to a current VM).
    pub const NO_GUARDIAN: (u16, &str) = (403, "guardian-not-configured");
    /// The guardian endpoint could not be connected to.
    pub const UNREACHABLE: (u16, &str) = (502, "guardian-unreachable");
    /// The guardian did not answer within the relay's timeout.
    pub const TIMEOUT: (u16, &str) = (504, "guardian-timeout");
    /// The guardian's answer broke the relay contract (over the response
    /// cap, a redirect, a transport error mid-body).
    pub const BAD_RESPONSE: (u16, &str) = (502, "guardian-bad-response");
    /// The request body is over [`super::GUARDIAN_MAX_REQUEST_BYTES`].
    pub const REQUEST_TOO_LARGE: (u16, &str) = (413, "guardian-request-too-large");
    /// The relay could not produce this VM's launch recipe.
    pub const NO_RECIPE: (u16, &str) = (503, "guardian-recipe-unavailable");
    /// The VM is over the relay's per-VM request rate; retry later.
    pub const RATE_LIMITED: (u16, &str) = (429, "guardian-rate-limited");
}

// ---------------------------------------------------------------------
// Key mode + measured cmdline grammar
// ---------------------------------------------------------------------

/// Measured cmdline key selecting the [`KeyMode`].
pub const KEY_MODE_TOKEN: &str = "hippius.key_mode";
/// Measured cmdline key carrying the guardian's Ed25519 public key as 64
/// lowercase hex characters.
pub const GUARDIAN_PK_TOKEN: &str = "hippius.guardian_pk";
/// Measured cmdline key carrying the guardian endpoint: the LOWERCASE
/// HEX of the canonical `host:port` string ([`GuardianEndpoint::to_wire`]),
/// never the endpoint itself — see [`encode_guardian_ep_token`].
///
/// Why hex: cloud-init reads `cc:` … `end_cc` from ANYWHERE in the kernel
/// cmdline, even from inside another token's value, and a perfectly
/// ordinary customer endpoint spells it (`guardian.example.cc:443`,
/// `[2001:db8::cc:1]:443`). Hex has no `:` and no `_`, so no endpoint can
/// form either marker, and [`carries_cloud_init_directive`] can keep
/// refusing both markers everywhere without refusing any real guardian.
///
/// Callers never see the hex: [`GuardianBinding::endpoint`] is the
/// DECODED endpoint, and the launch order's `guardian_ep` stays the plain
/// canonical string it is compared against.
pub const GUARDIAN_EP_TOKEN: &str = "hippius.guardian_ep";

const GRAMMAR_KEYS: [&str; 3] = [KEY_MODE_TOKEN, GUARDIAN_PK_TOKEN, GUARDIAN_EP_TOKEN];

/// The only `ds=` values a customer-keys cmdline may carry. `nocloud` /
/// `nocloud-net` select the datasource the bake already pins; the `s=`
/// seed path is the bake's pinned `seedfrom` (which overrides it anyway).
/// Any other `ds=` value — another datasource, or NoCloud meta-data
/// such as `i=` (instance-id), `h=` (hostname) or arbitrary keys like
/// `public-keys` — is refused.
pub const ALLOWED_DS_VALUES: [&str; 4] = [
    "nocloud",
    "nocloud-net",
    "nocloud;s=/run/cloud-init/seed/",
    "nocloud-net;s=/run/cloud-init/seed/",
];

/// `true` if `cmdline` carries anything cloud-init (or its `ds-identify`
/// generator) takes from the kernel cmdline and acts on, on every boot.
/// Checked against cloud-init 22.4.2 (Debian 12), 24.4 (CentOS Stream
/// 10), 25.1.4 (Debian 13), 25.2 (Fedora 43) and 26.1 (Ubuntu 24.04):
///
/// - `cc:` … `end_cc` — `util.read_cc_from_cmdline` merges it into the
///   system config. Up to 25.x it matches `cc:` ANYWHERE, even inside
///   another token (`hippius.vm_id=acc:…end_cc`), so both markers are
///   refused as substrings; `ds-identify` also greps `*cc:*datasource_list*`.
/// - token keys (`key=value` split on the first `=`, whitespace-split —
///   `util.keyval_str_to_dict` / `ds-identify`'s `${tok%%=*}`, so
///   `hippius.kbs_url=` is NOT `url=`):
///   - `cloud-config-url`, `url` — fetched and merged as cloud-config;
///   - `network-config` — base64 network config, preferred over every
///     other source;
///   - `ci.*` — `ci.ds` / `ci.datasource` (datasource override),
///     `ci.di.policy` (ds-identify policy), `ci.datasource.ec2.strict_id`;
///   - `ds` — datasource selection and NoCloud meta-data; only
///     [`ALLOWED_DS_VALUES`] pass. NoCloud matches any token that STARTS
///     with `ds=nocloud`, so the whole value is compared.
///
/// Not refused, because it cannot hand cloud-init content: `ip=`/`ip6=`
/// (only makes cloud-init read `/run/net-*.conf`, which the measured
/// initramfs owns), `root=`, `net.ifnames=`, `cloud-init=disabled` and the
/// `scaleway`/`vultr` markers (datasources outside the pinned list; at
/// worst a denial of service, which a compromised Hippius has anyway).
///
/// Applied only to cmdlines that mention a grammar key (M1/M2 and
/// explicit `hippius`); an M0 cmdline is not read by this function at
/// all. The input is already printable ASCII with no `"`, so tokens are
/// separated by spaces only — the same split cloud-init's `str.split()`
/// makes.
pub fn carries_cloud_init_directive(cmdline: &str) -> bool {
    if cmdline.contains("cc:") || cmdline.contains("end_cc") {
        return true;
    }
    cmdline.split_ascii_whitespace().any(|token| {
        let (key, value) = match token.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (token, None),
        };
        match key {
            "url" | "cloud-config-url" | "network-config" => true,
            "ds" => value.is_none_or(|v| !ALLOWED_DS_VALUES.contains(&v)),
            k => k.starts_with("ci."),
        }
    })
}

/// Who holds the disk key. The wire string is lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyMode {
    /// M0 — Hippius (KBS + Vault Transit) holds the key. Today's mode.
    Hippius,
    /// M1 — split: the key needs Hippius' share AND the guardian's.
    Split,
    /// M2 — customer: the key is derived from the guardian's share only.
    Customer,
}

impl KeyMode {
    /// The wire / cmdline string.
    pub fn as_wire(self) -> &'static str {
        match self {
            KeyMode::Hippius => "hippius",
            KeyMode::Split => "split",
            KeyMode::Customer => "customer",
        }
    }

    /// Parse a wire string. Exact match only; unknown ⇒ `None`.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "hippius" => Some(KeyMode::Hippius),
            "split" => Some(KeyMode::Split),
            "customer" => Some(KeyMode::Customer),
            _ => None,
        }
    }
}

/// Why a cmdline does not parse under the guardian grammar. Fixed
/// classifiers (no free text) so the guest can report them as-is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CmdlineError {
    /// A grammar key appears more than once. The kernel keeps the last
    /// occurrence while a naive parser keeps the first, so any repeat is
    /// a way to make two readers disagree.
    #[error("guardian-cmdline-duplicate-token")]
    DuplicateToken,
    /// A grammar key with no `=` or an empty value.
    #[error("guardian-cmdline-empty-token")]
    EmptyToken,
    /// A key that is a grammar key up to ASCII case or `-`/`_` (the
    /// kernel treats dashes and underscores in parameter names as equal)
    /// but not spelled exactly.
    #[error("guardian-cmdline-lookalike-token")]
    LookalikeToken,
    /// A `"` anywhere in a cmdline that mentions a grammar key. The
    /// kernel lets a quoted value contain spaces, so a grammar token
    /// inside quotes is one token to the kernel and another to a
    /// whitespace splitter — refused rather than resolved.
    #[error("guardian-cmdline-quoted")]
    Quoted,
    /// A byte outside printable ASCII (`0x20..=0x7E`) in a cmdline that
    /// mentions a grammar key — tabs, `\x0B`, `0xA0`, any control or
    /// non-ASCII byte. Different whitespace definitions would otherwise
    /// let the kernel and this parser split the cmdline differently.
    #[error("guardian-cmdline-non-printable")]
    NonPrintable,
    /// `hippius.key_mode` has a value outside [`KeyMode`].
    #[error("guardian-cmdline-unknown-mode")]
    UnknownMode,
    /// A guardian token without a customer-keys mode (M0, implicit or
    /// explicit). Measured guardian tokens that no code path reads are
    /// a mismatch waiting to be exploited, never a harmless extra.
    #[error("guardian-cmdline-orphan-guardian-token")]
    OrphanGuardianToken,
    /// `split` / `customer` without `hippius.guardian_pk`.
    #[error("guardian-cmdline-missing-guardian-pk")]
    MissingGuardianPk,
    /// `split` / `customer` without `hippius.guardian_ep`.
    #[error("guardian-cmdline-missing-guardian-ep")]
    MissingGuardianEp,
    /// `hippius.guardian_pk` is not 64 lowercase hex characters.
    #[error("guardian-cmdline-bad-guardian-pk")]
    BadGuardianPk,
    /// `hippius.guardian_ep` is not the lowercase hex of a canonical
    /// `host:port` (see [`GUARDIAN_EP_TOKEN`]).
    #[error("guardian-cmdline-bad-guardian-ep")]
    BadGuardianEp,
    /// A cmdline that mentions a grammar key also carries something
    /// cloud-init reads from `/proc/cmdline` on every boot and acts on
    /// (see [`carries_cloud_init_directive`]).
    #[error("guardian-cmdline-cloud-init-directive")]
    CloudInitDirective,
}

/// Host part of a [`GuardianEndpoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardianHost {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    /// A lowercase LDH DNS name whose last label is not all-digit.
    Dns(String),
}

/// A guardian endpoint: an IPv4 literal, a bracketed IPv6 literal or a
/// DNS name, then `:port`.
///
/// The grammar accepts exactly ONE spelling per endpoint (lowercase,
/// RFC 5952 IPv6, no leading zeros in an IPv4 octet or the port), so the
/// measured token, the launch order's relay destination and the
/// guardian's own config compare as plain strings. There is no userinfo,
/// scheme or path: the relay dials `host:port` and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianEndpoint {
    pub host: GuardianHost,
    pub port: u16,
}

impl GuardianEndpoint {
    /// Parse a canonical `host:port`. Anything else is an error.
    pub fn parse(s: &str) -> core::result::Result<Self, CmdlineError> {
        parse_endpoint(s).ok_or(CmdlineError::BadGuardianEp)
    }

    /// The canonical string form — for every accepted input, exactly the
    /// string [`parse`](Self::parse) was given.
    pub fn to_wire(&self) -> String {
        match &self.host {
            GuardianHost::Ipv4(a) => format!("{a}:{}", self.port),
            GuardianHost::Ipv6(a) => format!("[{a}]:{}", self.port),
            GuardianHost::Dns(d) => format!("{d}:{}", self.port),
        }
    }
}

// No up-front length check: a DNS/IPv4 host is capped at 253 bytes and
// the port at 5 digits below, and a canonical IPv6 literal is at most 45,
// so nothing longer than MAX_ENDPOINT_LEN can get through.
fn parse_endpoint(s: &str) -> Option<GuardianEndpoint> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        if !inner
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b':' || b == b'.')
        {
            return None;
        }
        let addr: Ipv6Addr = inner.parse().ok()?;
        // RFC 5952 canonical form only: one spelling per address.
        if addr.to_string() != inner {
            return None;
        }
        (GuardianHost::Ipv6(addr), port)
    } else {
        let (host, port) = s.rsplit_once(':')?;
        (parse_name_or_ipv4(host)?, port)
    };
    Some(GuardianEndpoint {
        host,
        port: parse_port(port)?,
    })
}

fn parse_name_or_ipv4(host: &str) -> Option<GuardianHost> {
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        // All digits and dots is an IPv4 literal or nothing: `1.2.3` is
        // not a DNS name we accept (inet_aton would read it as 1.2.0.3).
        let addr: Ipv4Addr = host.parse().ok()?;
        if addr.to_string() != host {
            return None;
        }
        return Some(GuardianHost::Ipv4(addr));
    }
    let mut last = "";
    for label in host.split('.') {
        let ok_len = !label.is_empty() && label.len() <= 63;
        let ok_chars = label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok_len || !ok_chars || label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        last = label;
    }
    // An all-digit last label (`a.1`, `0x7f.1`) is not a real name, and
    // some resolvers would read the whole host as an address.
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(GuardianHost::Dns(host.to_string()))
}

fn parse_port(p: &str) -> Option<u16> {
    // The digit check is load-bearing: `u16::from_str` accepts a leading
    // `+`. Empty and out-of-range strings fail the parse itself; a leading
    // zero (including port 0) is refused as a second spelling.
    if p.starts_with('0') || !p.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    p.parse().ok()
}

/// The measured `hippius.guardian_ep=` value for `endpoint`: the lowercase
/// hex of its canonical string. The one encoding
/// [`GuardianBinding::from_cmdline`] accepts.
pub fn encode_guardian_ep_token(endpoint: &GuardianEndpoint) -> String {
    lower_hex(endpoint.to_wire().as_bytes())
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Decode a measured `hippius.guardian_ep=` value. Exactly one spelling
/// per endpoint: non-empty, even-length, lowercase hex only; the bytes it
/// decodes to are UTF-8 and a CANONICAL endpoint ([`GuardianEndpoint::parse`]);
/// and that endpoint re-encodes to the very same value.
fn parse_guardian_ep_token(v: &str) -> Option<GuardianEndpoint> {
    let b = v.as_bytes();
    if b.is_empty() || !b.len().is_multiple_of(2) || b.len() > 2 * MAX_ENDPOINT_LEN {
        return None;
    }
    let mut raw = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        raw.push((lower_hex_nibble(pair[0])? << 4) | lower_hex_nibble(pair[1])?);
    }
    let ep = GuardianEndpoint::parse(core::str::from_utf8(&raw).ok()?).ok()?;
    // Implied by the two rules above (lowercase hex is one-to-one, and the
    // endpoint grammar accepts only its own `to_wire`), and checked anyway:
    // this is the property every reader relies on.
    if encode_guardian_ep_token(&ep) != v {
        return None;
    }
    Some(ep)
}

fn parse_guardian_pk(v: &str) -> Option<[u8; KEY_LEN]> {
    let b = v.as_bytes();
    if b.len() != KEY_LEN * 2 {
        return None;
    }
    let mut out = [0u8; KEY_LEN];
    for (i, pair) in b.chunks_exact(2).enumerate() {
        out[i] = (lower_hex_nibble(pair[0])? << 4) | lower_hex_nibble(pair[1])?;
    }
    Some(out)
}

fn lower_hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Normalise a parameter name the way the kernel compares them
/// (`-` ≡ `_`), plus ASCII case, to catch lookalikes.
fn normalize_key(k: &str) -> String {
    k.bytes()
        .map(|b| match b {
            b'-' => '_',
            other => char::from(other.to_ascii_lowercase()),
        })
        .collect()
}

/// The guardian half of a VM's measured cmdline. Present iff the VM runs
/// M1 or M2; an M0 VM has no binding at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianBinding {
    /// [`KeyMode::Split`] or [`KeyMode::Customer`], never
    /// [`KeyMode::Hippius`].
    pub mode: KeyMode,
    /// The guardian identity key `GK` every guardian decision must verify
    /// against. Crypto-free here: this is 32 bytes, not yet checked to be
    /// a valid Ed25519 point — the verifier does that.
    pub guardian_pk: [u8; KEY_LEN],
    /// Where the relay dials — DECODED from the hex token, so it compares
    /// directly with a launch order's plain `guardian_ep`.
    pub endpoint: GuardianEndpoint,
}

impl GuardianBinding {
    /// Read the guardian tokens out of a kernel cmdline (as in
    /// `/proc/cmdline` or [`LaunchRecipe::cmdline`]).
    ///
    /// - no `hippius.key_mode` ⇒ `Ok(None)` (M0, byte-identical to a
    ///   pre-guardian VM) — and then any guardian token is an error;
    /// - `hippius.key_mode=hippius` ⇒ `Ok(None)` with the same rule;
    /// - `split` / `customer` ⇒ both guardian tokens are required and
    ///   must be canonical (`hippius.guardian_ep` is hex-encoded, see
    ///   [`GUARDIAN_EP_TOKEN`]; the binding carries it decoded);
    /// - any grammar key twice, empty, lookalike-spelled or inside a
    ///   quoted cmdline ⇒ an error.
    ///
    /// Tokens are split on ASCII whitespace; everything that is not a
    /// grammar key is ignored here (the guardian applies its own strict
    /// whole-cmdline policy on top). Tokens after a `--` are read like
    /// any other: guest and guardian both call this one function, so
    /// they cannot disagree, and a grammar key there is still a
    /// duplicate if it also appears before.
    pub fn from_cmdline(cmdline: &str) -> core::result::Result<Option<Self>, CmdlineError> {
        // `/proc/cmdline` ends in exactly one `\n` the kernel appends; the
        // measured string does not. Both spellings read the same.
        let cmdline = cmdline.strip_suffix('\n').unwrap_or(cmdline);
        let norm = normalize_key(cmdline);
        if GRAMMAR_KEYS.iter().any(|k| norm.contains(k)) {
            // The kernel splits on C `isspace` (which includes `\x0B`)
            // and, in some paths, Latin-1 0xA0; `split_ascii_whitespace`
            // does not. Rather than chase every whitespace definition,
            // a cmdline that carries a grammar key must be plain
            // printable ASCII, so the only separator left is ` `.
            if !cmdline.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                return Err(CmdlineError::NonPrintable);
            }
            if cmdline.contains('"') {
                return Err(CmdlineError::Quoted);
            }
            if carries_cloud_init_directive(cmdline) {
                return Err(CmdlineError::CloudInitDirective);
            }
        }
        let mut found: [Option<&str>; 3] = [None; 3];
        for token in cmdline.split_ascii_whitespace() {
            let (key, value) = match token.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (token, None),
            };
            let norm = normalize_key(key);
            let Some(idx) = GRAMMAR_KEYS.iter().position(|k| *k == norm) else {
                continue;
            };
            if key != GRAMMAR_KEYS[idx] {
                return Err(CmdlineError::LookalikeToken);
            }
            if found[idx].is_some() {
                return Err(CmdlineError::DuplicateToken);
            }
            match value {
                Some(v) if !v.is_empty() => found[idx] = Some(v),
                _ => return Err(CmdlineError::EmptyToken),
            }
        }
        let [mode, pk, ep] = found;
        let mode = match mode {
            None => KeyMode::Hippius,
            Some(m) => KeyMode::from_wire(m).ok_or(CmdlineError::UnknownMode)?,
        };
        if mode == KeyMode::Hippius {
            if pk.is_some() || ep.is_some() {
                return Err(CmdlineError::OrphanGuardianToken);
            }
            return Ok(None);
        }
        let pk = pk.ok_or(CmdlineError::MissingGuardianPk)?;
        let ep = ep.ok_or(CmdlineError::MissingGuardianEp)?;
        Ok(Some(GuardianBinding {
            mode,
            guardian_pk: parse_guardian_pk(pk).ok_or(CmdlineError::BadGuardianPk)?,
            endpoint: parse_guardian_ep_token(ep).ok_or(CmdlineError::BadGuardianEp)?,
        }))
    }
}

// ---------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------

/// `POST /v1/guardian/nonce` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianNonceRequest {
    pub v: u32,
    pub vm_id: String,
}

impl GuardianNonceRequest {
    pub fn validate(&self) -> Result<()> {
        check_v(self.v)?;
        check_vm_id(&self.vm_id)
    }
}

/// `/v1/guardian/nonce` response: a single-use nonce (the guardian keeps
/// it for 120 s) the guest folds into its report via
/// [`crate::report_data::guardian`].
///
/// The nonce endpoint never answers with a signed denial: a denial is
/// only replay-safe when it echoes a nonce the guest is waiting on, and
/// at this point there is none. Refusals here are plain HTTP errors the
/// guest treats as "retry".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianNonceResponse {
    pub v: u32,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
}

impl GuardianNonceResponse {
    pub fn validate(&self) -> Result<()> {
        check_v(self.v)?;
        check_len("nonce", &self.nonce, KEY_LEN)
    }
}

/// Everything the guardian needs to RECOMPUTE the SNP launch digest and
/// compare it with `report.measurement` — so it verifies a recipe it can
/// read, not an opaque hash.
///
/// The three image digests NAME the artifacts; they are not the digest
/// inputs. The guardian resolves each against its customer-pinned
/// release set (the published golden manifest) and runs the launch-digest
/// computation over the pinned artifacts, so an unpinned digest is a
/// `release-not-pinned` denial before any measurement math.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRecipe {
    /// SHA-384 of the OVMF firmware file.
    #[serde(with = "serde_bytes")]
    pub ovmf_sha384: Vec<u8>,
    /// SHA-256 of the kernel image.
    #[serde(with = "serde_bytes")]
    pub kernel_sha256: Vec<u8>,
    /// SHA-256 of the initrd.
    #[serde(with = "serde_bytes")]
    pub initrd_sha256: Vec<u8>,
    /// The exact measured cmdline (no trailing newline).
    pub cmdline: String,
    pub vcpus: u32,
    /// vCPU model as `hippius-launch-digest --vcpu-type` takes it
    /// (`EpycGenoa`, `EpycTurin`, …).
    pub vcpu_type: String,
    /// SEV-SNP guest-features bitmap (`0x1` = SNPActive today).
    pub guest_features: u64,
}

impl LaunchRecipe {
    pub fn validate(&self) -> Result<()> {
        check_len("ovmf_sha384", &self.ovmf_sha384, SHA384_LEN)?;
        check_len("kernel_sha256", &self.kernel_sha256, KEY_LEN)?;
        check_len("initrd_sha256", &self.initrd_sha256, KEY_LEN)?;
        if self.cmdline.is_empty() || self.cmdline.len() > MAX_MEASURED_CMDLINE_LEN {
            return Err(schema("cmdline length out of bounds".into()));
        }
        // The recipe is the MEASURED string, never the `/proc/cmdline`
        // spelling: no trailing `\n`, no control or non-ASCII byte. Else
        // the guardian (which strips one `\n`) and the guest (whose
        // `/proc/cmdline` appends another) would read different strings.
        if !self.cmdline.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
            return Err(schema("cmdline must be printable ASCII".into()));
        }
        if self.vcpus == 0 || self.vcpus > MAX_VCPUS {
            return Err(schema("vcpus out of bounds".into()));
        }
        let vt = self.vcpu_type.as_bytes();
        if vt.is_empty()
            || vt.len() > MAX_VCPU_TYPE_LEN
            || !vt.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return Err(schema("vcpu_type malformed".into()));
        }
        Ok(())
    }

    /// The guardian binding the recipe's cmdline declares.
    pub fn binding(&self) -> core::result::Result<Option<GuardianBinding>, CmdlineError> {
        GuardianBinding::from_cmdline(&self.cmdline)
    }
}

/// `POST /v1/guardian/release` body.
///
/// `snp_report.REPORT_DATA` must equal
/// [`crate::report_data::guardian`]`(nonce, vm_id, guest_pub, share_c_version)`.
/// `guest_pub` is a fresh X25519 key for this request, distinct from the
/// KBS leg's ephemeral key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianReleaseRequest {
    pub v: u32,
    pub vm_id: String,
    pub key_mode: KeyMode,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub snp_report: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub guest_pub: Vec<u8>,
    /// Concatenated DER: VCEK, ASK and optionally ARK, as the guest (or
    /// the miner, via the extended report) found them. Untrusted input:
    /// the guardian verifies it up to its own PINNED ARK, so no KDS round
    /// trip is needed. Empty = none supplied (the guardian may then fetch
    /// from KDS, or deny `bad-chain`).
    #[serde(with = "serde_bytes")]
    pub vcek_chain: Vec<u8>,
    pub launch_recipe: LaunchRecipe,
    /// The `share_C` version recorded in the volume's LUKS2 token.
    /// Absent on first boot (blank volume, nothing recorded yet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_c_version: Option<u32>,
}

impl GuardianReleaseRequest {
    pub fn validate(&self) -> Result<()> {
        check_v(self.v)?;
        check_vm_id(&self.vm_id)?;
        check_guardian_mode(self.key_mode)?;
        check_len("nonce", &self.nonce, KEY_LEN)?;
        if self.snp_report.is_empty() || self.snp_report.len() > MAX_SNP_REPORT_LEN {
            return Err(schema("snp_report length out of bounds".into()));
        }
        check_len("guest_pub", &self.guest_pub, KEY_LEN)?;
        if self.vcek_chain.len() > MAX_VCEK_CHAIN_LEN {
            return Err(schema("vcek_chain too long".into()));
        }
        if self.share_c_version == Some(0) {
            return Err(schema("share_c_version must be >= 1".into()));
        }
        self.launch_recipe.validate()?;
        // The request's `key_mode` is untrusted relay input; the measured
        // cmdline is not. A request whose mode differs from the one its
        // recipe measures (M2 asked as M1, or any mode over an M0 recipe)
        // is refused here, before any mode-specific policy runs.
        let binding = self
            .launch_recipe
            .binding()
            .map_err(|e| schema(format!("launch_recipe cmdline: {e}")))?
            .ok_or_else(|| schema("launch_recipe measures no guardian binding".into()))?;
        if binding.mode != self.key_mode {
            return Err(schema(
                "key_mode does not match the measured cmdline".into(),
            ));
        }
        Ok(())
    }
}

/// An HPKE-sealed 32-byte secret: `(enc, ct)` from the §20 suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianWrapped {
    #[serde(with = "serde_bytes")]
    pub enc: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ct: Vec<u8>,
}

impl GuardianWrapped {
    fn validate(&self, field: &str) -> Result<()> {
        if self.enc.len() != HPKE_ENC_LEN || self.ct.len() != WRAPPED_CT_LEN {
            return Err(schema(format!("{field}: bad sealed length")));
        }
        Ok(())
    }
}

/// The guardian's positive decision. Echoes `vm_id`, `nonce` and
/// `sha256(guest_pub)` so the guest refuses a response minted for any
/// request but the one it has outstanding.
///
/// The guest verifies the [`SignedGuardianResponse`] signature against
/// the MEASURED `guardian_pk` before it opens anything. HPKE alone is not
/// enough: in M2 an unauthenticated share on first boot would let the
/// relay choose the KEK the blank volume gets formatted with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianResponse {
    pub v: u32,
    pub vm_id: String,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub guest_pub_hash: Vec<u8>,
    pub key_mode: KeyMode,
    /// The version of the share sealed below (≥ 1). The guest records it
    /// in the LUKS2 token on first boot and sends it back afterwards.
    pub share_c_version: u32,
    /// `share_C`, sealed to `guest_pub` under [`SHARE_HPKE_INFO`] with
    /// `aad = `[`GuardianResponse::wrap_aad`].
    pub wrapped_share: GuardianWrapped,
    /// M2 only: the guardian's confirmed volume stamp `E` — the guest
    /// refuses a volume whose stamp is below it (port of the KBS
    /// `volume_stamp` semantics; in M2 the KBS stamp is off).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_volume_stamp: Option<u64>,
    /// M2 only: the single-use token authorising
    /// [`GuardianStampConfirm`] for `E + 1`, sealed under
    /// [`STAMP_TOKEN_HPKE_INFO`] with the same `aad`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stamp_token_wrapped: Option<GuardianWrapped>,
}

impl GuardianResponse {
    pub fn validate(&self) -> Result<()> {
        check_v(self.v)?;
        check_vm_id(&self.vm_id)?;
        check_len("nonce", &self.nonce, KEY_LEN)?;
        check_len("guest_pub_hash", &self.guest_pub_hash, KEY_LEN)?;
        check_guardian_mode(self.key_mode)?;
        if self.share_c_version == 0 {
            return Err(schema("share_c_version must be >= 1".into()));
        }
        self.wrapped_share.validate("wrapped_share")?;
        // The stamp belongs to the guardian in M2 and to the KBS in M1:
        // the stamp fields ride with `customer` and with nothing else,
        // and never one without the other.
        match (
            self.key_mode,
            self.expected_volume_stamp,
            &self.stamp_token_wrapped,
        ) {
            (KeyMode::Customer, Some(_), Some(t)) => t.validate("stamp_token_wrapped"),
            (KeyMode::Split, None, None) => Ok(()),
            _ => Err(schema("stamp fields do not match key_mode".into())),
        }
    }

    /// The HPKE `aad` of both sealed fields: `sha256` of the canonical
    /// CBOR of this body with `wrapped_share` and `stamp_token_wrapped`
    /// removed. It binds each ciphertext to every other field of the
    /// exact signed response it arrived in (vm_id, nonce, guest key,
    /// mode, version, stamp), so a sealed share lifted into another
    /// response does not open. The sealed fields themselves are left out
    /// because the aad has to exist before they do.
    pub fn wrap_aad(&self) -> Result<[u8; KEY_LEN]> {
        let mut v = Value::serialized(self).map_err(|e| schema(format!("encode: {e}")))?;
        if let Value::Map(entries) = &mut v {
            entries.retain(|(k, _)| {
                !matches!(k, Value::Text(t) if t == "wrapped_share" || t == "stamp_token_wrapped")
            });
        }
        let bytes = to_canonical_vec(&v)?;
        Ok(Sha256::digest(&bytes).into())
    }

    /// Is this (signature-verified, decoded) response an answer to
    /// `request`, for the VM whose measured cmdline yielded `binding`?
    ///
    /// One shared rule set so the guest and every other consumer refuse
    /// the same things: `vm_id`, `nonce` and `sha256(guest_pub)` must
    /// echo the request; `key_mode` must equal both the request's and
    /// the measured binding's; and when the request named a
    /// `share_c_version` (the one in the volume's LUKS2 token) the
    /// response must seal exactly that version — a different share
    /// would open no keyslot, or on a rollback open an old one. The
    /// caller verifies the Ed25519 signature against
    /// `binding.guardian_pk` BEFORE calling this.
    pub fn check_against(
        &self,
        binding: &GuardianBinding,
        request: &GuardianReleaseRequest,
    ) -> Result<()> {
        self.validate()?;
        check_echo(&self.vm_id, &self.nonce, &self.guest_pub_hash, request)?;
        if self.key_mode != request.key_mode || self.key_mode != binding.mode {
            return Err(schema("key_mode does not match the request".into()));
        }
        if request
            .share_c_version
            .is_some_and(|v| v != self.share_c_version)
        {
            return Err(schema("share_c_version does not match the request".into()));
        }
        Ok(())
    }
}

/// The request echo every guardian decision must carry.
fn check_echo(
    vm_id: &str,
    nonce: &[u8],
    guest_pub_hash_echo: &[u8],
    request: &GuardianReleaseRequest,
) -> Result<()> {
    if vm_id != request.vm_id {
        return Err(schema("vm_id does not match the request".into()));
    }
    if nonce != request.nonce.as_slice() {
        return Err(schema("nonce does not match the request".into()));
    }
    if guest_pub_hash_echo != guest_pub_hash(&request.guest_pub) {
        return Err(schema("guest_pub_hash does not match the request".into()));
    }
    Ok(())
}

/// Signed response: `sig = Ed25519(GK, `[`RESP_SIG_DOMAIN`]` ‖ body)`,
/// `body` = canonical CBOR of [`GuardianResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGuardianResponse {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

impl SignedGuardianResponse {
    /// The exact bytes `sig` covers.
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(RESP_SIG_DOMAIN, &self.body)
    }

    pub fn validate(&self) -> Result<()> {
        check_len("sig", &self.sig, SIG_LEN)
    }
}

/// Closed vocabulary of a signed guardian refusal (design §6). The guest
/// surfaces it as `awaiting-guardian:refused:<wire>` and keeps waiting —
/// except [`Erased`](Self::Erased), which is terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuardianDenyReason {
    /// Unknown VM and auto-enroll is off: waits for `guardian approve`.
    AwaitingApproval,
    /// An OVMF / kernel / initrd digest is not in the pinned release set.
    ReleaseNotPinned,
    /// The recomputed launch digest, or a measured cmdline token, does
    /// not match.
    MeasurementMismatch,
    /// SNP guest policy is not the allowed value (or VMPL ≠ 0).
    Policy,
    /// TCB below the customer's floor.
    Tcb,
    /// Chip not allowed by the VM's chip policy (`tofu` / `allowlist`).
    ChipNotApproved,
    /// Request / cmdline mode differs from the enrolled mode.
    ModeMismatch,
    /// The guardian does not know this VM and will not enroll it.
    UnknownVm,
    /// The VM's shares were erased. Terminal.
    Erased,
    /// Nonce unknown, expired or already used.
    BadNonce,
    /// Report malformed, bad signature, or `REPORT_DATA` mismatch.
    BadReport,
    /// Certificate chain does not verify to the pinned ARK.
    BadChain,
    /// Rate limited.
    Rate,
    /// The request named a `share_c_version` (the one recorded in the
    /// volume's LUKS2 token) that the guardian no longer holds — pruned,
    /// or never issued. Not terminal: the customer can restore it from a
    /// guardian export.
    ShareVersionUnavailable,
}

impl GuardianDenyReason {
    /// Every reason, for exhaustive tests and UIs.
    pub const ALL: [GuardianDenyReason; 14] = [
        GuardianDenyReason::AwaitingApproval,
        GuardianDenyReason::ReleaseNotPinned,
        GuardianDenyReason::MeasurementMismatch,
        GuardianDenyReason::Policy,
        GuardianDenyReason::Tcb,
        GuardianDenyReason::ChipNotApproved,
        GuardianDenyReason::ModeMismatch,
        GuardianDenyReason::UnknownVm,
        GuardianDenyReason::Erased,
        GuardianDenyReason::BadNonce,
        GuardianDenyReason::BadReport,
        GuardianDenyReason::BadChain,
        GuardianDenyReason::Rate,
        GuardianDenyReason::ShareVersionUnavailable,
    ];

    /// The kebab-case wire string.
    pub fn as_wire(self) -> &'static str {
        match self {
            GuardianDenyReason::AwaitingApproval => "awaiting-approval",
            GuardianDenyReason::ReleaseNotPinned => "release-not-pinned",
            GuardianDenyReason::MeasurementMismatch => "measurement-mismatch",
            GuardianDenyReason::Policy => "policy",
            GuardianDenyReason::Tcb => "tcb",
            GuardianDenyReason::ChipNotApproved => "chip-not-approved",
            GuardianDenyReason::ModeMismatch => "mode-mismatch",
            GuardianDenyReason::UnknownVm => "unknown-vm",
            GuardianDenyReason::Erased => "erased",
            GuardianDenyReason::BadNonce => "bad-nonce",
            GuardianDenyReason::BadReport => "bad-report",
            GuardianDenyReason::BadChain => "bad-chain",
            GuardianDenyReason::Rate => "rate",
            GuardianDenyReason::ShareVersionUnavailable => "share-version-unavailable",
        }
    }

    /// Parse a wire string. Unknown ⇒ `None`.
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_wire() == s)
    }

    /// `true` for the one reason no retry can clear.
    pub fn is_terminal(self) -> bool {
        self == GuardianDenyReason::Erased
    }
}

/// The guardian's signed refusal. Echoes the request's `nonce` AND
/// `sha256(guest_pub)`.
///
/// The nonce alone is not enough: it reaches the guest through the
/// unsigned nonce response, so a relay can hand the guest an OLD nonce
/// and then replay the signed denial it recorded for it — e.g. a terminal
/// `erased` from before the customer restored their guardian. The
/// `guest_pub` is a fresh X25519 key the guest generated in SNP RAM for
/// this one request, so no earlier denial can carry its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianDenial {
    pub v: u32,
    pub vm_id: String,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub guest_pub_hash: Vec<u8>,
    pub reason: GuardianDenyReason,
}

impl GuardianDenial {
    pub fn validate(&self) -> Result<()> {
        check_v(self.v)?;
        check_vm_id(&self.vm_id)?;
        check_len("nonce", &self.nonce, KEY_LEN)?;
        check_len("guest_pub_hash", &self.guest_pub_hash, KEY_LEN)
    }

    /// Is this (signature-verified, decoded) denial an answer to
    /// `request`? Same echo rules as
    /// [`GuardianResponse::check_against`]: `vm_id`, `nonce` and
    /// `sha256(guest_pub)`. A denial that fails this is noise, never a
    /// reason to show `refused:*` — least of all a terminal `erased`.
    pub fn check_against(&self, request: &GuardianReleaseRequest) -> Result<()> {
        self.validate()?;
        check_echo(&self.vm_id, &self.nonce, &self.guest_pub_hash, request)
    }
}

/// Signed denial: `sig = Ed25519(GK, `[`DENY_SIG_DOMAIN`]` ‖ body)`,
/// `body` = canonical CBOR of [`GuardianDenial`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGuardianDenial {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

impl SignedGuardianDenial {
    /// The exact bytes `sig` covers.
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(DENY_SIG_DOMAIN, &self.body)
    }

    pub fn validate(&self) -> Result<()> {
        check_len("sig", &self.sig, SIG_LEN)
    }
}

/// `POST /v1/guardian/stamp/confirm` body (M2 only). The guardian-side
/// twin of the KBS `VolumeStampConfirmBody { vm_id, value, token }`:
/// after writing stamp `target = E + 1` into its unlocked volume the
/// guest presents the single-use `token` it unwrapped from
/// [`GuardianResponse::stamp_token_wrapped`]. The guardian's CAS accepts
/// only `stored + 1`, so an aborted boot confirms nothing and cannot
/// widen the expected-vs-actual gap. No attestation: the sealed token is
/// the authenticator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianStampConfirm {
    pub v: u32,
    pub vm_id: String,
    pub target: u64,
    #[serde(with = "serde_bytes")]
    pub token: Vec<u8>,
}

impl GuardianStampConfirm {
    pub fn validate(&self) -> Result<()> {
        check_v(self.v)?;
        check_vm_id(&self.vm_id)?;
        if self.target == 0 {
            return Err(schema("target must be >= 1".into()));
        }
        check_len("token", &self.token, KEY_LEN)
    }
}

/// The body of the guardian's SIGNED answer to a [`GuardianStampConfirm`]
/// (M2): "I advanced this VM's stamp to `target`, on THIS token".
///
/// The miner relays the answer, so an unsigned ack would let it tell the
/// guest a confirm landed while it dropped it — freezing the guardian's
/// `E` at a value the guest believes is behind it, which is a free
/// rollback window. So the guest (on the mandatory first-boot confirm)
/// counts a confirm as done only on a [`SignedGuardianStampAck`] that
/// verifies under the MEASURED `guardian_pk` and passes
/// [`check_against`](Self::check_against) its own request.
///
/// `token_hash` is `sha256` of the single-use token being confirmed
/// ([`stamp_token_hash`]). `vm_id` and `target` alone are not unique: after
/// a guardian re-init or an authorised rollback the same `(vm_id, target)`
/// comes round again, and an ack recorded then would verify now. The
/// token's hash pins the ack to this exact confirm — PROVIDED the token
/// is fresh per release. Guardian requirement: mint the stamp token at
/// random for every release (and keep it for the CAS). A deterministic
/// token such as `HMAC(mac_key, vm_id ‖ target)` recurs with its
/// `(vm_id, target)` and would let a recorded ack be replayed. The hash,
/// not the token: the ack is relayed in the clear and must not hand the
/// token to the relay (it is already spent, but the relay has no business
/// holding it).
///
/// Guardian requirement, liveness: a confirm that re-presents the token
/// of the target the guardian ALREADY holds (the CAS committed, the ack
/// was lost on the way back) must be answered with the same signed ack,
/// not refused as a spent token — the guest's first-boot confirm retries
/// and otherwise fails closed on a stamp that did advance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianStampAck {
    pub v: u32,
    pub vm_id: String,
    /// The stamp value the guardian now holds (`E + 1` of the release).
    pub target: u64,
    /// `sha256(token)` of the confirmed [`GuardianStampConfirm::token`].
    #[serde(with = "serde_bytes")]
    pub token_hash: Vec<u8>,
}

impl GuardianStampAck {
    pub fn validate(&self) -> Result<()> {
        check_v(self.v)?;
        check_vm_id(&self.vm_id)?;
        if self.target == 0 {
            return Err(schema("target must be >= 1".into()));
        }
        check_len("token_hash", &self.token_hash, KEY_LEN)
    }

    /// Is this (signature-verified, decoded) ack the answer to `confirm`?
    /// `vm_id`, `target` and `sha256(token)` must all echo it. The caller
    /// verifies the Ed25519 signature against the measured `guardian_pk`
    /// over [`STAMP_ACK_SIG_DOMAIN`] BEFORE calling this.
    pub fn check_against(&self, confirm: &GuardianStampConfirm) -> Result<()> {
        self.validate()?;
        if self.vm_id != confirm.vm_id {
            return Err(schema("vm_id does not match the confirm".into()));
        }
        if self.target != confirm.target {
            return Err(schema("target does not match the confirm".into()));
        }
        if self.token_hash != stamp_token_hash(&confirm.token) {
            return Err(schema("token_hash does not match the confirm".into()));
        }
        Ok(())
    }
}

/// `sha256(token)` as carried in [`GuardianStampAck::token_hash`].
pub fn stamp_token_hash(token: &[u8]) -> [u8; KEY_LEN] {
    Sha256::digest(token).into()
}

/// `/v1/guardian/stamp/confirm` response (M2):
/// `sig = Ed25519(GK, `[`STAMP_ACK_SIG_DOMAIN`]` ‖ body)`, `body` =
/// canonical CBOR of [`GuardianStampAck`]. A refusal is a plain non-2xx
/// answer (the guest just retries or gives up; nothing it could act on).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGuardianStampAck {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

impl SignedGuardianStampAck {
    /// The exact bytes `sig` covers.
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(STAMP_ACK_SIG_DOMAIN, &self.body)
    }

    pub fn validate(&self) -> Result<()> {
        check_len("sig", &self.sig, SIG_LEN)
    }
}

/// `domain ‖ body` — the exact bytes a guardian signature covers.
pub fn signing_input(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + body.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(body);
    out
}

/// `sha256(guest_pub)` as echoed in [`GuardianResponse::guest_pub_hash`].
pub fn guest_pub_hash(guest_pub: &[u8]) -> [u8; KEY_LEN] {
    Sha256::digest(guest_pub).into()
}

/// Canonical (RFC 8949 §4.2.1) CBOR of any guardian struct.
pub fn encode_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let v = Value::serialized(value).map_err(|e| schema(format!("encode: {e}")))?;
    to_canonical_vec(&v)
}

/// Decode a guardian struct, accepting ONLY the exact bytes
/// [`encode_canonical`] would produce for the decoded value — same rule
/// and same reasons as [`crate::custody::decode_canonical`] (serde's
/// typed decode also takes integer arrays for byte strings, ignores
/// tags and reads `null` as an omitted `Option`; each would be a second
/// wire image of one signed message).
pub fn decode_canonical<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    assert_canonical(bytes)?;
    let value: T = ciborium::de::from_reader(bytes).map_err(|e| schema(format!("decode: {e}")))?;
    if encode_canonical(&value)? != bytes {
        return Err(schema("not the canonical encoding of its own value".into()));
    }
    Ok(value)
}

// ---------------------------------------------------------------------
// KEK combine
// ---------------------------------------------------------------------

/// Derive the disk keyslot KEK from the shares the guest holds.
///
/// ```text
/// M0 hippius : KEK = share_H                                   (byte-identical to today)
/// M1 split   : KEK = HKDF-SHA256(salt = "hippius-kek-split-v1",
///                                ikm  = share_H ‖ share_C,
///                                info = u16be(len vm_id) ‖ vm_id, L = 32)
/// M2 customer: KEK = HKDF-SHA256(salt = "hippius-kek-customer-v1",
///                                ikm  = share_C, info = same, L = 32)
/// ```
///
/// Why HKDF and not XOR: the per-mode salt means the same `share_C`
/// never yields the same KEK under M1 and M2, and `info` binds the KEK to
/// the VM, so a share replayed into another VM derives a key that opens
/// nothing. Both shares are fixed 32 bytes, so `share_H ‖ share_C` is
/// unambiguous.
///
/// The mode decides which shares must be present; any other combination
/// (a share missing, or a share the mode does not use) is an error rather
/// than a silent fallback — a guest that somehow holds `share_H` in M2
/// has a bug worth stopping on.
///
/// The IKM copy lives in a zeroizing buffer and the output is returned
/// in one. (`hkdf`'s internal PRK state is not zeroized on drop; it
/// lives on this function's stack for the duration of the call only.)
pub fn combine_kek(
    mode: KeyMode,
    share_h: Option<&[u8; KEY_LEN]>,
    share_c: Option<&[u8; KEY_LEN]>,
    vm_id: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    match (mode, share_h, share_c) {
        (KeyMode::Hippius, Some(h), None) => Ok(Zeroizing::new(*h)),
        (KeyMode::Split, Some(h), Some(c)) => {
            let mut ikm = Zeroizing::new([0u8; 2 * KEY_LEN]);
            ikm[..KEY_LEN].copy_from_slice(h);
            ikm[KEY_LEN..].copy_from_slice(c);
            hkdf_kek(KEK_SPLIT_SALT, &ikm[..], vm_id)
        }
        (KeyMode::Customer, None, Some(c)) => hkdf_kek(KEK_CUSTOMER_SALT, c, vm_id),
        _ => Err(schema(format!(
            "combine_kek: shares do not match key_mode {}",
            mode.as_wire()
        ))),
    }
}

fn hkdf_kek(salt: &[u8], ikm: &[u8], vm_id: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    check_vm_id(vm_id)?;
    // `check_vm_id` bounds the length far below u16::MAX; the conversion
    // stays checked so the framing can never silently truncate.
    let len = u16::try_from(vm_id.len()).map_err(|_| schema("vm_id too long".into()))?;
    let mut info = Vec::with_capacity(2 + vm_id.len());
    info.extend_from_slice(&len.to_be_bytes());
    info.extend_from_slice(vm_id.as_bytes());
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(&info, &mut okm[..])
        .map_err(|_| schema("hkdf expand".into()))?;
    Ok(okm)
}

fn check_guardian_mode(mode: KeyMode) -> Result<()> {
    if mode == KeyMode::Hippius {
        // M0 never talks to a guardian.
        return Err(schema("key_mode hippius has no guardian".into()));
    }
    Ok(())
}

fn check_v(v: u32) -> Result<()> {
    if v != GUARDIAN_WIRE_V {
        return Err(schema(format!(
            "unsupported v={v} (want {GUARDIAN_WIRE_V})"
        )));
    }
    Ok(())
}

fn check_vm_id(vm_id: &str) -> Result<()> {
    if vm_id.is_empty() || vm_id.len() > MAX_VM_ID_LEN {
        return Err(schema("vm_id length out of bounds".into()));
    }
    Ok(())
}

fn check_len(field: &str, bytes: &[u8], want: usize) -> Result<()> {
    if bytes.len() != want {
        return Err(schema(format!("{field} must be {want} bytes")));
    }
    Ok(())
}

fn schema(msg: String) -> HippiusTypesError {
    HippiusTypesError::GuardianSchema(msg)
}

#[cfg(test)]
mod tests;
