//! Stage 1 — load + decode the COSE_Sign1 `OrderTicket` (§6).
//!
//! The ticket arrives at the guest via the miner-supplied UKI input
//! channel (a file path baked into the measured config). It is two
//! things at once:
//!
//! - the opaque `cose_ticket` field of the KBS `/v1/kbs/release`
//!   request — shipped to the KBS **byte-for-byte untouched**, and
//! - the source of the `ExpectedRelease` bindings the §6/§7/§19/§20
//!   verify gate checks — which means the agent must DECODE it.
//!
//! ## Decoding without verifying is safe
//!
//! The agent does NOT verify the L1 COSE signature on the ticket —
//! that is the KBS's job (§7). Reading the payload un-verified is
//! still safe: every field the agent pulls out of the `OrderTicket`
//! feeds an `ExpectedRelease` that [`hippius_guest::verify_and_unwrap_release`]
//! checks against the **KBS-signed** response. A tampered ticket can
//! only produce a *wrong* `ExpectedRelease`, which makes the verify
//! gate fail closed — it can never weaken the gate.

use crate::pipeline::AgentError;
use coset::{CborSerializable, CoseSign1};
use hippius_types::cbor::assert_canonical;
use hippius_types::guardian::KeyMode;
use hippius_types::ticket::OrderTicket;

/// A loaded OrderTicket: the raw COSE_Sign1 envelope bytes plus the
/// decoded inner [`OrderTicket`].
///
/// No `Debug` is derived — the decoded ticket carries tenant / VM
/// identifiers, and a stray `dbg!()` must not surface them to the
/// serial console (§20).
pub struct Ticket {
    /// COSE_Sign1 bytes — the exact `cose_ticket` request field.
    cose: Vec<u8>,
    /// Decoded inner ticket — source of the `ExpectedRelease` bindings.
    order: OrderTicket,
}

impl Ticket {
    /// Raw COSE_Sign1 bytes, shipped to the KBS untouched.
    pub fn cose_bytes(&self) -> &[u8] {
        &self.cose
    }

    /// The decoded inner [`OrderTicket`].
    pub fn order(&self) -> &OrderTicket {
        &self.order
    }

    /// Decode a COSE_Sign1 envelope into a [`Ticket`]: parse the COSE
    /// structure, extract the payload, decode it as a CBOR
    /// [`OrderTicket`]. Does NOT verify the L1 signature (see module
    /// docs). Fails closed on a malformed envelope / payload.
    ///
    /// `hippius` (M0) tickets only — the legacy agent has no guardian
    /// leg. See [`Self::from_cose_for_mode`].
    pub fn from_cose(cose: Vec<u8>) -> Result<Self, AgentError> {
        Self::from_cose_for_mode(cose, KeyMode::Hippius)
    }

    /// [`Self::from_cose`] for a guest whose MEASURED cmdline selects
    /// key mode `measured` (`hippius` when it carries no guardian
    /// binding). The ticket's signed `key_mode` must be exactly that
    /// mode, checked BEFORE any KBS or guardian contact.
    ///
    /// Both sides are pinned: the cmdline by the launch measurement, the
    /// ticket by the L1 signature the KBS verifies. A disagreement is a
    /// launch the guest cannot run correctly — an M1 ticket on an M0
    /// cmdline would open the disk with the Hippius share alone, an M0
    /// ticket on an M1 cmdline would get a KEK the combine was never
    /// meant to see — so it fails closed rather than picking a side.
    pub fn from_cose_for_mode(cose: Vec<u8>, measured: KeyMode) -> Result<Self, AgentError> {
        let sign1 = CoseSign1::from_slice(&cose).map_err(|_| AgentError::Ticket("cose-parse"))?;
        let payload = sign1.payload.ok_or(AgentError::Ticket("cose-no-payload"))?;
        // §6 OrderTickets are deterministic CBOR. Enforce canonical
        // encoding before decode — defence-in-depth, consistent with
        // the crate's canonical-everywhere discipline, and it rejects
        // a payload with trailing junk that `from_reader` alone would
        // silently ignore. (The KBS performs the same check.)
        assert_canonical(&payload).map_err(|_| AgentError::Ticket("order-non-canonical"))?;
        let order: OrderTicket = ciborium::de::from_reader(payload.as_slice())
            .map_err(|_| AgentError::Ticket("order-decode"))?;
        // Customer-held keys: the ticket's mode must be the measured
        // one. An M0 guest keeps the pre-guardian classifier for an
        // M1/M2 ticket (before `key_mode` existed, `deny_unknown_fields`
        // refused it right here) — otherwise an M1 ticket would open the
        // disk with the Hippius share alone, and an M2 one would spend a
        // KBS release it cannot use.
        if order.key_mode() != measured {
            return Err(AgentError::Ticket(if measured == KeyMode::Hippius {
                "key-mode-unsupported"
            } else {
                "key-mode-mismatch"
            }));
        }
        Ok(Self { cose, order })
    }
}

/// Load + decode the COSE_Sign1 ticket.
///
/// `source` is a URI-style string that dispatches the loader:
///
/// - **`vsock://<expected-source-cid>:<port>`** — production. Accept
///   one inbound vsock connection on `(VMADDR_CID_ANY, <port>)`,
///   read a `u32 BE length + body` frame (see
///   [`super::ticket_vsock`]), pass the body to [`Ticket::from_cose`].
///   The `<expected-source-cid>` segment is informational: the
///   receiver always pins source = `2` (host) internally.
/// - **any other string** — treated as a filesystem path and read
///   with `std::fs::read`. Kept for dev / integration tests / a
///   future fallback mode; production uses `vsock://`.
///
/// Fails closed if the bytes cannot be read or are not a well-formed
/// COSE_Sign1 `OrderTicket`. Never logs the bytes — they bind the
/// tenant identity (§20).
pub fn load(source: &str) -> Result<Ticket, AgentError> {
    load_for_mode(source, KeyMode::Hippius)
}

/// [`load`] for a guest whose measured cmdline selects key mode
/// `measured` — see [`Ticket::from_cose_for_mode`].
pub fn load_for_mode(source: &str, measured: KeyMode) -> Result<Ticket, AgentError> {
    if let Some(rest) = source.strip_prefix("vsock://") {
        let port = parse_vsock_port(rest)?;
        let cose = super::ticket_vsock::recv_ticket(port)?;
        return Ticket::from_cose_for_mode(cose, measured);
    }
    let cose = std::fs::read(source).map_err(|_| AgentError::Ticket("read"))?;
    Ticket::from_cose_for_mode(cose, measured)
}

/// Parse `<expected-cid>:<port>` out of the URI's authority. Tolerates
/// an absent CID (`vsock://:18505`) — the receiver pins source CID
/// internally so the URI's CID is informational only.
fn parse_vsock_port(authority: &str) -> Result<u32, AgentError> {
    // Strip a trailing path / query if any caller adds one — only the
    // authority's `:<port>` carries information for this loader.
    let auth = authority.split('/').next().unwrap_or(authority);
    let port_str = match auth.rsplit_once(':') {
        Some((_cid, port)) => port,
        None => return Err(AgentError::Ticket("vsock-uri")),
    };
    port_str
        .parse::<u32>()
        .map_err(|_| AgentError::Ticket("vsock-uri"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // `matches!` rather than `.unwrap_err()`: `Ticket` deliberately
    // has no `Debug` (it carries tenant identifiers), and `unwrap_err`
    // would require the `Ok` side to be `Debug`.

    #[test]
    fn from_cose_rejects_non_cose_bytes() {
        assert!(matches!(
            Ticket::from_cose(vec![0xff, 0xff, 0xff]),
            Err(AgentError::Ticket("cose-parse"))
        ));
    }

    /// A canonical, unsigned COSE_Sign1 `OrderTicket` (the loader does
    /// not verify the signature) with an optional `key_mode` entry.
    fn cose_with_key_mode(key_mode: Option<&str>) -> Vec<u8> {
        use ciborium::value::Value;
        let t = |s: &str| Value::Text(s.into());
        let vref = |p: &str| Value::Map(vec![(t("path"), t(p)), (t("version"), 1.into())]);
        let mut entries = vec![
            (
                t("allowed_measurements"),
                Value::Array(vec![Value::Bytes(vec![7; 48])]),
            ),
            (t("allowed_userdata_digest"), Value::Bytes(vec![9; 32])),
            (t("expiry"), 2_000.into()),
            (t("flavor"), t("small")),
            (t("issue_time"), 1_000.into()),
            (t("lease_id"), t("l")),
            (t("lifecycle_perms"), Value::Array(vec![])),
            (t("luks_vault_ref"), vref("p/abc/luks-kek")),
            (t("node_id"), t("n")),
            (t("nonce"), Value::Bytes(vec![1; 32])),
            (t("platform_id"), t("aa")),
            (t("tenant_id"), t("t")),
            (t("ticket_id"), t("tk")),
            (t("user_id"), t("u")),
            (t("userdata_vault_ref"), vref("p/abc/userdata")),
            (t("v"), 2.into()),
            (t("vm_generation"), 1.into()),
            (t("vm_id"), t("abc")),
        ];
        if let Some(m) = key_mode {
            entries.push((t("key_mode"), t(m)));
        }
        let payload = hippius_types::cbor::to_canonical_vec(&Value::Map(entries)).unwrap();
        coset::CoseSign1Builder::new()
            .protected(
                coset::HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::EdDSA)
                    .build(),
            )
            .payload(payload)
            .signature(vec![0; 64])
            .build()
            .to_vec()
            .unwrap()
    }

    #[test]
    fn from_cose_admits_m0_and_refuses_every_other_key_mode() {
        let m0 = Ticket::from_cose(cose_with_key_mode(None));
        assert!(matches!(m0, Ok(ref t) if t.order().key_mode() == KeyMode::Hippius));
        for mode in ["split", "customer"] {
            assert!(
                matches!(
                    Ticket::from_cose(cose_with_key_mode(Some(mode))),
                    Err(AgentError::Ticket("key-mode-unsupported"))
                ),
                "{mode}"
            );
        }
    }

    #[test]
    fn from_cose_for_mode_admits_only_the_measured_mode() {
        let modes = [
            (None, KeyMode::Hippius),
            (Some("split"), KeyMode::Split),
            (Some("customer"), KeyMode::Customer),
        ];
        for (wire, ticket_mode) in modes {
            for (_, measured) in modes {
                let got = Ticket::from_cose_for_mode(cose_with_key_mode(wire), measured);
                if ticket_mode == measured {
                    assert!(
                        matches!(got, Ok(ref t) if t.order().key_mode() == measured),
                        "{wire:?} under {measured:?}"
                    );
                } else if measured == KeyMode::Hippius {
                    // The M0 guest keeps its pre-guardian classifier.
                    assert!(
                        matches!(got, Err(AgentError::Ticket("key-mode-unsupported"))),
                        "{wire:?} under {measured:?}"
                    );
                } else {
                    assert!(
                        matches!(got, Err(AgentError::Ticket("key-mode-mismatch"))),
                        "{wire:?} under {measured:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn load_rejects_a_missing_file() {
        assert!(matches!(
            load("/nonexistent/ticket.cose"),
            Err(AgentError::Ticket("read"))
        ));
    }
}
