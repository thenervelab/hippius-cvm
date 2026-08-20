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
    pub fn from_cose(cose: Vec<u8>) -> Result<Self, AgentError> {
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
    if let Some(rest) = source.strip_prefix("vsock://") {
        let port = parse_vsock_port(rest)?;
        let cose = super::ticket_vsock::recv_ticket(port)?;
        return Ticket::from_cose(cose);
    }
    let cose = std::fs::read(source).map_err(|_| AgentError::Ticket("read"))?;
    Ticket::from_cose(cose)
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

    #[test]
    fn load_rejects_a_missing_file() {
        assert!(matches!(
            load("/nonexistent/ticket.cose"),
            Err(AgentError::Ticket("read"))
        ));
    }
}
