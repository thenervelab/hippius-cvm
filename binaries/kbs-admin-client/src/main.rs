//! `hippius-kbs-admin-client` — subprocess that POSTs a signed
//! OrderTicket to the KBS admin endpoint (ARCHITECTURE.md §24/§25).
//!
//! Phase A scope: `register-vm` only. Phase B adds `decommission`,
//! `crypto-erase`, `activate`.
//!
//! ## Usage
//!
//! ```text
//! hippius-kbs-admin-client register-vm \
//!     --kbs-url      https://kbs-server-admin.kbs.svc:8001 \
//!     --vm-id        tenant-pra-1 \
//!     --ticket       /tmp/tk-pra.cose \
//!     --client-cert  /etc/hippius/kbs-admin-tls/tls.crt \
//!     --client-key   /etc/hippius/kbs-admin-tls/tls.key \
//!     --ca-cert      /etc/hippius/kbs-admin-tls/ca.crt \
//!     --timeout-secs 5
//! ```
//!
//! ## mTLS
//!
//! The admin listener authenticates its callers with mTLS against a
//! pinned client CA (`kbs-server/src/admin_tls.rs`); this binary is the
//! client half. The three `--client-cert` / `--client-key` / `--ca-cert`
//! flags are required together whenever `--kbs-url` is `https://`, and
//! refused when it is `http://` — see [`mtls::AdminClientMode::decide`]
//! for the full decision table and why each refusal exists. There is no
//! flag that skips server-cert verification and no fallback to the
//! system trust store.
//!
//! ## Exit codes (vali parses them)
//!
//! | code | meaning |
//! |------|---------|
//! |  0   | 200 OK — applied (or cached idempotent hit) |
//! |  2   | 409 Conflict — terminal, operator must reconcile |
//! |  3   | 400/401/403/413 — terminal client error |
//! | 64   | misconfigured CLI args (no retry helps) |
//! | 65   | network / timeout — retryable |
//! | 66   | 5xx — retryable |
//! | 67   | response decode failure (likely kbs-server bug) |
//!
//! ## §20 logging discipline
//!
//! Stderr carries human-readable progress + one structured JSON line
//! on completion (`{outcome, status, request_id, vm_id, …}`). Stdout
//! is reserved for the OK-path JSON the runbook chains on.
//! The COSE ticket bytes themselves are NEVER logged.

use clap::Parser;
use hippius_kbs_admin_client::mtls::{self, AdminClientMode};
use hippius_types::admin::{AdminErrorResponse, AdminRegisterVmResponse};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "hippius-kbs-admin-client",
    version,
    about = "POST signed OrderTickets to the KBS admin endpoint (Hippius §24/§25)."
)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Subcommand, Debug)]
enum Cmd {
    /// `POST /v1/admin/vm/{vm_id}/register-vm` — pre-register a
    /// `VmState::Active` with the KBS before vali dispatches the
    /// launch. Idempotent on the ticket's `ticket_id`: a retry with
    /// the same ticket bytes returns 200 cached, a retry with a
    /// different body for the same `ticket_id` returns 409.
    RegisterVm(RegisterVmArgs),
    /// `GET /v1/admin/vm/{vm_id}/evidence` against a vm_id that need not
    /// exist — a READ-ONLY reachability + authentication probe. Mutates
    /// nothing. Exit 0 means the TLS handshake completed, the KBS
    /// accepted our client certificate, and a handler answered (200 or
    /// 404 — both prove the router was reached). This is the check the
    /// mTLS cutover runbook runs between steps.
    Probe(ProbeArgs),
}

/// The mTLS material, shared by every subcommand.
///
/// Required together whenever `--kbs-url` is `https://`; refused when it
/// is `http://`. `mtls::AdminClientMode::decide` owns that policy — this
/// struct only carries the flags.
#[derive(clap::Args, Debug, Clone, Default)]
struct TlsArgs {
    /// PEM client cert chain presented to the KBS admin listener (leaf
    /// first). Its SAN URI becomes the `peer_san` on every admin audit
    /// row, so it is an identity, not just a key.
    #[arg(long, env = "KBS_ADMIN_CLIENT_CERT")]
    client_cert: Option<PathBuf>,
    /// PEM private key for `--client-cert` (PKCS#8 / SEC1). Never
    /// logged, never echoed.
    #[arg(long, env = "KBS_ADMIN_CLIENT_KEY")]
    client_key: Option<PathBuf>,
    /// PEM CA bundle the KBS admin listener's server cert must chain to.
    /// REPLACES the system trust store — the admin hop is an internal
    /// service and must not be satisfiable by any public CA.
    #[arg(long, env = "KBS_ADMIN_CA_CERT")]
    ca_cert: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct RegisterVmArgs {
    /// Base URL of the KBS admin listener. `https://` requires the
    /// `--client-*` / `--ca-cert` material (mTLS); `http://` is the
    /// pre-cutover plaintext path and requires that NO material is set.
    #[arg(long, env = "KBS_ADMIN_URL")]
    kbs_url: String,
    /// `{vm_id}` path component. MUST equal the verified ticket's
    /// `vm_id` (KBS rejects 400 otherwise).
    #[arg(long)]
    vm_id: String,
    /// Path to the signed COSE_Sign1 OrderTicket. Same bytes vali
    /// submits to `POST /v1/order_ticket`.
    #[arg(long)]
    ticket: PathBuf,
    /// Request timeout, seconds. Default 5 — the KBS admin path is
    /// in-memory (ticket verify + CAS); 5 s is generous.
    #[arg(long, default_value_t = 5)]
    timeout_secs: u64,
    #[command(flatten)]
    tls: TlsArgs,
}

#[derive(clap::Args, Debug)]
struct ProbeArgs {
    /// Base URL of the KBS admin listener — same rules as `register-vm`.
    #[arg(long, env = "KBS_ADMIN_URL")]
    kbs_url: String,
    /// vm_id to ask about. Deliberately defaulted to a name no launch
    /// ever mints, so a 404 is the expected healthy answer and the probe
    /// touches no real VM's records.
    #[arg(long, default_value = "__mtls-probe__")]
    vm_id: String,
    /// Request timeout, seconds.
    #[arg(long, default_value_t = 5)]
    timeout_secs: u64,
    #[command(flatten)]
    tls: TlsArgs,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let outcome = match args.cmd {
        Cmd::RegisterVm(rv) => run_register(rv),
        Cmd::Probe(p) => run_probe(p),
    };
    match outcome {
        Ok(exit) => exit,
        Err(e) => {
            eprintln!("kbs-admin-client: ERROR: {e}");
            e.exit_code()
        }
    }
}

/// Resolve the flags into a decided transport and build the ureq agent.
///
/// Every refusal here is a [`CliError::Config`] ⇒ exit 64 ("misconfigured
/// CLI args, no retry helps"), which vali maps to `EffectUnavailable` —
/// the launch fails loudly rather than proceeding over an unauthenticated
/// hop.
fn build_agent(
    kbs_url: &str,
    tls: &TlsArgs,
    timeout: Duration,
) -> Result<(ureq::Agent, &'static str), CliError> {
    let mode = AdminClientMode::decide(
        kbs_url,
        tls.client_cert.as_deref(),
        tls.client_key.as_deref(),
        tls.ca_cert.as_deref(),
    )
    .map_err(|e| CliError::Config(e.to_string()))?;

    let builder = ureq::AgentBuilder::new().timeout(timeout);
    match mode {
        AdminClientMode::Mtls(paths) => {
            let cfg = mtls::build_client_config(&paths)
                .map_err(|e| CliError::Config(format!("admin mTLS material rejected: {e}")))?;
            Ok((builder.tls_config(Arc::new(cfg)).build(), "mtls"))
        }
        AdminClientMode::Plaintext => Ok((builder.build(), "plaintext")),
    }
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("config: {0}")]
    Config(String),
    #[error("network: {0}")]
    Network(String),
    #[error("server returned 5xx: {0}")]
    ServerInternal(String),
    #[error("server returned terminal 4xx: status {status}, reason {reason}")]
    Terminal { status: u16, reason: String },
    #[error("server returned 409 conflict: ticket_id={ticket_id:?}, reason={reason}")]
    Conflict {
        ticket_id: Option<String>,
        reason: String,
    },
    #[error("response decode: {0}")]
    Decode(String),
}

impl CliError {
    fn exit_code(&self) -> ExitCode {
        match self {
            CliError::Config(_) => ExitCode::from(64),
            CliError::Network(_) => ExitCode::from(65),
            CliError::ServerInternal(_) => ExitCode::from(66),
            CliError::Terminal { status, .. } => match *status {
                409 => ExitCode::from(2),
                _ => ExitCode::from(3),
            },
            CliError::Conflict { .. } => ExitCode::from(2),
            CliError::Decode(_) => ExitCode::from(67),
        }
    }
}

fn run_register(args: RegisterVmArgs) -> Result<ExitCode, CliError> {
    // 1. Read the ticket.
    let ticket = std::fs::read(&args.ticket)
        .map_err(|e| CliError::Config(format!("read --ticket {}: {e}", args.ticket.display())))?;
    if ticket.is_empty() {
        return Err(CliError::Config(format!(
            "--ticket {} is empty",
            args.ticket.display()
        )));
    }

    // 2. Compose URL.
    let url = format!(
        "{}/v1/admin/vm/{}/register-vm",
        args.kbs_url.trim_end_matches('/'),
        url_encode_segment(&args.vm_id),
    );

    // 3. Decide the transport (mTLS vs the pre-cutover plaintext path)
    //    and POST. A refusal here never dials.
    let (agent, transport) = build_agent(
        &args.kbs_url,
        &args.tls,
        Duration::from_secs(args.timeout_secs),
    )?;
    eprintln!("kbs-admin-client: POST {url} ({transport})");
    let response = match agent
        .post(&url)
        .set("content-type", "application/cbor")
        .send_bytes(&ticket)
    {
        Ok(r) => r,
        Err(ureq::Error::Status(status, resp)) => {
            // 4xx / 5xx — decode the AdminErrorResponse body.
            let body = resp.into_string().unwrap_or_default();
            let parsed = ciborium::de::from_reader::<AdminErrorResponse, _>(body.as_bytes());
            let reason = match parsed {
                Ok(b) => b.reason,
                Err(_) => format!("(undecodable body: {} bytes)", body.len()),
            };
            return classify_error_status(status, reason);
        }
        Err(ureq::Error::Transport(t)) => {
            return Err(CliError::Network(t.to_string()));
        }
    };

    // 4. 200 OK — decode + log.
    let status = response.status();
    if status != 200 {
        // ureq treats 2xx as Ok; defensive.
        return Err(CliError::ServerInternal(format!(
            "unexpected 2xx status {status}"
        )));
    }
    let mut buf = Vec::with_capacity(256);
    response
        .into_reader()
        .take(4096)
        .read_to_end(&mut buf)
        .map_err(|e| CliError::Decode(format!("body read: {e}")))?;
    let ok: AdminRegisterVmResponse = ciborium::de::from_reader(buf.as_slice())
        .map_err(|e| CliError::Decode(format!("cbor decode: {e}")))?;

    // 5. Emit a JSON line the caller can parse.
    let summary = format!(
        "{{\"outcome\":\"ok\",\"status\":200,\"ticket_id\":\"{}\",\"vm_id\":\"{}\",\"vm_generation\":{},\"cached\":{}}}",
        json_escape(&ok.ticket_id),
        json_escape(&ok.vm_id),
        ok.vm_generation,
        ok.cached
    );
    println!("{summary}");
    eprintln!(
        "kbs-admin-client: 200 OK ticket_id={} vm_id={} gen={} cached={}",
        ok.ticket_id, ok.vm_id, ok.vm_generation, ok.cached
    );
    Ok(ExitCode::SUCCESS)
}

/// READ-ONLY reachability + authentication probe.
///
/// `GET /v1/admin/vm/{vm_id}/evidence` is the only admin route that
/// mutates nothing, so it is the one safe thing to fire at a production
/// listener from a runbook. What the exit code means:
///
/// | exit | meaning |
/// |------|---------|
/// | 0    | handshake completed, our client cert was ACCEPTED, a handler answered (200 or 404) |
/// | 64   | our own flags are inconsistent — nothing was dialled |
/// | 65   | transport: TCP refused, timeout, **or a TLS handshake rejection** |
/// | 3    | the KBS answered a terminal 4xx (401/403/413/415/429) |
///
/// The 65 bucket deliberately includes handshake failures: rustls
/// reports "the server rejected our certificate" and "we rejected the
/// server's certificate" as transport errors, and both are retry-able
/// only after an operator fixes material. The underlying rustls message
/// IS printed to stderr, which is what tells the operator which side
/// refused.
fn run_probe(args: ProbeArgs) -> Result<ExitCode, CliError> {
    let url = format!(
        "{}/v1/admin/vm/{}/evidence",
        args.kbs_url.trim_end_matches('/'),
        url_encode_segment(&args.vm_id),
    );
    let (agent, transport) = build_agent(
        &args.kbs_url,
        &args.tls,
        Duration::from_secs(args.timeout_secs),
    )?;
    eprintln!("kbs-admin-client: PROBE GET {url} ({transport})");

    let status = match agent.get(&url).call() {
        Ok(r) => r.status(),
        // 404 is the EXPECTED healthy answer for a vm_id that does not
        // exist: reaching a handler at all proves the handshake
        // completed and the listener admitted us.
        Err(ureq::Error::Status(404, _)) => 404,
        Err(ureq::Error::Status(status, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            let reason = match ciborium::de::from_reader::<AdminErrorResponse, _>(body.as_bytes()) {
                Ok(b) => b.reason,
                Err(_) => format!("(undecodable body: {} bytes)", body.len()),
            };
            return classify_error_status(status, reason);
        }
        Err(ureq::Error::Transport(t)) => {
            // Includes every TLS handshake rejection. Print the rustls
            // detail — it names which side refused, which is the whole
            // diagnostic value of the probe.
            return Err(CliError::Network(t.to_string()));
        }
    };

    println!("{{\"outcome\":\"ok\",\"status\":{status},\"transport\":\"{transport}\"}}");
    eprintln!("kbs-admin-client: PROBE ok status={status} transport={transport}");
    Ok(ExitCode::SUCCESS)
}

fn classify_error_status(status: u16, reason: String) -> Result<ExitCode, CliError> {
    match status {
        409 => Err(CliError::Conflict {
            ticket_id: None,
            reason,
        }),
        400 | 401 | 403 | 413 | 415 | 429 => Err(CliError::Terminal { status, reason }),
        500..=599 => Err(CliError::ServerInternal(format!("{status}: {reason}"))),
        _ => Err(CliError::Terminal { status, reason }),
    }
}

/// Minimal URL-segment percent-encoding. The vm_id charset is
/// `[A-Za-z0-9._-]` per the existing OrderTicket convention; we still
/// pass it through this helper to fail loud if a stray character slips
/// in.
fn url_encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// Minimal JSON string escape — only `"` and `\` need quoting for the
/// short, controlled fields we emit (ticket_id, vm_id from the
/// verified ticket).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

// `std::io::Read::take` is needed for `into_reader().take()`.
use std::io::Read;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_passthrough_for_alnum_dot_dash() {
        assert_eq!(url_encode_segment("tenant-pra-1"), "tenant-pra-1");
        assert_eq!(url_encode_segment("vm_0.gen3"), "vm_0.gen3");
    }

    #[test]
    fn url_encode_quotes_unsafe_chars() {
        assert_eq!(url_encode_segment("a/b"), "a%2Fb");
        assert_eq!(url_encode_segment("x?y"), "x%3Fy");
        assert_eq!(url_encode_segment("v 1"), "v%201");
    }

    #[test]
    fn json_escape_handles_quotes() {
        assert_eq!(json_escape("hello"), "hello");
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("c\\d"), "c\\\\d");
    }
}
