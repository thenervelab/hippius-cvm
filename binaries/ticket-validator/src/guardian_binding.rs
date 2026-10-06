//! `parse-guardian-binding` — read a kernel cmdline on stdin and print
//! what [`GuardianBinding::from_cmdline`] makes of it.
//!
//! Customer-held keys: vali builds the measured cmdline that carries
//! `hippius.key_mode` / `hippius.guardian_pk` / `hippius.guardian_ep`, and
//! the guest and the guardian read it back with `GuardianBinding`. vali's
//! Python validation mirrors that grammar; this subcommand exposes the Rust
//! parser itself so vali's tests can diff the two over a fixture corpus
//! (the Rust grammar is the source of truth).
//!
//! Output (one JSON object on stdout):
//! - `{"tag":"ok","binding":null}` — M0 (no binding), exit 0;
//! - `{"tag":"ok","binding":{"mode","guardian_pk_hex","guardian_ep"}}`, exit 0
//!   (`guardian_ep` is the DECODED canonical `host:port`; the cmdline
//!   token is its lowercase hex);
//! - `{"tag":"err","error":"<CmdlineError classifier>"}`, exit 2.

use std::io::{self, Read};
use std::process::ExitCode;

use hippius_types::guardian::GuardianBinding;
use serde::Serialize;

use crate::{INTERNAL_FAIL, SCHEMA_FAIL};

#[derive(Serialize)]
struct BindingJson {
    mode: &'static str,
    guardian_pk_hex: String,
    guardian_ep: String,
}

#[derive(Serialize)]
#[serde(tag = "tag", rename_all = "lowercase")]
enum Out {
    Ok { binding: Option<BindingJson> },
    Err { error: String },
}

fn parse(raw: &[u8]) -> Out {
    let Ok(cmdline) = std::str::from_utf8(raw) else {
        return Out::Err {
            error: "non-utf8".into(),
        };
    };
    match GuardianBinding::from_cmdline(cmdline) {
        Ok(binding) => Out::Ok {
            binding: binding.map(|b| BindingJson {
                mode: b.mode.as_wire(),
                guardian_pk_hex: hex::encode(b.guardian_pk),
                guardian_ep: b.endpoint.to_wire(),
            }),
        },
        Err(e) => Out::Err {
            error: e.to_string(),
        },
    }
}

pub fn run() -> ExitCode {
    let mut raw = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut raw) {
        eprintln!("hippius-ticket-validator: stdin read failed: {e}");
        return ExitCode::from(INTERNAL_FAIL);
    }
    let out = parse(&raw);
    let code = match out {
        Out::Ok { .. } => 0,
        Out::Err { .. } => SCHEMA_FAIL,
    };
    match serde_json::to_writer(io::stdout().lock(), &out) {
        Ok(()) => ExitCode::from(code),
        Err(e) => {
            eprintln!("hippius-ticket-validator: stdout write failed: {e}");
            ExitCode::from(INTERNAL_FAIL)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const PK: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    fn json(raw: &str) -> serde_json::Value {
        serde_json::to_value(parse(raw.as_bytes())).unwrap()
    }

    #[test]
    fn m0_has_no_binding() {
        assert_eq!(
            json("console=hvc0 boot=hippius-golden"),
            serde_json::json!({"tag": "ok", "binding": null})
        );
    }

    #[test]
    fn a_binding_is_reported_in_canonical_form() {
        // `[2001:db8::1]:7443`, hex-encoded: reported DECODED.
        let v = json(&format!(
            "console=hvc0 hippius.key_mode=customer hippius.guardian_pk={PK} \
             hippius.guardian_ep=5b323030313a6462383a3a315d3a37343433"
        ));
        assert_eq!(
            v,
            serde_json::json!({"tag": "ok", "binding": {
                "mode": "customer", "guardian_pk_hex": PK, "guardian_ep": "[2001:db8::1]:7443"}})
        );
    }

    #[test]
    fn a_grammar_error_is_its_classifier() {
        assert_eq!(
            json("hippius.guardian_ep=1.2.3.4:1"),
            serde_json::json!({"tag": "err", "error": "guardian-cmdline-orphan-guardian-token"})
        );
        assert_eq!(
            serde_json::to_value(parse(&[0xff])).unwrap(),
            serde_json::json!({"tag": "err", "error": "non-utf8"})
        );
    }
}
