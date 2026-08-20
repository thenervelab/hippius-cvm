//! AMD-rooted SNP verifier the broker uses to verify the KBS's own
//! self-report.
//!
//! The trust ANCHOR — the AMD Root Key (ARK) + AMD SEV Signing Key
//! (ASK) for the host's generation (Milan / Genoa / Turin) — is
//! built into the binary and never accepted from the wire. The VEK
//! (the per-chip VCEK or host-loaded VLEK leaf), by contrast, is
//! TCB-specific: it rolls every time the platform's bootloader / SNP
//! firmware / microcode updates. So the broker takes the VEK from the
//! self-report itself (the host PSP's extended-report cert table, §17
//! / #394) when present, and only falls back to an operator-mounted
//! VEK when the report carries none. That keeps the chain matching the
//! report's current TCB with no static per-host VEK to go stale.
//!
//! Each `verify` builds a fresh `Chain { ARK, ASK, VEK }` and runs the
//! same `kbs_core::snp_real` walk the KBS uses for guest reports.

use kbs_core::error::KbsError;
use kbs_core::snp::{AttestationVerifier, VerifiedReport};
use kbs_core::snp_real::{RealSnpVerifier, SevChainVerifier};
use sev::certs::snp::{builtin, ca, Certificate, Chain, Verifiable};

use crate::config::{Generation, Snp};
use crate::error::BrokerError;
use crate::redeem::SelfReportVerifier;

/// Built-in AMD ARK/ASK for the KBS host's generation, plus VEK
/// resolution: report-carried → KDS-fetched (cached) → mounted
/// fallback. Implements [`SelfReportVerifier`].
pub struct BrokerVerifier {
    ark: Certificate,
    ask: Certificate,
    /// Fallback VEK used only when a redeem carries no `vek_der` and
    /// KDS fetch is disabled/unavailable.
    mounted_vek: Option<Certificate>,
    generation: Generation,
    /// AMD KDS base URL (e.g. `https://kdsintf.amd.com`), if KDS fetch
    /// is enabled. The broker derives the per-chip VCEK URL from each
    /// report and fetches once per (chip_id, TCB).
    kds_base: Option<String>,
    kds_agent: ureq::Agent,
    /// VCEK cache keyed by the derived KDS URL (chip_id + TCB are
    /// baked into it) — a release never blocks on KDS after the first.
    vcek_cache: std::sync::Mutex<std::collections::HashMap<String, Certificate>>,
}

/// Build the verifier from `[snp]` config: load the built-in ARK/ASK
/// for the configured generation, and — if `vek_pem_path` is set —
/// the operator-mounted VEK fallback (chain-verified at boot so a
/// wrong generation↔VEK pairing aborts startup loudly). Production may
/// omit the mounted VEK entirely and rely on the report-carried one.
pub fn build(snp: &Snp) -> core::result::Result<BrokerVerifier, BrokerError> {
    let (ark, ask) = match snp.generation {
        Generation::Milan => (
            builtin::milan::ark()
                .map_err(|e| BrokerError::Config(format!("built-in Milan ARK: {e}")))?,
            builtin::milan::ask()
                .map_err(|e| BrokerError::Config(format!("built-in Milan ASK: {e}")))?,
        ),
        Generation::Genoa => (
            builtin::genoa::ark()
                .map_err(|e| BrokerError::Config(format!("built-in Genoa ARK: {e}")))?,
            builtin::genoa::ask()
                .map_err(|e| BrokerError::Config(format!("built-in Genoa ASK: {e}")))?,
        ),
        Generation::Turin => (
            builtin::turin::ark()
                .map_err(|e| BrokerError::Config(format!("built-in Turin ARK: {e}")))?,
            builtin::turin::ask()
                .map_err(|e| BrokerError::Config(format!("built-in Turin ASK: {e}")))?,
        ),
    };

    let mounted_vek = match &snp.vek_pem_path {
        Some(path) => {
            let pem = std::fs::read(path).map_err(|e| {
                BrokerError::Config(format!("snp.vek_pem_path {}: {e}", path.display()))
            })?;
            let vek = Certificate::from_pem(&pem)
                .map_err(|e| BrokerError::Config(format!("VEK PEM parse: {e}")))?;
            // Fail-fast boot gate: the mounted VEK MUST chain to the
            // built-in ARK/ASK now, so a wrong generation↔VEK pairing
            // aborts startup rather than every redeem.
            let chain = Chain {
                ca: ca::Chain {
                    ark: ark.clone(),
                    ask: ask.clone(),
                },
                vek: vek.clone(),
            };
            (&chain).verify().map_err(|e| {
                BrokerError::Config(format!("mounted VEK chain (ARK→ASK→VEK) verify: {e}"))
            })?;
            Some(vek)
        }
        None => None,
    };

    let kds_base = snp
        .kds_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_string());

    eprintln!(
        "kbs-vault-broker: [snp] wired — generation={:?}, VEK resolution: report-carried \
         → {} → mounted-fallback({})",
        snp.generation,
        match &kds_base {
            Some(u) => format!("KDS({u})"),
            None => "KDS(disabled)".to_string(),
        },
        if mounted_vek.is_some() {
            "present"
        } else {
            "none"
        },
    );
    Ok(BrokerVerifier {
        ark,
        ask,
        mounted_vek,
        generation: snp.generation,
        kds_base,
        kds_agent: ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(5))
            .timeout_read(std::time::Duration::from_secs(15))
            .build(),
        vcek_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
    })
}

impl BrokerVerifier {
    /// Generation path segment in the KDS URL.
    fn kds_gen(&self) -> &'static str {
        match self.generation {
            Generation::Milan => "Milan",
            Generation::Genoa => "Genoa",
            Generation::Turin => "Turin",
        }
    }

    /// Build the canonical AMD KDS VCEK URL for `report`'s chip + TCB
    /// (same shape `snphost show vcek-url` emits). Turin uses the
    /// 8-byte HWID; Milan/Genoa the full 64-byte chip_id. SPL params
    /// are the TCB field values, 2-digit zero-padded decimal; `fmcSPL`
    /// only when the report carries an FMC (Turin).
    fn kds_vcek_url(&self, base: &str, report: &sev::firmware::guest::AttestationReport) -> String {
        let id_len = if matches!(self.generation, Generation::Turin) {
            8
        } else {
            64
        };
        let chip = hex::encode_upper(&report.chip_id[..id_len]);
        let t = &report.reported_tcb;
        let mut url = format!(
            "{base}/vcek/v1/{}/{chip}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            self.kds_gen(),
            t.bootloader,
            t.tee,
            t.snp,
            t.microcode,
        );
        if let Some(fmc) = t.fmc {
            url.push_str(&format!("&fmcSPL={fmc:02}"));
        }
        url
    }

    /// Fetch (and cache) the per-chip VCEK from KDS for `report`.
    fn fetch_vcek(
        &self,
        base: &str,
        report: &sev::firmware::guest::AttestationReport,
    ) -> kbs_core::error::Result<Certificate> {
        let url = self.kds_vcek_url(base, report);
        if let Some(c) = self
            .vcek_cache
            .lock()
            .map_err(|_| KbsError::Attestation("VCEK cache lock poisoned".into()))?
            .get(&url)
        {
            return Ok(c.clone());
        }
        let resp = self
            .kds_agent
            .get(&url)
            .call()
            .map_err(|e| KbsError::Attestation(format!("KDS VCEK fetch: {}", kds_err(&e))))?;
        use std::io::Read as _;
        let mut der = Vec::new();
        resp.into_reader()
            .take(16 * 1024)
            .read_to_end(&mut der)
            .map_err(|_| KbsError::Attestation("KDS VCEK read".into()))?;
        let cert = Certificate::from_der(&der)
            .map_err(|e| KbsError::Attestation(format!("KDS VCEK DER parse: {e}")))?;
        self.vcek_cache
            .lock()
            .map_err(|_| KbsError::Attestation("VCEK cache lock poisoned".into()))?
            .insert(url, cert.clone());
        Ok(cert)
    }
}

/// Secret-free classifier for a KDS `ureq` error.
fn kds_err(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, _) => format!("http-{code}"),
        ureq::Error::Transport(_) => "transport".to_string(),
    }
}

impl SelfReportVerifier for BrokerVerifier {
    fn verify(&self, raw_report: &[u8], vek_der: &[u8]) -> kbs_core::error::Result<VerifiedReport> {
        // VEK resolution order: (1) the VEK carried in the report (the
        // host PSP cert table — always TCB-current, no network); (2)
        // a KDS fetch of the per-chip VCEK derived from the report,
        // cached by (chip_id, TCB); (3) an operator-mounted VEK (dev
        // fallback). The AMD ARK trust anchor is always built-in.
        let vek = if !vek_der.is_empty() {
            Certificate::from_der(vek_der)
                .map_err(|e| KbsError::Attestation(format!("report-carried VEK DER parse: {e}")))?
        } else if let Some(base) = &self.kds_base {
            use sev::firmware::guest::AttestationReport;
            use sev::parser::ByteParser as _;
            let report = AttestationReport::from_bytes(raw_report)
                .map_err(|e| KbsError::Attestation(format!("SNP report parse for KDS: {e}")))?;
            self.fetch_vcek(base, &report)?
        } else if let Some(v) = &self.mounted_vek {
            v.clone()
        } else {
            return Err(KbsError::Attestation(format!(
                "no VEK: report carried none, KDS fetch disabled, no mounted fallback (generation={:?})",
                self.generation
            )));
        };

        let chain = Chain {
            ca: ca::Chain {
                ark: self.ark.clone(),
                ask: self.ask.clone(),
            },
            vek,
        };
        // The ARK is the trust anchor (built-in, never from the wire);
        // SevChainVerifier pins the report's chain to it.
        let chain_verifier = SevChainVerifier::new(chain, &self.ark)
            .map_err(|e| KbsError::Attestation(format!("SevChainVerifier: {e}")))?;
        RealSnpVerifier::new(chain_verifier).verify(raw_report)
    }
}
