//! Production SEV-SNP attestation wiring — generation-agnostic.
//!
//! Wraps [`kbs_core::snp_real::RealSnpVerifier`] — the trait impl that
//! parses the raw SNP report via the `sev` crate (ABI-correct), refuses
//! `MaskedChipId` + unsupported report versions, enforces TCB rollback,
//! and delegates the cryptographic chain check to a [`ChainVerifier`]
//! seam. Two branches:
//!
//! - operator left `[snp]` absent → [`build`] wires
//!   [`UnconfiguredChainVerifier`]; every report fails the chain check
//!   with an explicit error class (`release fails closed`);
//! - operator declared `[snp]` → the binary wires
//!   [`MultiGenChainVerifier`], which is **generation-agnostic**: for
//!   EACH incoming guest report it
//!     1. identifies the AMD CPU generation (Milan / Genoa / Turin)
//!        from the report's OWN fields (V3/V5 CPUID family+model, or
//!        the V2 chip_id Turin-marker),
//!     2. anchors to the built-in AMD ARK + ASK for THAT generation,
//!     3. resolves the report's VCEK via AMD KDS (keyed by chip_id +
//!        reported TCB, cached) or — when the report's generation
//!        matches the configured static `[snp].generation` — the
//!        operator-mounted static VEK fallback,
//!     4. verifies the report signature against `ARK → ASK → VCEK`,
//!        rejecting (fail-closed) if the generation can't be matched to
//!        a built-in AMD root or any chain link fails.
//!
//! This is SECURITY-CRITICAL: every report still chains to a genuine
//! built-in AMD ARK for ITS generation. A forged report (bad sig), a
//! report whose VCEK chains to the wrong generation's ARK, and a report
//! whose generation has no built-in ARK are all DENIED. The change is
//! purely additive over the prior Genoa-only static-VEK path — that
//! path survives as the `kds_url`-disabled, matching-generation fallback
//! (a Genoa-only deploy).
//!
//! There is no "static-accept" path — `kbs_core::snp_real` refuses to
//! construct one without an anchored AMD root.

use crate::config::{SnpConfig, SnpGeneration};
use crate::error::Error;
use kbs_core::error::{KbsError, Result as KbsResult};
use kbs_core::snp::{AttestationVerifier, VerifiedReport};
use kbs_core::snp_real::{ChainVerifier, RealSnpVerifier, SevChainVerifier};
use sev::certs::snp::{builtin, ca, Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;
use sev::Generation;
use std::collections::HashMap;
use std::sync::Mutex;

/// Reason text the unconfigured-chain branch returns. Surfaced inside
/// `KbsError::Attestation` so an operator running `/v1/kbs/release`
/// against a chain-unconfigured KBS sees exactly what is blocked. The
/// release path itself returns the higher-level fail-closed error.
pub const UNCONFIGURED_CHAIN_MSG: &str =
    "AMD SEV-SNP chain not configured ([snp].vek_pem_path); release fails closed \
     until the per-CHIP_ID VEK is mounted (production fetch + cache is the \
     §17 follow-up)";

/// Deny-closed [`ChainVerifier`] used when the operator has not yet
/// mounted a VEK. Distinct from a "test accept" — there is no such
/// thing in the production binary; the only way to a successful chain
/// check is the real [`SevChainVerifier`] anchored to a built-in ARK.
pub struct UnconfiguredChainVerifier;

impl ChainVerifier for UnconfiguredChainVerifier {
    fn verify_report(&self, _r: &AttestationReport, _raw: &[u8]) -> KbsResult<Vec<u8>> {
        Err(KbsError::Attestation(UNCONFIGURED_CHAIN_MSG.into()))
    }
}

/// Built-in AMD ARK + ASK pair for one generation, loaded once at
/// startup. Held by [`MultiGenChainVerifier`] for every generation it
/// can anchor (Milan, Genoa, Turin).
struct ArkAsk {
    ark: Certificate,
    ask: Certificate,
}

/// Load the built-in ARK + ASK for a `sev::Generation`. The `sev`
/// crate's `builtin::{milan,genoa,turin}` modules ship the AMD roots
/// compiled into the binary — they are NEVER read from the wire.
fn builtin_ark_ask(gen: Generation) -> Result<ArkAsk, Error> {
    let (ark, ask) = match gen {
        Generation::Milan => (
            builtin::milan::ark().map_err(|e| Error::Wiring(format!("built-in Milan ARK: {e}")))?,
            builtin::milan::ask().map_err(|e| Error::Wiring(format!("built-in Milan ASK: {e}")))?,
        ),
        Generation::Genoa => (
            builtin::genoa::ark().map_err(|e| Error::Wiring(format!("built-in Genoa ARK: {e}")))?,
            builtin::genoa::ask().map_err(|e| Error::Wiring(format!("built-in Genoa ASK: {e}")))?,
        ),
        Generation::Turin => (
            builtin::turin::ark().map_err(|e| Error::Wiring(format!("built-in Turin ARK: {e}")))?,
            builtin::turin::ask().map_err(|e| Error::Wiring(format!("built-in Turin ASK: {e}")))?,
        ),
    };
    Ok(ArkAsk { ark, ask })
}

/// Map the binary's `[snp].generation` config enum onto the `sev`
/// crate's `Generation` so the static-VEK fallback can be matched
/// against the per-report identified generation.
fn config_gen(g: SnpGeneration) -> Generation {
    match g {
        SnpGeneration::Milan => Generation::Milan,
        SnpGeneration::Genoa => Generation::Genoa,
        SnpGeneration::Turin => Generation::Turin,
    }
}

/// Stable lower-case label for a `sev::Generation`, used in the KDS URL
/// path segment and in error/log strings.
fn gen_label(gen: Generation) -> &'static str {
    match gen {
        Generation::Milan => "Milan",
        Generation::Genoa => "Genoa",
        Generation::Turin => "Turin",
    }
}

/// Identify the AMD CPU generation that produced `report`, mirroring the
/// `sev` crate's own decode logic so the answer matches exactly what
/// signed the report:
///
/// - V3/V5 reports (Turin always; newer Genoa kernels) carry the CPUID
///   family + model — `Generation::identify_cpu` maps them to
///   Milan/Genoa/Turin.
/// - V2 reports (no CPUID fields) are disambiguated by the chip_id
///   Turin-marker: a Turin chip_id has its last 56 bytes zero. A
///   non-Turin-like V2 chip_id is Genoa (the `sev` crate makes the same
///   call; a V2 Milan report is indistinguishable from Genoa by the
///   report alone — both share report version 2 — and the operator's
///   static-VEK generation disambiguates that legacy case).
///
/// Returns `Err` (fail-closed) if the generation can't be identified
/// against a known AMD generation — e.g. a CPUID family/model with no
/// built-in ARK.
fn identify_report_generation(report: &AttestationReport) -> KbsResult<Generation> {
    match report.version {
        2 => {
            // Last 56 bytes of a Turin chip_id are zero (the `sev`
            // crate's `chip_id_is_turin_like`). MaskedChipId (all-zero)
            // is already refused upstream in `RealSnpVerifier`.
            if report.chip_id[8..].iter().all(|&b| b == 0) {
                Ok(Generation::Turin)
            } else {
                Ok(Generation::Genoa)
            }
        }
        _ => {
            let family = report.cpuid_fam_id.unwrap_or(0);
            let model = report.cpuid_mod_id.unwrap_or(0);
            Generation::identify_cpu(family, model).map_err(|_| {
                KbsError::Attestation(format!(
                    "SNP report CPUID family={family:#x} model={model:#x} \
                     matches no known AMD SEV-SNP generation — no built-in ARK to anchor"
                ))
            })
        }
    }
}

/// Per-report VCEK resolver + multi-generation chain verifier.
///
/// Implements [`ChainVerifier`]: for EACH guest report it identifies the
/// CPU generation, anchors to that generation's built-in AMD ARK/ASK,
/// resolves the VCEK (KDS fetch keyed by chip_id + TCB, cached; or the
/// matching-generation static fallback), and runs the
/// `kbs_core::snp_real::SevChainVerifier` walk (ARK pin → ARK self-sig →
/// ARK→ASK → ASK→VCEK → report-sig). Fail-closed on every miss.
pub struct MultiGenChainVerifier {
    /// Built-in ARK/ASK for every generation we can anchor. Keyed by a
    /// stable label so a generation never identified for a report is
    /// simply never looked up.
    roots: HashMap<&'static str, ArkAsk>,
    /// The configured static-VEK generation + leaf — used ONLY when an
    /// incoming report's identified generation MATCHES it AND KDS fetch
    /// did not (or could not) supply a VCEK. Preserves the legacy
    /// single-generation static-VEK deploy (Genoa-only).
    static_vek_gen: Generation,
    static_vek: Certificate,
    /// AMD KDS base URL (trailing slash trimmed) for per-chip VCEK
    /// fetch, or `None` to disable KDS.
    kds_base: Option<String>,
    kds_agent: ureq::Agent,
    /// VCEK cache keyed by the derived KDS URL (chip_id + TCB baked in),
    /// so a release never blocks on KDS after the first per (chip, TCB).
    vcek_cache: Mutex<HashMap<String, Certificate>>,
}

impl MultiGenChainVerifier {
    /// Build the canonical AMD KDS VCEK URL for `report`'s chip + TCB
    /// (same shape `snphost show vcek-url` emits). Turin uses the
    /// 8-byte HWID; Milan/Genoa the full 64-byte chip_id. SPL params are
    /// the reported-TCB field values, 2-digit zero-padded decimal;
    /// `fmcSPL` only when the report carries an FMC (Turin).
    /// Build the canonical AMD KDS VCEK URL for `gen` + `chip_id` keyed
    /// by an EXPLICIT `tcb` (the caller decides whether that is the
    /// report's `reported_tcb` or `current_tcb` — see
    /// [`Self::candidate_vcek_urls`]).
    fn kds_vcek_url_for_tcb(
        base: &str,
        gen: Generation,
        report: &AttestationReport,
        tcb: &sev::firmware::host::TcbVersion,
    ) -> String {
        let id_len = if matches!(gen, Generation::Turin) {
            8
        } else {
            64
        };
        let chip = hex::encode_upper(&report.chip_id[..id_len]);
        let mut url = format!(
            "{base}/vcek/v1/{}/{chip}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            gen_label(gen),
            tcb.bootloader,
            tcb.tee,
            tcb.snp,
            tcb.microcode,
        );
        if let Some(fmc) = tcb.fmc {
            url.push_str(&format!("&fmcSPL={fmc:02}"));
        }
        url
    }

    /// The ordered TCB candidates to key the VCEK by, for a report whose
    /// signing VCEK is unknown a-priori. Per the AMD KDS convention the
    /// VCEK is keyed by the report's TCB; on Milan/Genoa parts
    /// `reported_tcb == current_tcb` so this is a single candidate. But
    /// some Turin firmware (API 1.55, live-observed on an EPYC 9255
    /// 2026-06-29) reports a LOWER `reported_tcb` (the TCB the guest may
    /// attest) than the `current_tcb` the firmware actually signed with —
    /// only the `current_tcb`-keyed VCEK verifies the report signature.
    ///
    /// We try `reported_tcb` FIRST (the AMD convention — keeps the exact
    /// prior behavior + single fetch for Milan/Genoa where the two are
    /// equal), then `current_tcb`, and accept whichever VCEK actually
    /// VERIFIES the report signature. The signature is ground truth, so
    /// this is provably correct for every generation and cannot regress a
    /// part whose reported_tcb already signs. Capped at these two
    /// spec-plausible candidates.
    fn candidate_vcek_urls(base: &str, gen: Generation, report: &AttestationReport) -> Vec<String> {
        let reported = Self::kds_vcek_url_for_tcb(base, gen, report, &report.reported_tcb);
        let current = Self::kds_vcek_url_for_tcb(base, gen, report, &report.current_tcb);
        if reported == current {
            vec![reported]
        } else {
            vec![reported, current]
        }
    }

    /// Fetch (and cache) a per-chip VCEK from a fully-built KDS `url`.
    fn fetch_vcek_url(&self, url: &str) -> KbsResult<Certificate> {
        if let Some(c) = self
            .vcek_cache
            .lock()
            .map_err(|_| KbsError::Attestation("VCEK cache lock poisoned".into()))?
            .get(url)
        {
            return Ok(c.clone());
        }
        let resp = self
            .kds_agent
            .get(url)
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
            .insert(url.to_string(), cert.clone());
        Ok(cert)
    }
}

impl ChainVerifier for MultiGenChainVerifier {
    fn verify_report(&self, report: &AttestationReport, raw_report: &[u8]) -> KbsResult<Vec<u8>> {
        // 1. Identify the generation from the report's own fields.
        let gen = identify_report_generation(report)?;

        // 2. Look up the built-in AMD ARK/ASK for THAT generation. A
        //    generation with no built-in root is a hard deny.
        let roots = self.roots.get(gen_label(gen)).ok_or_else(|| {
            KbsError::Attestation(format!(
                "no built-in AMD ARK for identified generation {} — release fails closed",
                gen_label(gen)
            ))
        })?;

        // 3. Resolve + verify the VCEK leaf. The guest report is a bare
        //    1184-byte report (no cert table). With KDS enabled we try
        //    the candidate TCB-keyed VCEK URLs (reported_tcb, then
        //    current_tcb if it differs) and accept the FIRST whose VCEK
        //    fully verifies — chain (ARK pinned → ARK self-sig → ARK→ASK
        //    → ASK→VCEK) AND the report signature over the RAW WIRE BYTES.
        //    The signature is ground truth, so this both fixes the Turin
        //    `reported_tcb != current_tcb` case (only the current_tcb
        //    VCEK signs) and cannot regress Milan/Genoa (their TCBs are
        //    equal → a single candidate → identical prior behavior).
        //    Without KDS, only the matching-generation static VEK is
        //    tried. No static-accept exists; every candidate is chained
        //    to the built-in ARK and must sign the report.
        let build_verify = |vek: Certificate| -> KbsResult<Vec<u8>> {
            let chain = Chain {
                ca: ca::Chain {
                    ark: roots.ark.clone(),
                    ask: roots.ask.clone(),
                },
                vek,
            };
            let chain_verifier = SevChainVerifier::new(chain, &roots.ark)
                .map_err(|e| KbsError::Attestation(format!("SevChainVerifier: {e}")))?;
            chain_verifier.verify_report(report, raw_report)
        };

        let mut last_err: Option<KbsError> = None;
        if let Some(base) = &self.kds_base {
            for url in Self::candidate_vcek_urls(base, gen, report) {
                let vek = match self.fetch_vcek_url(&url) {
                    Ok(v) => v,
                    Err(e) => {
                        last_err = Some(e);
                        continue;
                    }
                };
                match build_verify(vek) {
                    Ok(pem) => return Ok(pem),
                    Err(e) => last_err = Some(e),
                }
            }
        } else if gen_label(gen) == gen_label(self.static_vek_gen) {
            match build_verify(self.static_vek.clone()) {
                Ok(pem) => return Ok(pem),
                Err(e) => last_err = Some(e),
            }
        } else {
            return Err(KbsError::Attestation(format!(
                "no VCEK for generation {}: KDS fetch disabled and the static-VEK \
                 fallback is generation {} — configure [snp].kds_url to verify {} guests",
                gen_label(gen),
                gen_label(self.static_vek_gen),
                gen_label(gen),
            )));
        }

        // No candidate VCEK verified the report — fail closed. Log the
        // generation + BOTH TCBs + the candidate URLs (all PUBLIC
        // attestation metadata, no secret) so a future miss (wrong HWID,
        // a new firmware TCB convention, or a genuine forgery) is
        // diagnosable. A `current_tcb != reported_tcb` that STILL fails
        // both points past the TCB to the HWID/chip or a forgery.
        let c = &report.current_tcb;
        let r = &report.reported_tcb;
        let urls = self
            .kds_base
            .as_deref()
            .map(|b| Self::candidate_vcek_urls(b, gen, report).join(" | "))
            .unwrap_or_else(|| "<static-vek>".to_string());
        eprintln!(
            "kbs-server: SNP report-sig verify FAILED (no candidate VCEK signed) gen={} \
             version={} chip_id_prefix={} \
             current_tcb=(bl={} tee={} snp={} ucode={} fmc={:?}) \
             reported_tcb=(bl={} tee={} snp={} ucode={} fmc={:?}) candidate_urls={urls}",
            gen_label(gen),
            report.version,
            hex::encode_upper(&report.chip_id[..8.min(report.chip_id.len())]),
            c.bootloader,
            c.tee,
            c.snp,
            c.microcode,
            c.fmc,
            r.bootloader,
            r.tee,
            r.snp,
            r.microcode,
            r.fmc,
        );
        Err(last_err.unwrap_or_else(|| {
            KbsError::Attestation("no VCEK candidate available for report".into())
        }))
    }
}

/// Secret-free classifier for a KDS `ureq` error (mirrors the broker).
fn kds_err(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, _) => format!("http-{code}"),
        ureq::Error::Transport(_) => "transport".to_string(),
    }
}

/// Production attestation verifier. A static enum over the two
/// configured branches so we get a single `Arc<dyn AttestationVerifier>`
/// without boxing the chain verifier separately.
///
/// The `Sev` variant carries every generation's AMD ARK+ASK + the
/// static-VEK fallback chain and dwarfs the zero-sized `Unconfigured`
/// variant. The enum is constructed ONCE at startup and held behind an
/// `Arc` for the process lifetime, so the size asymmetry has no
/// allocation / copy cost — boxing the `Sev` payload would just add a
/// pointer indirection on every `verify()` call.
#[allow(clippy::large_enum_variant)]
pub enum RuntimeAttestationVerifier {
    Unconfigured(RealSnpVerifier<UnconfiguredChainVerifier>),
    Sev(RealSnpVerifier<MultiGenChainVerifier>),
}

impl AttestationVerifier for RuntimeAttestationVerifier {
    fn verify(&self, raw_report: &[u8]) -> KbsResult<VerifiedReport> {
        match self {
            Self::Unconfigured(v) => v.verify(raw_report),
            Self::Sev(v) => v.verify(raw_report),
        }
    }
}

/// Build the attestation verifier the binary wires into
/// `DefaultKbsService`. The branch is purely a function of operator
/// config (`[snp]` present + readable VEK file), so a missing /
/// unreadable file aborts startup rather than running the KBS with a
/// silently-degraded verifier.
pub fn build(cfg: Option<&SnpConfig>) -> Result<RuntimeAttestationVerifier, Error> {
    let snp = match cfg {
        None => {
            eprintln!(
                "kbs-server: [snp] absent — wiring RealSnpVerifier with the deny-closed chain \
                 verifier; every release fails closed until [snp] is configured"
            );
            return Ok(RuntimeAttestationVerifier::Unconfigured(
                RealSnpVerifier::new(UnconfiguredChainVerifier),
            ));
        }
        Some(snp) => snp,
    };

    // Built-in ARK + ASK for EVERY generation we can anchor (Milan,
    // Genoa, Turin). The AMD roots are compiled into the binary and are
    // NEVER accepted from the wire; the per-report chain verifier
    // byte-compares each report's chain ARK against the matching pinned
    // ARK, so a fake chain that self-signs its own ARK is rejected at
    // the anchor.
    let mut roots: HashMap<&'static str, ArkAsk> = HashMap::new();
    for gen in [Generation::Milan, Generation::Genoa, Generation::Turin] {
        roots.insert(gen_label(gen), builtin_ark_ask(gen)?);
    }

    // Configured static-VEK fallback (legacy single-generation path,
    // e.g. a Genoa-only deploy). The mounted VEK MUST chain to its own
    // generation's built-in ARK/ASK NOW — a wrong generation↔VEK
    // pairing aborts startup loudly rather than failing every release.
    let static_vek_gen = config_gen(snp.generation);
    let static_roots = builtin_ark_ask(static_vek_gen)?;
    let vek_pem = std::fs::read(&snp.vek_pem_path).map_err(|e| {
        Error::Config(format!(
            "snp.vek_pem_path {}: {e}",
            snp.vek_pem_path.display()
        ))
    })?;
    let static_vek = Certificate::from_pem(&vek_pem)
        .map_err(|e| Error::Wiring(format!("VEK PEM parse: {e}")))?;
    let static_chain = Chain {
        ca: ca::Chain {
            ark: static_roots.ark.clone(),
            ask: static_roots.ask.clone(),
        },
        vek: static_vek.clone(),
    };
    (&static_chain)
        .verify()
        .map_err(|e| Error::Wiring(format!("SNP static-VEK chain (ARK→ASK→VEK) verify: {e}")))?;

    let kds_base = snp
        .kds_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_string());

    eprintln!(
        "kbs-server: [snp] wired — generation-agnostic RealSnpVerifier (Milan/Genoa/Turin \
         anchored to built-in AMD ARKs); VCEK resolution: {} → static-{:?}-VEK fallback at {} \
         (static chain ARK→ASK→VEK verified)",
        match &kds_base {
            Some(u) => format!("KDS({u})"),
            None => "KDS(disabled)".to_string(),
        },
        snp.generation,
        snp.vek_pem_path.display(),
    );

    let chain_verifier = MultiGenChainVerifier {
        roots,
        static_vek_gen,
        static_vek,
        kds_base,
        kds_agent: ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(5))
            .timeout_read(std::time::Duration::from_secs(15))
            .build(),
        vcek_cache: Mutex::new(HashMap::new()),
    };
    Ok(RuntimeAttestationVerifier::Sev(RealSnpVerifier::new(
        chain_verifier,
    )))
}

/// Placeholder for the KBS's OWN verified SNP report.
///
/// `DefaultKbsService` requires an `Arc<VerifiedReport>` for the KBS
/// itself. It is consumed ONLY inside the attested-Vault step of the
/// release pipeline — the static-token `vault_mvp::StaticTokenVaultKv`
/// plus the `kbs_measurement_ok: |_| false` / `min_tcb: u64::MAX`
/// policy in `wiring.rs` make that step structurally unreachable, so
/// this all-zero value is never read. The SNP-attested Vault broker
/// (#102) replaces it with the KBS's real runtime self-attestation.
pub fn placeholder_verified_report() -> VerifiedReport {
    VerifiedReport {
        measurement: [0u8; 48],
        report_data: [0u8; 64],
        tcb: 0,
        policy: 0,
        chip_id: [0u8; 64],
        chain_pem: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sev::firmware::host::TcbVersion;
    use sev::parser::Encoder as SevEncoder;

    fn nonzero_chip() -> [u8; 64] {
        let mut c = [0u8; 64];
        c[0] = 0xAA;
        c[63] = 0xBB;
        c
    }

    fn tcb() -> TcbVersion {
        TcbVersion {
            fmc: None,
            bootloader: 1,
            tee: 2,
            snp: 3,
            microcode: 4,
        }
    }

    fn synth_v2_report(measurement: [u8; 48]) -> Vec<u8> {
        let r = AttestationReport {
            version: 2,
            measurement,
            report_data: [0u8; 64],
            chip_id: nonzero_chip(),
            reported_tcb: tcb(),
            launch_tcb: tcb(),
            ..AttestationReport::default()
        };
        let mut buf = Vec::new();
        r.encode(&mut buf, ()).expect("encode v2 SNP report");
        buf
    }

    #[test]
    fn unconfigured_chain_denies_with_clear_classifier() {
        // Build a syntactically-valid v2 report so the deny lands on
        // the chain step (not on the parser). The classifier MUST be
        // the `UNCONFIGURED_CHAIN_MSG` so an operator running
        // `/v1/kbs/release` sees exactly what is blocked.
        let raw = synth_v2_report([7u8; 48]);
        let v = build(None).expect("build with no config must succeed");
        let err = v.verify(&raw).expect_err("chain step must deny");
        match err {
            KbsError::Attestation(msg) => assert!(
                msg.contains("chain not configured"),
                "unexpected classifier: {msg}"
            ),
            other => panic!("expected Attestation, got {other:?}"),
        }
    }

    #[test]
    fn unconfigured_branch_still_runs_parse_gates() {
        // The real verifier's pre-chain gates (version != 2, masked
        // CHIP_ID, etc.) MUST still fire before the deny-closed chain
        // step — that's the whole point of routing through
        // `RealSnpVerifier`.
        let v = build(None).expect("build with no config");
        // version 99 should be rejected as unsupported BEFORE the
        // chain check.
        let mut bad = vec![0u8; 64];
        bad[0..4].copy_from_slice(&99u32.to_le_bytes());
        let err = v.verify(&bad).unwrap_err();
        match err {
            KbsError::Attestation(msg) => assert!(
                msg.contains("unsupported SNP report version"),
                "expected version classifier, got: {msg}"
            ),
            other => panic!("expected Attestation, got {other:?}"),
        }
    }

    #[test]
    fn truncated_buffer_denied_before_chain() {
        // A buffer shorter than the SNP report header MUST be rejected
        // by the parser, NOT by the chain step — preserves the order
        // `parse → MaskedChipId → chain → TCB → policy` (`snp_real`
        // module doc).
        let v = build(None).expect("build with no config");
        let short = vec![0u8; 3];
        let err = v.verify(&short).expect_err("short buffer must deny");
        match err {
            KbsError::Attestation(msg) => assert!(
                msg.contains("shorter than header"),
                "expected parse classifier, got: {msg}"
            ),
            other => panic!("expected Attestation(short), got {other:?}"),
        }
    }

    #[test]
    fn placeholder_is_all_zero() {
        let r = placeholder_verified_report();
        assert_eq!(r.tcb, 0);
        assert_eq!(r.policy, 0);
        assert!(r.measurement.iter().all(|&b| b == 0));
        assert!(r.chip_id.iter().all(|&b| b == 0));
    }

    /// Where to find a Genoa VEK to test against (see
    /// `test_vectors/snp/REGENERATE.md`).
    ///
    /// This is NOT committed, and that is deliberate. A VEK is issued
    /// per-chip, so it carries the 64-byte CHIP_ID of the machine it
    /// was fetched for in X.509 extension `1.3.6.1.4.1.3704.1.4`. The
    /// certificate is public AMD-signed material and conveys no
    /// secret — but it does name one physical host, and this
    /// repository is meant to be publishable.
    ///
    /// So the fixture is supplied out of band via
    /// `HIPPIUS_VEK_FIXTURE`. CI writes it from a secret; a developer
    /// exports the path to a VEK fetched from their own hardware. When
    /// the variable is unset the two tests below SKIP rather than
    /// fail, because an outsider who cloned this repo has no reason to
    /// possess one.
    ///
    /// The skip is the part to be careful with: a test that quietly
    /// does nothing is worse than no test. It is bounded two ways —
    /// when the variable IS set the tests run and must pass, and CI
    /// hard-fails if the secret is missing on the branches that
    /// matter (see `.github/workflows/ci.yml`).
    fn genoa_vek_fixture_path() -> Option<std::path::PathBuf> {
        let p = std::path::PathBuf::from(std::env::var_os("HIPPIUS_VEK_FIXTURE")?);
        p.is_file().then_some(p)
    }

    /// Emit the reason once, so a skipped run says so in the log
    /// instead of looking like a pass.
    fn skip_no_vek(test: &str) {
        eprintln!(
            "{test}: SKIPPED — no Genoa VEK available. Set HIPPIUS_VEK_FIXTURE to a \
             PEM fetched from AMD KDS for your own Genoa host (see \
             test_vectors/snp/REGENERATE.md). This test asserts AMD chain \
             consistency and cannot run without one."
        );
    }

    fn genoa_static_cfg(vek: std::path::PathBuf) -> SnpConfig {
        SnpConfig {
            generation: SnpGeneration::Genoa,
            vek_pem_path: vek,
            kds_url: None,
        }
    }

    #[test]
    fn build_with_genoa_vek_yields_sev_branch() {
        // Wiring smoke test: `[snp].generation = "genoa"` + a real AMD-
        // signed Genoa VEK MUST produce the `Sev(_)` variant (not
        // `Unconfigured`, not Err). Catches a regression where the
        // Genoa builtin pair stops loading or the chain construction
        // changes shape.
        let Some(vek) = genoa_vek_fixture_path() else {
            return skip_no_vek("build_with_genoa_vek_yields_sev_branch");
        };
        match build(Some(&genoa_static_cfg(vek))) {
            Ok(RuntimeAttestationVerifier::Sev(_)) => {}
            Ok(RuntimeAttestationVerifier::Unconfigured(_)) => {
                panic!("[snp].generation=genoa + a readable VEK must yield Sev, got Unconfigured")
            }
            Err(e) => panic!("build with real Genoa VEK fixture failed: {e:?}"),
        }
    }

    #[test]
    fn genoa_builtin_chain_verifies_against_fixture_vek() {
        // Stronger guarantee than `build_with_genoa_vek_yields_sev_branch`:
        // construct the exact `sev::certs::snp::Chain` the binary would
        // anchor (built-in Genoa ARK + ASK + fixture VEK) and run
        // `Chain::verify()` — that walks ARK self-sig, ARK→ASK sig, and
        // ASK→VEK sig. A green test proves the production-shape chain is
        // internally consistent AMD-signed end-to-end. Failure means
        // either the sev crate's built-in Genoa pair drifted, or the
        // fixture VEK is stale relative to its TCB (regenerate per
        // `test_vectors/snp/REGENERATE.md`).
        use sev::certs::snp::Verifiable;
        let Some(vek_path) = genoa_vek_fixture_path() else {
            return skip_no_vek("genoa_builtin_chain_verifies_against_fixture_vek");
        };
        let ark = builtin::genoa::ark().expect("built-in Genoa ARK");
        let ask = builtin::genoa::ask().expect("built-in Genoa ASK");
        let vek_pem = std::fs::read(&vek_path).expect("read fixture VEK");
        let vek = Certificate::from_pem(&vek_pem).expect("parse fixture VEK PEM");
        let chain = Chain {
            ca: ca::Chain {
                ark: ark.clone(),
                ask,
            },
            vek,
        };
        (&chain)
            .verify()
            .expect("Genoa ARK→ASK→VEK chain must verify against the fixture VEK");
    }

    #[test]
    fn build_aborts_startup_on_generation_vek_mismatch() {
        // The operator-facing fail-fast boot gate: `attest::build` MUST
        // run `Chain::verify()` and refuse to return a half-wired
        // verifier when `snp.generation = "milan"` is paired with a
        // Genoa-signed VEK (or vice versa). Without this, the KBS pod
        // would reach `/readyz` and only fail at the first release.
        let Some(vek) = genoa_vek_fixture_path() else {
            return skip_no_vek("build_aborts_startup_on_generation_vek_mismatch");
        };
        let cfg = SnpConfig {
            generation: SnpGeneration::Milan,
            vek_pem_path: vek,
            kds_url: None,
        };
        match build(Some(&cfg)) {
            Ok(_) => panic!(
                "expected build() to refuse milan-generation + genoa-VEK with a chain-verify Err"
            ),
            Err(Error::Wiring(msg)) => assert!(
                msg.contains("chain") || msg.contains("Chain"),
                "expected chain-verify classifier in error, got: {msg}"
            ),
            Err(other) => panic!("expected Wiring(chain verify), got {other:?}"),
        }
    }

    #[test]
    fn build_with_milan_generation_and_genoa_vek_fails_chain_construction() {
        // Defense-in-depth assertion: if an operator picks the wrong
        // built-in pair, the chain check MUST fail. We can't observe
        // that failure at `build` time (the chain-construction step
        // does no signature verify — the chain assembles regardless).
        // But constructing the chain locally + running `Chain::verify()`
        // MUST refuse the cross-generation mismatch. This locks the
        // expectation that picking `generation = "milan"` for a Genoa
        // host's VEK does NOT silently widen the trust set.
        use sev::certs::snp::Verifiable;
        let Some(vek_path) = genoa_vek_fixture_path() else {
            return skip_no_vek(
                "build_with_milan_generation_and_genoa_vek_fails_chain_construction",
            );
        };
        let ark = builtin::milan::ark().expect("built-in Milan ARK");
        let ask = builtin::milan::ask().expect("built-in Milan ASK");
        let vek_pem = std::fs::read(&vek_path).expect("read fixture VEK");
        let vek = Certificate::from_pem(&vek_pem).expect("parse fixture VEK PEM");
        let chain = Chain {
            ca: ca::Chain {
                ark: ark.clone(),
                ask,
            },
            vek,
        };
        assert!(
            (&chain).verify().is_err(),
            "Milan ARK MUST NOT chain-verify a Genoa-signed VEK"
        );
    }

    #[test]
    fn missing_vek_file_aborts_startup() {
        // A configured [snp] section pointing at a non-existent VEK
        // file must abort startup — never run with a silently-broken
        // chain verifier.
        let cfg = SnpConfig {
            generation: SnpGeneration::Milan,
            vek_pem_path: "/nonexistent/vek.pem".into(),
            kds_url: None,
        };
        // `RuntimeAttestationVerifier` (Ok variant) has no `Debug` —
        // pattern-match the error explicitly instead of leaning on
        // `Result::unwrap_err`'s `Debug` bound.
        match build(Some(&cfg)) {
            Ok(_) => panic!("expected Config(vek_pem_path), got Ok(_)"),
            Err(Error::Config(msg)) => assert!(
                msg.contains("vek_pem_path"),
                "unexpected Config error: {msg}"
            ),
            Err(other) => panic!("expected Config(vek_pem_path), got {other:?}"),
        }
    }

    // ───────────────────────── generation-agnostic ─────────────────────────
    //
    // The verifier's security rests on TWO independently-testable
    // layers: (1) it identifies the CORRECT generation per report, and
    // (2) it anchors to that generation's genuine built-in AMD ARK and
    // rejects anything whose VCEK/signature does not chain to it. We
    // cannot synthesize a report bearing a REAL AMD Turin signature
    // (that needs AMD's private VCEK key), so the "valid Turin report"
    // case is proven structurally: a Turin report routes to the Turin
    // ARK, and the Turin built-in ARK→ASK chain is itself AMD-valid.
    // Forgery/wrong-generation/no-anchor cases ARE fully exercised
    // against the real Genoa fixture + built-in roots.

    /// Synthesize a V5 report carrying the given CPUID family/model so
    /// `identify_report_generation` exercises the `identify_cpu` path
    /// (the Turin / newer-Genoa case).
    fn synth_v5_report(family: u8, model: u8, chip: [u8; 64]) -> AttestationReport {
        AttestationReport {
            version: 5,
            chip_id: chip,
            cpuid_fam_id: Some(family),
            cpuid_mod_id: Some(model),
            cpuid_step: Some(0),
            reported_tcb: tcb(),
            launch_tcb: tcb(),
            ..AttestationReport::default()
        }
    }

    /// A Turin-like V2 chip_id: nonzero in the first 8 bytes, zero in
    /// the last 56.
    fn turin_like_chip() -> [u8; 64] {
        let mut c = [0u8; 64];
        c[0] = 0x11;
        c[7] = 0x22;
        c
    }

    #[test]
    fn identifies_turin_from_v5_cpuid() {
        // Family 0x1A model 0x00..=0x11 is Turin per `Generation::identify_cpu`.
        let r = synth_v5_report(0x1A, 0x01, nonzero_chip());
        assert_eq!(
            gen_label(identify_report_generation(&r).unwrap()),
            "Turin",
            "family 0x1A must identify as Turin"
        );
    }

    #[test]
    fn identifies_genoa_from_v5_cpuid() {
        // Family 0x19 model 0x10..=0x1F is Genoa.
        let r = synth_v5_report(0x19, 0x11, nonzero_chip());
        assert_eq!(gen_label(identify_report_generation(&r).unwrap()), "Genoa");
    }

    #[test]
    fn identifies_milan_from_v5_cpuid() {
        // Family 0x19 model 0x0..=0xF is Milan.
        let r = synth_v5_report(0x19, 0x01, nonzero_chip());
        assert_eq!(gen_label(identify_report_generation(&r).unwrap()), "Milan");
    }

    #[test]
    fn identifies_turin_from_v2_chip_marker() {
        // A V2 report with the last 56 chip_id bytes zero is Turin-like.
        let r = AttestationReport {
            version: 2,
            chip_id: turin_like_chip(),
            reported_tcb: tcb(),
            launch_tcb: tcb(),
            ..AttestationReport::default()
        };
        assert_eq!(gen_label(identify_report_generation(&r).unwrap()), "Turin");
    }

    #[test]
    fn identifies_genoa_from_v2_full_chip() {
        // A V2 report with a full (non-Turin-like) chip_id is Genoa.
        let r = AttestationReport {
            version: 2,
            chip_id: nonzero_chip(),
            reported_tcb: tcb(),
            launch_tcb: tcb(),
            ..AttestationReport::default()
        };
        assert_eq!(gen_label(identify_report_generation(&r).unwrap()), "Genoa");
    }

    #[test]
    fn unknown_cpuid_generation_denied() {
        // A CPUID family with no AMD SEV-SNP generation (e.g. 0x17 Zen1)
        // MUST fail closed — there is no built-in ARK to anchor it.
        let r = synth_v5_report(0x17, 0x01, nonzero_chip());
        match identify_report_generation(&r) {
            Ok(g) => panic!("unknown family must deny, identified {}", gen_label(g)),
            Err(KbsError::Attestation(msg)) => assert!(
                msg.contains("no known AMD SEV-SNP generation"),
                "unexpected classifier: {msg}"
            ),
            Err(other) => panic!("expected Attestation, got {other:?}"),
        }
    }

    #[test]
    fn turin_builtin_ark_ask_chain_is_amd_valid() {
        // Structural proof that a Turin report — which `verify_report`
        // anchors to the built-in Turin ARK/ASK — has a genuine AMD
        // root: the Turin ARK self-signs and signs the Turin ASK. This
        // is the same guarantee `genoa_builtin_chain_verifies_against_
        // fixture_vek` gives for Genoa, minus the leaf (we have no real
        // Turin VCEK fixture). Failure means the vendored Turin builtin
        // pair drifted.
        use sev::certs::snp::Verifiable;
        let ca = ca::Chain {
            ark: builtin::turin::ark().expect("built-in Turin ARK"),
            ask: builtin::turin::ask().expect("built-in Turin ASK"),
        };
        (&ca)
            .verify()
            .expect("Turin ARK→ASK chain must be AMD-valid");
    }

    #[test]
    fn build_loads_all_three_generation_roots() {
        // The generation-agnostic verifier must carry Milan, Genoa AND
        // Turin built-in roots — `build` loads all three via
        // `builtin_ark_ask` before assembling the verifier, so a missing
        // builtin pair would abort here. Also directly asserts the three
        // labels resolve to a loadable pair.
        for gen in [Generation::Milan, Generation::Genoa, Generation::Turin] {
            builtin_ark_ask(gen)
                .unwrap_or_else(|e| panic!("built-in {} ARK/ASK must load: {e:?}", gen_label(gen)));
        }
        let Some(vek) = genoa_vek_fixture_path() else {
            return skip_no_vek("build_loads_all_three_generation_roots");
        };
        match build(Some(&genoa_static_cfg(vek))) {
            Ok(RuntimeAttestationVerifier::Sev(_)) => {}
            Ok(RuntimeAttestationVerifier::Unconfigured(_)) => {
                panic!("expected Sev verifier carrying all roots, got Unconfigured")
            }
            Err(e) => panic!("build must succeed loading all three roots: {e:?}"),
        }
    }

    #[test]
    fn forged_genoa_report_signature_denied() {
        // Full-path forgery test against the REAL Genoa fixture VEK: a
        // synthesized V2 Genoa report (correct generation identification,
        // correct ARK anchor, correct static-VEK leaf) but a bogus /
        // absent signature MUST be denied at the report-signature step.
        // This is the core anti-forgery guarantee — a non-genuine guest
        // cannot unlock a disk.
        let Some(vek) = genoa_vek_fixture_path() else {
            return skip_no_vek("forged_genoa_report_signature_denied");
        };
        let cfg = genoa_static_cfg(vek); // KDS off → static Genoa VEK used
        let v = build(Some(&cfg)).expect("build with Genoa fixture");
        // A V2 report whose chip_id is full (Genoa), default (zero)
        // signature — the fixture VEK will NOT have signed it.
        let raw = synth_v2_report([0x42u8; 48]);
        let err = v.verify(&raw).expect_err("forged signature must be denied");
        match err {
            KbsError::Attestation(msg) => assert!(
                // The default (all-zero) signature is denied either at the
                // p384 scalar-decode (all-zero is not a valid signature)
                // or at the digest-verify step — both are anti-forgery
                // denials at the report-signature boundary. The raw-bytes
                // verifier surfaces the former for an empty signature.
                msg.contains("does not sign")
                    || msg.contains("chain/sig verify")
                    || msg.contains("report signature parse"),
                "expected a signature-verify denial, got: {msg}"
            ),
            other => panic!("expected Attestation(sig), got {other:?}"),
        }
    }

    #[test]
    fn turin_report_denied_when_no_turin_vek_source() {
        // A Turin guest report, with KDS disabled and only a Genoa
        // static-VEK fallback, has no Turin VCEK source — it MUST fail
        // closed with a clear classifier (NOT silently fall through to
        // the Genoa VEK, which would anchor to the wrong ARK). This is
        // the fail-closed boundary of the additive change.
        let Some(vek) = genoa_vek_fixture_path() else {
            return skip_no_vek("turin_report_denied_when_no_turin_vek_source");
        };
        let cfg = genoa_static_cfg(vek); // static gen = Genoa, KDS off
        let v = build(Some(&cfg)).expect("build with Genoa fixture");
        // V5 Turin report (family 0x1A) — identified as Turin.
        let mut buf = Vec::new();
        synth_v5_report(0x1A, 0x01, nonzero_chip())
            .encode(&mut buf, ())
            .expect("encode v5 Turin report");
        let err = v.verify(&buf).expect_err("Turin w/o source must deny");
        match err {
            KbsError::Attestation(msg) => assert!(
                msg.contains("no VCEK for generation Turin"),
                "expected the fail-closed Turin-no-source classifier, got: {msg}"
            ),
            other => panic!("expected Attestation(no VCEK), got {other:?}"),
        }
    }

    #[test]
    fn turin_kds_url_uses_8byte_chip_and_fmc_spl() {
        // The KDS URL builder must (a) use the 8-byte chip_id form for
        // Turin (the §102 "Turin 8-byte chip_id URL form" gotcha) and
        // (b) emit the fmcSPL param when the report carries an FMC. The
        // base is pre-trimmed of any trailing slash by `build`.
        let mut chip = [0u8; 64];
        for (i, b) in chip.iter_mut().enumerate().take(8) {
            *b = i as u8;
        }
        let r = AttestationReport {
            version: 5,
            chip_id: chip,
            cpuid_fam_id: Some(0x1A),
            cpuid_mod_id: Some(0x01),
            cpuid_step: Some(0),
            // current_tcb != reported_tcb (the Turin firmware case). The
            // candidate list must offer BOTH URLs, reported_tcb FIRST.
            current_tcb: TcbVersion {
                fmc: Some(7),
                bootloader: 3,
                tee: 0,
                snp: 20,
                microcode: 72,
            },
            reported_tcb: TcbVersion {
                fmc: Some(9),
                bootloader: 9,
                tee: 9,
                snp: 9,
                microcode: 9,
            },
            launch_tcb: tcb(),
            ..AttestationReport::default()
        };
        let urls = MultiGenChainVerifier::candidate_vcek_urls(
            "https://kdsintf.amd.com",
            Generation::Turin,
            &r,
        );
        // Two distinct candidates (reported_tcb differs from current_tcb).
        assert_eq!(urls.len(), 2, "two TCB candidates: {urls:?}");
        // Candidate 0 = reported_tcb (AMD convention first), all-9s.
        assert!(
            urls[0].contains("/vcek/v1/Turin/0001020304050607?"),
            "{}",
            urls[0]
        );
        assert!(urls[0].contains("blSPL=09"), "reported first: {}", urls[0]);
        assert!(
            urls[0].contains("ucodeSPL=09"),
            "reported first: {}",
            urls[0]
        );
        assert!(urls[0].contains("fmcSPL=09"), "reported first: {}", urls[0]);
        // Candidate 1 = current_tcb (the Turin firmware signer).
        assert!(urls[1].contains("blSPL=03"), "current second: {}", urls[1]);
        assert!(urls[1].contains("snpSPL=20"), "current second: {}", urls[1]);
        assert!(
            urls[1].contains("ucodeSPL=72"),
            "current second: {}",
            urls[1]
        );
        assert!(urls[1].contains("fmcSPL=07"), "current second: {}", urls[1]);
    }

    #[test]
    fn genoa_kds_url_uses_full_64byte_chip_and_no_fmc() {
        // Genoa uses the full 64-byte chip_id and (with no FMC in TCB)
        // emits no fmcSPL — the contrast with the Turin form above.
        // reported_tcb == current_tcb (the Milan/Genoa norm) ⇒ a SINGLE
        // candidate URL: identical to the pre-fix behavior (no regression,
        // no extra KDS fetch).
        let r = AttestationReport {
            version: 5,
            chip_id: nonzero_chip(),
            cpuid_fam_id: Some(0x19),
            cpuid_mod_id: Some(0x11),
            cpuid_step: Some(0),
            current_tcb: tcb(),  // fmc = None
            reported_tcb: tcb(), // equal ⇒ one candidate
            launch_tcb: tcb(),
            ..AttestationReport::default()
        };
        let urls = MultiGenChainVerifier::candidate_vcek_urls(
            "https://kdsintf.amd.com",
            Generation::Genoa,
            &r,
        );
        assert_eq!(
            urls.len(),
            1,
            "equal reported/current TCB ⇒ one candidate (no regression): {urls:?}"
        );
        let url = &urls[0];
        assert!(url.contains("/vcek/v1/Genoa/"), "{url}");
        // full 64-byte chip → 128 hex chars between the gen and the `?`
        let chip_hex = url
            .split("/Genoa/")
            .nth(1)
            .and_then(|s| s.split('?').next())
            .expect("chip segment");
        assert_eq!(chip_hex.len(), 128, "Genoa uses full 64-byte chip: {url}");
        assert!(!url.contains("fmcSPL"), "no FMC ⇒ no fmcSPL param: {url}");
    }
}
