//! Real AMD SEV-SNP attestation verifier (replaces the test-only
//! [`crate::snp::AttestationVerifier`] seam from the scaffold).
//!
//! Strict spec alignment (ARCHITECTURE.md §7): ABI-correct report parsing via
//! the `sev` crate (we do NOT hand-roll SNP report offsets — that is a
//! security risk); cryptographic chain verification behind the
//! [`ChainVerifier`] trait; TCB rollback rejection (`current_tcb >=
//! launch_tcb` AND `committed_tcb >= launch_tcb` — the actual running /
//! committed TCB, NOT the host-settable `reported_tcb`); and
//! `MaskedChipId` (CHIP_ID all-zero) refused by the parser
//! so we always have an attested per-CPU identity for §8/§23 platform binding.
//!
//! The production [`SevChainVerifier`] wraps `sev::certs::snp::{Chain,
//! Verifiable}` — pure-Rust P-384 ECDSA via the `sev` crate's `crypto_nossl`
//! feature (no OpenSSL system dep). Tests use an injected mock chain so the
//! verifier logic is testable without live AMD KDS access. The chain *fetch*
//! (AMD KDS HTTP + per-`CHIP_ID/TCB` cache) is the §17 follow-up; the trait
//! pins the SHAPE so no static-trust path exists.

use crate::error::{KbsError, Result};
use crate::report_data::ct_eq;
use crate::snp::{AttestationVerifier, VerifiedReport};
use sev::certs::snp::{Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::TcbVersion;
use sev::parser::ByteParser;

/// SNP report versions this verifier accepts. V2 covers Milan/Genoa
/// silicon; V5 is what Debian Trixie's 6.12 kernel emits on the same
/// silicon (live-observed 2026-05-26 on an EPYC 9254 (Genoa) host).
/// V3/V4 are the AMD "pre-Turin" report layout (the V3 variant in the
/// `sev` crate: `ReportVariant::decode` maps both `3 | 4 => V3`,
/// populating the CPUID family/model/step fields V3 added); V4 is what
/// the newer SEV-SNP firmware (API 1.55) on the Turin miners emits
/// (live-observed 2026-06-29 on an EPYC Turin host). All four are
/// fully-implemented, spec-correct variants — generation is derived
/// from the chip_id/CPUID, NOT the version, so a V4 report from a Turin
/// chip decodes as Generation::Turin with the Turin TCB byte layout.
/// Pinning here forbids ONLY the `sev` crate's "treat unknown version
/// `> 5` as V5" forward-default — a future-ABI accept path; an unknown
/// version still fails this set-check (which precedes the parse).
/// Adding a version to this list is a §22-affecting policy change.
pub const SUPPORTED_REPORT_VERSIONS: &[u32] = &[2, 3, 4, 5];

/// Length, in bytes, of the SNP attestation report region the VCEK
/// signs. Per the SEV-SNP ABI the signature covers bytes `0..0x2a0`
/// (the comment on `AttestationReport::signature` reads "Signature of
/// bytes 0 to 0x29F inclusive"). This offset is VERSION-INVARIANT — it
/// is identical for report versions 2/3/4/5 and is where every future
/// version's signed body ends, with the 512-byte signature following.
pub const SIGNED_REPORT_LEN: usize = 0x2a0;

/// Verify the SNP report signature over the RAW WIRE BYTES, against a
/// VCEK leaf certificate's SEC1 public key.
///
/// ## Why raw bytes, never a re-serialized struct
///
/// The signed message is `raw_report[..0x2a0]` exactly as it arrived on
/// the wire. We MUST NOT reconstruct it by re-encoding a parsed
/// `AttestationReport`: the `sev` crate maps report version 4 onto its
/// V3 variant (`3 | 4 => V3`), and the V3 decode treats the 168-byte
/// region at `0x150..0x1F8` as a reserved `skip_bytes::<168>` — exactly
/// where V5 carries `launch_mit_vector` + `current_mit_vector`. A Turin
/// chip emitting a v4 report POPULATES that region (Turin has
/// mitigation vectors), so the V3 decode discards those bytes and a
/// subsequent re-encode writes ZEROS there. `to_bytes()` then differs
/// from the wire in the signed region, the SHA-384 digest differs, and
/// P-384 verify fails with "VEK does not sign the attestation report"
/// even though the chain and VCEK are correct. Hashing the raw wire
/// bytes is correct for every version and immune to any field the
/// parser drops.
fn verify_report_sig_over_raw(
    vek: &Certificate,
    report: &AttestationReport,
    raw_report: &[u8],
) -> Result<()> {
    verify_report_sig_over_raw_sec1(vek.public_key_sec1(), report, raw_report)
}

/// Inner signature check against a VCEK's SEC1-encoded P-384 public
/// key. Split from [`verify_report_sig_over_raw`] so the wire-bytes
/// invariant is unit-testable with a synthetic key (no forged AMD
/// X.509 cert needed) — the certificate wrapper only contributes the
/// SEC1 pubkey bytes.
fn verify_report_sig_over_raw_sec1(
    vek_sec1: &[u8],
    report: &AttestationReport,
    raw_report: &[u8],
) -> Result<()> {
    use p384::ecdsa::signature::DigestVerifier;
    use sha2::Digest;

    if raw_report.len() < SIGNED_REPORT_LEN {
        return Err(KbsError::Attestation(format!(
            "SNP report shorter than the signed region ({} < {SIGNED_REPORT_LEN})",
            raw_report.len()
        )));
    }
    // The signature field itself round-trips fine (it is read/written at
    // fixed offsets in every variant), so extracting it from the parsed
    // struct is safe — only the SIGNED MESSAGE must come from the wire.
    let sig = p384::ecdsa::Signature::try_from(&report.signature)
        .map_err(|e| KbsError::Attestation(format!("SNP report signature parse: {e}")))?;
    let digest = sha2::Sha384::new_with_prefix(&raw_report[..SIGNED_REPORT_LEN]);
    let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(vek_sec1)
        .map_err(|e| KbsError::Attestation(format!("VCEK SEC1 pubkey: {e}")))?;
    verifying_key.verify_digest(digest, &sig).map_err(|e| {
        // Diagnostic: if a sig still fails, report HOW FAR the parser's
        // re-encode drifts from the wire inside the signed body. A
        // non-empty diff range here is the fingerprint of a parser that
        // drops a wire field (the v4/Turin mit-vector class of bug) — and
        // confirms that hashing the wire bytes (which we do) is the only
        // correct message. Emitted to stderr, never to the signed denial.
        if let Ok(reencoded) = report.to_bytes() {
            let lo = (0..SIGNED_REPORT_LEN).find(|&i| raw_report[i] != reencoded[i]);
            if let Some(lo) = lo {
                let hi = (0..SIGNED_REPORT_LEN)
                    .rev()
                    .find(|&i| raw_report[i] != reencoded[i])
                    .unwrap_or(lo);
                eprintln!(
                    "kbs-core::snp_real: report re-encode differs from wire in the signed \
                     region at 0x{lo:x}..=0x{hi:x} — the raw-wire-bytes path is authoritative \
                     (a re-encode-hash verifier would have failed here even with a valid VCEK)"
                );
            }
        }
        KbsError::Attestation(format!(
            "AMD chain/sig verify: VEK does not sign the attestation report (raw-bytes): {e}"
        ))
    })
}

/// Final step of `(Chain, AttestationReport).verify()`: cryptographically
/// proves that the report was signed by the VEK at the leaf of a valid
/// `ARK → ASK → VEK` chain. Modeled as a trait so unit tests can inject
/// a known-good (or known-bad) verifier without round-tripping real AMD
/// certificates, while production uses [`SevChainVerifier`].
///
/// `verify_report` returns the PEM bytes of the AMD certificate chain
/// (VCEK → ASK → ARK in verification order) it just anchored the report
/// to — captured into [`crate::snp::VerifiedReport::chain_pem`] so the
/// §280 evidence bundle the release path archives carries the same
/// bytes a future client verifier would re-anchor to AMD's root.
/// Returning the chain FROM `verify_report` (rather than a separate
/// `chain_pem()` accessor) lets a verifier resolve a DIFFERENT chain
/// per report — the generation-agnostic case where the ARK/ASK/VCEK is
/// selected from the report's own CPU generation — with no shared
/// mutable state to race across concurrent releases.
///
/// Test mocks return an empty `Vec`; production verifiers return the
/// real serialized chain.
pub trait ChainVerifier {
    /// Verify the report against the AMD chain and return the anchored
    /// chain PEM. `raw_report` is the original wire-bytes buffer — the
    /// report signature is verified over `raw_report[..0x2a0]`, NEVER a
    /// re-serialized struct (see [`verify_report_sig_over_raw`]).
    fn verify_report(&self, report: &AttestationReport, raw_report: &[u8]) -> Result<Vec<u8>>;
}

/// Production verifier. A `sev::certs::snp::Chain` (ARK + ASK + VEK)
/// pre-fetched from AMD KDS for the host's `CHIP_ID/TCB`, **plus the
/// expected AMD ARK pinned by the binary (compiled-in)** — without
/// anchoring, `Chain::verify()` only checks self-consistency (a fake
/// chain self-signs its own ARK and passes). Fields are private; the
/// only constructor takes the pinned ARK, so the production type cannot
/// be built without it.
pub struct SevChainVerifier {
    chain: Chain,
    trusted_ark_bytes: Vec<u8>,
}

impl SevChainVerifier {
    /// Build a chain verifier anchored to `trusted_ark`. The byte
    /// comparison uses DER (the `x509-cert` canonical form), so both
    /// sides agree regardless of any prior PEM/DER round-trip.
    pub fn new(chain: Chain, trusted_ark: &Certificate) -> Result<Self> {
        let der = trusted_ark
            .to_der()
            .map_err(|e| KbsError::Attestation(format!("trusted ARK DER: {e}")))?;
        if der.is_empty() {
            return Err(KbsError::Attestation("trusted ARK is empty".into()));
        }
        Ok(Self {
            chain,
            trusted_ark_bytes: der,
        })
    }
}

impl ChainVerifier for SevChainVerifier {
    fn verify_report(&self, report: &AttestationReport, raw_report: &[u8]) -> Result<Vec<u8>> {
        // Anchor: the chain's ARK MUST byte-equal the pinned ARK.
        let chain_ark = self
            .chain
            .ca
            .ark
            .to_der()
            .map_err(|e| KbsError::Attestation(format!("chain ARK DER: {e}")))?;
        if !ct_eq(&chain_ark, &self.trusted_ark_bytes) {
            return Err(KbsError::Attestation(
                "chain ARK does not match pinned AMD root".into(),
            ));
        }
        // Walk the AMD certificate chain (ARK self-sig → ARK→ASK →
        // ASK→VCEK) and obtain the VCEK leaf. `Chain::verify()` does NOT
        // touch the report signature, so this is purely the cert-chain
        // proof — the leaf it returns is the key the report must be
        // signed by.
        let vek = self
            .chain
            .verify()
            .map_err(|e| KbsError::Attestation(format!("AMD cert chain verify: {e}")))?;
        // Report signature over the RAW WIRE BYTES (never a re-encoded
        // struct — see the helper's rationale for the v4/Turin
        // mit-vector drop bug).
        verify_report_sig_over_raw(vek, report, raw_report)?;
        chain_to_pem(&self.chain)
    }
}

/// Serialize an AMD SEV-SNP `Chain` to PEM in verification order
/// (VCEK → ASK → ARK), one PEM block per cert, concatenated. Same
/// format `openssl x509`-style toolchains expect. Each
/// `Certificate::to_pem()` already includes the trailing newline that
/// delimits PEM blocks, so simple concatenation is enough.
///
/// Shared by [`SevChainVerifier`] and the binary's generation-agnostic
/// verifier so the §280 evidence bundle carries the exact AMD chain the
/// report was anchored to, regardless of which generation's ARK signed.
pub fn chain_to_pem(chain: &Chain) -> Result<Vec<u8>> {
    let vek = chain
        .vek
        .to_pem()
        .map_err(|e| KbsError::Attestation(format!("VEK PEM: {e}")))?;
    let ask = chain
        .ca
        .ask
        .to_pem()
        .map_err(|e| KbsError::Attestation(format!("ASK PEM: {e}")))?;
    let ark = chain
        .ca
        .ark
        .to_pem()
        .map_err(|e| KbsError::Attestation(format!("ARK PEM: {e}")))?;
    let mut out = Vec::with_capacity(vek.len() + ask.len() + ark.len());
    out.extend_from_slice(&vek);
    out.extend_from_slice(&ask);
    out.extend_from_slice(&ark);
    Ok(out)
}

/// The real `AttestationVerifier` for SEV-SNP. Parses the raw report via
/// the `sev` crate (ABI-correct), then delegates the cryptographic chain
/// verification to the [`ChainVerifier`] seam, then enforces TCB
/// rollback rejection and CHIP_ID presence before returning a
/// [`VerifiedReport`].
pub struct RealSnpVerifier<C: ChainVerifier> {
    pub chain_verifier: C,
}

impl<C: ChainVerifier> RealSnpVerifier<C> {
    pub fn new(chain_verifier: C) -> Self {
        Self { chain_verifier }
    }
}

/// Pack a `TcbVersion` into a single `u64` in a way that **preserves
/// the derived `Ord`** on `TcbVersion` (which compares fields in
/// declaration order: `fmc, bootloader, tee, snp, microcode`).
///
/// Distinguishing `None` from `Some(0)` for `fmc` matters because the
/// rollback check uses the derived `Ord` and `None < Some(_)`. We
/// encode that with a separate "fmc present" bit one position above
/// the `fmc` value byte:
/// `[bit 40 = fmc_present][bits 32..39 = fmc value]
///  [bits 24..31 = bootloader][bits 16..23 = tee]
///  [bits 8..15 = snp][bits 0..7 = microcode]`.
fn pack_tcb(t: &TcbVersion) -> u64 {
    let fmc_present = u64::from(t.fmc.is_some());
    let fmc_val = u64::from(t.fmc.unwrap_or(0));
    (fmc_present << 40)
        | (fmc_val << 32)
        | (u64::from(t.bootloader) << 24)
        | (u64::from(t.tee) << 16)
        | (u64::from(t.snp) << 8)
        | u64::from(t.microcode)
}

impl<C: ChainVerifier> AttestationVerifier for RealSnpVerifier<C> {
    fn verify(&self, raw_report: &[u8]) -> Result<VerifiedReport> {
        // 0. Pin the report version up front — the `sev` crate treats an
        //    unknown `version > 5` as V5, which is a future-ABI accept
        //    path. We refuse anything outside our supported version set.
        if raw_report.len() < 4 {
            return Err(KbsError::Attestation(
                "SNP report shorter than header".into(),
            ));
        }
        let version = u32::from_le_bytes(
            raw_report[0..4]
                .try_into()
                .map_err(|e| KbsError::Attestation(format!("SNP version slice: {e}")))?,
        );
        if !SUPPORTED_REPORT_VERSIONS.contains(&version) {
            return Err(KbsError::Attestation(format!(
                "unsupported SNP report version {version} (only {SUPPORTED_REPORT_VERSIONS:?})"
            )));
        }

        // 1. ABI-correct parse (refuses wrong length).
        let report = AttestationReport::from_bytes(raw_report)
            .map_err(|e| KbsError::Attestation(format!("SNP report parse: {e}")))?;

        // 2. Defense-in-depth: explicitly reject MaskedChipId. The sev
        //    crate refuses this on V2 generation detection, but not on
        //    V3/V5; pin it here unconditionally so the §8/§23 platform
        //    binding invariant holds regardless of parser internals.
        if report.chip_id.iter().all(|&b| b == 0) {
            return Err(KbsError::Attestation(
                "MaskedChipId (CHIP_ID all-zero) — no platform binding".into(),
            ));
        }

        // 3. AMD chain + report signature (pure-Rust P-384 via sev's
        //    `crypto_nossl`); the production verifier additionally
        //    anchors the chain's ARK to the binary-pinned AMD root for
        //    THIS report's CPU generation. Returns the VCEK → ASK → ARK
        //    PEM that was anchored, for the §280 evidence bundle.
        let chain_pem = self.chain_verifier.verify_report(&report, raw_report)?;

        // 4. TCB rollback rejection (§7) — uses TcbVersion's derived Ord.
        //
        // The anti-rollback invariant is that the platform's ACTUAL
        // RUNNING TCB has not been rolled back below the TCB the guest
        // launched on. Per the AMD SNP ABI, `launch_tcb` is "the
        // CurrentTcb at the time the guest was launched", and
        // `current_tcb` is the TCB the platform is running NOW — so the
        // correct check is `current_tcb >= launch_tcb`.
        //
        // We must NOT key this off `reported_tcb`: the ABI defines it as
        // "the TCB used to derive the VCEK", and it is HOST-SETTABLE to a
        // value at/below current_tcb (the reportable floor — e.g. lowered
        // for cross-platform migration compatibility). Some Turin
        // firmware (API 1.55, live-observed on an EPYC 9255) reports
        // `reported_tcb.microcode = 0` while running `current_tcb.microcode
        // = 0x47` and launching at the same `launch_tcb.microcode = 0x47`
        // — a perfectly valid, NON-rolled-back platform that the old
        // `reported_tcb < launch_tcb` check false-denied. Keying off the
        // host-settable reported_tcb is also weaker: a host could set it
        // high to mask an actual current_tcb rollback. We additionally
        // require `committed_tcb >= launch_tcb` (the firmware's committed
        // floor cannot have rolled back below launch either).
        if report.current_tcb < report.launch_tcb {
            return Err(KbsError::Policy(format!(
                "TCB rollback: current_tcb {:?} < launch_tcb {:?}",
                report.current_tcb, report.launch_tcb
            )));
        }
        if report.committed_tcb < report.launch_tcb {
            return Err(KbsError::Policy(format!(
                "TCB rollback: committed_tcb {:?} < launch_tcb {:?}",
                report.committed_tcb, report.launch_tcb
            )));
        }

        // 5. Read the raw `policy` 8 bytes straight from the report at
        //    the ABI offset (0x08), bypassing `GuestPolicy::into(): u64`
        //    which ORs reserved bit 17 and would corrupt later policy
        //    bit checks.
        let policy = u64::from_le_bytes(
            raw_report[8..16]
                .try_into()
                .map_err(|e| KbsError::Attestation(format!("SNP policy slice: {e}")))?,
        );

        // 6. The chain bytes the verifier just anchored (step 3) are
        //    archived in the §280 evidence bundle the release path
        //    writes on grant. Mocks return empty; the production
        //    verifier returns VCEK → ASK → ARK PEM. A serialization
        //    failure inside `verify_report` is already a hard error —
        //    better fail the release closed than archive a
        //    half-evidence bundle.
        Ok(VerifiedReport {
            measurement: report.measurement,
            report_data: report.report_data,
            tcb: pack_tcb(&report.reported_tcb),
            policy,
            chip_id: report.chip_id,
            chain_pem,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sev::parser::Encoder as SevEncoder;

    /// Test ChainVerifier — always accepts. Lets us exercise parsing, field
    /// extraction, and TCB/CHIP_ID checks without real AMD certificates.
    struct AcceptChain;
    impl ChainVerifier for AcceptChain {
        fn verify_report(&self, _r: &AttestationReport, _raw: &[u8]) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }
    /// Test ChainVerifier: always denies.
    struct DenyChain;
    impl ChainVerifier for DenyChain {
        fn verify_report(&self, _r: &AttestationReport, _raw: &[u8]) -> Result<Vec<u8>> {
            Err(KbsError::Attestation("test: chain denies".into()))
        }
    }

    fn synthesize_report(
        measurement: [u8; 48],
        report_data: [u8; 64],
        chip_id: [u8; 64],
        reported_tcb: TcbVersion,
        launch_tcb: TcbVersion,
    ) -> Vec<u8> {
        // The §7 anti-rollback check keys off current_tcb + committed_tcb
        // (the actual running/committed TCB), NOT reported_tcb. For the
        // common-case synthesized report, set them equal to launch_tcb so
        // the rollback check passes (current_tcb == launch_tcb). Tests
        // that exercise the rollback path use `synthesize_report_tcbs`.
        synthesize_report_tcbs(
            measurement,
            report_data,
            chip_id,
            reported_tcb,
            launch_tcb,
            launch_tcb,
            launch_tcb,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn synthesize_report_tcbs(
        measurement: [u8; 48],
        report_data: [u8; 64],
        chip_id: [u8; 64],
        reported_tcb: TcbVersion,
        launch_tcb: TcbVersion,
        current_tcb: TcbVersion,
        committed_tcb: TcbVersion,
    ) -> Vec<u8> {
        // Build a v2 report (the sev crate then picks Generation =
        // Genoa for non-Turin-like CHIP_IDs).
        let r = AttestationReport {
            version: 2,
            measurement,
            report_data,
            chip_id,
            reported_tcb,
            launch_tcb,
            current_tcb,
            committed_tcb,
            ..AttestationReport::default()
        };
        let mut buf = Vec::new();
        r.encode(&mut buf, ()).expect("encode round-trip");
        buf
    }

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

    #[test]
    fn parses_and_extracts_fields() {
        let m = [7u8; 48];
        let rd = {
            let mut x = [0u8; 64];
            x[..4].copy_from_slice(b"DEAD");
            x
        };
        let chip = nonzero_chip();
        let raw = synthesize_report(m, rd, chip, tcb(), tcb());
        let v = RealSnpVerifier::new(AcceptChain).verify(&raw).unwrap();
        assert_eq!(v.measurement, m);
        assert_eq!(v.report_data, rd);
        assert_eq!(v.chip_id, chip);
        // pack_tcb(bl=1, tee=2, snp=3, microcode=4) = 0x01_02_03_04
        assert_eq!(v.tcb, 0x01_02_03_04);
    }

    #[test]
    fn denying_chain_denies_release() {
        let raw = synthesize_report([0u8; 48], [0u8; 64], nonzero_chip(), tcb(), tcb());
        assert!(RealSnpVerifier::new(DenyChain).verify(&raw).is_err());
    }

    #[test]
    fn truncated_bytes_denied() {
        let raw = synthesize_report([0u8; 48], [0u8; 64], nonzero_chip(), tcb(), tcb());
        let bad = &raw[..raw.len() - 8];
        assert!(RealSnpVerifier::new(AcceptChain).verify(bad).is_err());
    }

    #[test]
    fn tcb_rollback_denied_on_current_below_launch() {
        // The §7 check keys off the ACTUAL RUNNING TCB: current_tcb <
        // launch_tcb ⇒ rollback (the platform is running below the TCB
        // the guest launched on).
        let older = TcbVersion {
            fmc: None,
            bootloader: 1,
            tee: 1,
            snp: 1,
            microcode: 1,
        };
        let newer = TcbVersion {
            fmc: None,
            bootloader: 5,
            tee: 5,
            snp: 5,
            microcode: 5,
        };
        // launch_tcb = newer, current_tcb = older (rolled back), committed = newer.
        let raw = synthesize_report_tcbs(
            [0u8; 48],
            [0u8; 64],
            nonzero_chip(),
            newer, // reported_tcb (irrelevant to the check now)
            newer, // launch_tcb
            older, // current_tcb  ← below launch ⇒ rollback
            newer, // committed_tcb
        );
        let err = RealSnpVerifier::new(AcceptChain).verify(&raw).unwrap_err();
        match err {
            KbsError::Policy(s) => {
                assert!(s.contains("TCB rollback"), "{s}");
                assert!(s.contains("current_tcb"), "must cite current_tcb: {s}");
            }
            other => panic!("expected Policy(TCB rollback), got {other:?}"),
        }
    }

    #[test]
    fn tcb_rollback_denied_on_committed_below_launch() {
        let older = TcbVersion {
            fmc: None,
            bootloader: 1,
            tee: 1,
            snp: 1,
            microcode: 1,
        };
        let newer = TcbVersion {
            fmc: None,
            bootloader: 5,
            tee: 5,
            snp: 5,
            microcode: 5,
        };
        // committed_tcb below launch ⇒ rollback (current ok).
        let raw = synthesize_report_tcbs(
            [0u8; 48],
            [0u8; 64],
            nonzero_chip(),
            newer,
            newer,
            newer, // reported, launch, current all newer
            older, // committed_tcb ← below launch
        );
        let err = RealSnpVerifier::new(AcceptChain).verify(&raw).unwrap_err();
        match err {
            KbsError::Policy(s) => assert!(s.contains("committed_tcb"), "{s}"),
            other => panic!("expected Policy(TCB rollback), got {other:?}"),
        }
    }

    #[test]
    fn turin_lower_reported_tcb_is_not_a_rollback() {
        // THE observed Turin case: the firmware reports a LOWER
        // reported_tcb (host-settable reportable floor) than launch_tcb,
        // while current_tcb == committed_tcb == launch_tcb (NOT rolled
        // back). The old `reported_tcb < launch_tcb` check false-denied
        // this. The fix keys off current/committed, so it must ALLOW it.
        let low = TcbVersion {
            fmc: Some(0),
            bootloader: 0,
            tee: 0,
            snp: 1,
            microcode: 0, // observed Turin reported_tcb.microcode = 0
        };
        let running = TcbVersion {
            fmc: Some(0),
            bootloader: 0,
            tee: 0,
            snp: 1,
            microcode: 0x47, // observed Turin current/launch microcode = 71
        };
        let raw = synthesize_report_tcbs(
            [0u8; 48],
            [0u8; 64],
            nonzero_chip(),
            low,     // reported_tcb (lower — must NOT trip rollback)
            running, // launch_tcb
            running, // current_tcb (== launch ⇒ OK)
            running, // committed_tcb (== launch ⇒ OK)
        );
        // AcceptChain bypasses the sig; the §7 check must pass ⇒ a full
        // VerifiedReport, NOT a Policy(rollback) error.
        let v = RealSnpVerifier::new(AcceptChain)
            .verify(&raw)
            .expect("lower reported_tcb with running==launch must NOT be a rollback");
        // tcb() field reported in VerifiedReport packs reported_tcb.
        assert_eq!(v.chip_id, nonzero_chip());
    }

    #[test]
    fn masked_chip_id_denied_by_parser() {
        // The sev crate refuses to encode/decode a report with an
        // all-zero CHIP_ID (MaskChipId). We get a parse Err — that's
        // still a deny, which is the §8/§23 invariant we care about.
        let r = AttestationReport {
            version: 2,
            chip_id: [0u8; 64],
            reported_tcb: tcb(),
            launch_tcb: tcb(),
            ..AttestationReport::default()
        };
        let mut raw = Vec::new();
        assert!(r.encode(&mut raw, ()).is_err());
    }

    #[test]
    fn unsupported_version_denied() {
        // Build a v=99 report buffer — the version check rejects before parse.
        let mut bad = vec![0u8; 64];
        bad[0..4].copy_from_slice(&99u32.to_le_bytes());
        let err = RealSnpVerifier::new(AcceptChain).verify(&bad).unwrap_err();
        match err {
            KbsError::Attestation(s) => assert!(s.contains("unsupported SNP report version")),
            other => panic!("expected Attestation(unsupported), got {other:?}"),
        }
    }

    #[test]
    fn v4_report_accepted_and_fields_extracted() {
        // that Turin host's SEV-SNP firmware (API 1.55) emits report version 4 —
        // the AMD "pre-Turin" V3 layout (cpuid fam/mod/step populated).
        // The version gate must accept it (it is in SUPPORTED_REPORT_
        // VERSIONS) and the sev crate must decode the V3 variant so the
        // §8/§23 fields (measurement, report_data, chip_id, tcb) come out
        // byte-correct. `nonzero_chip()` is NOT turin-like (byte 63 set),
        // so this exercises the Genoa-flavoured V3 path; the live Turin
        // path differs only in chip_id shape + TCB byte layout, both of
        // which the crate keys off chip_id/CPUID, not the version.
        let m = [0x42u8; 48];
        let rd = [0x11u8; 64];
        let chip = nonzero_chip();
        let r = AttestationReport {
            version: 4,
            measurement: m,
            report_data: rd,
            chip_id: chip,
            reported_tcb: tcb(),
            launch_tcb: tcb(),
            // current/committed >= launch so the §7 anti-rollback check
            // (now keyed off current_tcb + committed_tcb) passes.
            current_tcb: tcb(),
            committed_tcb: tcb(),
            // V3 variant carries the CPUID identity fields — Some(_) so
            // the encoder writes them at the V3 offsets.
            cpuid_fam_id: Some(0x1A),
            cpuid_mod_id: Some(0x02),
            cpuid_step: Some(0x01),
            ..AttestationReport::default()
        };
        let mut raw = Vec::new();
        r.encode(&mut raw, ()).expect("v4 encode round-trip");
        assert_eq!(u32::from_le_bytes(raw[0..4].try_into().unwrap()), 4);
        let v = RealSnpVerifier::new(AcceptChain)
            .verify(&raw)
            .expect("v4 report must be accepted by the version gate + parse");
        // The §8/§23 platform-binding fields decode byte-correct from the
        // V3 variant. (TCB packing is exercised by `parses_and_extracts_
        // fields`; the V3/Turin TCB byte layout differs from V2's and is
        // read self-consistently from a real firmware report.)
        assert_eq!(v.measurement, m);
        assert_eq!(v.report_data, rd);
        assert_eq!(v.chip_id, chip);
    }

    #[test]
    fn policy_read_from_raw_bytes_no_reserved_bit() {
        // Raw policy bytes at offset 0x08 ARE what we expose; the sev
        // `GuestPolicy::into(): u64` would OR in reserved bit 17. By
        // reading raw bytes we don't.
        let raw = synthesize_report([0u8; 48], [0u8; 64], nonzero_chip(), tcb(), tcb());
        let v = RealSnpVerifier::new(AcceptChain).verify(&raw).unwrap();
        // The synthesized report leaves `policy` at the default (0); raw
        // bytes therefore yield 0, NOT (0 | (1<<17)).
        assert_eq!(
            v.policy, 0,
            "policy must be raw, not sev::GuestPolicy::into"
        );
    }

    #[test]
    fn fmc_present_bit_disambiguates_none_from_some_zero() {
        // None < Some(0) per derived Ord — our packing must agree, else
        // a Some(0) report would compare equal to a None one in the
        // `policy.min_tcb` check while differing in the rollback check.
        let none = TcbVersion {
            fmc: None,
            bootloader: 0,
            tee: 0,
            snp: 0,
            microcode: 0,
        };
        let some0 = TcbVersion {
            fmc: Some(0),
            bootloader: 0,
            tee: 0,
            snp: 0,
            microcode: 0,
        };
        assert!(none < some0);
        assert!(pack_tcb(&none) < pack_tcb(&some0));
    }

    #[test]
    fn pack_tcb_is_monotonic() {
        let a = TcbVersion {
            fmc: None,
            bootloader: 1,
            tee: 1,
            snp: 1,
            microcode: 1,
        };
        let b = TcbVersion {
            fmc: None,
            bootloader: 1,
            tee: 1,
            snp: 1,
            microcode: 2,
        };
        let c = TcbVersion {
            fmc: None,
            bootloader: 2,
            tee: 0,
            snp: 0,
            microcode: 0,
        };
        assert!(pack_tcb(&a) < pack_tcb(&b));
        assert!(pack_tcb(&b) < pack_tcb(&c));
        assert!(a < b && b < c); // sanity vs derived Ord on TcbVersion
    }

    /// Build a sev `Signature` field from a p384 ECDSA signature. The
    /// sev field stores `r`/`s` as 72-byte little-endian arrays; the
    /// crate's `TryFrom<&Signature> for p384::ecdsa::Signature` reads
    /// `bytes.take(48).rev()` (LE→BE) — so we write the BE scalar bytes
    /// reversed into the low 48 bytes of each 72-byte array.
    fn sev_signature_from_p384(sig: &p384::ecdsa::Signature) -> sev::certs::snp::ecdsa::Signature {
        let (r_be, s_be) = (sig.r().to_bytes(), sig.s().to_bytes());
        let mut r = [0u8; 72];
        let mut s = [0u8; 72];
        for (i, b) in r_be.iter().rev().enumerate() {
            r[i] = *b;
        }
        for (i, b) in s_be.iter().rev().enumerate() {
            s[i] = *b;
        }
        sev::certs::snp::ecdsa::Signature::new(r, s)
    }

    #[test]
    fn report_sig_verifies_over_raw_wire_bytes_not_reencode() {
        // THE REGRESSION TEST for the v4/Turin "VEK does not sign" bug.
        //
        // A Turin chip emitting a report version 4 populates the 168-byte
        // mitigation-vector region inside the signed body `[..0x2a0]`.
        // The `sev` crate maps v4 → its V3 variant, whose decode treats
        // that region as a reserved `skip_bytes::<168>` and re-encodes it
        // as ZEROS. So `report.to_bytes()` differs from the wire there,
        // and a verifier that hashes the RE-ENCODED struct computes the
        // wrong SHA-384 digest → P-384 verify fails even with the correct
        // VCEK. We hash the RAW WIRE BYTES instead, which is correct.
        //
        // This test proves the raw-bytes path by:
        //   1. signing the genuine raw `[..0x2a0]` and verifying it,
        //   2. flipping a byte INSIDE the dropped region of the raw
        //      buffer and asserting the verify now FAILS — i.e. the
        //      verifier really hashed those bytes (the old re-encode path
        //      zeroed them, so it could NOT have detected this flip).
        use p384::ecdsa::signature::DigestVerifier as _;
        use p384::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        use sha2::Digest;

        // Deterministic non-zero P-384 secret scalar.
        let sk = SigningKey::from_bytes((&[0x11u8; 48]).into()).expect("p384 signing key");
        let vk_sec1 = sk.verifying_key().to_sec1_bytes();

        // A v4 report whose raw buffer has NON-ZERO bytes in the 168-byte
        // mit-vector region (0x150..0x1F8) — the region the V3 re-encode
        // would zero. We can't synthesize that via the struct encoder (it
        // writes zeros there), so we patch the raw buffer directly.
        let mut raw = synthesize_report([0x42u8; 48], [0x11u8; 64], nonzero_chip(), tcb(), tcb());
        assert!(raw.len() >= SIGNED_REPORT_LEN);
        // Stamp a recognisable pattern across the dropped mit-vector
        // region (well inside the signed `[..0x2a0]` body).
        for (i, b) in raw[0x150..0x1F8].iter_mut().enumerate() {
            *b = 0xC0u8.wrapping_add(i as u8);
        }

        // Sign the GENUINE raw signed body and stamp the signature in.
        let digest = sha2::Sha384::new_with_prefix(&raw[..SIGNED_REPORT_LEN]);
        let good_sig: p384::ecdsa::Signature = sk
            .sign_prehash(&digest.clone().finalize())
            .expect("sign prehash");
        // sanity: the key really signs this digest
        sk.verifying_key()
            .verify_digest(digest, &good_sig)
            .expect("self-check");

        let report = AttestationReport {
            version: 4,
            signature: sev_signature_from_p384(&good_sig),
            ..AttestationReport::default()
        };

        // 1. The genuine raw bytes verify against the SEC1 pubkey.
        verify_report_sig_over_raw_sec1(&vk_sec1, &report, &raw)
            .expect("genuine raw-bytes signature must verify");

        // 2. Flip a byte INSIDE the dropped mit-vector region. The
        //    re-encode path zeroes this region, so it would have produced
        //    the SAME digest and MASKED the tamper. The raw-bytes path
        //    hashes it, so the signature must now fail to verify.
        let mut tampered = raw.clone();
        tampered[0x160] ^= 0xFF;
        let err = verify_report_sig_over_raw_sec1(&vk_sec1, &report, &tampered)
            .expect_err("a flip in the signed mit-vector region must break verification");
        match err {
            KbsError::Attestation(s) => {
                assert!(s.contains("VEK does not sign"), "unexpected: {s}")
            }
            other => panic!("expected Attestation(VEK does not sign), got {other:?}"),
        }

        // 3. Guard: a buffer shorter than the signed region fails closed.
        assert!(
            verify_report_sig_over_raw_sec1(&vk_sec1, &report, &raw[..SIGNED_REPORT_LEN - 1])
                .is_err()
        );
    }
}
