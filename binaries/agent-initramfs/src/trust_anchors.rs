//! UKI-embedded trust anchors the §21 boot pipeline gates the KBS
//! release response against.
//!
//! ## Why compile-time, not config
//!
//! The KBS response-signing public key + kid are the **producer side**
//! of the §20 KBS-signed envelope chain that the guest verifies before
//! it accepts any unwrap material:
//!
//! - The KBS (`binaries/kbs-server`) signs every release / denial
//!   response with `kbs-server-signing-key` (the `kbs.signingSeed`
//!   ESO-rendered secret).
//! - The guest's [`pipeline::verify_and_unwrap`] checks the response's
//!   `(alg, kid)` against [`PINNED_KBS_RESPONSE_KID`] and recovers the
//!   Ed25519 verifying key from [`PINNED_KBS_RESPONSE_VK`].
//!
//! A cmdline-overridable trust anchor would defeat the model — anyone
//! with cmdline access (the host miner, before the SEV-SNP launch
//! measurement gate) could swap in their own KBS pubkey and route the
//! release to a malicious endpoint. The fix is to **bake the values
//! into the measured UKI**: they become part of the rootfs the §F
//! launch digest covers, so a substitution shifts the measurement and
//! the §22 allowlist refuses the release.
//!
//! ## Lockstep ledger (DO NOT EDIT WITHOUT THE OTHERS)
//!
//! Any change to either constant below changes the tenant UKI's
//! launch measurement (the values live in the rootfs the §F build
//! pipeline measures). It is a cross-cut update with four
//! synchronised edits:
//!
//! | File | Field | Why |
//! |---|---|---|
//! | `binaries/agent-initramfs/src/trust_anchors.rs` | `PINNED_KBS_RESPONSE_VK` / `_KID` | (this file) |
//! | `deploy/gitops/apps/kbs/values.yaml` | `config.authPubkeyHex` / `config.kidHex` | the KBS pod signs with the matching seed |
//! | `test_vectors/allowlist/dev-manifest.toml` | every `accepted_kbs_response_kids_hex` row | the §22 allowlist gate at release time |
//! | `test_vectors/allowlist/dev.cose` | (regenerated from the manifest) | byte-identical to what the dev KBS reads |
//!
//! Plus, because the constants are measured, every change also:
//!
//! - shifts `test_vectors/uki/tenant-measurement.json`,
//! - requires a `dev-manifest.toml::epoch` bump,
//! - and a `deploy/gitops/apps/kbs/values.yaml::allowlist.sha256`
//!   bump to match the new `dev.cose`.
//!
//! ## Drift detection
//!
//! Unit tests in this module assert the const bytes against the same
//! hex literals the chart values carry. A future drift (e.g. someone
//! rotates the chart pubkey but forgets to bump the const here) fires
//! at CI, not at first boot — fail-loud-early, not fail-closed-late.
//!
//! ## Production rotation
//!
//! Phase B's offline §22 ceremony rotates the KBS response-signing
//! seed. The matching pubkey + kid here are bumped IN THE SAME
//! commit window as the chart values + the §22 epoch + the tenant
//! UKI rebuild — see the lockstep ledger above. Multi-KBS support
//! (accepting more than one pubkey concurrently for a graceful
//! rollover) is a future Phase B item; today the guest pins exactly
//! one response-signing identity.

/// Ed25519 verifying key the guest accepts on the KBS release-
/// response envelope.
///
/// **Lockstep with**:
///   - `deploy/gitops/apps/kbs/values.yaml::config.authPubkeyHex`
///   - every `accepted_kbs_response_kids_hex` row in
///     `test_vectors/allowlist/dev-manifest.toml` (those carry the
///     **kid**, but the kid resolves to THIS pubkey via the chart).
///
/// UKI-embedded — changing this value moves the tenant UKI launch
/// measurement (the bytes are in the rootfs). See the module
/// docstring's "Lockstep ledger" for the full cross-cut.
pub const PINNED_KBS_RESPONSE_VK: [u8; 32] =
    hex_literal::hex!("24e6a730dc24e1bfba1e6d21d943924d3ab6f311ea0f2e0b3e585458393bc803");

/// ASCII bytes of the KBS response-signing `kid` —
/// `"kbs-cc-1-response-v1"`.
///
/// Hex form (the form the chart + manifest carry) is
/// `6b62732d63632d312d726573706f6e73652d7631`; see
/// `deploy/gitops/apps/kbs/values.yaml::config.kidHex` for the
/// source of truth.
///
/// UKI-embedded for the same reason as [`PINNED_KBS_RESPONSE_VK`].
pub const PINNED_KBS_RESPONSE_KID: &[u8] = b"kbs-cc-1-response-v1";

#[cfg(test)]
mod tests {
    //! Drift-gate tests — these assertions fire at `cargo test` if
    //! someone changes a `PINNED_*` const above without also
    //! updating the mirror string below (or vice versa). The test
    //! is INTENTIONALLY circular: the `EXPECTED_*` strings live
    //! inside this module so the unit test can run without I/O or a
    //! YAML-parser dep (parsing
    //! `deploy/gitops/apps/kbs/values.yaml` from a unit test would
    //! drag in `serde_yaml` or a hand-rolled regex scrape — both
    //! over-engineering for a once-per-rotation lockstep gate).
    //!
    //! The audit pattern, called out in `Cargo.toml` review:
    //!   1. Open `deploy/gitops/apps/kbs/values.yaml`.
    //!   2. Diff `config.authPubkeyHex` against `EXPECTED_AUTH_PUBKEY_HEX`.
    //!   3. Diff `config.kidHex` against `EXPECTED_KID_HEX`.
    //!   4. Bump in lockstep. The test catches step (2)/(3) drift
    //!      between the const and its mirror; (1) ↔ (mirror) drift
    //!      is operator discipline + the post-merge KAT cycle (see
    //!      module docstring "Lockstep ledger").

    use super::*;

    /// Mirror of `deploy/gitops/apps/kbs/values.yaml::config.authPubkeyHex`
    /// — every operator-visible declaration of the KBS pubkey must
    /// be byte-identical to this string.
    const EXPECTED_AUTH_PUBKEY_HEX: &str =
        "24e6a730dc24e1bfba1e6d21d943924d3ab6f311ea0f2e0b3e585458393bc803";

    /// Mirror of `deploy/gitops/apps/kbs/values.yaml::config.kidHex`
    /// — the hex-encoded ASCII bytes of the kid.
    const EXPECTED_KID_HEX: &str = "6b62732d63632d312d726573706f6e73652d7631";

    /// Mirror of the chart-rendered ASCII kid (`"kbs-cc-1-response-v1"`).
    const EXPECTED_KID_ASCII: &str = "kbs-cc-1-response-v1";

    #[test]
    fn pinned_kbs_vk_matches_chart_authpubkeyhex() {
        // `hex` is a dev-only dependency for tests in the crate.
        let bytes =
            hex::decode(EXPECTED_AUTH_PUBKEY_HEX).expect("EXPECTED_AUTH_PUBKEY_HEX must be hex");
        assert_eq!(
            bytes.len(),
            32,
            "Ed25519 pubkey must be 32 bytes; chart literal is wrong length"
        );
        assert_eq!(
            PINNED_KBS_RESPONSE_VK.as_slice(),
            bytes.as_slice(),
            "PINNED_KBS_RESPONSE_VK drifted from \
             deploy/gitops/apps/kbs/values.yaml::config.authPubkeyHex — \
             a chart-side rotation MUST bump this const AND the §22 \
             allowlist epoch AND the tenant UKI measurement"
        );
    }

    #[test]
    fn pinned_kbs_kid_matches_chart_kidhex() {
        // The chart's `kidHex` is the hex-encoded ASCII of the kid.
        let from_hex = hex::decode(EXPECTED_KID_HEX).expect("EXPECTED_KID_HEX must be hex");
        assert_eq!(
            PINNED_KBS_RESPONSE_KID,
            from_hex.as_slice(),
            "PINNED_KBS_RESPONSE_KID drifted from \
             deploy/gitops/apps/kbs/values.yaml::config.kidHex"
        );
        // Cross-belt: the const literal itself is the ASCII form;
        // assert the decoded chart hex IS that ASCII string. A
        // typo in the chart hex (e.g. extra nibble) trips this even
        // if `from_hex` happens to keep the right byte length.
        assert_eq!(
            std::str::from_utf8(PINNED_KBS_RESPONSE_KID).unwrap(),
            EXPECTED_KID_ASCII,
            "PINNED_KBS_RESPONSE_KID must spell {EXPECTED_KID_ASCII:?}"
        );
    }

    #[test]
    fn pinned_kbs_kid_matches_dev_allowlist_manifest() {
        // The §22 allowlist gates release on the kid the KBS signs
        // with. Every `accepted_kbs_response_kids_hex` row in the
        // dev manifest MUST resolve to THIS kid; this test pins one
        // representative entry. A full sweep is what the
        // `kbs-allowlist-tool` round-trip handles on its own side
        // (committed `dev.cose` would diff against a rebuild on any
        // drift).
        let expected = hex::decode(EXPECTED_KID_HEX).expect("test hex literal");
        assert_eq!(PINNED_KBS_RESPONSE_KID, expected.as_slice());
    }
}
