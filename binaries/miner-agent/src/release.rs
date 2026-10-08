//! The release this binary was built as.
//!
//! The release workflow (`.github/workflows/miner-agent-release.yml`)
//! builds with `HIPPIUS_RELEASE_TAG=<tag>` in the environment and the tag
//! is compiled in. Any other build — `cargo build` by hand, play 05's
//! source build, the container image — carries [`DEV_RELEASE`].
//!
//! `--version` prints `hippius-miner-agent <crate version> (<tag>)`. The
//! crate version stays in the line on purpose: play 05 skips its source
//! build only while `--version` contains `versions.miner_agent`. The
//! auto-updater reads the parenthesised tag and refuses a downloaded
//! binary whose tag is not the release it was published under.

use std::sync::OnceLock;

/// Tag of an unreleased build.
pub const DEV_RELEASE: &str = "dev";

/// The release tag compiled into this binary (`vYYYY.MM.DD[.N]`), or
/// [`DEV_RELEASE`].
pub const RELEASE_TAG: &str = match option_env!("HIPPIUS_RELEASE_TAG") {
    Some(tag) if !tag.is_empty() => tag,
    _ => DEV_RELEASE,
};

/// The `--version` line, minus the binary name clap prepends.
pub fn version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| format!("{} ({RELEASE_TAG})", env!("CARGO_PKG_VERSION")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_carries_the_crate_version_and_the_release_tag() {
        assert_eq!(
            version(),
            format!("{} ({})", env!("CARGO_PKG_VERSION"), RELEASE_TAG)
        );
    }

    #[test]
    fn release_tag_follows_the_build_environment() {
        match option_env!("HIPPIUS_RELEASE_TAG") {
            Some(tag) if !tag.is_empty() => assert_eq!(RELEASE_TAG, tag),
            _ => assert_eq!(RELEASE_TAG, DEV_RELEASE),
        }
    }
}
