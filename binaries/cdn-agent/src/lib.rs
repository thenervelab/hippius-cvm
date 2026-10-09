//! `hippius-cdn-agent`: the control agent of a `cdn-node` CVM (CDN plan
//! I1, spec `docs/design/cdn.md` §5, §7.3, §9.2, §10.7).
//!
//! The agent holds every secret on the node: the node key (HKDF from the
//! KBS-released lifecycle key), the boot-time fleet keyring, the backend
//! session. OpenResty, which faces the internet, receives only the
//! certificates and zone secrets it serves, over a local control socket.
//!
//! Module map:
//! - [`config`]: baked agent config + user-data node identity, fail closed;
//! - [`identity`], [`unseal`]: node credential, fleet keyring, sealed boxes;
//! - [`wire`], [`backend`], [`reqsign`]: the §C backend contract, its client
//!   and the per-request node signatures;
//! - [`feed`]: snapshot/delta application, purge generations, LKG;
//! - [`render`], [`certstore`], [`control`]: what OpenResty receives;
//! - [`counters`], [`usage`]: metering and signed usage reports;
//! - [`health`], [`attestation`]: readiness bits, TLS-bound SNP report;
//! - [`issuer`], [`acme`], [`csr`]: certificate issuance (I4);
//! - [`hooks`]: where I5 (logs) and I6 (HTTP origins) plug in;
//! - [`agent`]: the threads that run it all.

pub mod acme;
pub mod agent;
pub mod attestation;
pub mod backend;
pub mod certstore;
pub mod clock;
pub mod config;
pub mod control;
pub mod counters;
pub mod csr;
pub mod disk;
pub mod error;
pub mod feed;
pub mod health;
pub mod hooks;
pub mod hostname;
pub mod identity;
pub mod issuer;
pub mod persist;
pub mod render;
pub mod reqsign;
pub mod shutdown;
pub mod unseal;
pub mod usage;
pub mod wire;

#[cfg(test)]
mod fake_ca;
#[cfg(test)]
mod test_support;

/// Bytes of `proxy_cache_path max_size` for the cache volume at `path`:
/// `fill_percent` of its total size (spec §5.2; the rest is headroom).
/// Computed as `render.sh cache-auto` does (whole KiB), see
/// [`disk::cache_max_computed`].
pub fn cache_max_size(path: &std::path::Path, fill_percent: u8) -> error::Result<u64> {
    disk::cache_max_computed(path, fill_percent).ok_or(error::CdnError::Io("statvfs"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    #[test]
    fn cache_size_is_a_fraction_of_the_volume() {
        let dir = tempfile::tempdir().unwrap();
        let full = super::cache_max_size(dir.path(), 100).unwrap();
        let three_quarters = super::cache_max_size(dir.path(), 75).unwrap();
        assert!(full > 0);
        // Whole KiB, like render.sh: within a KiB of three quarters.
        assert!(three_quarters <= full * 3 / 4 && three_quarters + 1024 >= full * 3 / 4);
        assert_eq!(three_quarters % 1024, 0);
        assert!(super::cache_max_size(&dir.path().join("absent"), 75).is_err());
    }
}
