//! Customer-held keys (M1/M2) — the miner-side facts the guardian vsock
//! relay ([`crate::vsock::guardian_relay`]) serves from.
//!
//! A customer-keys VM's launch order names its key guardian
//! ([`crate::orders::LaunchOrder::guardian_ep`]). The launch checks that
//! endpoint against the MEASURED cmdline, captures the VM's
//! [`LaunchRecipe`] (the exact inputs its launch digest was computed
//! over), and keeps both on the [`super::CvmHandle`] as a
//! [`GuardianRoute`]. The relay resolves a connecting vsock CID to the
//! CURRENT handle that owns it ([`super::CvmLifecycle::guardian_route_for_cid`])
//! and only ever dials that route's endpoint.
//!
//! Nothing here is secret. The endpoint is in the measured cmdline, and
//! the recipe is the public measurement input the guest itself hands the
//! guardian; the guardian recomputes the digest, so a wrong recipe only
//! earns a `measurement-mismatch` denial.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use hippius_types::guardian::{GuardianBinding, GuardianEndpoint, GuardianHost, LaunchRecipe};
use sha2::{Digest, Sha256, Sha384};

use super::qemu_config::QemuConfig;
use crate::error::{MinerAgentError, Result};

/// SEV-SNP guest-features bitmap every tenant launch is measured with.
/// MUST equal the `SNP_GUEST_FEATURES` the digest is computed with
/// (`launch_digest::snp_impl`) and `packer/kbs-uki/uki/Makefile` (`0x1`
/// = SNPActive).
pub const SNP_GUEST_FEATURES: u64 = 0x1;

/// Where the relay may send a VM's guardian traffic, and what it answers
/// the guest's recipe request with. One per customer-keys VM, held on its
/// [`super::CvmHandle`] and re-adopted with it.
#[derive(Clone, PartialEq, Eq)]
pub struct GuardianRoute {
    /// The canonical `host:port` (the order's `guardian_ep`, equal to the
    /// DECODED measured `hippius.guardian_ep=` token — the cmdline carries
    /// it hex-encoded).
    pub endpoint: String,
    /// The launch recipe the VM's digest was computed over.
    pub recipe: LaunchRecipe,
}

/// Who a CID's guardian traffic belongs to right now: the VM, the exact
/// libvirt domain incarnation (UUID) running it, and its route. The relay
/// pins this at accept and requires the same `(vm_id, domain)` after the
/// request is read.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RouteBinding {
    pub vm_id: super::VmId,
    pub domain: String,
    pub route: GuardianRoute,
}

/// Hand-written so a `{:?}` of a handle can never print the cmdline
/// (`LaunchOrder` / `QemuConfig` keep it out of logs for the same reason).
impl std::fmt::Debug for GuardianRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardianRoute")
            .field("endpoint", &self.endpoint)
            .field("cmdline", &"<redacted>")
            .field("vcpus", &self.recipe.vcpus)
            .field("vcpu_type", &self.recipe.vcpu_type)
            .finish()
    }
}

impl GuardianRoute {
    /// Validate a route read back from disk (re-adoption): the endpoint
    /// is canonical and dialable, the recipe is well-formed, and its
    /// cmdline pins exactly this endpoint.
    pub fn validate(&self) -> Result<()> {
        self.recipe
            .validate()
            .map_err(|_| MinerAgentError::LaunchInput("guardian-recipe-invalid"))?;
        let ep = check_order_guardian(&self.recipe.cmdline, Some(&self.endpoint))?;
        if ep.is_none() {
            return Err(MinerAgentError::LaunchInput("guardian-ep-orphan"));
        }
        Ok(())
    }
}

/// Check a launch's `guardian_ep` against its MEASURED cmdline.
///
/// | cmdline binding | `guardian_ep` | result |
/// |---|---|---|
/// | none (M0) | absent | `Ok(None)` — today's launch, untouched |
/// | none (M0) | present | `guardian-ep-orphan` |
/// | M1/M2 | absent | `guardian-ep-missing` (the guest could never unlock) |
/// | M1/M2 | present, ≠ the decoded token | `guardian-ep-mismatch` |
/// | M1/M2 | present, = the decoded token | `Ok(Some(endpoint))` |
///
/// The measured token is the lowercase HEX of the canonical endpoint
/// (so no endpoint can spell cloud-init's `cc:`); the order carries the
/// plain canonical string. The comparison is between the order's PARSED
/// endpoint and the binding's DECODED one — never the order string
/// against the raw token.
///
/// Plus: the order's string must be the ONE canonical spelling
/// (`guardian-ep-invalid`), a cmdline the guardian grammar refuses fails
/// `guardian-cmdline`, and an endpoint on a loopback / link-local /
/// unspecified / multicast address fails `guardian-ep-forbidden-address`
/// — the relay dials FROM the miner host, so such an endpoint would
/// point guest-originated traffic at the host's own services.
///
/// The measured token is what the guardian and the guest read; this check
/// only stops an honest-but-buggy dispatcher from launching a VM that can
/// never reach its guardian. A lying miner gains nothing by skipping it.
pub fn check_order_guardian(
    cmdline: &str,
    guardian_ep: Option<&str>,
) -> Result<Option<GuardianEndpoint>> {
    let binding = GuardianBinding::from_cmdline(cmdline)
        .map_err(|_| MinerAgentError::LaunchInput("guardian-cmdline"))?;
    let (binding, ep) = match (binding, guardian_ep) {
        (None, None) => return Ok(None),
        (None, Some(_)) => return Err(MinerAgentError::LaunchInput("guardian-ep-orphan")),
        (Some(_), None) => return Err(MinerAgentError::LaunchInput("guardian-ep-missing")),
        (Some(b), Some(ep)) => (b, ep),
    };
    let parsed = GuardianEndpoint::parse(ep)
        .map_err(|_| MinerAgentError::LaunchInput("guardian-ep-invalid"))?;
    if parsed.to_wire() != ep {
        return Err(MinerAgentError::LaunchInput("guardian-ep-invalid"));
    }
    if parsed != binding.endpoint {
        return Err(MinerAgentError::LaunchInput("guardian-ep-mismatch"));
    }
    if !endpoint_host_allowed(&parsed.host) {
        return Err(MinerAgentError::LaunchInput(
            "guardian-ep-forbidden-address",
        ));
    }
    Ok(Some(parsed))
}

/// Whether the relay may dial `host`. IP literals must be
/// [`ip_allowed`]; a DNS name is checked again on every resolved address
/// at dial time, and the `localhost` names are refused outright.
pub fn endpoint_host_allowed(host: &GuardianHost) -> bool {
    match host {
        GuardianHost::Ipv4(a) => ip_allowed(IpAddr::V4(*a)),
        GuardianHost::Ipv6(a) => ip_allowed(IpAddr::V6(*a)),
        GuardianHost::Dns(name) => name != "localhost" && !name.ends_with(".localhost"),
    }
}

/// `false` for addresses a customer's guardian can never legitimately
/// have, seen from a miner: loopback, unspecified, `0.0.0.0/8`,
/// link-local (incl. cloud metadata 169.254.169.254), multicast,
/// broadcast, and the PRIVATE ranges — RFC 1918 and IPv6 ULA
/// `fc00::/7` — which from the miner's side name the miner's own LAN,
/// never the customer's. The same for IPv4-mapped IPv6 forms.
///
/// CGNAT `100.64.0.0/10` stays allowed: that is where a NetBird guardian
/// lives (design §0 finding 1). Public addresses are allowed. The miner's
/// OWN addresses in any allowed range are refused at dial time
/// ([`is_local_address`]).
pub fn ip_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => ipv4_allowed(a),
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => ipv4_allowed(v4),
            None => ipv6_allowed(a),
        },
    }
}

/// NetBird's own in-mesh service addresses (the embedded DNS resolver
/// and its companion). Inside 100.64.0.0/10, but never a customer's
/// guardian — from the miner they are the miner's own NetBird agent.
pub const NETBIRD_SERVICE_ADDRS: [Ipv4Addr; 2] = [
    Ipv4Addr::new(100, 100, 100, 100),
    Ipv4Addr::new(100, 100, 100, 200),
];

fn ipv4_allowed(a: Ipv4Addr) -> bool {
    !(a.is_loopback()
        || a.is_unspecified()
        || a.octets()[0] == 0
        || a.is_link_local()
        || a.is_multicast()
        || a.is_broadcast()
        || a.is_private()
        || NETBIRD_SERVICE_ADDRS.contains(&a))
}

fn ipv6_allowed(a: Ipv6Addr) -> bool {
    let link_local = (a.segments()[0] & 0xffc0) == 0xfe80;
    let unique_local = (a.segments()[0] & 0xfe00) == 0xfc00;
    !(a.is_loopback() || a.is_unspecified() || a.is_multicast() || link_local || unique_local)
}

/// `true` iff `ip` is assigned to one of THIS host's interfaces — the
/// kernel lets a socket bind only to a local address (absent
/// `ip_nonlocal_bind`, which the miner does not set). A guardian endpoint
/// on the miner's own NetBird / public address would point guest traffic
/// at the miner's own services; the dialer refuses it. Any doubt (the
/// probe cannot even be attempted) reads as local.
pub fn is_local_address(ip: IpAddr) -> bool {
    match std::net::UdpSocket::bind(std::net::SocketAddr::new(ip, 0)) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::AddrNotAvailable,
    }
}

/// What a [`LaunchRecipe`] is computed from: the three artifact files,
/// the exact cmdline QEMU was given, and the vCPU count. Built from a
/// launch's [`QemuConfig`], or — on re-adoption — from the live domain
/// XML's `<os>` block.
#[derive(Clone, PartialEq, Eq)]
pub struct RecipeInputs {
    pub ovmf: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub cmdline: String,
    pub vcpus: u32,
}

impl RecipeInputs {
    pub fn from_config(config: &QemuConfig) -> Self {
        Self {
            ovmf: config.ovmf_path.clone(),
            kernel: config.kernel_path.clone(),
            initrd: config.initrd_path.clone(),
            cmdline: config.cmdline.clone(),
            vcpus: u32::from(config.cpu_count),
        }
    }
}

/// Build the [`LaunchRecipe`] for `inputs`: the SHA-384 of the OVMF file,
/// the SHA-256 of the kernel and initrd, the exact cmdline QEMU is given,
/// the vCPU count, and the vCPU model + guest features the digest folds
/// in. `vcpu_type` is the `hippius-launch-digest --vcpu-type` spelling
/// (`EpycGenoa`, …).
///
/// Fails closed (`guardian-recipe-*`): a customer-keys VM whose recipe
/// cannot be produced could never be verified by its guardian, so its
/// launch is refused rather than started to wait forever.
pub fn build_launch_recipe(
    inputs: &RecipeInputs,
    vcpu_type: &str,
    guest_features: u64,
) -> Result<LaunchRecipe> {
    let recipe = LaunchRecipe {
        ovmf_sha384: hash_file::<Sha384>(&inputs.ovmf)?,
        kernel_sha256: hash_file::<Sha256>(&inputs.kernel)?,
        initrd_sha256: hash_file::<Sha256>(&inputs.initrd)?,
        cmdline: inputs.cmdline.clone(),
        vcpus: inputs.vcpus,
        vcpu_type: vcpu_type.to_string(),
        guest_features,
    };
    recipe
        .validate()
        .map_err(|_| MinerAgentError::LaunchInput("guardian-recipe-invalid"))?;
    Ok(recipe)
}

/// Stream `path` through digest `D`.
fn hash_file<D: Digest>(path: &Path) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)
        .map_err(|_| MinerAgentError::LaunchInput("guardian-recipe-read"))?;
    let mut hasher = D::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|_| MinerAgentError::LaunchInput("guardian-recipe-read"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    /// An M1 cmdline measuring `ep` — hex-encoded, as vali mints it.
    fn m1(ep: &str) -> String {
        let tok = hex::encode(ep.as_bytes());
        format!("console=hvc0 hippius.key_mode=split hippius.guardian_pk={PK} hippius.guardian_ep={tok} quiet")
    }

    fn class(r: Result<Option<GuardianEndpoint>>) -> &'static str {
        match r {
            Ok(None) => "m0",
            Ok(Some(_)) => "ok",
            Err(MinerAgentError::LaunchInput(c)) => c,
            Err(_) => "other",
        }
    }

    #[test]
    fn m0_without_endpoint_is_untouched() {
        assert_eq!(
            class(check_order_guardian("console=hvc0 quiet", None)),
            "m0"
        );
        // Explicit M0 too.
        assert_eq!(
            class(check_order_guardian("hippius.key_mode=hippius", None)),
            "m0"
        );
    }

    #[test]
    fn endpoint_must_match_the_measured_token() {
        let ep = "100.64.1.2:7443";
        assert_eq!(class(check_order_guardian(&m1(ep), Some(ep))), "ok");
        let got = check_order_guardian(&m1(ep), Some(ep)).unwrap().unwrap();
        assert_eq!(got.to_wire(), ep);
        assert_eq!(
            class(check_order_guardian(&m1(ep), Some("100.64.1.3:7443"))),
            "guardian-ep-mismatch"
        );
        assert_eq!(
            class(check_order_guardian(&m1(ep), None)),
            "guardian-ep-missing"
        );
        assert_eq!(
            class(check_order_guardian("quiet", Some(ep))),
            "guardian-ep-orphan"
        );
    }

    /// H1b: the order's plain endpoint is compared with the DECODED
    /// token, never with the raw hex.
    #[test]
    fn the_order_is_compared_with_the_decoded_token() {
        for ep in [
            "100.64.1.2:7443",
            "guardian.example.cc:443",
            "[2001:db8::cc:1]:443",
        ] {
            let got = check_order_guardian(&m1(ep), Some(ep)).unwrap().unwrap();
            assert_eq!(got.to_wire(), ep);
        }
        // The order carrying the raw hex token is not an endpoint at all.
        let ep = "100.64.1.2:7443";
        let tok = hex::encode(ep.as_bytes());
        assert_eq!(
            class(check_order_guardian(&m1(ep), Some(&tok))),
            "guardian-ep-invalid"
        );
        // A cmdline measuring the PLAIN endpoint (the pre-H1b spelling)
        // is refused by the grammar, whatever the order says.
        let plain = format!(
            "console=hvc0 hippius.key_mode=split hippius.guardian_pk={PK} hippius.guardian_ep={ep}"
        );
        assert_eq!(
            class(check_order_guardian(&plain, Some(ep))),
            "guardian-cmdline"
        );
        // Uppercase hex is a second spelling of the token: refused.
        let upper = format!(
            "console=hvc0 hippius.key_mode=split hippius.guardian_pk={PK} hippius.guardian_ep={}",
            tok.to_ascii_uppercase()
        );
        assert_eq!(
            class(check_order_guardian(&upper, Some(ep))),
            "guardian-cmdline"
        );
    }

    #[test]
    fn a_non_canonical_or_malformed_endpoint_is_refused() {
        let ep = "guardian.example.com:7443";
        for bad in [
            "GUARDIAN.example.com:7443",
            "guardian.example.com:07443",
            "http://guardian.example.com:7443",
            "guardian.example.com",
            "",
        ] {
            assert_eq!(
                class(check_order_guardian(&m1(ep), Some(bad))),
                "guardian-ep-invalid",
                "{bad}"
            );
        }
    }

    #[test]
    fn a_bad_guardian_cmdline_is_refused() {
        // Duplicate token — the grammar refuses, so does the launch.
        let cmd = format!("{} hippius.key_mode=split", m1("10.0.0.1:1"));
        assert_eq!(
            class(check_order_guardian(&cmd, Some("10.0.0.1:1"))),
            "guardian-cmdline"
        );
    }

    #[test]
    fn host_local_endpoints_are_refused() {
        for ep in [
            "127.0.0.1:9700",
            "0.0.0.0:1",
            "169.254.169.254:80",
            "224.0.0.1:1",
            "255.255.255.255:1",
            "[::1]:9700",
            "[::]:1",
            "[fe80::1]:1",
            "[ff02::1]:1",
            "[::ffff:127.0.0.1]:1",
            "[::ffff:10.0.0.1]:1",
            "10.1.2.3:7443",
            "172.16.0.1:7443",
            "172.31.255.254:7443",
            "192.168.1.1:7443",
            "0.1.2.3:7443",
            "[fd00::1]:7443",
            "[fc00::1]:7443",
            "100.100.100.100:53",
            "100.100.100.200:7443",
            "[::ffff:100.100.100.100]:53",
            "localhost:7443",
            "a.localhost:7443",
        ] {
            assert_eq!(
                class(check_order_guardian(&m1(ep), Some(ep))),
                "guardian-ep-forbidden-address",
                "{ep}"
            );
        }
        for ep in [
            "100.64.0.1:7443",
            "100.127.255.254:7443",
            "100.100.100.101:7443",
            "100.100.100.199:7443",
            "172.32.0.1:7443",
            "8.8.8.8:443",
            "[2001:db8::1]:7443",
            "guardian.example.com:7443",
        ] {
            assert_eq!(class(check_order_guardian(&m1(ep), Some(ep))), "ok", "{ep}");
        }
    }

    #[test]
    fn local_addresses_are_detected() {
        assert!(is_local_address("127.0.0.1".parse().unwrap()));
        // TEST-NET-1 / documentation prefix: never assigned to a host.
        assert!(!is_local_address("192.0.2.1".parse().unwrap()));
    }

    fn config_in(dir: &Path, cmdline: &str) -> QemuConfig {
        use crate::lifecycle::cvm_handle::{DomainUuid, VmId};
        std::fs::write(dir.join("ovmf"), b"ovmf-bytes").unwrap();
        std::fs::write(dir.join("kernel"), b"kernel-bytes").unwrap();
        std::fs::write(dir.join("initrd"), b"initrd-bytes").unwrap();
        QemuConfig {
            vm_id: VmId::new("t").unwrap(),
            domain_uuid: DomainUuid::parse("11111111-2222-4333-8444-555555555555").unwrap(),
            ovmf_path: dir.join("ovmf"),
            kernel_path: dir.join("kernel"),
            initrd_path: dir.join("initrd"),
            cmdline: cmdline.to_string(),
            luks_disk_path: dir.join("d.img"),
            luks_disk_size_gb: 10,
            rootfs_data_path: dir.join("rootfs.img"),
            rootfs_hash_path: dir.join("rootfs.verity"),
            state_disk_path: dir.join("state.raw"),
            data_disk_path: None,
            data_disk_size_gb: 0,
            cpu_count: 4,
            memory_mb: 1024,
            golden: false,
            cid: 3,
        }
    }

    #[test]
    fn recipe_hashes_the_exact_files_and_keeps_the_exact_cmdline() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = m1("100.64.0.1:7443");
        let cfg = config_in(dir.path(), &cmd);
        let r = build_launch_recipe(
            &RecipeInputs::from_config(&cfg),
            "EpycTurin",
            SNP_GUEST_FEATURES,
        )
        .unwrap();
        assert_eq!(r.ovmf_sha384, Sha384::digest(b"ovmf-bytes").to_vec());
        assert_eq!(r.kernel_sha256, Sha256::digest(b"kernel-bytes").to_vec());
        assert_eq!(r.initrd_sha256, Sha256::digest(b"initrd-bytes").to_vec());
        assert_eq!(r.cmdline, cmd);
        assert_eq!(r.vcpus, 4);
        assert_eq!(r.vcpu_type, "EpycTurin");
        assert_eq!(r.guest_features, 1);
    }

    #[test]
    fn recipe_fails_closed_on_a_missing_file_or_an_unmeasurable_cmdline() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config_in(dir.path(), "quiet");
        cfg.initrd_path = dir.path().join("missing");
        assert!(matches!(
            build_launch_recipe(&RecipeInputs::from_config(&cfg), "EpycGenoa", 1),
            Err(MinerAgentError::LaunchInput("guardian-recipe-read"))
        ));
        let mut cfg = config_in(dir.path(), &"a".repeat(2048));
        cfg.cpu_count = 1;
        assert!(matches!(
            build_launch_recipe(&RecipeInputs::from_config(&cfg), "EpycGenoa", 1),
            Err(MinerAgentError::LaunchInput("guardian-recipe-invalid"))
        ));
    }

    #[test]
    fn route_validation_rejects_a_route_that_disagrees_with_its_recipe() {
        let dir = tempfile::tempdir().unwrap();
        let ep = "100.64.0.1:7443";
        let cfg = config_in(dir.path(), &m1(ep));
        let recipe = build_launch_recipe(&RecipeInputs::from_config(&cfg), "EpycGenoa", 1).unwrap();
        let good = GuardianRoute {
            endpoint: ep.into(),
            recipe: recipe.clone(),
        };
        good.validate().unwrap();
        let other = GuardianRoute {
            endpoint: "100.64.0.2:7443".into(),
            recipe: recipe.clone(),
        };
        assert!(other.validate().is_err());
        let mut m0 = recipe;
        m0.cmdline = "quiet".into();
        assert!(GuardianRoute {
            endpoint: ep.into(),
            recipe: m0
        }
        .validate()
        .is_err());
    }

    #[test]
    fn debug_never_prints_the_cmdline() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_in(dir.path(), &m1("100.64.0.1:7443"));
        let route = GuardianRoute {
            endpoint: "100.64.0.1:7443".into(),
            recipe: build_launch_recipe(&RecipeInputs::from_config(&cfg), "EpycGenoa", 1).unwrap(),
        };
        let dbg = format!("{route:?}");
        assert!(!dbg.contains("key_mode"), "{dbg}");
        assert!(dbg.contains("100.64.0.1:7443"));
    }
}
