//! The `cpu` section: `/proc/cpuinfo` (model, family / model / stepping,
//! microcode, topology, flags), `smt/{control,active}`, cpu0's cpufreq
//! limits and the `kvm_amd` SEV parameters.
//!
//! The SNP firmware / TCB is NOT read here: vali has it attested (the
//! host attestor, the host beacon).

use std::collections::BTreeSet;

use hippius_host_inventory::{
    CpuFlag, CpuSection, SmtControl, MAX_CPU_FLAGS, MAX_NAME_LEN, MAX_TEXT_LEN,
};

use super::{clean_text, HostPaths, Source, Tally};

/// The cpuinfo flag each allowlisted [`CpuFlag`] is spelled as.
const FLAGS: [(&str, CpuFlag); 8] = [
    ("sev", CpuFlag::Sev),
    ("sev_es", CpuFlag::SevEs),
    ("sev_snp", CpuFlag::SevSnp),
    ("avx2", CpuFlag::Avx2),
    ("avx512f", CpuFlag::Avx512f),
    ("aes", CpuFlag::Aes),
    ("sha_ni", CpuFlag::Sha),
    ("vaes", CpuFlag::Vaes),
];

/// One `processor` block of `/proc/cpuinfo`, `key: value` pairs.
type Block<'a> = Vec<(&'a str, &'a str)>;

fn blocks(cpuinfo: &str) -> Vec<Block<'_>> {
    cpuinfo
        .split("\n\n")
        .map(|b| {
            b.lines()
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim(), v.trim()))
                .collect::<Block<'_>>()
        })
        .filter(|b| b.iter().any(|(k, _)| *k == "processor"))
        .collect()
}

fn get<'a>(block: &Block<'a>, key: &str) -> Option<&'a str> {
    block.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

fn number(block: &Block<'_>, key: &str) -> Option<u32> {
    get(block, key)?.parse().ok()
}

/// Sockets, cores, threads. Sockets: distinct `physical id` (1 when the
/// kernel prints none). Cores: the sum of each socket's `cpu cores`, else
/// distinct `(physical id, core id)` pairs, else the threads. Threads: the
/// processor entries.
fn topology(blocks: &[Block<'_>]) -> (u32, u32, u32) {
    let threads = u32::try_from(blocks.len()).unwrap_or(u32::MAX);
    let mut per_socket: std::collections::BTreeMap<&str, Option<u32>> = Default::default();
    let mut core_pairs = BTreeSet::new();
    for b in blocks {
        let socket = get(b, "physical id").unwrap_or("0");
        per_socket
            .entry(socket)
            .or_insert_with(|| number(b, "cpu cores"));
        if let Some(core) = get(b, "core id") {
            core_pairs.insert((socket, core));
        }
    }
    let sockets = u32::try_from(per_socket.len().max(1)).unwrap_or(u32::MAX);
    let declared: Option<u32> = per_socket
        .values()
        .try_fold(0u32, |sum, c| c.map(|c| sum.saturating_add(c)));
    let cores = match declared {
        Some(c) if c > 0 => c,
        _ if !core_pairs.is_empty() => u32::try_from(core_pairs.len()).unwrap_or(u32::MAX),
        _ => threads,
    };
    (sockets, cores, threads)
}

fn smt_control(s: &str) -> Option<SmtControl> {
    Some(match s {
        "on" => SmtControl::On,
        "off" => SmtControl::Off,
        "forceoff" => SmtControl::Forceoff,
        "notsupported" => SmtControl::Notsupported,
        "notimplemented" => SmtControl::Notimplemented,
        _ => return None,
    })
}

/// A cpufreq kHz reading in MHz.
fn mhz(khz: Option<String>) -> Option<u32> {
    khz?.parse::<u64>()
        .ok()
        .and_then(|k| u32::try_from(k / 1000).ok())
        .filter(|&m| m > 0)
}

/// A module parameter `Y` / `1`.
fn enabled(s: Option<String>) -> bool {
    matches!(s.as_deref(), Some("Y" | "y" | "1"))
}

pub fn collect_cpu(paths: &HostPaths) -> CpuSection {
    let mut tally = Tally::default();
    let cpuinfo = tally
        .required(Source::read(&paths.proc.join("cpuinfo")))
        .unwrap_or_default();
    let blocks = blocks(&cpuinfo);
    let first = blocks.first().cloned().unwrap_or_default();
    let (sockets, cores, threads) = if blocks.is_empty() {
        (0, 0, 0)
    } else {
        topology(&blocks)
    };
    let cpu = paths.sys.join("devices/system/cpu");
    let mut optional = |rel: &str| tally.optional(Source::read(&cpu.join(rel)));
    let smt = optional("smt/control").as_deref().and_then(smt_control);
    let smt_active = optional("smt/active").as_deref() == Some("1");
    let base_mhz = mhz(optional("cpu0/cpufreq/base_frequency"));
    let max_mhz = mhz(optional("cpu0/cpufreq/cpuinfo_max_freq"));
    let kvm = paths.sys.join("module/kvm_amd/parameters");
    let mut param = |name: &str| enabled(tally.optional(Source::read(&kvm.join(name))));
    let (sev, sev_es, sev_snp) = (param("sev"), param("sev_es"), param("sev_snp"));

    let present: BTreeSet<&str> = get(&first, "flags")
        .map(|f| f.split_ascii_whitespace().collect())
        .unwrap_or_default();
    let mut flags: Vec<CpuFlag> = FLAGS
        .iter()
        .filter(|(name, _)| present.contains(name))
        .map(|(_, f)| *f)
        .collect();
    flags.sort();
    flags.truncate(MAX_CPU_FLAGS);
    // cpuinfo that holds no processor entry is as good as none.
    let status = if blocks.is_empty() {
        hippius_host_inventory::SectionStatus::Unavailable
    } else {
        tally.status()
    };
    CpuSection {
        status,
        model: get(&first, "model name").and_then(|s| clean_text(s.as_bytes(), MAX_TEXT_LEN)),
        family: number(&first, "cpu family").unwrap_or(0),
        model_id: number(&first, "model").unwrap_or(0),
        stepping: number(&first, "stepping").unwrap_or(0),
        sockets,
        cores,
        threads,
        smt_control: smt,
        smt_active,
        base_mhz,
        max_mhz,
        microcode: get(&first, "microcode").and_then(|s| clean_text(s.as_bytes(), MAX_NAME_LEN)),
        sev,
        sev_es,
        sev_snp,
        flags,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::fixture::Host;
    use super::*;
    use hippius_host_inventory::SectionStatus;

    fn processor(n: u32, socket: u32, core: u32, cores: u32) -> String {
        format!(
            "processor\t: {n}\nvendor_id\t: AuthenticAMD\ncpu family\t: 25\nmodel\t\t: 17\n\
             model name\t: AMD EPYC 9254 24-Core Processor\nstepping\t: 1\n\
             microcode\t: 0xa101148\ncpu MHz\t\t: 2900.000\nphysical id\t: {socket}\n\
             siblings\t: {cores}\ncore id\t\t: {core}\ncpu cores\t: {cores}\n\
             flags\t\t: fpu vme sse2 aes avx2 sha_ni avx512f vaes sev sev_es sev_snp \
             avx512_bf16 svm\n\n"
        )
    }

    /// A Genoa-like host: 2 processors on one socket, SMT off, SNP on.
    pub(crate) fn genoa(h: &Host) {
        h.write(
            "proc/cpuinfo",
            format!("{}{}", processor(0, 0, 0, 2), processor(1, 0, 1, 2)),
        );
        h.write("sys/devices/system/cpu/smt/control", "off\n");
        h.write("sys/devices/system/cpu/smt/active", "0\n");
        h.write(
            "sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq",
            "4150000\n",
        );
        for (p, v) in [("sev", "Y"), ("sev_es", "Y"), ("sev_snp", "Y")] {
            h.write(
                &format!("sys/module/kvm_amd/parameters/{p}"),
                format!("{v}\n"),
            );
        }
    }

    #[test]
    fn reads_a_genoa_host() {
        let h = Host::new();
        genoa(&h);
        let c = collect_cpu(&h.paths());
        assert_eq!(c.status, SectionStatus::Ok);
        assert_eq!(c.model.as_deref(), Some("AMD EPYC 9254 24-Core Processor"));
        assert_eq!((c.family, c.model_id, c.stepping), (25, 17, 1));
        assert_eq!(c.microcode.as_deref(), Some("0xa101148"));
        assert_eq!((c.sockets, c.cores, c.threads), (1, 2, 2));
        assert_eq!(c.smt_control, Some(SmtControl::Off));
        assert!(!c.smt_active);
        assert_eq!(c.base_mhz, None, "no base_frequency");
        assert_eq!(c.max_mhz, Some(4150));
        assert!(c.sev && c.sev_es && c.sev_snp);
        assert_eq!(
            c.flags,
            [
                CpuFlag::Sev,
                CpuFlag::SevEs,
                CpuFlag::SevSnp,
                CpuFlag::Avx2,
                CpuFlag::Avx512f,
                CpuFlag::Aes,
                CpuFlag::Sha,
                CpuFlag::Vaes
            ]
        );
    }

    #[test]
    fn counts_a_dual_socket_host() {
        let h = Host::new();
        let mut info = String::new();
        let mut n = 0;
        for socket in 0..2 {
            for core in 0..4 {
                // SMT on: two threads per core.
                for _ in 0..2 {
                    info.push_str(&processor(n, socket, core, 4));
                    n += 1;
                }
            }
        }
        h.write("proc/cpuinfo", info);
        h.write("sys/devices/system/cpu/smt/control", "on\n");
        h.write("sys/devices/system/cpu/smt/active", "1\n");
        h.write(
            "sys/devices/system/cpu/cpu0/cpufreq/base_frequency",
            "2900000\n",
        );
        h.write("sys/module/kvm_amd/parameters/sev_snp", "N\n");
        let c = collect_cpu(&h.paths());
        assert_eq!((c.sockets, c.cores, c.threads), (2, 8, 16));
        assert_eq!(c.smt_control, Some(SmtControl::On));
        assert!(c.smt_active);
        assert_eq!(c.base_mhz, Some(2900));
        assert!(!c.sev_snp && !c.sev);
    }

    #[test]
    fn falls_back_to_core_pairs_without_cpu_cores() {
        let info = "processor : 0\nphysical id : 0\ncore id : 0\n\n\
                    processor : 1\nphysical id : 0\ncore id : 0\n\n\
                    processor : 2\nphysical id : 0\ncore id : 1\n\n";
        assert_eq!(topology(&blocks(info)), (1, 2, 3));
        // No topology at all (some VMs): one socket, a core per thread.
        assert_eq!(
            topology(&blocks("processor : 0\n\nprocessor : 1\n")),
            (1, 2, 2)
        );
    }

    #[test]
    fn no_cpuinfo_is_unavailable() {
        let h = Host::new();
        let c = collect_cpu(&h.paths());
        assert_eq!(c.status, SectionStatus::Unavailable);
        assert_eq!((c.sockets, c.cores, c.threads), (0, 0, 0));
        assert!(c.flags.is_empty());
        h.write("proc/cpuinfo", "garbage\n");
        assert_eq!(collect_cpu(&h.paths()).status, SectionStatus::Unavailable);
    }
}
