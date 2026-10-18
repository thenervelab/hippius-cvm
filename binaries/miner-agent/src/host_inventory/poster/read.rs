//! Reading the collector's sections (`<dir>/<section>.json`): each file
//! bounded, parsed into its crate type (`deny_unknown_fields`), put in
//! its one valid order and checked on its own. A file that fails is
//! skipped and counted by class — never logged by content: sections
//! carry serials and by-id names.

use std::collections::BTreeMap;
use std::path::Path;

use hippius_host_inventory::{HostInventory, ReportKind, Sections, DOMAIN, SCHEMA_VERSION};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use super::plan::SECTIONS;

/// A section file is never read past this (the collector's pretty JSON
/// of the largest section — storage at its caps — is well under it).
pub const MAX_SECTION_FILE_BYTES: u64 = 1024 * 1024;

/// One read of the collector's directory.
#[derive(Debug, Clone, Default)]
pub struct ReadOutcome {
    /// The sections that parsed and validated.
    pub sections: Sections,
    /// Each section's digest: hex SHA-256 of its canonical CBOR.
    pub digests: BTreeMap<&'static str, String>,
    /// The sections skipped, and why (`too-large`, `unreadable`, `parse`,
    /// `invalid`).
    pub skipped: BTreeMap<&'static str, &'static str>,
}

fn read_capped(path: &Path) -> Result<Option<Vec<u8>>, &'static str> {
    use std::io::Read;
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("unreadable"),
    };
    let mut bytes = Vec::new();
    file.take(MAX_SECTION_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "unreadable")?;
    if bytes.len() as u64 > MAX_SECTION_FILE_BYTES {
        return Err("too-large");
    }
    Ok(Some(bytes))
}

fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, &'static str> {
    serde_json::from_slice(bytes).map_err(|_| "parse")
}

/// `sections` holding one section, normalized and validated alone; the
/// section back when it passes.
fn checked(sections: Sections) -> Result<Sections, &'static str> {
    let mut body = HostInventory {
        schema_version: SCHEMA_VERSION,
        domain: DOMAIN.to_string(),
        miner_id: "reader".to_string(),
        timestamp_unix: 0,
        sequence: 0,
        report: ReportKind::Change,
        sections,
    };
    body.normalize();
    body.validate().map_err(|_| "invalid")?;
    Ok(body.sections)
}

/// The hex SHA-256 of a value's canonical CBOR.
pub fn digest<T: serde::Serialize>(value: &T) -> Option<String> {
    let v = ciborium::value::Value::serialized(value).ok()?;
    let bytes = hippius_types::cbor::to_canonical_vec(&v).ok()?;
    Some(hex::encode(Sha256::digest(bytes)))
}

/// Read every section file of `dir`. A missing file is an absent section
/// (not counted).
pub fn read_sections(dir: &Path) -> ReadOutcome {
    let mut out = ReadOutcome::default();
    for name in SECTIONS {
        let bytes = match read_capped(&dir.join(format!("{name}.json"))) {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(class) => {
                out.skipped.insert(name, class);
                continue;
            }
        };
        let mut one = Sections::default();
        let parsed = match name {
            "system" => parse(&bytes).map(|s| one.system = Some(s)),
            "cpu" => parse(&bytes).map(|s| one.cpu = Some(s)),
            "memory" => parse(&bytes).map(|s| one.memory = Some(s)),
            "storage" => parse(&bytes).map(|s| one.storage = Some(s)),
            "network" => parse(&bytes).map(|s| one.network = Some(s)),
            "pci" => parse(&bytes).map(|s| one.pci = Some(s)),
            "sensors" => parse(&bytes).map(|s| one.sensors = Some(s)),
            _ => parse(&bytes).map(|s| one.software = Some(s)),
        };
        let one = match parsed.and_then(|()| checked(one)) {
            Ok(one) => one,
            Err(class) => {
                out.skipped.insert(name, class);
                continue;
            }
        };
        let s = &mut out.sections;
        let digest = match name {
            "system" => one
                .system
                .as_ref()
                .and_then(digest)
                .inspect(|_| s.system = one.system.clone()),
            "cpu" => one
                .cpu
                .as_ref()
                .and_then(digest)
                .inspect(|_| s.cpu = one.cpu.clone()),
            "memory" => one
                .memory
                .as_ref()
                .and_then(digest)
                .inspect(|_| s.memory = one.memory.clone()),
            "storage" => one
                .storage
                .as_ref()
                .and_then(digest)
                .inspect(|_| s.storage = one.storage.clone()),
            "network" => one
                .network
                .as_ref()
                .and_then(digest)
                .inspect(|_| s.network = one.network.clone()),
            "pci" => one
                .pci
                .as_ref()
                .and_then(digest)
                .inspect(|_| s.pci = one.pci.clone()),
            "sensors" => one
                .sensors
                .as_ref()
                .and_then(digest)
                .inspect(|_| s.sensors = one.sensors.clone()),
            _ => one
                .software
                .as_ref()
                .and_then(digest)
                .inspect(|_| s.software = one.software.clone()),
        };
        match digest {
            Some(d) => {
                out.digests.insert(name, d);
            }
            None => {
                out.skipped.insert(name, "invalid");
            }
        }
    }
    out
}

/// `sections` reduced to the names in `keep`.
pub fn select(sections: &Sections, keep: &std::collections::BTreeSet<&'static str>) -> Sections {
    let has = |n: &str| keep.contains(n);
    Sections {
        system: sections.system.clone().filter(|_| has("system")),
        cpu: sections.cpu.clone().filter(|_| has("cpu")),
        memory: sections.memory.clone().filter(|_| has("memory")),
        storage: sections.storage.clone().filter(|_| has("storage")),
        network: sections.network.clone().filter(|_| has("network")),
        pci: sections.pci.clone().filter(|_| has("pci")),
        sensors: sections.sensors.clone().filter(|_| has("sensors")),
        software: sections.software.clone().filter(|_| has("software")),
    }
}
