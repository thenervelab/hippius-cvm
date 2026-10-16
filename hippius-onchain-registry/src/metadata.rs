//! A minimal walker over runtime metadata v14 / v15 — just far enough to
//! list one pallet's storage entries.
//!
//! An authorization read ([`crate::fetch_node_family`]) must not trust a
//! fossil: a pallet or map removed by a runtime upgrade keeps answering
//! raw storage reads with its last-written bytes. A byte search for the
//! names is not proof (a name can survive in another pallet or a type
//! path), so this decodes the metadata structurally: skip the type
//! registry, then find the pallet by name and read its storage section.
//!
//! Layout (SCALE, `frame-metadata` v14/v15 with `scale-info` portable
//! types):
//!
//! ```text
//! "meta" ++ version:u8 ++ RuntimeMetadataV14|V15 {
//!   types: Vec<{ id: Compact<u32>, ty: { path: Vec<String>,
//!          type_params: Vec<{ name: String, ty: Option<Compact<u32>> }>,
//!          type_def: TypeDef, docs: Vec<String> } }>,
//!   pallets: Vec<{ name: String,
//!          storage: Option<{ prefix: String, entries: Vec<{ name: String,
//!                   modifier: u8, ty: Plain(Compact) | Map{ hashers: Vec<u8>,
//!                   key: Compact, value: Compact }, default: Vec<u8>,
//!                   docs: Vec<String> }> }>,
//!          calls: Option<Compact>, event: Option<Compact>,
//!          constants: Vec<{ name: String, ty: Compact, value: Vec<u8>,
//!                           docs: Vec<String> }>,
//!          error: Option<Compact>, index: u8,
//!          docs: Vec<String>  /* v15 only */ }>,
//!   … (not read) }
//! ```
//!
//! Every malformed or truncated input is an error (fail closed); nothing
//! is allocated from a declared length.

use codec::{Compact, Decode};

use crate::{category, RegistryError};

/// `StorageHasher::Blake2_128Concat`'s index.
pub const BLAKE2_128_CONCAT: u8 = 2;

/// One storage entry of a pallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageEntry {
    pub name: String,
    /// `Some(hashers)` for a map, `None` for a plain value.
    pub map_hashers: Option<Vec<u8>>,
}

/// A pallet's storage section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PalletStorage {
    pub prefix: String,
    pub entries: Vec<StorageEntry>,
}

fn malformed(what: &str) -> RegistryError {
    RegistryError::new(
        category::METADATA_SHAPE,
        format!("metadata is malformed: {what}"),
    )
}

struct Cursor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Result<u8, RegistryError> {
        let (&first, rest) = self.bytes.split_first().ok_or_else(|| malformed("eof"))?;
        self.bytes = rest;
        Ok(first)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], RegistryError> {
        if n > self.bytes.len() {
            return Err(malformed("eof"));
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(head)
    }

    fn compact(&mut self) -> Result<u32, RegistryError> {
        Compact::<u32>::decode(&mut self.bytes)
            .map(|c| c.0)
            .map_err(|_| malformed("compact"))
    }

    fn len(&mut self) -> Result<usize, RegistryError> {
        let n = self.compact()? as usize;
        // Every element takes at least one byte: a length beyond what is
        // left is a lie, not a reason to loop.
        if n > self.bytes.len() {
            return Err(malformed("length beyond input"));
        }
        Ok(n)
    }

    fn bytes_vec(&mut self) -> Result<&'a [u8], RegistryError> {
        let n = self.len()?;
        self.take(n)
    }

    fn string(&mut self) -> Result<&'a [u8], RegistryError> {
        self.bytes_vec()
    }

    fn option(&mut self) -> Result<bool, RegistryError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(malformed("option tag")),
        }
    }

    fn strings(&mut self) -> Result<(), RegistryError> {
        for _ in 0..self.len()? {
            self.string()?;
        }
        Ok(())
    }

    fn option_compact(&mut self) -> Result<(), RegistryError> {
        if self.option()? {
            self.compact()?;
        }
        Ok(())
    }

    fn field(&mut self) -> Result<(), RegistryError> {
        if self.option()? {
            self.string()?; // name
        }
        self.compact()?; // ty
        if self.option()? {
            self.string()?; // type_name
        }
        self.strings() // docs
    }

    fn fields(&mut self) -> Result<(), RegistryError> {
        for _ in 0..self.len()? {
            self.field()?;
        }
        Ok(())
    }

    fn type_def(&mut self) -> Result<(), RegistryError> {
        match self.u8()? {
            0 => self.fields(),
            1 => {
                for _ in 0..self.len()? {
                    self.string()?; // name
                    self.fields()?;
                    self.u8()?; // index
                    self.strings()?; // docs
                }
                Ok(())
            }
            2 | 6 => self.compact().map(|_| ()),
            3 => {
                self.take(4)?; // len: u32
                self.compact().map(|_| ())
            }
            4 => {
                for _ in 0..self.len()? {
                    self.compact()?;
                }
                Ok(())
            }
            5 => self.u8().map(|_| ()),
            7 => {
                self.compact()?;
                self.compact().map(|_| ())
            }
            _ => Err(malformed("type_def tag")),
        }
    }

    fn types(&mut self) -> Result<(), RegistryError> {
        for _ in 0..self.len()? {
            self.compact()?; // id
            self.strings()?; // path
            for _ in 0..self.len()? {
                self.string()?; // param name
                self.option_compact()?; // param ty
            }
            self.type_def()?;
            self.strings()?; // docs
        }
        Ok(())
    }

    fn storage(&mut self) -> Result<PalletStorage, RegistryError> {
        let prefix = utf8(self.string()?)?;
        let mut entries = Vec::new();
        for _ in 0..self.len()? {
            let name = utf8(self.string()?)?;
            self.u8()?; // modifier
            let map_hashers = match self.u8()? {
                0 => {
                    self.compact()?;
                    None
                }
                1 => {
                    let hashers = self.bytes_vec()?.to_vec();
                    self.compact()?; // key
                    self.compact()?; // value
                    Some(hashers)
                }
                _ => return Err(malformed("storage entry type tag")),
            };
            self.bytes_vec()?; // default
            self.strings()?; // docs
            entries.push(StorageEntry { name, map_hashers });
        }
        Ok(PalletStorage { prefix, entries })
    }
}

fn utf8(bytes: &[u8]) -> Result<String, RegistryError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| malformed("non-UTF-8 name"))
}

/// The storage section of `pallet` in `metadata` (v14 / v15): `Ok(None)`
/// when the runtime has no such pallet or it has no storage.
pub fn pallet_storage(
    metadata: &[u8],
    pallet: &str,
) -> Result<Option<PalletStorage>, RegistryError> {
    let mut cur = Cursor { bytes: metadata };
    if cur.take(4)? != b"meta" {
        return Err(RegistryError::new(
            category::METADATA_SHAPE,
            "metadata does not start with the 'meta' magic".to_string(),
        ));
    }
    let version = cur.u8()?;
    if version != 14 && version != 15 {
        return Err(RegistryError::new(
            category::METADATA_SHAPE,
            format!("unsupported metadata version {version}"),
        ));
    }
    cur.types()?;
    let mut found = None;
    for _ in 0..cur.len()? {
        let name = cur.string()?;
        let storage = if cur.option()? {
            Some(cur.storage()?)
        } else {
            None
        };
        cur.option_compact()?; // calls
        cur.option_compact()?; // event
        for _ in 0..cur.len()? {
            cur.string()?; // name
            cur.compact()?; // ty
            cur.bytes_vec()?; // value
            cur.strings()?; // docs
        }
        cur.option_compact()?; // error
        cur.u8()?; // index
        if version == 15 {
            cur.strings()?; // docs
        }
        if name == pallet.as_bytes() {
            if found.is_some() {
                return Err(malformed("pallet listed twice"));
            }
            found = Some(storage);
        }
    }
    Ok(found.flatten())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use super::*;
    use codec::Encode;

    fn s(text: &str) -> Vec<u8> {
        text.encode()
    }

    fn c(n: u32) -> Vec<u8> {
        Compact(n).encode()
    }

    fn vec_of(items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = c(items.len() as u32);
        for item in items {
            out.extend_from_slice(item);
        }
        out
    }

    fn docs(lines: &[&str]) -> Vec<u8> {
        vec_of(&lines.iter().map(|l| s(l)).collect::<Vec<_>>())
    }

    fn field(name: Option<&str>, ty: u32) -> Vec<u8> {
        let mut out = match name {
            Some(n) => [vec![1], s(n)].concat(),
            None => vec![0],
        };
        out.extend(c(ty));
        out.extend([vec![1], s("u32")].concat());
        out.extend(docs(&["a field"]));
        out
    }

    /// A type registry exercising every `TypeDef` variant.
    fn registry() -> Vec<u8> {
        let ty = |id: u32, path: &[&str], def: Vec<u8>| {
            let mut out = c(id);
            out.extend(docs(path));
            // one type param with a type, one without
            out.extend(vec_of(&[
                [s("T"), vec![1], c(0)].concat(),
                [s("U"), vec![0]].concat(),
            ]));
            out.extend(def);
            out.extend(docs(&["type docs mention NodeIdToChild"]));
            out
        };
        vec_of(&[
            ty(0, &["u32"], vec![5, 4]),
            ty(
                1,
                &["NodeIdToChild"],
                [vec![0], vec_of(&[field(Some("a"), 0), field(None, 0)])].concat(),
            ),
            ty(
                2,
                &["Enum"],
                [
                    vec![1],
                    vec_of(&[[
                        s("ChildRegistrations"),
                        vec_of(&[field(None, 0)]),
                        vec![3],
                        docs(&[]),
                    ]
                    .concat()]),
                ]
                .concat(),
            ),
            ty(3, &[], [vec![2], c(0)].concat()),
            ty(
                4,
                &[],
                [vec![3], 32u32.to_le_bytes().to_vec(), c(0)].concat(),
            ),
            ty(5, &[], [vec![4], vec_of(&[c(0), c(1)])].concat()),
            ty(6, &[], [vec![6], c(0)].concat()),
            ty(7, &[], [vec![7], c(0), c(1)].concat()),
        ])
    }

    fn entry(name: &str, hashers: Option<&[u8]>) -> Vec<u8> {
        let mut out = s(name);
        out.push(0); // modifier
        match hashers {
            None => out.extend([vec![0], c(0)].concat()),
            Some(h) => out.extend([vec![1], h.to_vec().encode(), c(0), c(1)].concat()),
        }
        out.extend(vec![1u8, 2, 3].encode()); // default
        out.extend(docs(&["entry docs"]));
        out
    }

    fn pallet(version: u8, name: &str, storage: Option<(&str, Vec<Vec<u8>>)>) -> Vec<u8> {
        let mut out = s(name);
        match storage {
            None => out.push(0),
            Some((prefix, entries)) => {
                out.push(1);
                out.extend(s(prefix));
                out.extend(vec_of(&entries));
            }
        }
        out.extend([vec![1], c(1)].concat()); // calls
        out.push(0); // event
        out.extend(vec_of(&[
            [s("Max"), c(0), vec![4u8].encode(), docs(&[])].concat()
        ]));
        out.extend([vec![1], c(2)].concat()); // error
        out.push(7); // index
        if version == 15 {
            out.extend(docs(&["pallet docs"]));
        }
        out
    }

    /// `meta ++ version ++ types ++ pallets ++ trailing`.
    pub(crate) fn metadata(version: u8, pallets: &[Vec<u8>]) -> Vec<u8> {
        let mut out = b"meta".to_vec();
        out.push(version);
        out.extend(registry());
        out.extend(vec_of(pallets));
        out.extend([0u8, 1, 2, 3]); // extrinsic … (never read)
        out
    }

    /// A runtime with `ComputeScoring` holding both maps (Blake2_128Concat).
    pub(crate) fn live(version: u8) -> Vec<u8> {
        metadata(
            version,
            &[
                pallet(
                    version,
                    "System",
                    Some(("System", vec![entry("Number", None)])),
                ),
                pallet(
                    version,
                    "ComputeScoring",
                    Some((
                        "ComputeScoring",
                        vec![
                            entry("CurrentEpoch", None),
                            entry("ChildRegistrations", Some(&[BLAKE2_128_CONCAT])),
                            entry("NodeIdToChild", Some(&[BLAKE2_128_CONCAT])),
                        ],
                    )),
                ),
                pallet(version, "Balances", None),
            ],
        )
    }

    /// Runtimes where the family read must refuse: pallet gone, a map
    /// gone (its name still elsewhere), a map re-hashed, another prefix.
    pub(crate) fn fossils() -> Vec<(&'static str, Vec<u8>)> {
        let with = |prefix: &str, entries: Vec<Vec<u8>>| {
            metadata(
                14,
                &[
                    pallet(
                        14,
                        "Other",
                        Some((
                            "Other",
                            vec![
                                entry("NodeIdToChild", Some(&[BLAKE2_128_CONCAT])),
                                entry("ChildRegistrations", Some(&[BLAKE2_128_CONCAT])),
                            ],
                        )),
                    ),
                    pallet(14, "ComputeScoring", Some((prefix, entries))),
                ],
            )
        };
        let both = || {
            vec![
                entry("ChildRegistrations", Some(&[BLAKE2_128_CONCAT])),
                entry("NodeIdToChild", Some(&[BLAKE2_128_CONCAT])),
            ]
        };
        vec![
            (
                "pallet removed",
                metadata(14, &[pallet(14, "System", None)]),
            ),
            (
                "pallet without storage",
                metadata(14, &[pallet(14, "ComputeScoring", None)]),
            ),
            (
                "NodeIdToChild removed",
                with(
                    "ComputeScoring",
                    vec![entry("ChildRegistrations", Some(&[BLAKE2_128_CONCAT]))],
                ),
            ),
            (
                "ChildRegistrations removed",
                with(
                    "ComputeScoring",
                    vec![entry("NodeIdToChild", Some(&[BLAKE2_128_CONCAT]))],
                ),
            ),
            (
                "re-hashed",
                with(
                    "ComputeScoring",
                    vec![
                        entry("ChildRegistrations", Some(&[5])),
                        entry("NodeIdToChild", Some(&[BLAKE2_128_CONCAT])),
                    ],
                ),
            ),
            (
                "plain value",
                with(
                    "ComputeScoring",
                    vec![
                        entry("ChildRegistrations", None),
                        entry("NodeIdToChild", Some(&[BLAKE2_128_CONCAT])),
                    ],
                ),
            ),
            ("other prefix", with("Scoring", both())),
        ]
    }

    #[test]
    fn finds_the_pallets_storage_in_v14_and_v15() {
        for version in [14, 15] {
            let storage = pallet_storage(&live(version), "ComputeScoring")
                .unwrap()
                .unwrap();
            assert_eq!(storage.prefix, "ComputeScoring");
            let names: Vec<_> = storage.entries.iter().map(|e| e.name.as_str()).collect();
            assert_eq!(
                names,
                ["CurrentEpoch", "ChildRegistrations", "NodeIdToChild"]
            );
            assert_eq!(storage.entries[0].map_hashers, None);
            assert_eq!(
                storage.entries[2].map_hashers,
                Some(vec![BLAKE2_128_CONCAT])
            );
            assert_eq!(pallet_storage(&live(version), "Balances").unwrap(), None);
            assert_eq!(pallet_storage(&live(version), "Nope").unwrap(), None);
        }
    }

    #[test]
    fn a_name_elsewhere_is_not_the_pallets_entry() {
        // The map names survive in a type path, a variant and another
        // pallet; `ComputeScoring` itself no longer has them.
        let meta = metadata(
            14,
            &[
                pallet(
                    14,
                    "Other",
                    Some(("Other", vec![entry("NodeIdToChild", Some(&[2]))])),
                ),
                pallet(
                    14,
                    "ComputeScoring",
                    Some(("ComputeScoring", vec![entry("CurrentEpoch", None)])),
                ),
            ],
        );
        let storage = pallet_storage(&meta, "ComputeScoring").unwrap().unwrap();
        assert_eq!(storage.entries.len(), 1);
    }

    #[test]
    fn malformed_metadata_fails() {
        let good = live(14);
        // The trailing 4 bytes (past the pallets) are never read.
        for cut in [3, 5, 40, good.len() / 2, good.len() - 5] {
            assert!(
                pallet_storage(&good[..cut], "ComputeScoring").is_err(),
                "cut at {cut}"
            );
        }
        let mut bad_version = good.clone();
        bad_version[4] = 13;
        assert!(pallet_storage(&bad_version, "ComputeScoring").is_err());
        let mut bad_magic = good;
        bad_magic[0] = b'x';
        assert!(pallet_storage(&bad_magic, "ComputeScoring").is_err());
        let twice = metadata(
            14,
            &[
                pallet(14, "ComputeScoring", None),
                pallet(14, "ComputeScoring", None),
            ],
        );
        assert!(pallet_storage(&twice, "ComputeScoring").is_err());
    }
}
