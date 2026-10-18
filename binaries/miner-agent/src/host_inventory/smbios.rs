//! A small, bounds-checked SMBIOS structure-table parser — the raw table
//! the kernel exports at `/sys/firmware/dmi/tables/DMI` — so the collector
//! needs no `dmidecode`. Only what the inventory reads: type 16 (Physical
//! Memory Array: the ECC type), type 17 (Memory Device: a DIMM), type 38
//! (IPMI Device Information).
//!
//! The table comes from firmware the miner controls. Every read is a
//! checked `get`: a truncated header, a length past the end or a string
//! set without its terminator ends the walk with what was parsed so far,
//! flagged `truncated` — never a panic, never an out-of-range index.

/// The walk stops after this many structures (a real table has a few
/// hundred).
pub const MAX_STRUCTURES: usize = 4096;

/// End-of-table.
const TYPE_END: u8 = 127;
pub const TYPE_MEMORY_ARRAY: u8 = 16;
pub const TYPE_MEMORY_DEVICE: u8 = 17;
pub const TYPE_IPMI_DEVICE: u8 = 38;

/// One structure: its formatted area (header included, so the offsets are
/// the spec's) and its strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Structure<'a> {
    pub kind: u8,
    pub handle: u16,
    formatted: &'a [u8],
    strings: Vec<&'a [u8]>,
}

impl<'a> Structure<'a> {
    pub fn byte(&self, offset: usize) -> Option<u8> {
        self.formatted.get(offset).copied()
    }

    pub fn word(&self, offset: usize) -> Option<u16> {
        let b = self.formatted.get(offset..offset.checked_add(2)?)?;
        Some(u16::from_le_bytes([*b.first()?, *b.get(1)?]))
    }

    pub fn dword(&self, offset: usize) -> Option<u32> {
        let b = self.formatted.get(offset..offset.checked_add(4)?)?;
        let mut le = [0u8; 4];
        le.copy_from_slice(b);
        Some(u32::from_le_bytes(le))
    }

    /// The string whose 1-based index is the byte at `offset`; `None` for
    /// index 0 ("no string") or one past the set.
    pub fn string(&self, offset: usize) -> Option<&'a [u8]> {
        let index = usize::from(self.byte(offset)?);
        self.strings.get(index.checked_sub(1)?).copied()
    }
}

/// The parsed table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Table<'a> {
    pub structures: Vec<Structure<'a>>,
    /// The walk stopped on a malformed structure (or the cap) before the
    /// end-of-table marker or the end of the data.
    pub truncated: bool,
}

impl<'a> Table<'a> {
    pub fn of_kind(&self, kind: u8) -> impl Iterator<Item = &Structure<'a>> {
        self.structures.iter().filter(move |s| s.kind == kind)
    }

    pub fn by_handle(&self, handle: u16) -> Option<&Structure<'a>> {
        self.structures.iter().find(|s| s.handle == handle)
    }
}

/// Walk `table`.
pub fn parse(table: &[u8]) -> Table<'_> {
    let mut out = Table::default();
    let mut pos = 0usize;
    while pos < table.len() {
        if out.structures.len() >= MAX_STRUCTURES {
            out.truncated = true;
            break;
        }
        let Some(header) = table.get(pos..pos.saturating_add(4)) else {
            out.truncated = true;
            break;
        };
        let (kind, length) = (header[0], usize::from(header[1]));
        let handle = u16::from_le_bytes([header[2], header[3]]);
        let Some(formatted) = (length >= 4)
            .then(|| table.get(pos..pos.saturating_add(length)))
            .flatten()
        else {
            out.truncated = true;
            break;
        };
        let (strings, next) = string_set(table, pos + length);
        out.structures.push(Structure {
            kind,
            handle,
            formatted,
            strings,
        });
        match next {
            Some(next) if kind != TYPE_END => pos = next,
            Some(_) => break,
            None => {
                out.truncated = true;
                break;
            }
        }
    }
    out
}

/// The strings starting at `start` and the offset past their double-NUL
/// terminator; `None` for the offset when the set runs off the end (the
/// strings read so far are kept).
fn string_set(table: &[u8], start: usize) -> (Vec<&[u8]>, Option<usize>) {
    let mut strings = Vec::new();
    // No strings: the set is just the two NULs.
    if table.get(start) == Some(&0) {
        let end = (table.get(start + 1) == Some(&0)).then_some(start + 2);
        return (strings, end);
    }
    let mut cur = start;
    loop {
        let Some(rest) = table.get(cur..) else {
            return (strings, None);
        };
        let Some(len) = rest.iter().position(|&b| b == 0) else {
            return (strings, None);
        };
        if let Some(s) = rest.get(..len) {
            strings.push(s);
        }
        cur += len + 1;
        match table.get(cur) {
            Some(0) => return (strings, Some(cur + 1)),
            Some(_) => {}
            None => return (strings, None),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One structure: `formatted` is the area after the 4-byte header.
    pub(crate) fn structure(kind: u8, handle: u16, formatted: &[u8], strings: &[&str]) -> Vec<u8> {
        let mut v = vec![kind, (formatted.len() + 4) as u8];
        v.extend_from_slice(&handle.to_le_bytes());
        v.extend_from_slice(formatted);
        if strings.is_empty() {
            v.extend_from_slice(&[0, 0]);
        } else {
            for s in strings {
                v.extend_from_slice(s.as_bytes());
                v.push(0);
            }
            v.push(0);
        }
        v
    }

    /// A type 17 (SMBIOS 3.3 length 0x5C) for array `array`, size word
    /// `size`, extended size `ext`, with its strings at 1..=5.
    pub(crate) fn memory_device(
        handle: u16,
        array: u16,
        size: u16,
        ext: u32,
        speed: u16,
    ) -> Vec<u8> {
        let mut f = vec![0u8; 0x5C - 4];
        let mut put = |off: usize, bytes: &[u8]| {
            f[off - 4..off - 4 + bytes.len()].copy_from_slice(bytes);
        };
        put(0x04, &array.to_le_bytes());
        put(0x0C, &size.to_le_bytes());
        put(0x10, &[1]); // Locator
        put(0x11, &[2]); // Bank Locator
        put(0x12, &[0x22]); // DDR5
        put(0x15, &speed.to_le_bytes());
        put(0x17, &[3]); // Manufacturer
        put(0x18, &[4]); // Serial
        put(0x1A, &[5]); // Part Number
        put(0x1C, &ext.to_le_bytes());
        put(0x20, &4800u16.to_le_bytes()); // Configured speed
        put(0x54, &5600u32.to_le_bytes()); // Extended speed
        structure(
            17,
            handle,
            &f,
            &[
                "DIMM 0",
                "P0 CHANNEL A",
                "Samsung",
                "S3R1AL01",
                "M321R8GA0BB0-CQK",
            ],
        )
    }

    /// Type 16 (multi-bit ECC) 0x1000, an installed 128 GiB DIMM (Extended
    /// Size, speed via Extended Speed), an empty slot, type 38 (IPMI 2.0),
    /// end-of-table.
    pub(crate) fn sample_table() -> Vec<u8> {
        let mut t = Vec::new();
        let mut array = vec![0u8; 0x17 - 4];
        array[0x05 - 4] = 3; // Use: system memory
        array[0x06 - 4] = 6; // Multi-bit ECC
        t.extend(structure(16, 0x1000, &array, &[]));
        t.extend(memory_device(0x1100, 0x1000, 0x7FFF, 131_072, 0xFFFF));
        let mut empty = memory_device(0x1101, 0x1000, 0, 0, 0);
        // A distinct locator string for the empty slot.
        let at = empty.windows(6).position(|w| w == b"DIMM 0").unwrap();
        empty[at + 5] = b'1';
        t.extend(empty);
        let mut ipmi = vec![0u8; 0x12 - 4];
        ipmi[0] = 1; // 0x04: interface type, KCS
        ipmi[0x05 - 4] = 0x20; // spec revision 2.0
        t.extend(structure(38, 0x2600, &ipmi, &[]));
        t.extend(structure(127, 0xFFFF, &[], &[]));
        t
    }

    #[test]
    fn parses_a_table() {
        let bytes = sample_table();
        let t = parse(&bytes);
        assert!(!t.truncated);
        let kinds: Vec<u8> = t.structures.iter().map(|s| s.kind).collect();
        assert_eq!(kinds, [16, 17, 17, 38, 127]);
        let dimm = t.of_kind(17).next().unwrap();
        assert_eq!(dimm.word(0x04), Some(0x1000));
        assert_eq!(dimm.string(0x10), Some(&b"DIMM 0"[..]));
        assert_eq!(dimm.string(0x1A), Some(&b"M321R8GA0BB0-CQK"[..]));
        assert_eq!(dimm.dword(0x1C), Some(131_072));
        // Past the formatted area, and string index 0 / past the set.
        assert_eq!(dimm.byte(0x5C), None);
        assert_eq!(dimm.dword(0x5A), None);
        assert_eq!(dimm.string(0x13), None);
        assert_eq!(t.by_handle(0x1000).unwrap().byte(0x06), Some(6));
    }

    #[test]
    fn malformed_tables_never_panic() {
        let good = sample_table();
        // Every prefix of a real table: a truncated header, a length past
        // the end, a string set cut before its terminator.
        for n in 0..good.len() {
            let t = parse(&good[..n]);
            assert!(t.structures.len() <= 5, "prefix {n}");
        }
        // A length below the header.
        let t = parse(&[17, 2, 0, 0, 0, 0]);
        assert!(t.truncated && t.structures.is_empty());
        // A length past the end.
        let t = parse(&[17, 0xFF, 0, 0, 1, 2, 3]);
        assert!(t.truncated && t.structures.is_empty());
        // A string set with no terminator: the structure is kept with what
        // was read.
        let mut no_term = structure(17, 1, &[0u8; 0x5C - 4], &[]);
        no_term.truncate(no_term.len() - 2);
        no_term.extend_from_slice(b"DIMM 0");
        let t = parse(&no_term);
        assert!(t.truncated);
        assert_eq!(t.structures.len(), 1);
        assert!(t.structures[0].strings.is_empty());
        // A single NUL after the formatted area.
        let mut one_nul = structure(16, 1, &[0u8; 0x13], &[]);
        one_nul.pop();
        assert!(parse(&one_nul).truncated);
        // Garbage of every length.
        let noise: Vec<u8> = (0..2048u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        for n in (0..noise.len()).step_by(7) {
            let _ = parse(&noise[..n]);
        }
    }

    #[test]
    fn the_walk_is_capped() {
        let one = structure(1, 0, &[], &[]);
        let many: Vec<u8> = one.repeat(MAX_STRUCTURES + 10);
        let t = parse(&many);
        assert_eq!(t.structures.len(), MAX_STRUCTURES);
        assert!(t.truncated);
    }
}
