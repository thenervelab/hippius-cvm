//! Apply an incremental backup (a backing-less qcow2) onto a raw base —
//! the restore's replacement for `qemu-img rebase -u` + `commit`.
//!
//! The incremental comes from the SOURCE miner, which is untrusted, so it
//! never reaches `qemu-img`: its whole attack surface (L1/L2/refcount
//! tables, snapshots, extensions, compression, external data files) would
//! otherwise be parsed by a C program running with the agent's host
//! privileges. This reader accepts only what `blockdev-backup` into a
//! freshly created qcow2 produces — v3, 64 KiB clusters, no backing, no
//! encryption, no incompatible feature, standard (non-extended) L2
//! entries, no compressed clusters — and walks only the active L1/L2
//! tables, bounds-checking every offset against the file. No two L1
//! entries may share an L2 table and no two L2 entries may share a data
//! cluster (QEMU never produces either), so the work is bounded by one
//! write per guest cluster — the same as a genuine incremental that
//! rewrote the whole disk — whatever the image claims. A cluster is
//! either absent (skip), a zero cluster (write zeroes), or data (copy).
//! Refcounts, snapshots and extensions are never read: nothing here needs
//! them, and ignoring them removes them from the attack surface.

use std::os::unix::fs::FileExt;
use std::path::Path;

use crate::error::{MinerAgentError, Result};

/// qcow2 magic, `QFI\xfb`.
const MAGIC: [u8; 4] = [b'Q', b'F', b'I', 0xfb];

/// The only cluster size accepted — QEMU's default, what `qemu-img
/// create` gives the backup target.
const CLUSTER_BITS: u32 = 16;
const CLUSTER_SIZE: u64 = 1 << CLUSTER_BITS;

/// Entries per L2 table (8-byte entries in one cluster).
const L2_ENTRIES: u64 = CLUSTER_SIZE / 8;

/// Host-offset field of an L1 / standard L2 entry (bits 9..=55).
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;

/// L2 entry: compressed cluster.
const L2_COMPRESSED: u64 = 1 << 62;
/// L2 entry: reads as zeroes (v3).
const L2_ZERO: u64 = 1;
/// L1 / L2 "copied" flag (refcount == 1) — informational.
const COPIED: u64 = 1 << 63;

/// The header fields the applier uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Virtual size.
    pub size: u64,
    /// Active L1 table: entries.
    pub l1_size: u64,
    /// Active L1 table: file offset.
    pub l1_offset: u64,
}

/// Parse + validate the header (first 104 bytes are enough).
pub fn parse_header(h: &[u8], expected_size: u64) -> Result<Header> {
    let be32 = |o: usize| -> Result<u32> {
        h.get(o..o + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or(MinerAgentError::Backup("inc-not-qcow2"))
    };
    let be64 = |o: usize| -> Result<u64> {
        h.get(o..o + 8)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(MinerAgentError::Backup("inc-not-qcow2"))
    };
    if h.get(0..4) != Some(&MAGIC[..]) || be32(4)? != 3 {
        return Err(MinerAgentError::Backup("inc-not-qcow2"));
    }
    // backing_file_offset, crypt_method, incompatible_features (bit 2 is
    // the external data file; nothing here produces any of them).
    if be64(8)? != 0 || be32(32)? != 0 || be64(72)? != 0 {
        return Err(MinerAgentError::Backup("inc-external-ref"));
    }
    if be32(20)? != CLUSTER_BITS {
        return Err(MinerAgentError::Backup("inc-cluster-size"));
    }
    let size = be64(24)?;
    if size != expected_size {
        return Err(MinerAgentError::Backup("inc-size-mismatch"));
    }
    Ok(Header {
        size,
        l1_size: u64::from(be32(36)?),
        l1_offset: be64(40)?,
    })
}

/// Apply the incremental at `inc` onto the raw `base` (whose length must
/// be `expected_size`). Blocking — run it on a blocking thread.
pub fn apply(inc: &Path, base: &Path, expected_size: u64) -> Result<()> {
    let inc = std::fs::File::open(inc).map_err(|_| MinerAgentError::Backup("inc-read"))?;
    let inc_len = inc
        .metadata()
        .map_err(|_| MinerAgentError::Backup("inc-read"))?
        .len();
    let base = std::fs::OpenOptions::new()
        .write(true)
        .open(base)
        .map_err(|_| MinerAgentError::Backup("base-open"))?;
    let base_len = base
        .metadata()
        .map_err(|_| MinerAgentError::Backup("base-open"))?
        .len();
    if base_len != expected_size {
        return Err(MinerAgentError::Backup("full-size-mismatch"));
    }

    let mut h = [0u8; 104];
    inc.read_exact_at(&mut h, 0)
        .map_err(|_| MinerAgentError::Backup("inc-not-qcow2"))?;
    let hdr = parse_header(&h, expected_size)?;

    let per_l1 = CLUSTER_SIZE * L2_ENTRIES;
    let needed_l1 = hdr.size.div_ceil(per_l1);
    if hdr.l1_size < needed_l1 || hdr.l1_size > needed_l1 + 1 {
        return Err(MinerAgentError::Backup("inc-l1"));
    }
    let l1_bytes = hdr.l1_size * 8;
    in_file(hdr.l1_offset, l1_bytes, inc_len)?;
    if !hdr.l1_offset.is_multiple_of(CLUSTER_SIZE) {
        return Err(MinerAgentError::Backup("inc-l1"));
    }
    let mut l1 =
        vec![0u8; usize::try_from(l1_bytes).map_err(|_| MinerAgentError::Backup("inc-l1"))?];
    inc.read_exact_at(&mut l1, hdr.l1_offset)
        .map_err(|_| MinerAgentError::Backup("inc-read"))?;

    let mut seen_l2 = std::collections::HashSet::new();
    let mut seen_data = std::collections::HashSet::new();
    let mut l2 = vec![0u8; CLUSTER_SIZE as usize];
    let mut cluster = vec![0u8; CLUSTER_SIZE as usize];
    let zeroes = vec![0u8; CLUSTER_SIZE as usize];
    for (i, e) in l1.chunks_exact(8).enumerate() {
        let e = u64::from_be_bytes(
            e.try_into()
                .map_err(|_| MinerAgentError::Backup("inc-l1"))?,
        );
        if e & !(OFFSET_MASK | COPIED) != 0 {
            return Err(MinerAgentError::Backup("inc-l1"));
        }
        let l2_off = e & OFFSET_MASK;
        if l2_off == 0 {
            continue;
        }
        if (i as u64) >= needed_l1 || !l2_off.is_multiple_of(CLUSTER_SIZE) {
            return Err(MinerAgentError::Backup("inc-l1"));
        }
        in_file(l2_off, CLUSTER_SIZE, inc_len)?;
        if !seen_l2.insert(l2_off) {
            return Err(MinerAgentError::Backup("inc-aliased"));
        }
        inc.read_exact_at(&mut l2, l2_off)
            .map_err(|_| MinerAgentError::Backup("inc-read"))?;
        for (j, e) in l2.chunks_exact(8).enumerate() {
            let e = u64::from_be_bytes(
                e.try_into()
                    .map_err(|_| MinerAgentError::Backup("inc-l2"))?,
            );
            if e == 0 {
                continue;
            }
            if e & L2_COMPRESSED != 0 {
                return Err(MinerAgentError::Backup("inc-compressed"));
            }
            if e & !(OFFSET_MASK | COPIED | L2_ZERO) != 0 {
                return Err(MinerAgentError::Backup("inc-l2"));
            }
            let guest = (i as u64 * L2_ENTRIES + j as u64) * CLUSTER_SIZE;
            if guest >= hdr.size {
                return Err(MinerAgentError::Backup("inc-l2"));
            }
            let len = usize::try_from(CLUSTER_SIZE.min(hdr.size - guest))
                .map_err(|_| MinerAgentError::Backup("inc-l2"))?;
            let data_off = e & OFFSET_MASK;
            if e & L2_ZERO != 0 {
                // A zero cluster (a preallocated one keeps an offset,
                // which is irrelevant: it still reads as zeroes).
                base.write_all_at(&zeroes[..len], guest)
                    .map_err(|_| MinerAgentError::Backup("base-write"))?;
                continue;
            }
            if data_off == 0 || !data_off.is_multiple_of(CLUSTER_SIZE) {
                return Err(MinerAgentError::Backup("inc-l2"));
            }
            in_file(data_off, len as u64, inc_len)?;
            if !seen_data.insert(data_off) {
                return Err(MinerAgentError::Backup("inc-aliased"));
            }
            inc.read_exact_at(&mut cluster[..len], data_off)
                .map_err(|_| MinerAgentError::Backup("inc-read"))?;
            base.write_all_at(&cluster[..len], guest)
                .map_err(|_| MinerAgentError::Backup("base-write"))?;
        }
    }
    base.sync_all()
        .map_err(|_| MinerAgentError::Backup("base-write"))
}

/// `[off, off+len)` lies within a file of `file_len` bytes.
fn in_file(off: u64, len: u64, file_len: u64) -> Result<()> {
    match off.checked_add(len) {
        Some(end) if end <= file_len => Ok(()),
        _ => Err(MinerAgentError::Backup("inc-out-of-bounds")),
    }
}

#[cfg(test)]
pub(crate) mod testimg {
    //! Build small qcow2 images the way QEMU lays them out.

    use super::*;

    /// A qcow2 of virtual `size` holding `clusters`: `(guest cluster
    /// index, Some(data) | None for a zero cluster)`.
    pub(crate) fn build(size: u64, clusters: &[(u64, Option<u8>)]) -> Vec<u8> {
        let cs = CLUSTER_SIZE as usize;
        let l1_size = size.div_ceil(CLUSTER_SIZE * L2_ENTRIES);
        // Layout: header | L1 | L2 tables (one per used L1 slot) | data.
        let mut img = vec![0u8; cs];
        img[0..4].copy_from_slice(&MAGIC);
        img[4..8].copy_from_slice(&3u32.to_be_bytes());
        img[20..24].copy_from_slice(&CLUSTER_BITS.to_be_bytes());
        img[24..32].copy_from_slice(&size.to_be_bytes());
        img[36..40].copy_from_slice(&(l1_size as u32).to_be_bytes());
        img[40..48].copy_from_slice(&(CLUSTER_SIZE).to_be_bytes());
        img[100..104].copy_from_slice(&104u32.to_be_bytes());
        img.resize(2 * cs, 0); // L1 at cluster 1
        let mut l2_of: std::collections::BTreeMap<u64, usize> = Default::default();
        for (g, _) in clusters {
            let slot = g / L2_ENTRIES;
            if let std::collections::btree_map::Entry::Vacant(e) = l2_of.entry(slot) {
                e.insert(img.len());
                img.resize(img.len() + cs, 0);
            }
        }
        for (slot, off) in &l2_of {
            let e = (*off as u64) | COPIED;
            let p = CLUSTER_SIZE as usize + (*slot as usize) * 8;
            img[p..p + 8].copy_from_slice(&e.to_be_bytes());
        }
        for (g, data) in clusters {
            let l2 = l2_of[&(g / L2_ENTRIES)];
            let p = l2 + ((g % L2_ENTRIES) as usize) * 8;
            let e = match data {
                Some(b) => {
                    let off = img.len();
                    img.resize(off + cs, *b);
                    (off as u64) | COPIED
                }
                None => L2_ZERO,
            };
            img[p..p + 8].copy_from_slice(&e.to_be_bytes());
        }
        img
    }
}

#[cfg(test)]
mod tests {
    use super::testimg::build;
    use super::*;

    const SIZE: u64 = 1 << 20; // 16 clusters

    fn apply_bytes(inc: &[u8], base: &[u8]) -> Result<Vec<u8>> {
        let dir = tempfile::tempdir().unwrap();
        let (i, b) = (dir.path().join("i"), dir.path().join("b"));
        std::fs::write(&i, inc).unwrap();
        std::fs::write(&b, base).unwrap();
        apply(&i, &b, base.len() as u64)?;
        Ok(std::fs::read(&b).unwrap())
    }

    #[test]
    fn data_zero_and_absent_clusters() {
        let base = vec![0x55u8; SIZE as usize];
        let inc = build(SIZE, &[(0, Some(0xaa)), (3, None), (15, Some(0xbb))]);
        let out = apply_bytes(&inc, &base).unwrap();
        let cs = CLUSTER_SIZE as usize;
        assert!(out[..cs].iter().all(|b| *b == 0xaa));
        assert!(
            out[cs..3 * cs].iter().all(|b| *b == 0x55),
            "absent ⇒ untouched"
        );
        assert!(out[3 * cs..4 * cs].iter().all(|b| *b == 0), "zero cluster");
        assert!(out[15 * cs..].iter().all(|b| *b == 0xbb));
    }

    #[test]
    fn a_partial_last_cluster_is_clipped_to_the_virtual_size() {
        let size = SIZE + 4096;
        let base = vec![0u8; size as usize];
        let inc = build(size, &[(16, Some(0xcc))]);
        let out = apply_bytes(&inc, &base).unwrap();
        assert_eq!(out.len() as u64, size, "base never grows");
        assert!(out[SIZE as usize..].iter().all(|b| *b == 0xcc));
    }

    /// Apply onto a sparse zero base of `size` (big virtual sizes).
    fn apply_bytes_sized(inc: &[u8], size: u64) -> Result<()> {
        let dir = tempfile::tempdir().unwrap();
        let (i, b) = (dir.path().join("i"), dir.path().join("b"));
        std::fs::write(&i, inc).unwrap();
        std::fs::File::create(&b).unwrap().set_len(size).unwrap();
        apply(&i, &b, size)
    }

    fn set(img: &mut [u8], at: usize, v: u64) {
        img[at..at + 8].copy_from_slice(&v.to_be_bytes());
    }

    fn l2_entry_pos(img: &[u8], guest_cluster: usize) -> usize {
        let l2 = u64::from_be_bytes(img[65536..65544].try_into().unwrap()) & OFFSET_MASK;
        l2 as usize + guest_cluster * 8
    }

    #[test]
    fn hostile_images_are_refused() {
        let base = vec![0u8; SIZE as usize];
        let good = build(SIZE, &[(1, Some(1))]);

        let mut compressed = good.clone();
        let p = l2_entry_pos(&compressed, 1);
        let e = u64::from_be_bytes(compressed[p..p + 8].try_into().unwrap());
        set(&mut compressed, p, e | L2_COMPRESSED);
        assert!(matches!(
            apply_bytes(&compressed, &base),
            Err(MinerAgentError::Backup("inc-compressed"))
        ));

        let mut oob = good.clone();
        let p = l2_entry_pos(&oob, 1);
        set(&mut oob, p, (1 << 40) | COPIED);
        assert!(matches!(
            apply_bytes(&oob, &base),
            Err(MinerAgentError::Backup("inc-out-of-bounds"))
        ));

        let mut misaligned = good.clone();
        let p = l2_entry_pos(&misaligned, 1);
        set(&mut misaligned, p, 0x200);
        assert!(matches!(
            apply_bytes(&misaligned, &base),
            Err(MinerAgentError::Backup("inc-l2"))
        ));

        let mut beyond = good.clone();
        let p = l2_entry_pos(&beyond, 16); // guest cluster 16 of a 16-cluster disk
        set(&mut beyond, p, L2_ZERO);
        assert!(matches!(
            apply_bytes(&beyond, &base),
            Err(MinerAgentError::Backup("inc-l2"))
        ));

        // Two L1 slots pointing at one L2 table (needs a 2-slot disk).
        let two = SIZE * 8192;
        let mut aliased = build(two, &[(1, Some(1)), (8192, Some(2))]);
        let first = aliased[65536..65544].to_vec();
        aliased[65544..65552].copy_from_slice(&first);
        assert!(matches!(
            apply_bytes_sized(&aliased, two),
            Err(MinerAgentError::Backup("inc-aliased"))
        ));
        // Two L2 entries sharing one data cluster.
        let mut shared = build(SIZE, &[(1, Some(1)), (2, Some(2))]);
        let p1 = l2_entry_pos(&shared, 1);
        let e1 = shared[p1..p1 + 8].to_vec();
        let p2 = l2_entry_pos(&shared, 2);
        shared[p2..p2 + 8].copy_from_slice(&e1);
        assert!(matches!(
            apply_bytes(&shared, &base),
            Err(MinerAgentError::Backup("inc-aliased"))
        ));

        let mut data_file = good.clone();
        set(&mut data_file, 72, 4);
        assert!(matches!(
            apply_bytes(&data_file, &base),
            Err(MinerAgentError::Backup("inc-external-ref"))
        ));

        let mut backing = good.clone();
        set(&mut backing, 8, 512);
        assert!(matches!(
            apply_bytes(&backing, &base),
            Err(MinerAgentError::Backup("inc-external-ref"))
        ));

        let mut bigger = good.clone();
        bigger[20..24].copy_from_slice(&21u32.to_be_bytes());
        assert!(matches!(
            apply_bytes(&bigger, &base),
            Err(MinerAgentError::Backup("inc-cluster-size"))
        ));

        let mut huge_l1 = good.clone();
        huge_l1[36..40].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            apply_bytes(&huge_l1, &base),
            Err(MinerAgentError::Backup("inc-l1"))
        ));

        let mut v2 = good.clone();
        v2[4..8].copy_from_slice(&2u32.to_be_bytes());
        assert!(matches!(
            apply_bytes(&v2, &base),
            Err(MinerAgentError::Backup("inc-not-qcow2"))
        ));

        assert!(matches!(
            apply_bytes(&build(SIZE * 2, &[]), &base),
            Err(MinerAgentError::Backup("inc-size-mismatch"))
        ));
        assert!(matches!(
            apply_bytes(b"not a qcow2 at all", &base),
            Err(MinerAgentError::Backup("inc-not-qcow2"))
        ));
    }
}
