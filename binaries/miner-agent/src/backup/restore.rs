//! Rebuild a VM's golden overlay + state disk from a backup chain — the
//! failover restore behind `migrate-activate` chain mode.
//!
//! A chain is one full backup (a raw image of the overlay) and N
//! incrementals (backing-less qcow2s holding the clusters written since
//! their parent point). Rebuild:
//!
//! 1. check the sizes vali recorded against the measured disk size and
//!    the free space (full + the largest incremental + headroom);
//! 2. GET the full into the work dir — capped at its recorded size,
//!    sha256-verified;
//! 3. per incremental, in order: GET (capped, verified), then apply its
//!    clusters onto the full with [`super::qcow2::apply`] — a bounds-
//!    checked Rust reader, because the source miner that produced it is
//!    untrusted and `qemu-img` must never parse it; delete it;
//! 4. GET the state disk (exactly 1 MiB) next to its final path;
//! 5. install: rename the overlay, then the state disk, fsyncing both
//!    directories.
//!
//! Nothing lands on the live paths until every piece verified and every
//! incremental applied. The install order matters if it is torn: a new
//! overlay with an old counter fails closed at the KBS; the reverse (new
//! counter, old overlay) would let an old disk unlock.

use std::path::{Path, PathBuf};

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::capture::SpaceLedger;
use super::transfer::Transfer;
use crate::error::{MinerAgentError, Result};
use crate::lifecycle::state_disk::STATE_DISK_BYTES;

/// Upper bound on incrementals in one chain (vali rebases at 24 by
/// default); bounds the work a hostile order can ask for.
pub const MAX_CHAIN_INCREMENTALS: usize = 64;

/// One piece of a chain: a presigned GET, the object's sha256 and size.
///
/// Not `Debug`: the URL is a short-TTL secret.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainPiece {
    /// Presigned S3 GET URL.
    pub url: String,
    /// Lower-case hex sha256 of the object.
    pub sha256_hex: String,
    /// The object's length — the download is cut off past it.
    pub size: u64,
    /// The multipart part size the object was uploaded in. `0` (absent)
    /// ⇒ unknown: the object comes down as one stream. Otherwise it comes
    /// down as parallel byte ranges aligned on these parts.
    #[serde(default)]
    pub part_size: u64,
    /// Lower-case hex sha256 of each part, in order (the upload's part
    /// receipts). Empty (absent) ⇒ only the whole-object sha is checked;
    /// otherwise one per part, each range is checked (and retried) on
    /// its own. `sha256_hex` is verified at the end either way.
    #[serde(default)]
    pub part_sha256_hex: Vec<String>,
}

impl ChainPiece {
    /// Check the part layout (see [`super::transfer::plan_ranges`]); a
    /// piece without one is always valid here.
    pub fn check_parts(&self) -> Result<()> {
        if self.part_size == 0 {
            if !self.part_sha256_hex.is_empty() {
                return Err(MinerAgentError::Backup("part-sha-count"));
            }
            return Ok(());
        }
        super::transfer::plan_ranges(self.size, self.part_size, &self.part_sha256_hex).map(|_| ())
    }
}

/// How a restore downloads its pieces.
#[derive(Clone)]
pub struct FetchOpts {
    /// Parallel ranged GETs per piece (`1..=MAX_STREAMS`).
    pub streams: usize,
    /// Bytes downloaded so far, across pieces (a failed attempt takes
    /// its bytes back).
    pub progress: Arc<AtomicU64>,
    /// Stops the rebuild between steps: a download in progress is
    /// dropped, a qcow2 apply already running is let finish (it writes
    /// through a blocking thread that cannot be interrupted), so nothing
    /// writes into the work dir once the rebuild has returned.
    pub cancel: tokio_util::sync::CancellationToken,
}

impl Default for FetchOpts {
    fn default() -> Self {
        Self {
            streams: super::transfer::DEFAULT_STREAMS,
            progress: Arc::default(),
            cancel: tokio_util::sync::CancellationToken::new(),
        }
    }
}

/// `fetcher.fetch`, abandoned (and its partial file removed) if `opts`
/// is cancelled first.
async fn fetch_or_cancel(
    fetcher: &dyn PieceFetcher,
    piece: &ChainPiece,
    dest: &Path,
    opts: &FetchOpts,
) -> Result<()> {
    let r = tokio::select! {
        r = fetcher.fetch(piece, dest, opts) => r,
        _ = opts.cancel.cancelled() => Err(MinerAgentError::Backup("restore-cancelled")),
    };
    if r.is_err() {
        let _ = tokio::fs::remove_file(dest).await;
    }
    r
}

/// The restore point a failover boots from.
///
/// Not `Debug`: it holds presigned URLs.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreChain {
    /// Unique per restore ATTEMPT (vali's job id). It keys the
    /// `.restored-from` marker: a retried activation must restore again
    /// rather than boot what a failed attempt left behind.
    pub restore_id: String,
    /// The full backup (raw).
    pub full: ChainPiece,
    /// The incrementals, oldest first.
    #[serde(default)]
    pub incrementals: Vec<ChainPiece>,
    /// The state disk taken with the last piece.
    pub state: ChainPiece,
}

impl RestoreChain {
    /// The identity recorded in the `.restored-from` marker.
    pub fn identity(&self) -> String {
        let last = self.incrementals.last().unwrap_or(&self.full);
        let path = last
            .url
            .split_once('?')
            .map_or(last.url.as_str(), |(p, _)| p);
        format!("chain:{}:{path}", self.restore_id)
    }
}

/// Fetch one piece to `dest`: at most `piece.size` bytes, exactly that
/// many, matching `piece.sha256_hex`. [`Transfer`] in production.
#[async_trait]
pub trait PieceFetcher: Send + Sync {
    /// GET `piece` into `dest`; on any mismatch `Err` and no file.
    async fn fetch(&self, piece: &ChainPiece, dest: &Path, opts: &FetchOpts) -> Result<()>;
}

#[async_trait]
impl PieceFetcher for Transfer {
    async fn fetch(&self, piece: &ChainPiece, dest: &Path, opts: &FetchOpts) -> Result<()> {
        if piece.part_size == 0 {
            if !piece.part_sha256_hex.is_empty() {
                return Err(MinerAgentError::Backup("part-sha-count"));
            }
            return self
                .download_verified_progress(
                    &piece.url,
                    &piece.sha256_hex,
                    piece.size,
                    dest,
                    &opts.progress,
                )
                .await;
        }
        let ranges =
            super::transfer::plan_ranges(piece.size, piece.part_size, &piece.part_sha256_hex)?;
        let object = super::transfer::RangedObject {
            url: &piece.url,
            sha256_hex: &piece.sha256_hex,
            size: piece.size,
            ranges,
        };
        self.download_ranged(object, opts.streams, dest, &opts.progress)
            .await
    }
}

#[async_trait]
impl<T: PieceFetcher + ?Sized> PieceFetcher for Arc<T> {
    async fn fetch(&self, piece: &ChainPiece, dest: &Path, opts: &FetchOpts) -> Result<()> {
        (**self).fetch(piece, dest, opts).await
    }
}

/// The seam `activate_dest` restores a chain through.
#[async_trait]
pub trait ChainRestorer: Send + Sync {
    /// Rebuild `chain` into `overlay_path` + `state_path`, staging in
    /// `work_dir` (on the overlay's filesystem). `expected_size` (the
    /// measured `disk_gb`), when known, must equal the full's size.
    async fn restore(
        &self,
        chain: &RestoreChain,
        work_dir: &Path,
        overlay_path: &Path,
        state_path: &Path,
        expected_size: Option<u64>,
    ) -> Result<()>;
}

/// Production [`ChainRestorer`].
pub struct BackupChainRestorer<F> {
    fetcher: F,
    space: Arc<SpaceLedger>,
    headroom_bytes: u64,
}

impl<F: PieceFetcher> BackupChainRestorer<F> {
    /// Restore through `fetcher`, reserving its peak disk use in `space`
    /// (the ledger backups reserve in, so restores and captures cannot
    /// both count the same free blocks) and keeping
    /// [`super::capture::SPACE_RESERVE_BYTES`] free on top.
    pub fn new(fetcher: F, space: Arc<SpaceLedger>) -> Self {
        Self {
            fetcher,
            space,
            headroom_bytes: super::capture::SPACE_RESERVE_BYTES,
        }
    }

    /// Override the free-space headroom (tests).
    pub fn with_headroom(mut self, headroom_bytes: u64) -> Self {
        self.headroom_bytes = headroom_bytes;
        self
    }
}

#[async_trait]
impl<F: PieceFetcher> ChainRestorer for BackupChainRestorer<F> {
    async fn restore(
        &self,
        chain: &RestoreChain,
        work_dir: &Path,
        overlay_path: &Path,
        state_path: &Path,
        expected_size: Option<u64>,
    ) -> Result<()> {
        let result = rebuild(
            &self.fetcher,
            &self.space,
            chain,
            &Target {
                work_dir,
                overlay_path,
                state_path,
            },
            expected_size,
            self.headroom_bytes,
            &FetchOpts::default(),
        )
        .await;
        // The staging dir only ever holds this rebuild's temps.
        let _ = tokio::fs::remove_dir_all(work_dir).await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(sibling(state_path, ".restore-part")).await;
        }
        result
    }
}

/// Where a rebuild works and what it installs.
pub(crate) struct Target<'a> {
    /// Scratch dir on the overlay's filesystem (emptied first).
    pub work_dir: &'a Path,
    /// Where the rebuilt overlay is renamed to.
    pub overlay_path: &'a Path,
    /// Where the state disk is renamed to.
    pub state_path: &'a Path,
}

/// The checks a chain must pass before anything is downloaded: its
/// length, the full's size (== `expected_size` when known), the state
/// disk's size, each piece's part layout.
pub(crate) fn check_chain(chain: &RestoreChain, expected_size: Option<u64>) -> Result<()> {
    if chain.incrementals.len() > MAX_CHAIN_INCREMENTALS {
        return Err(MinerAgentError::Backup("chain-too-long"));
    }
    let full_size = chain.full.size;
    if full_size == 0 || expected_size.is_some_and(|s| s != full_size) {
        return Err(MinerAgentError::Backup("full-size-mismatch"));
    }
    if chain.state.size != STATE_DISK_BYTES {
        return Err(MinerAgentError::Backup("state-size"));
    }
    chain.full.check_parts()?;
    chain.state.check_parts()?;
    for p in &chain.incrementals {
        p.check_parts()?;
    }
    Ok(())
}

/// Bytes a chain downloads in all.
pub(crate) fn chain_bytes(chain: &RestoreChain) -> u64 {
    chain
        .incrementals
        .iter()
        .fold(chain.full.size.saturating_add(chain.state.size), |a, p| {
            a.saturating_add(p.size)
        })
}

/// Peak work-dir use of a rebuild: the full and one incremental coexist.
pub(crate) fn chain_peak_bytes(chain: &RestoreChain) -> u64 {
    let largest_inc = chain.incrementals.iter().map(|p| p.size).max().unwrap_or(0);
    chain.full.size.saturating_add(largest_inc)
}

/// See the module docs.
pub(crate) async fn rebuild(
    fetcher: &dyn PieceFetcher,
    space: &SpaceLedger,
    chain: &RestoreChain,
    target: &Target<'_>,
    expected_size: Option<u64>,
    headroom_bytes: u64,
    opts: &FetchOpts,
) -> Result<()> {
    let Target {
        work_dir,
        overlay_path,
        state_path,
    } = *target;
    check_chain(chain, expected_size)?;
    let full_size = chain.full.size;
    let _ = tokio::fs::remove_dir_all(work_dir).await;
    tokio::fs::create_dir_all(work_dir)
        .await
        .map_err(|_| MinerAgentError::Backup("work-dir"))?;
    // Peak: the full and one incremental coexist in the work dir. (The
    // state disk lands on its own filesystem; it is 1 MiB.)
    let _space = space.reserve(work_dir, chain_peak_bytes(chain), headroom_bytes)?;

    let base = work_dir.join("overlay.img");
    fetch_or_cancel(fetcher, &chain.full, &base, opts).await?;

    for (i, piece) in chain.incrementals.iter().enumerate() {
        let inc = work_dir.join(format!("inc-{i}.qcow2"));
        fetch_or_cancel(fetcher, piece, &inc, opts).await?;
        let (inc2, base2) = (inc.clone(), base.clone());
        tokio::task::spawn_blocking(move || super::qcow2::apply(&inc2, &base2, full_size))
            .await
            .map_err(|_| MinerAgentError::Backup("apply-join"))??;
        let _ = tokio::fs::remove_file(&inc).await;
    }

    let state_dir = parent(state_path, "state-path")?;
    tokio::fs::create_dir_all(state_dir)
        .await
        .map_err(|_| MinerAgentError::Backup("state-path"))?;
    let state_part = sibling(state_path, ".restore-part");
    fetch_or_cancel(fetcher, &chain.state, &state_part, opts).await?;

    if opts.cancel.is_cancelled() {
        let _ = tokio::fs::remove_file(&state_part).await;
        return Err(MinerAgentError::Backup("restore-cancelled"));
    }
    let overlay_dir = parent(overlay_path, "overlay-path")?;
    tokio::fs::create_dir_all(overlay_dir)
        .await
        .map_err(|_| MinerAgentError::Backup("overlay-path"))?;
    tokio::fs::rename(&base, overlay_path)
        .await
        .map_err(|_| MinerAgentError::Backup("overlay-install"))?;
    sync_dir(overlay_dir).await?;
    tokio::fs::rename(&state_part, state_path)
        .await
        .map_err(|_| MinerAgentError::Backup("state-install"))?;
    sync_dir(state_dir).await
}

fn parent<'p>(path: &'p Path, class: &'static str) -> Result<&'p Path> {
    path.parent().ok_or(MinerAgentError::Backup(class))
}

/// fsync a directory so a rename in it survives a crash.
pub(crate) async fn sync_dir(dir: &Path) -> Result<()> {
    let d = tokio::fs::File::open(dir)
        .await
        .map_err(|_| MinerAgentError::Backup("dir-sync"))?;
    d.sync_all()
        .await
        .map_err(|_| MinerAgentError::Backup("dir-sync"))
}

pub(crate) fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::super::qcow2::testimg;
    use super::*;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;

    const CS: usize = 1 << 16;
    const FULL: u64 = 16 * CS as u64;

    /// Serves pieces from memory, keyed by URL; enforces size + sha like
    /// the real fetcher.
    struct MemFetcher(HashMap<String, Vec<u8>>);

    #[async_trait]
    impl PieceFetcher for MemFetcher {
        async fn fetch(&self, piece: &ChainPiece, dest: &Path, _: &FetchOpts) -> Result<()> {
            let body = self
                .0
                .get(&piece.url)
                .ok_or(MinerAgentError::Backup("get-status"))?;
            if body.len() as u64 != piece.size {
                return Err(MinerAgentError::Backup("size-mismatch"));
            }
            if hex::encode(Sha256::digest(body)) != piece.sha256_hex {
                return Err(MinerAgentError::Backup("sha-mismatch"));
            }
            tokio::fs::write(dest, body).await.unwrap();
            Ok(())
        }
    }

    fn piece(url: &str, body: &[u8]) -> ChainPiece {
        ChainPiece {
            url: url.into(),
            sha256_hex: hex::encode(Sha256::digest(body)),
            size: body.len() as u64,
            part_size: 0,
            part_sha256_hex: Vec::new(),
        }
    }

    struct Fixture {
        dir: tempfile::TempDir,
        chain: RestoreChain,
        fetcher: MemFetcher,
    }

    fn fixture(incs: Vec<Vec<u8>>) -> Fixture {
        let full = vec![0u8; FULL as usize];
        let state = vec![5u8; STATE_DISK_BYTES as usize];
        let mut objs = HashMap::new();
        objs.insert("u/full".to_string(), full.clone());
        objs.insert("u/state".to_string(), state.clone());
        let mut pieces = Vec::new();
        for (i, b) in incs.into_iter().enumerate() {
            let url = format!("u/inc{i}?X-Amz-Signature=s");
            pieces.push(piece(&url, &b));
            objs.insert(url, b);
        }
        Fixture {
            dir: tempfile::tempdir().unwrap(),
            chain: RestoreChain {
                restore_id: "job-1".into(),
                full: piece("u/full", &full),
                incrementals: pieces,
                state: piece("u/state", &state),
            },
            fetcher: MemFetcher(objs),
        }
    }

    fn restorer(f: MemFetcher) -> BackupChainRestorer<MemFetcher> {
        BackupChainRestorer::new(f, Arc::default()).with_headroom(0)
    }

    #[tokio::test]
    async fn applies_incrementals_in_order_and_installs() {
        let f = fixture(vec![
            testimg::build(FULL, &[(0, Some(1)), (1, Some(2))]),
            testimg::build(FULL, &[(1, Some(3)), (0, None)]),
        ]);
        let root = f.dir.path();
        let overlay = root.join("overlay/vm.img");
        let state = root.join("state/vm.raw");
        restorer(f.fetcher)
            .restore(
                &f.chain,
                &root.join("backup/vm/restore"),
                &overlay,
                &state,
                Some(FULL),
            )
            .await
            .unwrap();
        let got = std::fs::read(&overlay).unwrap();
        assert!(got[..CS].iter().all(|b| *b == 0), "zeroed by the later inc");
        assert!(
            got[CS..2 * CS].iter().all(|b| *b == 3),
            "the later inc wins"
        );
        assert_eq!(
            std::fs::read(&state).unwrap().len() as u64,
            STATE_DISK_BYTES
        );
        assert!(!root.join("backup/vm/restore").exists());
        assert_eq!(
            f.chain.identity(),
            "chain:job-1:u/inc1",
            "the identity strips the presigned query"
        );
    }

    #[tokio::test]
    async fn a_bad_piece_leaves_the_live_paths_untouched() {
        let mut f = fixture(vec![testimg::build(FULL, &[(0, Some(1))])]);
        f.chain.incrementals[0].sha256_hex = hex::encode(Sha256::digest(b"x"));
        let root = f.dir.path();
        let overlay = root.join("overlay/vm.img");
        std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
        std::fs::write(&overlay, b"previous").unwrap();
        let err = restorer(f.fetcher)
            .restore(
                &f.chain,
                &root.join("w"),
                &overlay,
                &root.join("state/vm.raw"),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("sha-mismatch")));
        assert_eq!(std::fs::read(&overlay).unwrap(), b"previous");
        assert!(!root.join("state/vm.raw").exists());
        assert!(!root.join("state/vm.raw.restore-part").exists());
    }

    #[tokio::test]
    async fn a_crafted_incremental_is_refused_and_nothing_installs() {
        let mut bad = testimg::build(FULL, &[(0, Some(1))]);
        bad[72..80].copy_from_slice(&4u64.to_be_bytes()); // external data file
        let f = fixture(vec![bad]);
        let root = f.dir.path();
        let err = restorer(f.fetcher)
            .restore(
                &f.chain,
                &root.join("w"),
                &root.join("overlay/vm.img"),
                &root.join("state/vm.raw"),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("inc-external-ref")));
        assert!(!root.join("overlay/vm.img").exists());
    }

    #[tokio::test]
    async fn sizes_are_checked_before_any_download() {
        let f = fixture(vec![]);
        let root = f.dir.path();
        let err = restorer(f.fetcher)
            .restore(
                &f.chain,
                &root.join("w"),
                &root.join("o/vm.img"),
                &root.join("s/vm.raw"),
                Some(FULL * 2),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("full-size-mismatch")));

        let mut f = fixture(vec![]);
        f.chain.state.size = 10;
        let root = f.dir.path();
        let err = restorer(f.fetcher)
            .restore(
                &f.chain,
                &root.join("w"),
                &root.join("o/vm.img"),
                &root.join("s/vm.raw"),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("state-size")));

        let mut f = fixture(vec![]);
        f.chain.full.size = u64::MAX / 2;
        let root = f.dir.path();
        let err = restorer(f.fetcher)
            .restore(
                &f.chain,
                &root.join("w"),
                &root.join("o/vm.img"),
                &root.join("s/vm.raw"),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("insufficient-space")));
    }

    #[tokio::test]
    async fn a_restore_is_refused_the_space_a_live_disk_was_promised() {
        // The host ledger nets out a live VM's unwritten sparse tail; the
        // same chain restores fine through a raw-`statvfs` ledger
        // (`applies_incrementals_in_order_and_installs`).
        let f = fixture(vec![]);
        let root = f.dir.path();
        let free = super::super::capture::free_bytes(root).unwrap();
        let data = crate::lifecycle::data_disk::data_dir(root);
        std::fs::create_dir_all(&data).unwrap();
        std::fs::File::create(data.join("tenant-live.img"))
            .unwrap()
            .set_len(free)
            .unwrap();
        let err = BackupChainRestorer::new(f.fetcher, Arc::new(SpaceLedger::host(root)))
            .with_headroom(0)
            .restore(
                &f.chain,
                &root.join("w"),
                &root.join("o/vm.img"),
                &root.join("s/vm.raw"),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("insufficient-space")));
        assert!(!root.join("o/vm.img").exists());
    }

    #[tokio::test]
    async fn an_incremental_for_another_disk_size_is_refused() {
        let f = fixture(vec![testimg::build(FULL * 2, &[])]);
        let root = f.dir.path();
        let err = restorer(f.fetcher)
            .restore(
                &f.chain,
                &root.join("w"),
                &root.join("o/vm.img"),
                &root.join("s/vm.raw"),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("inc-size-mismatch")));
    }

    #[test]
    fn identity_without_incrementals_is_the_full() {
        let f = fixture(vec![]);
        assert_eq!(f.chain.identity(), "chain:job-1:u/full");
    }
}
