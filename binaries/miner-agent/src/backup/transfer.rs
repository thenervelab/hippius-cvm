//! Moving backup pieces to and from S3 through presigned URLs.
//!
//! The miner never holds S3 credentials: vali presigns a multipart
//! upload's `UploadPart` URLs (and a single PUT for the state disk), the
//! miner PUTs, reports each part's ETag + sha256, and vali completes the
//! upload itself. A restore GETs each object through one presigned URL:
//! as parallel byte ranges aligned on the parts it was uploaded in (each
//! range checked against the part's sha256 and retried on its own), or as
//! one stream when the part layout is not known. Either way the whole
//! object's sha256 is checked at the end.
//!
//! The pieces go up **uncompressed**. The overlay is LUKS ciphertext end
//! to end (`luksFormat --integrity` writes every sector), and an
//! incremental allocates only dirty — i.e. ciphertext — clusters, so the
//! phase-0 spike measured a zstd ratio of 1.0. Streaming raw byte ranges
//! lets each part go straight from the file with a known length and no
//! buffering.

use std::io::SeekFrom;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::error::{MinerAgentError, Result};

/// S3's floor on every part but the last.
pub const MIN_PART_SIZE: u64 = 5 << 20;

/// The store's ceiling on one part: hippius-s3 answers `EntityTooLarge`
/// above 512 MiB (S3's own is 5 GiB). Refused up front — a larger part
/// could only half-upload.
pub const MAX_PART_SIZE: u64 = 512 << 20;

/// S3's ceiling on the number of parts.
pub const MAX_PARTS: usize = 10_000;

/// Attempts per part (a part is re-read from the file on each).
pub(crate) const PART_ATTEMPTS: u32 = 3;

/// Attempts per download — one byte range, or a whole object on the
/// single-stream path: the first try and three retries.
pub(crate) const DOWNLOAD_ATTEMPTS: u32 = 4;

/// Pause before the first retry of a download; doubled on each further
/// retry.
#[cfg(not(test))]
const RETRY_BACKOFF: Duration = Duration::from_secs(2);
#[cfg(test)]
const RETRY_BACKOFF: Duration = Duration::from_millis(5);

/// Parallel ranged GETs a restore uses when the order does not say.
pub const DEFAULT_STREAMS: usize = 8;

/// Most parallel ranged GETs one piece may use.
pub const MAX_STREAMS: usize = 16;

/// Slowest sustained rate one byte range may run at before it is cut
/// off (and retried). Lower than [`TRANSFER_MIN_RATE`]: with up to
/// [`MAX_STREAMS`] ranges sharing the link, each gets a fraction of it.
const RANGE_MIN_RATE: u64 = 5 << 20;

/// Time budget for one byte range of `len` bytes.
pub fn range_timeout(len: u64) -> Duration {
    TRANSFER_BASE_TIMEOUT + Duration::from_secs(len / RANGE_MIN_RATE)
}

/// Clamp an order's stream count to `1..=MAX_STREAMS`.
pub fn clamp_streams(streams: u8) -> usize {
    usize::from(streams).clamp(1, MAX_STREAMS)
}

/// One byte range of a ranged download, and the sha256 it must hash to
/// when the part layout recorded one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// First byte.
    pub offset: u64,
    /// Length (never 0).
    pub len: u64,
    /// The recorded sha256 of exactly these bytes, if known.
    pub sha256: Option<[u8; 32]>,
}

/// Split a `size`-byte object uploaded in `part_size` parts into the
/// ranges a download fetches: one per part, so each can be checked
/// against its part's recorded sha256 (`part_sha256_hex`, one per part,
/// or empty when not recorded). The part size is held to the store's
/// multipart limits — a tiny one would turn one object into millions of
/// requests.
pub fn plan_ranges(
    size: u64,
    part_size: u64,
    part_sha256_hex: &[String],
) -> Result<Vec<ByteRange>> {
    check_part_size(part_size)?;
    let n = part_count(size, part_size);
    if n == 0 {
        return Err(MinerAgentError::Backup("empty-piece"));
    }
    if n > MAX_PARTS {
        return Err(MinerAgentError::Backup("part-count"));
    }
    if !part_sha256_hex.is_empty() && part_sha256_hex.len() != n {
        return Err(MinerAgentError::Backup("part-sha-count"));
    }
    let mut ranges = Vec::with_capacity(n);
    for i in 0..n {
        let offset = i as u64 * part_size;
        let sha256 = match part_sha256_hex.get(i) {
            Some(h) => Some(parse_sha256_hex(h).ok_or(MinerAgentError::Backup("bad-part-sha"))?),
            None => None,
        };
        ranges.push(ByteRange {
            offset,
            len: part_size.min(size - offset),
            sha256,
        });
    }
    Ok(ranges)
}

/// Pause before retry `attempt` (1-based) of a download.
fn retry_pause(attempt: u32) -> Duration {
    RETRY_BACKOFF * 2u32.saturating_pow(attempt.saturating_sub(1))
}

/// Fixed part of a request's time budget.
const TRANSFER_BASE_TIMEOUT: Duration = Duration::from_secs(600);

/// Slowest sustained rate a transfer is allowed before it is cut off.
const TRANSFER_MIN_RATE: u64 = 10 << 20;

/// Time budget for moving `len` bytes: generous enough that a
/// multi-hundred-GiB full is never cut off by a flat cap, bounded so a
/// stalled peer cannot hold a run forever.
pub fn transfer_timeout(len: u64) -> Duration {
    TRANSFER_BASE_TIMEOUT + Duration::from_secs(len / TRANSFER_MIN_RATE)
}

/// Connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Read granularity of the streamed body.
const CHUNK: usize = 1 << 20;

/// One uploaded part, as vali needs it to complete the upload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PartReceipt {
    /// 1-based S3 part number.
    pub part_number: u32,
    /// The ETag S3 returned, verbatim (quotes included).
    pub etag: String,
    /// Lower-case hex sha256 of the part's bytes.
    pub sha256_hex: String,
    /// The part's length.
    pub size: u64,
}

/// A whole uploaded piece.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PieceReceipt {
    /// Parts in order (empty for a single-PUT piece).
    pub parts: Vec<PartReceipt>,
    /// Total bytes.
    pub size: u64,
    /// Lower-case hex sha256 of the whole object.
    pub sha256_hex: String,
}

/// How many parts a `len`-byte piece takes at `part_size`.
pub fn part_count(len: u64, part_size: u64) -> usize {
    if len == 0 || part_size == 0 {
        return 0;
    }
    usize::try_from(len.div_ceil(part_size)).unwrap_or(usize::MAX)
}

/// Validate a part size against the store's multipart limits.
pub fn check_part_size(part_size: u64) -> Result<()> {
    if !(MIN_PART_SIZE..=MAX_PART_SIZE).contains(&part_size) {
        return Err(MinerAgentError::Backup("part-size"));
    }
    Ok(())
}

/// The presigned-URL HTTP client.
#[derive(Clone)]
pub struct Transfer {
    client: reqwest::Client,
}

impl Transfer {
    /// Build the client (same TLS posture as the §25 snapshot client).
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| MinerAgentError::Backup("http-client"))?;
        Ok(Self { client })
    }

    /// Upload `len` bytes of `file` as consecutive `part_size` parts to
    /// `part_urls` (URL `i` is part `i+1`). Parts go one at a time so the
    /// whole-object sha256 accumulates in order; a failed part is retried
    /// from the file.
    pub async fn upload_parts(
        &self,
        file: &std::fs::File,
        len: u64,
        part_size: u64,
        part_urls: &[String],
    ) -> Result<PieceReceipt> {
        check_part_size(part_size)?;
        let n = part_count(len, part_size);
        if n == 0 {
            return Err(MinerAgentError::Backup("empty-piece"));
        }
        if n > MAX_PARTS || n > part_urls.len() {
            return Err(MinerAgentError::Backup("too-few-part-urls"));
        }
        let mut whole = Sha256::new();
        let mut parts = Vec::with_capacity(n);
        for (i, url) in part_urls.iter().take(n).enumerate() {
            let offset = i as u64 * part_size;
            let size = part_size.min(len - offset);
            let mut last = MinerAgentError::Backup("part-put");
            let mut done = None;
            for _ in 0..PART_ATTEMPTS {
                match self.put_range(file, offset, size, url, whole.clone()).await {
                    Ok(ok) => {
                        done = Some(ok);
                        break;
                    }
                    Err(e) => last = e,
                }
            }
            let (etag, part_sha, advanced) = done.ok_or(last)?;
            whole = advanced;
            parts.push(PartReceipt {
                part_number: u32::try_from(i + 1)
                    .map_err(|_| MinerAgentError::Backup("part-count"))?,
                etag: etag.ok_or(MinerAgentError::Backup("part-etag"))?,
                sha256_hex: hex::encode(part_sha),
                size,
            });
        }
        Ok(PieceReceipt {
            parts,
            size: len,
            sha256_hex: hex::encode(whole.finalize()),
        })
    }

    /// PUT a small in-memory object (the state disk) to one presigned URL.
    pub async fn put_small(&self, url: &str, body: Vec<u8>) -> Result<PieceReceipt> {
        let size = body.len() as u64;
        let sha = hex::encode(Sha256::digest(&body));
        let resp = self
            .client
            .put(url)
            .timeout(transfer_timeout(size))
            .header(reqwest::header::CONTENT_LENGTH, size)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(body)
            .send()
            .await
            .map_err(|_| MinerAgentError::Backup("state-put"))?;
        if !resp.status().is_success() {
            return Err(MinerAgentError::Backup("state-put-status"));
        }
        Ok(PieceReceipt {
            parts: Vec::new(),
            size,
            sha256_hex: sha,
        })
    }

    /// Stream one byte range as a PUT body, hashing it as it goes.
    /// Returns (ETag, part sha256, `whole` advanced over the range).
    async fn put_range(
        &self,
        file: &std::fs::File,
        offset: u64,
        size: u64,
        url: &str,
        whole: Sha256,
    ) -> Result<(Option<String>, [u8; 32], Sha256)> {
        let std_file = file
            .try_clone()
            .map_err(|_| MinerAgentError::Backup("piece-read"))?;
        let mut f = tokio::fs::File::from_std(std_file);
        f.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| MinerAgentError::Backup("piece-read"))?;
        let hashers = Arc::new(Mutex::new((Sha256::new(), whole)));
        let h = Arc::clone(&hashers);
        let reader = f.take(size);
        let stream = hashing_stream(reader, h);
        let resp = self
            .client
            .put(url)
            .timeout(transfer_timeout(size))
            .header(reqwest::header::CONTENT_LENGTH, size)
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
            .map_err(|_| MinerAgentError::Backup("part-put"))?;
        if !resp.status().is_success() {
            eprintln!(
                "hippius-miner-agent: transfer: part PUT refused: HTTP {}",
                resp.status().as_u16()
            );
            return Err(MinerAgentError::Backup("part-status"));
        }
        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let (part, whole) = Arc::try_unwrap(hashers)
            .map_err(|_| MinerAgentError::Backup("part-put"))?
            .into_inner()
            .map_err(|_| MinerAgentError::LockPoisoned)?;
        Ok((etag, part.finalize().into(), whole))
    }

    /// GET a whole object into `dest` (created, truncated): exactly
    /// `size` bytes — a longer body is cut off as soon as it overruns, so
    /// an untrusted object cannot fill the disk — matching `sha256_hex`.
    /// A failed attempt (transport, size, sha) is retried from scratch
    /// [`DOWNLOAD_ATTEMPTS`] times in all. On final failure the file is
    /// removed.
    pub async fn download_verified(
        &self,
        url: &str,
        sha256_hex: &str,
        size: u64,
        dest: &Path,
    ) -> Result<()> {
        self.download_verified_progress(url, sha256_hex, size, dest, &AtomicU64::new(0))
            .await
    }

    /// [`Self::download_verified`], adding the bytes written to
    /// `progress` as they land (a failed attempt takes its bytes back).
    pub async fn download_verified_progress(
        &self,
        url: &str,
        sha256_hex: &str,
        size: u64,
        dest: &Path,
        progress: &AtomicU64,
    ) -> Result<()> {
        let expected = parse_sha256_hex(sha256_hex).ok_or(MinerAgentError::Backup("bad-sha"))?;
        let mut last = MinerAgentError::Backup("get-send");
        for attempt in 0..DOWNLOAD_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(retry_pause(attempt)).await;
            }
            let mut counted = 0u64;
            let result = self
                .download_into(url, size, dest, progress, &mut counted)
                .await;
            match result {
                Ok(got) if got == expected => return Ok(()),
                Ok(_) => last = MinerAgentError::Backup("sha-mismatch"),
                Err(e) => last = e,
            }
            progress.fetch_sub(counted, Ordering::Relaxed);
            let _ = tokio::fs::remove_file(dest).await;
        }
        Err(last)
    }

    async fn download_into(
        &self,
        url: &str,
        size: u64,
        dest: &Path,
        progress: &AtomicU64,
        counted: &mut u64,
    ) -> Result<[u8; 32]> {
        let mut resp = self
            .client
            .get(url)
            .timeout(transfer_timeout(size))
            .send()
            .await
            .map_err(|_| MinerAgentError::Backup("get-send"))?;
        if !resp.status().is_success() {
            return Err(MinerAgentError::Backup("get-status"));
        }
        if resp.content_length().is_some_and(|l| l != size) {
            return Err(MinerAgentError::Backup("size-mismatch"));
        }
        let mut f = tokio::fs::File::create(dest)
            .await
            .map_err(|_| MinerAgentError::Backup("get-write"))?;
        let mut hasher = Sha256::new();
        let mut len = 0u64;
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|_| MinerAgentError::Backup("get-read"))?
        {
            len += chunk.len() as u64;
            if len > size {
                return Err(MinerAgentError::Backup("size-mismatch"));
            }
            hasher.update(&chunk);
            f.write_all(&chunk)
                .await
                .map_err(|_| MinerAgentError::Backup("get-write"))?;
            *counted += chunk.len() as u64;
            progress.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
        if len != size {
            return Err(MinerAgentError::Backup("size-mismatch"));
        }
        f.sync_all()
            .await
            .map_err(|_| MinerAgentError::Backup("get-write"))?;
        Ok(hasher.finalize().into())
    }

    /// GET a `size`-byte object as parallel byte ranges into `dest`: the
    /// file is preallocated, `streams` workers take `ranges` in order,
    /// each range is written in place, held to its length and to its
    /// part's sha256 (when recorded), and retried on its own up to
    /// [`DOWNLOAD_ATTEMPTS`] times. Then the whole file is hashed and
    /// must match `sha256_hex` — the per-range checks only make a bad
    /// range cheap to retry; the whole-object sha is what the restore
    /// trusts. Without per-part shas a bad range is only seen there, so
    /// the whole piece is then fetched once more. On final failure the
    /// file is removed and the piece's bytes are taken back from
    /// `progress`.
    pub async fn download_ranged(
        &self,
        object: RangedObject<'_>,
        streams: usize,
        dest: &Path,
        progress: &Arc<AtomicU64>,
    ) -> Result<()> {
        let expected =
            parse_sha256_hex(object.sha256_hex).ok_or(MinerAgentError::Backup("bad-sha"))?;
        let attempts = if object.ranges.iter().all(|r| r.sha256.is_some()) {
            1
        } else {
            2
        };
        let mut last = MinerAgentError::Backup("sha-mismatch");
        for _ in 0..attempts {
            let before = progress.load(Ordering::Relaxed);
            let result = self
                .download_ranged_inner(
                    object.url,
                    object.size,
                    object.ranges.clone(),
                    streams,
                    dest,
                    progress,
                )
                .await;
            match result {
                Ok(got) if got == expected => return Ok(()),
                Ok(_) => last = MinerAgentError::Backup("sha-mismatch"),
                Err(e) => last = e,
            }
            let _ = tokio::fs::remove_file(dest).await;
            let added = progress.load(Ordering::Relaxed).saturating_sub(before);
            progress.fetch_sub(added, Ordering::Relaxed);
            if !matches!(last, MinerAgentError::Backup("sha-mismatch")) {
                break;
            }
        }
        Err(last)
    }

    async fn download_ranged_inner(
        &self,
        url: &str,
        size: u64,
        ranges: Vec<ByteRange>,
        streams: usize,
        dest: &Path,
        progress: &Arc<AtomicU64>,
    ) -> Result<[u8; 32]> {
        // The ranges must tile the object exactly: every byte fetched
        // once, nothing past `size`.
        let mut next_offset = 0u64;
        for r in &ranges {
            if r.len == 0 || r.offset != next_offset {
                return Err(MinerAgentError::Backup("range-plan"));
            }
            next_offset = r.offset.saturating_add(r.len);
        }
        if next_offset != size || ranges.is_empty() {
            return Err(MinerAgentError::Backup("range-plan"));
        }
        {
            let f = tokio::fs::File::create(dest)
                .await
                .map_err(|_| MinerAgentError::Backup("get-write"))?;
            f.set_len(size)
                .await
                .map_err(|_| MinerAgentError::Backup("get-write"))?;
        }
        let whole = ranges.len() == 1;
        let ranges = Arc::new(ranges);
        let next = Arc::new(AtomicUsize::new(0));
        let mut workers = tokio::task::JoinSet::new();
        for _ in 0..streams.clamp(1, MAX_STREAMS).min(ranges.len()) {
            let worker = RangeWorker {
                client: self.client.clone(),
                url: url.to_string(),
                dest: dest.to_path_buf(),
                ranges: Arc::clone(&ranges),
                next: Arc::clone(&next),
                progress: Arc::clone(progress),
                whole,
                size,
            };
            workers.spawn(worker.run());
        }
        while let Some(joined) = workers.join_next().await {
            let outcome = joined.unwrap_or(Err(MinerAgentError::Backup("range-join")));
            if let Err(e) = outcome {
                workers.abort_all();
                while workers.join_next().await.is_some() {}
                return Err(e);
            }
        }
        let f = tokio::fs::OpenOptions::new()
            .write(true)
            .open(dest)
            .await
            .map_err(|_| MinerAgentError::Backup("get-write"))?;
        f.sync_all()
            .await
            .map_err(|_| MinerAgentError::Backup("get-write"))?;
        drop(f);
        let path = dest.to_path_buf();
        tokio::task::spawn_blocking(move || hash_file(&path, size))
            .await
            .map_err(|_| MinerAgentError::Backup("hash-join"))?
    }
}

/// The object a ranged download fetches: its presigned URL, whole-object
/// sha256 and size, and the ranges ([`plan_ranges`]) it is fetched in.
pub struct RangedObject<'a> {
    /// Presigned GET URL (a short-TTL secret — never logged).
    pub url: &'a str,
    /// Lower-case hex sha256 of the whole object.
    pub sha256_hex: &'a str,
    /// The object's length.
    pub size: u64,
    /// The ranges, tiling `0..size`.
    pub ranges: Vec<ByteRange>,
}

/// One of a ranged download's parallel workers: takes the next range,
/// fetches it (with retries), repeats until none are left.
struct RangeWorker {
    client: reqwest::Client,
    url: String,
    dest: std::path::PathBuf,
    ranges: Arc<Vec<ByteRange>>,
    next: Arc<AtomicUsize>,
    progress: Arc<AtomicU64>,
    /// The only range covers the whole object: a plain `200` answer is
    /// then the same bytes.
    whole: bool,
    /// The object's length (the `/<total>` of every `Content-Range`).
    size: u64,
}

impl RangeWorker {
    async fn run(self) -> Result<()> {
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&self.dest)
            .await
            .map_err(|_| MinerAgentError::Backup("get-write"))?;
        loop {
            let i = self.next.fetch_add(1, Ordering::Relaxed);
            let Some(range) = self.ranges.get(i).copied() else {
                return Ok(());
            };
            let mut last = MinerAgentError::Backup("range-send");
            let mut done = false;
            for attempt in 0..DOWNLOAD_ATTEMPTS {
                if attempt > 0 {
                    tokio::time::sleep(retry_pause(attempt)).await;
                }
                let mut counted = 0u64;
                match self.fetch(&mut f, range, &mut counted).await {
                    Ok(()) => {
                        done = true;
                        break;
                    }
                    Err(e) => {
                        self.progress.fetch_sub(counted, Ordering::Relaxed);
                        last = e;
                    }
                }
            }
            if !done {
                return Err(last);
            }
        }
    }

    async fn fetch(
        &self,
        f: &mut tokio::fs::File,
        range: ByteRange,
        counted: &mut u64,
    ) -> Result<()> {
        let end = range.offset + range.len - 1;
        let mut resp = self
            .client
            .get(&self.url)
            .header(
                reqwest::header::RANGE,
                format!("bytes={}-{end}", range.offset),
            )
            .timeout(range_timeout(range.len))
            .send()
            .await
            .map_err(|_| MinerAgentError::Backup("range-send"))?;
        let status = resp.status();
        let partial = status == reqwest::StatusCode::PARTIAL_CONTENT;
        if !(partial || (self.whole && status == reqwest::StatusCode::OK)) {
            return Err(MinerAgentError::Backup("range-status"));
        }
        if partial {
            // `bytes <start>-<end>/<total>`: the store must answer the
            // range asked, of the object recorded, not a neighbour.
            let content_range = resp
                .headers()
                .get(reqwest::header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok());
            let want = format!("bytes {}-{end}/{}", range.offset, self.size);
            if content_range != Some(want.as_str()) {
                return Err(MinerAgentError::Backup("range-mismatch"));
            }
        }
        if resp.content_length().is_some_and(|l| l != range.len) {
            return Err(MinerAgentError::Backup("range-size"));
        }
        f.seek(SeekFrom::Start(range.offset))
            .await
            .map_err(|_| MinerAgentError::Backup("get-write"))?;
        let mut hasher = Sha256::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|_| MinerAgentError::Backup("range-read"))?
        {
            let n = chunk.len() as u64;
            if *counted + n > range.len {
                return Err(MinerAgentError::Backup("range-size"));
            }
            hasher.update(&chunk);
            f.write_all(&chunk)
                .await
                .map_err(|_| MinerAgentError::Backup("get-write"))?;
            *counted += n;
            self.progress.fetch_add(n, Ordering::Relaxed);
        }
        if *counted != range.len {
            return Err(MinerAgentError::Backup("range-size"));
        }
        f.flush()
            .await
            .map_err(|_| MinerAgentError::Backup("get-write"))?;
        if let Some(want) = range.sha256 {
            let got: [u8; 32] = hasher.finalize().into();
            if got != want {
                return Err(MinerAgentError::Backup("range-sha-mismatch"));
            }
        }
        Ok(())
    }
}

/// sha256 of the first `size` bytes of `path` (exactly `size` must be
/// there).
fn hash_file(path: &Path, size: u64) -> Result<[u8; 32]> {
    use std::io::Read;
    let f = std::fs::File::open(path).map_err(|_| MinerAgentError::Backup("hash-read"))?;
    let mut reader = std::io::BufReader::with_capacity(CHUNK, f).take(size);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|_| MinerAgentError::Backup("hash-read"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    if total != size {
        return Err(MinerAgentError::Backup("size-mismatch"));
    }
    Ok(hasher.finalize().into())
}

/// Adapt a bounded reader into a body stream that feeds both hashers.
fn hashing_stream(
    reader: tokio::io::Take<tokio::fs::File>,
    hashers: Arc<Mutex<(Sha256, Sha256)>>,
) -> impl futures_util::Stream<Item = std::io::Result<bytes::Bytes>> + Send + 'static {
    use futures_util::StreamExt;
    tokio_util::io::ReaderStream::with_capacity(reader, CHUNK).map(move |chunk| {
        if let (Ok(b), Ok(mut g)) = (&chunk, hashers.lock()) {
            g.0.update(b);
            g.1.update(b);
        }
        chunk
    })
}

/// Parse a 64-char hex sha256.
pub fn parse_sha256_hex(s: &str) -> Option<[u8; 32]> {
    let v = hex::decode(s).ok()?;
    v.try_into().ok()
}

#[cfg(test)]
pub(crate) mod test_server {
    //! A local HTTP stand-in for S3 presigned URLs.

    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use axum::body::Bytes;
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::put;
    use axum::Router;

    /// Every GET served: (key, Range header).
    pub(crate) type GetLog = Arc<Mutex<Vec<(String, Option<String>)>>>;

    /// Stored objects by key, and a counter of failures to inject.
    #[derive(Clone, Default)]
    pub(crate) struct Store {
        pub(crate) objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        pub(crate) fail_next: Arc<Mutex<u32>>,
        /// GETs whose body gets one byte flipped (per key-and-offset),
        /// and how many more times: a corrupted range that heals on retry
        /// (1) or never does (`u32::MAX`).
        pub(crate) corrupt: Arc<Mutex<HashMap<(String, u64), u32>>>,
        /// Every GET served.
        pub(crate) gets: GetLog,
        /// Artificial per-GET delay (default none): widens the window a
        /// test can poll a staging's progress mid-flight, without making
        /// every other test using this server slower.
        pub(crate) get_delay: Arc<Mutex<std::time::Duration>>,
    }

    async fn put_obj(
        State(st): State<Store>,
        Path(key): Path<String>,
        body: Bytes,
    ) -> impl IntoResponse {
        {
            let mut f = st.fail_next.lock().unwrap();
            if *f > 0 {
                *f -= 1;
                return (StatusCode::INTERNAL_SERVER_ERROR, [("etag", String::new())]);
            }
        }
        let etag = format!("\"etag-{key}-{}\"", body.len());
        st.objects.lock().unwrap().insert(key, body.to_vec());
        (StatusCode::OK, [("etag", etag)])
    }

    async fn get_obj(
        State(st): State<Store>,
        Path(key): Path<String>,
        headers: axum::http::HeaderMap,
    ) -> axum::response::Response {
        let range = headers
            .get("range")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        st.gets.lock().unwrap().push((key.clone(), range.clone()));
        let delay = *st.get_delay.lock().unwrap();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let Some(body) = st.objects.lock().unwrap().get(&key).cloned() else {
            return (StatusCode::NOT_FOUND, Vec::new()).into_response();
        };
        let (status, start, mut slice, content_range) = match range
            .as_deref()
            .and_then(|r| r.strip_prefix("bytes="))
            .and_then(|r| r.split_once('-'))
        {
            Some((a, b)) => {
                let a: usize = a.parse().unwrap();
                let b: usize = b.parse::<usize>().unwrap().min(body.len() - 1);
                (
                    StatusCode::PARTIAL_CONTENT,
                    a as u64,
                    body[a..=b].to_vec(),
                    Some(format!("bytes {a}-{b}/{}", body.len())),
                )
            }
            None => (StatusCode::OK, 0, body, None),
        };
        {
            let mut c = st.corrupt.lock().unwrap();
            if let Some(n) = c.get_mut(&(key.clone(), start)) {
                if *n > 0 {
                    *n -= 1;
                    slice[0] ^= 0xff;
                }
            }
        }
        let mut resp = (status, slice).into_response();
        if let Some(cr) = content_range {
            resp.headers_mut()
                .insert("content-range", cr.parse().unwrap());
        }
        resp
    }

    /// Serve on an ephemeral port; returns the base URL.
    pub(crate) async fn start(store: Store) -> String {
        let app = Router::new()
            .route("/o/:key", put(put_obj).get(get_obj))
            .layer(axum::extract::DefaultBodyLimit::disable())
            .with_state(store);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/o")
    }
}

#[cfg(test)]
mod tests {
    use super::test_server::{start, Store};
    use super::*;
    use std::io::Write;

    fn file_with(bytes: &[u8]) -> std::fs::File {
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(bytes).unwrap();
        f
    }

    #[test]
    fn timeouts_scale_with_size() {
        assert_eq!(transfer_timeout(0), TRANSFER_BASE_TIMEOUT);
        // A 1 TiB full gets ~29 h, not a flat hour.
        assert!(transfer_timeout(1 << 40) > Duration::from_secs(24 * 3600));
    }

    #[test]
    fn part_math() {
        assert_eq!(part_count(0, MIN_PART_SIZE), 0);
        assert_eq!(part_count(1, MIN_PART_SIZE), 1);
        assert_eq!(part_count(MIN_PART_SIZE, MIN_PART_SIZE), 1);
        assert_eq!(part_count(MIN_PART_SIZE + 1, MIN_PART_SIZE), 2);
        assert!(check_part_size(MIN_PART_SIZE - 1).is_err());
        assert!(check_part_size(MAX_PART_SIZE + 1).is_err());
        check_part_size(256 << 20).unwrap();
        check_part_size(512 << 20).unwrap();
        // hippius-s3 refuses a part over 512 MiB (`EntityTooLarge`).
        assert!(check_part_size((512 << 20) + 1).is_err());
    }

    #[tokio::test]
    async fn parts_reassemble_to_the_file_and_hashes_match() {
        let store = Store::default();
        let base = start(store.clone()).await;
        let data: Vec<u8> = (0..(MIN_PART_SIZE * 2 + 12345))
            .map(|i| (i * 7 % 251) as u8)
            .collect();
        let f = file_with(&data);
        let urls: Vec<String> = (1..=4).map(|i| format!("{base}/p{i}")).collect();
        // One transient failure: the retry re-reads the part.
        *store.fail_next.lock().unwrap() = 1;
        let t = Transfer::new().unwrap();
        let r = t
            .upload_parts(&f, data.len() as u64, MIN_PART_SIZE, &urls)
            .await
            .unwrap();
        assert_eq!(r.parts.len(), 3);
        assert_eq!(r.size, data.len() as u64);
        assert_eq!(r.sha256_hex, hex::encode(Sha256::digest(&data)));
        let objs = store.objects.lock().unwrap();
        let mut joined = Vec::new();
        for p in &r.parts {
            let body = &objs[&format!("p{}", p.part_number)];
            assert_eq!(p.sha256_hex, hex::encode(Sha256::digest(body)));
            assert_eq!(p.size, body.len() as u64);
            assert_eq!(
                p.etag,
                format!("\"etag-p{}-{}\"", p.part_number, body.len())
            );
            joined.extend_from_slice(body);
        }
        assert_eq!(joined, data);
        assert!(!objs.contains_key("p4"));
    }

    #[tokio::test]
    async fn too_few_urls_is_refused_up_front() {
        let t = Transfer::new().unwrap();
        let f = file_with(&vec![1u8; (MIN_PART_SIZE + 1) as usize]);
        let err = t
            .upload_parts(&f, MIN_PART_SIZE + 1, MIN_PART_SIZE, &["http://x/1".into()])
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("too-few-part-urls")));
    }

    #[tokio::test]
    async fn download_verifies_and_removes_on_mismatch() {
        let store = Store::default();
        let base = start(store.clone()).await;
        store
            .objects
            .lock()
            .unwrap()
            .insert("k".into(), b"hello".to_vec());
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let t = Transfer::new().unwrap();
        let good = hex::encode(Sha256::digest(b"hello"));
        t.download_verified(&format!("{base}/k"), &good, 5, &dest)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello");
        let bad = hex::encode(Sha256::digest(b"other"));
        let err = t
            .download_verified(&format!("{base}/k"), &bad, 5, &dest)
            .await
            .unwrap_err();
        assert!(matches!(err, MinerAgentError::Backup("sha-mismatch")));
        assert!(!dest.exists());
        // A body longer (or shorter) than recorded is refused.
        for size in [4, 6] {
            let err = t
                .download_verified(&format!("{base}/k"), &good, size, &dest)
                .await
                .unwrap_err();
            assert!(matches!(err, MinerAgentError::Backup("size-mismatch")));
            assert!(!dest.exists());
        }
    }

    /// A raw HTTP/1.1 server that answers one GET with `head_len` as the
    /// Content-Length (none if `None`), writes `body`, then hangs up —
    /// a connection cut mid-object, which a well-formed S3 stand-in cannot
    /// produce.
    async fn serve_cut(head_len: Option<usize>, body: Vec<u8>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let cl = head_len
                        .map(|n| format!("content-length: {n}\r\n"))
                        .unwrap_or_default();
                    let head = format!("HTTP/1.1 200 OK\r\n{cl}connection: close\r\n\r\n");
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        format!("http://{addr}/piece")
    }

    #[tokio::test]
    async fn a_truncated_download_fails_loudly_and_leaves_no_file() {
        // A restore must never build a disk from a short piece: the GET is
        // held to the size vali recorded, and to its sha256.
        let full: Vec<u8> = (0..(1u32 << 20)).map(|i| (i % 251) as u8).collect();
        let size = full.len() as u64;
        let sha = hex::encode(Sha256::digest(&full));
        let half = full[..full.len() / 2].to_vec();
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let t = Transfer::new().unwrap();

        // The whole object comes back intact.
        let url = serve_cut(Some(full.len()), full.clone()).await;
        t.download_verified(&url, &sha, size, &dest).await.unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), full);

        // Connection cut mid-body under a full Content-Length.
        let url = serve_cut(Some(full.len()), half.clone()).await;
        let err = t
            .download_verified(&url, &sha, size, &dest)
            .await
            .unwrap_err();
        assert!(
            matches!(err, MinerAgentError::Backup("get-read")),
            "{err:?}"
        );
        assert!(!dest.exists());

        // No Content-Length (close-delimited): the short body is counted.
        let url = serve_cut(None, half.clone()).await;
        let err = t
            .download_verified(&url, &sha, size, &dest)
            .await
            .unwrap_err();
        assert!(
            matches!(err, MinerAgentError::Backup("size-mismatch")),
            "{err:?}"
        );
        assert!(!dest.exists());

        // A store that reports a short object is refused before any write.
        let url = serve_cut(Some(half.len()), half).await;
        let err = t
            .download_verified(&url, &sha, size, &dest)
            .await
            .unwrap_err();
        assert!(
            matches!(err, MinerAgentError::Backup("size-mismatch")),
            "{err:?}"
        );
        assert!(!dest.exists());
    }

    /// An object of three parts (the last short) and its part shas.
    fn parted() -> (Vec<u8>, Vec<String>) {
        let data: Vec<u8> = (0..(MIN_PART_SIZE * 2 + 12345))
            .map(|i| (i * 13 % 251) as u8)
            .collect();
        let shas = data
            .chunks(MIN_PART_SIZE as usize)
            .map(|c| hex::encode(Sha256::digest(c)))
            .collect();
        (data, shas)
    }

    async fn ranged(
        t: &Transfer,
        url: &str,
        data: &[u8],
        shas: &[String],
        dest: &Path,
        progress: &Arc<AtomicU64>,
    ) -> Result<()> {
        let ranges = plan_ranges(data.len() as u64, MIN_PART_SIZE, shas).unwrap();
        let sha = hex::encode(Sha256::digest(data));
        let object = RangedObject {
            url,
            sha256_hex: &sha,
            size: data.len() as u64,
            ranges,
        };
        t.download_ranged(object, 2, dest, progress).await
    }

    #[tokio::test]
    async fn ranged_download_fetches_each_part_and_reassembles_the_object() {
        let store = Store::default();
        let base = start(store.clone()).await;
        let (data, shas) = parted();
        store
            .objects
            .lock()
            .unwrap()
            .insert("o".into(), data.clone());
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let progress = Arc::new(AtomicU64::new(0));
        let t = Transfer::new().unwrap();
        ranged(&t, &format!("{base}/o"), &data, &shas, &dest, &progress)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), data);
        assert_eq!(progress.load(Ordering::Relaxed), data.len() as u64);
        let mut asked: Vec<String> = store
            .gets
            .lock()
            .unwrap()
            .iter()
            .map(|(_, r)| r.clone().unwrap())
            .collect();
        asked.sort();
        let p = MIN_PART_SIZE;
        let end = data.len() as u64 - 1;
        let mut want = [
            format!("bytes=0-{}", p - 1),
            format!("bytes={}-{}", p, 2 * p - 1),
            format!("bytes={}-{end}", 2 * p),
        ];
        want.sort();
        assert_eq!(asked, want, "one range per recorded part");
    }

    #[tokio::test]
    async fn a_corrupt_range_is_retried_alone_and_heals() {
        let store = Store::default();
        let base = start(store.clone()).await;
        let (data, shas) = parted();
        store
            .objects
            .lock()
            .unwrap()
            .insert("o".into(), data.clone());
        store
            .corrupt
            .lock()
            .unwrap()
            .insert(("o".into(), MIN_PART_SIZE), 2);
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let progress = Arc::new(AtomicU64::new(0));
        let t = Transfer::new().unwrap();
        ranged(&t, &format!("{base}/o"), &data, &shas, &dest, &progress)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), data);
        assert_eq!(
            progress.load(Ordering::Relaxed),
            data.len() as u64,
            "failed attempts take their bytes back"
        );
        let gets = store.gets.lock().unwrap();
        let second = format!("bytes={}-{}", MIN_PART_SIZE, 2 * MIN_PART_SIZE - 1);
        assert_eq!(
            gets.iter()
                .filter(|(_, r)| r.as_deref() == Some(&*second))
                .count(),
            3,
            "the bad range, twice more"
        );
        assert_eq!(gets.len(), 5, "the good ranges once each");
    }

    #[tokio::test]
    async fn a_range_that_never_verifies_fails_the_piece_and_leaves_no_file() {
        let store = Store::default();
        let base = start(store.clone()).await;
        let (data, shas) = parted();
        store
            .objects
            .lock()
            .unwrap()
            .insert("o".into(), data.clone());
        store
            .corrupt
            .lock()
            .unwrap()
            .insert(("o".into(), 0), u32::MAX);
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let t = Transfer::new().unwrap();
        let progress = Arc::new(AtomicU64::new(0));
        let err = ranged(&t, &format!("{base}/o"), &data, &shas, &dest, &progress)
            .await
            .unwrap_err();
        assert!(
            matches!(err, MinerAgentError::Backup("range-sha-mismatch")),
            "{err:?}"
        );
        assert!(!dest.exists());
        let gets = store.gets.lock().unwrap();
        let first = format!("bytes=0-{}", MIN_PART_SIZE - 1);
        assert_eq!(
            gets.iter()
                .filter(|(_, r)| r.as_deref() == Some(&*first))
                .count(),
            DOWNLOAD_ATTEMPTS as usize
        );
    }

    #[tokio::test]
    async fn without_part_shas_the_whole_object_sha_still_decides() {
        let store = Store::default();
        let base = start(store.clone()).await;
        let (data, _) = parted();
        store
            .objects
            .lock()
            .unwrap()
            .insert("o".into(), data.clone());
        store
            .corrupt
            .lock()
            .unwrap()
            .insert(("o".into(), MIN_PART_SIZE), u32::MAX);
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let t = Transfer::new().unwrap();
        let progress = Arc::new(AtomicU64::new(0));
        let err = ranged(&t, &format!("{base}/o"), &data, &[], &dest, &progress)
            .await
            .unwrap_err();
        assert!(
            matches!(err, MinerAgentError::Backup("sha-mismatch")),
            "{err:?}"
        );
        assert!(!dest.exists());
        assert_eq!(
            progress.load(Ordering::Relaxed),
            0,
            "a failed piece takes its bytes back"
        );
    }

    #[tokio::test]
    async fn without_part_shas_a_one_off_bad_range_costs_one_more_pass() {
        let store = Store::default();
        let base = start(store.clone()).await;
        let (data, _) = parted();
        store
            .objects
            .lock()
            .unwrap()
            .insert("o".into(), data.clone());
        store
            .corrupt
            .lock()
            .unwrap()
            .insert(("o".into(), MIN_PART_SIZE), 1);
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let progress = Arc::new(AtomicU64::new(0));
        let t = Transfer::new().unwrap();
        ranged(&t, &format!("{base}/o"), &data, &[], &dest, &progress)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), data);
        assert_eq!(progress.load(Ordering::Relaxed), data.len() as u64);
        assert_eq!(store.gets.lock().unwrap().len(), 6, "two passes of three");
    }

    #[tokio::test]
    async fn a_range_of_another_object_is_refused() {
        // A 206 whose Content-Range names the asked span of an object of
        // another size.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (data, shas) = parted();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let total = data.len() + 1;
        let body = data.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_lowercase();
                    let span = req
                        .split("range: bytes=")
                        .nth(1)
                        .and_then(|r| r.split("\r\n").next())
                        .unwrap_or("0-0")
                        .to_string();
                    let (a, b) = span.split_once('-').unwrap();
                    let (a, b): (usize, usize) = (a.parse().unwrap(), b.parse().unwrap());
                    let head = format!(
                        "HTTP/1.1 206 Partial Content\r\ncontent-range: bytes {a}-{b}/{total}\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n",
                        b - a + 1
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body[a..=b]).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let t = Transfer::new().unwrap();
        let err = ranged(
            &t,
            &format!("http://{addr}/o"),
            &data,
            &shas,
            &dest,
            &Arc::default(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, MinerAgentError::Backup("range-mismatch")),
            "{err:?}"
        );
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn a_store_that_ignores_the_range_is_refused() {
        let (data, shas) = parted();
        let url = serve_cut(Some(data.len()), data.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let t = Transfer::new().unwrap();
        let err = ranged(&t, &url, &data, &shas, &dest, &Arc::default())
            .await
            .unwrap_err();
        assert!(
            matches!(err, MinerAgentError::Backup("range-status")),
            "{err:?}"
        );
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn the_single_stream_retries_a_corrupt_object() {
        let store = Store::default();
        let base = start(store.clone()).await;
        store
            .objects
            .lock()
            .unwrap()
            .insert("k".into(), b"hello".to_vec());
        store.corrupt.lock().unwrap().insert(("k".into(), 0), 1);
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let t = Transfer::new().unwrap();
        t.download_verified(
            &format!("{base}/k"),
            &hex::encode(Sha256::digest(b"hello")),
            5,
            &dest,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello");
        assert_eq!(store.gets.lock().unwrap().len(), 2);
    }

    #[test]
    fn range_plans_follow_the_recorded_parts() {
        let one = hex::encode([1u8; 32]);
        let r = plan_ranges(
            MIN_PART_SIZE + 1,
            MIN_PART_SIZE,
            &[one.clone(), one.clone()],
        )
        .unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!((r[1].offset, r[1].len), (MIN_PART_SIZE, 1));
        assert_eq!(r[0].sha256, Some([1u8; 32]));
        assert!(
            plan_ranges(MIN_PART_SIZE + 1, MIN_PART_SIZE, &[]).unwrap()[0]
                .sha256
                .is_none()
        );
        for (size, part, shas, class) in [
            (10, 1u64, vec![], "part-size"),
            (
                MIN_PART_SIZE + 1,
                MIN_PART_SIZE,
                vec![one.clone()],
                "part-sha-count",
            ),
            (1, MIN_PART_SIZE, vec!["zz".repeat(32)], "bad-part-sha"),
            (0, MIN_PART_SIZE, vec![], "empty-piece"),
        ] {
            let err = plan_ranges(size, part, &shas).unwrap_err();
            assert!(
                matches!(err, MinerAgentError::Backup(c) if c == class),
                "{err:?}"
            );
        }
        assert_eq!(clamp_streams(0), 1);
        assert_eq!(clamp_streams(8), 8);
        assert_eq!(clamp_streams(200), MAX_STREAMS);
        // A 512 MiB range gets 600 s + ~102 s.
        assert_eq!(range_timeout(512 << 20), Duration::from_secs(702));
    }

    #[tokio::test]
    async fn small_put_reports_its_hash() {
        let store = Store::default();
        let base = start(store.clone()).await;
        let t = Transfer::new().unwrap();
        let r = t
            .put_small(&format!("{base}/s"), vec![9u8; 1024])
            .await
            .unwrap();
        assert_eq!(r.size, 1024);
        assert_eq!(r.sha256_hex, hex::encode(Sha256::digest([9u8; 1024])));
        assert_eq!(store.objects.lock().unwrap()["s"], vec![9u8; 1024]);
    }
}
