//! `miner-uki-fetch` CLI — pull + §22-verify + atomically install a UKI.
//!
//! ```text
//! miner-uki-fetch --hash <sha256-hex> --output <path> [--cache-dir <path>]
//! ```
//!
//! `--hash` is the UKI's **SHA-256** — its content address in the
//! Hippius image bucket (ARCHITECTURE.md §11; issue #41 §F: "verify
//! SHA-256 vs signed provenance before boot"). The tool fails closed
//! on any hash or signature mismatch and never installs a partial file.
//!
//! ## Hippius S3 backend
//!
//! `HippiusS3ImageStore` is wired against the live `s3.hippius.com`
//! image bucket (PR-F UKI build pins + publish). The fetch + verify +
//! atomic-install pipeline reads its `get()` directly: a single
//! `GET <endpoint>/<bucket>/<key>` against the public-read `images/`
//! prefix — no miner-side credentials are needed. Writes are
//! operator-only (the §22 publish path holds those creds).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use hippius_image_provenance::store::HippiusS3ImageStore;
use hippius_miner_uki_fetch::{fetch, Error, FetchOutcome, Result};
use hippius_types::provenance::SHA256_LEN;

/// The Hippius S3 image bucket (ARCHITECTURE.md §11) — a fixed name.
const IMAGE_BUCKET: &str = "hippius-compute-images";

#[derive(Parser)]
#[command(
    name = "miner-uki-fetch",
    version,
    about = "Miner-side UKI fetch with §22 provenance verification + atomic install"
)]
struct Cli {
    /// SHA-256 of the UKI to fetch (64 hex chars) — its content address.
    #[arg(long)]
    hash: String,
    /// Where to install the verified UKI.
    #[arg(long)]
    output: PathBuf,
    /// Optional local content-addressed cache directory — a cached
    /// UKI whose hash matches is reused instead of re-downloading.
    #[arg(long)]
    cache_dir: Option<PathBuf>,
    /// Hippius S3 API endpoint. The image bucket is anonymous-readable
    /// on the `images/` prefix (writer-only ACL) — no miner-side creds.
    #[arg(long, default_value = "https://s3.hippius.com")]
    s3_endpoint: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("miner-uki-fetch: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    let requested = parse_hash(&cli.hash)?;
    let store =
        HippiusS3ImageStore::new(IMAGE_BUCKET, cli.s3_endpoint.clone()).map_err(Error::Store)?;
    let outcome = fetch(&store, &requested, &cli.output, cli.cache_dir.as_deref())?;

    let out = cli.output.display();
    match outcome {
        FetchOutcome::AlreadyPresent => {
            println!("cached: {out} already holds the requested UKI (sha256 match) — skipped");
        }
        FetchOutcome::FetchedFromCache => {
            println!("installed {out} from the local cache (§22-verified)");
        }
        FetchOutcome::FetchedFromStore => {
            println!("installed {out} from {IMAGE_BUCKET} (§22-verified)");
        }
    }
    Ok(())
}

/// Parse `--hash` into a 32-byte SHA-256.
fn parse_hash(s: &str) -> Result<[u8; SHA256_LEN]> {
    let bytes = hex::decode(s.trim()).map_err(|_| Error::HashArg("not valid hex".into()))?;
    bytes.as_slice().try_into().map_err(|_| {
        Error::HashArg(format!(
            "must be a {SHA256_LEN}-byte SHA-256 ({} hex chars), got {} bytes",
            SHA256_LEN * 2,
            bytes.len()
        ))
    })
}
