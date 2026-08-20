//! `hippius-image-provenance` CLI — §11/§22 signed image provenance.
//!
//! Three subcommands:
//!
//! * `sign` — build a provenance map from a `hippius-uki-measure`
//!   envelope + the artifact, Ed25519-sign it with the §22 root key,
//!   write a `provenance.cbor` envelope.
//! * `verify` — decode + verify a `provenance.cbor` against the §22
//!   root public key, print the bound provenance.
//! * `publish` — verify, then idempotently push the artifact + its
//!   provenance to the Hippius S3 image bucket.
//!
//! `sign` is offline-capable (the production §22 root is air-gapped);
//! `publish` is the online CI step.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use hippius_image_provenance::build::{build_provenance, read_artifact, BuildInputs};
use hippius_image_provenance::measurement::MeasurementEnvelope;
use hippius_image_provenance::publish::publish;
use hippius_image_provenance::sign::{
    load_signing_key, load_verifying_key, public_key_bytes, sign_provenance, verify_provenance,
};
use hippius_image_provenance::store::HippiusS3ImageStore;
use hippius_image_provenance::Error;
use hippius_types::provenance::{ProvenanceMap, SignedProvenance};

#[derive(Parser)]
#[command(
    name = "hippius-image-provenance",
    version,
    about = "§11/§22 signed image provenance"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build + Ed25519-sign a provenance map into a `provenance.cbor`.
    Sign(SignArgs),
    /// Verify a `provenance.cbor` against the §22 root public key.
    Verify(VerifyArgs),
    /// Verify, then idempotently push artifact + provenance to S3.
    Publish(PublishArgs),
}

#[derive(Parser)]
struct SignArgs {
    /// Path to the `hippius-uki-measure` JSON envelope (SNP build).
    #[arg(long)]
    measurement: PathBuf,
    /// Path to the measured artifact (the signed UKI PE binary).
    #[arg(long)]
    artifact: PathBuf,
    /// Path to the §22 root signing key (64-hex-char Ed25519 seed).
    #[arg(long)]
    signing_key: PathBuf,
    /// Target S3 bucket for the content-addressed image.
    #[arg(long, default_value = "hippius-compute-images")]
    bucket: String,
    /// Build timestamp (Unix seconds) — an explicit input, NOT the
    /// wall clock, so a re-sign of the same image is byte-reproducible
    /// (pass `SOURCE_DATE_EPOCH`, as the rest of the §F build does).
    #[arg(long)]
    built_at: u64,
    /// Where to write the signed `provenance.cbor` envelope.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Parser)]
struct VerifyArgs {
    /// Path to the signed `provenance.cbor` envelope.
    #[arg(long)]
    provenance: PathBuf,
    /// Path to the §22 root public key (64-hex-char Ed25519 key).
    #[arg(long)]
    root_pubkey: PathBuf,
}

#[derive(Parser)]
struct PublishArgs {
    /// Path to the signed `provenance.cbor` envelope.
    #[arg(long)]
    provenance: PathBuf,
    /// Path to the artifact to publish (must match the provenance).
    #[arg(long)]
    artifact: PathBuf,
    /// Path to the §22 root public key — provenance is re-verified
    /// before anything is pushed.
    #[arg(long)]
    root_pubkey: PathBuf,
    /// Target S3 bucket.
    #[arg(long, default_value = "hippius-compute-images")]
    bucket: String,
    /// Hippius S3 API endpoint URL.
    #[arg(long)]
    s3_endpoint: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Sign(args) => run_sign(args),
        Command::Verify(args) => run_verify(args),
        Command::Publish(args) => run_publish(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hippius-image-provenance: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_sign(args: SignArgs) -> Result<(), Error> {
    let signing_key = load_signing_key(&args.signing_key)?;
    let signer_pubkey = public_key_bytes(&signing_key);

    let envelope = MeasurementEnvelope::load(&args.measurement)?;
    let artifact_bytes = read_artifact(&args.artifact)?;

    let map = build_provenance(&BuildInputs {
        envelope: &envelope,
        artifact_bytes: &artifact_bytes,
        s3_bucket: &args.bucket,
        built_at_unix: args.built_at,
        signer_pubkey,
    })?;

    let signed = sign_provenance(&signing_key, &map)?;
    let bytes = signed.encode()?;
    std::fs::write(&args.out, &bytes).map_err(|source| Error::Write {
        path: args.out.clone(),
        source,
    })?;

    println!("signed provenance written: {}", args.out.display());
    print_map(&map);
    println!("  envelope_bytes     {}", bytes.len());
    Ok(())
}

fn run_verify(args: VerifyArgs) -> Result<(), Error> {
    let bytes = std::fs::read(&args.provenance).map_err(|source| Error::Read {
        path: args.provenance.clone(),
        source,
    })?;
    let signed = SignedProvenance::decode(&bytes)?;
    let root = load_verifying_key(&args.root_pubkey)?;
    let map = verify_provenance(&signed, &root)?;

    println!("provenance signature OK ({})", args.provenance.display());
    print_map(&map);
    Ok(())
}

fn run_publish(args: PublishArgs) -> Result<(), Error> {
    let bytes = std::fs::read(&args.provenance).map_err(|source| Error::Read {
        path: args.provenance.clone(),
        source,
    })?;
    let signed = SignedProvenance::decode(&bytes)?;
    let root = load_verifying_key(&args.root_pubkey)?;

    // Decode (not yet trusted) only to read the declared target
    // bucket; `publish` performs the authoritative signature check.
    let declared = ProvenanceMap::decode(&signed.body)?;
    if declared.s3_bucket != args.bucket {
        return Err(Error::ArtifactMismatch(format!(
            "provenance s3_bucket {:?} does not match --bucket {:?}",
            declared.s3_bucket, args.bucket
        )));
    }
    let artifact_bytes = read_artifact(&args.artifact)?;

    let store = HippiusS3ImageStore::new(args.bucket.clone(), args.s3_endpoint.clone())?;
    let report = publish(&store, &signed, &artifact_bytes, &root)?;

    println!("published to bucket {} ({})", args.bucket, args.s3_endpoint);
    println!(
        "  artifact   {} [{:?}]",
        report.artifact_key, report.artifact.outcome
    );
    println!(
        "  provenance {} [{:?}]",
        report.provenance_key, report.provenance.outcome
    );
    if report.was_already_published() {
        println!("  (image was already published — idempotent no-op)");
    }
    Ok(())
}

/// Print a provenance map as a human-auditable block — the §22
/// ceremony operator eyeballs this before trusting a signature.
fn print_map(map: &ProvenanceMap) {
    println!("  schema_version     {}", map.schema_version);
    println!("  measurement_kind   {}", map.measurement_kind);
    println!(
        "  launch_measurement {}",
        hex::encode(map.launch_measurement)
    );
    println!("  artifact_sha256    {}", hex::encode(map.artifact_sha256));
    println!("  verity_root_hash   {}", hex::encode(map.verity_root_hash));
    println!("  kernel_sha256      {}", hex::encode(map.kernel_sha256));
    println!("  initrd_sha256      {}", hex::encode(map.initrd_sha256));
    println!("  cmdline_sha256     {}", hex::encode(map.cmdline_sha256));
    println!("  ovmf_sha256        {}", hex::encode(map.ovmf_sha256));
    println!(
        "  snp_launch_config  vcpus={} vcpu_type={} guest_features={}",
        map.snp_launch_config.vcpus,
        map.snp_launch_config.vcpu_type,
        map.snp_launch_config.guest_features,
    );
    println!("  s3_bucket          {}", map.s3_bucket);
    println!("  s3_key             {}", map.s3_key);
    println!("  built_at_unix      {}", map.built_at_unix);
    println!("  signer_pubkey      {}", hex::encode(map.signer_pubkey));
}
