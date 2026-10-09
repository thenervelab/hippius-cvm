//! Crate error type — [`MinerAgentError`].
//!
//! Every variant's `Display` is a fixed `&'static str` classifier (the
//! §H `EdgeError` discipline): a structured-log line, or a bare
//! `eprintln!("{err}")`, can never echo a filesystem path, a key byte,
//! or any other run-time value. A few variants carry a second
//! `&'static str` sub-classifier — also compile-time-constant, so it
//! is still leak-free. Callers that need the underlying detail walk
//! `std::error::Error::source()`.
//!
//! Every variant is **fail-closed**: there is no path that downgrades
//! an error into a partial success.

/// Result alias for the crate.
pub type Result<T> = std::result::Result<T, MinerAgentError>;

/// Anything that can go wrong in the miner-agent.
#[derive(Debug, thiserror::Error)]
pub enum MinerAgentError {
    /// The operator config file could not be read.
    #[error("config-read")]
    ConfigRead(#[source] std::io::Error),

    /// The operator config file is not valid TOML.
    ///
    /// Carries the 1-based line and column, and NOTHING else. The
    /// classifier alone is unactionable — a first-time operator whose
    /// config has one unfilled placeholder gets `config-parse` and no
    /// way to find it — but `toml::de::Error`'s own Display quotes the
    /// offending source line back at you, which is exactly the run-time
    /// content this error type refuses to echo. A coordinate is not
    /// content: it says where to look without saying what is there.
    #[error("config-parse/line {line} col {col}")]
    ConfigParse { line: usize, col: usize },

    /// The config parsed but a field is unusable. The sub-classifier
    /// names the field — a compile-time constant, never user input.
    #[error("config-invalid/{0}")]
    ConfigInvalid(&'static str),

    /// `init-identity` found an existing key and `--force` was not
    /// given — refusing to overwrite is the idempotent, safe default.
    #[error("identity-exists")]
    IdentityExists,

    /// An identity key file was expected but is absent — the operator
    /// must run `init-identity` first.
    #[error("identity-missing")]
    IdentityMissing,

    /// The OS CSPRNG failed to produce a seed.
    #[error("identity-keygen")]
    IdentityKeygen,

    /// An on-disk identity file is malformed. The sub-classifier names
    /// *which* check failed; it never echoes key bytes.
    #[error("identity-parse/{0}")]
    IdentityParse(&'static str),

    /// Minting the self-signed mTLS client cert from the identity key
    /// failed (the permissionless Edge auth path).
    #[error("identity-cert/{0}")]
    IdentityCert(&'static str),

    /// A `sign-registration` CLI argument was malformed (a family /
    /// child AccountId that was not 32 bytes of hex).
    #[error("registration-arg/{0}")]
    RegistrationArg(&'static str),

    /// A filesystem operation failed.
    #[error("io")]
    Io(#[from] std::io::Error),

    /// The `--hash` argument was not a 64-char lowercase-hex SHA-256.
    /// The sub-classifier is `length` or `hex`.
    #[error("hash-arg/{0}")]
    HashArg(&'static str),

    /// The miner-uki-fetch fetch + §22-verify pipeline failed closed.
    #[error("image-fetch")]
    ImageFetch(#[from] hippius_miner_uki_fetch::Error),

    /// `HippiusS3ImageStore::new` failed at construction time — the
    /// `reqwest::Client` builder rejected the TLS configuration. A
    /// boot-fatal condition; the agent cannot relay images without it.
    #[error("image-store")]
    ImageStore(#[from] hippius_image_provenance::error::ImageStoreError),

    /// A CVM launch was requested for a `VmId` the lifecycle is
    /// already tracking. `launch` is idempotent — the second call is
    /// refused, never a double-spawn.
    #[error("cvm-already-launched")]
    AlreadyLaunched,

    /// A `stop` / `query` named a `VmId` the lifecycle is not
    /// tracking.
    #[error("cvm-not-found")]
    VmNotFound,

    /// A `stop` was requested for a CVM whose launch is still in
    /// flight (`LaunchPrep` / `Launching`). The launching task owns
    /// teardown — a concurrent stop is refused so it cannot race the
    /// launch and orphan a running domain.
    #[error("cvm-busy")]
    CvmBusy,

    /// Launching the CVM would overcommit the host's accounted CPU or
    /// memory — or the accounting arithmetic itself would overflow.
    /// Fail closed: a confidential host is never overcommitted.
    #[error("cvm-insufficient-resources")]
    InsufficientResources,

    /// Launching the CVM would overcommit the host's tenant DISK: the
    /// declared `[host] cvm_disk_gb_budget`, or the measured free space of
    /// `[storage] data_disk_root` net of every existing disk's unwritten
    /// sparse tail. A distinct class from [`Self::InsufficientResources`]
    /// so vali can tell a full disk from a full host (and from a SEV start
    /// failure), re-place, and account it as a capacity event.
    #[error("cvm-insufficient-disk")]
    InsufficientDisk,

    /// A `LaunchOrder` / `QemuConfig` field is unusable. The
    /// sub-classifier names which check failed — a compile-time
    /// constant, never an echoed path or run-time value.
    #[error("cvm-launch-input/{0}")]
    LaunchInput(&'static str),

    /// The pre-flight SEV-SNP launch-digest computation failed. The
    /// sub-classifier is `feature-disabled` (the binary was built
    /// without `--features snp`), `sev-compute` (the `sev` crate
    /// rejected the launch inputs), or `digest-shape` (the result was
    /// not a 48-byte digest). A launch never proceeds past this.
    #[error("cvm-launch-digest/{0}")]
    LaunchDigest(&'static str),

    /// A `tenant-preflight` order step failed. The sub-classifier is
    /// one of: `ovmf-missing`, `cpu-count-zero`, `staging-mkdir`,
    /// `bad-sha256-hex`, `fetch-network`, `fetch-http-status`,
    /// `fetch-body`, `sha256-mismatch`, `stage-{create,write,sync,rename}`,
    /// `json-encode`, or `digest-shape`. Never echoes the presigned
    /// URL or the bytes.
    #[error("tenant-preflight/{0}")]
    Preflight(&'static str),

    /// A libvirt driver operation failed. The sub-classifier names the
    /// operation (`virsh-spawn`, `define`, `create`, `destroy`,
    /// `domstate`, `list`, `state-parse`, `name-parse`); it never
    /// echoes the domain XML, a path, or raw virsh output.
    #[error("libvirt-driver/{0}")]
    LibvirtDriver(&'static str),

    /// The domain was defined and created but did not reach the
    /// running state. The sub-classifier is `timeout` (the poll
    /// deadline elapsed), `domain-error` (libvirt reported a failed or
    /// crashed domain), `rng` (the domain-UUID CSPRNG draw failed), or
    /// `teardown` (a stop could not be confirmed).
    #[error("cvm-launch-failed/{0}")]
    LaunchFailed(&'static str),

    /// No AF_VSOCK context id could be assigned to a CVM (MA-4). The
    /// sub-classifier is `exhausted` — the deterministic guest-CID
    /// range is full. A launch fails closed here, before any `virsh`
    /// call, rather than booting a CVM with no host relay channel.
    #[error("cvm-vsock-cid/{0}")]
    VsockCid(&'static str),

    /// A CVM `destroy` (§24 decommission) could not complete its
    /// capacity-reclaim step. The sub-classifier is `disk-remove` —
    /// the LUKS ciphertext file could not be unlinked. The domain is
    /// already stopped; only the disk free-up failed (the cryptographic
    /// erase is the Vault KEK-destroy, vali's job — never the miner's).
    #[error("cvm-destroy/{0}")]
    Destroy(&'static str),

    /// A `CvmLifecycle` internal lock was poisoned by a panicking
    /// thread — fail closed rather than operate on possibly-torn
    /// handle state.
    #[error("lock-poisoned")]
    LockPoisoned,

    /// A subsystem deliberately not wired until a later MA-* PR was
    /// invoked (the Edge mTLS client — [`crate::edge_client`]).
    /// Returned so a caller fails closed rather than silently
    /// proceeding on a no-op.
    #[error("not-yet-wired")]
    NotYetWired,

    /// Building a [`crate::heartbeat::MinerHeartbeat`] failed (PR-MA-6).
    /// The sub-classifier names the step: `metrics` (a `/proc` source
    /// read failed), `lifecycle` (the CVM phase query failed),
    /// `encode` (the canonical-CBOR encode failed), `clock` (the host
    /// clock is before the Unix epoch). A compile-time constant.
    #[error("heartbeat-build/{0}")]
    HeartbeatBuild(&'static str),

    /// The persisted heartbeat sequence counter could not be read or
    /// written (PR-MA-6). The sub-classifier is `read`, `write`, or
    /// `parse` — a compile-time constant; it never echoes the path or
    /// the counter value.
    #[error("heartbeat-sequence/{0}")]
    HeartbeatSequence(&'static str),

    /// A `net-policy` order failed its shape checks. The sub-classifier
    /// names the field (`region`, `ip`, `vm-caps`, …).
    #[error("net-policy-invalid/{0}")]
    NetPolicyInvalid(&'static str),

    /// A `net-policy` order is past its `not_after_unix`.
    #[error("net-policy-expired")]
    NetPolicyExpired,

    /// A `net-policy` order carries a lower revision than the one
    /// persisted (a replay of an older policy).
    #[error("net-policy-stale-revision")]
    NetPolicyStaleRevision,

    /// A `net-policy` order carries the persisted revision with other
    /// content.
    #[error("net-policy-revision-conflict")]
    NetPolicyRevisionConflict,

    /// The persisted net policy could not be read, parsed or written.
    /// The sub-classifier is `read`, `parse`, `encode`, `write`, `sync`,
    /// `schema` or `lock`.
    #[error("net-policy-store/{0}")]
    NetPolicyStore(&'static str),

    /// A `net-policy` order asks for something this agent cannot apply.
    /// The sub-classifier is `edge-mode` (edge-mode rules are not
    /// rendered by this agent version).
    #[error("net-policy-unsupported/{0}")]
    NetPolicyUnsupported(&'static str),

    /// The persisted net policy could not be installed on the host. The
    /// sub-classifier is `uplink` (no usable uplink interface), `tap`
    /// (a tap name or MAC failed its charset check), `nft` (the
    /// ruleset load failed; the previous one stays in place) or
    /// `persist` (the loaded ruleset could not be saved for the boot
    /// loader).
    #[error("net-policy-apply/{0}")]
    NetPolicyApply(&'static str),

    /// Launch and migrate-in refused: an edge-mode net policy is
    /// persisted but its rules are not loaded on this host.
    #[error("net-policy-not-loaded")]
    NetPolicyNotLoaded,

    /// The heartbeat pusher's mTLS Edge client could not be built
    /// (PR-MA-6) — a bad CA / client cert / key, or a `reqwest`
    /// builder failure. The sub-classifier is `ca`, `client-identity`,
    /// or `build`. A compile-time constant.
    #[error("heartbeat-client/{0}")]
    HeartbeatClient(&'static str),

    /// Relaying a guest envelope (a tenant served-delivery receipt) to
    /// the Edge failed (MA-3). The sub-classifier is `transport` (the
    /// mTLS POST could not be sent / no response) or `rejected` (the
    /// Edge answered non-2xx). A compile-time constant — never echoes the
    /// opaque guest body or the URL.
    #[error("edge-relay/{0}")]
    EdgeRelay(&'static str),

    /// The host→guest vsock push of the L1-minted `OrderTicket` COSE
    /// envelope (`hippius_types::ticket_vsock::PORT`) could not
    /// complete. Sub-classifiers — all compile-time `&'static str`,
    /// never an echoed COSE byte or a tenant path:
    /// `empty` (LaunchOrder carried an empty `cose_ticket` — a
    /// producer bug); `oversize` (COSE exceeds
    /// `ticket_vsock::MAX_TICKET_BYTES`); `no-cid` (the lifecycle
    /// never allocated a CID for this `vm_id` — a launch-ordering
    /// bug); `connect-timeout` (the guest listener did not come up
    /// inside `ticket_vsock::PUSH_TIMEOUT_SECS`); `write-failed` (the
    /// connection came up but the framed write errored).
    #[error("ticket-delivery/{0}")]
    TicketDelivery(&'static str),

    /// §25 migration **M1** — a source-side quiesce or snapshot step
    /// failed. Sub-classifiers — all compile-time `&'static str`, never
    /// an echoed path, presigned URL, or disk byte:
    ///
    /// - `quiesce-stop`: the clean stop of the source guest could not
    ///   be confirmed (libvirt fault). The volume may not be static, so
    ///   the snapshot must not proceed — fail closed.
    /// - `not-quiesced`: a snapshot was requested for a `vm_id` that was
    ///   not first quiesced (no recorded migration state). The source
    ///   guest may still be writing — refused.
    /// - `disk-missing`: the writable LUKS volume path is not known for
    ///   this `vm_id` (the lifecycle never tracked it, or it was already
    ///   reclaimed).
    /// - `disk-open`: the on-disk LUKS volume could not be opened for
    ///   reading.
    /// - `upload-client`: the `reqwest` client for the S3 PUT could not
    ///   be built.
    /// - `upload-send`: the streaming PUT to the presigned URL failed to
    ///   send / dial.
    /// - `upload-status`: S3 answered a non-2xx status to the PUT.
    ///
    /// §25 migration **M2** (destination activation) sub-classifiers:
    /// - `download-client`: the `reqwest` client for the S3 GET could
    ///   not be built.
    /// - `download-send`: the streaming GET from the presigned URL
    ///   failed to dial / send.
    /// - `download-status`: S3 answered a non-2xx status to the GET.
    /// - `download-write`: writing the streamed ciphertext to the dest
    ///   disk failed (create / write / sync / rename).
    /// - `download-read`: reading a chunk from the S3 response stream
    ///   failed mid-transfer.
    /// - `dest-artifacts-missing`: a required pre-staged boot artifact
    ///   (OVMF / kernel / initrd) is absent on the destination host. M2
    ///   requires them pre-staged (M3 wires the staging); the dest fails
    ///   closed rather than booting a half-provisioned domain.
    /// - `disk-path-invalid`: the dest `luks_disk_path` is empty or has
    ///   no parent directory (a producer bug).
    /// - `dest-launch-failed`: the libvirt domain recreate on the dest
    ///   (the launch path) failed after a successful snapshot download.
    #[error("migration/{0}")]
    Migration(&'static str),

    /// `request-graceful-exit` failed. Sub-classifiers (all compile-time
    /// `&'static str`): `encode` (canonical-CBOR of the request/envelope
    /// failed), `runtime` (tokio runtime build failed), `client` (the
    /// `reqwest` client could not be built / the POST failed to send),
    /// `rejected` (vali answered a non-2xx status).
    #[error("graceful-exit/{0}")]
    GracefulExit(&'static str),

    /// Phase 2B of audit follow-up Review #2 — provisioning the per-VM
    /// 1 MiB ext4 state disk that backs the anti-rollback boot counter
    /// failed. Sub-classifiers — all compile-time `&'static str`, never
    /// an echoed path or `mkfs.ext4` stderr line:
    ///
    /// - `mkdir`: could not create the `MINER_ROOT/state/` parent.
    /// - `create`: `OpenOptions::create_new` failed for a reason other
    ///   than AlreadyExists (permission, no-space, …).
    /// - `race`: a concurrent `launch` for the same `vm_id` raced past
    ///   us; the caller fails closed rather than reusing a half-formed
    ///   image.
    /// - `truncate`: `set_len(1 MiB)` failed (most likely ENOSPC).
    /// - `mkfs-spawn`: `mkfs.ext4` could not be exec'd (missing binary
    ///   on the host).
    /// - `mkfs-failed`: `mkfs.ext4` exec'd but exited non-zero.
    /// - `no-parent`: the derived state-disk path lacked a parent
    ///   component (a programmer bug — `state_disk_path` always
    ///   returns `{root}/state/{vm_id}.raw`).
    #[error("state-disk/{0}")]
    StateDisk(&'static str),

    /// #365 — the per-VM tenant **data disk** (`/dev/vde`) could not be
    /// provisioned. A blank sparse raw image the miner attaches at the
    /// flavor size; the guest formats it fresh (LUKS2 + dm-integrity)
    /// with a guest-held key at first boot, so the miner writes no
    /// secret and runs no mkfs. Sub-classifiers — all compile-time
    /// `&'static str`, never an echoed path:
    ///
    /// - `mkdir`: could not create the `data/` subdirectory.
    /// - `create`: `O_CREAT | O_EXCL` open failed (not a race).
    /// - `race`: a concurrent `launch` for the same `vm_id` created the
    ///   file first; the caller fails closed rather than reuse it.
    /// - `truncate`: `set_len(size_gb)` failed (most likely ENOSPC).
    /// - `size-zero`: a data disk was requested with a zero size.
    /// - `size-overflow`: `size_gb * 1 GiB` overflowed `u64`.
    /// - `no-parent`: the derived path lacked a parent component
    ///   (a programmer bug — `data_disk_path` always returns
    ///   `{root}/data/{vm_id}.img`).
    #[error("data-disk/{0}")]
    DataDisk(&'static str),

    /// golden-bake PR3 — the per-VM GOLDEN overlay UPPER disk (the blank
    /// writable volume the guest formats with a guest-generated LUKS
    /// master key at first boot, mirroring the `/dev/vde` data disk).
    /// Same closed-vocabulary sub-classifiers as [`Self::DataDisk`]
    /// (`size-zero` / `size-overflow` / `mkdir` / `statvfs` /
    /// `insufficient-space` / `race` / `create` / `truncate` /
    /// `no-parent`). No secret bytes touch this path — the miner writes
    /// a blank sparse extent; the guest owns the key + every integrity
    /// tag.
    #[error("overlay-disk/{0}")]
    OverlayDisk(&'static str),

    /// A RELAUNCH order (`LaunchOrder::require_existing_disks`) named a
    /// VM whose per-VM disks are NOT on this host. Every `ensure_*`
    /// provisioner creates a BLANK disk when the file is absent — right
    /// for a first launch, a data-death hazard for a relaunch: a blank
    /// state disk resets the anti-rollback boot counter (the KBS then
    /// refuses the release) and a blank golden overlay gets
    /// `luksFormat`ted by the guest the moment a KEK IS released. So a
    /// relaunch refuses before any of them runs, and creates nothing.
    /// The sub-classifier names the FIRST missing disk: `state-disk`,
    /// `overlay` (golden `/dev/vda`) or `data-disk` (legacy `/dev/vde`).
    #[error("relaunch-disks-missing/{0}")]
    RelaunchDisksMissing(&'static str),

    /// A relaunch could not tell whether a per-VM disk is present: the
    /// metadata lookup itself failed (EIO, EACCES, a storage mount not up
    /// yet). NOT [`Self::RelaunchDisksMissing`] — nothing is known to be
    /// absent, so it is retryable and must never make vali give up on the
    /// VM. Same sub-classifiers.
    #[error("relaunch-disks-unreadable/{0}")]
    RelaunchDisksUnreadable(&'static str),

    /// A live VM backup (QMP capture, part upload) or a backup-chain
    /// restore failed. Sub-classifiers are compile-time `&'static str`
    /// (see `crate::backup`); a presigned URL, a path or QEMU's error
    /// text never reaches the Display.
    #[error("backup/{0}")]
    Backup(&'static str),

    /// Issue #116 — `snp_config::SnpCpuConfig::probe` could not read
    /// the SEV-SNP launch parameters from the host CPU's
    /// `CPUID 0x8000001f`. Returned by `QemuConfig::validate` so a
    /// launch is fail-closed at admission instead of producing QEMU
    /// args that the AMD SP would refuse. Sub-classifiers — all
    /// compile-time `&'static str`, never an echoed CPUID value:
    ///
    /// - `cpuid-not-amd`: vendor isn't `AuthenticAMD` (Intel /
    ///   non-x86_64 host).
    /// - `cpuid-leaf-missing`: AMD predates SEV; extended CPUID
    ///   leaf `0x8000001f` not present.
    /// - `cbitpos-zero`: `EBX[5:0]` reports zero — no SEV-capable
    ///   AMD CPU should ever do this; treat as a CPUID lie / VM-
    ///   under-VM situation, fail-closed.
    #[error("snp-probe/{0}")]
    SnpProbe(&'static str),

    /// The per-VM guest-poweroff policy file
    /// ([`crate::lifecycle::power_policy`]) could not be read or written.
    /// Sub-classifiers: `mkdir`, `write`, `sync`, `rename`, `remove`,
    /// `read`, `parse`, `encode`.
    #[error("power-policy-store/{0}")]
    PowerPolicyStore(&'static str),
}
