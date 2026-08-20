# Grow-at-first-boot tenant disks (#365)

Status: **REDESIGNED 2026-06-11.** Phase 1 (measured size anchor)
landed. The original grow-by-resize plan (Phases 2/3 below) is
**abandoned** — the live cryptsetup matrix proved it impossible — and
replaced by a **separate fresh-formatted data disk** (see the next
section). The Phases 2/3 text is retained below for history.

## Redesign: separate fresh-formatted data disk (the shipped approach)

**Why the resize plan died.** The matrix the original design gated on
(run on miner-1, cryptsetup 2.8; the guest's 2.7 has the same limit)
showed `cryptsetup resize` of a LUKS2 + `--integrity hmac-sha256`
volume returns a hard refusal — *"Resize of LUKS2 device with integrity
protection is not supported."* — and `cryptsetup open` has no
`--integrity-recalculate` flag. Growing the inner dm-integrity layer
(`integritysetup resize`) + reopening is off-label, fragile, and leaves
the grown region tag-less (EIO) with no clean cryptsetup-level
backfill. Not shippable on a security-critical disk. (Memory:
`grow_365_cryptsetup_integrity_resize_unsupported`.)

**The approach that ships.** Stop trying to grow one disk:

1. **Rootfs (`/dev/vda`)** stays a fixed, flavor-INDEPENDENT minimal
   image (measured; §296 header pin intact). The bake no longer sizes
   it to the flavor (`scripts/tenant-image-bake.sh` — `--flavor` is now
   name-validated only; size is `--output-qcow2-gb` / `HCC_BAKE_QCOW2_GB`).
2. **Data disk (`/dev/vde`)** — the miner attaches a BLANK sparse raw
   image sized to the flavor's `disk_gb`
   (`binaries/miner-agent/src/lifecycle/data_disk.rs`); not a measured
   launch input (blank + guest-keyed).
3. **Guest first boot** (`hippius-data-disk-init` +
   `hippius-data-disk.service`, baked into the rootfs) reads the
   measured `hippius.disk_gb=` token, fail-closed size-checks
   `/dev/vde`, then does a **fresh** `cryptsetup luksFormat --type luks2
   --integrity hmac-sha256` (no resize, ever) with a 32-byte key it
   generates inside the SNP boundary and seals on the encrypted rootfs
   at `/etc/hippius/data.key`, then `mkfs.ext4` + mount `/data`.
   Subsequent boots just `cryptsetup open` with the persisted key.

**Security (untrusted miner).** Identical posture to the rootfs: the
data key never leaves the guest; every dm-integrity HMAC tag is written
by the guest, so a miner tampering any byte of `/dev/vde` makes the
guest read fault (EIO — validated live). The size is anchored by the
measured `hippius.disk_gb=` token — a short/missing disk fails closed.
The data-disk LUKS header is guest-created, so it is intentionally NOT
in the launch measurement; its integrity derives from the guest-held
key, not a baked/pinned header.

**Cost.** The first-boot integrity wipe (~1 GiB/s; ≈64 s for xlarge …
≈4 min for 4xlarge) runs without blocking sshd/login — `/data` appears
once it completes. This moves the wipe off the bake→S3→download
critical path (the original win) while keeping it a supported op.

**Live primitive validation.** `cryptsetup luksFormat --integrity` →
`mkfs.ext4` → mount → reboot (close/reopen) → fsck clean, canary +
payload intact → tamper of an unwritten region = EIO. Plus the guest
`hippius-data-disk-init` logic (no-token skip, short-disk fail-closed,
first-boot format, reboot reopen, tamper EIO) — all green on miner-1.

---

## Historical: the original grow-by-resize plan (ABANDONED)

The text below is the original Phase 2/3 design. It is kept for the
record; the resize mechanism it depends on does not exist in
cryptsetup. Do not implement it.

## Problem

The bake materialises the FULL flavor disk (8/16/32 GiB) because
`--integrity hmac-sha256` requires every 512 B sector to carry a valid
HMAC tag, so `luksFormat` wipes the whole device to initialise them.
Consequences: full-size incompressible qcow2 per tenant, large S3
uploads + miner downloads, and a wipe whose cost scales with flavor
(post-#352 the wipe dominates the bake).

Standard cloud practice is a minimum-size image grown at first boot.
LUKS alone does not block that; dm-integrity makes it non-trivial but
not impossible.

## Target shape

1. **Bake** a minimal image (rootfs + slack, ~4–5 GiB), flavor-INDEPENDENT.
2. **Miner staging**: after sha256-verifying the downloaded artifact,
   `qemu-img resize` the qcow2 to the flavor size (metadata-only,
   instant). The OrderTicket keeps pinning the *artifact* sha; the
   resize is local + post-verification.
3. **Guest first boot** (inside the SNP guest, post-attestation,
   post-unlock):
   - `cryptsetup resize cryptroot` (whole-disk LUKS, no partition
     table → no growpart),
   - dm-integrity backfills tags for the grown region via the
     `--integrity-recalculate` activation flag (kernel ≥ 5.7; guests
     run 6.8),
   - online `resize2fs`.

## Security analysis — UNTRUSTED miner (the gate for this work)

The whole feature is acceptable ONLY because every miner manipulation
either fails closed or is loudly visible. No new trust is placed in
the miner.

| Miner action | Outcome | Mechanism |
|---|---|---|
| Tampers grown-region bytes before the guest writes them | Guest read → **EIO** | dm-integrity tags for the new region are written by the GUEST (HMAC-keyed from the LUKS volume key the miner never sees). Untagged/mistagged sectors fault. |
| Skips the resize / resizes smaller | **fail-visible** | Guest enforces the expected size from the measured `hippius.disk_gb=` cmdline token; a too-small block device → boot-time size check fails. |
| Resizes LARGER than the flavor | **fail-closed** | Same measured token: the guest refuses to grow past the attested size, so a miner can't silently hand a tenant a bigger (and differently-measured) disk. |
| Swaps the LUKS header | **caught** | Existing §296 header-sha pin (`hippius.luks_header_sha256=`, cmdline-measured). `cryptsetup resize` does NOT touch the header — the LUKS2 segment size is `dynamic`. |
| Tampers the pre-existing (baked) region | **caught** | dm-integrity, exactly as today. |

**The measured `hippius.disk_gb=` token is the anchor.** It folds into
the SEV-SNP launch measurement (kernelHashes=yes → cmdline measured),
so the guest's notion of "how big should this disk be" is attested,
not miner-supplied. Without it, a miner controlling the block-device
size could grow/shrink at will. Phase 1 (below) lands exactly this
token so the anchor exists before any resize code does.

## Why this is NOT in the keyscript

The keyscript runs in the initramfs and only emits the KEK on stdout;
cryptsetup-initramfs does the `crypt_activate_by_passphrase` against
the detached header. The resize must run AFTER the device is open and
the rootfs is mounted — i.e. a guest-side first-boot systemd unit
(ordered before the app workload, after `cryptsetup.target`), or a
cloud-init `bootcmd`. Doing it pre-open in the initramfs would race
the activation and can't online-resize a mounted ext4.

## Phased plan

### Phase 1 — measured size anchor (LANDED)

`vali_create_vm` appends `hippius.disk_gb=<flavor disk_gb>` to the
cmdline (same `_augment_cmdline_with_token` pattern as
`hippius.rootfs_sha256` / `hippius.luks_header_sha256`). The value is
the flavor's canonical `disk_gb` from `hippius_types::flavor`. It is
inert today (nothing reads it yet) but, being cmdline-measured, it
becomes part of the launch digest immediately — so the allowlist entry
for a grow-enabled image is bound to the attested size from day one.

This is pure, testable, and reversible, and it is the security
precondition for Phases 2–3.

### Phase 2 — bake minimal + miner resize (GATED)

- Bake: stop sizing the LUKS device to the flavor; bake a fixed
  minimal device (rootfs + ~1 GiB slack). The qcow2 becomes
  flavor-independent.
- Miner staging (miner-agent): `qemu-img resize` the verified qcow2 to
  the flavor `disk_gb` before defining the domain. Pure metadata.
- Guest: a first-boot unit reads `hippius.disk_gb=`, compares it to
  the block device size, and ONLY proceeds to Phase 3 if the device
  is at least the attested size (smaller ⇒ fail-closed; larger device
  but token smaller ⇒ resize the LUKS mapping only up to the token).

### Phase 3 — guest cryptsetup resize + integrity recalc (GATED on live matrix)

- `cryptsetup resize cryptroot` then `resize2fs`.
- dm-integrity tag backfill via `--integrity-recalculate` (set at the
  cryptsetup-initramfs activation, or a re-activate cycle on first
  boot).

**Must pass before Phase 3 lands enabled** — these interactions are
not safe to ship blind on a security-critical disk path:

1. `cryptsetup resize` + dm-integrity `recalculate` + **detached
   header** (`header=/run/hippius/luks.header`) on noble's cryptsetup
   2.7 — full matrix, confirm the grown region reports EIO until the
   guest writes valid tags.
2. ext4 online `resize2fs` over a region whose integrity tags are
   still recalculating — confirm ext4 never reads unwritten blocks
   (expected) and that an fsck path can't trip a false EIO.
3. First-boot latency budget: recalc is background but IO-competes
   with cloud-init; measure on `large`.

## Expected wins

- Bake: wipe ~5 GiB instead of up to 32 → bake time ~flavor-independent.
- S3 transfer + miner download: ~4–6× smaller for `large`.
- Stage-1 cache (#352) covers proportionally more of the bake.

Boot time is unchanged except the one-time first-boot resize +
background recalc.
