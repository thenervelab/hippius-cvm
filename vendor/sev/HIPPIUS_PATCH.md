# `vendor/sev/` — virtee/sev 7.1.0 with two Hippius patches

This is a verbatim copy of [`sev = "7.1.0"`](https://crates.io/crates/sev/7.1.0)
(the AMD-blessed Rust SEV-SNP measurement crate, see AMD pub. 58217
"Platform Attestation Using VirTEE/SEV") with **two** targeted patches,
both in `src/measurement/vcpu_types.rs`.

## Patch 1 — Genoa stepping fix

```diff
-    CpuType::EpycGenoa => cpu_sig(25, 17, 0),
+    CpuType::EpycGenoa => cpu_sig(25, 17, 1),
```

## Patch 2 — add a silicon-correct `EpycTurin`

7.1.0 has **no** Turin `CpuType`. We add `EpycTurin` (+ an
`EpycTurinV1` mirror) as a first-class variant — wired into `TryFrom<u8>`,
`TryFrom<i32>`, `sig()`, `Display`, and `TryFrom<&str>`:

```diff
+    CpuType::EpycTurin => cpu_sig(26, 2, 1),   // 0x00B00F21 — EPYC 9255
+    CpuType::EpycTurinV1 => cpu_sig(26, 0, 0), // upstream generic placeholder
```

**Why `cpu_sig(26, 2, 1)` and not upstream's `cpu_sig(26, 0, 0)`?**
Upstream `main` (PR #392) ships `EpycTurin => cpu_sig(26, 0, 0)` =
CPUID `0x00B00F00`, a generic family-26 placeholder. Real Turin silicon —
measured on an EPYC 9255 — reports `family=26, model=2,
stepping=1`, i.e. CPUID `0x00B00F21`, read straight off
`/dev/cpu/0/cpuid` leaf 1 EAX on that host (`0x00B00F21`). This is the
**exact same class of bug as Patch 1**: QEMU `-cpu host` writes the real
silicon CPUID into the BSP VMSA's RDX before AMD-SP measures it, so the
generic `0x00B00F00` would be `0x21` off and every Turin KBS release
would fail-close `attestation: measurement not in ticket's allowed set`.
We therefore pin the genuine silicon value on `EpycTurin` and keep the
upstream placeholder on `EpycTurinV1` for reference.

Every byte outside these two `vcpu_types.rs` patches is byte-identical
to the published crate.

## Why

Upstream `EpycGenoa` returns `cpu_sig(family=25, model=17, stepping=0)` =
CPUID `0x00A10F10`. Real Genoa silicon — *specifically* an EPYC 9254 we
measured, and per `/proc/cpuinfo` likely every shipping
Zen 4 EPYC — reports `stepping=1`, i.e. CPUID `0x00A10F11`.

QEMU's SEV-SNP launch path with `-cpu host` writes the actual silicon
CPUID into the BSP VMSA's `rdx` register *before* AMD-SP measures the
VMSA pages into the launch_digest. Result: AMD-SP's measurement is
computed over different VMSA bytes than `snp_calc_launch_digest`
predicts upstream — every §22 allowlist entry we minted was 8 bytes
off in the RDX low nibble, and every KBS release attempt fail-closed
with `attestation: measurement not in ticket's allowed set`.

Proven 2026-05-26 by:

1. Capturing AMD-SP-reported measurement from a live boot (debug
   `eprintln!` in `binaries/agent-initramfs/src/stages/kbs_client.rs`
   dumping the SNP report's `measurement` field offset 144..192):
   `673a516f8daaf60b415ed71ca224a482a8cb48225eabf33e5f29730b8021ca9b970b606e19497d05166ec5199fdb660e`.
2. Re-running `hippius-uki-measure --features snp` with this patch
   applied; output matched **byte-for-byte**. The same inputs measured
   against upstream sev returned `ef275b66...` — 8 bytes off as
   predicted, in exactly the RDX position.

The bug surface is shared with every downstream tool that copies the
QEMU vCPU-model table (virtee/sev-snp-measure Python, sev-snp-measure-go,
Cloud Hypervisor's pre-launch prediction path). It is **not** reported
upstream as of 2026-05-26 — searches across virtee/sev issues+PRs for
`stepping`, `cpu_sig`, `9254`, and `EpycGenoaV2` return only the closed
Turin-flavored #317 and the Turin-add #392. A clean upstream fix would
add `EpycGenoaV2 = cpu_sig(25, 17, 1)` (and mirror in sev-snp-measure)
rather than overriding `EpycGenoa`. We don't upstream because we need
to ship now; that's a Phase B follow-up.

## Bump procedure

When sev publishes a new release on crates.io:

1. `cargo download sev=$NEW_VERSION` into a scratch dir.
2. Diff against `vendor/sev/` — confirm the upstream tree is otherwise
   compatible (no API breaks for `snp_calc_launch_digest`,
   `SnpMeasurementArgs`, `CpuType`).
3. If upstream **has merged** the Genoa stepping fix (look for either
   `EpycGenoaV2` variant or `EpycGenoa` returning `cpu_sig(25, 17, 1)`)
   AND ships a silicon-correct Turin (`cpu_sig(26, 2, 1)`, not the
   `cpu_sig(26, 0, 0)` placeholder), delete `vendor/sev/` and the
   workspace `[patch.crates-io]` entry, bump the crates.io pin instead.
   Note: as of this writing upstream's Turin is the generic
   `cpu_sig(26, 0, 0)` placeholder, which is WRONG for EPYC 9255 — so a
   bare version bump would silently re-break Turin. Re-apply Patch 2.
4. If upstream has **not** merged the fixes, replace `vendor/sev/`
   contents with the new tree and re-apply BOTH patches. Confirm
   the test_vectors/snp/ KAT in `binaries/uki-measure/src/main.rs`
   either stays byte-identical (silent bump = safe) or surfaces a
   deliberate measurement shift (intentional bump = re-attest §22
   allowlist in lockstep).
5. Verify both patches survive:
   - `grep 'EpycGenoa => cpu_sig(25, 17, 1)' vendor/sev/src/measurement/vcpu_types.rs`
   - `grep 'EpycTurin => cpu_sig(26, 2, 1)'  vendor/sev/src/measurement/vcpu_types.rs`
   must each return their one line.

## Why vendor instead of git-fork

A `[patch.crates-io] sev = { git = "..." }` pin to a private fork would
work, but:

- The patch is visible in every PR diff that touches `vendor/sev/`
  (a git submodule is invisible until somebody updates it).
- Phase A close cannot wait for our fork repo to be set up, reviewed,
  and pinned in a way that the CI runners can fetch.
- The crate is small (1.3 MB of source — `git ls-files vendor/sev/ |
  wc -l` ≈ 200 files) so the repo-size cost is negligible against the
  operational clarity.

When the upstream fix lands and we delete this directory, the diff
that removes it stands as the audit trail of the original divergence.
