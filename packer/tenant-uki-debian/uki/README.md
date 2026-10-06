# `packer/tenant-uki-debian/` — Debian 13 tenant UKI factory (EPIC #186 Phase 1)

Sibling factory to [`packer/tenant-uki/`](../../tenant-uki/) (which
ships the §F placeholder rootfs). This one stands up a **full
Debian 13 (trixie) userspace** an operator can spawn + SSH into +
run real workloads on — systemd + sshd + cloud-init + netbird +
the §23 tenant-telemetry binary, all dm-verity-protected and
folded into the SEV-SNP launch digest.

## Layout

```
uki/
├── Dockerfile               — multi-stage build environment
│                              (agent-builder + UKI-assembly runtime)
├── Makefile                 — pipeline: fetch → initramfs → rootfs
│                              → assemble → sign → measure
├── cmdline                  — kernel cmdline (panic=1,
│                              hippius.kbs_url=, hippius.luks_device=,
│                              init=/sbin/init, ds=nocloud)
├── inputs.lock              — pinned kernel + systemd-stub + netbird
│                              + Debian bootstrap-mirror SHA-256s
├── os-release.template      — baked into the UKI's `.osrel` section
├── scripts/
│   ├── fetch-inputs.sh         — SHA-verified downloads
│   ├── build-initramfs.sh      — minimal PID-1 initramfs (same agent
│                                  binary as the placeholder factory)
│   ├── build-rootfs.sh         — **THE** new piece: mmdebstrap +
│                                  chroot apt + scrub_state +
│                                  mksquashfs + veritysetup. Read its
│                                  header for the reproducibility
│                                  discipline.
│   ├── assemble-uki.sh         — ukify build with embedded cmdline +
│                                  dm-verity root hash
│   ├── sign-uki.sh             — sbsign with the shared §F dev key
│                                  under `packer/kbs-uki/keys/dev/`
│   └── verify-reproducible.sh  — convenience wrapper around
│                                  `make uki-reproducible-check`
└── rootfs-config/
    ├── systemd/
    │   ├── netbird.service             — joins mesh post-pivot,
    │                                      Before=ssh.service; sets
    │                                      USER/HOME/LOGNAME env (the
    │                                      CGO_ENABLED=0 trap from
    │                                      hccs/hcc-image-builder/src/
    │                                      debian.rs:606-609).
    │   ├── hippius-tenant-telemetry.service
    │   └── overrides/MASK-UNITS        — rsyslog / cron / getty@*
    │                                      / apt-daily{,upgrade} /
    │                                      timesyncd masked at build
    │                                      time.
    ├── cloud-init/
    │   ├── 90-hippius-nocloud.cfg     — datasource pin to
    │                                      /var/lib/cloud/seed/nocloud
    │                                      (the agent-initramfs
    │                                      `stages::seed` write path).
    │   └── ds-identify.cfg            — ds-identify disabled (skip
    │                                      datasource probing at
    │                                      first boot).
    ├── ssh/
    │   └── sshd_config.d-99-hippius.conf — keys-only, hardened
    │                                       sshd drop-in.
    └── apt/
        └── sources.list              — snapshot.debian.org-pinned
                                         repo (matches inputs.lock).
```

## Quick build

```sh
make pin-base       # one-time: resolve Dockerfile FROM digests
make pin-apt        # one-time: resolve apt= version pins
make uki            # full pipeline; output at uki/output/
make uki-reproducible-check
                    # double-build + diff -r; the shipping gate
```

Output:

```
uki/output/
├── rootfs.img                    — squashfs of the Debian userspace
├── rootfs.verity                 — dm-verity hash tree
├── rootfs.roothash               — 64-hex verity root hash
├── packages.lock                 — sorted apt package=version list
│                                    (audit trail; diff-r picks up
│                                    package version drift)
├── passwd.golden, group.golden   — UID/GID stability snapshots
├── tenant-debian-0.0.1.uki        — unsigned UKI (kernel+initrd+
│                                    cmdline+osrel inside a PE)
├── tenant-debian-0.0.1.uki.signed — sbsign-stamped flavour
└── measurement.json               — snp_launch_digest_v1 over the
                                     signed UKI + OVMF (the value
                                     Phase 2 pins into the §22
                                     allowlist).
```

## Reproducibility regime

`mmdebstrap` + chroot `apt` are NOT reproducible by default — every
install touches mtimes, allocates fresh UIDs, writes timestamped
dpkg state, generates random `/etc/machine-id` + random ssh host
keys + a random `/var/lib/dbus/machine-id`, regenerates
`/var/cache/ldconfig/aux-cache` with build-host paths, etc.
`build-rootfs.sh`'s `scrub_state` step (header docs the full list)
removes every one before `mksquashfs`. The two-build byte-identity
check (`make uki-reproducible-check`) is the load-bearing CI gate:
if it fails, the rootfs has unidentified non-determinism and the
launch digest will drift across builds → the §22 allowlist will
refuse the next build → tenant launches fail closed silently. The
PR that introduces a new package or a new rootfs-config file MUST
re-run this check + bump the allowlist epoch in lockstep.

## §22 allowlist coupling

The launch digest of every reproducible build is a §22-allowlist
input. Phase 1 ships the factory; Phase 2 (separate small PR) adds:

1. `test_vectors/uki/tenant-debian-measurement.json` — the pinned
   measurement, populated from the first `tenant-uki-debian-build`
   workflow run on `main` after this PR lands.
2. A second entry in `test_vectors/allowlist/dev-manifest.toml`
   for the Debian image (the placeholder entry stays — both
   tenant UKIs coexist in the dev allowlist; operators choose
   per-launch which to deploy).
3. Re-mint `test_vectors/allowlist/dev.cose`.
4. Bump `deploy/gitops/apps/kbs/values.yaml::allowlist.sha256`.

After Phase 2 merges, the operator:

1. `aws s3 cp test_vectors/allowlist/dev.cose s3://hippius-compute-images/allowlist/v1/dev.cose --acl public-read`
2. Argo refresh `hippius-compute-kbs` → KBS pod roll → log
   `allowlist epoch=N+1`
3. Stage the Debian UKI on a Genoa host with the new S3 SHA
   (`scripts/tenant-uki-stage-miner.sh --tenant-uki-sha <new>`).
4. Mint the OrderTicket with `--allowed-measurement-hex <new
   tenant-debian measurement>`.
5. Dispatch → KBS release → LUKS unlock → switch_root → systemd
   boot → SSH login over the NetBird mesh.

## Authoritative reference

The per-distro reproducibility traps (USER/HOME/LOGNAME for CGO_OFF
netbird, ssh host keys, machine-id, dpkg log) are documented inside
`scripts/build-rootfs.sh`'s header + the per-step comments. The
prior art is
[`thenervelab/hccs/hcc-image-builder/src/debian.rs`](https://github.com/thenervelab/hccs/blob/main/hcc-image-builder/src/debian.rs)
(1167 LOC); the relevant traps are read into the script's comments
verbatim.
