#!/usr/bin/env bash
# `build-rootfs.sh DEBIAN_BOOTSTRAP_URL DEBIAN_BOOTSTRAP_SECURITY_URL`
#
# Builds a reproducible, dm-verity-protected Debian 13 (trixie)
# tenant rootfs. Sibling to `packer/tenant-uki/uki/scripts/build-
# rootfs.sh`, which ships a §F placeholder; this one ships a FULL
# Debian userspace an operator can spawn + SSH into + run real
# workloads on (EPIC #186 Phase 1).
#
# Output, in /build/work/:
#
#   rootfs.img            — read-only squashfs of the userspace tree.
#   rootfs.verity         — the dm-verity hash tree over rootfs.img.
#   rootfs.roothash       — the verity root hash (64 hex chars), the
#                           value `assemble-uki.sh` embeds into the
#                           UKI cmdline as `dm-verity.root=<hash>`.
#   passwd.golden, group.golden, packages.lock — audit-trail
#                           snapshots of UID/GID + installed package
#                           versions; published to /build/output/ so
#                           `make uki-reproducible-check` and CI can
#                           compare them across builds.
#
# ## What the Debian rootfs contains (vs the placeholder)
#
# The placeholder ships a deterministic minimal init + the
# tenant-telemetry + netbird binaries; the Debian rootfs ships a
# FULL Debian 13 userspace:
#
#   - systemd (PID 1, replaces the placeholder's `/sbin/init`)
#   - openssh-server (the §RUNTIME tenant entry point)
#   - cloud-init (consumes the agent-initramfs NoCloud seed)
#   - netbird + telemetry binaries (same set as the placeholder)
#   - dbus, systemd-networkd, systemd-resolved (network + dns)
#   - apt + dpkg + curl + wget + gnupg + ca-certificates
#   - bash + coreutils + procps + iproute2 + iputils-ping + vim-tiny
#
# All of it is inside the squashfs → covered by the dm-verity root
# hash → folded into the launch digest. A version bump for any
# pinned package is a §22 allowlist-affecting PR.
#
# ## Reproducibility — the load-bearing invariant
#
# Two runs MUST produce a byte-identical rootfs.img AND therefore
# the SAME verity root hash. debootstrap + apt are NOT reproducible
# by default — every install touches mtimes, allocates UIDs, writes
# dpkg state with timestamps, generates random SSH host keys, drops
# random /etc/machine-id, writes random /var/lib/dbus/machine-id,
# regenerates /var/cache/ldconfig/aux-cache with build-time paths,
# etc. This script scrubs ALL of those, in this order:
#
#   1. mmdebstrap pins SOURCE_DATE_EPOCH into the bootstrap (its
#      `--variant=minbase` + the snapshot.debian.org URL pin make
#      the package SET deterministic);
#   2. in-chroot apt installs the rest of the package set with
#      `--no-install-recommends`;
#   3. scrub_state removes:
#        - /etc/machine-id  (regenerated at first boot)
#        - /var/lib/dbus/machine-id  (likewise)
#        - /etc/ssh/ssh_host_*  (regenerated at first boot by
#          ssh-keygen.service / ssh.service)
#        - /var/log/dpkg.log, /var/log/alternatives.log,
#          /var/log/apt/*.log  (build-time logs leak wall-clock)
#        - /var/lib/apt/extended_states  (apt's "auto-installed"
#          markers — partial-state with mtime)
#        - /var/lib/apt/lists/*  (apt metadata cache)
#        - /var/cache/apt/*  (downloaded .deb cache)
#        - /var/cache/ldconfig/aux-cache  (ldconfig cache contains
#          build-host paths)
#        - /var/cache/debconf/*-old  (debconf state)
#        - /var/lib/systemd/random-seed  (regenerated at first boot)
#        - /etc/hostname  (cloud-init sets per-instance hostname)
#        - /usr/share/info/dir  (info index regenerated on demand)
#   4. /etc/resolv.conf → symlink to /run/systemd/resolve/stub-
#      resolv.conf (systemd-resolved creates the destination at
#      first boot);
#   5. mask the units in rootfs-config/systemd/overrides/MASK-UNITS
#      via /etc/systemd/system/<name> → /dev/null symlinks (the
#      symlinks have mtime-forced bytes);
#   6. enable the netbird + tenant-telemetry units via
#      /etc/systemd/system/multi-user.target.wants/<name> →
#      ../<name> symlinks (same mtime-forced bytes);
#   7. force-set mtime to ${SOURCE_DATE_EPOCH} on EVERY entry
#      (files + dirs + symlinks; `-h` flag);
#   8. mksquashfs with `-comp gzip -all-time ${SOURCE_DATE_EPOCH}
#      -mkfs-time ${SOURCE_DATE_EPOCH} -all-root -no-xattrs
#      -processors 1`;
#   9. veritysetup format with pinned --salt + --uuid.
#
# `make uki-reproducible-check` runs this twice into isolated dirs +
# `diff -r`s. THE SHIPPING GATE. If it fails, the rootfs has
# unidentified non-determinism — re-audit the scrub list.

set -euo pipefail
umask 022

if [[ $# -ne 2 ]]; then
    echo "usage: $0 DEBIAN_BOOTSTRAP_URL DEBIAN_BOOTSTRAP_SECURITY_URL" >&2
    exit 64
fi

DEBIAN_BOOTSTRAP_URL="$1"
DEBIAN_BOOTSTRAP_SECURITY_URL="$2"

# Paths default to the in-container layout.
WORK="${ROOTFS_WORK:-/build/work}"
OUTPUT="${ROOTFS_OUTPUT:-/build/output}"
STAGING="$WORK/rootfs-staging"
ROOTFS_IMG="$WORK/rootfs.img"
VERITY="$WORK/rootfs.verity"
ROOTHASH_FILE="$WORK/rootfs.roothash"

# Bundled-binary sources. Same paths the placeholder factory uses;
# the agent-builder Docker stage drops both at /opt/hippius/.
TENANT_TELEMETRY_BIN="${TENANT_TELEMETRY_BIN:-/opt/hippius/tenant-telemetry}"
NETBIRD_BIN="${NETBIRD_BIN:-$WORK/netbird}"

# Rootfs-config tree (systemd units + cloud-init + sshd + apt). The
# script READS files from /repo (read-only bind-mount) and copies
# them into the chroot. Single source of truth = repo, no inline
# heredocs (a heredoc with `$variables` would either leak or refuse
# to escape).
ROOTFS_CONFIG_REPO=/repo/packer/tenant-uki-debian/uki/rootfs-config

mkdir -p "$WORK"

# Pinned dm-verity salt + superblock UUID — same posture as the
# placeholder factory (both default to random; we pin both so the
# root hash is reproducible AND the rootfs.verity file bytes are
# byte-identical across runs).
VERITY_SALT="0000000000000000000000000000000000000000000000000000000000000000"
VERITY_UUID="00000000-0000-0000-0000-000000000000"
VERITY_HASH_ALG="sha256"
VERITY_BLOCK_SIZE="4096"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

# ── Sanity: required tools ──────────────────────────────────────────
for tool in mmdebstrap mksquashfs veritysetup chroot; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "build-rootfs: required tool '$tool' not found on PATH." >&2
        echo "build-rootfs: this script runs inside the pinned UKI Docker image" >&2
        echo "build-rootfs: (debootstrap + mmdebstrap + squashfs-tools + cryptsetup-bin)." >&2
        exit 69
    fi
done

if [[ ! -x "$TENANT_TELEMETRY_BIN" ]]; then
    echo "build-rootfs: tenant-telemetry binary missing at $TENANT_TELEMETRY_BIN" >&2
    echo "build-rootfs: COPY'd from the agent-builder Docker stage; see uki/Dockerfile." >&2
    exit 70
fi
if [[ ! -x "$NETBIRD_BIN" ]]; then
    echo "build-rootfs: netbird binary missing at $NETBIRD_BIN" >&2
    echo "build-rootfs: run 'make fetch' first; see uki/scripts/fetch-inputs.sh." >&2
    exit 71
fi
if [[ ! -d "$ROOTFS_CONFIG_REPO" ]]; then
    echo "build-rootfs: rootfs-config tree missing at $ROOTFS_CONFIG_REPO" >&2
    echo "build-rootfs: /repo is bind-mounted read-only; this script expects" >&2
    echo "build-rootfs: rootfs-config/ under packer/tenant-uki-debian/uki/." >&2
    exit 72
fi

# ── Step 1: mmdebstrap — first-stage bootstrap ──────────────────────
#
# mmdebstrap is more reproducible than debootstrap by default (it
# pins the time + accepts SOURCE_DATE_EPOCH) AND faster. We use
# `--variant=minbase` for the minimal install set; the rest comes
# from the in-chroot apt step below.
#
# `--customize-hook='chroot $1 …'` is mmdebstrap's idiom for
# running commands inside the freshly-bootstrapped chroot before it
# unmounts; we keep this step minimal here and do the heavy apt
# install separately so the failure modes are clearer.
echo "build-rootfs: step 1/6 — mmdebstrap bootstrap (snapshot=$DEBIAN_BOOTSTRAP_URL)" >&2
rm -rf "$STAGING"
mkdir -p "$STAGING"

# mmdebstrap reads SDE from the environment and pins file mtimes to
# it inside the bootstrap target. We pass the snapshot URL as the
# mirror so the bootstrap pulls EXACTLY the package versions the
# snapshot timestamp pinned.
#
# `--include` adds packages to the first-stage install (resolved by
# mmdebstrap's bootstrap, not the in-chroot apt). Keep this set
# TIGHT — every package here forks more dpkg state to scrub later.
# `init` is essential (provides `/sbin/init` -> systemd symlink);
# `dbus-broker` is the modern dbus replacement (faster, lower
# memory) Debian Trixie ships by default.
mmdebstrap \
    --architectures=amd64 \
    --variant=minbase \
    --components=main \
    --include=systemd,systemd-sysv,init,dbus,ca-certificates,libpam-systemd \
    --aptopt='Apt::Install-Recommends "false";' \
    --aptopt='Apt::AutoRemove::SuggestsImportant "false";' \
    --keyring=/usr/share/keyrings/debian-archive-keyring.gpg \
    trixie \
    "$STAGING" \
    "$DEBIAN_BOOTSTRAP_URL"

# ── Step 2: write the in-chroot sources.list + apt configuration ───
#
# The bootstrap left /etc/apt/sources.list pointing at the mirror
# URL we passed. Replace it with the multi-component sources from
# rootfs-config/apt/sources.list with the @-placeholders substituted
# so a runtime `apt-cache search` resolves against the same snapshot.
echo "build-rootfs: step 2/6 — install apt sources.list pointing at the snapshot" >&2
sed \
    -e "s|@DEBIAN_BOOTSTRAP_URL@|${DEBIAN_BOOTSTRAP_URL}|g" \
    -e "s|@DEBIAN_BOOTSTRAP_SECURITY_URL@|${DEBIAN_BOOTSTRAP_SECURITY_URL}|g" \
    "$ROOTFS_CONFIG_REPO/apt/sources.list" \
    > "$STAGING/etc/apt/sources.list"

# Keep apt from spending wall-clock on `check-valid-until`. The
# snapshot's Release file is signed but its valid-until window has
# long since expired (snapshot pins are by definition immutable
# history; the Release file's lifetime check is irrelevant for a
# pinned snapshot). Same flag also lives in sources.list above for
# belt + braces (apt 2.x respects either).
mkdir -p "$STAGING/etc/apt/apt.conf.d"
cat > "$STAGING/etc/apt/apt.conf.d/99-hippius-snapshot.conf" <<'APTCONF'
Acquire::Check-Valid-Until "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::AutoRemove::SuggestsImportant "false";
APTCONF

# ── Step 3: chroot + apt install — the tenant package set ──────────
#
# These packages bring us from mmdebstrap's minbase to a usable
# tenant userspace. `--no-install-recommends` (also pinned in
# 99-hippius-snapshot.conf above) keeps the set TIGHT. The keyring
# is bind-mounted so apt update can verify the snapshot's Release.
# gpg.
#
# Mount /proc, /sys, /dev for the postinst scripts. We unmount them
# in a `trap` so a failure halfway doesn't leak the mounts.
echo "build-rootfs: step 3/6 — chroot + apt install (full tenant package set)" >&2

mount --bind /proc "$STAGING/proc"
mount --bind /sys  "$STAGING/sys"
mount --bind /dev  "$STAGING/dev"
trap 'umount -lf "$STAGING/proc" "$STAGING/sys" "$STAGING/dev" 2>/dev/null || true' EXIT

# `DEBIAN_FRONTEND=noninteractive` suppresses debconf prompts;
# `DEBCONF_NONINTERACTIVE_SEEN=true` tells debconf to mark seen
# questions so post-install hooks don't write per-build prompts.
chroot "$STAGING" /usr/bin/env -i \
    HOME=/root \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    SHELL=/bin/bash \
    LC_ALL=C \
    LANG=C \
    TZ=UTC \
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    DEBIAN_FRONTEND=noninteractive \
    DEBCONF_NONINTERACTIVE_SEEN=true \
    /bin/bash -eu -o pipefail <<'CHROOT_APT'
# apt update with the snapshot sources.list. The keyring debootstrap
# left at /etc/apt/trusted.gpg.d/ + the multi-arch debian-archive-
# keyring.gpg verify the Release.gpg.
apt-get update

# systemd + sshd + cloud-init + network + tooling. Keep the set
# small but operator-usable — a future PR can add per-tenant
# extras via cloud-init runcmd.
#
# NOTE: systemd-networkd is NOT a separate package in Debian trixie
# (unlike Ubuntu) — the networkd binary + its .service unit ship
# inside the main `systemd` package (already installed by the
# mmdebstrap `--include=systemd`). Listing it here makes apt fail with
# "Unable to locate package systemd-networkd"; the daemon is enabled
# via the multi-user.target.wants symlinks in rootfs-config, not by an
# install. `systemd-resolved` IS a separate package, so it stays.
apt-get install --no-install-recommends -y \
    systemd-resolved \
    openssh-server \
    cloud-init \
    iproute2 \
    iputils-ping \
    netcat-openbsd \
    curl \
    wget \
    gnupg \
    procps \
    psmisc \
    less \
    bash-completion \
    vim-tiny \
    libnss-systemd

# Enable networkd + resolved. In Debian these ship in the base
# `systemd` package but their preset is DISABLED, and (unlike Ubuntu)
# there is no `systemd-networkd` package whose postinst would enable
# them — so without this the guest boots with no networking. `systemctl
# enable` runs offline in the chroot (a pure symlink operation) and
# also wires the .socket + dbus-alias units their [Install] sections
# declare. cloud-init renders the per-launch .network from the NoCloud
# metadata on top of this.
systemctl enable systemd-networkd.service systemd-resolved.service

# Cleanup the apt cache + lists immediately so they don't linger
# into the scrub_state step (belt + braces).
apt-get clean
rm -rf /var/lib/apt/lists/*
CHROOT_APT

# ── Step 4: install bundled binaries + rootfs-config ───────────────

echo "build-rootfs: step 4/6 — install bundled binaries + rootfs-config" >&2

# netbird → /usr/local/bin/netbird (matches the systemd unit's
# `ExecStart=` path).
install -D -m 0755 "$NETBIRD_BIN" "$STAGING/usr/local/bin/netbird"

# tenant-telemetry → /usr/local/sbin/hippius-agent-tenant-telemetry.
install -D -m 0755 "$TENANT_TELEMETRY_BIN" \
    "$STAGING/usr/local/sbin/hippius-agent-tenant-telemetry"

# systemd units.
install -D -m 0644 "$ROOTFS_CONFIG_REPO/systemd/netbird.service" \
    "$STAGING/etc/systemd/system/netbird.service"
install -D -m 0644 "$ROOTFS_CONFIG_REPO/systemd/hippius-tenant-telemetry.service" \
    "$STAGING/etc/systemd/system/hippius-tenant-telemetry.service"

# Cloud-init drop-ins.
install -D -m 0644 "$ROOTFS_CONFIG_REPO/cloud-init/90-hippius-nocloud.cfg" \
    "$STAGING/etc/cloud/cloud.cfg.d/90-hippius-nocloud.cfg"
install -D -m 0644 "$ROOTFS_CONFIG_REPO/cloud-init/ds-identify.cfg" \
    "$STAGING/etc/cloud/ds-identify.cfg"

# sshd drop-in.
install -D -m 0644 "$ROOTFS_CONFIG_REPO/ssh/sshd_config.d-99-hippius.conf" \
    "$STAGING/etc/ssh/sshd_config.d/99-hippius.conf"

# Mask the units listed in rootfs-config/systemd/overrides/MASK-UNITS.
# Mask = `ln -sf /dev/null /etc/systemd/system/<unit>`. A symlink's
# bytes ARE its target path string ("/dev/null"); 9 bytes, mtime is
# applied by the later force_mtime sweep.
mask_units_file="$ROOTFS_CONFIG_REPO/systemd/overrides/MASK-UNITS"
mkdir -p "$STAGING/etc/systemd/system"
while IFS= read -r unit; do
    # Strip comments + blanks.
    unit="${unit%%#*}"
    unit="${unit//[[:space:]]/}"
    [[ -z "$unit" ]] && continue
    ln -sf /dev/null "$STAGING/etc/systemd/system/$unit"
done < "$mask_units_file"

# Enable our two units via the standard wants/ symlink convention
# (matches what `systemctl enable` does). multi-user.target.wants
# is created by mmdebstrap as part of the systemd install.
mkdir -p "$STAGING/etc/systemd/system/multi-user.target.wants"
ln -sf /etc/systemd/system/netbird.service \
    "$STAGING/etc/systemd/system/multi-user.target.wants/netbird.service"
ln -sf /etc/systemd/system/hippius-tenant-telemetry.service \
    "$STAGING/etc/systemd/system/multi-user.target.wants/hippius-tenant-telemetry.service"

# ── Step 5: scrub non-deterministic state ───────────────────────────

echo "build-rootfs: step 5/6 — scrub non-deterministic state" >&2

# /etc/machine-id and /var/lib/dbus/machine-id — empty (NOT remove;
# systemd-firstboot.service / dbus expect the file to exist at boot).
: > "$STAGING/etc/machine-id"
mkdir -p "$STAGING/var/lib/dbus"
: > "$STAGING/var/lib/dbus/machine-id"

# /etc/ssh/ssh_host_* — remove. ssh.service / ssh-keygen.service
# regenerates at first boot.
rm -f "$STAGING"/etc/ssh/ssh_host_*

# /etc/resolv.conf — point at the systemd-resolved stub.
# systemd-resolved creates /run/systemd/resolve/stub-resolv.conf at
# service start (first boot).
rm -f "$STAGING/etc/resolv.conf"
ln -sf ../run/systemd/resolve/stub-resolv.conf "$STAGING/etc/resolv.conf"

# /etc/hostname — empty. cloud-init writes the per-instance hostname.
: > "$STAGING/etc/hostname"

# Logs.
: > "$STAGING/var/log/dpkg.log"
: > "$STAGING/var/log/alternatives.log"
find "$STAGING/var/log/apt" -type f -name '*.log' -exec sh -c ': > "$1"' _ {} \; 2>/dev/null || true
find "$STAGING/var/log" -maxdepth 1 -type f -name '*.log' -exec sh -c ': > "$1"' _ {} \;

# Apt state.
rm -f "$STAGING/var/lib/apt/extended_states"
rm -rf "$STAGING/var/lib/apt/lists/"*
rm -rf "$STAGING/var/cache/apt/"*
# Empty the apt history journal too (it logs install timestamps).
: > "$STAGING/var/log/apt/history.log" 2>/dev/null || true
: > "$STAGING/var/log/apt/term.log"    2>/dev/null || true

# Ldconfig cache — contains host build-time paths.
rm -rf "$STAGING/var/cache/ldconfig"
mkdir -p "$STAGING/var/cache/ldconfig"
chmod 0755 "$STAGING/var/cache/ldconfig"

# Debconf state — keep the configs (templates.dat) but drop the
# `-old` rotated copies that have build-mtime metadata.
find "$STAGING/var/cache/debconf" -type f -name '*-old' -delete 2>/dev/null || true

# Systemd random-seed — regenerated at first boot.
rm -f "$STAGING/var/lib/systemd/random-seed"

# Info index — regenerated on demand.
rm -f "$STAGING/usr/share/info/dir"

# /var/lib/dpkg/triggers/Unincorp — dpkg's "needs to run triggers"
# marker (a list of package names; ordering can vary). Don't touch
# /var/lib/dpkg state itself (status, available, info/* — those are
# stable given the same package SET in the same install order).
# Just ensure no trigger queue persists.
rm -f "$STAGING/var/lib/dpkg/triggers/Unincorp"
# Same for any "deferred" trigger queue.
rm -f "$STAGING/var/lib/dpkg/triggers/Triggers-pending"

# Audit-trail snapshots. We publish to $OUTPUT/ so
# uki-reproducible-check's `diff -r` between two runs picks up any
# UID drift or package-version drift IMMEDIATELY (a different
# /etc/passwd or different installed package versions are the two
# most likely sources of rootfs.img divergence).
mkdir -p "$OUTPUT"
cp "$STAGING/etc/passwd" "$OUTPUT/passwd.golden"
cp "$STAGING/etc/group"  "$OUTPUT/group.golden"
# SC2016: the literal `${Package}` / `${Version}` are dpkg-query's
# own template syntax — they MUST NOT expand in the shell.
# shellcheck disable=SC2016
chroot "$STAGING" /usr/bin/dpkg-query \
    --showformat='${Package}=${Version}\n' --show \
    | LC_ALL=C sort \
    > "$OUTPUT/packages.lock"

# ── Step 6: force mtime + squashfs + dm-verity ──────────────────────

echo "build-rootfs: step 6/6 — mksquashfs + veritysetup format" >&2

# Unmount /proc + /sys + /dev FIRST — before both the mtime touch and
# mksquashfs. mksquashfs would otherwise descend into them and pack the
# host's /proc into the image (multi-GB, non-deterministic, a privacy
# disaster); and the `find … touch` below would walk the live
# /proc/<pid> tree whose entries vanish mid-traversal, making touch exit
# non-zero (No such file or directory / Operation not permitted) and —
# under `set -e` — abort the whole build.
umount -lf "$STAGING/proc" "$STAGING/sys" "$STAGING/dev"
trap - EXIT

# Force-set mtime on every entry (files, dirs, symlinks) so squashfs
# cannot leak the build wall-clock into the archive. `-h` covers
# symlinks; the find pattern matches dirs + files + symlinks (the
# default behaviour of `find STAGING` without `-type` restrictions).
find "$STAGING" -depth -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

rm -f "$ROOTFS_IMG"
# Flag rationale:
#   -all-root      : uid/gid 0 for every entry (no host-uid leak).
#   -no-xattrs     : xattrs are non-deterministic; drop them.
#   -noappend      : never append to a stale image.
#   -comp gzip     : same compressor as the placeholder (parity);
#                     deterministic given fixed -Xcompression-level.
#   -Xcompression-level 9 : max gzip ratio + stable across runs.
#   -processors 1  : single-threaded block packing — multi-threaded
#                     mksquashfs has historically had a race that
#                     reorders blocks across runs.
#
# Timestamps come SOLELY from the exported SOURCE_DATE_EPOCH (set +
# exported above): mksquashfs reads it for every file mtime AND the
# superblock mkfs_time. The explicit -all-time/-mkfs-time flags are
# NOT passed — newer squashfs-tools FATAL-errors when SOURCE_DATE_EPOCH
# and those flags are given together ("can't be used at the same time
# to set timestamp(s)"). This matches the kbs-uki build-rootfs.sh.
mksquashfs "$STAGING" "$ROOTFS_IMG" \
    -all-root \
    -no-xattrs \
    -noappend \
    -comp gzip \
    -Xcompression-level 9 \
    -processors 1 \
    -no-progress \
    >/dev/null

rm -f "$VERITY"
verity_out=$(veritysetup format "$ROOTFS_IMG" "$VERITY" \
    --salt="$VERITY_SALT" \
    --uuid="$VERITY_UUID" \
    --hash="$VERITY_HASH_ALG" \
    --data-block-size="$VERITY_BLOCK_SIZE" \
    --hash-block-size="$VERITY_BLOCK_SIZE")

ROOT_HASH=$(echo "$verity_out" | awk '/^Root hash:/ {print $NF}')
if [[ ! "$ROOT_HASH" =~ ^[0-9a-f]{64}$ ]]; then
    echo "build-rootfs: could not parse a 64-hex root hash from veritysetup:" >&2
    echo "$verity_out" >&2
    exit 74
fi

printf '%s' "$ROOT_HASH" > "$ROOTHASH_FILE"

# Publish the rootfs artefacts to the output dir alongside the UKI so
# `make uki-reproducible-check` (which diffs the output dir) proves
# the rootfs + its root hash are byte-identical across runs too.
cp "$ROOTFS_IMG" "$VERITY" "$ROOTHASH_FILE" "$OUTPUT/"

# Force mtime on the audit-trail snapshots too (cp preserves source
# mtime; the snapshots were `touch`'d above but the cp targets get
# fresh mtimes unless we re-touch).
touch -h -d "@${SOURCE_DATE_EPOCH}" \
    "$OUTPUT/rootfs.img" \
    "$OUTPUT/rootfs.verity" \
    "$OUTPUT/rootfs.roothash" \
    "$OUTPUT/passwd.golden" \
    "$OUTPUT/group.golden" \
    "$OUTPUT/packages.lock"

echo "build-rootfs: OK" >&2
echo "  rootfs.img      $(stat -c%s "$ROOTFS_IMG") bytes" >&2
echo "  rootfs.verity   $(stat -c%s "$VERITY") bytes" >&2
echo "  root hash       $ROOT_HASH" >&2
echo "  packages.lock   $(wc -l < "$OUTPUT/packages.lock") packages" >&2
