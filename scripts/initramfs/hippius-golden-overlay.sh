#!/bin/sh
# `hippius-golden-overlay.sh` — the GOLDEN-mode guest root assembly
# (golden-bake PR3), sourced (never executed) by the initramfs hook
# `hippius-golden-mount` (initramfs-tools local-top) and, on the RHEL
# family, by the dracut golden mount module.
#
# ═══════════════════════════════════════════════════════════════════
# WHAT GOLDEN MODE IS (and why it is a SEPARATE boot path)
# ═══════════════════════════════════════════════════════════════════
# In the LEGACY path (`hippius-release-core.sh` + the crypttab
# keyscript / dracut runner) the per-VM LUKS `/dev/vda` IS the tenant
# rootfs: the KBS-released KEK unlocks it and the distro mounts
# `/dev/mapper/cryptroot` as `/`. That path is UNTOUCHED by this file.
#
# In GOLDEN mode the shared, read-only, per-distro dm-verity base
# (golden-bake PR1: `rootfs.img` squashfs on `/dev/vdb` + `rootfs.verity`
# hash tree on `/dev/vdc`, root hash MEASURED into the SNP launch digest
# as the `dm-verity.root=` cmdline token — PR2) is the OS. It is
# byte-identical across every same-distro tenant so the miner-agent
# content-addressed image cache (#823) HITs on it. Because it is SHARED
# it MUST carry NO tenant secret and NO shared master key — it is an
# UNKEYED Merkle tree (integrity only), NOT a LUKS `--integrity` volume
# (a shared LUKS master key would let a miner running its OWN
# same-distro VM forge integrity-valid tampered ciphertext → cross-tenant
# RCE).
#
# Every tenant-mutable byte lands on a PER-VM, guest-keyed writable
# overlay UPPER:
#
#   overlayfs root = lowerdir (RO dm-verity golden base, shared)
#                  + upperdir (per-VM guest-keyed LUKS2+integrity volume)
#
# ═══════════════════════════════════════════════════════════════════
# THE MAKE-OR-BREAK INVARIANT (fully untrusted miner)
# ═══════════════════════════════════════════════════════════════════
# The upper's LUKS master key is GENERATED INSIDE the SNP guest by
# `cryptsetup luksFormat` at first boot (fresh /dev/urandom MK) and
# NEVER leaves the guest — exactly like the `/dev/vde` data disk
# (`data_disk.rs`). It is NEVER the shared golden key (the golden base
# has NO key at all).
#
# The upper's keyslot passphrase is the PER-VM KEK that the §21 KBS
# release returns — the SAME per-VM, HSM-wrapped KEK legacy `/dev/vda`
# uses, released ONLY to the attested guest and authorized PER-VM by the
# KBS ticket (per-VM authz, PR2). The miner never sees the KEK plaintext
# and cannot get another tenant's KEK (a different ticket → a different
# KEK). Because the KBS release is per-VM-authorized, the upper is
# exactly as confidential as legacy `/dev/vda`, EVEN THOUGH the golden
# measurement is shared across same-distro tenants.
#
# WHY NOT an SNP-measurement-derived sealing key (SNP_GET_DERIVED_KEY):
# the reboot-stable derived key the host-attestor uses is VCEK-bound +
# MEASUREMENT-only (`agent-host-attestor::derived_key`). In golden mode
# the measurement is SHARED across same-distro tenants (PR2), and the
# VCEK is per-CHIP, so a miner running its OWN same-distro golden VM on
# the same host derives the IDENTICAL key and could unwrap a co-located
# tenant's upper. SNP_GET_DERIVED_KEY has NO per-VM authorization input,
# so it is UNSAFE as the upper's anchor. The KBS KEK, gated by the
# per-VM ticket, is the safe anchor and is reused verbatim.
#
# ═══════════════════════════════════════════════════════════════════
# SECRET DISCIPLINE (§20)
# ═══════════════════════════════════════════════════════════════════
# The KEK plaintext touches: `hippius-guest-release` stdout → a tmpfs
# 0600 keyfile → `cryptsetup --key-file`. Diagnostics go to stderr/kmsg;
# the KEK is NEVER on a log line. The guest MK never leaves cryptsetup.
# Failure paths shred the KEK + fail closed (the disk stays locked, the
# overlay is never mounted, the boot aborts).

# ── Device / parameter defaults (overridable by cmdline tokens) ──────
# The RO dm-verity golden lower — the SAME `/dev/vdb` (squashfs data) +
# `/dev/vdc` (hash tree) the miner-agent already attaches (qemu_config.rs
# vdb/vdc). The verity superblock on `/dev/vdc` carries salt/uuid/
# hash-alg/block-sizes; ONLY the 64-hex root hash travels on the
# measured cmdline (`dm-verity.root=`), matching the vali emitter (PR2)
# and the Rust guest parser (`agent-initramfs::stages::verity`).
HIPPIUS_GOLDEN_LOWER_DATA_DEFAULT="/dev/vdb"
HIPPIUS_GOLDEN_LOWER_HASH_DEFAULT="/dev/vdc"
# The per-VM guest-keyed writable upper. `/dev/vda` in golden mode is a
# BLANK per-VM disk the miner-agent attaches (golden.rs), NOT a baked
# tenant qcow2 — the guest formats it fresh at first boot.
HIPPIUS_GOLDEN_UPPER_DEFAULT="/dev/vda"

# dm-mapper names (fixed — no per-boot names, mirroring the Rust
# `verity::MAPPER_NAME` / `unlock::MAPPER_NAME` discipline).
HIPPIUS_GOLDEN_LOWER_MAPPER="hippius-golden"
HIPPIUS_GOLDEN_UPPER_MAPPER="hippius-upper"

# First-boot ext4 formatter for the guest-keyed upper. The golden hook
# (`hippius-golden-hook`) stages the REAL e2fsprogs `mkfs.ext4` here, at a
# hippius-private path busybox never installs into. This is deliberate:
# some distros' busybox ships an `mke2fs` applet (Debian trixie does), and
# the `0_busybox` initramfs-tools hook — which runs BEFORE ours — installs
# busybox as `/usr/sbin/mke2fs`; `copy_exec` is idempotent (skips a target
# that already exists) so the real e2fsprogs binary never lands, and the
# `mkfs.ext4 -> mke2fs` symlink resolves to busybox, which has no
# `mkfs.ext4` applet ("applet not found") → the first-boot format would
# fail closed. Overridable so the unit test can point it at a stub.
: "${HIPPIUS_GOLDEN_MKFS:=/lib/hippius/mkfs.ext4}"

# Mount points inside the initramfs (moved across switch_root only via
# the final overlay at $rootmnt; these staging mounts stay in the
# initramfs and are shadowed after the pivot).
HIPPIUS_GOLDEN_LOWER_MNT="/hippius-golden/lower"
HIPPIUS_GOLDEN_UPPER_MNT="/hippius-golden/upper"

# ── Anti-rollback: bind a CONFIRMED stamp to the volume it protects ──
#
# THE HOLE THIS CLOSES (documented, and confirmed reproducible, at
# `binaries/miner-agent/src/lifecycle/state_disk.rs`):
# the Phase-2B anti-rollback counter lives on `/dev/vdd`, a 1 MiB
# PLAINTEXT ext4 "state disk" the miner can read AND write. Nothing
# binds that counter to the ciphertext it is meant to protect. So a
# malicious host can:
#   1. snapshot the LUKS overlay (`/dev/vda`) at boot N,
#   2. let the VM run on to boot N+k,
#   3. restore the OLD overlay image while LEAVING the CURRENT counter
#      (N+k) on the state disk.
# The guest then submits N+k+1, the KBS compare-and-swap PASSES, the
# KEK is released, and the stale overlay opens with ZERO integrity
# errors — dm-integrity is satisfied because the old image is authentic
# ciphertext under the same master key. Net effect: the miner silently
# reverts the tenant's disk (undoes a security patch, resurrects deleted
# or rotated credentials, replays application state).
#
# THE FIX: keep a stamp INSIDE the encrypted volume and compare it,
# after unlock and BEFORE the overlayfs root is assembled, against an
# expectation the KBS supplies in the SIGNED release response.
#
# ── WHY NOT COMPARE AGAINST THE STATE DISK (the obvious design, and
#    why it is worse than the bug) ─────────────────────────────────
# The tempting version of this gate compares the in-volume copy against
# the plaintext boot counter with a small tolerance. That is BROKEN, and
# dangerously so. The boot counter advances on every successful
# RELEASE, not on every successful BOOT: `kbs-core::release` commits it
# the moment the release is durably committed and has no idea whether
# the guest ever finishes booting, and `hippius_acquire` writes the
# state disk before `hippius_golden_open_upper` even runs. A boot that
# dies anywhere between the KEK release and this gate therefore leaves
# the counter one ahead of the volume, and THE GAP GROWS BY ONE PER
# ABORTED BOOT. The host controls the VM's lifetime — boot it, let it
# take the KEK, kill it, repeat — so any fixed tolerance S is exhausted
# after S+1 kill cycles, after which the volume can NEVER be opened
# again, on any host, because the KBS counter is authoritative and
# nothing can re-stamp the volume. That trades a silent rollback for a
# trivial, permanent, unrecoverable destruction primitive.
#
# ── THE REFERENCE THAT ACTUALLY WORKS ───────────────────────────────
# The KBS keeps a second per-VM value, the CONFIRMED volume stamp
# (`kbs-core::volume_stamp`), which moves ONLY when a guest has
# confirmed that it actually wrote the stamp. The release response
# carries it as `expected_volume_stamp` (E) plus a single-use,
# HPKE-sealed token authorising an advance to E+1. This gate compares
# the in-volume stamp S against E, writes E+1, and then confirms. An
# aborted boot confirms nothing, so E does not move and no gap can
# accumulate.
#
# The three rollback cases stay exhaustive:
#   - roll back the OVERLAY only  → S < E → this gate refuses.
#   - roll back the STATE DISK only → the guest submits a stale boot
#     counter → the KBS CAS refuses (`kbs-core::release` gate 5b).
#   - roll back BOTH → same stale submission → the KBS CAS refuses.
# The attacker cannot strip this check: it lives in the MEASURED boot
# path (the dm-verity'd golden base / the measured initramfs), so
# removing it changes the launch measurement and the KBS refuses the
# KEK outright.
#
# The stamp lives at the ROOT of the guest-keyed volume — one level
# ABOVE the overlayfs `upperdir` (`<upper-mnt>/upper`) — so the tenant's
# merged filesystem never sees it and in-guest root cannot edit it.
HIPPIUS_GOLDEN_STAMP_NAME=".hippius-volume-stamp"

# THE ACCEPT WINDOW is exactly {E, E+1}, i.e. a slack of ONE that
# CANNOT accumulate.
#
# S == E     — the steady state.
# S == E + 1 — the guest wrote the stamp but the confirm did not land
#              (crash, or the miner dropped the request). The next boot
#              re-confirms and converges.
# The guest NEVER writes beyond E+1, so the divergence is bounded at one
# BY CONSTRUCTION rather than by a tolerance constant — repeated aborted
# boots leave both E and S exactly where they were.
#
# S > E + 1 is impossible for an honest guest and is refused.
# S < E is the rollback and is refused.

# Tmpfs paths `hippius-guest-release` writes during the release (see
# HIPPIUS_EXTRA_RELEASE_FLAGS below). The EXPECTED file holds one
# decimal integer and nothing secret; the CTX file is 0600 and holds the
# confirm token, and is touched ONLY by `hippius-guest-release
# --confirm-volume-stamp` — this shell never reads it, so the token
# never enters the script's environment (§20).
HIPPIUS_GOLDEN_STAMP_EXPECTED="${HIPPIUS_GOLDEN_STAMP_EXPECTED:-/run/hippius/volume-stamp.expected}"
HIPPIUS_GOLDEN_STAMP_CTX="${HIPPIUS_GOLDEN_STAMP_CTX:-/run/hippius/volume-stamp.ctx}"

# ── cmdline token readers (pure; unit-tested) ───────────────────────
# Read a `key=value` token from a cmdline string. Echoes the value or
# nothing. Kept parameterized (not reading /proc/cmdline directly) so
# the resolvers are testable without a live /proc.
hippius_golden_cmdline_value() {
    _hgcv_cmdline="$1"
    _hgcv_key="$2"
    for _hgcv_tok in ${_hgcv_cmdline}; do
        case "${_hgcv_tok}" in
            "${_hgcv_key}="*)
                printf '%s' "${_hgcv_tok#"${_hgcv_key}"=}"
                return 0 ;;
        esac
    done
    return 1
}

# GOLDEN-mode signal, computed from a cmdline STRING (pure; testable).
# Robust signal, consistent with PR2 + the Rust guest: golden ⇔
# `dm-verity.root=` PRESENT and `hippius.luks_header_sha256=` ABSENT.
# Requiring BOTH conditions fail-closes on a half-formed cmdline (a
# miner cannot flip a legacy VM into golden — the cmdline is measured).
hippius_is_golden_cmdline() {
    _higc_cmdline="$1"
    if hippius_golden_cmdline_value "${_higc_cmdline}" "dm-verity.root" >/dev/null 2>&1 \
        && ! hippius_golden_cmdline_value "${_higc_cmdline}" "hippius.luks_header_sha256" >/dev/null 2>&1
    then
        return 0
    fi
    return 1
}

# Live wrapper: is THIS boot golden? Reads /proc/cmdline.
hippius_is_golden_mode() {
    hippius_is_golden_cmdline "$(cat /proc/cmdline 2>/dev/null || true)"
}

# Validate a dm-verity root hash: exactly 64 lowercase hex chars (a
# SHA-256 Merkle root). Fail-closed on anything else (mirrors the Rust
# `verity::resolve_verity_root_hash_from` ROOT_HEX check + the vali
# emitter regex).
hippius_golden_valid_root_hash() {
    case "$1" in
        *[!0-9a-f]* | "") return 1 ;;
    esac
    [ "$(printf '%s' "$1" | wc -c)" -eq 64 ]
}

# Validate `hippius.disk_gb=` — a positive decimal integer (the MEASURED
# size anchor for the upper; a miner cannot shrink it without changing
# the launch digest).
hippius_golden_valid_disk_gb() {
    case "$1" in
        "" | *[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] 2>/dev/null
}

# ── Golden parameter resolution (fail-closed) ───────────────────────
# Sets, from /proc/cmdline:
#   HIPPIUS_GOLDEN_ROOT_HASH   (required, 64-hex, MEASURED integrity anchor)
#   HIPPIUS_GOLDEN_DISK_GB     (required, positive int, MEASURED size anchor)
#   HIPPIUS_GOLDEN_LOWER_DATA / _HASH / UPPER  (device overrides or defaults)
hippius_golden_resolve() {
    _hgr_cmdline="$(cat /proc/cmdline 2>/dev/null || true)"

    HIPPIUS_GOLDEN_ROOT_HASH="$(hippius_golden_cmdline_value "${_hgr_cmdline}" "dm-verity.root" || true)"
    hippius_golden_valid_root_hash "${HIPPIUS_GOLDEN_ROOT_HASH}" \
        || hippius_die "golden: dm-verity.root= missing/malformed (need 64 lowercase hex)"

    HIPPIUS_GOLDEN_DISK_GB="$(hippius_golden_cmdline_value "${_hgr_cmdline}" "hippius.disk_gb" || true)"
    hippius_golden_valid_disk_gb "${HIPPIUS_GOLDEN_DISK_GB}" \
        || hippius_die "golden: hippius.disk_gb= missing/malformed (need positive integer)"

    HIPPIUS_GOLDEN_LOWER_DATA="$(hippius_golden_cmdline_value "${_hgr_cmdline}" "hippius.rootfs_data" || printf '%s' "${HIPPIUS_GOLDEN_LOWER_DATA_DEFAULT}")"
    HIPPIUS_GOLDEN_LOWER_HASH="$(hippius_golden_cmdline_value "${_hgr_cmdline}" "hippius.rootfs_hash" || printf '%s' "${HIPPIUS_GOLDEN_LOWER_HASH_DEFAULT}")"
    HIPPIUS_GOLDEN_UPPER="$(hippius_golden_cmdline_value "${_hgr_cmdline}" "hippius.overlay_upper" || printf '%s' "${HIPPIUS_GOLDEN_UPPER_DEFAULT}")"

    hippius_log "golden: lower=${HIPPIUS_GOLDEN_LOWER_DATA}(+${HIPPIUS_GOLDEN_LOWER_HASH}) upper=${HIPPIUS_GOLDEN_UPPER} disk_gb=${HIPPIUS_GOLDEN_DISK_GB}"
}

# ── dm-verity modules (golden-only; keeps the legacy modprobe chain
#    byte-identical) ────────────────────────────────────────────────
hippius_golden_modprobe() {
    for _hgm in dm_mod dm_verity overlay squashfs; do
        modprobe "${_hgm}" 2>>/dev/kmsg || true
    done
}

# ── Open the RO dm-verity golden lower (integrity, no key) ──────────
# `veritysetup open <data> <name> <hash> <root_hash>` reconstructs the
# device-mapper verity target; the kernel verifies EVERY read against
# the Merkle tree rooted at the MEASURED root hash, so a miner tampering
# any byte of `/dev/vdb`/`/dev/vdc` yields EIO (invariant A — holds even
# if the attacker holds a golden KEK from its own VM: there is no key).
#
# Fail-closed asserts AFTER open: the mapper MUST be verity-type AND
# read-only. A golden lower that is somehow writable would break the
# "no tenant-mutable byte on shared bytes" invariant.
hippius_golden_open_lower() {
    [ -b "${HIPPIUS_GOLDEN_LOWER_DATA}" ] || hippius_die "golden: lower data ${HIPPIUS_GOLDEN_LOWER_DATA} is not a block device"
    [ -b "${HIPPIUS_GOLDEN_LOWER_HASH}" ] || hippius_die "golden: lower hash ${HIPPIUS_GOLDEN_LOWER_HASH} is not a block device"

    veritysetup open \
        "${HIPPIUS_GOLDEN_LOWER_DATA}" \
        "${HIPPIUS_GOLDEN_LOWER_MAPPER}" \
        "${HIPPIUS_GOLDEN_LOWER_HASH}" \
        "${HIPPIUS_GOLDEN_ROOT_HASH}" >>/dev/kmsg 2>&1 \
        || hippius_die "golden: veritysetup open failed (tampered base or wrong root hash) — fail-closed"

    # Assert verity is genuinely active (type=VERITY) — not some other
    # target a miner-substituted mapper could present.
    if ! veritysetup status "${HIPPIUS_GOLDEN_LOWER_MAPPER}" 2>/dev/null | grep -qi 'type:.*VERITY'; then
        veritysetup close "${HIPPIUS_GOLDEN_LOWER_MAPPER}" 2>/dev/null || true
        hippius_die "golden: dm-verity mapper is not VERITY-type — fail-closed"
    fi
    # Assert the mapper is read-only (blockdev --getro == 1). dm-verity
    # is RO by construction; this is defense-in-depth.
    if [ "$(blockdev --getro "/dev/mapper/${HIPPIUS_GOLDEN_LOWER_MAPPER}" 2>/dev/null || echo 0)" != "1" ]; then
        veritysetup close "${HIPPIUS_GOLDEN_LOWER_MAPPER}" 2>/dev/null || true
        hippius_die "golden: dm-verity mapper is not read-only — fail-closed"
    fi
    hippius_log "golden: dm-verity lower active + RO (root=${HIPPIUS_GOLDEN_ROOT_HASH})"
}

# ── Open (first-boot: FORMAT) the per-VM guest-keyed writable upper ──
# Arg 1 = path to the tmpfs keyfile holding the 32-byte KBS KEK.
#
# Size anchor: the upper block device MUST be at least the MEASURED
# `hippius.disk_gb`. A miner attaching a short disk fails closed
# (mirrors data_disk.rs' size-anchor discipline — never trust the file
# length, enforce the attested size).
#
# First-boot detection: `cryptsetup isLuks`. A blank per-VM disk is not
# LUKS → luksFormat --integrity (MK generated in-guest, keyslot wrapped
# by the KEK) → open → mkfs.ext4. A subsequent boot finds a LUKS header
# → open with the KEK. A miner planting a foreign LUKS header only makes
# `open` fail (its keyslots are not for OUR per-VM KEK) → fail-closed;
# no reformat, no data loss, boot aborts.
# Resolve the first-boot ext4 formatter. Prefer the busybox-shadow-proof
# private copy the golden hook stages; fall back to `$PATH` `mkfs.ext4`
# (Ubuntu's busybox omits the `mke2fs` applet so its real e2fsprogs binary
# survives in `$PATH`; a dracut-family initrd stages no private copy). Kept
# as a tiny pure resolver so it is unit-testable without a live format.
hippius_golden_mkfs_bin() {
    if [ -x "${HIPPIUS_GOLDEN_MKFS}" ]; then
        echo "${HIPPIUS_GOLDEN_MKFS}"
    else
        echo "mkfs.ext4"
    fi
}

hippius_golden_open_upper() {
    _hgou_kek="$1"
    [ -b "${HIPPIUS_GOLDEN_UPPER}" ] || hippius_die "golden: upper ${HIPPIUS_GOLDEN_UPPER} is not a block device"
    [ -r "${_hgou_kek}" ] || hippius_die "golden: KEK keyfile missing"
    [ "$(wc -c < "${_hgou_kek}")" -eq 32 ] || hippius_die "golden: KEK is not 32 bytes — fail-closed"

    # Size anchor (attested vs actual). 1 GiB = 1073741824 bytes.
    _hgou_want=$(( HIPPIUS_GOLDEN_DISK_GB * 1073741824 ))
    _hgou_have="$(blockdev --getsize64 "${HIPPIUS_GOLDEN_UPPER}" 2>/dev/null || echo 0)"
    if [ "${_hgou_have}" -lt "${_hgou_want}" ]; then
        hippius_die "golden: upper too small (have=${_hgou_have} want>=${_hgou_want}) — miner under-provisioned, fail-closed"
    fi

    if cryptsetup isLuks "${HIPPIUS_GOLDEN_UPPER}" 2>/dev/null; then
        hippius_log "golden: upper already LUKS — reopening (persisted tenant writes)"
        cryptsetup open "${HIPPIUS_GOLDEN_UPPER}" "${HIPPIUS_GOLDEN_UPPER_MAPPER}" \
            --key-file "${_hgou_kek}" >>/dev/kmsg 2>&1 \
            || hippius_die "golden: upper open failed (wrong/absent KEK or tampered header) — fail-closed"
    else
        hippius_log "golden: upper blank — first-boot luksFormat --integrity (MK generated in-guest, never leaves)"
        # LUKS2 + dm-integrity (hmac-sha256): authenticated encryption,
        # so a miner tampering the upper ciphertext read-faults (EIO)
        # rather than silently corrupting — same guarantee as vde.
        # The MK is generated fresh from the kernel CSPRNG INSIDE this
        # SNP guest; only the KEK (per-VM) protects the keyslot.
        cryptsetup luksFormat --type luks2 --integrity hmac-sha256 \
            --batch-mode "${HIPPIUS_GOLDEN_UPPER}" --key-file "${_hgou_kek}" >>/dev/kmsg 2>&1 \
            || hippius_die "golden: upper luksFormat failed — fail-closed"
        cryptsetup open "${HIPPIUS_GOLDEN_UPPER}" "${HIPPIUS_GOLDEN_UPPER_MAPPER}" \
            --key-file "${_hgou_kek}" >>/dev/kmsg 2>&1 \
            || hippius_die "golden: upper open (post-format) failed — fail-closed"
        # dm-integrity data-device init has already zeroed integrity
        # tags via the format; lay down a fresh ext4 for the overlay
        # upperdir/workdir.
        "$(hippius_golden_mkfs_bin)" -q -F "/dev/mapper/${HIPPIUS_GOLDEN_UPPER_MAPPER}" >>/dev/kmsg 2>&1 \
            || hippius_die "golden: mkfs.ext4 on upper failed — fail-closed"
    fi
    hippius_log "golden: per-VM guest-keyed upper open at /dev/mapper/${HIPPIUS_GOLDEN_UPPER_MAPPER}"
}

# ── Mount the overlay at $rootmnt (lower + upper already open) ───────
# Split from the driver (golden-bake PR5) so the RO dm-verity lower can
# be opened + verity/RO-asserted BEFORE any network / KBS KEK release
# (validate-before-mutate), and the guest-keyed upper opened only AFTER
# the per-VM KEK is released.
# Arg 1 = the distro rootfs mount point ($rootmnt on initramfs-tools;
#         /sysroot on dracut).
# lowerdir = RO dm-verity golden base (shared, integrity-only)
# upperdir = /<upper-mnt>/upper (per-VM guest-keyed, all tenant writes)
# workdir  = /<upper-mnt>/work  (overlayfs scratch, MUST share the upper fs)
# Stamp the RO lower's "/" SELinux label onto the per-VM upper's overlay-root
# dir so the merged overlay "/" inherits it (overlayfs takes the merged root
# label from the UPPER dir inode, ignoring the `rootcontext=` mount option).
# Prefer the REAL label the golden base carries on "/" (read from the mounted
# lower); fall back to the canonical targeted-policy root label. Fail CLOSED if
# the label is malformed or the stamp fails — an unlabeled "/" bricks the
# enforcing guest. `HIPPIUS_GOLDEN_ROOT_SECONTEXT` overrides the resolved
# value (test/ops knob).
hippius_golden_label_upper_root() {
    _hglur="${HIPPIUS_GOLDEN_ROOT_SECONTEXT:-}"
    if [ -z "${_hglur}" ] && command -v getfattr >/dev/null 2>&1; then
        _hglur="$(getfattr --absolute-names -n security.selinux --only-values \
            "${HIPPIUS_GOLDEN_LOWER_MNT}" 2>/dev/null | tr -d '\000')"
    fi
    [ -n "${_hglur}" ] || _hglur="system_u:object_r:root_t:s0"
    # The label is interpolated into a `setfattr -v` value; it is a measured
    # constant / non-attacker-settable, but reject anything not shaped like an
    # SELinux context `user:role:type:level[:mcs]` (defense-in-depth).
    case "${_hglur}" in
        *[!:_a-zA-Z0-9.,-]* )
            hippius_die "golden: refusing malformed root secontext '${_hglur}'" ;;
        *:*:*:* ) : ;;
        * )
            hippius_die "golden: refusing non-context root secontext '${_hglur}'" ;;
    esac
    setfattr -n security.selinux -v "${_hglur}" "${HIPPIUS_GOLDEN_UPPER_MNT}/upper" \
        || hippius_die "golden: failed to stamp overlay upper-root label '${_hglur}'"
    hippius_log "golden: SELinux base — stamped overlay root label ${_hglur}"
}

# ── Anti-rollback helpers (pure-ish; unit-tested against temp dirs) ──
# Parse an ASCII-decimal counter. Echoes the value and returns 0; returns
# 1 (echoing nothing) on empty / non-decimal / absurdly long input. The
# 18-digit cap keeps the later `$(( ))` comparison inside every POSIX
# shell's signed-integer range (dash/busybox ash use intmax_t); a real
# counter is a boot count, so 10^18 is unreachable.
hippius_golden_parse_counter() {
    _hgpc_v="$1"
    case "${_hgpc_v}" in
        "" | *[!0-9]*) return 1 ;;
    esac
    [ "${#_hgpc_v}" -le 18 ] || return 1
    printf '%s' "${_hgpc_v}"
}

# Read the KBS's expectation for THIS boot — the last CONFIRMED volume
# stamp, echoed in the SIGNED release response and written to tmpfs by
# `hippius-guest-release --volume-stamp-expected-out`. Echoes the value
# (exit 0) or nothing (exit 1 = no expectation available).
#
# Note what is NOT here any more: the read-only re-mount of the
# miner-writable `/dev/vdd`. The expectation now arrives inside a
# KBS-signed response, so the reference value is no longer something the
# host can write at all.
hippius_golden_expected_stamp() {
    [ -r "${HIPPIUS_GOLDEN_STAMP_EXPECTED}" ] || return 1
    hippius_golden_parse_counter "$(cat "${HIPPIUS_GOLDEN_STAMP_EXPECTED}" 2>/dev/null || true)"
}

# Tell the KBS the stamp landed. ONLY this advances the KBS's
# expectation, which is what keeps an aborted boot from moving it.
#
# DELIBERATELY NON-FATAL. If this fails (network blip, or a miner simply
# dropping the request) the volume is at E+1 while the KBS is still at E
# — which the {E, E+1} accept window absorbs, and the next boot
# re-confirms. Making it fatal would hand the miner a trivial denial of
# service: block one route, refuse every boot. A miner who blocks it
# forever freezes the expectation at E rather than disabling the gate —
# E is still enforced as a floor, so rollback past it is still refused.
hippius_golden_confirm_stamp() {
    [ -r "${HIPPIUS_GOLDEN_STAMP_CTX}" ] || {
        hippius_log "golden: anti-rollback: no confirm context at ${HIPPIUS_GOLDEN_STAMP_CTX} — stamp NOT confirmed (next boot re-confirms)"
        return 0
    }
    # Capture the binary's diagnostics rather than redirecting them
    # straight at /dev/kmsg, so the classifier lands on the SAME
    # hippius_log line as the verdict. Safe under §20: the confirm token
    # is never printed by `hippius-guest-release` (its diagnostics are
    # classifier-only, enforced by scripts/check-no-seed-logging.sh), and
    # this shell never reads the ctx file itself.
    if _hgcs_out="$(hippius-guest-release --confirm-volume-stamp "${HIPPIUS_GOLDEN_STAMP_CTX}" \
        --kbs-url "${HIPPIUS_KBS_URL}" 2>&1)"; then
        hippius_log "golden: anti-rollback: stamp CONFIRMED to the KBS"
    else
        hippius_log "golden: anti-rollback WARNING: stamp confirm FAILED (${_hgcs_out}) — booting anyway; the KBS expectation stays put and the next boot re-confirms (a dropped confirm must not be a denial of service)"
    fi
    return 0
}

# Persist `$2` to `$1` (0600) as ASCII decimal + newline.
# tmp-write → sync → rename → sync: `rename(2)` is atomic within the
# directory, so a crash can never leave a HALF-WRITTEN counter behind —
# which is what lets the reader treat an unparseable value as hostile
# rather than as a torn write. Fail CLOSED on any write error: the same
# volume root is about to receive `mkdir upper work`, so an unwritable
# upper aborts the boot two lines later anyway.
hippius_golden_write_counter() {
    _hgwc_path="$1"
    _hgwc_val="$2"
    _hgwc_tmp="${_hgwc_path}.new"
    ( umask 0177; printf '%s\n' "${_hgwc_val}" > "${_hgwc_tmp}" ) \
        || hippius_die "golden: anti-rollback: cannot stage in-volume boot counter at ${_hgwc_tmp} — fail-closed"
    sync
    mv -f "${_hgwc_tmp}" "${_hgwc_path}" \
        || hippius_die "golden: anti-rollback: cannot commit in-volume boot counter to ${_hgwc_path} — fail-closed"
    sync
}

# THE GATE. `hippius_golden_check_stamp <volume-root> <expected>`
#   <volume-root> = the mounted guest-keyed volume (NOT the overlayfs
#                   upperdir — the stamp must sit one level above it so
#                   the tenant root can neither see nor edit it).
#   <expected>    = E, the last CONFIRMED stamp from the SIGNED release
#                   response, or "" when this boot has no expectation.
#
# Refuses (hippius_die → the caller's KEK-shred + fail-closed abort)
# unless the in-volume stamp S is in {E, E+1}. On accept it writes E+1
# and the caller confirms it.
#
# E == 0 — no expectation on record: a genuinely fresh VM, a VM that
# predates this gate, or a REBUILT KBS store (`vali_kbs_recover`). Adopt
# whatever is there and stamp 1. This is the self-healing path that
# stops a lost KBS store from bricking the fleet; it is gated by KBS
# integrity, exactly like the boot counter's own `stored == 0` handling.
#
# LEGACY MIGRATION: every VM that exists today has NO in-volume stamp. An
# ABSENT stamp is therefore accepted EXACTLY ONCE and then created —
# absence is indistinguishable from a first boot under this code, and
# treating it as an attack would brick every live tenant on the first
# deploy. Only a PRESENT-and-too-old stamp is a refusal. The accept paths
# log DISTINCTLY so an operator can watch the fleet converge.
#
# UNPARSEABLE ⇒ REFUSE (not "legacy"). Absence is the legacy signal; a
# present-but-garbage value is not a legacy VM. It cannot be a torn
# write (see `hippius_golden_write_counter`'s rename), and it cannot be
# miner-authored — the stamp lives inside a LUKS2+dm-integrity volume the
# miner has no key for, so any tampering surfaces as EIO, not as garbage.
# That leaves only "our own bug", which must fail closed.
#
# NO EXPECTATION AT ALL (the file is missing): this is NOT the same as
# E == 0. The expected file and the in-volume stamp are written by the
# SAME measured code, so a stamped volume with no expectation is
# incoherent — either the release did not run the stamp path (an image
# built without it) or something is wrong we do not model. Refuse. This
# is the one piece of armour carried over from the state-disk design; it
# is not redundant, it has simply been re-anchored from "the miner
# detached /dev/vdd" to "the expectation did not arrive".
hippius_golden_check_stamp() {
    _hgcs_root="$1"
    _hgcs_expected="$2"
    _hgcs_file="${_hgcs_root}/${HIPPIUS_GOLDEN_STAMP_NAME}"

    if [ -z "${_hgcs_expected}" ]; then
        if [ -e "${_hgcs_file}" ]; then
            hippius_die "golden: ANTI-ROLLBACK REFUSED — the volume carries a stamp but this boot received NO expectation from the KBS (expected=<absent>) — fail-closed"
        fi
        hippius_log "golden: anti-rollback: no KBS expectation and no in-volume stamp — nothing to bind (pre-gate image)"
        return 0
    fi

    _hgcs_target="$(( _hgcs_expected + 1 ))"

    if [ ! -e "${_hgcs_file}" ]; then
        if [ "${_hgcs_expected}" -eq 0 ]; then
            hippius_log "golden: anti-rollback SEED — fresh volume, stamping ${_hgcs_target}"
        else
            hippius_log "golden: anti-rollback MIGRATION — pre-existing VM with no in-volume stamp; accepting ONCE and stamping ${_hgcs_target} (every later boot is compared)"
        fi
        hippius_golden_write_counter "${_hgcs_file}" "${_hgcs_target}"
        return 0
    fi

    _hgcs_in="$(hippius_golden_parse_counter "$(cat "${_hgcs_file}" 2>/dev/null || true)" || true)"
    if [ -z "${_hgcs_in}" ]; then
        hippius_die "golden: ANTI-ROLLBACK REFUSED — the in-volume stamp is unparseable (expected=${_hgcs_expected} in_volume=<malformed>) — fail-closed"
    fi

    # E == 0 ⇒ no expectation on record; adopt whatever is present.
    if [ "${_hgcs_expected}" -eq 0 ]; then
        hippius_log "golden: anti-rollback ADOPT — the KBS holds no confirmed stamp (fresh VM or rebuilt store); adopting in_volume=${_hgcs_in} and stamping ${_hgcs_target}"
        hippius_golden_write_counter "${_hgcs_file}" "${_hgcs_target}"
        return 0
    fi

    if [ "${_hgcs_in}" -lt "${_hgcs_expected}" ]; then
        hippius_die "golden: ANTI-ROLLBACK REFUSED — the guest-keyed overlay is STALE: in_volume=${_hgcs_in} expected=${_hgcs_expected}; the host restored an OLD upper — fail-closed"
    fi
    if [ "${_hgcs_in}" -gt "${_hgcs_target}" ]; then
        hippius_die "golden: ANTI-ROLLBACK REFUSED — the in-volume stamp is AHEAD of anything an honest guest could have written: in_volume=${_hgcs_in} expected=${_hgcs_expected} (max ${_hgcs_target}) — fail-closed"
    fi

    if [ "${_hgcs_in}" -eq "${_hgcs_target}" ]; then
        hippius_log "golden: anti-rollback OK — in_volume=${_hgcs_in} expected=${_hgcs_expected}: the previous boot's confirm did not land; re-confirming ${_hgcs_target}"
    else
        hippius_log "golden: anti-rollback OK — in_volume=${_hgcs_in} expected=${_hgcs_expected}; stamping ${_hgcs_target}"
    fi
    hippius_golden_write_counter "${_hgcs_file}" "${_hgcs_target}"
}

hippius_golden_mount_overlay() {
    _hgmo_rootmnt="$1"

    mkdir -p "${HIPPIUS_GOLDEN_LOWER_MNT}" "${HIPPIUS_GOLDEN_UPPER_MNT}"
    mount -o ro "/dev/mapper/${HIPPIUS_GOLDEN_LOWER_MAPPER}" "${HIPPIUS_GOLDEN_LOWER_MNT}" \
        || hippius_die "golden: mount RO lower failed"
    mount "/dev/mapper/${HIPPIUS_GOLDEN_UPPER_MAPPER}" "${HIPPIUS_GOLDEN_UPPER_MNT}" \
        || hippius_die "golden: mount upper failed"

    # Anti-rollback: the encrypted volume is open and the overlayfs is
    # NOT yet assembled — the only window where the in-volume stamp is
    # reachable and the tenant root does not exist yet. Refuses a stale
    # (host-restored) upper before a single tenant byte is exposed, then
    # confirms the new stamp so the KBS expectation advances in lockstep
    # with the volume (and ONLY with the volume).
    _hgmo_expected="$(hippius_golden_expected_stamp || true)"
    hippius_golden_check_stamp "${HIPPIUS_GOLDEN_UPPER_MNT}" "${_hgmo_expected}"
    hippius_golden_confirm_stamp

    # overlayfs requires upperdir + workdir on the SAME (writable) fs.
    mkdir -p "${HIPPIUS_GOLDEN_UPPER_MNT}/upper" "${HIPPIUS_GOLDEN_UPPER_MNT}/work"

    # SELinux root-inode label (RHEL family: CentOS Stream 10 / Fedora).
    #
    # The per-VM upper is a freshly `mkfs.ext4`'d volume with NO SELinux
    # labels. overlayfs derives the MERGED root dir ("/") label from the
    # UPPER's own root-dir inode — NOT from a `rootcontext=` mount option
    # (overlayfs silently ignores it) and NOT from the RO lower. So an
    # enforcing guest sees "/" as `unlabeled_t` and DENIES every confined
    # domain `search /` (journald / NetworkManager / netbird / serial-getty
    # all fail — only fully-unconfined init runs, so the guest boots but has
    # no network, console or NetBird enrolment). The RO dm-verity lower carries
    # the correct label ("/" = `root_t`), so STAMP that label onto the upper's
    # overlay-root dir BEFORE the overlay mount — the merged "/" inherits it.
    # Writing `security.selinux` here is a raw xattr op (SELinux policy is not
    # yet loaded in the initramfs), root-owned. This RESTORES confinement: all
    # lower files keep their own labels and copied-up dirs inherit the lower's
    # `security.selinux` xattr; only the root inode is stamped. Gated on the
    # lower shipping /etc/selinux/config ⇒ the initramfs-tools (Debian/Ubuntu,
    # no SELinux) path is byte-identical.
    if [ -e "${HIPPIUS_GOLDEN_LOWER_MNT}/etc/selinux/config" ]; then
        hippius_golden_label_upper_root
    fi

    mkdir -p "${_hgmo_rootmnt}"
    mount -t overlay hippius-overlay \
        -o "lowerdir=${HIPPIUS_GOLDEN_LOWER_MNT},upperdir=${HIPPIUS_GOLDEN_UPPER_MNT}/upper,workdir=${HIPPIUS_GOLDEN_UPPER_MNT}/work" \
        "${_hgmo_rootmnt}" \
        || hippius_die "golden: overlayfs mount at ${_hgmo_rootmnt} failed"

    hippius_log "golden: overlay root ready at ${_hgmo_rootmnt} (lower=RO-verity, upper=per-VM guest-keyed)"
}

# ── §20: shred the tmpfs KEK keyfile (idempotent, quiet) ────────────
# Safe to call on EVERY exit path — the success path, a mid-path
# `hippius_die`, or after the file was already removed. `shred -u`
# overwrites then unlinks; `rm -f` is the fallback if shred is
# unavailable. Never logs the path's contents (§20).
hippius_golden_shred_kek() {
    [ -n "${1:-}" ] || return 0
    shred -u "$1" 2>/dev/null || rm -f "$1" 2>/dev/null || true
}

# ── Driver: the full golden boot ────────────────────────────────────
# `hippius_golden_run <rootmnt>` — the golden analogue of the legacy
# wrappers. Reuses the AUDITED §21 release sequence verbatim
# (`hippius_parse_cmdline` + `hippius_acquire` from
# hippius-release-core.sh: net → ticket → state-disk anti-rollback →
# seed → KBS release), then assembles the overlay instead of handing
# the KEK to the crypttab. NOTE it does NOT call `hippius_verify_header`
# (the golden base is unkeyed dm-verity — there is no measured LUKS
# header to verify; integrity is the dm-verity root hash + the guest-
# keyed upper). The core's `hippius_verify_header` also self-skips in
# golden mode as defense-in-depth.
#
# ── ORDERING (golden-bake PR5): verify-BEFORE-network ──────────────
# The golden lower is PUBLIC — an UNKEYED dm-verity base, no KEK, no
# secret. So it is opened + verity/RO-asserted FIRST, BEFORE any network
# I/O or the per-VM KBS KEK release, restoring the legacy discipline of
# "validate what you can before you reach out to the network / before
# you mutate anything". A tampered or wrong-root-hash base fails closed
# at `hippius_golden_open_lower` WITHOUT ever contacting the KBS or
# releasing a per-VM KEK. Only the guest-keyed UPPER needs the KEK, so
# only `hippius_golden_open_upper` runs after `hippius_acquire`. The
# cmdline parse + verity open need neither network nor KEK.
#
# ── §20 SECRET HYGIENE ─────────────────────────────────────────────
# The per-VM KEK keyfile is ALWAYS shredded (`hippius_golden_shred_kek`)
# — on the success path AND on ANY failure, including a mid-path
# `hippius_die` inside acquire / open_upper / overlay mount (which exits
# the subshell non-zero and falls through to the unconditional shred).
# This matches the legacy crypttab keyscript's shred discipline. The KEK
# also lives only in SNP-encrypted RAM, so this is defense-in-depth, but
# it is now uniform across every golden exit path.
#
# Caller MUST have already sourced hippius-release-core.sh.
hippius_golden_run() {
    _hgrun_rootmnt="$1"
    [ -n "${_hgrun_rootmnt}" ] || hippius_die "golden: hippius_golden_run needs a rootmnt arg"

    hippius_parse_cmdline

    # Verify-BEFORE-network: open + verity/RO-assert the PUBLIC golden
    # lower before any KBS/network contact (no KEK needed — it is an
    # unkeyed Merkle tree). A tampered base fails closed here.
    hippius_golden_modprobe
    hippius_golden_resolve
    hippius_golden_open_lower

    _hgrun_kek="$(mktemp -p /run hippius-gold-kek.XXXXXX)"
    chmod 0600 "${_hgrun_kek}"

    # Ask the release for the anti-rollback outputs (GOLDEN only — the
    # legacy path leaves HIPPIUS_EXTRA_RELEASE_FLAGS empty and builds a
    # byte-identical hippius-guest-release command line). The EXPECTED
    # file carries one integer this script reads; the CTX file is 0600,
    # carries the confirm token, and is read ONLY by
    # `hippius-guest-release --confirm-volume-stamp` — the token never
    # enters this shell (§20).
    mkdir -p "$(dirname "${HIPPIUS_GOLDEN_STAMP_EXPECTED}")" 2>/dev/null || true
    rm -f "${HIPPIUS_GOLDEN_STAMP_EXPECTED}" "${HIPPIUS_GOLDEN_STAMP_CTX}" 2>/dev/null || true
    HIPPIUS_EXTRA_RELEASE_FLAGS="--volume-stamp-expected-out ${HIPPIUS_GOLDEN_STAMP_EXPECTED} --volume-stamp-ctx-out ${HIPPIUS_GOLDEN_STAMP_CTX}"
    export HIPPIUS_EXTRA_RELEASE_FLAGS

    # Now the network half: reuse the §21 release VERBATIM (releases the
    # per-VM KEK to ${_hgrun_kek}), open the guest-keyed upper, mount the
    # overlay. A subshell so a mid-path hippius_die (exit 1) aborts only
    # the ATTEMPT (not the init) and ALWAYS falls through to the shred
    # below. dm-mapper devices + kernel mounts created inside persist
    # (kernel state); only shell env — unused afterward — is scoped.
    _hgrun_rc=0
    ( hippius_acquire "${_hgrun_kek}" \
        && hippius_golden_open_upper "${_hgrun_kek}" \
        && hippius_golden_mount_overlay "${_hgrun_rootmnt}" ) || _hgrun_rc=$?

    # §20: ALWAYS shred the KEK — success OR any failure path.
    hippius_golden_shred_kek "${_hgrun_kek}"

    [ "${_hgrun_rc}" -eq 0 ] \
        || hippius_die "golden: KBS release / overlay assembly failed — fail-closed (disk stays locked; KEK shredded)"

    hippius_log "golden: boot assembled — handing control back for switch_root into ${_hgrun_rootmnt}"
}
