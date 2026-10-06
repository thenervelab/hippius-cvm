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
# The guest-keyed volume's root holds (docs/design/golden-data-path.md):
#   .hippius-volume-stamp / .hippius-volume-timeline   anti-rollback (against
#                          the host); not exposed via the merged root or the bind
#   upper/ work/   the overlayfs upperdir + workdir
#   data/          plain ext4, bound at /var/lib/hippius-data (#1347) — the
#                  one non-overlay path, for container runtimes & co.
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

# Non-overlay data path (#1347). The kernel refuses an overlayfs whose
# upperdir is itself on an overlay, so a container runtime (containerd /
# Docker overlay2 snapshots) cannot keep its root anywhere in the merged
# "/". The guest-keyed volume therefore carries a THIRD directory next to
# `upper/` and `work/`, bound (the directory only — never the volume root,
# which holds the anti-rollback stamp) at a FIXED path in the tenant root.# Both names are constants of this measured file: nothing the miner hands
# the guest (cmdline, fw_cfg, cidata) can move them.
HIPPIUS_GOLDEN_DATA_NAME="data"
HIPPIUS_GOLDEN_DATA_MOUNT="/var/lib/hippius-data"

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

# ── Stamp protocol v2: the stamp is the pair (TIMELINE, value) ───────
# THE HOLE THIS CLOSES (blocker B1 of an authorized rollback, "restore to
# an earlier boot"): the rollback sets E := E_T, and the restored timeline
# then writes E_T+1, E_T+2, … — the very numbers the ABANDONED
# (pre-rollback) timeline's disks already carry. With a bare number the
# miner could present an abandoned disk later and undo the rollback.
#
# So the volume also carries the TIMELINE it belongs to, in a sidecar
# next to the stamp (the stamp file itself keeps its exact v1 format, so
# an older image still reads it): `.hippius-volume-timeline`, 64
# lowercase hex chars. No sidecar = the zero timeline (a legacy stamp).
# The release attests v2 in its SNP REPORT_DATA and the SIGNED response
# carries `volume_stamp_transition {expected, target}`, which
# `hippius-guest-release --volume-stamp-transition-out` writes here as
# `<expected hex> <target hex>`. The v2 gate accepts the volume only on
# the EXPECTED timeline (and S in {E, E+1}), then writes the TARGET
# timeline and E+1. A normal release expects and targets the VM's
# current timeline; the one release an authorized rollback admits expects
# the restored point's timeline and targets a fresh random one — after
# which every abandoned disk is on a timeline no release expects,
# WHATEVER its value.
#
# ABSENT transition file = a v1 release, which ONLY M2 (whose stamp is
# the guardian's) ever gets: the v1 gate runs, byte for byte, and leaves
# the timeline sidecar untouched. M0/M1 attest v2 and NEVER fall back to
# v1 (`hippius-guest-release` treats a denial of the v2 report as final:
# every KBS refusal is the same 403, so a miner could forge one to buy a
# v1 adopt after a KBS store wipe). An M0/M1 boot without a transition is
# therefore REFUSED here too (defence in depth).
HIPPIUS_GOLDEN_TIMELINE_NAME=".hippius-volume-timeline"
HIPPIUS_GOLDEN_ZERO_TIMELINE="0000000000000000000000000000000000000000000000000000000000000000"
HIPPIUS_GOLDEN_STAMP_TRANSITION="${HIPPIUS_GOLDEN_STAMP_TRANSITION:-/run/hippius/volume-stamp.transition}"

# ── Customer-held disk keys (M1 `split` / M2 `customer`) ────────────
# With the MEASURED `hippius.key_mode=split|customer` token the KEK that
# `hippius-guest-release` emits is no longer the KBS KEK: it is
# `combine_kek(mode, share_H, share_C, vm_id)`, with `share_C` released
# by the customer's key guardian (see the binary's docs). The KEK
# contract with this script is UNCHANGED — 32 bytes to a tmpfs keyfile.
#
# What this script adds, for M1/M2 ONLY (an M0 cmdline — no token, or
# `hippius.key_mode=hippius` — takes none of these branches, reads no
# token and writes none):
#
#   - a LUKS2 token `hippius-keymode` on the upper, imported right after
#     the first-boot `luksFormat`:
#       {"type":"hippius-keymode","keyslots":[],"mode":"split|customer",
#        "guardian_fp":"<64 hex>","share_c_version":N}
#     `guardian_fp` = SHA-256 (lowercase hex) of the 64-char lowercase
#     hex `hippius.guardian_pk` value. `share_c_version` = the version
#     the guardian sealed, which `hippius-guest-release
#     --share-c-version-out` leaves on tmpfs;
#   - on later boots, BEFORE any KBS or guardian contact, the token is
#     read back: its mode and guardian_fp must equal the measured
#     binding (else fail closed — this volume belongs to another mode or
#     guardian), and its version is passed as `--share-c-version`, so
#     the guardian seals the share this volume's keyslot was made with.
#
# The token is PLAINTEXT header metadata the miner can rewrite. That is
# fine: the version only selects which share the guardian seals (a
# wrong one opens no keyslot — denial of service, which the miner has
# anyway), and mode/fp are compared against the measured cmdline, never
# trusted. A LUKS upper with NO token in M1/M2 fails closed unless its
# label says the first-boot init never finished (the token is imported
# before the relabel, so an honest volume past init always carries it).
HIPPIUS_GOLDEN_KEYMODE_TOKEN_TYPE="hippius-keymode"
HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT="${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT:-/run/hippius/share-c-version}"

# The customer-keys mode a cmdline STRING measures (pure; testable).
# Echoes `split` / `customer` and returns 0; returns 1 (echoing nothing)
# for M0 — no `hippius.key_mode` token, or `hippius`; returns 2 for any
# other value (the caller fails closed).
hippius_golden_key_mode_of() {
    _hgkm_v="$(hippius_golden_cmdline_value "$1" "hippius.key_mode" || true)"
    case "${_hgkm_v}" in
        "" | hippius) return 1 ;;
        split | customer) printf '%s' "${_hgkm_v}"; return 0 ;;
        *) return 2 ;;
    esac
}

# The guardian fingerprint a cmdline STRING measures (pure; testable):
# SHA-256 (lowercase hex) of the `hippius.guardian_pk` value. Returns 1
# unless that value is exactly 64 lowercase hex characters.
hippius_golden_guardian_fp_of() {
    _hggf_pk="$(hippius_golden_cmdline_value "$1" "hippius.guardian_pk" || true)"
    hippius_golden_valid_root_hash "${_hggf_pk}" || return 1
    printf '%s' "${_hggf_pk}" | sha256sum | awk '{print $1}'
}

# A share version: decimal, 1..4294967295 (u32, never 0). Echoes it.
hippius_golden_valid_share_version() {
    case "$1" in
        "" | 0* | *[!0-9]*) return 1 ;;
    esac
    [ "${#1}" -le 10 ] && [ "$1" -le 4294967295 ] 2>/dev/null || return 1
    printf '%s' "$1"
}

# The token JSON (pure; testable).
hippius_golden_keymode_token_json() {
    printf '{"type":"%s","keyslots":[],"mode":"%s","guardian_fp":"%s","share_c_version":%s}' \
        "${HIPPIUS_GOLDEN_KEYMODE_TOKEN_TYPE}" "$1" "$2" "$3"
}

# One string field / one number field of a token JSON. `cryptsetup token
# export` prints compact JSON; whitespace around `:` is tolerated anyway.
_hippius_golden_json_str() {
    printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"
}
_hippius_golden_json_num() {
    printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p"
}

# Parse a `hippius-keymode` token (pure; testable). Sets
# _HGKT_MODE / _HGKT_FP / _HGKT_VERSION; returns 1 on anything that is
# not exactly the shape this script writes (wrong type, unknown mode,
# a fingerprint that is not 64 lowercase hex, a version outside u32 ≥ 1).
hippius_golden_parse_keymode_token() {
    _HGKT_MODE=""; _HGKT_FP=""; _HGKT_VERSION=""
    [ "$(_hippius_golden_json_str "$1" type)" = "${HIPPIUS_GOLDEN_KEYMODE_TOKEN_TYPE}" ] || return 1
    _HGKT_MODE="$(_hippius_golden_json_str "$1" mode)"
    case "${_HGKT_MODE}" in split | customer) : ;; *) return 1 ;; esac
    _HGKT_FP="$(_hippius_golden_json_str "$1" guardian_fp)"
    hippius_golden_valid_root_hash "${_HGKT_FP}" || return 1
    _HGKT_VERSION="$(hippius_golden_valid_share_version "$(_hippius_golden_json_num "$1" share_c_version)")" \
        || return 1
}

# Read the upper's `hippius-keymode` token into _HGKT_JSON (left empty
# when the header carries none). Called directly, never in `$( )`, so a
# fail-closed `hippius_die` here aborts the boot rather than a subshell.
# More than one such token is a header this script never writes.
hippius_golden_read_keymode_token() {
    _HGKT_JSON=""
    _hgrt_dump="$(cryptsetup luksDump "${HIPPIUS_GOLDEN_UPPER}" 2>/dev/null)" \
        || hippius_die "golden: customer keys: the upper is LUKS but its header cannot be dumped — fail-closed"
    _hgrt_ids="$(printf '%s\n' "${_hgrt_dump}" \
        | sed -n '/^Tokens:/,/^[A-Za-z]/p' \
        | sed -n "s/^[[:space:]]*\([0-9][0-9]*\):[[:space:]]*${HIPPIUS_GOLDEN_KEYMODE_TOKEN_TYPE}[[:space:]]*\$/\1/p")"
    [ -n "${_hgrt_ids}" ] || return 0
    [ "$(printf '%s\n' "${_hgrt_ids}" | wc -l)" -eq 1 ] \
        || hippius_die "golden: customer keys: the upper carries more than one ${HIPPIUS_GOLDEN_KEYMODE_TOKEN_TYPE} token — fail-closed"
    _HGKT_JSON="$(cryptsetup token export --token-id "${_hgrt_ids}" "${HIPPIUS_GOLDEN_UPPER}" 2>/dev/null)" \
        || hippius_die "golden: customer keys: cannot export the ${HIPPIUS_GOLDEN_KEYMODE_TOKEN_TYPE} token — fail-closed"
    [ -n "${_HGKT_JSON}" ] \
        || hippius_die "golden: customer keys: the ${HIPPIUS_GOLDEN_KEYMODE_TOKEN_TYPE} token is empty — fail-closed"
}

# ── Customer keys: a blank upper is a first boot ONLY under E == 0 ────
# In M1/M2 a miner that zeroes the upper's LUKS header must not get a
# "first boot": the guardian would seal the VM's ACTIVE share (no share
# version is sent for a blank upper), the guest would format under the
# SAME KEK it had before, and — with the first-boot user-data running as
# root — that root could rebuild the KEK and open a copy of the OLD upper.
# So, for M1/M2 only:
#   - `cryptsetup isLuks` must answer exactly "LUKS" (0) or "not LUKS"
#     (1); any other status (missing/unreadable device) fails closed
#     instead of reading as "blank";
#   - a blank upper is formatted only when the SIGNED expectation E (the
#     KBS's in M1, the guardian's in M2) is exactly 0 — the VM has never
#     confirmed a boot. E > 0 or no E: fail closed, never format;
#   - the anti-rollback gate refuses the "no stamp, E > 0" legacy
#     migration (M1/M2 have no pre-stamp VMs) and a missing expectation.
# E alone is forgeable by a compromised Hippius in M1 (it signs the KBS
# response); the guardian's own "share_c_version=None once per VM" rule
# (`guardian approve-reinit` to allow it again) is the second layer.
#
# ONE classification, before any contact, is authoritative. The disk is
# miner-controlled and can change between the release and the open (keep
# the token so a version is sent, then flip the unauthenticated label to
# init or blank the header). So `hippius_golden_keymode_prepare` puts the
# upper in exactly one class, in HIPPIUS_GOLDEN_UPPER_CLASS (a shell
# variable, reset when this file is sourced, never taken from the
# environment), and everything after follows it:
#   ready  LUKS, ready label, valid token → the token's share version is
#          sent; the upper is only ever REOPENED this boot. If it now looks
#          blank, init-labelled or unreadable: fail closed.
#   blank  no LUKS header → NO share version; formatted only if the
#          release was version-less AND the signed E == 0.
#   init   the init label (interrupted first boot), token or not → NO
#          share version; same format gate as blank.
# Only that format path sets the first-boot flag, so only it installs
# user-data, and its stamp confirm is mandatory (a dropped confirm must
# not leave E at 0 behind a provisioned first boot).
# M0 takes none of these branches.
HIPPIUS_GOLDEN_UPPER_CLASS=""

# `cryptsetup isLuks` on the upper, strictly (M1/M2). Returns 0 for LUKS,
# 1 for "not LUKS"; any other exit status fails closed. Call it directly
# (an `if` condition is fine), never inside `$( )`.
hippius_golden_keyed_is_luks() {
    _hgkil_rc=0
    cryptsetup isLuks "${HIPPIUS_GOLDEN_UPPER}" 2>/dev/null || _hgkil_rc=$?
    case "${_hgkil_rc}" in
        0) return 0 ;;
        1) return 1 ;;
        *) hippius_die "golden: customer keys: cannot tell whether the upper is LUKS (cryptsetup isLuks exit ${_hgkil_rc}) — fail-closed" ;;
    esac
}

# Pure (testable): may M1/M2 format a BLANK upper, given the signed
# expectation $1 ("" when absent)? Only when it is exactly 0.
hippius_golden_keyed_may_format_blank() {
    _hgkmf_exp="$(hippius_golden_parse_counter "$1" || true)"
    [ -n "${_hgkmf_exp}" ] || return 1
    [ "${_hgkmf_exp}" -eq 0 ]
}

# BEFORE any KBS/guardian contact: resolve this boot's customer-keys
# state. Sets HIPPIUS_GOLDEN_KEY_MODE (empty for M0), HIPPIUS_GOLDEN_GUARDIAN_FP
# and HIPPIUS_GOLDEN_SHARE_C_VERSION (empty on a first boot). M0 returns
# at once — no token is read.
hippius_golden_keymode_prepare() {
    HIPPIUS_GOLDEN_UPPER_CLASS=""
    HIPPIUS_GOLDEN_KEY_MODE=""
    HIPPIUS_GOLDEN_GUARDIAN_FP=""
    HIPPIUS_GOLDEN_SHARE_C_VERSION=""
    _hgkp_cmdline="$(cat /proc/cmdline 2>/dev/null || true)"
    _hgkp_rc=0
    HIPPIUS_GOLDEN_KEY_MODE="$(hippius_golden_key_mode_of "${_hgkp_cmdline}")" || _hgkp_rc=$?
    case "${_hgkp_rc}" in
        0) : ;;
        1) HIPPIUS_GOLDEN_KEY_MODE=""; return 0 ;;
        *) hippius_die "golden: customer keys: hippius.key_mode= has an unknown value — fail-closed" ;;
    esac
    HIPPIUS_GOLDEN_GUARDIAN_FP="$(hippius_golden_guardian_fp_of "${_hgkp_cmdline}")" \
        || hippius_die "golden: customer keys: hippius.guardian_pk= missing/malformed (need 64 lowercase hex) — fail-closed"

    if ! hippius_golden_keyed_is_luks; then
        HIPPIUS_GOLDEN_UPPER_CLASS="blank"
        hippius_log "golden: customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): no LUKS header on the upper — class blank: version-less release, formatted only under a signed expectation of 0"
        return 0
    fi
    _hgkp_label="$(hippius_golden_upper_label)" \
        || hippius_die "golden: customer keys: the upper is LUKS but its header cannot be dumped — fail-closed"
    if [ "${_hgkp_label}" = "${HIPPIUS_GOLDEN_INIT_LABEL}" ]; then
        # An interrupted first boot. Any token on it is IGNORED: the
        # label is unauthenticated, so this goes through the guardian's
        # version-less gate (once per VM, or `approve-reinit`) and E == 0.
        HIPPIUS_GOLDEN_UPPER_CLASS="init"
        hippius_log "golden: customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): first-boot init never finished — class init: version-less release, formatted only under a signed expectation of 0"
        return 0
    fi
    hippius_golden_read_keymode_token
    [ -n "${_HGKT_JSON}" ] \
        || hippius_die "golden: customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): the upper carries no ${HIPPIUS_GOLDEN_KEYMODE_TOKEN_TYPE} token — not a volume this mode formatted — fail-closed"
    hippius_golden_parse_keymode_token "${_HGKT_JSON}" \
        || hippius_die "golden: customer keys: the ${HIPPIUS_GOLDEN_KEYMODE_TOKEN_TYPE} token is malformed — fail-closed"
    [ "${_HGKT_MODE}" = "${HIPPIUS_GOLDEN_KEY_MODE}" ] \
        || hippius_die "golden: customer keys: the volume was formatted in mode ${_HGKT_MODE} but this boot measures ${HIPPIUS_GOLDEN_KEY_MODE} — fail-closed"
    [ "${_HGKT_FP}" = "${HIPPIUS_GOLDEN_GUARDIAN_FP}" ] \
        || hippius_die "golden: customer keys: the volume was formatted for guardian ${_HGKT_FP} but this boot measures guardian ${HIPPIUS_GOLDEN_GUARDIAN_FP} — fail-closed"
    HIPPIUS_GOLDEN_SHARE_C_VERSION="${_HGKT_VERSION}"
    HIPPIUS_GOLDEN_UPPER_CLASS="ready"
    hippius_log "golden: customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): volume token OK, share version ${HIPPIUS_GOLDEN_SHARE_C_VERSION} — class ready: never formatted this boot"
}

# Right after the first-boot `luksFormat` (M1/M2 only; a no-op for M0):
# record mode, guardian and the share version the guardian just sealed.
# Before the wipe and BEFORE the ready relabel, so the relabel stays the
# last header write of the init (see "Interrupted first boot").
hippius_golden_write_keymode_token() {
    [ -n "${HIPPIUS_GOLDEN_KEY_MODE:-}" ] || return 0
    _hgwt_v="$(hippius_golden_valid_share_version \
        "$(cat "${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT}" 2>/dev/null | tr -d '\n')")" \
        || hippius_die "golden: customer keys: no valid share version from the release at ${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT} — fail-closed"
    hippius_golden_keymode_token_json "${HIPPIUS_GOLDEN_KEY_MODE}" "${HIPPIUS_GOLDEN_GUARDIAN_FP}" "${_hgwt_v}" \
        | cryptsetup token import "${HIPPIUS_GOLDEN_UPPER}" >>/dev/kmsg 2>&1 \
        || hippius_die "golden: customer keys: writing the ${HIPPIUS_GOLDEN_KEYMODE_TOKEN_TYPE} token failed — fail-closed"
    hippius_log "golden: customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): volume token written, share version ${_hgwt_v}"
}

# The extra `hippius-guest-release` flags for M1/M2 (empty for M0).
hippius_golden_keymode_release_flags() {
    [ -n "${HIPPIUS_GOLDEN_KEY_MODE:-}" ] || return 0
    printf ' --share-c-version-out %s' "${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT}"
    if [ -n "${HIPPIUS_GOLDEN_SHARE_C_VERSION:-}" ]; then
        printf ' --share-c-version %s' "${HIPPIUS_GOLDEN_SHARE_C_VERSION}"
    fi
    printf ' --instance-id-out %s' "${HIPPIUS_GOLDEN_IID_OUT}"
}

# ── Customer-held keys: cloud-init user-data on FIRST BOOT ONLY (H5b) ──
# In M0 the release core writes the KBS-released user-data straight into
# the NoCloud seed with a RANDOM instance-id each boot, so cloud-init
# re-runs every per-instance module (users, ssh keys, write_files,
# runcmd, ...) as root on every boot. vali mints that user-data. For
# M1/M2 that would let a compromised Hippius run code in the unlocked
# guest on any later boot, which is exactly what the customer's key
# share is meant to rule out. So, for M1/M2 only:
#
#   - the instance-id is STABLE: `iid-<32 hex>` that `hippius-guest-release
#     --instance-id-out` derives from the ticket's vm_id (the same vm_id
#     the keyslot key is combined under — another vm_id opens nothing);
#   - the release writes the user-data to a tmpfs STAGING file, not to
#     the seed. Whether it reaches cloud-init is decided only once the
#     upper has been opened, because only then is it known whether THIS
#     boot formatted the volume;
#   - the boot that formatted the upper (blank disk, or an interrupted
#     first boot re-formatted under E == 0) moves the staged user-data
#     into the seed. Every other boot shreds it and gives cloud-init an
#     EMPTY user-data with the same instance-id: cloud-init sees the
#     same instance, skips its per-instance modules, and has no new
#     content from Hippius for the per-boot ones (bootcmd, boothooks —
#     which DO run a non-empty user-data under the same instance-id, so
#     empty is load-bearing). What the first boot installed for later
#     boots (per-boot scripts, units) still runs: that is the first-boot
#     exposure below;
#   - fail closed: the "formatted this boot" flag is set only by
#     `hippius_golden_format_upper` (inside the driver's subshell, where
#     the seed is installed), reset when this file is sourced and never
#     read from the environment. Anything else — including a state we
#     cannot tell — is "not the first boot": the user-data is ignored.
#
# Blanking the upper of a VM that has booted before does NOT make a first
# boot: a blank upper is formatted only under a signed expectation of 0
# (see "a blank upper is a first boot ONLY under E == 0" above), and the
# guardian seals for "no share version" once per VM. The first boot
# itself stays exposed to the user-data vali mints (plan decision D1;
# v1.1 moves the NetBird key out and lets the guardian pin the user-data
# digest).
#
# Consequence to know: a host reset after the upper is marked ready but
# before cloud-init has applied the first-boot user-data leaves a VM
# whose later boots get none of it (no tenant key, no NetBird). The
# volume holds nothing but the first-boot state then; relaunch it.
#
# The paths are FIXED (not `${VAR:-default}`): unknown `key=value` words
# on the kernel cmdline reach the initramfs as environment variables.
HIPPIUS_GOLDEN_SEED_DIR="/run/cloud-init/seed"
HIPPIUS_GOLDEN_USERDATA_STAGED="/run/hippius/userdata.staged"
HIPPIUS_GOLDEN_IID_OUT="/run/hippius/instance-id"
HIPPIUS_GOLDEN_FIRST_BOOT=""

# `iid-` + exactly 32 lowercase hex (pure; testable).
hippius_golden_valid_iid() {
    case "$1" in
        iid-*) _hgvi_hex="${1#iid-}" ;;
        *) return 1 ;;
    esac
    [ "${#_hgvi_hex}" -eq 32 ] || return 1
    case "${_hgvi_hex}" in
        *[!0-9a-f]*) return 1 ;;
    esac
    return 0
}

# M1/M2 only (a no-op for M0, whose seed the release core already
# wrote): build the NoCloud seed from the stable instance-id, handing
# the staged user-data over on the volume's first boot and shredding it
# on every other. Runs after the overlay is assembled, so a boot that
# fails anywhere earlier never exposes the user-data at all.
hippius_golden_install_seed() {
    [ -n "${HIPPIUS_GOLDEN_KEY_MODE:-}" ] || return 0
    _hgis_iid="$(cat "${HIPPIUS_GOLDEN_IID_OUT}" 2>/dev/null | tr -d '\n')"
    hippius_golden_valid_iid "${_hgis_iid}" \
        || hippius_die "golden: customer keys: no valid instance-id from the release at ${HIPPIUS_GOLDEN_IID_OUT} — fail-closed"
    mkdir -p "${HIPPIUS_GOLDEN_SEED_DIR}" \
        || hippius_die "golden: customer keys: cannot create the cloud-init seed dir — fail-closed"
    chmod 0755 "${HIPPIUS_GOLDEN_SEED_DIR}"
    rm -f "${HIPPIUS_GOLDEN_SEED_DIR}/user-data" "${HIPPIUS_GOLDEN_SEED_DIR}/meta-data"
    _hgis_first=""
    if [ "${HIPPIUS_GOLDEN_FIRST_BOOT}" = "yes" ] && [ -z "${HIPPIUS_GOLDEN_SHARE_C_VERSION:-}" ]; then
        case "${HIPPIUS_GOLDEN_UPPER_CLASS}" in blank | init) _hgis_first=1 ;; esac
    fi
    if [ -n "${_hgis_first}" ]; then
        [ -f "${HIPPIUS_GOLDEN_USERDATA_STAGED}" ] \
            || hippius_die "golden: customer keys: first boot but the release left no user-data — fail-closed"
        mv -f "${HIPPIUS_GOLDEN_USERDATA_STAGED}" "${HIPPIUS_GOLDEN_SEED_DIR}/user-data" \
            || hippius_die "golden: customer keys: cannot hand the first-boot user-data to cloud-init — fail-closed"
        hippius_log "golden: customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): first boot of this volume — the released user-data goes to cloud-init (instance ${_hgis_iid})"
    else
        hippius_golden_shred_kek "${HIPPIUS_GOLDEN_USERDATA_STAGED}"
        [ ! -e "${HIPPIUS_GOLDEN_USERDATA_STAGED}" ] \
            || hippius_die "golden: customer keys: cannot discard the released user-data — fail-closed"
        : > "${HIPPIUS_GOLDEN_SEED_DIR}/user-data" \
            || hippius_die "golden: customer keys: cannot write the empty user-data — fail-closed"
        chmod 0644 "${HIPPIUS_GOLDEN_SEED_DIR}/user-data"
        hippius_log "golden: customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): not the first boot of this volume — the released user-data is discarded; cloud-init gets an empty user-data (instance ${_hgis_iid})"
    fi
    printf 'instance-id: %s\n' "${_hgis_iid}" > "${HIPPIUS_GOLDEN_SEED_DIR}/meta-data" \
        || hippius_die "golden: customer keys: cannot write the cloud-init meta-data — fail-closed"
    chmod 0644 "${HIPPIUS_GOLDEN_SEED_DIR}/meta-data"
}

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
# by the KEK) → wipe → open → mkfs.ext4. A subsequent boot finds a LUKS
# header → open with the KEK. A miner planting a foreign LUKS header only
# makes `open` fail (its keyslots are not for OUR per-VM KEK) →
# fail-closed; no reformat, no data loss, boot aborts.
#
# ── The wipe (why it is not cryptsetup's) ───────────────────────────
# dm-integrity keeps a tag per sector; a sector never written through the
# mapping reads back EILSEQ, so every sector is written once before the
# filesystem goes on. `luksFormat` does that itself with one synchronous
# 1 MiB write at a time, which made first boot take disk_gb / serial_rate
# (72 min for a 2xlarge on a write-through SATA RAID). We format with
# `--integrity-no-wipe` and let `hippius-guest-release --integrity-wipe`
# write the same zeros through the same mapping with 8 writers in flight.
# The end state is the one cryptsetup produces: every sector written once
# under the in-guest MK, every tag valid, any later host modification
# reads EILSEQ. The wipe runs on a `--integrity-no-journal` activation,
# as cryptsetup's own wipe does (journaling zeros only doubles the
# writes); the volume is then reopened journaled, as on every boot.
#
# `--sector-size 4096`: one 32-byte tag per 4 KiB instead of per 512 B
# (0.8 % of the disk instead of 6.25 %, 8x fewer HMACs), same AEAD, same
# per-sector IV binding. Volumes formatted earlier keep their 512-byte
# sectors; the sector size is read from their header on open.
#
# ── Interrupted first boot ──────────────────────────────────────────
# A host reset during the wipe or mkfs used to leave a LUKS header with no
# filesystem: the next boot took the "already LUKS" branch, the mount
# failed, and the VM was dead for good. The header's LUKS2 label now
# records progress: `luksFormat` writes ${HIPPIUS_GOLDEN_INIT_LABEL}, and
# only a successful wipe + mkfs replaces it with
# ${HIPPIUS_GOLDEN_READY_LABEL}, still in the initramfs, before the overlay
# is mounted — so an honest volume carrying the init label has never held a
# tenant byte. Such a volume is formatted again from scratch (fresh
# in-guest MK) ONLY when the KBS-SIGNED expectation is exactly 0 as well
# (the KBS has never confirmed a boot of this VM). Init label with any
# other expectation fails closed; volumes from before this change have no
# label and always take the plain reopen path.
#
# The label is NOT authenticated: a miner can write the init label onto a
# live volume whose expectation is 0 and have it reformatted. That is no
# new power — zeroing the header already sends the guest down the
# blank-disk path, which formats a fresh volume and seeds the stamp. No
# filesystem probe is used to decide: mounting to look, even `ro,noload`,
# lets ext4's orphan cleanup write to an un-replayed journal.
#
# INVARIANT: after first boot, the relabel below must stay the ONLY write to
# this LUKS2 header. A later header writer (a keyslot change, a token, a
# custody rekey) that tears could let cryptsetup fall back to a header copy
# that still says init — and, with E == 0, reformat a live volume. Any such
# writer has to account for that before it lands. (The customer-keys
# `hippius-keymode` token is written INSIDE the init — right after
# `luksFormat`, before the wipe — so it is not such a writer.)
HIPPIUS_GOLDEN_INIT_LABEL="hippius-upper-init"
HIPPIUS_GOLDEN_READY_LABEL="hippius-upper"
: "${HIPPIUS_GOLDEN_WIPE_BIN:=hippius-guest-release}"

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

# The upper's LUKS2 label (empty when it has none). `luksDump` prints
# one `Label:` line, followed by the label or `(no label)`. Returns
# non-zero when the header cannot be dumped, so the caller never mistakes
# an unreadable label for "not the init label".
hippius_golden_upper_label() {
    _hgul_dump="$(cryptsetup luksDump "${HIPPIUS_GOLDEN_UPPER}" 2>/dev/null)" || return 1
    printf '%s\n' "${_hgul_dump}" | sed -n 's/^Label:[[:space:]]*//p'
}

# Pure decision for an upper whose label says our init never finished.
# $1 = LUKS2 label, $2 = KBS expectation ("" when absent). Returns 0 only
# for an interrupted first boot: the init label AND a signed expectation
# of exactly 0. See "Interrupted first boot" above.
hippius_golden_may_reinit() {
    [ "$1" = "${HIPPIUS_GOLDEN_INIT_LABEL}" ] || return 1
    _hgmr_exp="$(hippius_golden_parse_counter "$2" || true)"
    [ -n "${_hgmr_exp}" ] || return 1
    [ "${_hgmr_exp}" -eq 0 ]
}

# Format the upper (fresh in-guest MK, init label), wipe it, mkfs, mark it
# ready. Leaves it open (journaled).
hippius_golden_format_upper() {
    # LUKS2 + dm-integrity (hmac-sha256): authenticated encryption,
    # so a miner tampering the upper ciphertext read-faults (EIO)
    # rather than silently corrupting — same guarantee as vde.
    # The MK is generated fresh from the kernel CSPRNG INSIDE this
    # SNP guest; only the KEK (per-VM) protects the keyslot.
    cryptsetup luksFormat --type luks2 --integrity hmac-sha256 \
        --integrity-no-wipe --sector-size 4096 --label "${HIPPIUS_GOLDEN_INIT_LABEL}" \
        --batch-mode "${HIPPIUS_GOLDEN_UPPER}" --key-file "$1" >>/dev/kmsg 2>&1 \
        || hippius_die "golden: upper luksFormat failed — fail-closed"
    hippius_golden_write_keymode_token
    hippius_golden_init_upper "$1"
    # H5b: THE first-boot signal — this boot formatted a fresh volume.
    HIPPIUS_GOLDEN_FIRST_BOOT="yes"
}

# Wipe every sector through a journal-less activation, with udev paused.
#
# Why pause udev: the moment the wipe mapping appears, udev runs blkid on
# it, and blkid reads sectors the wipe has not written yet. Those reads
# fail verification and the kernel logs `INTEGRITY AEAD ERROR` on every
# first boot — which would make an integrity error ambiguous (tampering, or
# just the probe?). cryptsetup's own wipe hides its mapping from udev with a
# private activation the CLI cannot request. So instead: stop udev's event
# queue, activate with `DM_DISABLE_UDEV=1` (libdevmapper creates the node
# itself and does not wait for udev, which would deadlock on the stopped
# queue), wipe, close, and restart the queue. The queued events then run
# against a mapping that is gone. Same two primitives on all four distros.
# No udevd running (udevadm absent or `control` refused) ⇒ nothing probes,
# nothing to pause. The queue is restarted on the failure path too.
hippius_golden_wipe_upper() {
    _hgwu_paused=""
    if ! command -v udevadm >/dev/null 2>&1; then
        hippius_log "golden: udevadm not in the initramfs — udev NOT paused for the wipe (a pre-wipe probe would log AEAD errors)"
    elif udevadm control --stop-exec-queue >>/dev/kmsg 2>&1; then
        _hgwu_paused=1
    else
        hippius_log "golden: udev refused to pause (no udevd?) — wiping without a pause"
    fi
    _hgwu_rc=0
    (
        DM_DISABLE_UDEV=1
        export DM_DISABLE_UDEV
        cryptsetup open --integrity-no-journal "${HIPPIUS_GOLDEN_UPPER}" "${HIPPIUS_GOLDEN_UPPER_MAPPER}" \
            --key-file "$1" >>/dev/kmsg 2>&1 \
            || hippius_die "golden: upper open for the wipe failed — fail-closed"
        hippius_log "golden: upper integrity wipe — every sector, parallel writers"
        if ! "${HIPPIUS_GOLDEN_WIPE_BIN}" --integrity-wipe "/dev/mapper/${HIPPIUS_GOLDEN_UPPER_MAPPER}" >>/dev/kmsg 2>&1; then
            # Close the half-wiped mapping BEFORE udev resumes, or its
            # queued probe reads unwritten sectors on exactly the boot
            # someone will be debugging.
            cryptsetup close "${HIPPIUS_GOLDEN_UPPER_MAPPER}" >>/dev/kmsg 2>&1 || true
            hippius_die "golden: upper integrity wipe failed — fail-closed (no filesystem on a partly initialised device)"
        fi
        cryptsetup close "${HIPPIUS_GOLDEN_UPPER_MAPPER}" >>/dev/kmsg 2>&1 \
            || hippius_die "golden: upper close after the wipe failed — fail-closed"
    ) || _hgwu_rc=$?
    if [ -n "${_hgwu_paused}" ]; then
        udevadm control --start-exec-queue >>/dev/kmsg 2>&1 \
            || hippius_die "golden: could not restart the udev event queue — fail-closed"
    fi
    [ "${_hgwu_rc}" -eq 0 ] || hippius_die "golden: upper wipe failed — fail-closed"
}

# Wipe every sector, then lay down the filesystem and mark the init done.
# Expects the upper freshly formatted and NOT open; leaves it open
# (journaled).
hippius_golden_init_upper() {
    _hgiu_kek="$1"
    hippius_golden_wipe_upper "${_hgiu_kek}"
    cryptsetup open "${HIPPIUS_GOLDEN_UPPER}" "${HIPPIUS_GOLDEN_UPPER_MAPPER}" \
        --key-file "${_hgiu_kek}" >>/dev/kmsg 2>&1 \
        || hippius_die "golden: upper open (post-wipe) failed — fail-closed"
    # Every sector now carries a valid tag; lay down a fresh ext4 for the
    # overlay upperdir/workdir.
    "$(hippius_golden_mkfs_bin)" -q -F "/dev/mapper/${HIPPIUS_GOLDEN_UPPER_MAPPER}" >>/dev/kmsg 2>&1 \
        || hippius_die "golden: mkfs.ext4 on upper failed — fail-closed"
    cryptsetup config --label "${HIPPIUS_GOLDEN_READY_LABEL}" "${HIPPIUS_GOLDEN_UPPER}" >>/dev/kmsg 2>&1 \
        || hippius_die "golden: marking the upper initialised failed — fail-closed"
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

    # Customer keys (M1/M2): the pre-contact classification decides.
    if [ -n "${HIPPIUS_GOLDEN_KEY_MODE:-}" ]; then
        hippius_golden_open_upper_keyed "${_hgou_kek}"
        return 0
    fi

    if ! cryptsetup isLuks "${HIPPIUS_GOLDEN_UPPER}" 2>/dev/null; then
        hippius_log "golden: upper blank — first-boot luksFormat --integrity (MK generated in-guest, never leaves)"
        hippius_golden_format_upper "${_hgou_kek}"
        hippius_log "golden: per-VM guest-keyed upper open at /dev/mapper/${HIPPIUS_GOLDEN_UPPER_MAPPER}"
        return 0
    fi

    _hgou_label="$(hippius_golden_upper_label)" \
        || hippius_die "golden: upper is LUKS but its header cannot be dumped — fail-closed"
    if [ "${_hgou_label}" = "${HIPPIUS_GOLDEN_INIT_LABEL}" ]; then
        _hgou_expected="$(hippius_golden_expected_stamp || true)"
        hippius_golden_may_reinit "${HIPPIUS_GOLDEN_INIT_LABEL}" "${_hgou_expected}" \
            || hippius_die "golden: upper's first-boot init never finished but the KBS expectation is ${_hgou_expected:-<absent>}, not 0 — refusing to reformat a volume that may hold tenant data — fail-closed"
        hippius_log "golden: upper's first-boot init never finished and the KBS has never confirmed a boot — interrupted first boot, formatting again"
        hippius_golden_format_upper "${_hgou_kek}"
    else
        hippius_log "golden: upper already LUKS — reopening (persisted tenant writes)"
        cryptsetup open "${HIPPIUS_GOLDEN_UPPER}" "${HIPPIUS_GOLDEN_UPPER_MAPPER}" \
            --key-file "${_hgou_kek}" >>/dev/kmsg 2>&1 \
            || hippius_die "golden: upper open failed (wrong/absent KEK or tampered header) — fail-closed"
    fi
    hippius_log "golden: per-VM guest-keyed upper open at /dev/mapper/${HIPPIUS_GOLDEN_UPPER_MAPPER}"
}

# M1/M2: open the upper as `hippius_golden_keymode_prepare` classified it
# BEFORE the release — never re-decided from the disk as it is now.
hippius_golden_open_upper_keyed() {
    _hgouk_kek="$1"
    case "${HIPPIUS_GOLDEN_UPPER_CLASS}" in
        ready)
            hippius_golden_keyed_is_luks \
                || hippius_die "golden: customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): the upper was a formatted volume before the release and has no LUKS header now — it changed under us — fail-closed"
            _hgouk_label="$(hippius_golden_upper_label)" \
                || hippius_die "golden: upper is LUKS but its header cannot be dumped — fail-closed"
            [ "${_hgouk_label}" != "${HIPPIUS_GOLDEN_INIT_LABEL}" ] \
                || hippius_die "golden: customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): the upper was ready before the release and now says its init never finished — refusing to re-initialise — fail-closed"
            hippius_log "golden: upper already LUKS — reopening (persisted tenant writes)"
            cryptsetup open "${HIPPIUS_GOLDEN_UPPER}" "${HIPPIUS_GOLDEN_UPPER_MAPPER}" \
                --key-file "${_hgouk_kek}" >>/dev/kmsg 2>&1 \
                || hippius_die "golden: upper open failed (wrong/absent KEK or tampered header) — fail-closed"
            ;;
        blank | init)
            [ -z "${HIPPIUS_GOLDEN_SHARE_C_VERSION:-}" ] \
                || hippius_die "golden: customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): a first-boot format needs a version-less release — fail-closed"
            _hgouk_expected="$(hippius_golden_expected_stamp || true)"
            hippius_golden_keyed_may_format_blank "${_hgouk_expected}" \
                || hippius_die "golden: customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): the upper is ${HIPPIUS_GOLDEN_UPPER_CLASS} but the signed expectation is ${_hgouk_expected:-<absent>}, not 0 — this VM has booted before, a blanked upper is not a first boot — refusing to format — fail-closed"
            hippius_log "golden: customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): first boot (${HIPPIUS_GOLDEN_UPPER_CLASS}, version-less release, E == 0) — luksFormat --integrity (MK generated in-guest, never leaves)"
            hippius_golden_format_upper "${_hgouk_kek}"
            ;;
        *)
            hippius_die "golden: customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): the upper was not classified before the release — fail-closed"
            ;;
    esac
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

# M1/M2 FIRST boot only: the confirm is MANDATORY. The first-boot format
# is what hands the Hippius-minted user-data to cloud-init; if its stamp
# confirm could be dropped, E would stay 0 behind a provisioned volume and
# every later boot would still look "never booted" to the E == 0 gate.
# So: a few attempts with backoff, then fail closed BEFORE the seed is
# installed. The cost is availability at first boot only (a miner can
# refuse a first boot anyway); the volume is then ready-labelled with no
# user-data applied — the documented "crash in the first-boot window"
# case: relaunch. Later boots keep the non-fatal confirm (a dropped
# confirm there must not be a denial of service).
HIPPIUS_GOLDEN_FIRST_CONFIRM_TRIES=5
hippius_golden_confirm_first_stamp() {
    [ -r "${HIPPIUS_GOLDEN_STAMP_CTX}" ] \
        || hippius_die "golden: customer keys: first boot but no confirm context at ${HIPPIUS_GOLDEN_STAMP_CTX} — fail-closed"
    _hgcf_try=1
    _hgcf_wait=2
    while :; do
        if _hgcf_out="$(hippius-guest-release --confirm-volume-stamp "${HIPPIUS_GOLDEN_STAMP_CTX}" \
            --kbs-url "${HIPPIUS_KBS_URL}" 2>&1)"; then
            hippius_log "golden: anti-rollback: first-boot stamp CONFIRMED (attempt ${_hgcf_try})"
            return 0
        fi
        [ "${_hgcf_try}" -lt "${HIPPIUS_GOLDEN_FIRST_CONFIRM_TRIES}" ] \
            || hippius_die "golden: customer keys: the first-boot stamp confirm failed ${_hgcf_try} times (${_hgcf_out}) — no user-data is handed over with E still at 0 — fail-closed (relaunch)"
        hippius_log "golden: anti-rollback: first-boot stamp confirm failed (attempt ${_hgcf_try}: ${_hgcf_out}) — retrying in ${_hgcf_wait}s"
        sleep "${_hgcf_wait}"
        _hgcf_try=$(( _hgcf_try + 1 ))
        _hgcf_wait=$(( _hgcf_wait * 2 ))
    done
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

    if [ -z "${_hgcs_expected}" ] && [ -n "${HIPPIUS_GOLDEN_KEY_MODE:-}" ]; then
        hippius_die "golden: ANTI-ROLLBACK REFUSED — customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): this boot received NO signed expectation (M1/M2 have no pre-gate images) — fail-closed"
    fi
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
        elif [ -n "${HIPPIUS_GOLDEN_KEY_MODE:-}" ]; then
            hippius_die "golden: ANTI-ROLLBACK REFUSED — customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): the volume carries no stamp but the signed expectation is ${_hgcs_expected} (M1/M2 have no pre-stamp VMs to migrate) — fail-closed"
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

# Parse a timeline id: exactly 64 lowercase hex chars. Echoes it and
# returns 0; returns 1 (echoing nothing) otherwise.
hippius_golden_parse_timeline() {
    _hgpt_v="$1"
    [ "${#_hgpt_v}" -eq 64 ] || return 1
    case "${_hgpt_v}" in
        *[!0-9a-f]*) return 1 ;;
    esac
    printf '%s' "${_hgpt_v}"
}

# The v2 transition of THIS boot's release. Echoes `<expected> <target>`
# and returns 0; returns 1 when there is none (a v1 release); returns 2
# when the file is present but malformed — the caller must refuse, never
# fall back to the v1 gate.
hippius_golden_stamp_transition() {
    [ -e "${HIPPIUS_GOLDEN_STAMP_TRANSITION}" ] || return 1
    _hgst_e=""
    _hgst_t=""
    _hgst_rest=""
    read -r _hgst_e _hgst_t _hgst_rest < "${HIPPIUS_GOLDEN_STAMP_TRANSITION}" || return 2
    [ -z "${_hgst_rest}" ] || return 2
    _hgst_e="$(hippius_golden_parse_timeline "${_hgst_e}")" || return 2
    _hgst_t="$(hippius_golden_parse_timeline "${_hgst_t}")" || return 2
    printf '%s %s' "${_hgst_e}" "${_hgst_t}"
}

# THE v2 GATE. `hippius_golden_check_stamp_v2 <volume-root> <expected>
# <expected-timeline> <target-timeline>` — as `hippius_golden_check_stamp`,
# plus the timeline:
#   - E == 0: ADOPT (fresh VM, or a rebuilt KBS store — the gate is open
#     for every VM until its next confirm, exactly as in v1): write the
#     target timeline and stamp 1. The KBS makes that target a FRESH
#     timeline (its gate 5c'), so once the confirm lands every disk of an
#     earlier timeline — including the zero timeline the VM counted from
#     before a store wipe — is refused.
#   - no in-volume stamp: the one-time LEGACY MIGRATION of v1, and ONLY
#     for a legacy volume (no timeline sidecar) staying on the zero
#     timeline. A timeline-bound volume or release never takes it.
#   - the volume's timeline (sidecar, or zero for a legacy stamp) must be
#     the EXPECTED one — else this is a disk of another (abandoned)
#     timeline, refused whatever its value — and S must be in {E, E+1}.
# On accept: the TARGET timeline FIRST, then E+1. A crash between the two
# leaves (target, S) with S still in {E, E+1}, which the next release
# (expecting the target) accepts; the reverse order could leave a restored
# volume on the old timeline for good.
hippius_golden_check_stamp_v2() {
    _hgv2_root="$1"
    _hgv2_expected="$2"
    _hgv2_exp_t="$3"
    _hgv2_tgt_t="$4"
    _hgv2_file="${_hgv2_root}/${HIPPIUS_GOLDEN_STAMP_NAME}"
    _hgv2_tfile="${_hgv2_root}/${HIPPIUS_GOLDEN_TIMELINE_NAME}"

    [ -n "${_hgv2_expected}" ] \
        || hippius_die "golden: ANTI-ROLLBACK REFUSED — a timeline transition arrived without an expectation — fail-closed"
    _hgv2_target="$(( _hgv2_expected + 1 ))"

    if [ -e "${_hgv2_tfile}" ]; then
        _hgv2_in_t="$(hippius_golden_parse_timeline "$(cat "${_hgv2_tfile}" 2>/dev/null || true)" || true)"
        [ -n "${_hgv2_in_t}" ] \
            || hippius_die "golden: ANTI-ROLLBACK REFUSED — the in-volume timeline is unparseable — fail-closed"
    else
        _hgv2_in_t="${HIPPIUS_GOLDEN_ZERO_TIMELINE}"
    fi

    if [ "${_hgv2_expected}" -eq 0 ]; then
        hippius_log "golden: anti-rollback ADOPT (v2) — the KBS holds no confirmed stamp (fresh VM or rebuilt store); adopting timeline=${_hgv2_in_t} and stamping ${_hgv2_tgt_t}:${_hgv2_target}"
        hippius_golden_write_timeline "${_hgv2_tfile}" "${_hgv2_tgt_t}"
        hippius_golden_write_counter "${_hgv2_file}" "${_hgv2_target}"
        return 0
    fi

    if [ ! -e "${_hgv2_file}" ]; then
        # Customer keys (M1): no pre-stamp VM exists to migrate — a missing
        # stamp under E > 0 is a blanked or swapped volume (H5b B1).
        [ -z "${HIPPIUS_GOLDEN_KEY_MODE:-}" ] \
            || hippius_die "golden: ANTI-ROLLBACK REFUSED — customer keys (${HIPPIUS_GOLDEN_KEY_MODE}): the volume carries no stamp but the signed expectation is ${_hgv2_expected} (M1/M2 have no pre-stamp VMs to migrate) — fail-closed"
        if [ ! -e "${_hgv2_tfile}" ] \
            && [ "${_hgv2_exp_t}" = "${HIPPIUS_GOLDEN_ZERO_TIMELINE}" ] \
            && [ "${_hgv2_tgt_t}" = "${HIPPIUS_GOLDEN_ZERO_TIMELINE}" ]; then
            hippius_log "golden: anti-rollback MIGRATION (v2) — pre-existing VM with no in-volume stamp on the zero timeline; accepting ONCE and stamping ${_hgv2_target}"
            hippius_golden_write_timeline "${_hgv2_tfile}" "${_hgv2_tgt_t}"
            hippius_golden_write_counter "${_hgv2_file}" "${_hgv2_target}"
            return 0
        fi
        hippius_die "golden: ANTI-ROLLBACK REFUSED — no in-volume stamp, but this release is bound to timeline ${_hgv2_exp_t} (volume timeline ${_hgv2_in_t}) — fail-closed"
    fi

    _hgv2_in="$(hippius_golden_parse_counter "$(cat "${_hgv2_file}" 2>/dev/null || true)" || true)"
    [ -n "${_hgv2_in}" ] \
        || hippius_die "golden: ANTI-ROLLBACK REFUSED — the in-volume stamp is unparseable (expected=${_hgv2_expected} in_volume=<malformed>) — fail-closed"

    if [ "${_hgv2_in_t}" != "${_hgv2_exp_t}" ]; then
        hippius_die "golden: ANTI-ROLLBACK REFUSED — the volume is on timeline ${_hgv2_in_t} but this release expects timeline ${_hgv2_exp_t}: a disk of an ABANDONED timeline (e.g. the pre-rollback disk after an authorized rollback), whatever its value (in_volume=${_hgv2_in} expected=${_hgv2_expected}) — fail-closed"
    fi
    if [ "${_hgv2_in}" -lt "${_hgv2_expected}" ]; then
        hippius_die "golden: ANTI-ROLLBACK REFUSED — the guest-keyed overlay is STALE: in_volume=${_hgv2_in} expected=${_hgv2_expected} (timeline ${_hgv2_in_t}); the host restored an OLD upper — fail-closed"
    fi
    if [ "${_hgv2_in}" -gt "${_hgv2_target}" ]; then
        hippius_die "golden: ANTI-ROLLBACK REFUSED — the in-volume stamp is AHEAD of anything an honest guest could have written: in_volume=${_hgv2_in} expected=${_hgv2_expected} (max ${_hgv2_target}) — fail-closed"
    fi

    if [ "${_hgv2_exp_t}" != "${_hgv2_tgt_t}" ]; then
        hippius_log "golden: anti-rollback ROLLBACK — authorized restore accepted on timeline ${_hgv2_exp_t} (in_volume=${_hgv2_in} expected=${_hgv2_expected}); moving to timeline ${_hgv2_tgt_t}, stamping ${_hgv2_target}"
    else
        hippius_log "golden: anti-rollback OK (v2) — timeline ${_hgv2_in_t} in_volume=${_hgv2_in} expected=${_hgv2_expected}; stamping ${_hgv2_target}"
    fi
    hippius_golden_write_timeline "${_hgv2_tfile}" "${_hgv2_tgt_t}"
    hippius_golden_write_counter "${_hgv2_file}" "${_hgv2_target}"
}

# THE v1 GATE as the boot path runs it — reached ONLY by M2 (M0/M1 are
# refused before it when the release carried no transition, see
# `hippius_golden_mount_overlay`): `hippius_golden_check_stamp`, preceded
# by a DEFENCE that stays even though no honest M2 volume is ever
# timeline-bound (M2 never gets a v2 release): a volume that IS
# timeline-bound (a non-zero sidecar, written by an earlier v2 release) is
# REFUSED under a v1 release, at every E — fail closed, nothing written.
# A v1 release names no timeline, and the KBS serves one only for a VM on
# the zero timeline (its gate 5a-t), so it can never be consistent with
# such a volume:
#   - E > 0 (or no expectation): a value-only comparison would take a
#     disk of an abandoned timeline for the current one.
#   - E == 0 (a rebuilt KBS store): adopting would leave the sidecar on
#     T1 while a v1 confirm lands on the zero timeline (an honest VM
#     bricked); resetting the sidecar to zero would pin the VM to the
#     zero timeline for good, re-opening every abandoned zero-timeline
#     disk once E catches up.
# A zero-timeline sidecar, or none (a legacy stamp), is the v1 gate
# exactly as before.
hippius_golden_check_stamp_v1() {
    _hgv1_root="$1"
    _hgv1_expected="$2"
    _hgv1_tfile="${_hgv1_root}/${HIPPIUS_GOLDEN_TIMELINE_NAME}"

    if [ -e "${_hgv1_tfile}" ]; then
        _hgv1_t="$(hippius_golden_parse_timeline "$(cat "${_hgv1_tfile}" 2>/dev/null || true)" || true)"
        [ -n "${_hgv1_t}" ] \
            || hippius_die "golden: ANTI-ROLLBACK REFUSED — the in-volume timeline is unparseable (v1 release) — fail-closed"
        if [ "${_hgv1_t}" != "${HIPPIUS_GOLDEN_ZERO_TIMELINE}" ]; then
            hippius_die "golden: ANTI-ROLLBACK REFUSED — the volume is bound to timeline ${_hgv1_t} but this boot got a v1 release (expected=${_hgv1_expected:-<absent>}), which names no timeline — fail-closed (a v2 release, or a KBS at stamp protocol v2 or later, is required)"
        fi
    fi
    hippius_golden_check_stamp "${_hgv1_root}" "${_hgv1_expected}"
}

# Write the timeline sidecar (tmp + rename, like the stamp) — skipped when
# it already holds `$2`. A LEGACY volume (no sidecar) gets one on its
# first v2 boot, which only ever happens under a release that expected
# the zero timeline (the gate above checked it).
hippius_golden_write_timeline() {
    if [ -e "$1" ] && [ "$(cat "$1" 2>/dev/null || true)" = "$2" ]; then
        return 0
    fi
    hippius_golden_write_counter "$1" "$2"
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
    # v2 (a timeline transition came with the release) or v1 (none). A
    # malformed transition never degrades to the v1 gate.
    _hgmo_rc=0
    _hgmo_transition="$(hippius_golden_stamp_transition)" || _hgmo_rc=$?
    case "${_hgmo_rc}" in
        0)
            # shellcheck disable=SC2086  # two hex words, split on purpose
            hippius_golden_check_stamp_v2 "${HIPPIUS_GOLDEN_UPPER_MNT}" "${_hgmo_expected}" ${_hgmo_transition}
            ;;
        1)
            # Only M2 gets a v1 release. M0/M1 never downgrade: no
            # transition means the release was not the v2 one this guest
            # attested — refuse, never run the v1 gate.
            [ "${HIPPIUS_GOLDEN_KEY_MODE:-}" = "customer" ] \
                || hippius_die "golden: ANTI-ROLLBACK REFUSED — an M0/M1 release carried no timeline transition (stamp protocol v2 is required; a v2 guest never downgrades to v1) — fail-closed"
            hippius_golden_check_stamp_v1 "${HIPPIUS_GOLDEN_UPPER_MNT}" "${_hgmo_expected}"
            ;;
        *)
            hippius_die "golden: ANTI-ROLLBACK REFUSED — the release's timeline transition is malformed — fail-closed"
            ;;
    esac
    if [ -n "${HIPPIUS_GOLDEN_KEY_MODE:-}" ] && [ "${HIPPIUS_GOLDEN_FIRST_BOOT}" = "yes" ]; then
        hippius_golden_confirm_first_stamp
    else
        hippius_golden_confirm_stamp
    fi

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

    hippius_golden_bind_data "${_hgmo_rootmnt}"
}

# Bind the guest-keyed volume's `data/` at ${rootmnt}${HIPPIUS_GOLDEN_DATA_MOUNT}
# (#1347): a plain ext4 directory, same LUKS2+integrity volume as the
# upper, so the anti-rollback stamp, backups and §25 migration (which all
# work on the whole volume) cover it unchanged.
#
# `data/` is created ONCE (an existing VM's volume has none), mode 0755
# root, labelled like the lower's /var/lib on an SELinux base (best-effort,
# like every other relabel here — a tenant who relabels it keeps their
# label, it is never overwritten). Only `data/` itself is bound, never the
# volume root: `..` at a bind root walks to the parent MOUNT (the tenant's
# /var/lib), so neither the stamp nor `upper/`/`work/` is reachable through
# it. If either end is not a plain directory at its expected place (a
# symlink, a file, a missing /var/lib), the bind is SKIPPED with a warning:
# following a symlink could bind the volume root itself or land the bind
# outside the tenant root, and refusing to boot would brick a VM whose root
# can only be repaired from inside. Skipping exposes nothing — the tenant
# just boots without the data path. Only in-guest root can plant such an
# entry (the volume is guest-keyed), so this is a robustness guard, not a
# confidentiality one: in-guest root can mount the volume itself anyway.
# A failed mkdir or mount on a healthy tree is a broken boot: fail-closed.
hippius_golden_bind_data() {
    _hgbd_rootmnt="$1"
    _hgbd_src="${HIPPIUS_GOLDEN_UPPER_MNT}/${HIPPIUS_GOLDEN_DATA_NAME}"
    _hgbd_dst="${_hgbd_rootmnt}${HIPPIUS_GOLDEN_DATA_MOUNT}"
    # Same gate as the upper-root label: the Debian/Ubuntu path writes no xattr.
    _hgbd_selinux=no
    [ -e "${HIPPIUS_GOLDEN_LOWER_MNT}/etc/selinux/config" ] && _hgbd_selinux=yes

    if [ ! -e "${_hgbd_src}" ] && [ ! -L "${_hgbd_src}" ]; then
        mkdir -m 0755 "${_hgbd_src}" \
            || hippius_die "golden: could not create the data directory on the guest-keyed volume"
        [ "${_hgbd_selinux}" = yes ] \
            && _hippius_golden_relabel_from "${HIPPIUS_GOLDEN_LOWER_MNT}/var/lib" "${_hgbd_src}"
        hippius_log "golden: data directory created on the guest-keyed volume"
    fi
    if [ ! -d "${_hgbd_src}" ] || [ -L "${_hgbd_src}" ]; then
        hippius_log "golden: WARN the volume's data entry is not a plain directory — booting WITHOUT ${HIPPIUS_GOLDEN_DATA_MOUNT}"
        return 0
    fi

    # The mount point's parent (/var/lib, shipped by every lower) must
    # resolve to itself inside the tenant root BEFORE anything is created
    # there: a symlinked /var or /var/lib would otherwise make the mkdir and
    # the bind land outside it. `cd` + `pwd -P` are shell builtins — no
    # dependency on a `readlink -f` busybox/klibc/coreutils may not stage.
    _hgbd_parent="${HIPPIUS_GOLDEN_DATA_MOUNT%/*}"
    _hgbd_root_real="$(cd "${_hgbd_rootmnt}" 2>/dev/null && pwd -P)" || _hgbd_root_real=""
    _hgbd_parent_real="$(cd "${_hgbd_rootmnt}${_hgbd_parent}" 2>/dev/null && pwd -P)" || _hgbd_parent_real=""
    if [ -z "${_hgbd_root_real}" ] || [ "${_hgbd_parent_real}" != "${_hgbd_root_real}${_hgbd_parent}" ]; then
        hippius_log "golden: WARN ${_hgbd_parent} is missing or not a plain directory in the overlay root — booting WITHOUT ${HIPPIUS_GOLDEN_DATA_MOUNT}"
        return 0
    fi

    if [ ! -e "${_hgbd_dst}" ] && [ ! -L "${_hgbd_dst}" ]; then
        mkdir -m 0755 "${_hgbd_dst}" \
            || hippius_die "golden: could not create ${HIPPIUS_GOLDEN_DATA_MOUNT} in the overlay root"
        [ "${_hgbd_selinux}" = yes ] \
            && _hippius_golden_relabel_from "${_hgbd_rootmnt}${_hgbd_parent}" "${_hgbd_dst}"
    fi
    if [ ! -d "${_hgbd_dst}" ] || [ -L "${_hgbd_dst}" ]; then
        hippius_log "golden: WARN ${HIPPIUS_GOLDEN_DATA_MOUNT} is not a plain directory in the overlay root — booting WITHOUT it"
        return 0
    fi

    mount -o bind "${_hgbd_src}" "${_hgbd_dst}" \
        || hippius_die "golden: bind of the data directory at ${HIPPIUS_GOLDEN_DATA_MOUNT} failed"
    hippius_log "golden: data path ready at ${HIPPIUS_GOLDEN_DATA_MOUNT} (guest-keyed ext4, not overlay)"
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
# ── M0 UNTRUSTED-MINER GUEST HARDENING ──────────────────────────────
# The miner writes the libvirt domain XML and can attach devices the SNP
# launch measurement does NOT cover (only OVMF+kernel+initrd+cmdline are):
# a `cidata`-labelled disk cloud-init would merge, a virtio-serial channel
# a guest agent would answer on, unmeasured SMBIOS/fw_cfg strings systemd
# would import credentials from. The tenant bake removes/masks these, but
# we ALSO re-assert them here, from the MEASURED initramfs, into the per-VM
# overlay UPPER on EVERY boot — so an existing VM is made safe by a
# relaunch onto this initramfs (no rootfs re-bake needed), a mask in the
# upper overrides whatever the base ships, and a wiped mask is restored
# next boot. A `/dev/null` symlink is systemd's own "masked" sentinel; a
# mask is equivalent to a purge for our purpose.
#
# Runs AFTER the overlay is mounted at ${rootmnt} (writes land in the
# guest-keyed upper) and BEFORE switch_root. Fail-closed, like every other
# step on this path.
# Pure predicate (testable): does a cmdline STRING disable systemd
# credential import with the SAME effective semantics systemd uses?
# systemd keeps the LAST matching value, and in an initrd
# `rd.systemd.import_credentials=` also applies, so a naive substring check
# would accept `...=no ...=yes`. Require at least one
# `systemd.import_credentials=no` and REJECT any `systemd.import_credentials=`
# whose value is not `no`, or any `rd.systemd.import_credentials=` whose
# value is not `no`. Matches what the vali emitter now forces (exactly one
# canonical =no, no rd. override).
#
# Two things systemd does that a shell word split does not, both closed
# here rather than emulated:
#   - systemd UNQUOTES and concatenates quoted fragments (EXTRACT_UNQUOTE):
#     `'systemd.import_credentials'=yes` or `"x systemd.import_credentials=no"`
#     mean something other than their shell words. vali never emits a quote
#     or a backslash (0 of 600 recorded cmdlines on 2026-09-28), so ANY
#     `"`, `'` or `\` in the cmdline refuses outright.
#   - systemd splits on space, tab, newline AND carriage return; a CR is
#     refused too, since the shell split would not see it as a separator.
#   - an unquoted `$1` would also GLOB against the initramfs filesystem
#     (`systemd.import_credentials=n?` matching a file named `...=no`). The
#     body is a subshell with `set -f`, so pathname expansion is off here
#     and nowhere else.
hippius_golden_has_no_credential_import() (
    set -f
    case "$1" in
        *\"* | *\'* | *\\*) exit 1 ;;
    esac
    # systemd also splits on CR, the shell's default IFS does not: refuse it
    # (vali never emits one) rather than let `x<CR>key=yes` hide a token.
    _hci_cr="$(printf '\r')"
    case "$1" in
        *"${_hci_cr}"*) exit 1 ;;
    esac
    _hci_seen_no=0
    for _hci_tok in $1; do
        _hci_key="${_hci_tok%%=*}"
        _hci_val="${_hci_tok#*=}"
        # systemd treats `-` and `_` as equivalent in a cmdline key, so both
        # spellings of import_credentials (and the rd.* initrd variant) count.
        case "${_hci_key}" in
            systemd.import_credentials | systemd.import-credentials)
                if [ "${_hci_val}" = no ]; then _hci_seen_no=1; else exit 1; fi ;;
            rd.systemd.import_credentials | rd.systemd.import-credentials)
                [ "${_hci_val}" = no ] || exit 1 ;;
        esac
    done
    [ "${_hci_seen_no}" -eq 1 ]
)

# Best-effort SELinux relabel: copy the security.selinux context of a
# reference path in the SAME base onto a path we just created, so the file
# is not left unlabeled under enforcing SELinux (Fedora/CS10). NON-fatal:
# the real cidata/agent protection comes from the MEASURED base (dm-verity
# lower, labeled at bake) — the upper copy here is defense-in-depth, so a
# labeling miss must never fail-close the boot. No-op on a non-SELinux base
# (getfattr returns nothing).
_hippius_golden_relabel_from() {
    _hgrf_ref="$1"
    _hgrf_dst="$2"
    command -v getfattr >/dev/null 2>&1 || return 0
    command -v setfattr >/dev/null 2>&1 || return 0
    # `|| _hgrf_ctx=""`: a ref with no security.selinux attr makes getfattr
    # exit non-zero — that just means "non-SELinux base", not an error (and
    # must not trip a caller's `set -e`).
    _hgrf_ctx="$(getfattr --absolute-names -h -n security.selinux --only-values \
        "${_hgrf_ref}" 2>/dev/null | tr -d '\000')" || _hgrf_ctx=""
    [ -n "${_hgrf_ctx}" ] || return 0
    case "${_hgrf_ctx}" in
        *[!:_a-zA-Z0-9.,-]* | *:*:*:* ) : ;;
        * ) return 0 ;;
    esac
    setfattr -h -n security.selinux -v "${_hgrf_ctx}" "${_hgrf_dst}" 2>/dev/null \
        || hippius_log "golden: WARN could not relabel ${_hgrf_dst} (best-effort)"
}

# The security.selinux label of a path, or nothing (non-SELinux base, or no
# getfattr to read it with).
_hippius_golden_selinux_ctx() {
    command -v getfattr >/dev/null 2>&1 || return 0
    getfattr --absolute-names -h -n security.selinux --only-values "$1" 2>/dev/null \
        | tr -d '\000' || true
}

# Directory-safe mask: point ${path} at /dev/null (systemd's masked
# sentinel), removing whatever is there first. `ln -sf /dev/null dir` would
# create dir/null and falsely succeed, so remove any existing node, create
# the symlink, and VERIFY it is a symlink to exactly /dev/null. Fail-closed.
_hippius_golden_mask_path() {
    _hgmp_path="$1"
    _hgmp_ref="$2"
    rm -rf "${_hgmp_path}" 2>/dev/null || true
    ln -s /dev/null "${_hgmp_path}" \
        || hippius_die "golden: write_masks could not mask ${_hgmp_path}"
    { [ -L "${_hgmp_path}" ] && [ "$(readlink "${_hgmp_path}")" = /dev/null ]; } \
        || hippius_die "golden: mask verify failed for ${_hgmp_path} (not a /dev/null symlink)"
    [ -n "${_hgmp_ref}" ] && _hippius_golden_relabel_from "${_hgmp_ref}" "${_hgmp_path}"
    return 0
}

# Pure filesystem writer (testable): stamp the guest-side masks + the
# cloud-init NoCloud pin + the sshd key-only drop-in into ${root}'s /etc (the
# overlay upper at boot).
# Fail-closed on any write error — a healthy overlay upper never fails
# these, so a failure means the boot is broken.
hippius_golden_write_masks() {
    _hgwm_root="$1"
    [ -n "${_hgwm_root}" ] || hippius_die "golden: write_masks needs a root arg"

    # Mask host->guest control surfaces: an `/etc` unit/generator symlinked
    # to /dev/null wins over the vendor copy in /usr/lib. Guest agents
    # (qemu-guest-agent / spice / vmtools) answer on a miner-attachable
    # virtio channel — mask spice's socket too, not only its service.
    # systemd-ssh-generator binds sshd to AF_VSOCK. The getty TEMPLATES are
    # masked (not only serial-getty@ttyS0): systemd-getty-generator
    # auto-instantiates serial-getty@ for any miner-attached console incl.
    # virtio /dev/hvc0, and getty@ for /dev/tty1. systemd-imds-generator /
    # systemd-imds-import (systemd >=261) fetch credentials from
    # miner-controlled DMI/network — masked for a future Fedora bump
    # (no-op on today's systemd 258). hippius-data-disk (#365, #1350): a
    # golden VM has no data disk, so on a golden base that unit could only
    # format + mount a /dev/vde the miner attached on its own, with no
    # anti-rollback; bakes before #1351 still ship it in /etc.
    _hgwm_sysd="${_hgwm_root}/etc/systemd/system"
    _hgwm_gen="${_hgwm_root}/etc/systemd/system-generators"
    mkdir -p "${_hgwm_sysd}" "${_hgwm_gen}" \
        || hippius_die "golden: write_masks could not create ${_hgwm_sysd} / ${_hgwm_gen} in the overlay upper"
    for _hgwm_unit in \
        qemu-guest-agent.service \
        spice-vdagentd.service \
        spice-vdagentd.socket \
        spice-vdagent.service \
        vmtoolsd.service \
        open-vm-tools.service \
        serial-getty@.service \
        getty@.service \
        hippius-data-disk.service \
        systemd-imds-import.service; do
        _hippius_golden_mask_path "${_hgwm_sysd}/${_hgwm_unit}" "${_hgwm_sysd}"
    done
    for _hgwm_g in systemd-ssh-generator systemd-imds-generator; do
        _hippius_golden_mask_path "${_hgwm_gen}/${_hgwm_g}" "${_hgwm_gen}"
    done

    # cloud-init: pin NoCloud to the tenant tmpfs seed and turn OFF the
    # `cidata` volume probe, so a miner-attached disk labelled `cidata`
    # cannot merge user-data/meta-data (public-keys, runcmd) over ours. The
    # `99-zz-` prefix sorts LAST in cloud.cfg.d so this wins the merge; the
    # measured base (which we control) must never ship a later-sorting file
    # that re-enables the probe. Restores the setting even on a base that
    # predates the bake-time fix.
    _hgwm_cc="${_hgwm_root}/etc/cloud/cloud.cfg.d"
    mkdir -p "${_hgwm_cc}" \
        || hippius_die "golden: write_masks could not create ${_hgwm_cc} in the overlay upper"
    _hgwm_ccf="${_hgwm_cc}/99-zz-hippius-harden.cfg"
    cat > "${_hgwm_ccf}" <<'HIPPIUS_HARDEN_CC' \
        || hippius_die "golden: write_masks could not write the cloud-init hardening drop-in"
# hippius M0 hardening — re-asserted by the measured initramfs every boot.
# NoCloud reads ONLY the tenant tmpfs seed; the `cidata` volume probe is
# OFF so an unmeasured, miner-attached disk labelled `cidata` is ignored.
datasource_list: [ NoCloud, None ]
datasource:
  NoCloud:
    fs_label: null
    seedfrom: /run/cloud-init/seed/
HIPPIUS_HARDEN_CC
    # Label the new drop-in like an existing /etc/cloud file so enforcing
    # SELinux (Fedora/CS10) does not deny cloud-init reading it.
    if [ -f "${_hgwm_root}/etc/cloud/cloud.cfg" ]; then
        _hippius_golden_relabel_from "${_hgwm_root}/etc/cloud/cloud.cfg" "${_hgwm_ccf}"
    else
        _hippius_golden_relabel_from "${_hgwm_cc}" "${_hgwm_ccf}"
    fi

    # sshd key-only: the bake's 00-hippius-harden.conf, byte for byte
    # (golden-overlay-test pins the two equal). sshd keeps the first value
    # it reads and reads sshd_config.d in name order, so 00- wins over the
    # 50-cloud-init.conf a seed with `ssh_pwauth: true` wrote. Re-asserted
    # every boot like the masks above, which also brings VMs whose base
    # predates the bake-time file to key-only. The tenant overrides it with
    # an earlier-sorting drop-in or a `Match` block, not by editing it.
    _hgwm_sshd="${_hgwm_root}/etc/ssh/sshd_config.d"
    mkdir -p "${_hgwm_sshd}" \
        || hippius_die "golden: write_masks could not create ${_hgwm_sshd} in the overlay upper"
    _hgwm_sshdf="${_hgwm_sshd}/00-hippius-harden.conf"
    # Remove whatever sits at the path first (a tenant symlink or file): the
    # drop-in is always a fresh regular file, never written through a link.
    rm -f "${_hgwm_sshdf}" \
        || hippius_die "golden: write_masks could not replace ${_hgwm_sshdf}"
    cat > "${_hgwm_sshdf}" <<'HIPPIUS_SSHD_HARDEN' \
        || hippius_die "golden: write_masks could not write the sshd hardening drop-in"
# hippius: SSH is key-only by default. sshd keeps the first value it reads
# for each keyword and reads sshd_config.d in name order, so this file wins
# over cloud-init's 50-cloud-init.conf (ssh_pwauth) and the distro defaults.
# On golden images it is re-written at every boot. To change a setting on
# your VM, put it in a drop-in that sorts BEFORE this one (for example
# 00-00-local.conf) or in a `Match` block, which overrides it.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
X11Forwarding no
GSSAPIAuthentication no
GSSAPIKeyExchange no
HIPPIUS_SSHD_HARDEN
    chmod 0644 "${_hgwm_sshdf}" \
        || hippius_die "golden: write_masks could not chmod the sshd hardening drop-in"
    # Labeled like sshd_config (else like its directory) so enforcing
    # SELinux (CS10/Fedora) lets sshd read it. A label that did not take is
    # NOT left behind: sshd exits when an Included file cannot be opened, so
    # an unreadable drop-in would lock the tenant out of SSH. The drop-in is
    # removed instead (the base's own config applies, as before this file
    # existed) and the boot goes on, with a WARN in the boot log.
    _hgwm_sshref="${_hgwm_root}/etc/ssh/sshd_config"
    [ -f "${_hgwm_sshref}" ] || _hgwm_sshref="${_hgwm_sshd}"
    _hippius_golden_relabel_from "${_hgwm_sshref}" "${_hgwm_sshdf}"
    _hgwm_want="$(_hippius_golden_selinux_ctx "${_hgwm_sshref}")"
    if [ -n "${_hgwm_want}" ] \
        && [ "$(_hippius_golden_selinux_ctx "${_hgwm_sshdf}")" != "${_hgwm_want}" ]; then
        rm -f "${_hgwm_sshdf}" \
            || hippius_die "golden: could not remove the unlabeled sshd drop-in ${_hgwm_sshdf} (sshd would not start)"
        hippius_log "golden: WARN sshd drop-in not labeled ${_hgwm_want}; removed it so sshd still starts (SSH is NOT forced key-only this boot)"
    fi
}

hippius_golden_harden_root() {
    _hghr_root="$1"
    [ -n "${_hghr_root}" ] || hippius_die "golden: harden_root needs a rootmnt arg"

    # Defense-in-depth measured guarantee: vali bakes
    # `systemd.import_credentials=no` into the measured cmdline (the only
    # kill switch for systemd credential import from the unmeasured SMBIOS
    # type 11 / fw_cfg surfaces the miner controls — root ssh keys,
    # tmpfiles.extra, fstab.extra). If some launch path emitted a cmdline
    # without it, refuse to switch_root rather than boot a guest whose
    # systemd would import a miner-set credential.
    hippius_golden_has_no_credential_import "$(cat /proc/cmdline 2>/dev/null || true)" \
        || hippius_die "golden: measured cmdline lacks systemd.import_credentials=no — refusing switch_root (unmeasured SMBIOS/fw_cfg credential import would be enabled)"

    hippius_golden_write_masks "${_hghr_root}"

    hippius_log "golden: M0 guest masks + cloud-init pin + sshd key-only re-asserted into the overlay upper"
}

# ── Guest components release (docs/design/guest-component-rollout.md) ──
# A components release is appended to the base's initrd as one more cpio
# member. It replaces this library and the other Hippius initramfs files,
# and carries the Hippius ROOTFS agents (keepalive, telemetry, eol-sign)
# and their units as ONE squashfs image. This step mounts that image in
# guest RAM and points the units at it, so every Hippius byte the guest
# runs comes from its measured initrd (G1), never from the base.
#
# The release lives at fixed paths of the initrd — constants of this
# measured file, NOT cmdline-, env- or device-selectable:
#   ${dir}/release             the release record (below)
#   ${dir}/components.squashfs the rootfs components image
#   ${dir}/busybox             static busybox (sha256sum, cp, loop mount):
#                              no dependency on the base initrd's tools
#
# The record is `key=value` lines, written by
# scripts/guest/build-guest-release.sh:
#   version=<int>  security_epoch=<int>  commit=<40 hex>
#   squashfs_sha256=<64 hex>
#   enable=<unit>:<target>   (repeatable) link the unit + its .wants link
#   retire=<unit>            (repeatable) mask a unit an earlier release
#                            (or the base) shipped
#
# Policy:
#   - no record ⇒ strict no-op (every initrd built before this design):
#     the base's units and agents run as before;
#   - a record ⇒ the links are ALWAYS written, fail-closed like the M0
#     masks, whether or not the image mounted. A mount failure (only a
#     build bug can cause it: record and image are both measured) leaves
#     the links dangling and NO Hippius agent running — never the base's
#     older agents;
#   - a malformed record is a build bug ⇒ fail-closed.
HIPPIUS_GUEST_DIR="/lib/hippius/guest"
HIPPIUS_GUEST_RUN="/run/hippius"
# The image is mounted at ${HIPPIUS_GUEST_RUN}/guest. /run is moved into
# the new root at switch_root by both initramfs families (with its
# submounts) and systemd keeps it. A mount of its own, so the `noexec`
# initramfs-tools puts on /run does not apply to it.
HIPPIUS_GUEST_MOUNT_NAME="guest"

# Pure predicate: a systemd unit or target name we accept in a record.
hippius_golden_valid_unit_name() {
    case "$1" in
        '' | *[!A-Za-z0-9@._-]* | .* ) return 1 ;;
        *.service | *.target | *.socket | *.timer | *.path ) return 0 ;;
    esac
    return 1
}

# Pure parser (testable): validate a release record and print it back as
# normalised lines (`version N`, `security_epoch N`, `commit H`,
# `squashfs_sha256 H`, then `enable <unit> <target>` / `retire <unit>` in
# record order). Non-zero on any malformed line, unknown or repeated
# scalar key, or a missing required key.
hippius_golden_parse_release() (
    set -f
    _hgpr_file="$1"
    [ -r "${_hgpr_file}" ] || exit 1
    _hgpr_v="" _hgpr_e="" _hgpr_c="" _hgpr_s="" _hgpr_h=""
    _hgpr_out=""
    _hgpr_nl='
'
    while IFS= read -r _hgpr_line || [ -n "${_hgpr_line}" ]; do
        case "${_hgpr_line}" in
            '' | '#'*) continue ;;
        esac
        _hgpr_key="${_hgpr_line%%=*}"
        _hgpr_val="${_hgpr_line#*=}"
        [ "${_hgpr_key}" != "${_hgpr_line}" ] || exit 1
        case "${_hgpr_key}" in
            version)
                case "${_hgpr_val}" in '' | *[!0-9]*) exit 1 ;; esac
                [ -z "${_hgpr_v}" ] || exit 1
                _hgpr_v="${_hgpr_val}"
                ;;
            security_epoch)
                case "${_hgpr_val}" in '' | *[!0-9]*) exit 1 ;; esac
                [ -z "${_hgpr_e}" ] || exit 1
                _hgpr_e="${_hgpr_val}"
                ;;
            commit)
                case "${_hgpr_val}" in *[!0-9a-f]*) exit 1 ;; esac
                [ "${#_hgpr_val}" -eq 40 ] && [ -z "${_hgpr_c}" ] || exit 1
                _hgpr_c="${_hgpr_val}"
                ;;
            squashfs_sha256)
                case "${_hgpr_val}" in *[!0-9a-f]*) exit 1 ;; esac
                [ "${#_hgpr_val}" -eq 64 ] && [ -z "${_hgpr_s}" ] || exit 1
                _hgpr_s="${_hgpr_val}"
                ;;
            health_mask)
                # The health checks the release's keepalive attests (vali's
                # gate reads it from the build); nothing at boot uses it.
                case "${_hgpr_val}" in '' | *[!0-9]*) exit 1 ;; esac
                [ "${#_hgpr_val}" -le 10 ] && [ -z "${_hgpr_h}" ] || exit 1
                _hgpr_h="${_hgpr_val}"
                ;;
            enable)
                _hgpr_unit="${_hgpr_val%%:*}"
                _hgpr_tgt="${_hgpr_val#*:}"
                [ "${_hgpr_unit}" != "${_hgpr_val}" ] || exit 1
                hippius_golden_valid_unit_name "${_hgpr_unit}" || exit 1
                case "${_hgpr_unit}" in *.target) exit 1 ;; esac
                case "${_hgpr_tgt}" in *.target) ;; *) exit 1 ;; esac
                hippius_golden_valid_unit_name "${_hgpr_tgt}" || exit 1
                _hgpr_out="${_hgpr_out}enable ${_hgpr_unit} ${_hgpr_tgt}${_hgpr_nl}"
                ;;
            retire)
                hippius_golden_valid_unit_name "${_hgpr_val}" || exit 1
                _hgpr_out="${_hgpr_out}retire ${_hgpr_val}${_hgpr_nl}"
                ;;
            *) exit 1 ;;
        esac
    done < "${_hgpr_file}"
    [ -n "${_hgpr_v}" ] && [ -n "${_hgpr_e}" ] && [ -n "${_hgpr_c}" ] && [ -n "${_hgpr_s}" ] \
        || exit 1
    printf 'version %s\nsecurity_epoch %s\ncommit %s\nsquashfs_sha256 %s\n%s' \
        "${_hgpr_v}" "${_hgpr_e}" "${_hgpr_c}" "${_hgpr_s}" "${_hgpr_out}"
)

# Strict SELinux label: set ${ctx} on ${dst} and VERIFY it took. ${ctx}
# comes from the verity-checked LOWER (never from the tenant-writable
# upper), so a forged or missing upper label cannot be copied along.
# Unlike the best-effort `_hippius_golden_relabel_from`, a miss is fatal:
# a unit link systemd may not read would silently drop the agent. No-op
# when ${ctx} is empty (a base without SELinux).
_hippius_golden_label_strict() {
    _hgls_ctx="$1"
    _hgls_dst="$2"
    [ -n "${_hgls_ctx}" ] || return 0
    setfattr -h -n security.selinux -v "${_hgls_ctx}" "${_hgls_dst}" 2>/dev/null \
        || hippius_die "golden: components: could not label ${_hgls_dst}"
    [ "$(_hippius_golden_selinux_ctx "${_hgls_dst}")" = "${_hgls_ctx}" ] \
        || hippius_die "golden: components: label of ${_hgls_dst} did not take"
}

# The context unit links get on this base: the label of the LOWER's
# /etc/systemd/system, or nothing on a base without SELinux. Fatal when
# the base is SELinux but the label (or the tools) cannot be had.
_hippius_golden_unit_ctx() {
    [ -e "${HIPPIUS_GOLDEN_LOWER_MNT}/etc/selinux/config" ] || return 0
    command -v getfattr >/dev/null 2>&1 && command -v setfattr >/dev/null 2>&1 \
        || hippius_die "golden: components: SELinux base but no getfattr/setfattr in the initramfs"
    _hguc_ctx="$(_hippius_golden_selinux_ctx "${HIPPIUS_GOLDEN_LOWER_MNT}/etc/systemd/system")"
    [ -n "${_hguc_ctx}" ] \
        || hippius_die "golden: components: the base's /etc/systemd/system carries no SELinux label"
    printf '%s' "${_hguc_ctx}"
}

# Is ${root}/${rel} reachable as REAL directories only? Walks one component
# at a time and creates a missing one, but never follows a symlink: ${root}
# is the overlay as the initramfs sees it, so an absolute symlink the
# tenant planted in the upper (`/etc/systemd/system -> /x`) would resolve
# against the INITRAMFS and send every write outside the guest root.
# Non-zero when a component is a symlink or not a directory.
_hippius_golden_real_dir() {
    _hgrd_path="$1"
    _hgrd_rest="$2"
    { [ -d "${_hgrd_path}" ] && [ ! -L "${_hgrd_path}" ]; } || return 1
    while [ -n "${_hgrd_rest}" ]; do
        _hgrd_part="${_hgrd_rest%%/*}"
        if [ "${_hgrd_part}" = "${_hgrd_rest}" ]; then _hgrd_rest=""; else _hgrd_rest="${_hgrd_rest#*/}"; fi
        _hgrd_path="${_hgrd_path}/${_hgrd_part}"
        if [ -L "${_hgrd_path}" ]; then
            return 1
        elif [ ! -e "${_hgrd_path}" ]; then
            mkdir "${_hgrd_path}" || return 1
        elif [ ! -d "${_hgrd_path}" ]; then
            return 1
        fi
    done
    return 0
}

# Directory-safe symlink: ${path} -> ${target}, whatever was there before
# (a tenant file, a directory, another link), verified, labelled strictly.
# The caller has checked the parent with `_hippius_golden_real_dir`.
# Fail-closed, like `_hippius_golden_mask_path`.
_hippius_golden_link_path() {
    _hglp_path="$1"
    _hglp_target="$2"
    _hglp_ctx="$3"
    rm -rf "${_hglp_path}" 2>/dev/null || true
    ln -s "${_hglp_target}" "${_hglp_path}" \
        || hippius_die "golden: components: could not link ${_hglp_path}"
    { [ -L "${_hglp_path}" ] && [ "$(readlink "${_hglp_path}")" = "${_hglp_target}" ]; } \
        || hippius_die "golden: components: link verify failed for ${_hglp_path}"
    _hippius_golden_label_strict "${_hglp_ctx}" "${_hglp_path}"
}

# Mount the components image. Best-effort: non-zero on any miss, after
# logging why. ${dir} is the release dir in the initramfs, ${run} the
# /run/hippius directory, ${sha} the record's image sha256.
_hippius_golden_components_mount() {
    _hgcm_dir="$1"
    _hgcm_run="$2"
    _hgcm_sha="$3"
    _hgcm_bb="${_hgcm_dir}/busybox"
    _hgcm_img="${_hgcm_dir}/components.squashfs"
    _hgcm_copy="${_hgcm_run}/${HIPPIUS_GUEST_MOUNT_NAME}.squashfs"
    _hgcm_mnt="${_hgcm_run}/${HIPPIUS_GUEST_MOUNT_NAME}"
    [ -x "${_hgcm_bb}" ] || { hippius_log "golden: components: WARN no busybox in the release"; return 1; }
    [ -r "${_hgcm_img}" ] || { hippius_log "golden: components: WARN no image in the release"; return 1; }
    mkdir -p "${_hgcm_mnt}" || { hippius_log "golden: components: WARN cannot create ${_hgcm_mnt}"; return 1; }
    # Into guest RAM (tmpfs): the initramfs's own files are freed at
    # switch_root; the copy is what the loop device keeps open. The sha is
    # checked on the copy, the bytes actually mounted.
    "${_hgcm_bb}" cp "${_hgcm_img}" "${_hgcm_copy}" \
        || { hippius_log "golden: components: WARN copy to ${_hgcm_copy} failed"; return 1; }
    _hgcm_got="$("${_hgcm_bb}" sha256sum "${_hgcm_copy}" 2>/dev/null)" || _hgcm_got=""
    _hgcm_got="${_hgcm_got%% *}"
    if [ "${_hgcm_got}" != "${_hgcm_sha}" ]; then
        rm -f "${_hgcm_copy}"
        hippius_log "golden: components: WARN image sha256 mismatch (got '${_hgcm_got}')"
        return 1
    fi
    # `loop` is built in on most kernels; where it is a module the
    # initramfs may not carry it, so fall back to the base's own module
    # tree on the verity-checked lower (open and mounted at this point).
    if [ ! -e /dev/loop-control ]; then
        modprobe loop 2>/dev/null \
            || modprobe -d "${HIPPIUS_GOLDEN_LOWER_MNT}" loop 2>/dev/null \
            || true
    fi
    "${_hgcm_bb}" mount -t squashfs -o ro,nosuid,nodev,loop "${_hgcm_copy}" "${_hgcm_mnt}" \
        || { hippius_log "golden: components: WARN mount of the image failed"; return 1; }
    if [ ! -d "${_hgcm_mnt}/units" ]; then
        "${_hgcm_bb}" umount "${_hgcm_mnt}" 2>/dev/null || true
        hippius_log "golden: components: WARN the image carries no units/"
        return 1
    fi
    return 0
}

# The boot step proper, parameterised for the unit test: ${root} is the
# assembled overlay root, ${dir} the release dir, ${run} /run/hippius as
# the initramfs sees it. The links always name the FINAL path
# (${HIPPIUS_GUEST_RUN}/guest/units/...), the one the booted system sees.
_hippius_golden_components_run() {
    _hgcr_root="$1"
    _hgcr_dir="$2"
    _hgcr_run="$3"
    _hgcr_rec="${_hgcr_dir}/release"
    if [ ! -e "${_hgcr_rec}" ] && [ ! -L "${_hgcr_rec}" ]; then
        hippius_log "golden: components: no release in this initrd — base agents unchanged"
        return 0
    fi
    _hgcr_parsed="$(hippius_golden_parse_release "${_hgcr_rec}")" \
        || hippius_die "golden: components: malformed release record ${_hgcr_rec} — fail-closed"
    _hgcr_version="" _hgcr_epoch="" _hgcr_commit="" _hgcr_sha=""
    while read -r _hgcr_k _hgcr_v _hgcr_rest; do
        case "${_hgcr_k}" in
            version) _hgcr_version="${_hgcr_v}" ;;
            security_epoch) _hgcr_epoch="${_hgcr_v}" ;;
            commit) _hgcr_commit="${_hgcr_v}" ;;
            squashfs_sha256) _hgcr_sha="${_hgcr_v}" ;;
        esac
    done <<HIPPIUS_REC_EOF
${_hgcr_parsed}
HIPPIUS_REC_EOF

    mkdir -p "${_hgcr_run}" \
        || hippius_die "golden: components: could not create ${_hgcr_run}"
    _hgcr_mounted=no
    if _hippius_golden_components_mount "${_hgcr_dir}" "${_hgcr_run}" "${_hgcr_sha}"; then
        _hgcr_mounted=yes
    fi

    # The unit links. A symlinked /etc, /etc/systemd or /etc/systemd/system
    # (something only in-guest root can plant: the upper is guest-keyed) is
    # never followed — it would resolve against the initramfs — and the
    # links cannot be written without it, so the boot stops: a release
    # never runs the base's agents. A symlinked .wants is replaced.
    _hgcr_ctx="$(_hippius_golden_unit_ctx)" \
        || hippius_die "golden: components: cannot determine the unit label"
    _hgcr_sysd="${_hgcr_root}/etc/systemd/system"
    _hippius_golden_real_dir "${_hgcr_root}" etc/systemd/system \
        || hippius_die "golden: components: /etc/systemd/system is not a plain directory in the guest root (a symlink?) — the unit links cannot be written — fail-closed"
    _hippius_golden_label_strict "${_hgcr_ctx}" "${_hgcr_sysd}"
    while read -r _hgcr_k _hgcr_unit _hgcr_tgt; do
        case "${_hgcr_k}" in
            enable)
                _hippius_golden_link_path "${_hgcr_sysd}/${_hgcr_unit}" \
                    "${HIPPIUS_GUEST_RUN}/${HIPPIUS_GUEST_MOUNT_NAME}/units/${_hgcr_unit}" \
                    "${_hgcr_ctx}"
                _hgcr_wants="${_hgcr_sysd}/${_hgcr_tgt}.wants"
                if [ -L "${_hgcr_wants}" ] || { [ -e "${_hgcr_wants}" ] && [ ! -d "${_hgcr_wants}" ]; }; then
                    rm -f "${_hgcr_wants}" \
                        || hippius_die "golden: components: could not replace ${_hgcr_wants}"
                fi
                _hippius_golden_real_dir "${_hgcr_sysd}" "${_hgcr_tgt}.wants" \
                    || hippius_die "golden: components: could not create ${_hgcr_wants}"
                _hippius_golden_label_strict "${_hgcr_ctx}" "${_hgcr_wants}"
                _hippius_golden_link_path "${_hgcr_wants}/${_hgcr_unit}" "../${_hgcr_unit}" \
                    "${_hgcr_ctx}"
                ;;
            retire)
                _hippius_golden_link_path "${_hgcr_sysd}/${_hgcr_unit}" /dev/null \
                    "${_hgcr_ctx}"
                ;;
        esac
    done <<HIPPIUS_REC_EOF
${_hgcr_parsed}
HIPPIUS_REC_EOF
    # For the agents to report; nothing at boot reads it.
    printf 'version=%s\nsecurity_epoch=%s\ncommit=%s\nmounted=%s\n' \
        "${_hgcr_version}" "${_hgcr_epoch}" "${_hgcr_commit}" "${_hgcr_mounted}" \
        > "${_hgcr_run}/guest-components" \
        || hippius_die "golden: components: could not write ${_hgcr_run}/guest-components"
    if [ "${_hgcr_mounted}" = yes ]; then
        hippius_log "golden: components: release ${_hgcr_version} (epoch ${_hgcr_epoch}) mounted at ${HIPPIUS_GUEST_RUN}/${HIPPIUS_GUEST_MOUNT_NAME}"
    else
        hippius_log "golden: components: WARN release ${_hgcr_version} NOT mounted — no Hippius agent runs this boot"
    fi
}

hippius_golden_mount_components() {
    [ -n "$1" ] || hippius_die "golden: mount_components needs a rootmnt arg"
    _hippius_golden_components_run "$1" "${HIPPIUS_GUEST_DIR}" "${HIPPIUS_GUEST_RUN}"
}

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

    # Customer-held keys (M1/M2 only; M0 returns at once): check the
    # volume's key-mode token against the measured binding and pick up
    # its share version — still before any KBS or guardian contact.
    hippius_golden_keymode_prepare

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
    rm -f "${HIPPIUS_GOLDEN_STAMP_EXPECTED}" "${HIPPIUS_GOLDEN_STAMP_CTX}" \
        "${HIPPIUS_GOLDEN_STAMP_TRANSITION}" 2>/dev/null || true
    # Stamp protocol v2: the release's timeline transition (absent only
    # for M2's v1 release; M0/M1 refuse without one — see
    # HIPPIUS_GOLDEN_TIMELINE_NAME).
    HIPPIUS_EXTRA_RELEASE_FLAGS="--volume-stamp-expected-out ${HIPPIUS_GOLDEN_STAMP_EXPECTED} --volume-stamp-ctx-out ${HIPPIUS_GOLDEN_STAMP_CTX} --volume-stamp-transition-out ${HIPPIUS_GOLDEN_STAMP_TRANSITION}"
    # M1/M2: where the release leaves the sealed share version, and the
    # version this volume's token names. Nothing for M0 (byte-identical
    # command line).
    # And no KBS contact at all before the guardian leg: the release
    # core's diagnostic KBS preflight is skipped.
    if [ -n "${HIPPIUS_GOLDEN_KEY_MODE:-}" ]; then
        rm -f "${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT}" "${HIPPIUS_GOLDEN_IID_OUT}" \
            "${HIPPIUS_GOLDEN_USERDATA_STAGED}" 2>/dev/null || true
        HIPPIUS_EXTRA_RELEASE_FLAGS="${HIPPIUS_EXTRA_RELEASE_FLAGS}$(hippius_golden_keymode_release_flags)"
        HIPPIUS_GUARDIAN_FIRST=1
        export HIPPIUS_GUARDIAN_FIRST
        # H5b: the release stages the user-data instead of writing it to
        # the seed; `hippius_golden_install_seed` rewrites the whole seed
        # (the core's per-boot meta-data included) once the upper is open
        # (see "cloud-init user-data on FIRST BOOT ONLY").
        HIPPIUS_USERDATA_OUT="${HIPPIUS_GOLDEN_USERDATA_STAGED}"
    fi
    export HIPPIUS_EXTRA_RELEASE_FLAGS

    # Now the network half: reuse the §21 release VERBATIM (releases the
    # per-VM KEK to ${_hgrun_kek}), open the guest-keyed upper, mount the
    # overlay. A subshell so a mid-path hippius_die (exit 1) aborts only
    # the ATTEMPT (not the init) and ALWAYS falls through to the shred
    # below. dm-mapper devices + kernel mounts created inside persist
    # (kernel state); only shell env — unused afterward — is scoped
    # (HIPPIUS_GOLDEN_FIRST_BOOT included: it is set and read in here).
    _hgrun_rc=0
    ( hippius_acquire "${_hgrun_kek}" \
        && hippius_golden_open_upper "${_hgrun_kek}" \
        && hippius_golden_mount_overlay "${_hgrun_rootmnt}" \
        && hippius_golden_install_seed ) || _hgrun_rc=$?

    # §20: ALWAYS shred the KEK — success OR any failure path. H5b: and
    # the staged user-data, which the success path has already moved or
    # shredded (M0 never creates it).
    hippius_golden_shred_kek "${_hgrun_kek}"
    hippius_golden_shred_kek "${HIPPIUS_GOLDEN_USERDATA_STAGED}"

    [ "${_hgrun_rc}" -eq 0 ] \
        || hippius_die "golden: KBS release / overlay assembly failed — fail-closed (disk stays locked; KEK shredded)"

    # M0 untrusted-miner hardening: re-assert the guest-side masks into the
    # per-VM overlay upper before switch_root. Runs from the MEASURED
    # initramfs, so it is trusted; it makes existing VMs safe on a relaunch
    # without a rootfs re-bake, and defends against a base that predates the
    # bake-time hardening. Fail-closed like the rest of this path.
    hippius_golden_harden_root "${_hgrun_rootmnt}"

    # Guest components release: mount the measured agents image and point
    # the units at it (strict no-op on an initrd that carries no release).
    hippius_golden_mount_components "${_hgrun_rootmnt}"

    hippius_log "golden: boot assembled — handing control back for switch_root into ${_hgrun_rootmnt}"
}
