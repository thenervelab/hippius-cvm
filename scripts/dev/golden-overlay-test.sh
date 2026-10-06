#!/usr/bin/env bash
# Unit test for the pure-logic functions of `hippius-golden-overlay.sh`
# (golden-bake PR3) — the GOLDEN-mode detection + parameter validation
# that gates the guest overlay boot. Root-free, no /proc, no devices:
# it sources the library and drives the pure resolvers with cmdline
# STRINGS, so the security-load-bearing branch (golden ⇔ dm-verity.root
# PRESENT and luks_header_sha256 ABSENT; 64-hex root hash; positive
# disk_gb) is pinned in CI without a live boot.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LIB="${HERE}/../initramfs/hippius-golden-overlay.sh"
[[ -r "${LIB}" ]] || { echo "golden-overlay-test: lib not found at ${LIB}" >&2; exit 1; }

# Stubs so the library sources cleanly (the pure functions never call
# these, but a future edit might — fail loud if so).
hippius_log() { :; }
hippius_die() { echo "hippius_die: $*" >&2; return 1; }
# shellcheck source=scripts/initramfs/hippius-golden-overlay.sh
. "${LIB}"

fail=0
ok()  { echo "golden-overlay-test: OK — $*"; }
err() { echo "golden-overlay-test: FAIL — $*" >&2; fail=1; }

GOOD_HASH="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# ── 1. cmdline value extraction ─────────────────────────────────────
v="$(hippius_golden_cmdline_value "ro quiet dm-verity.root=${GOOD_HASH} boot=hippius-golden" "dm-verity.root")"
[[ "${v}" == "${GOOD_HASH}" ]] || err "cmdline_value did not extract dm-verity.root (got '${v}')"
[[ "$(hippius_golden_cmdline_value "ro quiet" "dm-verity.root" || true)" == "" ]] \
    || err "cmdline_value returned a value for an absent key"
ok "cmdline value extraction"

# ── 2. GOLDEN detection: BOTH conditions required ───────────────────
# golden ⇔ dm-verity.root present AND luks_header_sha256 absent.
if hippius_is_golden_cmdline "ro quiet dm-verity.root=${GOOD_HASH} hippius.disk_gb=10 boot=hippius-golden"; then
    ok "golden cmdline detected"
else
    err "golden cmdline NOT detected"
fi
# Legacy: luks header present, no verity root → NOT golden.
if hippius_is_golden_cmdline "ro quiet hippius.luks_header_sha256=${GOOD_HASH} hippius.disk_gb=10"; then
    err "legacy cmdline wrongly detected as golden"
else
    ok "legacy cmdline not golden"
fi
# Half-formed / hostile: BOTH tokens present → fail closed (NOT golden),
# so a miner cannot splice dm-verity.root onto a legacy cmdline to skip
# the LUKS-header gate.
if hippius_is_golden_cmdline "ro dm-verity.root=${GOOD_HASH} hippius.luks_header_sha256=${GOOD_HASH}"; then
    err "both-tokens cmdline wrongly detected as golden (fail-open!)"
else
    ok "both-tokens cmdline fails closed (not golden)"
fi
# Neither token → not golden.
if hippius_is_golden_cmdline "ro quiet console=ttyS0"; then
    err "bare cmdline wrongly detected as golden"
else
    ok "bare cmdline not golden"
fi

# ── 3. root-hash validation (64 lowercase hex) ──────────────────────
hippius_golden_valid_root_hash "${GOOD_HASH}"       || err "valid 64-hex root hash rejected"
! hippius_golden_valid_root_hash ""                 || err "empty root hash accepted"
! hippius_golden_valid_root_hash "abc"              || err "short root hash accepted"
! hippius_golden_valid_root_hash "$(printf 'A%.0s' $(seq 64))" || err "uppercase root hash accepted"
! hippius_golden_valid_root_hash "$(printf 'z%.0s' $(seq 64))" || err "non-hex root hash accepted"
ok "root-hash validation (64 lowercase hex; fail-closed otherwise)"

# ── 4. disk_gb validation (positive integer) ────────────────────────
hippius_golden_valid_disk_gb "10"   || err "valid disk_gb rejected"
hippius_golden_valid_disk_gb "1"    || err "disk_gb=1 rejected"
! hippius_golden_valid_disk_gb "0"  || err "disk_gb=0 accepted"
! hippius_golden_valid_disk_gb ""   || err "empty disk_gb accepted"
! hippius_golden_valid_disk_gb "5x" || err "non-numeric disk_gb accepted"
ok "disk_gb validation (positive integer; the MEASURED size anchor)"

# ── 4b. first-boot mkfs resolver (busybox-shadow-proof) ─────────────
# The upper is formatted with the REAL e2fsprogs mkfs.ext4 the golden hook
# stages at the private HIPPIUS_GOLDEN_MKFS path (some distros' busybox
# ships an `mke2fs` applet that shadows the real binary in $PATH — Debian
# trixie does). Prefer the private copy when present + executable; fall
# back to `$PATH` `mkfs.ext4` otherwise (Ubuntu's busybox omits the applet;
# a dracut-family initrd stages no private copy).
_mkfs_stub="$(mktemp)"; chmod +x "${_mkfs_stub}"
HIPPIUS_GOLDEN_MKFS="${_mkfs_stub}" \
    && [[ "$(HIPPIUS_GOLDEN_MKFS="${_mkfs_stub}" hippius_golden_mkfs_bin)" == "${_mkfs_stub}" ]] \
    && ok "mkfs resolver prefers the private staged binary" \
    || err "mkfs resolver did not prefer the private staged binary"
[[ "$(HIPPIUS_GOLDEN_MKFS="/nonexistent/hippius/mkfs.ext4" hippius_golden_mkfs_bin)" == "mkfs.ext4" ]] \
    && ok "mkfs resolver falls back to \$PATH mkfs.ext4 when the private copy is absent" \
    || err "mkfs resolver did not fall back to \$PATH mkfs.ext4"
rm -f "${_mkfs_stub}"

# ── 4c. M0 guest hardening: credential-import predicate + mask writer ─
# The predicate uses systemd's effective-value semantics (last-wins; the
# initrd rd.* variant also applies), not a naive substring check.
hippius_golden_has_no_credential_import "ro quiet systemd.import_credentials=no boot=x" \
    && ok "import-credential predicate accepts the token" \
    || err "import-credential predicate rejected a cmdline that has the token"
! hippius_golden_has_no_credential_import "ro quiet console=ttyS0" \
    && ok "import-credential predicate fails closed when the token is absent" \
    || err "import-credential predicate accepted a cmdline without the token"
! hippius_golden_has_no_credential_import "ro systemd.import_credentials=noop" \
    && ok "import-credential predicate rejects a lookalike value (noop)" \
    || err "import-credential predicate matched a lookalike value (fail-open!)"
! hippius_golden_has_no_credential_import "ro systemd.import_credentials=yes" \
    && ok "import-credential predicate rejects =yes" \
    || err "import-credential predicate accepted =yes (fail-open!)"
! hippius_golden_has_no_credential_import "ro systemd.import_credentials=no systemd.import_credentials=yes" \
    && ok "import-credential predicate rejects a later contradicting =yes (last-wins)" \
    || err "import-credential predicate accepted =no then =yes (fail-open!)"
! hippius_golden_has_no_credential_import "ro systemd.import_credentials=no rd.systemd.import_credentials=yes" \
    && ok "import-credential predicate rejects an rd.* override to yes" \
    || err "import-credential predicate accepted an rd.* override to yes (fail-open!)"
hippius_golden_has_no_credential_import "ro systemd.import_credentials=no rd.systemd.import_credentials=no" \
    && ok "import-credential predicate accepts rd.* also set to no" \
    || err "import-credential predicate rejected rd.* also =no"
# systemd treats '-' and '_' as equivalent in a key, so the dash spelling
# is the SAME option and must be caught.
! hippius_golden_has_no_credential_import "ro systemd.import_credentials=no systemd.import-credentials=yes" \
    && ok "import-credential predicate rejects the dash-spelled override" \
    || err "import-credential predicate accepted a dash-spelled =yes (fail-open!)"
hippius_golden_has_no_credential_import "ro systemd.import-credentials=no" \
    && ok "import-credential predicate accepts the dash spelling of =no" \
    || err "import-credential predicate rejected the dash spelling of =no"
# systemd unquotes args, so a quoted token must be seen through.
! hippius_golden_has_no_credential_import 'ro systemd.import_credentials=no "systemd.import_credentials=yes"' \
    && ok "import-credential predicate sees through a quoted override" \
    || err "import-credential predicate accepted a quoted =yes (fail-open!)"
# systemd unquotes and CONCATENATES quoted fragments, so a quoted key
# fragment or a quoted multi-word arg means something the shell split does
# not see. Any quote or backslash in the cmdline refuses.
! hippius_golden_has_no_credential_import "ro systemd.import_credentials=no 'systemd.import_credentials'=yes" \
    && ok "import-credential predicate refuses a single-quoted key fragment" \
    || err "import-credential predicate accepted 'key'=yes (fail-open!)"
! hippius_golden_has_no_credential_import 'ro systemd.import_credentials=no "systemd.import_credentials"=yes' \
    && ok "import-credential predicate refuses a double-quoted key fragment" \
    || err "import-credential predicate accepted \"key\"=yes (fail-open!)"
! hippius_golden_has_no_credential_import 'ro "x systemd.import_credentials=no"' \
    && ok "import-credential predicate refuses a token hidden inside a quoted arg" \
    || err "import-credential predicate accepted a quoted multi-word arg (fail-open!)"
! hippius_golden_has_no_credential_import 'ro systemd.import_credentials=n\o' \
    && ok "import-credential predicate refuses a backslash" \
    || err "import-credential predicate accepted a backslash-escaped value"
# systemd splits on CR; the shell's default IFS does not.
! hippius_golden_has_no_credential_import "ro systemd.import_credentials=no x$(printf '\r')systemd.import_credentials=yes" \
    && ok "import-credential predicate refuses a carriage return" \
    || err "import-credential predicate accepted a CR-separated =yes (fail-open!)"
# Pathname expansion must be off: with a file literally named
# `systemd.import_credentials=no` in the cwd, `=n?` must not glob to it.
_GLOBDIR="$(mktemp -d)"
( cd "${_GLOBDIR}" && : > 'systemd.import_credentials=no' \
    && ! hippius_golden_has_no_credential_import "ro systemd.import_credentials=n?" ) \
    && ok "import-credential predicate does not glob (=n? with a matching file)" \
    || err "import-credential predicate globbed =n? to a file (fail-open!)"
rm -f "${_GLOBDIR}/systemd.import_credentials=no"; rmdir "${_GLOBDIR}"
# The shape vali actually emits on a golden launch must pass.
_PROD_CMDLINE="console=ttyS0,115200 ro quiet ds=nocloud;s=/run/cloud-init/seed/ hippius.kbs_url=vsock://2:19266 dm-verity.root=$(printf 'ab%.0s' $(seq 32)) boot=hippius-golden systemd.import_credentials=no hippius.disk_gb=40 hippius.lifecycle_key_path=/run/hippius/lifecycle.key"
hippius_golden_has_no_credential_import "${_PROD_CMDLINE}" \
    && ok "import-credential predicate accepts the production golden cmdline shape" \
    || err "import-credential predicate REJECTS the production cmdline (would brick every VM)"

# write_masks stamps the unit/generator masks + the cloud-init pin into a
# fake overlay upper. Root-free (symlinks + a file under a tmpdir).
_MASKROOT="$(mktemp -d)"
# #1350: a pre-#1351 golden base ships the #365 data-disk unit as a REAL
# file in /etc, enabled — the mask must replace it, not sit beside it.
mkdir -p "${_MASKROOT}/etc/systemd/system/multi-user.target.wants"
printf '[Service]\nExecStart=/usr/local/sbin/hippius-data-disk-init\n' \
    > "${_MASKROOT}/etc/systemd/system/hippius-data-disk.service"
ln -s ../hippius-data-disk.service \
    "${_MASKROOT}/etc/systemd/system/multi-user.target.wants/hippius-data-disk.service"
hippius_golden_write_masks "${_MASKROOT}"
_mask_fail=0
for _u in qemu-guest-agent.service spice-vdagentd.service spice-vdagentd.socket \
    spice-vdagent.service vmtoolsd.service open-vm-tools.service \
    serial-getty@.service getty@.service hippius-data-disk.service systemd-imds-import.service; do
    _t="${_MASKROOT}/etc/systemd/system/${_u}"
    { [[ -L "${_t}" ]] && [[ "$(readlink "${_t}")" == /dev/null ]]; } \
        || { err "write_masks did not mask ${_u} to /dev/null"; _mask_fail=1; }
done
for _gn in systemd-ssh-generator systemd-imds-generator; do
    _g="${_MASKROOT}/etc/systemd/system-generators/${_gn}"
    { [[ -L "${_g}" ]] && [[ "$(readlink "${_g}")" == /dev/null ]]; } \
        || { err "write_masks did not mask ${_gn} to /dev/null"; _mask_fail=1; }
done
_cc="${_MASKROOT}/etc/cloud/cloud.cfg.d/99-zz-hippius-harden.cfg"
grep -qx '    fs_label: null' "${_cc}" 2>/dev/null \
    || { err "write_masks cloud drop-in lacks 'fs_label: null'"; _mask_fail=1; }
grep -qxF 'datasource_list: [ NoCloud, None ]' "${_cc}" 2>/dev/null \
    || { err "write_masks cloud drop-in lacks the pinned datasource_list"; _mask_fail=1; }
# sshd key-only: the same bytes the bake writes (an edit to one copy only
# would leave the bake and the every-boot re-assert disagreeing).
_sshd="${_MASKROOT}/etc/ssh/sshd_config.d/00-hippius-harden.conf"
_bake_sshd="$(awk "/<<'HIPPIUS_SSHD_HARDEN'\$/{f=1; next} /^HIPPIUS_SSHD_HARDEN\$/{f=0} f" "${HERE}/../tenant-image-bake.sh")"
for _kv in 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'PermitRootLogin no' 'X11Forwarding no' 'GSSAPIAuthentication no' 'GSSAPIKeyExchange no'; do
    grep -qxF "${_kv}" "${_sshd}" 2>/dev/null \
        || { err "write_masks sshd drop-in lacks '${_kv}'"; _mask_fail=1; }
done
[[ -n "${_bake_sshd}" && "$(cat "${_sshd}" 2>/dev/null)" == "${_bake_sshd}" ]] \
    || { err "write_masks sshd drop-in differs from the bake's 00-hippius-harden.conf"; _mask_fail=1; }
[[ "$(stat -c %a "${_sshd}" 2>/dev/null)" == 644 ]] \
    || { err "write_masks sshd drop-in is not mode 0644"; _mask_fail=1; }
# A tenant edit does not survive the next boot's re-assert.
echo 'PasswordAuthentication yes' > "${_sshd}"
hippius_golden_write_masks "${_MASKROOT}"
[[ "$(cat "${_sshd}")" == "${_bake_sshd}" ]] \
    || { err "write_masks does not restore an edited sshd drop-in"; _mask_fail=1; }
# Directory false-success trap: a pre-existing DIRECTORY at a unit path must
# be replaced by the /dev/null symlink, not have `null` created inside it.
_trap="${_MASKROOT}/etc/systemd/system/qemu-guest-agent.service"
rm -rf "${_trap}"; mkdir -p "${_trap}"
hippius_golden_write_masks "${_MASKROOT}" \
    || { err "write_masks failed over a pre-existing directory"; _mask_fail=1; }
{ [[ -L "${_trap}" ]] && [[ "$(readlink "${_trap}")" == /dev/null ]]; } \
    || { err "write_masks left a directory unmasked (ln -sf dir/null trap)"; _mask_fail=1; }
# Idempotent: a further run over the same tree must not error or duplicate.
hippius_golden_write_masks "${_MASKROOT}" \
    || { err "write_masks is not idempotent (repeat run failed)"; _mask_fail=1; }
[[ "$(readlink "${_MASKROOT}/etc/systemd/system-generators/systemd-ssh-generator")" == /dev/null ]] \
    || { err "write_masks repeat run broke the ssh-generator mask"; _mask_fail=1; }
[[ "${_mask_fail}" -eq 0 ]] && ok "write_masks stamps all masks + the cloud-init pin + the sshd key-only drop-in (= the bake's; dir-safe, idempotent)"
# A tenant symlink at the drop-in path is replaced, never written through.
_victim="${_MASKROOT}/victim"
echo keep > "${_victim}"
rm -f "${_sshd}"; ln -s "${_victim}" "${_sshd}"
hippius_golden_write_masks "${_MASKROOT}"
if [[ ! -L "${_sshd}" && "$(cat "${_sshd}")" == "${_bake_sshd}" && "$(cat "${_victim}")" == keep ]]; then
    ok "write_masks replaces a symlink at the sshd drop-in path (target untouched)"
else
    err "write_masks wrote the sshd drop-in through a symlink"
fi
rm -rf "${_MASKROOT}"

# sshd drop-in SELinux label (CS10/Fedora enforcing). An unlabeled drop-in
# is not readable by sshd, and sshd exits when an Included file cannot be
# opened: SSH lockout. getfattr/setfattr are stubbed over a per-path label
# store, so the label write_masks leaves is observable root-free.
_XA="$(mktemp -d)"
_xa_key() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
getfattr() {
    local p="${*: -1}" k
    k="$(_xa_key "${p}")"
    [[ -f "${_XA}/${k}" ]] || return 1
    cat "${_XA}/${k}"
}
setfattr() {
    local v="" p="${*: -1}"
    while [[ $# -gt 1 ]]; do [[ "$1" == -v ]] && v="$2"; shift; done
    [[ -z "${SETFATTR_FAIL:-}" ]] || return 1
    printf '%s' "${v}" > "${_XA}/$(_xa_key "${p}")"
    echo "${p}" >> "${_XA}/setfattr.log"
}
_xa_set() { printf '%s' "$2" > "${_XA}/$(_xa_key "$1")"; }
_xa_get() { getfattr --absolute-names -h -n security.selinux --only-values "$1" 2>/dev/null || true; }
_SEL_WARN="$(mktemp)"
hippius_log() { echo "$*" >> "${_SEL_WARN}"; }
_sel_root() {
    local r
    r="$(mktemp -d -p "${_XA}")"
    mkdir -p "${r}/etc/ssh/sshd_config.d" "${r}/etc/cloud" "${r}/etc/systemd/system" "${r}/etc/systemd/system-generators"
    echo "${r}"
}
_sel_fail=0
# a) labeled sshd_config: the drop-in gets etc_t, and is kept.
_R="$(_sel_root)"; : > "${_R}/etc/ssh/sshd_config"
_xa_set "${_R}/etc/ssh/sshd_config" "system_u:object_r:etc_t:s0"
_xa_set "${_R}/etc/ssh/sshd_config.d" "system_u:object_r:etc_t:s0"
hippius_golden_write_masks "${_R}" || { err "selinux a: write_masks failed"; _sel_fail=1; }
_f="${_R}/etc/ssh/sshd_config.d/00-hippius-harden.conf"
[[ -f "${_f}" && "$(_xa_get "${_f}")" == "system_u:object_r:etc_t:s0" ]] \
    || { err "selinux a: drop-in not labeled etc_t like sshd_config (got '$(_xa_get "${_f}")')"; _sel_fail=1; }
grep -qxF "${_f}" "${_XA}/setfattr.log" 2>/dev/null \
    || { err "selinux a: setfattr never called on the drop-in"; _sel_fail=1; }
# b) no sshd_config: the drop-in takes its directory's label.
_R="$(_sel_root)"
_xa_set "${_R}/etc/ssh/sshd_config.d" "system_u:object_r:sshd_config_dir_t:s0"
hippius_golden_write_masks "${_R}" || { err "selinux b: write_masks failed"; _sel_fail=1; }
_f="${_R}/etc/ssh/sshd_config.d/00-hippius-harden.conf"
[[ -f "${_f}" && "$(_xa_get "${_f}")" == "system_u:object_r:sshd_config_dir_t:s0" ]] \
    || { err "selinux b: drop-in did not fall back to the directory label (got '$(_xa_get "${_f}")')"; _sel_fail=1; }
# c) the label does not take: no unlabeled drop-in is left, the boot goes on.
_R="$(_sel_root)"; : > "${_R}/etc/ssh/sshd_config"
_xa_set "${_R}/etc/ssh/sshd_config" "system_u:object_r:etc_t:s0"
: > "${_SEL_WARN}"
SETFATTR_FAIL=1 hippius_golden_write_masks "${_R}" || { err "selinux c: a failed label failed the boot"; _sel_fail=1; }
[[ ! -e "${_R}/etc/ssh/sshd_config.d/00-hippius-harden.conf" ]] \
    || { err "selinux c: an UNLABELED sshd drop-in was left (sshd would not start: SSH lockout)"; _sel_fail=1; }
grep -q 'WARN sshd drop-in not labeled' "${_SEL_WARN}" \
    || { err "selinux c: no WARN logged for the removed drop-in"; _sel_fail=1; }
# d) non-SELinux base (no labels anywhere): the drop-in is kept as is.
_R="$(_sel_root)"; : > "${_R}/etc/ssh/sshd_config"
hippius_golden_write_masks "${_R}" || { err "selinux d: write_masks failed"; _sel_fail=1; }
[[ -f "${_R}/etc/ssh/sshd_config.d/00-hippius-harden.conf" ]] \
    || { err "selinux d: drop-in missing on a non-SELinux base"; _sel_fail=1; }
[[ "${_sel_fail}" -eq 0 ]] && ok "sshd drop-in SELinux label: etc_t from sshd_config, directory fallback, removed (not left unlabeled) when the label fails, untouched on non-SELinux"
unset -f getfattr setfattr
hippius_log() { :; }
rm -rf "${_XA}" "${_SEL_WARN}"

# ── 4b. Size anchor: a miner-attached upper shorter than disk_gb ────
# The per-VM upper (/dev/vda) MUST be at least the MEASURED
# `hippius.disk_gb`: a miner that attaches a truncated sparse file would
# otherwise get a VM whose filesystem runs past the end of its device
# (EIO later, data loss). `hippius_golden_open_upper` refuses BEFORE any
# cryptsetup call — no format, no open. `blockdev` / `cryptsetup` are
# stubbed: the device is never read, only `[ -b ]` needs a real block
# node, so any one on the runner will do.
_SA_DEV="$(find /dev -maxdepth 1 -type b 2>/dev/null | head -1)"
if [[ -z "${_SA_DEV}" ]]; then
    echo "golden-overlay-test: SKIP — size anchor (no block device node on this host)"
else
    _SA_KEK="$(mktemp)"; head -c 32 /dev/zero > "${_SA_KEK}"
    _SA_LOG="$(mktemp)"
    # $1 = blockdev size (bytes); prints what the function did.
    _sa_run() (
        hippius_die() { echo "die: $*" >>"${_SA_LOG}"; exit 1; }
        cryptsetup() { echo "cryptsetup $1" >>"${_SA_LOG}"; return 1; }
        hippius_golden_format_upper() { echo "format" >>"${_SA_LOG}"; }
        HIPPIUS_GOLDEN_UPPER="${_SA_DEV}"
        HIPPIUS_GOLDEN_DISK_GB=40
        HIPPIUS_GOLDEN_KEY_MODE=""
        _sa_size="$1"
        blockdev() { echo "${_sa_size}"; }
        hippius_golden_open_upper "${_SA_KEK}"
    )
    _want=$(( 40 * 1073741824 ))
    : >"${_SA_LOG}"
    if _sa_run "$(( _want - 4096 ))" 2>/dev/null; then
        err "size anchor: a 4 KiB-short upper was ACCEPTED (fail-open)"
    elif grep -q 'die: golden: upper too small' "${_SA_LOG}" && ! grep -q '^cryptsetup\|^format' "${_SA_LOG}"; then
        ok "size anchor: an upper shorter than hippius.disk_gb is refused before any cryptsetup call"
    else
        err "size anchor: short upper not refused cleanly: $(tr '\n' ';' <"${_SA_LOG}")"
    fi
    : >"${_SA_LOG}"
    if _sa_run "${_want}" 2>/dev/null && grep -q '^format' "${_SA_LOG}"; then
        ok "size anchor: an upper of exactly hippius.disk_gb proceeds (first-boot format)"
    else
        err "size anchor: a full-size upper did not proceed: $(tr '\n' ';' <"${_SA_LOG}")"
    fi
    rm -f "${_SA_KEK}" "${_SA_LOG}"
fi

# ── 5. Driver ordering + KEK shred (golden-bake PR5) ────────────────
# Drive `hippius_golden_run` with STUBBED collaborators that record call
# order + a fake tmpfs KEK, no live boot/devices. Pins two PR5 invariants:
#   (a) the PUBLIC golden lower is opened/verity-verified BEFORE any
#       network / KBS KEK release (validate-before-mutate);
#   (b) the per-VM KEK keyfile is ALWAYS shredded — on success AND on a
#       mid-path hippius_die inside assembly (§20 secret hygiene).
# Section 5 exercises the DRIVER, where hippius_die must model the real
# init's `exit 1` (not the `return 1` the pure-function sections above
# want) — otherwise a mid-path die would fall through to the trailing
# hippius_log and wrongly report success.
hippius_die() { echo "hippius_die: $*" >&2; exit 1; }

ORDER_LOG="$(mktemp)"
KEK_PATH="$(mktemp)"; rm -f "${KEK_PATH}"

# Collaborator stubs (override the real ones the lib just defined).
hippius_parse_cmdline()        { echo parse        >>"${ORDER_LOG}"; }
hippius_golden_modprobe()      { echo modprobe     >>"${ORDER_LOG}"; }
hippius_golden_resolve()       { echo resolve      >>"${ORDER_LOG}"; }
hippius_golden_open_lower()    { echo open_lower   >>"${ORDER_LOG}"; }
# Customer-held keys: the M0 outcome of the real prepare (no key mode).
hippius_golden_keymode_prepare() {
    echo keymode_prepare >>"${ORDER_LOG}"
    HIPPIUS_GOLDEN_KEY_MODE="${STUB_KEY_MODE:-}"
    HIPPIUS_GOLDEN_SHARE_C_VERSION="${STUB_SHARE_C_VERSION:-}"
}
FLAGS_SEEN="$(mktemp)"
hippius_acquire()              { echo acquire      >>"${ORDER_LOG}"; printf '%s|%s' "${HIPPIUS_EXTRA_RELEASE_FLAGS}" "${HIPPIUS_GUARDIAN_FIRST:-}" >"${FLAGS_SEEN}"; printf 'k' >"$1"; }
hippius_golden_open_upper()    { echo open_upper   >>"${ORDER_LOG}"; }
hippius_golden_mount_overlay() { echo mount_overlay >>"${ORDER_LOG}"; }
# H5b: the seed is built once the overlay is up, before harden_root (real
# one tested in golden-userdata-test.sh).
hippius_golden_install_seed()  { echo install_seed >>"${ORDER_LOG}"; }
hippius_golden_harden_root()   { echo harden_root  >>"${ORDER_LOG}"; }
# Pin the KEK path so the test can assert it is shredded.
mktemp() {
    case "$*" in
        *hippius-gold-kek*) printf '%s' "${KEK_PATH}"; : >"${KEK_PATH}" ;;
        *) command mktemp "$@" ;;
    esac
}

# 5a. Success path: order + shred.
: >"${ORDER_LOG}"
hippius_golden_run "/fake/rootmnt"
lower_ln="$(grep -n '^open_lower$' "${ORDER_LOG}" | head -1 | cut -d: -f1)"
acq_ln="$(grep -n '^acquire$'    "${ORDER_LOG}" | head -1 | cut -d: -f1)"
if [[ -n "${lower_ln}" && -n "${acq_ln}" && "${lower_ln}" -lt "${acq_ln}" ]]; then
    ok "golden lower verified BEFORE network KBS release (validate-before-mutate)"
else
    err "verity-before-network order violated (open_lower=${lower_ln} acquire=${acq_ln})"
fi
[[ ! -e "${KEK_PATH}" ]] && ok "KEK shredded on the success path" || err "KEK survived the success path"
# The M0 guard runs AFTER the overlay is mounted (writes land in the upper).
mnt_ln="$(grep -n '^mount_overlay$' "${ORDER_LOG}" | head -1 | cut -d: -f1)"
hrd_ln="$(grep -n '^harden_root$'   "${ORDER_LOG}" | head -1 | cut -d: -f1)"
if [[ -n "${mnt_ln}" && -n "${hrd_ln}" && "${mnt_ln}" -lt "${hrd_ln}" ]]; then
    ok "M0 harden_root runs AFTER the overlay mount (writes land in the upper)"
else
    err "harden_root order violated (mount_overlay=${mnt_ln} harden_root=${hrd_ln})"
fi
kp_ln="$(grep -n '^keymode_prepare$' "${ORDER_LOG}" | head -1 | cut -d: -f1)"
if [[ -n "${kp_ln}" && "${lower_ln}" -lt "${kp_ln}" && "${kp_ln}" -lt "${acq_ln}" ]]; then
    ok "customer-keys token check runs after the verity lower and BEFORE any KBS/guardian contact"
else
    err "keymode_prepare order (open_lower=${lower_ln} keymode_prepare=${kp_ln} acquire=${acq_ln})"
fi
# H5b: the seed after the upper is open and the overlay mounted, and
# BEFORE harden_root, so harden_root's masks and cloud-init pin win over
# anything seeded.
[[ "$(tail -4 "${ORDER_LOG}" | tr '\n' ' ')" == "open_upper mount_overlay install_seed harden_root " ]] \
    && ok "H5b: the cloud-init seed is installed after open_upper + mount_overlay and before harden_root" \
    || err "install_seed order: $(tr '\n' ' ' < "${ORDER_LOG}")"
sd_ln="$(grep -n '^install_seed$' "${ORDER_LOG}" | head -1 | cut -d: -f1)"
[[ -n "${sd_ln}" && -n "${hrd_ln}" && "${sd_ln}" -lt "${hrd_ln}" ]] \
    && ok "H5b: install_seed < harden_root" \
    || err "install_seed/harden_root order (install_seed=${sd_ln} harden_root=${hrd_ln})"
# Stamp protocol v2: every golden release asks for the timeline
# transition file (absent after a v1 release, so the v1 gate runs).
M0_FLAGS="--volume-stamp-expected-out ${HIPPIUS_GOLDEN_STAMP_EXPECTED} --volume-stamp-ctx-out ${HIPPIUS_GOLDEN_STAMP_CTX} --volume-stamp-transition-out ${HIPPIUS_GOLDEN_STAMP_TRANSITION}"
[[ "$(cat "${FLAGS_SEEN}")" == "${M0_FLAGS}|" ]] \
    && ok "M0: the release command line carries the stamp outputs and no customer-keys flag" \
    || err "M0 release flags changed: '$(cat "${FLAGS_SEEN}")'"

# 5a'. M1/M2: the share-version flags ride the same release call.
: >"${ORDER_LOG}"
( STUB_KEY_MODE=split STUB_SHARE_C_VERSION=4 hippius_golden_run "/fake/rootmnt" )
[[ "$(cat "${FLAGS_SEEN}")" == "${M0_FLAGS} --share-c-version-out ${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT} --share-c-version 4 --instance-id-out ${HIPPIUS_GOLDEN_IID_OUT}|1" ]] \
    && ok "keyed: --share-c-version-out and the token's --share-c-version are passed; no KBS preflight" \
    || err "keyed release flags: '$(cat "${FLAGS_SEEN}")'"
: >"${ORDER_LOG}"
( STUB_KEY_MODE=customer hippius_golden_run "/fake/rootmnt" )
[[ "$(cat "${FLAGS_SEEN}")" == "${M0_FLAGS} --share-c-version-out ${HIPPIUS_GOLDEN_SHARE_C_VERSION_OUT} --instance-id-out ${HIPPIUS_GOLDEN_IID_OUT}|1" ]] \
    && ok "keyed first boot: no --share-c-version" \
    || err "keyed first-boot release flags: '$(cat "${FLAGS_SEEN}")'"

# 5b. Mid-path failure (open_upper dies AFTER the KEK is released) still
# shreds the KEK and fails the boot closed.
hippius_golden_open_upper() { echo open_upper >>"${ORDER_LOG}"; hippius_die "simulated mid-path failure"; }
: >"${ORDER_LOG}"
if ( hippius_golden_run "/fake/rootmnt" ) 2>/dev/null; then
    err "mid-path failure did NOT fail the golden boot closed (fail-open!)"
else
    ok "mid-path failure fails the golden boot closed"
fi
! grep -q '^install_seed$' "${ORDER_LOG}" \
    && ok "H5b: a failed boot never reaches the seed install" \
    || err "install_seed ran on a failed boot"
[[ ! -e "${KEK_PATH}" ]] && ok "KEK shredded even on a mid-path failure (§20)" || err "KEK survived a mid-path failure — secret-hygiene breach"

rm -f "${ORDER_LOG}" "${KEK_PATH}" "${FLAGS_SEEN}"

if [[ "${fail}" -ne 0 ]]; then
    echo "golden-overlay-test: FAILED" >&2
    exit 1
fi
echo "golden-overlay-test: OK (all checks passed)"
