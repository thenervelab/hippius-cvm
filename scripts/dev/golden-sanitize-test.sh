#!/usr/bin/env bash
# Unit test for `golden_sanitize_base()` (golden-bake PR4) — the
# per-instance identity + secret scrub that runs on the SHARED golden
# dm-verity base before it is packaged as the squashfs lower.
#
# Root-free: it EXTRACTS just the `golden_sanitize_base` function body
# from scripts/tenant-image-bake.sh and drives it against a fake root
# tree in a tempdir the test user owns, with `sudo` stubbed to a
# passthrough (no privilege needed on a self-owned tree). It pins the
# make-or-break proof-B invariant: NOTHING per-instance/secret survives
# on the shared base (ssh host keys, machine-id, cloud-init state, logs)
# and swap on the shared bytes fails the bake closed.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BAKE="${HERE}/../tenant-image-bake.sh"
[[ -r "${BAKE}" ]] || { echo "golden-sanitize-test: bake script not found at ${BAKE}" >&2; exit 1; }

# Extract ONLY the `golden_sanitize_base() { ... }` function. Its body
# uses if/fi (no bare `{`/`}` blocks), so the sole line beginning with
# `}` at column 0 is the function's closing brace.
FUNC_SRC="$(awk '/^golden_sanitize_base\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "${BAKE}")"
[[ -n "${FUNC_SRC}" ]] || { echo "golden-sanitize-test: could not extract golden_sanitize_base" >&2; exit 1; }

# Stubs. `sudo` runs the command verbatim (the fake root is user-owned);
# `log` is quiet; `die` exits non-zero so a swap assertion is catchable
# in a subshell.
sudo() { "$@"; }
log()  { :; }
die()  { echo "DIE: $*" >&2; exit 3; }
# shellcheck disable=SC1090
eval "${FUNC_SRC}"

fail=0
ok()  { echo "golden-sanitize-test: OK — $*"; }
err() { echo "golden-sanitize-test: FAIL — $*" >&2; fail=1; }

# Build a fake customised root carrying exactly the per-instance state a
# real chroot customise would leave behind.
make_root() {
    local r
    r="$(mktemp -d)"
    mkdir -p "${r}/etc/ssh" "${r}/var/lib/dbus" "${r}/var/lib/cloud/instances/iid-abc" "${r}/var/log/apt" "${r}/etc" "${r}/var/lib/systemd"
    mkdir -p "${r}/etc/systemd/system" "${r}/lib/systemd/system" "${r}/usr/lib/systemd/system"
    mkdir -p "${r}/var/lib/dhcp" "${r}/var/lib/NetworkManager"
    printf 'PRIVATEKEY\n' > "${r}/etc/ssh/ssh_host_ed25519_key"
    printf 'PUBKEY\n'     > "${r}/etc/ssh/ssh_host_ed25519_key.pub"
    printf 'RSAKEY\n'     > "${r}/etc/ssh/ssh_host_rsa_key"
    printf 'sshd_config\n' > "${r}/etc/ssh/sshd_config"           # must SURVIVE
    printf 'deadbeefdeadbeefdeadbeefdeadbeef\n' > "${r}/etc/machine-id"
    printf 'deadbeefdeadbeefdeadbeefdeadbeef\n' > "${r}/var/lib/dbus/machine-id"
    printf 'baked-instance-state\n' > "${r}/var/lib/cloud/instances/iid-abc/user-data.txt"
    printf 'BUILD LOG LINE\n' > "${r}/var/log/apt/history.log"
    printf 'SHARED-SEED\n'     > "${r}/var/lib/systemd/random-seed"    # cross-tenant CSPRNG seed — must be REMOVED
    printf 'SHARED-CRED\n'     > "${r}/var/lib/systemd/credential.secret"  # must be REMOVED
    printf 'lease {\n}\n'      > "${r}/var/lib/dhcp/dhclient.leases"   # stale lease — must be CLEARED
    printf 'ts\n'             > "${r}/var/lib/NetworkManager/timestamps"  # runtime state — must be CLEARED
    # Package-manager indexes and caches (reproducibility).
    mkdir -p "${r}/var/lib/apt/lists/partial" "${r}/var/cache/apt/archives" "${r}/var/cache/ldconfig" \
        "${r}/var/cache/dnf/fedora-1234" "${r}/var/cache/libdnf5/updates-5678"
    printf 'Date: x\n' > "${r}/var/lib/apt/lists/deb.example_dists_trixie-updates_InRelease"
    printf 'pkgs\n'   > "${r}/var/lib/apt/lists/deb.example_dists_trixie_main_binary-amd64_Packages"
    : > "${r}/var/lib/apt/lists/lock"
    printf 'half\n'   > "${r}/var/lib/apt/lists/partial/x"
    mkdir -p "${r}/var/lib/apt/lists/auxfiles"
    printf 'aux\n'    > "${r}/var/lib/apt/lists/auxfiles/x"
    printf 'bin\n'    > "${r}/var/cache/apt/pkgcache.bin"
    printf 'bin\n'    > "${r}/var/cache/apt/srcpkgcache.bin"
    printf 'aux\n'    > "${r}/var/cache/ldconfig/aux-cache"
    printf 'db\n'     > "${r}/var/lib/apt/listchanges"
    printf 'db\n'     > "${r}/var/lib/apt/listchanges-old"
    printf 'md\n'     > "${r}/var/cache/dnf/fedora-1234/repomd.xml"
    printf 'md\n'     > "${r}/var/cache/libdnf5/updates-5678/repomd.xml"
    mkdir -p "${r}/var/cache/swcatalog/cache" "${r}/var/lib/command-not-found"
    printf 'xb\n'     > "${r}/var/cache/swcatalog/cache/C-os-catalog.xb"
    printf 'db\n'     > "${r}/var/lib/command-not-found/commands.db"
    printf 'md\n'     > "${r}/var/lib/command-not-found/commands.db.metadata"
    mkdir -p "${r}/var/lib/dnf/repos/baseos-1" "${r}/usr/lib/sysimage/libdnf5" "${r}/etc/dnf/plugins" "${r}/var/lib/rpm"
    printf 'h\n' > "${r}/var/lib/dnf/history.sqlite"
    printf 'h\n' > "${r}/var/lib/dnf/history.sqlite-wal"
    printf 'h\n' > "${r}/usr/lib/sysimage/libdnf5/transaction_history.sqlite"
    printf 'h\n' > "${r}/usr/lib/sysimage/libdnf5/transaction_history.sqlite-shm"
    printf 'p\n' > "${r}/usr/lib/sysimage/libdnf5/packages.toml"          # must SURVIVE
    printf 'w\n' > "${r}/var/lib/dnf/repos/baseos-1/countme"
    printf 'rpm\n' > "${r}/var/lib/rpm/rpmdb.sqlite"                     # must SURVIVE
    printf '# Added lock on Wed Oct  7 2026\nkernel-0:6.12-1.*\n' > "${r}/etc/dnf/plugins/versionlock.list"
    printf 'version = "1.0"\n[[packages]]\nname = "kernel"\ncomment = "Added on 2026-10-07 16:41:33"\n' \
        > "${r}/etc/dnf/versionlock.toml"
    printf 'ld\n'     > "${r}/etc/ld.so.cache"                           # must SURVIVE
    # A golden fstab is written EMPTY upstream — mirror that (no swap).
    printf '# hippius-bake-managed (golden_verity_overlay): empty\n' > "${r}/etc/fstab"
    printf '%s' "${r}"
}

# ── 1. Happy path: full scrub, keeper files preserved ───────────────
ROOT="$(make_root)"
golden_sanitize_base "${ROOT}"

# SSH host keys gone; sshd_config kept.
if compgen -G "${ROOT}/etc/ssh/ssh_host_*" >/dev/null; then
    err "ssh host keys survived the scrub"
else
    ok "ssh host keys deleted"
fi
[[ -f "${ROOT}/etc/ssh/sshd_config" ]] || err "sshd_config wrongly deleted"

# machine-id truncated to empty (present, size 0).
if [[ -f "${ROOT}/etc/machine-id" && ! -s "${ROOT}/etc/machine-id" ]]; then
    ok "machine-id emptied (present, 0 bytes)"
else
    err "machine-id not emptied"
fi
# dbus regular-file machine-id removed.
[[ -e "${ROOT}/var/lib/dbus/machine-id" ]] && err "dbus machine-id copy survived" || ok "dbus machine-id removed"

# cloud-init instance state cleared (dir exists, empty).
if [[ -d "${ROOT}/var/lib/cloud" ]] && [[ -z "$(ls -A "${ROOT}/var/lib/cloud")" ]]; then
    ok "/var/lib/cloud emptied"
else
    err "/var/lib/cloud not emptied"
fi

# Logs truncated (file present, 0 bytes).
if [[ -f "${ROOT}/var/log/apt/history.log" && ! -s "${ROOT}/var/log/apt/history.log" ]]; then
    ok "build logs truncated"
else
    err "build logs not truncated"
fi

# systemd CSPRNG seed + credential secret removed (the make-or-break
# cross-tenant crypto invariant — a shared seed correlates in-guest
# entropy before the overlay luksFormat MK is generated).
[[ -e "${ROOT}/var/lib/systemd/random-seed" ]] && err "systemd random-seed survived the scrub" || ok "systemd random-seed removed"
[[ -e "${ROOT}/var/lib/systemd/credential.secret" ]] && err "systemd credential.secret survived the scrub" || ok "systemd credential.secret removed"

# DHCP + NetworkManager runtime state cleared (dir present, empty).
if [[ -d "${ROOT}/var/lib/dhcp" && -z "$(ls -A "${ROOT}/var/lib/dhcp")" ]]; then
    ok "/var/lib/dhcp emptied"
else
    err "/var/lib/dhcp not emptied"
fi
if [[ -d "${ROOT}/var/lib/NetworkManager" && -z "$(ls -A "${ROOT}/var/lib/NetworkManager")" ]]; then
    ok "/var/lib/NetworkManager emptied"
else
    err "/var/lib/NetworkManager not emptied"
fi
# Package indexes and caches gone; apt's lock and partial/ dirs kept
# empty; the real loader cache stays.
left="$(cd "${ROOT}/var/lib/apt/lists" && find . -mindepth 1 | LC_ALL=C sort | tr '\n' ' ')"
if [[ "${left}" == "./lock ./partial " ]]; then
    ok "apt lists emptied (lock + partial/ kept)"
else
    err "apt lists not emptied (left: ${left})"
fi
for f in var/cache/apt/pkgcache.bin var/cache/apt/srcpkgcache.bin var/cache/ldconfig/aux-cache \
         var/lib/apt/listchanges var/lib/apt/listchanges-old; do
    [[ -e "${ROOT}/${f}" ]] && err "${f} survived the scrub" || ok "${f} removed"
done
for f in var/lib/command-not-found/commands.db var/lib/command-not-found/commands.db.metadata; do
    [[ -e "${ROOT}/${f}" ]] && err "${f} survived the scrub" || ok "${f} removed"
done
for d in var/cache/dnf var/cache/libdnf5 var/cache/swcatalog; do
    if [[ -d "${ROOT}/${d}" && -z "$(ls -A "${ROOT}/${d}")" ]]; then
        ok "${d} emptied"
    else
        err "${d} not emptied"
    fi
done
[[ -d "${ROOT}/var/cache/apt/archives" ]] || err "/var/cache/apt/archives wrongly removed"
[[ -f "${ROOT}/etc/ld.so.cache" ]] || err "ld.so.cache wrongly removed"
for f in var/lib/dnf/history.sqlite var/lib/dnf/history.sqlite-wal \
         usr/lib/sysimage/libdnf5/transaction_history.sqlite \
         usr/lib/sysimage/libdnf5/transaction_history.sqlite-shm var/lib/dnf/repos/baseos-1/countme; do
    [[ -e "${ROOT}/${f}" ]] && err "${f} survived the scrub" || ok "${f} removed"
done
[[ -f "${ROOT}/usr/lib/sysimage/libdnf5/packages.toml" && -f "${ROOT}/var/lib/rpm/rpmdb.sqlite" ]] \
    || err "the package state or rpm database was wrongly removed"
if [[ "$(cat "${ROOT}/etc/dnf/plugins/versionlock.list")" == "kernel-0:6.12-1.*" ]]; then
    ok "versionlock.list keeps the lock, drops the dated comment"
else
    err "versionlock.list not normalised"
fi
if grep -q comment "${ROOT}/etc/dnf/versionlock.toml" || ! grep -q 'name = "kernel"' "${ROOT}/etc/dnf/versionlock.toml"; then
    err "versionlock.toml not normalised"
else
    ok "versionlock.toml keeps the lock, drops the dated comment"
fi
rm -rf "${ROOT}"

# ── 2. Swap fstab entry → bake fails closed ─────────────────────────
ROOT="$(make_root)"
printf '/swapfile none swap sw 0 0\n' >> "${ROOT}/etc/fstab"
if ( golden_sanitize_base "${ROOT}" ) 2>/dev/null; then
    err "swap fstab entry did NOT fail the bake (fail-open!)"
else
    ok "swap fstab entry fails the bake closed"
fi
rm -rf "${ROOT}"

# ── 3. On-disk swapfile → bake fails closed ─────────────────────────
ROOT="$(make_root)"
printf 'zeros\n' > "${ROOT}/swapfile"
if ( golden_sanitize_base "${ROOT}" ) 2>/dev/null; then
    err "on-disk swapfile did NOT fail the bake (fail-open!)"
else
    ok "on-disk swapfile fails the bake closed"
fi
rm -rf "${ROOT}"

# ── 4. Differently-named systemd .swap unit → bake fails closed ─────
# The name-based (5) + fstab (5) scans miss this; the .swap-unit scan
# (5b) must catch it.
ROOT="$(make_root)"
printf '[Swap]\nWhat=/dev/vdz\n' > "${ROOT}/etc/systemd/system/data-swap.swap"
if ( golden_sanitize_base "${ROOT}" ) 2>/dev/null; then
    err "systemd .swap unit did NOT fail the bake (fail-open!)"
else
    ok "systemd .swap unit fails the bake closed"
fi
rm -rf "${ROOT}"

# ── 5. Enabled swap .wants symlink → bake fails closed ──────────────
# An enabled swap unit is a *.wants/*.swap symlink (even if dangling /
# the unit file lives elsewhere).
ROOT="$(make_root)"
mkdir -p "${ROOT}/etc/systemd/system/swap.target.wants"
ln -s /dev/null "${ROOT}/etc/systemd/system/swap.target.wants/zram0.swap"
if ( golden_sanitize_base "${ROOT}" ) 2>/dev/null; then
    err "enabled swap .wants symlink did NOT fail the bake (fail-open!)"
else
    ok "enabled swap .wants symlink fails the bake closed"
fi
rm -rf "${ROOT}"

# ── 6. #365 data-disk provisioner on the golden base → fails closed ─
# (#1350) A golden VM has no data disk: the unit could only act on a
# miner-attached /dev/vde. The unit file, its enablement symlink alone
# (dangling), or the init script alone each fail the bake.
for what in unit wants script; do
    ROOT="$(make_root)"
    case "${what}" in
        unit)   printf '[Service]\n' > "${ROOT}/etc/systemd/system/hippius-data-disk.service" ;;
        wants)  mkdir -p "${ROOT}/etc/systemd/system/multi-user.target.wants"
                ln -s ../hippius-data-disk.service "${ROOT}/etc/systemd/system/multi-user.target.wants/hippius-data-disk.service" ;;
        script) mkdir -p "${ROOT}/usr/local/sbin"; printf '#!/bin/bash\n' > "${ROOT}/usr/local/sbin/hippius-data-disk-init" ;;
    esac
    if ( golden_sanitize_base "${ROOT}" ) 2>/dev/null; then
        err "a data-disk ${what} on the golden base did NOT fail the bake (fail-open!)"
    else
        ok "a data-disk ${what} on the golden base fails the bake closed"
    fi
    rm -rf "${ROOT}"
done

# The bake itself must skip the section for goldens: the whole #365 block
# sits inside the not-golden guard.
block="$(awk '/^# ── #365 tenant data disk first-boot provisioner/{f=1} /^# ── 4b\. Run the chroot apt install/{f=0} f' "${BAKE}")"
first="$(grep -v -e '^#' -e '^$' <<< "${block}" | head -1)"
last="$(grep -v '^$' <<< "${block}" | tail -1)"
if [[ "${first}" == 'if [[ "${disk_mode}" != "golden_verity_overlay" ]]; then' && "${last}" == fi ]] \
    && grep -q 'hippius-data-disk.service' <<< "${block}"; then
    ok "the bake installs the #365 provisioner only outside golden mode"
else
    err "the #365 provisioner is not wrapped in the not-golden guard (first='${first}' last='${last}')"
fi

if [[ "${fail}" -ne 0 ]]; then
    echo "golden-sanitize-test: FAILED" >&2
    exit 1
fi
echo "golden-sanitize-test: all checks passed"
