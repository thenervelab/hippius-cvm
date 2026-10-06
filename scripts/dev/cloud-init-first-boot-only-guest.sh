#!/usr/bin/env bash
#
# Runs INSIDE a throwaway container (see cloud-init-first-boot-only-check.sh),
# as root, against the distro's REAL cloud-init: five simulated boots, each
# running the four cloud-init stages in order against the NoCloud seed the
# golden initramfs leaves on /run/cloud-init/seed/, with the bake's own
# NoCloud + ssh-hostkey config.
#
# It pins what H5b (customer-held keys, user-data on first boot only)
# relies on:
#   boot 1  M1/M2 first boot: stable iid + the tenant's user-data
#           ⇒ everything applies (user + ssh key, bootcmd, runcmd,
#             write_files).
#   boot 2  M1/M2 later boot: SAME iid + EMPTY user-data
#           ⇒ nothing from this boot's user-data runs; the tenant user, its
#             authorized_keys and the ssh host key are untouched; one
#             instance dir; cloud-init reports no error.
#   boot 3  control: SAME iid + user-data Hippius could mint
#           ⇒ its bootcmd and boothook DO run (per-boot), its runcmd /
#             users / keys / write_files do not (per-instance). This is
#             why the later-boot user-data must be empty, not merely
#             "same instance"; it also proves this harness sees a
#             per-boot execution when there is one.
#   boot 4  M1/M2 later boot again ⇒ nothing, as boot 2.
#   boot 5  M0 control: a NEW random iid + the tenant user-data
#           ⇒ per-instance modules run again (runcmd re-runs), which is
#             M0's every-boot semantics, unchanged by H5b.
#   boot 6/7 the first-boot residual (plan decision D1): a first-boot
#           user-data carrying a `text/x-shellscript-per-boot` part
#           installs it under /var/lib/cloud/scripts/per-boot, and it
#           runs on every LATER boot even though that boot's user-data
#           is empty. Whoever writes the first-boot user-data can leave
#           code that outlives it; H5b only stops NEW later-boot content.
#
# Exit 0 = every assertion held.
set -u
export LC_ALL=C

fail=0
ok()  { echo "cloud-init-first-boot-only: OK — $*"; }
err() { echo "cloud-init-first-boot-only: FAIL — $*" >&2; fail=1; }

if ! command -v cloud-init >/dev/null 2>&1; then
    echo "cloud-init-first-boot-only: installing cloud-init" >&2
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null \
            && apt-get install -y -qq --no-install-recommends cloud-init openssh-server sudo >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q cloud-init openssh-server sudo >/dev/null 2>&1
    fi
fi
command -v cloud-init >/dev/null 2>&1 || { echo "cloud-init-first-boot-only: cannot install cloud-init" >&2; exit 2; }
echo "cloud-init-first-boot-only: $(cloud-init --version 2>&1)"

SEED=/run/cloud-init/seed
mkdir -p /etc/cloud/cloud.cfg.d
# The bake's pins (scripts/tenant-image-bake.sh, 99-hippius-*.cfg).
cat > /etc/cloud/cloud.cfg.d/99-hippius-nocloud.cfg <<'EOF'
datasource_list: [ NoCloud, None ]
datasource:
  NoCloud:
    fs_label: null
    seedfrom: /run/cloud-init/seed/
EOF
echo 'ssh_deletekeys: false' > /etc/cloud/cloud.cfg.d/99-hippius-ssh-hostkeys.cfg

IID="iid-3a693f9c2cd7229cb0d0ee2256270777"
TENANT_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH5bTENANTTENANTTENANTTENANTTENANTTENANT tenant"
EVIL_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH5bEVILEVILEVILEVILEVILEVILEVILEVILEVIL evil"
TENANT_UD="#cloud-config
users:
  - name: tenant
    ssh_authorized_keys: [ \"${TENANT_KEY}\" ]
bootcmd:
  - [ touch, /tmp/mark-tenant-bootcmd ]
runcmd:
  - [ touch, /tmp/mark-tenant-runcmd ]
write_files:
  - path: /tmp/mark-tenant-write-files
    content: x
"
EVIL_UD="Content-Type: multipart/mixed; boundary=\"H5B\"
MIME-Version: 1.0

--H5B
Content-Type: text/cloud-boothook

#!/bin/sh
touch /tmp/mark-evil-boothook
--H5B
Content-Type: text/cloud-config

users:
  - name: evil
    ssh_authorized_keys: [ \"${EVIL_KEY}\" ]
ssh_authorized_keys: [ \"${EVIL_KEY}\" ]
bootcmd:
  - [ touch, /tmp/mark-evil-bootcmd ]
runcmd:
  - [ touch, /tmp/mark-evil-runcmd ]
write_files:
  - path: /tmp/mark-evil-write-files
    content: x
--H5B--
"

# $1 instance-id, $2 user-data. /run is tmpfs in the guest: cloud-init's
# run state starts empty every boot, and the initramfs writes the seed.
boot() {
    find /run/cloud-init -mindepth 1 -delete 2>/dev/null
    find /tmp -maxdepth 1 -name 'mark-*' -delete
    mkdir -p "${SEED}"
    printf 'instance-id: %s\n' "$1" > "${SEED}/meta-data"
    printf '%s' "$2" > "${SEED}/user-data"
    for stage in "init --local" "init" "modules --mode config" "modules --mode final"; do
        # shellcheck disable=SC2086 # the stage is two or three words
        cloud-init ${stage} >> /tmp/cloud-init-stages.log 2>&1 \
            || err "cloud-init ${stage} exited non-zero (iid $1)"
    done
    MARKS="$(find /tmp -maxdepth 1 -name 'mark-*' -printf '%f\n' | sort | tr '\n' ' ')"
    ERRORS="$(cloud-init status --long 2>/dev/null | sed -n 's/^errors:[[:space:]]*//p')"
}
keys() { cat /home/tenant/.ssh/authorized_keys 2>/dev/null; }
hostkey() { sha256sum /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null | cut -d' ' -f1; }
instances() { find /var/lib/cloud/instances -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | sort | tr '\n' ' '; }

# ── boot 1: first boot of an M1/M2 volume ────────────────────────────
boot "${IID}" "${TENANT_UD}"
[ "${MARKS}" = "mark-tenant-bootcmd mark-tenant-runcmd mark-tenant-write-files " ] \
    || err "boot 1 ran: '${MARKS}'"
[ "$(keys)" = "${TENANT_KEY}" ] || err "boot 1: tenant authorized_keys = '$(keys)'"
[ "${ERRORS}" = "[]" ] || err "boot 1: cloud-init errors: ${ERRORS}"
KEYS1="$(keys)"; HOST1="$(hostkey)"
[ -n "${HOST1}" ] || err "boot 1: no ssh host key generated"
ok "first boot (stable iid + tenant user-data): user, key, bootcmd, runcmd, write_files all applied"

# ── boot 2: later boot, same iid, empty user-data ───────────────────
later_boot() { # $1 label
    boot "${IID}" ""
    [ -z "${MARKS}" ] || err "$1: something ran: '${MARKS}'"
    [ "$(keys)" = "${KEYS1}" ] || err "$1: authorized_keys changed: '$(keys)'"
    [ "$(hostkey)" = "${HOST1}" ] || err "$1: ssh host key changed"
    getent passwd tenant >/dev/null || err "$1: tenant user gone"
    [ "$(instances)" = "${IID} " ] || err "$1: instance dirs '$(instances)'"
    [ "${ERRORS}" = "[]" ] || err "$1: cloud-init errors: ${ERRORS}"
    [ ! -s /var/lib/cloud/instance/user-data.txt ] || err "$1: cloud-init stored a non-empty user-data"
}
later_boot "boot 2"
ok "later boot (same iid + empty user-data): nothing runs; user, keys, host key kept; same instance; no error"

# ── boot 3: control — same iid, Hippius-minted user-data ─────────────
boot "${IID}" "${EVIL_UD}"
[ "${MARKS}" = "mark-evil-bootcmd mark-evil-boothook " ] \
    || err "control boot: expected exactly the per-boot boothook + bootcmd to run, got '${MARKS}'"
[ "$(keys)" = "${KEYS1}" ] || err "control boot: tenant authorized_keys changed"
! getent passwd evil >/dev/null || err "control boot: a per-instance module (users) ran"
ok "control (same iid + injected user-data): its boothook and bootcmd DO run as root every boot — the later-boot user-data must be empty"

# ── boot 4: later boot again ─────────────────────────────────────────
later_boot "boot 4"
ok "later boot again: nothing runs"

# ── boot 5: M0 semantics (new random iid every boot) ─────────────────
boot "iid-$(cat /proc/sys/kernel/random/uuid)" "${TENANT_UD}"
case "${MARKS}" in
    *mark-tenant-runcmd*) ok "M0 control (new iid + user-data): per-instance modules re-run, as today" ;;
    *) err "M0 control: runcmd did not re-run under a new instance-id: '${MARKS}'" ;;
esac

# ── boots 6/7: what the first boot can leave behind ──────────────────
IID2="iid-0f1e2d3c4b5a69788796a5b4c3d2e1f0"
PERBOOT_UD="Content-Type: multipart/mixed; boundary=\"H5B\"
MIME-Version: 1.0

--H5B
Content-Type: text/x-shellscript-per-boot

#!/bin/sh
touch /tmp/mark-firstboot-per-boot
--H5B--
"
boot "${IID2}" "${PERBOOT_UD}"
boot "${IID2}" ""
[ "${MARKS}" = "mark-firstboot-per-boot " ] \
    || err "first-boot residual: expected only the first boot's per-boot script on a later boot, got '${MARKS}'"
ok "first-boot residual: a per-boot script the FIRST boot's user-data installed still runs later (D1: the first boot stays exposed)"

if [ "${fail}" -ne 0 ]; then
    echo "---- cloud-init stage output (tail) ----" >&2
    tail -60 /tmp/cloud-init-stages.log >&2
    exit 1
fi
echo "cloud-init-first-boot-only: OK (all checks passed)"
