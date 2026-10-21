#!/usr/bin/env bash
# Tenant-launch preflight probe — run by miner-tasks/launch-preflight.yml
# (06-miner-bootstrap.yml play "09"). Prints `key=value` lines that
# filter_plugins/launch_preflight.py judges; it never fails itself.
#
# Read-only by default. `--write` adds the probes that create and then
# delete a scratch file (O_DIRECT, the agent sandbox), `--smoke` the
# paused, transient smoke domain. Everything they create is removed on
# exit, whatever happens.
#
# Usage:
#   launch-preflight-probe.sh --data-root DIR --state-root DIR \
#     --staging-root DIR --unit NAME --config FILE \
#     [--write] [--smoke] [--smoke-timeout SECONDS]
set -uo pipefail
# virsh and coreutils messages are matched below: never localised.
export LC_ALL=C

data_root=""
state_root=""
staging_root=""
unit=""
config=""
write=0
smoke=0
smoke_timeout=60

while [ "$#" -gt 0 ]; do
  case "$1" in
    --data-root) data_root=$2; shift 2 ;;
    --state-root) state_root=$2; shift 2 ;;
    --staging-root) staging_root=$2; shift 2 ;;
    --unit) unit=$2; shift 2 ;;
    --config) config=$2; shift 2 ;;
    --write) write=1; shift ;;
    --smoke) smoke=1; shift ;;
    --smoke-timeout) smoke_timeout=$2; shift 2 ;;
    *) echo "probe_error=unknown argument $1"; exit 0 ;;
  esac
done

kv() { printf '%s=%s\n' "$1" "$2"; }
# One line, bounded: the value ends up in an operator-facing message.
oneline() { tr '\n\t' '  ' | sed -E 's/ +/ /g; s/^ //; s/ $//' | cut -c1-400; }

# ── Cleanup: every scratch file, dir and the smoke domain ───────────
virsh_cmd=(virsh --connect qemu:///system)
scratch=()
smoke_name=""
smoke_started=0
# Destroy the smoke domain until libvirt no longer knows it. A `virsh
# create` that failed or timed out can still complete inside libvirtd,
# so then it is looked for again after a pause, not only once.
smoke_destroy() {
  local attempt
  for attempt in 1 2 3; do
    "${virsh_cmd[@]}" destroy "$smoke_name" >/dev/null 2>&1
    if ! "${virsh_cmd[@]}" domstate "$smoke_name" >/dev/null 2>&1; then
      [ "$smoke_started" = 1 ] || [ "$attempt" -ge 2 ] && return 0
    fi
    sleep 5
  done
  ! "${virsh_cmd[@]}" domstate "$smoke_name" >/dev/null 2>&1
}
cleanup() {
  if [ -n "$smoke_name" ]; then
    smoke_destroy
  fi
  if [ "${#scratch[@]}" -gt 0 ]; then
    rm -rf -- "${scratch[@]}"
  fi
}
trap cleanup EXIT

if ! command -v virsh >/dev/null 2>&1; then
  kv virsh 0
  exit 0
fi
kv virsh 1

# ── The user QEMU runs as ───────────────────────────────────────────
# The last uncommented `user = "..."` of qemu.conf; libvirt's default
# when there is none. `+N` is a numeric uid.
qemu_user=$(sed -nE 's/^[[:space:]]*user[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' \
  /etc/libvirt/qemu.conf 2>/dev/null | tail -1)
qemu_user=${qemu_user:-libvirt-qemu}
qemu_group=$(sed -nE 's/^[[:space:]]*group[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' \
  /etc/libvirt/qemu.conf 2>/dev/null | tail -1)
# `+N` (or a bare number) is a uid / gid: runuser needs the names.
case "$qemu_user" in
  +*|[0-9]*) qemu_user=$(getent passwd "${qemu_user#+}" | cut -d: -f1) ;;
esac
case "$qemu_group" in
  +*|[0-9]*) qemu_group=$(getent group "${qemu_group#+}" | cut -d: -f1) ;;
esac
kv qemu_user "$qemu_user"
kv qemu_group "$qemu_group"
if [ -n "$qemu_user" ] && id -u -- "$qemu_user" >/dev/null 2>&1; then
  qemu_user_ok=1
else
  qemu_user_ok=0
fi
kv qemu_user_ok "$qemu_user_ok"

as_qemu() {
  if [ "$qemu_user" = root ]; then
    "$@"
  elif [ -n "$qemu_group" ]; then
    runuser -u "$qemu_user" -g "$qemu_group" -- "$@"
  else
    runuser -u "$qemu_user" -- "$@"
  fi
}

# ── The libvirt `default` network ───────────────────────────────────
if info=$("${virsh_cmd[@]}" net-info default 2>/dev/null); then
  kv net_defined 1
  if grep -qE '^Active:[[:space:]]+yes' <<<"$info"; then kv net_active 1; else kv net_active 0; fi
  if grep -qE '^Autostart:[[:space:]]+yes' <<<"$info"; then kv net_autostart 1; else kv net_autostart 0; fi
  kv net_xml "$("${virsh_cmd[@]}" net-dumpxml default 2>/dev/null | tr -d '\n')"
else
  kv net_defined 0
fi
if "${virsh_cmd[@]}" nwfilter-dumpxml clean-traffic >/dev/null 2>&1; then
  kv nwfilter_clean_traffic 1
else
  kv nwfilter_clean_traffic 0
fi

# ── Can QEMU traverse down to each storage directory? ───────────────
# namei-style: every directory from / to the target needs search (x)
# permission for the QEMU user. libvirt chowns the disk file, never its
# parents. The agent's own subdirs are walked too once they exist.
blocked_roots=" "
walk() {
  local target=$1 cur="" part blocked=""
  local -a parts
  if [ ! -d "$target" ]; then
    echo "-missing-|"
    return
  fi
  IFS=/ read -r -a parts <<<"${target#/}"
  if ! as_qemu test -x /; then blocked=/; fi
  for part in "${parts[@]}"; do
    [ -n "$blocked" ] && break
    [ -n "$part" ] || continue
    cur="$cur/$part"
    if ! as_qemu test -x "$cur"; then blocked=$cur; fi
  done
  if [ -n "$blocked" ]; then
    echo "$blocked|$(stat -c '%A %U:%G' -- "$blocked" 2>/dev/null)"
  else
    echo "|"
  fi
}

declare -A seen=()
targets=()
for t in "$data_root" "$state_root" "$staging_root" \
  "$data_root/data" "$data_root/overlay" "$state_root/state"; do
  [ -n "$t" ] || continue
  t=${t%/}
  [ -n "${seen[$t]:-}" ] && continue
  seen[$t]=1
  targets+=("$t")
done

i=0
if [ "$qemu_user_ok" = 1 ]; then
  for t in "${targets[@]}"; do
    verdict=$(walk "$t")
    kv "traverse_$i" "$t|$verdict"
    case "$verdict" in
      "|"|-missing-*) ;;
      *) blocked_roots="$blocked_roots$t " ;;
    esac
    i=$((i + 1))
  done
fi

# ── The agent's sandbox ─────────────────────────────────────────────
if [ -n "$unit" ] && systemctl cat "$unit.service" >/dev/null 2>&1; then
  kv unit_present 1
  unit_ps=$(systemctl show "$unit" -p ProtectSystem --value 2>/dev/null)
  unit_rw=$(systemctl show "$unit" -p ReadWritePaths --value 2>/dev/null)
  kv unit_protect_system "$unit_ps"
  kv unit_rw_paths "$unit_rw"
else
  kv unit_present 0
fi

# `[storage]` roots of the INSTALLED config: what the agent really uses.
toml_storage() {
  awk -v key="$1" '
    /^[[:space:]]*\[/ { in_storage = ($0 ~ /^[[:space:]]*\[storage\][[:space:]]*$/) ; next }
    in_storage {
      line = $0
      sub(/#.*/, "", line)
      if (match(line, "^[[:space:]]*" key "[[:space:]]*=")) {
        v = substr(line, RLENGTH + 1)
        gsub(/^[[:space:]]*"|"[[:space:]]*$/, "", v)
        print v
        exit
      }
    }' "$config" 2>/dev/null
}
config_data_root=""
config_state_root=""
if [ -n "$config" ] && [ -r "$config" ]; then
  config_data_root=$(toml_storage data_disk_root)
  config_state_root=$(toml_storage state_disk_root)
fi
kv config_data_root "$config_data_root"
kv config_state_root "$config_state_root"

[ "$write" = 1 ] || exit 0

# A file created and deleted inside the unit's own sandbox (its
# effective properties, drop-ins included), in each root the config names.
if [ "${unit_ps+set}" = set ]; then
  sandbox_props=(-p NoNewPrivileges=yes)
  for prop in User Group RootDirectory ProtectSystem ProtectHome PrivateTmp PrivateDevices \
    ReadWritePaths ReadOnlyPaths InaccessiblePaths TemporaryFileSystem BindPaths BindReadOnlyPaths; do
    value=$(systemctl show "$unit" -p "$prop" --value 2>/dev/null)
    [ -n "$value" ] && sandbox_props+=(-p "$prop=$value")
  done
  i=0
  declare -A sandbox_seen=()
  for root in "${config_data_root:-$data_root}" "${config_state_root:-$state_root}"; do
    [ -n "$root" ] || continue
    [ -n "${sandbox_seen[$root]:-}" ] && continue
    sandbox_seen[$root]=1
    # shellcheck disable=SC2016  # $1 expands in the sandboxed shell
    if err=$(timeout 60 systemd-run --quiet --wait --collect --pipe "${sandbox_props[@]}" \
      /bin/sh -c 'f=$(mktemp -p "$1" .hippius-preflight-rw.XXXXXX) && rm -f -- "$f"' sh "$root" \
      </dev/null 2>&1); then
      kv "sandbox_$i" "$root|ok"
    else
      kv "sandbox_$i" "$root|fail:$(printf '%s' "$err" | oneline)"
    fi
    i=$((i + 1))
  done
fi

# O_DIRECT: one aligned 4 KiB write + fsync + read, as QEMU's user on a
# file it owns (the way libvirt hands it a disk). A root failure is the
# filesystem; a QEMU-user-only failure is a permission. In every storage
# directory that exists, the agent's own subdirs included: any of them
# can be a mount of its own. (The scratch name has no `.img`, so the
# agent's disk accounting never counts it; declared pools are probed by
# the agent itself.)
#
# Python, not dd: the uutils dd of Ubuntu 26.04 reads `iflag=direct`
# into an unaligned buffer and gets EINVAL on any filesystem, which would
# refuse every 26.04 host. An anonymous mmap is page-aligned.
python=$(command -v python3)
# shellcheck disable=SC2016  # Python source, not shell
odirect_py='
import mmap, os, sys
path = sys.argv[1]
buf = mmap.mmap(-1, 4096)
step = "open for write"
try:
    fd = os.open(path, os.O_WRONLY | os.O_DIRECT)
    try:
        step = "write"
        if os.write(fd, buf) != 4096:
            raise OSError(0, "short write")
        step = "fsync"
        os.fsync(fd)
    finally:
        os.close(fd)
    step = "open for read"
    fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
    try:
        step = "read"
        if os.readv(fd, [buf]) != 4096:
            raise OSError(0, "short read")
    finally:
        os.close(fd)
except OSError as err:
    sys.exit("O_DIRECT %s: %s" % (step, err.strerror or err))
'
odirect_rw() {
  if [ -z "$python" ]; then
    echo "python3 not found"
    return 1
  fi
  "$@" "$python" -I -c "$odirect_py" "$file" 2>&1
}
i=0
for root in "${targets[@]}"; do
  if [ ! -d "$root" ]; then
    kv "odirect_$i" "$root|skipped:missing"
    i=$((i + 1))
    continue
  fi
  if ! file=$(mktemp -p "$root" .hippius-preflight-odirect.XXXXXX 2>&1); then
    kv "odirect_$i" "$root|fail:cannot create a file: $(printf '%s' "$file" | oneline)"
    i=$((i + 1))
    continue
  fi
  scratch+=("$file")
  chmod 0600 "$file"
  verdict=""
  if [ "$qemu_user_ok" = 1 ] && [ "${blocked_roots/ $root /}" = "$blocked_roots" ]; then
    chown "$qemu_user" "$file"
    if user_err=$(odirect_rw as_qemu); then
      verdict=ok
    fi
  fi
  if [ -z "$verdict" ]; then
    if root_err=$(odirect_rw env); then
      if [ -n "${user_err+set}" ]; then
        verdict="fail-user:$(printf '%s' "$user_err" | oneline)"
      else
        verdict="skipped:traverse"
      fi
    else
      verdict="fail:$(printf '%s' "$root_err" | oneline)"
    fi
  fi
  unset user_err
  rm -f -- "$file"
  kv "odirect_$i" "$root|$verdict"
  i=$((i + 1))
done

[ "$smoke" = 1 ] || exit 0

# ── The smoke domain ────────────────────────────────────────────────
# What a tenant `virsh start` does that the host-attestor does not:
# open a raw `cache='none'` (O_DIRECT) disk under the data root through
# libvirt's ownership + AppArmor handling, and attach a NIC to `default`
# with the tenant filter. Started --paused: QEMU opens the disk and
# libvirt plugs the tap before any vCPU runs, so no guest code, image or
# key is needed. Transient (`virsh create`): no definition is left
# behind. No SNP (the attestor already proves it here, and it would take
# a scarce ASID), no vsock (no CID to collide with a tenant's), and a
# name outside the agent's `hippius-tenant-` / `hippius-infra-` prefixes.
case "$data_root" in
  *[\'\"\<\>\&]*) kv smoke fail; kv smoke_err "data root contains XML-special characters"; exit 0 ;;
esac
if ! smoke_dir=$(mktemp -d -p "$data_root" .hippius-preflight-smoke.XXXXXX 2>&1); then
  kv smoke fail
  kv smoke_err "cannot create a scratch dir in $data_root: $(printf '%s' "$smoke_dir" | oneline)"
  exit 0
fi
scratch+=("$smoke_dir")
# mktemp -d is 0700, which QEMU's user could not enter.
chmod 0755 "$smoke_dir"
truncate -s 16M "$smoke_dir/disk.img"
smoke_name="hippius-preflight-smoke-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
cat >"$smoke_dir/domain.xml" <<EOF
<domain type='kvm'>
  <name>$smoke_name</name>
  <memory unit='MiB'>64</memory>
  <vcpu placement='static'>1</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
  </os>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>destroy</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source file='$smoke_dir/disk.img'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
      <port isolated='yes'/>
      <filterref filter='clean-traffic'>
        <parameter name='CTRL_IP_LEARNING' value='dhcp'/>
        <parameter name='DHCPSERVER' value='192.168.122.1'/>
      </filterref>
    </interface>
    <memballoon model='none'/>
  </devices>
</domain>
EOF

err=$(timeout "$smoke_timeout" "${virsh_cmd[@]}" create "$smoke_dir/domain.xml" --paused 2>&1 >/dev/null)
rc=$?
if [ "$rc" != 0 ]; then
  [ "$rc" = 124 ] && err="virsh create timed out after ${smoke_timeout}s. $err"
  kv smoke fail
  kv smoke_err "$(printf '%s' "${err:-virsh create failed with no message}" | oneline)"
  exit 0
fi
smoke_started=1
state=$("${virsh_cmd[@]}" domstate "$smoke_name" 2>&1 | oneline)
if [ "$state" != paused ]; then
  kv smoke fail
  kv smoke_err "the smoke domain is '$state', not paused"
  exit 0
fi
if ! "${virsh_cmd[@]}" domiflist "$smoke_name" 2>/dev/null | grep -qE '[[:space:]]network[[:space:]]+default[[:space:]]'; then
  kv smoke fail
  kv smoke_err "the smoke domain started without a NIC on the default network"
  exit 0
fi
if ! smoke_destroy; then
  kv smoke fail
  kv smoke_err "the smoke domain $smoke_name could not be destroyed: virsh destroy $smoke_name"
  exit 0
fi
rm -f -- "/var/log/libvirt/qemu/$smoke_name.log"
kv smoke ok
