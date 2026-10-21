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
#     --staging-root DIR --unit NAME --config FILE [--ovmf FILE] \
#     [--host-kernel FILE] [--write] [--smoke] [--smoke-timeout SECONDS]
set -uo pipefail
# virsh and coreutils messages are matched below: never localised.
export LC_ALL=C

data_root=""
state_root=""
staging_root=""
unit=""
config=""
ovmf=""
host_kernel="/boot/vmlinuz-$(uname -r)"
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
    --ovmf) ovmf=$2; shift 2 ;;
    --host-kernel) host_kernel=$2; shift 2 ;;
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

# The per-VM staging dirs a launch already left (VM ids only): a dir the
# agent created under a restrictive umask shows up here.
walk_targets=("${targets[@]}")
if [ -d "$staging_root" ]; then
  n=0
  for d in "$staging_root"/*/; do
    d=${d%/}
    case "${d##*/}" in
      *[!a-z0-9-]*|"*") continue ;;
    esac
    walk_targets+=("$d")
    n=$((n + 1))
    [ "$n" -lt 20 ] || break
  done
fi

i=0
if [ "$qemu_user_ok" = 1 ]; then
  for t in "${walk_targets[@]}"; do
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
  unit_umask=$(systemctl show "$unit" -p UMask --value 2>/dev/null)
  kv unit_protect_system "$unit_ps"
  kv unit_rw_paths "$unit_rw"
  kv unit_umask "$unit_umask"
else
  kv unit_present 0
fi

# `[section] key` of the INSTALLED config: what the agent really uses.
toml_get() {
  awk -v section="[$1]" -v key="$2" '
    /^[[:space:]]*\[/ { line = $0; gsub(/[[:space:]]/, "", line); in_section = (line == section); next }
    in_section {
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
config_image_cache=""
if [ -n "$config" ] && [ -r "$config" ]; then
  config_data_root=$(toml_get storage data_disk_root)
  config_state_root=$(toml_get storage state_disk_root)
  config_image_cache=$(toml_get image cache_dir)
fi
kv config_data_root "$config_data_root"
kv config_state_root "$config_state_root"

# ── Symlinks on the way to anything QEMU opens ──────────────────────
# libvirt's per-domain AppArmor profile (virt-aa-helper) lists each disk,
# kernel and firmware by the path libvirt was GIVEN; the kernel checks
# the RESOLVED path. A symlink anywhere on the way (a staging dir moved
# to a bigger disk and linked back, say) makes every open of it a
# DENIED. A bind mount at the configured path has no such gap.
first_symlink() {
  local cur="" part
  local -a parts
  IFS=/ read -r -a parts <<<"${1#/}"
  for part in "${parts[@]}"; do
    [ -n "$part" ] || continue
    cur="$cur/$part"
    if [ -L "$cur" ]; then
      echo "$cur|$(readlink -f -- "$cur")"
      return
    fi
    [ -e "$cur" ] || break
  done
  echo "|"
}
i=0
declare -A link_seen=()
for t in "${targets[@]}" "$config_data_root" "$config_state_root" "$config_image_cache" "$ovmf"; do
  t=${t%/}
  [ -n "$t" ] || continue
  [ -n "${link_seen[$t]:-}" ] && continue
  link_seen[$t]=1
  kv "symlink_$i" "$t|$(first_symlink "$t")"
  i=$((i + 1))
done

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
# What a tenant `virsh start` does that the host-attestor does not, laid
# out like a golden tenant: a per-VM staging dir holding the kernel, the
# initrd and the read-only rootfs data + dm-verity hash disks; the
# overlay, state and data disks in the agent's overlay/, state/ and data/
# dirs (their roots while the agent has not created them yet); the
# tenant OVMF as the loader; a NIC on `default` with the tenant filter.
# Every file goes through libvirt's ownership handling and the per-domain
# AppArmor profile, exactly as a tenant's does.
#
# Started --paused: QEMU loads the firmware, kernel and initrd and opens
# every disk, and libvirt plugs the tap, before any vCPU runs — no guest
# code, image or key is needed. Transient (`virsh create`): no definition
# is left behind. No SNP (the attestor already proves it here, and it
# would take a scarce ASID), no vsock (no CID to collide with a
# tenant's), and a name outside the agent's `hippius-tenant-` /
# `hippius-infra-` prefixes. Every scratch name starts with a dot, which
# no VM id can, and none ends in `.img`, so the agent's sweeps and disk
# accounting never take them for a VM.
smoke_fail() {
  kv smoke fail
  kv smoke_err "$1"
  exit 0
}
for d in "$data_root" "$state_root" "$staging_root" "$ovmf"; do
  case "$d" in
    *[\'\"\<\>\&]*) smoke_fail "a storage path contains XML-special characters: $d" ;;
  esac
done
# The agent's subdir when it exists, else the root it will be created in.
in_dir() {
  if [ -d "$1/$2" ]; then echo "$1/$2"; else echo "$1"; fi
}
staging_parent=$staging_root
[ -d "$staging_parent" ] || staging_parent=$state_root
tag=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
# The modes the agent would give its own dirs and files (create_dir_all /
# File::create under the unit's UMask), not friendlier ones: a umask that
# shuts QEMU out of a per-VM dir must fail here too.
smoke_umask=${unit_umask:-0022}
case "$smoke_umask" in
  *[!0-7]*|"") smoke_umask=0022 ;;
esac
dir_mode=$(printf '%o' $((0777 & ~8#$smoke_umask)))
file_mode=$(printf '%o' $((0666 & ~8#$smoke_umask)))
if ! smoke_stage=$(mktemp -d -p "$staging_parent" .hippius-preflight-smoke.XXXXXX 2>&1); then
  smoke_fail "cannot create a scratch dir in $staging_parent: $(printf '%s' "$smoke_stage" | oneline)"
fi
scratch+=("$smoke_stage")
# mktemp -d is always 0700: give it the mode the agent's mkdir would.
chmod "$dir_mode" "$smoke_stage"
overlay_disk="$(in_dir "$data_root" overlay)/.hippius-preflight-smoke-$tag-overlay.raw"
state_disk="$(in_dir "$state_root" state)/.hippius-preflight-smoke-$tag-state.raw"
data_disk="$(in_dir "$data_root" data)/.hippius-preflight-smoke-$tag-data.raw"
for f in "$overlay_disk" "$state_disk" "$data_disk" "$smoke_stage/rootfs.img" "$smoke_stage/rootfs.verity"; do
  scratch+=("$f")
  if ! err=$(truncate -s 16M -- "$f" 2>&1); then
    smoke_fail "cannot create $f: $(printf '%s' "$err" | oneline)"
  fi
  chmod "$file_mode" "$f"
done

# Direct kernel boot, like a tenant: QEMU loads the kernel at start-up,
# so it must be a real one — a copy of this host's. Without one, the
# disks are still checked.
kernel_xml=""
if [ -r "$host_kernel" ] && cp -- "$host_kernel" "$smoke_stage/vmlinuz" 2>/dev/null; then
  truncate -s 4K "$smoke_stage/initrd"
  chmod "$file_mode" "$smoke_stage/vmlinuz" "$smoke_stage/initrd"
  kernel_xml="<kernel>$smoke_stage/vmlinuz</kernel>
    <initrd>$smoke_stage/initrd</initrd>
    <cmdline>console=ttyS0</cmdline>"
  kv smoke_kernel ok
else
  kv smoke_kernel "skipped:no readable host kernel at $host_kernel"
fi
loader_xml=""
if [ -n "$ovmf" ] && [ -f "$ovmf" ]; then
  loader_xml="<loader type='rom'>$ovmf</loader>"
fi

disk_xml() {
  # $1 file, $2 target, $3 cache, $4 "ro" for a read-only disk
  printf "    <disk type='file' device='disk'>\n      <driver name='qemu' type='raw' cache='%s'/>\n      <source file='%s'/>\n      <target dev='%s' bus='virtio'/>\n%s    </disk>\n" \
    "$3" "$1" "$2" "$([ "${4:-}" = ro ] && printf '      <readonly/>\n')"
}

smoke_name="hippius-preflight-smoke-$tag"
smoke_uuid=$(cat /proc/sys/kernel/random/uuid)
smoke_since=$(date +%s)
cat >"$smoke_stage/domain.xml" <<EOF
<domain type='kvm'>
  <name>$smoke_name</name>
  <uuid>$smoke_uuid</uuid>
  <memory unit='MiB'>64</memory>
  <vcpu placement='static'>1</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    $loader_xml
    $kernel_xml
  </os>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>destroy</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
$(disk_xml "$overlay_disk" vda none)
$(disk_xml "$smoke_stage/rootfs.img" vdb none ro)
$(disk_xml "$smoke_stage/rootfs.verity" vdc none ro)
$(disk_xml "$state_disk" vdd none)
$(disk_xml "$data_disk" vde writeback)
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

# What AppArmor refused this domain (or virt-aa-helper building its
# profile) since the smoke started: the RESOLVED path, labelled by which
# of the smoke's files it is (a symlinked dir resolves elsewhere).
report_apparmor() {
  local line path mask profile label n=0
  while IFS= read -r line; do
    path=$(sed -nE 's/.* name="([^"]*)".*/\1/p' <<<"$line")
    mask=$(sed -nE 's/.* requested_mask="([^"]*)".*/\1/p' <<<"$line")
    profile=$(sed -nE 's/.* profile="([^"]*)".*/\1/p' <<<"$line")
    case "$path" in
      *-overlay.raw) label=OVERLAY ;;
      *-state.raw) label=STATE ;;
      *-data.raw) label=DATA ;;
      */rootfs.img|*/rootfs.verity|*/vmlinuz|*/initrd) label=STAGING ;;
      "$ovmf"|*/"${ovmf##*/}") label=OVMF ;;
      *) label=OTHER ;;
    esac
    kv "apparmor_denied_$n" "$label|$path|$mask|$profile"
    n=$((n + 1))
    [ "$n" -lt 10 ] || break
  done < <(journalctl -k --since "@$smoke_since" --no-pager -o cat 2>/dev/null |
    grep 'apparmor="DENIED"' |
    grep -E "profile=\"libvirt-$smoke_uuid\"|profile=\"virt-aa-helper\".*hippius-preflight-smoke")
}

err=$(timeout "$smoke_timeout" "${virsh_cmd[@]}" create "$smoke_stage/domain.xml" --paused 2>&1 >/dev/null)
rc=$?
if [ "$rc" != 0 ]; then
  [ "$rc" = 124 ] && err="virsh create timed out after ${smoke_timeout}s. $err"
  report_apparmor
  smoke_fail "$(printf '%s' "${err:-virsh create failed with no message}" | oneline)"
fi
smoke_started=1
state=$("${virsh_cmd[@]}" domstate "$smoke_name" 2>&1 | oneline)
if [ "$state" != paused ]; then
  smoke_fail "the smoke domain is '$state', not paused"
fi
if ! "${virsh_cmd[@]}" domiflist "$smoke_name" 2>/dev/null | grep -qE '[[:space:]]network[[:space:]]+default[[:space:]]'; then
  smoke_fail "the smoke domain started without a NIC on the default network"
fi
if ! smoke_destroy; then
  smoke_fail "the smoke domain $smoke_name could not be destroyed: virsh destroy $smoke_name"
fi
rm -f -- "/var/log/libvirt/qemu/$smoke_name.log"
kv smoke ok
