#!/bin/sh
# `hippius-release-core.sh` — the SHARED §21 release sequence for the
# BYO base-OS unlock path, sourced (never executed) by exactly two thin
# wrappers:
#
#   - `hippius-luks-keyscript` (Debian family): invoked by
#     cryptsetup-initramfs via /etc/crypttab `keyscript=`; emits the
#     KEK on its fd 3.
#   - `hippius-release-runner` (RHEL family, dracut): a systemd initrd
#     unit ordered before cryptsetup-pre.target; writes the KEK to the
#     /run keyfile /etc/crypttab references.
#
# ONE library, TWO wrappers — so the audited security sequence can
# never drift between the families. The full ordering rationale lives
# with each step below; the driver `hippius_release_run` is the only
# sanctioned entry point (wrappers MUST NOT call the steps directly,
# or the step-order CI golden in scripts/dev/release-core-order-test.sh
# will not protect them).
#
# Sequence (audit follow-up Codex finding #8 — cheap, network-free,
# fail-closed work FIRST):
#   1. hippius_parse_cmdline   — /proc/cmdline hippius.* tokens.
#   2. hippius_verify_header   — #296 detached-header sha gate. MUST
#                                precede ANY network activity.
#   3. hippius_modprobe_chain  — sev-guest/vsock/integrity modules.
#   4. hippius_net_up          — static libvirt-NAT bring-up.
#   5. hippius_fetch_ticket    — vsock pull (or hippius.ticket_path=).
#   6. hippius_mount_state_disk— Phase 2B /dev/vdd anti-rollback.
#   7. hippius_write_seed_meta — NoCloud meta-data stub (tmpfs).
#   8. hippius_run_release     — hippius-guest-release: userdata to
#                                tmpfs BEFORE the KEK lands (fail-
#                                closed ordering), 32-byte check.
#   9. hippius_umount_state_disk.
#
# (Step 3 runs before the network in this shared core — on the Debian
# family the modules were already auto-loaded from /etc/modules before
# the keyscript ran, so the earlier position is behavior-neutral there;
# dracut has no such auto-load, and the vsock fetch in step 5 needs the
# vsock chain present.)
#
# §20 secret discipline
# --------------------
# The KEK plaintext touches: hippius-guest-release stdout → the
# caller-supplied tmpfs path (0600) → the wrapper's egress (fd 3 or the
# crypttab keyfile). Diagnostics go to stderr/kmsg; the KEK is NEVER on
# a log line. Failure paths shred the partial KEK + the userdata.
#
# Wrapper contract
# ----------------
#   . /lib/hippius/hippius-release-core.sh
#   hippius_release_run /run/<kek-tmpfile>     # or:
#   hippius_prepare && hippius_acquire /run/<kek-tmpfile>
# The wrapper may pre-define `hippius_log` / `hippius_die` (both
# variadic, die exits non-zero). HIPPIUS_LOG_TAG names the wrapper in
# the default logger. `hippius_prepare` + `hippius_acquire` are split
# so the dracut runner can bound-retry the NETWORK-dependent half while
# the header gate stays single-shot fail-closed.

# ── Logging (overridable by the wrapper) ─────────────────────────────
HIPPIUS_LOG_TAG="${HIPPIUS_LOG_TAG:-hippius-release-core}"

if ! command -v hippius_log >/dev/null 2>&1; then
hippius_log() {
    printf '%s: %s\n' "$HIPPIUS_LOG_TAG" "$*" >&2
    printf '%s: %s\n' "$HIPPIUS_LOG_TAG" "$*" > /dev/kmsg 2>/dev/null || true
}
fi

if ! command -v hippius_die >/dev/null 2>&1; then
hippius_die() {
    hippius_log "FATAL: $*"
    exit 1
}
fi

# ── GOLDEN-mode detection (golden-bake PR3) ─────────────────────────
# GOLDEN mode replaces the legacy per-VM LUKS `/dev/vda` rootfs with a
# shared RO dm-verity base (lower) + a per-VM guest-keyed overlay upper
# (see hippius-golden-overlay.sh). Robust signal, consistent with the
# vali cmdline emitter (PR2) and the Rust guest parser: golden ⇔
# `dm-verity.root=` PRESENT and `hippius.luks_header_sha256=` ABSENT.
# Requiring BOTH fail-closes on a half-formed cmdline; the cmdline is
# SNP-measured, so a miner cannot flip a legacy VM into golden. This is
# behaviorally inert for legacy boots (both conditions false ⇒ the
# legacy path runs byte-identically).
hippius_is_golden_mode() {
    _higm_cmdline="$(cat /proc/cmdline 2>/dev/null || true)"
    case " ${_higm_cmdline} " in
        *" dm-verity.root="*) : ;;
        *) return 1 ;;
    esac
    case " ${_higm_cmdline} " in
        *" hippius.luks_header_sha256="*) return 1 ;;
    esac
    return 0
}

# ── 1. Parse /proc/cmdline ──────────────────────────────────────────
# Sets: HIPPIUS_KBS_URL (required), HIPPIUS_TICKET_PATH (optional),
# HIPPIUS_LUKS_DEVICE (default /dev/vda),
# HIPPIUS_EXPECTED_HEADER_SHA (required, 64 lowercase hex),
# HIPPIUS_LIFECYCLE_KEY_PATH (optional, §7 — see hippius_run_release).
hippius_parse_cmdline() {
    HIPPIUS_KBS_URL=""
    HIPPIUS_TICKET_PATH=""
    HIPPIUS_LUKS_DEVICE=""
    HIPPIUS_EXPECTED_HEADER_SHA=""
    HIPPIUS_LIFECYCLE_KEY_PATH=""
    for tok in $(cat /proc/cmdline); do
        case "$tok" in
            hippius.kbs_url=*)
                HIPPIUS_KBS_URL="${tok#hippius.kbs_url=}" ;;
            hippius.ticket_path=*)
                HIPPIUS_TICKET_PATH="${tok#hippius.ticket_path=}" ;;
            hippius.luks_device=*)
                HIPPIUS_LUKS_DEVICE="${tok#hippius.luks_device=}" ;;
            hippius.luks_header_sha256=*)
                HIPPIUS_EXPECTED_HEADER_SHA="${tok#hippius.luks_header_sha256=}" ;;
            # §7 lifecycle key — vali bakes this MEASURED token at launch
            # (hippius.lifecycle_key_path=/run/hippius/lifecycle.key). When
            # present, the release step writes the KBS-released Ed25519
            # signing seed to it on TMPFS so the post-pivot
            # `hippius-eol-sign.service` (`eol --sign-only`) can read the
            # SAME path to sign the §24/§25 StoppedAck. Absent ⇒ pre-§7 VM,
            # no key written, eol logs `eol-no-key` (fail-closed).
            hippius.lifecycle_key_path=*)
                HIPPIUS_LIFECYCLE_KEY_PATH="${tok#hippius.lifecycle_key_path=}" ;;
        esac
    done
    [ -n "$HIPPIUS_KBS_URL" ] || hippius_die "hippius.kbs_url= missing from /proc/cmdline"
    [ -n "$HIPPIUS_LUKS_DEVICE" ] || HIPPIUS_LUKS_DEVICE=/dev/vda
    hippius_log "KBS URL: $HIPPIUS_KBS_URL"
}

# ── 2. #296 — LUKS2 header verification ─────────────────────────────
# Trail of Bits / CVE-2025-59054 family: the LUKS2 header itself is
# unauthenticated (CRC32 is for accidents). Detached-header pattern:
# luksHeaderBackup copies the header into tmpfs (guest-private under
# SEV-SNP), the COPY's sha256 is compared to the MEASURED cmdline
# value, and the crypttab `header=/run/hippius/luks.header` makes the
# eventual open use the verified copy — closing the TOCTOU where a
# miner swaps the on-disk header between our read and the open.
# MUST run before ANY network bring-up (a header-tampered boot teaches
# the miner nothing if the network never came up).
hippius_verify_header() {
    # GOLDEN mode (golden-bake PR3): there is NO measured LUKS header to
    # verify — the shared base is an unkeyed dm-verity Merkle tree
    # (integrity anchored by the MEASURED `dm-verity.root=` root hash),
    # and the per-VM writable upper is a guest-formatted LUKS2+integrity
    # volume whose header the guest itself generates at first boot (so
    # its sha is not knowable/measurable ahead of time). Skip the #296
    # header gate; the golden overlay path (hippius-golden-overlay.sh)
    # owns integrity. Legacy boots never take this branch (the token is
    # present) → byte-identical.
    if hippius_is_golden_mode; then
        hippius_log "golden mode: skipping #296 LUKS-header gate (unkeyed dm-verity base; upper is guest-formatted)"
        return 0
    fi
    [ -n "$HIPPIUS_EXPECTED_HEADER_SHA" ] \
        || hippius_die "hippius.luks_header_sha256= missing from /proc/cmdline (#296)"
    case "$HIPPIUS_EXPECTED_HEADER_SHA" in
        *[!0-9a-f]* | "")
            hippius_die "hippius.luks_header_sha256 must be 64 lowercase hex chars" ;;
    esac
    if [ "$(printf '%s' "$HIPPIUS_EXPECTED_HEADER_SHA" | wc -c)" -ne 64 ]; then
        hippius_die "hippius.luks_header_sha256 must be 64 lowercase hex chars (got $(printf '%s' "$HIPPIUS_EXPECTED_HEADER_SHA" | wc -c))"
    fi

    # tmpfs under /run; wipe any prior copy (retry loops) so a stale
    # header from a previous invocation can't be reused.
    mkdir -p /run/hippius
    chmod 0700 /run/hippius
    rm -f /run/hippius/luks.header

    cryptsetup luksHeaderBackup "$HIPPIUS_LUKS_DEVICE" \
        --header-backup-file /run/hippius/luks.header >>/dev/kmsg 2>&1 \
        || hippius_die "luksHeaderBackup failed for $HIPPIUS_LUKS_DEVICE (#296)"

    actual_sha=$(sha256sum /run/hippius/luks.header | awk '{print $1}')
    if [ "$HIPPIUS_EXPECTED_HEADER_SHA" != "$actual_sha" ]; then
        # Wipe the unverified copy so the crypttab `header=` open can
        # never pick it up.
        shred -u /run/hippius/luks.header 2>/dev/null || rm -f /run/hippius/luks.header
        hippius_die "LUKS2 header tampered (#296): expected=$HIPPIUS_EXPECTED_HEADER_SHA actual=$actual_sha"
    fi
    hippius_log "LUKS2 header verified (#296): sha256=$HIPPIUS_EXPECTED_HEADER_SHA from $HIPPIUS_LUKS_DEVICE → /run/hippius/luks.header"
}

# ── 3. Kernel modules ───────────────────────────────────────────────
# /dev/sev-guest is created when sev-guest attaches; nothing auto-loads
# it (no udev rule). configfs/tsm are its deps; the gcm(aes) AEAD probe
# allocates from the crypto modules; the vsock chain backs the ticket
# fetch; ext4 backs the Phase 2B state disk; dm_integrity backs the
# `--integrity hmac-sha256` activation stack.
hippius_modprobe_chain() {
    for m in configfs tsm sev-guest crypto_null gf128mul ghash-generic gcm vsock vmw_vsock_virtio_transport_common vmw_vsock_virtio_transport ext4 dm_integrity; do
        modprobe "$m" 2>>/dev/kmsg || true
    done
    hippius_log "modprobe sev-guest done; /dev/sev-guest exists: $([ -e /dev/sev-guest ] && echo yes || echo no)"
}

# ── 4. Static network bring-up ──────────────────────────────────────
# Hand-written lease against libvirt's well-known default-NAT shape
# (DHCP clients proved flaky in initramfs — see the keyscript history):
#   bridge/gw/DNS 192.168.122.1, static IP at the top of the range.
# The KBS hostname (parsed out of `hippius.kbs_url=`) is pinned in
# /etc/hosts so no DNS dependency exists in the §21 exchange. Both the
# host and its address are DEPLOYMENT CONFIG: the host comes from the
# measured cmdline, the address from `hippius.kbs_ip=` /
# $HIPPIUS_KBS_IP. Neither has a built-in default — an unset address
# simply skips the pin and falls back to $HIPPIUS_STATIC_DNS.
hippius_net_up() {
    hippius_log "bringing up network (static, libvirt-NAT shape)"
    iface=$(ls /sys/class/net | grep -E '^(eth|en)' | head -n 1 || true)
    [ -n "${iface:-}" ] || hippius_die "no ethernet interface found in /sys/class/net"
    ip link set "$iface" up || hippius_die "link up $iface failed"

    static_ip="${HIPPIUS_STATIC_IP:-192.168.122.253/24}"
    static_gw="${HIPPIUS_STATIC_GW:-192.168.122.1}"
    static_dns="${HIPPIUS_STATIC_DNS:-192.168.122.1}"
    kbs_ip="${HIPPIUS_KBS_IP:-}"
    # Host portion of `hippius.kbs_url=` — e.g. `https://kbs.example/v1`
    # yields `kbs.example`. Empty for the vsock:// authority (which
    # needs no /etc/hosts entry at all).
    kbs_host=$(printf '%s' "$HIPPIUS_KBS_URL" \
        | sed -e 's|^[a-z][a-z0-9+.-]*://||' -e 's|[/?#].*$||' -e 's|:[0-9]*$||')

    set +e
    ip -4 addr add "$static_ip" dev "$iface" 2>>/dev/kmsg
    rc_addr=$?
    ip -4 route flush dev "$iface" default 2>/dev/null || true
    ip -4 route add default via "$static_gw" dev "$iface" 2>>/dev/kmsg
    rc_route=$?
    # Fresh resolv.conf + hosts every call (retry loops would compound
    # stale entries otherwise).
    printf 'nameserver %s\n' "$static_dns" > /etc/resolv.conf
    rc_resolv=$?
    if [ -n "$kbs_ip" ] && [ -n "$kbs_host" ]; then
        printf '127.0.0.1 localhost\n%s %s\n' "$kbs_ip" "$kbs_host" > /etc/hosts
    else
        printf '127.0.0.1 localhost\n' > /etc/hosts
    fi
    rc_hosts=$?
    set -e
    hippius_log "static-net: addr=$rc_addr route=$rc_route resolv=$rc_resolv hosts=$rc_hosts"
    hippius_log "ip-addr: $(ip -4 -o addr show "$iface" 2>/dev/null)"
    hippius_log "ip-route: $(ip -4 -o route show 2>/dev/null | tr '\n' '|')"
    if [ "$rc_addr" -ne 0 ] && [ "$rc_addr" -ne 2 ]; then
        # rc=2 = "File exists" (already configured on a retry) — fine.
        hippius_die "static-net: ip addr failed rc=$rc_addr"
    fi
    hippius_log "static-net up on $iface"
    HIPPIUS_IFACE="$iface"
    HIPPIUS_KBS_IP_RESOLVED="$kbs_ip"
    HIPPIUS_KBS_HOST_RESOLVED="$kbs_host"
}

# ── 4b. KBS reachability preflight (diagnostics only) ───────────────
# Hits /v1/kbs/nonce so a later `kbs-failed:connect` has visible
# context (remote IP, HTTP code, timings) on the serial. NO `-k`: the
# CA bundle is staged, and a `-k` probe could let a miner spoof a
# healthy TLS handshake on the diagnostic while MITMing the real
# release (audit finding #7). Failure here is non-fatal — the release
# binary is the actual gate.
hippius_kbs_preflight() {
    command -v curl >/dev/null 2>&1 || return 0
    pf="$(curl -s --max-time 5 -X POST -o /dev/null \
        -w 'remote=%{remote_ip} code=%{http_code} dns=%{time_namelookup}s connect=%{time_connect}s' \
        "${HIPPIUS_KBS_URL}/v1/kbs/nonce" 2>&1 || true)"
    hippius_log "preflight: $pf"
    # Second probe only makes sense once an explicit address is pinned.
    [ -n "${HIPPIUS_KBS_IP_RESOLVED:-}" ] || return 0
    [ -n "${HIPPIUS_KBS_HOST_RESOLVED:-}" ] || return 0
    pf2="$(curl -s --max-time 5 -X POST -o /dev/null \
        --resolve "${HIPPIUS_KBS_HOST_RESOLVED}:443:${HIPPIUS_KBS_IP_RESOLVED}" \
        -w 'remote=%{remote_ip} code=%{http_code} dns=%{time_namelookup}s connect=%{time_connect}s' \
        "${HIPPIUS_KBS_URL}/v1/kbs/nonce" 2>&1 || true)"
    hippius_log "preflight --resolve: $pf2"
}

# ── 5. Fetch the OrderTicket ────────────────────────────────────────
# Production: vsock pull from the miner-agent (CID 2, the shared
# hippius_types::ticket_vsock::PORT). Dev/smoke: hippius.ticket_path=.
# Sets HIPPIUS_TICKET_FILE.
hippius_fetch_ticket() {
    HIPPIUS_TICKET_FILE=/run/hippius-ticket.cose
    if [ -n "$HIPPIUS_TICKET_PATH" ] && [ -r "$HIPPIUS_TICKET_PATH" ]; then
        cp "$HIPPIUS_TICKET_PATH" "$HIPPIUS_TICKET_FILE"
        hippius_log "ticket loaded from $HIPPIUS_TICKET_PATH ($(wc -c < "$HIPPIUS_TICKET_FILE") bytes)"
        return 0
    fi
    command -v hippius-vsock-ticket >/dev/null 2>&1 \
        || hippius_die "hippius-vsock-ticket not staged (hook/module bug); rebake the image"
    # ash/dash have no pipefail; capture the rc directly so a 0-byte
    # receive can't masquerade as success.
    if ! hippius-vsock-ticket --out "$HIPPIUS_TICKET_FILE" 2>>/dev/kmsg; then
        hippius_die "vsock ticket receive failed"
    fi
    ticket_bytes=$(wc -c < "$HIPPIUS_TICKET_FILE")
    if [ "${ticket_bytes:-0}" -lt 100 ]; then
        hippius_die "vsock ticket too small (${ticket_bytes} bytes; expected 700-1500)"
    fi
    hippius_log "ticket loaded from vsock (${ticket_bytes} bytes)"
}

# ── 6. Phase 2B — per-VM state disk (anti-rollback) ─────────────────
# /dev/vdd (1 MiB ext4, miner-provisioned) is mounted BEFORE the
# release so hippius-guest-release can read/advance the boot counter
# BEFORE the KEK ships. Graceful degrade with a loud line when absent.
# Sets HIPPIUS_STATE_DISK_FLAGS + HIPPIUS_STATE_DISK_MOUNTED.
hippius_mount_state_disk() {
    HIPPIUS_STATE_DISK_FLAGS=""
    HIPPIUS_STATE_DISK_MOUNTED="no"
    if [ -b /dev/vdd ]; then
        mkdir -p /hippius-state
        chmod 0700 /hippius-state
        if mount -t ext4 -o sync,noatime,nodev,nosuid,noexec /dev/vdd /hippius-state 2>>/dev/kmsg; then
            hippius_log "Phase 2B state disk mounted: /dev/vdd -> /hippius-state"
            HIPPIUS_STATE_DISK_FLAGS="--last-counter-file /hippius-state/boot-counter --new-counter-file /hippius-state/boot-counter"
            HIPPIUS_STATE_DISK_MOUNTED="yes"
        else
            hippius_log "Phase 2B state disk mount FAILED; booting without anti-rollback (best-effort)"
        fi
    else
        hippius_log "Phase 2B: /dev/vdd not present; booting without anti-rollback"
    fi
}

hippius_umount_state_disk() {
    if [ "$HIPPIUS_STATE_DISK_MOUNTED" = "yes" ]; then
        sync
        umount /hippius-state 2>>/dev/kmsg \
            || hippius_log "Phase 2B state disk umount failed (re-mounted post-pivot)"
        HIPPIUS_STATE_DISK_MOUNTED="no"
    fi
}

# ── 7. NoCloud seed meta-data (tmpfs, RAM-only) ─────────────────────
# /run is moved across the pivot (initramfs-tools mount --move; systemd
# does the same under dracut), so the seed written here is what
# cloud-init's `ds=nocloud;s=/run/cloud-init/seed/` reads post-boot.
# Per-boot instance-id so per-instance semaphores re-run every launch.
# NB: deliberately NO `local-hostname` — that makes cloud-init run
# cc_set_hostname at the EARLY init-local stage (before the system D-Bus
# is up), and on Fedora 43 `hostnamectl set-hostname` then fails
# ("Failed to connect to system scope bus") → cloud-init reports the
# whole run as errored (5 failed units) even though the SSH key + netbird
# runcmd applied fine. Omitting local-hostname keeps cloud-init `done` on
# every distro; a tenant that wants a specific hostname sets it via
# userdata `hostname:` (applied at a later, post-D-Bus stage). The netbird
# peer name comes from its own `--hostname` template, not the OS hostname.
hippius_write_seed_meta() {
    mkdir -p /run/cloud-init/seed
    chmod 0755 /run/cloud-init/seed
    ci_iid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "00000000-0000-0000-0000-000000000000")
    {
        printf 'instance-id: %s\n' "iid-${ci_iid}"
    } > /run/cloud-init/seed/meta-data
    chmod 0644 /run/cloud-init/seed/meta-data
}

# ── 8. The release exchange ─────────────────────────────────────────
# hippius-guest-release: X25519 keygen → /v1/kbs/nonce → SNP report
# (/dev/sev-guest, REPORT_DATA = nonce ‖ pub) → POST /v1/kbs/release →
# verify + HPKE-unwrap. Userdata lands on tmpfs BEFORE the KEK is
# emitted (write failure ⇒ fail-closed, disk stays locked). The KEK is
# buffered via the caller's tmpfs path (32-byte length check) — never
# piped straight to the consumer (EPIPE race vs cryptsetup's reader).
hippius_run_release() {
    kek_out="$1"
    command -v hippius-guest-release >/dev/null 2>&1 \
        || hippius_die "hippius-guest-release not staged (hook/module bug); rebake the image"

    # §7 lifecycle key out (optional). When the launch baked
    # `hippius.lifecycle_key_path` into the measured cmdline, pass it as
    # `--lifecycle-key-out` so hippius-guest-release writes the
    # KBS-released Ed25519 signing seed (HPKE-unwrapped, attested-guest
    # only) to that TMPFS path (mode 0600). The path lives under /run
    # (the same tmpfs survives switch_root), so the post-pivot
    # `eol --sign-only` reads it to sign the §24/§25 StoppedAck. WITHOUT
    # this flag the key is never materialised and the §25 migration ack
    # is never produced → fail-closed stall. Empty ⇒ pre-§7 image.
    #
    # P9/#12: the "TMPFS path" part is ENFORCED by the binary, not by
    # this shell — `hippius-guest-release` refuses any
    # `--lifecycle-key-out` that is not strictly under /run/ (lexically
    # AND after symlink resolution) and exits EXIT_USAGE=1 before it
    # sends anything to the KBS. Deliberately NOT re-implemented here: a
    # second, string-matching copy of the gate would be the one that
    # silently drifts. The `mkdir -p` below therefore runs against an
    # unvalidated dirname, which at worst leaves an EMPTY directory
    # behind on a hostile path — no key material ever reaches it,
    # because the very next command refuses and aborts the boot.
    HIPPIUS_LIFECYCLE_FLAGS=""
    if [ -n "${HIPPIUS_LIFECYCLE_KEY_PATH:-}" ]; then
        # The parent dir must exist on tmpfs before guest-release writes
        # the 0600 seed (it creates the file, not necessarily the tree).
        mkdir -p "$(dirname "$HIPPIUS_LIFECYCLE_KEY_PATH")" 2>/dev/null || true
        HIPPIUS_LIFECYCLE_FLAGS="--lifecycle-key-out $HIPPIUS_LIFECYCLE_KEY_PATH"
        hippius_log "lifecycle key out: $HIPPIUS_LIFECYCLE_KEY_PATH"
    fi

    # Caller-supplied extra flags (GOLDEN mode uses this to request the
    # volume-stamp anti-rollback outputs — see hippius-golden-overlay.sh).
    # EMPTY by default, so the legacy Debian/RHEL unlock path builds a
    # byte-identical command line and is entirely unaffected.
    HIPPIUS_EXTRA_RELEASE_FLAGS="${HIPPIUS_EXTRA_RELEASE_FLAGS:-}"

    # Word-splitting on the flags vars is intentional — they are built
    # internally (empty or --flag path pairs); no user input.
    # shellcheck disable=SC2086
    if ! hippius-guest-release \
            --kbs-url "$HIPPIUS_KBS_URL" \
            --ticket "$HIPPIUS_TICKET_FILE" \
            --userdata-out /run/cloud-init/seed/user-data \
            $HIPPIUS_LIFECYCLE_FLAGS \
            $HIPPIUS_STATE_DISK_FLAGS \
            $HIPPIUS_EXTRA_RELEASE_FLAGS \
            > "$kek_out" \
            2>>/dev/kmsg; then
        shred -u "$kek_out" 2>/dev/null || rm -f "$kek_out"
        rm -f /run/cloud-init/seed/user-data 2>/dev/null || true
        hippius_umount_state_disk
        hippius_die "KBS release exchange failed (see kmsg for the fail-closed class)"
    fi
    kek_bytes=$(wc -c < "$kek_out")
    if [ "${kek_bytes:-0}" -ne 32 ]; then
        shred -u "$kek_out" 2>/dev/null || rm -f "$kek_out"
        rm -f /run/cloud-init/seed/user-data 2>/dev/null || true
        hippius_umount_state_disk
        hippius_die "KBS release exchange returned ${kek_bytes} bytes; expected 32"
    fi
    # The COSE ticket is public (a placement assertion) — removing it
    # is tidiness, not secrecy.
    rm -f "$HIPPIUS_TICKET_FILE"
}

# ── Drivers ─────────────────────────────────────────────────────────
# `hippius_prepare`: the single-shot, fail-closed, NETWORK-FREE half.
# Never retried — a failed header gate must not loop.
hippius_prepare() {
    hippius_parse_cmdline
    hippius_verify_header
}

# `hippius_acquire <kek-out>`: the network-dependent half. The dracut
# runner bound-retries THIS (transient vsock/KBS hiccups); the Debian
# keyscript relies on cryptroot's own retry loop instead.
hippius_acquire() {
    hippius_modprobe_chain
    # `hippius_net_up` + the preflight run UNCONDITIONALLY — even for a
    # `vsock://` KBS that needs no IP network. Two attempts to skip the
    # initramfs network for vsock (#670 dropped `IP=dhcp`, #673 gated
    # these two calls behind a vsock case) BOTH silently hung the guest
    # pre-KBS and were reverted (#672/#675): some effect of the
    # initramfs network path is boot-load-bearing beyond KBS
    # reachability itself. This exact unconditional sequence is the
    # live-proven-good boot path — DO NOT re-gate it. The double-IP the
    # initramfs bring-up used to leave behind is fixed in USERSPACE
    # instead (the init-bottom `hippius-net-teardown` flush + the baked
    # systemd-networkd `ClientIdentifier=mac` drop-in), never here.
    hippius_net_up
    hippius_kbs_preflight
    hippius_fetch_ticket
    hippius_mount_state_disk
    hippius_write_seed_meta
    hippius_run_release "$1"
    hippius_umount_state_disk
}

# `hippius_release_run <kek-out>`: the full audited sequence. The KEK
# (exactly 32 bytes) is left at <kek-out> (0600 recommended); the
# wrapper owns its egress + shredding.
hippius_release_run() {
    hippius_prepare
    hippius_acquire "$1"
    hippius_log "KEK released to tmpfs; wrapper will hand it to cryptsetup"
}
