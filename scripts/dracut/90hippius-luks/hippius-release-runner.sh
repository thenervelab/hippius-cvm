#!/bin/sh
# `hippius-release-runner` — RHEL-family (dracut) wrapper around the
# SHARED §21 release sequence in `hippius-release-core.sh`. Invoked by
# `hippius-release.service` (Before=cryptsetup-pre.target); writes the
# released 32-byte KEK to the tmpfs keyfile `/run/hippius/kek` that the
# initrd /etc/crypttab references, then exits. systemd-cryptsetup does
# the actual unlock against the #296-VERIFIED header copy
# (`header=/run/hippius/luks.header`, staged by the core).
#
# ALL security-relevant logic lives in the core (see
# scripts/initramfs/hippius-release-core.sh) — shared byte-for-byte
# with the Debian-family keyscript so the two unlock paths can never
# drift. This wrapper owns only:
#   - the keyfile egress (atomic mv into /run/hippius/kek, 0600),
#   - the bounded retry of the NETWORK-dependent half (dracut has no
#     cryptroot-style keyscript retry loop; transient vsock/KBS
#     hiccups during early boot deserve a few attempts),
#   - never retrying the header gate (hippius_prepare is single-shot:
#     a tampered header must fail closed immediately).
#
# §20: the KEK lands at /run/hippius/kek (tmpfs, 0600) for the few ms
# until systemd-cryptsetup consumes it; hippius-net-teardown shreds it
# (and the header copy) before switch-root.

set -eu

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

HIPPIUS_LOG_TAG="hippius-release-runner"

CORE=/lib/hippius/hippius-release-core.sh
if [ ! -r "$CORE" ]; then
    printf 'hippius-release-runner: FATAL: %s not staged (module-setup bug); rebake the image\n' "$CORE" >&2
    exit 1
fi
# shellcheck source=scripts/initramfs/hippius-release-core.sh
. "$CORE"

# Single-shot, network-free, fail-closed half (cmdline + #296 header
# gate). NEVER retried.
hippius_prepare

# Bounded retry of the network-dependent half. 3 attempts × 5 s
# backoff covers the early-boot races (miner-agent's vsock push
# arriving a beat after our listener, KBS LB warm-up) without giving a
# tampering miner a meaningful oracle.
KEK_TMP=$(mktemp -p /run/hippius kek.XXXXXX)
chmod 0600 "$KEK_TMP"
attempt=1
max_attempts="${HIPPIUS_NET_RETRIES:-3}"
while :; do
    # SUBSHELL is load-bearing: the core's failure paths call
    # hippius_die → `exit 1`, which must kill only THIS attempt, not
    # the runner (or the retry loop would be dead code). The subshell
    # inherits the HIPPIUS_* vars hippius_prepare set; the KEK lands
    # in the $KEK_TMP file, which outlives the subshell.
    if ( hippius_acquire "$KEK_TMP" ); then
        break
    fi
    if [ "$attempt" -ge "$max_attempts" ]; then
        hippius_die "release acquire failed after ${attempt} attempts"
    fi
    attempt=$((attempt + 1))
    hippius_log "acquire failed; retry ${attempt}/${max_attempts} in 5s"
    sleep 5
done
# Re-assert the 32-byte invariant in the runner's own shell (the
# subshell's checks passed, but the file is the contract here).
kek_bytes=$(wc -c < "$KEK_TMP")
if [ "${kek_bytes:-0}" -ne 32 ]; then
    shred -u "$KEK_TMP" 2>/dev/null || rm -f "$KEK_TMP"
    hippius_die "staged KEK is ${kek_bytes} bytes; expected 32"
fi

# Atomic publish: crypttab points at /run/hippius/kek; mv within the
# same tmpfs is atomic, so systemd-cryptsetup can never observe a
# partial keyfile.
mv "$KEK_TMP" /run/hippius/kek
chmod 0600 /run/hippius/kek

hippius_log "KEK staged at /run/hippius/kek; systemd-cryptsetup will unlock"
exit 0
