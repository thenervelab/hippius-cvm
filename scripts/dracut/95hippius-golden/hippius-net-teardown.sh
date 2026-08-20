#!/bin/sh
# `hippius-net-teardown` (golden dracut variant) — runs just before
# switch-root via `hippius-net-teardown.service`
# (WantedBy=initrd-switch-root.target, Before=initrd-switch-root.service).
#
# Identical intent to the legacy 90hippius-luks teardown, extended for
# golden's KEK keyfile location:
#   1. Flush the static IPv4 state the release core configured, so the
#      booted system's NetworkManager/cloud-init re-configures a clean
#      NIC instead of stacking a `secondary` address.
#   2. Shred any KEK residue. The golden overlay lib already shreds its
#      own tmpfs keyfile (`/run/hippius-gold-kek.*`) on every exit path;
#      this is belt-and-braces before /run is move-mounted into the real
#      root across the pivot. Also covers the legacy `/run/hippius/kek*`
#      + header paths if ever present.
#
# Fail-quiet: a teardown hiccup must never block switch-root.

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

log() {
    printf 'hippius-net-teardown: %s\n' "$*" > /dev/kmsg 2>/dev/null || true
}

# ── 1. Flush IPv4 state on every non-lo interface ───────────────────
if command -v ip >/dev/null 2>&1; then
    for iface in /sys/class/net/*; do
        name="${iface##*/}"
        [ "$name" = "lo" ] && continue
        [ -d "$iface" ] || continue
        log "flushing IPv4 state on $name"
        ip -4 route flush dev "$name" 2>/dev/null || true
        ip -4 addr flush dev "$name" 2>/dev/null || true
    done
else
    log "ip(8) not found in initrd; skipping net flush"
fi

# ── 2. Wipe any unlock-secret residue from tmpfs ────────────────────
for f in /run/hippius-gold-kek.* /run/hippius/kek /run/hippius/kek.* /run/hippius/luks.header; do
    [ -e "$f" ] || continue
    shred -u "$f" 2>/dev/null || rm -f "$f"
    log "wiped $f"
done

exit 0
