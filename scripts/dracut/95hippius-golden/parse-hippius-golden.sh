#!/bin/sh
# `parse-hippius-golden.sh` — dracut `cmdline` hook (priority 30) for the
# GOLDEN-mode boot (dracut module 95hippius-golden). Runs inside
# `dracut-cmdline.service`.
#
# The golden measured cmdline carries NO `root=` token (the guest root is
# an overlayfs the initrd assembles, not a block device systemd can
# mount). Without a claimed root handler dracut warns/waits for a root
# device that never appears. This hook detects golden mode and sets
# `rootok=1` — the SAME signal `90dmsquash-live::parse-dmsquash-live.sh`
# uses for `root=live:...` — so dracut proceeds and lets
# `hippius-golden-mount.service` own `/sysroot` assembly.
#
# GOLDEN signal (fail-closed, identical to the guest overlay lib + the
# miner-agent + the vali emitter): `dm-verity.root=` PRESENT and
# `hippius.luks_header_sha256=` ABSENT. Requiring BOTH conditions
# fail-closes on a half-formed cmdline — and since the cmdline is
# SNP-measured, a miner cannot flip a legacy VM into golden.
#
# This hook ONLY claims the root; it mounts nothing (the systemd mount
# service does that, so the security-load-bearing assembly stays in the
# audited shared library). Claiming rootok on a non-golden cmdline is a
# no-op here.

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

if getarg dm-verity.root= >/dev/null 2>&1 \
    && ! getarg hippius.luks_header_sha256= >/dev/null 2>&1; then
    info "hippius-golden: golden overlay root detected — claiming root (rootok=1)"
    # shellcheck disable=SC2034
    rootok=1
fi
