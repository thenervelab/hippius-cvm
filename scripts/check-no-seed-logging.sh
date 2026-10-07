#!/usr/bin/env bash
# §20 "no seed logging" guard — PR-E1.5, §E.
#
# Fails if anything under the initramfs agent's `src/` tree could leak
# secret material to a log / the serial console:
#   1. a `dbg!(` invocation (dumps its argument via `Debug`), or
#   2. a print / log / format macro interpolating a secret-bearing
#      identifier (`{luks}`, `{userdata}`, `{plaintext}`, …).
#
# This mirrors `binaries/agent-initramfs/tests/no_seed_logging.rs` as a
# fast, separately-visible CI gate. Both must stay in sync.
#
# §7: the scan now also covers `binaries/guest-release/src` (the
# cryptsetup keyscript that materialises the released LUKS KEK + the
# user-data + the lifecycle SIGNING key to tmpfs) and `hippius-guest/src`
# (the verify+unwrap library that produces those plaintexts), so a leak
# of the new lifecycle key is caught in every crate that touches it.
#
# CDN I1: `binaries/cdn-agent/src` derives the node key from the
# lifecycle key and unseals certificate keys and zone secrets, so it is
# scanned too, with its secret identifiers (`key_pem`, `session_token`,
# the sealed blobs) added to the list.
set -euo pipefail

# Each entry is a crate src/ tree that handles release plaintext.
SRCS=(
  "binaries/agent-initramfs/src"
  "binaries/guest-release/src"
  "hippius-guest/src"
  "binaries/cdn-agent/src"
)
status=0

for SRC in "${SRCS[@]}"; do
  [ -d "$SRC" ] || continue

  # (1) `dbg!(` is banned outright — it has no `{}` placeholder, so the
  #     interpolation scan in (2) would never see it. Comment lines
  #     (which mention `dbg!()` in prose) are excluded.
  dbg_hits="$(grep -rn --include='*.rs' 'dbg!(' "$SRC" \
              | grep -vE ':[0-9]+:[[:space:]]*//' || true)"
  if [ -n "$dbg_hits" ]; then
    echo "ERROR: dbg!() found in ${SRC} — §20 (no seed logging) forbids it:" >&2
    echo "$dbg_hits" >&2
    status=1
  fi

  # (2) A log / format macro interpolating a secret identifier on the
  #     same line. Comment lines (`file:NN:   // …`) are excluded — a
  #     commented-out line cannot leak.
  macros='println!|eprintln!|print!|eprint!|panic!|write!|writeln!|format!|log::|info!|warn!|error!|debug!|trace!'
  secrets='luks|userdata|user_data|plaintext|passphrase|guest_sk|signing_key|lifecycle_key|seed_bytes|key_pem|session_token|sealed_b64|sealed_blob_b64'
  hits="$(grep -rnE --include='*.rs' "(${macros})" "$SRC" \
          | grep -vE ':[0-9]+:[[:space:]]*//' \
          | grep -E "\{(${secrets})[:}]" || true)"
  if [ -n "$hits" ]; then
    echo "ERROR: a log/format macro interpolates a secret identifier (${SRC}) — §20 violation:" >&2
    echo "$hits" >&2
    status=1
  fi
done

if [ "$status" -eq 0 ]; then
  echo "no-seed-logging: clean."
fi
exit "$status"
