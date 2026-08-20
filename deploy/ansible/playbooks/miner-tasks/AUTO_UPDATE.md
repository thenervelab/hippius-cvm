# miner-agent auto-update (S3 channel)

Each miner runs a systemd timer that pulls the latest published
`hippius-miner-agent` build from Hippius S3, verifies it, installs it
atomically, and rolls back on an unhealthy restart. Modelled on arion's
`arion-miner-update.sh` (GitHub-release driven), adapted to **S3** as the
distribution channel.

## Flow

```
CI / operator builds hippius-miner-agent (--features snp)
        │
        ▼
deploy/scripts/publish-miner-agent.sh  (sha256, optional Ed25519 sign)
        │ uploads (public-read)
        ▼
s3://<bucket>/miner-agent/<tag>/hippius-miner-agent
s3://<bucket>/miner-agent/latest.json   { tag, sha256, url [, sig] }
        │
        ▼  (every ~15 min, randomized, per miner)
hippius-miner-update.timer → hippius-miner-update.service
        │ fetch latest.json → compare sha256 vs installed binary
        │ download → sha256 MUST match → optional sig verify
        │ sanity-run --help → stop → backup → install -m 0755 → start
        │ health-check: is-active AND a fresh delivered heartbeat
        ▼
healthy → drop backup       unhealthy → restore .bak + restart, exit 1
```

## Why sha256, not `--version`

`hippius-miner-agent --version` prints a **static** `hippius-miner-agent 0.0.1`
— the Cargo crate version, which is never bumped. A version compare would never
detect a fresh build. The manifest instead carries the build's `sha256`, and
the updater compares it against `sha256sum /usr/local/bin/hippius-miner-agent`.
Different → a new build was published → update. The `tag` (e.g. `sha-<gitsha>`)
is for human-readable logging only.

## Integrity + signing

- **sha256 over HTTPS (baseline, mandatory):** after download the updater
  recomputes the sha256 and refuses to install unless it equals the manifest's
  `sha256`. The binary is a *client* binary (not a secret), so no read creds are
  needed — integrity comes from the hash served over TLS.
- **Ed25519 signature (optional, future-proof):** set
  `miner_auto_update_pubkey` (group_vars, 64-hex or a PEM path on the miner) to
  pin an operator public key. When set, the updater **requires** the manifest to
  carry a valid `sig` (Ed25519 over the lowercase sha256-hex string, base64).
  `publish-miner-agent.sh --sign-key <ed25519-private.pem>` produces it. Until a
  key is pinned the signature step is skipped — do **not** block rollout on
  signing being set up.

## Health check + rollback

After install + restart the updater requires **both**:
1. `systemctl is-active hippius-miner-agent` is true, and
2. a fresh `heartbeat-pusher: ... outcome=delivered` line appears in the
   journal since the restart (polled up to ~30s).

If either fails it restores the `.bak` binary, restarts the service, and exits
non-zero. A failed run therefore always leaves the **previous, known-good**
binary running.

## Disabling auto-update

- **Per miner:** `touch /var/lib/hippius-miner/.no-auto-update` (the updater
  skips while the sentinel exists). Or set `AUTO_UPDATE_DISABLED=true` in
  `/etc/hippius-miner/auto-update.env`.
- **Whole group:** set `miner_auto_update_enabled: false` in
  `group_vars/miner_nodes.yml` and re-run the playbook — it stops + disables the
  timer.

## Rollout model — AUTO-LATEST (caveat)

There are no channels/staging: every published `latest.json` rolls to the
**entire fleet** within ~15 min (the timer's `RandomizedDelaySec` only spreads
the stampede, it does not gate the rollout). **Only publish validated builds.**
To canary, `touch .no-auto-update` on all but one miner, publish, verify, then
remove the sentinels.

## Publishing a build

```bash
export AWS_ACCESS_KEY_ID=...        # writable operator creds
export AWS_SECRET_ACCESS_KEY=...    # (Vault secret/hippius-compute/s3/operator)

deploy/scripts/publish-miner-agent.sh \
    --binary target/release/hippius-miner-agent \
    --tag    "sha-$(git rev-parse --short HEAD)" \
    # --sign-key ~/.config/hippius/miner-agent-ed25519.pem   # optional
    # --dry-run                                              # print, no upload
```

Defaults: bucket `hippius-compute-images`, prefix `miner-agent`, endpoint
`https://s3.hippius.com` (path-style, SigV4). Override via flags or
`MINER_AGENT_BUCKET` / `MINER_AGENT_PREFIX` / `S3_ENDPOINT_URL`.

## Files

| Path | Role |
|------|------|
| `files/hippius-miner-update.sh` | the updater (→ `/usr/local/bin/hippius-miner-update`) |
| `templates/hippius-miner-update.service.j2` | oneshot unit |
| `templates/hippius-miner-update.timer.j2` | ~15 min timer |
| `templates/auto-update.env.j2` | renders `S3_BASE` (+ `UPDATE_PUBKEY`) |
| `../../group_vars/miner_nodes.yml` | `miner_auto_update_*` vars |
| `../../../scripts/publish-miner-agent.sh` | operator/CI publish side |
