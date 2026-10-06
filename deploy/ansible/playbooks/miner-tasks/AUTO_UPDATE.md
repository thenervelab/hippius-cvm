# miner-agent auto-update (S3 channel)

> **Disarmed by default.** `miner_auto_update_enabled` defaults to `false`:
> the playbook installs the updater script and units but stops + disables
> `hippius-miner-update.timer` and renders `AUTO_UPDATE_DISABLED=true`.
> `hippius-miner-agent.service` is never touched by this switch. Armed, a
> publish restarts every armed agent within ~15 min, all at once, with no
> canary — so agent rollouts are done by hand, canary first
> ([manual rollout](#manual-rollout--sigkill-swap-canary-first)).

When armed, each miner runs a systemd timer that pulls the latest published
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
- **Whole group:** `miner_auto_update_enabled: false` (the default) in
  `group_vars/miner_nodes.yml`; re-running the playbook stops + disables the
  timer on a previously armed miner. The auto-update tasks are tagged
  `miner_auto_update`, so the switch applies alone, one host at a time,
  without re-running the rest of the agent install:

  ```bash
  cd deploy/ansible
  ansible-playbook -i inventory.yml playbooks/06-miner-bootstrap.yml \
      --limit <miner> --tags miner_auto_update --check --diff
  ansible-playbook -i inventory.yml playbooks/06-miner-bootstrap.yml \
      --limit <miner> --tags miner_auto_update
  # on the miner: disabled / inactive, agent untouched
  systemctl is-enabled hippius-miner-update.timer
  systemctl is-active hippius-miner-update.timer
  ```

## Rollout model — AUTO-LATEST (caveat, armed miners only)

There are no channels/staging: every published `latest.json` rolls to
**every armed miner** within ~15 min (the timer's `RandomizedDelaySec` only
spreads the stampede, it does not gate the rollout). This is why the timer is
disarmed by default and `publish-miner-agent.sh` refuses a real upload without
`--fleet-roll`.

## Manual rollout — SIGKILL swap, canary first

One host at a time, canary first; move to the next host only once the
previous one is healthy.

1. Check `skip_shutdown_teardown = true` under `[host]` in
   `/etc/hippius-miner/config.toml`. Without it a graceful stop destroys
   **every** domain on the host.
2. `virsh list --all > /tmp/domains.before`.
3. Back up the running binary:
   `cp -a /usr/local/bin/hippius-miner-agent /usr/local/bin/hippius-miner-agent.bak-$(date +%s)`.
4. Install the new build (built with `--features snp`):
   `install -m 0755 hippius-miner-agent /usr/local/bin/hippius-miner-agent`.
5. `systemctl kill --signal=SIGKILL hippius-miner-agent`. Do not use
   `systemctl restart`/`stop`. QEMU runs in `machine.slice`, so the domains
   survive. `Restart=on-failure` brings the agent back, and it re-adopts the
   running CVMs.
6. Verify: `journalctl -u hippius-miner-agent` shows `serve — up` and
   `re-adopted N running tenant CVM(s)`, and `virsh list --all` matches
   `/tmp/domains.before`. Rollback = the same swap with the `.bak-*` binary.

## Publishing a build

```bash
export AWS_ACCESS_KEY_ID=...        # writable operator creds
export AWS_SECRET_ACCESS_KEY=...    # (Vault secret/hippius-compute/s3/operator)

deploy/scripts/publish-miner-agent.sh \
    --binary target/release/hippius-miner-agent \
    --tag    "sha-$(git rev-parse --short HEAD)" \
    --fleet-roll \
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
