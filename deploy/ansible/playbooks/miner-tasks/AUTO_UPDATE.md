# miner-agent auto-update (GitHub Releases)

Each miner runs a systemd timer that installs the latest
`hippius-miner-agent` release of
[`thenervelab/hippius-cvm`](https://github.com/thenervelab/hippius-cvm/releases)
once that release is at least 24 hours old and has been verified. It swaps
the agent without stopping it and puts the previous binary back if the new
one does not deliver a heartbeat. The model is arion's
`arion-miner-update.sh`, adapted to a host that carries tenant CVMs.

> **On by default** (`miner_auto_update_enabled: true` in
> `group_vars/miner_nodes.yml`). The fleet operator's own miners set it to
> `false` in their `host_vars` until a canary has taken a release through
> the updater.

## Flow

```
git tag vYYYY.MM.DD on thenervelab/hippius-cvm
        │
        ▼  .github/workflows/miner-agent-release.yml
build (tag compiled in) ─ rebuild in another dir, bytes must match
        │
        ▼
attest-build-provenance (Sigstore, keyless) → re-verified with the
miner's exact cosign command → GitHub Release:
  hippius-miner-agent-x86_64-linux-gnu
  SHA256SUMS
  BUILD-INFO.txt
  hippius-miner-agent-x86_64-linux-gnu.sigstore.json
        │
        ▼  every 30 min + random 0-6 h, per miner
hippius-miner-update.timer → hippius-miner-update.service
  1. opt-outs (.no-auto-update, AUTO_UPDATE_DISABLED)
  2. update-in-progress left by a cut-short run? finish it if the new
     binary is running and healthy, else roll back
  3. GET api.github.com/repos/thenervelab/hippius-cvm/releases?per_page=20
     → the newest ELIGIBLE tag: complete (binary + SHA256SUMS +
       .sigstore.json, not draft/prerelease), newer than installed, no
       .update-failed-<tag> marker, complete for >= MIN_RELEASE_AGE_H.
       None → exit 0 ("up to date", "waiting", "downgrade refused")
  6. download → sha256 vs SHA256SUMS → cosign attestation → --version == tag
  7. preflight: skip_shutdown_teardown = true, Restart= set, agent active,
     no QEMU anywhere in the agent's cgroup tree, virsh lists the domains
  8. .bak, update-in-progress = <tag>, atomic install, systemctl kill
     --signal=SIGKILL, wait for systemd to relaunch (start it by hand if
     systemd does not)
  9. the relaunched PID stays up and logs outcome=delivered within 5 min
     (a domain gone across the swap → WARNING "DOMAIN-LOSS", update kept)
        │
healthy → installed-release = <tag>, update-in-progress removed
unhealthy → same SIGKILL swap back to .bak, .update-failed-<tag>, exit 1
```

Logs: `journalctl -t hippius-miner-update`.

## Why SIGKILL, never stop/restart

A graceful stop of `hippius-miner-agent` destroys **every** domain on the
host (tenants and the host-attestor) unless the running process started
with `skip_shutdown_teardown = true` under `[host]`. SIGKILL runs no
shutdown path at all. QEMU runs in `machine.slice`, outside the agent's
cgroup, so the domains survive. `Restart=always` brings the agent
back, and it re-adopts the running CVMs.

The updater still refuses to swap without `skip_shutdown_teardown = true`
in `/etc/hippius-miner/config.toml` (logged as `ERROR: refusing to swap`).
Every later graceful stop needs it: `systemctl stop netbird` also stops
the agent, and so does a host shutdown. It also refuses when the unit has
no `Restart=`, when the agent is not running (an operator stopped it), or
when a QEMU process sits inside the agent's cgroup.

The agent unit sets `StartLimitIntervalSec=0`, so systemd's start-rate
limit can never leave it down after a kill. The key takes effect only once
play 05 has re-rendered the unit (it reloads systemd); until then the
updater's own `systemctl start` fallback covers a unit systemd gave up on
(`failed`). The cost: a binary that crash-loops restarts every
`RestartSec` (10 s) until the health window ends and the rollback lands.
The QEMU check is repeated right before every kill, rollback included.

An agent an operator stopped, or is stopping, on purpose is never
started: the swap refuses a stopped agent up front, `deactivating` is
always left alone (a `start` would replace the pending stop), and when a
cut-short run is resumed an `inactive` agent is left stopped, with `.bak`
restored on disk and no marker. Within a run, after the updater's own
kill, `inactive` is a binary that exited cleanly: the agent unit uses
`Restart=always`, and the updater also starts it once itself. If the
rollback still cannot bring it back, the run logs an ERROR and marks the
tag failed.

`/var/lib/hippius-miner/update-in-progress` holds the target tag from
just before the new binary is installed until the update is committed or
rolled back. A run cut short in between (unit timeout, power loss) is
picked up by the next run before anything else: if the binary on disk is
the target tag, the running agent was started after it was installed,
and it delivers a heartbeat, the update is finished as is; otherwise it
is rolled back to `.bak`. With `.no-auto-update` present the next run
does nothing at all, the in-progress file included: remove the flag, or
finish by hand (check `--version`, then write `installed-release` and
delete `update-in-progress`, or reinstall `.bak` with the manual swap).

`scripts/dev/miner-update-test.sh` fails if the updater or its unit ever
calls `systemctl stop`/`restart`, and its `systemctl` mock fails any run
that tries.

## What a miner accepts

All three checks are mandatory, in this order:

1. **sha256**: `SHA256SUMS` lists the asset exactly once and its digest
   matches the download.
2. **Build provenance**: `cosign verify-blob-attestation` of
   `<asset>.sigstore.json` with type `https://slsa.dev/provenance/v1`,
   issuer `https://token.actions.githubusercontent.com`, identity
   `https://github.com/thenervelab/hippius-cvm/.github/workflows/miner-agent-release.yml@refs/tags/<tag>`
   (exact match, no regexp), workflow repository `thenervelab/hippius-cvm`,
   ref `refs/tags/<tag>`, trigger `push`. Cosign also checks the Rekor
   inclusion proof and that the attestation's subject digest is this
   binary. The repository's old name, `thenervelab/hippius-compute`,
   still redirects to another repository; the updater refuses it as
   `RELEASE_REPO`, and the exact identity could never match it anyway.
3. **`--version`**: the downloaded binary prints
   `hippius-miner-agent 0.0.1 (<tag>)`. The release workflow compiles the
   tag in (`HIPPIUS_RELEASE_TAG`); any other build prints `(dev)`.

cosign is installed by the play at
`/usr/local/libexec/hippius-miner/cosign`, version and sha256 pinned in
`miner_cosign`. Its Sigstore trust root (TUF) is cached in
`/var/lib/hippius-miner/sigstore-tuf`.

## Ordering: tags, downgrade, age, retries

- Tags are `vYYYY.MM.DD` or `vYYYY.MM.DD.N` (N = 1-999), compared as the
  integers (YYYY, MM, DD, N), N = 0 when absent:
  `v2026.10.08 < v2026.10.08.1 < v2026.10.09`. Any other shape is
  refused, both by the release workflow and by the updater.
- The installed release is the higher of
  `/var/lib/hippius-miner/installed-release` and the tag compiled into
  the installed binary. Only a strictly newer tag is installed. If
  neither is a release (a source build, or `v2026.10.07`, which predates
  the compiled-in tag), the latest release counts as an upgrade.
- The updater reads the last 20 releases and takes the newest eligible
  one. A release missing any of the three files (its workflow failed, or
  it was published empty: `v2026.10.08`, created by a second workflow
  racing on the tag before releases had one creator) is passed over
  instead of stalling the fleet, and so is a tag dated more than one day
  after the UTC day it was published (the day of slack covers a
  maintainer tagging "today" just after midnight in a UTC+ zone):
  anti-downgrade would otherwise pin the host to
  a mistyped far-future tag. A newer tag that is too young or marked
  failed does not hide an older tag that is eligible.
- A release is skipped until the last of its three files has been
  attached for `MIN_RELEASE_AGE_H` hours (default 24; the clock starts at
  the newest asset `updated_at`, not at the release's `published_at`). A
  bad release can be pulled in that window: delete it, or publish a newer
  fixed tag.
- A domain that was running before the swap and is gone after it is
  logged as `WARNING: DOMAIN-LOSS: …` (`journalctl -t hippius-miner-update
  -g DOMAIN-LOSS`), and the update is kept: tenants stop and orders
  destroy during the window, and a rollback would only SIGKILL the agent
  again without bringing a domain back.
- A tag that failed its health check leaves
  `/var/lib/hippius-miner/.update-failed-<tag>` and is never retried.
  Delete the marker to retry it.

## Disabling auto-update

- **On one miner, now:** `touch /var/lib/hippius-miner/.no-auto-update`.
- **Per host, durably:** `miner_auto_update_enabled: false` in
  `host_vars/<host>.yml`, then apply only the auto-update tasks:

  ```bash
  cd deploy/ansible
  ansible-playbook -i inventory.yml playbooks/06-miner-bootstrap.yml \
      --limit <miner> --tags miner_auto_update --check --diff
  ansible-playbook -i inventory.yml playbooks/06-miner-bootstrap.yml \
      --limit <miner> --tags miner_auto_update
  systemctl is-enabled hippius-miner-update.timer   # disabled
  ```

  That stops and disables the timer and renders
  `AUTO_UPDATE_DISABLED=true`; `hippius-miner-agent.service` is not
  touched.

## Variables (`group_vars/miner_nodes.yml`)

| Variable | Default | |
|---|---|---|
| `miner_auto_update_enabled` | `true` | the switch |
| `miner_auto_update_release_repo` | `thenervelab/hippius-cvm` | where releases come from; also the attested identity |
| `miner_auto_update_min_release_age_h` | `24` | `0` for a canary |
| `miner_auto_update_interval` | `30min` | timer period |
| `miner_auto_update_randomized_delay` | `6h` | random delay added to each firing |
| `miner_auto_update_health_timeout_s` | `300` | heartbeat window before rollback |
| `miner_cosign` | `v3.1.3` + sha256 | the verifier |

## Canary

On one miner, with the release published:

```bash
# host_vars/<canary>.yml
miner_auto_update_enabled: true
miner_auto_update_min_release_age_h: 0
```

Apply with `--tags miner_auto_update`, then on the miner:

```bash
grep -A30 '^\[host\]' /etc/hippius-miner/config.toml | grep skip_shutdown_teardown
virsh list --all > /tmp/domains.before
systemctl start hippius-miner-update.service      # one run, now
journalctl -t hippius-miner-update -n 50 --no-pager
cat /var/lib/hippius-miner/installed-release
/usr/local/bin/hippius-miner-agent --version
virsh list --all | diff /tmp/domains.before -
```

Set `miner_auto_update_min_release_age_h` back to the default afterwards.

## Manual swap (hosts with auto-update off)

1. Check `skip_shutdown_teardown = true` under `[host]` in
   `/etc/hippius-miner/config.toml`.
2. `virsh list --all > /tmp/domains.before`.
3. `cp -a /usr/local/bin/hippius-miner-agent /usr/local/bin/hippius-miner-agent.bak-$(date +%s)`.
4. Verify the release (see "Verifying a release by hand" in
   `docs/operator/onboarding-a-miner.md`), then
   `install -m 0755 hippius-miner-agent-x86_64-linux-gnu /usr/local/bin/hippius-miner-agent`.
5. `systemctl kill --signal=SIGKILL hippius-miner-agent`. Never
   `systemctl restart`/`stop`.
6. Verify: `journalctl -u hippius-miner-agent` shows `serve — up` and
   `re-adopted N running tenant CVM(s)`, and `virsh list --all` matches
   `/tmp/domains.before`. Rollback is the same swap with the `.bak-*`
   binary.
7. `echo <tag> > /var/lib/hippius-miner/installed-release` so a later
   auto-update run knows what is installed.

## Files

| Path | Role |
|------|------|
| `files/hippius-miner-update.sh` | the updater (→ `/usr/local/bin/hippius-miner-update`) |
| `templates/hippius-miner-update.service.j2` | oneshot unit |
| `templates/hippius-miner-update.timer.j2` | timer |
| `templates/auto-update.env.j2` | `/etc/hippius-miner/auto-update.env` |
| `../../../../.github/workflows/miner-agent-release.yml` | builds, attests, publishes |
| `../../../../scripts/release/build-miner-agent.sh` | the build + smoke both release jobs run |
| `../../../../scripts/dev/miner-update-test.sh` | updater tests (mocked GitHub, cosign, systemd) |
