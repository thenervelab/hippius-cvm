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
     (the list read, auto-update-status.json records the check)
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

## First install (play 05)

Play 05 installs the binary with the same script:
`hippius-miner-update --install` (`miner-agent-binary.yml`), when
`/usr/local/bin/hippius-miner-agent` is missing or its `--version` does
not report `versions.miner_agent`. One trust model for both:

- the same selection (step 3), except that the binary in place is not
  trusted for anti-downgrade: only a recorded `installed-release` sets a
  floor, and that tag itself may be installed again;
- the same three checks (step 6), with the same pinned cosign, installed
  just before;
- then `installed-release = <tag>` and an atomic install (in that
  order: a run cut short leaves the binary still foreign, which the next
  play 05 run installs again). Nothing else:
  no `.bak`, no `update-in-progress`, no swap, no health check, and the
  agent is never signalled, started or stopped (a process still running
  an earlier binary keeps it; play 05 says so).

The opt-outs (`.no-auto-update`, `AUTO_UPDATE_DISABLED`) do not apply:
they stop updates, not the first install. No eligible release, an update
run holding the lock, or a cut-short update (`update-in-progress`) is an
error: the play stops with `[MINER_AGENT_INSTALL_FAILED]` and installs
nothing. A binary already reporting `versions.miner_agent` is never
reinstalled by the play: from then on only the timer moves it.

## An exact release (`--tag`, play 05's `miner_agent_version`)

`hippius-miner-update [--install] --tag <tag>` installs exactly `<tag>`:
the release object comes from `releases/tags/<tag>`, the three checks of
step 6 are the same, and the soak does not apply. It refuses a tag that
is not `vYYYY.MM.DD[.N]`, one without a complete release, one with a
`.update-failed-<tag>` marker, and one older than the installed release
(`installed-release`, or the binary's own tag outside `--install`; the
same tag as `installed-release` is allowed), and it does not run over a
cut-short swap (`update-in-progress`; the timer's next run resolves it).
Without `--install` it is
an update (steps 7-10: preflight, SIGKILL swap, health check, rollback),
and nothing at all when the binary already reports `<tag>`. The opt-outs
do not apply (an operator asked), `MIN_RELEASE_AGE_H` is ignored, and
`auto-update.env` is never written: the timer keeps its soak. Play 05 runs
it with `-e miner_agent_version=<tag>`: `--tag` alone when the agent is
active, `--install --tag` otherwise (missing, foreign, or stopped:
nothing to swap).

## Why SIGKILL, never stop/restart

A graceful stop of `hippius-miner-agent` destroys **every** domain on the
host (tenants and the host-attestor) when the running process started
with `skip_shutdown_teardown = false` under `[host]` — or, for releases
before the default flipped to `true`, without the key at all. SIGKILL runs no
shutdown path at all. QEMU runs in `machine.slice`, outside the agent's
cgroup, so the domains survive. `Restart=always` brings the agent
back, and it re-adopts the running CVMs.

The updater still refuses to swap without `skip_shutdown_teardown = true`
in `/etc/hippius-miner/config.toml` (logged as `ERROR: refusing to swap`),
even though current agents treat an absent key as `true`: the binary it
rolls back to may be an older release whose default is still `false`.
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

A rollback to a binary older than the dedicated-disk helpers (no
`dedicated-hold` / `dedicated-release` subcommands) leaves the hold and
release units pointing at subcommands that binary does not have: holds
fail (a launch with dedicated disks is refused, `dedicated-hold-failed`),
release wipes fail and stay queued (the disks read `unavailable`,
`disk-release-pending`), and the running holds keep holding. Nothing is
wiped or attached wrongly, but no dedicated disk is given or freed until a
binary with the helpers is back: on a host with assigned dedicated disks,
roll forward rather than back.

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

Off is an abnormal state: the operator dashboard warns about it (below).
If you cut it, put it back.

## Dashboard: what the node reports

The operator dashboard shows, per node (`GET /v1/operator/nodes`, and the
staff `/v1/operator/fleet` rows):

| Field | Source |
|---|---|
| `agent_version` | the release tag the agent reports in its heartbeat |
| `latest_agent_release` `{tag, published_at, eligible_at}` | vali's own read of the GitHub release list (`vali_agent_release_watch`, the same completeness rule as the updater); `eligible_at` = last required file + 24 h |
| `update_pending` | `agent_version` is older than the newest release past `eligible_at`; `null` when either side is unknown |
| `auto_update` `{enabled, disabled_reason, last_check_at, failed_tag, reported_at}` | the node itself, in its host inventory (`software.auto_update`) |

The node reads `auto_update` from files only; nothing runs the updater:

- `enabled` is false when the first of these applies, in this order
  (`disabled_reason`): `/var/lib/hippius-miner/.no-auto-update` exists
  (`no_auto_update_file`); `AUTO_UPDATE_DISABLED=true` in
  `/etc/hippius-miner/auto-update.env` (`disabled_in_env`);
  `hippius-miner-update.timer` is not enabled, masked, or was never
  installed (`timer_disabled`).
- `last_check_at`: each timer run that reads the release list writes
  `/var/lib/hippius-miner/auto-update-status.json`
  (`{"schema":1,"last_check_unix":<epoch>}`). Opted-out runs, runs that
  cannot reach GitHub, `--install` and `--tag` do not. `null` until the
  first such run (a host still on an older updater script, or a fresh
  install). The report reaches vali every 6 h, and the timer adds up to
  6 h of jitter: older than about 13 h while `enabled` means the timer
  does not run or GitHub is unreachable from the host.
- `failed_tag`: the newest `.update-failed-<tag>` newer than the agent
  reporting. That release is never retried here.
- `auto_update` is `null` when the node does not report it (below), or
  when one of the files exists but cannot be read: unknown, never a
  guess.
- The node reads the default paths only (`/var/lib/hippius-miner`,
  `/etc/hippius-miner/auto-update.env`, `/etc/systemd/system`). A host
  that moves `MINER_STATE_DIR`, points the updater at another env file
  (`HIPPIUS_MINER_UPDATE_ENV`, e.g. a one-off canary copy), or sets
  `AUTO_UPDATE_DISABLED` in a systemd drop-in is reported from the
  defaults. A timer that is enabled but stopped, or whose runs fail
  before reading the release list, shows `enabled: true` with a
  `last_check_at` that stops moving.

### Remedy text

For the dashboard, per `disabled_reason`:

- `no_auto_update_file`: "Auto-update is off on this node. Turn it back
  on: `sudo rm /var/lib/hippius-miner/.no-auto-update`."
- `disabled_in_env` or `timer_disabled`: "Auto-update is off on this
  node. Turn it back on: re-run play 06 with `--tags miner_auto_update`,
  without `miner_auto_update_enabled=false` (remove it from the host's
  `host_vars` and from `-e`)."

  ```bash
  cd deploy/ansible
  ansible-playbook -i inventory.yml playbooks/06-miner-bootstrap.yml \
      --limit <miner> --tags miner_auto_update
  ```

- `failed_tag` set: "Release `<tag>` failed its health check on this node
  and will not be retried. Check `journalctl -t hippius-miner-update`,
  then `sudo rm /var/lib/hippius-miner/.update-failed-<tag>` to retry it,
  or wait for the next release."

One sentence for every case: "Auto-update is off on this node: remove
`/var/lib/hippius-miner/.no-auto-update`, or re-run play 06 with
`--tags miner_auto_update` without `miner_auto_update_enabled=false`."

### Rollout (vali first, then the nodes)

`software.auto_update` is a new key of the host inventory. vali's verifier
decodes it with `deny_unknown_fields`: a vali older than the key refuses
the WHOLE report. So:

1. vali image with the key pinned (and, for `latest_agent_release`,
   `agentReleaseWatch.enabled: "true"` in the vali chart).
2. An agent release that knows `--report-auto-update` rolled to the fleet
   (an older collector exits on the unknown flag: its inventory goes
   stale, the agent itself is not affected).
3. `miner_inventory_report_auto_update: true`, applied with
   `--tags miner_inventory` (the collector units only, no agent restart).

The updater script writes the status file once play 05/06 has installed
this version of it; until then `last_check_at` is `null`.

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
| `miner-agent-binary.yml` | the first install (`--install`), from play 05 |
| `../../../../.github/workflows/miner-agent-release.yml` | builds, attests, publishes |
| `../../../../scripts/release/build-miner-agent.sh` | the build + smoke both release jobs run |
| `../../../../scripts/dev/miner-update-test.sh` | updater tests (mocked GitHub, cosign, systemd) |
