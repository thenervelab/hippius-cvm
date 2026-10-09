# Golden re-bake runbook — monthly re-bake → real-boot checks → human bless

A golden image freezes its packages at bake time. A month after a bless
it typically carries a hundred or so pending security updates
(openssh-server, openssl, sudo, libc6, …). unattended-upgrades then patches each VM's own
overlay upper, so the running root moves away from the measured golden and
every VM downloads the same updates. The fix is to re-bake on a schedule,
with the updates applied inside the measured base.

The machine does the bake and a first boot test. A human does the bless.

| Step | Who | What |
| --- | --- | --- |
| 1. Re-bake | `golden-rebake` CronJob (monthly) | 4 golden bakes with a package refresh, **one at a time** |
| 2. Smoke | same CronJob | synthetic full e2e on each new, **unblessed** bake |
| 3. Real-boot checks | operator | the checklist below, per distro |
| 4. Bless | operator | `vali_bless_golden_image` (never automatic) |

## 1. The re-bake (`vali_scheduled_golden_rebake`)

For each image (`VALI_GOLDEN_REBAKE_IMAGES`, default
`ubuntu,debian,cs10,fedora,cdn-node`) the command:

- clones the **currently blessed** bake's inputs (dated base image URL +
  sha256, size, bucket) into a new golden `TenantBake`:
  - `vm_id` = `golden-<image>-rebake-<YYYYMMDD>`;
  - S3 prefix = `tenant/<vm_id>/`. A golden bake writes fixed keys
    (`rootfs.img`, `rootfs.verity`, …) under its prefix, so a new prefix is
    what keeps the blessed bake's artifacts intact;
  - `package_refresh` = the stamp. The baker then runs `apt-get
    dist-upgrade` (Ubuntu/Debian) or `dnf upgrade` (CentOS Stream 10/Fedora)
    in the chroot before the hippius install. The stamp is part of the
    stage-1 cache key, so the refresh is always a cache MISS and never
    reuses a stage-1 with older packages. A refreshed stage-1 is
    single-use, so it is **not stored** in the cache PVC (no GC there);
  - stage 5 refuses a kernel and initrd built for different kernel
    versions (an upgrade can leave two kernels installed);
- queues it only when **no other bake is in flight**, and waits until it
  is terminal before the next image. Concurrent bake pods race on loop
  devices ("losetup: device node /dev/loopN is lost") and fail;
- the guarantee itself is in `vali_bake_spawn`, the only component that
  creates bake Jobs: a re-bake row (`package_refresh` set) is spawned only
  when no earlier live bake is in flight, and nothing requested after a
  live re-bake row starts before it is terminal. That also covers a bake
  someone queues between the command's check and its insert. Without a
  re-bake row in flight the spawner behaves as before;
- the command's own check and INSERT run under `bake_queue_lock` (a
  Postgres advisory lock), which `POST /v1/tenant-bakes` and
  `vali_tenant_bake_create` also take around their INSERT, so nothing is
  inserted between the check and the re-bake row;
- "live" = every Queued row (the spawner re-spawns them whatever their
  age) plus Running rows claimed less than
  `VALI_TENANT_BAKE_ORPHAN_RUNNING_S` (6 h) ago. An older Running row is
  an orphan whose pod died. It is logged on every run with the command to
  close it — close it explicitly (below) rather than leaving it to the age
  rule;
- stops the whole run if a bake is still in flight when its wait expires
  (the next bake would run next to it). A **Failed** bake does not stop the
  others;
- re-running the same stamp reuses a Succeeded bake and retries a Failed
  one;
- **never touches `GoldenImage`.** Nothing a tenant launches changes;
- with the e2e on, first reaps synthetic-tenant VMs a killed run left
  behind (the synthetic reaper, age-bounded; the light tier also runs it
  every 15 min). The e2e's own `finally` teardown cannot run on SIGKILL.

The e2e pins the new bake's measurement with `auto_pin_allowlist`. The
§22 carry-forward keeps only measurements of VMs that are not
destroyed/failed (plus active host-attestor releases), so once the test
VM is §24'd, that measurement leaves the KBS allowlist at the next pin. It
is not pinned forever, but it stays allowed until some later launch pins.

The base image stays the blessed one; the refresh brings its packages up to
date. Moving to a newer dated upstream image is still a manual bake
(`byo-base-os-bake-runbook.md`).

### Enabling it

Chart `deploy/gitops/apps/vali/values.yaml`, `goldenRebake` (both flags
default `"false"`):

```yaml
goldenRebake:
  enabled: "true"      # monthly re-bake CronJob + its failure alerts
  e2e: "true"          # synthetic full e2e on each new bake
  freshness:
    enabled: "true"    # hourly freshness report + age / awaiting-bless alerts
```

Prerequisite: the tenant baker image must carry `tenant-image-bake.sh
--package-refresh`. An older baker drops the env var and the "re-bake" is a
plain cache HIT of the old packages, so pin a baker built from this change
first (`tenantBake.image.digest` in `values.yaml`).

### Before the first run: close orphaned bakes

A bake row left Running with no pod (its pod died) blocks every re-bake.
For each one, check its Job is gone, then close it:

```sh
kubectl -n vali get job tenant-bake-<bake_id>   # NotFound
kubectl -n vali exec deploy/vali -- python manage.py vali_tenant_bake_close_orphan \
  <bake_id> --reason "no pod since <date>"
```

The command only closes a Running row claimed at least `--min-age-hours`
(6) ago, never a Queued one, and CASes it to `Failed` with an
`orphan closed by operator:` reason. List the others with:

```sh
kubectl -n vali exec deploy/vali -- python manage.py shell -c "
from apps.tenant_bake.models import TenantBake as T
print(list(T.objects.filter(state__in=['queued','running']).values_list('bake_id','vm_id','state','started_at')))"
```

### Running it by hand

```sh
kubectl -n vali create job --from=cronjob/golden-rebake golden-rebake-manual-$(date +%s)
# or, from the vali pod (flag-gated — set it for the one run):
kubectl -n vali exec deploy/vali -- env VALI_GOLDEN_REBAKE_ENABLED=true \
  python manage.py vali_scheduled_golden_rebake --json [--stamp 20261101]
```

`--report-only` only reads the DB and pushes the freshness gauges.

### Metrics and alerts

Pushed to the Pushgateway under `job="golden-rebake"`; alerts in
`templates/prometheusrule-golden-rebake.yaml`.

| Metric | Meaning |
| --- | --- |
| `hippius_golden_blessed_age_days{distro}` | days since the blessed bake was produced |
| `hippius_golden_blessed_bake_timestamp_seconds{distro}` | when it was produced (the age alert keys off this) |
| `hippius_golden_rebake_awaiting_bless{distro}` | 1 = a Succeeded re-bake newer than the blessed one waits for a bless |
| `hippius_golden_rebake_ready_timestamp_seconds{distro}` | when that re-bake finished |
| `hippius_golden_rebake_bake_success{distro}` | last re-bake run's result |
| `hippius_golden_rebake_e2e_success{distro}` | synthetic e2e on the new bake |

| Alert | Fires when |
| --- | --- |
| `GoldenImageStale` | blessed bake older than `freshness.maxAgeDays` (45) |
| `GoldenRebakeAwaitingBless` | a re-bake has waited more than `freshness.awaitingBlessDays` (7) |
| `GoldenFreshnessReportStale` | the hourly report has not pushed for 6 h |
| `GoldenRebakeFailed` | a re-bake did not Succeed, or was never reached after an abort (for 7 d after the run) |
| `GoldenRebakeE2EFailed` | the e2e failed on a new bake — do not bless it (for 7 d after the run) |
| `GoldenRebakeRunIncomplete` | the last run never reported completion within its deadline (killed part-way; re-run by hand, the same stamp reuses Succeeded bakes) |
| `GoldenRebakeRunStale` | no run started in 35 d (CronJob not firing) |

Results are pushed after every image, so a run killed part-way has already
published the images it finished. Any synthetic VM it left behind is reaped
by the synthetic light tier and at the start of the next re-bake run.

A re-bake whose e2e failed (`TenantBake.rebake_e2e_passed = false`) never
counts as awaiting a bless.

Find the new bakes:

```sh
kubectl -n vali exec deploy/vali -- python manage.py shell -c "
from apps.tenant_bake.models import TenantBake as T
for b in T.objects.filter(vm_id__contains='-rebake-').order_by('-requested_at')[:8]:
    print(b.vm_id, b.bake_id, b.state, b.package_refresh, b.finished_at, b.failure_reason)"
```

## 2. Real-boot checks (operator, before any bless)

The synthetic e2e proves launch → KEK release → boot → NetBird → §24. It
does not look inside the guest. Boot one throwaway VM **per distro** on the
new `bake_id` (`launching-a-vm.md`, API path, `"bake_id": "<new id>"`, an
operator tenant id such as `t-rebake-<stamp>`), SSH in over NetBird, and
check:

1. **Packages are current.** `apt list --upgradable 2>/dev/null | wc -l`
   (Ubuntu/Debian) or `dnf -q check-update | wc -l` (CS10/Fedora) is near 0.
   The point of the exercise; record the number.
2. **Data path.** `findmnt /var/lib/hippius-data` shows `ext4` with source
   `/dev/mapper/hippius-upper[/data]`.
3. **SELinux (CS10/Fedora).** `getenforce` = `Enforcing`; `ls -Zd /
   /var/lib/hippius-data` shows real labels (not `unlabeled_t`;
   `var_lib_t` on the data path); `ausearch -m avc -ts boot` is empty.
4. **Nested overlay.** A container runtime works on the data path and is
   refused on `/`: `docker run --rm hello-world` with Docker's root under
   `/var/lib/hippius-data` (Debian/Ubuntu), `podman --root
   /var/lib/hippius-data/podman run --rm quay.io/podman/hello` (CS10/Fedora).
5. **Stamp unreachable.** No `.hippius-volume-stamp` /
   `.hippius-volume-timeline` is visible from the tenant root:
   `find / -xdev -name '.hippius-volume-*' 2>/dev/null` and
   `ls -a /var/lib/hippius-data` show nothing.
6. **#365 data-disk unit masked.** `systemctl is-enabled
   hippius-data-disk.service` = `masked` (link to `/dev/null`).
7. **M0 masks.** `readlink /etc/systemd/system-generators/systemd-ssh-generator`
   and `readlink /etc/systemd/system/serial-getty@ttyS0.service` both =
   `/dev/null`; `rpm -q qemu-guest-agent` / `dpkg -l qemu-guest-agent` = not
   installed; `grep -r fs_label /etc/cloud/cloud.cfg.d/` shows `fs_label:
   null`.
8. **Reboot.** `sudo reboot`; after it comes back, 2. still holds and a
   file written under `/var/lib/hippius-data` before the reboot is intact.

Then `§24`-decommission every throwaway (`POST /v1/vm/<id>/decommission`).

Any failure ⇒ do not bless that distro; open an issue with the bake_id and
the failing check. The other distros can still be blessed.

## 3. Bless (operator only)

```sh
kubectl -n vali exec deploy/vali -- python manage.py vali_bless_golden_image \
  ubuntu <new-ubuntu-bake-id> --blessed-by <you>
# repeat for debian / cs10 (--distro centos-stream-10) / fedora
```

The `ubuntu-keepalive` and `ubuntu-stamped` aliases point at the Ubuntu
bake too; re-point them with the same command, or they keep launching the
old one.

Record the previous bake_ids before blessing: re-blessing them is the
rollback. After the bless, the next synthetic full run tests the new
blessed images (it reads the catalog), and
`hippius_golden_rebake_awaiting_bless` drops to 0 within the hour.

Existing VMs keep their bake; a new golden only reaches new launches.

## cdn-node

`cdn-node` is re-baked with the others: the blessed cdn-node bake is cloned
with `profile=cdn-node` and the current `VALI_CDN_BACKEND_URL` (a bare
https origin, or the image is not re-baked). This is also how a node gets
a new GeoIP database: the database is pinned in
`packer/cdn-node/openresty/geoip.env` and baked from the tenant-baker
image, so the order is: merge the monthly `geoip.env` bump, pin the rebuilt
tenant-baker image, then this re-bake picks it up.

- The synthetic e2e is **not** run on a cdn-node bake: it launches the
  bake as a tenant VM, which a cdn-node image is not.
- A blessed cdn-node with a missing or invalid `VALI_CDN_BACKEND_URL` is
  not re-baked, and shows up as `GoldenRebakeFailed` for `cdn-node`.
- Its real-boot check is the node itself: after `vali_bless_golden_image
  cdn-node`, vali replaces the CDN nodes; check one new node's
  `/__hippius/health` (200, `canary: true`), its journal (`geoip database
  loaded: DBIP-Country-Lite ...`) and a usage sample's `geoip_db`.
