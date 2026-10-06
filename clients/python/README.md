# hippius-validator-client

A typed Python SDK (sync + async) for the Hippius validator (vali)
VM-lifecycle HTTP API. Wraps the tenant-bake, launch, and lifecycle
endpoints so a downstream app (e.g. Django) can drive VM provisioning
without hand-rolling `requests` / `httpx` calls.

## Install

```bash
pip install ./clients/python          # editable-friendly package
# or, for tests / linting:
pip install "./clients/python[dev]"
```

The package is `hippius-validator-client`; the import name is
`hippius_validator_client`. It has no source dependency on vali — it only
speaks the HTTP wire contract.

## Auth & Host header

- Auth is `Authorization: Bearer <ServiceToken>`, where the token belongs to
  a `ServiceClient` the endpoint's permission allows. **Launch / migrate /
  decommission / transition** are root-only — the token must be the
  `orchestration-root` principal (`IsOrchestrationRoot`). Bake create/get and
  VM state/list accept any authenticated `ServiceClient`.
- vali validates the `Host` header against `ALLOWED_HOSTS`. When you call it
  by IP (it is a ClusterIP service, typically reached via
  `kubectl port-forward`), pass `host_header` with an allowed name, e.g.
  `localhost` or `vali.vali.svc.cluster.local`.
- `verify` accepts `True`/`False`/a CA-bundle path (self-signed nginx in
  front of vali → point it at the CA or set `False` for a port-forward).

```python
from hippius_validator_client import HippiusValidatorClient

client = HippiusValidatorClient(
    base_url="https://127.0.0.1:8443",
    token="<orchestration-root service token>",
    host_header="vali.vali.svc.cluster.local",
    verify="/etc/hippius/vali-ca.pem",
    timeout=30,
)
```

## Launch by image (the fast default path)

The quickest way to launch a VM is to name an operator-blessed golden **image**
— no bake step at all. vali resolves the name to the current blessed golden
`bake_id`, so every fresh launch reuses the shared golden base (cache-HIT on the
miner → ~2-3 min boot):

```python
from hippius_validator_client import LaunchRequest

# Discover the launchable image names (each maps to a blessed golden bake).
for img in client.list_images():
    print(img.image_name, img.distro, img.is_golden)   # e.g. "ubuntu ubuntu True"

# Launch by image NAME — no bake_id, no raw artefact fields.
job = client.launch_vm(LaunchRequest(
    tenant_id="tenant-1", user_id="user-1", vm_id="tenant-vm-1",
    lease_id="lease-1", flavor="small", cmdline="console=ttyS0 root=/dev/vda",
    image="ubuntu",                                     # ← the whole disk spec
    # NetBird is ON by default. Use the SHIPPED template as your userdata —
    # it carries the {{NETBIRD_SETUP_KEY}} / {{NETBIRD_HOSTNAME}} placeholders
    # vali substitutes AND the write_files + runcmd that actually enrol the
    # guest. See "NetBird userdata" below; pass enable_netbird=False to opt out.
    # Path is relative to a hippius-compute checkout; fill in
    # ssh_authorized_keys first or the VM boots unreachable.
    userdata=open("docs/operator/userdata-templates/"
                  "netbird-enabled.yaml.example").read(),
    auto_pin_allowlist=True,                            # ← REQUIRED, see below
))
job = client.wait_for_launch(job.job_id)                # -> "succeeded"
```

> ### ⚠️ `auto_pin_allowlist=True` is required, and omitting it fails SILENTLY
>
> **Every** launch through this API — golden or self-baked — bakes per-launch
> values into the **measured** cmdline (a fresh EOL nonce, and the §23
> validator nonce that forms the telemetry challenge — plus, for a legacy
> disk, the per-VM LUKS-header MAC), so **every VM has its own launch
> measurement**. The KBS releases a key
> only for a measurement present in the §22 allowlist, so unless this launch
> pins its own digest the guest is refused (`403`), never unlocks its root disk
> and never reaches `kek_released`. (Observed in practice as a guest sitting in
> the initramfs indefinitely.)
>
> The failure is silent and easy to misread: the `LaunchJob` still reaches
> `succeeded` (it is CAS'd on the miner accepting the order, and nothing on the
> launch path waits for a key release), so `wait_for_launch` returns normally.
> Only `wait_for_boot` shows it, stalling at `booting` and never reaching
> `kek_released`.
>
> It defaults to `False` server-side and the SDK will not flip it for you — set
> it explicitly, or pre-pin the measurement out of band.

`image` and `bake_id` are **mutually exclusive**; an unknown image is rejected
(the launch never falls through to an arbitrary bake). The catalog is
operator-controlled — a tenant only ever names an image, never a bake.

## The provision flow (bake your own image)

A bake is **per-VM** — the LUKS KEK is scoped to `vm_id` — so the self-baked
path is: create a bake, wait for it to succeed, then launch the VM referencing
that bake (`bake_id` auto-resolves the artefact SHAs, LUKS-header MAC, KEK Vault
path and S3 location on the server). `provision_vm` chains all four steps:

```python
from hippius_validator_client import BakeRequest, LaunchRequest

bake = BakeRequest(
    vm_id="tenant-vm-1",
    base_image_url="https://images.example/ubuntu-24.04.qcow2",
    base_image_sha256="<64 hex>",
    size_gb=20,
    kek_vault_path="secret/data/hippius-compute/vms/tenant-vm-1/luks-kek",
    s3_output_bucket="hippius-bakes",
    s3_output_prefix="tenant/tenant-vm-1/",
)

launch = LaunchRequest(
    tenant_id="tenant-1",
    user_id="user-1",
    vm_id="tenant-vm-1",
    lease_id="lease-1",
    flavor="small",
    cmdline="console=ttyS0 root=/dev/vda",
    # required; staged to Vault. Minimal example, so NetBird is opted out —
    # see "NetBird userdata" below to enable it.
    userdata="#cloud-config\nusers: [...]\n",
    enable_netbird=False,
    auto_pin_allowlist=True,   # REQUIRED here too — see the callout above
    # bake_id is filled in by provision_vm after the bake succeeds
)

job = client.provision_vm(bake=bake, launch=launch)
print(job.state, job.miner_id, job.result)   # -> "succeeded", ...
```

### Step-by-step (sync) — the full tenant lifecycle

```python
# 1. Bake a per-VM disk (legacy LUKS by default; see "Golden bakes" below).
bake = client.create_bake(bake_request)          # 202, state "queued"
bake = client.wait_for_bake(bake.bake_id)        # polls to "succeeded"

# 2. Launch, referencing the bake (bake_id resolves the artefact SHAs, LUKS
#    header MAC, KEK Vault path and S3 location server-side).
launch_request.bake_id = bake.bake_id
job = client.launch_vm(launch_request)           # 202, state "queued"
job = client.wait_for_launch(job.job_id)         # polls to "succeeded"

# 3. Wait for the guest to boot and surface its SSH-reachable overlay IP.
for step in client.wait_for_boot(job.vm_id):     # booting → kek_released → running
    print(step.phase.value, step.detail)
ip = client.wait_for_netbird_ip(job.vm_id)       # -> "100.72.1.5"

vm = client.get_vm_state(job.vm_id)              # lifecycle row
print(vm.state, vm.generation, vm.netbird_ip)

# 4. Tear down — the server crypto-erases the disk + revokes the NetBird peer.
dec = client.decommission_vm(job.vm_id)          # 202, DecommissionJob
dec = client.wait_for_decommission(job.vm_id, dec.job_id)   # polls to "done"
assert dec.is_done
```

## NetBird userdata

`enable_netbird` defaults to **True**, and the launch **fails closed** unless
the userdata contains the literal `{{NETBIRD_SETUP_KEY}}` placeholder — vali
mints a one-off setup key and substitutes it in memory, so the key never
touches durable storage.

Passing the placeholder is necessary but **not sufficient**: the guest also has
to *use* it. Use the shipped template rather than hand-rolling userdata —

```
docs/operator/userdata-templates/netbird-enabled.yaml.example
```

— which carries both placeholders vali substitutes (`{{NETBIRD_SETUP_KEY}}` and
`{{NETBIRD_HOSTNAME}}`) plus the `write_files` + `runcmd` that actually enrol
the agent. Userdata that merely *mentions* the placeholder passes intake and
boots fine, but the guest never joins the overlay and `wait_for_netbird_ip`
times out.

The path is relative to a **hippius-compute checkout** — installing the SDK
from a package does not ship it. And the template leaves
`ssh_authorized_keys: []`: fill in your key (or a password) before launching,
or you get a VM that boots, unlocks and joins the overlay but that nothing can
log into.

For a minimal example with no overlay networking, pass `enable_netbird=False`.

## Migration and `wait_for_boot` (0.5.1)

`boot_phase` advances **monotonically** server-side. A §25 migration used to
carry the source's terminal `running` across to the destination, which did not
merely leave a stale value — it permanently **suppressed** the destination's
milestones, because `booting` ranks below `running` and was refused. So
`wait_for_boot` returned immediately and could not be used to wait for a
destination boot at all.

Against a validator carrying the fix, a migrated VM restarts at `""` and
progresses again, so `wait_for_boot` works after `migrate_vm`. Against an
older one it still returns immediately — treat "no steps yielded right after a
migrate" as **cannot tell**, not as **booted**.

`wait_for_netbird_ip` behaves differently, and needs a warning rather than a
reassurance. The IP is **preserved** across a migration rather than cleared,
and it is correct whenever the guest rejoins as the same peer — its NetBird
identity travels on the migrated disk and nothing re-mints a key or revokes
the source peer.

But the setup key is minted **ephemeral**, so NetBird can garbage-collect a
peer that stays offline past that window, and a cold migration can exceed it.
The destination cannot re-enrol (cloud-init re-runs the enrolment with the
single-use launch key, already consumed), and nothing re-resolves the field
after 30 minutes from launch. So a post-migration IP is **last known**, not
verified reachable — confirm with a real connection before relying on it.

It is preserved rather than cleared because clearing is strictly worse: a
cleared field would stay permanently blank, since the server stops re-resolving
30 minutes after launch and every migration candidate is older than that.

## Attestation: `attested` can be `null` (0.5.0)

`get_vm_attestation()["attested"]` is a **positive claim only**:

| value | meaning |
| --- | --- |
| `True` | proven — a fresh live attestation, or the KBS release bundle |
| `null` | **unknown** — neither came back |

It is **never `False` on absent evidence**. Absence is ambiguous: the KBS
release archive does not survive a KBS restart, and a VM launched before live
attestation existed has no live samples, so "nothing on record" covers both
"never attested" and "attested but unrecorded".

> **Breaking vs 0.4.0.** `if not resp["attested"]` now treats *unknown* as
> *not attested* — the exact confusion this change removes. Branch on
> `attestation_state` instead: `attested-live` (a KBS-verified live
> attestation of the current launch within `live_attestation.max_age_s`
> — survives a KBS restart) / `attested-at-boot` (the release bundle in
> `kbs_evidence`) / `stale` / `unavailable` (KBS fetch failed, see
> `kbs_evidence_error`) / `unproven` (nothing on record — not a negative).
> `attestation_status` keeps its three legacy values: `evidence-recorded`
> (`attested-live` or `attested-at-boot`) / `no-evidence-recorded` /
> `evidence-unavailable`.

## Migrating a VM between miners (§25)

A §25 migration is **cold**: the guest is quiesced, its encrypted volume is
snapshotted to object storage, and the destination re-attests and boots at a
new generation. The validator never sees plaintext, and the destination is
activated ONLY after a verified guest-signed source-stopped ack — so the
source can never keep running against the same disk.

```python
job = client.migrate_vm("vm-abc", dest_node_id="miner-node-3")
job = client.wait_for_migration(job.vm_id, job.job_id)   # polls to "done"
assert job.is_done

vm = client.get_vm_state("vm-abc")
print(vm.host, vm.generation)      # -> the destination, generation + 1
```

Because the whole volume moves, this is the slowest lifecycle operation —
`wait_for_migration` defaults to a **1 hour** budget (vs 30 min for the other
poll helpers). It raises `MigrationFailedError` if the job reaches `failed`,
and `HippiusTimeoutError` if it is still running when the budget expires.

> **`done` does not yet prove the guest is serving.** The server marks a
> migration `done` once the destination miner has *launched* the domain, not
> once the guest has attested and unlocked its disk. A destination that boots
> but fails its key release therefore still reports `done`. Until that gate is
> tightened, confirm the workload yourself after a migration — reach the guest
> over its overlay IP rather than trusting the job state. Note also that
> `boot_phase` and `netbird_ip` on the `Vm` row are **not reset** by a
> migration, so they still describe the *source* boot: `wait_for_boot` will
> return immediately on the stale value and cannot be used to wait for a
> destination boot.

> **A migration can take the VM off the overlay.** The guest keeps its
> NetBird identity across the move, but the management-side peer record is
> deleted after ~10 min offline and a cold migration can exceed that — the
> destination cannot re-enrol itself, so the VM comes back **running and
> unreachable**, with `netbird_ip` still showing its old address. The server
> checks this after every migration and reports it as `netbird_status`
> (`""` | `pending` | `ok` | `lost`) on `GET /v1/vm/<vm_id>/state`:
>
> ```python
> vm = client.get_vm_state("tenant-vm-1")
> if vm.netbird_lost:            # netbird_status == "lost"
>     ...  # the overlay IP is stale — the guest needs operator re-enrolment
> ```
>
> `netbird_status` is `None` on an older validator that does not report it;
> `netbird_lost` is then `False` (absence of the signal is not evidence of
> loss).

**Intake errors** (`HippiusApiError.category`). Request-shape and lookup
failures are checked first, then the admission checks (all 409 except
`same-node`):

| category | HTTP | meaning |
| --- | --- | --- |
| `wire` | 400 | body is not a JSON object, or `dest_node_id` is missing / empty / not a string / over 64 chars |
| `not-found` | 404 | no such `vm_id` |
| `vm-not-active` | 409 | the VM is not `Active` |
| `same-node` | **400** | `dest_node_id` is the VM's current host |
| `job-in-flight` | 409 | the VM already has an orchestration job running |
| `miner-unknown` | 409 | a miner has no registered identity — **source or destination** (the VM's current host is resolved first) |
| `platform-id-invalid` | 409 | a miner's registered `platform_id` is malformed (not hex, or not an 8-/64-byte CHIP_ID) so its SNP generation can't be resolved — source or destination |
| `cross-gen` | 409 | the destination is a different SNP generation — it would boot a different measurement and the KBS would refuse the key |
| `not-migratable` | 409 | a **golden** VM whose destination boot tuple can't be resolved from its launch record: almost always one launched before the measured cmdline was persisted (relaunch it), or an unknown flavor. Golden-only — a legacy VM with the same defect passes intake and fails later at dest-activation |
| `no-eol-nonce` | 409 | the launch never baked an EOL nonce, so the stopped-ack could never verify |

**Cancelling.** Only a job still in `draining` can be cancelled — that is the
one state that runs with the VM still `Active` and its guest still running.
From `quiescing` on, the generation fence has flipped the VM to `Migrating`
and the guest has been stopped, so `cancel_migration` returns 409
`past-fence` (recovery there is forward-only).

## Golden bakes (dm-verity overlay)

`BakeRequest` takes an optional `disk_mode`:

- `legacy_luks` (default when omitted) — a per-VM confidential LUKS qcow2 with a
  KEK scoped to `vm_id`. The bake response fills `qcow2_sha256`.
- `golden_verity_overlay` — a shared, non-confidential dm-verity base (no
  per-VM qcow2, no per-VM KEK). The bake response instead fills
  `rootfs_img_sha256`, `rootfs_verity_sha256` and `verity_root_hash`, and
  leaves `qcow2_sha256` null.

```python
bake = BakeRequest(..., disk_mode="golden_verity_overlay")
done = client.wait_for_bake(client.create_bake(bake).bake_id)
assert done.is_golden and done.qcow2_sha256 is None
```

**Golden-ness is transparent at launch.** The launch intent has no
tenant-settable disk mode — the server resolves it from the `bake_id`. The
`provision_vm` / step-by-step flow above is identical for both modes; just set
`disk_mode` on the `BakeRequest`.

## Progress streaming (drive a frontend progress bar)

The poll helpers (`wait_for_bake`, `wait_for_launch`) and `provision_vm` accept
an `on_progress` callback, and there is an `iter_provision` generator — pick
whichever fits your UI. Both emit a typed `ProvisionStep`:

```python
@dataclass
class ProvisionStep:
    phase: ProvisionPhase      # coarse lifecycle phase (enum, str-valued)
    state: str                 # raw wire state ("queued"/"running"/...)
    detail: str                # human-readable, e.g. "placed on miner-node-3"
    pct: int                   # 0-100 progress ESTIMATE derived from phase
    miner_id: str | None       # set once the scheduler places the launch
    reason: str | None         # failure reason on a failed phase
    netbird_ip: str | None     # tenant NetBird overlay IP on the boot steps
    raw: dict                  # the full parsed API row (use any other field)

    @property
    def terminal(self) -> bool: ...   # SUCCEEDED / FAILED / BAKE_FAILED / TIMED_OUT
```

`ProvisionPhase` values, in lifecycle order:

| phase | pct | meaning |
| --- | --- | --- |
| `BAKING` | 20 | bake queued/running |
| `BAKE_SUCCEEDED` | 45 | bake done (milestone — launch follows, **not** terminal) |
| `LAUNCH_QUEUED` | 55 | launch enqueued, awaiting the scheduler |
| `STAGING` | 60 | staging launch secrets (server `phase`) |
| `PLACING` | 70 | scheduler placing on a miner (server `phase`) |
| `DISPATCHING` | 80 | dispatching to the miner (server `phase`) |
| `PLACED` | 80 | scheduler placed it (`miner_id` set — coarse fallback) |
| `SUCCEEDED` | 100 | launch accepted (milestone — the guest boot follows when the server reports it) |
| `BOOTING` | 100 | guest domain started (server `Vm.boot_phase`) |
| `KEK_RELEASED` | 100 | KEK released, unlocking the encrypted disk (server `Vm.boot_phase`) |
| `RUNNING` | 100 | guest fully up + billing (terminal; carries `netbird_ip`) |
| `BAKE_FAILED` | 100 | bake failed (terminal, `reason` set) |
| `FAILED` | 100 | launch failed (terminal, `reason` set) |
| `TIMED_OUT` | 100 | the poll budget elapsed (terminal) |

Against an older validator that does not report guest boot, `SUCCEEDED`
(launch accepted) is the terminal phase. Against a newer one the stream
continues `booting → kek_released → running`, and `RUNNING` (the guest is up)
becomes terminal — its step carries the tenant's NetBird overlay IP once it
resolves. (`RUNNING` doubles as a coarse-fallback launch phase at pct 65 on an
old server that omits the launch `phase` field; in the boot half it is the
terminal 100.)

### Callback: `on_progress`

Fires on **every** poll — the first, each intermediate, and the terminal one.
A callback that raises never crashes the poll loop (the error is logged and
swallowed). `provision_vm` streams the bake phases and then the launch phases
through the same callback:

```python
def on_step(step: ProvisionStep) -> None:
    progress_bar.set(step.pct)                       # 0-100 estimate
    status_line.set(f"{step.phase.value}: {step.detail}")
    if step.terminal and step.phase is not ProvisionPhase.SUCCEEDED:
        status_line.error(step.reason or step.detail)

job = client.provision_vm(bake=bake, launch=launch, on_progress=on_step)
# provision_vm still returns the final LaunchJob and still RAISES on failure.
```

### Iterator: `iter_provision`

Prefer a `for` loop (e.g. to bridge to Server-Sent Events / websockets)? Unlike
`provision_vm`, the iterator does **not** raise on failure — it yields the
terminal step (`FAILED` / `BAKE_FAILED` / `TIMED_OUT`) and stops:

```python
for step in client.iter_provision(bake=bake, launch=launch):
    sse.send({"phase": step.phase.value, "pct": step.pct, "detail": step.detail})
    if step.terminal:
        break
```

Async mirrors both — `on_progress` on the async methods, and
`async for step in client.async_iter_provision(bake=..., launch=...)`.

> **API-granularity note.** `pct` is an **estimate** mapped from the coarse
> phase — the validator exposes no real percentage. Beyond bake/launch `state`
> and `miner_id` (placement), a newer validator also reports the launch job's
> fine-grained `phase` (staging → placing → dispatching) and the guest
> `Vm.boot_phase` (booting → kek_released → running), all of which the SDK
> surfaces as `ProvisionStep`s. The SDK degrades gracefully against an older
> server that omits any of these.

## Guest boot & the NetBird IP

Once the launch is accepted, the guest boots asynchronously on the miner. A
newer validator records the guest's progress on the VM row's `boot_phase`
(`"" → booting → kek_released → running`) and its NetBird overlay IP under
`netbird_ip` (`""` until the overlay peer resolves, then a `100.x.y.z` address
— the SSH-reachable guest IP), both readable via `get_vm_state`.

`provision_vm` / `iter_provision` (and their async twins) automatically
continue past launch-succeeded into these boot phases, emitting a
`ProvisionStep` for each — the `RUNNING` step carries `netbird_ip` once it has
resolved. To wait for just the boot, or just the IP:

```python
# Stream booting → kek_released → running (yields nothing on an old server):
for step in client.wait_for_boot("tenant-vm-1"):
    print(step.phase.value, step.detail, step.netbird_ip)

# Or block until the SSH-reachable overlay IP is known (None on timeout / old
# server that never reports it):
ip = client.wait_for_netbird_ip("tenant-vm-1")   # -> "100.72.1.5"
```

## Async

The async client mirrors every method as `async def` over
`httpx.AsyncClient`:

```python
import asyncio
from hippius_validator_client import AsyncHippiusValidatorClient, BakeRequest, LaunchRequest

async def main() -> None:
    async with AsyncHippiusValidatorClient(base_url, token, host_header="localhost") as client:
        job = await client.provision_vm(bake=bake, launch=launch)
        print(job.state)

asyncio.run(main())
```

## Errors

Every non-2xx response is the uniform envelope `{"error", "category"}` and is
raised as `HippiusApiError` carrying `status`, `error`, `category`, and the
parsed `body`:

```python
from hippius_validator_client import HippiusApiError

try:
    client.launch_vm(intent, userdata="")
except HippiusApiError as e:
    print(e.status, e.category, e.error)   # 400 wire "userdata must be a non-empty string"
```

`category` is a stable machine-readable slug — branch on it rather than the
human message. Common values: `wire`, `bad-field`, `not-found`, `conflict`,
`already-in-flight`, `version-conflict`, `internal`. The poll helpers add
client-side categories: `bake-failed` / `launch-failed` / `migration-failed` /
`decommission-failed` (a polled job reached the terminal `failed` state) and
`client-timeout` (the poll budget elapsed).

## Endpoints wrapped

| Method | Endpoint | Client call |
| --- | --- | --- |
| POST | `/v1/tenant-bakes` | `create_bake` |
| GET | `/v1/tenant-bakes/{bake_id}` | `get_bake` / `wait_for_bake` |
| POST | `/v1/vm/launch` | `launch_vm` |
| GET | `/v1/vm/launch/{job_id}` | `get_launch` / `wait_for_launch` |
| GET | `/v1/vm` | `list_vms` |
| GET | `/v1/vm/{vm_id}/state` | `get_vm_state` / `wait_for_boot` / `wait_for_netbird_ip` |
| GET | `/v1/vm/{vm_id}/attestation` | `get_vm_attestation` |
| POST | `/v1/vm/{vm_id}/transition` | `transition_vm` |
| POST | `/v1/vm/{vm_id}/migrate` | `migrate_vm` |
| GET | `/v1/vm/{vm_id}/migrate/{job_id}` | `get_migration` / `wait_for_migration` |
| POST | `/v1/vm/{vm_id}/migrate/{job_id}/cancel` | `cancel_migration` |
| POST | `/v1/vm/{vm_id}/decommission` | `decommission_vm` |
| GET | `/v1/vm/{vm_id}/decommission/{job_id}` | `get_decommission` / `wait_for_decommission` |
| GET | `/v1/admin/audit/measurements` | `audit_measurements` |

Not wrapped, by design:

- **Worker / guest / miner ingress** — `POST /v1/tenant-bakes/{bake_id}/finalize`,
  `POST /v1/lifecycle/stopped`, and the miner-facing telemetry / scheduler /
  edge-registry / packer paths. These are owned by the bake worker, the
  measured guest, and the miners — not by a downstream API client.
- **Operator-facing admin routes** — the miner admin surface
  (`POST /v1/admin/miner/register`, `GET /v1/admin/miner/list`,
  `POST /v1/admin/miner/{id}/quarantine`) and the price-recommendation
  surface (`GET /v1/price-recommendations` + `/approve` + `/dismiss`). These
  are authenticated but fleet-operator tools rather than tenant lifecycle;
  call them directly if you need them.

## Tests

The HTTP layer is fully mocked (`responses` for sync, `respx` for async) — no
live server needed:

```bash
cd clients/python
pytest -q
ruff check .
```
