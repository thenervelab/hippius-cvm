"""Full end-to-end synthetic probe — SELF-CLEANING.

Every 6 h a CronJob runs this against the LIVE control plane for one
rotated distro: launch a THROWAWAY golden VM through the real public API,
watch it boot + join NetBird, then decommission it via the real §24 API
and verify crypto-erase.

The single most important property is that **the throwaway VM is torn
down on EVERY exit path** — success, failure, exception, or timeout. The
`run_e2e` body is wrapped so that once a launch has been requested, the
`finally` block ALWAYS runs `_teardown`, which:

  1. is a no-op if the VM row is absent or already `destroyed`
     (the happy path already decommissioned it), else
  2. drives the real §24 decommission API to completion, else
  3. force-erases (Vault transit key + KV) and destroys the domain
     in-process as a last resort.

So a stuck / failing run can NEVER leak a synthetic VM or an un-erased
tenant KEK.
"""

from __future__ import annotations

import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from django.conf import settings
from django.utils import timezone

from apps.orchestration import teardown

log = logging.getLogger("apps.synthetic.e2e")

# Fixed rotation — index derived from wall-clock so each 6-h slot picks
# the next distro and every distro is re-proven ~once/day.
DISTRO_ROTATION = ("ubuntu", "debian", "cs10", "fedora")
_ROTATION_PERIOD_S = 6 * 3600

# The REAL product NetBird bring-up userdata (mirrors
# docs/operator/userdata-templates/netbird-enabled.yaml.example, which
# every real tenant launch uses). A bare `netbird up --setup-key <key>`
# does NOT enrol on the golden image — the agent is PRE-INSTALLED at bake
# time and first boot only ENROLS via the setup-key FILE against the real
# management URL, exactly as real tenants do. Using the real template
# makes the synthetic monitor genuinely exercise the NetBird path (a bare
# inline key left the peer un-joined → the netbird stage could never go
# green even on a healthy system). `{{NETBIRD_SETUP_KEY}}` /
# `{{NETBIRD_HOSTNAME}}` are substituted in-memory by the launch service.
# Ordering-cycle canary. A systemd ordering cycle in a golden guest is
# broken by deleting one job per boot, and WHICH job is graph-dependent:
# hippius-eol-sign.service once closed a cycle that systemd broke by
# deleting cloud-init-network.service on Fedora (#1322), while the blessed
# image of the same distro happened to sacrifice a harmless target and
# looked healthy. The monitor has no shell in its guest, but it already
# fails when no NetBird IP appears — so the probe withholds the enrol when
# the boot journal shows ANY ordering cycle. Both the fatal variant (the
# enrol never runs) and the latent one (it runs, but a cycle exists) then
# surface as a failed `netbird` stage instead of a silent green. Only
# systemd's own messages (`_PID=1`) are read: a plain `journalctl -b` also
# holds command lines that contain the phrase (this very guard, if the
# runcmd is ever logged, or an operator's sudo), which would make the
# probe trip on itself.
_ORDERING_CYCLE_GUARD = (
    "if journalctl -b _PID=1 2>/dev/null | grep -qi 'ordering cycle'; then "
    "echo 'hippius-synthetic: systemd ordering cycle in this boot; "
    "NetBird enrol withheld so the monitor alerts' > /dev/console; "
    "else netbird up "
    "--setup-key-file=/var/lib/cloud/seed/nocloud/netbird-setup-key "
    "--management-url=https://vpn.hippius.network "
    "--hostname={{NETBIRD_HOSTNAME}} --no-browser; fi"
)

_DEFAULT_USERDATA = (
    "#cloud-config\n"
    "# Synthetic-monitor throwaway VM — decommissioned within the run.\n"
    "# Mirrors the REAL product NetBird-enabled tenant userdata so the\n"
    "# monitor exercises the actual enrolment path.\n"
    "write_files:\n"
    "  - path: /var/lib/cloud/seed/nocloud/netbird-setup-key\n"
    "    permissions: '0600'\n"
    "    owner: root:root\n"
    "    content: |\n"
    "      {{NETBIRD_SETUP_KEY}}\n"
    "runcmd:\n"
    "  - [ sh, -c, \"" + _ORDERING_CYCLE_GUARD + "\" ]\n"
    # The template's last step: purge the key and cloud-init's copies.
    "  - [ systemd-run, --no-block, -pAfter=cloud-final.service, sh, -c, "
    "\"cd /var/lib/cloud/instances && rm -f */user-data.txt* */cloud-config.txt "
    "*/obj.pkl ../seed/nocloud/netbird-setup-key /run/cloud-init/seed/user-data "
    "/run/cloud-init/combined-cloud-config.json\" ]\n"
)

# Injection seams (tests monkeypatch these).
_now = time.monotonic
_sleep = time.sleep


class ConfigError(Exception):
    """The synthetic monitor is mis-configured (fail loud, don't leak)."""


class ApiError(Exception):
    """A call to the vali public API failed."""


def distro_for(wall_clock_s: float) -> str:
    idx = int(wall_clock_s // _ROTATION_PERIOD_S) % len(DISTRO_ROTATION)
    return DISTRO_ROTATION[idx]


@dataclass
class StageResult:
    name: str
    ok: bool
    duration_s: float
    detail: str


@dataclass
class E2EOutcome:
    distro: str
    vm_id: str
    success: bool
    stages: list[StageResult] = field(default_factory=list)
    teardown_detail: str = ""
    teardown_forced: bool = False


# ── The real-API client (injectable for tests) ───────────────────────


class ApiClient:
    """Thin HTTP client for the vali public API, authenticated as the
    orchestration-root ServiceClient via a Bearer token from a k8s
    Secret. Exercises the REAL `POST /v1/vm/launch` + §24 path."""

    def __init__(self, base: str, token: str, timeout_s: float) -> None:
        if not token:
            raise ConfigError(
                "VALI_SYNTHETIC_ROOT_TOKEN is empty — the full-e2e tier needs "
                "the orchestration-root Bearer token (from the "
                "vali-synthetic-monitor Secret). Refusing to run."
            )
        self._base = base.rstrip("/")
        self._token = token
        self._timeout = timeout_s

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        import json

        url = f"{self._base}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise ApiError(f"{method} {path} → HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise ApiError(f"{method} {path} unreachable: {exc}") from exc

    def launch(self, body: dict) -> dict:
        return self._request("POST", "/v1/vm/launch", body)

    def poll_launch(self, job_id: str) -> dict:
        return self._request("GET", f"/v1/vm/launch/{job_id}")

    def decommission(self, vm_id: str) -> dict:
        return self._request("POST", f"/v1/vm/{vm_id}/decommission", {})

    def poll_decommission(self, vm_id: str, job_id: str) -> dict:
        return self._request("GET", f"/v1/vm/{vm_id}/decommission/{job_id}")


# ── Intent construction ──────────────────────────────────────────────


def _golden_bake_id(distro: str) -> str:
    """The bake a tenant launching `distro` TODAY would actually get.

    Read from the operator-blessed `GoldenImage` catalog — the same lookup
    `launch_jobs._resolve_golden_image` performs for `image=<distro>` — so
    the probe exercises the artifacts real launches use.

    This used to read `VALI_SYNTHETIC_GOLDEN_BAKES`, a hand-maintained JSON
    map of bake_ids. That is a SECOND source of truth for something the
    catalog already owns, and it drifted: on 2026-08-18 all four distros
    were re-blessed and the map still named the previous bakes. Three of
    them kept passing — their old artifacts were still in S3 under their
    own prefixes — so the monitor reported green while testing images no
    tenant could launch. Only debian failed, and only because a later bake
    had overwritten its prefix, which is what finally exposed the drift.

    A monitor pinned to a stale artifact set is worse than no monitor: it
    cannot detect a broken blessed image, and it raises alarms about one
    nobody uses. Reading the catalog makes "the probe passed" and "a tenant
    can launch" the same statement.
    """
    from apps.images.models import GoldenImage

    try:
        golden = GoldenImage.objects.get(image_name=distro)
    except GoldenImage.DoesNotExist:
        known = sorted(GoldenImage.objects.values_list("image_name", flat=True))
        raise ConfigError(
            f"distro {distro!r} is not a blessed golden image "
            f"(catalog has: {known}). Bless it with `vali_bless_golden_image` "
            f"— the monitor deliberately has no private bake list to fall "
            f"back on, because that is what drifted."
        ) from None
    return str(golden.bake_id)


def build_launch_body(distro: str, vm_id: str, bake_id: str | None = None) -> dict:
    """Assemble the `POST /v1/vm/launch` body for a throwaway golden VM.
    The golden `bake_id` resolves the artifact SHAs + verity trio, and
    the launch service provisions the per-VM overlay KEK server-side, so
    the body stays small.

    `bake_id` overrides the blessed catalog lookup — ONLY for the scheduled
    re-bake (F6), which proves a new, not-yet-blessed bake boots before a
    human blesses it. The periodic monitor never passes it."""
    tenant = settings.VALI_SYNTHETIC_TENANT_ID
    userdata = settings.VALI_SYNTHETIC_USERDATA or _DEFAULT_USERDATA
    return {
        "tenant_id": tenant,
        "user_id": tenant,
        "vm_id": vm_id,
        "lease_id": f"synmon-{vm_id}",
        "flavor": settings.VALI_SYNTHETIC_FLAVOR,
        "cmdline": settings.VALI_SYNTHETIC_CMDLINE,
        "bake_id": bake_id or _golden_bake_id(distro),
        "disk_mode": "golden_verity_overlay",
        # Empty platform_id ⇒ the scheduler picks any dispatchable miner.
        "platform_id": "",
        "enable_netbird": True,
        "auto_pin_allowlist": True,
        "userdata": userdata,
    }


# ── The state machine ────────────────────────────────────────────────


def run_e2e(
    *, api: ApiClient, distro: str, budget_s: float, bake_id: str | None = None
) -> E2EOutcome:
    """Drive the full launch→boot→decommission→erase probe for `distro`,
    hard-capped at `budget_s`. ALWAYS tears the VM down before returning.
    `bake_id` targets a specific (possibly unblessed) bake — see
    `build_launch_body`."""
    vm_id = _synthetic_vm_id(distro)
    outcome = E2EOutcome(distro=distro, vm_id=vm_id, success=False)
    deadline = _now() + budget_s
    launched = False
    try:
        # 1) LAUNCH via the real API. Once the POST is attempted, teardown
        #    is MANDATORY — the request may have created a Vm even if the
        #    response then errored, so we must always try to clean it up.
        job = _stage(outcome, "launch", lambda: _do_launch(api, distro, vm_id, bake_id))
        launched = True
        if job is None:
            return _finish(outcome)
        job_id = job["job_id"]

        # Poll the launch job to a terminal state.
        if not _stage(
            outcome,
            "launch_complete",
            lambda: _await_launch(api, job_id, deadline),
        ):
            return _finish(outcome)

        # 2) RELEASE — the guest reached kek-released (KBS released the KEK).
        if not _stage(
            outcome, "release", lambda: _await_boot_phase(vm_id, "kek_released", deadline)
        ):
            return _finish(outcome)

        # 3) KEK_ALIVE — the POSITIVE CONTROL for the crypto_erase stage.
        #    The guest has just been released to, so `kek-<vm_id>` MUST
        #    exist right now. Observing it ALIVE here is what gives the
        #    post-§24 "it is gone" any meaning at all; without it, absence
        #    afterwards is indistinguishable from a KEK that was never
        #    there. See `_verify_kek_alive`.
        #    The observation is CARRIED (not re-asserted as a literal) into
        #    the verify below, so deleting this stage does not leave a
        #    hard-coded `True` behind — it fails to resolve.
        kek_was_alive = _stage(outcome, "kek_alive", lambda: _verify_kek_alive(vm_id))
        if not kek_was_alive:
            return _finish(outcome)

        # 4) BOOT — the guest reached running (cloud-init done).
        if not _stage(outcome, "boot", lambda: _await_boot_phase(vm_id, "running", deadline)):
            return _finish(outcome)

        # 5) NETBIRD — a mesh IP was assigned.
        if not _stage(outcome, "netbird", lambda: _await_netbird(vm_id, deadline)):
            return _finish(outcome)

        # 6) DECOMMISSION via the real §24 API.
        if not _stage(outcome, "decommission", lambda: _do_decommission(api, vm_id, deadline)):
            return _finish(outcome)

        # 7) CRYPTO-ERASE — the KEK (transit key + KV) is gone, domain
        #    stopped. `kek_was_alive` is the stage-3 observation: the
        #    verify REFUSES to certify an erase it has no before-state for.
        if not _stage(
            outcome,
            "crypto_erase",
            lambda: _verify_crypto_erase(vm_id, kek_was_alive=kek_was_alive),
        ):
            return _finish(outcome)

        outcome.success = all(s.ok for s in outcome.stages)
        return _finish(outcome)
    finally:
        # ── The no-leak guarantee ──────────────────────────────────────
        if launched:
            try:
                detail, forced = _teardown(api, vm_id)
                outcome.teardown_detail = detail
                outcome.teardown_forced = forced
            except Exception as exc:  # last-ditch — log, never re-raise
                log.exception("synthetic teardown crashed for %s", vm_id)
                outcome.teardown_detail = f"teardown crashed: {exc}"
                outcome.teardown_forced = True


def _finish(outcome: E2EOutcome) -> E2EOutcome:
    outcome.success = bool(outcome.stages) and all(s.ok for s in outcome.stages)
    return outcome


def _stage(outcome: E2EOutcome, name: str, fn) -> Any:
    """Run one stage, record its result + duration, return the fn value on
    success or None on failure. A raised exception is a failed stage — it
    never propagates past the state machine, so the outer `finally`
    (teardown) still runs when the caller returns early."""
    start = _now()
    try:
        val = fn()
        ok = _stage_ok(val)
        outcome.stages.append(StageResult(name, ok, _now() - start, _stage_detail(val, ok)))
        return val if ok else None
    except Exception as exc:
        log.warning("synthetic stage %s failed: %s", name, exc)
        outcome.stages.append(StageResult(name, False, _now() - start, str(exc)))
        return None


def _stage_ok(val: Any) -> bool:
    # A stage that returns a job dict (launch) is OK; a stage that returns
    # a bool is OK iff True.
    if isinstance(val, dict):
        return True
    return bool(val)


def _stage_detail(val: Any, ok: bool) -> str:
    if isinstance(val, dict):
        return f"job={val.get('job_id', '?')} state={val.get('state', '?')}"
    return "ok" if ok else "failed"


def _synthetic_vm_id(distro: str) -> str:
    # [a-z0-9-]{1,64}; timestamp keeps runs unique + sortable.
    return f"synmon-{distro}-{int(time.time())}"


# ── Stage implementations ────────────────────────────────────────────


def _do_launch(api: ApiClient, distro: str, vm_id: str, bake_id: str | None = None) -> dict:
    body = build_launch_body(distro, vm_id, bake_id)
    job = api.launch(body)
    if not job.get("job_id"):
        raise ApiError(f"launch returned no job_id: {job}")
    log.info("synthetic launch enqueued distro=%s vm=%s job=%s", distro, vm_id, job["job_id"])
    return job


def _await_launch(api: ApiClient, job_id: str, deadline: float) -> bool:
    interval = float(settings.VALI_SYNTHETIC_POLL_INTERVAL_S)
    launch_deadline = min(deadline, _now() + float(settings.VALI_SYNTHETIC_LAUNCH_TIMEOUT_S))
    while _now() < launch_deadline:
        job = api.poll_launch(job_id)
        state = job.get("state")
        if state == "succeeded":
            return True
        if state == "failed":
            raise ApiError(f"launch job failed: {job.get('reason') or job.get('result')}")
        _sleep(interval)
    raise ApiError("launch did not complete within timeout")


def _await_boot_phase(vm_id: str, target: str, deadline: float) -> bool:
    """Poll the Vm row (ORM — the harness IS the vali app) until the
    monotonic boot phase reaches `target`. `booting → kek_released →
    running` is ordered, so 'running' satisfies a 'kek_released' target."""
    from apps.lifecycle.models import Vm

    order = {"booting": 0, "kek_released": 1, "running": 2}
    want = order[target]
    boot_deadline = min(deadline, _now() + float(settings.VALI_SYNTHETIC_BOOT_TIMEOUT_S))
    interval = float(settings.VALI_SYNTHETIC_POLL_INTERVAL_S)
    while _now() < boot_deadline:
        try:
            vm = Vm.objects.get(vm_id=vm_id)
        except Vm.DoesNotExist:
            _sleep(interval)
            continue
        if order.get(vm.boot_phase, -1) >= want:
            return True
        _sleep(interval)
    raise ApiError(f"boot phase {target!r} not reached within timeout")


def _await_netbird(vm_id: str, deadline: float) -> bool:
    from apps.lifecycle.models import Vm

    nb_deadline = min(deadline, _now() + float(settings.VALI_SYNTHETIC_BOOT_TIMEOUT_S))
    interval = float(settings.VALI_SYNTHETIC_POLL_INTERVAL_S)
    while _now() < nb_deadline:
        vm = Vm.objects.filter(vm_id=vm_id).first()
        if vm and vm.netbird_ip:
            return True
        _sleep(interval)
    raise ApiError(
        "no NetBird IP assigned within timeout (the probe withholds the enrol "
        "when the guest's boot journal shows a systemd ordering cycle — check "
        "the serial console for 'hippius-synthetic: systemd ordering cycle')"
    )


def _do_decommission(api: ApiClient, vm_id: str, deadline: float) -> bool:
    job = api.decommission(vm_id)
    job_id = job.get("job_id")
    if not job_id:
        raise ApiError(f"decommission returned no job_id: {job}")
    dec_deadline = min(deadline, _now() + float(settings.VALI_SYNTHETIC_DECOMMISSION_TIMEOUT_S))
    interval = float(settings.VALI_SYNTHETIC_POLL_INTERVAL_S)
    while _now() < dec_deadline:
        cur = api.poll_decommission(vm_id, job_id)
        state = cur.get("state")
        if state == "done":
            return True
        if state == "failed":
            raise ApiError(f"decommission failed: {cur.get('reason')}")
        _sleep(interval)
    raise ApiError("decommission did not complete within timeout")


def _verify_kek_alive(vm_id: str) -> bool:
    """The POSITIVE CONTROL for `_verify_crypto_erase` — assert that the
    per-VM Transit key `kek-<vm_id>` EXISTS while the VM is still running.

    Why this stage exists (and why the monitor was unsound without it):
    `_verify_crypto_erase` proves data-death by observing that the key is
    ABSENT after §24. But absence has two causes, and the post-state alone
    cannot tell them apart:

      * §24 destroyed the key            ⇒ crypto-erase VERIFIED, or
      * the key was NEVER at that name   ⇒ nothing was erased, nothing
                                            could be, and the tenant's real
                                            key material is untouched
                                            somewhere else.

    Every downstream branch treats the second case as a pass: a missing
    Transit key answers "not found" (⇒ `transit_key_gone` True), §24's
    `transit_key_delete` is idempotent on 404 (⇒ SUCCESS), and the KV read
    403s by KEK-HSM design (⇒ accepted as gone). So a regression that stops
    the launch path provisioning `kek-<vm_id>` — or that drifts the name
    between the provisioning and erase paths — would be reported as
    `crypto_erase ok` forever, on the one property the confidential-compute
    design rests on. Observing the key ALIVE first is what turns the check
    into a DIFFERENTIAL (alive → dead) instead of an absence assertion.

    Called after the `release` stage, i.e. after the KBS has released this
    exact KEK to the attested guest, so its existence is not merely
    expected — it is what just happened.

    Cost / safety: probes the SAME stateless route the post-erase check
    uses (`transit/datakey/wrapped/kek-*`, already granted by the
    `vali-orchestrator` policy — no new capability). On a live key that
    route DERIVES a fresh datakey and returns only its WRAPPED ciphertext;
    it does not rotate, mutate or re-version the key, does not touch the KV
    blob the guest booted from, and vali cannot unwrap the result
    (`transit/decrypt` and `transit/datakey/plaintext` stay denied). The
    returned ciphertext is discarded inside `transit_key_gone`, which
    yields only a bool.

    Fail-closed: a denied / ambiguous / unreachable probe raises out of
    `transit_key_gone` rather than being read either way, so a broken probe
    can never manufacture the control it is supposed to provide.
    """
    from apps.orchestration.services import vault_kv

    transit_key = vault_kv.transit_key_name(vm_id)
    if vault_kv.transit_key_gone(transit_key):
        raise ApiError(
            f"transit key {transit_key!r} is ALREADY absent while the VM is "
            "running — the KEK this VM booted with is not at the name §24 "
            "erases, so a later 'key is gone' would prove NOTHING about the "
            "erase (check the launch path's KEK provisioning)"
        )
    return True


def _verify_crypto_erase(vm_id: str, *, kek_was_alive: bool) -> bool:
    """After §24, the per-VM golden KEK must be cryptographically DEAD.

    The STRONGEST proof is that the Vault Transit key `kek-<vm_id>` is
    DESTROYED — once it is gone the wrapped datakey can never be unwrapped,
    so the golden overlay's in-guest LUKS master key is irrecoverable. We
    assert that transit-key death DIRECTLY (the actual data-death signal),
    then confirm the wrapped-KEK KV blob is no longer recoverable BY VALI,
    and that the Vm row is destroyed.

    `kek_was_alive` is the `kek_alive` stage's observation that the key
    EXISTED before the decommission, and it is REQUIRED (keyword-only, no
    default) precisely so this cannot be called without one: a
    destroyed-key assertion with no before-state is satisfied by a key that
    never existed, which is a vacuous pass on the system's central
    confidentiality property. See `_verify_kek_alive`. This is a
    verification precondition, NOT a bypass — it can only ever make the
    check stricter, and there is no value of it that skips an assertion.

    KV note (KEK-HSM): the deployed vali token is DELIBERATELY read-denied
    on `luks-kek` (Phase 1 — only the attested guest ever sees a plaintext
    KEK), so a KV read returns 403, not the 404 an erase would otherwise
    show. Both a 404 (deleted) AND a 403 (read-denied) mean
    "not-recoverable-by-vali" and are treated as gone — NOT a failure. Only
    a clean 2xx read (the ciphertext still readable) is a failure. We do
    NOT rely on a 404 the token can't even observe. That acceptance is
    exactly why the transit-key half needs the positive control: it is the
    ONE half of this check that can actually distinguish present from
    absent.
    """
    from apps.lifecycle.models import Vm, VmState
    from apps.orchestration.services import vault_kv
    from apps.orchestration.services.vault_kv import EffectError, VaultNotFound

    # 0) The before-state MUST have been observed, or nothing below means
    #    anything. Fail closed rather than certify an unfalsifiable erase.
    if kek_was_alive is not True:
        raise ApiError(
            "crypto-erase verify has NO positive control: the KEK was never "
            f"observed alive before the decommission ({kek_was_alive!r}), so "
            "'the transit key is gone' cannot distinguish a successful erase "
            "from a KEK that was never provisioned at that name"
        )

    # 1) THE cryptographic death: BOTH per-VM Transit keys are gone.
    #    `kek-<vm_id>` wraps the disk KEK and the canonical userdata the
    #    KBS releases; `ud-<vm_id>` wraps vali's working copy of the same
    #    cloud-init. A surviving `ud-*` leaves that copy decryptable from
    #    any Vault backup or snapshot, so checking only the first would
    #    certify an erase that did not happen.
    for transit_key in (
        vault_kv.transit_key_name(vm_id),
        vault_kv.userdata_transit_key_name(vm_id),
    ):
        if not vault_kv.transit_key_gone(transit_key):
            raise ApiError(
                f"transit key {transit_key!r} still present after decommission "
                "(the wrapped secret it opens is still recoverable — NOT "
                "crypto-erased)"
            )

    # 2) Defence-in-depth: the wrapped-KEK KV blob is not recoverable by
    #    vali. 404 (deleted) OR 403 (KEK-HSM read-denied) ⇒ gone; only a
    #    clean read means the ciphertext is still present.
    mount = str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret"))
    prefix = str(getattr(settings, "VALI_VAULT_KV_PREFIX", ""))
    kv_path = f"{prefix}/{vm_id}/luks-kek"
    kv_readable = False
    try:
        vault_kv.get_kv(mount, kv_path)
        kv_readable = True
    except VaultNotFound:
        pass  # 404 — deleted, gone.
    except EffectError as exc:
        # 403 — vali is read-denied on luks-kek by KEK-HSM design ⇒ the KV
        # is not recoverable by vali, which is exactly as intended. Any
        # OTHER error (5xx, non-403/404) is a real failure.
        if "HTTP 403" not in str(exc):
            raise ApiError(f"KEK KV read errored (not 404/403): {exc}") from exc
    if kv_readable:
        raise ApiError("KEK KV still readable after decommission (NOT erased)")

    # 2b) The userdata blobs are GONE — and unlike the KEK, vali is not
    #     read-denied on these (the §6 re-mint reads them), so a 404 here
    #     is an observation the token can actually make. That makes this
    #     the half of the erase check with real discriminating power: a
    #     clean read means the tenant's cloud-init survived its VM.
    for leaf in ("userdata", "userdata-pending", "userdata-intake"):
        path = f"{prefix}/{vm_id}/{leaf}"
        try:
            vault_kv.get_kv(mount, path)
        except VaultNotFound:
            continue  # 404 — deleted, gone. The ONLY accepted outcome.
        except EffectError as exc:
            # NOT the 403-means-gone acceptance the KEK read needs: vali is
            # granted READ on these paths (the legacy re-mint fallback uses
            # it), so a 403 here means the ACL changed under us, not that
            # the secret was deleted. Accepting it would let an ACL
            # regression certify an erase nobody performed.
            raise ApiError(
                f"{leaf} KV read did not 404 after decommission ({exc}) — only "
                "an observed absence proves the erase on a path vali may read"
            ) from exc
        raise ApiError(
            f"{leaf} KV still readable after decommission — a destroyed VM's "
            "cloud-init (SSH keys, tokens, the NetBird enrolment secret) "
            "outlived it"
        )

    # 3) The Vm row is destroyed.
    vm = Vm.objects.filter(vm_id=vm_id).first()
    if vm is None or vm.state != VmState.DESTROYED:
        raise ApiError(f"vm state is {getattr(vm, 'state', 'missing')!r}, expected destroyed")
    return True


# ── Teardown — the no-leak safety net ────────────────────────────────
#
# The teardown itself lives in `apps.orchestration.teardown`, shared with
# other in-process throwaway-VM callers. These wrappers bind it to the
# synthetic monitor: §24 through the real public API, the monitor's own
# timeouts, and the module seams (`_now`, `_sleep`, `_force_destroy`) the
# tests patch.

_CANCEL_REASON = "cancelled by synthetic teardown (no-leak)"
_HANDOFF_REASON = "synthetic-reaper:destroy-undeliverable"
_LABEL = "synthetic"


def _teardown(api: ApiClient, vm_id: str) -> tuple[str, bool]:
    """Ensure the synthetic VM is gone. Returns (detail, forced) where
    `forced` marks that the in-process fallback had to run (alertable).
    See `teardown.teardown_vm`."""
    return teardown.teardown_vm(vm_id, **_teardown_kwargs(api))


def _reconcile_pending_launch(api: ApiClient, vm_id: str) -> tuple[str, bool]:
    """No `Vm` row exists — reconcile against a possibly-committed async
    `LaunchJob` so a launch whose response was lost never leaks. See
    `teardown.reconcile_pending_launch`."""
    return teardown.reconcile_pending_launch(vm_id, **_teardown_kwargs(api))


def _teardown_kwargs(api: ApiClient) -> dict[str, Any]:
    return {
        "decommission": lambda vm_id, deadline: _do_decommission(api, vm_id, deadline),
        "force_destroy": _force_destroy,
        "timeout_s": float(settings.VALI_SYNTHETIC_DECOMMISSION_TIMEOUT_S),
        "poll_interval_s": float(settings.VALI_SYNTHETIC_POLL_INTERVAL_S),
        "cancel_reason": _CANCEL_REASON,
        "label": _LABEL,
        "now": _now,
        "sleep": _sleep,
    }


def _force_destroy(vm_id: str) -> str:
    return teardown.force_destroy(vm_id, handoff_reason=_HANDOFF_REASON, label=_LABEL)


# ── Reaper — SIGKILL/OOM/eviction backstop ───────────────────────────


@dataclass
class ReaperResult:
    """Outcome of one reaper sweep. `reaped_total > 0` ⇒ a PRIOR run
    leaked (its in-process `finally` teardown could not run) — a bug worth
    an alert, surfaced via `hippius_synthetic_reaped_total` + `SyntheticLeak`."""

    reaped_vms: list[str] = field(default_factory=list)
    cancelled_jobs: list[str] = field(default_factory=list)
    detail: str = ""

    @property
    def reaped_total(self) -> int:
        return len(self.reaped_vms) + len(self.cancelled_jobs)


def run_reaper() -> ReaperResult:
    """Catch synthetic VMs / launch jobs that a killed run left behind.

    The in-process `finally` teardown (see `run_e2e`) cannot run on
    SIGKILL / OOM / eviction. This backstop — invoked from the frequent
    LIGHT tier — force-tears-down ANY leaked synthetic resource older than
    the reap age (~2 full-run budgets), so a leak is ALWAYS caught within
    one light cycle.

    HARD invariant: it targets ONLY the `synthetic-monitor` tenant, keyed
    strictly on `VALI_SYNTHETIC_TENANT_ID` — it can never touch a real
    tenant's VM or launch job.
    """
    from apps.lifecycle.models import Vm, VmState
    from apps.orchestration.models import (
        TERMINAL_LAUNCH_STATES,
        LaunchJob,
        LaunchJobState,
        LaunchPhase,
    )

    synth = settings.VALI_SYNTHETIC_TENANT_ID
    result = ReaperResult()
    if not synth:
        result.detail = "no synthetic tenant configured — reaper disabled"
        return result

    cutoff = timezone.now() - timezone.timedelta(seconds=int(settings.VALI_SYNTHETIC_REAP_AGE_S))

    # 1) Leaked VMs — any non-destroyed synthetic-tenant VM older than the
    #    reap age. A healthy synthetic VM is gone within one run budget, so
    #    an older one is a definite leak.
    stale_vms = Vm.objects.filter(tenant_id=synth, created_at__lt=cutoff).exclude(
        state=VmState.DESTROYED
    )
    for vm in stale_vms:
        log.warning(
            "synthetic reaper: force-tearing leaked VM %s (state=%s created=%s)",
            vm.vm_id,
            vm.state,
            vm.created_at,
        )
        try:
            _force_destroy(vm.vm_id)
        except Exception:
            log.exception("synthetic reaper: force-destroy crashed for %s", vm.vm_id)
        result.reaped_vms.append(vm.vm_id)

    # 2) Leaked pending launches — non-terminal synthetic LaunchJobs older
    #    than the reap age with no live VM (a VM is handled by (1)). Cancel
    #    via CAS so a stuck/orphaned job never places.
    stale_jobs = LaunchJob.objects.filter(tenant_id=synth, phase_started_at__lt=cutoff).exclude(
        state__in=list(TERMINAL_LAUNCH_STATES)
    )
    for job in stale_jobs:
        if Vm.objects.filter(vm_id=job.vm_id).exclude(state=VmState.DESTROYED).exists():
            continue  # its VM is reaped by (1); don't double-handle
        cancelled = (
            LaunchJob.objects.filter(id=job.id, version=job.version)
            .exclude(state__in=list(TERMINAL_LAUNCH_STATES))
            .update(
                state=LaunchJobState.FAILED.value,
                version=job.version + 1,
                reason="cancelled by synthetic reaper (leaked pending launch)",
                finished_at=timezone.now(),
                phase=LaunchPhase.FAILED.value,
                phase_started_at=timezone.now(),
            )
        )
        if cancelled:
            log.warning("synthetic reaper: cancelled leaked pending launch for %s", job.vm_id)
            result.cancelled_jobs.append(job.vm_id)

    if result.reaped_total:
        result.detail = (
            f"reaped {len(result.reaped_vms)} leaked vm(s), "
            f"cancelled {len(result.cancelled_jobs)} pending launch(es)"
        )
    else:
        result.detail = "no synthetic leaks"
    return result
