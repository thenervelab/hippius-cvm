"""Asynchronous client for the Hippius validator VM-lifecycle HTTP API."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from types import TracebackType
from typing import Any

import httpx

from . import _common
from .errors import (
    BakeFailedError,
    DecommissionFailedError,
    HippiusApiError,
    HippiusTimeoutError,
    LaunchFailedError,
    MigrationFailedError,
)
from .models import (
    Bake,
    BakeRequest,
    DecommissionJob,
    Feasibility,
    Image,
    LaunchJob,
    LaunchRequest,
    MigrationJob,
    OnProgress,
    ProvisionPhase,
    ProvisionStep,
    RegionsReport,
    Vm,
    VmListPage,
    VmPower,
    boot_advanced,
    boot_phase_of,
    reports_boot_phase,
    reports_netbird_ip,
)

_DEFAULT_TIMEOUT = 30.0
_DEFAULT_POLL_INTERVAL = 5.0
_DEFAULT_POLL_TIMEOUT = 1800.0
# Guest boot is fast relative to bake/launch; keep the boot-wait budget bounded
# so a validator that never reports ``boot_phase`` (or a stalled boot) ends the
# provision flow gracefully rather than hanging on the launch-succeeded step.
_DEFAULT_BOOT_TIMEOUT = 600.0
# A §25 migration is COLD: the destination downloads the whole encrypted
# volume (multi-GB) and re-attests before it activates, and the server's own
# dest-activation budget alone is ~20 min. Give the waiter a budget that
# comfortably covers snapshot upload + download + attested boot.
#
# Server worst case is ~55 min (the per-step deadlines reset on each state
# CAS: 5 x 300s + 600s awaiting-source-ack + 1200s dest-activation), so 1 h
# clears it only just. If an operator raises
# ``VALI_ORCHESTRATION_ACTIVATE_TIMEOUT_S``, this client budget becomes the
# binding constraint — pass an explicit ``timeout`` then.
_DEFAULT_MIGRATION_TIMEOUT = 3600.0


class AsyncHippiusValidatorClient:
    """Async client over ``httpx.AsyncClient`` — mirrors the sync client.

    See :class:`hippius_validator_client.client.HippiusValidatorClient` for
    the auth / ``host_header`` notes; every method is the same, as ``async
    def``.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        host_header: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        verify: bool | str = True,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.host_header = host_header
        self.timeout = timeout
        self.verify = verify
        self._client = client or httpx.AsyncClient(verify=verify, timeout=timeout)
        self._owns_client = client is None

    # ── context manager ──────────────────────────────────────────────

    async def __aenter__(self) -> AsyncHippiusValidatorClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # ── low-level ────────────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = _common.build_url(self.base_url, path)
        headers = _common.build_headers(
            self.token, self.host_header, json_body=json_body is not None
        )
        resp = await self._client.request(
            method,
            url,
            headers=headers,
            json=json_body,
            params=params,
            timeout=self.timeout,
        )
        body = _common.parse_json(resp.status_code, resp.text, _httpx_json(resp))
        return _common.handle_response(resp.status_code, body)

    # ── Bakes ────────────────────────────────────────────────────────

    async def create_bake(self, req: BakeRequest) -> Bake:
        """``POST /v1/tenant-bakes`` — queue a per-tenant bake (202)."""
        body = await self._request(
            "POST", "/v1/tenant-bakes", json_body=req.to_body()
        )
        return Bake.from_dict(body)

    async def get_bake(self, bake_id: str) -> Bake:
        """``GET /v1/tenant-bakes/<bake_id>``."""
        body = await self._request("GET", f"/v1/tenant-bakes/{bake_id}")
        return Bake.from_dict(body)

    async def wait_for_bake(
        self,
        bake_id: str,
        *,
        interval: float = _DEFAULT_POLL_INTERVAL,
        timeout: float = _DEFAULT_POLL_TIMEOUT,
        on_progress: OnProgress | None = None,
    ) -> Bake:
        """Poll ``get_bake`` until SUCCEEDED. Raise on FAILED / timeout.

        ``on_progress`` fires on every poll (including the first and terminal
        one) with the current :class:`ProvisionStep`.
        """
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while True:
            bake = await self.get_bake(bake_id)
            _common.emit_progress(on_progress, ProvisionStep.from_bake(bake))
            if bake.is_succeeded:
                return bake
            if bake.is_failed:
                raise BakeFailedError(
                    f"bake {bake_id} failed: {bake.failure_reason}", bake.raw
                )
            if loop.time() >= deadline:
                _common.emit_progress(
                    on_progress,
                    ProvisionStep.timed_out(
                        state=bake.state,
                        detail=f"bake {bake_id} timed out after {timeout}s",
                        raw=bake.raw,
                    ),
                )
                raise HippiusTimeoutError(
                    f"bake {bake_id} not terminal after {timeout}s "
                    f"(state={bake.state})",
                    bake.raw,
                )
            await asyncio.sleep(interval)

    # ── Images (golden-image catalog) ────────────────────────────────

    async def list_images(self) -> list[Image]:
        """``GET /v1/images`` — the operator-blessed golden-image catalog.

        Returns the launchable image NAMES (each mapping to the current
        blessed golden ``bake_id``) you can pass as
        :attr:`LaunchRequest.image` for a fast, cache-HIT launch.
        """
        body = await self._request("GET", "/v1/images")
        return [Image.from_dict(row) for row in body.get("images", [])]

    # ── Pre-sale feasibility ─────────────────────────────────────────

    async def feasibility(
        self,
        flavor: str | None = None,
        *,
        tenant_id: str | None = None,
        user_id: str | None = None,
        region: str | None = None,
    ) -> list[Feasibility]:
        """``GET /v1/scheduler/feasibility`` — can we place it before we sell it?

        Omit ``flavor`` for the whole catalogue (the "what can I sell right
        now" board). Pass ``tenant_id`` / ``user_id`` to get the answer for
        THAT customer — they feed anti-affinity and the per-owner budget —
        rather than for anybody. Pass ``region`` (ISO 3166-1 alpha-2) to ask
        for ONE country — the answer a launch with the same
        :attr:`LaunchRequest.region` would get.

        Read-only: asking never creates a VM or a placement.
        """
        params: dict[str, str] = {}
        if flavor:
            params["flavor"] = flavor
        if tenant_id:
            params["tenant_id"] = tenant_id
        if user_id:
            params["user_id"] = user_id
        if region:
            params["region"] = region
        body = await self._request(
            "GET", "/v1/scheduler/feasibility", params=params
        )
        return [Feasibility.from_dict(row) for row in body.get("flavors", [])]

    async def can_place(
        self,
        flavor: str,
        *,
        tenant_id: str | None = None,
        user_id: str | None = None,
        region: str | None = None,
    ) -> Feasibility:
        """:meth:`feasibility` for ONE flavor — the pre-sale gate.

        Typical use::

            answer = await client.can_place("2xlarge", tenant_id=tenant)
            if answer.verdict == "never":
                raise OutOfStock(answer.reason)   # do NOT take the money
            if not answer.sellable:
                retry_later()                     # fleet full, not broken
        """
        results = await self.feasibility(
            flavor, tenant_id=tenant_id, user_id=user_id, region=region
        )
        # Select by NAME rather than taking the first row. The server
        # filters, but this is a sales gate: a proxy or cache that drops
        # the query parameter would otherwise hand back some other
        # flavor's verdict, and the caller would price on it.
        for row in results:
            if row.flavor == flavor:
                if region and row.region.upper() != region.strip().upper():
                    # The answer is not FOR the region we asked about — a
                    # validator that pre-dates `?region=` ignores the
                    # parameter and answers fleet-wide, with no echo. Selling
                    # "FR" on that answer would place anywhere; refuse it.
                    raise HippiusApiError(
                        200,
                        f"validator did not answer feasibility for region {region!r} "
                        f"(echoed {row.region!r}); it may not support region "
                        "constraints yet",
                        "wire",
                    )
                return row
        # `wire` is the documented category for a response that does not
        # match the contract — which this is: we asked for one flavor and
        # got a body without it.
        raise HippiusApiError(
            200,
            f"validator returned no feasibility row for flavor {flavor!r}",
            "wire",
        )

    # ── Regions ──────────────────────────────────────────────────────

    async def regions(self, *, verified_only: bool = True) -> RegionsReport:
        """``GET /v1/operator/regions`` — where miners exist, with capacity.

        Every region is one the validator DETECTED a miner in (server-observed
        IP + GeoIP, bounded by measured latency, cross-checked against the
        egress of the tenant VMs on that host); miners declare nothing. The
        :attr:`Region.region` codes are what :attr:`LaunchRequest.region` and
        :meth:`can_place` accept.

        ``verified_only=True`` (the default, and the scheduler's own rule)
        counts only miners whose location passed every physical check; pass
        ``False`` to see unverified ones in the per-region counts too. Only
        the non-default is sent, so an older validator keeps answering.
        Operator token required.
        """
        params: dict[str, str] = {}
        if not verified_only:
            params["verified_only"] = "false"
        body = await self._request("GET", "/v1/operator/regions", params=params)
        return RegionsReport.from_dict(body)

    # ── Launch ───────────────────────────────────────────────────────

    async def launch_vm(
        self, intent: LaunchRequest, userdata: str | None = None
    ) -> LaunchJob:
        """``POST /v1/vm/launch`` — enqueue a launch (202). Root-only."""
        body = await self._request(
            "POST", "/v1/vm/launch", json_body=intent.to_body(userdata)
        )
        return LaunchJob.from_dict(body)

    async def get_launch(self, job_id: str) -> LaunchJob:
        """``GET /v1/vm/launch/<job_id>``."""
        body = await self._request("GET", f"/v1/vm/launch/{job_id}")
        return LaunchJob.from_dict(body)

    async def wait_for_launch(
        self,
        job_id: str,
        *,
        interval: float = _DEFAULT_POLL_INTERVAL,
        timeout: float = _DEFAULT_POLL_TIMEOUT,
        on_progress: OnProgress | None = None,
    ) -> LaunchJob:
        """Poll ``get_launch`` until succeeded. Raise on failed / timeout.

        ``on_progress`` fires on every poll (including the first and terminal
        one) with the current :class:`ProvisionStep`.
        """
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while True:
            job = await self.get_launch(job_id)
            _common.emit_progress(on_progress, ProvisionStep.from_launch(job))
            if job.is_succeeded:
                return job
            if job.is_failed:
                raise LaunchFailedError(
                    f"launch {job_id} failed: {job.reason}", job.raw
                )
            if loop.time() >= deadline:
                _common.emit_progress(
                    on_progress,
                    ProvisionStep.timed_out(
                        state=job.state,
                        detail=f"launch {job_id} timed out after {timeout}s",
                        raw=job.raw,
                    ),
                )
                raise HippiusTimeoutError(
                    f"launch {job_id} not terminal after {timeout}s "
                    f"(state={job.state})",
                    job.raw,
                )
            await asyncio.sleep(interval)

    # ── Lifecycle ────────────────────────────────────────────────────

    async def wait_for_boot(
        self,
        vm_id: str,
        *,
        interval: float = _DEFAULT_POLL_INTERVAL,
        timeout: float = _DEFAULT_BOOT_TIMEOUT,
    ) -> AsyncIterator[ProvisionStep]:
        """Poll ``get_vm`` and yield a :class:`ProvisionStep` each time the
        guest ``boot_phase`` advances (booting → kek_released → running),
        stopping at ``running`` (terminal success) or ``timeout``.

        The VM row (with ``boot_phase`` / ``boot_phase_at``) is read from
        ``GET /v1/vm/<vm_id>/state`` via :meth:`get_vm_state`.

        Best-effort and NON-raising: against an older validator that never
        reports ``boot_phase`` it returns immediately having yielded nothing,
        so the provision flow ends cleanly at launch-succeeded. If a newer
        server starts reporting but stalls, the poll gives up at ``timeout``
        — yielding a ``TIMED_OUT`` step only if it had already seen progress.
        """
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        last: ProvisionPhase | None = None
        while True:
            vm = await self.get_vm_state(vm_id)
            phase = boot_phase_of(vm)
            if phase is not None and boot_advanced(last, phase):
                last = phase
                yield ProvisionStep.from_boot(vm)
                if phase is ProvisionPhase.RUNNING:
                    return
            if not reports_boot_phase(vm):
                return  # older validator — no guest-boot reporting
            if loop.time() >= deadline:
                if last is not None:
                    yield ProvisionStep.timed_out(
                        state=vm.state,
                        detail=f"vm {vm_id} boot timed out after {timeout}s",
                        raw=vm.raw,
                    )
                return
            await asyncio.sleep(interval)

    async def wait_for_netbird_ip(
        self,
        vm_id: str,
        *,
        interval: float = _DEFAULT_POLL_INTERVAL,
        timeout: float = _DEFAULT_BOOT_TIMEOUT,
    ) -> str | None:
        """Poll ``get_vm_state`` until the tenant's NetBird overlay IP resolves.

        Returns the ``100.x.y.z`` overlay IP (the SSH-reachable guest address)
        as soon as the server reports a non-empty ``netbird_ip``. Best-effort
        and NON-raising: returns ``None`` if it never resolves within
        ``timeout``, or immediately (after a single GET) against an older
        validator that omits the ``netbird_ip`` key entirely.
        """
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while True:
            vm = await self.get_vm_state(vm_id)
            if vm.netbird_ip:
                return vm.netbird_ip
            if not reports_netbird_ip(vm):
                return None  # older validator — no NetBird reporting
            if loop.time() >= deadline:
                return None
            await asyncio.sleep(interval)

    async def get_vm_state(self, vm_id: str) -> Vm:
        """``GET /v1/vm/<vm_id>/state``."""
        body = await self._request("GET", f"/v1/vm/{vm_id}/state")
        return Vm.from_dict(body)

    async def list_vms(
        self,
        *,
        tenant_id: str | None = None,
        lease_id: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> VmListPage:
        """``GET /v1/vm`` — paginated VM list."""
        params = {
            "tenant_id": tenant_id,
            "lease_id": lease_id,
            "limit": limit,
            "offset": offset,
        }
        body = await self._request(
            "GET", "/v1/vm", params={k: v for k, v in params.items() if v is not None}
        )
        return VmListPage.from_dict(body)

    async def get_vm_attestation(self, vm_id: str) -> dict[str, Any]:
        """``GET /v1/vm/<vm_id>/attestation`` — raw attestation bundle.

        ``attested`` is a POSITIVE claim only: ``True`` when the VM is proven
        attested, ``None`` otherwise — **never** ``False``. ``attestation_state``
        says which proof: ``attested-live`` (a KBS-verified live attestation of
        the current launch, fresh — survives a KBS restart), ``attested-at-boot``
        (the KBS release bundle in ``kbs_evidence``), ``stale``, ``unavailable``
        or ``unproven`` (nothing on record — not proof the VM is unattested).
        ``attestation_status`` is its legacy three-value form —
        ``evidence-recorded`` / ``no-evidence-recorded`` /
        ``evidence-unavailable``.
        """
        return await self._request("GET", f"/v1/vm/{vm_id}/attestation")

    async def transition_vm(
        self,
        vm_id: str,
        to_state: str,
        if_version: int,
        *,
        new_generation: int | None = None,
        migration_dest: str | None = None,
        signed_stopped_ack_hex: str | None = None,
    ) -> Vm:
        """``POST /v1/vm/<vm_id>/transition`` — drive the lifecycle SM. Root-only."""
        payload: dict[str, Any] = {"to_state": to_state, "if_version": if_version}
        if new_generation is not None:
            payload["new_generation"] = new_generation
        if migration_dest is not None:
            payload["migration_dest"] = migration_dest
        if signed_stopped_ack_hex is not None:
            payload["signed_stopped_ack_hex"] = signed_stopped_ack_hex
        body = await self._request(
            "POST", f"/v1/vm/{vm_id}/transition", json_body=payload
        )
        return Vm.from_dict(body)

    async def migrate_vm(self, vm_id: str, dest_node_id: str) -> MigrationJob:
        """``POST /v1/vm/<vm_id>/migrate`` — start a §25 migration. Root-only.

        Returns the job in ``draining``; poll it with :meth:`wait_for_migration`.

        Intake raises :class:`HippiusApiError` with a stable ``category``.
        Request-shape and lookup failures come first:

        - ``wire`` (**400**)      — the body is not a JSON object, or
          ``dest_node_id`` is missing / empty / not a string / over 64 chars.
        - ``not-found`` (**404**) — no such ``vm_id``.

        Then the admission checks, all **409** except ``same-node``:

        - ``vm-not-active``   — the VM is not ``Active``.
        - ``same-node``       — ``dest_node_id`` is the VM's current host
          (**400** — the one admission check that is a 400).
        - ``job-in-flight``   — the VM already has an orchestration job running.
        - ``miner-unknown``   — a miner has no registered identity. This covers
          the **source as well as the destination**: the VM's current host is
          resolved FIRST, so this can mean the miner the VM already runs on.
        - ``platform-id-invalid`` — a miner's registered ``platform_id`` is
          malformed (not hex, or not an 8- or 64-byte CHIP_ID), so its SNP
          generation can't be resolved. Also applies to source or destination.
        - ``cross-gen``       — the destination is a DIFFERENT SNP generation
          (e.g. Turin source → Genoa dest). The destination would boot a
          different launch measurement and the KBS would refuse the key, so
          this is refused at intake rather than hanging.
        - ``not-migratable``  — a GOLDEN VM whose destination boot tuple
          can't be resolved from its launch record: almost always one launched
          before the measured cmdline was persisted (relaunch it to make it
          migratable), or an unknown flavor on the record. Refused BEFORE the
          source is fenced, so the VM is never stranded. Checked for golden
          VMs only — a legacy VM with the same defect passes intake and fails
          later at dest-activation, surfacing on the job's ``reason``.
        - ``no-eol-nonce``    — the launch never baked an EOL nonce, so the
          guest's stopped-ack could never verify.
        """
        body = await self._request(
            "POST",
            f"/v1/vm/{vm_id}/migrate",
            json_body={"dest_node_id": dest_node_id},
        )
        return MigrationJob.from_dict(body)

    async def get_migration(self, vm_id: str, job_id: str) -> MigrationJob:
        """``GET /v1/vm/<vm_id>/migrate/<job_id>``."""
        body = await self._request("GET", f"/v1/vm/{vm_id}/migrate/{job_id}")
        return MigrationJob.from_dict(body)

    async def wait_for_migration(
        self,
        vm_id: str,
        job_id: str,
        *,
        interval: float = _DEFAULT_POLL_INTERVAL,
        timeout: float = _DEFAULT_MIGRATION_TIMEOUT,
    ) -> MigrationJob:
        """Poll ``get_migration`` until the job is terminal.

        Returns the job on ``done`` (the VM is Active on the destination at
        ``new_gen``; the source is fenced and can no longer unlock its disk).
        Raises :class:`MigrationFailedError` on ``failed`` and
        :class:`HippiusTimeoutError` if the job is not terminal within
        ``timeout``.

        .. warning::
           ``done`` does NOT yet prove the guest is serving. The server marks
           the migration done once the destination miner has *launched* the
           domain — not once the guest has attested and unlocked its disk — so
           a destination that boots but fails its key release still reports
           ``done``. Confirm the workload yourself (reach the guest over its
           overlay IP) rather than trusting the job state. ``boot_phase`` and
           ``netbird_ip`` are NOT reset by a migration either: they still
           describe the *source* boot, so :meth:`wait_for_boot` returns
           immediately on the stale value and cannot wait for a dest boot.

        A §25 migration is COLD and moves the whole encrypted volume, so it is
        the slowest lifecycle operation: the destination downloads a multi-GB
        snapshot and re-attests before it activates. ``timeout`` therefore
        defaults to a generous budget rather than the shared poll default.
        """
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while True:
            job = await self.get_migration(vm_id, job_id)
            if job.is_done:
                return job
            if job.is_failed:
                raise MigrationFailedError(
                    f"migration {job_id} failed: {job.reason}", job.raw
                )
            if loop.time() >= deadline:
                raise HippiusTimeoutError(
                    f"migration {job_id} not terminal after {timeout}s "
                    f"(state={job.state})",
                    job.raw,
                )
            await asyncio.sleep(interval)

    async def cancel_migration(self, vm_id: str, job_id: str) -> MigrationJob:
        """``POST /v1/vm/<vm_id>/migrate/<job_id>/cancel``. Root-only.

        Only a job still in ``draining`` can be cancelled: that is the sole
        state that runs with the VM still ``Active`` and its guest still
        RUNNING, so abandoning it is a clean no-op. From ``quiescing`` on, the
        generation fence has flipped the VM to ``Migrating`` AND the guest has
        been gracefully stopped, so a cancel would orphan a powered-off VM —
        §25 recovery there is forward-only.

        Raises :class:`HippiusApiError` (409) with category ``past-fence``
        (the job has advanced past ``draining``) or ``already-terminal``.
        """
        body = await self._request("POST", f"/v1/vm/{vm_id}/migrate/{job_id}/cancel")
        return MigrationJob.from_dict(body)

    # ── Power operations ──────────────────────────────────────────────
    #
    # These move the VM's POWER state, not its lifecycle `state`. A stopped
    # VM stays `active`: that field is the KBS release gate, and the VM must
    # still be able to unlock when it starts again.
    #
    # A stopped VM keeps its reservation — overlay, KEK, anti-rollback
    # counter and its slot on one specific miner — which is what makes
    # `start_vm` able to succeed on the same host, and what the billing
    # layer charges for. The MINER is not paid meanwhile: accrual comes from
    # guest-attested receipts and a stopped guest emits none.

    async def stop_vm(self, vm_id: str) -> VmPower:
        """``POST /v1/vm/<vm_id>/stop`` — graceful stop, reservation kept."""
        return VmPower.from_dict(await self._request("POST", f"/v1/vm/{vm_id}/stop"))

    async def start_vm(self, vm_id: str) -> VmPower:
        """``POST /v1/vm/<vm_id>/start`` — relaunch on the SAME miner.

        Refused for a migrated VM (``generation > 1``): a relaunch bakes
        generation 1, which the KBS anti-rollback fence declines.
        """
        return VmPower.from_dict(await self._request("POST", f"/v1/vm/{vm_id}/start"))

    async def reboot_vm(self, vm_id: str) -> VmPower:
        """``POST /v1/vm/<vm_id>/reboot`` — stop, then start on the same miner.

        A guest can also reboot itself from inside; this is for when it will
        not.
        """
        return VmPower.from_dict(await self._request("POST", f"/v1/vm/{vm_id}/reboot"))

    async def decommission_vm(self, vm_id: str) -> DecommissionJob:
        """``POST /v1/vm/<vm_id>/decommission`` — start a §24 job. Root-only."""
        body = await self._request("POST", f"/v1/vm/{vm_id}/decommission")
        return DecommissionJob.from_dict(body)

    async def get_decommission(self, vm_id: str, job_id: str) -> DecommissionJob:
        """``GET /v1/vm/<vm_id>/decommission/<job_id>``."""
        body = await self._request("GET", f"/v1/vm/{vm_id}/decommission/{job_id}")
        return DecommissionJob.from_dict(body)

    async def wait_for_decommission(
        self,
        vm_id: str,
        job_id: str,
        *,
        interval: float = _DEFAULT_POLL_INTERVAL,
        timeout: float = _DEFAULT_POLL_TIMEOUT,
    ) -> DecommissionJob:
        """Poll ``get_decommission`` until the job is terminal.

        Returns the job on ``done`` (the disk was crypto-erased server-side +
        the NetBird peer revoked). Raises :class:`DecommissionFailedError` on
        ``failed`` and :class:`HippiusTimeoutError` if the job is not terminal
        within ``timeout``.
        """
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while True:
            job = await self.get_decommission(vm_id, job_id)
            if job.is_done:
                return job
            if job.is_failed:
                raise DecommissionFailedError(
                    f"decommission {job_id} failed: {job.reason}", job.raw
                )
            if loop.time() >= deadline:
                raise HippiusTimeoutError(
                    f"decommission {job_id} not terminal after {timeout}s "
                    f"(state={job.state})",
                    job.raw,
                )
            await asyncio.sleep(interval)

    async def audit_measurements(
        self,
        *,
        platform_id: str | None = None,
        vm_id: str | None = None,
        launch_digest: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> dict[str, Any]:
        """``GET /v1/admin/audit/measurements`` — pinned-measurement ledger. Root-only."""
        params = {
            "platform_id": platform_id,
            "vm_id": vm_id,
            "launch_digest": launch_digest,
            "limit": limit,
            "offset": offset,
        }
        return await self._request(
            "GET",
            "/v1/admin/audit/measurements",
            params={k: v for k, v in params.items() if v is not None},
        )

    # ── High-level ───────────────────────────────────────────────────

    async def provision_vm(
        self,
        *,
        bake: BakeRequest,
        launch: LaunchRequest,
        bake_interval: float = _DEFAULT_POLL_INTERVAL,
        bake_timeout: float = _DEFAULT_POLL_TIMEOUT,
        launch_interval: float = _DEFAULT_POLL_INTERVAL,
        launch_timeout: float = _DEFAULT_POLL_TIMEOUT,
        boot_interval: float = _DEFAULT_POLL_INTERVAL,
        boot_timeout: float = _DEFAULT_BOOT_TIMEOUT,
        on_progress: OnProgress | None = None,
    ) -> LaunchJob:
        """End-to-end: create the bake, wait for it, then launch and wait.

        Bakes are per-VM (the KEK is scoped to ``vm_id``), so this is the
        normal provisioning path: ``create_bake`` → ``wait_for_bake`` → fill
        ``launch.bake_id`` (the server resolves the artefact SHAs, KEK and S3
        location from the bake) → ``launch_vm`` → ``wait_for_launch`` →
        ``wait_for_boot`` (the guest boots asynchronously after the miner
        accepts the order).

        ``on_progress`` (if given) fires on every poll of the bake, launch AND
        guest-boot phases, so a frontend can drive one progress bar across the
        whole lifecycle. Raises exactly as before — use
        :meth:`async_iter_provision` for a non-raising, iterate-to-terminal
        stream. The boot-wait is best-effort: against an older validator that
        never reports ``boot_phase`` this returns at launch-succeeded exactly
        as before.
        """
        created = await self.create_bake(bake)
        done = await self.wait_for_bake(
            created.bake_id,
            interval=bake_interval,
            timeout=bake_timeout,
            on_progress=on_progress,
        )
        launch.bake_id = done.bake_id
        job = await self.launch_vm(launch)
        launched = await self.wait_for_launch(
            job.job_id,
            interval=launch_interval,
            timeout=launch_timeout,
            on_progress=on_progress,
        )
        if launched.vm_id:
            async for step in self.wait_for_boot(
                launched.vm_id, interval=boot_interval, timeout=boot_timeout
            ):
                _common.emit_progress(on_progress, step)
        return launched

    async def _aiter_bake(
        self, bake_id: str, *, interval: float, timeout: float
    ) -> AsyncIterator[ProvisionStep]:
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while True:
            bake = await self.get_bake(bake_id)
            yield ProvisionStep.from_bake(bake)
            if bake.is_terminal:
                return
            if loop.time() >= deadline:
                yield ProvisionStep.timed_out(
                    state=bake.state,
                    detail=f"bake {bake_id} timed out after {timeout}s",
                    raw=bake.raw,
                )
                return
            await asyncio.sleep(interval)

    async def _aiter_launch(
        self, job_id: str, *, interval: float, timeout: float
    ) -> AsyncIterator[ProvisionStep]:
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while True:
            job = await self.get_launch(job_id)
            yield ProvisionStep.from_launch(job)
            if job.is_terminal:
                return
            if loop.time() >= deadline:
                yield ProvisionStep.timed_out(
                    state=job.state,
                    detail=f"launch {job_id} timed out after {timeout}s",
                    raw=job.raw,
                )
                return
            await asyncio.sleep(interval)

    async def async_iter_provision(
        self,
        *,
        bake: BakeRequest,
        launch: LaunchRequest,
        bake_interval: float = _DEFAULT_POLL_INTERVAL,
        bake_timeout: float = _DEFAULT_POLL_TIMEOUT,
        launch_interval: float = _DEFAULT_POLL_INTERVAL,
        launch_timeout: float = _DEFAULT_POLL_TIMEOUT,
        boot_interval: float = _DEFAULT_POLL_INTERVAL,
        boot_timeout: float = _DEFAULT_BOOT_TIMEOUT,
    ) -> AsyncIterator[ProvisionStep]:
        """Yield each :class:`ProvisionStep` as the provision progresses.

        Unlike :meth:`provision_vm`, this does NOT raise on a failed /
        timed-out job: it yields the terminal step (``BAKE_FAILED`` /
        ``FAILED`` / ``TIMED_OUT``) and stops. Ideal for an ``async for step
        in client.async_iter_provision(...)`` loop or an SSE / websocket
        bridge.

        Once the launch reaches ``SUCCEEDED`` the stream CONTINUES into the
        guest-boot phases (booting → kek_released → running) via
        :meth:`wait_for_boot`; against an older validator with no boot
        reporting it ends at ``SUCCEEDED`` exactly as before.
        """
        created = await self.create_bake(bake)
        bake_ok = False
        async for step in self._aiter_bake(
            created.bake_id, interval=bake_interval, timeout=bake_timeout
        ):
            yield step
            bake_ok = step.phase is ProvisionPhase.BAKE_SUCCEEDED
        if not bake_ok:
            return
        launch.bake_id = created.bake_id
        job = await self.launch_vm(launch)
        launch_step: ProvisionStep | None = None
        async for step in self._aiter_launch(
            job.job_id, interval=launch_interval, timeout=launch_timeout
        ):
            yield step
            launch_step = step
        if launch_step is not None and launch_step.phase is ProvisionPhase.SUCCEEDED:
            vm_id = str(launch_step.raw.get("vm_id") or "")
            if vm_id:
                async for step in self.wait_for_boot(
                    vm_id, interval=boot_interval, timeout=boot_timeout
                ):
                    yield step


def _httpx_json(resp: httpx.Response) -> Any:
    """Return a callable that decodes ``resp``'s text via httpx's JSON parser."""

    def _loader(_text: str) -> Any:
        return resp.json()

    return _loader
