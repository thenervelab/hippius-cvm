"""The launch `purpose` marker — "this VM is OURS, never pay for it".

Julien's rule: a miner is never paid for hosting our own test VMs. Until
now the only key was `Placement.owner` ∈ the reward-excluded owners
(`scheduler.scoring._excluded_owners`) — right, but it rests on a body
field (`user_id`) any root caller writes and on a config list. `purpose` is
a second key, explicit and AUTHENTICATED:

- `POST /v1/vm/launch` (and the in-process launchers) may name one of
  `PURPOSES`. It is accepted only from vali's own launchers
  (`allowed_principals`): the orchestration-root principal (the synthetic
  CronJobs drive the API with its token), the disk-tier probe's in-process
  actor, and `VALI_LAUNCH_PURPOSE_PRINCIPALS`. Any other caller naming one
  is refused `purpose-forbidden` (403) before anything is staged.
- It is persisted on `LaunchJob.purpose` (never in `spec_json`: an older
  worker would crash on the unknown key mid-roll; the worker hands it to
  `LaunchSpec`) and every `Placement.purpose` of the VM (the launch's own
  rows, and every row that carries the VM's reservation forward).
- It is FIXED by the VM's first launch (`check_fixed`): a later launch can
  neither mark a tenant VM as ours nor clear one of ours, which is what
  makes "any launch or placement of the VM carried it" the VM's purpose.
- A VM with a purpose earns nothing and proves nothing:
  `scheduler.scoring._excluded_vm_ids` (the usage weight AND the priced
  bill), the snapshot weight source, and the earned-capacity fill proof
  (`capacity_earn._live_attested`) all drop it; the launch-terminal
  webhook to the product backend is not sent for it, so the backend never
  learns of it (it bills only VMs it created itself).

Setting a purpose can only REMOVE pay, never add it. Residual: the product
backend authenticates as the same orchestration-root principal the
synthetic CronJobs use, so a compromised or buggy backend could mark a NEW
tenant VM as ours (a miner then loses pay for it; `purpose` is echoed on
the launch job, so it is visible). A dedicated synthetic principal would
close that; the root can already decommission any VM, so it is not a new
power over tenants.

The marker never reaches the miner (not in the order, not on the measured
cmdline): a probe must not be told apart by what we send it.
"""

from __future__ import annotations

from typing import Any

from django.conf import settings

PROBE = "probe"
CANARY = "canary"
LOAD_TEST = "load_test"
SYNMON = "synmon"
PURPOSES: frozenset[str] = frozenset({PROBE, CANARY, LOAD_TEST, SYNMON})

#: `LaunchIntentError` categories (mapped to HTTP by the launch view).
CATEGORY_FORBIDDEN = "purpose-forbidden"
CATEGORY_INVALID = "purpose-invalid"
CATEGORY_FIXED = "purpose-fixed"

#: The disk-tier probe's in-process actor (`apps.disktier.probe.ACTOR_NAME`).
_DISK_PROBE_ACTOR = "disk-probe"


class PurposeError(ValueError):
    def __init__(self, message: str, category: str) -> None:
        super().__init__(message)
        self.category = category


def allowed_principals() -> frozenset[str]:
    """`ServiceClient.name`s whose launches may carry a purpose."""
    names = {
        str(getattr(settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", "") or ""),
        _DISK_PROBE_ACTOR,
        *(str(n) for n in getattr(settings, "VALI_LAUNCH_PURPOSE_PRINCIPALS", ()) or ()),
    }
    return frozenset(n.strip() for n in names if n and n.strip())


def parse(intent: dict[str, Any], decided_by: Any) -> str:
    """The launch's purpose (`""` when it names none). Raises
    `PurposeError`: `purpose-invalid` off the enum, `purpose-forbidden`
    from a caller that is not one of vali's own launchers."""
    raw = intent.get("purpose")
    if raw is None or raw == "":
        return ""
    if not isinstance(raw, str) or raw not in PURPOSES:
        raise PurposeError(
            f"purpose must be one of: {', '.join(sorted(PURPOSES))}", CATEGORY_INVALID
        )
    name = str(getattr(decided_by, "name", "") or "")
    is_operator = bool(getattr(decided_by, "is_operator_principal", False))
    if not is_operator or name not in allowed_principals():
        raise PurposeError(
            "only vali's own launchers may mark a launch with a purpose", CATEGORY_FORBIDDEN
        )
    return raw


def check_fixed(vm_id: str, purpose: str, existing_vm: Any) -> None:
    """A VM's purpose is set by its FIRST launch and never changes: a
    re-POST must carry the purpose its earlier launches carried, and a VM
    that already exists without any launch job (a CLI / legacy row) cannot
    take one. Raises `PurposeError(purpose-fixed)` (409)."""
    from apps.orchestration.models import LaunchJob

    prior = set(LaunchJob.objects.filter(vm_id=vm_id).values_list("purpose", flat=True))
    if prior:
        if prior != {purpose}:
            was = sorted(prior)[-1] or None
            raise PurposeError(
                f"vm {vm_id!r} was launched with purpose {was!r}; it cannot change",
                CATEGORY_FIXED,
            )
        return
    if existing_vm is not None and purpose:
        raise PurposeError(
            f"vm {vm_id!r} already exists without a purpose; only a fresh VM takes one",
            CATEGORY_FIXED,
        )


def purpose_vm_ids() -> frozenset[str]:
    """`vm_id`s launched or placed with a purpose — on a `LaunchJob` OR any
    `Placement` of the VM (either suffices: a VM's purpose never changes).

    Materialised, like the owner set it is unioned with in
    `scoring._excluded_vm_ids`: one epoch read over the partial purpose
    indexes, a few rows per probe (~50 probes a day). The per-node reads use
    `exclude_purpose`'s subqueries instead."""
    from apps.orchestration.models import LaunchJob
    from apps.scheduler.models import Placement

    jobs = LaunchJob.objects.exclude(purpose="").values_list("vm_id", flat=True)
    placed = Placement.objects.exclude(purpose="").values_list("vm__vm_id", flat=True)
    return frozenset(jobs) | frozenset(placed)


def exclude_purpose(placements: Any) -> Any:
    """`placements` (a `Placement` queryset) without OUR VMs: a purpose on
    any launch job or any placement of the VM (a row written by a
    purpose-blind path, e.g. `/v1/scheduler/place`, is still caught) — as
    subqueries over the partial purpose indexes, so a per-node read never
    materialises the whole set."""
    from apps.orchestration.models import LaunchJob
    from apps.scheduler.models import Placement

    return (
        placements.exclude(purpose__gt="")
        .exclude(vm__vm_id__in=LaunchJob.objects.exclude(purpose="").values("vm_id"))
        .exclude(vm__in=Placement.objects.exclude(purpose="").values("vm"))
    )
