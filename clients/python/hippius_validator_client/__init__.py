"""Python SDK for the Hippius validator VM-lifecycle HTTP API.

Public API:

    from hippius_validator_client import (
        HippiusValidatorClient,        # sync (requests)
        AsyncHippiusValidatorClient,   # async (httpx)
        BakeRequest, LaunchRequest,    # typed request models
        Bake, LaunchJob, Vm, ...       # typed response models
        ProvisionStep, ProvisionPhase, # per-poll progress events (streaming)
        OnProgress,                    # on_progress callback type alias
        HippiusApiError,               # {error, category} envelope
    )

The poll helpers (``wait_for_bake`` / ``wait_for_launch``) and ``provision_vm``
accept an ``on_progress`` callback, and ``iter_provision`` /
``async_iter_provision`` yield a ``ProvisionStep`` per poll — so a frontend can
render live per-step provisioning progress.
"""

from __future__ import annotations

from .async_client import AsyncHippiusValidatorClient
from .client import HippiusValidatorClient
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
    HostFit,
    Image,
    LaunchJob,
    LaunchRequest,
    MigrationJob,
    OnProgress,
    ProvisionPhase,
    ProvisionStep,
    Region,
    RegionCapacity,
    RegionsReport,
    Vm,
    VmListPage,
    VmPower,
)

__version__ = "0.5.1"

__all__ = [
    "VmPower",
    "AsyncHippiusValidatorClient",
    "Bake",
    "BakeFailedError",
    "BakeRequest",
    "DecommissionFailedError",
    "DecommissionJob",
    "HippiusApiError",
    "HippiusTimeoutError",
    "HippiusValidatorClient",
    "Feasibility",
    "HostFit",
    "Image",
    "LaunchFailedError",
    "LaunchJob",
    "LaunchRequest",
    "MigrationFailedError",
    "MigrationJob",
    "OnProgress",
    "ProvisionPhase",
    "ProvisionStep",
    "Region",
    "RegionCapacity",
    "RegionsReport",
    "Vm",
    "VmListPage",
    "__version__",
]
