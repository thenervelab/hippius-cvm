"""§23 'async kick au Packer trigger' — ensure a guest image exists.

When the scheduler creates a `Pending` placement it kicks the PR-G3
Packer trigger so the confidential-guest base image is prepared *if
necessary*. "Kick" here means: idempotently ensure a `guest`
`PackerBuild` row exists — creating a `Queued` row IS the trigger
(the Packer Kubernetes Job picks `Queued` rows up, PR-F*).

This is **best-effort and non-blocking**: the placement does not
wait for the build, and a failed kick never fails the placement.
The `Placement` row is the source of truth; a missing image is
re-kicked on the next placement.
"""

from __future__ import annotations

import logging
import secrets

from django.db import IntegrityError

from apps.identity.models import ServiceClient
from apps.packer.models import PackerBuild, PackerBuildState, PackerImageKind

log = logging.getLogger("apps.scheduler.packer_trigger")

# A guest image is "available or being prepared" in any of these
# states — no kick needed. (`failed` is NOT here: a prior failed
# build should be re-kicked.)
_GUEST_READY_OR_INFLIGHT: tuple[str, ...] = (
    PackerBuildState.QUEUED.value,
    PackerBuildState.RUNNING.value,
    PackerBuildState.SUCCEEDED.value,
)


def ensure_guest_image_build(requested_by: ServiceClient) -> PackerBuild | None:
    """Ensure a `guest` `PackerBuild` exists; return it iff newly kicked.

    Returns the freshly-created `PackerBuild` when this call kicked a
    build, or `None` when an image was already ready / in-flight (or
    the kick lost a race / failed). Never raises — a Packer-trigger
    failure must not abort the caller's placement.
    """
    try:
        existing = PackerBuild.objects.filter(
            image_kind=PackerImageKind.GUEST.value,
            state__in=_GUEST_READY_OR_INFLIGHT,
        ).first()
        if existing is not None:
            return None
        build = PackerBuild.objects.create(
            build_id=secrets.token_hex(16),
            image_kind=PackerImageKind.GUEST.value,
            state=PackerBuildState.QUEUED.value,
            requested_by=requested_by,
        )
        log.info("scheduler kicked guest image build: build_id=%s", build.build_id)
        return build
    except IntegrityError:
        # The packer app's partial unique index ("one active build
        # per image_kind") rejected a concurrent kick — another
        # caller already triggered it. Benign.
        log.info("guest image packer kick lost a race — already in flight")
        return None
    except Exception:  # noqa: BLE001 — best-effort boundary, logged loudly.
        # Any other failure (DB hiccup, etc.) must NOT fail the
        # placement. Logged at exception level so it is never silent.
        log.exception("guest image packer kick failed (non-fatal)")
        return None
