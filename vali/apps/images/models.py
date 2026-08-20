"""The golden-image catalog — the OPERATOR-controlled trust anchor for
launch-by-image ("golden-everywhere").

A tenant may launch a VM by naming a golden IMAGE (e.g. ``ubuntu``) instead
of a ``bake_id``. This model is the mapping the validator resolves that name
through:

    image_name  →  the CURRENT operator-blessed golden ``bake_id``

The row is written ONLY by the operator (`vali_bless_golden_image`
management command); there is NO tenant-writable endpoint. A tenant supplies
only the image NAME on the launch intent — vali maps it to the blessed bake
via this table — so a tenant can NEVER cause a launch off an un-blessed or
arbitrary bake. That is the whole security value of the catalog: it is the
place (and the only place) where "this bake is blessed for this image" is
recorded, and it is operator-only.

Golden-ness itself stays transparent at launch: the ``image`` field is pure
sugar for "use the current golden bake for this distro". Once the name is
resolved to a ``bake_id`` the EXISTING golden bake resolution path
(`apps.orchestration.launch_jobs._resolve_bake`) runs unchanged.

Field-by-field:

- ``image_name``  the tenant-facing launchable name (unique). Charset-locked
                  to ``[a-z0-9-]{1,64}`` at the bless boundary so it is a safe
                  lookup key (it is not interpolated into any path, but the
                  lock rejects junk early and mirrors ``vm_id``).
- ``distro``      a human distro label for display / discovery
                  (e.g. ``centos-stream-10``). Not load-bearing.
- ``bake_id``     the currently-blessed golden ``TenantBake.bake_id``. A
                  plain string (not a FK) so re-blessing is a one-row update
                  and the launch path re-validates the bake via the existing
                  ``_resolve_bake`` (Succeeded check) — defence in depth if a
                  blessed bake is later removed.
- ``blessed_at``  when the current bake was blessed for this image.
- ``blessed_by``  free-form operator identity recorded for the audit trail.
"""

from __future__ import annotations

from django.db import models


class GoldenImage(models.Model):
    """The current operator-blessed golden bake for one launchable image."""

    image_name = models.CharField(max_length=64, unique=True)
    distro = models.CharField(max_length=64)
    bake_id = models.CharField(max_length=64)
    blessed_at = models.DateTimeField()
    blessed_by = models.CharField(max_length=128, blank=True, default="")

    class Meta:
        ordering = ["image_name"]

    def __str__(self) -> str:
        return f"GoldenImage {self.image_name} → {self.bake_id} ({self.distro})"
