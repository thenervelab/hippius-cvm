from __future__ import annotations

from django.apps import AppConfig


class DiskTierConfig(AppConfig):
    """Verified disk tiers (docs/design/disk-tier-verification.md): the
    storage pools and dedicated disks miners offer, the tier a probe proved
    for each, and the probe runs that proved it. Nothing reads these tables
    yet — no placement, billing or reward decision depends on them."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.disktier"
    label = "disktier"
    verbose_name = "vali disk tiers"
