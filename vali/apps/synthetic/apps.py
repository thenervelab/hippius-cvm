from __future__ import annotations

from django.apps import AppConfig


class SyntheticConfig(AppConfig):
    """Carries the `vali_synthetic_monitor` command, its light / full /
    per-miner probe logic, and the per-miner probe ledger (`MinerProbe`)."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.synthetic"
    verbose_name = "Synthetic monitor"
