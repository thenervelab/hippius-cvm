from __future__ import annotations

from django.apps import AppConfig


class SyntheticConfig(AppConfig):
    """Model-less app — carries only the `vali_synthetic_monitor` command
    and its light/full-tier probe logic. No migrations."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.synthetic"
    verbose_name = "Synthetic monitor"
