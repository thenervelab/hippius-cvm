from __future__ import annotations

from django.apps import AppConfig


class OperatorConfig(AppConfig):
    """Model-less app — the operator-facing read surface the upstream
    product API assembles a node-operator dashboard from. Reads the
    miner registry, host-attestor and scheduler ledgers; owns no table.
    No migrations."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.operator"
    label = "operator"
    verbose_name = "vali operator node status"
