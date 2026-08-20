from __future__ import annotations

from django.apps import AppConfig


class TenantBakeConfig(AppConfig):
    name = "apps.tenant_bake"
    label = "tenant_bake"
    verbose_name = "vali per-tenant encrypted-qcow2 bake trigger"
