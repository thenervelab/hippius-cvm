from __future__ import annotations

from django.apps import AppConfig


class CdnConfig(AppConfig):
    """The Hippius CDN fleet (docs/design/cdn.md): its regions, its nodes and
    their lifecycle, and the CDN CA that certifies each node's key. Inert
    while `VALI_CDN_ENABLED` is off."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.cdn"
    label = "cdn"
    verbose_name = "vali CDN fleet"
