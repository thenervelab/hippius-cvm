from __future__ import annotations

from django.apps import AppConfig


class PackerConfig(AppConfig):
    name = "apps.packer"
    label = "packer"
    verbose_name = "vali Packer trigger + S3 presigning"
