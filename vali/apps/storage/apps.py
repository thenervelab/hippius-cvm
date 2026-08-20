from __future__ import annotations

from django.apps import AppConfig


class StorageConfig(AppConfig):
    name = "apps.storage"
    label = "vali_storage"
    verbose_name = "vali Hippius S3 client abstraction"
