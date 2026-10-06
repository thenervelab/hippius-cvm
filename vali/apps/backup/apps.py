from __future__ import annotations

from django.apps import AppConfig


class BackupConfig(AppConfig):
    """Live backups of running golden VMs into vali's own bucket: the
    per-VM policy, the chains (one full + its incrementals, all taken
    within one boot) and the runs. Restoring from a chain is the §25
    dest-activation with a `backup_chain`; deciding WHEN to restore
    (failover) is not here. See `docs/design/backup-failover.md`."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.backup"
    label = "backup"
    verbose_name = "vali VM backups"
