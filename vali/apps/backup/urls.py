from __future__ import annotations

from django.urls import path

from .views import VmBackupPolicyView, VmBackupsView

urlpatterns = [
    path("vm/<str:vm_id>/backup-policy", VmBackupPolicyView.as_view(), name="vm_backup_policy"),
    path("vm/<str:vm_id>/backups", VmBackupsView.as_view(), name="vm_backups"),
]
