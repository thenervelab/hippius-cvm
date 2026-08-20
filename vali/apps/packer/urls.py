from __future__ import annotations

from django.urls import path

from .views import (
    PackerBuildCreateView,
    PackerBuildDetailView,
    PackerBuildFinalizeView,
    PackerBuildPresignGetView,
)

urlpatterns = [
    path(
        "packer/build",
        PackerBuildCreateView.as_view(),
        name="packer_build_create",
    ),
    path(
        "packer/build/<str:build_id>",
        PackerBuildDetailView.as_view(),
        name="packer_build_detail",
    ),
    path(
        "packer/build/<str:build_id>/finalize",
        PackerBuildFinalizeView.as_view(),
        name="packer_build_finalize",
    ),
    path(
        "packer/build/<str:build_id>/presign-image-get",
        PackerBuildPresignGetView.as_view(),
        name="packer_build_presign_get",
    ),
]
