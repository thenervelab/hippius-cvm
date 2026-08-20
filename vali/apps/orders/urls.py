from __future__ import annotations

from django.urls import path

from .views import OrderTicketIntakeView

urlpatterns = [
    path("order_ticket", OrderTicketIntakeView.as_view(), name="order_ticket_intake"),
]
