"""Django admin registrations for `apps.orders` (#152).

`OrderTicketIntake` rows are byte-exact COSE_Sign1 envelopes L1 handed
over to vali; the entire model is an append-only audit log. Everything
is read-only — the intake view (`POST /v1/order_ticket`) is the only
sanctioned writer.

`cose_blob` is the canonical L1 envelope re-emitted verbatim to the
KBS. Editing it from the admin would silently break that
re-transmission contract.
"""

from __future__ import annotations

from django.contrib import admin

from .models import OrderTicketIntake


@admin.register(OrderTicketIntake)
class OrderTicketIntakeAdmin(admin.ModelAdmin):
    list_display = (
        "ticket_id",
        "vm_id",
        "tenant_id",
        "lease_id",
        "vm_generation",
        "node_id",
        "received_from",
        "received_at",
    )
    list_filter = ("resource_class", "received_from")
    search_fields = (
        "ticket_id",
        "vm_id",
        "tenant_id",
        "user_id",
        "lease_id",
        "node_id",
        "platform_id",
        "kid_hex",
    )
    date_hierarchy = "received_at"
    ordering = ("-received_at",)

    def get_readonly_fields(self, request, obj=None):  # type: ignore[override]
        """Mark every concrete model field readonly on the change form.

        Static `readonly_fields = (…)` would silently leave a future-
        added column editable; a dynamic lookup against `_meta.fields`
        keeps the "append-only audit log" invariant load-bearing as
        the model evolves. The `id` field (UUID PK) is added
        explicitly because it's set by `default=` not a column the
        admin would normally surface.
        """
        return ["id", *(f.name for f in self.model._meta.fields)]

    def has_add_permission(self, request) -> bool:  # type: ignore[override]
        # Tickets are created by the intake view only. Block the
        # admin "Add" button so an operator can't synthesize a row
        # that would never have passed the validator shell-out.
        return False

    def has_delete_permission(self, request, obj=None) -> bool:  # type: ignore[override]
        # Append-only by policy — §15 audit trail. Blocking delete at
        # the `ModelAdmin` layer removes both the per-row "Delete"
        # button AND the `delete_selected` bulk action from the
        # changelist (Django wires both off `has_delete_permission`).
        return False
