"""Customer-held keys — a tenant's key guardian on the NetBird mesh.

OPERATOR surface (the orchestration root principal: the backend, with its
operator token). No tenant API: the backend hands the setup key to its
tenant. See `services.guardian_netbird`.

  POST   /v1/guardian/<tenant_id>/netbird/setup-key   {port?, ttl_s?}
      Ensure the tenant's guardian group + the `miners → guardian:port`
      (TCP) policy, then mint a one-off setup key that joins ONLY that
      group. → 201 {tenant_id, setup_key, setup_key_id, expires_in_s,
      group, group_id, policy, policy_id, port}.
  PUT    /v1/guardian/<tenant_id>/netbird/policy       {port?}
      Ensure the group + policy only (idempotent; a port change rewrites
      the rule). → 200 {tenant_id, group, group_id, policy, policy_id, port}.
  DELETE /v1/guardian/<tenant_id>/netbird
      Revoke: the policy, the setup keys, the guardian peers, the group.
      Idempotent. → 200 {tenant_id, deleted: [...]}.

Minting and ensuring need `VALI_CUSTOMER_KEYS_ENABLED`; revoking never
does (clean-up must always work).
"""

from __future__ import annotations

from typing import Any

from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.identity import scoping

from .effects import EffectError, EffectUnavailable
from .permissions import IsOrchestrationRoot
from .services import customer_keys
from .services import guardian_netbird as gn

_TAGS = ["Customer keys"]
_TENANT = OpenApiParameter("tenant_id", str, OpenApiParameter.PATH)

_ERROR_STATUS = {
    "bad-request": status.HTTP_400_BAD_REQUEST,
    "customer-keys-disabled": status.HTTP_409_CONFLICT,
    "guardian-peer-shared": status.HTTP_409_CONFLICT,
    "guardian-netbird-open-policy": status.HTTP_409_CONFLICT,
    "guardian-netbird-misconfigured": status.HTTP_503_SERVICE_UNAVAILABLE,
    "netbird-unavailable": status.HTTP_503_SERVICE_UNAVAILABLE,
    "netbird-error": status.HTTP_502_BAD_GATEWAY,
}


class GuardianErrorSerializer(serializers.Serializer):
    error = serializers.CharField()
    detail = serializers.CharField()


class GuardianKeyRequestSerializer(serializers.Serializer):
    port = serializers.IntegerField(
        required=False, help_text="The guardian's TCP port (default VALI_GUARDIAN_DEFAULT_PORT)."
    )
    ttl_s = serializers.IntegerField(
        required=False, help_text="Setup-key lifetime, 60..604800 s (default 86400)."
    )


class GuardianPolicyRequestSerializer(serializers.Serializer):
    port = serializers.IntegerField(required=False)


class GuardianAccessSerializer(serializers.Serializer):
    tenant_id = serializers.CharField()
    group = serializers.CharField()
    group_id = serializers.CharField()
    policy = serializers.CharField()
    policy_id = serializers.CharField()
    port = serializers.IntegerField()


class GuardianKeySerializer(GuardianAccessSerializer):
    setup_key = serializers.CharField(help_text="One-off NetBird setup key — a secret.")
    setup_key_id = serializers.CharField()
    expires_in_s = serializers.IntegerField()


class GuardianRevokeSerializer(serializers.Serializer):
    tenant_id = serializers.CharField()
    deleted = serializers.ListField(child=serializers.CharField())


def _access(a: gn.GuardianAccess) -> dict[str, Any]:
    return {
        "tenant_id": a.tenant_id,
        "group": a.group,
        "group_id": a.group_id,
        "policy": a.policy,
        "policy_id": a.policy_id,
        "port": a.port,
    }


def _refuse(code: str, detail: str) -> Response:
    return Response(
        {"error": code, "detail": detail},
        status=_ERROR_STATUS.get(code, status.HTTP_400_BAD_REQUEST),
    )


def _body(request: Request, allowed: frozenset[str]) -> dict[str, Any]:
    data = request.data if request.data else {}
    if not isinstance(data, dict):
        raise gn.GuardianNetbirdError("bad-request", "body must be a JSON object")
    unknown = set(data) - allowed
    if unknown:
        raise gn.GuardianNetbirdError(
            "bad-request", f"unknown field(s): {', '.join(sorted(unknown))}"
        )
    return data


def _require_enabled() -> None:
    if not customer_keys.enabled():
        raise gn.GuardianNetbirdError(
            "customer-keys-disabled",
            "customer-held keys are not enabled (VALI_CUSTOMER_KEYS_ENABLED)",
        )


def _run(fn: Any) -> Response:
    try:
        return fn()
    except gn.GuardianNetbirdError as exc:
        return _refuse(exc.code, exc.message)
    except EffectUnavailable as exc:
        return _refuse("netbird-unavailable", str(exc))
    except EffectError as exc:
        return _refuse("netbird-error", str(exc))


class _RootView(APIView):
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated, IsOrchestrationRoot]


_COMMON = {
    400: OpenApiResponse(GuardianErrorSerializer, "`bad-request`."),
    403: OpenApiResponse(GuardianErrorSerializer, "Not the orchestration root principal."),
    502: OpenApiResponse(GuardianErrorSerializer, "`netbird-error`."),
    503: OpenApiResponse(
        GuardianErrorSerializer, "`netbird-unavailable` / `guardian-netbird-misconfigured`."
    ),
}


class GuardianSetupKeyView(_RootView):
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Mint a NetBird setup key for a tenant's key guardian",
        description=(
            "Ensures the tenant's guardian group and the policy letting the miners "
            "reach ONLY the guardian's TCP port, then mints a one-off setup key whose "
            "peer joins only that group. Operator surface; the key is a secret."
        ),
        tags=_TAGS,
        parameters=[_TENANT],
        request=GuardianKeyRequestSerializer,
        responses={
            201: GuardianKeySerializer,
            409: OpenApiResponse(
                GuardianErrorSerializer,
                "`customer-keys-disabled` / `guardian-netbird-open-policy`.",
            ),
            **_COMMON,
        },
    )
    def post(self, request: Request, tenant_id: str) -> Response:
        def go() -> Response:
            body = _body(request, frozenset({"port", "ttl_s"}))
            _require_enabled()
            minted = gn.mint_setup_key(
                tenant_id, gn.check_port(body.get("port")), gn.check_ttl(body.get("ttl_s"))
            )
            return Response(
                {
                    **_access(minted.access),
                    "setup_key": minted.key,
                    "setup_key_id": minted.key_id,
                    "expires_in_s": minted.expires_in_s,
                },
                status=status.HTTP_201_CREATED,
            )

        return _run(go)


class GuardianPolicyView(_RootView):
    http_method_names = ["put", "options"]

    @extend_schema(
        summary="Ensure a tenant's key-guardian NetBird policy",
        description=(
            "Idempotent: creates, or rewrites on drift, the tenant's guardian group "
            "and the one-rule policy miners → guardian, TCP, the guardian port only."
        ),
        tags=_TAGS,
        parameters=[_TENANT],
        request=GuardianPolicyRequestSerializer,
        responses={
            200: GuardianAccessSerializer,
            409: OpenApiResponse(
                GuardianErrorSerializer,
                "`customer-keys-disabled` / `guardian-netbird-open-policy` (another enabled "
                "policy, e.g. NetBird's Default All<->All, reaches the guardian).",
            ),
            **_COMMON,
        },
    )
    def put(self, request: Request, tenant_id: str) -> Response:
        def go() -> Response:
            body = _body(request, frozenset({"port"}))
            _require_enabled()
            access = gn.ensure_policy(tenant_id, gn.check_port(body.get("port")))
            return Response(_access(access), status=status.HTTP_200_OK)

        return _run(go)


class GuardianRevokeView(_RootView):
    http_method_names = ["delete", "options"]

    @extend_schema(
        summary="Revoke a tenant's key guardian from the NetBird mesh",
        description=(
            "Deletes the policy, the tenant's guardian setup keys, its guardian "
            "peers and its group. Idempotent. Refuses `guardian-peer-shared` (409, "
            "nothing deleted) when a peer in the group is also in another group."
        ),
        tags=_TAGS,
        parameters=[_TENANT],
        responses={
            200: GuardianRevokeSerializer,
            409: OpenApiResponse(GuardianErrorSerializer, "`guardian-peer-shared`."),
            **_COMMON,
        },
    )
    def delete(self, request: Request, tenant_id: str) -> Response:
        def go() -> Response:
            deleted = gn.revoke(tenant_id)
            return Response(
                {"tenant_id": tenant_id, "deleted": deleted}, status=status.HTTP_200_OK
            )

        return _run(go)
