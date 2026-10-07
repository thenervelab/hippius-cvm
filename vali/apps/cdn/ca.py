"""The CDN CA (docs/design/cdn.md §9.2, CDN plan V1).

The CA's Ed25519 private key is a Vault Transit key (`VALI_CDN_CA_TRANSIT_KEY`,
default `cdn-ca`), the same HSM pattern as the tenant KEKs: an operator
creates it once, non-exportable and without plaintext backup,

    vault write transit/keys/cdn-ca type=ed25519 exportable=false allow_plaintext_backup=false

and vali's policy grants only `transit/sign/cdn-ca` and a read of
`transit/keys/cdn-ca` (its public metadata). vali never holds the private
key, so a vali RCE can have certificates signed while it lasts, but cannot
take the CA away with it. Every signature — the CA certificate and each node
certificate — first re-reads the key and refuses one Transit reports as
exportable, plaintext-backup-able or imported, or whose public key is not
the one vali recorded; and the signature Transit returns must verify under
that public key.

X.509 without the private key: `cryptography` builds a certificate only by
signing it, so vali builds the TBSCertificate with a throwaway Ed25519 key —
no field of the TBS depends on the signing key: the signature algorithm is
Ed25519 for any Ed25519 key, and the issuer and authority key id are set
from the CA explicitly — then has Transit sign those exact bytes and
assembles `Certificate ::= SEQUENCE { tbs, algorithm, signature }` itself.
The result is parsed back and verified against the CA certificate before it
is used.

Node certificates (§B.1): Ed25519, `notAfter` 7 days out
(`VALI_CDN_NODE_CERT_DAYS`), one SAN URI
`spiffe://<VALI_CDN_TRUST_DOMAIN>/cdn/<region>/<vm_id>/g<generation>`,
client and server auth (usage signing and shield mTLS). The certified key is
the node key vali derives from the VM's own lifecycle seed
(`apps.cdn.node_key`), never a key someone handed in.
"""

from __future__ import annotations

import base64
import datetime as dt
import logging
import re
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.common.cdn import cdn_enabled, is_cdn_tenant
from apps.lifecycle.models import Vm, VmState

from . import node_key
from .models import (
    CERTIFIABLE_NODE_STATES,
    PUBLISHED_CA_STATES,
    CdnCaKey,
    CdnCaState,
    CdnNode,
    CdnRevision,
)

log = logging.getLogger("apps.cdn")

#: `AlgorithmIdentifier ::= SEQUENCE { OID 1.3.101.112 }` (RFC 8410: no
#: parameters).
_ED25519_ALGORITHM_DER = bytes.fromhex("300506032b6570")

_REGION_RE = re.compile(r"[A-Z]{2}")
#: The cdn-agent's id rule (`config::is_valid_id`): it ends up in a SAN URI.
_ID_RE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}")

#: Backdating of `notBefore`, for clocks a little behind vali's. The agent
#: tolerates 300 s the other way.
_NOT_BEFORE_BACKDATE = dt.timedelta(minutes=5)


class CaError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# ── Transit ────────────────────────────────────────────────────────────


def transit_key_name() -> str:
    name = str(getattr(settings, "VALI_CDN_CA_TRANSIT_KEY", "") or "").strip()
    if not name:
        raise CaError("ca-not-configured", "VALI_CDN_CA_TRANSIT_KEY is empty")
    return name


@dataclass(frozen=True)
class TransitCaKey:
    name: str
    version: int
    public_key: bytes


def read_transit_key(*, name: str | None = None, version: int | None = None) -> TransitCaKey:
    """The CA Transit key's public half at `version` (default: latest).

    Refuses (`ca-key-unsafe`) a key that is not Ed25519, that Transit
    reports as exportable or plaintext-backup-able — such a key can leave
    Vault, which is the one thing the CA must not be able to do — or that
    was imported, and so existed outside Vault before."""
    from apps.orchestration.services import vault_kv

    name = name or transit_key_name()
    try:
        data = vault_kv.transit_read_key(name)
    except vault_kv.VaultNotFound as exc:
        raise CaError(
            "ca-key-missing", f"no Vault Transit key {name!r}: an operator creates it first"
        ) from exc
    if data.get("type") != "ed25519":
        raise CaError("ca-key-unsafe", f"Transit key {name!r} is not ed25519")
    if data.get("exportable") is not False or data.get("allow_plaintext_backup") is not False:
        raise CaError(
            "ca-key-unsafe",
            f"Transit key {name!r} is exportable or allows a plaintext backup",
        )
    if data.get("imported_key"):
        raise CaError("ca-key-unsafe", f"Transit key {name!r} was imported")
    keys = data.get("keys")
    latest = data.get("latest_version")
    want = version if version is not None else latest
    if isinstance(want, bool) or not isinstance(want, int) or want < 1:
        raise CaError("ca-key-shape", f"Transit key {name!r} has no usable version")
    entry = keys.get(str(want)) if isinstance(keys, dict) else None
    public_b64 = entry.get("public_key") if isinstance(entry, dict) else None
    if not isinstance(public_b64, str):
        raise CaError("ca-key-shape", f"Transit key {name!r} v{want} has no public key")
    try:
        public = base64.b64decode(public_b64, validate=True)
    except ValueError as exc:
        raise CaError("ca-key-shape", f"Transit key {name!r} v{want}: bad public key") from exc
    if len(public) != 32:
        raise CaError("ca-key-shape", f"Transit key {name!r} v{want}: bad public key")
    return TransitCaKey(name=name, version=want, public_key=public)


def _transit_sign(key: TransitCaKey, tbs: bytes) -> bytes:
    """Have Transit sign `tbs` with `key`, and check the signature under the
    public key vali holds for it before returning it."""
    from apps.orchestration.services import vault_kv

    signature = vault_kv.transit_sign(key.name, tbs, key_version=key.version)
    if len(signature) != 64:
        raise CaError("ca-signature-invalid", "Transit returned a malformed Ed25519 signature")
    try:
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(signature, tbs)
    except InvalidSignature as exc:
        raise CaError(
            "ca-signature-invalid",
            f"Transit's signature does not verify under {key.name} v{key.version}",
        ) from exc
    return signature


# ── DER assembly ────────────────────────────────────────────────────────


def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _assemble_certificate(tbs: bytes, signature: bytes) -> x509.Certificate:
    bit_string = b"\x00" + signature
    content = tbs + _ED25519_ALGORITHM_DER + b"\x03" + _der_length(len(bit_string)) + bit_string
    der = b"\x30" + _der_length(len(content)) + content
    cert = x509.load_der_x509_certificate(der)
    if cert.tbs_certificate_bytes != tbs or cert.signature != signature:
        raise CaError("ca-assembly", "the assembled certificate does not round-trip")
    return cert


def _sign_with_transit(builder: x509.CertificateBuilder, key: TransitCaKey) -> x509.Certificate:
    # The throwaway key only makes `cryptography` emit the TBS; its
    # signature is discarded and the key dies with this frame.
    scratch = Ed25519PrivateKey.generate()
    tbs = builder.sign(scratch, None).tbs_certificate_bytes
    del scratch
    return _assemble_certificate(tbs, _transit_sign(key, tbs))


def _public_key_raw(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


# ── The CA certificate ──────────────────────────────────────────────────


def kid_for(version: int) -> str:
    return f"cdnca-{version}"


def build_ca_certificate(key: TransitCaKey, *, now: dt.datetime) -> x509.Certificate:
    """A self-signed CA certificate over Transit key `key`, signed by it."""
    days = int(getattr(settings, "VALI_CDN_CA_VALIDITY_DAYS", 1825))
    if days < 30:
        raise CaError("ca-not-configured", "VALI_CDN_CA_VALIDITY_DAYS must be at least 30")
    public = Ed25519PublicKey.from_public_bytes(key.public_key)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Hippius"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"Hippius CDN CA {kid_for(key.version)}"),
        ]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _NOT_BEFORE_BACKDATE)
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
    )
    cert = _sign_with_transit(builder, key)
    cert.verify_directly_issued_by(cert)
    return cert


def init_ca(*, now: dt.datetime | None = None) -> tuple[CdnCaKey, bool]:
    """Make the CA certificate for the Transit key's latest version, if vali
    has none for it yet. `(row, created)`.

    The first CA is `active`. A later one (after an operator rotated the
    Transit key) is `pending`: published, so the backend trusts it, but not
    signing until `activate_ca`."""
    now = now or timezone.now()
    key = read_transit_key()
    kid = kid_for(key.version)
    existing = CdnCaKey.objects.filter(
        transit_key=key.name, transit_key_version=key.version
    ).first()
    if existing is not None:
        if bytes(existing.public_key) != key.public_key:
            raise CaError(
                "ca-key-changed",
                f"{kid}: Transit reports a different public key than the one vali recorded",
            )
        return existing, False
    if CdnCaKey.objects.filter(state=CdnCaState.PENDING).exists():
        raise CaError("ca-pending-exists", "a pending CA exists: activate or retire it first")
    cert = build_ca_certificate(key, now=now)
    with transaction.atomic():
        has_active = CdnCaKey.objects.select_for_update().filter(state=CdnCaState.ACTIVE).exists()
        row = CdnCaKey.objects.create(
            kid=kid,
            transit_key=key.name,
            transit_key_version=key.version,
            public_key=key.public_key,
            cert_pem=_pem(cert),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            state=CdnCaState.PENDING if has_active else CdnCaState.ACTIVE,
        )
        CdnRevision.bump()
    log.info("cdn: CA %s created (%s)", row.kid, row.state)
    return row, True


def activate_ca(kid: str) -> CdnCaKey:
    """Make the pending CA `kid` the signing one; the previous active CA
    becomes `retiring` (still published: its node certificates live on for
    up to `VALI_CDN_NODE_CERT_DAYS`)."""
    with transaction.atomic():
        row = CdnCaKey.objects.select_for_update().filter(kid=kid).first()
        if row is None:
            raise CaError("ca-not-found", f"no CA {kid!r}")
        if row.state != CdnCaState.PENDING:
            raise CaError("ca-not-pending", f"{kid} is {row.state}, not pending")
        CdnCaKey.objects.select_for_update().filter(state=CdnCaState.ACTIVE).update(
            state=CdnCaState.RETIRING
        )
        row.state = CdnCaState.ACTIVE
        row.save(update_fields=["state", "updated_at"])
        CdnRevision.bump()
    return row


def retire_ca(kid: str) -> CdnCaKey:
    """Drop the `retiring` CA `kid` from the published bundle. Refused while a
    live node still carries a certificate it signed."""
    with transaction.atomic():
        row = CdnCaKey.objects.select_for_update().filter(kid=kid).first()
        if row is None:
            raise CaError("ca-not-found", f"no CA {kid!r}")
        if row.state != CdnCaState.RETIRING:
            raise CaError("ca-not-retiring", f"{kid} is {row.state}, not retiring")
        still = CdnNode.objects.filter(
            cert_ca_kid=kid, state__in=CERTIFIABLE_NODE_STATES, cert_not_after__gt=timezone.now()
        ).count()
        if still:
            raise CaError("ca-in-use", f"{still} live node certificate(s) still chain to {kid}")
        row.state = CdnCaState.RETIRED
        row.save(update_fields=["state", "updated_at"])
        CdnRevision.bump()
    return row


def active_ca() -> CdnCaKey | None:
    return CdnCaKey.objects.filter(state=CdnCaState.ACTIVE).first()


def published_cas() -> list[CdnCaKey]:
    """Every CA the backend must trust, active first."""
    rows = list(CdnCaKey.objects.filter(state__in=PUBLISHED_CA_STATES))
    order = {CdnCaState.ACTIVE: 0, CdnCaState.PENDING: 1, CdnCaState.RETIRING: 2}
    return sorted(rows, key=lambda r: (order[CdnCaState(r.state)], r.transit_key_version))


def bundle_pem() -> str:
    """The CA bundle PEM: every published CA certificate, active first."""
    return "".join(row.cert_pem for row in published_cas())


# ── Node certificates ───────────────────────────────────────────────────


def spiffe_uri(region: str, vm_id: str, generation: int) -> str:
    domain = str(getattr(settings, "VALI_CDN_TRUST_DOMAIN", "") or "").strip()
    if not domain:
        raise CaError("ca-not-configured", "VALI_CDN_TRUST_DOMAIN is empty")
    return f"spiffe://{domain}/cdn/{region}/{vm_id}/g{generation}"


def _node_cert_lifetime() -> dt.timedelta:
    days = int(getattr(settings, "VALI_CDN_NODE_CERT_DAYS", 7))
    if not 1 <= days <= 30:
        raise CaError("ca-not-configured", "VALI_CDN_NODE_CERT_DAYS must be in 1..30")
    return dt.timedelta(days=days)


def build_node_certificate(
    ca: CdnCaKey,
    *,
    node_public_key: bytes,
    region: str,
    vm_id: str,
    generation: int,
    now: dt.datetime,
) -> x509.Certificate:
    """A node certificate over `node_public_key`, signed by `ca` through
    Transit, checked against the CA certificate."""
    if not _REGION_RE.fullmatch(region):
        raise CaError("node-bad-region", f"region {region!r} is not upper-case alpha-2")
    if not _ID_RE.fullmatch(vm_id):
        raise CaError("node-bad-id", f"vm id {vm_id!r} cannot appear in a SAN URI")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        raise CaError("node-bad-generation", f"generation {generation!r}")
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode("ascii"))
    not_before = now - _NOT_BEFORE_BACKDATE
    not_after = now + _node_cert_lifetime()
    if not_after > ca_cert.not_valid_after_utc:
        raise CaError(
            "ca-expiring", f"{ca.kid} expires before a node certificate would: rotate the CA"
        )
    uri = spiffe_uri(region, vm_id, generation)
    public = Ed25519PublicKey.from_public_bytes(node_public_key)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, vm_id)]))
        .issuer_name(ca_cert.subject)
        .public_key(public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=False
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                Ed25519PublicKey.from_public_bytes(bytes(ca.public_key))
            ),
            critical=False,
        )
    )
    # The key must still be what it was when the CA was made: never
    # exportable, and the same public key.
    key = read_transit_key(name=ca.transit_key, version=ca.transit_key_version)
    if key.public_key != bytes(ca.public_key):
        raise CaError(
            "ca-key-changed",
            f"{ca.kid}: Transit reports a different public key than the one vali recorded",
        )
    cert = _sign_with_transit(builder, key)
    cert.verify_directly_issued_by(ca_cert)
    _check_node_certificate(cert, node_public_key=node_public_key, uri=uri)
    return cert


def _check_node_certificate(cert: x509.Certificate, *, node_public_key: bytes, uri: str) -> None:
    public = cert.public_key()
    if not isinstance(public, Ed25519PublicKey) or _public_key_raw(public) != node_public_key:
        raise CaError("node-cert-key-mismatch", "the certificate does not carry the node key")
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if san.get_values_for_type(x509.UniformResourceIdentifier) != [uri] or len(list(san)) != 1:
        raise CaError("node-cert-san", "the certificate SAN is not exactly the node URI")


@dataclass(frozen=True)
class IssuedCert:
    node_id: str
    pem: str
    serial_hex: str
    not_before: dt.datetime
    not_after: dt.datetime
    generation: int
    ca_kid: str


def _certifiable_vm(node: CdnNode) -> Vm:
    vm = node.vm
    if node.state not in CERTIFIABLE_NODE_STATES:
        raise CaError("node-not-certifiable", f"node {node.node_id} is {node.state}")
    if vm is None:
        raise CaError("node-vm-missing", f"node {node.node_id} has no VM yet")
    if vm.vm_id != node.node_id:
        raise CaError("node-vm-mismatch", f"node {node.node_id} is bound to vm {vm.vm_id}")
    if vm.state != VmState.ACTIVE:
        raise CaError("node-vm-not-active", f"vm {vm.vm_id} is {vm.state}")
    if not is_cdn_tenant(vm.tenant_id):
        raise CaError("node-not-cdn-tenant", f"vm {vm.vm_id} does not run as the CDN tenant")
    return vm


def issue_node_cert(node_id: str, *, now: dt.datetime | None = None) -> IssuedCert:
    """Issue (or renew) the certificate of CDN node `node_id`.

    The certified key is derived from the node VM's own lifecycle seed,
    after checking that seed against the VM's recorded lifecycle public key
    (`node_key.node_public_key_for`): a certificate for node X can only
    ever carry X's key, and the SAN names X's region, vm id and current
    generation. The node and its VM are re-read under lock before the
    certificate is stored: if either moved while Transit signed (another
    generation, another state, another key), nothing is stored.

    Raises `CaError` / `node_key.NodeKeyError`, or the Vault client's
    errors. Refuses (`cdn-disabled`) while `VALI_CDN_ENABLED` is off."""
    if not cdn_enabled():
        raise CaError("cdn-disabled", "VALI_CDN_ENABLED is off")
    now = now or timezone.now()
    node = CdnNode.objects.select_related("vm").filter(node_id=node_id).first()
    if node is None:
        raise CaError("node-not-found", f"no CDN node {node_id!r}")
    vm = _certifiable_vm(node)
    ca = active_ca()
    if ca is None:
        raise CaError("ca-not-initialised", "no active CDN CA: run `vali_cdn_ca init`")
    public = node_key.node_public_key_for(vm)
    if node.node_public_key is not None and bytes(node.node_public_key) != public:
        raise CaError(
            "node-key-changed",
            f"node {node_id}: the derived key differs from the one first certified",
        )
    generation = int(vm.generation)
    cert = build_node_certificate(
        ca,
        node_public_key=public,
        region=node.region,
        vm_id=vm.vm_id,
        generation=generation,
        now=now,
    )
    issued = IssuedCert(
        node_id=node.node_id,
        pem=_pem(cert),
        serial_hex=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        generation=generation,
        ca_kid=ca.kid,
    )
    with transaction.atomic():
        locked = CdnNode.objects.select_for_update().get(pk=node.pk)
        locked_vm = (
            Vm.objects.select_for_update().filter(pk=locked.vm_id).first()
            if locked.vm_id is not None
            else None
        )
        if locked_vm is None or locked_vm.pk != vm.pk:
            raise CaError("node-moved", f"node {node_id} changed while its certificate was signed")
        locked.vm = locked_vm
        _certifiable_vm(locked)
        if (
            int(locked_vm.generation) != generation
            or bytes(locked_vm.lifecycle_vk or b"") != bytes(vm.lifecycle_vk or b"")
            or locked.region != node.region
            or (locked.node_public_key is not None and bytes(locked.node_public_key) != public)
        ):
            raise CaError("node-moved", f"node {node_id} changed while its certificate was signed")
        if not CdnCaKey.objects.filter(kid=ca.kid, state=CdnCaState.ACTIVE).exists():
            raise CaError("ca-moved", f"{ca.kid} stopped being the active CA during issuance")
        locked.node_public_key = public
        locked.cert_pem = issued.pem
        locked.cert_serial = issued.serial_hex
        locked.cert_not_before = issued.not_before
        locked.cert_not_after = issued.not_after
        locked.cert_generation = generation
        locked.cert_ca_kid = ca.kid
        locked.save(
            update_fields=[
                "node_public_key",
                "cert_pem",
                "cert_serial",
                "cert_not_before",
                "cert_not_after",
                "cert_generation",
                "cert_ca_kid",
                "updated_at",
            ]
        )
        CdnRevision.bump()
    log.info(
        "cdn: node %s certificate %s issued by %s (g%d, until %s)",
        node_id,
        issued.serial_hex,
        ca.kid,
        generation,
        issued.not_after.isoformat(),
    )
    return issued


def cert_needs_renewal(node: CdnNode, *, now: dt.datetime | None = None) -> bool:
    """The node has no certificate, or one for another generation, or by a
    CA that no longer signs, or past 2/3 of its lifetime."""
    now = now or timezone.now()
    if not node.cert_pem or node.cert_not_before is None or node.cert_not_after is None:
        return True
    if node.vm is None or node.cert_generation != int(node.vm.generation):
        return True
    ca = active_ca()
    if ca is None or node.cert_ca_kid != ca.kid:
        return True
    lifetime = node.cert_not_after - node.cert_not_before
    return now >= node.cert_not_before + lifetime * 2 / 3
