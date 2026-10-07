"""The CDN CA: Transit-held key, CA certificate, node certificates."""

from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import ExtendedKeyUsageOID
from django.conf import settings
from django.utils import timezone

from apps.lifecycle.models import Vm, VmState

from .. import ca, node_key
from ..models import CdnCaKey, CdnCaState, CdnNode, CdnNodeState, CdnRevision
from .conftest import FakeTransit, make_node, raw_public

pytestmark = pytest.mark.django_db

_VECTORS = Path(__file__).resolve().parents[4] / "test_vectors" / "cdn" / "vectors.json"


def _cert(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode())


# ── node key ────────────────────────────────────────────────────────────


def test_node_key_matches_the_shared_vector() -> None:
    """vali's HKDF is the cdn-agent's (`identity.rs`): the same lifecycle
    seed gives the same node key on both sides."""
    v = json.loads(_VECTORS.read_text())["node_key"]
    assert v["info"] == node_key.NODE_KEY_INFO.decode()
    seed = bytes.fromhex(v["lifecycle_seed_hex"])
    assert node_key.derive_node_public_key(seed).hex() == v["node_public_hex"]


def test_node_key_differs_from_the_lifecycle_key() -> None:
    seed = bytes([7] * 32)
    assert node_key.derive_node_public_key(seed) != raw_public(
        Ed25519PrivateKey.from_private_bytes(seed)
    )


# ── the CA ───────────────────────────────────────────────────────────────


def test_init_makes_a_self_signed_ca_signed_by_transit(fake_transit: FakeTransit) -> None:
    row, created = ca.init_ca()
    assert created and row.kid == "cdnca-1" and row.state == CdnCaState.ACTIVE
    cert = _cert(row.cert_pem)
    cert.verify_directly_issued_by(cert)
    pub = cert.public_key()
    assert isinstance(pub, Ed25519PublicKey)
    assert raw_public(fake_transit.versions[0]) == bytes(row.public_key)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical and bc.value.ca and bc.value.path_length == 0
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign and not ku.digital_signature
    # Transit signed exactly the TBS the certificate carries.
    assert fake_transit.signed[-1] == ("cdn-ca", 1, cert.tbs_certificate_bytes)
    assert CdnRevision.current() == 1


def test_init_is_idempotent(fake_transit: FakeTransit) -> None:
    first, _ = ca.init_ca()
    again, created = ca.init_ca()
    assert not created and again.kid == first.kid
    assert CdnCaKey.objects.count() == 1


@pytest.mark.parametrize(
    ("attr", "value"),
    [("exportable", True), ("allow_plaintext_backup", True), ("key_type", "aes256-gcm96")],
)
def test_init_refuses_a_key_that_can_leave_vault(
    fake_transit: FakeTransit, attr: str, value: object
) -> None:
    setattr(fake_transit, attr, value)
    with pytest.raises(ca.CaError) as exc:
        ca.init_ca()
    assert exc.value.code == "ca-key-unsafe"
    assert not CdnCaKey.objects.exists()


def test_init_refuses_a_missing_key(fake_transit: FakeTransit) -> None:
    fake_transit.name = "other"
    with pytest.raises(ca.CaError) as exc:
        ca.init_ca()
    assert exc.value.code == "ca-key-missing"


def test_a_signature_that_does_not_verify_is_refused(fake_transit: FakeTransit) -> None:
    fake_transit.rogue = Ed25519PrivateKey.generate()
    with pytest.raises(ca.CaError) as exc:
        ca.init_ca()
    assert exc.value.code == "ca-signature-invalid"
    assert not CdnCaKey.objects.exists()


def test_a_changed_transit_public_key_is_refused(fake_transit: FakeTransit) -> None:
    ca.init_ca()
    fake_transit.versions[0] = Ed25519PrivateKey.generate()
    with pytest.raises(ca.CaError) as exc:
        ca.init_ca()
    assert exc.value.code == "ca-key-changed"


@pytest.mark.parametrize(
    ("attr", "value"), [("exportable", True), ("allow_plaintext_backup", True)]
)
def test_node_issuance_refuses_a_key_turned_unsafe(
    fake_transit: FakeTransit, attr: str, value: object
) -> None:
    """The check runs before every node certificate too, not only at init:
    Vault never turns `exportable` back off."""
    ca.init_ca()
    node = make_node(fake_transit)
    setattr(fake_transit, attr, value)
    with pytest.raises(ca.CaError) as exc:
        ca.issue_node_cert(node.node_id)
    assert exc.value.code == "ca-key-unsafe"
    assert len(fake_transit.signed) == 1
    node.refresh_from_db()
    assert node.cert_pem == ""


def test_node_issuance_refuses_a_changed_ca_public_key(fake_transit: FakeTransit) -> None:
    ca.init_ca()
    node = make_node(fake_transit)
    fake_transit.versions[0] = Ed25519PrivateKey.generate()
    with pytest.raises(ca.CaError) as exc:
        ca.issue_node_cert(node.node_id)
    assert exc.value.code == "ca-key-changed"


def test_an_imported_key_is_refused(
    fake_transit: FakeTransit, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = fake_transit.read_key

    def imported(name: str) -> dict[str, object]:
        return {**real(name), "imported_key": True}

    from apps.orchestration.services import vault_kv

    monkeypatch.setattr(vault_kv, "transit_read_key", imported)
    with pytest.raises(ca.CaError) as exc:
        ca.init_ca()
    assert exc.value.code == "ca-key-unsafe"


def test_signing_refuses_a_key_turned_exportable(fake_transit: FakeTransit) -> None:
    """The check runs on every CA build, not only the first."""
    ca.init_ca()
    fake_transit.rotate()
    fake_transit.exportable = True
    with pytest.raises(ca.CaError) as exc:
        ca.init_ca()
    assert exc.value.code == "ca-key-unsafe"


def test_rotation_pending_activate_retire(fake_transit: FakeTransit) -> None:
    ca.init_ca()
    fake_transit.rotate()
    nxt, created = ca.init_ca()
    assert created and nxt.kid == "cdnca-2" and nxt.state == CdnCaState.PENDING
    bundle = ca.bundle_pem()
    assert bundle.count("BEGIN CERTIFICATE") == 2
    assert bundle.startswith(CdnCaKey.objects.get(kid="cdnca-1").cert_pem)

    fake_transit.rotate()
    with pytest.raises(ca.CaError) as exc:
        ca.init_ca()
    assert exc.value.code == "ca-pending-exists"

    ca.activate_ca("cdnca-2")
    assert CdnCaKey.objects.get(kid="cdnca-1").state == CdnCaState.RETIRING
    assert ca.active_ca().kid == "cdnca-2"
    assert ca.bundle_pem().startswith(CdnCaKey.objects.get(kid="cdnca-2").cert_pem)

    ca.retire_ca("cdnca-1")
    assert ca.bundle_pem().count("BEGIN CERTIFICATE") == 1


def test_retire_refused_while_a_live_certificate_chains_to_it(fake_transit: FakeTransit) -> None:
    ca.init_ca()
    node = make_node(fake_transit)
    ca.issue_node_cert(node.node_id)
    fake_transit.rotate()
    ca.init_ca()
    ca.activate_ca("cdnca-2")
    with pytest.raises(ca.CaError) as exc:
        ca.retire_ca("cdnca-1")
    assert exc.value.code == "ca-in-use"
    ca.issue_node_cert(node.node_id)
    assert CdnNode.objects.get().cert_ca_kid == "cdnca-2"
    ca.retire_ca("cdnca-1")


# ── node certificates ────────────────────────────────────────────────────


def test_node_certificate_shape(fake_transit: FakeTransit) -> None:
    ca_row, _ = ca.init_ca()
    seed = bytes([7] * 32)
    node = make_node(fake_transit, seed=seed, generation=3)
    issued = ca.issue_node_cert(node.node_id)
    cert = _cert(issued.pem)

    cert.verify_directly_issued_by(_cert(ca_row.cert_pem))
    v = json.loads(_VECTORS.read_text())["node_key"]
    assert raw_public_of(cert) == bytes.fromhex(v["node_public_hex"])
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert list(san) == [
        x509.UniformResourceIdentifier("spiffe://hippius.network/cdn/FR/cdn-fr-7k2m/g3")
    ]
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == dt.timedelta(days=7, minutes=5)
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert set(eku) == {ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH}
    assert cert.issuer == _cert(ca_row.cert_pem).subject

    node.refresh_from_db()
    assert node.cert_pem == issued.pem
    assert bytes(node.node_public_key) == bytes.fromhex(v["node_public_hex"])
    assert node.cert_generation == 3 and node.cert_ca_kid == "cdnca-1"
    assert node.cert_serial == issued.serial_hex


def raw_public_of(cert: x509.Certificate) -> bytes:
    pub = cert.public_key()
    assert isinstance(pub, Ed25519PublicKey)
    return pub.public_bytes_raw()


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl CLI")
def test_openssl_verifies_the_chain_as_a_tls_client(
    fake_transit: FakeTransit, tmp_path: Path
) -> None:
    """A standard X.509 verifier chains a node certificate to the exported
    bundle, as the backend's register check does."""
    ca.init_ca()
    node = make_node(fake_transit)
    issued = ca.issue_node_cert(node.node_id)
    (tmp_path / "ca.pem").write_text(ca.bundle_pem())
    (tmp_path / "node.pem").write_text(issued.pem)
    for purpose in ("sslclient", "sslserver"):
        out = subprocess.run(
            [
                "openssl",
                "verify",
                "-purpose",
                purpose,
                "-CAfile",
                str(tmp_path / "ca.pem"),
                str(tmp_path / "node.pem"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert out.returncode == 0, out.stdout + out.stderr


def test_issue_refused_while_cdn_disabled(
    fake_transit: FakeTransit, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca.init_ca()
    node = make_node(fake_transit)
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)
    with pytest.raises(ca.CaError) as exc:
        ca.issue_node_cert(node.node_id)
    assert exc.value.code == "cdn-disabled"
    assert len(fake_transit.signed) == 1  # the CA certificate only


def test_issue_refused_without_a_ca(fake_transit: FakeTransit) -> None:
    node = make_node(fake_transit)
    with pytest.raises(ca.CaError) as exc:
        ca.issue_node_cert(node.node_id)
    assert exc.value.code == "ca-not-initialised"


def test_a_seed_that_is_not_the_vms_lifecycle_key_is_refused(fake_transit: FakeTransit) -> None:
    """The proof: the staged seed's public key must be the VM's recorded
    lifecycle key. A seed swapped at the path (or a later KV version
    misread) never gets certified."""
    ca.init_ca()
    node = make_node(fake_transit)
    fake_transit.kv[f"hippius-compute/kbs/tenants/{node.node_id}/lifecycle-key"] = bytes(32)
    with pytest.raises(node_key.NodeKeyError) as exc:
        ca.issue_node_cert(node.node_id)
    assert exc.value.code == "lifecycle-key-mismatch"
    node.refresh_from_db()
    assert node.cert_pem == "" and node.node_public_key is None


def test_a_missing_seed_is_refused(fake_transit: FakeTransit) -> None:
    ca.init_ca()
    node = make_node(fake_transit)
    fake_transit.kv.clear()
    with pytest.raises(node_key.NodeKeyError) as exc:
        ca.issue_node_cert(node.node_id)
    assert exc.value.code == "lifecycle-key-missing"


def test_each_node_gets_its_own_key(fake_transit: FakeTransit) -> None:
    ca.init_ca()
    a = make_node(fake_transit, "cdn-fr-a")
    b = make_node(fake_transit, "cdn-fr-b")
    ca_a = _cert(ca.issue_node_cert(a.node_id).pem)
    ca_b = _cert(ca.issue_node_cert(b.node_id).pem)
    assert raw_public_of(ca_a) != raw_public_of(ca_b)
    seed_a = fake_transit.kv["hippius-compute/kbs/tenants/cdn-fr-a/lifecycle-key"]
    assert raw_public_of(ca_a) == node_key.derive_node_public_key(seed_a)


@pytest.mark.parametrize(
    "state",
    [
        CdnNodeState.LAUNCHING,
        CdnNodeState.DRAINED,
        CdnNodeState.DECOMMISSIONING,
        CdnNodeState.FAILED,
        CdnNodeState.DESTROYED,
    ],
)
def test_issue_refused_outside_the_certifiable_states(
    fake_transit: FakeTransit, state: str
) -> None:
    ca.init_ca()
    node = make_node(fake_transit, state=state)
    with pytest.raises(ca.CaError) as exc:
        ca.issue_node_cert(node.node_id)
    assert exc.value.code == "node-not-certifiable"


@pytest.mark.parametrize("vm_state", [VmState.MIGRATING, VmState.DESTROYED])
def test_issue_refused_for_a_vm_that_is_not_active(
    fake_transit: FakeTransit, vm_state: str
) -> None:
    ca.init_ca()
    node = make_node(fake_transit)
    Vm.objects.filter(pk=node.vm_id).update(
        state=vm_state, new_generation=4, migration_dest="miner-b"
    )
    with pytest.raises(ca.CaError) as exc:
        ca.issue_node_cert(node.node_id)
    assert exc.value.code == "node-vm-not-active"


def test_issue_refused_for_a_vm_outside_the_cdn_tenant(fake_transit: FakeTransit) -> None:
    ca.init_ca()
    node = make_node(fake_transit, tenant_id="tenant-a")
    with pytest.raises(ca.CaError) as exc:
        ca.issue_node_cert(node.node_id)
    assert exc.value.code == "node-not-cdn-tenant"


def test_issue_refused_when_node_id_and_vm_disagree(fake_transit: FakeTransit) -> None:
    ca.init_ca()
    node = make_node(fake_transit)
    CdnNode.objects.filter(pk=node.pk).update(node_id="cdn-fr-other")
    with pytest.raises(ca.CaError) as exc:
        ca.issue_node_cert("cdn-fr-other")
    assert exc.value.code == "node-vm-mismatch"


def test_a_changed_node_key_is_refused(fake_transit: FakeTransit) -> None:
    ca.init_ca()
    node = make_node(fake_transit)
    ca.issue_node_cert(node.node_id)
    CdnNode.objects.filter(pk=node.pk).update(node_public_key=bytes(32))
    with pytest.raises(ca.CaError) as exc:
        ca.issue_node_cert(node.node_id)
    assert exc.value.code == "node-key-changed"


def test_nothing_is_stored_when_the_vm_moved_during_signing(
    fake_transit: FakeTransit, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A §25 migration bumping the generation while Transit signs: the
    certificate names the old generation, so it is dropped."""
    ca.init_ca()
    node = make_node(fake_transit, generation=3)
    real_sign = fake_transit.sign

    def sign_then_move(name: str, message: bytes, *, key_version: int) -> bytes:
        Vm.objects.filter(pk=node.vm_id).update(generation=4)
        return real_sign(name, message, key_version=key_version)

    from apps.orchestration.services import vault_kv

    monkeypatch.setattr(vault_kv, "transit_sign", sign_then_move)
    with pytest.raises(ca.CaError) as exc:
        ca.issue_node_cert(node.node_id)
    assert exc.value.code == "node-moved"
    node.refresh_from_db()
    assert node.cert_pem == ""


def test_nothing_is_stored_when_the_node_left_service_during_signing(
    fake_transit: FakeTransit, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca.init_ca()
    node = make_node(fake_transit)
    real_sign = fake_transit.sign

    def sign_then_drain(name: str, message: bytes, *, key_version: int) -> bytes:
        CdnNode.objects.filter(pk=node.pk).update(state=CdnNodeState.DECOMMISSIONING)
        return real_sign(name, message, key_version=key_version)

    from apps.orchestration.services import vault_kv

    monkeypatch.setattr(vault_kv, "transit_sign", sign_then_drain)
    with pytest.raises(ca.CaError) as exc:
        ca.issue_node_cert(node.node_id)
    assert exc.value.code == "node-not-certifiable"
    node.refresh_from_db()
    assert node.cert_pem == ""


def test_renewal_predicate(fake_transit: FakeTransit) -> None:
    ca.init_ca()
    node = make_node(fake_transit, generation=3)
    assert ca.cert_needs_renewal(node)
    ca.issue_node_cert(node.node_id)
    node = CdnNode.objects.select_related("vm").get(pk=node.pk)
    now = timezone.now()
    assert not ca.cert_needs_renewal(node, now=now)
    assert ca.cert_needs_renewal(node, now=now + dt.timedelta(days=5))
    Vm.objects.filter(pk=node.vm_id).update(generation=4)
    node = CdnNode.objects.select_related("vm").get(pk=node.pk)
    assert ca.cert_needs_renewal(node, now=now)


def test_node_certificate_never_outlives_its_ca(
    fake_transit: FakeTransit, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_CA_VALIDITY_DAYS", 30)
    ca.init_ca()
    node = make_node(fake_transit)
    with pytest.raises(ca.CaError) as exc:
        ca.issue_node_cert(node.node_id, now=timezone.now() + dt.timedelta(days=25))
    assert exc.value.code == "ca-expiring"


def test_the_ca_row_holds_no_private_key(fake_transit: FakeTransit) -> None:
    """The only key material vali stores for the CA is its public key."""
    row, _ = ca.init_ca()
    fields = {f.name for f in CdnCaKey._meta.get_fields()}
    assert not {f for f in fields if "private" in f or "seed" in f or "secret" in f}
    assert bytes(row.public_key) == raw_public(fake_transit.versions[0])


def test_ca_states_are_exclusive(fake_transit: FakeTransit) -> None:
    from django.db import IntegrityError, transaction

    row, _ = ca.init_ca()
    with pytest.raises(IntegrityError), transaction.atomic():
        CdnCaKey.objects.create(
            kid="cdnca-9",
            transit_key="cdn-ca",
            transit_key_version=9,
            public_key=bytes(32),
            cert_pem=row.cert_pem,
            not_before=row.not_before,
            not_after=row.not_after,
            state=CdnCaState.ACTIVE,
        )


def test_a_ready_node_records_when(fake_transit: FakeTransit) -> None:
    from django.db import IntegrityError, transaction

    node = make_node(fake_transit)
    with pytest.raises(IntegrityError), transaction.atomic():
        CdnNode.objects.filter(pk=node.pk).update(state=CdnNodeState.READY)


@pytest.mark.parametrize("state", [CdnNodeState.DRAINED, CdnNodeState.DECOMMISSIONING])
def test_a_node_that_was_ready_leaves_only_after_dns_released(
    fake_transit: FakeTransit, state: str
) -> None:
    from django.db import IntegrityError, transaction

    node = make_node(fake_transit)
    CdnNode.objects.filter(pk=node.pk).update(state=CdnNodeState.READY, ready_at=timezone.now())
    with pytest.raises(IntegrityError), transaction.atomic():
        CdnNode.objects.filter(pk=node.pk).update(state=state)
    CdnNode.objects.filter(pk=node.pk).update(state=state, dns_released_at=timezone.now())
    # A node never ready never had a DNS record.
    other = make_node(fake_transit, "cdn-fr-other")
    CdnNode.objects.filter(pk=other.pk).update(state=state)


def test_issue_refused_before_the_node_has_a_vm(fake_transit: FakeTransit) -> None:
    ca.init_ca()
    node = CdnNode.objects.create(node_id="cdn-fr-new", region="FR", state=CdnNodeState.BOOTING)
    with pytest.raises(ca.CaError) as exc:
        ca.issue_node_cert(node.node_id)
    assert exc.value.code == "node-vm-missing"
    assert ca.cert_needs_renewal(node)
