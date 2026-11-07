"""Phase 1 'done when' check: run with   pytest -v"""
import time

import pytest
from cryptography.exceptions import InvalidTag

from backend.crypto import pki, pqc, symmetric


# ------------------------------------------------------------ ML-DSA ---
def test_sign_and_verify():
    kp = pqc.sig_keygen()
    sig = pqc.sign(b"power=7.2kW", kp)
    assert pqc.verify(b"power=7.2kW", sig, kp.public_key)


def test_tampered_message_fails():
    kp = pqc.sig_keygen()
    sig = pqc.sign(b"power=7.2kW", kp)
    assert not pqc.verify(b"power=99kW", sig, kp.public_key)


def test_wrong_key_fails():
    kp, other = pqc.sig_keygen(), pqc.sig_keygen()
    sig = pqc.sign(b"hello", kp)
    assert not pqc.verify(b"hello", sig, other.public_key)


# ------------------------------------------------------------ ML-KEM ---
def test_kem_shared_secret_matches():
    gateway = pqc.kem_keygen()
    ct, device_secret = pqc.encapsulate(gateway.public_key)
    assert pqc.decapsulate(ct, gateway) == device_secret


# --------------------------------------------------------- AES-GCM ---
def test_encrypt_decrypt_and_tamper():
    gateway = pqc.kem_keygen()
    ct, s1 = pqc.encapsulate(gateway.public_key)
    s2 = pqc.decapsulate(ct, gateway)
    k_dev, k_gw = symmetric.derive_session_key(s1), symmetric.derive_session_key(s2)

    blob = symmetric.encrypt(k_dev, b'{"soc": 64}')
    assert symmetric.decrypt(k_gw, blob) == b'{"soc": 64}'

    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(InvalidTag):
        symmetric.decrypt(k_gw, tampered)


# --------------------------------------------------------------- PKI ---
@pytest.fixture(scope="module")
def pki_setup():
    root = pki.CertificateAuthority.create_root("QSG Root CA")
    inter = root.create_intermediate("QSG Intermediate CA")
    dev_kp = pqc.sig_keygen()
    dev_cert = inter.issue("EV_001", dev_kp.public_key)
    return root, inter, dev_kp, dev_cert


def test_valid_chain(pki_setup):
    root, inter, _, dev = pki_setup
    leaf = pki.validate_chain([dev, inter.cert], [root.cert])
    assert leaf.subject == "EV_001"


def test_serialization_roundtrip(pki_setup):
    _, _, _, dev = pki_setup
    assert pki.Certificate.from_bytes(dev.to_bytes()) == dev


def test_revoked_cert_rejected(pki_setup):
    root, inter, _, dev = pki_setup
    with pytest.raises(pki.ValidationError, match="revoked"):
        pki.validate_chain([dev, inter.cert], [root.cert], revoked_serials={dev.serial})


def test_expired_cert_rejected(pki_setup):
    root, inter, _, _ = pki_setup
    old = inter.issue("EV_OLD", pqc.sig_keygen().public_key, days=1,
                      not_before=int(time.time()) - 10 * 86400)
    with pytest.raises(pki.ValidationError, match="expired"):
        pki.validate_chain([old, inter.cert], [root.cert])


def test_fake_ca_rejected(pki_setup):
    root, _, _, _ = pki_setup
    fake_root = pki.CertificateAuthority.create_root("QSG Root CA")   # same name, different key
    fake_inter = fake_root.create_intermediate("QSG Intermediate CA")
    fake_dev = fake_inter.issue("EV_FAKE", pqc.sig_keygen().public_key)
    with pytest.raises(pki.ValidationError, match="bad signature"):
        pki.validate_chain([fake_dev, fake_inter.cert], [root.cert])
