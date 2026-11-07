"""
symmetric.py — turns the ML-KEM shared secret into an AES-256-GCM session key
and encrypts/decrypts telemetry. ML-KEM does NOT encrypt data; AES-GCM does.
"""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_LEN = 12  # bytes, standard for AES-GCM


def derive_session_key(shared_secret: bytes, context: bytes = b"quantumshield-grid v1") -> bytes:
    """HKDF-SHA256: shared secret -> 32-byte AES key. Both sides get the same key."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context).derive(shared_secret)


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """Returns nonce || ciphertext || 16-byte tag."""
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, associated_data)


def decrypt(key: bytes, blob: bytes, associated_data: bytes = b"") -> bytes:
    """Raises cryptography.exceptions.InvalidTag if anything was tampered with."""
    nonce, body = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, body, associated_data)
