"""
pqc.py — thin wrappers around liboqs for ML-KEM (FIPS 203) and ML-DSA (FIPS 204).

We never implement cryptography ourselves; liboqs does the real work.
These wrappers only give the rest of the project a small, clean API.
"""
from dataclasses import dataclass
import os
from pathlib import Path

# Auto-detect local liboqs install if OQS_INSTALL_PATH not explicitly set in environment
if "OQS_INSTALL_PATH" not in os.environ:
    repo_oqs = Path(__file__).resolve().parent.parent.parent / "_oqs"
    if repo_oqs.exists():
        os.environ["OQS_INSTALL_PATH"] = str(repo_oqs)

import oqs

# NIST Security Level 3 by default (change here to sweep parameter sets later)
KEM_ALG = "ML-KEM-768"
SIG_ALG = "ML-DSA-65"


# ---------------------------------------------------------------- ML-DSA ---
@dataclass
class SigKeyPair:
    alg: str
    public_key: bytes
    secret_key: bytes


def sig_keygen(alg: str = SIG_ALG) -> SigKeyPair:
    """Generate an ML-DSA key pair."""
    with oqs.Signature(alg) as signer:
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()
    return SigKeyPair(alg, pk, sk)


def sign(message: bytes, keypair: SigKeyPair) -> bytes:
    """Sign a message with the private key."""
    with oqs.Signature(keypair.alg, secret_key=keypair.secret_key) as signer:
        return signer.sign(message)


def verify(message: bytes, signature: bytes, public_key: bytes, alg: str = SIG_ALG) -> bool:
    """Return True only if the signature is valid for this message and public key."""
    with oqs.Signature(alg) as verifier:
        return verifier.verify(message, signature, public_key)


# ---------------------------------------------------------------- ML-KEM ---
@dataclass
class KemKeyPair:
    alg: str
    public_key: bytes
    secret_key: bytes


def kem_keygen(alg: str = KEM_ALG) -> KemKeyPair:
    """Gateway side: generate an ML-KEM key pair."""
    with oqs.KeyEncapsulation(alg) as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    return KemKeyPair(alg, pk, sk)


def encapsulate(public_key: bytes, alg: str = KEM_ALG) -> tuple[bytes, bytes]:
    """Device side: returns (ciphertext to send, shared secret to keep)."""
    with oqs.KeyEncapsulation(alg) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def decapsulate(ciphertext: bytes, keypair: KemKeyPair) -> bytes:
    """Gateway side: recover the same shared secret from the ciphertext."""
    with oqs.KeyEncapsulation(keypair.alg, secret_key=keypair.secret_key) as kem:
        return kem.decap_secret(ciphertext)


# ------------------------------------------------------------- sizes ---
def algorithm_sizes(kem_alg: str = KEM_ALG, sig_alg: str = SIG_ALG) -> dict:
    """Object sizes in bytes, read from liboqs (used in the baseline table)."""
    with oqs.KeyEncapsulation(kem_alg) as kem, oqs.Signature(sig_alg) as sig:
        k, s = kem.details, sig.details
    return {
        "kem_alg": kem_alg,
        "kem_public_key": k["length_public_key"],
        "kem_ciphertext": k["length_ciphertext"],
        "kem_shared_secret": k["length_shared_secret"],
        "sig_alg": sig_alg,
        "sig_public_key": s["length_public_key"],
        "sig_signature_max": s["length_signature"],
    }
