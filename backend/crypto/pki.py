"""
pki.py — a minimal certificate system signed with ML-DSA.

Standard X.509 tooling in Python does not yet issue ML-DSA certificates, so we use
a compact binary certificate with the same core fields as X.509 (serial, subject,
issuer, validity, public key, signature). Sizes are therefore close to, but not
identical to, real X.509 — state this in the report.

Chain:  Root CA  ->  Intermediate CA  ->  Device certificate
"""
import hashlib
import struct
import time
from dataclasses import dataclass, field

from . import pqc


# ------------------------------------------------------------ encoding ---
def _pack(*parts: bytes) -> bytes:
    """Length-prefixed concatenation (2-byte length + bytes for each field)."""
    return b"".join(struct.pack(">H", len(p)) + p for p in parts)


def _unpack(data: bytes) -> list[bytes]:
    out, i = [], 0
    while i < len(data):
        (n,) = struct.unpack(">H", data[i:i + 2])
        out.append(data[i + 2:i + 2 + n])
        i += 2 + n
    return out


# --------------------------------------------------------- certificate ---
@dataclass
class Certificate:
    serial: int
    subject: str
    issuer: str
    not_before: int          # unix seconds
    not_after: int           # unix seconds
    is_ca: bool
    sig_alg: str
    public_key: bytes
    signature: bytes = b""

    def tbs_bytes(self) -> bytes:
        """'To-be-signed' part: everything except the signature."""
        return _pack(
            struct.pack(">Q", self.serial),
            self.subject.encode(),
            self.issuer.encode(),
            struct.pack(">QQ", self.not_before, self.not_after),
            b"\x01" if self.is_ca else b"\x00",
            self.sig_alg.encode(),
            self.public_key,
        )

    def to_bytes(self) -> bytes:
        """Full serialized certificate — this is what goes on the wire."""
        return _pack(self.tbs_bytes(), self.signature)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Certificate":
        tbs, signature = _unpack(data)
        f = _unpack(tbs)
        (serial,) = struct.unpack(">Q", f[0])
        nb, na = struct.unpack(">QQ", f[3])
        return cls(serial, f[1].decode(), f[2].decode(), nb, na,
                   f[4] == b"\x01", f[5].decode(), f[6], signature)

    def fingerprint(self) -> bytes:
        """32-byte SHA-256 fingerprint — what certificate caching sends instead."""
        return hashlib.sha256(self.to_bytes()).digest()


# ------------------------------------------------------------------ CA ---
@dataclass
class CertificateAuthority:
    name: str
    keypair: pqc.SigKeyPair
    cert: Certificate
    next_serial: int = 1000
    revoked: set = field(default_factory=set)

    @classmethod
    def create_root(cls, name: str, days: int = 3650) -> "CertificateAuthority":
        kp = pqc.sig_keygen()
        now = int(time.time())
        cert = Certificate(1, name, name, now, now + days * 86400, True, kp.alg, kp.public_key)
        cert.signature = pqc.sign(cert.tbs_bytes(), kp)            # self-signed
        return cls(name, kp, cert)

    def issue(self, subject: str, public_key: bytes, is_ca: bool = False,
              days: int = 365, not_before: int | None = None) -> Certificate:
        nb = int(time.time()) if not_before is None else not_before
        cert = Certificate(self.next_serial, subject, self.name, nb, nb + days * 86400,
                           is_ca, self.keypair.alg, public_key)
        cert.signature = pqc.sign(cert.tbs_bytes(), self.keypair)
        self.next_serial += 1
        return cert

    def create_intermediate(self, name: str, days: int = 1825) -> "CertificateAuthority":
        kp = pqc.sig_keygen()
        cert = self.issue(name, kp.public_key, is_ca=True, days=days)
        return CertificateAuthority(name, kp, cert)

    def revoke(self, serial: int) -> None:
        self.revoked.add(serial)


# ---------------------------------------------------------- validation ---
class ValidationError(Exception):
    pass


def validate_chain(chain: list[Certificate], trusted_roots: list[Certificate],
                   revoked_serials: set | None = None, now: int | None = None) -> Certificate:
    """
    chain = [device_cert, intermediate_cert, ...] (leaf first, root NOT included).
    Checks, for every link: signature, issuer name, validity period, CA flag, revocation.
    Returns the leaf certificate if valid, otherwise raises ValidationError.
    """
    now = int(time.time()) if now is None else now
    revoked_serials = revoked_serials or set()
    roots = {r.subject: r for r in trusted_roots}

    for i, cert in enumerate(chain):
        if not (cert.not_before <= now <= cert.not_after):
            raise ValidationError(f"{cert.subject}: certificate expired or not yet valid")
        if cert.serial in revoked_serials:
            raise ValidationError(f"{cert.subject}: certificate revoked")

        issuer_cert = chain[i + 1] if i + 1 < len(chain) else roots.get(cert.issuer)
        if issuer_cert is None:
            raise ValidationError(f"{cert.subject}: unknown issuer {cert.issuer}")
        if issuer_cert.subject != cert.issuer:
            raise ValidationError(f"{cert.subject}: issuer name mismatch")
        if not issuer_cert.is_ca:
            raise ValidationError(f"{issuer_cert.subject}: issuer is not a CA")
        if not pqc.verify(cert.tbs_bytes(), cert.signature, issuer_cert.public_key, cert.sig_alg):
            raise ValidationError(f"{cert.subject}: bad signature")

    return chain[0]
