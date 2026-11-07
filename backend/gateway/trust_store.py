"""
trust_store.py — what the gateway trusts, and how it validates device certificates.

Holds: trusted root CAs, known intermediate CAs, the revocation list (CRL),
and — when gateway-assisted validation is on — a memo of intermediate CAs it has
already verified, so their signatures are not re-checked on every handshake.

Expiry and revocation are ALWAYS checked, for every certificate, on every handshake.
Only the expensive signature check of an already-verified CA certificate is skipped.
"""
import time
from dataclasses import dataclass, field

from backend.crypto import pqc
from backend.crypto.pki import Certificate, ValidationError


@dataclass
class TrustStore:
    roots: dict[str, Certificate] = field(default_factory=dict)
    intermediates: dict[str, Certificate] = field(default_factory=dict)
    revoked: set[int] = field(default_factory=set)
    verified_cas: set[bytes] = field(default_factory=set)   # fingerprints of verified CA certs
    signature_checks: int = 0                               # counted for the experiments

    def add_root(self, cert: Certificate) -> None:
        self.roots[cert.subject] = cert

    def add_intermediate(self, cert: Certificate) -> None:
        self.intermediates[cert.subject] = cert

    def revoke(self, serial: int) -> None:
        self.revoked.add(serial)

    # ------------------------------------------------------------------
    def _check_basic(self, cert: Certificate, now: float) -> None:
        if not (cert.not_before <= now <= cert.not_after):
            raise ValidationError(f"{cert.subject}: certificate expired or not yet valid")
        if cert.serial in self.revoked:
            raise ValidationError(f"{cert.subject}: certificate revoked")

    def _verify_signature(self, cert: Certificate, issuer: Certificate) -> None:
        if issuer.subject != cert.issuer:
            raise ValidationError(f"{cert.subject}: issuer name mismatch")
        if not issuer.is_ca:
            raise ValidationError(f"{issuer.subject}: issuer is not a CA")
        self.signature_checks += 1
        if not pqc.verify(cert.tbs_bytes(), cert.signature, issuer.public_key, cert.sig_alg):
            raise ValidationError(f"{cert.subject}: bad signature")

    def validate(self, leaf: Certificate, supplied: list[Certificate],
                 use_memo: bool, now: float | None = None) -> Certificate:
        """
        Validate leaf -> intermediate -> root.
        `supplied` = intermediate certificates the device sent (may be empty under chain optimization;
        then the gateway uses the intermediates it already holds).
        `use_memo` = gateway-assisted validation: skip re-verifying a CA signature verified before.
        """
        now = time.time() if now is None else now
        pool = {c.subject: c for c in supplied}

        self._check_basic(leaf, now)
        issuer = pool.get(leaf.issuer) or self.intermediates.get(leaf.issuer) or self.roots.get(leaf.issuer)
        if issuer is None:
            raise ValidationError(f"{leaf.subject}: unknown issuer {leaf.issuer}")
        self._verify_signature(leaf, issuer)

        # walk up until we reach a trusted root
        cert = issuer
        while cert.subject not in self.roots or self.roots[cert.subject].fingerprint() != cert.fingerprint():
            self._check_basic(cert, now)
            parent = pool.get(cert.issuer) or self.intermediates.get(cert.issuer) or self.roots.get(cert.issuer)
            if parent is None or parent.subject == cert.subject:
                raise ValidationError(f"{cert.subject}: does not chain to a trusted root")
            if not (use_memo and cert.fingerprint() in self.verified_cas):
                self._verify_signature(cert, parent)
                if use_memo:
                    self.verified_cas.add(cert.fingerprint())
            cert = parent
        return leaf
