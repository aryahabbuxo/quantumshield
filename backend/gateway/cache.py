"""
cache.py — certificate caching.

After a device's certificate passes FULL validation, the gateway stores it under its
32-byte SHA-256 fingerprint. Next time the device sends only the fingerprint (~5 KB saved).

Safety rules (this is what answers "isn't caching a security risk?"):
  * an entry expires at   min(certificate expiry, time validated + TTL)
  * revocation is checked on EVERY lookup, so a revoked certificate is never accepted
  * a cache hit only replaces sending the certificate — the device must still sign a
    fresh challenge, so a stolen fingerprint is useless without the private key
"""
import time
from dataclasses import dataclass

from backend.crypto.pki import Certificate


@dataclass
class CacheEntry:
    cert: Certificate
    validated_at: float
    expires_at: float


class CertCache:
    def __init__(self, ttl_s: int):
        self.ttl_s = ttl_s
        self._entries: dict[bytes, CacheEntry] = {}
        self.hits = 0
        self.misses = 0

    def put(self, cert: Certificate, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._entries[cert.fingerprint()] = CacheEntry(cert, now, min(cert.not_after, now + self.ttl_s))

    def get(self, fingerprint: bytes, revoked: set[int], now: float | None = None) -> Certificate | None:
        """Returns the certificate, or None on a miss (unknown, expired or revoked)."""
        now = time.time() if now is None else now
        entry = self._entries.get(fingerprint)
        if entry is None or now > entry.expires_at or entry.cert.serial in revoked:
            self._entries.pop(fingerprint, None)
            self.misses += 1
            return None
        self.hits += 1
        return entry.cert

    def __len__(self) -> int:
        return len(self._entries)
