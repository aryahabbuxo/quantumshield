"""
gateway.py — the PQC gateway: authenticates devices, establishes ML-KEM sessions,
decrypts telemetry and forwards it to the grid server.

Trust model (write this in the paper):
  * End-to-end mode (gateway_assisted = False): the grid server does NOT trust the gateway's
    word. The gateway forwards each device's certificate chain and per-reading device
    signatures, and the grid server verifies everything itself.
  * Gateway-assisted mode (gateway_assisted = True): the grid server trusts the gateway, which
    is authenticated by its own ML-DSA certificate over a PQC-secured backhaul channel. The gateway
    validates devices once, remembers verified CA certificates, and devices no longer sign each reading.
"""
import hashlib
import os
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag

from backend.crypto import pqc, symmetric
from backend.crypto.pki import Certificate, ValidationError

from .cache import CertCache
from .config import OptimizationConfig
from .messages import CertMode, MsgType, decode, encode, pack_fields, unpack_fields
from .trust_store import TrustStore


@dataclass
class Session:
    device_cert: Certificate
    chain: list[Certificate]
    key: bytes
    last_seq: int = 0
    announced_upstream: bool = False


@dataclass
class Gateway:
    name: str
    keypair: pqc.SigKeyPair
    cert: Certificate
    trust: TrustStore
    config: OptimizationConfig
    sessions: dict = field(default_factory=dict)
    uplink_key: bytes | None = None          # set by GridServer.register_gateway()
    alive: bool = True                       # False = crashed (used by GatewayCluster for failover)
    cache_listeners: list = field(default_factory=list)   # called when a certificate is cached
    clock: Callable[[], float] = time.time   # replaceable so experiments can simulate days in seconds
    # Optional live revocation check (OCSP-style), run on every FULL validation but not on a
    # cache hit. Returns True if the certificate is revoked. Between checks the gateway relies on
    # its local revocation list, which is refreshed periodically.
    status_check: Callable[[Certificate], bool] | None = None

    def __post_init__(self):
        self.cache = CertCache(self.config.cache_ttl_s)

    def connect(self) -> "GatewayConnection":
        return GatewayConnection(self)

    # ------------------------------------------------------- telemetry ---
    def on_telemetry(self, data: bytes) -> list[bytes]:
        """Decrypt one reading and return the upstream message(s) for the grid server."""
        _, (session_id, seq_b, blob, device_sig) = decode(data, MsgType.TELEMETRY)
        s = self.sessions.get(session_id)
        if s is None:
            raise PermissionError("unknown session")
        (seq,) = struct.unpack(">Q", seq_b)
        if seq <= s.last_seq:
            raise PermissionError("replayed message")
        try:
            reading = symmetric.decrypt(s.key, blob, associated_data=session_id + seq_b)
        except InvalidTag:
            raise PermissionError("tampered message")
        s.last_seq = seq

        out = []
        device_id = s.device_cert.subject.encode()
        if self.config.gateway_assisted:
            out.append(self._uplink(MsgType.UPSTREAM_DATA, b"\x01", device_id, seq_b, reading, b""))
        else:
            if not s.announced_upstream:
                out.append(self._uplink(MsgType.UPSTREAM_SESSION, device_id,
                                        pack_fields(*(c.to_bytes() for c in [s.device_cert, *s.chain]))))
                s.announced_upstream = True
            out.append(self._uplink(MsgType.UPSTREAM_DATA, b"\x00", device_id, seq_b, reading, device_sig))
        return out

    def _uplink(self, msg_type: MsgType, *fields: bytes) -> bytes:
        return symmetric.encrypt(self.uplink_key, encode(msg_type, *fields))


class GatewayConnection:
    """State for one device handshake."""

    def __init__(self, gateway: Gateway):
        self.gw = gateway
        self.cache_hit = False
        self.leaf: Certificate | None = None

    def _reject(self, reason: str) -> bytes:
        self.rejected = reason
        return encode(MsgType.HANDSHAKE_RESULT, b"\x00", reason.encode())

    def on_client_hello(self, data: bytes) -> bytes:
        cfg, trust, now = self.gw.config, self.gw.trust, self.gw.clock()
        _, (device_id, client_nonce, mode_b, payload) = decode(data, MsgType.CLIENT_HELLO)
        mode = CertMode(mode_b[0])
        self.chain: list[Certificate] = []

        if mode == CertMode.FINGERPRINT:
            cert = self.gw.cache.get(payload, trust.revoked, now) if cfg.cache else None
            if cert is None:
                return encode(MsgType.CERT_REQUIRED, b"cache miss")      # device resends full chain
            self.leaf, self.cache_hit = cert, True
        else:
            if mode == CertMode.LEAF_ONLY and not cfg.chain_opt:
                return encode(MsgType.CERT_REQUIRED, b"chain optimization disabled")
            certs = [Certificate.from_bytes(b) for b in unpack_fields(payload)]
            leaf, supplied = certs[0], certs[1:]
            try:
                trust.validate(leaf, supplied, use_memo=cfg.gateway_assisted, now=now)
            except ValidationError as e:
                if mode == CertMode.LEAF_ONLY and "unknown issuer" in str(e):
                    return encode(MsgType.CERT_REQUIRED, b"unknown intermediate")
                return self._reject(str(e))
            if self.gw.status_check is not None and self.gw.status_check(leaf):
                trust.revoke(leaf.serial)              # remember it locally too
                return self._reject(f"{leaf.subject}: certificate revoked (live status check)")
            self.leaf, self.chain = leaf, supplied   # chain is forwarded upstream in end-to-end mode

        if self.leaf.subject != device_id.decode():
            return self._reject("device id does not match certificate")

        # fresh ML-KEM key pair per handshake -> forward secrecy
        self.kem = pqc.kem_keygen()
        server_nonce = os.urandom(32)
        sig = pqc.sign(hashlib.sha256(data + server_nonce + self.kem.public_key).digest(), self.gw.keypair)
        response = encode(MsgType.SERVER_HELLO, server_nonce, self.kem.public_key, self.gw.cert.to_bytes(), sig)
        self.transcript = data + response
        return response

    def on_client_finish(self, data: bytes) -> bytes:
        _, (ciphertext, proof) = decode(data, MsgType.CLIENT_FINISH)
        transcript_hash = hashlib.sha256(self.transcript + ciphertext).digest()
        # the device must prove it owns the private key — even on a cache hit
        if not pqc.verify(transcript_hash, proof, self.leaf.public_key, self.leaf.sig_alg):
            return self._reject("device signature invalid")
        secret = pqc.decapsulate(ciphertext, self.kem)
        key = symmetric.derive_session_key(secret, b"qsg-session" + transcript_hash)

        session_id = os.urandom(16)
        self.gw.sessions[session_id] = Session(self.leaf, self.chain, key)
        if self.gw.config.cache and not self.cache_hit:
            self.gw.cache.put(self.leaf, self.gw.clock())
            for notify in self.gw.cache_listeners:     # e.g. replicate to backup gateways
                notify(self.leaf)
        return encode(MsgType.HANDSHAKE_RESULT, b"\x01", session_id)
