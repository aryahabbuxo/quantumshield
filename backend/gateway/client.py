"""
client.py — the device side of the protocol.

Person B's device simulators (EV charger, solar inverter, battery) each own a
DeviceClient and call it to connect and send telemetry. Keeping the protocol logic here
means B never has to touch cryptography, and C controls the whole protocol in one place.
"""
import hashlib
import os
import struct

from backend.crypto import pqc, symmetric
from backend.crypto.pki import Certificate

from .config import OptimizationConfig
from .messages import CertMode, MsgType, decode, encode, pack_fields
from .trust_store import TrustStore


class DeviceClient:
    def __init__(self, device_id: str, keypair: pqc.SigKeyPair, cert: Certificate,
                 intermediates: list[Certificate], trust: TrustStore, config: OptimizationConfig):
        self.device_id = device_id
        self.keypair = keypair
        self.cert = cert
        self.intermediates = intermediates      # CA certs between the device and the root
        self.trust = trust                      # what the device trusts (to check the gateway)
        self.config = config
        self.cached_at_gateway = False          # set after a successful handshake when caching is on
        self.session_id: bytes | None = None
        self.key: bytes | None = None
        self.seq = 0

    # -------------------------------------------------------- handshake ---
    def client_hello(self, force_full: bool = False, skip_cache: bool = False) -> bytes:
        """force_full: send the whole chain. skip_cache: don't send the fingerprint (after a cache miss)."""
        self.nonce = os.urandom(32)
        if self.config.cache and self.cached_at_gateway and not (force_full or skip_cache):
            mode, payload = CertMode.FINGERPRINT, self.cert.fingerprint()
        elif self.config.chain_opt and not force_full:
            mode, payload = CertMode.LEAF_ONLY, pack_fields(self.cert.to_bytes())
        else:
            mode, payload = CertMode.FULL_CHAIN, pack_fields(
                self.cert.to_bytes(), *(c.to_bytes() for c in self.intermediates))
        self.hello = encode(MsgType.CLIENT_HELLO, self.device_id.encode(), self.nonce, bytes([mode]), payload)
        return self.hello

    def on_server_hello(self, data: bytes) -> bytes:
        """Authenticate the gateway, run ML-KEM, prove our identity. Returns CLIENT_FINISH."""
        _, (server_nonce, kem_pk, gw_cert_bytes, gw_sig) = decode(data, MsgType.SERVER_HELLO)
        gw_cert = Certificate.from_bytes(gw_cert_bytes)
        self.trust.validate(gw_cert, [], use_memo=True)          # is this a genuine gateway?
        signed = hashlib.sha256(self.hello + server_nonce + kem_pk).digest()
        if not pqc.verify(signed, gw_sig, gw_cert.public_key, gw_cert.sig_alg):
            raise ValueError("gateway signature invalid")

        ciphertext, secret = pqc.encapsulate(kem_pk)                      # ML-KEM
        transcript_hash = hashlib.sha256(self.hello + data + ciphertext).digest()
        proof = pqc.sign(transcript_hash, self.keypair)                   # ML-DSA: proves key ownership
        self.key = symmetric.derive_session_key(secret, b"qsg-session" + transcript_hash)
        return encode(MsgType.CLIENT_FINISH, ciphertext, proof)

    def on_result(self, data: bytes) -> tuple[bool, str]:
        _, fields = decode(data, MsgType.HANDSHAKE_RESULT)
        if fields[0] != b"\x01":
            return False, fields[1].decode()
        self.session_id, self.seq = fields[1], 0
        if self.config.cache:
            self.cached_at_gateway = True
        return True, ""

    # -------------------------------------------------------- telemetry ---
    def telemetry(self, reading: bytes) -> bytes:
        """Encrypt one reading. In end-to-end mode the device also signs it for the grid server."""
        self.seq += 1
        seq = struct.pack(">Q", self.seq)
        blob = symmetric.encrypt(self.key, reading, associated_data=self.session_id + seq)
        sig = b""
        if not self.config.gateway_assisted:
            sig = pqc.sign(hashlib.sha256(self.device_id.encode() + seq + reading).digest(), self.keypair)
        return encode(MsgType.TELEMETRY, self.session_id, seq, blob, sig)
