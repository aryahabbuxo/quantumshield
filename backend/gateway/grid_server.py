"""
grid_server.py — the grid operator's server that receives readings from the gateway.

The gateway <-> grid link is a long-lived backhaul channel, set up once with ML-KEM and
authenticated with the gateway's ML-DSA certificate (register_gateway).
"""
import hashlib
from dataclasses import dataclass, field

from backend.crypto import pqc, symmetric
from backend.crypto.pki import Certificate

from .messages import MsgType, decode, unpack_fields
from .trust_store import TrustStore


@dataclass
class GridServer:
    trust: TrustStore
    readings: list = field(default_factory=list)
    device_certs: dict = field(default_factory=dict)
    channels: dict = field(default_factory=dict)

    def register_gateway(self, gateway) -> None:
        """One-time ML-KEM backhaul setup, authenticated by the gateway's certificate."""
        self.trust.validate(gateway.cert, [], use_memo=False)
        kem = pqc.kem_keygen()
        ciphertext, gw_secret = pqc.encapsulate(kem.public_key)               # gateway side
        proof = pqc.sign(hashlib.sha256(kem.public_key + ciphertext).digest(), gateway.keypair)
        if not pqc.verify(hashlib.sha256(kem.public_key + ciphertext).digest(), proof, gateway.cert.public_key):
            raise PermissionError("gateway authentication failed")
        grid_secret = pqc.decapsulate(ciphertext, kem)                       # grid side
        gateway.uplink_key = symmetric.derive_session_key(gw_secret, b"qsg-uplink")
        self.channels[gateway.name] = symmetric.derive_session_key(grid_secret, b"qsg-uplink")
        self.gateway_name = gateway.name

    def receive(self, data: bytes) -> dict:
        inner = symmetric.decrypt(self.channels[self.gateway_name], data)   # authenticated channel
        msg_type, f = decode(inner)

        if msg_type == MsgType.UPSTREAM_SESSION:                            # end-to-end mode only
            device_id, chain_b = f[0].decode(), f[1]
            certs = [Certificate.from_bytes(b) for b in unpack_fields(chain_b)]
            self.trust.validate(certs[0], certs[1:], use_memo=False)
            self.device_certs[device_id] = certs[0]
            return {"type": "session", "device": device_id}

        mode, device_id, seq, reading, device_sig = f[0], f[1].decode(), f[2], f[3], f[4]
        if mode == b"\x00":                                                 # end-to-end: verify device
            cert = self.device_certs.get(device_id)
            msg = hashlib.sha256(device_id.encode() + seq + reading).digest()
            if cert is None or not pqc.verify(msg, device_sig, cert.public_key, cert.sig_alg):
                raise PermissionError("device signature invalid at grid server")
        record = {"type": "reading", "device": device_id, "reading": reading,
                  "verified_by": "device" if mode == b"\x00" else "gateway"}
        self.readings.append(record)
        return record
