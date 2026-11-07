"""
messages.py — the wire format of every message in the protocol.

Each message = 1 type byte + length-prefixed fields. Because we serialize to real
bytes, `len(message)` is exactly what goes on the wire — this is how we measure
"bytes transmitted" honestly.

Handshake (device <-> gateway):
    1. CLIENT_HELLO     device -> gateway   device id, nonce, certificate (full chain / leaf / fingerprint)
    2. SERVER_HELLO     gateway -> device   nonce, fresh ML-KEM public key, gateway cert, gateway signature
       (or CERT_REQUIRED if the gateway needs the full chain after all)
    3. CLIENT_FINISH    device -> gateway   ML-KEM ciphertext, device signature over the transcript
    4. HANDSHAKE_RESULT gateway -> device   ok / rejected + session id
Data:
    5. TELEMETRY        device -> gateway   AES-GCM encrypted reading (+ device signature in end-to-end mode)
Upstream (gateway -> grid server):
    6. UPSTREAM_SESSION  device chain, sent once per session (end-to-end mode only)
    7. UPSTREAM_DATA     reading + device signature (end-to-end) or gateway attestation (assisted)
"""
import struct
from enum import IntEnum


class MsgType(IntEnum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CERT_REQUIRED = 3
    CLIENT_FINISH = 4
    HANDSHAKE_RESULT = 5
    TELEMETRY = 6
    UPSTREAM_SESSION = 7
    UPSTREAM_DATA = 8


class CertMode(IntEnum):
    FULL_CHAIN = 0     # leaf + intermediate certificates (baseline)
    LEAF_ONLY = 1      # chain-transmission optimization
    FINGERPRINT = 2    # certificate caching


def pack_fields(*fields: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(f)) + f for f in fields)


def unpack_fields(data: bytes) -> list[bytes]:
    out, i = [], 0
    while i < len(data):
        (n,) = struct.unpack(">I", data[i:i + 4])
        out.append(data[i + 4:i + 4 + n])
        i += 4 + n
    return out


def encode(msg_type: MsgType, *fields: bytes) -> bytes:
    return bytes([msg_type]) + pack_fields(*fields)


def decode(data: bytes, expected: MsgType | None = None) -> tuple[MsgType, list[bytes]]:
    msg_type = MsgType(data[0])
    if expected is not None and msg_type != expected:
        raise ValueError(f"expected {expected.name}, got {msg_type.name}")
    return msg_type, unpack_fields(data[1:])
