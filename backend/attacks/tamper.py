"""
tamper.py — attacks involving manipulation of messages in transit:
1. Tampered Handshake: Altering ciphertext or signature in CLIENT_FINISH.
2. Tampered Telemetry: Altering encrypted telemetry ciphertext or sequence headers.
3. Tampered Telemetry Signature: Altering device's per-reading ML-DSA signature in end-to-end mode.

Every attack must be caught and rejected.
"""
from dataclasses import dataclass
import hashlib
import struct

from backend.crypto import pqc, symmetric
from backend.gateway.gateway import Gateway
from backend.gateway.messages import MsgType, decode, encode
from backend.gateway.protocol import run_session
from backend.gateway.testbed import Testbed
from .impersonation import AttackResult


def attack_tampered_handshake_finish(testbed: Testbed) -> AttackResult:
    """Attacker intercepts CLIENT_FINISH and flips bits in the ML-KEM ciphertext or ML-DSA signature."""
    gw = testbed.gateway if isinstance(testbed.gateway, Gateway) else testbed.gateway.gateways[0]
    dev = testbed.devices[0]

    conn = gw.connect()
    hello = dev.client_hello()
    resp = conn.on_client_hello(hello)
    if resp[0] == MsgType.CERT_REQUIRED:
        hello = dev.client_hello(force_full=True)
        resp = conn.on_client_hello(hello)

    finish = dev.on_server_hello(resp)
    # Tamper with the proof signature (flip the last byte)
    _, (ciphertext, proof) = decode(finish, MsgType.CLIENT_FINISH)
    tampered_proof = proof[:-1] + bytes([proof[-1] ^ 0xFF])
    tampered_finish = encode(MsgType.CLIENT_FINISH, ciphertext, tampered_proof)

    result = conn.on_client_finish(tampered_finish)
    _, fields = decode(result, MsgType.HANDSHAKE_RESULT)
    blocked = (fields[0] == b"\x00")
    reason = fields[1].decode() if blocked else "Not rejected"

    return AttackResult(
        attack_name="Tampered Handshake Proof",
        attack_category="tamper",
        target_device=dev.device_id,
        config_name=gw.config.name,
        blocked=blocked,
        rejection_reason=reason,
    )


def attack_tampered_telemetry_ciphertext(testbed: Testbed) -> AttackResult:
    """Attacker intercepts an encrypted telemetry message and flips bits in the payload."""
    gw = testbed.gateway if isinstance(testbed.gateway, Gateway) else testbed.gateway.gateways[0]
    dev = testbed.devices[0]

    # Establish legitimate session
    rec = run_session(dev, gw, testbed.grid, [], "first")
    if not rec.success:
        return AttackResult("Tampered Telemetry Ciphertext", "tamper", dev.device_id, gw.config.name, False, "Setup failed")

    # Generate genuine telemetry packet
    legit_msg = dev.telemetry(b'{"voltage": 230.5, "current": 16.0}')
    _, (session_id, seq_b, blob, device_sig) = decode(legit_msg, MsgType.TELEMETRY)

    # Flip bits in the AES-GCM ciphertext
    tampered_blob = blob[:-2] + bytes([blob[-2] ^ 0xFF, blob[-1] ^ 0xAA])
    tampered_msg = encode(MsgType.TELEMETRY, session_id, seq_b, tampered_blob, device_sig)

    blocked = False
    reason = ""
    try:
        gw.on_telemetry(tampered_msg)
    except PermissionError as e:
        blocked = True
        reason = str(e)
    except Exception as e:
        blocked = True
        reason = type(e).__name__

    return AttackResult(
        attack_name="Tampered Telemetry Ciphertext",
        attack_category="tamper",
        target_device=dev.device_id,
        config_name=gw.config.name,
        blocked=blocked,
        rejection_reason=reason or "Not rejected",
    )


def attack_tampered_telemetry_signature_e2e(testbed: Testbed) -> AttackResult:
    """In end-to-end mode, device signature is verified by the grid server. Attacker tampers with the signature."""
    gw = testbed.gateway if isinstance(testbed.gateway, Gateway) else testbed.gateway.gateways[0]
    dev = testbed.devices[0]

    # Only relevant in end-to-end mode where device signatures are checked by grid server
    if gw.config.gateway_assisted:
        return AttackResult(
            attack_name="Tampered Telemetry Signature (E2E)",
            attack_category="tamper",
            target_device=dev.device_id,
            config_name=gw.config.name,
            blocked=True,
            rejection_reason="N/A (Gateway-assisted mode; gateway validates backhaul)",
        )

    # In E2E mode: establish session
    rec = run_session(dev, gw, testbed.grid, [], "first")
    legit_msg = dev.telemetry(b'{"kw": 45.2}')
    _, (session_id, seq_b, blob, device_sig) = decode(legit_msg, MsgType.TELEMETRY)

    tampered_sig = device_sig[:-1] + bytes([device_sig[-1] ^ 0x55])
    tampered_msg = encode(MsgType.TELEMETRY, session_id, seq_b, blob, tampered_sig)

    blocked = False
    reason = ""
    try:
        up_msgs = gw.on_telemetry(tampered_msg)
        for up in up_msgs:
            testbed.grid.receive(up)
    except ValueError as e:
        blocked = True
        reason = str(e)
    except Exception as e:
        blocked = True
        reason = type(e).__name__

    return AttackResult(
        attack_name="Tampered Telemetry Signature (E2E)",
        attack_category="tamper",
        target_device=dev.device_id,
        config_name=gw.config.name,
        blocked=blocked,
        rejection_reason=reason or "Not rejected",
    )
