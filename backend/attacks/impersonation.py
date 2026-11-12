"""
impersonation.py — attacks that attempt to impersonate legitimate grid devices:
1. Fake CA: Device presenting a certificate issued by an untrusted / rogue CA.
2. Identity Mismatch: Device claiming one ID while presenting a certificate for a different ID.
3. Stolen Identity / Stolen Fingerprint: Attacker sending a legitimate device's certificate or
   32-byte cached fingerprint without holding the corresponding ML-DSA private key.

Every attack must be rejected by the gateway.
"""
from dataclasses import dataclass
import hashlib
import os

from backend.crypto import pqc
from backend.crypto.pki import CertificateAuthority
from backend.gateway.client import DeviceClient
from backend.gateway.gateway import Gateway
from backend.gateway.grid_server import GridServer
from backend.gateway.messages import CertMode, MsgType, decode, encode, pack_fields
from backend.gateway.protocol import run_session
from backend.gateway.testbed import Testbed


@dataclass
class AttackResult:
    attack_name: str
    attack_category: str
    target_device: str
    config_name: str
    blocked: bool
    rejection_reason: str


def attack_fake_ca(testbed: Testbed) -> AttackResult:
    """Attacker creates a rogue Root/Intermediate CA and issues a certificate for an EV charger."""
    rogue_root = CertificateAuthority.create_root("Rogue Fake Root CA")
    rogue_inter = rogue_root.create_intermediate("Rogue Intermediate CA")
    attacker_kp = pqc.sig_keygen()
    device_id = "EV_ROGUE_001"
    rogue_cert = rogue_inter.issue(device_id, attacker_kp.public_key)

    # Attacker tries to connect to the gateway with rogue certificate
    attacker_client = DeviceClient(
        device_id,
        attacker_kp,
        rogue_cert,
        [rogue_inter.cert],
        testbed.devices[0].trust,
        testbed.gateway.config if isinstance(testbed.gateway, Gateway) else testbed.gateway.gateways[0].config,
    )

    gw = testbed.gateway if isinstance(testbed.gateway, Gateway) else testbed.gateway
    rec = run_session(attacker_client, gw, testbed.grid, [b"fake_telemetry"], "first")
    blocked = not rec.success
    return AttackResult(
        attack_name="Fake CA",
        attack_category="impersonation",
        target_device=device_id,
        config_name=rec.config,
        blocked=blocked,
        rejection_reason=rec.reason or "Failed",
    )


def attack_identity_mismatch(testbed: Testbed) -> AttackResult:
    """Attacker presents a valid cert for EV_002 while claiming to be EV_001."""
    legit_dev2 = testbed.devices[1] if len(testbed.devices) > 1 else testbed.devices[0]
    claimed_id = "EV_001"  # Claims to be EV_001, but cert subject is EV_002
    gw = testbed.gateway if isinstance(testbed.gateway, Gateway) else testbed.gateway.gateways[0]

    # Create spoofed client hello
    nonce = os.urandom(32)
    hello = encode(
        MsgType.CLIENT_HELLO,
        claimed_id.encode(),
        nonce,
        bytes([CertMode.FULL_CHAIN]),
        pack_fields(legit_dev2.cert.to_bytes(), *(c.to_bytes() for c in legit_dev2.intermediates)),
    )
    conn = gw.connect()
    resp = conn.on_client_hello(hello)
    msg_type, fields = decode(resp)
    blocked = (msg_type == MsgType.HANDSHAKE_RESULT and fields[0] == b"\x00")
    reason = fields[1].decode() if blocked else "Not rejected"

    return AttackResult(
        attack_name="Identity Mismatch",
        attack_category="impersonation",
        target_device=claimed_id,
        config_name=gw.config.name,
        blocked=blocked,
        rejection_reason=reason,
    )


def attack_stolen_fingerprint(testbed: Testbed) -> AttackResult:
    """Attacker intercepts EV_001's cached 32-byte fingerprint and tries to connect without the private key."""
    gw = testbed.gateway if isinstance(testbed.gateway, Gateway) else testbed.gateway.gateways[0]
    legit_dev = testbed.devices[0]

    # Warm up legitimate device so it gets cached at gateway
    run_session(legit_dev, gw, testbed.grid, [], "first")

    # Attacker crafts client hello with victim's device_id and stolen fingerprint
    attacker_kp = pqc.sig_keygen()  # Attacker does NOT have victim's private key
    nonce = os.urandom(32)
    stolen_fp = legit_dev.cert.fingerprint()
    hello = encode(MsgType.CLIENT_HELLO, legit_dev.device_id.encode(), nonce, bytes([CertMode.FINGERPRINT]), stolen_fp)

    conn = gw.connect()
    resp = conn.on_client_hello(hello)
    if resp[0] == MsgType.CERT_REQUIRED:
        # If cache is disabled, it asks for cert (rejected from impersonator's perspective)
        return AttackResult(
            attack_name="Stolen Fingerprint (no private key)",
            attack_category="impersonation",
            target_device=legit_dev.device_id,
            config_name=gw.config.name,
            blocked=True,
            rejection_reason="Cache miss / Certificate required",
        )

    # Gateway responded with SERVER_HELLO expecting valid ML-DSA signature on transcript
    _, (server_nonce, kem_pk, gw_cert_b, gw_sig) = decode(resp, MsgType.SERVER_HELLO)
    ciphertext, secret = pqc.encapsulate(kem_pk)
    transcript_hash = hashlib.sha256(hello + resp + ciphertext).digest()

    # Attacker tries to forge the proof using their own wrong private key
    fake_proof = pqc.sign(transcript_hash, attacker_kp)
    finish = encode(MsgType.CLIENT_FINISH, ciphertext, fake_proof)

    result = conn.on_client_finish(finish)
    _, res_fields = decode(result, MsgType.HANDSHAKE_RESULT)
    blocked = (res_fields[0] == b"\x00")
    reason = res_fields[1].decode() if blocked else "Not rejected"

    return AttackResult(
        attack_name="Stolen Fingerprint (no private key)",
        attack_category="impersonation",
        target_device=legit_dev.device_id,
        config_name=gw.config.name,
        blocked=blocked,
        rejection_reason=reason,
    )
