"""
revoked.py — attacks involving revoked and expired certificates:
1. Revoked Certificate (Initial Connection): Certificate revoked prior to handshake.
2. Revoked Certificate (Cached): Device previously connected and cached, then revoked.
   Proves that caching NEVER bypasses revocation checks.
3. Expired Certificate: Certificate whose validity period has elapsed.

Every attack must be rejected by the gateway.
"""
import time

from backend.crypto import pqc
from backend.crypto.pki import Certificate
from backend.gateway.client import DeviceClient
from backend.gateway.gateway import Gateway
from backend.gateway.messages import MsgType
from backend.gateway.protocol import run_session
from backend.gateway.testbed import Testbed
from .impersonation import AttackResult


def attack_revoked_cert_initial(testbed: Testbed) -> AttackResult:
    """Device attempts initial connection after its certificate has been revoked by the CA."""
    gw = testbed.gateway if isinstance(testbed.gateway, Gateway) else testbed.gateway.gateways[0]
    dev = testbed.devices[0]

    # Revoke device certificate in the gateway's trust store
    gw.trust.revoke(dev.cert.serial)

    rec = run_session(dev, gw, testbed.grid, [], "first")
    blocked = not rec.success
    return AttackResult(
        attack_name="Revoked Certificate (Initial)",
        attack_category="revoked_expired",
        target_device=dev.device_id,
        config_name=gw.config.name,
        blocked=blocked,
        rejection_reason=rec.reason or "Failed",
    )


def attack_revoked_cert_cached(testbed: Testbed) -> AttackResult:
    """Device connects successfully, gets cached at gateway, then is revoked by the CA.
    
    Subsequent repeat connections with fingerprint MUST be blocked.
    """
    gw = testbed.gateway if isinstance(testbed.gateway, Gateway) else testbed.gateway.gateways[0]
    dev = testbed.devices[0]

    # Ensure clean state and warm up cache
    gw.trust.revoked.discard(dev.cert.serial)
    rec1 = run_session(dev, gw, testbed.grid, [], "first")
    if not rec1.success:
        return AttackResult("Revoked Certificate (Cached)", "revoked_expired", dev.device_id, gw.config.name, False, "Warmup failed")

    # Now revoke certificate
    gw.trust.revoke(dev.cert.serial)

    # Attempt repeat session with fingerprint
    rec2 = run_session(dev, gw, testbed.grid, [], "repeat")
    blocked = not rec2.success

    return AttackResult(
        attack_name="Revoked Certificate (Cached)",
        attack_category="revoked_expired",
        target_device=dev.device_id,
        config_name=gw.config.name,
        blocked=blocked,
        rejection_reason=rec2.reason or "Failed",
    )


def attack_expired_cert(testbed: Testbed) -> AttackResult:
    """Device presents an expired certificate."""
    gw = testbed.gateway if isinstance(testbed.gateway, Gateway) else testbed.gateway.gateways[0]
    now = int(time.time())
    kp = pqc.sig_keygen()
    device_id = "EV_EXPIRED_001"

    # Issue cert from 10 days ago, valid for only 1 day -> expired 9 days ago
    expired_cert = testbed.intermediate.issue(
        device_id,
        kp.public_key,
        days=1,
        not_before=now - (10 * 86400),
    )

    client = DeviceClient(
        device_id,
        kp,
        expired_cert,
        [testbed.intermediate.cert],
        testbed.devices[0].trust,
        gw.config,
    )

    rec = run_session(client, gw, testbed.grid, [], "first")
    blocked = not rec.success

    return AttackResult(
        attack_name="Expired Certificate",
        attack_category="revoked_expired",
        target_device=device_id,
        config_name=gw.config.name,
        blocked=blocked,
        rejection_reason=rec.reason or "Failed",
    )
