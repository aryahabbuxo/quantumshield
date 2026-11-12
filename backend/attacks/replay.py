"""
replay.py — attacks that attempt to replay previously valid messages:
1. Replayed Telemetry: Re-sending an already transmitted telemetry packet with an older/equal sequence number.
2. Replayed Handshake: Replaying a CLIENT_FINISH proof from a previous session against a fresh server hello.

Both must be rejected immediately by the gateway.
"""
from backend.gateway.gateway import Gateway
from backend.gateway.messages import MsgType, decode, encode
from backend.gateway.protocol import run_session
from backend.gateway.testbed import Testbed
from .impersonation import AttackResult


def attack_replayed_telemetry(testbed: Testbed) -> AttackResult:
    """Attacker captures a valid telemetry packet and replays it to the gateway."""
    gw = testbed.gateway if isinstance(testbed.gateway, Gateway) else testbed.gateway.gateways[0]
    dev = testbed.devices[0]

    # Establish legitimate session
    rec = run_session(dev, gw, testbed.grid, [], "first")
    if not rec.success:
        return AttackResult("Replayed Telemetry", "replay", dev.device_id, gw.config.name, False, "Setup failed")

    # Send message 1
    msg1 = dev.telemetry(b'{"power_kw": 12.5}')
    up_msgs = gw.on_telemetry(msg1)
    for up in up_msgs:
        testbed.grid.receive(up)

    # Attacker replays message 1
    blocked = False
    reason = ""
    try:
        gw.on_telemetry(msg1)
    except PermissionError as e:
        blocked = True
        reason = str(e)
    except Exception as e:
        blocked = True
        reason = type(e).__name__

    return AttackResult(
        attack_name="Replayed Telemetry Packet",
        attack_category="replay",
        target_device=dev.device_id,
        config_name=gw.config.name,
        blocked=blocked,
        rejection_reason=reason or "Not rejected",
    )


def attack_replayed_handshake_finish(testbed: Testbed) -> AttackResult:
    """Attacker replays a CLIENT_FINISH message from an earlier session into a new handshake."""
    gw = testbed.gateway if isinstance(testbed.gateway, Gateway) else testbed.gateway.gateways[0]
    dev = testbed.devices[0]

    # Session 1: capture valid finish
    conn1 = gw.connect()
    hello1_b = dev.client_hello(force_full=True)
    resp1 = conn1.on_client_hello(hello1_b)
    finish1 = dev.on_server_hello(resp1)
    conn1.on_client_finish(finish1)

    # Session 2: new handshake initiated
    conn2 = gw.connect()
    hello2_b = dev.client_hello(force_full=True)
    resp2 = conn2.on_client_hello(hello2_b)

    # Attacker injects old finish1 instead of generating a fresh proof over session 2's transcript
    res2 = conn2.on_client_finish(finish1)
    _, fields = decode(res2, MsgType.HANDSHAKE_RESULT)
    blocked = (fields[0] == b"\x00")
    reason = fields[1].decode() if blocked else "Not rejected"

    return AttackResult(
        attack_name="Replayed Handshake Finish",
        attack_category="replay",
        target_device=dev.device_id,
        config_name=gw.config.name,
        blocked=blocked,
        rejection_reason=reason or "Not rejected",
    )
