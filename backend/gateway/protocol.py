"""
protocol.py — runs one complete device session and returns a metrics record.

This is the single entry point that Person D's benchmark runner and Person E's
dashboard call. One call = one handshake + N telemetry readings.
"""
import time
from dataclasses import asdict, dataclass

from .client import DeviceClient
from .gateway import Gateway
from .grid_server import GridServer
from .link import DirectLink
from .messages import MsgType, decode


@dataclass
class SessionRecord:
    config: str
    device_id: str
    connection: str          # "first" or "repeat"
    success: bool
    reason: str
    cache_hit: bool
    bytes_up: int
    bytes_down: int
    bytes_upstream: int
    handshake_bytes: int
    messages: int
    device_ms: float
    gateway_ms: float
    grid_ms: float
    network_ms: float
    # filled when the session runs over the network model (backend.network.EmulatedLink)
    network: str = "direct"
    wire_bytes: int = 0          # bytes on the wire incl. IP/TCP headers and retransmissions
    packets: int = 0
    retransmissions: int = 0

    @property
    def latency_ms(self) -> float:
        """End-to-end session time: computation on every side + simulated network time."""
        return self.device_ms + self.gateway_ms + self.grid_ms + self.network_ms

    @property
    def total_bytes(self) -> int:
        return self.bytes_up + self.bytes_down + self.bytes_upstream

    def to_dict(self) -> dict:
        return {**asdict(self), "total_bytes": self.total_bytes, "latency_ms": round(self.latency_ms, 3)}


class _Timer:
    def __init__(self):
        self.ms = {"device": 0.0, "gateway": 0.0, "grid": 0.0}

    def run(self, who: str, fn, *args):
        t = time.perf_counter()
        try:
            return fn(*args)
        finally:
            self.ms[who] += (time.perf_counter() - t) * 1000


def run_session(client: DeviceClient, gateway: Gateway, grid: GridServer,
                readings: list[bytes], connection: str = "first", link=None) -> SessionRecord:
    link = link or DirectLink()
    t = _Timer()
    conn = None
    reason, ok = "", False

    def record() -> SessionRecord:
        return SessionRecord(gateway.config.name, client.device_id, connection, ok, reason,
                             bool(conn and conn.cache_hit),
                             link.bytes_up, link.bytes_down, link.bytes_upstream, hs_bytes, link.messages,
                             round(t.ms["device"], 3), round(t.ms["gateway"], 3), round(t.ms["grid"], 3),
                             round(link.network_s * 1000, 3),
                             getattr(getattr(link, "preset", None), "name", "direct"),
                             getattr(link, "wire_bytes", 0), getattr(link, "packets_transmitted", 0),
                             getattr(link, "packets_retransmitted", 0))

    hs_bytes = 0
    try:
        conn = gateway.connect()                  # raises ConnectionError if every gateway is down
        resp = link.down(t.run("gateway", conn.on_client_hello, link.up(t.run("device", client.client_hello))))
        # CERT_REQUIRED costs one extra round trip each time:
        #   cache miss -> resend without the fingerprint (leaf-only if chain optimization is on)
        #   unknown intermediate / chain optimization off -> resend the full chain
        for _ in range(2):
            if resp[0] != MsgType.CERT_REQUIRED:
                break
            _, (why,) = decode(resp, MsgType.CERT_REQUIRED)
            if why == b"cache miss":
                hello = t.run("device", client.client_hello, False, True)
            else:
                hello = t.run("device", client.client_hello, True)
            resp = link.down(t.run("gateway", conn.on_client_hello, link.up(hello)))
        if resp[0] == MsgType.HANDSHAKE_RESULT:   # rejected at hello
            ok, reason = client.on_result(resp)
            hs_bytes = link.bytes_up + link.bytes_down
            return record()

        finish = link.up(t.run("device", client.on_server_hello, resp))
        result = link.down(t.run("gateway", conn.on_client_finish, finish))
        ok, reason = client.on_result(result)
        hs_bytes = link.bytes_up + link.bytes_down
        if not ok:
            return record()

        for r in readings:
            msg = link.up(t.run("device", client.telemetry, r))
            for up in t.run("gateway", gateway.on_telemetry, msg):
                t.run("grid", grid.receive, link.upstream(up))
    except Exception as e:                        # any rejection is recorded, never hidden
        ok, reason = False, f"{type(e).__name__}: {e}"
        hs_bytes = hs_bytes or link.bytes_up + link.bytes_down
    return record()
