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
from .messages import MsgType


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

    @property
    def total_bytes(self) -> int:
        return self.bytes_up + self.bytes_down + self.bytes_upstream

    def to_dict(self) -> dict:
        return {**asdict(self), "total_bytes": self.total_bytes}


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
    conn = gateway.connect()
    reason, ok = "", False

    def record() -> SessionRecord:
        hs = link.bytes_up + link.bytes_down
        return SessionRecord(gateway.config.name, client.device_id, connection, ok, reason, conn.cache_hit,
                             link.bytes_up, link.bytes_down, link.bytes_upstream, hs_bytes, link.messages,
                             round(t.ms["device"], 3), round(t.ms["gateway"], 3), round(t.ms["grid"], 3),
                             round(link.network_s * 1000, 3))

    hs_bytes = 0
    try:
        resp = link.down(t.run("gateway", conn.on_client_hello, link.up(t.run("device", client.client_hello))))
        if resp[0] == MsgType.CERT_REQUIRED:      # cache miss / unknown intermediate -> one extra round trip
            hello = link.up(t.run("device", client.client_hello, True))
            resp = link.down(t.run("gateway", conn.on_client_hello, hello))
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
