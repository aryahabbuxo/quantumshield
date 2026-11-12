"""
model.py — the network model (owner: B).

One engine, used everywhere: experiments, the device fleet and the live dashboard.

How one message is delivered (packet level):
  1. Split the message into packets of at most MTU bytes; each carries 40 B of IP+TCP header,
     so useful data per packet (MSS) = MTU - 40.
  2. Put every packet on the wire:      time += wire_bytes * 8 / bandwidth.
  3. Each packet is lost independently with probability loss_rate.
  4. If any were lost: wait one retransmission timeout (RTO), resend ONLY the lost packets,
     and repeat. RTO starts at max(min_rto, 1.5 x RTT) and doubles every round (backoff).
  5. When everything has arrived:      time += RTT / 2 (one-way propagation) + jitter.
  6. After max_retries failed rounds the message is lost -> the session fails (reliability).

Time is VIRTUAL: delays are calculated, not waited for, so 1,000 devices simulate in seconds.
Every link has its own seeded random generator, so every run is reproducible.

Limitations (state in the paper): no TCP congestion control or slow start, independent
packet loss (no bursts), no queueing at a shared bottleneck, each message counted one-way.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

IP_TCP_HEADER = 40  # 20 B IPv4 + 20 B TCP


@dataclass(frozen=True)
class NetworkConfig:
    name: str
    bandwidth_bps: float
    rtt_s: float
    loss_rate: float
    mtu: int = 1500
    jitter_s: float = 0.0
    header_bytes: int = IP_TCP_HEADER
    min_rto_s: float = 0.2
    max_retries: int = 8
    backoff: float = 2.0


NetworkPreset = NetworkConfig     # name used by the experiments code


@dataclass
class TransferResult:
    payload_bytes: int
    wire_bytes: int          # headers + retransmissions included
    packets: int             # distinct packets before retransmission
    retransmissions: int
    latency_s: float
    success: bool


def fragment(payload_bytes: int, mtu: int, header_bytes: int = IP_TCP_HEADER) -> list[int]:
    """On-the-wire size of each packet needed to carry the payload."""
    mss = mtu - header_bytes
    if mss <= 0:
        raise ValueError("MTU must be larger than the header size")
    if payload_bytes <= 0:
        return []
    full, rem = divmod(payload_bytes, mss)
    return [mtu] * full + ([rem + header_bytes] if rem else [])


def simulate_transfer(cfg: NetworkConfig, payload_bytes: int, rng: random.Random) -> TransferResult:
    """Deliver one message over the link described by cfg (pure computation, no sleeping)."""
    pending = fragment(payload_bytes, cfg.mtu, cfg.header_bytes)
    n_packets = len(pending)
    wire = retx = attempt = 0
    t = 0.0
    rto = max(cfg.min_rto_s, 1.5 * cfg.rtt_s)
    while pending:
        batch = sum(pending)
        wire += batch
        t += batch * 8 / cfg.bandwidth_bps
        lost = [s for s in pending if rng.random() < cfg.loss_rate]
        if not lost:
            break
        if attempt >= cfg.max_retries:
            return TransferResult(payload_bytes, wire, n_packets, retx, t, False)
        t += rto * (cfg.backoff ** attempt)
        retx += len(lost)
        pending = lost
        attempt += 1
    t += cfg.rtt_s / 2 + max(0.0, rng.gauss(0, cfg.jitter_s))
    return TransferResult(payload_bytes, wire, n_packets, retx, t, True)


@dataclass
class MessageLog:
    direction: str           # "up" (device->gateway), "down" (gateway->device), "upstream" (gateway->grid)
    kind: str                # message type name, e.g. CLIENT_HELLO
    payload_bytes: int
    wire_bytes: int
    packets: int
    retransmissions: int
    latency_ms: float


class LinkFailure(ConnectionError):
    """A message was lost after every retry: the session fails."""


@dataclass
class EmulatedLink:
    """
    Drop-in replacement for gateway.link.DirectLink (same methods, see docs/INTERFACES.md),
    so run_session() runs the REAL PQC handshake over this simulated network.
    """
    preset: NetworkConfig | None = None
    seed: int = 0
    backhaul: NetworkConfig | None = None
    bytes_up: int = 0
    bytes_down: int = 0
    bytes_upstream: int = 0
    messages: int = 0
    network_s: float = 0.0
    wire_bytes: int = 0
    packets_transmitted: int = 0
    packets_retransmitted: int = 0
    log: list = field(default_factory=list)

    def __post_init__(self):
        from .presets import BACKHAUL_FIBRE, URBAN_5G
        self.preset = self.preset or URBAN_5G
        self.backhaul = self.backhaul or BACKHAUL_FIBRE
        self._rng = random.Random(self.seed)

    def _send(self, data: bytes, direction: str, cfg: NetworkConfig) -> bytes:
        r = simulate_transfer(cfg, len(data), self._rng)
        self.network_s += r.latency_s
        self.wire_bytes += r.wire_bytes
        self.packets_transmitted += r.packets
        self.packets_retransmitted += r.retransmissions
        kind = _message_kind(data, direction)
        self.log.append(MessageLog(direction, kind, len(data), r.wire_bytes, r.packets,
                                   r.retransmissions, round(r.latency_s * 1000, 3)))
        if not r.success:
            raise LinkFailure(f"{kind} lost after {cfg.max_retries} retries on {cfg.name}")
        return data

    def up(self, data: bytes) -> bytes:
        self.bytes_up += len(data)
        self.messages += 1
        return self._send(data, "up", self.preset)

    def down(self, data: bytes) -> bytes:
        self.bytes_down += len(data)
        self.messages += 1
        return self._send(data, "down", self.preset)

    def upstream(self, data: bytes) -> bytes:
        self.bytes_upstream += len(data)
        return self._send(data, "upstream", self.backhaul)


def _message_kind(data: bytes, direction: str) -> str:
    if direction == "upstream":
        return "UPSTREAM (encrypted)"
    try:
        from backend.gateway.messages import MsgType
        return MsgType(data[0]).name
    except (ValueError, IndexError):
        return "UNKNOWN"


# Presets live in presets.py; re-exported here for code that imports them from model.
from .presets import ALL_PRESETS, PRESET_2G, PRESET_4G, PRESET_5G  # noqa: E402,F401
