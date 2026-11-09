"""
model.py — emulated network link with bandwidth, RTT, packet loss, and MTU fragmentation.

Implements the contract in docs/INTERFACES.md:
  up(data: bytes) -> bytes
  down(data: bytes) -> bytes
  upstream(data: bytes) -> bytes
  bytes_up, bytes_down, bytes_upstream, messages, network_s
"""
from dataclasses import dataclass, field
import math
import random


@dataclass(frozen=True)
class NetworkPreset:
    name: str
    bandwidth_bps: float      # bits per second
    rtt_s: float              # round-trip propagation + queuing delay (seconds)
    loss_rate: float          # packet drop probability [0.0, 1.0]
    mtu: int = 1500           # maximum transmission unit in bytes
    rto_s: float = 1.0        # TCP retransmission timeout (seconds)


# Standard India deployment presets from Build Plan
PRESET_5G = NetworkPreset(
    name="Urban 5G",
    bandwidth_bps=100_000_000.0,  # 100 Mbps
    rtt_s=0.015,                  # 15 ms RTT
    loss_rate=0.000,              # 0% packet loss
    mtu=1500,
    rto_s=0.2,
)

PRESET_4G = NetworkPreset(
    name="Highway 4G",
    bandwidth_bps=20_000_000.0,   # 20 Mbps
    rtt_s=0.060,                  # 60 ms RTT
    loss_rate=0.005,              # 0.5% packet loss
    mtu=1500,
    rto_s=0.5,
)

PRESET_2G = NetworkPreset(
    name="Rural 2G (lossy)",
    bandwidth_bps=100_000.0,      # 100 kbps (GPRS/EDGE)
    rtt_s=0.450,                  # 450 ms RTT
    loss_rate=0.040,              # 4% packet drop rate
    mtu=576,                      # standard 2G MTU
    rto_s=1.5,                    # slow retransmission backoff
)

ALL_PRESETS = [PRESET_5G, PRESET_4G, PRESET_2G]


@dataclass
class EmulatedLink:
    """Emulates a real wireless/cellular link between devices, gateway, and grid server."""
    preset: NetworkPreset = PRESET_5G
    deterministic: bool = True     # Use expected value for loss/delay if deterministic
    seed: int | None = None
    bytes_up: int = 0
    bytes_down: int = 0
    bytes_upstream: int = 0
    messages: int = 0
    network_s: float = 0.0
    packets_transmitted: int = 0
    packets_retransmitted: int = 0

    def __post_init__(self):
        self._rng = random.Random(self.seed) if self.seed is not None else random.Random(42)

    def _calc_delay(self, size_bytes: int, is_backhaul: bool = False) -> float:
        """Calculate transfer delay including fragmentation, transmission time, RTT, and loss."""
        if is_backhaul:
            # Gateway-to-grid fiber backhaul: 1 Gbps, 2 ms latency, 0% loss
            trans_s = (size_bytes * 8) / 1_000_000_000.0
            prop_s = 0.001
            return trans_s + prop_s

        p = self.preset
        payload_per_pkt = max(p.mtu - 40, 100)  # assume 40-byte IP/TCP header
        num_packets = math.ceil(size_bytes / payload_per_pkt) if size_bytes > 0 else 1
        self.packets_transmitted += num_packets

        trans_s = (size_bytes * 8) / p.bandwidth_bps
        one_way_delay = p.rtt_s / 2.0

        loss_delay = 0.0
        if p.loss_rate > 0:
            if self.deterministic:
                expected_retrans = num_packets * p.loss_rate
                loss_delay = expected_retrans * p.rto_s
                self.packets_retransmitted += int(round(expected_retrans))
            else:
                for _ in range(num_packets):
                    while self._rng.random() < p.loss_rate:
                        loss_delay += p.rto_s
                        self.packets_retransmitted += 1

        return trans_s + one_way_delay + loss_delay

    def up(self, data: bytes) -> bytes:
        size = len(data)
        self.bytes_up += size
        self.messages += 1
        self.network_s += self._calc_delay(size, is_backhaul=False)
        return data

    def down(self, data: bytes) -> bytes:
        size = len(data)
        self.bytes_down += size
        self.messages += 1
        self.network_s += self._calc_delay(size, is_backhaul=False)
        return data

    def upstream(self, data: bytes) -> bytes:
        size = len(data)
        self.bytes_upstream += size
        self.network_s += self._calc_delay(size, is_backhaul=True)
        return data
