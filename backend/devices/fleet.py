"""
fleet.py — a fleet of 1 to 1,000+ simulated clean-energy devices running the REAL protocol (owner: B).

Each device = a telemetry simulator (EV charger / solar inverter / battery, from this package)
            + a DeviceClient (C's protocol: real ML-KEM, ML-DSA, certificates)
            + its own EmulatedLink (B's network model: bandwidth, RTT, loss, MTU, retransmission).

Every "round", every device wakes up, takes a reading, connects to the gateway (a full PQC
handshake, or a cache hit if caching is on), sends its reading(s), and disconnects.
Devices run concurrently with asyncio; time is virtual unless time_scale > 0 (live demo).
"""
from __future__ import annotations

import asyncio
import random
from collections.abc import Callable
from dataclasses import dataclass

from backend.gateway.config import BASELINE, OptimizationConfig
from backend.gateway.protocol import SessionRecord, run_session
from backend.gateway.testbed import Testbed, build_testbed
from backend.network import EmulatedLink, NetworkConfig, get_preset

from .base import Device
from .battery import Battery
from .ev_charger import EVCharger
from .solar_inverter import SolarInverter

DEVICE_TYPES = {"ev_charger": EVCharger, "solar_inverter": SolarInverter, "battery": Battery}
ID_PREFIX = {"ev_charger": "EV", "solar_inverter": "SOLAR", "battery": "BAT"}
DEFAULT_MIX = {"ev_charger": 0.40, "solar_inverter": 0.35, "battery": 0.25}


def build_devices(n: int, mix: dict[str, float] | None = None, seed: int = 0) -> list[Device]:
    """Deterministic set of telemetry simulators; the type mix matches `mix` as closely as integers allow."""
    mix = mix or DEFAULT_MIX
    types, weights = list(mix), list(mix.values())
    edges, acc = [], 0.0
    for w in weights:
        acc += w / sum(weights)
        edges.append(acc)
    devices = []
    for i in range(n):
        kind = types[next(j for j, e in enumerate(edges) if (i + 0.5) / n <= e + 1e-9)]
        devices.append(DEVICE_TYPES[kind](f"{ID_PREFIX[kind]}-{i + 1:04d}", random.Random(seed * 1_000_003 + i)))
    return devices


@dataclass
class Fleet:
    config: OptimizationConfig
    preset: NetworkConfig
    testbed: Testbed
    devices: list[Device]
    seed: int = 0
    rounds_done: int = 0

    @property
    def clients(self):
        return {c.device_id: c for c in self.testbed.devices}


def build_fleet(n: int, config: OptimizationConfig = BASELINE, preset: str | NetworkConfig = "urban_5g",
                n_gateways: int = 1, seed: int = 0, mix: dict[str, float] | None = None) -> Fleet:
    """Simulators + a full PKI and gateway(s) with one certificate per device."""
    devices = build_devices(n, mix, seed)
    tb = build_testbed(config, device_ids=[d.device_id for d in devices], n_gateways=n_gateways)
    cfg = get_preset(preset) if isinstance(preset, str) else preset
    return Fleet(config, cfg, tb, devices, seed)


async def run_fleet(fleet: Fleet, rounds: int = 5, interval_s: float = 60.0, readings_per_session: int = 1,
                    time_scale: float = 0.0,
                    on_event: Callable[[dict], None] | None = None,
                    should_stop: Callable[[], bool] | None = None) -> list[SessionRecord]:
    """
    rounds               how many times each device wakes up and connects
    interval_s           simulated seconds between wake-ups (advances device state, e.g. solar curve)
    readings_per_session telemetry readings sent per connection
    time_scale           0 = as fast as possible; >0 = really sleep (network time + interval) x time_scale
    on_event             called with a dict for every session (used by the live dashboard)
    """
    records: list[SessionRecord] = []
    clients = fleet.clients
    tb = fleet.testbed

    async def device_loop(idx: int, dev: Device):
        client = clients[dev.device_id]
        if time_scale > 0:                               # stagger so devices don't all connect at once
            await asyncio.sleep(random.Random(idx).uniform(0, interval_s * time_scale))
        for r in range(rounds):
            if should_stop and should_stop():
                return
            telemetry = [dev.tick(interval_s) for _ in range(readings_per_session)]
            link = EmulatedLink(fleet.preset, seed=fleet.seed * 1_000_003 + idx * 1_009 + fleet.rounds_done + r)
            connection = "first" if (fleet.rounds_done + r) == 0 else "repeat"
            rec = run_session(client, tb.gateway, tb.grid, [dev.encode(t) for t in telemetry], connection, link)
            records.append(rec)
            if on_event:
                on_event({"type": "session", "device_id": dev.device_id, "device_type": dev.device_type,
                          "lat": dev.lat, "lon": dev.lon, "telemetry": telemetry[-1],
                          "record": rec.to_dict(),
                          "messages": [m.__dict__ for m in link.log]})
            await asyncio.sleep((rec.latency_ms / 1000 + interval_s) * time_scale if time_scale > 0 else 0)

    await asyncio.gather(*(device_loop(i, d) for i, d in enumerate(fleet.devices)))
    fleet.rounds_done += rounds
    return records
