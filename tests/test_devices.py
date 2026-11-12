"""Device simulator and fleet tests (owner: B)."""
import asyncio
import random

from backend.devices import SolarInverter, build_devices, build_fleet, run_fleet
from backend.gateway.config import COMBINED


def test_fleet_mix_and_determinism():
    kinds = [d.device_type for d in build_devices(100, seed=5)]
    assert kinds.count("ev_charger") == 40 and kinds.count("solar_inverter") == 35 and kinds.count("battery") == 25
    a = [d.tick(60) for d in build_devices(20, seed=5)]
    b = [d.tick(60) for d in build_devices(20, seed=5)]
    assert a == b


def test_telemetry_ranges():
    for d in build_devices(60, seed=9):
        for _ in range(200):
            t = d.tick(600)
            assert 200 < t["voltage_v"] < 480
            if "soc_pct" in t:
                assert 0 <= t["soc_pct"] <= 100
            assert t["power_kw"] >= -60


def test_solar_zero_at_night():
    assert SolarInverter("s", random.Random(1), start_hour=22.0).tick(60)["power_kw"] == 0


def test_fleet_runs_real_handshakes_end_to_end():
    events = []
    fleet = build_fleet(12, COMBINED, "highway_4g", seed=1)
    recs = asyncio.run(run_fleet(fleet, rounds=3, on_event=events.append))
    assert len(recs) == 36 == len(events)
    assert all(r.success for r in recs)
    assert sum(r.cache_hit for r in recs) == 24                    # rounds 2 and 3 hit the cache
    assert len(fleet.testbed.grid.readings) == 36                  # every reading reached the grid
    assert {"lat", "lon", "telemetry", "messages"} <= set(events[0])
