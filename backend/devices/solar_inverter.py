from __future__ import annotations
import math
from .base import Device


class SolarInverter(Device):
    """Output follows a daylight curve (06:00-18:00) scaled by a slowly drifting cloud factor."""
    device_type = "solar_inverter"

    def __init__(self, device_id, rng, start_hour=None):
        super().__init__(device_id, rng, start_hour)
        self.rated_kw = rng.choice([5.0, 10.0, 25.0, 50.0])
        self.cloud = rng.uniform(0.6, 1.0)
        self.power_kw = 0.0
        self.voltage_v = 230.0
        self.energy_kwh = 0.0

    def _step(self, dt_s):
        r = self.rng
        self.cloud = min(1.0, max(0.25, self.cloud + r.gauss(0, 0.08)))
        h = self.sim_hour
        daylight = math.sin(math.pi * (h - 6) / 12) if 6 < h < 18 else 0.0
        self.power_kw = self.rated_kw * 0.9 * daylight * self.cloud
        self.energy_kwh += self.power_kw * dt_s / 3600
        self.voltage_v = r.gauss(230, 3)

    def _fields(self):
        return {"state": "producing" if self.power_kw > 0.01 else "standby",
                "power_kw": round(self.power_kw, 2), "voltage_v": round(self.voltage_v, 1),
                "energy_kwh": round(self.energy_kwh, 2)}
