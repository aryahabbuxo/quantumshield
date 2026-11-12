from __future__ import annotations
from .base import Device


class Battery(Device):
    """Charges from solar at midday, discharges in the evening peak, idles otherwise.
    power_kw > 0 means charging, < 0 means discharging."""
    device_type = "battery"

    def __init__(self, device_id, rng, start_hour=None):
        super().__init__(device_id, rng, start_hour)
        self.capacity_kwh = rng.choice([10.0, 25.0, 50.0, 100.0])
        self.max_kw = self.capacity_kwh / 2
        self.soc = rng.uniform(20, 90)
        self.power_kw = 0.0
        self.temp_c = 25.0

    def _step(self, dt_s):
        h = self.sim_hour
        if 10 <= h < 16 and self.soc < 100:
            self.power_kw = self.max_kw * self.rng.uniform(0.5, 0.9)
        elif 18 <= h < 22 and self.soc > 10:
            self.power_kw = -self.max_kw * self.rng.uniform(0.4, 0.8)
        else:
            self.power_kw = 0.0
        self.soc = min(100.0, max(10.0, self.soc + self.power_kw * dt_s / 3600 / self.capacity_kwh * 100))
        self.temp_c = 25 + 10 * abs(self.power_kw) / self.max_kw + self.rng.gauss(0, 0.3)

    def _fields(self):
        voltage = 360 + 60 * self.soc / 100 + self.rng.gauss(0, 0.5)
        state = "charging" if self.power_kw > 0 else "discharging" if self.power_kw < 0 else "idle"
        return {"state": state, "power_kw": round(self.power_kw, 2),
                "soc_pct": round(self.soc, 1), "voltage_v": round(voltage, 1),
                "temp_c": round(self.temp_c, 1)}
