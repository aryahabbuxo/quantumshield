from __future__ import annotations
from .base import Device


class EVCharger(Device):
    """States: idle -> charging -> complete -> idle. Charge power tapers above 80% SoC."""
    device_type = "ev_charger"

    def __init__(self, device_id, rng, start_hour=None):
        super().__init__(device_id, rng, start_hour)
        self.rated_kw = rng.choice([7.4, 11.0, 22.0])
        self.state = "idle"
        self.soc = 0.0
        self.battery_kwh = rng.uniform(40, 80)
        self.power_kw = 0.0
        self.voltage_v = 230.0
        self._complete_ticks = 0

    def _step(self, dt_s):
        r = self.rng
        self.voltage_v = r.gauss(230, 2)
        if self.state == "idle":
            self.power_kw = 0.0
            if r.random() < 0.25:                     # a car plugs in
                self.state, self.soc = "charging", r.uniform(10, 60)
        elif self.state == "charging":
            taper = 1.0 if self.soc < 80 else max(0.1, (100 - self.soc) / 20)
            self.power_kw = self.rated_kw * taper * r.uniform(0.97, 1.0)
            self.soc = min(100.0, self.soc + self.power_kw * dt_s / 3600 / self.battery_kwh * 100)
            if self.soc >= 100:
                self.state, self.power_kw, self._complete_ticks = "complete", 0.0, 0
        else:  # complete
            self.power_kw = 0.0
            self._complete_ticks += 1
            if self._complete_ticks >= 2:
                self.state, self.soc = "idle", 0.0

    def _fields(self):
        return {"state": self.state, "power_kw": round(self.power_kw, 2),
                "soc_pct": round(self.soc, 1), "voltage_v": round(self.voltage_v, 1),
                "current_a": round(self.power_kw * 1000 / self.voltage_v, 1)}
