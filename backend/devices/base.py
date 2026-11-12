"""Device base class. Each device keeps its own simulated clock and state."""
from __future__ import annotations
import json
import random
from abc import ABC, abstractmethod

BANGALORE = (12.9716, 77.5946)


class Device(ABC):
    device_type: str = "device"

    def __init__(self, device_id: str, rng: random.Random, start_hour: float | None = None):
        self.device_id = device_id
        self.rng = rng
        self.sim_hour = rng.uniform(0, 24) if start_hour is None else start_hour
        self.sim_ts = 0.0  # seconds since simulation start
        # Spread devices around Bangalore (for E's live map)
        self.lat = BANGALORE[0] + rng.uniform(-0.12, 0.12)
        self.lon = BANGALORE[1] + rng.uniform(-0.12, 0.12)

    @abstractmethod
    def _step(self, dt_s: float) -> None:
        """Advance internal state by dt_s simulated seconds."""

    @abstractmethod
    def _fields(self) -> dict:
        """Current telemetry values specific to this device type."""

    def tick(self, dt_s: float) -> dict:
        """Advance simulated time and return one telemetry reading."""
        self.sim_ts += dt_s
        self.sim_hour = (self.sim_hour + dt_s / 3600) % 24
        self._step(dt_s)
        return {"device_id": self.device_id, "type": self.device_type,
                "ts": round(self.sim_ts, 1), "lat": round(self.lat, 5),
                "lon": round(self.lon, 5), **self._fields()}

    @staticmethod
    def encode(telemetry: dict) -> bytes:
        """Compact JSON bytes: this is the plaintext that AES-GCM will encrypt."""
        return json.dumps(telemetry, separators=(",", ":")).encode()
