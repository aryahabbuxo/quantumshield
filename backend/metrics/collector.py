"""
collector.py — collects bytes, latency, and success status for every handshake and session.

Consumed by Person D's benchmark runner and Person E's live dashboard stream.
"""
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
import statistics as st

from backend.gateway.protocol import SessionRecord


@dataclass
class ConfigSummary:
    config: str
    total_sessions: int
    success_count: int
    failure_count: int
    cache_hits: int
    cache_hit_rate: float
    mean_handshake_bytes: float
    mean_total_bytes: float
    mean_network_ms: float
    mean_device_ms: float
    mean_gateway_ms: float
    mean_total_ms: float


class MetricsCollector:
    """Collects and aggregates SessionRecord instances during testbed runs."""

    def __init__(self):
        self.records: list[SessionRecord] = []
        self._by_config: dict[str, list[SessionRecord]] = defaultdict(list)
        self._listeners: list[Callable[[SessionRecord], None]] = []

    def add_listener(self, listener: Callable[[SessionRecord], None]) -> None:
        """Register a callback invoked when a new session record arrives (e.g., WebSocket event)."""
        self._listeners.append(listener)

    def record(self, session_rec: SessionRecord) -> None:
        """Record a completed session record and notify all registered listeners."""
        self.records.append(session_rec)
        self._by_config[session_rec.config].append(session_rec)
        for listener in self._listeners:
            try:
                listener(session_rec)
            except Exception:
                pass

    def get_records(self, config: str | None = None, connection: str | None = None) -> list[SessionRecord]:
        """Filter records by configuration name and/or connection type ('first', 'repeat')."""
        recs = self._by_config[config] if config else self.records
        if connection:
            recs = [r for r in recs if r.connection == connection]
        return recs

    def compute_summary(self, config: str) -> ConfigSummary:
        """Compute aggregated performance metrics for a given configuration."""
        recs = self._by_config.get(config, [])
        if not recs:
            return ConfigSummary(config, 0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

        n = len(recs)
        succ = sum(1 for r in recs if r.success)
        fail = n - succ
        hits = sum(1 for r in recs if r.cache_hit)
        hs_bytes = [r.handshake_bytes for r in recs]
        tot_bytes = [r.total_bytes for r in recs]
        net_ms = [r.network_ms for r in recs]
        dev_ms = [r.device_ms for r in recs]
        gw_ms = [r.gateway_ms for r in recs]
        tot_ms = [r.network_ms + r.device_ms + r.gateway_ms + r.grid_ms for r in recs]

        return ConfigSummary(
            config=config,
            total_sessions=n,
            success_count=succ,
            failure_count=fail,
            cache_hits=hits,
            cache_hit_rate=hits / n if n > 0 else 0.0,
            mean_handshake_bytes=st.mean(hs_bytes) if hs_bytes else 0.0,
            mean_total_bytes=st.mean(tot_bytes) if tot_bytes else 0.0,
            mean_network_ms=st.mean(net_ms) if net_ms else 0.0,
            mean_device_ms=st.mean(dev_ms) if dev_ms else 0.0,
            mean_gateway_ms=st.mean(gw_ms) if gw_ms else 0.0,
            mean_total_ms=st.mean(tot_ms) if tot_ms else 0.0,
        )

    def bytes_saved_vs_baseline(self, config: str, baseline_config: str = "baseline") -> float:
        """Calculate bytes saved on average compared to baseline."""
        base_sum = self.compute_summary(baseline_config)
        cfg_sum = self.compute_summary(config)
        return max(0.0, base_sum.mean_total_bytes - cfg_sum.mean_total_bytes)

    def clear(self) -> None:
        self.records.clear()
        self._by_config.clear()
