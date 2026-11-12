"""
test_metrics.py — tests for Person D's metrics collector and CSV exporter.
"""
from pathlib import Path
import tempfile

from backend.gateway.protocol import SessionRecord
from backend.metrics.collector import MetricsCollector
from backend.metrics.exporter import (
    calculate_distribution_stats,
    compute_benchmark_statistics,
    export_records_to_csv,
    export_summary_to_csv,
)


def _make_dummy_record(config="baseline", conn="first", hs_bytes=20000, up=15000, down=5000, upstream=1000, net_ms=50.0):
    return SessionRecord(
        config=config,
        device_id="EV_001",
        connection=conn,
        success=True,
        reason="",
        cache_hit=(conn == "repeat"),
        bytes_up=up,
        bytes_down=down,
        bytes_upstream=upstream,
        handshake_bytes=hs_bytes,
        messages=4,
        device_ms=10.0,
        gateway_ms=5.0,
        grid_ms=2.0,
        network_ms=net_ms,
    )


def test_metrics_collector_aggregation():
    collector = MetricsCollector()
    # Baseline: 1st session total 21000 bytes, repeat session total 3000 bytes -> mean total = 12000 bytes
    collector.record(_make_dummy_record("baseline", "first", hs_bytes=20000, up=15000, down=5000, upstream=1000))
    collector.record(_make_dummy_record("baseline", "repeat", hs_bytes=2000, up=2000, down=800, upstream=200))
    # Cache: repeat session total 1500 bytes -> mean total = 1500 bytes
    collector.record(_make_dummy_record("cache", "repeat", hs_bytes=500, up=1000, down=300, upstream=200))

    summary_base = collector.compute_summary("baseline")
    assert summary_base.total_sessions == 2
    assert summary_base.cache_hits == 1
    assert summary_base.cache_hit_rate == 0.5
    assert summary_base.mean_handshake_bytes == 11000.0

    summary_cache = collector.compute_summary("cache")
    assert summary_cache.total_sessions == 1
    assert summary_cache.cache_hits == 1

    saved = collector.bytes_saved_vs_baseline("cache", "baseline")
    assert saved == (12000.0 - 1500.0)


def test_distribution_statistics_calculation():
    vals = [10.0, 20.0, 30.0, 40.0, 50.0]
    stats = calculate_distribution_stats(vals)
    assert stats["count"] == 5
    assert stats["mean"] == 30.0
    assert stats["median"] == 30.0
    assert stats["ci95_low"] < 30.0 < stats["ci95_high"]


def test_export_records_and_summary_csv():
    records = [
        _make_dummy_record("baseline", "first", hs_bytes=20000, up=15000, down=5000, upstream=1000),
        _make_dummy_record("baseline", "repeat", hs_bytes=20000, up=15000, down=5000, upstream=1000),
        _make_dummy_record("combined", "first", hs_bytes=15000, up=11000, down=4000, upstream=1000),
        _make_dummy_record("combined", "repeat", hs_bytes=1000, up=1000, down=500, upstream=500),
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        raw_csv = Path(tmpdir) / "raw.csv"
        export_records_to_csv(records, raw_csv)
        assert raw_csv.exists()
        assert raw_csv.stat().st_size > 0

        summary_rows = compute_benchmark_statistics(records, baseline_config_name="baseline")
        assert len(summary_rows) > 0
        sum_csv = Path(tmpdir) / "summary.csv"
        export_summary_to_csv(summary_rows, sum_csv)
        assert sum_csv.exists()
        assert sum_csv.stat().st_size > 0
