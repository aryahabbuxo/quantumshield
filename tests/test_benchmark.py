"""
test_benchmark.py — tests for Person D's benchmark runner.
"""
from pathlib import Path
import tempfile

from backend.experiments.benchmark import (
    generate_sample_telemetry,
    run_full_benchmark,
    run_single_config_benchmark,
)
from backend.gateway.config import BASELINE, COMBINED


def test_generate_sample_telemetry():
    t1 = generate_sample_telemetry("EV_001", 0)
    assert len(t1) > 0
    assert b"voltage_v" in t1
    assert b"EV_001" in t1


def test_run_single_config_benchmark():
    recs = run_single_config_benchmark(COMBINED, trials=2, n_devices=2, readings_count=2)
    # 2 trials x 2 connections (first + repeat) = 4 records
    assert len(recs) == 4
    for r in recs:
        assert r.success


def test_run_fast_benchmark_and_chart_generation():
    with tempfile.TemporaryDirectory() as tmpdir:
        all_recs, summary = run_full_benchmark(trials=2, output_dir=tmpdir, fast_mode=True)
        assert len(all_recs) > 0
        assert len(summary) > 0

        out_path = Path(tmpdir)
        assert (out_path / "benchmark_runs.csv").exists()
        assert (out_path / "benchmark_summary.csv").exists()
        assert (out_path / "attack_results.csv").exists()
        assert (out_path / "handshake_bytes_comparison.png").exists()
        assert (out_path / "network_latency_comparison.png").exists()
        assert (out_path / "ablation_study.png").exists()
        assert (out_path / "cumulative_bytes_timeline.png").exists()
        assert (out_path / "security_attack_matrix.png").exists()
