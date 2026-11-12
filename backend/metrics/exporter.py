"""
exporter.py — exports benchmark and metrics records to CSV, and computes rigorous statistics
(mean, std, median, 95th percentile, % reduction vs baseline, 95% confidence intervals).

Every number in the paper and demo comes from these CSVs; nothing is typed by hand.
"""
import csv
import math
from pathlib import Path
import statistics as st
from typing import Any

from backend.gateway.protocol import SessionRecord


def export_records_to_csv(records: list[SessionRecord], filepath: str | Path) -> Path:
    """Export raw session records to a CSV file."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not records:
        return path

    fieldnames = list(records[0].to_dict().keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow(r.to_dict())
    return path


def calculate_distribution_stats(values: list[float | int]) -> dict[str, float]:
    """Calculate mean, std, median, p95, and 95% confidence intervals for a metric series."""
    if not values:
        return {
            "count": 0,
            "mean": 0.0,
            "std": 0.0,
            "median": 0.0,
            "p95": 0.0,
            "ci95_low": 0.0,
            "ci95_high": 0.0,
            "ci95_margin": 0.0,
        }

    n = len(values)
    mean_val = float(st.mean(values))
    std_val = float(st.stdev(values)) if n > 1 else 0.0
    median_val = float(st.median(values))

    # 95th percentile
    sorted_vals = sorted(values)
    idx_p95 = int(math.ceil(0.95 * n)) - 1
    p95_val = float(sorted_vals[max(0, min(idx_p95, n - 1))])

    # 95% confidence interval margin using standard error
    se = std_val / math.sqrt(n) if n > 1 else 0.0
    margin = 1.96 * se
    ci_low = max(0.0, mean_val - margin)
    ci_high = mean_val + margin

    return {
        "count": n,
        "mean": round(mean_val, 3),
        "std": round(std_val, 3),
        "median": round(median_val, 3),
        "p95": round(p95_val, 3),
        "ci95_low": round(ci_low, 3),
        "ci95_high": round(ci_high, 3),
        "ci95_margin": round(margin, 3),
    }


def compute_benchmark_statistics(records: list[SessionRecord], baseline_config_name: str = "baseline") -> list[dict[str, Any]]:
    """Compute comprehensive statistics per configuration and connection type, including % reduction vs baseline."""
    from collections import defaultdict
    grouped = defaultdict(list)
    for r in records:
        grouped[(r.config, r.connection)].append(r)

    # First calculate baseline means for comparison
    baseline_first_hs = [r.handshake_bytes for r in grouped.get((baseline_config_name, "first"), [])]
    baseline_first_tot = [r.total_bytes for r in grouped.get((baseline_config_name, "first"), [])]
    baseline_rep_hs = [r.handshake_bytes for r in grouped.get((baseline_config_name, "repeat"), [])]
    baseline_rep_tot = [r.total_bytes for r in grouped.get((baseline_config_name, "repeat"), [])]

    base_first_hs_mean = st.mean(baseline_first_hs) if baseline_first_hs else 1.0
    base_first_tot_mean = st.mean(baseline_first_tot) if baseline_first_tot else 1.0
    base_rep_hs_mean = st.mean(baseline_rep_hs) if baseline_rep_hs else 1.0
    base_rep_tot_mean = st.mean(baseline_rep_tot) if baseline_rep_tot else 1.0

    summary_rows = []
    # Sort with baseline first, then others
    keys = sorted(grouped.keys(), key=lambda k: (0 if k[0] == baseline_config_name else 1, k[0], k[1]))

    for config_name, connection in keys:
        recs = grouped[(config_name, connection)]
        hs_stats = calculate_distribution_stats([r.handshake_bytes for r in recs])
        tot_stats = calculate_distribution_stats([r.total_bytes for r in recs])
        net_stats = calculate_distribution_stats([r.network_ms for r in recs])
        proc_stats = calculate_distribution_stats([r.device_ms + r.gateway_ms + r.grid_ms for r in recs])
        total_time_stats = calculate_distribution_stats([r.network_ms + r.device_ms + r.gateway_ms + r.grid_ms for r in recs])

        base_hs_mean = base_first_hs_mean if connection == "first" else base_rep_hs_mean
        base_tot_mean = base_first_tot_mean if connection == "first" else base_rep_tot_mean

        pct_reduction_hs = ((base_hs_mean - hs_stats["mean"]) / base_hs_mean) * 100.0 if base_hs_mean > 0 else 0.0
        pct_reduction_tot = ((base_tot_mean - tot_stats["mean"]) / base_tot_mean) * 100.0 if base_tot_mean > 0 else 0.0

        hits = sum(1 for r in recs if r.cache_hit)
        successes = sum(1 for r in recs if r.success)

        summary_rows.append({
            "config": config_name,
            "connection": connection,
            "samples": len(recs),
            "success_rate": round(successes / len(recs) * 100.0, 2),
            "cache_hit_rate": round(hits / len(recs) * 100.0, 2),
            # Handshake bytes
            "hs_mean_bytes": hs_stats["mean"],
            "hs_std_bytes": hs_stats["std"],
            "hs_median_bytes": hs_stats["median"],
            "hs_p95_bytes": hs_stats["p95"],
            "hs_ci95_margin": hs_stats["ci95_margin"],
            "hs_reduction_pct": round(pct_reduction_hs, 2),
            # Total bytes
            "total_mean_bytes": tot_stats["mean"],
            "total_std_bytes": tot_stats["std"],
            "total_median_bytes": tot_stats["median"],
            "total_p95_bytes": tot_stats["p95"],
            "total_ci95_margin": tot_stats["ci95_margin"],
            "total_reduction_pct": round(pct_reduction_tot, 2),
            # Latency (ms)
            "net_latency_mean_ms": net_stats["mean"],
            "proc_latency_mean_ms": proc_stats["mean"],
            "total_latency_mean_ms": total_time_stats["mean"],
            "total_latency_p95_ms": total_time_stats["p95"],
            "total_latency_ci95_margin": total_time_stats["ci95_margin"],
        })

    return summary_rows


def export_summary_to_csv(summary_rows: list[dict[str, Any]], filepath: str | Path) -> Path:
    """Export statistical summary rows to a CSV file."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not summary_rows:
        return path

    fieldnames = list(summary_rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in summary_rows:
            writer.writerow(row)
    return path
