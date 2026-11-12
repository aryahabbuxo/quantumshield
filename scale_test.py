"""
Scale test (owner: B) — real PQC handshakes for 1 to 1,000 devices on every network preset.
Run with:   python scale_test.py                      (all sizes; several minutes on a laptop)
            python scale_test.py --counts 1 10 100     (quick)

Each device connects `--rounds` times (first connection + repeats), sending one reading each time.
Compares the PQC baseline with all three optimizations combined.
Writes every session to results/scale_results.csv.
"""
import argparse
import asyncio
import csv
import statistics as st
import time
from pathlib import Path

from backend.devices import build_fleet, run_fleet
from backend.gateway.config import BASELINE, COMBINED
from backend.network import ALL_PRESETS


def p95(xs):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(0.95 * len(xs)))]


async def main(counts, rounds):
    rows = []
    head = (f"{'preset':18}{'config':22}{'devices':>8}{'sessions':>9}{'ok %':>7}{'mean ms':>10}{'p95 ms':>10}"
            f"{'retx/sess':>10}{'wire KB/sess':>13}{'wall s':>8}")
    print(head + "\n" + "-" * len(head))
    for preset in ALL_PRESETS:
        for cfg in (BASELINE, COMBINED):
            for n in counts:
                fleet = build_fleet(n, cfg, preset, seed=1)
                t0 = time.perf_counter()
                recs = await run_fleet(fleet, rounds=rounds)
                wall = time.perf_counter() - t0
                lat = [r.latency_ms for r in recs if r.success]
                rows += [{**r.to_dict(), "fleet_size": n} for r in recs]
                ok = 100 * sum(r.success for r in recs) / len(recs)
                print(f"{preset.name:18}{cfg.name:22}{n:>8}{len(recs):>9}{ok:>7.1f}{st.mean(lat):>10.1f}"
                      f"{p95(lat):>10.1f}{st.mean(r.retransmissions for r in recs):>10.2f}"
                      f"{st.mean(r.wire_bytes for r in recs) / 1024:>13.1f}{wall:>8.1f}")
    Path("results").mkdir(exist_ok=True)
    with open("results/scale_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    print(f"\n{len(rows)} sessions written to results/scale_results.csv")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--counts", type=int, nargs="+", default=[1, 10, 100, 1000])
    ap.add_argument("--rounds", type=int, default=3)
    a = ap.parse_args()
    asyncio.run(main(a.counts, a.rounds))
