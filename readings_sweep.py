"""
Experiment: how do the savings change with the number of readings sent per session?
Run with:  python readings_sweep.py

Why: gateway_demo.py uses 5 readings per session. Gateway-assisted mode removes a
3,309-byte device signature from EVERY reading, so its saving depends on traffic volume.
This sweep shows the saving across 1 to 100 readings, so no result depends on one chosen value.

Each point = 3 devices, steady state (repeat connection, so the cache is warm where enabled).
All byte counts are real serialized sizes.
"""
import csv
import statistics as st
from pathlib import Path

from backend.gateway.config import ALL_CONFIGS
from backend.gateway.protocol import run_session
from backend.gateway.testbed import build_testbed

READING_COUNTS = [1, 5, 20, 100]
N_DEVICES = 3


def reading(i: int) -> bytes:
    return f'{{"power_kw": {7 + (i % 10) * 0.1:.1f}, "soc": {60 + i % 40}}}'.encode()


rows = []
for cfg in ALL_CONFIGS:
    tb = build_testbed(cfg, N_DEVICES)
    for dev in tb.devices:                                     # warm-up: first connection
        assert run_session(dev, tb.gateway, tb.grid, [reading(0)]).success
    for n in READING_COUNTS:
        recs = [run_session(dev, tb.gateway, tb.grid, [reading(i) for i in range(n)], "repeat")
                for dev in tb.devices]
        assert all(r.success for r in recs)
        total = st.mean(r.total_bytes for r in recs)
        rows.append({"config": cfg.name, "readings": n,
                     "handshake_bytes": st.mean(r.handshake_bytes for r in recs),
                     "total_bytes": total, "bytes_per_reading": total / n})
    print(f"  finished {cfg.name}")

base = {r["readings"]: r["total_bytes"] for r in rows if r["config"] == "baseline"}
for r in rows:
    r["reduction_vs_baseline"] = (base[r["readings"]] - r["total_bytes"]) / base[r["readings"]]

Path("results").mkdir(exist_ok=True)
with open("results/readings_sweep.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys())
    w.writeheader()
    w.writerows(rows)

configs = [c.name for c in ALL_CONFIGS]
print("\nBytes per session vs readings per session (3 devices, repeat connection; % = reduction vs baseline)\n")
head = f"{'config':24}" + "".join(f"{f'{n} reading' + ('s' if n > 1 else ''):>20}" for n in READING_COUNTS)
print(head + "\n" + "-" * len(head))
for c in configs:
    cells = []
    for n in READING_COUNTS:
        r = next(x for x in rows if x["config"] == c and x["readings"] == n)
        pct = r["reduction_vs_baseline"]
        cells.append(f"{r['total_bytes']:>12,.0f} {('0%' if pct == 0 else f'-{pct:.0%}'):>6}")
    print(f"{c:24}" + "".join(f"{s:>20}" for s in cells))
print("\nRaw data: results/readings_sweep.csv")

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(7, 4))
    for c in configs[1:]:
        ys = [next(x for x in rows if x["config"] == c and x["readings"] == n)["reduction_vs_baseline"] * 100
              for n in READING_COUNTS]
        ax.plot(READING_COUNTS, ys, "o-", label=c)
    ax.set_xscale("log")
    ax.set_xticks(READING_COUNTS, [str(n) for n in READING_COUNTS])
    ax.set_xlabel("Readings per session (log scale)")
    ax.set_ylabel("Bytes saved vs baseline (%)")
    ax.set_ylim(0, 100)
    ax.set_title("Gateway-assisted savings grow with traffic; cache and chain savings shrink")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig("results/readings_sweep.png", dpi=150)
    print("Chart: results/readings_sweep.png")
except ImportError:
    print("(install matplotlib to also get a chart)")
