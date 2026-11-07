"""
Gateway demo (Person C) — run with:  python gateway_demo.py
Runs every optimization configuration on the same workload and prints measured results.
Workload per config: 3 devices x (first connection + repeat connection), 5 readings each.
Network delay is zero here; Person B's network model adds bandwidth, RTT and loss later.
"""
import csv
import statistics as st
from pathlib import Path

from backend.gateway.config import ALL_CONFIGS
from backend.gateway.protocol import run_session
from backend.gateway.testbed import build_testbed

READINGS = [f'{{"power_kw": {7 + i * 0.1:.1f}, "soc": {60 + i}}}'.encode() for i in range(5)]
records = []

for cfg in ALL_CONFIGS:
    tb = build_testbed(cfg, n_devices=3)
    for connection in ("first", "repeat"):
        for dev in tb.devices:
            r = run_session(dev, tb.gateway, tb.grid, READINGS, connection)
            assert r.success, r.reason
            records.append(r)

Path("results").mkdir(exist_ok=True)
with open("results/gateway_demo.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=records[0].to_dict().keys())
    w.writeheader()
    w.writerows(r.to_dict() for r in records)


def avg(cfg, conn, attr):
    return st.mean(getattr(r, attr) for r in records if r.config == cfg and r.connection == conn)


print("\nQuantumShield Grid - gateway optimizations (mean per device session, bytes)\n")
head = f"{'config':24}{'conn':8}{'handshake':>10}{'upstream':>10}{'total':>9}{'vs base':>9}{'gw ms':>8}{'cache':>7}"
print(head + "\n" + "-" * len(head))
for cfg in [c.name for c in ALL_CONFIGS]:
    for conn in ("first", "repeat"):
        total = avg(cfg, conn, "total_bytes")
        base = avg("baseline", conn, "total_bytes")
        hits = sum(r.cache_hit for r in records if r.config == cfg and r.connection == conn)
        print(f"{cfg:24}{conn:8}{avg(cfg, conn, 'handshake_bytes'):>10,.0f}{avg(cfg, conn, 'bytes_upstream'):>10,.0f}"
              f"{total:>9,.0f}{(total - base) / base * 100:>8.1f}%{avg(cfg, conn, 'gateway_ms'):>8.2f}{hits:>5}/3")
print("\nAll sessions succeeded. Raw records: results/gateway_demo.csv")
