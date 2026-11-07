"""
Failover demo (Person C) — run with:  python failover_demo.py

Scenario: 9 devices are connected to the primary gateway GW_001 and sending data.
GW_001 crashes. Every device's next reading fails, so it reconnects to the backup GW_002.
We measure the cost of recovery with and without cache replication.
"""
import statistics as st

from backend.gateway.config import CACHE_ONLY, COMBINED
from backend.gateway.protocol import run_session
from backend.gateway.testbed import build_testbed

READING = b'{"power_kw": 7.2, "soc": 64}'
N = 9

print("\nQuantumShield Grid - gateway failover (9 devices, primary GW_001 crashes)\n")
head = f"{'config':24}{'replication':13}{'lost':>6}{'recovered':>11}{'cache hits':>12}{'recovery bytes':>16}{'via':>8}"
print(head + "\n" + "-" * len(head))

for cfg in (CACHE_ONLY, COMBINED):
    for replicate in (False, True):
        tb = build_testbed(cfg, N, n_gateways=2, replicate_cache=replicate)
        for dev in tb.devices:                                  # normal operation on the primary
            assert run_session(dev, tb.gateway, tb.grid, [READING]).success

        tb.gateway.fail("GW_001")                               # crash
        lost = 0
        for dev in tb.devices:
            try:
                tb.gateway.on_telemetry(dev.telemetry(READING))
            except ConnectionError:
                lost += 1                                       # device notices the gateway is gone

        recovery = [run_session(dev, tb.gateway, tb.grid, [READING], "repeat") for dev in tb.devices]
        ok = sum(r.success for r in recovery)
        hits = sum(r.cache_hit for r in recovery)
        mean_bytes = st.mean(r.handshake_bytes for r in recovery)
        via = tb.grid.readings[-1]["via"]
        print(f"{cfg.name:24}{'on' if replicate else 'off':13}{lost:>6}{ok:>8}/{N}{hits:>9}/{N}"
              f"{mean_bytes:>16,.0f}{via:>8}")

print("\nSession keys are never shared: every device runs a fresh handshake with the backup.")
print("Replicated cache entries hold only public certificates; revocation reaches all gateways.")
