"""
Experiment: certificate cache lifetime (TTL) vs. bytes saved vs. revocation exposure.
Run with:  python cache_tradeoff.py        (about 1-2 minutes)

The question: caching saves bytes, but how long can a revoked device keep getting in?

Model (state these assumptions in the paper; all are parameters below):
  * One device reconnects every RECONNECT_S (15 min) for HORIZON_S (7 days), on a simulated clock.
    Every handshake is real: real ML-KEM, ML-DSA, certificates and byte counts.
  * The gateway learns about revocations in two ways:
      1. a live status check (OCSP-style) on every FULL validation. It costs a request plus a
         CA-signed ML-DSA response; those bytes are measured, not assumed.
      2. a revocation-list refresh every CRL_REFRESH_S (24 h).
  * A cache hit skips the live check; that is exactly what makes it cheap, and where exposure comes from.
  * Exposure = time from the CA revoking the device until the gateway first rejects it.
    Measured over TRIALS revocation times, spread evenly across the second day.
"""
import csv
import statistics as st
import struct
import time
from pathlib import Path

from backend.crypto import pqc
from backend.gateway.config import OptimizationConfig
from backend.gateway.messages import pack_fields
from backend.gateway.protocol import run_session
from backend.gateway.testbed import build_testbed

RECONNECT_S = 15 * 60
HORIZON_S = 7 * 24 * 3600
CRL_REFRESH_S = 24 * 3600
TRIALS = 12
TTLS_S = [0, 15 * 60, 3600, 4 * 3600, 12 * 3600, 24 * 3600, 48 * 3600]   # 0 = caching off


class SimClock:
    def __init__(self):
        self.start, self.t = time.time(), 0.0

    def __call__(self) -> float:
        return self.start + self.t


class StatusResponder:
    """The CA's live revocation-status service. Every answer is a real ML-DSA-signed response."""

    def __init__(self, ca):
        self.ca, self.revoked, self.bytes, self.checks = ca, set(), 0, 0

    def check(self, cert) -> bool:
        is_revoked = cert.serial in self.revoked
        body = pack_fields(struct.pack(">Q", cert.serial), bytes([is_revoked]), struct.pack(">d", time.time()))
        response = body + pqc.sign(body, self.ca.keypair)
        self.bytes += 8 + 32 + len(response)            # request (serial + nonce) + signed response
        self.checks += 1
        return is_revoked


def simulate(ttl_s: int, revoke_at: float | None = None) -> dict:
    tb = build_testbed(OptimizationConfig(cache=ttl_s > 0, cache_ttl_s=ttl_s), 1)
    clock, responder = SimClock(), StatusResponder(tb.intermediate)
    tb.gateway.clock, tb.gateway.status_check = clock, responder.check
    dev = tb.devices[0]
    next_refresh, handshake_bytes, hits, t = CRL_REFRESH_S, [], 0, 0.0

    while t < HORIZON_S:
        clock.t = t
        if revoke_at is not None and t >= revoke_at:
            responder.revoked.add(dev.cert.serial)                   # the CA revokes the device
        while next_refresh <= t:                                     # periodic revocation-list refresh
            for serial in responder.revoked:
                tb.gateway.trust.revoke(serial)
            next_refresh += CRL_REFRESH_S
        r = run_session(dev, tb.gateway, tb.grid, [], "repeat")
        if revoke_at is not None and t >= revoke_at and not r.success:
            return {"exposure_min": (t - revoke_at) / 60,
                    "accepted_after_revocation": int((t - revoke_at) // RECONNECT_S)}
        handshake_bytes.append(r.handshake_bytes)
        hits += r.cache_hit
        t += RECONNECT_S

    n = len(handshake_bytes)
    return {"sessions": n, "hit_rate": hits / n, "handshake_bytes": st.mean(handshake_bytes),
            "status_bytes": responder.bytes / n, "total_bytes": st.mean(handshake_bytes) + responder.bytes / n}


def label(ttl_s: int) -> str:
    return "no cache" if ttl_s == 0 else f"{ttl_s // 60} min" if ttl_s < 3600 else f"{ttl_s // 3600} h"


rows = []
# evenly over day 2, each landing mid-way between two reconnects (a revocation can happen any time)
revoke_times = [24 * 3600 + i * (24 * 3600 / TRIALS) + RECONNECT_S / 2 for i in range(TRIALS)]
for ttl in TTLS_S:
    cost = simulate(ttl)
    exposure = [simulate(ttl, rt) for rt in revoke_times]
    rows.append({"ttl": label(ttl), "ttl_s": ttl, **cost,
                 "exposure_mean_min": st.mean(e["exposure_min"] for e in exposure),
                 "exposure_max_min": max(e["exposure_min"] for e in exposure),
                 "accepted_after_revocation_max": max(e["accepted_after_revocation"] for e in exposure)})
    print(f"  finished TTL = {label(ttl)}")

base = rows[0]["total_bytes"]
Path("results").mkdir(exist_ok=True)
with open("results/cache_tradeoff.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys())
    w.writeheader()
    w.writerows(rows)

print("\nCache TTL trade-off (one device, reconnect every 15 min, 7 days; revocation list refreshed every 24 h)\n")
head = f"{'cache TTL':11}{'hit rate':>9}{'bytes/session':>15}{'saved':>8}{'exposure mean':>15}{'exposure max':>14}{'extra sessions':>16}"
print(head + "\n" + "-" * len(head))
for r in rows:
    print(f"{r['ttl']:11}{r['hit_rate']:>8.0%}{r['total_bytes']:>15,.0f}{(base - r['total_bytes']) / base:>8.0%}"
          f"{r['exposure_mean_min']:>11.0f} min{r['exposure_max_min']:>10.0f} min{r['accepted_after_revocation_max']:>16}")
print("\nbytes/session includes the live status check. 'extra sessions' = most sessions a revoked device still got.")
print("Raw data: results/cache_tradeoff.csv")

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax1 = plt.subplots(figsize=(7, 4))
    x = [r["ttl"] for r in rows]
    ax1.bar(x, [r["total_bytes"] / 1000 for r in rows], color="#4C78A8")
    ax1.set_xlabel("Cache TTL")
    ax1.set_ylabel("Bytes per session (KB)", color="#4C78A8")
    ax2 = ax1.twinx()
    ax2.plot(x, [r["exposure_mean_min"] / 60 for r in rows], "o-", color="#E45756")
    ax2.set_ylabel("Mean revocation exposure (hours)", color="#E45756")
    ax1.set_title("Beyond ~4 h, longer caching saves few bytes but delays revocation")
    fig.tight_layout()
    fig.savefig("results/cache_tradeoff.png", dpi=150)
    print("Chart: results/cache_tradeoff.png")
except ImportError:
    print("(install matplotlib to also get a chart)")
