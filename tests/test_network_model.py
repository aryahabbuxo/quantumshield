"""Network model tests (owner: B), ported from B's original package to the unified model."""
import random
import statistics as st

from backend.gateway.config import BASELINE, COMBINED
from backend.gateway.protocol import run_session
from backend.gateway.testbed import build_testbed
from backend.network import (EmulatedLink, NetworkConfig, RURAL_2G, URBAN_5G, fragment, get_preset,
                             simulate_transfer)


def test_fragment_sizes():
    sizes = fragment(16 * 1024, 1500, 40)
    assert sum(s - 40 for s in sizes) == 16 * 1024
    assert all(s <= 1500 for s in sizes) and len(sizes) == 12
    assert fragment(0, 1500) == []


def test_lossless_latency_is_exact():
    cfg = NetworkConfig("t", bandwidth_bps=1e6, rtt_s=0.1, loss_rate=0.0)
    r = simulate_transfer(cfg, 1460, random.Random(1))
    assert r.success and r.retransmissions == 0 and r.wire_bytes == 1500
    assert abs(r.latency_s - (1500 * 8 / 1e6 + 0.05)) < 1e-9


def test_total_loss_fails_after_retries():
    cfg = NetworkConfig("t", bandwidth_bps=1e6, rtt_s=0.01, loss_rate=1.0, max_retries=3)
    r = simulate_transfer(cfg, 5000, random.Random(1))
    assert not r.success and r.retransmissions > 0


def test_observed_loss_rate_matches_config():
    cfg = NetworkConfig("t", bandwidth_bps=1e9, rtt_s=0.001, loss_rate=0.05, max_retries=50)
    rng = random.Random(3)
    rs = [simulate_transfer(cfg, 1460 * 50, rng) for _ in range(300)]
    observed = sum(r.retransmissions for r in rs) / sum(r.packets for r in rs)
    assert 0.04 < observed < 0.07


def test_presets_ordering():
    rng = random.Random(4)
    t = {k: st.mean(simulate_transfer(get_preset(k), 16384, rng).latency_s for _ in range(100))
         for k in ("urban_5g", "highway_4g", "rural_2g")}
    assert t["urban_5g"] < t["highway_4g"] < t["rural_2g"]


def test_real_handshake_runs_over_network_model():
    tb = build_testbed(BASELINE, 1)
    link = EmulatedLink(URBAN_5G, seed=1)
    r = run_session(tb.devices[0], tb.gateway, tb.grid, [b'{"kw":7}'], link=link)
    assert r.success and r.network == "Urban 5G" and r.network_ms > 0
    assert r.wire_bytes > r.bytes_up + r.bytes_down      # headers on top of the payload
    assert [m.kind for m in link.log[:4]] == ["CLIENT_HELLO", "SERVER_HELLO", "CLIENT_FINISH", "HANDSHAKE_RESULT"]


def test_optimizations_cut_latency_on_rural_2g():
    def mean_latency(cfg):
        tb = build_testbed(cfg, 1)
        dev = tb.devices[0]
        run_session(dev, tb.gateway, tb.grid, [b"x"], link=EmulatedLink(RURAL_2G, seed=0))
        return st.mean(run_session(dev, tb.gateway, tb.grid, [b"x"], "repeat",
                                   EmulatedLink(RURAL_2G, seed=s)).network_ms for s in range(30))
    assert mean_latency(COMBINED) < 0.75 * mean_latency(BASELINE)


def test_lost_message_fails_session_cleanly():
    dead = NetworkConfig("dead", bandwidth_bps=1e6, rtt_s=0.01, loss_rate=1.0, max_retries=2)
    tb = build_testbed(BASELINE, 1)
    r = run_session(tb.devices[0], tb.gateway, tb.grid, [b"x"], link=EmulatedLink(dead))
    assert not r.success and "lost after" in r.reason
