"""Tests for the simulated clock and live revocation-status check (Person C)."""
from backend.gateway.config import BASELINE, OptimizationConfig
from backend.gateway.protocol import run_session
from backend.gateway.testbed import build_testbed


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def test_live_status_check_rejects_revoked_device():
    tb = build_testbed(BASELINE, 1)
    revoked = set()
    tb.gateway.status_check = lambda cert: cert.serial in revoked
    dev = tb.devices[0]
    assert run_session(dev, tb.gateway, tb.grid, []).success
    revoked.add(dev.cert.serial)
    r = run_session(dev, tb.gateway, tb.grid, [], "repeat")
    assert not r.success and "live status check" in r.reason


def test_cache_hit_skips_live_check_until_ttl_expires():
    import time
    tb = build_testbed(OptimizationConfig(cache=True, cache_ttl_s=3600), 1)
    clock, checks = Clock(time.time()), []
    tb.gateway.clock = clock
    tb.gateway.status_check = lambda cert: checks.append(cert.serial) or False
    dev = tb.devices[0]
    run_session(dev, tb.gateway, tb.grid, [])                     # full validation -> 1 check
    clock.t += 1800
    assert run_session(dev, tb.gateway, tb.grid, [], "repeat").cache_hit
    assert len(checks) == 1                                       # cache hit: no live check
    clock.t += 3600                                               # past the TTL
    r = run_session(dev, tb.gateway, tb.grid, [], "repeat")
    assert r.success and not r.cache_hit and len(checks) == 2     # expired -> full validation again
