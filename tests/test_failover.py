"""Gateway failover tests (Person C). Run with:  python -m pytest -v tests/test_failover.py"""
import pytest

from backend.gateway.config import BASELINE, CACHE_ONLY, COMBINED
from backend.gateway.protocol import run_session
from backend.gateway.testbed import build_testbed

READING = b'{"power_kw": 7.2}'


def connect(tb, dev, connection="first"):
    return run_session(dev, tb.gateway, tb.grid, [READING], connection)


def test_new_devices_go_to_backup_when_primary_down():
    tb = build_testbed(BASELINE, 1, n_gateways=2)
    tb.gateway.fail("GW_001")
    assert connect(tb, tb.devices[0]).success
    assert tb.grid.readings[-1]["via"] == "GW_002"


def test_old_session_dies_and_device_reconnects_to_backup():
    tb = build_testbed(COMBINED, 1, n_gateways=2)
    dev = tb.devices[0]
    assert connect(tb, dev).success
    tb.gateway.fail("GW_001")
    with pytest.raises(ConnectionError):
        tb.gateway.on_telemetry(dev.telemetry(READING))         # session lived on the primary
    r = connect(tb, dev, "repeat")
    assert r.success and tb.grid.readings[-1]["via"] == "GW_002"


def test_session_keys_are_not_shared():
    tb = build_testbed(BASELINE, 1, n_gateways=2)
    connect(tb, tb.devices[0])
    primary, backup = tb.gateway.gateways
    assert len(primary.sessions) == 1 and len(backup.sessions) == 0


@pytest.mark.parametrize("replicate, expect_hit", [(True, True), (False, False)])
def test_cache_replication_gives_cheap_reconnect(replicate, expect_hit):
    tb = build_testbed(CACHE_ONLY, 1, n_gateways=2, replicate_cache=replicate)
    dev = tb.devices[0]
    connect(tb, dev)
    tb.gateway.fail("GW_001")
    r = connect(tb, dev, "repeat")
    assert r.success and r.cache_hit == expect_hit


def test_revocation_reaches_backup_despite_replicated_cache():
    tb = build_testbed(CACHE_ONLY, 1, n_gateways=2, replicate_cache=True)
    dev = tb.devices[0]
    connect(tb, dev)
    tb.gateway.revoke(dev.cert.serial)
    tb.gateway.fail("GW_001")
    r = connect(tb, dev, "repeat")
    assert not r.success and "revoked" in r.reason


def test_all_gateways_down_is_reported():
    tb = build_testbed(BASELINE, 1, n_gateways=2)
    tb.gateway.fail("GW_001")
    tb.gateway.fail("GW_002")
    r = connect(tb, tb.devices[0])
    assert not r.success and "all gateways are down" in r.reason


def test_recovered_gateway_starts_clean():
    tb = build_testbed(CACHE_ONLY, 1, n_gateways=2)
    connect(tb, tb.devices[0])
    tb.gateway.fail("GW_001")
    tb.gateway.recover("GW_001")
    primary = tb.gateway.gateways[0]
    assert primary.alive and len(primary.sessions) == 0 and len(primary.cache) == 0
