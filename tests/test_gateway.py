"""Gateway tests (Person C). Run with:  python -m pytest -v tests/test_gateway.py"""
import time

import pytest

from backend.crypto import pqc
from backend.gateway.client import DeviceClient
from backend.gateway.config import (ALL_CONFIGS, ASSISTED_ONLY, BASELINE, CACHE_ONLY, CHAIN_ONLY,
                                    COMBINED, OptimizationConfig)
from backend.gateway.messages import MsgType, decode, encode
from backend.gateway.protocol import run_session
from backend.gateway.testbed import build_testbed

READING = b'{"power_kw": 7.2, "soc": 64}'


def connect(tb, dev, connection="first", readings=(READING,)):
    return run_session(dev, tb.gateway, tb.grid, list(readings), connection)


# ------------------------------------------------------------------ correctness ---
@pytest.mark.parametrize("config", ALL_CONFIGS, ids=lambda c: c.name)
def test_every_config_works_first_and_repeat(config):
    tb = build_testbed(config, n_devices=3)
    for dev in tb.devices:
        assert connect(tb, dev).success
        assert connect(tb, dev, "repeat").success
    assert len(tb.grid.readings) == 6


def test_end_to_end_vs_assisted_verification():
    tb = build_testbed(BASELINE, 1)
    connect(tb, tb.devices[0])
    assert tb.grid.readings[-1]["verified_by"] == "device"
    tb = build_testbed(ASSISTED_ONLY, 1)
    connect(tb, tb.devices[0])
    assert tb.grid.readings[-1]["verified_by"] == "gateway"


# ---------------------------------------------------------------- optimizations ---
def test_cache_hit_on_repeat_saves_bytes():
    tb = build_testbed(CACHE_ONLY, 1)
    first, repeat = connect(tb, tb.devices[0]), connect(tb, tb.devices[0], "repeat")
    assert not first.cache_hit and repeat.cache_hit
    assert repeat.bytes_up < first.bytes_up - 9000          # ~two certificates not resent


def test_chain_opt_saves_bytes_on_first_connection():
    base = connect(b := build_testbed(BASELINE, 1), b.devices[0])
    opt = connect(o := build_testbed(CHAIN_ONLY, 1), o.devices[0])
    assert opt.bytes_up < base.bytes_up - 5000               # intermediate not resent


def test_assisted_skips_repeat_ca_signature_checks():
    tb = build_testbed(ASSISTED_ONLY, 3)
    connect(tb, tb.devices[0])
    before = tb.gateway.trust.signature_checks
    connect(tb, tb.devices[1])
    assert tb.gateway.trust.signature_checks - before == 1   # leaf only; intermediate remembered


def test_cache_expiry_falls_back_to_full_chain():
    tb = build_testbed(OptimizationConfig(cache=True, cache_ttl_s=0), 1)
    connect(tb, tb.devices[0])
    time.sleep(0.01)
    repeat = connect(tb, tb.devices[0], "repeat")
    assert repeat.success and not repeat.cache_hit           # one extra round trip, still secure


# --------------------------------------------------------------------- security ---
@pytest.mark.parametrize("config", ALL_CONFIGS, ids=lambda c: c.name)
def test_revoked_device_rejected_even_if_cached(config):
    tb = build_testbed(config, 1)
    dev = tb.devices[0]
    assert connect(tb, dev).success
    tb.gateway.trust.revoke(dev.cert.serial)
    r = connect(tb, dev, "repeat")
    assert not r.success and "revoked" in r.reason


@pytest.mark.parametrize("config", ALL_CONFIGS, ids=lambda c: c.name)
def test_impersonator_with_stolen_fingerprint_rejected(config):
    """Attacker knows the victim's certificate (public) but not its private key."""
    tb = build_testbed(config, 1)
    victim = tb.devices[0]
    connect(tb, victim)
    attacker = DeviceClient(victim.device_id, pqc.sig_keygen(), victim.cert, victim.intermediates,
                            victim.trust, config)
    attacker.cached_at_gateway = victim.cached_at_gateway
    r = connect(tb, attacker)
    assert not r.success and "signature invalid" in r.reason


@pytest.mark.parametrize("config", ALL_CONFIGS, ids=lambda c: c.name)
def test_fake_ca_device_rejected(config):
    tb = build_testbed(config, 1)
    fake = build_testbed(config, 1)                              # same CA names, different keys
    r = connect(tb, fake.devices[0])
    assert not r.success


def test_expired_certificate_rejected():
    tb = build_testbed(BASELINE, 1)
    kp = pqc.sig_keygen()
    old = tb.intermediate.issue("EV_OLD", kp.public_key, days=1, not_before=int(time.time()) - 5 * 86400)
    dev = DeviceClient("EV_OLD", kp, old, [tb.intermediate.cert], tb.devices[0].trust, BASELINE)
    r = connect(tb, dev)
    assert not r.success and "expired" in r.reason


def test_device_id_must_match_certificate():
    tb = build_testbed(BASELINE, 2)
    a, b = tb.devices
    liar = DeviceClient(b.device_id, a.keypair, a.cert, a.intermediates, a.trust, BASELINE)
    r = connect(tb, liar)
    assert not r.success and "does not match" in r.reason


@pytest.mark.parametrize("config", [BASELINE, COMBINED], ids=lambda c: c.name)
def test_replayed_and_tampered_telemetry_rejected(config):
    tb = build_testbed(config, 1)
    dev = tb.devices[0]
    connect(tb, dev, readings=())
    msg = dev.telemetry(READING)
    tb.gateway.on_telemetry(msg)
    with pytest.raises(PermissionError, match="replayed"):
        tb.gateway.on_telemetry(msg)                             # replay
    _, (sid, seq, blob, sig) = decode(dev.telemetry(READING), MsgType.TELEMETRY)
    tampered_blob = blob[:-1] + bytes([blob[-1] ^ 1])            # flip one bit of the ciphertext
    with pytest.raises(PermissionError, match="tampered"):
        tb.gateway.on_telemetry(encode(MsgType.TELEMETRY, sid, seq, tampered_blob, sig))
