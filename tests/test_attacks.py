"""
test_attacks.py — tests for Person D's attack suite.

Verifies that 100% of attacks are blocked across all gateway optimization configurations.
"""
import pytest

from backend.attacks.impersonation import (
    attack_fake_ca,
    attack_identity_mismatch,
    attack_stolen_fingerprint,
)
from backend.attacks.replay import attack_replayed_handshake_finish, attack_replayed_telemetry
from backend.attacks.revoked import (
    attack_expired_cert,
    attack_revoked_cert_cached,
    attack_revoked_cert_initial,
)
from backend.attacks.suite import FULL_CONFIG_BATTERY, run_attack_suite, verify_security
from backend.attacks.tamper import (
    attack_tampered_handshake_finish,
    attack_tampered_telemetry_ciphertext,
    attack_tampered_telemetry_signature_e2e,
)
from backend.gateway.config import ALL_CONFIGS, BASELINE, COMBINED
from backend.gateway.testbed import build_testbed


@pytest.mark.parametrize("config", ALL_CONFIGS)
def test_fake_ca_rejected_in_all_configs(config):
    tb = build_testbed(config, n_devices=2)
    res = attack_fake_ca(tb)
    assert res.blocked, f"Fake CA was not blocked in {config.name}"


@pytest.mark.parametrize("config", ALL_CONFIGS)
def test_identity_mismatch_rejected_in_all_configs(config):
    tb = build_testbed(config, n_devices=2)
    res = attack_identity_mismatch(tb)
    assert res.blocked, f"Identity mismatch was not blocked in {config.name}"


@pytest.mark.parametrize("config", ALL_CONFIGS)
def test_stolen_fingerprint_rejected_in_all_configs(config):
    tb = build_testbed(config, n_devices=2)
    res = attack_stolen_fingerprint(tb)
    assert res.blocked, f"Stolen fingerprint was not blocked in {config.name}"


@pytest.mark.parametrize("config", ALL_CONFIGS)
def test_tampered_handshake_rejected_in_all_configs(config):
    tb = build_testbed(config, n_devices=2)
    res = attack_tampered_handshake_finish(tb)
    assert res.blocked, f"Tampered handshake was not blocked in {config.name}"


@pytest.mark.parametrize("config", ALL_CONFIGS)
def test_tampered_telemetry_rejected_in_all_configs(config):
    tb = build_testbed(config, n_devices=2)
    res = attack_tampered_telemetry_ciphertext(tb)
    assert res.blocked, f"Tampered telemetry was not blocked in {config.name}"


@pytest.mark.parametrize("config", ALL_CONFIGS)
def test_replayed_telemetry_rejected_in_all_configs(config):
    tb = build_testbed(config, n_devices=2)
    res = attack_replayed_telemetry(tb)
    assert res.blocked, f"Replayed telemetry was not blocked in {config.name}"


@pytest.mark.parametrize("config", ALL_CONFIGS)
def test_replayed_handshake_rejected_in_all_configs(config):
    tb = build_testbed(config, n_devices=2)
    res = attack_replayed_handshake_finish(tb)
    assert res.blocked, f"Replayed handshake was not blocked in {config.name}"


@pytest.mark.parametrize("config", ALL_CONFIGS)
def test_revoked_initial_rejected_in_all_configs(config):
    tb = build_testbed(config, n_devices=2)
    res = attack_revoked_cert_initial(tb)
    assert res.blocked, f"Revoked cert (initial) was not blocked in {config.name}"


@pytest.mark.parametrize("config", ALL_CONFIGS)
def test_revoked_cached_rejected_in_all_configs(config):
    tb = build_testbed(config, n_devices=2)
    res = attack_revoked_cert_cached(tb)
    assert res.blocked, f"Revoked cert (cached) was not blocked in {config.name}"


@pytest.mark.parametrize("config", ALL_CONFIGS)
def test_expired_cert_rejected_in_all_configs(config):
    tb = build_testbed(config, n_devices=2)
    res = attack_expired_cert(tb)
    assert res.blocked, f"Expired cert was not blocked in {config.name}"


def test_full_security_battery_100_percent_blocked():
    """Verify 100% block rate across full battery (baseline + combinations)."""
    results = run_attack_suite(configs=[BASELINE, COMBINED], n_devices=2)
    audit = verify_security(results)
    assert audit["all_blocked"], f"Some attacks were not blocked: {audit['failed_attacks']}"
    assert audit["block_rate_pct"] == 100.0
