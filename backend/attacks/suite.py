"""
suite.py — comprehensive attack suite and security verifier.

Runs the complete battery of attacks (impersonation, tamper, replay, revoked/expired certs)
across ALL gateway configurations to prove that optimizations NEVER weaken security.
100% of attacks must be blocked in every configuration.
"""
import csv
from dataclasses import asdict
from pathlib import Path
from typing import Any

from backend.gateway.config import (
    ALL_CONFIGS,
    BASELINE,
    CACHE_ONLY,
    CHAIN_ONLY,
    ASSISTED_ONLY,
    COMBINED,
    OptimizationConfig,
)
from backend.gateway.testbed import build_testbed

from .impersonation import (
    AttackResult,
    attack_fake_ca,
    attack_identity_mismatch,
    attack_stolen_fingerprint,
)
from .replay import attack_replayed_handshake_finish, attack_replayed_telemetry
from .revoked import (
    attack_expired_cert,
    attack_revoked_cert_cached,
    attack_revoked_cert_initial,
)
from .tamper import (
    attack_tampered_handshake_finish,
    attack_tampered_telemetry_ciphertext,
    attack_tampered_telemetry_signature_e2e,
)

# Standard and leave-one-out configurations
LEAVE_ONE_OUT_CONFIGS = [
    OptimizationConfig(cache=False, chain_opt=True, gateway_assisted=True),  # chain+assisted (no cache)
    OptimizationConfig(cache=True, chain_opt=False, gateway_assisted=True),  # cache+assisted (no chain)
    OptimizationConfig(cache=True, chain_opt=True, gateway_assisted=False),  # cache+chain (no assisted)
]

FULL_CONFIG_BATTERY = ALL_CONFIGS + LEAVE_ONE_OUT_CONFIGS

ATTACK_RUNNERS = [
    # Impersonation
    ("Fake CA", attack_fake_ca),
    ("Identity Mismatch", attack_identity_mismatch),
    ("Stolen Fingerprint", attack_stolen_fingerprint),
    # Tamper
    ("Tampered Handshake Proof", attack_tampered_handshake_finish),
    ("Tampered Telemetry Ciphertext", attack_tampered_telemetry_ciphertext),
    ("Tampered Telemetry Signature (E2E)", attack_tampered_telemetry_signature_e2e),
    # Replay
    ("Replayed Telemetry Packet", attack_replayed_telemetry),
    ("Replayed Handshake Finish", attack_replayed_handshake_finish),
    # Revoked & Expired
    ("Revoked Certificate (Initial)", attack_revoked_cert_initial),
    ("Revoked Certificate (Cached)", attack_revoked_cert_cached),
    ("Expired Certificate", attack_expired_cert),
]


def run_attack_suite(configs: list[OptimizationConfig] | None = None,
                     n_devices: int = 3) -> list[AttackResult]:
    """Execute all attacks against each configuration and return the list of AttackResult."""
    test_configs = configs or FULL_CONFIG_BATTERY
    results: list[AttackResult] = []

    for cfg in test_configs:
        for attack_name, runner in ATTACK_RUNNERS:
            # Build fresh testbed for each attack run to ensure isolation
            tb = build_testbed(cfg, n_devices=n_devices)
            res = runner(tb)
            results.append(res)

    return results


def verify_security(results: list[AttackResult]) -> dict[str, Any]:
    """Verify that 100% of attacks were successfully blocked. Raises AssertionError if any slipped through."""
    total = len(results)
    blocked = sum(1 for r in results if r.blocked)
    failed_attacks = [r for r in results if not r.blocked]
    block_rate = (blocked / total * 100.0) if total > 0 else 0.0

    return {
        "total_attacks": total,
        "blocked_attacks": blocked,
        "block_rate_pct": block_rate,
        "all_blocked": blocked == total,
        "failed_attacks": [asdict(f) for f in failed_attacks],
    }


def export_attack_results_to_csv(results: list[AttackResult], filepath: str | Path) -> Path:
    """Export attack outcomes to a clean CSV."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not results:
        return path

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["attack_name", "attack_category", "config_name", "target_device", "blocked", "rejection_reason"])
        writer.writeheader()
        for r in results:
            writer.writerow({
                "attack_name": r.attack_name,
                "attack_category": r.attack_category,
                "config_name": r.config_name,
                "target_device": r.target_device,
                "blocked": r.blocked,
                "rejection_reason": r.rejection_reason,
            })
    return path
