"""
Phase 1 demo — run with:  python phase1_demo.py
Shows the full secure flow for one EV charger and prints real object sizes.
"""
import os

from backend.crypto import pki, pqc, symmetric

print("=== QuantumShield Grid · Phase 1: crypto core ===\n")

# --- Setup: PKI --------------------------------------------------------
root = pki.CertificateAuthority.create_root("QSG Root CA")
inter = root.create_intermediate("QSG Intermediate CA")
dev_kp = pqc.sig_keygen()
dev_cert = inter.issue("EV_001", dev_kp.public_key)
gateway_kem = pqc.kem_keygen()
print("[setup] Root CA -> Intermediate CA -> EV_001 certificate issued")

# --- Step 1-2: device sends certificate chain, gateway validates it ----
chain_bytes = dev_cert.to_bytes() + inter.cert.to_bytes()
pki.validate_chain([dev_cert, inter.cert], [root.cert])
print(f"[1-2] Gateway validated chain ({len(chain_bytes):,} bytes on the wire)")

# --- Step 3: challenge-response proves the device owns the key ---------
challenge = os.urandom(32)
proof = pqc.sign(challenge, dev_kp)
assert pqc.verify(challenge, proof, dev_cert.public_key)
print(f"[3]   Device proved key ownership (signature {len(proof):,} bytes)")

# --- Step 4: ML-KEM key establishment ----------------------------------
ct, dev_secret = pqc.encapsulate(gateway_kem.public_key)
gw_secret = pqc.decapsulate(ct, gateway_kem)
assert dev_secret == gw_secret
print(f"[4]   Shared secret established (KEM public key {len(gateway_kem.public_key):,} B, "
      f"ciphertext {len(ct):,} B)")

# --- Step 5-6: session key + encrypted telemetry -----------------------
k_dev, k_gw = symmetric.derive_session_key(dev_secret), symmetric.derive_session_key(gw_secret)
telemetry = b'{"device":"EV_001","power_kw":7.2,"soc":64}'
blob = symmetric.encrypt(k_dev, telemetry)
assert symmetric.decrypt(k_gw, blob) == telemetry
print(f"[5-6] Telemetry encrypted with AES-256-GCM ({len(blob)} bytes) and decrypted by gateway")

# --- Size summary ------------------------------------------------------
handshake = len(chain_bytes) + len(proof) + len(gateway_kem.public_key) + len(ct)
print("\n--- Measured sizes (bytes) ---")
for k, v in pqc.algorithm_sizes().items():
    print(f"{k:20} {v}")
print(f"{'device certificate':20} {len(dev_cert.to_bytes())}")
print(f"{'certificate fingerprint':20} {len(dev_cert.fingerprint())}")
print(f"{'full handshake (approx)':20} {handshake}")
