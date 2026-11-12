# QuantumShield Grid: Literature Review Notes
**Author:** Person D (Security and Experiments Lead)  
**Audience:** Shared with Person A (Crypto Lead) and Person E (Integration & Paper Lead)  
**Target Venue:** IEEE Transactions on Smart Grid / ACM Transactions on Cyber-Physical Systems (Q1)

---

## 1. Post-Quantum Cryptography Standards & Primitives
* **NIST FIPS 203 (ML-KEM):** Based on the Module Learning with Errors (M-LWE) problem. Parameter set ML-KEM-768 provides NIST Security Category 3 (equivalent to AES-192). Public key: 1,184 bytes; ciphertext: 1,088 bytes; shared secret: 32 bytes. Compared to classical X25519 (32-byte public key / 32-byte ciphertext), ML-KEM imposes an approximately 35x-37x overhead per key exchange.
* **NIST FIPS 204 (ML-DSA):** Based on Module Short Integer Solution (M-SIS) and M-LWE. ML-DSA-65 provides Category 3 security. Public key: 1,952 bytes; signature: 3,309 bytes. Compared to ECDSA on secp256r1 (64-byte signature, 64-byte uncompressed public key), ML-DSA-65 signatures are over 50x larger.
* **FN-DSA (Falcon):** NTRU-lattice signature scheme. Smaller public keys (897 bytes) and signatures (666 bytes) at Level 1, but requires complex constant-time 64-bit floating point arithmetic that is difficult to implement securely on constrained embedded microcontrollers without floating point units (FPUs).
* **Smart Grid Urgency:** Clean-energy infrastructure assets (EV fast-charging stations, solar inverters, battery storage plants) possess operational lifespans exceeding 15–25 years. Under "Harvest Now, Decrypt Later" (HNDL) threats, grid telemetry and remote control commands recorded today risk retrospective compromise once cryptanalytically relevant quantum computers (CRQCs) emerge.

---

## 2. Smart Grid and EV Charging Protocols
* **OCPP 2.0.1 (Open Charge Point Protocol):** Governs communication between Charging Stations (EVSE) and Charging Station Management Systems (CSMS) over WebSockets / TLS. Mandates device mutual authentication and periodic meter reading transmission.
* **ISO 15118-2 & ISO 15118-20 (Plug & Charge):** Standardizes automated EV authentication and billing. Specifies a multi-tier Public Key Infrastructure (PKI):
  - Root Certificate Authority (V2G Root CA)
  - Sub-CA / Intermediate CA (OEM Sub-CA, Mobility Operator Sub-CA)
  - Leaf / Provisioning Certificate on the EV or charger.
* **The PQC Scaling Challenge in ISO 15118:** In a standard 2-tier or 3-tier PKI, transmitting the leaf certificate plus 1–2 intermediate CA certificates signed with ML-DSA-65 adds ~10–16 KB of raw certificate payload. Over constrained cellular or PLC (Power Line Communication) links, this induces severe TCP fragmentation, packet loss amplification, and latency spikes.

---

## 3. Handshake-Size Reduction Techniques & Related Work
* **RFC 8446 (TLS 1.3 Session Resumption / PSK):** Uses pre-shared keys derived from a previous handshake. While effective, standard TLS session tickets do not naturally integrate with asymmetric multi-tenant edge gateways where intermediate trust stores and CRLs must be dynamically checked without terminating end-to-end grid accountability.
* **RFC 8879 (TLS Certificate Compression):** Compresses certificate chains using zlib, Brotli, or Zstandard. However, structured lattice-based public keys (ML-DSA public keys and A-matrices) and pseudorandom signatures have near-maximal Kolmogorov entropy, yielding poor compression ratios (< 8–12% reduction for PQC certificates).
* **RFC 7924 (Cached Information Extension):** Allows clients to omit certificates or certificate authorities that the server is known to possess. QuantumShield Grid’s **Chain Transmission Optimization** and **Certificate Caching** adapt and extend this paradigm specifically for PQC lattice payloads on constrained grid uplinks.
* **RFC 9345 (Delegated Credentials for TLS):** Introduces short-lived delegated credentials signed by long-lived certificates. Similar in philosophy to QuantumShield Grid's **Gateway-Assisted Validation**, where the edge gateway acts as an authenticated verifier under a well-defined trust model.

---

## 4. Threat Models in Edge-Assisted Smart Grids
* **Dolev-Yao Adversary:** Active network attacker capable of intercepting, dropping, replaying, and modifying packets on the untrusted edge wireless link (Device $\leftrightarrow$ Gateway).
* **Rogue Infrastructure:** Malicious or compromised actors deploying unauthorized charging stations or fake solar inverters using self-signed or rogue CA hierarchies.
* **Stale Cache / Revocation Exposure:** When edge nodes cache validation state to conserve bandwidth, a revocation issued by the Central CA may not immediately reach or invalidate the edge cache until the Time-To-Live (TTL) expires. The literature terms this the *revocation exposure window* ($\Delta t_{\text{rev}}$).
* **QuantumShield Grid Contribution:** Quantifies this exact pareto frontier ($\Delta t_{\text{rev}}$ vs bandwidth saved) through empirical simulation with live OCSP-style ML-DSA status responders, providing operators with mathematically grounded configuration guidelines.
