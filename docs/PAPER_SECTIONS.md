# QuantumShield Grid: Research Paper Sections
**Author:** Person D (Security and Experiments Lead)  
**Contributions:** Threat Model (Sec. 4), Experimental Methodology (Sec. 5), Experimental Results & Trade-offs (Sec. 6)  
**Target Venue:** IEEE Transactions on Smart Grid / ACM TCPS

---

## 4. Threat Model and System Design

### 4.1 Threat Model and Security Objectives
We consider a distributed clean-energy distribution system operating across urban, highway, and rural environments (e.g., EV chargers, rooftop solar arrays, community energy storage). Communication across the wireless edge access link between field devices and the edge gateway is subject to a standard Dolev-Yao network adversary $\mathcal{A}$. Specifically:
1. **Active Link Adversary:** $\mathcal{A}$ can eavesdrop, intercept, drop, inject, tamper with, and replay packets transmitted over the air interface (Device $\leftrightarrow$ Gateway).
2. **Identity Impersonation:** $\mathcal{A}$ may attempt to register rogue clean-energy devices, inject false meter telemetry to manipulate dynamic grid tariffs, or masquerade as legitimate field equipment using forged or self-signed certificates.
3. **Compromised Credentials & Revocation:** Legitimate devices may suffer physical key extraction or firmware compromise. Upon discovery, the Central Grid Authority revokes the device's certificate. $\mathcal{A}$ may attempt to exploit validation caches to maintain unauthorized access after revocation.
4. **Trusted Components:** The Grid Core Server and the PKI Root/Intermediate CAs are assumed uncompromised. In *End-to-End Mode*, the Gateway is treated as an untrusted forwarder; in *Gateway-Assisted Mode*, the Gateway is trusted to perform initial device admission over an authenticated, mutually authenticated backhaul channel.

### 4.2 Security Invariants
The system design enforces three non-negotiable security invariants regardless of which performance optimizations are active:
* **Invariant 1 (Authenticity & Key Secrecy):** Mutual authentication and session key derivation require proof-of-possession of the device's ML-DSA private key over a fresh, ephemeral ML-KEM transcript. No optimization may permit key establishment without a valid cryptographic signature over a fresh challenge.
* **Invariant 2 (Strict Path Validation):** Device certificates must form an unbroken, cryptographically valid signature chain rooted in a trusted Trust Store anchor, strictly checking expiry (`not_before` $\le t \le$ `not_after`) and revocation state.
* **Invariant 3 (Message Integrity & Freshness):** All telemetry records transmitted under an established session must be protected by authenticated encryption with associated data (AEAD: AES-256-GCM) with strictly monotonically increasing sequence numbers ($seq > seq_{\text{last}}$). Replayed or tampered packets must be discarded before state modification.

### 4.3 Proposed Optimizations & Trust Architecture
To counter the high bandwidth tax of post-quantum cryptography (ML-KEM-768 and ML-DSA-65), QuantumShield Grid introduces three orthogonal, composable mechanisms:
1. **Certificate Caching:** Following an initial full certificate validation, the gateway caches the validated leaf certificate indexed by its 32-byte SHA-256 fingerprint. On subsequent reconnections within the cache TTL, the device transmits only its 32-byte fingerprint rather than the multi-kilobyte certificate. To prevent replay and spoofing, the device must still compute a fresh ML-DSA signature over the ephemeral ML-KEM transcript.
2. **Chain Transmission Optimization:** Because edge gateways in smart-grid deployments maintain pre-installed intermediate CA certificates in their local trust stores, clean-energy devices omit intermediate CA certificates from the handshake uplink. The gateway reconstructs and validates the full certificate path locally.
3. **Gateway-Assisted Validation:** In baseline end-to-end mode, the gateway blindly forwards full device certificates and per-reading device signatures to the grid server. Under gateway-assisted mode, the gateway establishes a permanent, high-bandwidth PQC backhaul tunnel with the grid server. The gateway validates device credentials once at the edge, verifies local readings, and streams aggregated telemetry upstream without redundant per-reading ML-DSA signatures.

---

## 5. Experimental Methodology

### 5.1 Testbed Implementation
Experiments are conducted on a reproducible Python 3.11 testbed utilizing official NIST-standardized implementations:
* **Post-Quantum Primitives:** Module Lattice-Based Key Encapsulation (ML-KEM-768, FIPS 203) and Digital Signature Algorithm (ML-DSA-65, FIPS 204) via `liboqs` (v0.16.0).
* **Symmetric Primitives:** AES-256-GCM for AEAD session encryption; HKDF-SHA256 for key derivation.
* **Network Emulation:** Custom link emulator implementing realistic packetization, MTU fragmentation, and propagation dynamics modeled on cellular traces.

### 5.2 India Cellular Network Presets
To assess realistic smart-grid communication links, we model three representative deployment scenarios:
* **Urban 5G (Metro Bangalore):** High-density smart-city deployment. Bandwidth: 100 Mbps; Round-Trip Time (RTT): 15 ms; Packet loss: 0.0%; MTU: 1500 bytes.
* **Highway 4G (Mysore Road EV Corridor):** Fast-charging stations along highway links. Bandwidth: 20 Mbps; RTT: 60 ms; Packet loss: 0.5%; MTU: 1500 bytes.
* **Rural 2G / GPRS (Constrained Agritech Microgrids):** Solar pumps and rural battery installations. Bandwidth: 100 kbps; RTT: 450 ms; Packet loss: 4.0%; MTU: 576 bytes; TCP Retransmission Timeout (RTO): 1.5 s.

### 5.3 Metrics and Statistical Rigor
For every experimental configuration, we execute $N = 100$ independent trials covering cold starts (first connection) and warm reconnects (repeat connection). In total, $2,800$ full sessions and $88$ distinct attack vectors were evaluated. Every reported metric includes:
* Sample mean ($\bar{x}$) and sample standard deviation ($s$).
* Median and 95th percentile ($P_{95}$) values.
* 95% Confidence Intervals calculated via Student's $t$ standard error:
  $$\text{CI}_{95} = \bar{x} \pm 1.96 \cdot \frac{s}{\sqrt{N}}$$
* Percentage reduction relative to the unoptimized baseline:
  $$\Delta \% = \frac{\bar{x}_{\text{baseline}} - \bar{x}_{\text{opt}}}{\bar{x}_{\text{baseline}}} \times 100\%$$

---

## 6. Experimental Results and Discussion

### 6.1 RQ1: Communication Overhead of Unoptimized PQC
Table 1 presents the empirical overhead imposed by transition to NIST Level 3 PQC (ML-KEM-768 + ML-DSA-65) without optimizations.

#### Table 1: Handshake and Session Overhead (Mean $\pm$ 95% CI, $N=100$)
| Configuration | Connection | Handshake Bytes | Total Session Bytes | Reduction vs Baseline |
| :--- | :--- | :--- | :--- | :--- |
| **Baseline (Unoptimized)** | First (Cold) | $25,059.64 \pm 0.49$ B | $71,615.14 \pm 4.66$ B | 0.00% (Reference) |
| **Baseline (Unoptimized)** | Repeat (Warm) | $25,059.64 \pm 0.49$ B | $71,615.14 \pm 4.66$ B | 0.00% (Reference) |
| **Cache Only** | First (Cold) | $25,059.64 \pm 0.49$ B | $71,614.78 \pm 4.67$ B | 0.00% |
| **Cache Only** | Repeat (Warm) | $14,401.32 \pm 0.25$ B | $55,609.46 \pm 4.43$ B | **22.35%** |
| **Chain Opt Only** | First & Repeat | $19,712.64 \pm 0.49$ B | $60,920.76 \pm 4.78$ B | **14.93%** |
| **Assisted Opt Only** | First & Repeat | $25,059.64 \pm 0.49$ B | $27,790.30 \pm 4.18$ B | **61.19%** |
| **All Combined** | First (Cold) | $19,712.64 \pm 0.49$ B | $22,443.68 \pm 4.25$ B | **68.66%** |
| **All Combined** | Repeat (Warm) | $14,401.32 \pm 0.25$ B | $17,132.36 \pm 4.01$ B | **76.08%** |

*Findings (RQ1):* Baseline PQC imposes $25.06$ KB per handshake. In a standard telemetry session (5 readings), upstream forwarding of raw certificates and per-reading signatures expands total traffic to $71.62$ KB. Over rural 2G links with 576-byte MTUs, a single handshake fragments into $44$ network packets, incurring $10.60$ seconds of handshake latency.

### 6.2 RQ2: Efficacy of Proposed Optimizations (Ablation Analysis)
As observed in Table 1 and Figure 3 (Ablation Study):
* **Chain Transmission Optimization** removes the intermediate CA certificate from the client uplink, cutting initial handshake size from $25.06$ KB to $19.71$ KB (a $21.34\%$ reduction in handshake bytes).
* **Certificate Caching** eliminates the leaf certificate on warm reconnects, replacing it with a 32-byte SHA-256 fingerprint while preserving the fresh ML-KEM exchange and ML-DSA proof. Handshake size drops to $14.40$ KB (a $42.53\%$ reduction in handshake bytes).
* **Gateway-Assisted Validation** yields the largest single volume reduction ($61.19\%$). By validating device telemetry at the edge and eliminating redundant per-reading ML-DSA signatures on the backhaul link, telemetry traffic drops from $46.56$ KB to $2.73$ KB.
* **All Combined:** Achieves a **$76.08\%$ total bandwidth reduction** on warm sessions ($17.13$ KB vs. $71.62$ KB baseline). Over 50 reconnect cycles (Figure 4), cumulative data transfer drops by **$88.1\%$**.

#### Table 2: Latency Impact Across Network Presets (Mean $\pm$ 95% CI, $N=100$)
| Network Preset | Baseline Latency (Cold) | Optimized Latency (Warm) | Latency Reduction |
| :--- | :--- | :--- | :--- |
| **Urban 5G** | $109.84 \pm 1.33$ ms | $83.02 \pm 0.69$ ms | **24.4%** |
| **Highway 4G** | $412.68 \pm 1.32$ ms | $336.34 \pm 0.76$ ms | **18.5%** |
| **Rural 2G (lossy)** | $10,602.29 \pm 1.15$ ms | $5,401.87 \pm 0.74$ ms | **49.0% (5.2 seconds saved!)** |

*Findings (RQ2):* Overhead reduction is magnified under constrained lossy links. Under rural 2G (4% loss, 576 B MTU), shrinking handshake and telemetry payloads cuts packet fragment count from $44$ to $12$ packets, mitigating TCP packet drop cascading and reducing end-to-end session latency from $10.6$ seconds to $5.4$ seconds.

### 6.3 RQ3: Security Robustness and Revocation Exposure
To answer RQ3, we conducted automated attack injections against every configuration across $88$ trials.

#### Table 3: Security Verification Matrix (100% Block Rate across All Configurations)
| Attack Class | Specific Threat Vector | Baseline | Cache | Chain | Assisted | Combined | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Impersonation** | Fake CA (Untrusted Root/Sub-CA) | Blocked | Blocked | Blocked | Blocked | Blocked | **100% Blocked** |
| **Impersonation** | Identity Mismatch (Claimed $\ne$ Cert Subject) | Blocked | Blocked | Blocked | Blocked | Blocked | **100% Blocked** |
| **Impersonation** | Stolen Fingerprint (No Private Key) | Blocked | Blocked | Blocked | Blocked | Blocked | **100% Blocked** |
| **Tampering** | Tampered Handshake Ciphertext / Proof | Blocked | Blocked | Blocked | Blocked | Blocked | **100% Blocked** |
| **Tampering** | Tampered Telemetry Payload (AEAD Tag) | Blocked | Blocked | Blocked | Blocked | Blocked | **100% Blocked** |
| **Tampering** | Tampered Telemetry Signature (E2E) | Blocked | Blocked | Blocked | N/A (Assisted) | N/A (Assisted) | **100% Blocked** |
| **Replay** | Replayed Telemetry Reading ($seq \le seq_{\text{last}}$) | Blocked | Blocked | Blocked | Blocked | Blocked | **100% Blocked** |
| **Replay** | Replayed Handshake Proof (Stale Transcript) | Blocked | Blocked | Blocked | Blocked | Blocked | **100% Blocked** |
| **Revocation** | Revoked Certificate (Initial Connection) | Blocked | Blocked | Blocked | Blocked | Blocked | **100% Blocked** |
| **Revocation** | Revoked Certificate in Active Cache | Blocked | Blocked | Blocked | Blocked | Blocked | **100% Blocked** |
| **Expiry** | Expired Certificate (`not_after` passed) | Blocked | Blocked | Blocked | Blocked | Blocked | **100% Blocked** |

*Findings (RQ3):*
1. **Zero Security Degradation:** Across all $88$ attack injections, $100\%$ were blocked. Caching a fingerprint never allows an attacker to bypass authentication: because the gateway issues a fresh random nonce and ephemeral ML-KEM key pair for each handshake, an attacker presenting a stolen fingerprint cannot forge the ML-DSA proof over the new transcript without the victim's private key.
2. **Revocation Invariant:** Even if a leaf certificate is present in the gateway's cache, every cache lookup checks the gateway's local revocation list (`trust.revoked`). When a device certificate is revoked, cache lookup immediately returns `None`, forcing full validation where the connection is definitively rejected.
3. **Revocation Exposure Window:** In environments with intermittent backhaul where the gateway updates its CRL periodically (e.g., every 24 hours), the cache TTL bounds the maximum exposure window ($\Delta t_{\text{rev}} \le \text{TTL}$). Operators can tune the TTL parameter along the empirical trade-off curve (e.g., 1-hour TTL delivers 76% bandwidth reduction while limiting exposure to $\le 60$ minutes).
