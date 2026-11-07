# QuantumShield Grid: interfaces (agree before building)

These contracts let all five of us build in parallel. Change them only after telling the team.

## 1. Crypto API (owner: A), `backend/crypto/`

| Function | Signature | Returns |
|---|---|---|
| `pqc.sig_keygen()` | `(alg="ML-DSA-65")` | `SigKeyPair(alg, public_key, secret_key)` |
| `pqc.sign()` | `(message: bytes, keypair)` | signature `bytes` |
| `pqc.verify()` | `(message, signature, public_key, alg)` | `bool` |
| `pqc.kem_keygen()` | `(alg="ML-KEM-768")` | `KemKeyPair` |
| `pqc.encapsulate()` | `(public_key)` | `(ciphertext, shared_secret)` |
| `pqc.decapsulate()` | `(ciphertext, keypair)` | `shared_secret` |
| `symmetric.derive_session_key()` | `(shared_secret, context)` | 32-byte AES key |
| `symmetric.encrypt()` / `decrypt()` | `(key, data, associated_data)` | `bytes` / raises `InvalidTag` |
| `pki.CertificateAuthority` | `create_root`, `create_intermediate`, `issue`, `revoke` | certificates |
| `pki.Certificate` | `to_bytes`, `from_bytes`, `fingerprint` (32 B SHA-256) | |

## 2. Protocol and gateway (owner: C), `backend/gateway/`

| Use | Call |
|---|---|
| Build a full network | `testbed.build_testbed(config, n_devices)` returns root, intermediate, gateway, grid, devices |
| Run one device session | `protocol.run_session(client, gateway, grid, readings, connection="first", link=None)` returns `SessionRecord` |
| Optimization switches | `config.OptimizationConfig(cache, chain_opt, gateway_assisted, cache_ttl_s)`; presets in `ALL_CONFIGS` |
| Device side (for B) | `client.DeviceClient`, which B's simulators wrap; they never call crypto directly |

Message types are listed in `messages.py`. Each message is 1 type byte followed by length-prefixed fields, so `len(message)` equals the bytes on the wire.

## 3. Network link (owner: B, replaces `link.DirectLink`)

Any link object must provide:

```python
up(data: bytes) -> bytes        # device -> gateway
down(data: bytes) -> bytes      # gateway -> device
upstream(data: bytes) -> bytes  # gateway -> grid server
bytes_up, bytes_down, bytes_upstream, messages  # counters
network_s: float                # total simulated network time (bandwidth, RTT, loss)
```

## 4. Metrics record (C produces, D consumes)

One `SessionRecord.to_dict()` row per session:

`config, device_id, connection, success, reason, cache_hit, bytes_up, bytes_down, bytes_upstream, handshake_bytes, messages, device_ms, gateway_ms, grid_ms, network_ms, total_bytes`

## 5. Live events (backend to E, over WebSocket)

```json
{"type": "handshake",      "record": {SessionRecord fields}}
{"type": "attack_blocked", "attack": "replay", "device_id": "EV_001", "reason": "replayed message"}
{"type": "metrics_update", "config": "baseline", "total_bytes": 69836}
```
