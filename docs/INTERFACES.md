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

## 3. Network model (owner: B), `backend/network/`

`EmulatedLink(preset, seed)` implements the same methods as `gateway.link.DirectLink`, so the real
handshake runs over it: `run_session(..., link=EmulatedLink(RURAL_2G, seed=1))`.

```python
up(data) / down(data) / upstream(data) -> data   # raises LinkFailure if a message is lost after all retries
bytes_up, bytes_down, bytes_upstream, messages    # payload counters
network_s, wire_bytes, packets_transmitted, packets_retransmitted
log: list[MessageLog]                             # per message: kind, direction, bytes, packets, resent, ms
```

Presets (one source of truth: `backend/network/presets.py`): `URBAN_5G`, `HIGHWAY_4G`, `RURAL_2G`,
`BACKHAUL_FIBRE`; `get_preset("rural_2g")`. All values are stated assumptions until cited.

## 3b. Devices and fleet (owner: B), `backend/devices/`

| Use | Call |
|---|---|
| Telemetry simulators | `EVCharger`, `SolarInverter`, `Battery` (seeded; each has a Bangalore lat/lon) |
| Fleet with real PQC | `build_fleet(n, config, preset, n_gateways=1, seed=0)` |
| Run it | `await run_fleet(fleet, rounds, readings_per_session, time_scale, on_event)` returns `list[SessionRecord]` |

## 4. Metrics record (C produces, D consumes)

One `SessionRecord.to_dict()` row per session:

`config, device_id, connection, success, reason, cache_hit, bytes_up, bytes_down, bytes_upstream, handshake_bytes, messages, device_ms, gateway_ms, grid_ms, network_ms, network, wire_bytes, packets, retransmissions, total_bytes, latency_ms`

## 5. Live dashboard (owner: E), `backend/api/server.py` + `frontend/index.html`

Run: `python -m uvicorn backend.api.server:app --port 8000`, then open http://localhost:8000

| Endpoint | Purpose |
|---|---|
| `POST /api/start` | `{cache, chain_opt, gateway_assisted, preset, devices, speed}` starts the live fleet |
| `POST /api/stop` | stop |
| `GET /api/attacks`, `POST /api/attack/{i}` | run one of D's attacks against the current configuration |
| `POST /api/gateway/GW_001/fail` / `recover` | failover demo |
| `GET /api/results`, `POST /api/experiments/run` | Experiment Lab: charts and CSV headlines from `results/` |
| `WS /ws` | events: `state`, `session` (record + per-message packet log), `reference`, `attack`, `gateway`, `experiments_done` |
