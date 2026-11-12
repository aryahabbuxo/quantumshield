# Phase 2 integration notes

What was merged for Phase 2, what changed, and what is still open.

## Merged

| From | What | Where |
|---|---|---|
| A (starter) | ML-KEM, ML-DSA, AES-GCM, PKI | `backend/crypto/` |
| B | Device simulators, packet-level network model, presets, fleet, scale test | `backend/devices/`, `backend/network/`, `scale_test.py` |
| C | Protocol, gateway, three optimizations, failover, cache trade-off, readings sweep | `backend/gateway/`, root scripts |
| D | Attack suite, metrics, benchmark, charts, literature notes, paper drafts | `backend/attacks/`, `backend/metrics/`, `backend/experiments/`, `docs/` |
| E (built by C) | Live control-room dashboard | `backend/api/server.py`, `frontend/` |

## Decisions made during integration

1. **One network model.** B and D had each written a network model with different preset values.
   B's packet-level engine (per-packet loss, only lost packets resent, doubling timeout, jitter,
   failure after 8 retries) now runs behind D's `EmulatedLink` interface, so the real handshake,
   the benchmark, the fleet and the dashboard all use the same model.
2. **One set of presets**, in `backend/network/presets.py` (B's values). `configs.yaml` matches them.
   These are assumptions until replaced with cited figures.
3. **B's stub handshake removed.** The fleet now runs the real PQC handshake for every device.
4. **`SessionRecord` gained network fields:** `network`, `wire_bytes`, `packets`, `retransmissions`,
   plus `latency_ms` (computation + simulated network time). Old fields are unchanged.
5. **Reliability is now measurable:** a message lost after every retry fails the session.

## Fixes to D's benchmark

1. Every network trial used the same random seed, so all 100 trials saw identical packet loss and
   the confidence intervals understated real variation. Each trial now gets its own seed.
2. The cumulative-bytes chart was drawn from hand-typed values (21.5 KB, 2.3 KB, "88.1%") that did
   not match the measurements. It is now built from the measured session means.
3. The latency chart's axis labels had preset values typed in; they now come from the presets.

## Open items (owners)

- **D:** regenerate the numbers in `docs/PAPER_SECTIONS.md` from the new CSVs. Latency values changed
  with the unified network model. Correct the revocation claim: exposure is bounded by the
  revocation-list refresh interval and the live status check, not simply "<= TTL", and a 1-hour TTL
  measured 39% savings with up to 68 min exposure (see `cache_tradeoff.py`), not 76%.
- **D:** add sources for unsourced claims in `LITERATURE_REVIEW.md` (for example the PQC compression ratio).
- **B:** replace preset values with cited figures; validate the model under Linux `tc netem`.
- **A:** review `backend/crypto/`, add the parameter-set sweep and classical / hybrid baselines.
- **E:** take ownership of the dashboard.
- **All:** certificates use a compact custom format with X.509's core fields, not real X.509;
  say so in the paper.
