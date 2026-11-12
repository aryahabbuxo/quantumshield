# QuantumShield Grid

A simulation testbed that measures how much communication overhead post-quantum cryptography
(ML-KEM-768, ML-DSA-65) adds to clean-energy device networks, and how much of it three gateway
optimizations remove without weakening security, plus a live control-room dashboard.

## Setup (once)

Prerequisites: Python 3.10+, a C compiler, CMake and Git.
On Windows: Visual Studio Build Tools with "Desktop development with C++", and run the first
`import oqs` inside the "x64 Native Tools Command Prompt for VS 2022" (or use WSL2).

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1          # Windows PowerShell   (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
python -c "import oqs; print(oqs.oqs_version())"   # first run compiles liboqs (can take 30+ min, once)
python -m pytest -q                                 # all tests must pass
```

## Run

| Command | What it does |
|---|---|
| `python -m backend.experiments.benchmark` | Full benchmark: 100 trials x 8 configs, 3 networks, 88 attacks; CSVs + charts in `results/` |
| `python scale_test.py` | 1 to 1,000 devices, real handshakes, every network (`--counts 1 10 100` for a quick run) |
| `python cache_tradeoff.py` | Cache lifetime vs revocation exposure |
| `python readings_sweep.py` | Savings vs readings per session |
| `python failover_demo.py` | Primary gateway crash and recovery |
| `python gateway_demo.py` / `python phase1_demo.py` | Quick protocol and crypto walkthroughs |
| `python -m uvicorn backend.api.server:app --port 8000` | **Live dashboard** at http://localhost:8000 |

## Structure

| Folder | Owner | Contents |
|---|---|---|
| `backend/crypto/` | A | ML-KEM, ML-DSA, AES-GCM, PKI |
| `backend/devices/` | B | EV charger, solar inverter and battery simulators; fleet of 1-1,000+ devices |
| `backend/network/` | B | Packet-level network model (bandwidth, RTT, loss, MTU, retransmission) and presets |
| `backend/gateway/` | C | Protocol, gateway, cache, trust store, failover cluster, grid server, testbed |
| `backend/attacks/`, `backend/metrics/`, `backend/experiments/` | D | Attacks, metrics, benchmark and charts |
| `backend/api/`, `frontend/` | E | Live dashboard |
| `docs/` | All | `INTERFACES.md` (contracts), `INTEGRATION_NOTES.md`, paper drafts |

## Rules

- One branch per task; open a pull request; one review; tests must pass before merging.
- Every number in the report comes from benchmark CSVs. Nothing is typed by hand.
- Network presets are modelling assumptions until replaced with cited figures.
