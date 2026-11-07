# QuantumShield Grid

A simulation testbed that measures how much communication overhead post-quantum cryptography
(ML-KEM-768, ML-DSA-65) adds to clean-energy device networks, and how much of it three gateway
optimizations remove without weakening security.

## Setup

Prerequisites: Python 3.10+, a C compiler, CMake and Git. On Windows, use WSL2 with Ubuntu.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -c "import oqs; print(oqs.oqs_version())"   # first run compiles liboqs (10+ min, once)
python -m pytest -v                                 # all tests must pass
python phase1_demo.py                               # crypto core walkthrough
python gateway_demo.py                              # gateway optimizations comparison
```

## Structure

| Folder | Owner | Contents |
|---|---|---|
| `backend/crypto/` | A | ML-KEM, ML-DSA, AES-GCM, PKI |
| `backend/devices/`, `backend/network/` | B | Device simulators, network model |
| `backend/gateway/` | C | Protocol, gateway, cache, trust store, grid server, testbed |
| `backend/attacks/`, `backend/metrics/`, `backend/experiments/` | D | Attacks, metrics, benchmarks |
| `backend/api/`, `frontend/` | E | API and dashboard |
| `docs/INTERFACES.md` | All | Contracts between modules. Read this first. |

## Rules

- One branch per task; open a pull request; one review; tests must pass before merging.
- Every number in the report comes from benchmark CSVs. Nothing is typed by hand.
