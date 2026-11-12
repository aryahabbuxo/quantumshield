"""
server.py — the live "Grid Security Control Room" (owner: E; built by C for the Phase 2 demo).

Run:   python -m uvicorn backend.api.server:app --port 8000      then open http://localhost:8000

Everything shown is computed live by the real system:
  * B's device fleet (EV chargers, solar inverters, batteries around Bangalore) and network model
  * C's PQC protocol: real ML-KEM-768 / ML-DSA-65 handshakes, the three optimizations, gateway failover
  * D's attack suite (each attack runs for real against the current configuration)
  * D's benchmark charts and CSVs in results/ (Experiment Lab tab)
"""
from __future__ import annotations

import asyncio
import csv
import statistics as st
import threading
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.attacks.suite import ATTACK_RUNNERS
from backend.crypto import pqc
from backend.devices import build_fleet, run_fleet
from backend.gateway.config import ALL_CONFIGS, OptimizationConfig
from backend.gateway.testbed import build_testbed
from backend.network import PRESETS, get_preset

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

GATEWAY_SITES = {"GW_001": (12.9352, 77.6245, "Koramangala substation (primary)"),
                 "GW_002": (13.0358, 77.5970, "Hebbal substation (backup)")}

app = FastAPI(title="QuantumShield Grid")
app.mount("/vendor", StaticFiles(directory=FRONTEND / "vendor"), name="vendor")
app.mount("/results", StaticFiles(directory=RESULTS), name="results")


class Settings(BaseModel):
    cache: bool = True
    chain_opt: bool = True
    gateway_assisted: bool = True
    preset: str = "urban_5g"
    devices: int = 30
    readings: int = 1
    speed: float = 1.0          # 1 = each device reports about every 5 s


class Sim:
    def __init__(self):
        self.settings = Settings()
        self.clients: set[WebSocket] = set()
        self.task: asyncio.Task | None = None
        self.fleet = None
        self.running = False
        self.reset_stats()

    def reset_stats(self):
        self.sessions = self.ok = self.cache_hits = self.attacks = self.blocked = 0
        self.bytes, self.latency = [], []          # steady-state sessions only (repeat connections)
        self.reference = {}
        self.run_id = getattr(self, "run_id", 0) + 1

    @property
    def config(self) -> OptimizationConfig:
        s = self.settings
        return OptimizationConfig(cache=s.cache, chain_opt=s.chain_opt, gateway_assisted=s.gateway_assisted)

    def kpis(self) -> dict:
        base = self.reference.get("baseline", {})
        mean_bytes = st.mean(self.bytes[-500:]) if self.bytes else 0
        mean_lat = st.mean(self.latency[-500:]) if self.latency else 0
        saved = (1 - mean_bytes / base["bytes"]) * 100 if base.get("bytes") and mean_bytes else None
        faster = (1 - mean_lat / base["latency"]) * 100 if base.get("latency") and mean_lat else None
        return {"sessions": self.sessions, "success_pct": 100 * self.ok / self.sessions if self.sessions else None,
                "cache_hits": self.cache_hits, "mean_bytes": mean_bytes, "mean_latency_ms": mean_lat,
                "bytes_saved_pct": saved, "latency_saved_pct": faster,
                "attacks": self.attacks, "blocked": self.blocked}

    async def broadcast(self, msg: dict):
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)


sim = Sim()


def gateway_status() -> list[dict]:
    gw = sim.fleet.testbed.gateway if sim.fleet else None
    gws = getattr(gw, "gateways", [gw] if gw else [])
    try:
        active = gw.active.name if hasattr(gw, "active") else (gw.name if gw else None)
    except ConnectionError:
        active = None
    return [{"name": g.name, "alive": g.alive, "active": g.name == active, "cached": len(g.cache),
             "lat": GATEWAY_SITES[g.name][0], "lon": GATEWAY_SITES[g.name][1], "site": GATEWAY_SITES[g.name][2]}
            for g in gws]


def state() -> dict:
    s = sim.settings
    preset = get_preset(s.preset)
    return {"running": sim.running, "settings": s.model_dump(), "config_name": sim.config.name,
            "preset": {"key": s.preset, "name": preset.name, "bandwidth_mbps": preset.bandwidth_bps / 1e6,
                       "rtt_ms": preset.rtt_s * 1000, "loss_pct": preset.loss_rate * 100, "mtu": preset.mtu},
            "presets": {k: v.name for k, v in PRESETS.items()},
            "devices": [{"id": d.device_id, "type": d.device_type, "lat": d.lat, "lon": d.lon}
                        for d in (sim.fleet.devices if sim.fleet else [])],
            "gateways": gateway_status() if sim.fleet else [],
            "algorithms": {"kem": pqc.KEM_ALG, "sig": pqc.SIG_ALG, "aead": "AES-256-GCM"},
            "kpis": sim.kpis(), "reference": sim.reference}


def _measure_all_configs(preset: str, readings: int) -> dict:
    """Same network, same workload, every configuration (steady state). Runs in a worker thread."""
    out = {}
    for cfg in ALL_CONFIGS:
        fleet = build_fleet(5, cfg, preset, seed=99)
        recs = asyncio.run(run_fleet(fleet, rounds=4, readings_per_session=readings))
        steady = [r for r in recs if r.connection == "repeat" and r.success] or recs
        out[cfg.name] = {"bytes": st.mean(r.total_bytes for r in steady),
                         "latency": st.mean(r.network_ms for r in steady),      # simulated network time
                         "wire": st.mean(r.wire_bytes for r in steady),
                         "handshake": st.mean(r.handshake_bytes for r in steady),
                         "packets": st.mean(r.packets for r in steady),
                         "retx": st.mean(r.retransmissions for r in steady)}
    return out


async def compute_reference(run_id: int):
    out = await asyncio.to_thread(_measure_all_configs, sim.settings.preset, sim.settings.readings)
    if run_id != sim.run_id:                    # settings changed meanwhile: discard
        return
    sim.reference = out
    await sim.broadcast({"type": "reference", "reference": out, "kpis": sim.kpis()})


async def run_live():
    s = sim.settings
    loop = asyncio.get_running_loop()

    def on_event(ev: dict):
        rec = ev["record"]
        sim.sessions += 1
        sim.ok += rec["success"]
        sim.cache_hits += rec["cache_hit"]
        if rec["success"] and rec["connection"] == "repeat":     # compare steady state with steady state
            sim.bytes.append(rec["total_bytes"])
            sim.latency.append(rec["network_ms"])
        gws = gateway_status()
        ev["via"] = next((g["name"] for g in gws if g["active"]), None)
        ev["kpis"] = sim.kpis()
        ev["gateways"] = gws
        loop.create_task(sim.broadcast(ev))

    asyncio.create_task(compute_reference(sim.run_id))      # comparison runs in the background
    await run_fleet(sim.fleet, rounds=100_000, interval_s=60, readings_per_session=s.readings,
                    time_scale=0.08 / max(0.1, s.speed), on_event=on_event, should_stop=lambda: not sim.running)


async def restart():
    await stop()
    sim.reset_stats()
    s = sim.settings
    sim.fleet = build_fleet(max(1, min(s.devices, 300)), sim.config, s.preset, n_gateways=2, seed=7)
    sim.running = True
    await sim.broadcast({"type": "state", "state": state()})
    sim.task = asyncio.create_task(run_live())


async def stop():
    sim.running = False
    if sim.task:
        sim.task.cancel()
        try:
            await sim.task
        except (asyncio.CancelledError, Exception):
            pass
        sim.task = None


# ------------------------------------------------------------------------------- routes ---
@app.get("/")
async def index():
    return FileResponse(FRONTEND / "index.html")


@app.get("/api/state")
async def get_state():
    return state()


@app.post("/api/start")
async def start(settings: Settings):
    get_preset(settings.preset)
    sim.settings = settings
    await restart()
    return state()


@app.post("/api/stop")
async def stop_route():
    await stop()
    await sim.broadcast({"type": "state", "state": state()})
    return state()


@app.get("/api/attacks")
async def list_attacks():
    return [name for name, _ in ATTACK_RUNNERS]


@app.post("/api/attack/{index}")
async def attack(index: int):
    """Run one of D's attacks for real against a fresh testbed with the CURRENT configuration."""
    name, runner = ATTACK_RUNNERS[index]
    res = runner(build_testbed(sim.config, n_devices=3))
    applicable = not res.rejection_reason.startswith("N/A")     # e.g. E2E-signature attack in assisted mode
    if applicable:
        sim.attacks += 1
        sim.blocked += res.blocked
    target = sim.fleet.devices[index % len(sim.fleet.devices)] if sim.fleet else None
    ev = {"type": "attack", "name": name, "category": res.attack_category, "blocked": res.blocked, "applicable": applicable,
          "reason": res.rejection_reason, "config": res.config_name,
          "lat": target.lat if target else None, "lon": target.lon if target else None, "kpis": sim.kpis()}
    await sim.broadcast(ev)
    return ev


@app.post("/api/gateway/{name}/{action}")
async def gateway_action(name: str, action: str):
    cluster = sim.fleet.testbed.gateway if sim.fleet else None
    if not hasattr(cluster, "fail"):
        return JSONResponse({"error": "start the simulation first"}, status_code=400)
    (cluster.fail if action == "fail" else cluster.recover)(name)
    ev = {"type": "gateway", "name": name, "action": action, "gateways": gateway_status()}
    await sim.broadcast(ev)
    return ev


@app.get("/api/results")
async def results():
    """Experiment Lab: every chart in results/ plus headline numbers from the CSVs."""
    charts = sorted(p.name for p in RESULTS.glob("*.png"))
    summary = []
    f = RESULTS / "benchmark_summary.csv"
    if f.exists():
        summary = list(csv.DictReader(open(f, encoding="utf-8")))
    attacks = []
    a = RESULTS / "attack_results.csv"
    if a.exists():
        attacks = list(csv.DictReader(open(a, encoding="utf-8")))
    applicable = [r for r in attacks if not r["rejection_reason"].startswith("N/A")]
    return {"charts": charts, "summary": summary,
            "attacks": {"total": len(applicable), "blocked": sum(r["blocked"] == "True" for r in applicable)}}


_bench_lock = threading.Lock()


@app.post("/api/experiments/run")
async def run_experiments():
    """Re-run D's full benchmark (100 trials x 8 configs + 3 networks + 88 attacks) in the background."""
    if not _bench_lock.acquire(blocking=False):
        return {"status": "already running"}
    loop = asyncio.get_running_loop()

    def work():
        try:
            from backend.experiments.benchmark import run_full_benchmark
            run_full_benchmark(trials=100, output_dir=RESULTS)
            asyncio.run_coroutine_threadsafe(sim.broadcast({"type": "experiments_done"}), loop)
        finally:
            _bench_lock.release()

    threading.Thread(target=work, daemon=True).start()
    return {"status": "started"}


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    sim.clients.add(websocket)
    await websocket.send_json({"type": "state", "state": state()})
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        sim.clients.discard(websocket)
