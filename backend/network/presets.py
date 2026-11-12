"""
presets.py — network presets (owner: B). ONE source of truth for the whole project.

These values are MODELLING ASSUMPTIONS chosen as representative round numbers.
Before the paper: replace each with a cited figure (e.g. TRAI / operator / 3GPP reports)
and validate the model against Linux tc netem.

| Preset            | Bandwidth | RTT    | Loss  | MTU  | Jitter | Scenario                         |
|-------------------|-----------|--------|-------|------|--------|----------------------------------|
| Urban 5G          | 100 Mbps  | 20 ms  | 0.1 % | 1500 | 5 ms   | Bangalore city chargers / solar  |
| Highway 4G        | 15 Mbps   | 60 ms  | 1 %   | 1500 | 20 ms  | Bangalore-Mysore EV corridor     |
| Rural 2G (lossy)  | 100 kbps  | 300 ms | 5 %   | 576  | 80 ms  | rural solar pumps / microgrids   |
| Backhaul fibre    | 1 Gbps    | 2 ms   | 0 %   | 1500 | 0      | gateway -> grid operator         |
"""
from .model import NetworkConfig

URBAN_5G = NetworkConfig("Urban 5G", bandwidth_bps=100e6, rtt_s=0.020, loss_rate=0.001,
                         mtu=1500, jitter_s=0.005)
HIGHWAY_4G = NetworkConfig("Highway 4G", bandwidth_bps=15e6, rtt_s=0.060, loss_rate=0.01,
                           mtu=1500, jitter_s=0.020)
RURAL_2G = NetworkConfig("Rural 2G (lossy)", bandwidth_bps=100e3, rtt_s=0.300, loss_rate=0.05,
                         mtu=576, jitter_s=0.080)
BACKHAUL_FIBRE = NetworkConfig("Backhaul fibre", bandwidth_bps=1e9, rtt_s=0.002, loss_rate=0.0)

# names kept for the experiments code
PRESET_5G, PRESET_4G, PRESET_2G = URBAN_5G, HIGHWAY_4G, RURAL_2G
ALL_PRESETS = [URBAN_5G, HIGHWAY_4G, RURAL_2G]
PRESETS = {"urban_5g": URBAN_5G, "highway_4g": HIGHWAY_4G, "rural_2g": RURAL_2G}


def get_preset(name: str) -> NetworkConfig:
    """Accepts 'urban_5g', 'Urban 5G', 'rural-2g', ..."""
    key = name.strip().lower().replace("(lossy)", "").strip().replace(" ", "_").replace("-", "_")
    if key not in PRESETS:
        raise KeyError(f"Unknown preset {name!r}. Choose from {sorted(PRESETS)}")
    return PRESETS[key]
