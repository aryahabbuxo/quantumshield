"""
test_network.py — tests for the network emulation model and India network presets.
"""
from backend.network.model import ALL_PRESETS, PRESET_2G, PRESET_4G, PRESET_5G, EmulatedLink


def test_presets_exist():
    assert len(ALL_PRESETS) == 3
    assert PRESET_5G.name == "Urban 5G"
    assert PRESET_4G.name == "Highway 4G"
    assert PRESET_2G.name == "Rural 2G (lossy)"


def test_emulated_link_delay_calculation():
    # 5G link
    link_5g = EmulatedLink(preset=PRESET_5G)
    data = b"x" * 1000
    res = link_5g.up(data)
    assert res == data
    assert link_5g.bytes_up == 1000
    assert link_5g.messages == 1
    assert link_5g.network_s > 0

    # 2G link has much higher delay due to low bandwidth, high RTT, and packet loss
    link_2g = EmulatedLink(preset=PRESET_2G)
    link_2g.up(data)
    assert link_2g.network_s > link_5g.network_s
