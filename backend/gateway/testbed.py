"""
testbed.py — builds a complete, ready-to-run network in one call:
PKI (Root -> Intermediate), a gateway, the grid server, and N devices.

Used by the tests, the demo, Person D's benchmark and Person E's dashboard.
"""
from dataclasses import dataclass

from backend.crypto import pqc
from backend.crypto.pki import CertificateAuthority

from .client import DeviceClient
from .config import OptimizationConfig
from .gateway import Gateway
from .grid_server import GridServer
from .trust_store import TrustStore

DEVICE_PREFIXES = ["EV", "SOLAR", "BAT"]


@dataclass
class Testbed:
    root: CertificateAuthority
    intermediate: CertificateAuthority
    gateway: Gateway
    grid: GridServer
    devices: list[DeviceClient]


def _trust(root: CertificateAuthority, inter: CertificateAuthority, with_intermediate: bool) -> TrustStore:
    t = TrustStore()
    t.add_root(root.cert)
    if with_intermediate:
        t.add_intermediate(inter.cert)
    return t


def build_testbed(config: OptimizationConfig, n_devices: int = 3) -> Testbed:
    root = CertificateAuthority.create_root("QSG Root CA")
    inter = root.create_intermediate("QSG Intermediate CA")

    # The gateway always holds the intermediate in its trust store; whether devices
    # still SEND it is what the chain-transmission optimization changes.
    gw_kp = pqc.sig_keygen()
    gateway = Gateway("GW_001", gw_kp, inter.issue("GW_001", gw_kp.public_key),
                      _trust(root, inter, True), config)
    grid = GridServer(_trust(root, inter, True))
    grid.register_gateway(gateway)

    devices = []
    for i in range(n_devices):
        device_id = f"{DEVICE_PREFIXES[i % 3]}_{i // 3 + 1:03d}"
        kp = pqc.sig_keygen()
        devices.append(DeviceClient(device_id, kp, inter.issue(device_id, kp.public_key), [inter.cert],
                                    _trust(root, inter, True), config))
    return Testbed(root, inter, gateway, grid, devices)
