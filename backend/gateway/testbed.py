"""
testbed.py — builds a complete, ready-to-run network in one call:
PKI (Root -> Intermediate), a gateway, the grid server, and N devices.

Used by the tests, the demo, Person D's benchmark and Person E's dashboard.
"""
from dataclasses import dataclass

from backend.crypto import pqc
from backend.crypto.pki import CertificateAuthority

from .client import DeviceClient
from .cluster import GatewayCluster
from .config import OptimizationConfig
from .gateway import Gateway
from .grid_server import GridServer
from .trust_store import TrustStore

DEVICE_PREFIXES = ["EV", "SOLAR", "BAT"]


@dataclass
class Testbed:
    root: CertificateAuthority
    intermediate: CertificateAuthority
    gateway: Gateway | GatewayCluster
    grid: GridServer
    devices: list[DeviceClient]


def _trust(root: CertificateAuthority, inter: CertificateAuthority, with_intermediate: bool) -> TrustStore:
    t = TrustStore()
    t.add_root(root.cert)
    if with_intermediate:
        t.add_intermediate(inter.cert)
    return t


def build_testbed(config: OptimizationConfig, n_devices: int = 3,
                  n_gateways: int = 1, replicate_cache: bool = True,
                  device_ids: list[str] | None = None) -> Testbed:
    """n_gateways > 1 returns a GatewayCluster (primary + backups) as `gateway`.
    device_ids: optional names for the devices (used by the device fleet); overrides n_devices."""
    root = CertificateAuthority.create_root("QSG Root CA")
    inter = root.create_intermediate("QSG Intermediate CA")
    grid = GridServer(_trust(root, inter, True))

    # Each gateway always holds the intermediate in its trust store; whether devices
    # still SEND it is what the chain-transmission optimization changes.
    gateways = []
    for i in range(n_gateways):
        name, gw_kp = f"GW_{i + 1:03d}", pqc.sig_keygen()
        g = Gateway(name, gw_kp, inter.issue(name, gw_kp.public_key), _trust(root, inter, True), config)
        grid.register_gateway(g)
        gateways.append(g)
    gateway = gateways[0] if n_gateways == 1 else GatewayCluster(gateways, replicate_cache)

    devices = []
    ids = device_ids or [f"{DEVICE_PREFIXES[i % 3]}_{i // 3 + 1:03d}" for i in range(n_devices)]
    for device_id in ids:
        kp = pqc.sig_keygen()
        devices.append(DeviceClient(device_id, kp, inter.issue(device_id, kp.public_key), [inter.cert],
                                    _trust(root, inter, True), config))
    return Testbed(root, inter, gateway, grid, devices)
