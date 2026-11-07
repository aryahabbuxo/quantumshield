"""
link.py — the interface between the protocol and the network.

DirectLink just counts bytes and round trips with zero delay. Person B's network model
replaces it with a class that has the SAME methods and returns real transfer times
(bandwidth, RTT, packet loss, MTU fragmentation).
"""
from dataclasses import dataclass


@dataclass
class DirectLink:
    bytes_up: int = 0          # device -> gateway
    bytes_down: int = 0        # gateway -> device
    bytes_upstream: int = 0    # gateway -> grid server
    messages: int = 0
    network_s: float = 0.0     # always 0 here; B's model adds real delay

    def up(self, data: bytes) -> bytes:
        self.bytes_up += len(data)
        self.messages += 1
        return data

    def down(self, data: bytes) -> bytes:
        self.bytes_down += len(data)
        self.messages += 1
        return data

    def upstream(self, data: bytes) -> bytes:
        self.bytes_upstream += len(data)
        return data
