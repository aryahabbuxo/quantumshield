"""
cluster.py — gateway failover: a primary and one or more backup gateways.

Answers the review's "single point of failure" criticism.

Design decisions (explain these in the paper):
  * Session keys are NEVER shared between gateways. If the primary fails, its sessions die
    with it and devices run a fresh handshake with the backup. Sharing keys would mean one
    compromised gateway exposes every session.
  * Cached certificates CAN be replicated (replicate_cache=True). They are public data, so
    copying them is safe, and it lets devices reconnect to the backup with a cheap cache hit
    instead of resending their full chain. We measure both options.
  * Revocation is applied to every gateway at once (revoke()), so a replicated cache entry
    can never outlive a revocation.

A GatewayCluster has the same methods as a Gateway (config, connect, on_telemetry), so
run_session(), the benchmark and the dashboard work with it unchanged.
"""
from .gateway import Gateway
from .messages import MsgType, decode


class GatewayCluster:
    def __init__(self, gateways: list[Gateway], replicate_cache: bool = True):
        if not gateways:
            raise ValueError("a cluster needs at least one gateway")
        self.gateways = gateways
        self.replicate_cache = replicate_cache
        self.config = gateways[0].config
        self.failovers = 0
        if replicate_cache:
            for g in gateways:
                g.cache_listeners.append(lambda cert, source=g: self._replicate(source, cert))

    # -------------------------------------------------------------- routing ---
    @property
    def active(self) -> Gateway:
        """The first healthy gateway. New devices always connect here."""
        for g in self.gateways:
            if g.alive:
                return g
        raise ConnectionError("all gateways are down")

    @property
    def name(self) -> str:
        return self.active.name

    def connect(self):
        return self.active.connect()

    def on_telemetry(self, data: bytes) -> list[bytes]:
        """Route a reading to the gateway that owns its session."""
        _, fields = decode(data, MsgType.TELEMETRY)
        for g in self.gateways:
            if fields[0] in g.sessions:
                if not g.alive:
                    raise ConnectionError(f"{g.name} is down; reconnect required")
                return g.on_telemetry(data)
        raise PermissionError("unknown session")

    # ------------------------------------------------------- failure control ---
    def fail(self, name: str) -> None:
        """Simulate a crash: the gateway stops answering."""
        self._get(name).alive = False
        self.failovers += 1

    def recover(self, name: str) -> None:
        """Restart after a crash: memory (sessions, cache) is lost, trust store is reloaded."""
        g = self._get(name)
        g.sessions.clear()
        g.cache = type(g.cache)(g.config.cache_ttl_s)
        g.alive = True

    def revoke(self, serial: int) -> None:
        """Revocation reaches every gateway, so no replicated cache entry outlives it."""
        for g in self.gateways:
            g.trust.revoke(serial)

    # -------------------------------------------------------------- helpers ---
    def _replicate(self, source: Gateway, cert) -> None:
        for g in self.gateways:
            if g is not source and g.alive:
                g.cache.put(cert)

    def _get(self, name: str) -> Gateway:
        for g in self.gateways:
            if g.name == name:
                return g
        raise KeyError(name)
