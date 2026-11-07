"""
config.py — the three optimization switches.

Every experiment is just a different OptimizationConfig, so the benchmark (Person D)
can test each optimization alone, all combined, and leave-one-out.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class OptimizationConfig:
    cache: bool = False              # certificate caching
    chain_opt: bool = False          # certificate-chain transmission optimization
    gateway_assisted: bool = False   # gateway-assisted validation
    cache_ttl_s: int = 3600          # max age of a cache entry (bounds revocation exposure)

    @property
    def name(self) -> str:
        on = [n for n, v in (("cache", self.cache), ("chain", self.chain_opt),
                             ("assisted", self.gateway_assisted)) if v]
        return "baseline" if not on else "+".join(on)


BASELINE = OptimizationConfig()
CACHE_ONLY = OptimizationConfig(cache=True)
CHAIN_ONLY = OptimizationConfig(chain_opt=True)
ASSISTED_ONLY = OptimizationConfig(gateway_assisted=True)
COMBINED = OptimizationConfig(cache=True, chain_opt=True, gateway_assisted=True)

ALL_CONFIGS = [BASELINE, CACHE_ONLY, CHAIN_ONLY, ASSISTED_ONLY, COMBINED]
