"""Controle de IPs bloqueados temporariamente."""

import time
from typing import Callable, Dict, List


_MAX_OPENFLOW_TIMEOUT = 65535


class BlockList:
    """Registra bloqueios e dobra sua duração a cada reincidência do IP."""

    def __init__(self, duration: float, clock: Callable[[], float] = time.monotonic) -> None:
        self._duration = duration
        self._clock = clock
        self._expires_at: Dict[str, float] = {}
        self._block_counts: Dict[str, int] = {}

    def block(self, ip: str) -> int:
        """Bloqueia o IP e retorna a duração efetiva, dobrada por reincidência."""
        count = self._block_counts.get(ip, 0)
        multiplier = 2 ** min(count, 16)
        duration = min(int(self._duration * multiplier), _MAX_OPENFLOW_TIMEOUT)
        self._block_counts[ip] = count + 1
        self._expires_at[ip] = self._clock() + duration
        return duration

    def is_blocked(self, ip: str) -> bool:
        expiry = self._expires_at.get(ip)
        return expiry is not None and expiry > self._clock()

    def active_ips(self) -> List[str]:
        """Retorna os IPs ainda bloqueados, sem alterar a lista."""
        now = self._clock()
        return sorted(ip for ip, expiry in self._expires_at.items() if expiry > now)

    def pop_expired(self) -> List[str]:
        now = self._clock()
        expired = [ip for ip, expiry in self._expires_at.items() if expiry <= now]
        for ip in expired:
            del self._expires_at[ip]
        return expired

    def __len__(self) -> int:
        return len(self._expires_at)
