"""Controle de IPs bloqueados temporariamente."""

import time
from typing import Callable, Dict, List


class BlockList:
    """Registra no controlador quais IPs estão bloqueados e até quando.

    O bloqueio efetivo é uma regra de drop no switch com ``hard_timeout``;
    esta lista é o espelho dessa regra no controlador, usada para suprimir
    novas detecções e para informar quando o bloqueio expirou.
    """

    def __init__(self, duration: float, clock: Callable[[], float] = time.monotonic) -> None:
        self._duration = duration
        self._clock = clock
        self._expires_at: Dict[str, float] = {}

    def block(self, ip: str) -> float:
        expiry = self._clock() + self._duration
        self._expires_at[ip] = expiry
        return expiry

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
