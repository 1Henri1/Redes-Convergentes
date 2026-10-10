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
        """
        Args:
            duration: Duração de cada bloqueio, em segundos.
            clock: Fonte de tempo (injetável para testes).
        """
        self._duration = duration
        self._clock = clock
        self._expires_at: Dict[str, float] = {}

    def block(self, ip: str) -> float:
        """Marca o IP como bloqueado a partir de agora.

        Returns:
            O instante (na base do ``clock``) em que o bloqueio termina.
        """
        expiry = self._clock() + self._duration
        self._expires_at[ip] = expiry
        return expiry

    def is_blocked(self, ip: str) -> bool:
        """Indica se o IP está bloqueado. Consulta pura, sem efeitos colaterais."""
        expiry = self._expires_at.get(ip)
        return expiry is not None and expiry > self._clock()

    def pop_expired(self) -> List[str]:
        """Remove e retorna os IPs cujo bloqueio já terminou.

        Separado de ``is_blocked`` para que uma simples consulta nunca
        altere o estado nem gere mensagens.
        """
        now = self._clock()
        expired = [ip for ip, expiry in self._expires_at.items() if expiry <= now]
        for ip in expired:
            del self._expires_at[ip]
        return expired

    def __len__(self) -> int:
        """Quantidade de entradas ainda registradas (inclui as não purgadas)."""
        return len(self._expires_at)
