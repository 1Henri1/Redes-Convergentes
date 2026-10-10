"""Cálculo de taxas (PPS/BPS) a partir de contadores cumulativos."""

import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

from .models import PortRate

PortKey = Tuple[int, int]  # (dpid, número da porta)


@dataclass(frozen=True)
class _Snapshot:
    packets: int
    bytes: int
    timestamp: float


class PortRateCalculator:
    """Converte contadores ``rx_packets``/``rx_bytes`` em taxas por segundo.

    Os contadores do switch só crescem, então a taxa vem da diferença entre
    duas leituras dividida pelo tempo decorrido.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        """
        Args:
            clock: Fonte de tempo. ``monotonic`` é usado (e não ``time.time``)
                para que ajustes do relógio do sistema (NTP) não distorçam
                as taxas. É injetável para facilitar os testes.
        """
        self._clock = clock
        self._previous: Dict[PortKey, _Snapshot] = {}

    def update(self, key: PortKey, rx_packets: int, rx_bytes: int) -> Optional[PortRate]:
        """Registra uma leitura e calcula a taxa desde a anterior.

        Args:
            key: ``(dpid, porta)`` do contador.
            rx_packets: Total de pacotes recebidos pela porta.
            rx_bytes: Total de bytes recebidos pela porta.

        Returns:
            A taxa medida, ou ``None`` quando não há como calcular: primeira
            leitura da porta, tempo decorrido nulo ou contador que diminuiu
            (o switch reiniciou). Nesse último caso a leitura atual vira a
            nova referência.
        """
        now = self._clock()
        previous = self._previous.get(key)
        self._previous[key] = _Snapshot(rx_packets, rx_bytes, now)

        if previous is None:
            return None

        elapsed = now - previous.timestamp
        delta_packets = rx_packets - previous.packets
        delta_bytes = rx_bytes - previous.bytes

        if elapsed <= 0 or delta_packets < 0 or delta_bytes < 0:
            return None

        return PortRate(
            delta_packets=delta_packets,
            delta_bytes=delta_bytes,
            pps=delta_packets / elapsed,
            bps=delta_bytes / elapsed,
        )

    def forget_switch(self, dpid: int) -> None:
        """Descarta as leituras de um switch desconectado."""
        for key in [k for k in self._previous if k[0] == dpid]:
            del self._previous[key]
