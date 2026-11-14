"""Entropia de Shannon para caracterizar a distribuição das origens por destino."""

from __future__ import annotations

import math
import statistics
from collections import deque
from dataclasses import dataclass
from typing import Deque, Mapping, Optional

from .config import DetectorConfig


@dataclass(frozen=True)
class EntropyResult:
    """Resumo da distribuição das origens em uma janela de monitoramento."""

    entropy_bits: float
    normalized_entropy: float
    source_count: int
    total_packets: int
    baseline_size: int
    baseline_ready: bool
    mean: Optional[float] = None
    std: Optional[float] = None
    limit: Optional[float] = None
    anomalous: bool = False


def shannon_entropy(packet_counts: Mapping[str, int]) -> tuple[float, float, int, int]:
    """Retorna H em bits, H normalizada, número de origens e total de pacotes.

    Apenas contagens positivas participam do cálculo. A normalização divide H
    por log2(N), ficando entre 0 e 1; para zero ou uma origem, H normalizada é 0.
    """
    positive = [int(value) for value in packet_counts.values() if int(value) > 0]
    source_count = len(positive)
    total_packets = sum(positive)
    if total_packets == 0:
        return 0.0, 0.0, 0, 0

    entropy = 0.0
    for count in positive:
        probability = count / total_packets
        entropy -= probability * math.log2(probability)

    normalized = entropy / math.log2(source_count) if source_count > 1 else 0.0
    return entropy, min(1.0, normalized), source_count, total_packets


class DestinationEntropyDetector:
    """Mantém uma baseline de entropia por destino.

    A entropia elevada não dispara bloqueio sozinha. Ela caracteriza como
    distribuído um evento que já foi sinalizado pelo detector de PPS agregado.
    Janelas de volume anômalo não atualizam a baseline.
    """

    def __init__(self, config: DetectorConfig) -> None:
        self._config = config
        self._history: Deque[float] = deque(maxlen=config.history_size)

    @property
    def baseline_ready(self) -> bool:
        return len(self._history) >= self._config.baseline_samples

    def evaluate(
        self,
        packet_counts: Mapping[str, int],
        *,
        update_baseline: bool = True,
    ) -> EntropyResult:
        entropy, normalized, source_count, total_packets = shannon_entropy(packet_counts)

        if not self.baseline_ready:
            if update_baseline:
                self._history.append(entropy)
            # Esta amostra ainda pertence à fase de formação da baseline.
            # Mesmo que ela complete a quantidade exigida, média/desvio/limite
            # só estarão disponíveis na próxima avaliação.
            return EntropyResult(
                entropy, normalized, source_count, total_packets,
                len(self._history), False,
            )

        mean = statistics.fmean(self._history)
        std = statistics.stdev(self._history)
        # O incremento mínimo evita um limite praticamente nulo quando a
        # distribuição normal permanece constante (por exemplo, H = 0).
        limit = max(
            mean + self._config.entropy_threshold_factor * std,
            mean + self._config.minimum_entropy_delta,
        )
        anomalous = (
            source_count >= self._config.minimum_distributed_sources
            and entropy > limit
        )

        # Não aprende a partir de distribuições atípicas nem durante uma
        # janela em que o PPS agregado já foi considerado anômalo.
        if update_baseline and not anomalous:
            self._history.append(entropy)

        return EntropyResult(
            entropy, normalized, source_count, total_packets,
            len(self._history), True, mean, std, limit, anomalous,
        )
