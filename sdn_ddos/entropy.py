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
    consecutive_anomalies: int = 0
    should_block: bool = False


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
    Janelas de volume anômalo não atualizam a baseline. Uma elevação
    persistente de entropia também pode acionar a mitigação por conta própria.
    """

    def __init__(self, config: DetectorConfig) -> None:
        self._config = config
        self._history: Deque[float] = deque(maxlen=config.history_size)
        self._anomaly_streak = 0

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

        # A baseline só aceita janelas válidas: pelo menos duas origens
        # contribuíram com pacotes. Janelas vazias ou de origem única não
        # representam a distribuição do tráfego e não devem contaminá-la.
        collecting_baseline = not self.baseline_ready
        if collecting_baseline and update_baseline and source_count >= 2 and total_packets > 0:
            self._history.append(entropy)

        if not self.baseline_ready:
            return EntropyResult(
                entropy, normalized, source_count, total_packets,
                len(self._history), False,
            )

        # Se esta amostra completou a baseline, já calculamos as estatísticas
        # nesta mesma avaliação, evitando baseline_ready=True com campos None.
        mean = statistics.fmean(self._history)
        std = statistics.stdev(self._history)
        # O fator mínimo exige que a entropia seja pelo menos 50% maior
        # que a média da baseline, além do critério média + k desvios.
        limit = max(
            mean + self._config.entropy_threshold_factor * std,
            mean * self._config.minimum_entropy_factor,
        )
        anomalous = (
            source_count >= self._config.minimum_distributed_sources
            and entropy > limit
        )
        if anomalous:
            self._anomaly_streak += 1
        else:
            self._anomaly_streak = 0
        should_block = anomalous and self._anomaly_streak >= self._config.required_anomalies
        streak = self._anomaly_streak
        if should_block:
            self._anomaly_streak = 0

        # Não aprende a partir de distribuições atípicas nem durante uma
        # janela em que o PPS agregado já foi considerado anômalo.
        if update_baseline and not collecting_baseline and not anomalous:
            self._history.append(entropy)

        return EntropyResult(
            entropy, normalized, source_count, total_packets,
            len(self._history), True, mean, std, limit, anomalous,
            streak, should_block,
        )
