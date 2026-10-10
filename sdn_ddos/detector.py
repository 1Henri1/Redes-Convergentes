"""Detecção estatística de anomalias de tráfego (sem dependência do OS-Ken)."""

import statistics
from collections import defaultdict, deque
from typing import DefaultDict, Deque, Sequence

from .config import DetectorConfig
from .models import Detection, DetectionStatus


class AnomalyDetector:
    """Detecta picos de PPS por IP comparando com a linha de base do próprio IP.

    Funcionamento:
      1. As primeiras ``baseline_samples`` amostras formam a linha de base.
      2. Depois, uma amostra é anômala se superar
         ``max(média + k * desvio, média * min_rate_factor)``.
         O segundo termo evita que um desvio padrão quase nulo (tráfego muito
         regular) faça qualquer oscilação virar "ataque".
      3. Só amostras normais entram no histórico; do contrário, um ataque
         prolongado "ensinaria" o detector a considerá-lo normal.
      4. O bloqueio só é sugerido após ``required_anomalies`` anomalias
         consecutivas, para ignorar picos isolados.

    A classe apenas *decide*; quem bloqueia é o chamador (SRP).
    """

    def __init__(self, config: DetectorConfig) -> None:
        self._config = config
        self._history: DefaultDict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=config.history_size)
        )
        self._streaks: DefaultDict[str, int] = defaultdict(int)

    def evaluate(self, ip: str, pps: float) -> Detection:
        """Analisa uma amostra de PPS de um IP e atualiza o estado interno.

        Args:
            ip: IP de origem do tráfego medido.
            pps: Pacotes por segundo na última janela.

        Returns:
            O veredito. Quando ``should_block`` é ``True``, a sequência de
            anomalias do IP já foi zerada, pronta para um novo ciclo.
        """
        history = self._history[ip]

        if len(history) < self._config.baseline_samples:
            history.append(pps)
            return Detection(DetectionStatus.BASELINE, pps, baseline_size=len(history))

        mean = statistics.fmean(history)
        std = statistics.stdev(history)
        limit = self._compute_limit(history)

        if pps > limit:
            streak = self._streaks[ip] + 1
            should_block = streak >= self._config.required_anomalies
            self._streaks[ip] = 0 if should_block else streak
            return Detection(
                DetectionStatus.ANOMALY, pps, len(history),
                mean=mean, std=std, limit=limit,
                consecutive_anomalies=streak, should_block=should_block,
            )

        self._streaks[ip] = 0
        history.append(pps)
        return Detection(
            DetectionStatus.NORMAL, pps, len(history),
            mean=mean, std=std, limit=limit,
        )

    def _compute_limit(self, history: Sequence[float]) -> float:
        """Calcula o limite acima do qual uma amostra é considerada anômala."""
        mean = statistics.fmean(history)
        statistical = mean + self._config.threshold_factor * statistics.stdev(history)
        relative = mean * self._config.min_rate_factor
        return max(statistical, relative)
