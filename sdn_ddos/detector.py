"""Detecção estatística global de anomalias de tráfego."""

import statistics
from collections import defaultdict, deque
from typing import Deque, DefaultDict

from .config import DetectorConfig
from .models import Detection, DetectionStatus


class AnomalyDetector:
    """Usa o primeiro IP para formar a linha de base global de PPS."""

    def __init__(self, config: DetectorConfig) -> None:
        self._config = config
        self._first_ip: str | None = None
        self._history: Deque[float] = deque(
            maxlen=config.history_size
        )
        self._streaks: DefaultDict[str, int] = defaultdict(int)

    def evaluate(self, ip: str, pps: float) -> Detection:
        """Avalia o PPS usando a referência global."""

        if self._first_ip is None:
            self._first_ip = ip

        # Apenas o primeiro IP forma a linha de base inicial.
        if len(self._history) < self._config.baseline_samples:
            if ip != self._first_ip:
                return Detection(
                    DetectionStatus.BASELINE,
                    pps,
                    baseline_size=len(self._history),
                )

            self._history.append(pps)
            return Detection(
                DetectionStatus.BASELINE,
                pps,
                baseline_size=len(self._history),
            )

        mean = statistics.fmean(self._history)
        std = statistics.stdev(self._history)

        limit = max(
            mean + self._config.threshold_factor * std,
            mean * self._config.min_rate_factor,
        )

        if pps > limit:
            streak = self._streaks[ip] + 1
            should_block = (
                streak >= self._config.required_anomalies
            )
            self._streaks[ip] = 0 if should_block else streak

            return Detection(
                DetectionStatus.ANOMALY,
                pps,
                len(self._history),
                mean=mean,
                std=std,
                limit=limit,
                consecutive_anomalies=streak,
                should_block=should_block,
            )

        # Apenas taxas normais atualizam o histórico global.
        self._streaks[ip] = 0
        self._history.append(pps)

        return Detection(
            DetectionStatus.NORMAL,
            pps,
            len(self._history),
            mean=mean,
            std=std,
            limit=limit,
        )
