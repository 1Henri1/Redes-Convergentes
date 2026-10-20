"""Detecção estatística de anomalias independente por par origem-destino."""
import statistics
from collections import defaultdict, deque
from typing import Deque, DefaultDict, Dict
from .config import DetectorConfig
from .models import Detection, DetectionStatus

class AnomalyDetector:
    """Mantém baseline e histórico separados para cada par IP."""
    def __init__(self, config: DetectorConfig) -> None:
        self._config = config
        self._history: Dict[str, Deque[float]] = {}
        self._streaks: DefaultDict[str, int] = defaultdict(int)

    def evaluate(self, pair_id: str, pps: float) -> Detection:
        """Avalia PPS usando somente o histórico do próprio par."""
        history = self._history.setdefault(pair_id, deque(maxlen=self._config.history_size))
        if len(history) < self._config.baseline_samples:
            history.append(pps)
            return Detection(DetectionStatus.BASELINE, pps, baseline_size=len(history))

        mean = statistics.fmean(history)
        std = statistics.stdev(history)
        limit = max(mean + self._config.threshold_factor * std,
                    mean * self._config.min_rate_factor, self._config.minimum_pps)
        if pps > limit:
            streak = self._streaks[pair_id] + 1
            should_block = streak >= self._config.required_anomalies
            self._streaks[pair_id] = 0 if should_block else streak
            return Detection(DetectionStatus.ANOMALY, pps, len(history), mean=mean, std=std,
                             limit=limit, consecutive_anomalies=streak, should_block=should_block)
        self._streaks[pair_id] = 0
        history.append(pps)
        return Detection(DetectionStatus.NORMAL, pps, len(history), mean=mean, std=std, limit=limit)
