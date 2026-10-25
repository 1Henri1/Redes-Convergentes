"""Detecção com uma baseline global inicializada pelo primeiro par observado."""
import statistics
from collections import defaultdict, deque
from typing import Deque, DefaultDict, Optional, Tuple
from .config import DetectorConfig
from .models import Detection, DetectionStatus

class AnomalyDetector:
    """Usa uma baseline global; sequência de anomalias é mantida por par."""
    def __init__(self, config: DetectorConfig) -> None:
        self._config = config
        self._history: Deque[float] = deque(maxlen=config.history_size)
        self._baseline_pair: Optional[str] = None
        self._streaks: DefaultDict[str, int] = defaultdict(int)

    @property
    def baseline_pair(self) -> Optional[str]:
        return self._baseline_pair

    @property
    def baseline_ready(self) -> bool:
        return len(self._history) >= self._config.baseline_samples

    def global_limits(self, minimum_rate: Optional[float] = None) -> Optional[Tuple[float, float, float]]:
        """Retorna média, desvio e limite globais, se a baseline estiver pronta."""
        if not self.baseline_ready:
            return None
        mean = statistics.fmean(self._history)
        std = statistics.stdev(self._history)
        floor = self._config.minimum_pps if minimum_rate is None else minimum_rate
        limit = max(mean + self._config.threshold_factor * std,
                    mean * self._config.min_rate_factor, floor)
        return mean, std, limit

    def evaluate(
        self, pair_id: str, rate: float, minimum_rate: Optional[float] = None,
        include_zero_rates: bool = False,
    ) -> Detection:
        """Avalia uma métrica; somente o primeiro par forma a baseline inicial global."""
        # Não fixe a baseline em um par cuja primeira taxa seja zero:
        # isso pode impedir que a métrica forme sua baseline (especialmente bytes/s).
        if self._baseline_pair is None and rate > 0:
            self._baseline_pair = pair_id
        if not self.baseline_ready:
            if (
                self._baseline_pair is not None
                and pair_id == self._baseline_pair
                and (rate > 0 or include_zero_rates)
            ):
                self._history.append(rate)
            return Detection(DetectionStatus.BASELINE, rate, baseline_size=len(self._history))

        mean, std, limit = self.global_limits(minimum_rate)
        if rate <= 0:
            self._streaks[pair_id] = 0
            if include_zero_rates:
                self._history.append(0.0)
            return Detection(DetectionStatus.NORMAL, rate, len(self._history),
                             mean=mean, std=std, limit=limit)
        if rate > limit:
            streak = self._streaks[pair_id] + 1
            should_block = streak >= self._config.required_anomalies
            self._streaks[pair_id] = 0 if should_block else streak
            return Detection(DetectionStatus.ANOMALY, rate, len(self._history), mean=mean, std=std,
                             limit=limit, consecutive_anomalies=streak, should_block=should_block)
        self._streaks[pair_id] = 0
        self._history.append(rate)
        return Detection(DetectionStatus.NORMAL, rate, len(self._history), mean=mean, std=std, limit=limit)
