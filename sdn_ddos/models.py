"""Estruturas de dados compartilhadas entre os módulos."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class DetectionStatus(Enum):
    """Resultado da análise de uma amostra de tráfego."""

    BASELINE = "baseline"  # ainda coletando a linha de base
    NORMAL = "normal"      # dentro do limite
    ANOMALY = "anomaly"    # acima do limite


@dataclass(frozen=True)
class PortRate:
    """Taxa de recepção de uma porta entre duas coletas consecutivas."""

    delta_packets: int
    delta_bytes: int
    pps: float
    bps: float


@dataclass(frozen=True)
class Detection:
    """Veredito do detector para uma amostra de PPS.

    ``mean``, ``std`` e ``limit`` só são preenchidos depois que a linha de
    base está formada.
    """

    status: DetectionStatus
    pps: float
    baseline_size: int
    mean: Optional[float] = None
    std: Optional[float] = None
    limit: Optional[float] = None
    consecutive_anomalies: int = 0
    should_block: bool = False


@dataclass
class ControllerStats:
    """Contadores acumulados desde o início do controlador."""

    detections: int = 0
    blocks: int = 0
