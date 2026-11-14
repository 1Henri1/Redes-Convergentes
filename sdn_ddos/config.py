"""Configuração imutável e validada do detector/monitoramento."""

from __future__ import annotations

import os
from dataclasses import dataclass, fields
from typing import Mapping, Optional

from .exceptions import ConfigurationError

ENV_PREFIX = "SDN_DDOS_"

# O campo hard_timeout do OpenFlow é um uint16, e 0 significa "permanente".
_MAX_OPENFLOW_TIMEOUT = 65535


@dataclass(frozen=True)
class DetectorConfig:
    """Parâmetros de monitoramento, detecção e mitigação."""

    monitor_interval: float = 5.0
    baseline_samples: int = 5
    history_size: int = 20
    threshold_factor: float = 3.0
    min_rate_factor: float = 1.5
    minimum_pps: float = 10.0
    entropy_threshold_factor: float = 3.0
    minimum_entropy_delta: float = 0.25
    minimum_distributed_sources: int = 2
    required_anomalies: int = 2
    block_time: int = 30
    summary_every_cycles: int = 6

    def __post_init__(self) -> None:
        """Valida os parâmetros logo na criação (fail-fast)."""
        rules = (
            (self.monitor_interval > 0, "monitor_interval deve ser > 0"),
            (self.baseline_samples >= 2, "baseline_samples deve ser >= 2"),
            (
                self.history_size >= self.baseline_samples,
                "history_size deve ser >= baseline_samples",
            ),
            (self.threshold_factor >= 0, "threshold_factor deve ser >= 0"),
            (self.min_rate_factor >= 1, "min_rate_factor deve ser >= 1"),
            (self.minimum_pps >= 0, "minimum_pps deve ser >= 0"),
            (
                self.entropy_threshold_factor >= 0,
                "entropy_threshold_factor deve ser >= 0",
            ),
            (
                self.minimum_entropy_delta >= 0,
                "minimum_entropy_delta deve ser >= 0",
            ),
            (
                self.minimum_distributed_sources >= 2,
                "minimum_distributed_sources deve ser >= 2",
            ),
            (self.required_anomalies >= 1, "required_anomalies deve ser >= 1"),
            (
                1 <= self.block_time <= _MAX_OPENFLOW_TIMEOUT,
                f"block_time deve estar entre 1 e {_MAX_OPENFLOW_TIMEOUT}",
            ),
            (self.summary_every_cycles >= 0, "summary_every_cycles deve ser >= 0"),
        )
        for is_valid, message in rules:
            if not is_valid:
                raise ConfigurationError(message)

    @classmethod
    def from_env(
        cls,
        environ: Optional[Mapping[str, str]] = None,
        prefix: str = ENV_PREFIX,
    ) -> "DetectorConfig":
        """Cria a configuração a partir de variáveis de ambiente."""
        environ = os.environ if environ is None else environ
        overrides = {}
        for field in fields(cls):
            raw = environ.get(prefix + field.name.upper())
            if raw is None:
                continue
            caster = type(field.default)
            try:
                overrides[field.name] = caster(raw)
            except ValueError as exc:
                raise ConfigurationError(
                    f"{prefix}{field.name.upper()}={raw!r} não é um "
                    f"{caster.__name__} válido"
                ) from exc
        return cls(**overrides)
