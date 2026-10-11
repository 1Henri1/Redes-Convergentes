"""Configuração imutável e validada do detector/monitoramento."""

from __future__ import annotations

import os
from dataclasses import dataclass, fields
from typing import Mapping, Optional

from .exceptions import ConfigurationError

ENV_PREFIX = "SDN_DDOS_"

# O campo hard_timeout do OpenFlow é um uint16, e 0 significa "permanente".
# Aceitar 0 transformaria um bloqueio *temporário* em definitivo.
_MAX_OPENFLOW_TIMEOUT = 65535


@dataclass(frozen=True)
class DetectorConfig:
    """Parâmetros de monitoramento, detecção e mitigação.

    Attributes:
        monitor_interval: Segundos entre duas coletas de estatísticas.
        baseline_samples: Amostras necessárias para formar a linha de base.
        history_size: Tamanho da janela deslizante de PPS "normais" por IP.
        threshold_factor: Limite estatístico = média + fator * desvio padrão.
        min_rate_factor: O tráfego também precisa superar média * fator.
            Evita falsos positivos quando o desvio padrão é muito pequeno.
        required_anomalies: Janelas anômalas consecutivas antes de bloquear.
        block_time: Duração do bloqueio, em segundos.
        summary_every_cycles: Imprime o resumo a cada N ciclos (0 desativa).
    """

    monitor_interval: float = 5.0
    baseline_samples: int = 5
    history_size: int = 20
    threshold_factor: float = 3.0
    min_rate_factor: float = 1.5
    required_anomalies: int = 2
    block_time: int = 30
    summary_every_cycles: int = 6

    def __post_init__(self) -> None:
        """Valida os parâmetros logo na criação (fail-fast)."""
        rules = (
            (self.monitor_interval > 0, "monitor_interval deve ser > 0"),
            # stdev exige pelo menos 2 amostras.
            (self.baseline_samples >= 2, "baseline_samples deve ser >= 2"),
            (
                self.history_size >= self.baseline_samples,
                "history_size deve ser >= baseline_samples",
            ),
            (self.threshold_factor >= 0, "threshold_factor deve ser >= 0"),
            (self.min_rate_factor >= 1, "min_rate_factor deve ser >= 1"),
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
        """Cria a configuração a partir de variáveis de ambiente.

        Variáveis de ambiente (e não argparse) são usadas porque o OS-Ken
        faz o seu próprio parsing de argumentos de linha de comando.
        Exemplo: ``SDN_DDOS_BLOCK_TIME=60``.

        Args:
            environ: Mapeamento a consultar (padrão: ``os.environ``).
            prefix: Prefixo das variáveis.

        Returns:
            Configuração com os valores informados e padrões para o resto.

        Raises:
            ConfigurationError: Se um valor não puder ser convertido ou
                violar as regras de validação.
        """
        environ = os.environ if environ is None else environ
        overrides = {}
        for field in fields(cls):
            raw = environ.get(prefix + field.name.upper())
            if raw is None:
                continue
            # O tipo do valor padrão indica como converter (int ou float).
            caster = type(field.default)
            try:
                overrides[field.name] = caster(raw)
            except ValueError as exc:
                raise ConfigurationError(
                    f"{prefix}{field.name.upper()}={raw!r} não é um "
                    f"{caster.__name__} válido"
                ) from exc
        return cls(**overrides)
