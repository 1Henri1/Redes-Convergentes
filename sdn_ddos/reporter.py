"""Apresentação (logs formatados) dos eventos do controlador.

Toda a formatação fica aqui para que a lógica de detecção e de rede não
contenha ``print``/f-strings de interface e possa ser testada em silêncio.
"""

import logging
from typing import List, Optional

from .config import DetectorConfig
from .flow_manager import BLOCK_PRIORITY
from .logging_setup import LOGGER_NAME
from .models import ControllerStats, Detection, DetectionStatus, PortRate

_WIDTH = 70


def _box(title: str, rows: Optional[List[str]] = None, fill: str = "-") -> str:
    """Desenha uma caixa de texto com título centralizado e linhas opcionais."""
    border = "+" + fill * _WIDTH + "+"
    lines = ["", border, f"| {title:^{_WIDTH - 2}} |", border]
    for row in rows or []:
        lines.append(f"| {row:<{_WIDTH - 2}} |")
    if rows:
        lines.append(border)
    return "\n".join(lines)


class ConsoleReporter:
    """Emite os eventos do controlador no log, em formato legível."""

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self._log = logger or logging.getLogger(LOGGER_NAME)

    # --- Ciclo de vida ---------------------------------------------------

    def banner(self, config: DetectorConfig) -> None:
        self._log.info(_box("SDN DDoS DETECTION CONTROLLER", [
            f"Monitoramento         : {config.monitor_interval:g}s",
            f"Amostras de baseline  : {config.baseline_samples}",
            f"Fator estatístico     : {config.threshold_factor:g}x",
            f"Fator mínimo          : {config.min_rate_factor:g}x",
            f"Piso absoluto         : {config.minimum_pps:g} PPS",
            f"Anomalias necessárias : {config.required_anomalies}",
            f"Tempo de bloqueio     : {config.block_time}s",
        ], fill="="))

    def switch_connected(self, dpid: int) -> None:
        self._log.info("[SWITCH] Switch %s conectado (OpenFlow 1.3); table-miss instalada", dpid)

    def switch_registered(self, dpid: int) -> None:
        self._log.info("[SWITCH] Datapath %s registrado para monitoramento", dpid)

    def switch_disconnected(self, dpid: int) -> None:
        self._log.warning("[SWITCH] Datapath %s desconectado", dpid)

    # --- Tráfego e detecção ------------------------------------------------

    def pair_result(
        self, src: str, dst: str, rate: PortRate,
        pps_detection: Detection, bps_detection: Detection, required: int
    ) -> None:
        """Registra tráfego e os resultados de PPS e bytes/s em uma única linha."""
        def status(detection: Detection) -> str:
            if detection.status is DetectionStatus.BASELINE:
                return "BASELINE %s/%s" % (detection.baseline_size, required)
            if detection.status is DetectionStatus.ANOMALY:
                return "ANOMALIA %s/%s" % (detection.consecutive_anomalies, required)
            return "NORMAL"

        self._log.info(
            "[TRÁFEGO/ANÁLISE] Origem: %-15s | Destino: %-15s | "
            "PPS: %6.2f (%s) | bytes/s: %10.2f (%s) | Pkts: %-4s",
            src, dst, rate.pps, status(pps_detection), rate.bps,
            status(bps_detection), rate.delta_packets,
        )

    def blocked_traffic(self, src: str, dst: str, rate: PortRate) -> None:
        self._log.warning(
            "[IP DE ORIGEM BLOQUEADO] Origem: %-15s | Destino: %-15s | "
            "PPS: %6.2f | bytes/s: %10.2f",
            src, dst, rate.pps, rate.bps,
        )

    def blocked_destination_traffic(self, src: str, dst: str, rate: PortRate) -> None:
        self._log.warning(
            "[IP DE DESTINO BLOQUEADO] Origem: %-15s | Destino: %-15s | "
            "PPS: %6.2f | bytes/s: %10.2f",
            src, dst, rate.pps, rate.bps,
        )

    def destination_flow_result(
        self, dst: str, new_flows: int, flows_per_second: float,
        sources: int, detection: Detection, required: int,
    ) -> None:
        """Registra a taxa agregada de novos fluxos recebidos por destino."""
        if detection.status is DetectionStatus.BASELINE:
            status = "BASELINE %s/%s" % (detection.baseline_size, required)
        elif detection.status is DetectionStatus.ANOMALY:
            status = "ANOMALIA %s/%s" % (detection.consecutive_anomalies, required)
        else:
            status = "NORMAL"
        self._log.info(
            "[FLUXOS NOVOS/ANÁLISE] Destino: %-15s | Novos fluxos: %-4s | "
            "Fluxos/s: %8.2f (%s) | Origens novas: %s",
            dst, new_flows, flows_per_second, status, sources,
        )

    def baseline(self, pair_id: str, detection: Detection, required: int) -> None:
        self._log.info(
            "[BASELINE] %-34s Amostra %s/%s | PPS: %.2f",
            pair_id, detection.baseline_size, required, detection.pps,
        )

    def normal(self, pair_id: str, detection: Detection) -> None:
        self._log.info(
            "[ANÁLISE] %-34s PPS: %6.2f | Status: NORMAL",
            pair_id, detection.pps,
        )

    def anomaly(
        self, pair_id: str, detection: Detection, required: int, metric: str = "PPS"
    ) -> None:
        self._log.warning(
            "[MITIGAÇÃO] Anomalia de %s em %s; sequência %s/%s.",
            metric, pair_id, detection.consecutive_anomalies, required,
        )

    def global_limits(self, metric: str, mean: float, std: float, limit: float) -> None:
        self._log.info(
            "[LIMITES GLOBAIS] %s | Média: %.2f %s | Desvio: %.2f %s | Limite: %.2f %s",
            metric, mean, metric, std, metric, limit, metric,
        )

    # --- Mitigação -------------------------------------------------------

    def block_activated(self, ip: str, duration: int) -> None:
        self._log.warning("[IP DE ORIGEM BLOQUEADO] %s por %ss", ip, duration)
        self._log.warning(_box("[BLOQUEIO ATIVADO]", [
            f"IP                 : {ip}",
            f"Duração            : {duration}s",
            f"Prioridade OpenFlow: {BLOCK_PRIORITY}",
        ], fill="="))

    def block_expired(self, ip: str) -> None:
        self._log.info("[BLOQUEIO EXPIRADO] %s - tráfego novamente permitido.", ip)

    # --- Resumo ----------------------------------------------------------

    def summary(self, stats: ControllerStats, switches: int, blocked_ips: int) -> None:
        self._log.info(_box("RESUMO DO CONTROLADOR", [
            f"Switches conectados : {switches}",
            f"Detecções           : {stats.detections}",
            f"Bloqueios           : {stats.blocks}",
            f"IPs bloqueados      : {blocked_ips}",
        ]))
