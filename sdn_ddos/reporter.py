"""Apresentação (logs formatados) dos eventos do controlador.

Toda a formatação fica aqui para que a lógica de detecção e de rede não
contenha ``print``/f-strings de interface e possa ser testada em silêncio.
"""

import logging
from typing import List, Optional

from .config import DetectorConfig
from .flow_manager import BLOCK_PRIORITY
from .logging_setup import LOGGER_NAME
from .models import ControllerStats, Detection, PortRate

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

    def traffic(self, ip: str, port: int, rate: PortRate, blocked: bool) -> None:
        self._log.info(
            "[TRÁFEGO] IP: %-15s | Porta: %-2s | PPS: %6.2f | Bytes/s: %9.2f | "
            "Pkts: %-4s | %s",
            ip, port, rate.pps, rate.bps, rate.delta_packets,
            "BLOQUEADO" if blocked else "NORMAL",
        )

    def baseline(self, ip: str, detection: Detection, required: int) -> None:
        self._log.info(
            "[BASELINE] %-15s Amostra %s/%s | PPS: %.2f",
            ip, detection.baseline_size, required, detection.pps,
        )

    def normal(self, ip: str, detection: Detection) -> None:
        self._log.info(
            "[ANÁLISE] %-15s PPS: %6.2f | Limite: %6.2f | Status: NORMAL",
            ip, detection.pps, detection.limit,
        )

    def anomaly(self, ip: str, detection: Detection, required: int) -> None:
        self._log.warning(
            "\n[!] ANOMALIA DETECTADA\n"
            "    IP        : %s\n"
            "    PPS       : %.2f\n"
            "    Média     : %.2f\n"
            "    Desvio    : %.2f\n"
            "    Limite    : %.2f\n"
            "    Sequência : %s/%s",
            ip, detection.pps, detection.mean, detection.std, detection.limit,
            detection.consecutive_anomalies, required,
        )

    # --- Mitigação -------------------------------------------------------

    def block_activated(self, ip: str, duration: int) -> None:
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
