"""Apresentação (logs formatados) dos eventos do controlador."""

import logging
from typing import List, Optional

from .config import DetectorConfig
from .entropy import EntropyResult
from .flow_manager import BLOCK_PRIORITY
from .logging_setup import LOGGER_NAME
from .models import ControllerStats, Detection, DetectionStatus, PortRate

_WIDTH = 70


def _box(title: str, rows: Optional[List[str]] = None, fill: str = "-") -> str:
    border = "+" + fill * _WIDTH + "+"
    lines = ["", border, f"| {title:^{_WIDTH - 2}} |", border]
    for row in rows or []:
        lines.append(f"| {row:<{_WIDTH - 2}} |")
    if rows:
        lines.append(border)
    return "\n".join(lines)


class ConsoleReporter:
    """Emite eventos do controlador em formato legível."""

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self._log = logger or logging.getLogger(LOGGER_NAME)

    def banner(self, config: DetectorConfig) -> None:
        self._log.info(_box("SDN DDoS DETECTION CONTROLLER", [
            f"Monitoramento             : {config.monitor_interval:g}s",
            f"Amostras da baseline      : {config.baseline_samples}",
            f"Limiar PPS                : média + {config.threshold_factor:g}σ",
            f"Piso mínimo PPS           : {config.minimum_pps:g}",
            f"Limiar de entropia        : média + {config.entropy_threshold_factor:g}σ",
            f"Incremento mínimo H       : {config.minimum_entropy_delta:g} bits",
            f"Mínimo de origens p/ DDoS : {config.minimum_distributed_sources}",
            f"Janelas para confirmação  : {config.required_anomalies}",
            f"Tempo de bloqueio         : {config.block_time}s",
        ], fill="="))

    def switch_connected(self, dpid: int) -> None:
        self._log.info("[SWITCH] Switch %s conectado (OpenFlow 1.3); table-miss instalada", dpid)

    def switch_registered(self, dpid: int) -> None:
        self._log.info("[SWITCH] Datapath %s registrado para monitoramento", dpid)

    def switch_disconnected(self, dpid: int) -> None:
        self._log.warning("[SWITCH] Datapath %s desconectado", dpid)

    def pair_result(
        self, src: str, dst: str, rate: PortRate,
        bps_detection: Detection, required: int,
        icmp_stats: Optional[dict] = None,
    ) -> None:
        """Registra as taxas individuais; a decisão principal de PPS é por destino."""
        def status(detection: Detection) -> str:
            if detection.status is DetectionStatus.BASELINE:
                return "BASELINE %s/%s" % (detection.baseline_size, required)
            if detection.status is DetectionStatus.ANOMALY:
                return "ANOMALIA %s/%s" % (detection.consecutive_anomalies, required)
            return "NORMAL"

        ping_info = ""
        if icmp_stats is not None:
            if icmp_stats["rtt_count"]:
                rtt_info = "%.3f ms (médio %.3f ms)" % (
                    icmp_stats["last_rtt_ms"],
                    icmp_stats["rtt_sum_ms"] / icmp_stats["rtt_count"],
                )
            else:
                rtt_info = "sem respostas"
            ping_info = (
                " | ICMP enviados: %d | recebidos: %d | perdidos: %d | RTT: %s"
                % (
                    icmp_stats["sent"], icmp_stats["received"],
                    icmp_stats["lost"], rtt_info,
                )
            )
        self._log.info(
            "[PAR] Origem: %-15s | Destino: %-15s | PPS: %7.2f | "
            "bytes/s: %10.2f (%s) | Pkts: %-5s%s",
            src, dst, rate.pps, rate.bps,
            status(bps_detection), rate.delta_packets, ping_info,
        )

    def destination_result(
        self,
        dst: str,
        total_pps: float,
        total_bps: float,
        detection: Detection,
        entropy: EntropyResult,
        required: int,
    ) -> None:
        """Exibe em uma linha o volume agregado e a distribuição das origens."""
        if detection.status is DetectionStatus.BASELINE:
            pps_status = "BASELINE %s/%s" % (detection.baseline_size, required)
        elif detection.status is DetectionStatus.ANOMALY:
            pps_status = "ANOMALIA %s/%s" % (detection.consecutive_anomalies, required)
        else:
            pps_status = "NORMAL"

        if not entropy.baseline_ready:
            entropy_status = "BASELINE %s/%s" % (entropy.baseline_size, required)
            entropy_limit = "formando"
        else:
            entropy_status = "ALTA" if entropy.anomalous else "normal"
            entropy_limit = "%.3f bits" % entropy.limit

        self._log.info(
            "[DESTINO] %-15s | PPS: %8.2f | bytes/s: %10.2f | "
            "origens: %2d | H: %.3f bits (norm %.3f) | Hlim: %s | PPS: %s | H: %s",
            dst, total_pps, total_bps, entropy.source_count,
            entropy.entropy_bits, entropy.normalized_entropy,
            entropy_limit, pps_status, entropy_status,
        )

    def destination_classification(
        self, dst: str, entropy: EntropyResult, distributed: bool
    ) -> None:
        """Diferencia uma anomalia de volume concentrada de um padrão distribuído."""
        pattern = (
            "PADRÃO DISTRIBUÍDO (possível DDoS)"
            if distributed
            else "PADRÃO CONCENTRADO/INCONCLUSIVO (possível DoS)"
        )
        self._log.warning(
            "[CLASSIFICAÇÃO] Destino: %s | %s | origens: %d | "
            "entropia: %.3f bits | normalizada: %.3f",
            dst, pattern, entropy.source_count,
            entropy.entropy_bits, entropy.normalized_entropy,
        )

    def destination_candidates(self, dst: str, candidates: List[str]) -> None:
        self._log.warning(
            "[ATRIBUIÇÃO] Destino: %s | novas origens candidatas: %s",
            dst, ", ".join(candidates) if candidates else "nenhuma",
        )

    def destination_without_attribution(self, dst: str) -> None:
        self._log.warning(
            "[MITIGAÇÃO] Destino %s excedeu o limite, mas nenhuma origem nova "
            "foi identificada; nenhum IP foi bloqueado.",
            dst,
        )

    def blocked_traffic(self, src: str, dst: str, rate: PortRate) -> None:
        self._log.warning(
            "[TRÁFEGO DESCARTADO - ORIGEM BLOQUEADA] Origem: %-15s | "
            "Destino: %-15s | PPS: %7.2f | bytes/s: %10.2f",
            src, dst, rate.pps, rate.bps,
        )

    def blocked_destination_traffic(self, src: str, dst: str, rate: PortRate) -> None:
        self._log.warning(
            "[TRÁFEGO DESCARTADO - DESTINO BLOQUEADO] Origem: %-15s | "
            "Destino: %-15s | PPS: %7.2f | bytes/s: %10.2f",
            src, dst, rate.pps, rate.bps,
        )

    def baseline(self, pair_id: str, detection: Detection, required: int) -> None:
        self._log.info(
            "[BASELINE] %-34s Amostra %s/%s | PPS: %.2f",
            pair_id, detection.baseline_size, required, detection.pps,
        )

    def normal(self, pair_id: str, detection: Detection) -> None:
        self._log.info("[ANÁLISE] %-34s PPS: %6.2f | Status: NORMAL", pair_id, detection.pps)

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

    def block_activated(self, ip: str, duration: int) -> None:
        self._log.warning(
            "[BLOQUEIO ATIVADO] IP %s bloqueado para ENVIAR e RECEBER por %ss "
            "(prioridade OpenFlow %s).",
            ip, duration, BLOCK_PRIORITY,
        )

    def block_expired(self, ip: str) -> None:
        self._log.info("[BLOQUEIO EXPIRADO] %s - tráfego novamente permitido.", ip)

    def summary(self, stats: ControllerStats, switches: int, blocked_ips: int) -> None:
        self._log.info(_box("RESUMO DO CONTROLADOR", [
            f"Switches conectados        : {switches}",
            f"Detecções                   : {stats.detections}",
            f"Eventos com padrão DDoS     : {stats.distributed_events}",
            f"Eventos concentrados       : {stats.concentrated_events}",
            f"Bloqueios                   : {stats.blocks}",
            f"IPs bloqueados              : {blocked_ips}",
        ]))
