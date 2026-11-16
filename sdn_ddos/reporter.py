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
        self._pending: list[tuple[int, str, tuple]] = []

    def _queue(self, level: int, message: str, *args: object) -> None:
        """Armazena eventos e métricas até o próximo relatório periódico."""
        self._pending.append((level, message, args))

    def banner(self, config: DetectorConfig) -> None:
        self._log.info(_box("SDN DDoS DETECTION CONTROLLER", [
            f"Intervalo de avaliação    : {config.monitor_interval:g}s",
            f"Intervalo de relatório    : {config.report_interval:g}s",
            f"Amostras da baseline      : {config.baseline_samples}",
            f"Limiar PPS                : média + {config.threshold_factor:g}σ",
            f"Piso mínimo PPS           : {config.minimum_pps:g}",
            f"Limiar de entropia        : média + {config.entropy_threshold_factor:g}σ",
            f"Fator mínimo de entropia  : {config.minimum_entropy_factor:g}x a média",
            f"Mínimo de origens p/ DDoS : {config.minimum_distributed_sources}",
            f"Janelas para confirmação  : {config.required_anomalies}",
            f"Tempo de bloqueio         : {config.block_time}s",
        ], fill="="))

    def switch_connected(self, dpid: int) -> None:
        self._queue(logging.INFO, "[SWITCH] Switch %s conectado (OpenFlow 1.3); table-miss instalada", dpid)

    def switch_registered(self, dpid: int) -> None:
        self._queue(logging.INFO, "[SWITCH] Datapath %s registrado para monitoramento", dpid)

    def switch_disconnected(self, dpid: int) -> None:
        self._queue(logging.WARNING, "[SWITCH] Datapath %s desconectado", dpid)

    def pair_result(
        self, src: str, dst: str, rate: PortRate,
        bps_detection: Detection, required: int,
        icmp_stats: Optional[dict] = None,
    ) -> None:
        """Registra as taxas individuais; a decisão principal de PPS é por destino."""
        def status(detection: Detection) -> str:
            # O progresso da baseline é exibido uma única vez na linha do destino.
            if detection.status is DetectionStatus.BASELINE:
                return "contextual"
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
        self._queue(logging.INFO, 
            "[PAR] Origem: %-15s | Destino: %-15s | PPS: %7.2f | "
            "bytes/s: %10.2f (%s) | Pkts: %-5s%s",
            src, dst, rate.pps, rate.bps,
            status(bps_detection), rate.delta_packets, ping_info,
        )

    def destination_baseline(
        self, dst: str, sample: int, total: int,
        total_pps: float, total_bps: float, entropy_bits: float,
    ) -> None:
        """Mostra o progresso único da baseline conjunta do destino."""
        self._queue(
            logging.INFO,
            "[BASELINE] Destino: %-15s | Amostra %s/%s | "
            "PPS: %.2f | bytes/s: %.2f | H: %.3f bits",
            dst, sample, total, total_pps, total_bps, entropy_bits,
        )

    def destination_result(
        self, dst: str, total_pps: float, total_bps: float, source_count: int,
        pps_mean: float, pps_std: float, bytes_mean: float, bytes_std: float,
        pps_limit: float, bytes_limit: float,
        entropy: EntropyResult, required: int,
    ) -> None:
        """Exibe totais e estatísticas transversais das origens do destino."""
        if entropy.baseline_ready:
            entropy_mean = "N/A" if entropy.mean is None else "%.3f" % entropy.mean
            entropy_std = "N/A" if entropy.std is None else "%.3f" % entropy.std
            entropy_limit = "N/A" if entropy.limit is None else "%.3f" % entropy.limit
            entropy_status = (
                "DDoS %s/%s" % (entropy.consecutive_anomalies, required)
                if entropy.anomalous else "normal"
            )
            entropy_detail = "H média %s | H desvio %s | H limite %s | %s" % (
                entropy_mean, entropy_std, entropy_limit, entropy_status,
            )
        else:
            entropy_detail = "H baseline %s/%s" % (entropy.baseline_size, required)

        self._queue(
            logging.INFO,
            "[DESTINO] %-15s | PPS total: %8.2f (média %.2f | desvio %.2f | limite %.2f) | "
            "bytes/s total: %10.2f (média %.2f | desvio %.2f | limite %.2f) | "
            "origens: %2d | H: %.3f bits (norm. %.3f) | %s",
            dst, total_pps, pps_mean, pps_std, pps_limit,
            total_bps, bytes_mean, bytes_std, bytes_limit,
            source_count, entropy.entropy_bits, entropy.normalized_entropy, entropy_detail,
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
        self._queue(logging.WARNING, 
            "[CLASSIFICAÇÃO] Destino: %s | %s | origens: %d | "
            "entropia: %.3f bits | normalizada: %.3f",
            dst, pattern, entropy.source_count,
            entropy.entropy_bits, entropy.normalized_entropy,
        )

    def destination_candidates(
        self, dst: str, candidates: List[str], trigger: str = "PPS"
    ) -> None:
        self._queue(
            logging.WARNING,
            "[ATRIBUIÇÃO] Destino: %s | gatilho: %s | origens identificadas: %s",
            dst, trigger, ", ".join(candidates) if candidates else "nenhuma",
        )

    def destination_without_attribution(self, dst: str) -> None:
        self._queue(logging.WARNING, 
            "[MITIGAÇÃO] Destino %s excedeu o limite, mas nenhuma origem pôde ser atribuída; nenhum IP foi bloqueado.",
            dst,
        )

    def blocked_traffic(self, src: str, dst: str, rate: PortRate) -> None:
        self._queue(logging.WARNING, 
            "[TRÁFEGO DESCARTADO - ORIGEM BLOQUEADA] Origem: %-15s | "
            "Destino: %-15s | PPS: %7.2f | bytes/s: %10.2f",
            src, dst, rate.pps, rate.bps,
        )

    def blocked_destination_traffic(self, src: str, dst: str, rate: PortRate) -> None:
        self._queue(logging.WARNING, 
            "[TRÁFEGO DESCARTADO - DESTINO BLOQUEADO] Origem: %-15s | "
            "Destino: %-15s | PPS: %7.2f | bytes/s: %10.2f",
            src, dst, rate.pps, rate.bps,
        )

    def baseline(self, pair_id: str, detection: Detection, required: int) -> None:
        self._queue(logging.INFO, 
            "[BASELINE] %-34s Amostra %s/%s | PPS: %.2f",
            pair_id, detection.baseline_size, required, detection.pps,
        )

    def normal(self, pair_id: str, detection: Detection) -> None:
        self._queue(logging.INFO, "[ANÁLISE] %-34s PPS: %6.2f | Status: NORMAL", pair_id, detection.pps)

    def anomaly(
        self, pair_id: str, detection: Detection, required: int, metric: str = "PPS"
    ) -> None:
        self._queue(logging.WARNING, 
            "[MITIGAÇÃO] Anomalia de %s em %s; sequência %s/%s.",
            metric, pair_id, detection.consecutive_anomalies, required,
        )

    def global_limits(self, metric: str, mean: float, std: float, limit: float) -> None:
        self._queue(logging.INFO, 
            "[LIMITES GLOBAIS] %s | Média: %.2f %s | Desvio: %.2f %s | Limite: %.2f %s",
            metric, mean, metric, std, metric, limit, metric,
        )

    def block_activated(self, ip: str, duration: int) -> None:
        self._queue(logging.WARNING, 
            "[BLOQUEIO ATIVADO] IP %s bloqueado para ENVIAR e RECEBER por %ss "
            "(prioridade OpenFlow %s).",
            ip, duration, BLOCK_PRIORITY,
        )

    def block_expired(self, ip: str) -> None:
        self._queue(logging.INFO, "[BLOQUEIO EXPIRADO] %s - tráfego novamente permitido.", ip)

    def blocked_ips(self, ips: List[str]) -> None:
        """Exibe em todo ciclo os IPs bloqueados nas duas direções."""
        values = ", ".join(ips) if ips else "nenhum"
        self._queue(logging.INFO, "[IPS BLOQUEADOS] %s", values)

    def destination_expired(self, dst: str) -> None:
        self._queue(
            logging.INFO,
            "[DESTINO REMOVIDO] %s ficou 2 ciclos consecutivos com 0 PPS; "
            "baseline PPS, entropia e histórico foram descartados.",
            dst,
        )

    def baseline_started(self, dst: str, samples: int) -> None:
        self._queue(
            logging.INFO,
            "[BASELINE] Iniciada para o novo destino %s: coleta de %s ciclos",
            dst, samples,
        )

    def report(
        self, elapsed: float, stats: ControllerStats, switches: int,
        blocked_ips: List[str],
    ) -> None:
        """Despeja em lote os acontecimentos desde o relatório anterior."""
        self._log.info(_box(
            "RELATÓRIO DOS ÚLTIMOS %.1f SEGUNDOS" % elapsed,
            [
                f"Switches conectados         : {switches}",
                f"Detecções registradas       : {stats.detections}",
                f"Eventos distribuídos       : {stats.distributed_events}",
                f"Eventos concentrados       : {stats.concentrated_events}",
                f"Bloqueios realizados        : {stats.blocks}",
                f"IPs atualmente bloqueados   : {len(blocked_ips)}",
            ],
            fill="=",
        ))
        if not self._pending:
            self._log.info("[RELATÓRIO] Nenhum evento ou tráfego reportável no período.")
        else:
            for level, message, args in self._pending:
                self._log.log(level, message, *args)
        values = ", ".join(blocked_ips) if blocked_ips else "nenhum"
        self._log.info("[IPS BLOQUEADOS] %s", values)
        self._pending.clear()
