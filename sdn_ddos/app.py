"""Aplicação OS-Ken: orquestra learning switch, monitoramento e mitigação.

Esta classe é deliberadamente fina. Ela só traduz eventos OpenFlow em
chamadas aos colaboradores especializados (HostTable, PortRateCalculator,
AnomalyDetector, BlockList, FlowManager, ConsoleReporter), cada um com uma
única responsabilidade.

Importante: o OS-Ken só carrega a classe se ela estiver *definida* no módulo
informado a ``run_apps`` (``sdn_ddos.app``); por isso ela não é reexportada.
"""

import logging
import statistics
import time
from typing import Any, Dict

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from os_ken.lib import hub
from os_ken.lib.packet import arp, ethernet, icmp, ipv4, packet, tcp, udp
from os_ken.ofproto import ofproto_v1_3

from .blocklist import BlockList
from .config import DetectorConfig
from .detector import AnomalyDetector, DestinationConnectionDetector, DestinationPpsDetector
from .entropy import DestinationEntropyDetector
from .flow_manager import FlowManager
from .host_table import HostTable
from .logging_setup import LOGGER_NAME, configure_logging
from .models import ControllerStats, Detection, DetectionStatus
from .reporter import ConsoleReporter
from .traffic_meter import PortRateCalculator

_logger = logging.getLogger(LOGGER_NAME)

class SdnDdosController(app_manager.OSKenApp):
    """Learning switch com detecção estatística de DDoS e bloqueio temporário."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        configure_logging()

        self._config = DetectorConfig.from_env()
        self._hosts = HostTable()
        self._rates = PortRateCalculator()
        self._bps_detector = AnomalyDetector(self._config)
        # Cada servidor mantém sua própria baseline de PPS agregado recebido.
        self._destination_detectors: Dict[str, DestinationPpsDetector] = {}
        # Baseline agregada de bytes/s por destino; apenas informativa, não bloqueia.
        self._destination_bytes_detectors: Dict[str, DestinationPpsDetector] = {}
        # Apenas IPs que já foram observados como receptores entram no relatório agregado.
        self._known_destinations: set[str] = set()
        # Quantos ciclos consecutivos cada destino permaneceu com PPS = 0.
        self._destination_zero_cycles: Dict[str, int] = {}
        # Comparação estatística entre as conexões de cada destino.
        self._destination_connection_detectors: Dict[str, DestinationConnectionDetector] = {}
        # Entropia independente por destino; caracteriza a distribuição das origens.
        self._destination_entropy_detectors: Dict[str, DestinationEntropyDetector] = {}
        # Ciclo em que cada par origem-destino começou a aparecer.
        self._pair_first_seen_cycle: Dict[tuple[str, str], int] = {}
        self._pair_last_seen_cycle: Dict[tuple[str, str], int] = {}
        self._destination_anomaly_start: Dict[str, int] = {}
        self._destination_candidates: Dict[str, set[str]] = {}
        self._blocklist = BlockList(self._config.block_time)
        self._flows = FlowManager()
        self._reporter = ConsoleReporter()
        self._stats = ControllerStats()
        self._datapaths: Dict[int, Any] = {}
        # Telemetria dos pings manuais: chave do pedido = IPs, ID ICMP e sequência.
        self._icmp_pending: Dict[tuple, tuple[float, tuple]] = {}
        self._icmp_stats: Dict[tuple, Dict[str, float]] = {}

        self._reporter.banner(self._config)
        self._monitor_thread = hub.spawn(self._monitor_loop)

    def stop(self) -> None:
        """Encerra a thread de monitoramento antes de parar a aplicação."""
        hub.kill(self._monitor_thread)
        super().stop()

    # ==================================================================
    # Eventos de conexão dos switches
    # ==================================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev: Any) -> None:
        """Instala o table-miss assim que o switch conclui o handshake."""
        datapath = ev.msg.datapath
        self._flows.install_table_miss(datapath)
        self._reporter.switch_connected(datapath.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev: Any) -> None:
        """Mantém a lista de switches ativos e limpa o estado dos que caem."""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self._datapaths[datapath.id] = datapath
            self._reporter.switch_registered(datapath.id)
        elif ev.state == DEAD_DISPATCHER and datapath.id in self._datapaths:
            del self._datapaths[datapath.id]
            # Contadores e portas podem mudar quando o switch reconectar;
            # manter o estado antigo geraria taxas e IPs incorretos.
            disconnected_ips = self._hosts.ips_for_switch(datapath.id)
            for ip in disconnected_ips:
                self._destination_detectors.pop(ip, None)
                self._destination_bytes_detectors.pop(ip, None)
                self._known_destinations.discard(ip)
                self._destination_zero_cycles.pop(ip, None)
                self._destination_connection_detectors.pop(ip, None)
                self._destination_entropy_detectors.pop(ip, None)
                self._destination_anomaly_start.pop(ip, None)
                self._destination_candidates.pop(ip, None)
            for pair in list(self._pair_first_seen_cycle):
                if pair[0] in disconnected_ips or pair[1] in disconnected_ips:
                    self._pair_first_seen_cycle.pop(pair, None)
                    self._pair_last_seen_cycle.pop(pair, None)
            self._hosts.forget_switch(datapath.id)
            self._rates.forget_ips(disconnected_ips)
            self._reporter.switch_disconnected(datapath.id)

    # ==================================================================
    # Learning switch
    # ==================================================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev: Any) -> None:
        """Aprende MAC/IP de origem e encaminha o pacote.

        Exceções aqui são registradas pelo próprio OS-Ken sem derrubar o
        controlador, por isso não há try/except no handler.
        """
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        dpid = datapath.id
        self._hosts.learn_mac(dpid, eth.src, in_port)
        self._learn_ip(dpid, pkt, in_port)
        self._prepare_destination_baseline(pkt)

        # Conta o pacote inicial; cópias de regras de encaminhamento não devem
        # ser reenviadas pelo controlador.
        self._record_packet(pkt)
        if msg.reason == datapath.ofproto.OFPR_ACTION:
            return

        out_port = self._hosts.port_for_mac(dpid, eth.dst)
        if out_port is None:
            # Destino desconhecido: inunda e não instala regra (evita fixar
            # um caminho errado antes de aprender o host).
            out_port = datapath.ofproto.OFPP_FLOOD
        else:
            self._flows.install_forwarding(datapath, in_port, eth.dst, out_port)

        self._flows.forward_packet(datapath, msg, in_port, out_port)

    def _prepare_destination_baseline(self, pkt: packet.Packet) -> None:
        """Cria a baseline individual ao surgir uma solicitação para novo destino."""
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return

        # Considera solicitações que iniciam comunicação: TCP SYN, datagrama
        # UDP ou ICMP Echo Request. Respostas não disparam a criação.
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        is_request = (
            (tcp_pkt is not None and tcp_pkt.syn and not tcp_pkt.ack)
            or udp_pkt is not None
            or (icmp_pkt is not None and icmp_pkt.type == 8)
        )
        if not is_request:
            return

        dst = ip_pkt.dst
        if dst in self._destination_detectors:
            return

        # Não preenche a baseline antecipadamente. O detector será alimentado
        # uma vez por ciclo de monitoramento, inclusive com PPS = 0, até obter
        # as cinco amostras configuradas.
        self._destination_detectors[dst] = DestinationPpsDetector(self._config)
        self._destination_zero_cycles[dst] = 0
        self._known_destinations.add(dst)
        self._reporter.baseline_started(dst, self._config.baseline_samples)

    def _learn_ip(self, dpid: int, pkt: packet.Packet, in_port: int) -> None:
        """Aprende o IP do remetente a partir de IPv4 ou ARP.

        ARP também é usado porque, depois que o switch aprende os MACs, os
        pacotes IPv4 deixam de chegar ao controlador e alguns hosts nunca
        teriam o IP associado à porta (e ficariam sem monitoramento).
        """
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is not None:
            self._hosts.learn_ip(dpid, ip_pkt.src, in_port)
            return
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt is not None:
            self._hosts.learn_ip(dpid, arp_pkt.src_ip, in_port)

    # ==================================================================
    # Monitoramento
    # ==================================================================

    def _monitor_loop(self) -> None:
        """Avalia na frequência configurada e publica relatórios em lote."""
        cycle = 0
        last_report = time.monotonic()
        next_report = last_report + self._config.report_interval
        previous_stats = ControllerStats()

        while True:
            try:
                self._run_monitor_cycle(cycle)
            except Exception:  # noqa: BLE001 - o laço deve sobreviver a qualquer erro
                _logger.exception("Falha no ciclo de monitoramento %s", cycle)

            cycle += 1
            now = time.monotonic()
            if now >= next_report:
                current = self._stats
                interval_stats = ControllerStats(
                    detections=current.detections - previous_stats.detections,
                    blocks=current.blocks - previous_stats.blocks,
                    distributed_events=(
                        current.distributed_events - previous_stats.distributed_events
                    ),
                    concentrated_events=(
                        current.concentrated_events - previous_stats.concentrated_events
                    ),
                )
                self._reporter.report(
                    now - last_report,
                    interval_stats,
                    len(self._datapaths),
                    self._blocklist.active_ips(),
                )
                previous_stats = ControllerStats(
                    detections=current.detections,
                    blocks=current.blocks,
                    distributed_events=current.distributed_events,
                    concentrated_events=current.concentrated_events,
                )
                last_report = now
                next_report = now + self._config.report_interval

            # Acorda no próximo instante de avaliação ou de relatório.
            sleep_for = min(
                self._config.monitor_interval,
                max(0.01, next_report - time.monotonic()),
            )
            hub.    def _run_monitor_cycle(self, cycle: int) -> None:
        """Avalia DoS por origem e DDoS exclusivamente pela entropia."""
        self._expire_icmp_requests()
        icmp_interval = self._report_icmp_interval()
        for ip in self._blocklist.pop_expired():
            self._reporter.block_expired(ip)

        rates = self._rates.collect_rates()
        active_rates: Dict[tuple[str, str], Any] = {}
        for (src, dst), rate in rates.items():
            src_blocked = self._blocklist.is_blocked(src)
            dst_blocked = self._blocklist.is_blocked(dst)
            if src_blocked:
                self._reporter.blocked_traffic(src, dst, rate)
            if dst_blocked:
                self._reporter.blocked_destination_traffic(src, dst, rate)
            if src_blocked or dst_blocked:
                continue
            active_rates[(src, dst)] = rate
            pair = (src, dst)
            last_seen = self._pair_last_seen_cycle.get(pair)
            if last_seen is None or cycle - last_seen > 2:
                self._pair_first_seen_cycle[pair] = cycle
            self._pair_last_seen_cycle[pair] = cycle
            datapath = self._datapath_for_ip(src)
            if datapath is not None:
                self._process_pair_rate(datapath, src, dst, rate, icmp_interval.get((src, dst)))

        self._known_destinations.update(dst for (_src, dst) in active_rates)
        destinations = self._known_destinations | set(self._destination_detectors)
        for dst in sorted(destinations):
            if self._blocklist.is_blocked(dst):
                continue
            destination_rates = {
                src: rate for (src, target), rate in active_rates.items() if target == dst
            }
            total_pps = sum(rate.pps for rate in destination_rates.values())
            total_bps = sum(rate.bps for rate in destination_rates.values())

            if total_pps <= 0:
                self._destination_zero_cycles[dst] = self._destination_zero_cycles.get(dst, 0) + 1
                if self._destination_zero_cycles[dst] >= 2:
                    self._destination_detectors.pop(dst, None)
                    self._destination_bytes_detectors.pop(dst, None)
                    self._destination_connection_detectors.pop(dst, None)
                    self._destination_entropy_detectors.pop(dst, None)
                    self._known_destinations.discard(dst)
                    self._destination_zero_cycles.pop(dst, None)
                    self._destination_anomaly_start.pop(dst, None)
                    self._destination_candidates.pop(dst, None)
                    for pair in list(self._pair_first_seen_cycle):
                        if pair[1] == dst:
                            self._pair_first_seen_cycle.pop(pair, None)
                            self._pair_last_seen_cycle.pop(pair, None)
                    self._reporter.destination_expired(dst)
                    continue
            else:
                self._destination_zero_cycles[dst] = 0

            # DoS: PPS e bytes/s são comparados transversalmente entre origens.
            connection_detector = self._destination_connection_detectors.setdefault(
                dst, DestinationConnectionDetector(self._config)
            )
            connection_results = connection_detector.evaluate(destination_rates, cycle)
            dos_sources = set()
            for src, metrics in connection_results.items():
                pps_result, bytes_result = metrics["PPS"], metrics["BYTES/S"]
                if pps_result.status is DetectionStatus.ANOMALY or bytes_result.status is DetectionStatus.ANOMALY:
                    self._reporter.connection_result(
                        src, dst, destination_rates[src], pps_result, bytes_result,
                        self._config.required_anomalies,
                    )
                if pps_result.should_block or bytes_result.should_block:
                    dos_sources.add(src)

            # DDoS: somente a entropia classifica/confirma um ataque distribuído.
            source_packet_counts = {
                src: rate.delta_packets for src, rate in destination_rates.items()
                if rate.delta_packets > 0
            }
            entropy_detector = self._destination_entropy_detectors.setdefault(
                dst, DestinationEntropyDetector(self._config)
            )
            entropy_result = entropy_detector.evaluate(source_packet_counts)

            # Mantém apenas origens recentes como candidatas à atribuição do DDoS.
            lookback = max(self._config.baseline_samples, self._config.required_anomalies + 1)
            candidates = self._destination_candidates.setdefault(dst, set())
            recent_sources = {
                src for src, rate in destination_rates.items()
                if rate.pps > 0 and
                cycle - self._pair_first_seen_cycle.get((src, dst), cycle) <= lookback
            }
            candidates.intersection_update(recent_sources)
            candidates.update(recent_sources)

            if dos_sources:
                self._stats.detections += len(dos_sources)
                self._stats.concentrated_events += 1
                self._reporter.destination_candidates(dst, sorted(dos_sources), "DoS: PPS e/ou bytes/s por origem")
                for src in sorted(dos_sources):
                    if not self._blocklist.is_blocked(src):
                        datapath = self._datapath_for_ip(src)
                        if datapath is not None:
                            self._block(datapath, src)

            if entropy_result.anomalous:
                self._stats.detections += 1
                self._stats.distributed_events += 1
                self._reporter.destination_classification(dst, entropy_result, True)

            if not entropy_result.baseline_ready:
                self._reporter.destination_baseline(
                    dst, entropy_result.baseline_size, self._config.baseline_samples,
                    total_pps, total_bps, entropy_result.entropy_bits,
                )
            else:
                pps_values = [float(rate.pps) for rate in destination_rates.values()]
                bytes_values = [float(rate.bps) for rate in destination_rates.values()]
                pps_mean = statistics.fmean(pps_values) if pps_values else 0.0
                bytes_mean = statistics.fmean(bytes_values) if bytes_values else 0.0
                pps_std = statistics.stdev(pps_values) if len(pps_values) > 1 else 0.0
                bytes_std = statistics.stdev(bytes_values) if len(bytes_values) > 1 else 0.0
                self._reporter.destination_result(
                    dst, total_pps, total_bps, len(destination_rates),
                    pps_mean, pps_std, bytes_mean, bytes_std,
                    entropy_result, self._config.required_anomalies,
                )

            if entropy_result.should_block:
                ddos_sources = sorted(candidates)
                if ddos_sources:
                    self._reporter.destination_candidates(
                        dst, ddos_sources, "DDoS: entropia elevada e origens recentes"
                    )
                    for src in ddos_sources:
                        if not self._blocklist.is_blocked(src):
                            datapath = self._datapath_for_ip(src)
                            if datapath is not None:
                                self._block(datapath, src)
                else:
                    self._reporter.destination_without_attribution(dst)
                self._destination_candidates.pop(dst, None)

datapath, src)



    def _record_packet(self, pkt: packet.Packet) -> None:
        """Registra taxas e mede os pings manuais observados pelo switch."""
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return
        self._rates.record_packet(pkt, ip_pkt)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        data = getattr(icmp_pkt, "data", None) if icmp_pkt is not None else None
        ident = getattr(data, "id", None)
        seq = getattr(data, "seq", None)
        if ident is None or seq is None:
            return

        now = time.monotonic()
        if icmp_pkt.type == 8:  # Echo Request
            session = (ip_pkt.src, ip_pkt.dst, ident)
            request = (ip_pkt.src, ip_pkt.dst, ident, seq)
            stats = self._icmp_stats.setdefault(
                session, {"sent": 0, "received": 0, "lost": 0,
                          "rtt_sum_ms": 0.0, "rtt_count": 0, "last_rtt_ms": -1.0,
                          "interval_sent": 0, "interval_received": 0, "interval_lost": 0,
                          "interval_rtt_sum_ms": 0.0, "interval_rtt_count": 0,
                          "interval_last_rtt_ms": -1.0}
            )
            # A solicitação só entra na contagem quando seu resultado é
            # conhecido (resposta recebida ou timeout), mantendo enviados = recebidos + perdidos.
            self._icmp_pending[request] = (now, session)
        elif icmp_pkt.type == 0:  # Echo Reply
            request = (ip_pkt.dst, ip_pkt.src, ident, seq)
            pending = self._icmp_pending.pop(request, None)
            # Ignora respostas duplicadas ou solicitações que o switch não observou.
            if pending is None:
                return
            session = pending[1]
            stats = self._icmp_stats[session]
            stats["sent"] += 1
            stats["interval_sent"] += 1
            stats["received"] += 1
            stats["interval_received"] += 1
            rtt_ms = (now - pending[0]) * 1000.0
            stats["rtt_sum_ms"] += rtt_ms
            stats["rtt_count"] += 1
            stats["last_rtt_ms"] = rtt_ms
            stats["interval_rtt_sum_ms"] += rtt_ms
            stats["interval_rtt_count"] += 1
            stats["interval_last_rtt_ms"] = rtt_ms

    def _expire_icmp_requests(self) -> None:
        """Conta como perdida a solicitação sem resposta após 2 segundos."""
        now = time.monotonic()
        expired = [
            request for request, (sent_at, _session) in self._icmp_pending.items()
            if now - sent_at >= 2.0
        ]
        for request in expired:
            _sent_at, session = self._icmp_pending.pop(request)
            stats = self._icmp_stats[session]
            # Conta enviados no momento da conclusão, junto ao resultado.
            stats["sent"] += 1
            stats["interval_sent"] += 1
            stats["lost"] += 1
            stats["interval_lost"] += 1

    def _report_icmp_interval(self) -> Dict[tuple, Dict[str, float]]:
        """Reúne e zera as métricas ICMP por par para anexá-las à linha de tráfego."""
        interval: Dict[tuple, Dict[str, float]] = {}
        for session, stats in self._icmp_stats.items():
            src, dst, _ident = session
            sent = int(stats["interval_sent"])
            received = int(stats["interval_received"])
            lost = int(stats["interval_lost"])
            if sent or received or lost:
                pair = interval.setdefault((src, dst), {
                    "sent": 0, "received": 0, "lost": 0,
                    "rtt_sum_ms": 0.0, "rtt_count": 0, "last_rtt_ms": -1.0,
                })
                pair["sent"] += sent
                pair["received"] += received
                pair["lost"] += lost
                pair["rtt_sum_ms"] += stats["interval_rtt_sum_ms"]
                pair["rtt_count"] += stats["interval_rtt_count"]
                if stats["interval_last_rtt_ms"] >= 0:
                    pair["last_rtt_ms"] = stats["interval_last_rtt_ms"]

            stats["interval_sent"] = 0
            stats["interval_received"] = 0
            stats["interval_lost"] = 0
            stats["interval_rtt_sum_ms"] = 0.0
            stats["interval_rtt_count"] = 0
            stats["interval_last_rtt_ms"] = -1.0
        return interval

    def _datapath_for_ip(self, ip: str) -> Any | None:
        """Encontra o switch ao qual o host está conectado."""
        for dpid, datapath in self._datapaths.items():
            for port in self._hosts.ports_for_switch(dpid):
                if self._hosts.ip_for_port(dpid, port) == ip:
                    return datapath
        return None

    def _process_pair_rate(
        self, datapath: Any, src: str, dst: str, rate: Any,
        icmp_stats: Dict[str, float] | None = None,
    ) -> None:
        """Exibe PPS por par e mantém a análise auxiliar de bytes/s."""
        pair_id = "{}->{}".format(src, dst)
        bps_detection = self._bps_detector.evaluate(
            pair_id, rate.bps, minimum_rate=0.0
        )
        self._reporter.pair_result(
            src, dst, rate, bps_detection,
            self._config.required_anomalies, icmp_stats,
        )
        if bps_detection.status is DetectionStatus.ANOMALY:
            self._stats.detections += 1
            self._reporter.anomaly(
                pair_id, bps_detection, self._config.required_anomalies, "bytes/s"
            )

    def _block(self, datapath: Any, ip: str) -> None:
        """Aplica o bloqueio no switch e o registra no controlador."""
        self._flows.install_drop(datapath, ip, self._config.block_time)
        self._blocklist.block(ip)
        self._stats.blocks += 1
        self._reporter.block_activated(ip, self._config.block_time)
