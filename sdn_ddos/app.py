"""Aplicação OS-Ken: orquestra learning switch, monitoramento e mitigação.

Esta classe é deliberadamente fina. Ela só traduz eventos OpenFlow em
chamadas aos colaboradores especializados (HostTable, PortRateCalculator,
AnomalyDetector, BlockList, FlowManager, ConsoleReporter), cada um com uma
única responsabilidade.

Importante: o OS-Ken só carrega a classe se ela estiver *definida* no módulo
informado a ``run_apps`` (``sdn_ddos.app``); por isso ela não é reexportada.
"""

import logging
from dataclasses import replace
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
from os_ken.lib.packet import arp, ethernet, ipv4, packet
from os_ken.ofproto import ofproto_v1_3

from .blocklist import BlockList
from .config import DetectorConfig
from .detector import AnomalyDetector
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
        self._detector = AnomalyDetector(self._config)
        self._bps_detector = AnomalyDetector(self._config)
        # Rajadas de novos fluxos são mitigadas na primeira janela anômala.
        self._flow_config = replace(self._config, required_anomalies=1)
        self._flow_detector = AnomalyDetector(self._flow_config)
        self._flow_attack_sources: Dict[str, set[str]] = {}
        self._blocklist = BlockList(self._config.block_time)
        self._flows = FlowManager()
        self._reporter = ConsoleReporter()
        self._stats = ControllerStats()
        self._datapaths: Dict[int, Any] = {}

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
            self._hosts.forget_switch(datapath.id)
            self._rates.forget_switch(datapath.id)
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
        """Pede estatísticas periodicamente, para sempre.

        Cada ciclo tem seu próprio try/except: uma exceção não tratada
        mataria esta green thread e o monitoramento pararia em silêncio.
        """
        cycle = 0
        while True:
            try:
                self._run_monitor_cycle(cycle)
            except Exception:  # noqa: BLE001 - o laço deve sobreviver a qualquer erro
                _logger.exception("Falha no ciclo de monitoramento %s", cycle)
            cycle += 1
            hub.sleep(self._config.monitor_interval)

    def _run_monitor_cycle(self, cycle: int) -> None:
        """Executa um ciclo: expira bloqueios, coleta estatísticas e resume."""
        for ip in self._blocklist.pop_expired():
            self._reporter.block_expired(ip)

        # Avalia cada par separadamente; anomalia confirmada bloqueia a origem.
        for (src, dst), rate in self._rates.collect_rates().items():
            src_blocked = self._blocklist.is_blocked(src)
            dst_blocked = self._blocklist.is_blocked(dst)

            if src_blocked:
                self._reporter.blocked_traffic(src, dst, rate)
            if dst_blocked:
                self._reporter.blocked_destination_traffic(src, dst, rate)
            if src_blocked or dst_blocked:
                continue

            datapath = self._datapath_for_ip(src)
            if datapath is not None:
                self._process_pair_rate(datapath, src, dst, rate)

        # Mede a criação agregada de fluxos para cada destino. Se o limite
        # for excedido em janelas consecutivas, bloqueia todas as origens
        # que contribuíram para o pico, não apenas uma origem isolada.
        for dst, flow_rate in self._rates.collect_new_flow_rates().items():
            detection = self._flow_detector.evaluate(
                dst, flow_rate.flows_per_second, minimum_rate=1.0,
                include_zero_rates=True,
            )
            self._reporter.destination_flow_result(
                dst, flow_rate.new_flows, flow_rate.flows_per_second,
                len(flow_rate.sources), detection, self._flow_config.required_anomalies,
            )
            if detection.status is DetectionStatus.ANOMALY:
                pending = self._flow_attack_sources.setdefault(dst, set())
                pending.update(flow_rate.sources)
                self._stats.detections += 1
                self._reporter.anomaly(
                    "destino {}".format(dst), detection,
                    self._flow_config.required_anomalies, "fluxos novos/s",
                )
                # Uma rajada agregada por destino pode ser distribuída:
                # bloqueia todas as origens que contribuíram nesta janela.
                if detection.should_block:
                    for src in sorted(pending):
                        if self._blocklist.is_blocked(src):
                            continue
                        source_datapath = self._datapath_for_ip(src)
                        if source_datapath is not None:
                            self._block(source_datapath, src)
                    self._flow_attack_sources.pop(dst, None)
            elif detection.status is DetectionStatus.NORMAL:
                self._flow_attack_sources.pop(dst, None)

        pps_limits = self._detector.global_limits()
        if pps_limits is not None:
            self._reporter.global_limits("PPS", *pps_limits)
        bps_limits = self._bps_detector.global_limits(minimum_rate=0.0)
        if bps_limits is not None:
            self._reporter.global_limits("bytes/s", *bps_limits)
        flow_limits = self._flow_detector.global_limits(minimum_rate=1.0)
        if flow_limits is not None:
            self._reporter.global_limits("fluxos novos/s", *flow_limits)

        every = self._config.summary_every_cycles
        if every and cycle > 0 and cycle % every == 0:
            self._reporter.summary(self._stats, len(self._datapaths), len(self._blocklist))

    def _record_packet(self, pkt: packet.Packet) -> None:
        """Registra somente pacotes iniciadores, excluindo respostas."""
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is not None:
            self._rates.record_packet(pkt, ip_pkt)

    def _datapath_for_ip(self, ip: str) -> Any | None:
        """Encontra o switch ao qual o host está conectado."""
        for dpid, datapath in self._datapaths.items():
            for port in self._hosts.ports_for_switch(dpid):
                if self._hosts.ip_for_port(dpid, port) == ip:
                    return datapath
        return None

    def _process_pair_rate(self, datapath: Any, src: str, dst: str, rate: Any) -> None:
        """Avalia a taxa do par, mas mantém a mitigação no IP de origem."""
        pair_id = "{}->{}".format(src, dst)
        pps_detection = self._detector.evaluate(pair_id, rate.pps)
        bps_detection = self._bps_detector.evaluate(pair_id, rate.bps, minimum_rate=0.0)
        self._reporter.pair_result(
            src, dst, rate, pps_detection, bps_detection, self._config.required_anomalies
        )
        self._handle_detection(datapath, src, pair_id, pps_detection, "PPS", bps_detection, "bytes/s")

    def _handle_detection(
        self, datapath: Any, src: str, pair_id: str,
        first: Detection, first_metric: str,
        second: Detection, second_metric: str,
    ) -> None:
        """Registra anomalias de PPS/BPS e bloqueia a origem se alguma persistir."""
        should_block = False
        for detection, metric in ((first, first_metric), (second, second_metric)):
            if detection.status is not DetectionStatus.ANOMALY:
                continue
            self._stats.detections += 1
            self._reporter.anomaly(
                pair_id, detection, self._config.required_anomalies, metric
            )
            should_block = should_block or detection.should_block
        if should_block:
            self._block(datapath, src)

    def _block(self, datapath: Any, ip: str) -> None:
        """Aplica o bloqueio no switch e o registra no controlador."""
        self._flows.install_drop(datapath, ip, self._config.block_time)
        self._blocklist.block(ip)
        self._stats.blocks += 1
        self._reporter.block_activated(ip, self._config.block_time)
