"""Aplicação OS-Ken: orquestra learning switch, monitoramento e mitigação.

Esta classe é deliberadamente fina. Ela só traduz eventos OpenFlow em
chamadas aos colaboradores especializados (HostTable, PortRateCalculator,
AnomalyDetector, BlockList, FlowManager, ConsoleReporter), cada um com uma
única responsabilidade.

Importante: o OS-Ken só carrega a classe se ela estiver *definida* no módulo
informado a ``run_apps`` (``sdn_ddos.app``); por isso ela não é reexportada.
"""

import logging
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

        for datapath in list(self._datapaths.values()):
            try:
                self._flows.request_port_stats(datapath)
            except Exception:  # noqa: BLE001 - um switch ruim não afeta os demais
                _logger.exception("Falha ao solicitar estatísticas do datapath %s", datapath.id)

        every = self._config.summary_every_cycles
        if every and cycle > 0 and cycle % every == 0:
            self._reporter.summary(self._stats, len(self._datapaths), len(self._blocklist))

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev: Any) -> None:
        """Processa os contadores de cada porta do switch."""
        datapath = ev.msg.datapath
        for stat in ev.msg.body:
            # Ignora portas reservadas (ex.: LOCAL), que não são hosts.
            if stat.port_no >= datapath.ofproto.OFPP_MAX:
                continue
            self._process_port(datapath, stat.port_no, stat.rx_packets, stat.rx_bytes)

    def _process_port(self, datapath: Any, port: int, rx_packets: int, rx_bytes: int) -> None:
        """Mede, exibe e analisa o tráfego recebido numa porta."""
        dpid = datapath.id

        # Usa rx (e não tx): mede o que o host *envia* para a rede.
        rate = self._rates.update((dpid, port), rx_packets, rx_bytes)
        if rate is None:
            return

        ip = self._hosts.ip_for_port(dpid, port)
        if ip is None:
            return

        blocked = self._blocklist.is_blocked(ip)
        self._reporter.traffic(ip, port, rate, blocked)
        if blocked:
            # Já está bloqueado: não reanalisa nem contamina a linha de base.
            return

        self._handle_detection(datapath, ip, self._detector.evaluate(ip, rate.pps))

    def _handle_detection(self, datapath: Any, ip: str, detection: Detection) -> None:
        """Reage ao veredito do detector (exibição, contadores e bloqueio)."""
        if detection.status is DetectionStatus.BASELINE:
            self._reporter.baseline(ip, detection, self._config.baseline_samples)
        elif detection.status is DetectionStatus.NORMAL:
            self._reporter.normal(ip, detection)
        else:
            self._stats.detections += 1
            self._reporter.anomaly(ip, detection, self._config.required_anomalies)
            if detection.should_block:
                self._block(datapath, ip)

    def _block(self, datapath: Any, ip: str) -> None:
        """Aplica o bloqueio no switch e o registra no controlador."""
        self._flows.install_drop(datapath, ip, self._config.block_time)
        self._blocklist.block(ip)
        self._stats.blocks += 1
        self._reporter.block_activated(ip, self._config.block_time)
