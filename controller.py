from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls
)
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ipv4
from os_ken.lib import hub

from collections import defaultdict, deque
import time
import statistics


class Controller(app_manager.OSKenApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # ============================================================
    # CONFIGURAÇÕES
    # ============================================================

    MONITOR_INTERVAL = 5

    # Quantidade de amostras usadas para formar a linha de base
    BASELINE_SAMPLES = 5

    # Limite estatístico: média + fator * desvio padrão
    THRESHOLD_FACTOR = 3

    # Também exige que o tráfego seja pelo menos 50% maior
    # que a média normal
    MIN_RATE_FACTOR = 1.5

    # Número de janelas consecutivas acima do limite
    # antes de considerar ataque
    REQUIRED_ANOMALIES = 2

    # Tempo de bloqueio
    BLOCK_TIME = 30

    # ============================================================
    # INICIALIZAÇÃO
    # ============================================================

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Learning switch
        self.mac_to_port = {}

        # IP -> porta do switch
        self.ip_to_port = {}

        # Estatísticas anteriores
        self.previous_stats = {}

        # Histórico de PPS por IP
        self.pps_history = defaultdict(
            lambda: deque(maxlen=20)
        )

        # Quantidade de anomalias consecutivas
        self.anomaly_count = defaultdict(int)

        # IP -> instante em que o bloqueio termina
        self.blocked_until = {}

        # Datapaths conectados
        self.datapaths = {}

        # Estatísticas gerais
        self.total_detections = 0
        self.total_blocks = 0

        # Inicia monitoramento
        hub.spawn(self.monitor)

        self.print_header()

    # ============================================================
    # INTERFACE
    # ============================================================

    def print_header(self):

        print()
        print("=" * 72)
        print("              SDN DDoS DETECTION CONTROLLER")
        print("=" * 72)
        print(f"  Monitoramento       : {self.MONITOR_INTERVAL}s")
        print(f"  Amostras de baseline: {self.BASELINE_SAMPLES}")
        print(f"  Fator estatístico   : {self.THRESHOLD_FACTOR}x")
        print(f"  Fator mínimo        : {self.MIN_RATE_FACTOR}x")
        print(f"  Anomalias necessárias: {self.REQUIRED_ANOMALIES}")
        print(f"  Tempo de bloqueio   : {self.BLOCK_TIME}s")
        print("=" * 72)
        print()

    def print_section(self, title):

        print()
        print("+" + "-" * 70 + "+")
        print(f"| {title:<68} |")
        print("+" + "-" * 70 + "+")

    # ============================================================
    # CONEXÃO DO SWITCH
    # ============================================================

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER
    )
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        print()
        print("[SWITCH] Switch conectado")
        print(f"         ID: {datapath.id}")
        print(f"         OpenFlow: 1.3")

        # Table-miss
        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(
            datapath,
            priority=0,
            match=match,
            actions=actions
        )

        print("[SWITCH] Table-miss instalada")

    # ============================================================
    # REGISTRO DOS SWITCHES
    # ============================================================

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, CONFIG_DISPATCHER]
    )
    def state_change_handler(self, ev):

        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:

            self.datapaths[datapath.id] = datapath

            print(
                f"[SWITCH] Datapath {datapath.id} "
                f"registrado para monitoramento"
            )

        elif ev.state == "DEAD_DISPATCHER":

            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

            print(
                f"[SWITCH] Datapath {datapath.id} desconectado"
            )

    # ============================================================
    # INSTALAÇÃO DE FLUXOS
    # ============================================================

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        hard_timeout=0
    ):

        parser = datapath.ofproto_parser

        instructions = [
            parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            hard_timeout=hard_timeout
        )

        datapath.send_msg(mod)

    # ============================================================
    # PACKET-IN
    # ============================================================

    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    def packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        src = eth.src
        dst = eth.dst

        dpid = datapath.id

        # Cria tabela MAC para este switch
        self.mac_to_port.setdefault(dpid, {})

        # Aprende MAC
        self.mac_to_port[dpid][src] = in_port

        # Aprende IP
        ip = pkt.get_protocol(ipv4.ipv4)

        if ip is not None:
            self.ip_to_port[ip.src] = in_port

        # Verifica destino
        if dst in self.mac_to_port[dpid]:

            out_port = self.mac_to_port[dpid][dst]

        else:

            out_port = ofproto.OFPP_FLOOD

        actions = [
            parser.OFPActionOutput(out_port)
        ]

        # Instala fluxo somente se destino conhecido
        if out_port != ofproto.OFPP_FLOOD:

            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst
            )

            self.add_flow(
                datapath,
                priority=10,
                match=match,
                actions=actions
            )

        # Envia pacote original
        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)

    # ============================================================
    # SOLICITA ESTATÍSTICAS
    # ============================================================

    def request_port_stats(self, datapath):

        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(
            datapath,
            0,
            datapath.ofproto.OFPP_ANY
        )

        datapath.send_msg(req)

    # ============================================================
    # RECEBE ESTATÍSTICAS
    # ============================================================

    @set_ev_cls(
        ofp_event.EventOFPPortStatsReply,
        MAIN_DISPATCHER
    )
    def port_stats_reply_handler(self, ev):

        datapath = ev.msg.datapath
        dpid = datapath.id

        now = time.time()

        for stat in ev.msg.body:

            port = stat.port_no

            if port > 100:
                continue

            key = (dpid, port)

            packets = stat.rx_packets
            bytes_received = stat.rx_bytes

            # Primeira medição
            if key not in self.previous_stats:

                self.previous_stats[key] = (
                    packets,
                    bytes_received,
                    now
                )

                continue

            old_packets, old_bytes, old_time = \
                self.previous_stats[key]

            elapsed = now - old_time

            if elapsed <= 0:
                continue

            delta_packets = packets - old_packets
            delta_bytes = bytes_received - old_bytes

            pps = delta_packets / elapsed
            bps = delta_bytes / elapsed

            self.previous_stats[key] = (
                packets,
                bytes_received,
                now
            )

            ip = self.get_ip_from_port(port)

            if ip is None:
                continue

            self.show_traffic(
                ip,
                port,
                delta_packets,
                delta_bytes,
                pps,
                bps
            )

            self.detect_attack(
                dpid,
                ip,
                pps
            )

    # ============================================================
    # DESCOBRE IP DA PORTA
    # ============================================================

    def get_ip_from_port(self, port):

        for ip, ip_port in self.ip_to_port.items():

            if ip_port == port:
                return ip

        return None

    # ============================================================
    # EXIBE TRÁFEGO
    # ============================================================

    def show_traffic(
        self,
        ip,
        port,
        packets,
        bytes_received,
        pps,
        bps
    ):

        status = "BLOQUEADO" if self.is_blocked(ip) \
                 else "NORMAL"

        print(
            f"[TRÁFEGO] "
            f"IP: {ip:<15} | "
            f"Porta: {port:<2} | "
            f"PPS: {pps:>6.2f} | "
            f"Bytes/s: {bps:>9.2f} | "
            f"Pkts: {packets:<4} | "
            f"{status}"
        )

    # ============================================================
    # DETECÇÃO ESTATÍSTICA
    # ============================================================

    def detect_attack(
        self,
        dpid,
        ip,
        pps
    ):

        # Se está bloqueado, não tenta bloquear novamente
        if self.is_blocked(ip):

            return

        history = self.pps_history[ip]

        # Construção da baseline
        if len(history) < self.BASELINE_SAMPLES:

            history.append(pps)

            print(
                f"[BASELINE] {ip:<15} "
                f"Amostra {len(history)}/"
                f"{self.BASELINE_SAMPLES} "
                f"| PPS: {pps:.2f}"
            )

            return

        mean = statistics.mean(history)

        if len(history) >= 2:

            std = statistics.stdev(history)

        else:

            std = 0

        statistical_limit = (
            mean +
            self.THRESHOLD_FACTOR * std
        )

        relative_limit = (
            mean *
            self.MIN_RATE_FACTOR
        )

        limit = max(
            statistical_limit,
            relative_limit
        )

        # --------------------------------------------------------
        # ANOMALIA
        # --------------------------------------------------------

        if pps > limit:

            self.anomaly_count[ip] += 1

            count = self.anomaly_count[ip]

            self.total_detections += 1

            print()
            print(
                f"[!] ANOMALIA DETECTADA"
            )
            print(
                f"    IP        : {ip}"
            )
            print(
                f"    PPS       : {pps:.2f}"
            )
            print(
                f"    Média     : {mean:.2f}"
            )
            print(
                f"    Desvio    : {std:.2f}"
            )
            print(
                f"    Limite    : {limit:.2f}"
            )
            print(
                f"    Sequência : "
                f"{count}/{self.REQUIRED_ANOMALIES}"
            )

            # Só bloqueia depois de N anomalias consecutivas
            if count >= self.REQUIRED_ANOMALIES:

                datapath = self.datapaths.get(dpid)

                if datapath is not None:

                    self.block_ip(
                        datapath,
                        ip
                    )

                self.anomaly_count[ip] = 0

            return

        # --------------------------------------------------------
        # TRÁFEGO NORMAL
        # --------------------------------------------------------

        self.anomaly_count[ip] = 0

        # Somente tráfego normal entra na baseline
        history.append(pps)

        print(
            f"[ANÁLISE] {ip:<15} "
            f"PPS: {pps:>6.2f} | "
            f"Limite: {limit:>6.2f} | "
            f"Status: NORMAL"
        )

    # ============================================================
    # BLOQUEIO
    # ============================================================

    def block_ip(
        self,
        datapath,
        ip
    ):

        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip
        )

        # --------------------------------------------------------
        # IMPORTANTE:
        # instructions=[] significa DROP.
        #
        # hard_timeout garante que o próprio OVS remova
        # o bloqueio após BLOCK_TIME segundos.
        # --------------------------------------------------------

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=[],
            hard_timeout=self.BLOCK_TIME
        )

        datapath.send_msg(mod)

        self.blocked_until[ip] = (
            time.time() + self.BLOCK_TIME
        )

        self.total_blocks += 1

        print()
        print("+" + "=" * 70 + "+")
        print(
            f"| {'[BLOQUEIO ATIVADO]':^68} |"
        )
        print("+" + "=" * 70 + "+")
        print(
            f"| IP       : {ip:<57} |"
        )
        print(
            f"| Duração  : {self.BLOCK_TIME:<57} |"
        )
        print(
            f"| Prioridade OpenFlow: {100:<43} |"
        )
        print("+" + "=" * 70 + "+")
        print()

    # ============================================================
    # VERIFICA BLOQUEIO
    # ============================================================

    def is_blocked(self, ip):

        if ip not in self.blocked_until:
            return False

        remaining = (
            self.blocked_until[ip] -
            time.time()
        )

        if remaining > 0:

            return True

        # Bloqueio expirou no controlador
        del self.blocked_until[ip]

        print()
        print(
            f"[BLOQUEIO EXPIRADO] "
            f"{ip}"
        )
        print(
            f"                   "
            f"Tráfego novamente permitido."
        )
        print()

        return False

    # ============================================================
    # MONITORAMENTO
    # ============================================================

    def monitor(self):

        while True:

            for datapath in list(
                self.datapaths.values()
            ):

                self.request_port_stats(datapath)

            hub.sleep(
                self.MONITOR_INTERVAL
            )

    # ============================================================
    # RESUMO PERIÓDICO
    # ============================================================

    def print_summary(self):

        self.print_section(
            "RESUMO DO CONTROLADOR"
        )

        print(
            f"  Switches conectados : "
            f"{len(self.datapaths)}"
        )

        print(
            f"  Detecções           : "
            f"{self.total_detections}"
        )

        print(
            f"  Bloqueios           : "
            f"{self.total_blocks}"
        )

        print(
            f"  IPs bloqueados      : "
            f"{len(self.blocked_until)}"
        )

        print()
