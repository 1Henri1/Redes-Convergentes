"""Encapsula todas as mensagens OpenFlow 1.3 enviadas aos switches."""

from typing import Any, List

from os_ken.lib.packet import ether_types

# Quanto maior o número, maior a precedência. O bloqueio precisa vencer o
# encaminhamento aprendido, e este precisa vencer o table-miss.
TABLE_MISS_PRIORITY = 0
FORWARDING_PRIORITY = 10
BLOCK_PRIORITY = 100


class FlowManager:
    """Traduz intenções ("bloquear este IP") em mensagens OpenFlow.

    Concentrar isso aqui mantém o restante do código livre de detalhes do
    protocolo e permite trocar a versão do OpenFlow mexendo num só lugar.
    Não guarda estado: o ``datapath`` é sempre recebido como argumento.
    """

    def install_table_miss(self, datapath: Any) -> None:
        """Instala a regra de menor prioridade que envia ao controlador
        todo pacote sem regra específica (base do learning switch).

        ``OFPCML_NO_BUFFER`` envia o pacote inteiro, pois precisamos ler
        os cabeçalhos L2/L3 para aprender MACs e IPs.
        """
        ofproto, parser = datapath.ofproto, datapath.ofproto_parser
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self._add_flow(datapath, TABLE_MISS_PRIORITY, parser.OFPMatch(), actions)

    def install_forwarding(
        self, datapath: Any, in_port: int, eth_dst: str, out_port: int
    ) -> None:
        """Instala uma regra de encaminhamento por (porta de entrada, MAC destino).

        Depois dela, pacotes equivalentes são tratados pelo switch sem
        passar pelo controlador.
        """
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
        actions = [parser.OFPActionOutput(out_port)]
        self._add_flow(datapath, FORWARDING_PRIORITY, match, actions)

    def install_drop(self, datapath: Any, ipv4_src: str, hard_timeout: int) -> None:
        """Descarta todo o tráfego IPv4 originado em ``ipv4_src``.

        Em OpenFlow 1.3, uma regra *sem instruções* significa descartar.
        O ``hard_timeout`` faz o próprio switch remover o bloqueio, então a
        mitigação termina mesmo que o controlador falhe.
        """
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ipv4_src)
        self._send_flow_mod(
            datapath, BLOCK_PRIORITY, match, instructions=[], hard_timeout=hard_timeout
        )

    def forward_packet(self, datapath: Any, msg: Any, in_port: int, out_port: int) -> None:
        """Reenvia o pacote que causou o packet-in (via PacketOut).

        Se o switch guardou o pacote em buffer, basta referenciá-lo; senão
        os dados precisam acompanhar a mensagem.
        """
        ofproto, parser = datapath.ofproto, datapath.ofproto_parser
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        datapath.send_msg(
            parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=[parser.OFPActionOutput(out_port)],
                data=data,
            )
        )

    def request_port_stats(self, datapath: Any) -> None:
        """Solicita os contadores de todas as portas do switch."""
        ofproto, parser = datapath.ofproto, datapath.ofproto_parser
        datapath.send_msg(parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY))

    # ------------------------------------------------------------------
    # Internos
    # ------------------------------------------------------------------

    def _add_flow(self, datapath: Any, priority: int, match: Any, actions: List[Any]) -> None:
        """Instala uma regra cuja instrução é aplicar ``actions``."""
        parser = datapath.ofproto_parser
        instructions = [
            parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]
        self._send_flow_mod(datapath, priority, match, instructions)

    def _send_flow_mod(
        self,
        datapath: Any,
        priority: int,
        match: Any,
        instructions: List[Any],
        hard_timeout: int = 0,
    ) -> None:
        """Monta e envia um FlowMod (ponto único de criação de regras)."""
        datapath.send_msg(
            datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=instructions,
                hard_timeout=hard_timeout,
            )
        )
