"""Contabilização por fluxo, excluindo o sentido de resposta."""

import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Dict, Hashable, Tuple

from os_ken.lib.packet import icmp, tcp, udp
from .models import PortRate

FlowKey = Tuple[Hashable, ...]


@dataclass(frozen=True)
class _Snapshot:
    packets: int
    bytes: int
    timestamp: float


class PortRateCalculator:
    """Calcula PPS/BPS por IP usando apenas a direção iniciadora de cada fluxo.

    TCP: SYN inicia a direção; SYN-ACK é associado ao sentido inverso.
    UDP e protocolos sem sinal explícito: a primeira direção observada inicia
    o fluxo. ICMP Echo Reply é sempre excluído e associado ao Echo Request.
    UDP não define universalmente request/response, então a regra é heurística.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._initiators: set[FlowKey] = set()
        self._packets: Dict[str, int] = defaultdict(int)
        self._bytes: Dict[str, int] = defaultdict(int)
        self._previous: Dict[str, _Snapshot] = {}

    def record_packet(self, pkt: object, ip_pkt: object) -> None:
        """Conta bytes/pacotes somente se o pacote estiver no sentido iniciador."""
        proto = ip_pkt.proto
        src, dst = ip_pkt.src, ip_pkt.dst
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if tcp_pkt is not None:
            key = (proto, src, dst, tcp_pkt.src_port, tcp_pkt.dst_port)
            reverse = (proto, dst, src, tcp_pkt.dst_port, tcp_pkt.src_port)
            if tcp_pkt.syn and tcp_pkt.ack:
                self._initiators.add(reverse)
                return
        elif udp_pkt is not None:
            key = (proto, src, dst, udp_pkt.src_port, udp_pkt.dst_port)
            reverse = (proto, dst, src, udp_pkt.dst_port, udp_pkt.src_port)
        elif icmp_pkt is not None:
            data = getattr(icmp_pkt, "data", None)
            ident = getattr(data, "id", None)
            key = (proto, src, dst, icmp_pkt.type, ident)
            reverse = (proto, dst, src, 8, ident)
            if icmp_pkt.type == 0:  # ICMP Echo Reply
                return
        else:
            key = (proto, src, dst)
            reverse = (proto, dst, src)

        if reverse in self._initiators:
            return
        self._initiators.add(key)
        self._packets[src] += 1
        self._bytes[src] += len(pkt.data)

    def collect_rates(self) -> Dict[str, PortRate]:
        """Retorna taxas por janela e atualiza os snapshots."""
        now = self._clock()
        rates: Dict[str, PortRate] = {}
        for ip in list(self._packets):
            previous = self._previous.get(ip)
            packets, byte_count = self._packets[ip], self._bytes[ip]
            self._previous[ip] = _Snapshot(packets, byte_count, now)
            if previous is None:
                continue
            elapsed = now - previous.timestamp
            delta_packets = packets - previous.packets
            delta_bytes = byte_count - previous.bytes
            if elapsed <= 0 or delta_packets < 0 or delta_bytes < 0:
                continue
            rates[ip] = PortRate(
                delta_packets=delta_packets,
                delta_bytes=delta_bytes,
                pps=delta_packets / elapsed,
                bps=delta_bytes / elapsed,
            )
        return rates

    def forget_switch(self, dpid: int) -> None:
        """Mantido por compatibilidade; as taxas agora são indexadas por IP."""
        return
