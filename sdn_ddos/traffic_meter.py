"""Contabilização de tráfego por par e de novos fluxos por destino."""
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Dict, Hashable, Set, Tuple

from os_ken.lib.packet import icmp, tcp, udp

from .models import DestinationFlowRate, PortRate

FlowKey = Tuple[Hashable, ...]
PairKey = Tuple[str, str]
_FLOW_TTL = 120.0
_PRUNE_INTERVAL = 30.0


@dataclass(frozen=True)
class _Snapshot:
    packets: int
    bytes: int
    timestamp: float


class PortRateCalculator:
    """Calcula taxas por par e contabiliza cada novo fluxo uma única vez.

    TCP usa a tupla de 5 elementos e exclui SYN-ACK/respostas; UDP usa
    protocolo, IPs e portas; ICMP usa tipo e identificador. Fluxos inativos
    expiram após _FLOW_TTL. A taxa de volume é expressa em bytes/s.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._initiators: Dict[FlowKey, float] = {}
        self._packets: Dict[PairKey, int] = defaultdict(int)
        self._bytes: Dict[PairKey, int] = defaultdict(int)
        self._previous: Dict[PairKey, _Snapshot] = {}
        self._last_prune = self._clock()

        # Contadores por janela para medir a taxa agregada de criação de fluxos
        # direcionados a cada destino, independentemente da origem.
        self._new_flow_counts: Dict[str, int] = defaultdict(int)
        self._new_flow_sources: Dict[str, Set[str]] = defaultdict(set)
        self._known_flow_destinations: Set[str] = set()
        self._last_flow_collection = self._clock()

    def _expire_flows(self, now: float) -> None:
        if now - self._last_prune < _PRUNE_INTERVAL:
            return
        cutoff = now - _FLOW_TTL
        self._initiators = {
            key: timestamp for key, timestamp in self._initiators.items()
            if timestamp >= cutoff
        }
        self._last_prune = now

    def record_packet(self, pkt: object, ip_pkt: object) -> None:
        now = self._clock()
        self._expire_flows(now)
        proto, src, dst = ip_pkt.proto, ip_pkt.src, ip_pkt.dst
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if tcp_pkt is not None:
            key = (proto, src, dst, tcp_pkt.src_port, tcp_pkt.dst_port)
            reverse = (proto, dst, src, tcp_pkt.dst_port, tcp_pkt.src_port)
            if tcp_pkt.syn and tcp_pkt.ack:
                self._initiators[reverse] = now
                return
        elif udp_pkt is not None:
            key = (proto, src, dst, udp_pkt.src_port, udp_pkt.dst_port)
            reverse = (proto, dst, src, udp_pkt.dst_port, udp_pkt.src_port)
        elif icmp_pkt is not None:
            data = getattr(icmp_pkt, "data", None)
            ident = getattr(data, "id", None)
            key = (proto, src, dst, icmp_pkt.type, ident)
            reverse = (proto, dst, src, 8, ident)
            if icmp_pkt.type == 0:  # Echo Reply
                return
        else:
            key, reverse = (proto, src, dst), (proto, dst, src)

        # Respostas pertencentes a um fluxo já iniciado não contam como novas
        # origens nem como novos fluxos.
        if reverse in self._initiators:
            self._initiators[reverse] = now
            return

        is_new_flow = key not in self._initiators
        self._initiators[key] = now
        pair = (src, dst)
        self._packets[pair] += 1
        self._bytes[pair] += len(pkt.data)

        if is_new_flow:
            self._new_flow_counts[dst] += 1
            self._new_flow_sources[dst].add(src)
            self._known_flow_destinations.add(dst)

    def collect_rates(self) -> Dict[PairKey, PortRate]:
        now = self._clock()
        rates: Dict[PairKey, PortRate] = {}
        for pair in list(self._packets):
            previous = self._previous.get(pair)
            packets, byte_count = self._packets[pair], self._bytes[pair]
            self._previous[pair] = _Snapshot(packets, byte_count, now)
            if previous is None:
                continue
            elapsed = now - previous.timestamp
            dp, db = packets - previous.packets, byte_count - previous.bytes
            if elapsed <= 0 or dp < 0 or db < 0:
                continue
            rates[pair] = PortRate(dp, db, dp / elapsed, db / elapsed)
        return rates

    def collect_new_flow_rates(self) -> Dict[str, DestinationFlowRate]:
        """Retorna novos fluxos/s por destino e as origens vistas nesta janela."""
        now = self._clock()
        elapsed = now - self._last_flow_collection
        self._last_flow_collection = now
        if elapsed <= 0:
            return {}

        results: Dict[str, DestinationFlowRate] = {}
        for dst in self._known_flow_destinations:
            count = self._new_flow_counts.get(dst, 0)
            sources = tuple(sorted(self._new_flow_sources.get(dst, set())))
            results[dst] = DestinationFlowRate(
                new_flows=count,
                flows_per_second=count / elapsed,
                sources=sources,
            )
            self._new_flow_counts[dst] = 0
            self._new_flow_sources[dst].clear()
        return results

    def forget_switch(self, dpid: int) -> None:
        """A medição por IP não é específica de um switch."""
        return
