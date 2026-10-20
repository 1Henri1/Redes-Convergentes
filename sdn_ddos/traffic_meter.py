"""Contabilização de tráfego por par IP origem-destino."""
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Dict, Hashable, Tuple
from os_ken.lib.packet import icmp, tcp, udp
from .models import PortRate
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
    """Calcula PPS/BPS por par origem-destino no sentido iniciador.
    TCP usa SYN/SYN-ACK; UDP usa heurística da primeira direção observada.
    ICMP Echo Reply é excluído.
    """
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._initiators: Dict[FlowKey, float] = {}
        self._packets: Dict[PairKey, int] = defaultdict(int)
        self._bytes: Dict[PairKey, int] = defaultdict(int)
        self._previous: Dict[PairKey, _Snapshot] = {}
        self._last_prune = self._clock()
    def _expire_flows(self, now: float) -> None:
        if now - self._last_prune < _PRUNE_INTERVAL: return
        cutoff = now - _FLOW_TTL
        self._initiators = {k: t for k, t in self._initiators.items() if t >= cutoff}
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
            if icmp_pkt.type == 0: return
        else:
            key, reverse = (proto, src, dst), (proto, dst, src)
        if reverse in self._initiators:
            self._initiators[reverse] = now
            return
        self._initiators[key] = now
        pair = (src, dst)
        self._packets[pair] += 1
        self._bytes[pair] += len(pkt.data)
    def collect_rates(self) -> Dict[PairKey, PortRate]:
        now = self._clock()
        rates: Dict[PairKey, PortRate] = {}
        for pair in list(self._packets):
            previous = self._previous.get(pair)
            packets, byte_count = self._packets[pair], self._bytes[pair]
            self._previous[pair] = _Snapshot(packets, byte_count, now)
            if previous is None: continue
            elapsed = now - previous.timestamp
            dp, db = packets - previous.packets, byte_count - previous.bytes
            if elapsed <= 0 or dp < 0 or db < 0: continue
            rates[pair] = PortRate(dp, db, dp / elapsed, db / elapsed)
        return rates
    def forget_switch(self, dpid: int) -> None:
        """A medição por par IP não é específica de um switch."""
        return
