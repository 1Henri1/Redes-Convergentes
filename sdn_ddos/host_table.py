"""Tabelas de aprendizado de hosts (MAC -> porta e porta -> IP)."""

from typing import Dict, Optional

# Endereço usado por hosts que ainda não têm IP (ARP probe, DHCP).
_UNSPECIFIED_IP = "0.0.0.0"


class HostTable:
    """Memoriza onde cada host está conectado, separado por switch.

    Tudo é indexado por ``dpid``: portas só têm significado dentro do seu
    switch, e misturar switches causaria associações de IP incorretas.

    Limitação conhecida: assume-se um host por porta (topologia ``single``
    do Mininet). Com vários IPs numa mesma porta, vale o último aprendido.

    Não há locks: o OS-Ken usa green threads cooperativas, então um handler
    nunca é interrompido no meio de uma atualização.
    """

    def __init__(self) -> None:
        self._mac_to_port: Dict[int, Dict[str, int]] = {}
        self._port_to_ip: Dict[int, Dict[int, str]] = {}

    def learn_mac(self, dpid: int, mac: str, port: int) -> None:
        """Associa um MAC de origem à porta por onde ele foi visto."""
        self._mac_to_port.setdefault(dpid, {})[mac] = port

    def learn_ip(self, dpid: int, ip: str, port: int) -> None:
        """Associa um IP de origem à porta por onde ele foi visto.

        O IP ``0.0.0.0`` é ignorado por não identificar nenhum host.
        """
        if ip == _UNSPECIFIED_IP:
            return
        self._port_to_ip.setdefault(dpid, {})[port] = ip

    def port_for_mac(self, dpid: int, mac: str) -> Optional[int]:
        """Retorna a porta de um MAC, ou ``None`` se ainda não foi aprendido."""
        return self._mac_to_port.get(dpid, {}).get(mac)

    def ip_for_port(self, dpid: int, port: int) -> Optional[str]:
        """Retorna o IP aprendido numa porta, ou ``None`` se desconhecido."""
        return self._port_to_ip.get(dpid, {}).get(port)

    def forget_switch(self, dpid: int) -> None:
        """Descarta tudo o que foi aprendido sobre um switch desconectado."""
        self._mac_to_port.pop(dpid, None)
        self._port_to_ip.pop(dpid, None)
