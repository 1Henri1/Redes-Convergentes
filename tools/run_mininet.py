#!/usr/bin/env python3
"""Executa a topologia Mininet com enlaces configuráveis.

Execute com sudo, enquanto o controlador OS-Ken estiver rodando:
    sudo python3 tools/run_mininet.py

Não há ping automático. Envie pings manualmente no prompt mininet>; as métricas
ICMP são exibidas pelo controlador no primeiro terminal.
"""
from __future__ import annotations

import argparse
import time

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo


class SingleSwitchTopo(Topo):
    """Quatro hosts num switch, com parâmetros TC aplicados a cada enlace."""

    def build(
        self,
        bw: float = 0.1,
        delay: str = "100us",
        jitter: str = "0us",
        queue_size: int = 100,
        loss: float = 0.0,
    ) -> None:
        switch = self.addSwitch("s1", protocols="OpenFlow13")
        for number in range(1,11):
            host = self.addHost(f"h{number}", ip=f"10.0.0.{number}/8")
            self.addLink(
                host,
                switch,
                cls=TCLink,
                bw=bw,
                delay=delay,
                jitter=jitter,
                max_queue_size=queue_size,
                loss=loss,
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--bw", type=float, default=0.1, help="largura de banda por enlace (Mbps)")
    parser.add_argument("--delay", default="100us", help="atraso por enlace; 20us visa RTT teórico de 0,08ms entre h1 e h4")
    parser.add_argument("--jitter", default="0us", help="variação de atraso (padrão: 0us)")
    parser.add_argument("--queue", type=int, default=100, help="tamanho máximo da fila em pacotes")
    parser.add_argument("--loss", type=float, default=0.0, help="perda artificial em %% (padrão: 0)")
    args = parser.parse_args()

    if args.bw <= 0 or args.queue < 1:
        parser.error("--bw deve ser > 0 e --queue deve ser >= 1")
    if not 0 <= args.loss <= 100:
        parser.error("--loss deve estar entre 0 e 100")
    topo = SingleSwitchTopo(
        bw=args.bw,
        delay=args.delay,
        jitter=args.jitter,
        queue_size=args.queue,
        loss=args.loss,
    )
    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=False,
    )
    net.addController(
        "c0",
        controller=RemoteController,
        ip=args.controller_ip,
        port=args.controller_port,
    )

    try:
        info("*** Iniciando rede Mininet com enlaces TC configurados\n")
        info(
            f"*** Parâmetros: bw={args.bw:g} Mbps, delay={args.delay}, "
            f"jitter={args.jitter}, fila={args.queue} pacotes, "
            f"perda artificial={args.loss:g}%\n"
        )
        net.start()
        time.sleep(1)
        info("*** Rede pronta. Nenhum ping automático será executado.\n")
        info("*** Envie pings manualmente no prompt mininet>, por exemplo: h1 ping -c 10 h4\n")
        CLI(net)
    except KeyboardInterrupt:
        pass
    finally:
        net.stop()
    return 0


if __name__ == "__main__":
    setLogLevel("info")
    raise SystemExit(main())
