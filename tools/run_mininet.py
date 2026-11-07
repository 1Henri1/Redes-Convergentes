#!/usr/bin/env python3
"""Executa a topologia Mininet com enlaces configuráveis.

Execute com sudo, enquanto o controlador OS-Ken estiver rodando:
    sudo python3 tools/run_mininet.py
"""
from __future__ import annotations

import argparse
import time

from ping_scenario import PingScenario

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo


class SingleSwitchTopo(Topo):
    """10 hosts num switch, com parâmetros TC aplicados a cada enlace."""

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
    parser.add_argument("--delay", default="100us", help="atraso por enlace; 100us visa RTT teórico de 0,4ms entre h1 e h4")
    parser.add_argument("--jitter", default=0, help="variação de atraso (padrão: 0us)")
    parser.add_argument("--queue", type=int, default=100, help="tamanho máximo da fila em pacotes")
    parser.add_argument("--loss", type=float, default=0, help="perda artificial em %% (padrão: 0)")
    parser.add_argument("--auto-ping-test", action="store_true", help="executa tráfego normal seguido de sobrecarga por ping")
    parser.add_argument("--destination", default="h10", help="destino dos pings automáticos")
    parser.add_argument("--legitimate-sources", default="h1,h2", help="origens legítimas separadas por vírgula")
    parser.add_argument("--attack-sources", default="h3,h4,h5,h6", help="origens adicionais da fase de sobrecarga")
    parser.add_argument("--normal-duration", type=float, default=35.0, help="duração da fase normal em segundos")
    parser.add_argument("--attack-duration", type=float, default=30.0, help="duração da fase de sobrecarga em segundos")
    parser.add_argument("--legitimate-interval", type=float, default=1.0, help="intervalo dos pings legítimos em segundos")
    parser.add_argument("--attack-interval", type=float, default=0.1, help="intervalo dos pings de sobrecarga em segundos")
    args = parser.parse_args()

    if args.bw <= 0 or args.queue < 1:
        parser.error("--bw deve ser > 0 e --queue deve ser >= 1")
    if not 0 <= args.loss <= 100:
        parser.error("--loss deve estar entre 0 e 100")
    if min(args.normal_duration, args.attack_duration, args.legitimate_interval, args.attack_interval) <= 0:
        parser.error("durações e intervalos do cenário devem ser positivos")
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

    scenario = None
    try:
        info("*** Iniciando rede Mininet com enlaces TC configurados\n")
        info(
            f"*** Parâmetros: bw={args.bw:g} Mbps, delay={args.delay}, "
            f"jitter={args.jitter}, fila={args.queue} pacotes, "
            f"perda artificial={args.loss:g}%\n"
        )
        net.start()
        time.sleep(1)
        if args.auto_ping_test:
            scenario = PingScenario(
                destination=args.destination,
                legitimate_sources=tuple(x.strip() for x in args.legitimate_sources.split(",") if x.strip()),
                attack_sources=tuple(x.strip() for x in args.attack_sources.split(",") if x.strip()),
                normal_duration=args.normal_duration,
                attack_duration=args.attack_duration,
                legitimate_interval=args.legitimate_interval,
                attack_interval=args.attack_interval,
            )
            scenario.start(net)
            info("*** Cenário automático iniciado; acompanhe o terminal do controlador.\n")
        else:
            info("*** Envie pings manualmente no prompt mininet>, por exemplo: h1 ping -c 10 h4\n")
        CLI(net)
    except KeyboardInterrupt:
        pass
    finally:
        if scenario is not None:
            scenario.stop()
        net.stop()
    return 0


if __name__ == "__main__":
    setLogLevel("info")
    raise SystemExit(main())
