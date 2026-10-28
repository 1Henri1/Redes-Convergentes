#!/usr/bin/env python3
"""Executa a topologia Mininet com enlaces limitados e mede RTT/perda por ICMP.

Execute com sudo, enquanto o controlador OS-Ken estiver rodando:
    sudo python3 tools/run_mininet.py

As métricas são sondas ICMP cumulativas de h1 para h4; não representam a
contagem de todos os pacotes da rede. O tráfego de sondagem também atravessa
a rede e pode ser observado pelo controlador.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import threading
import time
from typing import Optional

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo


_SEQ_RE = re.compile(r"icmp_seq[= ](\d+)")
_RTT_RE = re.compile(r"time[=<]([0-9.]+)\s*ms")


class SingleSwitchTopo(Topo):
    """Quatro hosts num switch, com parâmetros TC aplicados a cada enlace."""

    def build(
        self,
        bw: float = 10.0,
        delay: str = "5ms",
        jitter: str = "1ms",
        queue_size: int = 100,
        loss: float = 0.0,
    ) -> None:
        switch = self.addSwitch("s1", protocols="OpenFlow13")
        for number in range(1, 5):
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


class IcmpProbe:
    """Sonda ICMP cumulativa; perda estimada por sequência enviada/recebida."""

    def __init__(self, host, destination: str, interval: float, report_every: float):
        self.host = host
        self.destination = destination
        self.interval = interval
        self.report_every = report_every
        self.process: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._max_seq = 0
        self._received: set[int] = set()
        self._rtt_sum_ms = 0.0
        self._rtt_count = 0
        self._reader: Optional[threading.Thread] = None
        self._reporter: Optional[threading.Thread] = None

    def start(self) -> None:
        self.process = self.host.popen(
            [
                "ping", "-n", "-D", "-O", "-i", str(self.interval),
                self.destination,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._reader = threading.Thread(target=self._read_output, daemon=True)
        self._reporter = threading.Thread(target=self._report_loop, daemon=True)
        self._reader.start()
        self._reporter.start()
        info(
            f"\n[REDE] Sonda ICMP ativa: h1 -> {self.destination}; "
            f"intervalo={self.interval:g}s; resumo a cada {self.report_every:g}s.\n"
        )

    def _read_output(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        for line in self.process.stdout:
            seq_match = _SEQ_RE.search(line)
            if not seq_match:
                continue
            seq = int(seq_match.group(1))
            with self._lock:
                self._max_seq = max(self._max_seq, seq)
                if "bytes from" in line:
                    self._received.add(seq)
                    rtt_match = _RTT_RE.search(line)
                    if rtt_match:
                        self._rtt_sum_ms += float(rtt_match.group(1))
                        self._rtt_count += 1

    def _report_loop(self) -> None:
        while not self._stop.wait(self.report_every):
            with self._lock:
                sent = self._max_seq
                received = len(self._received)
                lost = max(0, sent - received)
                loss_pct = (100.0 * lost / sent) if sent else 0.0
                avg_rtt = (
                    self._rtt_sum_ms / self._rtt_count
                    if self._rtt_count else None
                )
            rtt_text = f"{avg_rtt:.2f} ms" if avg_rtt is not None else "N/D"
            info(
                "\n[REDE/ICMP h1->h4] "
                f"Enviados: {sent} | Recebidos: {received} | Perdidos: {lost} "
                f"| Perda: {loss_pct:.2f}% | RTT médio: {rtt_text}\n"
            )

    def stop(self) -> None:
        self._stop.set()
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        for thread in (self._reader, self._reporter):
            if thread is not None:
                thread.join(timeout=2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--bw", type=float, default=10.0, help="largura de banda por enlace (Mbps)")
    parser.add_argument("--delay", default="5ms", help="atraso por enlace, ex.: 5ms")
    parser.add_argument("--jitter", default="1ms", help="variação de atraso, ex.: 1ms")
    parser.add_argument("--queue", type=int, default=100, help="tamanho máximo da fila em pacotes")
    parser.add_argument("--loss", type=float, default=0.0, help="perda artificial em %% (padrão: 0)")
    parser.add_argument("--probe-interval", type=float, default=0.2, help="intervalo entre sondas ICMP (s)")
    parser.add_argument("--report-every", type=float, default=5.0, help="intervalo dos relatórios (s)")
    args = parser.parse_args()

    if args.bw <= 0 or args.queue < 1:
        parser.error("--bw deve ser > 0 e --queue deve ser >= 1")
    if not 0 <= args.loss <= 100:
        parser.error("--loss deve estar entre 0 e 100")
    if args.probe_interval <= 0 or args.report_every <= 0:
        parser.error("--probe-interval e --report-every devem ser > 0")

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

    probe: Optional[IcmpProbe] = None
    try:
        info("*** Iniciando rede Mininet com enlaces TC configurados\n")
        info(
            f"*** Parâmetros: bw={args.bw:g} Mbps, delay={args.delay}, "
            f"jitter={args.jitter}, fila={args.queue} pacotes, "
            f"perda artificial={args.loss:g}%\n"
        )
        net.start()
        time.sleep(1)
        info("*** Aquecendo aprendizado e verificando conectividade (pingall)\n")
        net.pingAll()
        probe = IcmpProbe(
            net.get("h1"),
            "10.0.0.4",
            args.probe_interval,
            args.report_every,
        )
        probe.start()
        CLI(net)
    except KeyboardInterrupt:
        pass
    finally:
        if probe is not None:
            probe.stop()
        net.stop()
    return 0


if __name__ == "__main__":
    setLogLevel("info")
    raise SystemExit(main())
