#!/usr/bin/env python3
from __future__ import annotations

import random as rd
import subprocess
import threading
from typing import Sequence


class PingScenario:
    """Executa grupos de ping em paralelo dentro de uma rede Mininet."""

    def __init__(self, net=None) -> None:
        self.net = net
        self._groups: dict[str, list[subprocess.Popen]] = {}
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start_pings(
        self,
        group: str,
        sources: Sequence[str],
        destination: str,
        interval: float = 1.0,
        count: int = 100,
        packet_size: int = 56,
    ) -> None:
        """Inicia pings; count é a quantidade por origem e packet_size é em bytes."""
        if self.net is None:
            raise RuntimeError("A rede Mininet ainda não foi associada ao cenário.")
        if not group.strip():
            raise ValueError("Informe um nome para o grupo.")
        if not sources:
            raise ValueError("Informe ao menos uma origem.")
        if interval <= 0:
            raise ValueError("O intervalo deve ser positivo.")
        if count <= 0:
            raise ValueError("A quantidade de pacotes deve ser positiva.")
        if packet_size < 0:
            raise ValueError("O tamanho do pacote não pode ser negativo.")
        if destination in sources:
            raise ValueError("O destino não pode ser uma das origens.")

        destination_ip = self.net.get(destination).IP()
        with self._lock:
            if self._stop_event.is_set():
                return
            if group in self._groups:
                raise ValueError(f"O grupo '{group}' já existe.")
            processes = []
            try:
                for source in sources:
                    host = self.net.get(source)  # valida o host
                    process = host.popen(
                        [
                            "ping", "-n",
                            "-i", str(interval),
                            "-c", str(count),
                            "-s", str(packet_size),
                            destination_ip,
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.STDOUT,
                    )
                    processes.append(process)
                self._groups[group] = processes
            except Exception:
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                        process.wait()
                raise

        print(
            f"[PING TESTE] Grupo '{group}' iniciado: "
            f"{', '.join(sources)} -> {destination}, "
            f"intervalo={interval}s, pacotes por origem={count}, "
            f"tamanho={packet_size} bytes",
            flush=True,
        )

    def wait(self, seconds: float) -> None:
        """Insere uma pausa na sequência sem bloquear o encerramento do cenário."""
        if seconds < 0:
            raise ValueError("A pausa não pode ser negativa.")
        print(f"[PING TESTE] Aguardando {seconds:g} segundos...", flush=True)
        if self._stop_event.wait(seconds):
            raise InterruptedError("Execução do cenário interrompida.")

    def stop_pings(self, group: str) -> None:
        """Interrompe somente os processos pertencentes ao grupo informado."""
        with self._lock:
            processes = self._groups.pop(group, [])
        self._terminate(processes)
        print(f"[PING TESTE] Grupo '{group}' encerrado.", flush=True)

    @staticmethod
    def _terminate(processes: Sequence[subprocess.Popen]) -> None:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def stop_all(self) -> None:
        """Interrompe todos os grupos ainda ativos."""
        with self._lock:
            groups = list(self._groups.values())
            self._groups.clear()
        for processes in groups:
            self._terminate(processes)

    def Normal(self, Group: int, cont: int)-> int:
        for i in range(Group*5+1,Group*5+6):
            src = f"h{i}"
            num = rd.randint(1, 5)
            if num<5:
                self.start_pings(
                    group=f"N{i}{cont}",
                    sources=[src],
                    destination="h25",
                    interval=0.01+0.001*num,
                    count=int(5000/(num+2)),
                    packet_size=int(200+20*(num)/(Group+2)),
                )
                self.wait(num)
        if Group == 1:
            return 0
        else:
            return 1

    def AtaqDos(self, cont: int)-> None:
            for i in range(11,13):
                src = f"h{i}"
                num = rd.randint(1, 5)
                num2 = rd.randint(1,10)
                if num<5:
                    self.start_pings(
                        group=f"D{i}{cont}",
                        sources=[src],
                        destination="h25",
                        interval=0.005+0.005*(num2/num**2),
                        count=int(5000/num**2*num2),
                        packet_size=int(200*(num**2/num2)),
                    )
                    self.wait(num)

    def AtaqDDos(self, cont: int)-> None:
            for i in range(13,25):
                src = f"h{i}"
                num = rd.randint(1, 5)
                num2 = rd.randint(5,10)
                if num<5:
                    self.start_pings(
                        group=f"DD{i}{cont}",
                        sources=[src],
                        destination="h25",
                        interval=0.01+0.005*(num2/num),
                        count=int(5000/num**2*num2),
                        packet_size=int(150+20*(num**2/num2)),
                    )
                    self.wait(num)

    def main(self) -> None:
        cont = 0
        grupo = self.Normal(0,cont)
        self.wait(15)
        cont+=1
        grupo = self.Normal(grupo,cont)
        self.wait(15)
        cont+=1
        while True:
            num = rd.randint(0, 10)
            if num<5:
                grupo = self.Normal(grupo,cont)
                self.wait(25)
            elif num<10:
                self.AtaqDDos(cont)
                self.wait(10)
                cont+=1
            elif num==8:
                self.AtaqDos(cont)
                self.wait(10)
            else:
                self.AtaqDDos(cont)
                self.wait(10)
            cont+=1

    def start(self, net) -> None:
        """Executa main() em segundo plano para manter a CLI do Mininet disponível."""
        if self._thread and self._thread.is_alive():
            raise RuntimeError("O cenário já está em execução.")
        self.net = net
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            self.main()
        except InterruptedError:
            print("[PING TESTE] Cenário interrompido.", flush=True)
        except Exception as error:
            print(f"[PING TESTE] Erro no cenário: {error}", flush=True)
        finally:
            self.stop_all()

    def stop(self) -> None:
        """Interrompe pausas e encerra todos os pings, inclusive ao fechar o Mininet."""
        self._stop_event.set()
        self.stop_all()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
