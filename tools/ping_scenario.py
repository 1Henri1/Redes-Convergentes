#!/usr/bin/env python3
"""Edite o método main() para montar sequências personalizadas de pings."""
from __future__ import annotations

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

    def main(self) -> None:
        """Sequência do teste: edite este método para criar seus experimentos.

        Para adicionar etapas, chame start_pings() novamente.
        Use wait(segundos) para inserir pausas entre etapas.
        Grupos já iniciados continuam ativos até stop_pings() ou stop_all().
        """
        # BLOCO 1: tráfego normal. h1 e h2 permanecem ativos.
        self.start_pings(
            group="normal",
            sources=["h1", "h2"],
            destination="h10",
            interval=1.0,
            count=100,
            packet_size=56,
        )
        self.wait(35)

        # BLOCO 2: novas origens começam a enviar para o mesmo servidor.
        self.start_pings(
            group="sobrecarga",
            sources=["h3", "h4", "h5", "h6"],
            destination="h10",
            interval=0.1,
            count=500,
            packet_size=56,
        )
        self.wait(30)

        # Exemplo de pausa entre etapas:
        # self.wait(5)
        #
        # Exemplo de um terceiro bloco, mantendo os grupos anteriores ativos:
        # self.start_pings(
        #     "bloco_3", ["h7", "h8"], "h10",
        #     interval=0.05, count=1000, packet_size=128,
        # )
        # self.wait(20)

        # Encerra todos os pings ao final da sequência.
        self.stop_all()

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
