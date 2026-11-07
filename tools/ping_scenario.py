#!/usr/bin/env python3
"""Cenário de pings em duas fases para uma rede Mininet já iniciada."""
from __future__ import annotations

import subprocess
import threading
from typing import Sequence


class PingScenario:
    def __init__(
        self,
        destination: str = "h10",
        legitimate_sources: Sequence[str] = ("h1", "h2"),
        attack_sources: Sequence[str] = ("h3", "h4", "h5", "h6"),
        normal_duration: float = 20.0,
        attack_duration: float = 30.0,
        legitimate_interval: float = 1.0,
        attack_interval: float = 0.05,
    ) -> None:
        self.destination = destination
        self.legitimate_sources = tuple(legitimate_sources)
        self.attack_sources = tuple(attack_sources)
        self.normal_duration = normal_duration
        self.attack_duration = attack_duration
        self.legitimate_interval = legitimate_interval
        self.attack_interval = attack_interval
        self._processes: list[subprocess.Popen] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._net = None

        if not self.legitimate_sources or not self.attack_sources:
            raise ValueError("Informe origens legítimas e origens de sobrecarga.")
        if set(self.legitimate_sources) & set(self.attack_sources):
            raise ValueError("Uma máquina não pode estar nos dois grupos.")
        if self.destination in set(self.legitimate_sources) | set(self.attack_sources):
            raise ValueError("O destino não pode ser também uma origem.")
        if min(normal_duration, attack_duration, legitimate_interval, attack_interval) <= 0:
            raise ValueError("Durações e intervalos devem ser positivos.")

    def _start_pings(self, sources: Sequence[str], interval: float, phase: str) -> None:
        destination_ip = self._net.get(self.destination).IP()
        with self._lock:
            for source_name in sources:
                if self._stop_event.is_set():
                    return
                host = self._net.get(source_name)
                process = host.popen(
                    ["ping", "-n", "-i", str(interval), destination_ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                )
                self._processes.append(process)
                print(
                    f"[PING TESTE] {phase}: {source_name} -> {self.destination} "
                    f"({destination_ip}), intervalo={interval}s",
                    flush=True,
                )

    def _stop_pings(self) -> None:
        with self._lock:
            processes, self._processes = self._processes, []
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def _run_phases(self) -> None:
        print(
            f"[PING TESTE] Fase normal por {self.normal_duration:g}s. "
            f"Origens: {', '.join(self.legitimate_sources)}",
            flush=True,
        )
        if self._stop_event.wait(self.normal_duration):
            return

        print(
            f"[PING TESTE] INÍCIO DA SOBRECARGA por {self.attack_duration:g}s. "
            f"Novas origens: {', '.join(self.attack_sources)}",
            flush=True,
        )
        self._start_pings(self.attack_sources, self.attack_interval, "sobrecarga")
        if not self._stop_event.wait(self.attack_duration):
            print("[PING TESTE] Fim da fase de sobrecarga.", flush=True)
        self._stop_pings()

    def start(self, net) -> None:
        if self._thread and self._thread.is_alive():
            raise RuntimeError("O cenário já está em execução.")
        self._net = net
        for host_name in {
            self.destination, *self.legitimate_sources, *self.attack_sources
        }:
            net.get(host_name)  # valida os nomes na topologia
        self._stop_event.clear()
        self._start_pings(
            self.legitimate_sources, self.legitimate_interval, "tráfego normal"
        )
        self._thread = threading.Thread(target=self._run_phases, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._stop_pings()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
