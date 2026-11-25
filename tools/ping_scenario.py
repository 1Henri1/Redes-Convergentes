#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import os
import random as rd
import subprocess
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Sequence


class PingScenario:
    """Executa comandos ping e contabiliza cada processo uma única vez."""
    
    def __init__(self, net=None) -> None:
        self.net = net
        self._groups: dict[str, list[dict]] = {}
        self._commands: list[dict] = []
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._block_events_path = Path(os.getenv(
            "SDN_DDOS_BLOCK_EVENTS_PATH",
            "/tmp/sdn_ddos_block_events.jsonl",
        ))
        self._csv_path = Path(os.getenv(
            "SDN_DDOS_PING_RESULTS_PATH",
            "resultado_comandos_ping.csv",
        ))
        self._exported = False

    def start_pings(
        self,
        group: str,
        sources: Sequence[str],
        destination: str,
        interval: float = 1.0,
        count: int = 100,
        packet_size: int = 56,
    ) -> None:
        """Inicia um processo ping por origem; cada processo vale uma ocorrência."""
        if self.net is None:
            raise RuntimeError("A rede Mininet ainda não foi associada ao cenário.")
        if not group.strip():
            raise ValueError("Informe um nome para o grupo.")
        if not sources:
            raise ValueError("Informe ao menos uma origem.")
        if interval <= 0 or count <= 0 or packet_size < 0:
            raise ValueError("Intervalo/quantidade inválidos ou tamanho negativo.")
        if destination in sources:
            raise ValueError("O destino não pode ser uma das origens.")

        destination_ip = self.net.get(destination).IP()
        with self._lock:
            if self._stop_event.is_set():
                return
            if group in self._groups:
                raise ValueError(f"O grupo '{group}' já existe.")

            commands = []
            try:
                for source in sources:
                    host = self.net.get(source)
                    source_ip = host.IP()
                    started_at = time.monotonic()
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
                    command = {
                        "process": process,
                        "source": source,
                        "source_ip": source_ip,
                        "destination": destination,
                        "started_at": started_at,
                        "ended_at": None,
                        "finalized": False,
                        "finalizing": False,
                        "finalization_event": threading.Event(),
                    }
                    commands.append(command)
                    self._commands.append(command)
                self._groups[group] = commands
            except Exception:
                self._terminate_commands(commands)
                raise

        # Monitora cada processo independentemente do cenário principal.
        for command in commands:
            threading.Thread(
                target=self._monitor_command,
                args=(command,),
                daemon=True,
            ).start()

        print(
            f"[PING TESTE] Grupo '{group}' iniciado: "
            f"{', '.join(sources)} -> {destination}, "
            f"intervalo={interval}s, pacotes por origem={count}, "
            f"tamanho={packet_size} bytes",
            flush=True,
        )

    def _monitor_command(self, command: dict) -> None:
        """Registra o término real do processo ping."""
        command["process"].wait()
        self._finalize_command(command)

    def wait(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("A pausa não pode ser negativa.")
        print(f"[PING TESTE] Aguardando {seconds:g} segundos...", flush=True)
        if self._stop_event.wait(seconds):
            raise InterruptedError("Execução do cenário interrompida.")

    def stop_pings(self, group: str) -> None:
        with self._lock:
            commands = self._groups.pop(group, [])
        self._terminate_commands(commands)
        for command in commands:
            self._finalize_command(command)
        print(f"[PING TESTE] Grupo '{group}' encerrado.", flush=True)

    @staticmethod
    def _terminate_commands(commands: Sequence[dict]) -> None:
        for command in commands:
            process = command["process"]
            if process.poll() is None:
                process.terminate()
        for command in commands:
            process = command["process"]
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def _read_block_events(self) -> list[dict]:
        """Lê os intervalos de bloqueio registrados pelo controlador SDN."""
        events = []
        try:
            with self._block_events_path.open("r", encoding="utf-8") as file:
                for line in file:
                    try:
                        event = json.loads(line)
                        if {"ip", "start", "end"} <= event.keys():
                            events.append(event)
                    except (json.JSONDecodeError, TypeError):
                        continue
        except FileNotFoundError:
            print(
                f"[PING TESTE] Arquivo de bloqueios não encontrado: "
                f"{self._block_events_path}. Verifique se o controlador está ativo "
                "e se ambos os processos usam o mesmo caminho.",
                flush=True,
            )
        return events

    def _finalize_command(self, command: dict) -> None:
        """Classifica uma execução uma única vez, sincronizando as threads."""
        with self._lock:
            if command["finalized"]:
                return

            if command["finalizing"]:
                event = command["finalization_event"]
                is_owner = False
            else:
                command["finalizing"] = True
                command["ended_at"] = time.monotonic()
                event = command["finalization_event"]
                is_owner = True

        if not is_owner:
            event.wait()
            # Se a thread responsável falhou, tenta novamente.
            return self._finalize_command(command)

        try:
            events = self._read_block_events()
            started = command["started_at"]
            ended = command["ended_at"]
            source_ip = command["source_ip"]

            was_blocked = any(
                item["ip"] == source_ip
                and item["start"] <= ended
                and item["end"] >= started
                for item in events
            )

            with self._lock:
                command["result"] = "bloqueadas" if was_blocked else "normais"
                command["finalized"] = True
                command["finalizing"] = False

        except Exception:
            with self._lock:
                command["finalizing"] = False
            raise

        finally:
            event.set()

    def wait_for_all(self) -> None:
        """Espera todos os comandos iniciados, inclusive os de grupos anteriores."""
        with self._lock:
            commands = list(self._commands)
        for command in commands:
            command["process"].wait()
            self._finalize_command(command)

    def export_results(self) -> None:
        """Exporta uma linha por origem com contagem de comandos ping."""
        with self._lock:
            if self._exported:
                return
            commands = [
                c for c in self._commands
                if c["finalized"] and "result" in c
            ]

        totals = defaultdict(lambda: {"normais": 0, "bloqueadas": 0})
        for command in commands:
            totals[(command["source"], command["source_ip"])][command["result"]] += 1

        self._csv_path.parent.mkdir(parents=True, exist_ok=True)
        with self._csv_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["Origem", "IP", "Normais", "Bloqueadas", "Total"])
            for (source, source_ip), values in sorted(totals.items()):
                normal = values["normais"]
                blocked = values["bloqueadas"]
                writer.writerow([source, source_ip, normal, blocked, normal + blocked])

        with self._lock:
            self._exported = True

        print(
            f"[PING TESTE] CSV exportado: {self._csv_path.resolve()} "
            f"({len(commands)} comandos contabilizados).",
            flush=True,
        )

    def stop_all(self) -> None:
        with self._lock:
            groups = list(self._groups.values())
            self._groups.clear()
        for commands in groups:
            self._terminate_commands(commands)
            for command in commands:
                self._finalize_command(command)

    def Normal(self, Group: int, cont: int) -> int:
        """Tráfego normal: cinco hosts, cada um com 80% de chance."""
        for i in range(Group * 5 + 1, Group * 5 + 6):
            if rd.random() < 0.8:
                src = f"h{i}"
                self.start_pings(
                    group=f"N{i}{cont}",
                    sources=[src],
                    destination="h25",
                    interval=rd.uniform(0.05, 0.12),
                    count=rd.randint(200, 300),
                    packet_size=rd.randint(50, 85),
                )
                self.wait(rd.uniform(1.5, 2.5))
        return 0 if Group == 1 else 1

    def AtaqDos(self, cont: int) -> None:
        """DoS: hosts 11 e 12, cada um com 80% de chance."""
        for i in range(11, 13):
            if rd.random() < 0.8:
                self.start_pings(
                    group=f"D{i}{cont}",
                    sources=[f"h{i}"],
                    destination="h25",
                    interval=rd.uniform(0.01, 0.04),
                    count=rd.randint(500, 700),
                    packet_size=rd.randint(50, 125),
                )
                self.wait(rd.uniform(1.5, 2.5))

    def AtaqDDos(self, cont: int) -> None:
        """DDoS: hosts 13 a 24, cada um com 80% de chance."""
        for i in range(13, 25):
            if rd.random() < 0.8:
                self.start_pings(
                    group=f"DD{i}{cont}",
                    sources=[f"h{i}"],
                    destination="h25",
                    interval=rd.uniform(0.02, 0.05),
                    count=rd.randint(200, 300),
                    packet_size=rd.randint(50, 85),
                )
                self.wait(rd.uniform(0.1, 0.5))

    def main(self) -> None:
        """Executa os cenários com probabilidades de 80%, 10% e 10%."""
        cont = 0
        grupo = self.Normal(0, cont)
        cont += 1
        grupo = self.Normal(grupo, cont)
        cont += 1

        while cont < 50:
            tipo = rd.choices(
                ["normal", "dos", "ddos"],
                weights=[60, 20, 20],
                k=1,
            )[0]
            if tipo == "normal":
                grupo = self.Normal(grupo, cont)
            elif tipo == "dos":
                self.AtaqDos(cont)
            else:
                self.AtaqDDos(cont)
            cont += 1
            self.wait(rd.uniform(2, 4))

    def start(self, net) -> None:
        if self._thread and self._thread.is_alive():
            raise RuntimeError("O cenário já está em execução.")
        self.net = net
        self._stop_event.clear()
        self._exported = False
        self._commands.clear()
        self._groups.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            self.main()
            self.wait_for_all()
        except InterruptedError:
            print("[PING TESTE] Cenário interrompido.", flush=True)
        except Exception as error:
            print(f"[PING TESTE] Erro no cenário: {error}", flush=True)
        finally:
            self.stop_all()
            self.export_results()

    def stop(self) -> None:
        """Interrompe os pings e aguarda a thread exportar o CSV ao finalizar."""
        self._stop_event.set()
        self.stop_all()

        if self._thread and self._thread.is_alive():
            # A thread executa stop_all() e export_results() no finally de _run.
            # Esperar sua conclusão evita exportar antes da finalização dos comandos.
            self._thread.join()
        else:
            self.export_results()
