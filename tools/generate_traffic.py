#!/usr/bin/env python3
"""Generate controlled TCP/UDP traffic for experiments in a Mininet lab.

Run this script inside a Mininet host namespace. Use --server on the
destination host and omit it on client hosts.
"""
import argparse
import socket
import threading
import time


def serve_tcp(host, port, stop):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen()
        server.settimeout(1)
        print(f"[SERVER] TCP listening on {host}:{port}", flush=True)
        while not stop.is_set():
            try:
                conn, address = server.accept()
            except socket.timeout:
                continue
            threading.Thread(target=read_connection, args=(conn, address), daemon=True).start()


def read_connection(conn, address):
    with conn:
        while conn.recv(65536):
            pass


def serve_udp(host, port, stop):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((host, port))
        server.settimeout(1)
        print(f"[SERVER] UDP listening on {host}:{port}", flush=True)
        while not stop.is_set():
            try:
                server.recvfrom(65535)
            except socket.timeout:
                continue


def tcp_worker(dst, port, payload, duration, interval, start_event, errors, connected):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(15)
            sock.connect((dst, port))
            connected.append(1)
            start_event.wait()
            deadline = time.monotonic() + duration
            while time.monotonic() < deadline:
                sock.sendall(payload)
                if interval:
                    time.sleep(interval)
    except OSError as exc:
        errors.append(str(exc))


def udp_worker(dst, port, payload, duration, interval, start_event, errors):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((dst, port))
            start_event.wait()
            deadline = time.monotonic() + duration
            while time.monotonic() < deadline:
                sock.send(payload)
                if interval:
                    time.sleep(interval)
    except OSError as exc:
        errors.append(str(exc))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", action="store_true", help="run a TCP/UDP sink")
    parser.add_argument("--protocol", choices=("tcp", "udp"), default="tcp")
    parser.add_argument("--bind", default="0.0.0.0", help="server bind address")
    parser.add_argument("--dst", help="destination IP for client mode")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--flows", type=int, default=10, help="number of client sockets/flows")
    parser.add_argument("--duration", type=float, default=10, help="seconds to send traffic")
    parser.add_argument("--payload-size", type=int, default=1200, help="bytes per send (1..60000)")
    parser.add_argument("--interval", type=float, default=0.01, help="seconds between sends per flow; 0 sends as fast as possible")
    args = parser.parse_args()

    if not 1 <= args.payload_size <= 60000:
        parser.error("--payload-size must be between 1 and 60000")
    if args.port < 1 or args.port > 65535:
        parser.error("--port must be between 1 and 65535")
    if args.server:
        stop = threading.Event()
        try:
            if args.protocol == "tcp":
                serve_tcp(args.bind, args.port, stop)
            else:
                serve_udp(args.bind, args.port, stop)
        except KeyboardInterrupt:
            pass
        return
    if not args.dst:
        parser.error("--dst is required in client mode")
    if args.flows < 1 or args.duration <= 0 or args.interval < 0:
        parser.error("--flows and --duration must be positive; --interval cannot be negative")

    payload = b"x" * args.payload_size
    start_event = threading.Event()
    errors = []
    connected = []
    worker = tcp_worker if args.protocol == "tcp" else udp_worker
    threads = [
        threading.Thread(
            target=worker,
            args=(args.dst, args.port, payload, args.duration, args.interval, start_event, errors, connected)
            if args.protocol == "tcp"
            else (args.dst, args.port, payload, args.duration, args.interval, start_event, errors),
            daemon=True,
        )
        for _ in range(args.flows)
    ]
    for thread in threads:
        thread.start()
    # Let TCP connections establish before starting the timed send period.
    time.sleep(0.2)
    started = time.monotonic()
    start_event.set()
    for thread in threads:
        thread.join()
    elapsed = time.monotonic() - started
    print(
        f"[CLIENT] protocol={args.protocol} destination={args.dst}:{args.port} "
        f"flows={args.flows} established={len(connected) if args.protocol == \"tcp\" else args.flows} "
        f"payload={args.payload_size}B duration={elapsed:.2f}s",
        flush=True,
    )
    if errors:
        for error in sorted(set(errors)):
            print(f"[ERROR] {error}", flush=True)


if __name__ == "__main__":
    main()
