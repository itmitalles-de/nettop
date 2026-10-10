#!/usr/bin/env python3
"""Regression: bytes of sockets that close well inside a long refresh interval.

Run as root in the isolated container: python3 tests/short_lived.py /path/to/nettop
"""
import json
import multiprocessing as mp
import os
import socket
import subprocess
import sys
import time

PAYLOAD = b"s" * 65536
CONNECTIONS = 8


def tcp_server(port_pipe, done):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        port_pipe.send(listener.getsockname()[1])
        total = 0
        for _ in range(CONNECTIONS):
            connection, _ = listener.accept()
            with connection:
                while True:
                    data = connection.recv(65536)
                    if not data:
                        break
                    total += len(data)
        port_pipe.send(total)
        done.wait(40)


def udp_server(port_pipe, done):
    total = 0
    for _ in range(CONNECTIONS):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port_pipe.send(sock.getsockname()[1])
            received = 0
            while received < 8 * 1024:
                received += len(sock.recv(65536))
            total += received
            port_pipe.send("ok")
    port_pipe.send(total)
    done.wait(40)


def main():
    binary = sys.argv[1]
    done = mp.Event()
    tcp_parent, tcp_child = mp.Pipe()
    udp_parent, udp_child = mp.Pipe()
    tcp = mp.Process(target=tcp_server, args=(tcp_child, done))
    udp = mp.Process(target=udp_server, args=(udp_child, done))
    tcp.start()
    tcp_port = tcp_parent.recv()
    monitor = subprocess.Popen([binary, "--interface", "lo", "--json", "--interval", "20"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # Let pcap activation and the first attribution pass finish: sockets that
    # open and close before nettop's first pass are a known startup gap.
    time.sleep(2.0)
    udp.start()
    for _ in range(CONNECTIONS):
        # New client socket per connection: lives ~0.85 s, longer than one
        # 250-500 ms attribution pass, and is closed long before the sample.
        with socket.socket() as client:
            client.connect(("127.0.0.1", tcp_port))
            time.sleep(0.8)
            client.sendall(PAYLOAD)
            time.sleep(0.05)
        port = udp_parent.recv()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.connect(("127.0.0.1", port))
            # Longer than one 250-500 ms attribution pass.
            time.sleep(0.8)
            for _ in range(8):
                client.send(b"u" * 1024)
            assert udp_parent.recv() == "ok"
    tcp_total = tcp_parent.recv()
    udp_total = udp_parent.recv()
    output, errors = monitor.communicate(timeout=40)
    done.set()
    tcp.join()
    udp.join()
    assert monitor.returncode == 0, errors
    snapshot = json.loads(output)
    rows = {row["pid"]: row for row in snapshot["processes"]}
    def rx(pid):
        return rows.get(pid, {}).get("rx_bytes", 0)
    def tx(pid):
        return rows.get(pid, {}).get("tx_bytes", 0)
    unknown = rows.get(None, {})
    print(f"TCP server rx {rx(tcp.pid)} of payload {tcp_total}; UDP server rx {rx(udp.pid)} of {udp_total}; "
          f"client tx {tx(os.getpid())}; unattributed rx {unknown.get('rx_bytes', 0)} tx {unknown.get('tx_bytes', 0)}")
    print("capture:", snapshot["capture"])
    ok = rx(tcp.pid) >= tcp_total and rx(udp.pid) >= udp_total and tx(os.getpid()) >= tcp_total + udp_total
    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
