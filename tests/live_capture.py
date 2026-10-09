#!/usr/bin/env python3
"""Verify real per-process TCP/UDP attribution in an isolated Linux namespace.

Run as root with libpcap installed. The sender and receiver are separate PIDs;
both keep their sockets alive until the monitor has completed its sample.
Only loopback, ephemeral ports, and processes owned by this test are used.
"""

import json
import multiprocessing as mp
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def receiver(family, kind, control, finished, expected, dual_stack=False):
    address = "::" if dual_stack else ("127.0.0.1" if family == socket.AF_INET else "::1")
    with socket.socket(family, kind) as listener:
        if dual_stack:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        listener.bind((address, 0))
        if kind == socket.SOCK_STREAM:
            listener.listen(1)
        control.send(listener.getsockname()[1])
        connection = listener
        if kind == socket.SOCK_STREAM:
            connection, _ = listener.accept()
        control.send("ready")
        received = 0
        try:
            while received < expected:
                received += len(connection.recv(65536))
            control.send(received)
            finished.wait(10)
        finally:
            if connection is not listener:
                connection.close()


def run_case(binary, family, kind, dual_stack=False):
    label = ("IPv4" if family == socket.AF_INET else "IPv6") + " " + (
        "TCP" if kind == socket.SOCK_STREAM else "UDP"
    )
    if dual_stack:
        label += " to dual-stack IPv6 wildcard"
    payload = b"n" * 1024
    packets = 128
    expected = len(payload) * packets
    parent, child = mp.Pipe()
    finished = mp.Event()
    receiver_family = socket.AF_INET6 if dual_stack else family
    server = mp.Process(
        target=receiver,
        args=(receiver_family, kind, child, finished, expected, dual_stack),
    )
    server.start()
    child.close()
    monitor = None
    try:
        assert parent.poll(5), f"{label}: receiver did not bind"
        port = parent.recv()
        address = "127.0.0.1" if family == socket.AF_INET else "::1"
        with socket.socket(family, kind) as sender:
            sender.connect((address, port))
            assert parent.poll(5) and parent.recv() == "ready", f"{label}: receiver not ready"
            monitor = subprocess.Popen(
                [str(binary), "--interface", "lo", "--json", "--interval", "1.5"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            # Allow startup and the initial socket inventory to complete.
            time.sleep(0.35)
            for _ in range(packets):
                if kind == socket.SOCK_STREAM:
                    sender.sendall(payload)
                else:
                    sender.send(payload)
                time.sleep(0.002)
            assert parent.poll(5), f"{label}: receiver did not consume the payload"
            assert parent.recv() == expected
            output, errors = monitor.communicate(timeout=10)
            assert monitor.returncode == 0, f"{label}: monitor failed: {errors}"
            snapshot = json.loads(output)
            assert snapshot["capture"]["active"], f"{label}: {snapshot['capture']}"
            assert snapshot["capture"]["dropped"] == 0, f"{label}: capture dropped packets"
            rows = {row["pid"]: row for row in snapshot["processes"]}
            assert os.getpid() in rows, f"{label}: sender PID was not attributed"
            assert server.pid in rows, f"{label}: receiver PID was not attributed"
            sent = rows[os.getpid()]["tx_bytes"]
            received = rows[server.pid]["rx_bytes"]
            assert sent >= expected, f"{label}: sender TX {sent} < payload {expected}"
            assert received >= expected, f"{label}: receiver RX {received} < payload {expected}"
            # Detect loopback double counting without assuming exact TCP segmentation.
            assert sent < expected * 1.8, f"{label}: sender appears double counted: {sent}"
            assert received < expected * 1.8, f"{label}: receiver appears double counted: {received}"
            assert rows[os.getpid()]["tx_rate"] > 0
            assert rows[server.pid]["rx_rate"] > 0
            assert any(row["protocol"] == ("TCP" if kind == socket.SOCK_STREAM else "UDP")
                       and row["pid"] == server.pid for row in snapshot["connections"])
            interface = next(row for row in snapshot["interfaces"] if row["name"] == "lo")
            assert interface["rx_rate"] > 0 and interface["tx_rate"] > 0
            print(f"PASS {label}: {expected} payload bytes; TX {sent}, RX {received} IP bytes")
    finally:
        finished.set()
        if monitor is not None and monitor.poll() is None:
            monitor.kill()
            monitor.communicate()
        server.join(timeout=3)
        if server.is_alive():
            server.terminate()
            server.join()
        parent.close()


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run this integration test as root in an isolated test container.")
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 tests/live_capture.py /absolute/path/to/nettop")
    binary = Path(sys.argv[1]).resolve(strict=True)
    for family in (socket.AF_INET, socket.AF_INET6):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            run_case(binary, family, kind)
    run_case(binary, socket.AF_INET, socket.SOCK_DGRAM, dual_stack=True)
    print("All live capture checks passed.")


if __name__ == "__main__":
    main()
