#!/usr/bin/env python3
"""Bounded packet-load regression; run only in an owned QEMU/KVM guest.

Use --baseline to collect comparable evidence from an older binary. No firewall,
clock, namespace or host configuration changes are made by this test.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from extended import wait_capture


def run(args, count):
    with tempfile.TemporaryDirectory(prefix="nettop-pressure-") as config:
        monitor = subprocess.Popen(
            [str(args.binary), "--json", "--interface", "lo", "--interval", "8"],
            env=dict(os.environ, XDG_CONFIG_HOME=config, LANG="C"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        peak_rss = 0
        try:
            wait_capture(monitor)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender, \
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
                receiver.bind(("127.0.0.1", 0))
                receiver.settimeout(2)
                sender.connect(receiver.getsockname())
                time.sleep(.5)
                started = time.monotonic()
                payload = b"q" * 256
                for number in range(count):
                    assert sender.send(payload) == len(payload)
                    assert len(receiver.recv(1024)) == len(payload)
                    if number % 256 == 0:
                        status = Path(f"/proc/{monitor.pid}/status").read_text()
                        peak_rss = max(peak_rss, int(status.split("VmRSS:")[1].split()[0]))
                duration = time.monotonic() - started
                stdout, stderr = monitor.communicate(timeout=20)
            assert monitor.returncode == 0, stderr
            snapshot = json.loads(stdout)
            capture = snapshot["capture"]
            assert capture["active"], capture
            notes = capture.get("notes", [])
            own = next((r for r in snapshot["processes"] if r["pid"] == os.getpid()), {})
            expected = count * (len(payload) + 28)
            for direction in ("rx", "tx"):
                credited = own.get(direction + "_bytes", 0)
                assert credited <= expected, (direction, credited, expected, "duplicate bytes")
                accounted = sum(row[direction + "_bytes"] for row in snapshot["processes"])
                assert accounted <= expected + 4096, (direction, accounted, expected, "duplicate total")
                if not capture["dropped"]:
                    assert accounted >= expected * .9, (direction, accounted, expected, "missing bytes")
            assert peak_rss < 256 * 1024, ("unbounded resident memory", peak_rss)
            if not args.baseline:
                assert all(n["code"] != "flow_limit" for n in notes), "ambiguous legacy pressure notice"
            record = dict(packets=count, ip_bytes_each_direction=expected,
                          seconds=duration, packets_per_second=count / duration,
                          peak_rss_kib=peak_rss, capture=capture,
                          total_rx_bytes=sum(r["rx_bytes"] for r in snapshot["processes"]),
                          total_tx_bytes=sum(r["tx_bytes"] for r in snapshot["processes"]),
                          rx_bytes=own.get("rx_bytes", 0), tx_bytes=own.get("tx_bytes", 0))
            args.output.mkdir(parents=True, exist_ok=True)
            (args.output / f"pressure-{count}.json").write_text(json.dumps(record, indent=2) + "\n")
            print(json.dumps(record), flush=True)
        finally:
            if monitor.poll() is None:
                monitor.terminate()
                try:
                    monitor.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    monitor.kill()
                    monitor.communicate()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--isolated-vm", action="store_true", required=True)
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--counts", type=int, nargs="+", default=[4096, 20000, 80000])
    args = parser.parse_args()
    assert os.geteuid() == 0
    virt = subprocess.run(["systemd-detect-virt", "--vm"], capture_output=True, text=True)
    assert virt.returncode == 0 and virt.stdout.strip() in {"qemu", "kvm"}, "dedicated VM required"
    args.binary = args.binary.resolve(strict=True)
    for count in args.counts:
        assert 0 < count <= 200000
        run(args, count)


if __name__ == "__main__":
    main()
