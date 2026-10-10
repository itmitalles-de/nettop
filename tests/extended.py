#!/usr/bin/env python3
"""Real sub-poll-interval TCP/UDP attribution; explicitly isolated QEMU/KVM only.

Usage: sudo python3 tests/extended.py --isolated-vm /path/to/nwtop
The binary must include the ebpf feature. No host tracing is permitted.
"""
import argparse
import json
import multiprocessing as mp
import os
from pathlib import Path
import select
import signal
import socket
import statistics
import subprocess
import tempfile
import time

PAYLOAD = b"n" * 4096
REPLY = b"r" * 1024


def exact(connection, size):
    data = bytearray()
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise AssertionError("unexpected EOF")
        data.extend(part)
    return bytes(data)


def receiver(family, kind, count, control, finished, exit_early, udp_receive_mode):
    address = "127.0.0.1" if family == socket.AF_INET else "::1"
    with socket.socket(family, kind) as listener:
        listener.settimeout(5)
        listener.bind((address, 0))
        if kind == socket.SOCK_STREAM:
            listener.listen(16)
            control.send(listener.getsockname()[1])
            for _ in range(count):
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5)
                    assert exact(connection, len(PAYLOAD)) == PAYLOAD
                    connection.sendall(REPLY)
        else:
            # Rotate both endpoints so neither can be found by polling later.
            listener.close()
            for _ in range(count):
                with socket.socket(family, kind) as datagram:
                    datagram.settimeout(5)
                    datagram.bind((address, 0))
                    control.send(datagram.getsockname()[1])
                    if udp_receive_mode == "read":
                        # Python's timeout socket uses a nonblocking fd. Wait
                        # for readability before the real peerless read(2).
                        assert select.select([datagram], [], [], 5)[0], "UDP read timed out"
                        data = os.read(datagram.fileno(), 8192)
                    elif udp_receive_mode == "recv":
                        data = datagram.recv(8192)
                    else:
                        data, peer = datagram.recvfrom(8192)
                    assert data == PAYLOAD
                    if udp_receive_mode == "recvfrom":
                        assert datagram.sendto(REPLY, peer) == len(REPLY)
    control.send("finished")
    if not exit_early:
        finished.wait(15)


def wait_capture(monitor):
    """Wait for the process's own packet socket, not a fixed one-second gap."""
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        assert monitor.poll() is None, "monitor exited before capture was ready"
        try:
            handles = [os.readlink(p) for p in Path(f"/proc/{monitor.pid}/fd").iterdir()]
            packet_inodes = {
                line.split()[-1] for line in Path("/proc/net/packet").read_text().splitlines()[1:]
            }
            capture = any(h.startswith("socket:[") and h[8:-1] in packet_inodes for h in handles)
            if capture:
                assert any("bpf-link" in h or "bpf_link" in h for h in handles), "no attached optional socket events"
                # pcap configuration finishes immediately after opening the
                # socket. Stay well inside the historical first-second gap.
                time.sleep(0.05)
                return
        except (FileNotFoundError, ProcessLookupError):
            pass
        time.sleep(0.005)
    raise AssertionError("capture startup did not finish")


def run_case(binary, family, kind, exit_early=False, udp_receive_mode="recvfrom"):
    peerless = udp_receive_mode != "recvfrom"
    label = ("IPv4" if family == socket.AF_INET else "IPv6") + " " + (
        "TCP" if kind == socket.SOCK_STREAM else "UDP"
    ) + (" exited receiver" if exit_early else "") + (
        f" receive-only {udp_receive_mode} All" if peerless else ""
    )
    count = 60 if kind == socket.SOCK_STREAM else 200
    parent, child = mp.Pipe()
    finished = mp.Event()
    server = mp.Process(target=receiver, args=(family, kind, count, child, finished, exit_early, udp_receive_mode))
    monitor = None
    try:
        with tempfile.TemporaryDirectory(prefix="nwtop-extended-") as config:
            env = dict(os.environ, XDG_CONFIG_HOME=config)
            monitor = subprocess.Popen(
                [str(binary), "--interface", "all" if peerless else "lo", "--json", "--interval", "5"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
            )
            wait_capture(monitor)
            server.start()
            child.close()
            address = "127.0.0.1" if family == socket.AF_INET else "::1"
            durations = []
            tcp_port = None
            if kind == socket.SOCK_STREAM:
                assert parent.poll(5), f"{label}: listener did not bind"
                tcp_port = parent.recv()
            for _ in range(count):
                port = tcp_port
                if kind == socket.SOCK_DGRAM:
                    assert parent.poll(5), f"{label}: datagram receiver did not bind"
                    port = parent.recv()
                started = time.monotonic()
                with socket.socket(family, kind) as sender:
                    sender.settimeout(5)
                    if kind == socket.SOCK_STREAM:
                        sender.connect((address, port))
                        sender.sendall(PAYLOAD)
                        assert exact(sender, len(REPLY)) == REPLY
                    else:
                        # Exercise unconnected sendto and recvfrom metadata.
                        assert sender.sendto(PAYLOAD, (address, port)) == len(PAYLOAD)
                        if not peerless:
                            data, _ = sender.recvfrom(8192)
                            assert data == REPLY
                durations.append(time.monotonic() - started)
            assert parent.poll(5) and parent.recv() == "finished", f"{label}: receiver failed"
            if exit_early:
                server.join(timeout=3)
                assert server.exitcode == 0, f"{label}: receiver did not exit cleanly"
                assert not Path(f"/proc/{server.pid}").exists(), "receiver was not reaped"
            stdout, stderr = monitor.communicate(timeout=15)
            assert monitor.returncode == 0, f"{label}: {stderr}"
            snapshot = json.loads(stdout)
            capture = snapshot["capture"]
            notes = capture.get("notes", [])
            issues = [n for n in notes if n.get("code") == "extended_issue"]
            rows = {r["pid"]: r for r in snapshot["processes"]}
            expected = {
                (os.getpid(), "tx_bytes"): count * len(PAYLOAD),
                (server.pid, "rx_bytes"): count * len(PAYLOAD),
            }
            if not peerless:
                expected.update({
                    (os.getpid(), "rx_bytes"): count * len(REPLY),
                    (server.pid, "tx_bytes"): count * len(REPLY),
                })
            measured = {f"{pid}:{field}": rows.get(pid, {}).get(field, 0)
                        for pid, field in expected}
            print(json.dumps({"case": label, "connections": count,
                              "median_lifetime_ms": statistics.median(durations) * 1000,
                              "max_lifetime_ms": max(durations) * 1000,
                              "process_ip_bytes": measured,
                              "unattributed": rows.get(None, {}), "capture": capture}), flush=True)
            assert capture["active"] and capture["dropped"] == 0, f"{label}: {capture}"
            assert any(n.get("code") == "extended" for n in notes), f"{label}: {capture}"
            if peerless:
                assert any(n.get("code") == "all_socket_packets" for n in notes), capture
                assert not issues, f"{label}: {issues}"
                # No reply/sendto can supply a known-peer server event and
                # mask missing read/recv actors. Both directions count IP bytes
                # exactly; each UDP datagram has one ordinary IP+UDP header.
                ip_header = 20 if family == socket.AF_INET else 40
                ip_bytes = count * (len(PAYLOAD) + ip_header + 8)
                assert rows.get(server.pid, {}).get("rx_bytes", 0) == ip_bytes, rows
                assert rows.get(server.pid, {}).get("tx_bytes", 0) == 0, rows
                assert rows.get(os.getpid(), {}).get("tx_bytes", 0) == ip_bytes, rows
            # Closed TCP sockets can leave control packets outside the proven
            # ownership window. An untracked loopback flow must report that
            # limitation; accept only this precise notice and a bounded tail.
            if issues:
                missing_conntrack = (
                    "no confirmed conntrack entry for some flows; "
                    "only positive socket events can attribute them"
                )
                unknown = rows.get(None, {})
                assert kind == socket.SOCK_STREAM, f"{label}: {issues}"
                assert all(n.get("detail") == missing_conntrack for n in issues), (
                    f"{label}: optional attribution degraded: {issues}"
                )
                assert sum(unknown.get(f, 0) for f in ("rx_bytes", "tx_bytes")) > 0
                assert all(unknown.get(f, 0) <= count * 1024
                           for f in ("rx_bytes", "tx_bytes")), f"{label}: {unknown}"
            for (pid, field), payload in expected.items():
                value = rows.get(pid, {}).get(field, 0)
                assert value >= payload, f"{label}: PID {pid} {field} {value} < payload {payload}"
                assert value < payload * 1.9, f"{label}: duplicate count suspected: {field} {value}"
            # Scheduling outliers are possible; the median socket must still
            # finish an order of magnitude faster than the 250 ms polling tick.
            assert statistics.median(durations) < 0.025, f"{label}: test sockets were too slow"
    finally:
        finished.set()
        if monitor is not None and monitor.poll() is None:
            monitor.terminate()
            try:
                monitor.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                monitor.kill()
                monitor.communicate(timeout=3)
        if server.pid is not None:
            server.join(timeout=3)
            if server.is_alive():
                server.terminate()
                server.join(timeout=3)
        parent.close()
        child.close()


def run_burst(binary):
    """Cross libbpf's callback batch limit without overflowing packet queues."""
    count = 2500
    payload = b"b" * 32
    with tempfile.TemporaryDirectory(prefix="nwtop-event-burst-") as config:
        monitor = subprocess.Popen(
            [str(binary), "--json", "--interface", "lo", "--interval", "5"],
            env=dict(os.environ, XDG_CONFIG_HOME=config, LANG="C"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        stopped = False
        try:
            wait_capture(monitor)
            # The root monitor owns its collector and BPF links in process.
            # Stop every consumer while the attached kernel producers continue.
            os.kill(monitor.pid, signal.SIGSTOP)
            stopped = True
            deadline = time.monotonic() + 2
            states = []
            while time.monotonic() < deadline:
                states = [(task / "status").read_text().split("State:", 1)[1].splitlines()[0]
                          for task in Path(f"/proc/{monitor.pid}/task").iterdir()]
                if states and all("T" in state for state in states):
                    break
                time.sleep(0.001)
            assert states and all("T" in state for state in states), states
            started = time.monotonic()
            # At least 5000 metadata records, exceeding the 2048-event callback
            # batch but well below the 4 MiB ring. No pcap or conntrack traffic.
            for _ in range(count):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                    datagram.bind(("127.0.0.1", 0))
            duration = time.monotonic() - started
            os.kill(monitor.pid, signal.SIGCONT)
            stopped = False
            time.sleep(0.15)
            with (socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver,
                  socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender):
                receiver.bind(("127.0.0.1", 0))
                receiver.settimeout(2)
                assert sender.sendto(payload, receiver.getsockname()) == len(payload)
                assert receiver.recvfrom(1024)[0] == payload
            stdout, stderr = monitor.communicate(timeout=12)
            assert monitor.returncode == 0, stderr
            snapshot = json.loads(stdout)
            rows = {row["pid"]: row for row in snapshot["processes"]}
            own = rows.get(os.getpid(), {})
            capture = snapshot["capture"]
            expected = len(payload) + 28
            print(json.dumps({"case": "metadata ring burst", "metadata_only_sockets": count,
                              "minimum_queued_events": count * 2, "burst_seconds": duration,
                              "expected_ip_bytes_each_direction": expected, "process": own,
                              "unattributed": rows.get(None, {}), "capture": capture}), flush=True)
            assert capture["active"] and capture["dropped"] == 0, capture
            notes = capture.get("notes", [])
            assert any(note.get("code") == "extended" for note in notes), capture
            assert not any(note.get("code") == "extended_issue" for note in notes), capture
            assert own.get("rx_bytes") == expected and own.get("tx_bytes") == expected, own
        finally:
            if monitor.poll() is None:
                if stopped:
                    os.kill(monitor.pid, signal.SIGCONT)
                monitor.terminate()
                try:
                    monitor.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    monitor.kill()
                    monitor.communicate()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-vm", action="store_true", required=True)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--case", choices=["all", "tcp4", "tcp6", "udp4", "udp6", "exited", "burst", "peerless"], default="all")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run as root only inside the dedicated test VM")
    virtualization = subprocess.run(["systemd-detect-virt", "--vm"], capture_output=True, text=True)
    if virtualization.returncode != 0 or virtualization.stdout.strip() not in {"qemu", "kvm"}:
        raise SystemExit("refusing kernel tracing outside an explicitly isolated QEMU/KVM VM")
    binary = args.binary.resolve(strict=True)
    for name, family, kind in [
        ("tcp4", socket.AF_INET, socket.SOCK_STREAM),
        ("tcp6", socket.AF_INET6, socket.SOCK_STREAM),
        ("udp4", socket.AF_INET, socket.SOCK_DGRAM),
        ("udp6", socket.AF_INET6, socket.SOCK_DGRAM),
    ]:
        if args.case in {"all", name}:
            run_case(binary, family, kind)
    if args.case in {"all", "exited"}:
        run_case(binary, socket.AF_INET, socket.SOCK_DGRAM, exit_early=True)
    if args.case in {"all", "burst"}:
        run_burst(binary)
    if args.case in {"all", "peerless"}:
        for family in [socket.AF_INET, socket.AF_INET6]:
            for receive_mode in ["read", "recv"]:
                run_case(binary, family, socket.SOCK_DGRAM, udp_receive_mode=receive_mode)
    print("PASS optional socket attribution", flush=True)


if __name__ == "__main__":
    main()
