#!/usr/bin/env python3
"""Adversarial kernel attribution checks; only inside an owned QEMU/KVM VM."""
import argparse
import array
import contextlib
import json
import multiprocessing as mp
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import tempfile
import time


class Monitor:
    def __init__(self, binary, name, output, interval=4, interface="lo", readiness_delay=0):
        self.name, self.output, self.stopped = name, output, False
        self.config = tempfile.TemporaryDirectory(prefix="nwtop-adversarial-")
        self.process = subprocess.Popen(
            [str(binary), "--json", "--interval", str(interval), "--interface", interface],
            env=dict(os.environ, XDG_CONFIG_HOME=self.config.name, LANG="C"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(readiness_delay)
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                assert self.process.poll() is None, "monitor exited during startup"
                try:
                    handles = [os.readlink(p) for p in Path(f"/proc/{self.process.pid}/fd").iterdir()]
                    packets = {line.split()[-1] for line in Path("/proc/net/packet").read_text().splitlines()[1:]}
                    if any(h.startswith("socket:[") and h[8:-1] in packets for h in handles):
                        assert any("bpf_link" in h or "bpf-link" in h for h in handles), "BPF links missing"
                        time.sleep(.05)
                        return
                except FileNotFoundError:
                    pass
                time.sleep(.02)
            raise AssertionError("capture did not become ready")
        except BaseException:
            self.close()
            raise

    def freeze(self):
        os.kill(self.process.pid, signal.SIGSTOP)
        self.stopped = True
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            states = [(t / "status").read_text().split("State:")[1].splitlines()[0]
                      for t in Path(f"/proc/{self.process.pid}/task").iterdir()]
            if states and all("T" in state for state in states):
                return
            time.sleep(.001)
        raise AssertionError("monitor threads did not stop")

    def resume(self):
        if self.stopped:
            os.kill(self.process.pid, signal.SIGCONT)
            self.stopped = False

    def finish(self, details):
        self.resume()
        stdout, stderr = self.process.communicate(timeout=30)
        assert self.process.returncode == 0, stderr
        snapshot = json.loads(stdout)
        record = {"case": self.name, "details": details, "snapshot": snapshot}
        if self.output:
            self.output.mkdir(parents=True, exist_ok=True)
            (self.output / f"{self.name}.json").write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps(record), flush=True)
        capture = snapshot["capture"]
        assert capture["active"], capture
        assert any(n["code"] == "extended" for n in capture.get("notes", [])), capture
        return {row["pid"]: row for row in snapshot["processes"]}, capture

    def close(self):
        self.resume()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate()
        self.config.cleanup()


@contextlib.contextmanager
def monitor(args, name, interval=4):
    value = Monitor(args.binary, name, args.output, interval, args.interface, args.readiness_delay)
    try:
        yield value
    finally:
        value.close()


def amount(rows, pid, direction):
    return rows.get(pid, {}).get(direction + "_bytes", 0)


def notes(capture):
    return " ".join(n.get("detail", n["code"]) for n in capture.get("notes", []))


def clean_capture(capture, allow_clock=False):
    assert capture["dropped"] == 0, capture
    for note in capture.get("notes", []):
        if note["code"] == "extended_issue":
            assert allow_clock and "packet timestamps unavailable; uncertain event owners withheld" in note.get("detail", ""), capture


def udp_accounting(args, rows, size, rx_actors, tx_actors):
    if args.interface == "all":
        # Background SSH is legitimate; bound only this fixture's actual actors.
        for direction, actors in (("rx", rx_actors), ("tx", tx_actors)):
            assert sum(amount(rows, pid, direction) for pid in actors | {None}) >= size, (direction, rows)
            assert sum(amount(rows, pid, direction) for pid in actors) <= size, (direction, rows)
        return
    for direction, actors in (("rx", rx_actors), ("tx", tx_actors)):
        assert sum(row[direction + "_bytes"] for row in rows.values()) == size, (direction, rows)
        for pid, row in rows.items():
            assert pid in actors | {None} or row[direction + "_bytes"] == 0, (direction, row)


def reap(process):
    process.join(timeout=2)
    if process.is_alive():
        process.terminate()
        process.join(timeout=2)
    assert not process.is_alive(), "owned child survived cleanup"


def hold(ready, release):
    ready.send(os.getpid())
    release.wait(15)


def fork_case(args):
    with monitor(args, "fork") as mon, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(("127.0.0.1", 0))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            parent, child = mp.Pipe()
            release = mp.Event()
            worker = mp.Process(target=hold, args=(child, release))
            worker.start()
            try:
                assert parent.poll(5)
                inherited_pid = parent.recv()
                for _ in range(32):
                    sender.sendto(b"f" * 1024, receiver.getsockname())
                    assert len(receiver.recvfrom(2048)[0]) == 1024
                rows, capture = mon.finish({"actor": os.getpid(), "passive_holder": inherited_pid})
                clean_capture(capture)
                assert amount(rows, inherited_pid, "rx") == amount(rows, inherited_pid, "tx") == 0
                udp_accounting(args, rows, 32 * 1052, {os.getpid()}, {os.getpid()})
            finally:
                release.set()
                reap(worker)
                parent.close()
                child.close()


def passed_receiver(channel, report, release, active):
    data, ancdata, _, _ = channel.recvmsg(1, socket.CMSG_SPACE(array.array("i").itemsize))
    assert data == b"f"
    descriptors = array.array("i")
    for level, kind, content in ancdata:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors.frombytes(content[:len(content) - len(content) % descriptors.itemsize])
    assert len(descriptors) == 1
    with socket.socket(fileno=descriptors[0]) as receiver:
        receiver.settimeout(3)
        if active:
            assert len(receiver.recvfrom(2048)[0]) == 1024
        report.send(os.getpid())
        release.wait(15)


def passed_case(args):
    with monitor(args, "scm-rights") as mon:
        release = mp.Event()
        workers, channels, reports = [], [], []
        try:
            for active in (False, True):
                left, right = socket.socketpair()
                parent, child = mp.Pipe()
                worker = mp.Process(target=passed_receiver, args=(right, child, release, active))
                worker.start()
                workers.append(worker)
                channels.append(left)
                reports.append(parent)
                right.close()
                child.close()
            # Create after both forks: descriptors reach children only via SCM_RIGHTS.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                receiver.bind(("127.0.0.1", 0))
                sender.sendto(b"p" * 1024, receiver.getsockname())
                assert select.select([receiver], [], [], 2)[0]
                for channel in channels:
                    channel.sendmsg([b"f"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [receiver.fileno()]))])
            assert all(report.poll(5) for report in reports)
            passive, recipient = [report.recv() for report in reports]
            rows, capture = mon.finish({"sender_and_original_holder": os.getpid(), "actual_reader": recipient,
                                        "passive_holder": passive, "packet_queued_before_descriptor_transfer": True})
            clean_capture(capture)
            # Attribution describes a positively observed actor, not historical FD ownership.
            assert amount(rows, passive, "rx") == amount(rows, passive, "tx") == 0
            assert amount(rows, recipient, "tx") == 0
            assert amount(rows, os.getpid(), "rx") == 0, "queued RX credited to historical FD holder"
            assert amount(rows, recipient, "rx") <= 1052
            udp_accounting(args, rows, 1052, {recipient}, {os.getpid()})
        finally:
            release.set()
            for worker in workers:
                reap(worker)
            for channel in channels + reports:
                channel.close()


def reuse_receiver(port, channel, release):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        receiver.bind(("127.0.0.1", port))
        channel.send(receiver.getsockname()[1])
        assert channel.recv() == "inspect"
        channel.send(bool(select.select([receiver], [], [], 1)[0]))
        release.wait(15)  # Deliberately never read the queued datagrams.


def reuseport_case(args):
    with monitor(args, "reuseport-unread") as mon:
        releases, workers, channels = [], [], []
        port = 0
        try:
            for _ in range(2):
                parent, child = mp.Pipe()
                release = mp.Event()
                worker = mp.Process(target=reuse_receiver, args=(port, child, release))
                worker.start()
                releases.append(release)
                workers.append(worker)
                channels.append(parent)
                assert parent.poll(5)
                port = parent.recv()
                child.close()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                for _ in range(16):
                    sender.sendto(b"r" * 1024, ("127.0.0.1", port))
            for channel in channels:
                channel.send("inspect")
            queued = [channel.recv() for channel in channels]
            assert sum(queued) == 1, queued
            wrong = workers[queued.index(False)].pid
            correct = workers[queued.index(True)].pid
            rows, capture = mon.finish({"actual_queued_receiver": correct, "other_reuseport_pid": wrong,
                                        "packets_never_read": 16})
            clean_capture(capture)
            assert amount(rows, wrong, "rx") == 0, "credited unrelated reuseport receiver"
            udp_accounting(args, rows, 16 * 1052, {correct}, {os.getpid()})
        finally:
            for release in releases:
                release.set()
            for worker in workers:
                reap(worker)
            for channel in channels:
                channel.close()


def one_datagram(size=1024):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(2)
        sender.sendto(b"x" * size, receiver.getsockname())
        assert len(receiver.recvfrom(size + 1)[0]) == size


def overflow_case(args):
    with monitor(args, "event-overflow", interval=2.8) as mon:
        mon.freeze()
        for _ in range(50000):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                datagram.bind(("127.0.0.1", 0))
        mon.resume()
        time.sleep(.05)
        one_datagram()
        rows, capture = mon.finish({"minimum_metadata_records": 100000, "kernel_ring_bytes": 4194304})
        assert "socket events lost" in notes(capture), capture
        assert amount(rows, None, "tx") >= 1052, "lost evidence must quarantine attribution"


def clock_case(args):
    with monitor(args, "clock-step", interval=2.8) as mon:
        active = subprocess.run(["systemctl", "is-active", "--quiet", "systemd-timesyncd"]).returncode == 0
        if active:
            subprocess.run(["systemctl", "stop", "systemd-timesyncd"], check=True)
        before, mono = time.time(), time.monotonic()
        try:
            mon.freeze()
            time.clock_settime(time.CLOCK_REALTIME, before + 30)
            one_datagram()
        finally:
            time.clock_settime(time.CLOCK_REALTIME, before + time.monotonic() - mono)
            mon.resume()
            if active:
                subprocess.run(["systemctl", "start", "systemd-timesyncd"], check=True)
        rows, capture = mon.finish({"guest_realtime_step_seconds": 30, "clock_restored": True})
        if args.interface == "all":
            clean_capture(capture)
            assert amount(rows, os.getpid(), "tx") + amount(rows, None, "tx") >= 1052
        else:
            assert "timestamp" in notes(capture).lower(), capture
            assert amount(rows, os.getpid(), "tx") == 0, "uncertain packet timestamp credited"
            assert amount(rows, None, "tx") == 1052


def reused_sender(port, destination, report, release):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.bind(("127.0.0.1", port))
        sender.sendto(b"n" * 2000, destination)
        report.send(os.getpid())
        release.wait(15)


def conntrack_case(args):
    with monitor(args, "conntrack-reuse") as mon, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(3)
        mon.freeze()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.bind(("127.0.0.1", 0))
            port = sender.getsockname()[1]
            sender.sendto(b"o" * 1000, receiver.getsockname())
            assert len(receiver.recvfrom(4096)[0]) == 1000
        result = subprocess.run(["conntrack", "-D", "-p", "udp", "--orig-src", "127.0.0.1", "--orig-dst", "127.0.0.1",
                                 "--sport", str(port), "--dport", str(receiver.getsockname()[1])], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        parent, child = mp.Pipe()
        release = mp.Event()
        worker = mp.Process(target=reused_sender, args=(port, receiver.getsockname(), child, release))
        worker.start()
        try:
            assert parent.poll(5)
            new_pid = parent.recv()
            assert len(receiver.recvfrom(4096)[0]) == 2000
            mon.resume()
            rows, capture = mon.finish({"old_actor": os.getpid(), "new_actor": new_pid, "same_source_port": port,
                                        "old_ip_bytes": 1028, "new_ip_bytes": 2028, "explicit_delete": True})
            assert amount(rows, new_pid, "tx") <= 2028, "old tuple bytes credited to replacement actor"
            assert amount(rows, os.getpid(), "tx") <= 1028, "new tuple bytes credited to old actor"
            assert sum(row["tx_bytes"] for row in rows.values()) >= 3056
        finally:
            release.set()
            reap(worker)
            parent.close()
            child.close()


def uring_case(args):
    with tempfile.TemporaryDirectory(prefix="nwtop-uring-") as directory:
        helper = Path(directory) / "uring"
        subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", str(Path(__file__).with_name("adversarial-uring.c")),
                        "-luring", "-o", str(helper)], check=True)
        with monitor(args, "io-uring") as mon, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(5)
            worker = subprocess.Popen([str(helper), str(receiver.getsockname()[1])], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                assert select.select([worker.stdout], [], [], 10)[0], "io_uring helper not ready"
                details = json.loads(worker.stdout.readline())
                assert len(receiver.recvfrom(2048)[0]) == 1024
                rows, capture = mon.finish(details)
                clean_capture(capture)
                assert amount(rows, details["passive_holder"], "tx") == 0
                assert amount(rows, details["actor"], "tx") + amount(rows, None, "tx") >= 1052
                udp_accounting(args, rows, 1052, {os.getpid()}, {details["actor"]})
                assert not any((row.get("name", "").startswith("iou-wrk") or row.get("name", "").startswith("kworker")) and (row["tx_bytes"] or row["rx_bytes"]) for row in rows.values())
                _, stderr = worker.communicate("x", timeout=5)
                assert worker.returncode == 0, stderr
            finally:
                if worker.poll() is None:
                    worker.terminate()
                    worker.communicate(timeout=5)


def cpu_pressure(cpu, release):
    os.sched_setaffinity(0, {cpu})
    value = 1
    while not release.is_set():
        for _ in range(20000):
            value = (value * 1664525 + 1013904223) & 0xffffffff


def clock_pressure_case(args):
    release = mp.Event()
    workers = []
    with monitor(args, "clock-pressure", interval=4) as mon:
        tasks = list(Path(f"/proc/{mon.process.pid}/task").iterdir())
        cpu = min(os.sched_getaffinity(0))
        for task in tasks:
            os.sched_setaffinity(int(task.name), {cpu})
        def wait_ns():
            return sum(int((task / "schedstat").read_text().split()[1]) for task in tasks if task.exists())
        before = wait_ns()
        try:
            for _ in range(6):
                worker = mp.Process(target=cpu_pressure, args=(cpu, release))
                worker.start()
                workers.append(worker)
            time.sleep(.15)
            for _ in range(64):
                one_datagram()
                time.sleep(.002)
            time.sleep(.25)
            delayed = wait_ns() - before
            assert delayed > 1_000_000, "monitor did not experience real scheduler pressure"
            release.set()
            for worker in workers:
                reap(worker)
            rows, capture = mon.finish({"guest_cpu": cpu, "competing_cpu_workers": 6,
                                        "monitor_runqueue_wait_ns": delayed, "realtime_unchanged": True})
            clean_capture(capture, allow_clock=True)
            udp_accounting(args, rows, 64 * 1052, {os.getpid()}, {os.getpid()})
            for pid, row in rows.items():
                assert args.interface == "all" or pid in {None, os.getpid()} or row["rx_bytes"] == row["tx_bytes"] == 0
            # A rejected sampling bracket remains visible; pressure never licenses a guessed PID.
            if capture.get("timestamp_invalid", 0):
                assert "timestamp" in notes(capture).lower()
        finally:
            release.set()
            for worker in workers:
                reap(worker)


def tcp_counters():
    lines = Path("/proc/net/snmp").read_text().splitlines() + Path("/proc/net/netstat").read_text().splitlines()
    result = {}
    for index in range(0, len(lines), 2):
        keys, values = lines[index].split(), lines[index + 1].split()
        if keys[0] in {"Tcp:", "TcpExt:"}:
            result.update(zip(keys[1:], map(int, values[1:])))
    return result


def fastopen_case(args):
    setting = Path("/proc/sys/net/ipv4/tcp_fastopen")
    previous = setting.read_text()
    try:
        # Official ip-sysctl: client+server, no-cookie SYN data on both sides.
        setting.write_text(str(0x207))
        with monitor(args, "tcp-fastopen") as mon, socket.socket() as listener, socket.socket() as client:
            listener.settimeout(5)
            client.settimeout(5)
            listener.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 8)
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            before = tcp_counters()
            assert client.sendto(b"t" * 1024, socket.MSG_FASTOPEN, listener.getsockname()) == 1024
            # Data must precede accept; not merely be a conventional connect/send.
            time.sleep(.15)
            with listener.accept()[0] as peer:
                assert len(peer.recv(2048)) == 1024
                options = client.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)[5]
                assert options & 32, "kernel did not acknowledge SYN data (TCPI_OPT_SYN_DATA)"
                after = tcp_counters()
                assert after["TCPFastOpenActive"] > before["TCPFastOpenActive"]
                rows, capture = mon.finish({"actor": os.getpid(), "syn_data_acknowledged": True,
                                            "accept_delayed_ms": 150, "fastopen_active_delta": after["TCPFastOpenActive"] - before["TCPFastOpenActive"]})
                clean_capture(capture)
                for pid, row in rows.items():
                    assert args.interface == "all" or pid in {None, os.getpid()} or row["rx_bytes"] == row["tx_bytes"] == 0
                assert amount(rows, os.getpid(), "tx") + amount(rows, None, "tx") >= 1064
    finally:
        setting.write_text(previous)


def closed_sender(destination, channel, release):
    with socket.socket() as client:
        client.settimeout(5)
        client.connect(destination)
        channel.send(client.getsockname()[1])
        assert channel.recv() == "send"
        client.sendall(b"r" * 4096)
    channel.send("closed")
    release.wait(15)


def retransmit_case(args):
    table = "nwtop_adversarial_" + str(os.getpid())
    created = False
    release = mp.Event()
    worker = None
    try:
        with monitor(args, "tcp-retransmit", interval=5) as mon, socket.socket() as listener, \
                socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x800)) as witness:
            witness.bind(("lo", 0))
            witness.setblocking(False)
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(5)
            parent, child = mp.Pipe()
            worker = mp.Process(target=closed_sender, args=(listener.getsockname(), child, release))
            worker.start()
            with listener.accept()[0] as peer:
                assert parent.poll(5)
                port = parent.recv()
                rule = (f"add table inet {table}\n"
                        f"add chain inet {table} input {{ type filter hook input priority -10; policy accept; }}\n"
                        f"add rule inet {table} input ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport {listener.getsockname()[1]} tcp dport {port} tcp flags & ack == ack drop\n")
                subprocess.run(["nft", "-f", "-"], input=rule, text=True, check=True)
                created = True
                before = tcp_counters()["RetransSegs"]
                parent.send("send")
                assert parent.poll(5) and parent.recv() == "closed"
                deadline = time.monotonic() + 2
                sequences = {}
                while time.monotonic() < deadline:
                    if not select.select([witness], [], [], .05)[0]:
                        continue
                    packet, link = witness.recvfrom(65535)
                    # One inbound loopback copy only; inspect transport headers, never retain payload.
                    if link[2] != 0 or len(packet) < 40 or packet[9] != socket.IPPROTO_TCP:
                        continue
                    ip_len = (packet[0] & 15) * 4
                    tcp = packet[ip_len:ip_len + 20]
                    if len(tcp) < 20 or int.from_bytes(tcp[:2], "big") != port or int.from_bytes(tcp[2:4], "big") != listener.getsockname()[1]:
                        continue
                    payload_len = int.from_bytes(packet[2:4], "big") - ip_len - (tcp[12] >> 4) * 4
                    if payload_len <= 0:
                        continue
                    sequence = int.from_bytes(tcp[4:8], "big")
                    sequences[sequence] = sequences.get(sequence, 0) + 1
                    if max(sequences.values()) >= 2:
                        break
                retransmits = tcp_counters()["RetransSegs"] - before
                assert retransmits > 0 and max(sequences.values(), default=0) >= 2, "no real target-connection payload retransmission"
                subprocess.run(["nft", "delete", "table", "inet", table], check=True)
                created = False
                assert len(peer.recv(8192)) == 4096
                rows, capture = mon.finish({"closed_actor": worker.pid, "retransmitted_segments": retransmits,
                                            "final_sender_fd_closed": True, "same_tcp_sequence_seen": max(sequences.values())})
                clean_capture(capture)
                assert amount(rows, worker.pid, "tx") < 8192, "post-close retransmission credited as a live owner"
                assert amount(rows, None, "tx") >= 4096, "post-close retransmission must remain uncertain"
            parent.close()
            child.close()
    finally:
        if created:
            subprocess.run(["nft", "delete", "table", "inet", table], check=True)
        release.set()
        if worker:
            reap(worker)


CASES = {"fork": fork_case, "scm-rights": passed_case, "reuseport-unread": reuseport_case,
         "event-overflow": overflow_case, "clock-step": clock_case, "conntrack-reuse": conntrack_case,
         "io-uring": uring_case, "clock-pressure": clock_pressure_case, "tcp-fastopen": fastopen_case, "tcp-retransmit": retransmit_case}


@contextlib.contextmanager
def conntrack_fixture():
    # A fresh guest without a firewall may not register any conntrack hooks.
    # Read-only state counters activate tracking; they accept every packet.
    table = "nwtop_adversarial_ct_" + str(os.getpid())
    rules = (f"add table inet {table}\n"
             f"add chain inet {table} prerouting {{ type filter hook prerouting priority -150; policy accept; }}\n"
             f"add chain inet {table} output {{ type filter hook output priority -150; policy accept; }}\n"
             f"add rule inet {table} prerouting iifname lo ct state {{ new, established }} counter\n"
             f"add rule inet {table} output oifname lo ct state {{ new, established }} counter\n")
    subprocess.run(["nft", "-f", "-"], input=rules, text=True, check=True)
    try:
        yield
    finally:
        subprocess.run(["nft", "delete", "table", "inet", table], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--isolated-vm", action="store_true", required=True)
    parser.add_argument("--readiness-delay", type=float, default=0, help="Delay proc polling on slow emulators; product startup limits remain unchanged")
    parser.add_argument("--interface", choices=["lo", "all"], default="lo")
    parser.add_argument("--case", choices=["all", *CASES], default="all")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("guest root required")
    result = subprocess.run(["systemd-detect-virt", "--vm"], capture_output=True, text=True)
    if result.returncode != 0 or result.stdout.strip() not in {"qemu", "kvm"}:
        raise SystemExit("dedicated QEMU/KVM VM required")
    args.binary = args.binary.resolve(strict=True)
    if args.output:
        args.output = args.output / args.interface
    mp.set_start_method("fork")
    with conntrack_fixture():
        for name, test in CASES.items():
            if args.case in {"all", name}:
                test(args)
                print("PASS", name, args.interface, flush=True)


if __name__ == "__main__":
    main()
