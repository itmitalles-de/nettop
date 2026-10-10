#!/usr/bin/env python3
"""Exercise namespace/NAT process attribution only in an isolated QEMU/KVM VM.

Requires a binary built with --features ebpf, root, iproute2, nftables, libpcap
and libbpf. Creates three private network namespaces and changes forwarding/NAT
only inside its own router namespace. It never changes the VM's existing links,
firewall, forwarding setting, containers or conntrack entries.
"""

import argparse
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import time


PAYLOAD = 1024
PACKETS = 128
EXPECTED = PAYLOAD * PACKETS
CASES = ("tcp-direct-tracked", "udp-direct-tracked", "tcp-dnat", "udp-dnat", "udp-snat", "tcp-combined", "tcp-hairpin", "udp-hairpin", "tcp-untracked", "udp-untracked", "tcp-notrack", "udp-notrack", "tcp-loopback", "udp-loopback", "tcp-macvlan", "udp-macvlan", "tcp-ipvlan-l2", "udp-ipvlan-l2", "tcp-ipvlan-l3", "udp-ipvlan-l3", "tcp-vlan-snat", "udp-vlan-snat")


def command(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def in_namespace(namespace, *args, **kwargs):
    return command("ip", "netns", "exec", namespace, *args, **kwargs)


class Network:
    def __init__(self):
        prefix = f"nwtop-{os.getpid()}"
        self.client, self.router, self.server = [prefix + suffix for suffix in ("-c", "-r", "-s")]
        self.created = []
        self.processes = []
        self.has_rules = False
        self.server_address = "198.18.101.2"
        self.client_address = "198.18.100.2"
        self.client_namespace = self.client

    def setup(self, mode="direct-tracked"):
        existing = {line.split()[0] for line in command("ip", "netns", "list", capture_output=True).stdout.splitlines() if line.strip()}
        assert not existing.intersection((self.client, self.router, self.server)), "test namespace already exists"
        for namespace in (self.client, self.router, self.server):
            command("ip", "netns", "add", namespace)
            self.created.append(namespace)
            in_namespace(namespace, "ip", "link", "set", "lo", "up")
        if mode in ("loopback", "macvlan", "ipvlan-l2", "ipvlan-l3", "vlan-snat"):
            self.setup_edge(mode)
            return
        command("ip", "link", "add", "client", "netns", self.client, "type", "veth", "peer", "name", "outside", "netns", self.router)
        command("ip", "link", "add", "server", "netns", self.server, "type", "veth", "peer", "name", "inside", "netns", self.router)
        # A bridge adds an extra observation of each forwarded packet, as in
        # Docker's default topology. Only the receiver's veth boundary may
        # contribute its bytes to All; the outside link remains selectable.
        in_namespace(self.router, "ip", "link", "add", "bridge-test", "type", "bridge")
        in_namespace(self.router, "ip", "link", "set", "inside", "master", "bridge-test")
        in_namespace(self.router, "ip", "link", "set", "inside", "up")
        for namespace, interface, address in (
            (self.client, "client", "198.18.100.2/24"),
            (self.router, "outside", "198.18.100.1/24"),
            (self.server, "server", "198.18.101.2/24"),
            (self.router, "bridge-test", "198.18.101.1/24"),
        ):
            in_namespace(namespace, "ip", "addr", "add", address, "dev", interface)
            in_namespace(namespace, "ip", "link", "set", interface, "up")
        in_namespace(self.client, "ip", "route", "add", "default", "via", "198.18.100.1")
        in_namespace(self.server, "ip", "route", "add", "default", "via", "198.18.101.1")
        in_namespace(self.router, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")

    def setup_edge(self, mode):
        if mode == "loopback":
            self.client_namespace = self.server
            self.server_address = "127.0.0.1"
            self.client_address = "127.0.0.1"
            return
        if mode == "vlan-snat":
            command("ip", "link", "add", "outside", "netns", self.router, "type", "veth", "peer", "name", "underlay", "netns", self.server)
            for namespace, parent in ((self.router, "outside"), (self.server, "underlay")):
                in_namespace(namespace, "ip", "link", "set", parent, "up")
                in_namespace(namespace, "ip", "link", "add", "link", parent, "name", "vlan100", "type", "vlan", "id", "100")
                in_namespace(namespace, "ip", "link", "set", "vlan100", "up")
            in_namespace(self.router, "ip", "addr", "add", "198.18.211.1/24", "dev", "vlan100")
            in_namespace(self.router, "ip", "addr", "add", "198.18.212.1/32", "dev", "lo")
            in_namespace(self.server, "ip", "addr", "add", "198.18.211.2/24", "dev", "vlan100")
            in_namespace(self.server, "ip", "route", "add", "default", "via", "198.18.211.1")
            self.client_namespace = self.router
            self.client_address = "198.18.212.1"
            self.server_address = "198.18.211.2"
            return
        # The macvlan/ipvlan child has its own network namespace and no
        # host veth boundary. The observer can select its parent interface.
        command("ip", "link", "add", "client", "netns", self.client, "type", "veth", "peer", "name", "outside", "netns", self.router)
        for namespace, device in ((self.client, "client"), (self.router, "outside")):
            in_namespace(namespace, "ip", "link", "set", device, "up")
        kind, link_mode = ("macvlan", "bridge") if mode == "macvlan" else ("ipvlan", mode.rsplit("-", 1)[1])
        in_namespace(self.router, "ip", "link", "add", "link", "outside", "name", "child", "type", kind, "mode", link_mode)
        in_namespace(self.router, "ip", "link", "set", "child", "netns", self.server)
        in_namespace(self.server, "ip", "link", "set", "child", "up")
        in_namespace(self.router, "ip", "addr", "add", "198.18.201.1/24", "dev", "outside")
        in_namespace(self.client, "ip", "addr", "add", "198.18.201.2/24", "dev", "client")
        self.client_address = "198.18.201.2"
        self.server_address = "198.18.202.2" if mode == "ipvlan-l3" else "198.18.201.3"
        in_namespace(self.server, "ip", "addr", "add", self.server_address + "/24", "dev", "child")
        if mode == "ipvlan-l3":
            in_namespace(self.client, "ip", "route", "add", "198.18.202.0/24", "via", "198.18.201.1")
            in_namespace(self.server, "ip", "route", "add", "default", "dev", "child")

    def rules(self, protocol, mode):
        if self.has_rules:
            in_namespace(self.router, "nft", "delete", "table", "ip", "nwtop_test")
        dnat = f"{protocol} dport 18081 dnat to 198.18.101.2:18080;" if mode in ("dnat", "combined") else ""
        snat = "ip saddr 198.18.100.2 snat to 198.18.101.1;" if mode in ("snat", "combined") else ""
        if mode == "vlan-snat":
            snat = "ip saddr 198.18.212.1 snat to 198.18.211.1;"
        output = ""
        # Empty NAT chains do not activate conntrack in a fresh namespace.
        # Explicitly exercise tracked direct traffic, then separately verify
        # the selected-interface conservative result when tracking is disabled.
        tracking = ""
        if mode == "direct-tracked":
            tracking = "chain tracking { type filter hook forward priority filter; policy accept; ct state established,related counter; }"
        if mode == "notrack":
            tracking = "chain disable_tracking { type filter hook prerouting priority raw; policy accept; notrack; }"
        if mode == "hairpin":
            output = f"{protocol} dport 18081 dnat to 198.18.101.2:18080;"
            snat = "ip saddr 198.18.100.1 snat to 198.18.101.1;"
        rules = f"""table ip nwtop_test {{
 {tracking}
 chain pre {{
  type nat hook prerouting priority dstnat; policy accept;
  {dnat}
 }}
 chain output {{
  type nat hook output priority dstnat; policy accept;
  {output}
 }}
 chain post {{
  type nat hook postrouting priority srcnat; policy accept;
  {snat}
 }}
}}
"""
        in_namespace(self.router, "nft", "-f", "-", input=rules)
        self.has_rules = True

    def start(self, namespace, *args, **kwargs):
        process = subprocess.Popen(["ip", "netns", "exec", namespace, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs)
        self.processes.append(process)
        return process

    def cleanup(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
        for process in self.processes:
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
        for namespace in reversed(self.created):
            command("ip", "netns", "del", namespace)


def traffic_server(protocol, address="198.18.101.2"):
    kind = "socket.SOCK_DGRAM" if protocol == "udp" else "socket.SOCK_STREAM"
    common = f"""import socket,time
s=socket.socket(socket.AF_INET,{kind})
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(({address!r},18080))
"""
    if protocol == "udp":
        return common + """print('ready',flush=True)
while True:
 data,peer=s.recvfrom(65536)
 s.sendto(data,peer)
"""
    return common + """s.listen(1)
print('ready',flush=True)
c,peer=s.accept()
while True:
 data=c.recv(65536)
 if not data: break
 c.sendall(data)
time.sleep(5)
"""


def traffic_decoy(protocol):
    kind = "socket.SOCK_DGRAM" if protocol == "udp" else "socket.SOCK_STREAM"
    listen = "s.listen(1)" if protocol == "tcp" else ""
    return f"""import socket,select
s=socket.socket(socket.AF_INET,{kind})
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',18081))
{listen}
print('ready',flush=True)
assert not select.select([s],[],[],60)[0], 'pre-DNAT decoy received traffic'
"""


def traffic_client(protocol, destination, source_port, source_address="198.18.100.2", queued_receive=False):
    kind = "socket.SOCK_DGRAM" if protocol == "udp" else "socket.SOCK_STREAM"
    return f"""import socket,time
s=socket.socket(socket.AF_INET,{kind})
s.settimeout(3)
s.bind(({source_address!r},{source_port}))
s.connect({destination!r})
for _ in range({PACKETS}):
 s.sendall(b'n'*{PAYLOAD})
 {"time.sleep(.003)" if queued_receive else "pass"}
 received=0
 while received<{PAYLOAD}:
  received+=len(s.recv({PAYLOAD}-received))
 time.sleep(.004)
print('transferred',flush=True)
time.sleep(10)
"""


def await_line(process, expected, timeout):
    ready, _, _ = select.select([process.stdout], [], [], timeout)
    assert ready, f"PID {process.pid}: did not report {expected}"
    actual = process.stdout.readline().strip()
    assert actual == expected, (process.pid, actual, process.poll())


def await_capture(process):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        assert process.poll() is None, "monitor exited during startup"
        names = set()
        for path in Path(f"/proc/{process.pid}/task").glob("*/comm"):
            try:
                names.add(path.read_text().strip())
            except FileNotFoundError:
                pass
        # The attribution worker is created only after pcap readiness and the
        # initial descriptor scan. BPF verification can exceed a fixed sleep.
        if {"nwtop-capture", "nwtop-attrib"} <= names:
            return
        time.sleep(.025)
    raise AssertionError("monitor did not finish capture startup")


def run_case(network, binary, protocol, mode, interface, number, output_dir, environment):
    label = f"{protocol}-{mode}-{interface}"
    network.rules(protocol, mode)
    server = network.start(network.server, "python3", "-u", "-c", traffic_server(protocol, network.server_address))
    monitor = client = decoy = None
    try:
        await_line(server, "ready", 3)
        if mode == "dnat":
            # Ingress pcap sees this published port before DNAT. Its sampled
            # wildcard listener is a competing endpoint, never the recipient.
            decoy = network.start(network.router, "python3", "-u", "-c", traffic_decoy(protocol))
            await_line(decoy, "ready", 3)
        conservative_selected = interface != "all" and mode in ("untracked", "notrack", "macvlan", "ipvlan-l2", "ipvlan-l3")
        # Selected interfaces retain actual host pcap observations. Without CT
        # their unresolved endpoint bytes must survive the full deferral;
        # All uses positive socket-bound packets and is strictly attributable.
        interval = "6" if conservative_selected or mode in ("untracked", "notrack") else "3"
        monitor = network.start(network.router, str(binary), "--json", "--interface", interface, "--interval", interval, env=environment)
        await_capture(monitor)
        destination = ("198.18.100.1", 18081) if mode in ("dnat", "combined", "hairpin") else (network.server_address, 18080)
        client_namespace = network.router if mode == "hairpin" else network.client_namespace
        source_address = "198.18.100.1" if mode == "hairpin" else network.client_address
        client = network.start(client_namespace, "python3", "-u", "-c", traffic_client(protocol, destination, 36000 + number, source_address, queued_receive=mode in ("untracked", "notrack")))
        await_line(client, "transferred", 5)
        output, errors = monitor.communicate(timeout=10)
        assert monitor.returncode == 0, f"{label}: monitor failed: {errors}"
        snapshot = json.loads(output)
        if output_dir:
            (output_dir / f"{label}.json").write_text(output)
        capture = snapshot["capture"]
        assert capture["active"], f"{label}: capture inactive: {capture}"
        assert capture["dropped"] == 0, f"{label}: packet loss: {capture}"
        assert any(note["code"] == "extended" for note in capture["notes"]), f"{label}: extended backend not active"
        issues = [note for note in capture["notes"] if note["code"] == "extended_issue"]
        if conservative_selected:
            assert all("no confirmed conntrack entry" in note["detail"] for note in issues), f"{label}: unexpected metadata failure: {issues}"
        else:
            assert not issues, f"{label}: extended metadata errors: {issues}"
        rows = {row["pid"]: row for row in snapshot["processes"]}
        if decoy is not None:
            assert decoy.poll() is None, f"{label}: passive pre-DNAT decoy received traffic or exited"
            assert decoy.pid in rows, f"{label}: competing descriptor was not inventoried"
            assert rows[decoy.pid]["rx_bytes"] == rows[decoy.pid]["tx_bytes"] == 0, f"{label}: pre-DNAT decoy falsely attributed"
            decoy_connections = [row for row in snapshot["connections"] if row["pid"] == decoy.pid]
            assert any(row["local"] == "0.0.0.0:18081" for row in decoy_connections), f"{label}: competing wildcard socket missing"
            assert all(row["rx_bytes"] == row["tx_bytes"] == 0 for row in decoy_connections), f"{label}: pre-DNAT decoy received false connection bytes"
        for role, pid in (("sender", client.pid), ("receiver", server.pid)):
            if mode == "loopback" and interface == "lo":
                # Foreign lo also has ifindex 1. It must never leak into the
                # selected host lo view despite that numerical collision.
                assert pid not in rows or rows[pid]["rx_bytes"] == rows[pid]["tx_bytes"] == 0, f"{label}: foreign loopback counted on host lo"
                continue
            assert pid in rows, f"{label}: {role} PID {pid} missing"
            for direction in ("rx", "tx"):
                value = rows[pid][f"{direction}_bytes"]
                if not conservative_selected:
                    assert value >= EXPECTED * .9, f"{label}: {role} {direction}: {value} < 90% of {EXPECTED} payload bytes"
                assert value < EXPECTED * 1.8, f"{label}: {role} {direction}: {value} appears counted more than once"
        if mode == "loopback" and interface == "lo":
            assert sum(row["rx_bytes"] + row["tx_bytes"] for row in snapshot["processes"]) == 0, f"{label}: foreign loopback leaked into selected host lo"
        if interface != "all":
            for row in snapshot["processes"]:
                if row["pid"] not in (None, client.pid, server.pid):
                    assert row["rx_bytes"] == row["tx_bytes"] == 0, f"{label}: unrelated PID received test traffic: {row['pid']}"
        # All observes legitimate VM background too. Restrict its foreign-PID
        # check to this experiment's exact peer endpoints, never all processes.
        endpoints = {f"{network.server_address}:18080", f"{source_address}:{36000 + number}", "198.18.100.1:18081"}
        for row in snapshot["connections"]:
            if row["pid"] not in (None, client.pid, server.pid) and (row["local"] in endpoints or row["remote"] in endpoints):
                assert row["rx_bytes"] == row["tx_bytes"] == 0, f"{label}: another PID received a test connection"
        if conservative_selected:
            if any(rows.get(pid, {}).get(f"{direction}_bytes", 0) < EXPECTED * .9 for pid in (client.pid, server.pid) for direction in ("rx", "tx")):
                assert issues, f"{label}: partial attribution needs a visible limitation"
            for direction in ("rx", "tx"):
                total = sum(row[f"{direction}_bytes"] for row in snapshot["processes"])
                assert 2 * EXPECTED <= total < 2 * EXPECTED * 1.8, f"{label}: selected {direction} bytes disappeared or repeated: {total}"
        values = {role: {direction: rows.get(pid, {}).get(f"{direction}_bytes", 0) for direction in ("rx", "tx")} for role, pid in (("sender", client.pid), ("receiver", server.pid))}
        if decoy is not None:
            values["pre_dnat_decoy"] = {"pid": decoy.pid, "rx": 0, "tx": 0}
        print(f"PASS {label}: {values}", flush=True)
    finally:
        for process in (client, server, decoy, monitor):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--isolated-vm", action="store_true", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", action="append", choices=CASES, help="run only the selected case(s)")
    parser.add_argument("--interface", action="append", choices=("all", "outside", "bridge-test", "lo", "vlan100"), help="limit observation scope(s)")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run as root inside an isolated QEMU/KVM test VM.")
    identity = " ".join(path.read_text(errors="replace") for path in (Path("/sys/class/dmi/id/sys_vendor"), Path("/sys/class/dmi/id/product_name")) if path.exists()).lower()
    if not any(marker in identity for marker in ("qemu", "kvm", "bochs")):
        raise SystemExit("Refusing to create test networks outside a detected QEMU/KVM VM.")
    for dependency in ("ip", "nft", "sysctl", "python3"):
        if not shutil.which(dependency):
            raise SystemExit(f"Missing test dependency: {dependency}")
    binary = args.binary.resolve(strict=True)
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
    network = Network()
    try:
        with tempfile.TemporaryDirectory(prefix="nwtop-ns-config-") as config:
            environment = dict(os.environ, XDG_CONFIG_HOME=config)
            number = 0
            for case in args.case or CASES:
                protocol, mode = case.split("-", 1)
                network.cleanup()
                network = Network()
                network.setup(mode)
                if mode == "loopback":
                    scopes = ("all", "lo")
                elif mode == "vlan-snat":
                    scopes = ("all", "vlan100", "outside")
                else:
                    scopes = ("all", "bridge-test") if mode == "hairpin" else ("all", "outside")
                for interface in args.interface or scopes:
                    run_case(network, binary, protocol, mode, interface, number, args.output, environment)
                    number += 1
    finally:
        network.cleanup()
    print("PASS test processes, namespace links and NAT tables removed", flush=True)


if __name__ == "__main__":
    main()
