#!/usr/bin/env python3
"""Exercise the privileged helper in an explicitly disposable Linux environment.

Run only in an isolated container/runner as root, with NET_RAW, DAC_READ_SEARCH,
SYS_PTRACE and SETFCAP in its capability bounding set. This test installs at the
real helper path and refuses to replace a pre-existing installation. Example:

  python3 tests/helper.py --isolated target/release/nwtop target/release/nwtop-collector

The UI itself runs as nobody with no supplementary groups or capabilities.
Traffic stays on loopback; every process and installed file is test-owned.
"""

import argparse
import ctypes
import fcntl
import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path
import pty
import pwd
import select
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import termios
import time
from unittest.mock import patch


HELPER = Path("/usr/local/libexec/nwtop-collector")
RECEIPT = HELPER.with_name(".nwtop-collector.sha256")
READ_CAPS = (1 << 2) | (1 << 19)
HELPER_CAPS = READ_CAPS | (1 << 13)
FILE_CAPS = "cap_dac_read_search,cap_net_raw,cap_sys_ptrace=ep"
EXTENDED_FILE_CAPS = "cap_dac_read_search,cap_net_raw,cap_sys_ptrace,cap_net_admin,cap_bpf,cap_perfmon=ep"


def status(pid, tid=None):
    path = Path(f"/proc/{pid}/status" if tid is None else f"/proc/{pid}/task/{tid}/status")
    return dict(line.split(":", 1) for line in path.read_text().splitlines())


def children(pid):
    return [int(value) for value in Path(f"/proc/{pid}/task/{pid}/children").read_text().split()]


def wait_until(predicate, description, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.02)
    raise AssertionError(f"Timed out waiting for {description}")


def unprivileged(account):
    return {"user": account.pw_uid, "group": account.pw_gid, "extra_groups": []}


def check_capabilities(monitor, account):
    helper_pid = wait_until(lambda: children(monitor.pid), "capture helper child")[0]

    def privileges_dropped():
        states = [status(helper_pid, tid.name) for tid in Path(f"/proc/{helper_pid}/task").iterdir()]
        return len(states) >= 3 and all(int(state["NoNewPrivs"]) == 1 for state in states)

    wait_until(privileges_dropped, "per-thread privilege drop")
    ui = status(monitor.pid)
    assert all(int(value) == account.pw_uid for value in ui["Uid"].split()), "UI changed UID"
    for field in ("CapEff", "CapPrm"):
        assert int(ui[field], 16) == 0, f"UI retained {field}: {ui[field]}"
    for task in Path(f"/proc/{helper_pid}/task").iterdir():
        state = status(helper_pid, task.name)
        # The main sampling thread and the background socket attribution
        # thread read /proc; the capture worker keeps no capabilities.
        comm = Path(f"/proc/{helper_pid}/task/{task.name}/comm").read_text().strip()
        expected = READ_CAPS if int(task.name) == helper_pid or comm == "nwtop-attrib" else 0
        assert all(int(value) == account.pw_uid for value in state["Uid"].split()), "Helper changed UID"
        assert int(state["CapEff"], 16) == expected, f"Wrong effective capabilities: {state['CapEff']}"
        assert int(state["CapPrm"], 16) == expected, f"Wrong permitted capabilities: {state['CapPrm']}"
        assert int(state["CapInh"], 16) == 0 and int(state["CapAmb"], 16) == 0
        assert int(state["NoNewPrivs"]) == 1
    return helper_pid


def receiver(control, finished, expected):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        control.send(sock.getsockname()[1])
        received = 0
        while received < expected:
            received += len(sock.recv(65536))
        control.send(received)
        finished.wait(10)


def check_capture(binary, account):
    expected = 128 * 1024
    parent, child = mp.Pipe()
    finished = mp.Event()
    server = mp.Process(target=receiver, args=(child, finished, expected))
    server.start()
    child.close()
    monitor = None
    try:
        assert parent.poll(5), "Root receiver did not bind"
        port = parent.recv()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.connect(("127.0.0.1", port))
            monitor = subprocess.Popen(
                [str(binary), "--interface", "lo", "--json", "--interval", "1.5"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                **unprivileged(account),
            )
            helper_pid = check_capabilities(monitor, account)
            # Let the initial socket inventory and sampling baseline complete.
            time.sleep(0.3)
            for _ in range(128):
                sender.send(b"n" * 1024)
                time.sleep(0.002)
            assert parent.poll(5) and parent.recv() == expected, "Root receiver missed payload"
            output, errors = monitor.communicate(timeout=10)
            assert monitor.returncode == 0, f"Unprivileged UI failed: {errors}"
            assert not errors, f"Unexpected capture fallback: {errors}"
            snapshot = json.loads(output)
            assert snapshot["capture"]["active"], f"Helper capture inactive: {snapshot['capture']}"
            assert snapshot["capture"]["dropped"] == 0, "Helper dropped packets"
            rows = {row["pid"]: row for row in snapshot["processes"]}
            assert os.getpid() in rows and server.pid in rows, "Root-owned traffic was not attributed"
            sent = rows[os.getpid()]["tx_bytes"]
            received = rows[server.pid]["rx_bytes"]
            assert expected <= sent < expected * 1.8, f"Wrong root sender count: {sent}"
            assert expected <= received < expected * 1.8, f"Wrong root receiver count: {received}"
            assert rows[os.getpid()]["user"] == "root" and rows[server.pid]["user"] == "root"
            assert not Path(f"/proc/{helper_pid}").exists(), "Helper survived normal UI exit"
        print("PASS unprivileged UI: real root-process traffic, thread capability limits and child cleanup")
    finally:
        finished.set()
        if monitor is not None and monitor.poll() is None:
            monitor.kill()
            monitor.communicate(timeout=3)
        server.join(timeout=3)
        if server.is_alive():
            server.terminate()
            server.join(timeout=3)
        parent.close()


def check_no_capture(binary, account):
    # Files avoid filling a stdout pipe while observing the complete child tree.
    with tempfile.TemporaryFile(mode="w+") as output, tempfile.TemporaryFile(mode="w+") as errors:
        monitor = subprocess.Popen(
            [str(binary), "--no-capture", "--json", "--interval", "0.5"],
            stdout=output,
            stderr=errors,
            **unprivileged(account),
        )
        try:
            # Keep checking for the whole refresh interval, not just before spawn.
            deadline = time.monotonic() + 5
            while monitor.poll() is None:
                assert time.monotonic() < deadline, "--no-capture did not finish"
                assert not children(monitor.pid), "--no-capture launched a helper"
                time.sleep(0.02)
            output.seek(0)
            errors.seek(0)
            assert monitor.returncode == 0, errors.read()
            assert not json.load(output)["capture"]["active"]
            print("PASS --no-capture bypasses the installed helper")
        finally:
            if monitor.poll() is None:
                monitor.kill()
                monitor.wait(timeout=3)


def check_protocol(account):
    cases = {
        "protocol version": b'{"version":2,"interface":null}\n',
        "unknown field": b'{"version":1,"interface":null,"command":"unused"}\n',
        "interface path": b'{"version":1,"interface":"../net"}\n',
        "oversized request": b"x" * 1025 + b"\n",
        "incomplete request": b'{"version":1,"interface":null}',
    }
    for label, request in cases.items():
        result = subprocess.run(
            [str(HELPER), "--stdio"],
            input=request,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
            **unprivileged(account),
        )
        reply = json.loads(result.stdout)
        assert result.returncode != 0 and reply["result"] == "error", f"Accepted {label}: {reply}"
        assert len(result.stdout) < 4096, f"Unbounded error for {label}"
    print("PASS helper rejects invalid versions, unknown fields, path names and unbounded/incomplete frames")


def read_terminal(master, output, timeout):
    if select.select([master], [], [], timeout)[0]:
        output.extend(os.read(master, 65536))


def check_stopped_helper(binary, account, signal_exit=True):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    output = bytearray()
    monitor = None
    helper_pid = None
    try:
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 120, 0, 0))
        monitor = subprocess.Popen(
            [str(binary), "--interface", "lo", "--interval", "0.1"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env={**os.environ, "TERM": "xterm-256color", "LC_ALL": "C.UTF-8"},
            start_new_session=True,
            **unprivileged(account),
        )
        deadline = time.monotonic() + 5
        while b"Device" not in output or b"\x1b[?1049h" not in output:
            assert monitor.poll() is None, f"PTY monitor exited: {output!r}"
            assert time.monotonic() < deadline, f"PTY monitor did not draw: {output!r}"
            read_terminal(master, output, 0.05)
        helper_pid = check_capabilities(monitor, account)
        os.kill(helper_pid, signal.SIGSTOP)
        stopped_at = time.monotonic()
        # The next sample is now waiting on a helper that cannot answer.
        time.sleep(0.25)
        if not signal_exit:
            # After the ten-second deadline the monitor keeps running on direct
            # counters, reports the failure and stops and reaps the helper.
            deadline = time.monotonic() + 13
            while Path(f"/proc/{helper_pid}").exists():
                assert monitor.poll() is None, f"Helper timeout ended the monitor: {output!r}"
                assert time.monotonic() < deadline, "Stalled helper was not replaced"
                read_terminal(master, output, 0.05)
            assert time.monotonic() - stopped_at >= 9.5, "Helper response timed out prematurely"
            deadline = time.monotonic() + 3
            while b"timed out" not in output:
                assert monitor.poll() is None, f"Monitor exited after fallback: {output!r}"
                assert time.monotonic() < deadline, f"Missing timeout notice: {output!r}"
                read_terminal(master, output, 0.05)
            time.sleep(0.5)
            assert monitor.poll() is None, f"Monitor exited after fallback: {output!r}"
        monitor.send_signal(signal.SIGTERM)
        deadline = time.monotonic() + 3
        while monitor.poll() is None:
            assert time.monotonic() < deadline, "UI shutdown blocked on stopped helper"
            read_terminal(master, output, 0.05)
        while select.select([master], [], [], 0)[0]:
            read_terminal(master, output, 0)
        assert monitor.returncode == 0, f"Unexpected exit code: {monitor.returncode}"
        assert termios.tcgetattr(slave) == before, "Terminal attributes were not restored"
        assert b"\x1b[?1049l" in output and b"\x1b[?25h" in output, "Screen/cursor were not restored"
        assert not Path(f"/proc/{helper_pid}").exists(), "Stopped helper survived UI shutdown"
        if signal_exit:
            print("PASS SIGTERM interrupts a blocked helper response, restores the terminal and reaps the helper")
        else:
            print("PASS ten-second helper timeout shows a notice, falls back to direct counters and reaps the helper")
    finally:
        if helper_pid is not None and Path(f"/proc/{helper_pid}").exists():
            os.kill(helper_pid, signal.SIGKILL)
        if monitor is not None and monitor.poll() is None:
            monitor.kill()
            monitor.wait(timeout=3)
        termios.tcsetattr(slave, termios.TCSANOW, before)
        os.close(master)
        os.close(slave)


def controlling_terminal():
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def check_terminal_hangup(binary, account, controlling=False):
    """A closed terminal ends the UI promptly and stops and reaps the helper.

    Without a controlling terminal no SIGHUP arrives; the UI must notice the
    hang-up itself instead of spinning on end-of-file input.
    """
    master, slave = pty.openpty()
    output = bytearray()
    monitor = None
    helper_pid = None
    try:
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 120, 0, 0))
        monitor = subprocess.Popen(
            [str(binary), "--interface", "lo", "--interval", "60"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env={**os.environ, "TERM": "xterm-256color", "LC_ALL": "C.UTF-8"},
            start_new_session=True,
            preexec_fn=controlling_terminal if controlling else None,
            **unprivileged(account),
        )
        deadline = time.monotonic() + 5
        while b"Device" not in output or b"\x1b[?1049h" not in output:
            assert monitor.poll() is None, f"PTY monitor exited: {output!r}"
            assert time.monotonic() < deadline, f"PTY monitor did not draw: {output!r}"
            read_terminal(master, output, 0.05)
        helper_pid = check_capabilities(monitor, account)
        os.close(master)
        master = None
        try:
            monitor.wait(timeout=2)
        except subprocess.TimeoutExpired:
            raise AssertionError("UI kept running after its terminal closed") from None
        assert monitor.returncode == 0, f"Unexpected exit code: {monitor.returncode}"
        assert not Path(f"/proc/{helper_pid}").exists(), "Helper survived the terminal hang-up"
        kind = "controlling terminal" if controlling else "terminal without SIGHUP"
        print(f"PASS closed {kind} ends the UI within two seconds and reaps the helper")
    finally:
        if helper_pid is not None and Path(f"/proc/{helper_pid}").exists():
            os.kill(helper_pid, signal.SIGKILL)
        if monitor is not None and monitor.poll() is None:
            monitor.kill()
            monitor.wait(timeout=3)
        for descriptor in (master, slave):
            if descriptor is not None:
                os.close(descriptor)


def packet_inodes():
    return {line.split()[-1] for line in Path("/proc/net/packet").read_text().splitlines()[1:]}


def check_abrupt_exit(binary, account):
    # Adopt only this test's orphaned descendants, so both a container PID 1 and
    # an ordinary CI process can explicitly reap the helper after killing its UI.
    libc = ctypes.CDLL(None, use_errno=True)
    previous_subreaper = ctypes.c_int()
    assert libc.prctl(37, ctypes.byref(previous_subreaper), 0, 0, 0) == 0  # GET_CHILD_SUBREAPER
    assert libc.prctl(36, 1, 0, 0, 0) == 0  # SET_CHILD_SUBREAPER
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    output = bytearray()
    monitor = None
    helper_pid = None
    reaped = False
    try:
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 120, 0, 0))
        monitor = subprocess.Popen(
            [str(binary), "--interface", "lo", "--interval", "60"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env={**os.environ, "TERM": "xterm-256color", "LC_ALL": "C.UTF-8"},
            start_new_session=True,
            **unprivileged(account),
        )
        deadline = time.monotonic() + 5
        while b"Device" not in output or b"\x1b[?1049h" not in output:
            assert monitor.poll() is None, f"PTY monitor exited: {output!r}"
            assert time.monotonic() < deadline, f"PTY monitor did not draw: {output!r}"
            read_terminal(master, output, 0.05)
        helper_pid = check_capabilities(monitor, account)
        # The first rendered frame proves that the helper's initial reply was
        # consumed. During the long refresh interval it waits for another request.
        socket_inodes = set()
        for descriptor in Path(f"/proc/{helper_pid}/fd").iterdir():
            target = os.readlink(descriptor)
            if target.startswith("socket:["):
                socket_inodes.add(target.removeprefix("socket:[").removesuffix("]"))
        capture_inodes = socket_inodes & packet_inodes()
        assert capture_inodes, "Helper had no live packet-capture descriptor"
        monitor.kill()
        monitor.wait(timeout=3)

        def reap_helper():
            pid, result = os.waitpid(helper_pid, os.WNOHANG)
            return (pid, result) if pid else None

        _, result = wait_until(reap_helper, "orphaned helper exit on stdin EOF", timeout=3)
        reaped = True
        assert os.waitstatus_to_exitcode(result) == 0, f"Helper did not exit cleanly on EOF: {result}"
        assert capture_inodes.isdisjoint(packet_inodes()), "Orphaned helper retained its packet socket"
        print("PASS SIGKILL of UI closes private pipes; helper exits on EOF, closes its packet socket and is reaped")
    finally:
        if monitor is not None and monitor.poll() is None:
            monitor.kill()
            monitor.wait(timeout=3)
        if helper_pid is not None and not reaped:
            try:
                os.kill(helper_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(helper_pid, 0)
            except ChildProcessError:
                pass
        # SIGKILL cannot restore the UI's terminal; this test owns and restores it.
        termios.tcsetattr(slave, termios.TCSANOW, before)
        os.close(master)
        os.close(slave)
        assert libc.prctl(36, previous_subreaper.value, 0, 0, 0) == 0


def check_installer(script, build, account):
    digest = hashlib.sha256(build.read_bytes()).hexdigest()

    def install(success, target=account, shared="1", reassign="0", expect="", extended="0"):
        # nobody's primary group nogroup is not a user private group.
        command = ["bash", str(script), "--install", str(build), str(target.pw_uid),
                   str(target.pw_gid), digest, shared, reassign, extended]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        output = result.stdout + result.stderr
        assert (result.returncode == 0) == success, f"Unexpected installer result: {output}"
        assert expect in output, f"Installer did not explain {expect!r}: {output}"

    for option in ("yes", "01", "-1", "1;true"):
        install(False, extended=option, expect="Invalid installation options")
    install(False, shared="0", expect="not the private group")
    assert not os.path.lexists(HELPER), "A refused shared group still installed the helper"
    install(True)
    installed = HELPER.stat()
    assert installed.st_uid == 0 and installed.st_gid == account.pw_gid
    assert installed.st_mode & 0o7777 == 0o750
    assert RECEIPT.read_text().strip() == digest
    subprocess.run(["setcap", "-v", FILE_CAPS, str(HELPER)], check=True, stdout=subprocess.DEVNULL)
    # Validate the opt-in install grant and its removal without executing an
    # extended helper: default containers need no additional bounding-set caps.
    install(True, extended="1")
    subprocess.run(["setcap", "-v", EXTENDED_FILE_CAPS, str(HELPER)], check=True, stdout=subprocess.DEVNULL)
    install(True)
    subprocess.run(["setcap", "-v", FILE_CAPS, str(HELPER)], check=True, stdout=subprocess.DEVNULL)
    assert hashlib.sha256(HELPER.read_bytes()).hexdigest() == digest, "Clean update changed the binary"

    saved_receipt = RECEIPT.with_name(RECEIPT.name + ".test-backup")
    RECEIPT.rename(saved_receipt)
    try:
        install(False)
    finally:
        saved_receipt.rename(RECEIPT)

    saved_helper = HELPER.with_name(HELPER.name + ".test-backup")
    HELPER.rename(saved_helper)
    try:
        HELPER.symlink_to(build)
        install(False)
        assert HELPER.is_symlink(), "Installer replaced an untracked symlink"
    finally:
        HELPER.unlink()
        saved_helper.rename(HELPER)

    # A replacement must not silently erase a locally changed installed binary.
    with HELPER.open("ab") as stream:
        stream.write(b"changed-by-test")
    try:
        install(False)
        assert HELPER.read_bytes().endswith(b"changed-by-test")
    finally:
        # Restore only this test-owned installation, then verify the normal path.
        HELPER.unlink()
        RECEIPT.unlink()
        install(True)
    check_installer_groups(install, build, account)
    print("PASS installer: root ownership/capabilities, clean update, changed/untracked/symlink "
          "refusal, shared and reassigned groups, explicit extended grant and removal")


def check_installer_groups(install, build, account):
    """Shared primary groups and silent group takeover need explicit flags."""
    private, other, listed = "nwtop-test-private", "nwtop-test-other", "nwtop-test-listed"
    nologin = ["--no-create-home", "--shell", "/usr/sbin/nologin"]
    subprocess.run(["useradd", "--user-group", *nologin, private], check=True)
    try:
        owner = pwd.getpwnam(private)
        os.chown(build, owner.pw_uid, owner.pw_gid)
        # Another group already has access: moving it needs --reassign-group.
        install(False, owner, shared="0", expect="--reassign-group")
        assert HELPER.stat().st_gid == account.pw_gid
        install(True, owner, shared="0", reassign="1")
        assert HELPER.stat().st_gid == owner.pw_gid
        install(True, owner, shared="0")
        # A second account with the same primary group, or a listed member.
        subprocess.run(["useradd", "--gid", private, *nologin, other], check=True)
        install(False, owner, shared="0", expect=f"account {other} also has primary group")
        install(True, owner, shared="1")
        subprocess.run(["userdel", other], check=True)
        subprocess.run(["useradd", "--user-group", *nologin, listed], check=True)
        subprocess.run(["gpasswd", "--add", listed, private], check=True, stdout=subprocess.DEVNULL)
        install(False, owner, shared="0", expect=f"also lists {listed}")
    finally:
        for name in (other, listed):
            subprocess.run(["userdel", name], check=False, stderr=subprocess.DEVNULL)
        os.chown(build, account.pw_uid, account.pw_gid)
        install(True, reassign="1")
        subprocess.run(["userdel", private], check=False, stderr=subprocess.DEVNULL)
    assert HELPER.stat().st_gid == account.pw_gid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated", action="store_true", help="confirm this is a disposable container/runner")
    parser.add_argument("binary", type=Path)
    parser.add_argument("helper_binary", type=Path)
    args = parser.parse_args()
    if not args.isolated or os.geteuid() != 0:
        parser.error("run as root with --isolated only in a disposable Linux container/runner")
    effective = int(status(os.getpid())["CapEff"], 16)
    required = HELPER_CAPS | (1 << 31)  # SETFCAP is needed only by the installer.
    assert effective & required == required, "Container needs NET_RAW, DAC_READ_SEARCH, SYS_PTRACE and SETFCAP"
    assert not os.path.lexists(HELPER) and not os.path.lexists(RECEIPT), "Refusing a pre-existing helper installation"
    binary = args.binary.resolve(strict=True)
    helper_binary = args.helper_binary.resolve(strict=True)
    script = Path(__file__).resolve().parents[1] / "scripts/setup-capture.sh"
    account = pwd.getpwnam("nobody")
    assert account.pw_uid != 0 and account.pw_gid != 0
    try:
        with tempfile.TemporaryDirectory(prefix="nwtop-helper-test-") as directory:
            # Source ownership is checked by the real installer; allow nobody to
            # traverse the test staging directory without making it writable.
            os.chmod(directory, 0o755)
            build = Path(directory) / "nwtop-collector"
            shutil.copy2(helper_binary, build)
            os.chown(build, account.pw_uid, account.pw_gid)
            # Popen(user=...) changes credentials but inherits root's environment.
            # Give the UI a private, accessible preferences directory instead of
            # resolving settings underneath the test runner's root home.
            config_home = Path(directory) / "preferences"
            config_home.mkdir(mode=0o700)
            os.chown(config_home, account.pw_uid, account.pw_gid)
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(config_home)}):
                check_installer(script, build, account)
                check_capture(binary, account)
                check_no_capture(binary, account)
                check_protocol(account)
                check_stopped_helper(binary, account)
                check_stopped_helper(binary, account, signal_exit=False)
                check_terminal_hangup(binary, account)
                check_terminal_hangup(binary, account, controlling=True)
                check_abrupt_exit(binary, account)
    finally:
        # These paths were absent before this explicitly isolated test started.
        for path in (HELPER, RECEIPT):
            if os.path.lexists(path):
                path.unlink()
    print("All capability helper checks passed.")


if __name__ == "__main__":
    main()
