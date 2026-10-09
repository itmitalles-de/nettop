#!/usr/bin/env python3
"""Check terminal restoration after keyboard and external signal exits.

Run without root: python3 tests/terminal.py target/release/nettop
Each case owns a fresh pseudo-terminal and affects no interactive terminal.
"""

import fcntl
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time


def read_available(master, output, timeout):
    if select.select([master], [], [], timeout)[0]:
        output.extend(os.read(master, 65536))


def run_case(binary, exit_signal):
    label = "q" if exit_signal is None else signal.Signals(exit_signal).name
    master, slave = pty.openpty()
    child = None
    before = termios.tcgetattr(slave)
    output = bytearray()
    try:
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 120, 0, 0))
        child = subprocess.Popen(
            # A long refresh verifies that shutdown does not wait for a sample.
            [str(binary), "--demo", "--interval", "60"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env={**os.environ, "TERM": "xterm-256color"},
            start_new_session=True,
        )
        deadline = time.monotonic() + 5
        while b"nettop" not in output or b"\x1b[?1049h" not in output:
            assert child.poll() is None, f"{label}: monitor exited during startup: {output!r}"
            assert time.monotonic() < deadline, f"{label}: monitor did not draw: {output!r}"
            read_available(master, output, 0.05)
        assert termios.tcgetattr(slave) != before, f"{label}: terminal never entered raw mode"

        if exit_signal is None:
            os.write(master, b"q")
        else:
            child.send_signal(exit_signal)

        deadline = time.monotonic() + 3
        while child.poll() is None:
            assert time.monotonic() < deadline, f"{label}: shutdown blocked beyond three seconds"
            read_available(master, output, 0.05)
        while select.select([master], [], [], 0)[0]:
            read_available(master, output, 0)

        assert child.returncode == 0, f"{label}: unexpected exit code {child.returncode}"
        assert termios.tcgetattr(slave) == before, f"{label}: terminal attributes were not restored"
        assert b"\x1b[?1049l" in output, f"{label}: monitor did not leave the alternate screen"
        assert b"\x1b[?25h" in output, f"{label}: cursor was not restored"
        print(f"PASS {label}: terminal attributes, alternate screen and cursor restored")
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=3)
        termios.tcsetattr(slave, termios.TCSANOW, before)
        os.close(master)
        os.close(slave)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 tests/terminal.py /path/to/nettop")
    binary = Path(sys.argv[1]).resolve(strict=True)
    for exit_signal in (None, signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        run_case(binary, exit_signal)
    print("All terminal restoration checks passed.")


if __name__ == "__main__":
    main()
