#!/usr/bin/env python3
"""Check terminal restoration after keyboard, signal and error exits, and
clean non-interactive output into a closed pipe.

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


def environment():
    # Keep the expected terminal text English regardless of the runner's locale.
    env = {**os.environ, "TERM": "xterm-256color", "LC_ALL": "C.UTF-8"}
    env.pop("NO_COLOR", None)
    return env


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
            env=environment(),
            start_new_session=True,
        )
        deadline = time.monotonic() + 5
        while b"Device" not in output or b"\x1b[?1049h" not in output:
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


def run_error_case(binary):
    """An output error ends the monitor with an error but restores the terminal.

    Input and raw mode use one pseudo-terminal; screen output uses another whose
    master is closed after startup, so the next repaint fails with EIO.
    """
    master, slave = pty.openpty()
    screen_master, screen_slave = pty.openpty()
    child = None
    before = termios.tcgetattr(slave)
    output = bytearray()
    errors = bytearray()
    try:
        for descriptor in (slave, screen_slave):
            fcntl.ioctl(descriptor, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 120, 0, 0))
        child = subprocess.Popen(
            [str(binary), "--demo", "--interval", "0.1"],
            stdin=slave,
            stdout=screen_slave,
            stderr=slave,
            env=environment(),
            start_new_session=True,
        )
        os.close(screen_slave)
        screen_slave = None
        deadline = time.monotonic() + 5
        while b"Device" not in output or b"\x1b[?1049h" not in output:
            assert child.poll() is None, f"error case: monitor exited during startup: {output!r}"
            assert time.monotonic() < deadline, f"error case: monitor did not draw: {output!r}"
            read_available(screen_master, output, 0.05)
        assert termios.tcgetattr(slave) != before, "error case: terminal never entered raw mode"
        os.close(screen_master)
        screen_master = None

        deadline = time.monotonic() + 5
        while child.poll() is None:
            assert time.monotonic() < deadline, "error case: output failure did not end the monitor"
            read_available(master, errors, 0.05)
        while select.select([master], [], [], 0)[0]:
            read_available(master, errors, 0)
        assert child.returncode == 1, f"error case: unexpected exit code {child.returncode}"
        assert b"Error" in errors, f"error case: no error was reported: {errors!r}"
        assert termios.tcgetattr(slave) == before, "error case: terminal attributes were not restored"
        print("PASS output error: exit code 1, error reported and terminal attributes restored")
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=3)
        termios.tcsetattr(slave, termios.TCSANOW, before)
        for descriptor in (master, slave, screen_master, screen_slave):
            if descriptor is not None:
                os.close(descriptor)


def run_closed_pipe_case(binary):
    """A reader that closes the pipe early must not cause a panic."""
    for mode in ("--json", "--once"):
        reader, writer = os.pipe()
        os.close(reader)
        try:
            result = subprocess.run(
                [str(binary), "--demo", mode, "--interval", "0.1"],
                stdout=writer,
                stderr=subprocess.PIPE,
                env=environment(),
                timeout=5,
                check=False,
            )
        finally:
            os.close(writer)
        assert result.returncode == 0, f"{mode} into a closed pipe: exit {result.returncode}: {result.stderr!r}"
        assert b"panicked" not in result.stderr, f"{mode} panicked: {result.stderr!r}"
    print("PASS closed pipe: --json and --once exit cleanly without a panic")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 tests/terminal.py /path/to/nettop")
    binary = Path(sys.argv[1]).resolve(strict=True)
    for exit_signal in (None, signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        run_case(binary, exit_signal)
    run_error_case(binary)
    run_closed_pipe_case(binary)
    print("All terminal restoration checks passed.")


if __name__ == "__main__":
    main()
