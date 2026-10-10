#!/usr/bin/env python3
"""Exercise Setup and persisted preferences through the real terminal UI.

Run without root: python3 tests/setup.py target/release/nettop
Every process uses a temporary XDG directory and its own pseudo-terminal.
"""

import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import time


F2 = b"\x1bOQ"
F10 = b"\x1b[21~"
F12 = b"\x1b[24~"
RIGHT = b"\x1b[C"
LEFT = b"\x1b[D"
DOWN = b"\x1b[B"
UP = b"\x1b[A"
ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")


def environment(config_home, **overrides):
    env = {**os.environ, "XDG_CONFIG_HOME": str(config_home), "TERM": "xterm-256color"}
    # Exercise the color setting independently of a CI runner's color policy.
    env.pop("NO_COLOR", None)
    # Keep the terminal text English regardless of the runner's locale.
    for name in ("LC_ALL", "LC_MESSAGES", "LANG"):
        env.pop(name, None)
    env["LC_ALL"] = "C.UTF-8"
    for name, value in overrides.items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    return env


DEFAULT_ARGUMENTS = ("--interval", "0.1", "--history", "10")


class Terminal:
    def __init__(self, binary, config_home, arguments=DEFAULT_ARGUMENTS, ready=b"Device", **env):
        self.binary = binary
        self.config_home = config_home
        self.arguments = arguments
        self.ready = ready
        self.env = env
        self.master, self.slave = pty.openpty()
        self.before = termios.tcgetattr(self.slave)
        self.output = bytearray()
        self.child = None

    def __enter__(self):
        try:
            fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 120, 0, 0))
            self.child = subprocess.Popen(
                [str(self.binary), "--demo", *self.arguments],
                stdin=self.slave,
                stdout=self.slave,
                stderr=self.slave,
                env=environment(self.config_home, **self.env),
                start_new_session=True,
            )
            self.wait_for(
                lambda: self.ready in self.output and b"\x1b[?1049h" in self.output,
                "monitor startup",
            )
            return self
        except BaseException:
            self.close()
            raise

    def read(self, timeout=0.05):
        if select.select([self.master], [], [], timeout)[0]:
            self.output.extend(os.read(self.master, 65536))

    def wait_for(self, condition, label, timeout=3):
        deadline = time.monotonic() + timeout
        while not condition():
            assert self.child.poll() is None, f"{label}: process exited: {self.tail()}"
            assert time.monotonic() < deadline, f"{label}: timed out: {self.tail()}"
            self.read()

    def expect(self, text, after=0):
        self.wait_for(
            lambda: text in ANSI.sub(b"", bytes(self.output[after:])),
            f"terminal text {text!r}",
        )

    def send(self, keys):
        assert self.child.poll() is None, f"cannot send input to exited monitor: {self.tail()}"
        mark = len(self.output)
        os.write(self.master, keys)
        return mark

    def tail(self):
        return repr(ANSI.sub(b"", bytes(self.output[-1800:])))

    def quit(self):
        self.send(b"q")
        deadline = time.monotonic() + 3
        while self.child.poll() is None:
            assert time.monotonic() < deadline, f"q did not exit within three seconds: {self.tail()}"
            self.read()
        assert self.child.returncode == 0, f"unexpected exit {self.child.returncode}: {self.tail()}"
        assert termios.tcgetattr(self.slave) == self.before, "terminal mode was not restored"

    def close(self):
        if self.child is not None and self.child.poll() is None:
            self.child.kill()
            self.child.wait(timeout=3)
        termios.tcsetattr(self.slave, termios.TCSANOW, self.before)
        os.close(self.master)
        os.close(self.slave)

    def __exit__(self, *_):
        self.close()


def read_saved(path):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return None


def run_once(binary, config_home, *arguments):
    result = subprocess.run(
        [str(binary), "--demo", "--once", *arguments],
        env=environment(config_home),
        capture_output=True,
        text=True,
        timeout=3,
        check=True,
    )
    return result.stdout, result.stderr


def persistence_and_overrides(binary, config_home):
    path = config_home / "nettop/config.json"
    with Terminal(binary, config_home) as terminal:
        assert not path.exists(), "opening the monitor unexpectedly wrote settings"
        assert b"Settings:" not in terminal.output, "missing settings should silently use defaults"
        mark = terminal.send(F2)
        terminal.expect(b"Options", mark)
        # General: move from Color to update interval, then the units checkbox.
        mark = terminal.send(RIGHT + DOWN + b"+" + DOWN + b" ")
        terminal.expect(b"Unsaved changes", mark)
        # Chart: select Braille drawing and the next receive color.
        terminal.send(LEFT + DOWN + DOWN + RIGHT + DOWN + DOWN + b"\r" + DOWN + b"+")
        # Interface: select All instead of the automatic default route.
        terminal.send(LEFT + UP + RIGHT + DOWN + b"\r")
        assert not path.exists(), "editing Setup unexpectedly saved without F12"
        terminal.send(F12)
        terminal.wait_for(lambda: read_saved(path) is not None, "F12 saved settings")
        saved = read_saved(path)
        # --interval 0.1 became 0.2 in Setup and is saved; the untouched
        # --history 10 override is temporary and keeps the default.
        expected = {
            "version": 1,
            "interval_ms": 200,
            "history_seconds": 60,
            "bits": True,
            "color": True,
            "graph_style": "braille",
            "rx_color": "yellow",
            "interface": "all",
        }
        for key, value in expected.items():
            assert saved[key] == value, f"Setup did not persist {key}: {saved}"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, "saved settings are not private"
        terminal.expect(b"Saved ")
        mark = terminal.send(F10)
        terminal.expect(b"RX/s", mark)
        assert terminal.child.poll() is None, "F10 in Setup unexpectedly quit nettop"
        terminal.quit()

    before = path.read_bytes()
    stdout, stderr = run_once(binary, config_home)
    assert not stderr, f"unexpected settings warning after restart: {stderr}"
    assert "all interfaces" in stdout.splitlines()[0], "restart lost the saved interface choice"
    assert "bit/s" in stdout.splitlines()[1], "restart lost the saved bit/s units"
    assert path.read_bytes() == before, "reading settings unexpectedly rewrote them"

    # A 60-second saved interval makes a missing CLI override fail this 3-second
    # subprocess deadline, rather than accidentally passing with a short default.
    saved["interval_ms"] = 60_000
    path.write_text(json.dumps(saved))
    before = path.read_bytes()
    stdout, stderr = run_once(
        binary, config_home, "--bytes", "--interval", "0.1", "--interface", "enp112s0"
    )
    assert not stderr, f"unexpected warning with CLI overrides: {stderr}"
    assert "enp112s0" in stdout.splitlines()[0], "--interface did not override the saved choice"
    assert "B/s" in stdout.splitlines()[1], "--bytes did not override the saved units"
    assert "bit/s" not in stdout.splitlines()[1], "saved units overrode --bytes"
    assert path.read_bytes() == before, "temporary CLI overrides overwrote saved preferences"
    print("PASS Setup: F2 edits, F12 persistence, F10 returns, restart and CLI overrides")


def overrides_not_persisted(binary, config_home):
    path = config_home / "nettop/config.json"
    path.parent.mkdir(mode=0o700, parents=True)
    original = {
        "version": 1,
        "interface": "nettop-gone",
        "interval_ms": 1000,
        "history_seconds": 120,
        "bits": False,
        "color": True,
        "future_option": {"kept": True},
    }
    path.write_text(json.dumps(original))
    path.chmod(0o600)
    arguments = ("--bits", "--interval", "0.1", "--history", "10", "--no-color")
    with Terminal(binary, config_home, arguments, NO_COLOR="1") as terminal:
        terminal.expect(b"unknown keys")
        terminal.expect(b"Saved interface nettop-gone unavailable")
        # Saving without changes keeps every file value, despite CLI overrides,
        # NO_COLOR and the automatic fallback for the missing interface.
        before = path.read_bytes()
        terminal.send(F12)
        terminal.wait_for(lambda: path.read_bytes() != before, "F12 rewrote settings")
        saved = read_saved(path)
        assert saved == {**original, "show_graph": True, "graph_style": "steps", "rx_color": "green",
                         "tx_color": "yellow", "connections": False, "sort": "traffic",
                         "show_idle": True, "language": "auto"}, f"F12 persisted overrides: {saved}"
        # An override that the user explicitly changes in Setup is saved.
        mark = terminal.send(F2 + DOWN + DOWN + RIGHT + DOWN + b"+")
        terminal.expect(b"Unsaved changes", mark)
        terminal.send(F12)
        terminal.wait_for(lambda: read_saved(path)["history_seconds"] != 120, "F12 saved Setup")
        saved = read_saved(path)
        assert saved["history_seconds"] == 20, f"Setup change was not saved: {saved}"
        for key in ("interface", "interval_ms", "bits", "color", "future_option"):
            assert saved[key] == original[key], f"F12 changed untouched {key}: {saved}"
        terminal.send(F10)
        terminal.quit()
    print("PASS overrides: CLI options, NO_COLOR and interface fallback stay temporary; Setup edits save")


def german_interface(binary, config_home):
    path = config_home / "nettop/config.json"
    with Terminal(binary, config_home, ready="Gerät".encode(), LC_ALL=None, LANG="de_DE.UTF-8") as terminal:
        terminal.expect("Hilfe".encode())
        terminal.expect("Speichern".encode())
        mark = terminal.send(F2)
        terminal.expect(b"Optionen: Allgemein", mark)
        # General > Language: Auto -> English switches the running UI at once.
        mark = terminal.send(RIGHT + DOWN + DOWN + DOWN + b"\r")
        # Only changed cells are redrawn, so look for short distinct fragments.
        terminal.expect(b"[English", mark)
        terminal.expect(b"Done", mark)
        terminal.send(F12)
        terminal.wait_for(lambda: read_saved(path) is not None, "F12 saved the language")
        assert read_saved(path)["language"] == "en", read_saved(path)
        terminal.send(F10)
        terminal.quit()
    print("PASS language: German from LANG, Setup switches to English and F12 saves it")


def malformed_settings(binary, config_home):
    path = config_home / "nettop/config.json"
    path.parent.mkdir(mode=0o700, parents=True)
    original = b'{"bits": true, this is deliberately incomplete\n'
    path.write_bytes(original)
    path.chmod(0o600)
    stdout, stderr = run_once(binary, config_home, "--interval", "0.1")
    assert "Settings:" in stderr and "cannot load" in stderr, "malformed JSON had no warning"
    assert "B/s" in stdout.splitlines()[1], "malformed JSON did not fall back to defaults"

    with Terminal(binary, config_home) as terminal:
        terminal.expect(b"Settings:")
        mark = terminal.send(F2)
        terminal.expect(b"Options", mark)
        mark = terminal.send(F12)
        terminal.expect(b"Save failed:", mark)
        assert path.read_bytes() == original, "F12 discarded the malformed settings file"
        assert list(path.parent.iterdir()) == [path], "failed save left temporary files"
        mark = terminal.send(F10)
        terminal.expect(b"RX/s", mark)
        terminal.quit()
    assert path.read_bytes() == original, "exit overwrote malformed settings"
    print("PASS invalid settings: visible warning, usable defaults, original file preserved")


def vanished_interface(binary, config_home):
    path = config_home / "nettop/config.json"
    path.parent.mkdir(mode=0o700, parents=True)
    path.write_text(json.dumps({"version": 1, "interface": "nettop-gone"}))
    path.chmod(0o600)
    original = path.read_bytes()
    stdout, stderr = run_once(binary, config_home, "--interval", "0.1")
    assert "Saved interface nettop-gone unavailable" in stderr, "missing interface had no warning"
    assert "automatic selection" in stderr, "interface warning did not explain the fallback"
    assert "enp112s0" in stdout.splitlines()[0], "missing interface did not use the demo default"
    assert path.read_bytes() == original, "automatic fallback overwrote the saved interface"
    print("PASS vanished interface: visible warning, automatic fallback, saved choice preserved")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 tests/setup.py /path/to/nettop")
    binary = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="nettop-setup-test-") as temporary:
        root = Path(temporary)
        persistence_and_overrides(binary, root / "preferences")
        overrides_not_persisted(binary, root / "overrides")
        german_interface(binary, root / "german")
        malformed_settings(binary, root / "malformed")
        vanished_interface(binary, root / "vanished")
    print("All Setup and configuration integration checks passed.")


if __name__ == "__main__":
    main()
