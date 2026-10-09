# Verified state

- New private repository: `itmitalles-de/nettop`, branch `main`.
- Rust 1.88+ Linux binary, runtime-loaded libpcap; no libpcap development package.
- nvtop-inspired terminal UI: green RX, yellow TX, history graph, process/connection
  views, search, sorting, interface picker, bits toggle, pause and help. Layout
  tests cover 36x16, 40x24, 80x24 and 120x36.
- `cargo fmt --check`, Clippy with warnings denied, 23 Rust tests, release build,
  ShellCheck and CLI error/JSON checks passed on 2026-10-09.
- Real separate-PID TCP/UDP capture tests passed for IPv4 and IPv6 in an isolated
  Ubuntu 26.04 Docker container; no loopback double counting. CI repeats those
  tests on Ubuntu 24.04. See `tests/live_capture.py`.
- Interface monitoring works without root. Full process attribution needs
  capture permissions and accessible socket FDs, usually `sudo nettop` with an
  absolute binary path. Owners are sampled; short-lived and shared sockets can
  remain unattributed. Separate container network namespaces are not fully covered.
- Local installation uses `scripts/install.sh`, which refuses to replace an
  unrelated executable. Only explicitly requested `--demo` uses synthetic data.
