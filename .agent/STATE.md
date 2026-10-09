# Verified state

- New private repository: `itmitalles-de/nettop`, branch `main`.
- Rust 1.88+ Linux binary, runtime-loaded libpcap; no libpcap development package.
- nvtop-inspired terminal UI: green RX, yellow TX, history graph, process/connection
  views, search, sorting, interface picker, bits toggle, pause and help. Layout
  tests cover 36x16, 40x24, 80x24 and 120x36.
- Full repository code review completed; fixed terminal signal cleanup, reused
  socket attribution, IPv4/IPv6 wildcard matching and forwarding misattribution.
- `cargo fmt --check`, Clippy with warnings denied, 29 Rust tests, release build,
  ShellCheck, terminal/CLI/JSON checks and Cargo Audit (109 dependencies, no known
  vulnerabilities reported) passed on 2026-10-09.
- All Rust tests also passed with the declared minimum Rust 1.88.0; CI covers it.
- Real separate-PID TCP/UDP capture tests passed for IPv4 and IPv6 in an isolated
  Ubuntu 26.04 Docker container, including IPv4 to a dual-stack UDP listener; no
  loopback double counting. CI uses Ubuntu 24.04. See `tests/live_capture.py`.
- Normal-user capture uses the optional root-owned capability helper installed
  once by `scripts/setup-capture.sh` with administrator authentication. Daily
  launch is `nettop`; the UI has no capabilities. Helper updates need setup again.
- `tests/helper.py` verified root-owned traffic from an unprivileged UI, exact
  per-thread capability limits, installer refusal cases, protocol bounds,
  signal/timeout cleanup with a stopped helper, and EOF cleanup after UI SIGKILL.
- Owners are sampled; short-lived, shared and ambiguously reused sockets can
  remain unattributed. Separate container network namespaces are not fully covered.
- Local installation uses `scripts/install.sh`, which refuses to replace an
  unrelated executable. Only explicitly requested `--demo` uses synthetic data.
