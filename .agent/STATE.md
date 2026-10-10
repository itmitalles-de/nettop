# Verified state

## Optional attribution implementation (2026-10-10)

- Implementation merged as [PR #11](https://github.com/itmitalles-de/nettop/pull/11)
  (`cbb33c5`, implementation `98ccdb5`), closing #2.
- Opt-in `ebpf` build adds socket lifecycle events, namespace inventories,
  conntrack translation/reuse quarantine, veth deduplication and visible degraded
  status. Both installer scripts accept `--extended-attribution`; standard
  builds require neither clang/libbpf nor extra capabilities. Capture starts
  before the initial descriptor scan. Captured IP packets remain the byte source.
- Extended helper grants BPF, PERFMON and NET_ADMIN in addition to the standard
  capture/read capabilities. BPF and capture workers drop all capabilities;
  conntrack retains only NET_ADMIN and sampling only process-read capabilities.
  VM checks verified the unprivileged UI, exact per-thread limits, NO_NEW_PRIVS
  and complete helper/probe cleanup. No permanent service or pinned BPF object.
- Linux 6.8 x86_64 VM tests cover sub-millisecond TCP/UDP IPv4/IPv6 sockets,
  exited owners, and 16 positive namespace/NAT cases (tracked direct, DNAT, SNAT,
  combined NAT and host hairpin, All and selected interfaces). Separate negative
  cases passed with conservative untracked-flow attribution and a visible notice.
  One earlier VM run rejected five uncertain timestamps; an unchanged repeat
  passed. Preserve the log and extend stress coverage in #10.
  ARM64 BPF compilation passed; runtime coverage remains x86_64.
- Standard terminal/setup, isolated live TCP/UDP, short-socket and capability
  helper checks passed, including extended-build fallback without extra rights.
  Formatting, Clippy in both configurations, Rust tests including 1.88.0,
  ShellCheck and Cargo Audit passed. CI adds optional-feature compilation/tests.
- Remaining work: [#8](https://github.com/itmitalles-de/nettop/issues/8)
  untracked long-lived flows, [#9](https://github.com/itmitalles-de/nettop/issues/9)
  namespace capture boundaries, [#10](https://github.com/itmitalles-de/nettop/issues/10)
  further adversarial/kernel runtime coverage, and
  [#13](https://github.com/itmitalles-de/nettop/issues/13) bounded packet-queue
  pressure under host load. Missing conntrack mappings never
  prove absence of NAT, and nettop does not change firewall rules.
- Startup follow-up [PR #14](https://github.com/itmitalles-de/nettop/pull/14)
  merged as `5caf4cc` (implementation `12bae0e`), closing #12. It fixes
  libbpf callback yielding (negative return),
  attaches exits before entries and arms metadata recording only after all
  links are installed. Bounded loss diagnostics persist through quarantine;
  pending-map deletion failures are checked. The system-dependent IPv6 cache
  test now asserts only on its own socket.
- Real kernel regressions prove both fixes: 5000 queued metadata events no
  longer discard later events; deliberately incomplete attachment produces
  nested-call losses unless recording remains disarmed until setup completes.
  All six VM live cases and capability/cleanup checks passed on the final
  build. Formatting, Clippy in both modes and 141 Rust tests (also 1.88.0)
  passed. PR #14 standard/extended/MSRV/audit CI and all five CodeQL analyses
  passed; independent review found no material issues.
- Local `main` is synchronized; the merged local/remote work branch was
  removed. Extended UI and helper are installed on Linux 7.0 from this follow-up.
  Twelve fresh host starts showed no socket-event loss or ownership quarantine,
  known TX 3.85–4.05 MB/s and unknown TX 0–2.15 kB/s. Eleven samples had no
  packet overflow; one reported 438 packets at the flow limit without event
  loss or loss of normal attribution (#13). A final `--once` exited cleanly
  with roughly 4 MiB/s TX and unknown RX/TX of 138/95 B/s.
  Do not report that all host checks
  were overflow-free. The untracked-flow notice remains expected under #8.
  UI has no capabilities; helper is root:tim 0750 with the extended set.
  Verified SHA-256: UI `4ee579712ae9c9321ff6555f5a41e2aa482eb591fb534785de2e2443878f14ac`,
  helper `9a66ba48a869e8ba32bcfa1d9ae084a7c8c4a3f3601d96a12366c50778d22162`.
- Private evidence and the dedicated QEMU guest are outside Git under
  `../nettop-review/issue-2/`; use generated VM wrappers/current PID files,
  never stale ports. The Linux 6.8.0-146 guest is stopped; process exit and SSH
  closure were verified. Retain evidence and keep credentials and raw runtime
  snapshots out of Git.

## Completed baseline

- Public repository `itmitalles-de/nettop`, branch `main`, licensed
  GPL-3.0-or-later (owner relicensed from MIT on 2026-10-10).
- Rust 1.88+ Linux binary, runtime-loaded libpcap; no libpcap development package.
- Native ANSI htop/nvtop styling: green RX, yellow TX, stepped history graph,
  inverse green headers, cyan selection and function-key bar. F2 opens persistent
  Setup; F5 selects an interface, F6 selects sorting, F12 saves preferences.
  Layout tests cover 36x16, 40x24, 52x18, 80x24 and 120x36, including Setup.
- The device header omits the redundant app name. Table rows follow the graph
  directly; routine capture and table-summary lines are hidden. Notices, active
  filters and capture warnings can temporarily use one status row; details are in F1.
- Preferences use `$XDG_CONFIG_HOME/nettop/config.json` or
  `~/.config/nettop/config.json`, with atomic private writes. CLI options override
  saved values; malformed files stay intact. The helper never reads preferences.
- Full repository code review completed; fixed terminal signal cleanup, reused
  socket attribution, IPv4/IPv6 wildcard matching and forwarding misattribution.
- Second full review (2026-10-10) fixed: CLI overrides/NO_COLOR persisted by F12,
  runtime helper failure exiting the TUI, closed-pipe panics, unit rounding,
  `sudo -E` settings ownership, unknown config keys, fixed white text on light
  themes, collector environment (RDMA driver env), interval-dependent attribution
  (background `nettop-attrib` pass every 250–500 ms), O(N²) socket resolve,
  TIME-WAIT remnants, owner-scan latency, IPv4 alias labels, sticky drop/limit
  warnings, BIG TCP, SOCK_DIAG/fd-scan cost, fragments, docker-proxy DNAT and
  sysfs ifindex. TUI is English/German (`language` in Setup); the site has a
  system-aware light/dark theme and EN/DE, both with persisted toggles.
  `tests/short_lived.py` covers sockets closed within a 20 s interval and a
  slow acceptor. Its flake was fixed: an owner scan racing a descriptor close
  dropped the known owner, and a retained accept-queue entry (inode 0) made
  the accepted socket ambiguous for up to 3 s.
- `cargo fmt --check`, Clippy with warnings denied, 67 Rust tests (also on Rust
  1.88.0), release build, ShellCheck, PTY terminal/setup checks, isolated live
  capture, helper and short-lived socket tests passed on 2026-10-10. CI now also
  runs Cargo Audit (109 dependencies, none reported locally) with job timeouts.
- All Rust tests also passed with the declared minimum Rust 1.88.0; CI covers it.
- `tests/setup.py` verifies real PTY editing/saving, restart, CLI overrides,
  unavailable saved interfaces and malformed settings. Terminal restoration
  checks pass for q, SIGTERM, SIGINT and SIGHUP. New UI/preferences changes were
  independently reviewed; unavailable rates remain visible when idle rows are hidden.
- Closed-terminal hang fix (branch `fix/tty-hangup`, 2026-10-10): a closed PTY
  master previously left nettop spinning in crossterm's EOF read loop (~60 % CPU)
  and deaf to SIGHUP. `tests/terminal.py` now checks a closed terminal without
  SIGHUP, SIGHUP after closing and a closed controlling terminal (exit 0 within
  2 s); `tests/helper.py` checks that the helper is reaped in both hang-up cases.
- Review round 2 merged as PR #7 (`c887692`, 2026-10-10); issue #6 is closed.
  Likely root cause fixed (SOCK_DIAG deadline started before
  sendto(), which can autoload diag modules, plus a 2 s backoff after a timed-out
  dump and no deferral while V6ONLY was unknown). Also: drain before socket
  refresh and one-time deferral of local flows without a candidate, defer window
  derived from the owner-scan gap, SO_REUSEPORT ties credit their process,
  lower-device duplicates skipped in all-interface process rows, per-pass address
  sets, startup helper fallback for the second sample, translated collector status
  (structured `notes`, protocol v1 kept; mixed old/new UI and helper pass
  `tests/helper.py`), setup refuses shared groups/silent group takeover
  (`--allow-shared-group`, `--reassign-group`) and verifies a root-only copy.
  `tests/live_capture.py` adds sockets opened after monitor start; 10/10 runs
  passed locally (diag modules were already loaded on that host, so the autoload
  timing itself was not reproduced).
- Real separate-PID TCP/UDP capture tests passed for IPv4 and IPv6 in an isolated
  Ubuntu 26.04 Docker container, including IPv4 to a dual-stack UDP listener; no
  loopback double counting. CI uses Ubuntu 24.04. See `tests/live_capture.py`.
- Normal-user capture uses the optional root-owned capability helper installed
  once by `scripts/setup-capture.sh` with administrator authentication. Daily
  launch is `nettop`; the UI has no capabilities. Helper updates need setup again.
- `tests/helper.py` verified root-owned traffic from an unprivileged UI, exact
  per-thread capability limits, installer refusal cases, protocol bounds,
  signal/timeout cleanup with a stopped helper, and EOF cleanup after UI SIGKILL.
- Standard-mode owners are sampled; short-lived, shared and ambiguously reused
  sockets can remain unattributed. Extended-mode coverage and remaining namespace
  boundaries are recorded above.
- Local installation uses `scripts/install.sh`, which refuses to replace an
  unrelated executable. Only explicitly requested `--demo` uses synthetic data.
- Completion verified on 2026-10-10: `main` fast-forwarded to `c887692`; the
  merged review worktree and local/remote branch were removed. UI and helper
  were reinstalled with both scripts; installed SHA-256 hashes match the builds.
  Helper remains root:tim 0750 with DAC_READ_SEARCH, NET_RAW and SYS_PTRACE.
  Live `--once` attributed user and root processes; the sample had about
  6 KiB/s unattributed in each direction versus about 4 MiB/s total TX.
  Local fmt, Clippy with warnings denied and all 83 Rust tests passed; CI and
  CodeQL passed on the merge commit. Issue #2 was subsequently implemented
  by PR #11; current limits and follow-ups are recorded above.
- The redesigned README shares the site's banner and explicit DEMO image.
  `site/` contains the responsive project website, terminal recording and local
  licensed fonts. Pages is configured as public with custom domain
  `nettop.wutz.io`; the source repository is also public. The Pages workflow
  deploys static files independently of Rust CI and its container dependencies.
- GitHub approved the custom-domain certificate and HTTPS enforcement is enabled.
  DNS points directly to `itmitalles-de.github.io` without Cloudflare proxying.
  Pages deployments probe the public HTTPS page after publication. The full Rust
  CI, including isolated capture/helper tests and Rust 1.88, passed for the site work.
