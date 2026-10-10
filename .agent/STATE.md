# Verified state

## Optional attribution completion (2026-10-10)

- Current implementation: `b5f3b56`, [PR #15](https://github.com/itmitalles-de/nettop/pull/15),
  addressing #8, #9, #10 and #13. Earlier optional-backend work merged through
  PR #11 (`cbb33c5`, closing #2) and PR #14 (`5caf4cc`, closing #12).
- Extended All process totals use captured TCP/UDP IP skbs at actual socket
  endpoints across namespaces. All 23 BPF hooks attach before recording starts.
  Socket incarnation plus process/descriptor evidence resolves untracked queued
  traffic without inferring NAT from missing conntrack. No payloads, syscall
  byte counters, namespace entry or additional capabilities were introduced.
- Selected host interfaces retain conservative pcap/conntrack accounting;
  untracked traffic may remain unknown there. Pure forwarding requires a
  selected interface. Interface graphs retain host kernel counters, whereas All
  process totals cover accessible namespaces. GRO/GSO/fragmentation are counted
  as observed IP skbs, not reconstructed wire segments. These scopes are visible
  in status and documented in README and ARCHITECTURE.
- Sharing, reused identities and lost metadata remain conservative. Fatal socket
  identity cleanup failure disarms the backend until restart; All becomes
  unavailable instead of switching byte sources. UDP connection rows use actual
  packet endpoints; incomplete ports contribute only process bytes.
- Capture and attribution queue pressure have separate notices. Both bounded
  capture sources wake attribution at one-quarter capacity; wait-queue pressure
  preserves known endpoints and unknown captured bytes. Limits were not raised.
- Verified: formatting, Clippy in both modes, 150 extended Rust tests including
  Rust 1.88, standard isolated live/short-lived TCP/UDP, capability helper,
  terminal and settings tests. Implementation CI and all five CodeQL analyses
  passed. Independent production and harness reviews were resolved.
- Real guests: 46 namespace/NAT/NOTRACK cases on x86_64 Linux 6.8, plus four
  competing pre-DNAT-listener reruns on Linux 7.0. Linux 7.0 passed all ten
  adversarial cases in both All and selected scopes (20 cases). ARM64 Linux 6.8
  executed all 23 hooks and six application cases. Helper capabilities/cleanup
  and fatal-deletion fault injection passed. See tests/adversarial.md for exact
  coverage and retained emulation-related timeout/timestamp diagnostics; no
  safety guard or product deadline was relaxed.
- Six final Linux 7.0 pressure cases passed: 4096/20000/80000 datagrams in both
  scopes. All retained 100% of expected IP bytes at every size; larger selected
  bursts retained about 92.8%/92.7%, with visible pcap losses. No duplicate totals;
  maximum sampled RSS 23,392 KiB. No claim of loss-free pcap at arbitrary loads.
- Extended UI and helper installed and hashes verified before host testing.
  Twelve fresh All starts on the host had zero drops, queue overflows or
  socket-event failures; known TX 4.10–4.50 MB/s, unknown RX/TX below 0.8 kB/s.
  A final --once exited cleanly. Ordinary non-IP frames remained visibly counted
  as unsupported. UI has no capabilities; helper is root:tim 0750 with
  DAC_READ_SEARCH, NET_ADMIN, NET_RAW, SYS_PTRACE, PERFMON and BPF.
  UI SHA-256: `6fb79f9c2963ad3864a61511e7538a8e61796a1e9cd88a0c765659cb7993ce5b`;
  helper: `d41e1cd88dede5be2c1c1c767e2b895e14552d5e07389032a919edf7ad48b6c4`.
- Both owned VMs are shut down; PID absence and closed SSH ports verified.
  Private evidence is outside Git: ../nettop-review/remaining/VM-VALIDATION.md,
  ../nettop-review/remaining-attribution/{namespaces,host-final}/ and the initial
  pressure comparison in ../nettop-review/issue-2/. Retain overlays/evidence;
  use generated wrappers/current port files when restarting, never stale ports.

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
