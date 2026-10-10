use std::{
    io::{self, IsTerminal, Write},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use crossterm::event::{Event, KeyEventKind};
use nwtop::{
    collector::{Collector, default_interface},
    config::{ConfigFile, RootWithForeignSettings, Settings},
    helper::Client,
    i18n::Lang,
    input::{self, Events, Input},
    model::Snapshot,
    shutdown::SignalGuard,
    ui::{self, Action, App},
};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Linux network monitor with nvtop-style graphs and process traffic"
)]
struct Args {
    /// Network interface to monitor; 'all' includes virtual links
    #[arg(short, long)]
    interface: Option<String>,
    /// Refresh interval in seconds (0.1 to 60)
    #[arg(short = 'd', long, value_parser = parse_interval)]
    interval: Option<f64>,
    /// Visible history in seconds
    #[arg(long, value_parser = clap::value_parser!(u16).range(10..=600))]
    history: Option<u16>,
    /// Display rates in bits/s rather than bytes/s
    #[arg(short, long)]
    bits: bool,
    /// Override saved units and display bytes/s
    #[arg(long, conflicts_with = "bits")]
    bytes: bool,
    /// Disable colors (also available in F2 Setup)
    #[arg(long)]
    no_color: bool,
    /// Only inspect interface counters and sockets, without packet capture
    #[arg(long)]
    no_capture: bool,
    /// Print one snapshot after a refresh interval and exit
    #[arg(long)]
    once: bool,
    /// Print one snapshot as JSON and exit
    #[arg(long)]
    json: bool,
    /// Explicit preview with synthetic data, clearly labeled DEMO
    #[arg(long)]
    demo: bool,
}

fn parse_interval(value: &str) -> Result<f64, String> {
    let interval: f64 = value
        .parse()
        .map_err(|_| "expected seconds, for example 0.5".to_string())?;
    if !interval.is_finite() || !(0.1..=60.0).contains(&interval) {
        return Err("interval must be between 0.1 and 60 seconds".into());
    }
    Ok(interval)
}

enum Source {
    Live(Box<Collector>),
    Helper(Client),
    Demo {
        tick: u64,
        start: Instant,
    },
    #[cfg(test)]
    Failing {
        helper: bool,
    },
}

impl Source {
    fn sample(&mut self, interface: Option<&str>, shutdown: &SignalGuard) -> Result<Snapshot> {
        match self {
            Self::Live(collector) => collector.sample(interface),
            Self::Helper(client) => client.sample(interface, || shutdown.requested()),
            Self::Demo { tick, start } => {
                let snapshot = ui::demo_snapshot(*tick, start.elapsed().as_secs_f64());
                *tick += 1;
                Ok(snapshot)
            }
            #[cfg(test)]
            Self::Failing { .. } => bail!("injected sample failure"),
        }
    }

    /// A revoked, outdated, stalled or crashed helper must not prevent
    /// interface monitoring; direct counters replace it.
    fn is_helper(&self) -> bool {
        match self {
            Self::Helper(_) => true,
            #[cfg(test)]
            Self::Failing { helper } => *helper,
            _ => false,
        }
    }
}

/// Startup notices: English on stderr, the UI language in the terminal.
enum Notice {
    Settings(String),
    UnknownKeys(Vec<String>),
    InterfaceUnavailable(String),
}

impl Notice {
    fn text(&self, lang: Lang) -> String {
        match self {
            Self::Settings(error) => lang.settings_problem(error),
            Self::UnknownKeys(keys) => lang.unknown_keys(keys),
            Self::InterfaceUnavailable(name) => lang.interface_unavailable(name),
        }
    }
}

/// Apply command-line options and NO_COLOR to a copy of the saved settings.
/// These overrides apply to this run only and are never saved by F12.
fn runtime_settings(args: &Args, saved: &Settings, no_color_env: bool) -> Settings {
    let mut settings = saved.clone();
    if let Some(interval) = args.interval {
        settings.interval_ms = (interval * 1000.0).round() as u64;
    }
    if let Some(history) = args.history {
        settings.history_seconds = history;
    }
    if args.bits {
        settings.bits = true;
    }
    if args.bytes {
        settings.bits = false;
    }
    if args.no_color || no_color_env {
        settings.color = false;
    }
    if let Some(interface) = &args.interface {
        settings.interface = Some(interface.clone());
    }
    settings
}

fn main() -> Result<()> {
    let args = Args::parse();
    let shutdown = SignalGuard::new().context("registering shutdown handlers")?;
    let mut notices = Vec::new();
    let config = match ConfigFile::discover() {
        Ok(config) => Some(config),
        Err(error) => {
            notices.push(Notice::Settings(format!("{error:#}")));
            None
        }
    };
    let saved = match config
        .as_ref()
        .map(ConfigFile::load_with_unknown_keys)
        .transpose()
    {
        Ok(loaded) => {
            let loaded = loaded.unwrap_or_default();
            if !loaded.unknown_keys.is_empty() {
                notices.push(Notice::UnknownKeys(loaded.unknown_keys));
            }
            loaded.settings
        }
        Err(error) => {
            notices.push(Notice::Settings(format!("{error:#}")));
            Settings::default()
        }
    };
    let no_color_env = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
    let mut settings = runtime_settings(&args, &saved, no_color_env);
    settings.validate()?;
    for notice in &notices {
        eprintln!("{}", notice.text(Lang::En));
    }
    if !cfg!(target_os = "linux") && !args.demo {
        bail!("live monitoring requires Linux");
    }
    let mut helper_error = None;
    let mut source = if args.demo {
        Source::Demo {
            tick: 0,
            start: Instant::now(),
        }
    } else if !args.no_capture && unsafe { libc::geteuid() } != 0 {
        match Client::start() {
            Ok(client) => Source::Helper(client),
            Err(error) => {
                helper_error = Some(error);
                Source::Live(Box::new(Collector::new(true)?))
            }
        }
    } else {
        Source::Live(Box::new(
            Collector::new(!args.no_capture).context("cannot initialize Linux network counters")?,
        ))
    };
    let automatic_interface = if args.demo {
        Some("enp112s0".into())
    } else {
        default_interface()
    };
    let mut interface = match settings.interface.as_deref() {
        Some("all") => None,
        Some(name) => Some(name.to_string()),
        None => automatic_interface.clone(),
    };
    let Some(mut first) = startup_sample(
        &mut source,
        interface.as_deref(),
        &shutdown,
        &mut helper_error,
        direct_collector,
    )?
    else {
        return Ok(());
    };
    if let Some(name) = &interface
        && !first.interfaces.iter().any(|iface| &iface.name == name)
    {
        if args.interface.is_some() {
            bail!(
                "interface {name:?} does not exist; available: {}",
                first
                    .interfaces
                    .iter()
                    .map(|iface| iface.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let notice = Notice::InterfaceUnavailable(name.clone());
        eprintln!("{}", notice.text(Lang::En));
        notices.push(notice);
        // Only this run falls back; F12 keeps the saved choice unless changed.
        settings.interface = None;
        interface = automatic_interface.clone();
        let Some(retry) = startup_sample(
            &mut source,
            interface.as_deref(),
            &shutdown,
            &mut helper_error,
            direct_collector,
        )?
        else {
            return Ok(());
        };
        first = retry;
    }
    if !first.capture.active
        && let Some(error) = helper_error
    {
        eprintln!("Capture setup: {error:#}. Run scripts/setup-capture.sh once; see README.");
    }
    if args.once || args.json {
        let deadline = Instant::now() + Duration::from_millis(settings.interval_ms);
        while Instant::now() < deadline {
            if shutdown.requested() {
                return Ok(());
            }
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(100)),
            );
        }
        let snapshot = match source.sample(interface.as_deref(), &shutdown) {
            Err(_) if shutdown.requested() => return Ok(()),
            result => result?,
        };
        let mut stdout = io::stdout().lock();
        let written = if args.json {
            let json = serde_json::to_string_pretty(&snapshot)?;
            writeln!(stdout, "{json}")
        } else {
            print_snapshot(
                &mut stdout,
                &snapshot,
                interface.as_deref(),
                settings.bits,
                args.demo,
            )
        };
        ignore_closed_output(written.and_then(|()| stdout.flush()))?;
        return Ok(());
    }
    if !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        bail!("interactive mode needs a terminal; use --once or --json for non-interactive output");
    }
    let mut app = App::with_saved(interface, settings, saved, args.demo);
    app.system_lang = Lang::system();
    app.auto_interface = automatic_interface;
    if !notices.is_empty() {
        let lang = app.lang();
        app.show_error(
            notices
                .iter()
                .map(|notice| notice.text(lang))
                .collect::<Vec<_>>()
                .join(" | "),
        );
    }
    app.update(first);
    // Color policy is applied to the whole buffer by the UI, so changing it in
    // Setup can also reset previously colored cells and override NO_COLOR.
    crossterm::style::force_color_output(true);
    let mut terminal = ratatui::init();
    let result = Events::start()
        .context("starting terminal input")
        .and_then(|events| {
            run(
                &mut terminal,
                &mut source,
                &mut app,
                config.as_ref(),
                &shutdown,
                &events,
            )
        });
    let restored = ratatui::try_restore();
    let cursor = terminal.show_cursor();
    // ratatui reports restore and cursor errors (the latter when dropping the
    // terminal) with `eprintln!`, which panics on a closed terminal's stderr
    // and then aborts in ratatui's panic hook. Report them below instead.
    std::mem::forget(terminal);
    // A closed terminal ends the monitor like SIGHUP, which the kernel sends
    // only to a session leader. Output can fail just before the hang-up is
    // visible on input, so a failed run waits briefly for it.
    let grace = if result.is_err() {
        Duration::from_millis(100)
    } else {
        Duration::ZERO
    };
    if shutdown.requested() || input::terminal_hung_up(grace) {
        return Ok(());
    }
    if let Err(error) = restored.and(cursor) {
        let _ = writeln!(io::stderr(), "Failed to restore terminal: {error}");
    }
    result
}

/// A startup sample. A failed helper is replaced by `fallback` and its error
/// kept for the setup hint; `None` means shutdown was requested meanwhile.
fn startup_sample(
    source: &mut Source,
    interface: Option<&str>,
    shutdown: &SignalGuard,
    helper_error: &mut Option<anyhow::Error>,
    fallback: impl FnOnce() -> Result<Source>,
) -> Result<Option<Snapshot>> {
    match source.sample(interface, shutdown) {
        Ok(snapshot) => Ok(Some(snapshot)),
        Err(_) if shutdown.requested() => Ok(None),
        Err(error) if source.is_helper() => {
            *helper_error = Some(error);
            *source = fallback()?;
            match source.sample(interface, shutdown) {
                Err(_) if shutdown.requested() => Ok(None),
                result => result.map(Some),
            }
        }
        Err(error) => Err(error),
    }
}

/// A reader that exits early, as in `nwtop --json | head`, is not an error.
fn ignore_closed_output(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}

/// Take one sample. Failures become a visible notice instead of ending the
/// monitor; a failed capture helper is replaced by `fallback`.
fn refresh(
    source: &mut Source,
    app: &mut App,
    shutdown: &SignalGuard,
    fallback: impl FnOnce() -> Result<Source>,
) {
    let error = match source.sample(app.interface.as_deref(), shutdown) {
        Ok(snapshot) => {
            app.update(snapshot);
            return;
        }
        Err(_) if shutdown.requested() => return,
        Err(error) => error,
    };
    let lang = app.lang();
    if !source.is_helper() {
        app.show_error(lang.sample_failed(&format!("{error:#}")));
        return;
    }
    match fallback() {
        Ok(replacement) => {
            // Dropping the client also stops and reaps the failed helper.
            *source = replacement;
            match source.sample(app.interface.as_deref(), shutdown) {
                Ok(snapshot) => app.update(snapshot),
                Err(_) if shutdown.requested() => return,
                Err(retry) => {
                    app.show_error(lang.sample_failed(&format!("{retry:#}")));
                    return;
                }
            }
            app.show_error(lang.helper_failed(&format!("{error:#}")));
        }
        Err(fallback_error) => {
            app.show_error(lang.sample_failed(&format!("{error:#}; {fallback_error:#}")))
        }
    }
}

fn direct_collector() -> Result<Source> {
    Ok(Source::Live(Box::new(Collector::new(true)?)))
}

fn run(
    terminal: &mut ratatui::DefaultTerminal,
    source: &mut Source,
    app: &mut App,
    config: Option<&ConfigFile>,
    shutdown: &SignalGuard,
    events: &Events,
) -> Result<()> {
    let mut next_sample = Instant::now() + Duration::from_millis(app.settings.interval_ms);
    'running: loop {
        if shutdown.requested() || input::terminal_hung_up(Duration::ZERO) {
            break;
        }
        terminal.draw(|frame| ui::draw(frame, app))?;
        // Check frequently for external termination and terminal hang-up
        // without repainting between events or samples. Even a 60-second
        // interval exits promptly.
        let event = loop {
            if shutdown.requested() || input::terminal_hung_up(Duration::ZERO) {
                break 'running;
            }
            let remaining = next_sample.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break None;
            }
            match events.next(remaining.min(Duration::from_millis(100))) {
                Input::Event(event) => break Some(event),
                Input::Timeout => {}
                Input::Failed(error) => return Err(error).context("reading terminal input"),
            }
        };
        if let Some(event) = event {
            match event {
                Event::Key(key) if key.kind != KeyEventKind::Release => match app.handle_key(key) {
                    Action::Quit => break,
                    Action::InterfaceChanged => {
                        refresh(source, app, shutdown, direct_collector);
                        next_sample =
                            Instant::now() + Duration::from_millis(app.settings.interval_ms);
                    }
                    Action::SettingsChanged => {
                        next_sample = next_sample
                            .min(Instant::now() + Duration::from_millis(app.settings.interval_ms));
                    }
                    Action::SaveSettings => save_settings(app, config),
                    Action::None => {}
                },
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
        if Instant::now() >= next_sample {
            refresh(source, app, shutdown, direct_collector);
            next_sample = Instant::now() + Duration::from_millis(app.settings.interval_ms);
        }
    }
    Ok(())
}

fn save_settings(app: &mut App, config: Option<&ConfigFile>) {
    let lang = app.lang();
    let settings = app.settings_to_save();
    match config
        .context(lang.settings_path_unavailable())
        .and_then(|config| config.save(&settings).map(|()| config.path()))
    {
        Ok(path) => app.settings_saved(lang.saved(&path.display().to_string())),
        Err(error) if error.downcast_ref::<RootWithForeignSettings>().is_some() => {
            app.show_error(lang.root_with_foreign_settings())
        }
        Err(error) => app.show_error(lang.save_failed(&format!("{error:#}"))),
    }
}

fn print_snapshot(
    out: &mut impl Write,
    snapshot: &Snapshot,
    interface: Option<&str>,
    bits: bool,
    demo: bool,
) -> io::Result<()> {
    let (rx, tx, _, _) = ui::totals(snapshot, interface);
    writeln!(
        out,
        "nwtop{}  {}",
        if demo { " DEMO" } else { "" },
        interface.unwrap_or("all interfaces")
    )?;
    writeln!(
        out,
        "RX {}  TX {}",
        ui::format_rate(rx, bits),
        ui::format_rate(tx, bits)
    )?;
    writeln!(out, "{}", snapshot.capture.message)?;
    writeln!(
        out,
        "{:>8}  {:<12}  {:>14}  {:>14}  COMMAND",
        "PID", "USER", "RX/s", "TX/s"
    )?;
    let mut rows: Vec<_> = snapshot.processes.iter().collect();
    rows.sort_by(|a, b| (b.rx_rate + b.tx_rate).total_cmp(&(a.rx_rate + a.tx_rate)));
    for row in rows.into_iter().take(25) {
        writeln!(
            out,
            "{:>8}  {:<12.12}  {:>14}  {:>14}  {}",
            row.pid.map_or_else(|| "-".into(), |pid| pid.to_string()),
            row.user,
            if snapshot.capture.active {
                ui::format_rate(row.rx_rate, bits)
            } else {
                "-".into()
            },
            if snapshot.capture.active {
                ui::format_rate(row.tx_rate, bits)
            } else {
                "-".into()
            },
            row.name
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyCode;

    #[test]
    fn interval_rejects_nan_infinity_and_zero() {
        for invalid in ["0", "NaN", "inf", "-1", "61", "nope"] {
            assert!(parse_interval(invalid).is_err());
        }
        assert_eq!(parse_interval("0.5").unwrap(), 0.5);
    }

    #[test]
    fn command_line_overrides_and_no_color_are_runtime_only() {
        let saved = Settings {
            interface: Some("eth0".into()),
            ..Settings::default()
        };
        let args = Args::parse_from([
            "nwtop",
            "--bits",
            "--interval",
            "0.1",
            "--history",
            "10",
            "--interface",
            "lo",
        ]);
        let runtime = runtime_settings(&args, &saved, true);
        assert!(runtime.bits && !runtime.color);
        assert_eq!(runtime.interval_ms, 100);
        assert_eq!(runtime.history_seconds, 10);
        assert_eq!(runtime.interface.as_deref(), Some("lo"));
        let mut app = App::with_saved(Some("lo".into()), runtime, saved.clone(), true);
        assert_eq!(app.settings_to_save(), saved);
        assert!(!app.settings_dirty());
        // Toggling units in the monitor persists only that preference.
        app.handle_key(KeyCode::Char('b').into());
        let expected = Settings {
            bits: false,
            ..saved.clone()
        };
        assert_eq!(app.settings_to_save(), expected);
        assert!(!app.settings_dirty(), "false equals the saved value");
        app.handle_key(KeyCode::Char('b').into());
        assert!(app.settings_to_save().bits);
        assert!(app.settings_dirty());
        app.settings_saved("saved".into());
        assert!(!app.settings_dirty());
        assert!(app.settings_to_save().color, "NO_COLOR must not be saved");
        assert_eq!(app.settings_to_save().history_seconds, 60);
        assert_eq!(app.settings_to_save().interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn closed_output_pipes_are_a_clean_exit() {
        let closed = io::Error::from(io::ErrorKind::BrokenPipe);
        assert!(ignore_closed_output(Err(closed)).is_ok());
        let other = io::Error::from(io::ErrorKind::PermissionDenied);
        assert!(ignore_closed_output(Err(other)).is_err());
        let mut output = Vec::new();
        print_snapshot(
            &mut output,
            &ui::demo_snapshot(1, 1.0),
            Some("enp112s0"),
            false,
            true,
        )
        .unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .starts_with("nwtop DEMO  enp112s0")
        );
    }

    #[test]
    fn runtime_sample_errors_are_notices_and_helpers_fall_back() {
        let shutdown = SignalGuard::new().unwrap();
        let mut app = App::new(Some("enp112s0".into()), 60, false, true);
        let mut source = Source::Failing { helper: false };
        refresh(&mut source, &mut app, &shutdown, || {
            panic!("only a failed helper may be replaced")
        });
        assert!(app.notice_error);
        assert!(
            app.notice
                .as_deref()
                .unwrap()
                .contains("injected sample failure")
        );
        assert!(matches!(source, Source::Failing { .. }));

        let mut app = App::new(Some("enp112s0".into()), 60, false, true);
        let mut source = Source::Failing { helper: true };
        refresh(&mut source, &mut app, &shutdown, || {
            Ok(Source::Demo {
                tick: 0,
                start: Instant::now(),
            })
        });
        assert!(matches!(source, Source::Demo { .. }));
        assert!(app.notice_error);
        assert!(
            app.notice
                .as_deref()
                .unwrap()
                .starts_with("Capture helper failed")
        );
        assert_eq!(app.history.len(), 1, "fallback samples immediately");

        let mut app = App::new(Some("enp112s0".into()), 60, false, true);
        let mut source = Source::Failing { helper: true };
        refresh(&mut source, &mut app, &shutdown, || bail!("no counters"));
        assert!(app.notice.as_deref().unwrap().contains("no counters"));
    }

    #[test]
    fn every_startup_sample_falls_back_from_a_failed_helper() {
        let shutdown = SignalGuard::new().unwrap();
        let mut helper_error = None;
        let mut source = Source::Failing { helper: true };
        let snapshot = startup_sample(
            &mut source,
            Some("enp112s0"),
            &shutdown,
            &mut helper_error,
            || {
                Ok(Source::Demo {
                    tick: 0,
                    start: Instant::now(),
                })
            },
        )
        .unwrap();
        assert!(snapshot.is_some());
        assert!(matches!(source, Source::Demo { .. }));
        assert!(helper_error.is_some());
        // Direct collection errors are still reported, not replaced.
        let mut source = Source::Failing { helper: false };
        let mut helper_error = None;
        assert!(
            startup_sample(&mut source, None, &shutdown, &mut helper_error, || {
                panic!("only a failed helper may be replaced")
            })
            .is_err()
        );
        assert!(helper_error.is_none());
    }
}
