use std::{
    io::{self, IsTerminal},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use crossterm::event::{self, Event, KeyEventKind};
use nettop::{
    collector::{Collector, default_interface},
    config::{ConfigFile, Settings},
    helper::Client,
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
    Demo { tick: u64, start: Instant },
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
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let shutdown = SignalGuard::new().context("registering shutdown handlers")?;
    let (config, mut notice) = match ConfigFile::discover() {
        Ok(config) => (Some(config), None),
        Err(error) => (None, Some(format!("Settings: {error:#}"))),
    };
    let mut settings = match config.as_ref().map(ConfigFile::load).transpose() {
        Ok(settings) => settings.unwrap_or_default(),
        Err(error) => {
            notice = Some(format!("Settings: {error:#}"));
            Settings::default()
        }
    };
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
    if args.no_color || std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()) {
        settings.color = false;
    }
    if let Some(interface) = &args.interface {
        settings.interface = Some(interface.clone());
    }
    settings.validate()?;
    if let Some(notice) = &notice {
        eprintln!("{notice}");
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
    let mut first = match source.sample(interface.as_deref(), &shutdown) {
        Ok(snapshot) => snapshot,
        Err(_) if shutdown.requested() => return Ok(()),
        Err(error) if matches!(source, Source::Helper(_)) => {
            // A revoked/outdated helper must not prevent interface monitoring.
            helper_error = Some(error);
            source = Source::Live(Box::new(Collector::new(true)?));
            source.sample(interface.as_deref(), &shutdown)?
        }
        Err(error) => return Err(error),
    };
    if !first.capture.active
        && let Some(error) = helper_error
    {
        eprintln!("Capture setup: {error:#}. Run scripts/setup-capture.sh once; see README.");
    }
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
        let message = format!("Saved interface {name} unavailable; using automatic selection");
        eprintln!("{message}");
        notice = Some(message);
        settings.interface = None;
        interface = automatic_interface.clone();
        first = source.sample(interface.as_deref(), &shutdown)?;
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
        if args.json {
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
        } else {
            print_snapshot(&snapshot, interface.as_deref(), settings.bits, args.demo);
        }
        return Ok(());
    }
    if !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        bail!("interactive mode needs a terminal; use --once or --json for non-interactive output");
    }
    let mut app = App::with_settings(interface, settings, args.demo);
    app.auto_interface = automatic_interface;
    app.notice_error = notice.is_some();
    app.notice = notice;
    app.update(first);
    // Color policy is applied to the whole buffer by the UI, so changing it in
    // Setup can also reset previously colored cells and override NO_COLOR.
    crossterm::style::force_color_output(true);
    let mut terminal = ratatui::init();
    let result = run(
        &mut terminal,
        &mut source,
        &mut app,
        config.as_ref(),
        &shutdown,
    );
    ratatui::restore();
    if shutdown.requested() { Ok(()) } else { result }
}

fn run(
    terminal: &mut ratatui::DefaultTerminal,
    source: &mut Source,
    app: &mut App,
    config: Option<&ConfigFile>,
    shutdown: &SignalGuard,
) -> Result<()> {
    let mut next_sample = Instant::now() + Duration::from_millis(app.settings.interval_ms);
    'running: loop {
        if shutdown.requested() {
            break;
        }
        terminal.draw(|frame| ui::draw(frame, app))?;
        // Poll frequently for external termination without repainting between
        // events or samples. Even a 60-second interval exits promptly.
        let event_ready = loop {
            if shutdown.requested() {
                break 'running;
            }
            let remaining = next_sample.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break false;
            }
            if event::poll(remaining.min(Duration::from_millis(100)))? {
                break true;
            }
        };
        if event_ready {
            match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => match app.handle_key(key) {
                    Action::Quit => break,
                    Action::InterfaceChanged => {
                        app.update(source.sample(app.interface.as_deref(), shutdown)?);
                        next_sample =
                            Instant::now() + Duration::from_millis(app.settings.interval_ms);
                    }
                    Action::SettingsChanged => {
                        next_sample = next_sample
                            .min(Instant::now() + Duration::from_millis(app.settings.interval_ms));
                    }
                    Action::SaveSettings => match config
                        .context("settings path unavailable")
                        .and_then(|config| config.save(&app.settings).map(|()| config.path()))
                    {
                        Ok(path) => app.settings_saved(format!("Saved {}", path.display())),
                        Err(error) => {
                            app.notice = Some(format!("Save failed: {error:#}"));
                            app.notice_error = true;
                        }
                    },
                    Action::None => {}
                },
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
        if Instant::now() >= next_sample {
            app.update(source.sample(app.interface.as_deref(), shutdown)?);
            next_sample = Instant::now() + Duration::from_millis(app.settings.interval_ms);
        }
    }
    Ok(())
}

fn print_snapshot(snapshot: &Snapshot, interface: Option<&str>, bits: bool, demo: bool) {
    let (rx, tx, _, _) = ui::totals(snapshot, interface);
    println!(
        "nettop{}  {}",
        if demo { " DEMO" } else { "" },
        interface.unwrap_or("all interfaces")
    );
    println!(
        "RX {}  TX {}",
        ui::format_rate(rx, bits),
        ui::format_rate(tx, bits)
    );
    println!("{}", snapshot.capture.message);
    println!(
        "{:>8}  {:<12}  {:>14}  {:>14}  COMMAND",
        "PID", "USER", "RX/s", "TX/s"
    );
    let mut rows: Vec<_> = snapshot.processes.iter().collect();
    rows.sort_by(|a, b| (b.rx_rate + b.tx_rate).total_cmp(&(a.rx_rate + a.tx_rate)));
    for row in rows.into_iter().take(25) {
        println!(
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
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_rejects_nan_infinity_and_zero() {
        for invalid in ["0", "NaN", "inf", "-1", "61", "nope"] {
            assert!(parse_interval(invalid).is_err());
        }
        assert_eq!(parse_interval("0.5").unwrap(), 0.5);
    }
}
