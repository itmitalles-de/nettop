use std::{
    io::{self, IsTerminal},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use crossterm::event::{self, Event, KeyEventKind};
use nettop::{
    collector::{Collector, default_interface},
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
    #[arg(short = 'd', long, default_value = "1", value_parser = parse_interval)]
    interval: f64,
    /// Visible history in seconds
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u16).range(10..=600))]
    history: u16,
    /// Display rates in bits/s rather than bytes/s
    #[arg(short, long)]
    bits: bool,
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
    let interface = match args.interface.as_deref() {
        Some("all") => None,
        Some(name) => Some(name.to_string()),
        None if args.demo => Some("enp112s0".into()),
        None => default_interface(),
    };
    let first = match source.sample(interface.as_deref(), &shutdown) {
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
    if args.once || args.json {
        let deadline = Instant::now() + Duration::from_secs_f64(args.interval);
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
            print_snapshot(&snapshot, interface.as_deref(), args.bits, args.demo);
        }
        return Ok(());
    }
    if !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        bail!("interactive mode needs a terminal; use --once or --json for non-interactive output");
    }
    let mut app = App::new(interface, args.history, args.bits, args.demo);
    app.update(first);
    let mut terminal = ratatui::init();
    let result = run(
        &mut terminal,
        &mut source,
        &mut app,
        Duration::from_secs_f64(args.interval),
        &shutdown,
    );
    ratatui::restore();
    if shutdown.requested() { Ok(()) } else { result }
}

fn run(
    terminal: &mut ratatui::DefaultTerminal,
    source: &mut Source,
    app: &mut App,
    interval: Duration,
    shutdown: &SignalGuard,
) -> Result<()> {
    let mut next_sample = Instant::now() + interval;
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
                        next_sample = Instant::now() + interval;
                    }
                    Action::None => {}
                },
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
        if Instant::now() >= next_sample {
            app.update(source.sample(app.interface.as_deref(), shutdown)?);
            next_sample = Instant::now() + interval;
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
