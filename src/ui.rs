//! A compact nvtop-style terminal interface. No data is invented by the renderer.

use std::{cmp::Ordering, collections::VecDeque};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{
        Axis, Block, Borders, Cell, Chart, Clear, Dataset, GraphType, Paragraph, Row, Table,
        TableState, Wrap,
    },
};

use crate::model::{ConnectionRow, Interface, ProcessRow, Snapshot};

const RX: Color = Color::Green;
const TX: Color = Color::Yellow;
const KEY: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;
const SELECTED: Color = Color::Rgb(111, 143, 72);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Sort {
    #[default]
    Traffic,
    Receive,
    Send,
    Total,
    Pid,
    Name,
}

impl Sort {
    pub fn next(self) -> Self {
        match self {
            Self::Traffic => Self::Receive,
            Self::Receive => Self::Send,
            Self::Send => Self::Total,
            Self::Total => Self::Pid,
            Self::Pid => Self::Name,
            Self::Name => Self::Traffic,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Traffic => "traffic",
            Self::Receive => "RX",
            Self::Send => "TX",
            Self::Total => "total",
            Self::Pid => "PID",
            Self::Name => "command",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Overlay {
    #[default]
    None,
    Help,
    Interfaces,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    InterfaceChanged,
}

#[derive(Clone, Debug)]
pub struct Sample {
    pub at: f64,
    pub rx: f64,
    pub tx: f64,
}

pub struct App {
    pub snapshot: Snapshot,
    pub interface: Option<String>,
    pub history: VecDeque<Sample>,
    pub history_seconds: f64,
    pub bits: bool,
    pub paused: bool,
    pub connections: bool,
    pub sort: Sort,
    pub filter: String,
    pub searching: bool,
    pub overlay: Overlay,
    pub table: TableState,
    picker: usize,
    help_scroll: u16,
    visible_rows: usize,
    pub demo: bool,
}

impl App {
    pub fn new(interface: Option<String>, history_seconds: u16, bits: bool, demo: bool) -> Self {
        Self {
            snapshot: Snapshot::default(),
            interface,
            history: VecDeque::new(),
            history_seconds: f64::from(history_seconds),
            bits,
            paused: false,
            connections: false,
            sort: Sort::default(),
            filter: String::new(),
            searching: false,
            overlay: Overlay::None,
            table: TableState::default().with_selected(0),
            picker: 0,
            help_scroll: 0,
            visible_rows: 10,
            demo,
        }
    }

    pub fn update(&mut self, snapshot: Snapshot) {
        if self.paused {
            return;
        }
        let (rx, tx, _, _) = totals(&snapshot, self.interface.as_deref());
        let at = snapshot.elapsed;
        self.history.push_back(Sample { at, rx, tx });
        while self
            .history
            .front()
            .is_some_and(|sample| at - sample.at > self.history_seconds)
        {
            self.history.pop_front();
        }
        // Also cap storage if the collector's clock does not advance.
        while self.history.len() > 6001 {
            self.history.pop_front();
        }
        self.snapshot = snapshot;
        let count = self.row_count();
        self.table
            .select((count > 0).then(|| self.table.selected().unwrap_or(0).min(count - 1)));
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.code == KeyCode::F(10)
            || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
        {
            return Action::Quit;
        }
        if self.overlay != Overlay::None {
            return self.overlay_key(key);
        }
        if self.searching {
            match key.code {
                KeyCode::Esc => {
                    self.searching = false;
                    self.filter.clear();
                }
                KeyCode::Enter => self.searching = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(c)
                    if !key.modifiers.contains(KeyModifiers::CONTROL)
                        && self.filter.len() < 256 =>
                {
                    // Bound input even when pasted by a terminal.
                    self.filter.push(c);
                }
                _ => {}
            }
            self.table.select(Some(0));
            return Action::None;
        }
        match key.code {
            KeyCode::Char('q') => return Action::Quit,
            KeyCode::F(1) | KeyCode::Char('?') => {
                self.overlay = Overlay::Help;
                self.help_scroll = 0;
            }
            KeyCode::F(2) | KeyCode::Char('i') => {
                self.overlay = Overlay::Interfaces;
                self.picker = self
                    .snapshot
                    .interfaces
                    .iter()
                    .position(|iface| Some(iface.name.as_str()) == self.interface.as_deref())
                    .map_or(0, |index| index + 1);
            }
            KeyCode::Tab | KeyCode::BackTab => {
                let names: Vec<_> = self
                    .snapshot
                    .interfaces
                    .iter()
                    .filter(|iface| iface.state == "up" || iface.name == "lo")
                    .map(|iface| iface.name.clone())
                    .collect();
                if !names.is_empty() {
                    let current = names
                        .iter()
                        .position(|name| Some(name) == self.interface.as_ref());
                    let next = match (current, key.code == KeyCode::BackTab) {
                        (Some(index), true) => (index + names.len() - 1) % names.len(),
                        (Some(index), false) => (index + 1) % names.len(),
                        (None, true) => names.len() - 1,
                        (None, false) => 0,
                    };
                    self.set_interface(Some(names[next].clone()));
                    return Action::InterfaceChanged;
                }
            }
            KeyCode::F(3) | KeyCode::Char('/') => self.searching = true,
            KeyCode::F(6) | KeyCode::Char('s') => {
                self.sort = self.sort.next();
                self.table.select(Some(0));
            }
            KeyCode::Char('c') => {
                self.connections = !self.connections;
                self.table.select(Some(0));
            }
            KeyCode::Char('b') => self.bits = !self.bits,
            KeyCode::Char(' ') => self.paused = !self.paused,
            KeyCode::Esc => self.filter.clear(),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(self.visible_rows as isize),
            KeyCode::PageUp => self.move_selection(-(self.visible_rows as isize)),
            KeyCode::Home => self.table.select((self.row_count() > 0).then_some(0)),
            KeyCode::End => self.table.select(self.row_count().checked_sub(1)),
            _ => {}
        }
        Action::None
    }

    fn overlay_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::F(1) | KeyCode::Char('?') => {
                self.overlay = Overlay::None
            }
            KeyCode::Up | KeyCode::Char('k') if self.overlay == Overlay::Help => {
                self.help_scroll = self.help_scroll.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') if self.overlay == Overlay::Help => {
                self.help_scroll = self.help_scroll.saturating_add(1).min(60)
            }
            KeyCode::PageUp if self.overlay == Overlay::Help => {
                self.help_scroll = self.help_scroll.saturating_sub(8)
            }
            KeyCode::PageDown if self.overlay == Overlay::Help => {
                self.help_scroll = self.help_scroll.saturating_add(8).min(60)
            }
            KeyCode::Up | KeyCode::Char('k') if self.overlay == Overlay::Interfaces => {
                self.picker = self.picker.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') if self.overlay == Overlay::Interfaces => {
                self.picker = (self.picker + 1).min(self.snapshot.interfaces.len())
            }
            KeyCode::Home if self.overlay == Overlay::Interfaces => self.picker = 0,
            KeyCode::End if self.overlay == Overlay::Interfaces => {
                self.picker = self.snapshot.interfaces.len()
            }
            KeyCode::Enter if self.overlay == Overlay::Interfaces => {
                let interface = self
                    .picker
                    .checked_sub(1)
                    .and_then(|index| self.snapshot.interfaces.get(index))
                    .map(|iface| iface.name.clone());
                self.set_interface(interface);
                self.overlay = Overlay::None;
                return Action::InterfaceChanged;
            }
            _ => {}
        }
        Action::None
    }

    fn set_interface(&mut self, interface: Option<String>) {
        if self.interface != interface {
            self.interface = interface;
            self.history.clear();
            self.table.select(Some(0));
            // Switching device explicitly resumes live collection.
            self.paused = false;
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let count = self.row_count();
        if count == 0 {
            self.table.select(None);
            return;
        }
        let current = self.table.selected().unwrap_or(0) as isize;
        self.table
            .select(Some((current + delta).clamp(0, count as isize - 1) as usize));
    }

    fn row_count(&self) -> usize {
        if self.connections {
            self.connection_rows().len()
        } else {
            self.process_rows().len()
        }
    }

    pub fn process_rows(&self) -> Vec<&ProcessRow> {
        let filter = self.filter.to_lowercase();
        let mut rows: Vec<_> = self
            .snapshot
            .processes
            .iter()
            .filter(|row| {
                filter.is_empty()
                    || format!("{} {} {}", pid(row.pid), row.user, row.name)
                        .to_lowercase()
                        .contains(&filter)
            })
            .collect();
        rows.sort_by(|a, b| {
            self.compare(
                a.rx_rate,
                a.tx_rate,
                a.rx_bytes.saturating_add(a.tx_bytes),
                a.pid,
                &a.name,
                b.rx_rate,
                b.tx_rate,
                b.rx_bytes.saturating_add(b.tx_bytes),
                b.pid,
                &b.name,
            )
        });
        rows
    }

    fn connection_rows(&self) -> Vec<&ConnectionRow> {
        let filter = self.filter.to_lowercase();
        let mut rows: Vec<_> = self
            .snapshot
            .connections
            .iter()
            .filter(|row| {
                filter.is_empty()
                    || format!(
                        "{} {} {} {} {} {}",
                        pid(row.pid),
                        row.user,
                        row.process,
                        row.protocol,
                        row.local,
                        row.remote
                    )
                    .to_lowercase()
                    .contains(&filter)
            })
            .collect();
        rows.sort_by(|a, b| {
            self.compare(
                a.rx_rate,
                a.tx_rate,
                a.rx_bytes.saturating_add(a.tx_bytes),
                a.pid,
                &a.process,
                b.rx_rate,
                b.tx_rate,
                b.rx_bytes.saturating_add(b.tx_bytes),
                b.pid,
                &b.process,
            )
            .then_with(|| a.local.cmp(&b.local))
            .then_with(|| a.remote.cmp(&b.remote))
        });
        rows
    }

    #[allow(clippy::too_many_arguments)]
    fn compare(
        &self,
        arx: f64,
        atx: f64,
        total_a: u64,
        pid_a: Option<u32>,
        name_a: &str,
        brx: f64,
        btx: f64,
        total_b: u64,
        pid_b: Option<u32>,
        name_b: &str,
    ) -> Ordering {
        let order = match self.sort {
            Sort::Traffic => (brx + btx).total_cmp(&(arx + atx)),
            Sort::Receive => brx.total_cmp(&arx),
            Sort::Send => btx.total_cmp(&atx),
            Sort::Total => total_b.cmp(&total_a),
            Sort::Pid => pid_a.unwrap_or(u32::MAX).cmp(&pid_b.unwrap_or(u32::MAX)),
            Sort::Name => name_a.cmp(name_b),
        };
        order.then_with(|| pid_a.unwrap_or(u32::MAX).cmp(&pid_b.unwrap_or(u32::MAX)))
    }
}

pub fn totals(snapshot: &Snapshot, interface: Option<&str>) -> (f64, f64, u64, u64) {
    snapshot
        .interfaces
        .iter()
        .filter(|iface| interface.is_none_or(|name| iface.name == name))
        .fold((0.0, 0.0, 0u64, 0u64), |(rx, tx, rb, tb), iface| {
            (
                rx + iface.rx_rate,
                tx + iface.tx_rate,
                rb.saturating_add(iface.rx_bytes),
                tb.saturating_add(iface.tx_bytes),
            )
        })
}

pub fn format_rate(bytes: f64, bits: bool) -> String {
    if bits {
        let (value, unit) = scaled(
            bytes.max(0.0) * 8.0,
            1000.0,
            &["bit", "kbit", "Mbit", "Gbit", "Tbit"],
        );
        format!("{value:.1} {unit}/s")
    } else {
        format!("{}/s", format_bytes(bytes))
    }
}

pub fn format_bytes(bytes: f64) -> String {
    let (value, unit) = scaled(bytes.max(0.0), 1024.0, &["B", "KiB", "MiB", "GiB", "TiB"]);
    if unit == "B" {
        format!("{value:.0} {unit}")
    } else {
        format!("{value:.1} {unit}")
    }
}

fn scaled(mut value: f64, base: f64, units: &'static [&'static str]) -> (f64, &'static str) {
    if !value.is_finite() {
        value = 0.0;
    }
    let mut index = 0;
    while value >= base && index + 1 < units.len() {
        value /= base;
        index += 1;
    }
    (value, units[index])
}

fn pid(value: Option<u32>) -> String {
    value.map_or_else(|| "-".into(), |value| value.to_string())
}

pub fn draw(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();
    if area.width < 36 || area.height < 16 {
        frame.render_widget(
            Paragraph::new("nettop\nTerminal too small.\nUse at least 36 x 16.\nq / F10 to quit.")
                .style(Style::default().fg(KEY)),
            area,
        );
        return;
    }
    let graph_height = ((area.height.saturating_sub(9)) / 2).clamp(6, 13);
    let layout = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(graph_height),
        Constraint::Length(1),
        Constraint::Min(4),
        Constraint::Length(1),
    ])
    .split(area);
    draw_title(frame, app, layout[0]);
    draw_device(frame, app, layout[1]);
    draw_graph(frame, app, layout[2]);
    draw_status(frame, app, layout[3]);
    draw_table(frame, app, layout[4]);
    draw_footer(frame, layout[5]);
    match app.overlay {
        Overlay::Help => draw_help(frame, app, area),
        Overlay::Interfaces => draw_interfaces(frame, app, area),
        Overlay::None => {}
    }
}

fn draw_title(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let mut spans = vec![
        Span::styled(
            "nettop",
            Style::default().fg(KEY).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
    ];
    spans.push(Span::raw(
        app.interface.as_deref().unwrap_or("all interfaces"),
    ));
    if app.demo {
        spans.push(Span::styled("  DEMO", Style::default().fg(Color::Magenta)));
    }
    if app.paused {
        spans.push(Span::styled("  PAUSED", Style::default().fg(TX)));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_device(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let device = app
        .snapshot
        .interfaces
        .iter()
        .find(|iface| Some(iface.name.as_str()) == app.interface.as_deref());
    let (rx, tx, rx_total, tx_total) = totals(&app.snapshot, app.interface.as_deref());
    let summary = if let Some(iface) = device {
        let mut text = format!("[{}]", iface.state.to_uppercase());
        if let Some(speed) = iface.speed_mbps {
            text.push_str(&format!("  {speed} Mbit/s"));
        }
        if area.width >= 60 {
            if let Some(mtu) = iface.mtu {
                text.push_str(&format!("  MTU {mtu}"));
            }
            if let Some(address) = &iface.address {
                text.push_str(&format!("  {address}"));
            }
        }
        text
    } else if app.interface.is_some() {
        "[device unavailable]".into()
    } else {
        "[ALL]  includes virtual interfaces".into()
    };
    let peak = app
        .history
        .iter()
        .flat_map(|sample| [sample.rx, sample.tx])
        .fold(1024.0f64, f64::max);
    let line_speed = device
        .and_then(|iface| iface.speed_mbps)
        .filter(|speed| *speed > 0)
        .map(|speed| speed as f64 * 1_000_000.0 / 8.0);
    let scale = line_speed.unwrap_or(peak);
    let lines = vec![
        Line::from(Span::styled(summary, Style::default().fg(Color::White))),
        rate_line(
            "RX",
            rx,
            rx_total,
            RX,
            area.width,
            scale,
            line_speed.is_some(),
            app.bits,
        ),
        rate_line(
            "TX",
            tx,
            tx_total,
            TX,
            area.width,
            scale,
            line_speed.is_some(),
            app.bits,
        ),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}

#[allow(clippy::too_many_arguments)]
fn rate_line(
    label: &str,
    rate: f64,
    total: u64,
    color: Color,
    width: u16,
    scale: f64,
    link: bool,
    bits: bool,
) -> Line<'static> {
    let rate_text = format_rate(rate, bits);
    let suffix = if width >= 78 {
        format!("  total {}", format_bytes(total as f64))
    } else {
        String::new()
    };
    let percent = if link && width >= 52 {
        format!(" {:>4.1}%", (rate / scale * 100.0).min(100.0))
    } else {
        String::new()
    };
    let bar_width = (usize::from(width)
        .saturating_sub(label.len() + rate_text.len() + suffix.len() + percent.len() + 6))
    .min(54);
    let fill = ((rate / scale).clamp(0.0, 1.0) * bar_width as f64).round() as usize;
    Line::from(vec![
        Span::styled(format!("{label} ["), Style::default().fg(color)),
        Span::styled("|".repeat(fill), Style::default().fg(color)),
        Span::styled(
            " ".repeat(bar_width.saturating_sub(fill)),
            Style::default().fg(DIM),
        ),
        Span::styled(
            format!("] {rate_text}{percent}"),
            Style::default().fg(color),
        ),
        Span::styled(suffix, Style::default().fg(DIM)),
    ])
}

fn draw_graph(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let now = app.history.back().map_or(0.0, |sample| sample.at);
    let rx: Vec<_> = app
        .history
        .iter()
        .map(|sample| (sample.at - now, sample.rx))
        .collect();
    let tx: Vec<_> = app
        .history
        .iter()
        .map(|sample| (sample.at - now, sample.tx))
        .collect();
    let peak = app
        .history
        .iter()
        .flat_map(|sample| [sample.rx, sample.tx])
        .fold(1024.0f64, f64::max)
        * 1.1;
    let labels = [0.0, peak / 2.0, peak].map(|value| {
        Line::from(
            format_rate(value, app.bits)
                .trim_end_matches("/s")
                .to_string(),
        )
    });
    let datasets = vec![
        Dataset::default()
            .name("RX")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(RX))
            .data(&rx),
        Dataset::default()
            .name("TX")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(TX))
            .data(&tx),
    ];
    let chart = Chart::new(datasets)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(DIM))
                .title(format!(" Traffic  {:.0}s ", app.history_seconds)),
        )
        .x_axis(
            Axis::default()
                .style(Style::default().fg(DIM))
                .bounds([-app.history_seconds, 0.0])
                .labels([
                    Line::from(format!("-{:.0}s", app.history_seconds)),
                    Line::from(format!("-{:.0}s", app.history_seconds / 2.0)),
                    Line::from("0s"),
                ]),
        )
        .y_axis(
            Axis::default()
                .style(Style::default().fg(DIM))
                .bounds([0.0, peak])
                .labels(labels),
        );
    frame.render_widget(chart, area);
}

fn draw_status(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let text = if app.searching {
        format!("Search: {}_  Enter apply / Esc clear", app.filter)
    } else if app.demo {
        "DEMO data  |  live mode uses kernel counters".into()
    } else if !app.snapshot.capture.active {
        if app.snapshot.capture.message.is_empty() {
            "Interface mode | sudo nettop for process rates".into()
        } else {
            app.snapshot.capture.message.clone()
        }
    } else if app.snapshot.capture.dropped > 0 {
        format!(
            "Capture: {} dropped packets | rates incomplete",
            app.snapshot.capture.dropped
        )
    } else {
        app.snapshot.capture.message.clone()
    };
    frame.render_widget(
        Paragraph::new(text).style(Style::default().fg(if app.searching {
            KEY
        } else if !app.snapshot.capture.active {
            TX
        } else {
            DIM
        })),
        area,
    );
}

fn draw_table(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    app.visible_rows = usize::from(area.height.saturating_sub(3));
    let wide = area.width >= 94;
    let medium = area.width >= 64;
    let captured = app.snapshot.capture.active || app.demo;
    let rate = |value| {
        if captured {
            // The column header already carries /s; retain the whole unit at 40 columns.
            format_rate(value, app.bits)
                .trim_end_matches("/s")
                .to_string()
        } else {
            "-".to_string()
        }
    };
    let total = |value| {
        if captured {
            format_bytes(value as f64)
        } else {
            "-".to_string()
        }
    };
    let (headers, widths, rows): (Vec<&str>, Vec<Constraint>, Vec<Row<'_>>) = if app.connections {
        let records = app.connection_rows();
        if wide {
            (
                vec!["PID", "PROTO", "RX/s", "TX/s", "LOCAL", "REMOTE", "COMMAND"],
                vec![
                    Constraint::Length(7),
                    Constraint::Length(5),
                    Constraint::Length(12),
                    Constraint::Length(12),
                    Constraint::Percentage(25),
                    Constraint::Percentage(25),
                    Constraint::Min(8),
                ],
                records
                    .into_iter()
                    .map(|row| {
                        Row::new(vec![
                            Cell::from(pid(row.pid)),
                            Cell::from(row.protocol.clone()),
                            Cell::from(rate(row.rx_rate)).style(Style::default().fg(RX)),
                            Cell::from(rate(row.tx_rate)).style(Style::default().fg(TX)),
                            Cell::from(row.local.clone()),
                            Cell::from(row.remote.clone()),
                            Cell::from(row.process.clone()),
                        ])
                    })
                    .collect(),
            )
        } else {
            (
                vec!["PID", "RX/s", "TX/s", "REMOTE"],
                vec![
                    Constraint::Length(7),
                    Constraint::Length(if medium { 12 } else { 10 }),
                    Constraint::Length(if medium { 12 } else { 10 }),
                    Constraint::Min(6),
                ],
                records
                    .into_iter()
                    .map(|row| {
                        Row::new(vec![
                            Cell::from(pid(row.pid)),
                            Cell::from(rate(row.rx_rate)).style(Style::default().fg(RX)),
                            Cell::from(rate(row.tx_rate)).style(Style::default().fg(TX)),
                            Cell::from(row.remote.clone()),
                        ])
                    })
                    .collect(),
            )
        }
    } else {
        let records = app.process_rows();
        if wide {
            (
                vec!["PID", "USER", "RX/s", "TX/s", "TOTAL", "CONN", "COMMAND"],
                vec![
                    Constraint::Length(7),
                    Constraint::Length(10),
                    Constraint::Length(12),
                    Constraint::Length(12),
                    Constraint::Length(12),
                    Constraint::Length(5),
                    Constraint::Min(8),
                ],
                records
                    .into_iter()
                    .map(|row| {
                        Row::new(vec![
                            Cell::from(pid(row.pid)),
                            Cell::from(row.user.clone()),
                            Cell::from(rate(row.rx_rate)).style(Style::default().fg(RX)),
                            Cell::from(rate(row.tx_rate)).style(Style::default().fg(TX)),
                            Cell::from(total(row.rx_bytes.saturating_add(row.tx_bytes))),
                            Cell::from(row.connections.to_string()),
                            Cell::from(row.name.clone()),
                        ])
                    })
                    .collect(),
            )
        } else if medium {
            (
                vec!["PID", "RX/s", "TX/s", "CONN", "COMMAND"],
                vec![
                    Constraint::Length(7),
                    Constraint::Length(12),
                    Constraint::Length(12),
                    Constraint::Length(5),
                    Constraint::Min(10),
                ],
                records
                    .into_iter()
                    .map(|row| {
                        Row::new(vec![
                            Cell::from(pid(row.pid)),
                            Cell::from(rate(row.rx_rate)).style(Style::default().fg(RX)),
                            Cell::from(rate(row.tx_rate)).style(Style::default().fg(TX)),
                            Cell::from(row.connections.to_string()),
                            Cell::from(row.name.clone()),
                        ])
                    })
                    .collect(),
            )
        } else {
            (
                vec!["PID", "RX/s", "TX/s", "COMMAND"],
                vec![
                    Constraint::Length(7),
                    Constraint::Length(10),
                    Constraint::Length(10),
                    Constraint::Min(5),
                ],
                records
                    .into_iter()
                    .map(|row| {
                        Row::new(vec![
                            Cell::from(pid(row.pid)),
                            Cell::from(rate(row.rx_rate)).style(Style::default().fg(RX)),
                            Cell::from(rate(row.tx_rate)).style(Style::default().fg(TX)),
                            Cell::from(row.name.clone()),
                        ])
                    })
                    .collect(),
            )
        }
    };
    let count = rows.len();
    let title = format!(
        " {} ({count})  sort: {}{} ",
        if app.connections {
            "Connections"
        } else {
            "Processes"
        },
        app.sort.label(),
        if app.filter.is_empty() {
            String::new()
        } else {
            format!("  /{}", app.filter)
        }
    );
    let header = Row::new(headers).style(Style::default().fg(Color::Black).bg(SELECTED));
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(DIM))
                .title(title),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(44, 62, 31))
                .add_modifier(Modifier::BOLD),
        );
    frame.render_stateful_widget(table, area, &mut app.table);
    if count == 0 && area.height > 3 {
        let message = if app.filter.is_empty() {
            "Waiting for network activity..."
        } else {
            "No matching processes or connections."
        };
        frame.render_widget(
            Paragraph::new(message).style(Style::default().fg(DIM)),
            Rect {
                x: area.x,
                y: area.y + 2,
                width: area.width,
                height: 1,
            },
        );
    }
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect) {
    let keys = if area.width >= 94 {
        vec![
            ("F1", "Help"),
            ("F2", "Interface"),
            ("F3", "Search"),
            ("F6", "Sort"),
            ("c", "Connections"),
            ("b", "Bits"),
            ("Space", "Pause"),
            ("F10", "Quit"),
        ]
    } else if area.width >= 64 {
        vec![
            ("F1", "Help"),
            ("F2", "Iface"),
            ("/", "Search"),
            ("s", "Sort"),
            ("c", "Conn"),
            ("q", "Quit"),
        ]
    } else {
        vec![
            ("F1", "Help"),
            ("F2", "Iface"),
            ("s", "Sort"),
            ("q", "Quit"),
        ]
    };
    let mut spans = Vec::new();
    for (key, label) in keys {
        spans.push(Span::styled(key, Style::default().fg(Color::Black).bg(KEY)));
        spans.push(Span::raw(format!("{label} ")));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn popup(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(2));
    let height = height.min(area.height.saturating_sub(2));
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

fn draw_help(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let area = popup(area, 76, 23);
    frame.render_widget(Clear, area);
    let text = vec![
        Line::from("F1 / ?         Help     Esc closes"),
        Line::from("F2 / i         Choose interface"),
        Line::from("Tab / Shift-Tab Cycle up interfaces"),
        Line::from("F3 / /         Search PID, user, command, endpoint"),
        Line::from("F6 / s         Sort: traffic, RX, TX, total, PID, command"),
        Line::from("c              Processes / connections"),
        Line::from("b              Bytes/s / bits/s"),
        Line::from("Space          Pause / resume display"),
        Line::from("Up / Down      Select; PgUp / PgDn scroll"),
        Line::from("q / F10 / Ctrl-C Quit"),
        Line::from(""),
        Line::from("RX green: receive. TX yellow: send."),
        Line::from("Graph scale follows the visible peak."),
        Line::from("Bars use link speed, or visible peak when unknown."),
        Line::from("Interface totals are kernel counters since boot."),
        Line::from("Process totals are observed IP bytes this session."),
        Line::from("Shared, short-lived or inaccessible sockets can be unattributed."),
        Line::from("Virtual links can count the same traffic more than once in all mode."),
        Line::from("Start with sudo nettop for full process attribution."),
        Line::from(""),
        Line::from(app.snapshot.capture.message.as_str()),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .scroll((app.help_scroll, 0))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(KEY))
                    .title(" Help  Up/Down scroll / Esc close "),
            )
            .style(Style::default().fg(Color::White).bg(Color::Black)),
        area,
    );
}

fn draw_interfaces(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let area = popup(area, 72, (app.snapshot.interfaces.len() as u16 + 5).min(26));
    frame.render_widget(Clear, area);
    let mut rows = vec![Row::new(vec![
        "all".to_string(),
        "includes virtual links".to_string(),
    ])];
    rows.extend(app.snapshot.interfaces.iter().map(|iface| {
        Row::new(vec![
            iface.name.clone(),
            format!(
                "{}  RX {}  TX {}",
                iface.state,
                format_rate(iface.rx_rate, app.bits),
                format_rate(iface.tx_rate, app.bits)
            ),
        ])
    }));
    let mut state = TableState::default().with_selected(app.picker);
    let table = Table::new(rows, [Constraint::Length(16), Constraint::Min(10)])
        .header(
            Row::new(["INTERFACE", "STATE / TRAFFIC"])
                .style(Style::default().fg(Color::Black).bg(SELECTED)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Interface  Enter select / Esc close ")
                .border_style(Style::default().fg(KEY)),
        )
        .style(Style::default().bg(Color::Black))
        .row_highlight_style(Style::default().bg(Color::Rgb(44, 62, 31)));
    frame.render_stateful_widget(table, area, &mut state);
}

/// Explicit preview data; only called when the user passes --demo or by tests.
pub fn demo_snapshot(tick: u64, elapsed: f64) -> Snapshot {
    let wave = |offset: f64, max: f64| {
        let t = tick as f64 * 0.23 + offset;
        (0.15 + (t.sin() * 0.5 + 0.5) * 0.68 + (t * 2.8).sin().abs() * 0.17) * max
    };
    let rx = wave(0.0, 14_500_000.0);
    let tx = wave(1.7, 4_500_000.0);
    let processes = [
        (4823, "brave", rx * 0.68, tx * 0.06, 24),
        (9645, "docker", rx * 0.12, tx * 0.72, 8),
        (1005126, "curl", rx * 0.18, tx * 0.02, 1),
        (12826, "syncthing", rx * 0.02, tx * 0.18, 12),
        (27180, "ssh", 640.0, 2100.0, 2),
        (31140, "systemd-resolved", 320.0, 240.0, 3),
    ]
    .into_iter()
    .map(|(id, name, down, up, connections)| ProcessRow {
        pid: Some(id),
        user: "tim".into(),
        name: name.into(),
        rx_rate: down,
        tx_rate: up,
        rx_bytes: (down * elapsed) as u64,
        tx_bytes: (up * elapsed) as u64,
        connections,
    })
    .collect::<Vec<_>>();
    let connections = processes
        .iter()
        .enumerate()
        .map(|(index, process)| ConnectionRow {
            pid: process.pid,
            user: process.user.clone(),
            process: process.name.clone(),
            protocol: if index == 5 {
                "UDP".into()
            } else {
                "TCP".into()
            },
            local: format!("192.0.2.10:{}", 42000 + index),
            remote: format!("198.51.100.{}:443", index + 10),
            state: "ESTABLISHED".into(),
            rx_rate: process.rx_rate,
            tx_rate: process.tx_rate,
            rx_bytes: process.rx_bytes,
            tx_bytes: process.tx_bytes,
        })
        .collect();
    Snapshot {
        elapsed,
        interfaces: vec![
            Interface {
                name: "enp112s0".into(),
                state: "up".into(),
                address: Some("192.0.2.10".into()),
                speed_mbps: Some(2500),
                mtu: Some(1500),
                rx_rate: rx,
                tx_rate: tx,
                rx_bytes: 14_820_000_000 + (elapsed * rx) as u64,
                tx_bytes: 4_320_000_000 + (elapsed * tx) as u64,
                ..Default::default()
            },
            Interface {
                name: "tailscale0".into(),
                state: "up".into(),
                is_virtual: true,
                rx_rate: 8200.0,
                tx_rate: 4100.0,
                mtu: Some(1280),
                ..Default::default()
            },
            Interface {
                name: "lo".into(),
                state: "up".into(),
                is_virtual: true,
                ..Default::default()
            },
        ],
        processes,
        connections,
        capture: crate::model::CaptureStatus {
            active: true,
            message: "DEMO data".into(),
            dropped: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn app() -> App {
        let mut app = App::new(Some("enp112s0".into()), 60, false, true);
        for tick in 0..61 {
            app.update(demo_snapshot(tick, tick as f64));
        }
        app
    }

    #[test]
    fn layouts_fit_narrow_and_wide_terminals() {
        for (width, height) in [(36, 16), (40, 24), (80, 24), (120, 36)] {
            let mut app = app();
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|frame| draw(frame, &mut app)).unwrap();
            let buffer = terminal.backend().buffer();
            let text: String = buffer.content.iter().map(|cell| cell.symbol()).collect();
            assert!(text.contains("nettop"), "title missing at {width}x{height}");
            assert!(text.contains("RX/s"), "rates missing at {width}x{height}");
            assert!(
                text.contains("Quit"),
                "quit hint missing at {width}x{height}"
            );
            for overlay in [Overlay::Help, Overlay::Interfaces] {
                app.overlay = overlay;
                terminal.draw(|frame| draw(frame, &mut app)).unwrap();
            }
        }
    }

    #[test]
    fn sort_search_and_pause_preserve_expected_behavior() {
        let mut app = app();
        app.handle_key(KeyCode::F(3).into());
        for c in "curl".chars() {
            app.handle_key(KeyCode::Char(c).into());
        }
        app.handle_key(KeyCode::Enter.into());
        assert_eq!(app.process_rows().len(), 1);
        assert_eq!(app.process_rows()[0].name, "curl");
        app.handle_key(KeyCode::Esc.into());
        assert_eq!(app.process_rows().len(), 6);
        app.sort = Sort::Pid;
        assert_eq!(app.process_rows()[0].pid, Some(4823));
        app.handle_key(KeyCode::Char(' ').into());
        app.update(demo_snapshot(100, 100.0));
        assert_eq!(app.snapshot.elapsed, 60.0);
        app.handle_key(KeyCode::Char(' ').into());
        app.update(demo_snapshot(101, 101.0));
        assert_eq!(app.snapshot.elapsed, 101.0);
        assert!(app.history.iter().all(|sample| sample.at >= 41.0));
    }

    #[test]
    fn interface_switch_clears_mixed_history() {
        let mut app = app();
        assert_eq!(
            app.handle_key(KeyCode::Tab.into()),
            Action::InterfaceChanged
        );
        assert_eq!(app.interface.as_deref(), Some("tailscale0"));
        assert!(app.history.is_empty());
        app.set_interface(None);
        app.handle_key(KeyCode::Tab.into());
        assert_eq!(app.interface.as_deref(), Some("enp112s0"));
        app.set_interface(None);
        app.handle_key(KeyCode::BackTab.into());
        assert_eq!(app.interface.as_deref(), Some("lo"));
    }

    #[test]
    fn narrow_table_keeps_full_pids_and_bit_units() {
        let mut app = app();
        app.bits = true;
        app.snapshot.processes[2].rx_rate = 12_500_000.0;
        let mut terminal = Terminal::new(TestBackend::new(40, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("1005126"));
        assert!(text.contains("100.0 Mbit"));
    }

    #[test]
    fn units_are_distinct_and_unknown_capture_does_not_show_fake_rates() {
        assert_eq!(format_rate(125_000.0, true), "1.0 Mbit/s");
        assert_eq!(format_bytes(1024.0), "1.0 KiB");
        let mut app = app();
        app.demo = false;
        app.snapshot.capture.active = false;
        app.snapshot.capture.message = "Process rates unavailable; run sudo nettop".into();
        app.snapshot.processes[0].rx_rate = 9_000_000_000.0;
        let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("sudo nettop"));
        assert!(!text.contains(format_rate(9_000_000_000.0, false).trim_end_matches("/s")));
    }
}
