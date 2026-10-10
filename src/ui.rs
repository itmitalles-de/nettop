//! A compact nvtop-style terminal interface. No data is invented by the renderer.

use std::{
    cmp::Ordering,
    collections::{BTreeSet, VecDeque},
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{
        Axis, Block, Borders, Cell, Chart, Clear, Dataset, GraphType, Paragraph, Row, Table,
        TableState, Wrap,
    },
};

pub use crate::config::SortKey as Sort;
use crate::{
    config::{Field, GraphStyle, Language, PlotColor, Settings},
    i18n::Lang,
    model::{ConnectionRow, Interface, ProcessRow, Snapshot},
};

const RX: Color = Color::Green;
const TX: Color = Color::Yellow;
const KEY: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;
const SORTS: [Sort; 6] = [
    Sort::Traffic,
    Sort::Receive,
    Sort::Send,
    Sort::Total,
    Sort::Pid,
    Sort::Name,
];
const CATEGORY_COUNT: usize = 4;

fn categories(lang: Lang) -> [&'static str; CATEGORY_COUNT] {
    match lang {
        Lang::En => ["General", "Interface", "Chart", "Processes"],
        Lang::De => ["Allgemein", "Schnittstelle", "Diagramm", "Prozesse"],
    }
}

fn inverse(color: Color) -> Style {
    // ncurses A_STANDOUT: reverse the terminal's own foreground/background.
    Style::default().fg(color).add_modifier(Modifier::REVERSED)
}

fn plot_color(color: PlotColor) -> Color {
    match color {
        PlotColor::Green => Color::Green,
        PlotColor::Yellow => Color::Yellow,
        PlotColor::Cyan => Color::Cyan,
        PlotColor::Red => Color::Red,
        PlotColor::Blue => Color::Blue,
        PlotColor::Magenta => Color::Magenta,
        PlotColor::White => Color::White,
    }
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

    pub fn label(self, lang: Lang) -> &'static str {
        match self {
            Self::Traffic => lang.pick("traffic", "Verkehr"),
            Self::Receive => "RX",
            Self::Send => "TX",
            Self::Total => lang.pick("total", "gesamt"),
            Self::Pid => "PID",
            Self::Name => lang.pick("command", "Befehl"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Overlay {
    #[default]
    None,
    Help,
    Interfaces,
    Setup,
    Sort,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    InterfaceChanged,
    SettingsChanged,
    SaveSettings,
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
    /// Effective runtime settings, including CLI and environment overrides.
    pub settings: Settings,
    /// Settings as stored in the preferences file.
    saved_settings: Settings,
    /// Preferences the user changed in this session; only these are saved.
    touched: BTreeSet<Field>,
    /// Language used when the language preference is Auto.
    pub system_lang: Lang,
    pub auto_interface: Option<String>,
    pub notice: Option<String>,
    pub notice_error: bool,
    pub paused: bool,
    pub filter: String,
    pub searching: bool,
    pub overlay: Overlay,
    pub table: TableState,
    picker: usize,
    help_scroll: u16,
    visible_rows: usize,
    pub demo: bool,
    setup_category: usize,
    setup_option: usize,
    setup_focus: bool,
}

impl App {
    pub fn new(interface: Option<String>, history_seconds: u16, bits: bool, demo: bool) -> Self {
        let settings = Settings {
            interface: Some(interface.clone().unwrap_or_else(|| "all".into())),
            history_seconds,
            bits,
            ..Settings::default()
        };
        Self::with_settings(interface, settings, demo)
    }

    pub fn with_settings(interface: Option<String>, settings: Settings, demo: bool) -> Self {
        Self::with_saved(interface, settings.clone(), settings, demo)
    }

    /// `settings` may contain temporary overrides; `saved` is the file content.
    /// Saving writes `saved` plus the preferences the user changed at runtime.
    pub fn with_saved(
        interface: Option<String>,
        settings: Settings,
        saved: Settings,
        demo: bool,
    ) -> Self {
        Self {
            snapshot: Snapshot::default(),
            auto_interface: interface.clone(),
            interface,
            history: VecDeque::new(),
            saved_settings: saved,
            touched: BTreeSet::new(),
            system_lang: Lang::En,
            settings,
            notice: None,
            notice_error: false,
            paused: false,
            filter: String::new(),
            searching: false,
            overlay: Overlay::None,
            table: TableState::default().with_selected(0),
            picker: 0,
            help_scroll: 0,
            visible_rows: 10,
            demo,
            setup_category: 0,
            setup_option: 0,
            setup_focus: false,
        }
    }

    pub fn history_seconds(&self) -> f64 {
        f64::from(self.settings.history_seconds)
    }

    pub fn lang(&self) -> Lang {
        Lang::resolve(self.settings.language, self.system_lang)
    }

    /// Saved settings plus only the preferences changed in Setup or by keys.
    /// CLI options, NO_COLOR and automatic fallbacks stay temporary.
    pub fn settings_to_save(&self) -> Settings {
        let mut settings = self.saved_settings.clone();
        for field in &self.touched {
            settings.copy_field(&self.settings, *field);
        }
        settings
    }

    pub fn settings_dirty(&self) -> bool {
        self.settings_to_save() != self.saved_settings
    }

    /// Record a successful save of `settings_to_save()`.
    pub fn settings_saved(&mut self, message: String) {
        self.saved_settings = self.settings_to_save();
        self.touched.clear();
        self.notice = Some(message);
        self.notice_error = false;
    }

    pub fn show_error(&mut self, message: String) {
        self.notice = Some(message);
        self.notice_error = true;
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
            .is_some_and(|sample| at - sample.at > self.history_seconds())
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
        let before = self.settings.clone();
        let action = self.handle_key_inner(key);
        self.touched.extend(self.settings.differing(&before));
        action
    }

    fn handle_key_inner(&mut self, key: KeyEvent) -> Action {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }
        if key.code == KeyCode::F(12) {
            return Action::SaveSettings;
        }
        self.notice = None;
        if self.overlay == Overlay::Setup {
            return self.setup_key(key);
        }
        if key.code == KeyCode::F(10) {
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
            KeyCode::F(2) => {
                self.overlay = Overlay::Setup;
                self.setup_focus = false;
            }
            KeyCode::F(5) | KeyCode::Char('i') => {
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
            KeyCode::F(6) => {
                self.overlay = Overlay::Sort;
                self.picker = SORTS
                    .iter()
                    .position(|sort| *sort == self.settings.sort)
                    .unwrap_or(0);
            }
            KeyCode::Char('s') => {
                self.settings.sort = self.settings.sort.next();
                self.table.select(Some(0));
            }
            KeyCode::F(4) | KeyCode::Char('c') => {
                self.settings.connections = !self.settings.connections;
                self.table.select(Some(0));
            }
            KeyCode::Char('b') => self.settings.bits = !self.settings.bits,
            KeyCode::F(9) | KeyCode::Char(' ') => self.paused = !self.paused,
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
            KeyCode::Up | KeyCode::Char('k') if self.overlay == Overlay::Sort => {
                self.picker = self.picker.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') if self.overlay == Overlay::Sort => {
                self.picker = (self.picker + 1).min(SORTS.len() - 1);
            }
            KeyCode::Enter if self.overlay == Overlay::Sort => {
                self.settings.sort = SORTS[self.picker.min(SORTS.len() - 1)];
                self.table.select(Some(0));
                self.overlay = Overlay::None;
            }
            _ => {}
        }
        Action::None
    }

    fn set_interface(&mut self, interface: Option<String>) {
        // An explicit choice is saved even if it equals a temporary override.
        self.touched.insert(Field::Interface);
        self.settings.interface = Some(interface.clone().unwrap_or_else(|| "all".into()));
        if self.interface != interface {
            self.interface = interface;
            self.history.clear();
            self.table.select(Some(0));
            // Switching device explicitly resumes live collection.
            self.paused = false;
        }
    }

    fn setup_len(&self) -> usize {
        match self.setup_category {
            0 => 4,
            1 => self.snapshot.interfaces.len() + 2,
            2 => 5,
            _ => 3,
        }
    }

    fn setup_key(&mut self, key: KeyEvent) -> Action {
        self.setup_option = self.setup_option.min(self.setup_len().saturating_sub(1));
        match key.code {
            KeyCode::Esc | KeyCode::F(2) | KeyCode::F(10) | KeyCode::Char('q') => {
                self.overlay = Overlay::None;
            }
            KeyCode::Tab | KeyCode::BackTab => self.setup_focus = !self.setup_focus,
            KeyCode::Right | KeyCode::Enter | KeyCode::Char(' ') if !self.setup_focus => {
                self.setup_focus = true;
            }
            KeyCode::Left | KeyCode::Backspace if self.setup_focus => self.setup_focus = false,
            KeyCode::Up | KeyCode::Char('k') => {
                if self.setup_focus {
                    self.setup_option = self.setup_option.saturating_sub(1);
                } else {
                    self.setup_category = self.setup_category.saturating_sub(1);
                    self.setup_option = 0;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.setup_focus {
                    self.setup_option = (self.setup_option + 1).min(self.setup_len() - 1);
                } else {
                    self.setup_category = (self.setup_category + 1).min(CATEGORY_COUNT - 1);
                    self.setup_option = 0;
                }
            }
            KeyCode::Home if self.setup_focus => self.setup_option = 0,
            KeyCode::End if self.setup_focus => self.setup_option = self.setup_len() - 1,
            KeyCode::PageDown if self.setup_focus => {
                self.setup_option = (self.setup_option + 8).min(self.setup_len() - 1)
            }
            KeyCode::PageUp if self.setup_focus => {
                self.setup_option = self.setup_option.saturating_sub(8)
            }
            KeyCode::Right
            | KeyCode::Enter
            | KeyCode::Char(' ')
            | KeyCode::Char('+')
            | KeyCode::Char('=')
            | KeyCode::Char('-')
                if self.setup_focus =>
            {
                let direction = if key.code == KeyCode::Char('-') {
                    -1
                } else {
                    1
                };
                return self.change_setup(direction);
            }
            _ => {}
        }
        Action::None
    }

    fn change_setup(&mut self, direction: i32) -> Action {
        match (self.setup_category, self.setup_option) {
            (0, 0) => self.settings.color = !self.settings.color,
            (0, 1) => {
                self.settings.interval_ms = (self.settings.interval_ms as i64
                    + i64::from(direction) * 100)
                    .clamp(100, 60_000) as u64
            }
            (0, 2) => self.settings.bits = !self.settings.bits,
            (0, 3) => self.settings.language = self.settings.language.next(direction),
            (1, row) => {
                let interface = if row == 0 {
                    self.auto_interface.clone()
                } else if row == 1 {
                    None
                } else {
                    self.snapshot
                        .interfaces
                        .get(row - 2)
                        .map(|iface| iface.name.clone())
                };
                self.set_interface(interface);
                if row == 0 {
                    self.settings.interface = None;
                }
                return Action::InterfaceChanged;
            }
            (2, 0) => self.settings.show_graph = !self.settings.show_graph,
            (2, 1) => {
                self.settings.history_seconds = (i32::from(self.settings.history_seconds)
                    + direction * 10)
                    .clamp(10, 600) as u16
            }
            (2, 2) => self.settings.graph_style = self.settings.graph_style.next(direction),
            (2, 3) => self.settings.rx_color = self.settings.rx_color.next(direction),
            (2, 4) => self.settings.tx_color = self.settings.tx_color.next(direction),
            (3, 0) => self.settings.connections = !self.settings.connections,
            (3, 1) => {
                let current = SORTS
                    .iter()
                    .position(|sort| *sort == self.settings.sort)
                    .unwrap_or(0) as i32;
                self.settings.sort =
                    SORTS[(current + direction).rem_euclid(SORTS.len() as i32) as usize];
            }
            (3, 2) => self.settings.show_idle = !self.settings.show_idle,
            _ => {}
        }
        self.table.select(Some(0));
        Action::SettingsChanged
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
        if self.settings.connections {
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
                self.settings.show_idle
                    || !(self.snapshot.capture.active || self.demo)
                    || row.rx_rate > 0.0
                    || row.tx_rate > 0.0
            })
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
                self.settings.show_idle
                    || !(self.snapshot.capture.active || self.demo)
                    || row.rx_rate > 0.0
                    || row.tx_rate > 0.0
            })
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
        let order = match self.settings.sort {
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
        let (value, unit, decimals) = scaled(
            bytes.max(0.0) * 8.0,
            1000.0,
            &["bit", "kbit", "Mbit", "Gbit", "Tbit"],
            |_| 1,
        );
        format!("{value:.decimals$} {unit}/s")
    } else {
        format!("{}/s", format_bytes(bytes))
    }
}

pub fn format_bytes(bytes: f64) -> String {
    let (value, unit, decimals) = scaled(
        bytes.max(0.0),
        1024.0,
        &["B", "KiB", "MiB", "GiB", "TiB"],
        |index| if index == 0 { 0 } else { 1 },
    );
    format!("{value:.decimals$} {unit}")
}

/// Scale to the largest unit below `base` after rounding to the displayed
/// precision, so 1023.96 KiB becomes "1.0 MiB" rather than "1024.0 KiB".
/// Below the last unit, the result is at most "999.9 kbit" or "1023.9 KiB".
fn scaled(
    value: f64,
    base: f64,
    units: &'static [&'static str],
    decimals: impl Fn(usize) -> usize,
) -> (f64, &'static str, usize) {
    let mut value = if value.is_finite() { value } else { 0.0 };
    let mut index = 0;
    loop {
        let factor = 10f64.powi(decimals(index) as i32);
        let rounded = (value * factor).round() / factor;
        if rounded < base || index + 1 == units.len() {
            return (rounded, units[index], decimals(index));
        }
        value /= base;
        index += 1;
    }
}

fn pid(value: Option<u32>) -> String {
    value.map_or_else(|| "-".into(), |value| value.to_string())
}

fn number_cell(text: String) -> Cell<'static> {
    Cell::from(Line::from(text).alignment(Alignment::Right))
}

pub fn draw(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();
    if area.width < 36 || area.height < 16 {
        frame.render_widget(
            Paragraph::new(app.lang().pick(
                "nwtop\nTerminal too small.\nUse at least 36 x 16.\nq / F10 to quit.",
                "nwtop\nTerminal zu klein.\nMindestens 36 x 16.\nq / F10 beendet.",
            ))
            .style(Style::default().fg(if app.settings.color {
                KEY
            } else {
                Color::Reset
            })),
            area,
        );
        return;
    }
    let graph_height = if app.settings.show_graph {
        ((area.height.saturating_sub(9)) / 2).clamp(6, 13)
    } else {
        0
    };
    let status = status_line(app);
    let layout = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(graph_height),
        Constraint::Length(u16::from(status.is_some())),
        Constraint::Min(4),
        Constraint::Length(1),
    ])
    .split(area);
    draw_title(frame, app, layout[0]);
    draw_device(frame, app, layout[1]);
    draw_graph(frame, app, layout[2]);
    if let Some((text, color)) = status {
        frame.render_widget(
            Paragraph::new(text).style(Style::default().fg(color)),
            layout[3],
        );
    }
    draw_table(frame, app, layout[4]);
    draw_footer(frame, app, layout[5]);
    match app.overlay {
        Overlay::Help => draw_help(frame, app, area),
        Overlay::Interfaces => draw_interfaces(frame, app, area),
        Overlay::Setup => draw_setup(frame, app, area),
        Overlay::Sort => draw_sort(frame, app, area),
        Overlay::None => {}
    }
    if !app.settings.color {
        for cell in &mut frame.buffer_mut().content {
            cell.set_fg(Color::Reset).set_bg(Color::Reset);
        }
    }
}

fn draw_title(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let index = app
        .snapshot
        .interfaces
        .iter()
        .position(|iface| Some(&iface.name) == app.interface.as_ref());
    let lang = app.lang();
    let mut spans = vec![
        Span::styled(lang.pick("Device ", "Gerät "), Style::default().fg(RX)),
        Span::raw(index.map_or_else(
            || lang.pick("all", "alle").into(),
            |index| index.to_string(),
        )),
        Span::raw(" ["),
        Span::raw(
            app.interface
                .as_deref()
                .unwrap_or(lang.pick("all interfaces", "alle Schnittstellen")),
        ),
        Span::raw("]"),
    ];
    if app.demo {
        spans.push(Span::styled("  DEMO", Style::default().fg(Color::Magenta)));
    }
    if app.paused {
        spans.push(Span::styled(
            lang.pick("  PAUSED", "  PAUSIERT"),
            Style::default().fg(TX),
        ));
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
    let lang = app.lang();
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
        lang.pick("[device unavailable]", "[Gerät nicht verfügbar]")
            .into()
    } else {
        lang.pick(
            "[ALL]  includes virtual interfaces",
            "[ALLE]  inkl. virtueller Schnittstellen",
        )
        .into()
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
        // Default foreground keeps the summary readable on light and dark themes.
        Line::from(Span::raw(summary)),
        rate_line(
            "RX",
            rx,
            rx_total,
            plot_color(app.settings.rx_color),
            area.width,
            scale,
            line_speed.is_some(),
            app.settings.bits,
            lang,
        ),
        rate_line(
            "TX",
            tx,
            tx_total,
            plot_color(app.settings.tx_color),
            area.width,
            scale,
            line_speed.is_some(),
            app.settings.bits,
            lang,
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
    lang: Lang,
) -> Line<'static> {
    let rate_text = format_rate(rate, bits);
    let suffix = if width >= 78 {
        format!(
            "  {} {}",
            lang.pick("total", "gesamt"),
            format_bytes(total as f64)
        )
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
        Span::styled(label.to_owned(), Style::default().fg(color)),
        Span::raw("["),
        Span::styled("|".repeat(fill), Style::default().fg(color)),
        Span::styled(
            " ".repeat(bar_width.saturating_sub(fill)),
            Style::default().fg(DIM),
        ),
        Span::raw(format!("] {rate_text}{percent}")),
        Span::styled(suffix, Style::default().fg(DIM)),
    ])
}

fn draw_graph(frame: &mut Frame<'_>, app: &App, area: Rect) {
    if area.height == 0 {
        return;
    }
    if app.settings.graph_style == GraphStyle::Steps {
        draw_step_graph(frame, app, area);
        return;
    }
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
            format_rate(value, app.settings.bits)
                .trim_end_matches("/s")
                .to_string(),
        )
    });
    let datasets = vec![
        Dataset::default()
            .name("RX")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(plot_color(app.settings.rx_color)))
            .data(&rx),
        Dataset::default()
            .name("TX")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(plot_color(app.settings.tx_color)))
            .data(&tx),
    ];
    let chart = Chart::new(datasets)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default()),
        )
        .x_axis(
            Axis::default()
                .style(Style::default().fg(DIM))
                .bounds([-app.history_seconds(), 0.0])
                .labels([
                    Line::from(format!("-{:.0}s", app.history_seconds())),
                    Line::from(format!("-{:.0}s", app.history_seconds() / 2.0)),
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

fn draw_step_graph(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width < 14 || inner.height < 3 {
        return;
    }
    let peak = app
        .history
        .iter()
        .flat_map(|sample| [sample.rx, sample.tx])
        .fold(1024.0f64, f64::max)
        * 1.1;
    let labels = [peak, peak / 2.0, 0.0].map(|value| {
        format_rate(value, app.settings.bits)
            .trim_end_matches("/s")
            .to_owned()
    });
    let label_width = labels.iter().map(String::len).max().unwrap_or(6).min(11) as u16;
    let plot = Rect {
        x: inner.x + label_width + 1,
        y: inner.y,
        width: inner.width.saturating_sub(label_width + 1),
        height: inner.height - 1,
    };
    for (index, label) in labels.iter().enumerate() {
        let y = plot.y + (plot.height - 1) * index as u16 / 2;
        frame.render_widget(
            Paragraph::new(label.as_str()).alignment(ratatui::layout::Alignment::Right),
            Rect::new(inner.x, y, label_width, 1),
        );
    }
    let now = app.history.back().map_or(0.0, |sample| sample.at);
    // Draw TX first, so RX stays visible at intersections. Each series uses
    // terminal line characters, as in nvtop, rather than colored dot cells.
    for (receive, color) in [
        (false, app.settings.tx_color),
        (true, app.settings.rx_color),
    ] {
        let mut columns = vec![None; usize::from(plot.width)];
        for sample in &app.history {
            let progress = (sample.at - now + app.history_seconds()) / app.history_seconds();
            if !(0.0..=1.0).contains(&progress) {
                continue;
            }
            let x = (progress * f64::from(plot.width - 1)).round() as usize;
            let value = if receive { sample.rx } else { sample.tx };
            let y = ((1.0 - (value / peak).clamp(0.0, 1.0)) * f64::from(plot.height - 1)).round()
                as u16;
            columns[x] = Some(y);
        }
        let mut paths = vec![0u8; usize::from(plot.width) * usize::from(plot.height)];
        let index = |x: u16, y: u16| usize::from(y) * usize::from(plot.width) + usize::from(x);
        let mut previous = None;
        for (x, y) in columns
            .into_iter()
            .enumerate()
            .filter_map(|(x, y)| y.map(|y| (x as u16, y)))
        {
            if let Some((px, py)) = previous {
                for column in px..x {
                    paths[index(column, py)] |= 2;
                    paths[index(column + 1, py)] |= 8;
                }
                for row in py.min(y)..py.max(y) {
                    paths[index(x, row)] |= 4;
                    paths[index(x, row + 1)] |= 1;
                }
            } else {
                paths[index(x, y)] = 10;
            }
            previous = Some((x, y));
        }
        for y in 0..plot.height {
            for x in 0..plot.width {
                let symbol = match paths[index(x, y)] {
                    0 => continue,
                    1 | 4 | 5 => "│",
                    2 | 8 | 10 => "─",
                    3 => "└",
                    6 => "┌",
                    9 => "┘",
                    12 => "┐",
                    7 => "├",
                    11 => "┴",
                    13 => "┤",
                    14 => "┬",
                    _ => "┼",
                };
                frame.buffer_mut()[(plot.x + x, plot.y + y)]
                    .set_symbol(symbol)
                    .set_style(Style::default().fg(plot_color(color)));
            }
        }
    }
    for (row, label, color) in [
        (0, "RX", app.settings.rx_color),
        (1, "TX", app.settings.tx_color),
    ] {
        frame.render_widget(
            Paragraph::new(label).style(Style::default().fg(plot_color(color))),
            Rect::new(plot.x + 1, plot.y + row, 2, 1),
        );
    }
    let label_y = inner.bottom() - 1;
    frame.buffer_mut().set_stringn(
        plot.x,
        label_y,
        format!("-{:.0}s", app.history_seconds()),
        usize::from(plot.width),
        Style::default(),
    );
    if plot.width >= 28 {
        let label = format!("-{:.0}s", app.history_seconds() / 2.0);
        frame.buffer_mut().set_stringn(
            plot.x + (plot.width - label.len() as u16) / 2,
            label_y,
            &label,
            label.len(),
            Style::default(),
        );
    }
    frame
        .buffer_mut()
        .set_stringn(plot.right() - 2, label_y, "0s", 2, Style::default());
}

fn status_line(app: &App) -> Option<(String, Color)> {
    let lang = app.lang();
    if let Some(notice) = &app.notice {
        return Some((
            notice.clone(),
            if app.notice_error { Color::Red } else { KEY },
        ));
    }
    if app.searching {
        return Some((
            match lang {
                Lang::En => format!("Search: {}_  Enter apply / Esc clear", app.filter),
                Lang::De => format!("Suche: {}_  Enter übernimmt / Esc leert", app.filter),
            },
            KEY,
        ));
    }
    if !app.filter.is_empty() {
        return Some((
            format!(
                "Filter: {}  {}",
                app.filter,
                lang.pick("Esc clears", "Esc leert")
            ),
            KEY,
        ));
    }
    if app.demo {
        return None; // The device header already identifies synthetic data.
    }
    let capture = &app.snapshot.capture;
    if !capture.active {
        let message = if let Some(message) = lang.capture_status(capture, true) {
            message
        } else if capture.message.is_empty() {
            lang.pick(
                "Interface mode | enable process rates with scripts/setup-capture.sh",
                "Schnittstellenmodus | Prozessraten mit scripts/setup-capture.sh aktivieren",
            )
            .into()
        } else {
            capture.message.clone()
        };
        return Some((message, TX));
    }
    if app.snapshot.capture.dropped > 0 {
        return Some((
            match lang {
                Lang::En => format!(
                    "Capture: {} dropped packets | rates incomplete",
                    app.snapshot.capture.dropped
                ),
                Lang::De => format!(
                    "Capture: {} verworfene Pakete | Raten unvollständig",
                    app.snapshot.capture.dropped
                ),
            },
            TX,
        ));
    }
    // The routine explanation stays in F1 Help; runtime warnings are shown.
    if let Some(message) = lang.capture_status(capture, false) {
        return (!message.is_empty()).then_some((message, TX));
    }
    // Helpers without structured notes send one English text; strip the
    // explanation and preserve any appended warning.
    let message = app.snapshot.capture.message.strip_prefix(
        "Process rates: captured IP bytes; socket/PID owners sampled, brief sockets may be unattributed"
    ).unwrap_or(&app.snapshot.capture.message).trim_start_matches("; ");
    (!message.is_empty()).then(|| (message.to_string(), TX))
}

fn draw_table(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    app.visible_rows = usize::from(area.height.saturating_sub(1));
    let wide = area.width >= 94;
    let medium = area.width >= 52;
    let captured = app.snapshot.capture.active || app.demo;
    let lang = app.lang();
    let user = lang.pick("USER", "BENUTZER");
    let command = lang.pick("COMMAND", "BEFEHL");
    let remote = lang.pick("REMOTE", "FERN");
    let receive_color = plot_color(app.settings.rx_color);
    let send_color = plot_color(app.settings.tx_color);
    let rate = |value| {
        if captured {
            // The column header already carries /s; retain the whole unit at 40 columns.
            format_rate(value, app.settings.bits)
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
    let (headers, widths, rows): (Vec<&str>, Vec<Constraint>, Vec<Row<'_>>) = if app
        .settings
        .connections
    {
        let records = app.connection_rows();
        if wide {
            (
                vec![
                    "PID",
                    "PROTO",
                    "RX/s",
                    "TX/s",
                    lang.pick("LOCAL", "LOKAL"),
                    remote,
                    command,
                ],
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
                            number_cell(pid(row.pid)),
                            Cell::from(row.protocol.clone()),
                            number_cell(rate(row.rx_rate))
                                .style(Style::default().fg(receive_color)),
                            number_cell(rate(row.tx_rate)).style(Style::default().fg(send_color)),
                            Cell::from(row.local.clone()),
                            Cell::from(row.remote.clone()),
                            Cell::from(row.process.clone()),
                        ])
                    })
                    .collect(),
            )
        } else {
            (
                vec!["PID", "RX/s", "TX/s", remote],
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
                            number_cell(pid(row.pid)),
                            number_cell(rate(row.rx_rate))
                                .style(Style::default().fg(receive_color)),
                            number_cell(rate(row.tx_rate)).style(Style::default().fg(send_color)),
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
                vec![
                    "PID",
                    user,
                    "RX/s",
                    "TX/s",
                    lang.pick("TOTAL", "GESAMT"),
                    lang.pick("CONN", "VERB"),
                    command,
                ],
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
                            number_cell(pid(row.pid)),
                            Cell::from(row.user.clone()),
                            number_cell(rate(row.rx_rate))
                                .style(Style::default().fg(receive_color)),
                            number_cell(rate(row.tx_rate)).style(Style::default().fg(send_color)),
                            number_cell(total(row.rx_bytes.saturating_add(row.tx_bytes))),
                            number_cell(row.connections.to_string()),
                            Cell::from(row.name.clone()),
                        ])
                    })
                    .collect(),
            )
        } else if medium {
            (
                vec!["PID", user, "RX/s", "TX/s", command],
                vec![
                    Constraint::Length(7),
                    Constraint::Length(8),
                    Constraint::Length(if area.width >= 64 { 12 } else { 10 }),
                    Constraint::Length(if area.width >= 64 { 12 } else { 10 }),
                    Constraint::Min(6),
                ],
                records
                    .into_iter()
                    .map(|row| {
                        Row::new(vec![
                            number_cell(pid(row.pid)),
                            Cell::from(row.user.clone()),
                            number_cell(rate(row.rx_rate))
                                .style(Style::default().fg(receive_color)),
                            number_cell(rate(row.tx_rate)).style(Style::default().fg(send_color)),
                            Cell::from(row.name.clone()),
                        ])
                    })
                    .collect(),
            )
        } else {
            (
                vec!["PID", "RX/s", "TX/s", command],
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
                            number_cell(pid(row.pid)),
                            number_cell(rate(row.rx_rate))
                                .style(Style::default().fg(receive_color)),
                            number_cell(rate(row.tx_rate)).style(Style::default().fg(send_color)),
                            Cell::from(row.name.clone()),
                        ])
                    })
                    .collect(),
            )
        }
    };
    let count = rows.len();
    let header = Row::new(headers.into_iter().map(|header| {
        if matches!(
            header,
            "PID" | "RX/s" | "TX/s" | "TOTAL" | "CONN" | "GESAMT" | "VERB"
        ) {
            number_cell(header.into())
        } else {
            Cell::from(header)
        }
    }))
    .style(inverse(Color::Green));
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(inverse(KEY));
    frame.render_stateful_widget(table, area, &mut app.table);
    if count == 0 && area.height > 1 {
        let message = if app.filter.is_empty() {
            lang.pick(
                "Waiting for network activity...",
                "Warte auf Netzwerkaktivität...",
            )
        } else {
            lang.pick(
                "No matching processes or connections.",
                "Keine passenden Prozesse oder Verbindungen.",
            )
        };
        frame.render_widget(
            Paragraph::new(message).style(Style::default().fg(DIM)),
            Rect {
                x: area.x,
                y: area.y + 1,
                width: area.width,
                height: 1,
            },
        );
    }
}

fn draw_footer(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let lang = app.lang();
    // German labels are abbreviated like Midnight Commander's on narrow
    // terminals, so every required key fits at 36 columns.
    let wide = area.width >= 60;
    let mut keys = vec![
        ("F1", lang.pick("Help", "Hilfe")),
        ("F2", lang.pick("Setup", "Setup")),
    ];
    if area.width >= 44 {
        keys.push(("F3", lang.pick("Search", "Suche")));
    }
    if area.width >= 80 {
        keys.extend([
            ("F4", lang.pick("View", "Ansicht")),
            ("F5", lang.pick("Iface", "Gerät")),
        ]);
    }
    keys.push((
        "F6",
        if wide {
            lang.pick("Sort", "Sortieren")
        } else {
            lang.pick("Sort", "Sort")
        },
    ));
    if area.width >= 94 {
        keys.push((
            "F9",
            if app.paused {
                lang.pick("Resume", "Weiter")
            } else {
                lang.pick("Pause", "Pause")
            },
        ));
    }
    keys.push(("F10", lang.pick("Quit", "Ende")));
    keys.push((
        "F12",
        if wide {
            lang.pick("SaveConfig", "Speichern")
        } else {
            lang.pick("Save", "Speich")
        },
    ));
    draw_key_bar(frame, area, &keys);
}

fn draw_key_bar(frame: &mut Frame<'_>, area: Rect, keys: &[(&str, &str)]) {
    let used: usize = keys
        .iter()
        .map(|(key, label)| key.chars().count() + label.chars().count())
        .sum();
    let padding = usize::from(area.width).saturating_sub(used);
    let mut spans = Vec::new();
    for (index, (key, label)) in keys.iter().enumerate() {
        let spaces = padding / keys.len() + usize::from(index < padding % keys.len());
        spans.push(Span::raw((*key).to_owned()));
        spans.push(Span::styled(
            format!("{label}{}", " ".repeat(spaces)),
            inverse(KEY),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn plot_color_label(color: PlotColor, lang: Lang) -> &'static str {
    match (color, lang) {
        (_, Lang::En) | (PlotColor::Cyan | PlotColor::Magenta, _) => color.label(),
        (PlotColor::Green, Lang::De) => "Grün",
        (PlotColor::Yellow, Lang::De) => "Gelb",
        (PlotColor::Red, Lang::De) => "Rot",
        (PlotColor::Blue, Lang::De) => "Blau",
        (PlotColor::White, Lang::De) => "Weiß",
    }
}

fn draw_setup(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let lang = app.lang();
    let names = categories(lang);
    frame.render_widget(Clear, area);
    let vertical = Layout::vertical([
        Constraint::Min(6),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(area);
    // Room for the longest category and the focus marker " >".
    let category_width = names
        .iter()
        .map(|name| name.chars().count() as u16 + 2)
        .max()
        .unwrap_or(0)
        .max(12);
    let panes = Layout::horizontal([
        Constraint::Length(category_width),
        Constraint::Length(1),
        Constraint::Min(20),
    ])
    .split(vertical[0]);
    frame.render_widget(
        Paragraph::new("Setup").style(inverse(Color::Green)),
        Rect::new(panes[0].x, panes[0].y, panes[0].width, 1),
    );
    for (index, name) in names.iter().enumerate() {
        let current = app.setup_category == index;
        let style = if current && !app.setup_focus {
            inverse(KEY)
        } else if current {
            Style::default().fg(KEY).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let text = if current && app.setup_focus {
            format!("{name} >")
        } else {
            (*name).into()
        };
        frame.render_widget(
            Paragraph::new(text).style(style),
            Rect::new(panes[0].x, panes[0].y + index as u16 + 1, panes[0].width, 1),
        );
    }
    let check = |enabled| if enabled { "[*]" } else { "[ ]" };
    let options: Vec<String> = match app.setup_category {
        0 => vec![
            format!(
                "{} {}",
                check(app.settings.color),
                lang.pick("Color", "Farbe")
            ),
            format!(
                "[{:.1}s] {}",
                app.settings.interval_ms as f64 / 1000.0,
                lang.pick("Update interval", "Aktualisierung")
            ),
            format!(
                "{} {}",
                check(app.settings.bits),
                lang.pick("Rates in bits/s", "Raten in Bit/s")
            ),
            format!(
                "[{}] {}",
                match app.settings.language {
                    Language::Auto => "Auto",
                    Language::En => "English",
                    Language::De => "Deutsch",
                },
                lang.pick("Language", "Sprache")
            ),
        ],
        1 => {
            let mut rows = vec![
                format!(
                    "{} Auto ({})",
                    check(app.settings.interface.is_none()),
                    app.auto_interface
                        .as_deref()
                        .unwrap_or(lang.pick("all", "alle"))
                ),
                format!(
                    "{} {}",
                    check(app.settings.interface.as_deref() == Some("all")),
                    lang.pick("All interfaces", "Alle")
                ),
            ];
            rows.extend(app.snapshot.interfaces.iter().map(|iface| {
                format!(
                    "{} {} ({})",
                    check(app.settings.interface.as_deref() == Some(&iface.name)),
                    iface.name,
                    iface.state
                )
            }));
            rows
        }
        2 => vec![
            format!(
                "{} {}",
                check(app.settings.show_graph),
                lang.pick("Show graph", "Diagramm zeigen")
            ),
            format!(
                "[{}s] {}",
                app.settings.history_seconds,
                lang.pick("History", "Verlauf")
            ),
            format!(
                "[{}] {}",
                match (app.settings.graph_style, lang) {
                    (GraphStyle::Steps, Lang::De) => "Stufen",
                    (style, _) => style.label(),
                },
                lang.pick("Drawing", "Zeichnung")
            ),
            format!(
                "[{}] {}",
                plot_color_label(app.settings.rx_color, lang),
                lang.pick("Receive color", "Empfangsfarbe")
            ),
            format!(
                "[{}] {}",
                plot_color_label(app.settings.tx_color, lang),
                lang.pick("Send color", "Sendefarbe")
            ),
        ],
        _ => vec![
            format!(
                "[{}] {}",
                if app.settings.connections {
                    lang.pick("Connections", "Verbindungen")
                } else {
                    lang.pick("Processes", "Prozesse")
                },
                lang.pick("View", "Ansicht")
            ),
            format!(
                "[{}] {}",
                app.settings.sort.label(lang),
                lang.pick("Sort by", "Sortierung")
            ),
            format!(
                "{} {}",
                check(app.settings.show_idle),
                lang.pick("Show idle rows", "Inaktive Zeilen zeigen")
            ),
        ],
    };
    let name = names[app.setup_category];
    let header = match lang {
        Lang::En => format!("{name} Options"),
        Lang::De => format!("Optionen: {name}"),
    };
    // Narrow terminals show just the category rather than a cut-off header.
    let header = if header.chars().count() > usize::from(panes[2].width) {
        name.to_owned()
    } else {
        header
    };
    let mut state =
        TableState::default().with_selected(app.setup_focus.then_some(app.setup_option));
    let table = Table::new(
        options.into_iter().map(|row| Row::new([row])),
        [Constraint::Min(1)],
    )
    .header(Row::new([header]).style(inverse(Color::Green)))
    .row_highlight_style(inverse(KEY));
    frame.render_stateful_widget(table, panes[2], &mut state);
    let description = match (app.setup_category, app.setup_option) {
        (0, 0) => lang.pick(
            "Use the terminal's own ANSI palette. Selection stays visible in monochrome.",
            "Nutzt die ANSI-Palette des Terminals. Die Auswahl bleibt auch einfarbig sichtbar.",
        ),
        (0, 1) => lang.pick(
            "Refresh the display every 0.1 to 60 seconds. +/- changes by 0.1s.",
            "Aktualisiert alle 0,1 bis 60 Sekunden. +/- ändert um 0,1 s.",
        ),
        (0, 2) => lang.pick(
            "Switch between bytes per second (KiB/s) and bits per second (Mbit/s).",
            "Wechselt zwischen Byte pro Sekunde (KiB/s) und Bit pro Sekunde (Mbit/s).",
        ),
        (0, _) => lang.pick(
            "Auto follows the system language (LANG). English or German can be fixed here.",
            "Auto folgt der Systemsprache (LANG). Englisch oder Deutsch lässt sich festlegen.",
        ),
        (1, _) => lang.pick(
            "Enter selects an interface. Auto follows the default route at startup. All can count virtual links twice.",
            "Enter wählt eine Schnittstelle. Auto folgt beim Start der Standardroute. Alle kann virtuelle Links doppelt zählen.",
        ),
        (2, 0) => lang.pick(
            "Hide the graph to give the process table more space.",
            "Blendet das Diagramm aus, damit die Prozesstabelle mehr Platz hat.",
        ),
        (2, 1) => lang.pick(
            "Show 10 to 600 seconds of history. +/- changes by 10 seconds.",
            "Zeigt 10 bis 600 Sekunden Verlauf. +/- ändert um 10 Sekunden.",
        ),
        (2, 2) => lang.pick(
            "Steps uses nvtop-style terminal lines. Braille draws a finer curve.",
            "Stufen nutzt Terminal-Linien wie nvtop. Braille zeichnet eine feinere Kurve.",
        ),
        (2, _) => lang.pick(
            "Cycle through the terminal's standard colors with Enter or +/-.",
            "Wechselt mit Enter oder +/- durch die Standardfarben des Terminals.",
        ),
        (3, 0) => lang.pick(
            "Group traffic by process, or inspect individual connections.",
            "Gruppiert den Verkehr nach Prozess oder zeigt einzelne Verbindungen.",
        ),
        (3, 1) => lang.pick(
            "Choose the table's sort order. F6 opens the same choices in the monitor.",
            "Wählt die Sortierung der Tabelle. F6 bietet dieselbe Auswahl im Monitor.",
        ),
        _ => lang.pick(
            "Include sockets and processes with no traffic in the current sample.",
            "Zeigt auch Sockets und Prozesse ohne Verkehr in der aktuellen Messung.",
        ),
    };
    frame.render_widget(
        // Default foreground keeps the description readable on light themes.
        Paragraph::new(description).wrap(Wrap { trim: true }),
        vertical[1],
    );
    let message = app.notice.clone().unwrap_or_else(|| {
        if app.settings_dirty() {
            lang.pick(
                "Unsaved changes - F12 saves for next start",
                "Ungespeichert - F12 speichert für den nächsten Start",
            )
            .into()
        } else {
            lang.pick(
                "Arrows navigate | Enter / +/- change",
                "Pfeile wählen | Enter / +/- ändern",
            )
            .into()
        }
    });
    frame.render_widget(
        Paragraph::new(message).style(Style::default().fg(
            if app.notice_error && app.notice.is_some() {
                Color::Red
            } else {
                Color::Yellow
            },
        )),
        vertical[2],
    );
    draw_key_bar(
        frame,
        vertical[3],
        &[
            ("Tab", lang.pick("Panel", "Feld")),
            ("Ent", lang.pick("Change", "Ändern")),
            ("F10", lang.pick("Done", "Fertig")),
            (
                "F12",
                if area.width >= 40 {
                    lang.pick("Save", "Speichern")
                } else {
                    lang.pick("Save", "Speich")
                },
            ),
        ],
    );
}

fn draw_sort(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let area = popup(area, 32, 10);
    frame.render_widget(Clear, area);
    let lang = app.lang();
    let mut state = TableState::default().with_selected(app.picker.min(SORTS.len() - 1));
    let rows = SORTS.iter().map(|sort| Row::new([sort.label(lang)]));
    let table = Table::new(rows, [Constraint::Min(1)])
        .header(Row::new([lang.pick("Sort by", "Sortieren nach")]).style(inverse(Color::Green)))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(lang.pick(" Enter select / Esc close ", " Enter wählt / Esc schließt ")),
        )
        .row_highlight_style(inverse(KEY));
    frame.render_stateful_widget(table, area, &mut state);
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
    let lang = app.lang();
    let lines: &[&str] = match lang {
        Lang::En => &[
            "F1 / ?         Help     Esc closes",
            "F2             Setup: General, Interface, Chart, Processes",
            "F5 / i         Choose interface",
            "Tab / Shift-Tab Cycle up interfaces",
            "F3 / /         Search PID, user, command, endpoint",
            "F6             Choose sorting; s cycles sort order",
            "F12            Save current settings for next start",
            "F4 / c         Processes / connections",
            "b              Bytes/s / bits/s",
            "F9 / Space     Pause / resume display",
            "Up / Down      Select; PgUp / PgDn scroll",
            "q / F10 / Ctrl-C Quit",
            "",
            "RX: receive. TX: send. Default colors: green / yellow.",
            "Graph scale follows the visible peak.",
            "Bars use link speed, or visible peak when unknown.",
            "Interface totals are kernel counters since boot.",
            "Process totals are observed IP bytes this session.",
            "Shared, short-lived or inaccessible sockets can be unattributed.",
            "In all mode, virtual links can count forwarded traffic more than once.",
            "Command-line options and NO_COLOR apply only to this run.",
            "Enable process rates once: ./scripts/setup-capture.sh",
            "After setup, start nwtop without sudo.",
            "",
        ],
        Lang::De => &[
            "F1 / ?         Hilfe    Esc schließt",
            "F2             Setup: Allgemein, Schnittstelle, Diagramm, Prozesse",
            "F5 / i         Schnittstelle wählen",
            "Tab / Shift-Tab Aktive Schnittstellen durchlaufen",
            "F3 / /         PID, Benutzer, Befehl, Endpunkt suchen",
            "F6             Sortierung wählen; s wechselt die Sortierung",
            "F12            Aktuelle Einstellungen für den nächsten Start speichern",
            "F4 / c         Prozesse / Verbindungen",
            "b              Byte/s / Bit/s",
            "F9 / Leertaste Anzeige anhalten / fortsetzen",
            "Hoch / Runter  Auswählen; Bild hoch / runter blättert",
            "q / F10 / Strg-C Beenden",
            "",
            "RX: Empfang. TX: Senden. Standardfarben: grün / gelb.",
            "Die Diagrammskala folgt dem sichtbaren Spitzenwert.",
            "Balken nutzen die Link-Geschwindigkeit, sonst den sichtbaren Spitzenwert.",
            "Schnittstellensummen sind Kernel-Zähler seit dem Systemstart.",
            "Prozesssummen sind in dieser Sitzung beobachtete IP-Bytes.",
            "Geteilte, kurzlebige oder unzugängliche Sockets bleiben evtl. unzugeordnet.",
            "Im Modus Alle können virtuelle Links Weitergeleitetes mehrfach zählen.",
            "Kommandozeilenoptionen und NO_COLOR gelten nur für diesen Lauf.",
            "Prozessraten einmalig aktivieren: ./scripts/setup-capture.sh",
            "Danach nwtop ohne sudo starten.",
            "",
        ],
    };
    let mut text: Vec<Line<'_>> = lines.iter().map(|line| Line::from(*line)).collect();
    text.push(Line::from(
        lang.capture_status(&app.snapshot.capture, true)
            .unwrap_or_else(|| app.snapshot.capture.message.clone()),
    ));
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .scroll((app.help_scroll, 0))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(KEY))
                    .title(lang.pick(
                        " Help  Up/Down scroll / Esc close ",
                        " Hilfe  Hoch/Runter blättert / Esc schließt ",
                    )),
            )
            .style(Style::default()),
        area,
    );
}

fn draw_interfaces(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let area = popup(area, 72, (app.snapshot.interfaces.len() as u16 + 5).min(26));
    frame.render_widget(Clear, area);
    let lang = app.lang();
    let mut rows = vec![Row::new(vec![
        lang.pick("all", "alle").to_string(),
        lang.pick("includes virtual links", "inkl. virtueller Links")
            .to_string(),
    ])];
    rows.extend(app.snapshot.interfaces.iter().map(|iface| {
        Row::new(vec![
            iface.name.clone(),
            format!(
                "{}  RX {}  TX {}",
                iface.state,
                format_rate(iface.rx_rate, app.settings.bits),
                format_rate(iface.tx_rate, app.settings.bits)
            ),
        ])
    }));
    let mut state = TableState::default().with_selected(app.picker);
    let table = Table::new(rows, [Constraint::Length(16), Constraint::Min(10)])
        .header(
            Row::new([
                lang.pick("INTERFACE", "SCHNITTSTELLE"),
                lang.pick("STATE / TRAFFIC", "STATUS / VERKEHR"),
            ])
            .style(inverse(Color::Green)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(lang.pick(
                    " Interface  Enter select / Esc close ",
                    " Schnittstelle  Enter wählt / Esc schließt ",
                ))
                .border_style(Style::default().fg(KEY)),
        )
        .style(Style::default())
        .row_highlight_style(inverse(KEY));
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
            notes: Vec::new(),
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

    fn screen(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        let width = usize::from(buffer.area.width);
        buffer
            .content
            .chunks(width)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>() + "\n")
            .collect()
    }

    #[test]
    fn layouts_fit_narrow_and_wide_terminals_in_both_languages() {
        for (language, device, quit, done, save) in [
            (Language::En, "Device ", "F10Quit", "Done", "Save"),
            (Language::De, "Gerät ", "F10Ende", "Fertig", "Speich"),
        ] {
            for (width, height) in [(36, 16), (40, 24), (52, 18), (80, 24), (120, 36)] {
                let mut app = app();
                app.settings.language = language;
                let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                terminal.draw(|frame| draw(frame, &mut app)).unwrap();
                let text = screen(&terminal);
                let at = format!("{language:?} at {width}x{height}");
                assert!(text.contains(device), "title missing {at}");
                assert!(text.contains("RX/s"), "rates missing {at}");
                let footer = text.lines().last().unwrap();
                // Every required function key must be complete on the bottom row.
                for key in ["F1", "F2", "F6", quit, "F12"] {
                    assert!(footer.contains(key), "{key} missing {at}: {footer:?}");
                }
                assert!(
                    footer.trim_end().ends_with(save) || footer.contains(save),
                    "save label cut {at}: {footer:?}"
                );
                for overlay in [
                    Overlay::Help,
                    Overlay::Interfaces,
                    Overlay::Setup,
                    Overlay::Sort,
                ] {
                    app.overlay = overlay;
                    terminal.draw(|frame| draw(frame, &mut app)).unwrap();
                }
                app.overlay = Overlay::Setup;
                for (category, name) in categories(app.lang()).iter().enumerate() {
                    app.setup_category = category;
                    app.setup_focus = true;
                    app.setup_option = app.setup_len() - 1;
                    terminal.draw(|frame| draw(frame, &mut app)).unwrap();
                    let text = screen(&terminal);
                    assert!(
                        text.contains(&format!("{name} >")),
                        "category {name} cut {at}"
                    );
                    let keys = text.lines().last().unwrap();
                    assert!(keys.contains(done), "setup exit missing {at}: {keys:?}");
                    assert!(keys.contains(save), "setup save missing {at}: {keys:?}");
                }
            }
        }
    }

    #[test]
    fn german_text_covers_monitor_overlays_and_language_setup_row() {
        let mut app = app();
        app.system_lang = Lang::De;
        let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let text = screen(&terminal);
        for expected in [
            "Gerät ",
            "BENUTZER",
            "BEFEHL",
            "Hilfe",
            "Speichern",
            "gesamt",
        ] {
            assert!(text.contains(expected), "{expected} missing: {text}");
        }
        for (overlay, expected) in [
            (
                Overlay::Help,
                "Aktuelle Einstellungen für den nächsten Start",
            ),
            (Overlay::Sort, "Sortieren nach"),
            (Overlay::Interfaces, "SCHNITTSTELLE"),
            (Overlay::Setup, "Optionen: Allgemein"),
        ] {
            app.overlay = overlay;
            terminal.draw(|frame| draw(frame, &mut app)).unwrap();
            assert!(screen(&terminal).contains(expected), "{expected} missing");
        }
        // The fourth General row switches the language at runtime.
        app.overlay = Overlay::None;
        app.handle_key(KeyCode::F(2).into());
        app.handle_key(KeyCode::Right.into());
        for _ in 0..3 {
            app.handle_key(KeyCode::Down.into());
        }
        assert_eq!(
            app.handle_key(KeyCode::Enter.into()),
            Action::SettingsChanged
        );
        assert_eq!(app.settings.language, Language::En);
        assert_eq!(app.lang(), Lang::En);
        assert_eq!(app.settings_to_save().language, Language::En);
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert!(screen(&terminal).contains("[English] Language"));
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
        app.settings.sort = Sort::Pid;
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
        app.settings.bits = true;
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
        // 999.97 Mbit/s once rendered as "1000.0 Mbit" and lost its first digit.
        app.snapshot.processes[2].rx_rate = 999.97e6 / 8.0;
        app.settings.sort = Sort::Receive;
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let text = screen(&terminal);
        assert!(text.contains("1.0 Gbit"), "{text}");
        assert!(!text.contains("000.0"), "{text}");
    }

    #[test]
    fn plain_text_uses_the_terminal_default_foreground() {
        let mut app = app();
        let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        app.overlay = Overlay::Setup;
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert!(
            terminal
                .backend()
                .buffer()
                .content
                .iter()
                .all(|cell| cell.fg != Color::White),
            "white text is unreadable on light terminal themes"
        );
        app.overlay = Overlay::None;
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let buffer = terminal.backend().buffer();
        // The device summary ("[UP]  2500 Mbit/s ...") is the second row.
        let summary = (0..10).map(|x| &buffer[(x, 1)]).collect::<Vec<_>>();
        assert_eq!(summary[0].symbol(), "[");
        assert!(summary.iter().all(|cell| cell.fg == Color::Reset));
    }

    #[test]
    fn explicit_interface_choice_is_saved_even_when_it_matches_a_fallback() {
        let saved = Settings {
            interface: Some("gone0".into()),
            ..Settings::default()
        };
        let runtime = Settings {
            interface: None,
            ..saved.clone()
        };
        let mut app = App::with_saved(Some("enp112s0".into()), runtime, saved.clone(), true);
        app.update(demo_snapshot(1, 1.0));
        assert_eq!(app.settings_to_save(), saved);
        // Setup > Interface > Auto explicitly replaces the stale saved choice.
        app.handle_key(KeyCode::F(2).into());
        app.handle_key(KeyCode::Down.into());
        app.handle_key(KeyCode::Right.into());
        assert_eq!(
            app.handle_key(KeyCode::Enter.into()),
            Action::InterfaceChanged
        );
        assert_eq!(app.settings_to_save().interface, None);
        assert!(app.settings_dirty());
    }

    #[test]
    fn units_are_distinct_and_unknown_capture_does_not_show_fake_rates() {
        assert_eq!(format_rate(125_000.0, true), "1.0 Mbit/s");
        assert_eq!(format_bytes(1024.0), "1.0 KiB");
        // Rounding to the displayed precision may reach the next unit.
        assert_eq!(format_bytes(1023.6), "1.0 KiB");
        assert_eq!(format_bytes(1023.4), "1023 B");
        assert_eq!(format_bytes(1023.96 * 1024.0), "1.0 MiB");
        assert_eq!(format_bytes(1023.94 * 1024.0), "1023.9 KiB");
        assert_eq!(format_rate(999.97e6 / 8.0, true), "1.0 Gbit/s");
        assert_eq!(format_rate(999.96 / 8.0, true), "1.0 kbit/s");
        assert_eq!(format_rate(f64::NAN, false), "0 B/s");
        // Below the last unit, table cells and graph labels need 10 columns.
        let mut value = 0.5;
        while value < 1e14 {
            for bits in [false, true] {
                let text = format_rate(value, bits);
                let trimmed = text.trim_end_matches("/s");
                assert!(trimmed.len() <= 10, "{trimmed:?} is too wide");
            }
            assert!(format_bytes(value).len() <= 10);
            value *= 1.0007;
        }
        let mut app = app();
        app.demo = false;
        app.snapshot.capture.active = false;
        app.snapshot.capture.message =
            "Process rates unavailable; run scripts/setup-capture.sh".into();
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
        assert!(text.contains("setup-capture.sh"));
        assert!(!text.contains(format_rate(9_000_000_000.0, false).trim_end_matches("/s")));
    }

    #[test]
    fn setup_changes_apply_without_quitting_or_implicitly_saving() {
        let mut app = app();
        assert_eq!(app.handle_key(KeyCode::F(2).into()), Action::None);
        assert_eq!(app.overlay, Overlay::Setup);
        app.handle_key(KeyCode::Right.into());
        app.handle_key(KeyCode::Down.into());
        assert_eq!(
            app.handle_key(KeyCode::Char('+').into()),
            Action::SettingsChanged
        );
        assert_eq!(app.settings.interval_ms, 1100);
        assert!(app.settings_dirty());
        assert_eq!(app.handle_key(KeyCode::F(10).into()), Action::None);
        assert_eq!(app.overlay, Overlay::None);
        assert!(app.settings_dirty());
        assert_eq!(app.handle_key(KeyCode::F(12).into()), Action::SaveSettings);
        app.settings_saved("Saved test preferences".into());
        assert!(!app.settings_dirty());
        app.handle_key(KeyCode::F(6).into());
        app.handle_key(KeyCode::Down.into());
        app.handle_key(KeyCode::Enter.into());
        assert_eq!(app.settings.sort, Sort::Receive);
        assert_eq!(app.overlay, Overlay::None);
        assert_eq!(app.handle_key(KeyCode::F(10).into()), Action::Quit);
    }

    #[test]
    fn collector_status_follows_the_ui_language() {
        use crate::model::CaptureNote;
        let mut app = app();
        app.demo = false;
        app.settings.language = crate::config::Language::De;
        app.snapshot.capture.message = "English text from the collector".into();
        app.snapshot.capture.notes = vec![CaptureNote::Sampled, CaptureNote::OwnersInaccessible];
        let (line, _) = status_line(&app).unwrap();
        assert_eq!(line, "einige /proc-Besitzer unzugänglich");
        app.snapshot.capture.notes = vec![CaptureNote::Sampled];
        assert!(status_line(&app).is_none(), "the routine note stays in F1");
        app.snapshot.capture.active = false;
        app.snapshot.capture.notes = vec![CaptureNote::InterfaceMissing {
            name: "eth9".into(),
        }];
        assert_eq!(
            status_line(&app).unwrap().0,
            "F2: Schnittstelle wählen; eth9 ist nicht verfügbar"
        );
        // An older helper without notes: its text is shown as sent.
        app.snapshot.capture.notes.clear();
        assert_eq!(
            status_line(&app).unwrap().0,
            "English text from the collector"
        );
    }

    #[test]
    fn unavailable_rates_are_not_treated_as_idle() {
        let mut app = app();
        app.demo = false;
        app.settings.show_idle = false;
        for row in &mut app.snapshot.processes {
            row.rx_rate = 0.0;
            row.tx_rate = 0.0;
        }
        for row in &mut app.snapshot.connections {
            row.rx_rate = 0.0;
            row.tx_rate = 0.0;
        }
        assert!(app.process_rows().is_empty());
        assert!(app.connection_rows().is_empty());
        app.snapshot.capture.active = false;
        assert_eq!(app.process_rows().len(), app.snapshot.processes.len());
        assert_eq!(app.connection_rows().len(), app.snapshot.connections.len());
    }

    #[test]
    fn monochrome_covers_small_windows_and_all_overlays() {
        let mut app = app();
        app.settings.color = false;
        for (width, height) in [(20, 10), (36, 16), (52, 18), (120, 36)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            for overlay in [
                Overlay::None,
                Overlay::Help,
                Overlay::Setup,
                Overlay::Sort,
                Overlay::Interfaces,
            ] {
                app.overlay = overlay;
                terminal.draw(|frame| draw(frame, &mut app)).unwrap();
                assert!(
                    terminal
                        .backend()
                        .buffer()
                        .content
                        .iter()
                        .all(|cell| cell.fg == Color::Reset && cell.bg == Color::Reset),
                    "colored cell in {overlay:?} at {width}x{height}"
                );
            }
        }
    }

    #[test]
    fn graph_time_labels_stay_visible_and_hiding_graph_frees_rows() {
        let mut app = app();
        let mut terminal = Terminal::new(TestBackend::new(52, 18)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("-60s"));
        assert!(text.contains("-30s"));
        let with_graph = app.visible_rows;
        app.settings.show_graph = false;
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert!(app.visible_rows > with_graph);
    }
}
