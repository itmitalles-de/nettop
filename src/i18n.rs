//! English and German terminal UI text. CLI help, errors on stderr and JSON
//! output intentionally stay English and stable.

use crate::config::Language;
use crate::model::{CaptureNote, CaptureStatus};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Lang {
    #[default]
    En,
    De,
}

impl Lang {
    /// Choose the text for this language.
    pub fn pick<'a>(self, english: &'a str, german: &'a str) -> &'a str {
        match self {
            Self::En => english,
            Self::De => german,
        }
    }

    /// The POSIX message locale: the first non-empty value of LC_ALL,
    /// LC_MESSAGES and LANG. German locales select German, all others English.
    pub fn from_locale<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> Self {
        match values.into_iter().flatten().find(|value| !value.is_empty()) {
            Some(locale) if locale.starts_with("de") => Self::De,
            _ => Self::En,
        }
    }

    pub fn system() -> Self {
        let read = |name| std::env::var(name).ok();
        let (all, messages, lang) = (read("LC_ALL"), read("LC_MESSAGES"), read("LANG"));
        Self::from_locale([all.as_deref(), messages.as_deref(), lang.as_deref()])
    }

    pub fn resolve(setting: Language, system: Self) -> Self {
        match setting {
            Language::Auto => system,
            Language::En => Self::En,
            Language::De => Self::De,
        }
    }

    pub fn settings_problem(self, error: &str) -> String {
        format!("{}: {error}", self.pick("Settings", "Einstellungen"))
    }

    pub fn unknown_keys(self, keys: &[String]) -> String {
        let keys = keys.join(", ");
        match self {
            Self::En => format!("Settings: unknown keys ignored and kept on save: {keys}"),
            Self::De => format!(
                "Einstellungen: unbekannte Schlüssel ignoriert, beim Speichern behalten: {keys}"
            ),
        }
    }

    pub fn interface_unavailable(self, name: &str) -> String {
        match self {
            Self::En => format!("Saved interface {name} unavailable; using automatic selection"),
            Self::De => {
                format!("Gespeicherte Schnittstelle {name} fehlt; automatische Auswahl aktiv")
            }
        }
    }

    pub fn saved(self, path: &str) -> String {
        format!("{} {path}", self.pick("Saved", "Gespeichert:"))
    }

    pub fn save_failed(self, error: &str) -> String {
        format!(
            "{}: {error}",
            self.pick("Save failed", "Speichern fehlgeschlagen")
        )
    }

    pub fn root_with_foreign_settings(self) -> String {
        self.pick(
            "Save refused: nettop runs as root with another user's settings; start without sudo",
            "Nicht gespeichert: nettop läuft als root mit fremden Einstellungen; ohne sudo starten",
        )
        .into()
    }

    pub fn sample_failed(self, error: &str) -> String {
        format!(
            "{}: {error}",
            self.pick("Sample failed", "Messung fehlgeschlagen")
        )
    }

    pub fn settings_path_unavailable(self) -> &'static str {
        self.pick(
            "settings path unavailable",
            "Einstellungspfad nicht verfügbar",
        )
    }

    /// Collector status text. English is also the stable `message` field.
    /// Details from libpcap or the system stay as reported.
    pub fn capture_note(self, note: &CaptureNote) -> String {
        let de = self == Self::De;
        match note {
            CaptureNote::Disabled => self
                .pick(
                    "Capture disabled (--no-capture); interface counters and sockets only",
                    "Mitschnitt aus (--no-capture); nur Schnittstellenzähler und Sockets",
                )
                .into(),
            CaptureNote::LibpcapMissing => self
                .pick(
                    "Install libpcap runtime (libpcap0.8); process rates unavailable",
                    "libpcap-Laufzeit (libpcap0.8) installieren; Prozessraten nicht verfügbar",
                )
                .into(),
            CaptureNote::SetupNeeded { detail } if de => format!(
                "Prozess-Mitschnitt braucht einmalige Einrichtung (siehe README); nicht verfügbar: {detail}"
            ),
            CaptureNote::SetupNeeded { detail } => format!(
                "Process capture needs one-time setup (see README); capture unavailable: {detail}"
            ),
            CaptureNote::Unavailable { detail } if de => {
                format!("Prozess-Mitschnitt nicht verfügbar: {detail}")
            }
            CaptureNote::Unavailable { detail } => format!("Process capture unavailable: {detail}"),
            CaptureNote::NoInterfaceIndexes => self
                .pick(
                    "Process rates unavailable: libpcap lacks SLL2 interface indexes; upgrade libpcap or use -i all",
                    "Prozessraten nicht verfügbar: libpcap fehlen SLL2-Schnittstellenindizes; libpcap aktualisieren oder -i all nutzen",
                )
                .into(),
            CaptureNote::AllInterfaces => self
                .pick(
                    "ALL interfaces: forwarded bridge/veth packets can repeat; process rates count captured IP bytes",
                    "ALLE Schnittstellen: weitergeleitete Bridge/veth-Pakete können sich wiederholen; Prozessraten zählen mitgeschnittene IP-Bytes",
                )
                .into(),
            CaptureNote::Extended => self.pick("Process rates: captured IP bytes; socket events with sampled fallback", "Prozessraten: mitgeschnittene IP-Bytes; Socket-Ereignisse mit Abtast-Fallback").into(),
            CaptureNote::AllSocketPackets => self.pick("ALL: TCP/UDP socket packets across namespaces; forwarded traffic requires an interface selection", "ALLE: TCP/UDP-Socketpakete aller Namespaces; weitergeleiteten Verkehr auf einer Schnittstelle anzeigen").into(),
            CaptureNote::ExtendedIssue { detail } => format!("{}: {detail}",self.pick("Extended attribution", "Erweiterte Zuordnung")),
            CaptureNote::Sampled => self
                .pick(
                    "Process rates: captured IP bytes; socket/PID owners sampled, brief sockets may be unattributed",
                    "Prozessraten: mitgeschnittene IP-Bytes; Socket/PID-Besitzer abgetastet, kurze Sockets evtl. unzugeordnet",
                )
                .into(),
            CaptureNote::PcapMissed { packets } if de => {
                format!("pcap hat {packets} Pakete verpasst")
            }
            CaptureNote::PcapMissed { packets } => format!("pcap missed {packets} packets"),
            CaptureNote::FlowLimit { packets } if de => {
                format!("Flusslimit: {packets} Pakete unzugeordnet")
            }
            CaptureNote::FlowLimit { packets } => {
                format!("flow limit: {packets} packets unattributed")
            }
            CaptureNote::CaptureQueueLimit { packets } if de => {
                format!("Mitschnittpuffer voll: {packets} Pakete ohne Zuordnungsdetails")
            }
            CaptureNote::CaptureQueueLimit { packets } => {
                format!("capture queue full: {packets} packets without attribution detail")
            }
            CaptureNote::AttributionQueueLimit { packets } if de => {
                format!("Zuordnungspuffer voll: {packets} Beobachtungen ohne weitere Wartezeit ausgewertet")
            }
            CaptureNote::AttributionQueueLimit { packets } => {
                format!("attribution queue full: {packets} observations resolved without further waiting")
            }
            CaptureNote::Unreadable {
                unsupported,
                truncated,
            } if de => format!(
                "kein IP/nicht unterstützt {unsupported} / unlesbare Header {truncated}"
            ),
            CaptureNote::Unreadable {
                unsupported,
                truncated,
            } => format!("non-IP/unsupported {unsupported} / unreadable headers {truncated}"),
            CaptureNote::AttributionAtRefresh { error } if de => {
                format!("Zuordnung nur beim Aktualisieren: {error}")
            }
            CaptureNote::AttributionAtRefresh { error } => {
                format!("attribution only at refresh: {error}")
            }
            CaptureNote::Stopped { error } if de => format!(
                "Prozess-Mitschnitt gestoppt: {error}; Schnittstellenzähler bleiben verfügbar"
            ),
            CaptureNote::Stopped { error } => format!(
                "Process capture stopped: {error}; interface counters remain available"
            ),
            CaptureNote::OwnersInaccessible => self
                .pick(
                    "some /proc owners inaccessible",
                    "einige /proc-Besitzer unzugänglich",
                )
                .into(),
            CaptureNote::CounterLimit => self
                .pick(
                    "socket/owner counter limit reached",
                    "Socket/Besitzer-Zählerlimit erreicht",
                )
                .into(),
            CaptureNote::InterfaceMissing { name } if de => {
                format!("F2: Schnittstelle wählen; {name} ist nicht verfügbar")
            }
            CaptureNote::InterfaceMissing { name } => {
                format!("F2: choose interface; {name} is unavailable")
            }
            CaptureNote::Unknown => String::new(),
        }
    }

    /// The translated status, or `None` when it must be shown as sent: by a
    /// helper without structured notes, or with a note this UI does not know.
    /// `routine` includes the always-true explanation shown in F1 Help.
    pub fn capture_status(self, status: &CaptureStatus, routine: bool) -> Option<String> {
        if status.notes.is_empty() || status.notes.contains(&CaptureNote::Unknown) {
            return None;
        }
        Some(
            status
                .notes
                .iter()
                .filter(|note| {
                    routine || !matches!(note, CaptureNote::Sampled | CaptureNote::Extended)
                })
                .map(|note| self.capture_note(note))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    pub fn helper_failed(self, error: &str) -> String {
        match self {
            Self::En => format!("Capture helper failed: {error}; using direct counters"),
            Self::De => format!("Capture-Helper fehlgeschlagen: {error}; nutze direkte Zähler"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_precedence_and_german_detection() {
        assert_eq!(Lang::from_locale([None, None, None]), Lang::En);
        assert_eq!(
            Lang::from_locale([None, None, Some("de_DE.UTF-8")]),
            Lang::De
        );
        assert_eq!(
            Lang::from_locale([Some("C.UTF-8"), None, Some("de_DE.UTF-8")]),
            Lang::En
        );
        assert_eq!(
            Lang::from_locale([Some(""), Some("de_AT.UTF-8"), Some("en_US.UTF-8")]),
            Lang::De
        );
        assert_eq!(Lang::from_locale([None, None, Some("en_GB")]), Lang::En);
        assert_eq!(Lang::resolve(Language::Auto, Lang::De), Lang::De);
        assert_eq!(Lang::resolve(Language::En, Lang::De), Lang::En);
        assert_eq!(Lang::resolve(Language::De, Lang::En), Lang::De);
    }

    #[test]
    fn capture_status_is_translated_or_shown_as_sent() {
        let mut status = CaptureStatus {
            active: true,
            message: "raw helper text".into(),
            dropped: 0,
            notes: vec![
                CaptureNote::Sampled,
                CaptureNote::OwnersInaccessible,
                CaptureNote::InterfaceMissing {
                    name: "eth9".into(),
                },
            ],
        };
        assert_eq!(
            Lang::De.capture_status(&status, false).unwrap(),
            "einige /proc-Besitzer unzugänglich; F2: Schnittstelle wählen; eth9 ist nicht verfügbar"
        );
        let english = Lang::En.capture_status(&status, true).unwrap();
        assert!(english.starts_with("Process rates: captured IP bytes;"));
        assert!(english.ends_with(
            "; some /proc owners inaccessible; F2: choose interface; eth9 is unavailable"
        ));
        // Unknown codes from a newer helper decode, and the raw text is shown.
        let decoded: CaptureStatus = serde_json::from_str(
            r#"{"active":true,"message":"m","dropped":0,"notes":[{"code":"from_the_future","x":1}]}"#,
        )
        .unwrap();
        assert_eq!(decoded.notes, vec![CaptureNote::Unknown]);
        assert!(Lang::De.capture_status(&decoded, true).is_none());
        // Helpers predating structured notes send only the message.
        let old: CaptureStatus =
            serde_json::from_str(r#"{"active":false,"message":"m","dropped":0}"#).unwrap();
        assert!(old.notes.is_empty());
        status.notes.clear();
        assert!(Lang::De.capture_status(&status, true).is_none());
    }
}
