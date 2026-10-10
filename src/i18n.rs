//! English and German terminal UI text. CLI help, errors on stderr and JSON
//! output intentionally stay English and stable.

use crate::config::Language;

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
}
