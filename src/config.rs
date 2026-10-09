//! User-owned UI preferences. The privileged collector never reads this file.

use std::{
    env,
    ffi::{CStr, CString},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

const VERSION: u32 = 1;
const MAX_BYTES: u64 = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphStyle {
    #[default]
    Steps,
    Braille,
}

impl GraphStyle {
    pub fn next(self, direction: i32) -> Self {
        if direction.rem_euclid(2) == 0 {
            self
        } else {
            match self {
                Self::Steps => Self::Braille,
                Self::Braille => Self::Steps,
            }
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Steps => "Steps",
            Self::Braille => "Braille",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlotColor {
    #[default]
    Green,
    Yellow,
    Cyan,
    Red,
    Blue,
    Magenta,
    White,
}

impl PlotColor {
    pub fn next(self, direction: i32) -> Self {
        let colors = [
            Self::Green,
            Self::Yellow,
            Self::Cyan,
            Self::Red,
            Self::Blue,
            Self::Magenta,
            Self::White,
        ];
        let index = colors.iter().position(|color| *color == self).unwrap_or(0);
        colors[(index as i64 + i64::from(direction)).rem_euclid(colors.len() as i64) as usize]
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Green => "Green",
            Self::Yellow => "Yellow",
            Self::Cyan => "Cyan",
            Self::Red => "Red",
            Self::Blue => "Blue",
            Self::Magenta => "Magenta",
            Self::White => "White",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortKey {
    #[default]
    Traffic,
    Receive,
    Send,
    Total,
    Pid,
    Name,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub version: u32,
    pub interface: Option<String>,
    pub interval_ms: u64,
    pub history_seconds: u16,
    pub bits: bool,
    pub color: bool,
    pub show_graph: bool,
    pub graph_style: GraphStyle,
    pub rx_color: PlotColor,
    pub tx_color: PlotColor,
    pub connections: bool,
    pub sort: SortKey,
    pub show_idle: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            version: VERSION,
            interface: None,
            interval_ms: 1000,
            history_seconds: 60,
            bits: false,
            color: true,
            show_graph: true,
            graph_style: GraphStyle::Steps,
            rx_color: PlotColor::Green,
            tx_color: PlotColor::Yellow,
            connections: false,
            sort: SortKey::Traffic,
            show_idle: true,
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        if self.version != VERSION {
            bail!(
                "unsupported settings version {}; this nettop supports version {VERSION}",
                self.version
            );
        }
        if !(100..=60_000).contains(&self.interval_ms) {
            bail!("interval_ms must be between 100 and 60000");
        }
        if !(10..=600).contains(&self.history_seconds) {
            bail!("history_seconds must be between 10 and 600");
        }
        if let Some(name) = &self.interface
            && (name.is_empty()
                || name.len() >= libc::IFNAMSIZ
                || name == "."
                || name == ".."
                || name
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace() || c == '/' || c == ':'))
        {
            bail!("interface must be 'all' or a valid Linux interface name");
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ConfigFile {
    path: PathBuf,
}

impl ConfigFile {
    pub fn discover() -> Result<Self> {
        let base = match env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
            Some(value) if Path::new(&value).is_absolute() => PathBuf::from(value),
            // XDG specifies that relative environment paths must be ignored.
            _ => {
                let home =
                    env::var_os("HOME").context("HOME is not set; cannot locate settings")?;
                if !Path::new(&home).is_absolute() {
                    bail!("HOME must be an absolute path to locate settings");
                }
                PathBuf::from(home).join(".config")
            }
        };
        Ok(Self::at(base.join("nettop/config.json")))
    }

    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Settings> {
        self.load_inner().with_context(|| {
            format!(
                "cannot load {}; fix or move this settings file to use defaults",
                self.path.display()
            )
        })
    }

    fn load_inner(&self) -> Result<Settings> {
        let (parent, name) = self.location()?;
        let directory = match open_directory(parent) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Settings::default()),
            Err(error) => return Err(error.into()),
        };
        validate_directory(&directory)?;
        Ok(read_settings(&directory, &name)?.unwrap_or_default())
    }

    pub fn save(&self, settings: &Settings) -> Result<()> {
        settings.validate()?;
        self.save_inner(settings).with_context(|| {
            format!(
                "cannot save {}; existing settings have not been intentionally discarded",
                self.path.display()
            )
        })
    }

    fn save_inner(&self, settings: &Settings) -> Result<()> {
        let (parent, name) = self.location()?;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let directory = open_directory(parent)?;
        validate_directory(&directory)?;
        // Never replace an unreadable, malformed, unsupported, or unsafe file.
        read_settings(&directory, &name)?;
        let mut bytes = serde_json::to_vec_pretty(settings)?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_BYTES {
            bail!("serialized settings exceed 64 KiB");
        }
        let (mut file, mut temporary) = TemporaryFile::create(&directory)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        // Check again after writing. All operations stay relative to the opened
        // directory, including when a user has symlinked their config directory.
        read_settings(&directory, &name)?;
        // SAFETY: both names are valid C strings and directory stays open.
        let result = unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary.name.as_ptr(),
                directory.as_raw_fd(),
                name.as_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        temporary.exists = false;
        directory.sync_all().context("syncing settings directory")?;
        Ok(())
    }

    fn location(&self) -> Result<(&Path, CString)> {
        let name = self
            .path
            .file_name()
            .context("settings path needs a file name")?;
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        Ok((parent, CString::new(name.as_bytes())?))
    }
}

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
}

fn validate_directory(directory: &File) -> Result<()> {
    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no preconditions and does not modify process state.
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        bail!("settings directory must be user-owned and not writable by other users");
    }
    Ok(())
}

fn read_settings(directory: &File, name: &CStr) -> Result<Option<Settings>> {
    // O_NOFOLLOW rejects the file itself being a symlink; O_NONBLOCK prevents an
    // unsafe FIFO from blocking before its file type can be inspected.
    // SAFETY: name is a valid C string and directory owns an open directory fd.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error).context("opening settings; config.json must not be a symlink");
    }
    // SAFETY: successful openat returned a new fd, now owned only by this File.
    let file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions and does not modify process state.
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        bail!(
            "settings must be a user-owned regular file without hard links or other write access"
        );
    }
    if metadata.len() > MAX_BYTES {
        bail!("settings file exceeds 64 KiB");
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        bail!("settings file exceeds 64 KiB");
    }
    let settings: Settings = serde_json::from_slice(&bytes).context("invalid settings JSON")?;
    settings.validate()?;
    Ok(Some(settings))
}

struct TemporaryFile<'a> {
    directory: &'a File,
    name: CString,
    exists: bool,
}

impl<'a> TemporaryFile<'a> {
    fn create(directory: &'a File) -> Result<(File, Self)> {
        for _ in 0..100 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = CString::new(format!(".nettop-{}-{sequence}.tmp", std::process::id()))?;
            // SAFETY: name is a valid C string; O_EXCL reserves a new owned file.
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600 as libc::mode_t,
                )
            };
            if descriptor >= 0 {
                // SAFETY: this successful openat returned a new, uniquely owned fd.
                let file = unsafe { File::from_raw_fd(descriptor) };
                return Ok((
                    file,
                    Self {
                        directory,
                        name,
                        exists: true,
                    },
                ));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error.into());
            }
        }
        bail!("cannot reserve a temporary settings file");
    }
}

impl Drop for TemporaryFile<'_> {
    fn drop(&mut self) {
        if self.exists {
            // SAFETY: this removes only the temporary name we created; no links
            // are followed and the borrowed directory remains open until return.
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "nettop-config-test-{}-{sequence}",
                std::process::id()
            ));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn config(&self) -> ConfigFile {
            ConfigFile::at(self.0.join("nettop/config.json"))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn missing_settings_default_and_roundtrip_updates_are_private() {
        let directory = TestDirectory::new();
        let config = directory.config();
        assert_eq!(config.load().unwrap(), Settings::default());
        assert!(!config.path().exists());
        let mut expected = Settings {
            interface: Some("all".to_owned()),
            bits: true,
            rx_color: PlotColor::Magenta,
            ..Settings::default()
        };
        config.save(&expected).unwrap();
        assert_eq!(config.load().unwrap(), expected);
        assert_eq!(fs::metadata(config.path()).unwrap().mode() & 0o777, 0o600);
        expected.interval_ms = 250;
        config.save(&expected).unwrap();
        assert_eq!(config.load().unwrap(), expected);
        assert_eq!(
            fs::read_dir(config.path().parent().unwrap())
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn missing_fields_use_defaults_and_invalid_settings_are_preserved() {
        let directory = TestDirectory::new();
        let config = directory.config();
        config.save(&Settings::default()).unwrap();
        fs::write(config.path(), br#"{"bits": true}"#).unwrap();
        assert_eq!(
            config.load().unwrap(),
            Settings {
                bits: true,
                ..Settings::default()
            }
        );
        for bytes in [
            "this is not settings JSON".to_owned(),
            r#"{"interval_ms":99}"#.to_owned(),
            r#"{"interval_ms":60001}"#.to_owned(),
            r#"{"history_seconds":9}"#.to_owned(),
            r#"{"history_seconds":601}"#.to_owned(),
            r#"{"version":2}"#.to_owned(),
            r#"{"interface":"../x"}"#.to_owned(),
            r#"{"interface":"a\u0000b"}"#.to_owned(),
            r#"{"interface":"1234567890123456"}"#.to_owned(),
            r#"{"graph_style":"unknown"}"#.to_owned(),
            "x".repeat(MAX_BYTES as usize + 1),
        ] {
            fs::write(config.path(), &bytes).unwrap();
            assert!(config.load().is_err());
            assert!(config.save(&Settings::default()).is_err());
            assert_eq!(fs::read_to_string(config.path()).unwrap(), bytes);
        }
    }

    #[test]
    fn file_symlinks_hardlinks_and_unsafe_files_are_never_overwritten() {
        let directory = TestDirectory::new();
        let config = directory.config();
        DirBuilder::new()
            .mode(0o700)
            .create(config.path().parent().unwrap())
            .unwrap();
        let target = directory.0.join("unrelated");
        fs::write(&target, "precious data").unwrap();
        symlink(&target, config.path()).unwrap();
        assert!(config.load().is_err());
        assert!(config.save(&Settings::default()).is_err());
        assert!(config.path().is_symlink());
        assert_eq!(fs::read_to_string(&target).unwrap(), "precious data");
        fs::remove_file(config.path()).unwrap();
        fs::hard_link(&target, config.path()).unwrap();
        assert!(config.load().is_err());
        assert!(config.save(&Settings::default()).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "precious data");
        fs::remove_file(config.path()).unwrap();
        config.save(&Settings::default()).unwrap();
        fs::set_permissions(config.path(), fs::Permissions::from_mode(0o666)).unwrap();
        assert!(config.load().is_err());
        assert!(config.save(&Settings::default()).is_err());
    }

    #[test]
    fn safe_symlinked_directories_work_but_shared_directories_do_not() {
        let directory = TestDirectory::new();
        let actual = directory.0.join("actual");
        DirBuilder::new().mode(0o700).create(&actual).unwrap();
        let alias = directory.0.join("alias");
        symlink(&actual, &alias).unwrap();
        let config = ConfigFile::at(alias.join("config.json"));
        config.save(&Settings::default()).unwrap();
        assert_eq!(config.load().unwrap(), Settings::default());
        fs::set_permissions(&actual, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(config.load().is_err());
        assert!(config.save(&Settings::default()).is_err());
    }

    #[test]
    fn special_files_are_rejected_without_waiting_for_a_writer() {
        let directory = TestDirectory::new();
        let config = directory.config();
        DirBuilder::new()
            .mode(0o700)
            .create(config.path().parent().unwrap())
            .unwrap();
        let name = CString::new(config.path().as_os_str().as_bytes()).unwrap();
        // SAFETY: name is a valid C string in our owned temporary directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(config.load().is_err());
        assert!(config.save(&Settings::default()).is_err());
    }

    #[test]
    fn setting_choices_cycle_in_both_directions() {
        assert_eq!(PlotColor::Green.next(-1), PlotColor::White);
        assert_eq!(PlotColor::White.next(1), PlotColor::Green);
        assert_eq!(GraphStyle::Steps.next(-1), GraphStyle::Braille);
        assert_eq!(GraphStyle::Braille.next(1), GraphStyle::Steps);
        assert_eq!(PlotColor::Green.next(0), PlotColor::Green);
    }
}
