//! Persistent configuration: the operating mode and the whitelist.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, io};

/// The pseudo-path WFP reports for traffic originated by the kernel.
pub const SYSTEM_APP: &str = "System";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Zero trust: only whitelisted apps may connect.
    Normal,
    /// Outbound traffic is allowed and every app that connects is whitelisted.
    Learning,
    /// Phoswire filters are removed; only Windows Firewall applies.
    Disabled,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Mode::Normal => "normal",
            Mode::Learning => "learning",
            Mode::Disabled => "disabled",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Manual,
    Learned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Full path of the executable, or `System` for the kernel.
    pub path: String,
    /// Restrict the rule to one Windows service hosted in `path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Also accept unsolicited inbound connections (servers).
    #[serde(default)]
    pub inbound: bool,
    pub source: Source,
    /// Unix seconds.
    pub added: u64,
}

impl Rule {
    pub fn same_subject(&self, path: &str, service: Option<&str>) -> bool {
        self.path.eq_ignore_ascii_case(path)
            && match (self.service.as_deref(), service) {
                (None, None) => true,
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                _ => false,
            }
    }

    pub fn subject(&self) -> String {
        match &self.service {
            Some(s) => format!("{} [service: {}]", self.path, s),
            None => self.path.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub mode: Mode,
    /// Unix seconds at which learning mode was switched on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learning_since: Option<u64>,
    /// Unix seconds at which learning mode reverts to normal by itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learning_until: Option<u64>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl Default for Config {
    fn default() -> Self {
        Config { mode: Mode::Normal, learning_since: None, learning_until: None, rules: Vec::new() }
    }
}

impl Config {
    pub fn dir() -> PathBuf {
        let base = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
        PathBuf::from(base).join("Phoswire")
    }

    pub fn file() -> PathBuf {
        Self::dir().join("config.json")
    }

    /// Makes the data directory safe to trust and returns notes worth logging.
    ///
    /// `%ProgramData%` lets every user create files in new subfolders, so
    /// without this an unprivileged program could plant or take over the
    /// whitelist. The directory is restricted to SYSTEM and Administrators,
    /// and anything in it (or the directory itself) that an unprivileged
    /// user created is moved out of the way instead of being read.
    pub fn secure_dir() -> Result<Vec<String>, String> {
        let dir = Self::dir();
        let mut notes = Vec::new();
        if let Ok(meta) = fs::symlink_metadata(&dir) {
            if meta.file_type().is_symlink() || !meta.is_dir() || !crate::win::path_owner_trusted(&dir) {
                let aside = dir.with_file_name(format!("Phoswire.untrusted-{}", now()));
                fs::rename(&dir, &aside).map_err(|e| {
                    format!("{} is not owned by an administrator and cannot be moved aside: {e}", dir.display())
                })?;
                notes.push(format!(
                    "{} was not created by an administrator; moved it to {} and started fresh",
                    dir.display(),
                    aside.display()
                ));
            }
        }
        fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        // Not fatal: the ownership checks below and in `save` still hold, and
        // refusing a good whitelist over this would block the whole machine.
        if let Err(e) = crate::win::lock_down(&dir) {
            notes.push(e);
        }
        for entry in fs::read_dir(&dir).map_err(|e| format!("reading {}: {e}", dir.display()))?.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "untrusted") {
                continue;
            }
            let link = entry.file_type().map(|t| t.is_symlink()).unwrap_or(true);
            if link || !crate::win::path_owner_trusted(&path) {
                let mut aside = path.clone().into_os_string();
                aside.push(".untrusted");
                match fs::rename(&path, &aside) {
                    Ok(()) => notes.push(format!(
                        "{} was not created by an administrator; ignored and renamed to *.untrusted",
                        path.display()
                    )),
                    Err(e) => return Err(format!("{} is untrusted and cannot be moved aside: {e}", path.display())),
                }
            }
        }
        Ok(notes)
    }

    pub fn load() -> io::Result<Config> {
        match fs::read(Self::file()) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e),
        }
    }

    /// Write atomically so a crash never leaves a truncated whitelist behind.
    pub fn save(&self) -> io::Result<()> {
        use io::Write;
        let tmp = Self::dir().join("config.json.tmp");
        // Never write through a leftover: always a brand-new file of our own.
        let _ = fs::remove_file(&tmp);
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(&serde_json::to_vec_pretty(self).map_err(io::Error::other)?)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, Self::file())
    }

    pub fn find(&self, path: &str, service: Option<&str>) -> Option<usize> {
        self.rules.iter().position(|r| r.same_subject(path, service))
    }

    /// True when `path` is already covered, either exactly or by a rule for
    /// the whole executable.
    pub fn covers(&self, path: &str, service: Option<&str>) -> bool {
        self.rules.iter().any(|r| {
            r.path.eq_ignore_ascii_case(path)
                && (r.service.is_none() || r.same_subject(path, service))
        })
    }

    /// Adds a rule; returns false if an identical subject already existed
    /// (in which case `inbound` is only ever widened).
    pub fn add(&mut self, path: String, service: Option<String>, inbound: bool, source: Source) -> bool {
        if let Some(i) = self.find(&path, service.as_deref()) {
            self.rules[i].inbound |= inbound;
            return false;
        }
        self.rules.push(Rule { path, service, inbound, source, added: now() });
        true
    }
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
