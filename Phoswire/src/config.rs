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
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl Default for Config {
    fn default() -> Self {
        Config { mode: Mode::Normal, rules: Vec::new() }
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
        fs::create_dir_all(Self::dir())?;
        let tmp = Self::dir().join("config.json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(self).map_err(io::Error::other)?)?;
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
