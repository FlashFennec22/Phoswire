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
    /// Never turn this rule into a version pattern (`allow --exact`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exact: bool,
}

/// Compares names the way Windows does: ignoring case for every letter, not
/// only ASCII ones. WFP reports paths lower-cased, so without this a program
/// under `C:\Users\Émile` would get one rule from its events and a second
/// from its real path, and removing either would leave the other in force.
pub fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.chars().flat_map(char::to_lowercase).eq(b.chars().flat_map(char::to_lowercase))
}

/// True for a rule path with a version wildcard (see [`version_pattern`]).
pub fn is_pattern(path: &str) -> bool {
    path.contains('*')
}

/// True when `s` is a version number of at least three parts, optionally
/// followed by a build suffix: `157.0.4341.60`, `4.18.26080.4-0`.
fn is_version(s: &str) -> bool {
    let (main, suffix) = match s.split_once('-') {
        Some((m, b)) => (m, Some(b)),
        None => (s, None),
    };
    let digits = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    main.split('.').count() >= 3 && main.split('.').all(digits) && suffix.is_none_or(digits)
}

/// Byte range of the last version number in one path segment.
fn version_span(seg: &str) -> Option<(usize, usize)> {
    let b = seg.as_bytes();
    let mut found = None;
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let mut end = i;
        while end < b.len() && (b[end].is_ascii_digit() || b[end] == b'.') {
            end += 1;
        }
        let mut stop = end;
        while stop > i && b[stop - 1] == b'.' {
            stop -= 1;
        }
        // A build suffix such as Defender's `-0`.
        let mut with_suffix = stop;
        if stop == end && end + 1 < b.len() && b[end] == b'-' && b[end + 1].is_ascii_digit() {
            with_suffix = end + 1;
            while with_suffix < b.len() && b[with_suffix].is_ascii_digit() {
                with_suffix += 1;
            }
        }
        if is_version(&seg[i..with_suffix]) {
            found = Some((i, with_suffix));
        } else if is_version(&seg[i..stop]) {
            found = Some((i, stop));
        }
        i = end.max(with_suffix);
    }
    found
}

/// The rule path that keeps trusting a program across updates that install
/// each version into a folder of its own: the deepest folder in `path` whose
/// name contains a version number has that number replaced by `*`.
///
/// `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\MsMpEng.exe`
/// becomes `C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe`.
///
/// Only drive-letter paths qualify, and the file name itself is never
/// generalised. Whether the pattern is safe to trust depends on who may
/// create folders where the wildcard is, which is for the caller to check.
pub fn version_pattern(path: &str) -> Option<String> {
    let b = path.as_bytes();
    if is_pattern(path) || b.len() < 3 || !b[0].is_ascii_alphabetic() || b[1] != b':' || b[2] != b'\\' {
        return None;
    }
    let mut segs: Vec<String> = path.split('\\').map(String::from).collect();
    let last_dir = segs.len().checked_sub(2)?;
    for i in (1..=last_dir).rev() {
        if let Some((start, end)) = version_span(&segs[i]) {
            segs[i] = format!("{}*{}", &segs[i][..start], &segs[i][end..]);
            return Some(segs.join("\\"));
        }
    }
    None
}

/// Whether one path segment matches a pattern segment, where `*` stands for
/// a version number. Both are expected in lower case.
fn segment_matches(pattern: &str, seg: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == seg,
        Some((pre, suf)) => {
            seg.len() >= pre.len() + suf.len()
                && seg.starts_with(pre)
                && seg.ends_with(suf)
                && is_version(&seg[pre.len()..seg.len() - suf.len()])
        }
    }
}

/// True when `path` is the rule path itself or, for a version pattern, any
/// version of it.
pub fn path_matches(rule_path: &str, path: &str) -> bool {
    if !is_pattern(rule_path) {
        return eq_ignore_case(rule_path, path);
    }
    let (pattern, path) = (rule_path.to_lowercase(), path.to_lowercase());
    let (mut ps, mut ss) = (pattern.split('\\'), path.split('\\'));
    loop {
        match (ps.next(), ss.next()) {
            (None, None) => return true,
            (Some(p), Some(s)) if segment_matches(p, s) => {}
            _ => return false,
        }
    }
}

/// A version pattern split at its wildcard into the folder that holds the
/// versions, the pattern for their names, and the rest of the path.
pub fn split_pattern(pattern: &str) -> Option<(&str, &str, &str)> {
    let star = pattern.find('*')?;
    let dir_end = pattern[..star].rfind('\\')?;
    let seg_end = star + pattern[star..].find('\\')?;
    Some((&pattern[..dir_end], &pattern[dir_end + 1..seg_end], &pattern[seg_end + 1..]))
}

/// Most versions of one program a pattern is expanded to; anything beyond
/// this is left out rather than turned into ever more filters.
pub const MAX_VERSIONS: usize = 16;

/// The files on disk that a version pattern matches (highest name first),
/// and whether more than [`MAX_VERSIONS`] were found.
pub fn expand_pattern(pattern: &str) -> io::Result<(Vec<String>, bool)> {
    let (dir, name, rest) = split_pattern(pattern)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("not a version pattern: {pattern}")))?;
    let name = name.to_lowercase();
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)?.flatten() {
        // `file_type` does not follow links, so a junction is never a version.
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Some(folder) = entry.file_name().to_str().map(String::from) else { continue };
        if !segment_matches(&name, &folder.to_lowercase()) {
            continue;
        }
        let path = format!("{dir}\\{folder}\\{rest}");
        if fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
            found.push(path);
        }
    }
    found.sort_by(|a, b| b.cmp(a));
    let more = found.len() > MAX_VERSIONS;
    found.truncate(MAX_VERSIONS);
    Ok((found, more))
}

impl Rule {
    pub fn same_subject(&self, path: &str, service: Option<&str>) -> bool {
        eq_ignore_case(&self.path, path)
            && match (self.service.as_deref(), service) {
                (None, None) => true,
                (Some(a), Some(b)) => eq_ignore_case(a, b),
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
        PathBuf::from(crate::win::program_data()).join("Phoswire")
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

    /// Like `find`, but a concrete path also finds the version pattern that
    /// covers it.
    pub fn find_matching(&self, path: &str, service: Option<&str>) -> Option<usize> {
        self.find(path, service).or_else(|| {
            self.rules.iter().position(|r| {
                is_pattern(&r.path) && path_matches(&r.path, path) && r.same_subject(&r.path, service)
            })
        })
    }

    /// True when `path` is already covered: exactly, by a version pattern,
    /// or by a rule for the whole executable.
    pub fn covers(&self, path: &str, service: Option<&str>) -> bool {
        self.rules.iter().any(|r| {
            path_matches(&r.path, path) && (r.service.is_none() || r.same_subject(&r.path, service))
        })
    }

    /// Turns every rule `versioned` has a pattern for into that pattern, and
    /// merges rules that end up the same. Returns `(old, new)` for each rule
    /// changed.
    pub fn generalize(&mut self, versioned: impl Fn(&str) -> Option<String>) -> Vec<(String, String)> {
        let mut changed = Vec::new();
        for rule in self.rules.iter_mut().filter(|r| !r.exact && !is_pattern(&r.path)) {
            if let Some(pattern) = versioned(&rule.path) {
                let old = rule.subject();
                rule.path = pattern;
                changed.push((old, rule.subject()));
            }
        }
        if !changed.is_empty() {
            let mut merged: Vec<Rule> = Vec::with_capacity(self.rules.len());
            for rule in std::mem::take(&mut self.rules) {
                let same = merged
                    .iter_mut()
                    .find(|m| m.exact == rule.exact && m.same_subject(&rule.path, rule.service.as_deref()));
                match same {
                    Some(m) => {
                        m.inbound |= rule.inbound;
                        if rule.source == Source::Manual {
                            m.source = Source::Manual;
                        }
                        m.added = m.added.min(rule.added);
                    }
                    None => merged.push(rule),
                }
            }
            self.rules = merged;
        }
        changed
    }

    /// Adds a rule; returns false if an identical subject already existed
    /// (in which case `inbound` is only ever widened).
    pub fn add(&mut self, path: String, service: Option<String>, inbound: bool, source: Source) -> bool {
        if let Some(i) = self.find(&path, service.as_deref()) {
            self.rules[i].inbound |= inbound;
            return false;
        }
        self.rules.push(Rule { path, service, inbound, source, added: now(), exact: false });
        true
    }
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_match_whatever_the_case_of_any_letter() {
        let rule = Rule {
            path: r"C:\Users\Émile\App\Über.exe".into(),
            service: None,
            inbound: false,
            source: Source::Learned,
            added: 0,
            exact: false,
        };
        // What WFP reports for the same file.
        assert!(rule.same_subject(r"c:\users\émile\app\über.exe", None));
        assert!(!rule.same_subject(r"c:\users\emile\app\uber.exe", None));
        let cfg = Config { rules: vec![rule], ..Config::default() };
        assert!(cfg.covers(r"c:\users\émile\app\über.exe", None));
        assert_eq!(cfg.find(r"C:\USERS\ÉMILE\APP\ÜBER.EXE", None), Some(0));
    }

    #[test]
    fn versioned_folders_become_patterns() {
        let cases = [
            (
                r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\MsMpEng.exe",
                Some(r"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe"),
            ),
            (
                r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\157.0.4341.60\msedgewebview2.exe",
                Some(r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\*\msedgewebview2.exe"),
            ),
            (
                r"C:\Program Files\WindowsApps\Microsoft.WindowsStore_22410.1401.5.0_x64__8wekyb3d8bbwe\WinStore.App.exe",
                Some(r"C:\Program Files\WindowsApps\Microsoft.WindowsStore_*_x64__8wekyb3d8bbwe\WinStore.App.exe"),
            ),
            (r"C:\Users\a\AppData\Local\Discord\app-1.0.9187\Discord.exe", Some(r"C:\Users\a\AppData\Local\Discord\app-*\Discord.exe")),
            // Deepest versioned folder only.
            (r"C:\Tools\1.0.0\bin\2.0.0\x.exe", Some(r"C:\Tools\1.0.0\bin\*\x.exe")),
            // Not versions: too few parts, the file name, no drive letter.
            (r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE", None),
            (r"C:\Program Files\Python 3.12\python.exe", None),
            (r"C:\Tools\tool-1.2.3.exe", None),
            (r"\\10.0.0.1\share\app.exe", None),
            (r"\device\harddiskvolume3\1.2.3\app.exe", None),
            ("System", None),
            (r"C:\Windows\System32\svchost.exe", None),
        ];
        for (path, want) in cases {
            assert_eq!(version_pattern(path).as_deref(), want, "{path}");
        }
    }

    #[test]
    fn patterns_match_only_versions_of_the_same_program() {
        let p = r"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe";
        assert!(path_matches(p, r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.3-0\MsMpEng.exe"));
        assert!(path_matches(p, r"c:\programdata\microsoft\windows defender\platform\4.18.26090.1-0\msmpeng.exe"));
        assert!(path_matches(p, r"C:\ProgramData\Microsoft\Windows Defender\Platform\5.0.1\MsMpEng.exe"));
        for other in [
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\evil\MsMpEng.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1-0\x\MsMpEng.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1-0\MpCmdRun.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
            p,
        ] {
            assert!(!path_matches(p, other), "{other}");
        }
        let store = r"C:\Program Files\WindowsApps\Microsoft.WindowsStore_*_x64__8wekyb3d8bbwe\WinStore.App.exe";
        assert!(path_matches(store, r"C:\Program Files\WindowsApps\Microsoft.WindowsStore_22411.1.0.0_x64__8wekyb3d8bbwe\WinStore.App.exe"));
        assert!(!path_matches(store, r"C:\Program Files\WindowsApps\Microsoft.WindowsStore_22411.1.0.0_arm64__8wekyb3d8bbwe\WinStore.App.exe"));
        assert!(!path_matches(store, r"C:\Program Files\WindowsApps\Microsoft.WindowsStore_x_x64__8wekyb3d8bbwe\WinStore.App.exe"));
    }

    fn rule(path: &str, service: Option<&str>, inbound: bool, source: Source, added: u64) -> Rule {
        Rule { path: path.into(), service: service.map(Into::into), inbound, source, added, exact: false }
    }

    #[test]
    fn generalizing_merges_versions_and_respects_exact_rules() {
        let old = r"C:\P\App\1.2.3\app.exe";
        let new = r"C:\P\App\1.2.4\app.exe";
        let mut pinned = rule(r"C:\P\Pinned\1.0.0\pin.exe", None, false, Source::Manual, 1);
        pinned.exact = true;
        let mut cfg = Config {
            rules: vec![
                rule(old, None, false, Source::Learned, 20),
                rule(r"C:\P\plain.exe", None, false, Source::Learned, 5),
                rule(new, None, true, Source::Manual, 30),
                pinned,
            ],
            ..Config::default()
        };
        let changed = cfg.generalize(|p| version_pattern(p).filter(|p| p.starts_with(r"C:\P\App")));
        assert_eq!(changed.len(), 2);
        assert_eq!(cfg.rules.len(), 3);
        let r = &cfg.rules[0];
        assert_eq!(r.path, r"C:\P\App\*\app.exe");
        assert!(r.inbound && r.source == Source::Manual && r.added == 20);
        assert!(cfg.rules[2].exact && !is_pattern(&cfg.rules[2].path));
        // Later versions are covered and found through the pattern.
        assert!(cfg.covers(r"C:\P\App\2.0.0\APP.EXE", None));
        assert_eq!(cfg.find_matching(r"C:\P\App\2.0.0\app.exe", None), Some(0));
        assert_eq!(cfg.find_matching(r"C:\P\App\2.0.0\app.exe", Some("svc")), None);
        // Patterns and exact rules are left alone the second time round.
        assert!(cfg.generalize(version_pattern).is_empty());
    }

    #[test]
    fn patterns_expand_to_the_versions_on_disk() {
        let root = std::env::temp_dir().join(format!("phoswire-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for (dir, file) in [("1.2.3", true), ("1.2.4", true), ("1.2.5", false), ("evil", true), ("2.0.0.1-0", true)] {
            fs::create_dir_all(root.join(dir)).unwrap();
            if file {
                fs::write(root.join(dir).join("app.exe"), b"").unwrap();
            }
        }
        let pattern = format!(r"{}\*\app.exe", root.display());
        let (found, more) = expand_pattern(&pattern).unwrap();
        let names: Vec<_> = found.iter().map(|p| p.rsplit('\\').nth(1).unwrap().to_string()).collect();
        assert_eq!(names, ["2.0.0.1-0", "1.2.4", "1.2.3"]);
        assert!(!more);
        assert!(found.iter().all(|p| path_matches(&pattern, p)));
        fs::remove_dir_all(&root).unwrap();
        assert!(expand_pattern(r"C:\no\such\phoswire\*\x.exe").is_err());
    }

    #[test]
    fn old_rules_still_parse_and_exact_is_only_saved_when_set() {
        let r: Rule = serde_json::from_str(r#"{"path":"C:\\a.exe","inbound":false,"source":"manual","added":1}"#).unwrap();
        assert!(!r.exact);
        assert!(!serde_json::to_string(&r).unwrap().contains("exact"));
    }
}
