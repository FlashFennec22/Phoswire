//! The firewall core, and the Windows service that hosts it.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceDependency, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::config::{self, Config, Mode, Source};
use crate::ipc::{self, Blocked, Counters, Reply, Request, Status};
use crate::wfp::{self, Engine, NetEvent};
use crate::win;

pub const SERVICE_NAME: &str = "Phoswire";
const MAX_BLOCKED: usize = 500;
const MAX_UNRESOLVED: usize = 50;
const PORT_CACHE_TTL: Duration = Duration::from_secs(10);
const SOCKET_POLL: Duration = Duration::from_millis(250);
/// Net events waiting to be processed; beyond this they are dropped.
const EVENT_QUEUE: usize = 4096;
/// Learning left on this long without an end time earns a warning in `status`.
const LEARNING_NAG_SECS: u64 = 24 * 3600;
/// How long the service may take to get its filters in place.
const START_TIMEOUT: Duration = Duration::from_secs(30);
/// How often a failed attempt to end the learning period is repeated.
const EXPIRE_RETRY: Duration = Duration::from_secs(30);
/// How often the installed filters are checked against the engine.
const FILTER_CHECK: Duration = Duration::from_secs(30);

/// Set once the data directory has been verified; until then nothing is
/// written there, because it may be under an unprivileged user's control.
static LOG_TO_FILE: AtomicBool = AtomicBool::new(false);

pub fn log(msg: &str) {
    eprintln!("{msg}");
    if !LOG_TO_FILE.load(Ordering::Relaxed) {
        return;
    }
    let path = Config::dir().join("phoswire.log");
    if std::fs::metadata(&path).map(|m| m.len() > 1_000_000).unwrap_or(false) {
        let _ = std::fs::rename(&path, Config::dir().join("phoswire.log.old"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{} {msg}", config::now());
    }
}

fn allow_events_marker() -> PathBuf {
    Config::dir().join("allow-events.ours")
}

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------

pub struct Core {
    cfg: Config,
    engine: Engine,
    warnings: Vec<String>,
    unresolved: Vec<String>,
    blocked: HashMap<String, Blocked>,
    /// (protocol, v6, local port) -> services of the owning process.
    port_cache: HashMap<(u8, bool, u16), (Instant, Vec<String>)>,
    /// Processes the socket poller has already dealt with this learning session.
    polled: HashSet<u32>,
    polled_reset: Instant,
    counters: Counters,
    /// Why the data directory cannot be trusted. While set, nothing is read
    /// from or written to it and the configuration lives in memory only.
    storage_problem: Option<String>,
    /// A change was applied but deliberately not saved (see `storage_problem`).
    unsaved: bool,
    /// Why the last attempt to end the learning period failed, and when to
    /// try again.
    expire_error: Option<String>,
    expire_retry: Option<Instant>,
    filters_checked: Instant,
    /// The last attempt to reinstall missing filters failed (logged once).
    repair_failed: bool,
}

impl Core {
    pub fn start() -> Result<(Core, Receiver<NetEvent>), String> {
        let mut storage_problem = None;
        let mut cfg = match Config::secure_dir() {
            Ok(notes) => {
                LOG_TO_FILE.store(true, Ordering::Relaxed);
                notes.iter().for_each(|n| log(n));
                match Config::load() {
                    Ok(cfg) => cfg,
                    Err(e) => {
                        // Fail closed: an unreadable whitelist means nothing is trusted.
                        log(&format!("config unreadable ({e}); starting with an empty whitelist"));
                        let _ = std::fs::rename(Config::file(), Config::dir().join("config.json.bad"));
                        Config::default()
                    }
                }
            }
            Err(e) => {
                // Fail closed here too: a data directory someone else controls
                // is not read from and not written to (`commit` checks this).
                log(&format!("{e}; starting with an empty whitelist that will not be saved"));
                storage_problem = Some(e);
                Config::default()
            }
        };
        if cfg.mode == Mode::Learning && cfg.learning_until.is_some_and(|t| config::now() >= t) {
            // The period ran out while the service was down. Switch before any
            // filter is installed, so outbound is not reopened even briefly.
            cfg.mode = Mode::Normal;
            cfg.learning_since = None;
            cfg.learning_until = None;
            log("the learning period ended while the service was not running; mode set to normal");
            if let Err(e) = cfg.save() {
                log(&format!("saving the config failed: {e}"));
            }
        }
        if cfg.mode == Mode::Learning && cfg.learning_since.is_none() {
            cfg.learning_since = Some(config::now());
        }
        let mut engine = Engine::open()?;
        if storage_problem.is_none() && allow_events_marker().exists() {
            // A previous run turned on the reporting of allowed connections
            // and died before turning it off; `reapply` below now will.
            engine.adopt_allow_events();
        }
        let (tx, rx) = mpsc::sync_channel(EVENT_QUEUE);
        if let Err(e) = engine.subscribe(tx) {
            log(&format!("{e}; learning mode and the blocked list will not work"));
        }
        let mut core = Core {
            cfg,
            engine,
            warnings: Vec::new(),
            unresolved: Vec::new(),
            blocked: HashMap::new(),
            port_cache: HashMap::new(),
            polled: HashSet::new(),
            polled_reset: Instant::now(),
            counters: Counters::default(),
            storage_problem,
            unsaved: false,
            expire_error: None,
            expire_retry: None,
            filters_checked: Instant::now(),
            repair_failed: false,
        };
        core.reapply()?;
        log(&format!(
            "started: mode {}, {} rules, {} filters",
            core.cfg.mode,
            core.cfg.rules.len(),
            core.engine.filter_count()
        ));
        Ok((core, rx))
    }

    /// Pushes the current configuration into WFP.
    fn reapply(&mut self) -> Result<(), String> {
        let (specs, warnings) = wfp::build_policy(&self.cfg);
        self.engine.apply(&specs)?;
        self.warnings = warnings;
        if let Err(e) = self.engine.set_allow_events(self.cfg.mode == Mode::Learning) {
            self.warnings.push(e);
        }
        self.record_allow_events();
        Ok(())
    }

    /// Keeps a marker file for as long as the machine-wide "report allowed
    /// connections" flag is on because of us. The flag outlives the process,
    /// so without the marker a service that crashed while learning would
    /// come back, find the flag on, take it for someone else's and leave it.
    fn record_allow_events(&self) {
        if self.storage_problem.is_some() {
            return;
        }
        let marker = allow_events_marker();
        match (self.engine.allow_events_ours(), marker.exists()) {
            (true, false) => drop(std::fs::write(&marker, b"")),
            (false, true) => drop(std::fs::remove_file(&marker)),
            _ => {}
        }
    }

    /// Switches to `new`, rolling back if WFP rejects it.
    fn commit(&mut self, new: Config) -> Result<(), String> {
        let old = std::mem::replace(&mut self.cfg, new);
        if let Err(e) = self.reapply() {
            self.cfg = old;
            let _ = self.reapply();
            return Err(e);
        }
        if self.storage_problem.is_some() {
            // The data directory is under someone else's control: writing
            // there would let them steer where this process creates files.
            self.unsaved = true;
            return Ok(());
        }
        self.cfg.save().map_err(|e| format!("applied, but saving the config failed: {e}"))
    }

    pub fn shutdown(&mut self) {
        let _ = self.engine.apply(&[]);
        let _ = self.engine.set_allow_events(false);
        self.record_allow_events();
    }

    pub fn handle(&mut self, req: Request) -> Reply {
        self.unsaved = false;
        match (self.handle_inner(req), &self.storage_problem) {
            // Tell the caller when what they just changed will not survive a restart.
            (Ok(Reply::Done { message }), Some(why)) if self.unsaved => Reply::Done {
                message: format!("{message}\nnot saved, and lost when the service stops: {why}"),
            },
            (Ok(reply), _) => reply,
            (Err(message), _) => Reply::Error { message },
        }
    }

    /// True once a timed learning period has run out but the mode has not
    /// (yet) been switched back.
    fn learning_overdue(&self) -> bool {
        self.cfg.mode == Mode::Learning && self.cfg.learning_until.is_some_and(|t| config::now() >= t)
    }

    fn handle_inner(&mut self, req: Request) -> Result<Reply, String> {
        let done = |message: String| Ok(Reply::Done { message });
        match req {
            Request::Status => {
                let mut warnings = self.warnings.clone();
                if let Some(why) = &self.storage_problem {
                    warnings.push(format!(
                        "changes are not saved and will be lost when the service stops: {why}"
                    ));
                }
                // Ask the engine rather than trusting our own bookkeeping:
                // another WFP tool may have removed filters behind our back.
                let installed = self.engine.filter_count();
                let missing = self.engine.missing_filters();
                if missing > 0 {
                    warnings.push(format!(
                        "{missing} of {installed} filters are no longer in the Windows filter engine, so traffic is \
                         not being filtered as configured; reinstalling them is retried every {}s",
                        FILTER_CHECK.as_secs()
                    ));
                }
                if let (true, Some(e)) = (self.learning_overdue(), &self.expire_error) {
                    warnings.push(format!(
                        "the learning period is over but switching to normal failed, so outbound traffic is \
                         still open: {e}"
                    ));
                }
                let learning = self.cfg.mode == Mode::Learning;
                if learning && self.cfg.learning_until.is_none() {
                    let on_for = config::now().saturating_sub(self.cfg.learning_since.unwrap_or(u64::MAX));
                    if on_for >= LEARNING_NAG_SECS {
                        warnings.push(format!(
                            "learning mode has been on for {} day(s); outbound traffic is unfiltered until you run `phoswire mode normal`",
                            on_for / 86_400
                        ));
                    }
                }
                Ok(Reply::Status(Status {
                    version: env!("CARGO_PKG_VERSION").into(),
                    mode: self.cfg.mode,
                    learning_since: self.cfg.learning_since.filter(|_| learning),
                    learning_until: self.cfg.learning_until.filter(|_| learning),
                    rules: self.cfg.rules.len(),
                    filters: installed - missing,
                    warnings,
                    unresolved: self.unresolved.clone(),
                    counters: self.counters.clone(),
                }))
            }
            Request::SetMode { mode, hours } => {
                if hours.is_some() && mode != Mode::Learning {
                    return Err("--hours only applies to learning mode".into());
                }
                if hours == Some(0) {
                    return Err("--hours must be at least 1".into());
                }
                let mut new = self.cfg.clone();
                new.mode = mode;
                let now = config::now();
                new.learning_since = (mode == Mode::Learning).then_some(now);
                new.learning_until = hours.map(|h| now + u64::from(h) * 3600);
                self.commit(new)?;
                self.expire_error = None;
                self.expire_retry = None;
                if mode == Mode::Learning {
                    self.unresolved.clear();
                    self.polled.clear();
                }
                log(&format!("mode set to {mode}"));
                done(match hours {
                    Some(h) => format!("mode: {mode} (reverts to normal in {h}h)"),
                    None => format!("mode: {mode}"),
                })
            }
            Request::Allow { path, service, inbound, outbound_only } => {
                // Validate up front so a typo is an error, not a silent no-op.
                wfp::app_id(&path)?;
                if let Some(s) = &service {
                    win::service_sd(s)?;
                }
                let mut new = self.cfg.clone();
                let added = new.add(path.clone(), service.clone(), inbound, Source::Manual);
                if outbound_only {
                    if let Some(i) = new.find(&path, service.as_deref()) {
                        new.rules[i].inbound = false;
                    }
                }
                self.commit(new)?;
                self.blocked.retain(|_, b| !config::eq_ignore_case(&b.path, &path));
                log(&format!("allowed {path} (service {service:?}, inbound {inbound})"));
                done(if added { format!("allowed: {path}") } else { format!("already allowed: {path}") })
            }
            Request::Remove { path, service } => {
                let index = self
                    .cfg
                    .find(&path, service.as_deref())
                    .ok_or_else(|| format!("no rule for {path}"))?;
                self.remove_at(index)
            }
            Request::RemoveIndex { index } => {
                if index == 0 || index > self.cfg.rules.len() {
                    return Err(format!("no rule #{index}"));
                }
                self.remove_at(index - 1)
            }
            Request::List => Ok(Reply::Rules { rules: self.cfg.rules.clone() }),
            Request::Blocked => {
                let mut entries: Vec<Blocked> = self.blocked.values().cloned().collect();
                entries.sort_by_key(|b| std::cmp::Reverse(b.last));
                Ok(Reply::Blocked { entries })
            }
            Request::ClearBlocked => {
                self.blocked.clear();
                done("blocked list cleared".into())
            }
        }
    }

    fn remove_at(&mut self, index: usize) -> Result<Reply, String> {
        let mut new = self.cfg.clone();
        let rule = new.rules.remove(index);
        self.commit(new)?;
        log(&format!("removed {}", rule.subject()));
        Ok(Reply::Done { message: format!("removed: {}", rule.subject()) })
    }

    /// Services hosted by the process that owns a local port, cached briefly
    /// because one connection burst produces many events.
    fn services_for(&mut self, ev: &NetEvent) -> Vec<String> {
        let key = (ev.protocol, ev.v6, ev.local_port);
        let now = Instant::now();
        if let Some((at, services)) = self.port_cache.get(&key) {
            if now.duration_since(*at) < PORT_CACHE_TTL {
                return services.clone();
            }
        }
        if self.port_cache.len() > 4096 {
            self.port_cache.retain(|_, (at, _)| now.duration_since(*at) < PORT_CACHE_TTL);
        }
        // The lookup happens after the fact, so the port may already belong to
        // someone else; an owner that is not a service host is certainly wrong.
        let services = win::pid_for_port(ev.protocol, ev.v6, ev.local_port)
            .filter(|&pid| win::process_path(pid).is_some_and(|p| win::is_svchost(&p)))
            .and_then(|pid| win::services_by_pid().remove(&pid))
            .unwrap_or_default();
        self.port_cache.insert(key, (now, services.clone()));
        services
    }

    pub fn on_event(&mut self, ev: NetEvent) {
        if ev.allowed {
            self.counters.allow_events += 1;
        } else {
            self.counters.drop_events += 1;
        }
        if ev.loopback {
            return;
        }
        let (Some(layer), Some(app)) = (self.engine.layer(ev.layer_id), ev.app.as_deref()) else {
            self.counters.ignored_events += 1;
            return;
        };
        let path = win::nt_to_dos(app);
        if ev.allowed {
            if self.cfg.mode == Mode::Learning && !layer.is_inbound() && !self.learning_overdue() {
                self.learn_event(&ev, path);
            }
        } else if self.engine.is_default_block(ev.filter_id) {
            self.record_block(&ev, path, layer.is_inbound());
        }
    }

    fn learn_event(&mut self, ev: &NetEvent, path: String) {
        if self.cfg.covers(&path, None) {
            return;
        }
        let mut services = Vec::new();
        if win::is_svchost(&path) {
            services = self.services_for(ev);
            if services.is_empty() {
                let note = format!(
                    "svchost.exe -> {}:{} (protocol {})",
                    ev.remote.map(|a| a.to_string()).unwrap_or_else(|| "?".into()),
                    ev.remote_port,
                    ev.protocol
                );
                self.note_unresolved(note);
                return;
            }
        }
        self.counters.learned_from_events += self.learn(path, services, "net event");
    }

    fn note_unresolved(&mut self, note: String) {
        if self.unresolved.len() < MAX_UNRESOLVED && !self.unresolved.contains(&note) {
            self.unresolved.push(note);
        }
    }

    /// Ends a learning period whose time is up. If WFP refuses the switch, the
    /// attempt is repeated every `EXPIRE_RETRY` and reported in `status`;
    /// nothing more is learned in the meantime.
    fn expire_learning(&mut self) {
        let now = Instant::now();
        if self.expire_retry.is_some_and(|at| now < at) {
            return;
        }
        let mut new = self.cfg.clone();
        new.mode = Mode::Normal;
        new.learning_since = None;
        new.learning_until = None;
        let result = self.commit(new);
        // `commit` can fail after the switch itself went through (saving).
        let still_learning = self.cfg.mode == Mode::Learning;
        match result {
            Ok(()) => log("learning period over; mode set to normal"),
            Err(e) => {
                // Say it once, not on every retry.
                if self.expire_error.as_deref() != Some(e.as_str()) {
                    log(&format!("ending the learning period: {e}"));
                }
                self.expire_error = Some(e);
            }
        }
        if !still_learning {
            self.expire_error = None;
        }
        self.expire_retry = still_learning.then(|| now + EXPIRE_RETRY);
    }

    /// Housekeeping, called a few times a second.
    pub fn tick(&mut self) {
        self.check_filters();
        self.poll_sockets();
    }

    /// Reinstalls the filters if something else removed any of them from the
    /// engine; until that works, `status` reports them as missing.
    fn check_filters(&mut self) {
        if self.filters_checked.elapsed() < FILTER_CHECK {
            return;
        }
        self.filters_checked = Instant::now();
        let missing = self.engine.missing_filters();
        if missing == 0 {
            self.repair_failed = false;
            return;
        }
        match self.reapply() {
            Ok(()) => {
                log(&format!("{missing} filter(s) had been removed from the filter engine; reinstalled"));
                self.repair_failed = false;
            }
            Err(e) => {
                if !self.repair_failed {
                    log(&format!("{missing} filter(s) are missing from the filter engine and reinstalling failed: {e}"));
                }
                self.repair_failed = true;
            }
        }
    }

    /// Learning's second source: whitelist every process that currently holds
    /// a connection to another machine. Does nothing outside learning.
    fn poll_sockets(&mut self) {
        if self.cfg.mode != Mode::Learning {
            return;
        }
        if self.learning_overdue() {
            self.expire_learning();
            return;
        }
        // Forget handled processes now and then so a reused pid is not skipped forever.
        if self.polled_reset.elapsed() > Duration::from_secs(60) {
            self.polled.clear();
            self.polled_reset = Instant::now();
        }
        let mut by_pid: Option<HashMap<u32, Vec<String>>> = None;
        for pid in win::network_pids() {
            if !self.polled.insert(pid) {
                continue;
            }
            let Some(path) = win::process_path(pid) else { continue };
            if self.cfg.covers(&path, None) {
                continue;
            }
            let mut services = Vec::new();
            if win::is_svchost(&path) {
                services = by_pid.get_or_insert_with(win::services_by_pid).get(&pid).cloned().unwrap_or_default();
                if services.is_empty() {
                    continue;
                }
            }
            self.counters.learned_from_sockets += self.learn(path, services, "open socket");
        }
    }

    /// Whitelists `path` (or, for a shared service host, each of `services`)
    /// and returns how many rules were added.
    fn learn(&mut self, path: String, services: Vec<String>, how: &str) -> u64 {
        // A rule that cannot be turned into a filter (a mapped drive only the
        // user's session can see, say) would sit in the whitelist doing
        // nothing but raising a warning on every reload.
        if let Err(e) = wfp::app_id(&path) {
            self.note_unresolved(format!("{path} ({e})"));
            return 0;
        }
        let mut new = self.cfg.clone();
        let mut added = Vec::new();
        if services.is_empty() {
            // svchost.exe hosts most of Windows; trusting the whole binary
            // would defeat zero trust, so it is only ever learned per service.
            if !win::is_svchost(&path) && new.add(path.clone(), None, false, Source::Learned) {
                added.push(path);
            }
        } else {
            for service in services {
                if new.add(path.clone(), Some(service.clone()), false, Source::Learned) {
                    added.push(format!("{path} [service: {service}]"));
                }
            }
        }
        if added.is_empty() {
            return 0;
        }
        match self.commit(new) {
            Ok(()) => {
                added.iter().for_each(|a| log(&format!("learned {a} ({how})")));
                added.len() as u64
            }
            Err(e) => {
                log(&format!("learning {added:?} failed: {e}"));
                0
            }
        }
    }

    fn record_block(&mut self, ev: &NetEvent, path: String, inbound: bool) {
        let mut subject = path;
        if win::is_svchost(&subject) {
            let services = self.services_for(ev);
            if !services.is_empty() {
                subject = format!("{subject} [service: {}]", services.join(", "));
            }
        }
        let remote = match ev.remote {
            Some(addr) => format!("{addr}:{}", ev.remote_port),
            None => "?".into(),
        };
        let key = format!("{}|{inbound}", subject.to_ascii_lowercase());
        let now = config::now();
        if let Some(entry) = self.blocked.get_mut(&key) {
            entry.count += 1;
            entry.last = now;
            entry.remote = remote;
            entry.protocol = ev.protocol;
            return;
        }
        if self.blocked.len() >= MAX_BLOCKED {
            if let Some(oldest) = self.blocked.iter().min_by_key(|(_, b)| b.last).map(|(k, _)| k.clone()) {
                self.blocked.remove(&oldest);
            }
        }
        self.blocked.insert(
            key,
            Blocked { path: subject, inbound, protocol: ev.protocol, remote, count: 1, last: now },
        );
    }
}

/// Runs the firewall until `stop` fires (or forever if its sender is kept
/// alive). `ready` is called once the filters are in place.
pub fn run(stop: Receiver<()>, ready: impl FnOnce()) -> Result<(), String> {
    let (core, events) = Core::start()?;
    ready();
    let core = Arc::new(Mutex::new(core));

    let c = core.clone();
    std::thread::spawn(move || {
        for ev in events {
            c.lock().unwrap().on_event(ev);
        }
    });
    let c = core.clone();
    std::thread::spawn(move || {
        // `serve` only returns when the pipe cannot be created, typically
        // because another program holds the name. Keep trying: the name is
        // ours again the moment that program exits.
        let mut reported = false;
        loop {
            if let Err(e) = ipc::serve(|req| c.lock().unwrap().handle(req)) {
                if !reported {
                    log(&format!("control pipe unavailable ({e}); the firewall keeps running, retrying"));
                    reported = true;
                }
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    });

    let c = core.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(SOCKET_POLL);
        c.lock().unwrap().tick();
    });

    let _ = stop.recv();
    core.lock().unwrap().shutdown();
    log("stopped");
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows service plumbing
// ---------------------------------------------------------------------------

define_windows_service!(ffi_service_main, service_main);

/// Entry point when launched by the service control manager.
pub fn dispatch() -> Result<(), String> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| e.to_string())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = service_body() {
        log(&format!("service failed: {e}"));
    }
}

fn service_body() -> Result<(), String> {
    let (stop_tx, stop_rx) = mpsc::channel();
    let handle = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(|e| e.to_string())?;

    let status = |state, exit| {
        let (starting, running) = (state == ServiceState::StartPending, state == ServiceState::Running);
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(exit),
            checkpoint: u32::from(starting),
            wait_hint: if starting { START_TIMEOUT } else { Duration::default() },
            process_id: None,
        }
    };
    // "Running" is a promise that the machine is being filtered, so it is
    // only reported once the filters are in place; `install` and `start`
    // wait for it, and a service that fails before that is seen to fail.
    handle.set_service_status(status(ServiceState::StartPending, 0)).map_err(|e| e.to_string())?;
    let result = run(stop_rx, || {
        let _ = handle.set_service_status(status(ServiceState::Running, 0));
    });
    let exit = if result.is_ok() { 0 } else { 1 };
    let _ = handle.set_service_status(status(ServiceState::Stopped, exit));
    result
}

fn installed_exe() -> PathBuf {
    PathBuf::from(win::program_files()).join("Phoswire").join("phoswire.exe")
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager, String> {
    ServiceManager::local_computer(None::<&str>, access).map_err(|e| {
        format!("cannot open the service manager ({}); use an elevated prompt", describe(&e))
    })
}

fn describe(e: &windows_service::Error) -> String {
    match e {
        windows_service::Error::Winapi(io) => io.to_string(),
        other => other.to_string(),
    }
}

fn wait_stopped(service: &windows_service::service::Service) -> Result<(), String> {
    for _ in 0..100 {
        match service.query_status() {
            Ok(s) if s.current_state == ServiceState::Stopped => return Ok(()),
            Ok(_) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(describe(&e)),
        }
    }
    Err("the service did not stop in time".into())
}

/// Waits until the service reports that its filters are in place.
fn wait_running(service: &windows_service::service::Service) -> Result<(), String> {
    let log = Config::dir().join("phoswire.log");
    let deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < deadline {
        match service.query_status() {
            Ok(s) if s.current_state == ServiceState::Running => return Ok(()),
            Ok(s) if s.current_state == ServiceState::Stopped => {
                return Err(format!(
                    "the service stopped while starting, so this computer is NOT being filtered; see {}",
                    log.display()
                ))
            }
            Ok(_) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(describe(&e)),
        }
    }
    Err(format!(
        "the service has not finished starting, so this computer may not be filtered yet; see {}",
        log.display()
    ))
}

/// Copies the binary into Program Files (so the service never runs from a
/// user-writable folder), registers the service and starts it.
///
/// With `learning`, a machine that has no configuration yet starts out in
/// learning mode, reverting to normal after `hours` if given; an existing
/// configuration is never touched.
pub fn install(learning: bool, hours: Option<u32>) -> Result<String, String> {
    let scm = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::CHANGE_CONFIG;
    let existing = scm.open_service(SERVICE_NAME, access).ok();
    if let Some(service) = &existing {
        let _ = service.stop();
        wait_stopped(service)?;
    }

    // Lock the data directory down before anything is written to it.
    Config::secure_dir()?.iter().for_each(|note| eprintln!("warning: {note}"));
    if learning && !Config::file().exists() {
        let now = config::now();
        let cfg = Config {
            mode: Mode::Learning,
            learning_since: Some(now),
            learning_until: hours.map(|h| now + u64::from(h) * 3600),
            ..Config::default()
        };
        cfg.save().map_err(|e| format!("writing the initial configuration: {e}"))?;
    }

    let target = installed_exe();
    let current = std::env::current_exe().map_err(|e| e.to_string())?;
    if !same_file(&current, &target) {
        std::fs::create_dir_all(target.parent().unwrap()).map_err(|e| format!("creating {}: {e}", target.display()))?;
        std::fs::copy(&current, &target).map_err(|e| format!("copying to {}: {e}", target.display()))?;
    }

    let service = match existing {
        Some(service) => service,
        None => {
            let info = ServiceInfo {
                name: SERVICE_NAME.into(),
                display_name: "Phoswire Firewall".into(),
                service_type: ServiceType::OWN_PROCESS,
                start_type: ServiceStartType::AutoStart,
                error_control: ServiceErrorControl::Normal,
                executable_path: target.clone(),
                launch_arguments: vec!["service".into()],
                dependencies: vec![ServiceDependency::Service("BFE".into())],
                account_name: None, // LocalSystem
                account_password: None,
            };
            let service = scm.create_service(&info, access).map_err(|e| describe(&e))?;
            let _ = service.set_description("Zero-trust application firewall layered on the Windows Filtering Platform.");
            service
        }
    };
    // The filters live only as long as the process does, so a service that
    // dies must come straight back rather than leave the machine unfiltered.
    let restart = |secs| ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(secs) };
    let recovery = service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart(1), restart(5), restart(30)]),
        })
        .and_then(|()| service.set_failure_actions_on_non_crash_failures(true));
    service.start::<&str>(&[]).map_err(|e| format!("installed, but starting failed: {}", describe(&e)))?;
    wait_running(&service).map_err(|e| format!("installed, but {e}"))?;
    Ok(match recovery {
        Ok(()) => format!("installed and started ({})", target.display()),
        Err(e) => format!(
            "installed and started ({}), but automatic restart after a crash could not be configured: {}",
            target.display(),
            describe(&e)
        ),
    })
}

fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

pub fn uninstall() -> Result<String, String> {
    let scm = manager(ServiceManagerAccess::CONNECT)?;
    let service = scm
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)
        .map_err(|e| format!("cannot open the service: {}", describe(&e)))?;
    let _ = service.stop();
    wait_stopped(&service)?;
    service.delete().map_err(|e| describe(&e))?;
    let target = installed_exe();
    let current = std::env::current_exe().unwrap_or_default();
    if !same_file(&current, &target) {
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_dir(target.parent().unwrap());
    }
    Ok(format!("uninstalled; the whitelist is kept in {}", Config::dir().display()))
}

pub fn start() -> Result<String, String> {
    let scm = manager(ServiceManagerAccess::CONNECT)?;
    let service = scm
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::START)
        .map_err(|e| format!("cannot open the service: {}", describe(&e)))?;
    service.start::<&str>(&[]).map_err(|e| describe(&e))?;
    wait_running(&service)?;
    Ok("started".into())
}

pub fn stop() -> Result<String, String> {
    let scm = manager(ServiceManagerAccess::CONNECT)?;
    let service = scm
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)
        .map_err(|e| format!("cannot open the service: {}", describe(&e)))?;
    service.stop().map_err(|e| describe(&e))?;
    wait_stopped(&service)?;
    Ok("stopped; Phoswire filters are removed and only Windows Firewall applies".into())
}
