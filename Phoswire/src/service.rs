//! The firewall core, and the Windows service that hosts it.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceDependency, ServiceErrorControl,
    ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
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

pub fn log(msg: &str) {
    eprintln!("{msg}");
    let path = Config::dir().join("phoswire.log");
    let _ = std::fs::create_dir_all(Config::dir());
    if std::fs::metadata(&path).map(|m| m.len() > 1_000_000).unwrap_or(false) {
        let _ = std::fs::rename(&path, Config::dir().join("phoswire.log.old"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{} {msg}", config::now());
    }
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
}

impl Core {
    pub fn start() -> Result<(Core, Receiver<NetEvent>), String> {
        let cfg = match Config::load() {
            Ok(cfg) => cfg,
            Err(e) => {
                // Fail closed: an unreadable whitelist means nothing is trusted.
                log(&format!("config unreadable ({e}); starting with an empty whitelist"));
                let _ = std::fs::rename(Config::file(), Config::dir().join("config.json.bad"));
                Config::default()
            }
        };
        let mut engine = Engine::open()?;
        let (tx, rx) = mpsc::channel();
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
        Ok(())
    }

    /// Switches to `new`, rolling back if WFP rejects it.
    fn commit(&mut self, new: Config) -> Result<(), String> {
        let old = std::mem::replace(&mut self.cfg, new);
        if let Err(e) = self.reapply() {
            self.cfg = old;
            let _ = self.reapply();
            return Err(e);
        }
        self.cfg.save().map_err(|e| format!("applied, but saving the config failed: {e}"))
    }

    pub fn shutdown(&mut self) {
        let _ = self.engine.apply(&[]);
        let _ = self.engine.set_allow_events(false);
    }

    pub fn handle(&mut self, req: Request) -> Reply {
        match self.handle_inner(req) {
            Ok(reply) => reply,
            Err(message) => Reply::Error { message },
        }
    }

    fn handle_inner(&mut self, req: Request) -> Result<Reply, String> {
        let done = |message: String| Ok(Reply::Done { message });
        match req {
            Request::Status => Ok(Reply::Status(Status {
                version: env!("CARGO_PKG_VERSION").into(),
                mode: self.cfg.mode,
                rules: self.cfg.rules.len(),
                filters: self.engine.filter_count(),
                warnings: self.warnings.clone(),
                unresolved: self.unresolved.clone(),
                counters: self.counters.clone(),
            })),
            Request::SetMode { mode } => {
                let mut new = self.cfg.clone();
                new.mode = mode;
                self.commit(new)?;
                if mode == Mode::Learning {
                    self.unresolved.clear();
                    self.polled.clear();
                }
                log(&format!("mode set to {mode}"));
                done(format!("mode: {mode}"))
            }
            Request::Allow { path, service, inbound } => {
                // Validate up front so a typo is an error, not a silent no-op.
                wfp::app_id(&path)?;
                if let Some(s) = &service {
                    win::service_sd(s)?;
                }
                let mut new = self.cfg.clone();
                let added = new.add(path.clone(), service.clone(), inbound, Source::Manual);
                self.commit(new)?;
                self.blocked.retain(|_, b| !b.path.eq_ignore_ascii_case(&path));
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
        let services = win::pid_for_port(ev.protocol, ev.v6, ev.local_port)
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
            if self.cfg.mode == Mode::Learning && !layer.is_inbound() {
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
                if self.unresolved.len() < MAX_UNRESOLVED && !self.unresolved.contains(&note) {
                    self.unresolved.push(note);
                }
                return;
            }
        }
        self.counters.learned_from_events += self.learn(path, services, "net event");
    }

    /// Learning's second source: whitelist every process that currently owns
    /// a network socket. Called periodically; does nothing outside learning.
    pub fn poll_sockets(&mut self) {
        if self.cfg.mode != Mode::Learning {
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

/// Runs the firewall until `stop` fires (or forever if its sender is kept alive).
pub fn run(stop: Receiver<()>) -> Result<(), String> {
    let (core, events) = Core::start()?;
    let core = Arc::new(Mutex::new(core));

    let c = core.clone();
    std::thread::spawn(move || {
        for ev in events {
            c.lock().unwrap().on_event(ev);
        }
    });
    let c = core.clone();
    std::thread::spawn(move || {
        if let Err(e) = ipc::serve(|req| c.lock().unwrap().handle(req)) {
            log(&format!("control pipe failed: {e}"));
        }
    });

    let c = core.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(SOCKET_POLL);
        c.lock().unwrap().poll_sockets();
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

    let status = |state, accept, exit| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    handle
        .set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
        ))
        .map_err(|e| e.to_string())?;

    let result = run(stop_rx);
    let exit = if result.is_ok() { 0 } else { 1 };
    let _ = handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), exit));
    result
}

fn installed_exe() -> PathBuf {
    let base = std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into());
    PathBuf::from(base).join("Phoswire").join("phoswire.exe")
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

/// Copies the binary into Program Files (so the service never runs from a
/// user-writable folder), registers the service and starts it.
pub fn install() -> Result<String, String> {
    let scm = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP;
    let existing = scm.open_service(SERVICE_NAME, access).ok();
    if let Some(service) = &existing {
        let _ = service.stop();
        wait_stopped(service)?;
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
    service.start::<&str>(&[]).map_err(|e| format!("installed, but starting failed: {}", describe(&e)))?;
    Ok(format!("installed and started ({})", target.display()))
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
        .open_service(SERVICE_NAME, ServiceAccess::START)
        .map_err(|e| format!("cannot open the service: {}", describe(&e)))?;
    service.start::<&str>(&[]).map_err(|e| describe(&e))?;
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
