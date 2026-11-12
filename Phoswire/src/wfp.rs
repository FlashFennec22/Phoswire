//! Windows Filtering Platform engine.
//!
//! Phoswire owns one sublayer. Within it a low-weight block-all filter is
//! overridden by higher-weight permits for whitelisted apps. WFP arbitrates
//! across sublayers so that a block from any of them wins, which means
//! traffic must be accepted by both Phoswire and Windows Firewall.
//!
//! The session is dynamic: every object added here disappears when the engine
//! handle closes, so a crashed or stopped service never leaves the machine
//! locked out.

use std::collections::HashSet;
use std::mem::zeroed;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::{null, null_mut};
use std::sync::mpsc::SyncSender;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use crate::config::{Config, Mode, SYSTEM_APP};
use crate::win::{self, wide, IPPROTO_ICMPV6, IPPROTO_UDP};

const SUBLAYER_KEY: GUID = GUID::from_u128(0x7068_6f73_7769_7265_a1f0_3c5d_9e2b_4a61);
const FILTER_NOT_FOUND: u32 = windows_sys::Win32::Foundation::FWP_E_FILTER_NOT_FOUND as u32;

const W_BLOCK: u8 = 0;
const W_LEARN: u8 = 1;
const W_APP: u8 = 8;
const W_ESSENTIAL: u8 = 12;
const W_LOOPBACK: u8 = 15;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Layer {
    ConnectV4,
    ConnectV6,
    AcceptV4,
    AcceptV6,
}

impl Layer {
    pub const ALL: [Layer; 4] = [Layer::ConnectV4, Layer::ConnectV6, Layer::AcceptV4, Layer::AcceptV6];
    const OUTBOUND: [Layer; 2] = [Layer::ConnectV4, Layer::ConnectV6];
    const INBOUND: [Layer; 2] = [Layer::AcceptV4, Layer::AcceptV6];

    fn key(self) -> GUID {
        match self {
            Layer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Layer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            Layer::AcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            Layer::AcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        }
    }

    pub fn is_inbound(self) -> bool {
        matches!(self, Layer::AcceptV4 | Layer::AcceptV6)
    }
}

#[derive(Clone, Debug)]
pub enum Cond {
    Loopback,
    Protocol(u8),
    /// For ICMP this field carries the ICMP type.
    LocalPort(u16),
    RemotePort(u16),
    /// WFP application identifier blob.
    App(Vec<u8>),
    /// Self-relative security descriptor the caller's token must pass.
    UserSd(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct FilterSpec {
    pub name: String,
    pub layer: Layer,
    pub permit: bool,
    pub weight: u8,
    /// Conditions on different fields are ANDed; repeats of a field are ORed.
    pub conds: Vec<Cond>,
}

impl FilterSpec {
    fn permit(name: impl Into<String>, layer: Layer, weight: u8, conds: Vec<Cond>) -> Self {
        FilterSpec { name: name.into(), layer, permit: true, weight, conds }
    }
}

/// Builds the WFP application id for an executable path.
pub fn app_id(path: &str) -> Result<Vec<u8>, String> {
    if path.eq_ignore_ascii_case(SYSTEM_APP) {
        return Ok(wide(SYSTEM_APP).iter().flat_map(|c| c.to_le_bytes()).collect());
    }
    // Network shares and raw device paths (what WFP reports for an app with
    // no drive letter) are used as they are, without opening the file.
    if let Some(nt) = win::device_path(path) {
        return Ok(wide(&nt).iter().flat_map(|c| c.to_le_bytes()).collect());
    }
    unsafe {
        let mut blob: *mut FWP_BYTE_BLOB = null_mut();
        let rc = FwpmGetAppIdFromFileName0(wide(path).as_ptr(), &mut blob);
        if rc != 0 || blob.is_null() {
            // 2/3/0x7b: file, path or name not found. Anything else (typically
            // access denied from a self-protecting security product) means the
            // file is there but cannot be opened, so derive the id from the path.
            let missing = matches!(rc, 2 | 3 | 0x7b);
            return match win::dos_to_nt(path) {
                Some(nt) if !missing => Ok(wide(&nt).iter().flat_map(|c| c.to_le_bytes()).collect()),
                _ => Err(format!("cannot resolve `{path}` (error {rc:#x}); is the file missing?")),
            };
        }
        let bytes = std::slice::from_raw_parts((*blob).data, (*blob).size as usize).to_vec();
        FwpmFreeMemory0(&mut blob as *mut _ as *mut *mut core::ffi::c_void);
        Ok(bytes)
    }
}

/// Translates the configuration into the full filter set. Rules that cannot
/// be resolved are skipped and reported as warnings rather than failing the
/// whole policy.
pub fn build_policy(cfg: &Config) -> (Vec<FilterSpec>, Vec<String>) {
    let mut specs = Vec::new();
    let mut warnings = Vec::new();
    if cfg.mode == Mode::Disabled {
        return (specs, warnings);
    }

    for layer in Layer::ALL {
        specs.push(FilterSpec::permit("Phoswire: loopback", layer, W_LOOPBACK, vec![Cond::Loopback]));
    }

    let svchost = app_id(&win::system_svchost());

    // DHCP, without which the machine never gets an address. Limited to the
    // DHCP Client service so the ports are not an open channel for any app;
    // if the service cannot be resolved the rule stays, unscoped, rather than
    // costing the machine its address.
    let dhcp_scope = match (svchost.clone(), win::service_sd("Dhcp")) {
        (Ok(app), Ok(sd)) => vec![Cond::App(app.clone()), Cond::UserSd(sd)],
        (Err(e), _) | (_, Err(e)) => {
            warnings.push(format!("DHCP rules are not limited to the DHCP Client service: {e}"));
            Vec::new()
        }
    };
    let dhcp = |local: u16, remote: u16| {
        let mut conds = dhcp_scope.clone();
        conds.extend([Cond::Protocol(IPPROTO_UDP), Cond::LocalPort(local), Cond::RemotePort(remote)]);
        conds
    };
    for layer in [Layer::ConnectV4, Layer::AcceptV4] {
        specs.push(FilterSpec::permit("Phoswire: DHCP", layer, W_ESSENTIAL, dhcp(68, 67)));
    }
    for layer in [Layer::ConnectV6, Layer::AcceptV6] {
        specs.push(FilterSpec::permit("Phoswire: DHCPv6", layer, W_ESSENTIAL, dhcp(546, 547)));
        // Router/neighbour solicitation and advertisement: IPv6's ARP.
        let mut conds = vec![Cond::Protocol(IPPROTO_ICMPV6)];
        conds.extend((133..=136).map(Cond::LocalPort));
        specs.push(FilterSpec::permit("Phoswire: IPv6 neighbour discovery", layer, W_ESSENTIAL, conds));
    }

    // Name resolution, scoped to the DNS Client service only.
    match (svchost, win::service_sd("Dnscache")) {
        (Ok(app), Ok(sd)) => {
            for layer in Layer::OUTBOUND {
                specs.push(FilterSpec::permit(
                    "Phoswire: DNS client",
                    layer,
                    W_ESSENTIAL,
                    vec![Cond::App(app.clone()), Cond::UserSd(sd.clone()), Cond::RemotePort(53)],
                ));
            }
        }
        (Err(e), _) | (_, Err(e)) => warnings.push(format!("DNS client rule skipped: {e}")),
    }

    for rule in &cfg.rules {
        let mut conds = match app_id(&rule.path) {
            Ok(app) => vec![Cond::App(app)],
            Err(e) => {
                warnings.push(format!("rule skipped: {e}"));
                continue;
            }
        };
        if let Some(service) = &rule.service {
            match win::service_sd(service) {
                Ok(sd) => conds.push(Cond::UserSd(sd)),
                Err(e) => {
                    warnings.push(format!("rule skipped: {e}"));
                    continue;
                }
            }
        }
        let name = format!("Phoswire: {}", rule.subject());
        for layer in Layer::OUTBOUND {
            specs.push(FilterSpec::permit(name.clone(), layer, W_APP, conds.clone()));
        }
        if rule.inbound {
            for layer in Layer::INBOUND {
                specs.push(FilterSpec::permit(name.clone(), layer, W_APP, conds.clone()));
            }
        }
    }

    if cfg.mode == Mode::Learning {
        // Outbound is open while learning; the allow events these filters
        // generate are what the learner listens for.
        for layer in Layer::OUTBOUND {
            specs.push(FilterSpec::permit("Phoswire: learning", layer, W_LEARN, vec![]));
        }
    }
    let blocked: &[Layer] = if cfg.mode == Mode::Learning { &Layer::INBOUND } else { &Layer::ALL };
    for &layer in blocked {
        specs.push(FilterSpec {
            name: "Phoswire: default block".into(),
            layer,
            permit: false,
            weight: W_BLOCK,
            conds: vec![],
        });
    }
    (specs, warnings)
}

// ---------------------------------------------------------------------------
// Net events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NetEvent {
    pub allowed: bool,
    pub filter_id: u64,
    pub layer_id: u16,
    pub loopback: bool,
    /// NT device path of the executable, when WFP knows it.
    pub app: Option<String>,
    pub protocol: u8,
    pub v6: bool,
    pub local_port: u16,
    pub remote: Option<IpAddr>,
    pub remote_port: u16,
}

unsafe extern "system" fn on_net_event(context: *mut core::ffi::c_void, event: *const FWPM_NET_EVENT2) {
    if context.is_null() || event.is_null() {
        return;
    }
    let ev = &*event;
    let (allowed, filter_id, layer_id, loopback) = match ev.r#type {
        FWPM_NET_EVENT_TYPE_CLASSIFY_DROP if !ev.Anonymous.classifyDrop.is_null() => {
            let d = &*ev.Anonymous.classifyDrop;
            (false, d.filterId, d.layerId, d.isLoopback != 0)
        }
        FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW if !ev.Anonymous.classifyAllow.is_null() => {
            let a = &*ev.Anonymous.classifyAllow;
            (true, a.filterId, a.layerId, a.isLoopback != 0)
        }
        _ => return,
    };
    let h = &ev.header;
    let has = |flag: u32| h.flags & flag != 0;
    let app = (has(FWPM_NET_EVENT_FLAG_APP_ID_SET) && !h.appId.data.is_null() && h.appId.size >= 2).then(|| {
        let units = std::slice::from_raw_parts(h.appId.data as *const u16, h.appId.size as usize / 2);
        let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
        String::from_utf16_lossy(&units[..end])
    });
    let v6 = has(FWPM_NET_EVENT_FLAG_IP_VERSION_SET) && h.ipVersion == FWP_IP_VERSION_V6;
    let remote = has(FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET).then(|| {
        if v6 {
            IpAddr::V6(Ipv6Addr::from(h.Anonymous2.remoteAddrV6.byteArray16))
        } else {
            IpAddr::V4(Ipv4Addr::from(h.Anonymous2.remoteAddrV4))
        }
    });
    let out = NetEvent {
        allowed,
        filter_id,
        layer_id,
        loopback,
        app,
        protocol: if has(FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) { h.ipProtocol } else { 0 },
        v6,
        local_port: if has(FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET) { h.localPort } else { 0 },
        remote,
        remote_port: if has(FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET) { h.remotePort } else { 0 },
    };
    // Keep the WFP callback thread free: all real work happens on the receiver.
    // The queue is bounded; under a flood, events are dropped rather than
    // letting a local program grow the service's memory without limit.
    let _ = (*(context as *const SyncSender<NetEvent>)).try_send(out);
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

pub struct Engine {
    /// Dynamic session that owns the sublayer and filters.
    handle: HANDLE,
    /// Ordinary session for engine options and the event subscription, which
    /// WFP refuses from a dynamic session (FWP_E_DYNAMIC_SESSION_IN_PROGRESS).
    control: HANDLE,
    events: HANDLE,
    /// True while the "report allowed connections" keyword is on because we set it.
    allow_events_ours: bool,
    filter_ids: Vec<u64>,
    block_ids: HashSet<u64>,
    /// Run-time layer ids, as reported in net events.
    layer_ids: Vec<(u16, Layer)>,
}

// The handle is an RPC binding that is safe to use from any single thread at
// a time; the service keeps the engine behind a mutex.
unsafe impl Send for Engine {}

fn check(what: &str, rc: u32) -> Result<(), String> {
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("{what} failed (error {rc:#010x})"))
    }
}

impl Engine {
    pub fn open() -> Result<Engine, String> {
        unsafe {
            let mut name = wide("Phoswire");
            let mut session: FWPM_SESSION0 = zeroed();
            session.displayData.name = name.as_mut_ptr();
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;
            session.txnWaitTimeoutInMSec = 5000;
            let mut handle: HANDLE = null_mut();
            check(
                "opening the filter engine",
                FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut handle),
            )?;
            let mut control: HANDLE = null_mut();
            let control_session: FWPM_SESSION0 = zeroed();
            let rc = FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &control_session, &mut control);
            if rc != 0 {
                FwpmEngineClose0(handle);
                return Err(format!("opening the control session failed (error {rc:#010x})"));
            }
            // From here on, dropping `engine` closes both handles.
            let mut engine = Engine {
                handle,
                control,
                events: null_mut(),
                allow_events_ours: false,
                filter_ids: Vec::new(),
                block_ids: HashSet::new(),
                layer_ids: Vec::new(),
            };

            let mut sublayer: FWPM_SUBLAYER0 = zeroed();
            sublayer.subLayerKey = SUBLAYER_KEY;
            sublayer.displayData.name = name.as_mut_ptr();
            sublayer.weight = 0x8000;
            check("adding the sublayer", FwpmSubLayerAdd0(handle, &sublayer, null_mut()))?;

            for layer in Layer::ALL {
                let mut info: *mut FWPM_LAYER0 = null_mut();
                check("querying a layer", FwpmLayerGetByKey0(handle, &layer.key(), &mut info))?;
                engine.layer_ids.push(((*info).layerId, layer));
                FwpmFreeMemory0(&mut info as *mut _ as *mut *mut core::ffi::c_void);
            }
            Ok(engine)
        }
    }

    pub fn filter_count(&self) -> usize {
        self.filter_ids.len()
    }

    /// How many of the filters we installed the engine no longer has (or can
    /// no longer be asked about). Anything but zero means traffic is not
    /// being filtered as configured.
    pub fn missing_filters(&self) -> usize {
        self.filter_ids
            .iter()
            .filter(|&&id| unsafe {
                let mut filter: *mut FWPM_FILTER0 = null_mut();
                let rc = FwpmFilterGetById0(self.handle, id, &mut filter);
                if !filter.is_null() {
                    FwpmFreeMemory0(&mut filter as *mut _ as *mut *mut core::ffi::c_void);
                }
                rc != 0
            })
            .count()
    }

    /// True while the machine-wide "report allowed connections" flag is on
    /// because Phoswire turned it on.
    pub fn allow_events_ours(&self) -> bool {
        self.allow_events_ours
    }

    /// Takes responsibility for the flag when a previous run of the service
    /// turned it on and died before turning it off again.
    pub fn adopt_allow_events(&mut self) {
        self.allow_events_ours = true;
    }

    pub fn layer(&self, layer_id: u16) -> Option<Layer> {
        self.layer_ids.iter().find(|(id, _)| *id == layer_id).map(|(_, l)| *l)
    }

    pub fn is_default_block(&self, filter_id: u64) -> bool {
        self.block_ids.contains(&filter_id)
    }

    /// Atomically replaces every Phoswire filter with `specs`. On failure the
    /// previous filter set stays in force.
    pub fn apply(&mut self, specs: &[FilterSpec]) -> Result<(), String> {
        unsafe {
            check("starting a transaction", FwpmTransactionBegin0(self.handle, 0))?;
            let result = (|| {
                for &id in &self.filter_ids {
                    // A filter another tool already removed is as good as
                    // removed; failing here would freeze the policy for good.
                    match FwpmFilterDeleteById0(self.handle, id) {
                        FILTER_NOT_FOUND => {}
                        rc => check("removing a filter", rc)?,
                    }
                }
                let mut ids = Vec::with_capacity(specs.len());
                let mut blocks = HashSet::new();
                for spec in specs {
                    let id = self.add_filter(spec)?;
                    ids.push(id);
                    if !spec.permit {
                        blocks.insert(id);
                    }
                }
                Ok::<_, String>((ids, blocks))
            })();
            match result {
                Ok((ids, blocks)) => {
                    if let Err(e) = check("committing filters", FwpmTransactionCommit0(self.handle)) {
                        FwpmTransactionAbort0(self.handle);
                        return Err(e);
                    }
                    self.filter_ids = ids;
                    self.block_ids = blocks;
                    Ok(())
                }
                Err(e) => {
                    FwpmTransactionAbort0(self.handle);
                    Err(e)
                }
            }
        }
    }

    unsafe fn add_filter(&self, spec: &FilterSpec) -> Result<u64, String> {
        let mut name = wide(&spec.name);
        // Boxed so the pointers stored in the conditions stay valid.
        let mut blobs: Vec<Box<FWP_BYTE_BLOB>> = Vec::new();
        let mut conds: Vec<FWPM_FILTER_CONDITION0> = Vec::with_capacity(spec.conds.len());
        for cond in &spec.conds {
            let mut c: FWPM_FILTER_CONDITION0 = zeroed();
            c.matchType = FWP_MATCH_EQUAL;
            match cond {
                Cond::Loopback => {
                    c.fieldKey = FWPM_CONDITION_FLAGS;
                    c.matchType = FWP_MATCH_FLAGS_ALL_SET;
                    c.conditionValue.r#type = FWP_UINT32;
                    c.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
                }
                Cond::Protocol(p) => {
                    c.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                    c.conditionValue.r#type = FWP_UINT8;
                    c.conditionValue.Anonymous.uint8 = *p;
                }
                Cond::LocalPort(p) => {
                    c.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
                    c.conditionValue.r#type = FWP_UINT16;
                    c.conditionValue.Anonymous.uint16 = *p;
                }
                Cond::RemotePort(p) => {
                    c.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                    c.conditionValue.r#type = FWP_UINT16;
                    c.conditionValue.Anonymous.uint16 = *p;
                }
                Cond::App(bytes) | Cond::UserSd(bytes) => {
                    let mut blob = Box::new(FWP_BYTE_BLOB {
                        size: bytes.len() as u32,
                        data: bytes.as_ptr() as *mut u8,
                    });
                    let ptr: *mut FWP_BYTE_BLOB = &mut *blob;
                    blobs.push(blob);
                    if matches!(cond, Cond::App(_)) {
                        c.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                        c.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                        c.conditionValue.Anonymous.byteBlob = ptr;
                    } else {
                        c.fieldKey = FWPM_CONDITION_ALE_USER_ID;
                        c.conditionValue.r#type = FWP_SECURITY_DESCRIPTOR_TYPE;
                        c.conditionValue.Anonymous.sd = ptr;
                    }
                }
            }
            conds.push(c);
        }

        let mut filter: FWPM_FILTER0 = zeroed();
        filter.displayData.name = name.as_mut_ptr();
        filter.layerKey = spec.layer.key();
        filter.subLayerKey = SUBLAYER_KEY;
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = spec.weight;
        filter.numFilterConditions = conds.len() as u32;
        filter.filterCondition = if conds.is_empty() { null_mut() } else { conds.as_mut_ptr() };
        filter.action.r#type = if spec.permit { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK };
        let mut id = 0u64;
        let rc = FwpmFilterAdd0(self.handle, &filter, null_mut(), &mut id);
        drop(blobs);
        check(&format!("adding filter `{}`", spec.name), rc)?;
        Ok(id)
    }

    /// Starts delivering classify events to `tx`. Drops are always reported;
    /// allows only while `set_allow_events(true)` is in effect.
    pub fn subscribe(&mut self, tx: SyncSender<NetEvent>) -> Result<(), String> {
        unsafe {
            let mut on: FWP_VALUE0 = zeroed();
            on.r#type = FWP_UINT32;
            on.Anonymous.uint32 = 1;
            check(
                "enabling net events",
                FwpmEngineSetOption0(self.control, FWPM_ENGINE_COLLECT_NET_EVENTS, &on),
            )?;
            let subscription: FWPM_NET_EVENT_SUBSCRIPTION0 = zeroed();
            // Leaked on purpose: the callback may fire for as long as the
            // process lives.
            let context = Box::into_raw(Box::new(tx));
            check(
                "subscribing to net events",
                FwpmNetEventSubscribe1(
                    self.control,
                    &subscription,
                    Some(on_net_event),
                    context as *const core::ffi::c_void,
                    &mut self.events,
                ),
            )
        }
    }

    /// Asks the engine to also report permitted connections (learning mode).
    ///
    /// The keyword mask is one machine-wide setting shared with every other
    /// WFP tool, so only our own bit is touched, and it is only cleared if
    /// this process was the one that set it.
    pub fn set_allow_events(&mut self, enabled: bool) -> Result<(), String> {
        const ALLOW: u32 = FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW;
        unsafe {
            let mut current = 0u32;
            let mut got: *mut FWP_VALUE0 = null_mut();
            if FwpmEngineGetOption0(self.control, FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, &mut got) == 0
                && !got.is_null()
            {
                if (*got).r#type == FWP_UINT32 {
                    current = (*got).Anonymous.uint32;
                }
                FwpmFreeMemory0(&mut got as *mut _ as *mut *mut core::ffi::c_void);
            }
            let wanted = if enabled {
                if current & ALLOW == 0 {
                    self.allow_events_ours = true;
                }
                current | ALLOW
            } else if std::mem::take(&mut self.allow_events_ours) {
                current & !ALLOW
            } else {
                current
            };
            if wanted == current {
                return Ok(());
            }
            let mut v: FWP_VALUE0 = zeroed();
            v.r#type = FWP_UINT32;
            v.Anonymous.uint32 = wanted;
            check(
                "setting net event keywords",
                FwpmEngineSetOption0(self.control, FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, &v),
            )
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            if !self.events.is_null() {
                FwpmNetEventUnsubscribe0(self.control, self.events);
            }
            let _ = self.set_allow_events(false);
            FwpmEngineClose0(self.control);
            // Closing a dynamic session removes the sublayer and all filters.
            FwpmEngineClose0(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Rule, Source};

    fn rule(path: &str, service: Option<&str>, inbound: bool) -> Rule {
        Rule { path: path.into(), service: service.map(Into::into), inbound, source: Source::Manual, added: 0 }
    }

    fn svchost() -> String {
        win::system_svchost()
    }

    #[test]
    fn disabled_installs_nothing() {
        let (specs, warnings) = build_policy(&Config { mode: Mode::Disabled, rules: vec![rule(&svchost(), None, true)], ..Config::default() });
        assert!(specs.is_empty() && warnings.is_empty());
    }

    #[test]
    fn normal_blocks_every_layer_by_default() {
        let (specs, warnings) = build_policy(&Config { mode: Mode::Normal, ..Config::default() });
        assert!(warnings.is_empty(), "{warnings:?}");
        for layer in Layer::ALL {
            let blocks: Vec<_> = specs.iter().filter(|s| s.layer == layer && !s.permit).collect();
            assert_eq!(blocks.len(), 1);
            assert!(blocks[0].conds.is_empty());
            // Every unconditional permit would defeat the block.
            assert!(specs.iter().all(|s| !(s.layer == layer && s.permit && s.conds.is_empty())));
            // The block must be the lowest-weight filter in its layer.
            assert!(specs.iter().filter(|s| s.layer == layer && s.permit).all(|s| s.weight > blocks[0].weight));
        }
    }

    #[test]
    fn learning_opens_outbound_but_not_inbound() {
        let (specs, _) = build_policy(&Config { mode: Mode::Learning, ..Config::default() });
        for layer in Layer::ALL {
            let open = specs.iter().any(|s| s.layer == layer && s.permit && s.conds.is_empty());
            let blocked = specs.iter().any(|s| s.layer == layer && !s.permit);
            assert_eq!(open, !layer.is_inbound());
            assert_eq!(blocked, layer.is_inbound());
        }
    }

    #[test]
    fn rules_become_app_filters() {
        let cfg = Config {
            mode: Mode::Normal,
            rules: vec![
                rule(&svchost(), Some("Dnscache"), false),
                rule(&svchost(), None, true),
                rule(r"C:\does\not\exist.exe", None, false),
                rule(SYSTEM_APP, None, false),
            ],
            ..Config::default()
        };
        let (specs, warnings) = build_policy(&cfg);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let apps: Vec<_> = specs.iter().filter(|s| s.weight == W_APP).collect();
        // service rule: 2 outbound; inbound rule: 2 + 2; System: 2
        assert_eq!(apps.len(), 8);
        assert_eq!(apps.iter().filter(|s| s.layer.is_inbound()).count(), 2);
        assert_eq!(apps.iter().filter(|s| s.conds.iter().any(|c| matches!(c, Cond::UserSd(_)))).count(), 2);
    }

    #[test]
    fn app_id_is_a_device_path() {
        let id = app_id(&svchost()).unwrap();
        let units: Vec<u16> = id.chunks(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
        let nt = String::from_utf16_lossy(&units[..units.len() - 1]);
        assert!(nt.starts_with(r"\device\"), "{nt}");
        assert!(crate::win::nt_to_dos(&nt).eq_ignore_ascii_case(&svchost()), "{nt}");
        // The no-file-access fallback must produce the identical id.
        assert_eq!(win::dos_to_nt(&svchost()).unwrap(), nt);
    }

    #[test]
    fn paths_without_a_drive_letter_need_no_file_access() {
        let utf16 = |s: &str| -> Vec<u8> { wide(s).iter().flat_map(|c| c.to_le_bytes()).collect() };
        assert_eq!(app_id(r"\\Server\Share\App.exe").unwrap(), utf16(r"\device\mup\server\share\app.exe"));
        assert_eq!(app_id(r"\Device\Mup\server\share\app.exe").unwrap(), utf16(r"\device\mup\server\share\app.exe"));
        assert_eq!(win::device_path(r"C:\Windows\notepad.exe"), None);
        assert_eq!(win::device_path(r"\\?\C:\Windows\notepad.exe"), None);
    }

    #[test]
    fn only_the_real_svchost_is_a_service_host() {
        assert!(win::is_svchost(&svchost().to_uppercase()));
        assert!(!win::is_svchost(r"C:\Users\someone\svchost.exe"));
        assert!(win::path_protected(&svchost()));
        assert!(win::path_protected(SYSTEM_APP));
        assert!(!win::path_protected(r"C:\Users\someone\AppData\Local\app\app.exe"));
    }

    #[test]
    fn system_folders_do_not_come_from_the_environment() {
        // Agree with the environment on an ordinary machine...
        let env = |name: &str| std::env::var(name).unwrap();
        assert!(win::program_files().eq_ignore_ascii_case(&env("ProgramW6432")));
        assert!(win::program_data().eq_ignore_ascii_case(&env("ProgramData")));
        assert!(win::windows_dir().eq_ignore_ascii_case(&env("SystemRoot")));
        // ...but are not taken from it.
        std::env::set_var("ProgramData", r"C:\Users\Public\elsewhere");
        assert!(!Config::dir().starts_with(r"C:\Users\Public"));
    }

    #[test]
    fn permissions_decide_whether_a_path_is_protected() {
        let open = |sddl: &str| unsafe {
            let mut sd = win::sddl_to_sd(sddl).unwrap();
            let (mut present, mut dacl, mut defaulted) = (0, null_mut(), 0);
            let ok = windows_sys::Win32::Security::GetSecurityDescriptorDacl(
                sd.as_mut_ptr().cast(),
                &mut present,
                &mut dacl,
                &mut defaulted,
            );
            assert!(ok != 0 && present != 0);
            win::dacl_open_to_unprivileged(dacl)
        };
        // Program Files as installed: users may read and run, nothing more.
        assert!(!open("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"));
        // Entries that only describe what new children inherit do not count.
        assert!(!open("D:(A;;FA;;;BA)(A;OICIIO;GA;;;CO)(A;;0x1200a9;;;BU)"));
        // C:\Windows\Temp: users may create files.
        assert!(open("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x100026;;;BU)"));
        // A badly installed application: users may modify.
        assert!(open("D:(A;;FA;;;BA)(A;;0x1301bf;;;AU)"));
        assert!(open("D:(A;;FA;;;BA)(A;;GA;;;WD)"));
    }

    #[test]
    fn dhcp_is_limited_to_the_dhcp_service() {
        let (specs, _) = build_policy(&Config { mode: Mode::Normal, ..Config::default() });
        let dhcp: Vec<_> = specs.iter().filter(|s| s.name.contains("DHCP")).collect();
        assert_eq!(dhcp.len(), 4);
        for spec in dhcp {
            assert!(spec.conds.iter().any(|c| matches!(c, Cond::App(_))), "{}", spec.name);
            assert!(spec.conds.iter().any(|c| matches!(c, Cond::UserSd(_))), "{}", spec.name);
        }
    }

    #[test]
    fn ownership_check_tells_system_files_from_missing_ones() {
        assert!(win::path_owner_trusted(std::path::Path::new(win::program_data())));
        assert!(!win::path_owner_trusted(std::path::Path::new(r"C:\no\such\phoswire\file")));
    }

    #[test]
    fn old_configs_and_requests_still_parse() {
        let cfg: Config = serde_json::from_str(r#"{"mode":"learning","rules":[]}"#).unwrap();
        assert!(cfg.mode == Mode::Learning && cfg.learning_until.is_none());
        let req: crate::ipc::Request = serde_json::from_str(r#"{"cmd":"set_mode","mode":"normal"}"#).unwrap();
        assert!(matches!(req, crate::ipc::Request::SetMode { hours: None, .. }));
    }

    #[test]
    fn service_sd_resolves() {
        assert!(win::service_sd("Dnscache").unwrap().len() > 20);
    }

    #[test]
    fn port_owner_lookup_finds_our_own_sockets() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = std::net::UdpSocket::bind("[::1]:0").unwrap();
        let me = std::process::id();
        assert_eq!(win::pid_for_port(6, false, tcp.local_addr().unwrap().port()), Some(me));
        assert_eq!(win::pid_for_port(17, true, udp.local_addr().unwrap().port()), Some(me));
        assert!(win::services_by_pid().values().flatten().any(|s| s.eq_ignore_ascii_case("Dnscache")));

        // Holding a UDP socket, even one bound to every interface, is not
        // network use: the socket poller must not report (and so whitelist) us.
        let _any = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        assert!(!win::network_pids().contains(&me));
        let exe = std::env::current_exe().unwrap();
        assert!(win::process_path(me).unwrap().eq_ignore_ascii_case(&exe.to_string_lossy()));
        assert_eq!(win::process_path(4).as_deref(), Some(SYSTEM_APP));
    }
}
