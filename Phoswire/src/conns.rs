//! The open connections of each whitelisted program, for `phoswire
//! connections` and the tray window.
//!
//! Only TCP is reported: a UDP socket has no remote end to show. Connections
//! to this machine itself are left out, since Phoswire always allows them.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::config::{Config, Rule};
use crate::win;

const STATE_CLOSED: u32 = 1;
const STATE_LISTEN: u32 = 2;
const STATE_TIME_WAIT: u32 = 11;
const STATE_DELETE_TCB: u32 = 12;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    pub pid: u32,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
    /// `established`, `syn-sent`, `close-wait`, ...
    pub state: String,
    /// Accepted from the other machine rather than opened by the program.
    pub inbound: bool,
}

/// A whitelist rule and the connections it currently covers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConnections {
    pub rule: Rule,
    pub connections: Vec<Connection>,
}

/// A connection and what is known about the process that owns it.
struct Owned {
    path: String,
    services: Vec<String>,
    conn: Connection,
}

/// Every rule, in whitelist order, with the connections it covers now.
pub fn collect(rules: &[Rule]) -> Vec<AppConnections> {
    let rows = win::tcp_table();
    let listening: HashSet<(u32, bool, u16)> = rows
        .iter()
        .filter(|r| r.state == STATE_LISTEN)
        .map(|r| (r.pid, r.local.is_ipv6(), r.local_port))
        .collect();
    let mut paths: HashMap<u32, Option<String>> = HashMap::new();
    let mut services: Option<HashMap<u32, Vec<String>>> = None;
    let mut found = Vec::new();
    for r in &rows {
        let remote = r.remote.to_canonical();
        if r.pid == 0
            || matches!(r.state, STATE_CLOSED | STATE_LISTEN | STATE_TIME_WAIT | STATE_DELETE_TCB)
            || remote.is_loopback()
            || remote.is_unspecified()
        {
            continue;
        }
        let Some(path) = paths.entry(r.pid).or_insert_with(|| win::process_path(r.pid)).clone() else {
            continue;
        };
        let hosted = if win::is_svchost(&path) {
            services.get_or_insert_with(win::services_by_pid).get(&r.pid).cloned().unwrap_or_default()
        } else {
            Vec::new()
        };
        found.push(Owned {
            path,
            services: hosted,
            conn: Connection {
                pid: r.pid,
                local_port: r.local_port,
                remote,
                remote_port: r.remote_port,
                state: state_name(r.state).into(),
                inbound: listening.contains(&(r.pid, r.local.is_ipv6(), r.local_port)),
            },
        });
    }
    assign(rules, found)
}

/// Files each connection under the rule that lets it through. A rule for one
/// service wins over one for the whole executable; when a shared service host
/// runs several whitelisted services, the socket cannot be tied to one of
/// them, so it is listed under each.
fn assign(rules: &[Rule], found: Vec<Owned>) -> Vec<AppConnections> {
    let mut apps: Vec<AppConnections> =
        rules.iter().map(|r| AppConnections { rule: r.clone(), connections: Vec::new() }).collect();
    // Whether a rule covers a program is asked of `Config::covers`, the
    // firewall's own answer, rather than worked out again here, so this list
    // can never disagree with what the firewall lets through.
    let single: Vec<Config> = rules.iter().map(|r| Config { rules: vec![r.clone()], ..Config::default() }).collect();
    for o in found {
        let mut targets: Vec<usize> = rules
            .iter()
            .enumerate()
            .filter(|(i, r)| r.service.is_some() && o.services.iter().any(|h| single[*i].covers(&o.path, Some(h))))
            .map(|(i, _)| i)
            .collect();
        if targets.is_empty() {
            targets.extend(rules.iter().enumerate().position(|(i, r)| r.service.is_none() && single[i].covers(&o.path, None)));
        }
        for i in targets {
            apps[i].connections.push(o.conn.clone());
        }
    }
    for app in &mut apps {
        app.connections.sort_by(|a, b| {
            (a.remote, a.remote_port, a.local_port, a.pid).cmp(&(b.remote, b.remote_port, b.local_port, b.pid))
        });
    }
    apps
}

fn state_name(state: u32) -> &'static str {
    match state {
        1 => "closed",
        2 => "listening",
        3 => "syn-sent",
        4 => "syn-received",
        5 => "established",
        6 => "fin-wait-1",
        7 => "fin-wait-2",
        8 => "close-wait",
        9 => "closing",
        10 => "last-ack",
        11 => "time-wait",
        12 => "delete-tcb",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Source;

    fn rule(path: &str, service: Option<&str>) -> Rule {
        let mut cfg = Config::default();
        cfg.add(path.into(), service.map(Into::into), false, Source::Manual);
        cfg.rules.remove(0)
    }

    fn owned(path: &str, services: &[&str], port: u16) -> Owned {
        Owned {
            path: path.into(),
            services: services.iter().map(|s| s.to_string()).collect(),
            conn: Connection {
                pid: 7,
                local_port: 50_000,
                remote: "203.0.113.9".parse().unwrap(),
                remote_port: port,
                state: "established".into(),
                inbound: false,
            },
        }
    }

    const SVCHOST: &str = r"C:\Windows\System32\svchost.exe";

    #[test]
    fn connections_go_to_the_rule_that_allows_them() {
        let rules = [
            rule(r"C:\Program Files\App\app.exe", None),
            rule(SVCHOST, Some("Dnscache")),
            rule(SVCHOST, Some("BITS")),
            rule(r"C:\Idle\idle.exe", None),
        ];
        let apps = assign(
            &rules,
            vec![
                // WFP and the process table disagree on case; both must match.
                owned(r"c:\program files\app\APP.EXE", &[], 443),
                owned(SVCHOST, &["bits"], 80),
                owned(SVCHOST, &["Unlisted"], 8080),
                owned(r"C:\Other\other.exe", &[], 22),
            ],
        );
        let ports = |i: usize| apps[i].connections.iter().map(|c| c.remote_port).collect::<Vec<_>>();
        assert_eq!(apps.len(), 4, "every rule is reported, connected or not");
        assert_eq!(ports(0), [443]);
        assert_eq!(ports(1), [] as [u16; 0]);
        assert_eq!(ports(2), [80]);
        assert_eq!(ports(3), [] as [u16; 0]);
    }

    #[test]
    fn a_service_rule_wins_over_a_rule_for_the_whole_executable() {
        let rules = [rule(SVCHOST, None), rule(SVCHOST, Some("Dnscache"))];
        let apps = assign(&rules, vec![owned(SVCHOST, &["Dnscache"], 53), owned(SVCHOST, &[], 443)]);
        assert_eq!(apps[0].connections.iter().map(|c| c.remote_port).collect::<Vec<_>>(), [443]);
        assert_eq!(apps[1].connections.iter().map(|c| c.remote_port).collect::<Vec<_>>(), [53]);
    }
}
