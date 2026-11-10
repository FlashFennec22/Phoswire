//! Phoswire: a light zero-trust application firewall for Windows.

mod config;
mod ipc;
mod service;
mod wfp;
mod win;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use config::{Mode, Source, SYSTEM_APP};
use ipc::{Reply, Request};

#[derive(Parser)]
#[command(name = "phoswire", version, about = "Zero-trust application firewall that works alongside Windows Firewall")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Install and start the Phoswire service (elevated)
    Install {
        /// On a machine with no configuration yet, start in learning mode
        #[arg(long)]
        learning: bool,
    },
    /// Stop and remove the service (elevated)
    Uninstall,
    /// Start the installed service
    Start,
    /// Stop the service; its filters are removed
    Stop,
    /// Show mode, rule count and any problems
    Status,
    /// Switch mode: normal (block unless whitelisted), learning, or disabled
    Mode {
        mode: Mode,
        /// Learning only: switch back to normal by itself after this many hours
        #[arg(long)]
        hours: Option<u32>,
    },
    /// Whitelist an executable (or `System` for the kernel)
    Allow {
        path: String,
        /// Limit the rule to one Windows service hosted by the executable
        #[arg(long)]
        service: Option<String>,
        /// Also accept unsolicited inbound connections
        #[arg(long)]
        inbound: bool,
        /// Withdraw inbound access from a rule that has it
        #[arg(long, conflicts_with = "inbound")]
        outbound_only: bool,
    },
    /// Remove a rule by path or by its number from `list` (for a file whose
    /// name is a number, write it as a path: `.\3`)
    Remove {
        target: String,
        #[arg(long)]
        service: Option<String>,
    },
    /// List the whitelist
    List,
    /// Show apps Phoswire has blocked since the service started
    Blocked {
        /// Forget the recorded entries
        #[arg(long)]
        clear: bool,
    },
    /// Run the firewall in this console instead of as a service (elevated; for testing)
    Run,
    /// Service entry point, used by the service control manager
    #[command(hide = true)]
    Service,
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<(), String> {
    let request = match command {
        Command::Install { learning } => return service::install(learning).map(|m| println!("{m}")),
        Command::Uninstall => return service::uninstall().map(|m| println!("{m}")),
        Command::Start => return service::start().map(|m| println!("{m}")),
        Command::Stop => return service::stop().map(|m| println!("{m}")),
        Command::Service => return service::dispatch(),
        Command::Run => {
            println!("Phoswire running in the foreground; press Ctrl+C to stop and remove its filters.");
            // Keep the sender alive so the firewall runs until the process is killed.
            let (_keep, stop) = std::sync::mpsc::channel();
            return service::run(stop);
        }
        Command::Status => Request::Status,
        Command::Mode { mode, hours } => Request::SetMode { mode, hours },
        Command::Allow { path, service, inbound, outbound_only } => {
            Request::Allow { path: resolve_path(&path)?, service, inbound, outbound_only }
        }
        Command::Remove { target, service } => match target.parse::<usize>() {
            Ok(index) if service.is_none() => Request::RemoveIndex { index },
            _ => Request::Remove { path: resolve_path(&target).unwrap_or(target), service },
        },
        Command::List => Request::List,
        Command::Blocked { clear: true } => Request::ClearBlocked,
        Command::Blocked { clear: false } => Request::Blocked,
    };
    print_reply(ipc::request(&request)?)
}

/// Makes a path absolute relative to the caller's directory, since the
/// service has a different working directory.
fn resolve_path(path: &str) -> Result<String, String> {
    if path.eq_ignore_ascii_case(SYSTEM_APP) {
        return Ok(SYSTEM_APP.to_string());
    }
    let full = std::fs::canonicalize(path).map_err(|e| format!("{path}: {e}"))?;
    let full = full.to_string_lossy().into_owned();
    Ok(match full.strip_prefix(r"\\?\UNC\") {
        Some(unc) => format!(r"\\{unc}"),
        None => full.strip_prefix(r"\\?\").unwrap_or(&full).to_string(),
    })
}

fn age(then: u64) -> String {
    let secs = config::now().saturating_sub(then);
    match secs {
        0..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86_399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

fn protocol_name(p: u8) -> String {
    match p {
        1 => "ICMP".into(),
        6 => "TCP".into(),
        17 => "UDP".into(),
        58 => "ICMPv6".into(),
        other => format!("proto {other}"),
    }
}

fn print_reply(reply: Reply) -> Result<(), String> {
    match reply {
        Reply::Error { message } => return Err(message),
        Reply::Done { message } => println!("{message}"),
        Reply::Status(s) => {
            println!("Phoswire {}", s.version);
            println!("  mode:    {}", s.mode);
            println!("  rules:   {}", s.rules);
            println!("  filters: {}", s.filters);
            match s.mode {
                Mode::Learning => {
                    println!("  Outbound traffic is open and being learned; switch back with `phoswire mode normal`.");
                    if let Some(since) = s.learning_since {
                        println!("  Learning since {}.", age(since));
                    }
                    match s.learning_until {
                        Some(until) => {
                            let mins = until.saturating_sub(config::now()) / 60;
                            println!("  Reverts to normal in {}h {}m.", mins / 60, mins % 60);
                        }
                        None => println!("  No end time set; `phoswire mode learning --hours N` sets one."),
                    }
                }
                Mode::Disabled => println!("  Phoswire is not filtering; only Windows Firewall applies."),
                Mode::Normal => {}
            }
            let c = &s.counters;
            println!(
                "  events:  {} allowed, {} dropped, {} ignored",
                c.allow_events, c.drop_events, c.ignored_events
            );
            println!(
                "  learned: {} from events, {} from open sockets",
                c.learned_from_events, c.learned_from_sockets
            );
            for w in &s.warnings {
                println!("  warning: {w}");
            }
            if !s.unresolved.is_empty() {
                println!("  seen while learning but not whitelisted (could not be identified):");
                for u in &s.unresolved {
                    println!("    {u}");
                }
            }
        }
        Reply::Rules { rules } => {
            if rules.is_empty() {
                println!("The whitelist is empty.");
            }
            let mut unprotected = false;
            for (i, r) in rules.iter().enumerate() {
                let mut tags = vec![match r.source {
                    Source::Manual => "manual".to_string(),
                    Source::Learned => "learned".to_string(),
                }];
                if r.inbound {
                    tags.push("inbound".into());
                }
                if !win::in_protected_dir(&r.path) {
                    tags.push("unprotected path".into());
                    unprotected = true;
                }
                println!("{:>3}  {}  ({}, {})", i + 1, r.subject(), tags.join(", "), age(r.added));
            }
            if unprotected {
                println!();
                println!("Rules trust a path, not a file. \"unprotected path\" marks a rule outside Program Files and");
                println!("Windows, where a program without administrator rights could replace the trusted file.");
            }
        }
        Reply::Blocked { entries } => {
            if entries.is_empty() {
                println!("Nothing has been blocked.");
            }
            for b in &entries {
                println!(
                    "{}  {} {} {}  x{}  {}",
                    b.path,
                    if b.inbound { "<-" } else { "->" },
                    protocol_name(b.protocol),
                    b.remote,
                    b.count,
                    age(b.last)
                );
            }
        }
    }
    Ok(())
}
