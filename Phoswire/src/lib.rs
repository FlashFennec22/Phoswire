//! Phoswire: a light zero-trust application firewall for Windows.
//!
//! The library holds everything shared by the `phoswire` command (which is
//! also the service) and the `phoswire-tray` window.

pub mod config;
pub mod conns;
pub mod ipc;
pub mod service;
pub mod wfp;
pub mod win;
