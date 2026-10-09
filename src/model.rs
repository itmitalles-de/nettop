//! Values shared by the collector, terminal UI and machine-readable output.

use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct Interface {
    pub name: String,
    pub state: String,
    pub address: Option<String>,
    pub speed_mbps: Option<u64>,
    pub mtu: Option<u64>,
    pub is_virtual: bool,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub errors: u64,
    pub dropped: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ProcessRow {
    pub pid: Option<u32>,
    pub user: String,
    pub name: String,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub connections: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ConnectionRow {
    pub pid: Option<u32>,
    pub user: String,
    pub process: String,
    pub protocol: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CaptureStatus {
    pub active: bool,
    pub message: String,
    pub dropped: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Snapshot {
    pub elapsed: f64,
    pub interfaces: Vec<Interface>,
    pub processes: Vec<ProcessRow>,
    pub connections: Vec<ConnectionRow>,
    pub capture: CaptureStatus,
}
