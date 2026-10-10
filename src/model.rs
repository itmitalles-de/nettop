//! Values shared by the collector, terminal UI and machine-readable output.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CaptureStatus {
    pub active: bool,
    /// English text of `notes`, kept for `--once`, JSON consumers and older UIs.
    pub message: String,
    pub dropped: u64,
    /// The same status in structured form, translated by the UI. Helpers
    /// installed before this field existed omit it; the UI then shows `message`.
    #[serde(default)]
    pub notes: Vec<CaptureNote>,
}

/// One part of the capture status line. Older UIs ignore this field, and a
/// newer helper's unknown code decodes as `Unknown`, so neither direction
/// needs a protocol version change.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum CaptureNote {
    /// `--no-capture`.
    Disabled,
    LibpcapMissing,
    /// Capture permissions are missing; `detail` is libpcap's text.
    SetupNeeded {
        detail: String,
    },
    Unavailable {
        detail: String,
    },
    NoInterfaceIndexes,
    AllInterfaces,
    AllSocketPackets,
    /// The routine explanation; the UI keeps it in F1 Help only.
    Sampled,
    /// Optional socket events, namespace inventory and NAT metadata.
    Extended,
    ExtendedIssue {
        detail: String,
    },
    PcapMissed {
        packets: u64,
    },
    FlowLimit {
        packets: u64,
    },
    CaptureQueueLimit {
        packets: u64,
    },
    AttributionQueueLimit {
        packets: u64,
    },
    Unreadable {
        unsupported: u64,
        truncated: u64,
    },
    AttributionAtRefresh {
        error: String,
    },
    Stopped {
        error: String,
    },
    OwnersInaccessible,
    CounterLimit,
    InterfaceMissing {
        name: String,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Snapshot {
    pub elapsed: f64,
    pub interfaces: Vec<Interface>,
    pub processes: Vec<ProcessRow>,
    pub connections: Vec<ConnectionRow>,
    pub capture: CaptureStatus,
}
