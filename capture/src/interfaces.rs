use std::net::IpAddr;

use packetcity_core::devices::LocalNetwork;
use serde::Serialize;

use crate::platform::ensure_library;
use crate::CaptureError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum InterfaceKind {
    Ethernet,
    Wireless,
    Loopback,
    Virtual,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceAddress {
    pub address: IpAddr,
    pub netmask: Option<IpAddr>,
    pub broadcast: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceInfo {
    /// Identifier passed back to start a capture (e.g. `\Device\NPF_{GUID}` or `en0`).
    pub id: String,
    pub display_name: String,
    pub description: Option<String>,
    pub kind: InterfaceKind,
    pub addresses: Vec<InterfaceAddress>,
    pub is_up: bool,
    pub is_running: bool,
    pub connected: Option<bool>,
}

impl InterfaceInfo {
    pub fn local_ips(&self) -> Vec<IpAddr> {
        self.addresses.iter().map(|a| a.address).collect()
    }

    pub fn broadcast_ips(&self) -> Vec<IpAddr> {
        self.addresses.iter().filter_map(|a| a.broadcast).collect()
    }

    pub fn local_networks(&self) -> Vec<LocalNetwork> {
        self.addresses.iter().filter_map(|a| LocalNetwork::from_netmask(a.address, a.netmask?)).collect()
    }

    fn usefulness(&self) -> u8 {
        u8::from(self.connected != Some(false))
            + u8::from(self.is_up && self.is_running)
            + u8::from(!self.addresses.is_empty()) * 2
            + u8::from(!matches!(self.kind, InterfaceKind::Virtual | InterfaceKind::Loopback))
    }
}

/// Description substrings that identify virtual adapters. Heuristic, used only for sorting/labels.
const VIRTUAL_MARKERS: [&str; 10] =
    ["virtual", "hyper-v", "vmware", "virtualbox", "wan miniport", "tap-", "tunnel", "vpn", "docker", "wsl"];

fn kind_of(dev: &pcap::Device) -> InterfaceKind {
    let label = format!("{} {}", dev.name, dev.desc.as_deref().unwrap_or("")).to_ascii_lowercase();
    if dev.flags.is_loopback() || label.contains("loopback") {
        InterfaceKind::Loopback
    } else if dev.flags.is_wireless() || label.contains("wi-fi") || label.contains("wireless") || label.contains("wlan") {
        InterfaceKind::Wireless
    } else if VIRTUAL_MARKERS.iter().any(|m| label.contains(m)) {
        InterfaceKind::Virtual
    } else if label.contains("ethernet") || ["eth", "en", "em"].iter().any(|p| dev.name.starts_with(p)) {
        InterfaceKind::Ethernet
    } else {
        InterfaceKind::Unknown
    }
}

pub(crate) fn to_info(dev: &pcap::Device) -> InterfaceInfo {
    let display_name = if cfg!(windows) {
        dev.desc.clone().unwrap_or_else(|| dev.name.clone())
    } else {
        dev.name.clone()
    };
    InterfaceInfo {
        id: dev.name.clone(),
        display_name,
        description: dev.desc.clone(),
        kind: kind_of(dev),
        addresses: dev
            .addresses
            .iter()
            .map(|a| InterfaceAddress { address: a.addr, netmask: a.netmask, broadcast: a.broadcast_addr })
            .collect(),
        is_up: dev.flags.is_up(),
        is_running: dev.flags.is_running(),
        connected: match dev.flags.connection_status {
            pcap::ConnectionStatus::Connected => Some(true),
            pcap::ConnectionStatus::Disconnected => Some(false),
            _ => None,
        },
    }
}

pub(crate) fn find_device(id: &str) -> Result<pcap::Device, CaptureError> {
    ensure_library()?;
    pcap::Device::list()
        .map_err(|e| CaptureError::Open(e.to_string()))?
        .into_iter()
        .find(|d| d.name == id)
        .ok_or_else(|| CaptureError::InterfaceNotFound(id.to_string()))
}

/// Lists capture interfaces, most useful (connected, addressed, physical) first.
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, CaptureError> {
    ensure_library()?;
    let devices = pcap::Device::list().map_err(CaptureError::from_open)?;
    let mut infos: Vec<InterfaceInfo> = devices.iter().map(to_info).collect();
    infos.sort_by_key(|i| std::cmp::Reverse(i.usefulness()));
    Ok(infos)
}
