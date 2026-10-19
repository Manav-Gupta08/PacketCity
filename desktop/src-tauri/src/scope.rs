//! Honest description of what the current capture can see. Shown prominently in the UI so users
//! never assume visibility the application does not have.

use packetcity_capture::{InterfaceInfo, InterfaceKind};
use packetcity_core::replay::{CaptureAnalysis, PrefixSource};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureScope {
    pub mode: String,
    pub visibility: String,
}

fn scope(mode: &str, visibility: &str) -> CaptureScope {
    CaptureScope { mode: mode.into(), visibility: visibility.into() }
}

pub fn live_scope(interface: &InterfaceInfo, promiscuous: bool) -> CaptureScope {
    if interface.kind == InterfaceKind::Loopback {
        return scope("Loopback capture", "Only traffic between programs on this machine.");
    }
    if promiscuous {
        scope(
            "Promiscuous capture",
            "This machine's traffic, broadcast/multicast, and frames for other hosts only if the network delivers them here (hub, mirror/SPAN port). Switched networks and most Wi-Fi do not.",
        )
    } else {
        scope("Normal interface capture", "Traffic to and from this machine, plus broadcast and multicast on this network segment.")
    }
}

pub fn demo_scope() -> CaptureScope {
    CaptureScope {
        mode: "DEMO — synthetic traffic".into(),
        visibility: "No real network data. Generated locally using reserved documentation addresses.".into(),
    }
}

pub fn replay_scope(file_name: &str, a: &CaptureAnalysis) -> CaptureScope {
    let host = match (a.inferred_host, a.inferred_prefix, a.prefix_source) {
        (Some(h), Some(p), PrefixSource::Arp) => format!("recording host inferred as {h} on a /{p} (from ARP)"),
        (Some(h), Some(p), PrefixSource::Assumed) => format!("recording host inferred as {h}; subnet assumed /{p}"),
        _ => "recording host could not be inferred".into(),
    };
    CaptureScope {
        mode: format!("Replay of {file_name}"),
        visibility: format!("Whatever the original capture saw. Direction is relative to the {host}."),
    }
}
