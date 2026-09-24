//! Device discovery for the Global view. Endpoints are resolved to *nodes* of the city:
//! this host, the gateway (router), a LAN device, "the internet" (anything off-link, reached via
//! the gateway), or the broadcast domain.
//!
//! On-link = inside one of the capture interface's subnets (from its netmask) or link-local.
//! The gateway is learned, not assumed: it is the MAC that our off-link traffic is sent to or
//! arrives from. LAN devices are keyed by MAC when Ethernet is available, else by IP.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

use serde::{Serialize, Serializer};

use crate::direction::LocalHost;
use crate::oui;
use crate::packet::{AppProtocol, Direction, MacAddr, ParsedPacket};

pub type DeviceId = u32;

const MAX_IPS_PER_DEVICE: usize = 4;
const DHCP_CLIENT_MESSAGES: [u8; 3] = [1, 3, 8];
const NBNS_OWNER_OPCODES: [u8; 3] = [5, 8, 9];
const NBNS_WORKSTATION: u8 = 0x00;
const NBNS_SERVER: u8 = 0x20;

/// How a device's name was learned, weakest first; a stronger source replaces a weaker one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NameSource {
    Netbios,
    Llmnr,
    Mdns,
    /// The DHCP host name option: what the device calls itself.
    Dhcp,
}

/// A node of the network map that traffic travels between.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NodeRef {
    SelfHost,
    Gateway,
    Internet,
    Broadcast,
    Device(DeviceId),
    /// A LAN host that was not tracked because the device table is full.
    Lan,
}

impl fmt::Display for NodeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeRef::SelfHost => f.write_str("self"),
            NodeRef::Gateway => f.write_str("gateway"),
            NodeRef::Internet => f.write_str("internet"),
            NodeRef::Broadcast => f.write_str("broadcast"),
            NodeRef::Device(id) => write!(f, "dev:{id}"),
            NodeRef::Lan => f.write_str("lan"),
        }
    }
}

impl Serialize for NodeRef {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// An on-link IP network of the capture interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalNetwork {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl LocalNetwork {
    pub fn from_netmask(addr: IpAddr, netmask: IpAddr) -> Option<Self> {
        let prefix = match (addr, netmask) {
            (IpAddr::V4(_), IpAddr::V4(m)) => u32::from(m).leading_ones() as u8,
            (IpAddr::V6(_), IpAddr::V6(m)) => u128::from(m).leading_ones() as u8,
            _ => return None,
        };
        (prefix > 0).then_some(Self { addr, prefix })
    }

    fn masks(&self) -> (u128, u128) {
        let bits: u32 = if self.addr.is_ipv4() { 32 } else { 128 };
        let host_bits = bits - u32::from(self.prefix).min(bits);
        let full = if bits == 32 { u128::from(u32::MAX) } else { u128::MAX };
        let host = if host_bits >= 128 { u128::MAX } else { (1u128 << host_bits) - 1 };
        (full & !host, host)
    }

    fn as_u128(ip: &IpAddr) -> u128 {
        match ip {
            IpAddr::V4(v4) => u128::from(u32::from(*v4)),
            IpAddr::V6(v6) => u128::from(*v6),
        }
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        if ip.is_ipv4() != self.addr.is_ipv4() {
            return false;
        }
        let (net, _) = self.masks();
        Self::as_u128(ip) & net == Self::as_u128(&self.addr) & net
    }

    /// Directed broadcast address (IPv4 only; prefixes /31 and /32 have none).
    pub fn is_broadcast(&self, ip: &IpAddr) -> bool {
        if !self.addr.is_ipv4() || self.prefix >= 31 || !self.contains(ip) {
            return false;
        }
        let (_, host) = self.masks();
        Self::as_u128(ip) & host == host
    }
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xFFC0) == 0xFE80,
    }
}

#[derive(Clone, Debug)]
pub struct Device {
    pub id: DeviceId,
    pub mac: Option<MacAddr>,
    pub ips: Vec<IpAddr>,
    pub hostname: Option<(String, NameSource)>,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DeviceRole {
    ThisHost,
    Gateway,
    Lan,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSnapshot {
    /// Same string as the `NodeRef` used in traffic events ("self", "gateway", "dev:3").
    pub node: String,
    pub role: DeviceRole,
    /// Hostname if one was announced, else the primary IP (or MAC).
    pub label: String,
    pub hostname: Option<String>,
    pub hostname_source: Option<NameSource>,
    /// Manufacturer from the MAC prefix (IEEE registry).
    pub vendor: Option<&'static str>,
    pub mac: Option<String>,
    pub ips: Vec<String>,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceEvent {
    New { node: NodeRef, label: String, mac: Option<MacAddr> },
    /// A second MAC was seen using an IP already associated with another device.
    DuplicateIp { ip: IpAddr, first: MacAddr, second: MacAddr, node: NodeRef },
}

#[derive(Debug)]
pub struct DeviceTable {
    networks: Vec<LocalNetwork>,
    devices: Vec<Device>,
    by_mac: HashMap<MacAddr, DeviceId>,
    by_ip: HashMap<IpAddr, DeviceId>,
    gateway_mac: Option<MacAddr>,
    /// Unicast off-link frames seen per next-hop MAC; the majority is the gateway.
    gateway_votes: HashMap<MacAddr, u64>,
    max_devices: usize,
    untracked: u64,
    events: Vec<DeviceEvent>,
}

impl DeviceTable {
    pub fn new(networks: Vec<LocalNetwork>, max_devices: usize) -> Self {
        Self {
            networks,
            devices: Vec::new(),
            by_mac: HashMap::new(),
            by_ip: HashMap::new(),
            gateway_mac: None,
            gateway_votes: HashMap::new(),
            max_devices,
            untracked: 0,
            events: Vec::new(),
        }
    }

    pub fn take_events(&mut self) -> Vec<DeviceEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn is_on_link(&self, ip: &IpAddr) -> bool {
        is_link_local(ip) || self.networks.iter().any(|n| n.contains(ip))
    }

    fn is_broadcast_ip(&self, ip: &IpAddr) -> bool {
        ip.is_multicast()
            || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
            || self.networks.iter().any(|n| n.is_broadcast(ip))
    }

    fn is_off_link_unicast(&self, ip: &IpAddr, local: &LocalHost) -> bool {
        !local.is_local_ip(ip) && !self.is_on_link(ip) && !self.is_broadcast_ip(ip) && !ip.is_unspecified()
    }

    pub fn gateway_mac(&self) -> Option<MacAddr> {
        self.gateway_mac
    }

    fn vote_gateway(&mut self, mac: MacAddr) {
        let votes = self.gateway_votes.entry(mac).or_insert(0);
        *votes += 1;
        let votes = *votes;
        let current = self.gateway_mac.and_then(|m| self.gateway_votes.get(&m)).copied().unwrap_or(0);
        if votes > current {
            self.gateway_mac = Some(mac);
        }
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Resolves the packet's endpoints to map nodes and updates device counters.
    pub fn observe(&mut self, pkt: &ParsedPacket, direction: Direction, local: &LocalHost, ts: u64) -> (NodeRef, NodeRef) {
        let eth = pkt.ethernet.as_ref();
        let (src_ip, dst_ip) = (pkt.src_ip(), pkt.dst_ip());

        if let Some(eth) = eth {
            // Only unicast frames exchanged with this host count: a LAN device broadcasting from a
            // foreign (misconfigured) address must not be mistaken for the router.
            let unicast = !eth.dst.is_broadcast() && !eth.dst.is_multicast();
            let next_hop = match (direction, src_ip, dst_ip) {
                (Direction::Outgoing, _, Some(d)) if unicast && self.is_off_link_unicast(&d, local) => Some(eth.dst),
                (Direction::Incoming, Some(s), _) if unicast && self.is_off_link_unicast(&s, local) => Some(eth.src),
                _ => None,
            };
            if let Some(mac) = next_hop {
                self.vote_gateway(mac);
            }
        }

        let bytes = u64::from(pkt.wire_len);
        let dst_group_frame = eth.is_some_and(|e| e.dst.is_broadcast() || e.dst.is_multicast());
        let src = self.node_for(src_ip, eth.map(|e| e.src), local, ts, bytes, true);
        let dst = if dst_group_frame {
            NodeRef::Broadcast
        } else {
            self.node_for(dst_ip, eth.map(|e| e.dst), local, ts, bytes, false)
        };
        (src, dst)
    }

    fn node_for(&mut self, ip: Option<IpAddr>, mac: Option<MacAddr>, local: &LocalHost, ts: u64, bytes: u64, is_src: bool) -> NodeRef {
        let unicast_mac = mac.filter(|m| !m.is_broadcast() && !m.is_multicast() && *m != MacAddr::default());
        match ip {
            Some(ip) if local.is_local_ip(&ip) => NodeRef::SelfHost,
            Some(ip) if self.is_broadcast_ip(&ip) => NodeRef::Broadcast,
            // DHCP clients send from 0.0.0.0 before they have an address.
            Some(ip) if ip.is_unspecified() => match unicast_mac {
                Some(m) => self.device(Some(m), None, ts, bytes, is_src),
                None => NodeRef::Broadcast,
            },
            Some(ip) if self.is_on_link(&ip) => self.device(unicast_mac, Some(ip), ts, bytes, is_src),
            Some(_) => NodeRef::Internet,
            None => match (mac, unicast_mac) {
                (_, Some(m)) if local.is_local_mac(&m) => NodeRef::SelfHost,
                (_, Some(m)) => self.device(Some(m), None, ts, bytes, is_src),
                (Some(_), None) => NodeRef::Broadcast,
                (None, None) => NodeRef::Internet,
            },
        }
    }

    fn device(&mut self, mac: Option<MacAddr>, ip: Option<IpAddr>, ts: u64, bytes: u64, is_src: bool) -> NodeRef {
        // With a MAC, identity is the MAC alone: two hosts may claim the same IP (proxy ARP,
        // extenders, misconfiguration) and must not be merged. IP lookup is only for MAC-less links.
        let existing = match (mac, ip) {
            (Some(m), _) => self.by_mac.get(&m).copied(),
            (None, Some(i)) => self.by_ip.get(&i).copied(),
            (None, None) => None,
        };
        let id = match existing {
            Some(id) => id,
            None if self.devices.len() >= self.max_devices => {
                self.untracked += 1;
                return NodeRef::Lan;
            }
            None => {
                let id = self.devices.len() as DeviceId;
                self.devices.push(Device {
                    id,
                    mac,
                    ips: Vec::new(),
                    hostname: None,
                    first_seen_us: ts,
                    last_seen_us: ts,
                    packets_sent: 0,
                    packets_received: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                });
                if let Some(m) = mac {
                    self.by_mac.insert(m, id);
                }
                let label = ip.map(|i| i.to_string()).or_else(|| mac.map(|m| m.to_string())).unwrap_or_default();
                self.events.push(DeviceEvent::New { node: NodeRef::Device(id), label, mac });
                id
            }
        };

        if let (Some(ip), Some(m)) = (ip, mac) {
            if let Some(&other) = self.by_ip.get(&ip) {
                if let Some(first) = self.devices[other as usize].mac.filter(|f| other != id && *f != m) {
                    self.events.push(DeviceEvent::DuplicateIp { ip, first, second: m, node: NodeRef::Device(id) });
                }
            }
        }

        let dev = &mut self.devices[id as usize];
        if let Some(ip) = ip {
            if !dev.ips.contains(&ip) && dev.ips.len() < MAX_IPS_PER_DEVICE {
                dev.ips.push(ip);
                self.by_ip.insert(ip, id);
            }
        }
        if dev.mac.is_none() {
            if let Some(m) = mac {
                dev.mac = Some(m);
                self.by_mac.insert(m, id);
            }
        }
        dev.last_seen_us = dev.last_seen_us.max(ts);
        if is_src {
            dev.packets_sent += 1;
            dev.bytes_sent += bytes;
        } else {
            dev.packets_received += 1;
            dev.bytes_received += bytes;
        }

        if dev.mac.is_some() && dev.mac == self.gateway_mac {
            NodeRef::Gateway
        } else {
            NodeRef::Device(id)
        }
    }

    pub fn count_active(&self, now_us: u64, window_us: u64) -> usize {
        self.devices.iter().filter(|d| now_us.saturating_sub(d.last_seen_us) <= window_us).count()
    }

    /// Learns names hosts announce about themselves. Call after `observe` for the same packet.
    pub fn learn_names(&mut self, pkt: &ParsedPacket) {
        if let Some(d) = &pkt.dhcp {
            let from_client = d.message_type.is_some_and(|t| DHCP_CLIENT_MESSAGES.contains(&t));
            if let (true, Some(mac), Some(name)) = (from_client, d.client_mac, d.hostname.as_deref()) {
                if let Some(&id) = self.by_mac.get(&mac) {
                    self.set_name(id, name, NameSource::Dhcp);
                }
            }
        }
        if let Some(dns) = pkt.dns.as_ref().filter(|d| d.is_response) {
            let source = match pkt.app {
                AppProtocol::Mdns => Some(NameSource::Mdns),
                AppProtocol::Llmnr => Some(NameSource::Llmnr),
                _ => None,
            };
            for a in dns.answers.iter().filter(|_| source.is_some()) {
                let name = a.name.strip_suffix(".local").unwrap_or(&a.name);
                if let (true, Some(&id), Some(src)) = (self.is_on_link(&a.address), self.by_ip.get(&a.address), source) {
                    self.set_name(id, name, src);
                }
            }
        }
        if let Some(nb) = &pkt.netbios {
            let registers = !nb.is_response && NBNS_OWNER_OPCODES.contains(&nb.opcode);
            let answers_for_itself = nb.is_response && nb.opcode == 0 && nb.rcode == 0 && nb.address.map(IpAddr::V4) == pkt.src_ip();
            let host_name = !nb.group && matches!(nb.suffix, Some(NBNS_WORKSTATION | NBNS_SERVER));
            if let (true, true, Some(name), Some(addr)) = (registers || answers_for_itself, host_name, nb.name.as_deref(), nb.address) {
                if let Some(&id) = self.by_ip.get(&IpAddr::V4(addr)) {
                    self.set_name(id, name, NameSource::Netbios);
                }
            }
        }
    }

    fn set_name(&mut self, id: DeviceId, name: &str, source: NameSource) {
        let name = name.trim_end_matches('.');
        if name.is_empty() || name.contains('?') {
            return;
        }
        let dev = &mut self.devices[id as usize];
        if !dev.hostname.as_ref().is_some_and(|(_, s)| source < *s) {
            dev.hostname = Some((name.to_owned(), source));
        }
    }

    pub fn snapshots(&self) -> Vec<DeviceSnapshot> {
        let mut snaps: Vec<DeviceSnapshot> = self
            .devices
            .iter()
            .map(|d| {
                let gateway = d.mac.is_some() && d.mac == self.gateway_mac;
                let primary = d.ips.iter().find(|ip| ip.is_ipv4()).or(d.ips.first());
                let label = match (&d.hostname, primary, d.mac) {
                    (Some((name, _)), _, _) => name.clone(),
                    (None, Some(ip), _) => ip.to_string(),
                    (None, None, Some(mac)) => mac.to_string(),
                    (None, None, None) => format!("device {}", d.id),
                };
                DeviceSnapshot {
                    node: if gateway { NodeRef::Gateway.to_string() } else { NodeRef::Device(d.id).to_string() },
                    role: if gateway { DeviceRole::Gateway } else { DeviceRole::Lan },
                    label,
                    hostname: d.hostname.as_ref().map(|(n, _)| n.clone()),
                    hostname_source: d.hostname.as_ref().map(|(_, s)| *s),
                    vendor: d.mac.as_ref().and_then(oui::vendor),
                    mac: d.mac.map(|m| m.to_string()),
                    ips: d.ips.iter().map(ToString::to_string).collect(),
                    packets_sent: d.packets_sent,
                    packets_received: d.packets_received,
                    bytes_sent: d.bytes_sent,
                    bytes_received: d.bytes_received,
                    first_seen_us: d.first_seen_us,
                    last_seen_us: d.last_seen_us,
                }
            })
            .collect();

        // Hosts claiming the same IP get a MAC suffix so their labels stay distinguishable.
        let mut seen: HashMap<String, usize> = HashMap::new();
        for s in &snaps {
            *seen.entry(s.label.clone()).or_default() += 1;
        }
        for s in &mut snaps {
            if seen[&s.label] > 1 {
                if let Some(mac) = &s.mac {
                    s.label = format!("{} ({})", s.label, &mac[mac.len().saturating_sub(5)..]);
                }
            }
        }
        snaps
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::frame::LinkType;
    use crate::parser::parse_frame;
    use crate::synth::{self, Endpoints};

    const ME: Ipv4Addr = Ipv4Addr::new(10, 10, 10, 115);
    const ROUTER: Ipv4Addr = Ipv4Addr::new(10, 10, 10, 1);
    const PEER: Ipv4Addr = Ipv4Addr::new(10, 10, 10, 50);
    const REMOTE: Ipv4Addr = Ipv4Addr::new(142, 250, 1, 1);
    const MY_MAC: MacAddr = MacAddr([2, 0, 0, 0, 0, 0x73]);
    const GW_MAC: MacAddr = MacAddr([2, 0, 0, 0, 0, 1]);
    const PEER_MAC: MacAddr = MacAddr([2, 0, 0, 0, 0, 0x50]);

    fn net() -> LocalNetwork {
        LocalNetwork::from_netmask(IpAddr::V4(ME), IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))).unwrap()
    }

    fn setup() -> (DeviceTable, LocalHost) {
        (DeviceTable::new(vec![net()], 8), LocalHost::new([IpAddr::V4(ME)], [IpAddr::V4(Ipv4Addr::new(10, 10, 10, 255))]))
    }

    fn ep(src_mac: MacAddr, src: Ipv4Addr, dst_mac: MacAddr, dst: Ipv4Addr) -> Endpoints {
        Endpoints { src_mac, dst_mac, src_ip: IpAddr::V4(src), dst_ip: IpAddr::V4(dst) }
    }

    fn observe(t: &mut DeviceTable, h: &mut LocalHost, frame: Vec<u8>) -> (NodeRef, NodeRef) {
        let pkt = parse_frame(LinkType::Ethernet, &frame, frame.len() as u32);
        let cast = h.cast(&pkt);
        let dir = h.direction(&pkt, cast);
        let nodes = t.observe(&pkt, dir, h, 0);
        t.learn_names(&pkt);
        nodes
    }

    fn label_of(t: &DeviceTable, mac: MacAddr) -> (String, Option<NameSource>) {
        let s = t.snapshots().into_iter().find(|s| s.mac.as_deref() == Some(mac.to_string().as_str())).unwrap();
        (s.label, s.hostname_source)
    }

    #[test]
    fn devices_are_named_from_their_own_announcements() {
        let (mut t, mut h) = setup();
        let bcast = |mac| ep(mac, PEER, MacAddr::BROADCAST, Ipv4Addr::BROADCAST);
        let mdns_group = |mac| ep(mac, PEER, MacAddr([0x01, 0x00, 0x5e, 0, 0, 0xfb]), Ipv4Addr::new(224, 0, 0, 251));

        observe(&mut t, &mut h, synth::udp_frame(&bcast(PEER_MAC), 137, 137, &synth::nbns_registration("desktop-7", PEER)));
        assert_eq!(label_of(&t, PEER_MAC), ("DESKTOP-7".into(), Some(NameSource::Netbios)));

        observe(&mut t, &mut h, synth::udp_frame(&mdns_group(PEER_MAC), 5353, 5353, &synth::mdns_announcement("Studio-Mac.local", PEER)));
        assert_eq!(label_of(&t, PEER_MAC), ("Studio-Mac".into(), Some(NameSource::Mdns)), "mDNS outranks NetBIOS");

        let dhcp = ep(PEER_MAC, Ipv4Addr::UNSPECIFIED, MacAddr::BROADCAST, Ipv4Addr::BROADCAST);
        observe(&mut t, &mut h, synth::udp_frame(&dhcp, 68, 67, &synth::dhcp_request(PEER_MAC, "studio")));
        assert_eq!(label_of(&t, PEER_MAC), ("studio".into(), Some(NameSource::Dhcp)));

        // A weaker source cannot overwrite the DHCP name.
        observe(&mut t, &mut h, synth::udp_frame(&bcast(PEER_MAC), 137, 137, &synth::nbns_registration("other", PEER)));
        assert_eq!(label_of(&t, PEER_MAC).0, "studio");
    }

    #[test]
    fn vendor_comes_from_the_mac_prefix() {
        let (mut t, mut h) = setup();
        let tp_link = MacAddr([0x9c, 0xa2, 0xf4, 0x00, 0x00, 0x10]);
        observe(&mut t, &mut h, synth::arp_request_frame(tp_link, ROUTER, ME));
        observe(&mut t, &mut h, synth::arp_request_frame(PEER_MAC, PEER, ME));
        let snaps = t.snapshots();
        assert_eq!(snaps[0].vendor, Some("TP-Link Systems"));
        assert_eq!(snaps[1].vendor, Some(crate::oui::PRIVATE_ADDRESS), "02:.. is locally administered");
    }

    #[test]
    fn netmask_prefix_and_membership() {
        let n = net();
        assert_eq!(n.prefix, 24);
        assert!(n.contains(&IpAddr::V4(PEER)));
        assert!(!n.contains(&IpAddr::V4(REMOTE)));
        assert!(n.is_broadcast(&IpAddr::V4(Ipv4Addr::new(10, 10, 10, 255))));
        let v6 = LocalNetwork::from_netmask("2001:db8::5".parse().unwrap(), "ffff:ffff:ffff:ffff::".parse().unwrap()).unwrap();
        assert_eq!(v6.prefix, 64);
        assert!(v6.contains(&"2001:db8::99".parse().unwrap()));
    }

    #[test]
    fn internet_traffic_goes_via_learned_gateway() {
        let (mut t, mut h) = setup();
        let out = observe(&mut t, &mut h, synth::tcp_frame(&ep(MY_MAC, ME, GW_MAC, REMOTE), 5000, 443, 1, 1, 0x10, b""));
        assert_eq!(out, (NodeRef::SelfHost, NodeRef::Internet));
        assert_eq!(t.gateway_mac(), Some(GW_MAC));
        let dns = observe(&mut t, &mut h, synth::udp_frame(&ep(GW_MAC, ROUTER, MY_MAC, ME), 53, 5000, b""));
        assert_eq!(dns, (NodeRef::Gateway, NodeRef::SelfHost));
        assert_eq!(t.snapshots()[0].role, DeviceRole::Gateway);
    }

    #[test]
    fn hosts_sharing_an_ip_stay_separate_and_gateway_resolves() {
        let (mut t, mut h) = setup();
        let impostor = MacAddr([0x50, 0x91, 0xe3, 0x00, 0x00, 0xc2]);
        observe(&mut t, &mut h, synth::arp_request_frame(impostor, ROUTER, ME));
        observe(&mut t, &mut h, synth::tcp_frame(&ep(MY_MAC, ME, GW_MAC, REMOTE), 5000, 443, 1, 1, 0x10, b""));
        let dns = observe(&mut t, &mut h, synth::udp_frame(&ep(GW_MAC, ROUTER, MY_MAC, ME), 53, 5000, b""));
        assert_eq!(dns.0, NodeRef::Gateway);
        assert_eq!(t.len(), 2);
        assert!(t.take_events().iter().any(|e| matches!(e, DeviceEvent::DuplicateIp { second, .. } if *second == GW_MAC)));
        let labels: Vec<String> = t.snapshots().into_iter().map(|s| s.label).collect();
        assert_eq!(labels, vec!["10.10.10.1 (00:c2)", "10.10.10.1 (00:01)"]);
    }

    #[test]
    fn foreign_broadcaster_is_not_the_gateway() {
        let (mut t, mut h) = setup();
        for _ in 0..3 {
            observe(&mut t, &mut h, synth::tcp_frame(&ep(MY_MAC, ME, GW_MAC, REMOTE), 5000, 443, 1, 1, 0x10, b""));
        }
        let odd = ep(PEER_MAC, Ipv4Addr::new(192, 168, 50, 7), MacAddr::BROADCAST, Ipv4Addr::BROADCAST);
        for _ in 0..10 {
            observe(&mut t, &mut h, synth::udp_frame(&odd, 29810, 29810, b""));
        }
        assert_eq!(t.gateway_mac(), Some(GW_MAC));
        // A single stray unicast frame cannot outvote the established gateway either.
        observe(&mut t, &mut h, synth::tcp_frame(&ep(PEER_MAC, REMOTE, MY_MAC, ME), 443, 5000, 1, 1, 0x10, b""));
        assert_eq!(t.gateway_mac(), Some(GW_MAC));
    }

    #[test]
    fn lan_devices_broadcasts_and_arp() {
        let (mut t, mut h) = setup();
        let ssh = observe(&mut t, &mut h, synth::tcp_frame(&ep(MY_MAC, ME, PEER_MAC, PEER), 5000, 22, 1, 1, 0x10, b""));
        assert_eq!(ssh, (NodeRef::SelfHost, NodeRef::Device(0)));
        let mdns = observe(
            &mut t,
            &mut h,
            synth::udp_frame(&ep(PEER_MAC, PEER, MacAddr([0x01, 0, 0x5e, 0, 0, 0xfb]), Ipv4Addr::new(224, 0, 0, 251)), 5353, 5353, b""),
        );
        assert_eq!(mdns, (NodeRef::Device(0), NodeRef::Broadcast));
        // An ARP request must not invent a device for the address being asked about.
        let arp = observe(&mut t, &mut h, synth::arp_request_frame(PEER_MAC, PEER, Ipv4Addr::new(10, 10, 10, 77)));
        assert_eq!(arp, (NodeRef::Device(0), NodeRef::Broadcast));
        assert_eq!(t.len(), 1);
        let snap = &t.snapshots()[0];
        assert_eq!(snap.label, "10.10.10.50");
        assert_eq!(snap.packets_sent, 2);
        assert_eq!(snap.packets_received, 1);
    }

    #[test]
    fn capacity_overflow_maps_to_lan() {
        let mut t = DeviceTable::new(vec![net()], 1);
        let mut h = LocalHost::new([IpAddr::V4(ME)], []);
        observe(&mut t, &mut h, synth::udp_frame(&ep(PEER_MAC, PEER, MY_MAC, ME), 1, 2, b""));
        let other = observe(&mut t, &mut h, synth::udp_frame(&ep(MacAddr([2, 0, 0, 0, 0, 9]), Ipv4Addr::new(10, 10, 10, 9), MY_MAC, ME), 1, 2, b""));
        assert_eq!(other.0, NodeRef::Lan);
    }
}
