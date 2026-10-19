use std::net::IpAddr;

use serde::Serialize;

use super::key::{Endpoint, FlowKey, NetAddr};
use super::tcp::TcpTracker;
use crate::packet::{AppProtocol, Direction, FlowId, ParsedPacket, TcpFlags, TrafficClass};
use crate::threats::ThreatKind;

const US_PER_SEC: f64 = 1_000_000.0;

/// Where a flow's hostname came from. In-band names describe the flow itself; a DNS answer
/// only says that someone resolved a name to this address, so it is an inference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HostnameSource {
    /// TLS SNI, HTTP Host or DNS question in the flow's own packets.
    InBand,
    DnsAnswer,
}

#[derive(Clone, Debug)]
pub struct Flow {
    pub id: FlowId,
    pub key: FlowKey,
    /// Endpoint that sent the first packet (or the SYN side, when a SYN-ACK was seen first).
    pub initiator: Endpoint,
    pub responder: Endpoint,
    /// Direction of the initiator's packets relative to this host.
    pub direction: Direction,
    pub class: TrafficClass,
    pub app: AppProtocol,
    pub hostname: Option<String>,
    pub hostname_source: Option<HostnameSource>,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub packets_fwd: u64,
    pub packets_rev: u64,
    pub bytes_fwd: u64,
    pub bytes_rev: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub tcp: Option<TcpTracker>,
    /// First threat seen on any packet of this flow.
    pub threat: Option<ThreatKind>,
}

/// One packet's contribution to a flow.
pub(super) struct Observation<'a> {
    pub pkt: &'a ParsedPacket,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub class: TrafficClass,
    pub direction: Direction,
    pub ts: u64,
}

impl Flow {
    pub(super) fn new(id: FlowId, key: FlowKey, obs: &Observation) -> Self {
        let pkt = obs.pkt;
        let (initiator, responder, direction) =
            if first_packet_is_from_responder(pkt) { (obs.dst, obs.src, invert(obs.direction)) } else { (obs.src, obs.dst, obs.direction) };
        Self {
            id,
            key,
            initiator,
            responder,
            direction,
            class: obs.class,
            app: pkt.app,
            hostname: None,
            hostname_source: None,
            first_seen_us: obs.ts,
            last_seen_us: obs.ts,
            packets_fwd: 0,
            packets_rev: 0,
            bytes_fwd: 0,
            bytes_rev: 0,
            bytes_out: 0,
            bytes_in: 0,
            tcp: pkt.tcp.as_ref().map(TcpTracker::new),
            threat: None,
        }
    }

    pub(super) fn record(&mut self, obs: &Observation) {
        let Observation { pkt, src, class, direction, ts, .. } = *obs;
        let forward = src == self.initiator;
        let bytes = u64::from(pkt.wire_len);
        if forward {
            self.packets_fwd += 1;
            self.bytes_fwd += bytes;
        } else {
            self.packets_rev += 1;
            self.bytes_rev += bytes;
        }
        match direction {
            Direction::Outgoing => self.bytes_out += bytes,
            Direction::Incoming => self.bytes_in += bytes,
            Direction::Local | Direction::Transit => {}
        }
        self.last_seen_us = self.last_seen_us.max(ts);
        if is_generic(self.class) && !is_generic(class) {
            self.class = class;
            self.app = pkt.app;
        }
        if self.hostname_source != Some(HostnameSource::InBand) {
            if let Some(name) = pkt.hostname() {
                self.set_hostname(name.to_owned(), HostnameSource::InBand);
            }
        }
        if let (Some(tracker), Some(tcp)) = (self.tcp.as_mut(), pkt.tcp.as_ref()) {
            tracker.observe(tcp, forward);
        }
    }

    pub(super) fn set_hostname(&mut self, name: String, source: HostnameSource) {
        self.hostname = Some(name);
        self.hostname_source = Some(source);
    }

    /// IP addresses to try for a DNS-answer label, server side first.
    pub fn label_candidates(&self) -> impl Iterator<Item = IpAddr> {
        [self.responder.addr, self.initiator.addr].into_iter().filter_map(|a| match a {
            NetAddr::Ip(ip) => Some(ip),
            NetAddr::Mac(_) => None,
        })
    }

    pub fn packets(&self) -> u64 {
        self.packets_fwd + self.packets_rev
    }

    pub fn bytes(&self) -> u64 {
        self.bytes_fwd + self.bytes_rev
    }

    pub fn duration_us(&self) -> u64 {
        self.last_seen_us.saturating_sub(self.first_seen_us)
    }

    pub fn snapshot(&self) -> FlowSnapshot {
        let duration_s = self.duration_us() as f64 / US_PER_SEC;
        let packets = self.packets();
        FlowSnapshot {
            id: self.id,
            protocol: self.key.protocol.label(),
            initiator: self.initiator.to_string(),
            responder: self.responder.to_string(),
            direction: self.direction,
            class: self.class,
            app: self.app,
            hostname: self.hostname.clone(),
            hostname_source: self.hostname_source,
            first_seen_us: self.first_seen_us,
            last_seen_us: self.last_seen_us,
            duration_ms: self.duration_us() / 1000,
            packets,
            bytes: self.bytes(),
            packets_fwd: self.packets_fwd,
            packets_rev: self.packets_rev,
            bytes_fwd: self.bytes_fwd,
            bytes_rev: self.bytes_rev,
            bytes_out: self.bytes_out,
            bytes_in: self.bytes_in,
            packet_rate: if duration_s > 0.0 { packets as f64 / duration_s } else { 0.0 },
            avg_packet_size: if packets > 0 { self.bytes() as f64 / packets as f64 } else { 0.0 },
            tcp: self.tcp.clone(),
            threat: self.threat,
        }
    }
}

fn is_generic(class: TrafficClass) -> bool {
    matches!(class, TrafficClass::Tcp | TrafficClass::Udp | TrafficClass::Other)
}

/// IANA dynamic/ephemeral range start (RFC 6335).
const EPHEMERAL_PORT_MIN: u16 = 49152;
const WELL_KNOWN_PORT_MAX: u16 = 1023;

/// Decides who opened the conversation when the first packet we see is not a bare SYN:
/// a SYN-ACK comes from the responder; otherwise a service port talking to a client port does.
fn first_packet_is_from_responder(pkt: &ParsedPacket) -> bool {
    if let Some(tcp) = &pkt.tcp {
        let (syn, ack) = (tcp.flags.has(TcpFlags::SYN), tcp.flags.has(TcpFlags::ACK));
        if syn {
            return ack;
        }
    }
    match (pkt.src_port(), pkt.dst_port()) {
        (Some(sp), Some(dp)) => {
            let src_service = sp <= WELL_KNOWN_PORT_MAX || sp < EPHEMERAL_PORT_MIN;
            let dst_client = dp >= EPHEMERAL_PORT_MIN || (dp > WELL_KNOWN_PORT_MAX && sp <= WELL_KNOWN_PORT_MAX);
            src_service && dst_client
        }
        _ => false,
    }
}

fn invert(d: Direction) -> Direction {
    match d {
        Direction::Incoming => Direction::Outgoing,
        Direction::Outgoing => Direction::Incoming,
        other => other,
    }
}

/// Serializable view of a flow for the inspector and connection list.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowSnapshot {
    pub id: FlowId,
    pub protocol: String,
    pub initiator: String,
    pub responder: String,
    pub direction: Direction,
    pub class: TrafficClass,
    pub app: AppProtocol,
    pub hostname: Option<String>,
    pub hostname_source: Option<HostnameSource>,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub duration_ms: u64,
    pub packets: u64,
    pub bytes: u64,
    pub packets_fwd: u64,
    pub packets_rev: u64,
    pub bytes_fwd: u64,
    pub bytes_rev: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub packet_rate: f64,
    pub avg_packet_size: f64,
    pub tcp: Option<crate::flows::TcpTracker>,
    pub threat: Option<ThreatKind>,
}
