//! The packet-processing engine: RawFrame → parse → classify → direction → flow → stats → event.
//! Single-threaded and deterministic; threading lives in `pipeline`.

use std::net::IpAddr;

use crate::alerts::{Alert, AlertEngine, RETRANSMISSION_MIN_PACKETS, RETRANSMISSION_RATIO};
use crate::devices::{DeviceEvent, DeviceRole, DeviceSnapshot, DeviceTable, LocalNetwork, NodeRef};
use crate::direction::LocalHost;
use crate::events::{EventBatcher, TrafficBatch, TrafficEvent};
use crate::flows::{FlowSnapshot, FlowTable, FlowTableConfig, SniReassembler};
use crate::frame::{LinkType, RawFrame};
use crate::names::NameTable;
use crate::packet::{PacketId, PacketRecord, ParsedPacket};
use crate::parser::{classify, parse_frame_with_payload};
use crate::statistics::{StatsSnapshot, TrafficStats};
use crate::store::{FrameBytesStore, PacketStore, FRAME_BYTES_CAPACITY};

/// A flow counts as "active" if it carried a packet within this window.
pub const ACTIVE_FLOW_WINDOW_US: u64 = 10_000_000;
/// A device counts as "active" if it was seen within this window.
pub const ACTIVE_DEVICE_WINDOW_US: u64 = 300_000_000;
const MAX_DEVICES: usize = 256;

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub link: LinkType,
    /// Addresses of the capture interface; they define "this host" for direction.
    pub local_ips: Vec<IpAddr>,
    pub broadcast_ips: Vec<IpAddr>,
    /// On-link subnets of the capture interface; they separate LAN devices from the internet.
    pub local_networks: Vec<LocalNetwork>,
    pub flows: FlowTableConfig,
    pub packet_store_capacity: usize,
    pub max_events_per_batch: usize,
    pub max_aggregates_per_batch: usize,
    /// Keep raw frame bytes for the hex view. Off unless the user explicitly enables it.
    pub payload_capture: bool,
}

impl EngineConfig {
    pub fn new(link: LinkType, local_ips: Vec<IpAddr>, broadcast_ips: Vec<IpAddr>) -> Self {
        Self {
            link,
            local_ips,
            broadcast_ips,
            local_networks: Vec::new(),
            flows: FlowTableConfig::default(),
            packet_store_capacity: 50_000,
            max_events_per_batch: 256,
            max_aggregates_per_batch: 128,
            payload_capture: false,
        }
    }

    pub fn with_networks(mut self, networks: Vec<LocalNetwork>) -> Self {
        self.local_networks = networks;
        self
    }
}

#[derive(Debug)]
pub struct Engine {
    link: LinkType,
    local: LocalHost,
    local_ips: Vec<IpAddr>,
    flows: FlowTable,
    names: NameTable,
    sni: SniReassembler,
    devices: DeviceTable,
    alerts: AlertEngine,
    stats: TrafficStats,
    batcher: EventBatcher,
    store: PacketStore,
    frame_bytes: Option<FrameBytesStore>,
    next_packet_id: PacketId,
}

impl Engine {
    pub fn new(cfg: EngineConfig) -> Self {
        Self {
            link: cfg.link,
            local: LocalHost::new(cfg.local_ips.clone(), cfg.broadcast_ips),
            local_ips: cfg.local_ips,
            flows: FlowTable::new(cfg.flows),
            names: NameTable::default(),
            sni: SniReassembler::default(),
            devices: DeviceTable::new(cfg.local_networks, MAX_DEVICES),
            alerts: AlertEngine::default(),
            stats: TrafficStats::default(),
            batcher: EventBatcher::new(cfg.max_events_per_batch, cfg.max_aggregates_per_batch),
            store: PacketStore::new(cfg.packet_store_capacity),
            frame_bytes: cfg.payload_capture.then(|| FrameBytesStore::new(FRAME_BYTES_CAPACITY)),
            next_packet_id: 1,
        }
    }

    pub fn link(&self) -> LinkType {
        self.link
    }

    pub fn ingest(&mut self, frame: &RawFrame) -> PacketId {
        let id = self.next_packet_id;
        self.next_packet_id += 1;
        let ts = frame.timestamp_us;

        let (packet, payload) = parse_frame_with_payload(self.link, &frame.data, frame.wire_len);
        let class = classify(&packet);
        let cast = self.local.cast(&packet);
        let direction = self.local.direction(&packet, cast);
        let flow_id = self.flows.observe(&packet, class, direction, ts);
        self.names.observe(&packet, ts);
        if let Some(id) = flow_id {
            if let Some(sni) = self.sni.observe(id, &packet, payload, ts) {
                self.flows.set_in_band_hostname(id, sni);
            }
            let names = &self.names;
            self.flows.label_from_dns(id, |ip| names.lookup(ip));
        }
        let (src_node, dst_node) = self.devices.observe(&packet, direction, &self.local, ts);
        self.devices.learn_names(&packet);
        self.stats.record(ts, packet.wire_len, direction, class, packet.issue.is_some());
        self.update_alerts(&packet, ts);

        let host = flow_id
            .and_then(|f| self.flows.get(f))
            .and_then(|f| f.hostname.clone())
            .or_else(|| packet.hostname().map(str::to_owned));
        let (src, dst) = endpoints(&packet);
        self.batcher.push(TrafficEvent {
            packet_id: id,
            flow_id,
            timestamp_us: ts,
            direction,
            cast,
            class,
            transport: packet.transport,
            src_node,
            dst_node,
            src,
            dst,
            src_port: packet.src_port(),
            dst_port: packet.dst_port(),
            host,
            length: packet.wire_len,
            packets: 1,
            bytes: u64::from(packet.wire_len),
        });
        self.store.insert(PacketRecord { id, flow_id, timestamp_us: ts, direction, cast, class, packet });
        if let Some(bytes) = self.frame_bytes.as_mut() {
            bytes.insert(id, &frame.data);
        }
        id
    }

    /// Enabling starts keeping bytes of new packets; disabling discards everything kept so far.
    pub fn set_payload_capture(&mut self, enabled: bool) {
        match (enabled, self.frame_bytes.is_some()) {
            (true, false) => self.frame_bytes = Some(FrameBytesStore::new(FRAME_BYTES_CAPACITY)),
            (false, true) => self.frame_bytes = None,
            _ => {}
        }
    }

    pub fn payload_capture(&self) -> bool {
        self.frame_bytes.is_some()
    }

    pub fn packet_bytes(&self, id: PacketId) -> Option<&[u8]> {
        self.frame_bytes.as_ref()?.get(id)
    }

    fn update_alerts(&mut self, packet: &ParsedPacket, ts: u64) {
        let devices = &self.devices;
        self.alerts.observe_packet(packet, ts, &|ip| devices.is_on_link(ip));
        for event in self.devices.take_events() {
            match event {
                DeviceEvent::New { node, label, mac } => self.alerts.new_device(ts, &label, mac, node.to_string()),
                DeviceEvent::DuplicateIp { ip, first, second, node } => self.alerts.duplicate_ip(ts, ip, (first, second), node.to_string()),
            }
        }
    }

    pub fn has_pending_events(&self) -> bool {
        !self.batcher.is_empty()
    }

    pub fn take_batch(&mut self) -> TrafficBatch {
        self.batcher.take()
    }

    pub fn take_alerts(&mut self) -> Vec<Alert> {
        self.alerts.take()
    }

    /// Expires idle flows and runs periodic detections; returns how many flows were removed.
    pub fn maintain(&mut self, now_us: u64) -> usize {
        for f in self.flows.iter() {
            let Some(retrans) = f.tcp.as_ref().map(|t| t.retransmissions) else { continue };
            let packets = f.packets();
            if packets >= RETRANSMISSION_MIN_PACKETS && f64::from(retrans) / packets as f64 >= RETRANSMISSION_RATIO {
                let description = format!("{} ↔ {}", f.initiator, f.responder);
                self.alerts.retransmissions(now_us, f.id, &description, retrans, packets);
            }
        }
        self.alerts.maintain(now_us);
        self.sni.expire(now_us);
        self.flows.expire(now_us)
    }

    pub fn stats(&self, now_us: u64) -> StatsSnapshot {
        let mut counts = self.flows.counts(now_us, ACTIVE_FLOW_WINDOW_US);
        counts.active_devices = self.devices.count_active(now_us, ACTIVE_DEVICE_WINDOW_US);
        self.stats.snapshot(now_us, counts)
    }

    /// This host first, then LAN devices (gateway included) in discovery order.
    pub fn devices(&self) -> Vec<DeviceSnapshot> {
        let (packets_in, packets_out, bytes_in, bytes_out) = self.stats.host_totals();
        let ips: Vec<String> = self.local_ips.iter().map(ToString::to_string).collect();
        let this_host = DeviceSnapshot {
            node: NodeRef::SelfHost.to_string(),
            role: DeviceRole::ThisHost,
            label: self.local_ips.iter().find(|ip| ip.is_ipv4()).or(self.local_ips.first()).map_or("this host".into(), ToString::to_string),
            hostname: None,
            hostname_source: None,
            vendor: None,
            mac: None,
            ips,
            packets_sent: packets_out,
            packets_received: packets_in,
            bytes_sent: bytes_out,
            bytes_received: bytes_in,
            first_seen_us: 0,
            last_seen_us: self.stats.latest_us(),
        };
        std::iter::once(this_host).chain(self.devices.snapshots()).collect()
    }

    /// Timestamp of the newest packet seen (packet time).
    pub fn latest_packet_us(&self) -> u64 {
        self.stats.latest_us()
    }

    pub fn packet(&self, id: PacketId) -> Option<&PacketRecord> {
        self.store.get(id)
    }

    pub fn flow(&self, id: u64) -> Option<FlowSnapshot> {
        self.flows.get(id).map(|f| f.snapshot())
    }

    pub fn recent_flows(&self, now_us: u64, limit: usize) -> Vec<FlowSnapshot> {
        self.flows.recent(now_us, ACTIVE_FLOW_WINDOW_US, limit)
    }
}

fn endpoints(p: &ParsedPacket) -> (String, String) {
    match (p.src_ip(), p.dst_ip(), &p.ethernet) {
        (Some(s), Some(d), _) => (s.to_string(), d.to_string()),
        (_, _, Some(eth)) => (eth.src.to_string(), eth.dst.to_string()),
        _ => ("unknown".into(), "unknown".into()),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::flows::HostnameSource;
    use crate::packet::{Direction, MacAddr, TcpFlags, TrafficClass};
    use crate::synth::{self, Endpoints};

    const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);

    fn engine() -> Engine {
        Engine::new(EngineConfig::new(LinkType::Ethernet, vec![IpAddr::V4(ME)], vec![]))
    }

    fn frame(bytes: Vec<u8>, ts: u64) -> RawFrame {
        RawFrame { timestamp_us: ts, wire_len: bytes.len() as u32, data: bytes }
    }

    fn ep() -> Endpoints {
        Endpoints {
            src_mac: MacAddr([2, 0, 0, 0, 0, 5]),
            dst_mac: MacAddr([2, 0, 0, 0, 0, 1]),
            src_ip: IpAddr::V4(ME),
            dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        }
    }

    #[test]
    fn end_to_end_packet_to_event() {
        let mut e = engine();
        let q = synth::udp_frame(&ep(), 50000, 53, &synth::dns_query(7, "packet.city", 1));
        let a = synth::udp_frame(&ep().reversed(), 53, 50000, &synth::dns_response_a(7, "packet.city", Ipv4Addr::new(1, 2, 3, 4)));
        let id1 = e.ingest(&frame(q, 1_000_000));
        let id2 = e.ingest(&frame(a, 1_020_000));

        let batch = e.take_batch();
        assert_eq!(batch.events.len(), 2);
        let (out, inc) = (&batch.events[0], &batch.events[1]);
        assert_eq!(out.direction, Direction::Outgoing);
        assert_eq!(inc.direction, Direction::Incoming);
        assert_eq!(out.class, TrafficClass::Dns);
        assert_eq!(out.flow_id, inc.flow_id);
        assert_eq!(out.host.as_deref(), Some("packet.city"));
        assert_eq!(out.src, "10.0.0.5");
        assert_eq!(out.src_node, NodeRef::SelfHost);
        assert_eq!(out.dst_node, NodeRef::Internet);

        let rec = e.packet(id1).unwrap();
        assert_eq!(rec.packet.dns.as_ref().unwrap().query_name.as_deref(), Some("packet.city"));
        assert!(e.packet(id2).is_some());
        let flow = e.flow(out.flow_id.unwrap()).unwrap();
        assert_eq!(flow.packets, 2);
        assert_eq!(flow.direction, Direction::Outgoing);
    }

    #[test]
    fn stats_and_connections() {
        let mut e = engine();
        let c = ep();
        let s = c.reversed();
        e.ingest(&frame(synth::tcp_frame(&c, 40000, 443, 1, 0, TcpFlags::SYN, b""), 5_000_000));
        e.ingest(&frame(synth::tcp_frame(&s, 443, 40000, 9, 2, TcpFlags::SYN | TcpFlags::ACK, b""), 5_100_000));
        e.ingest(&frame(synth::tcp_frame(&c, 40000, 443, 2, 10, TcpFlags::ACK, b""), 5_200_000));
        let st = e.stats(7_000_000);
        assert_eq!(st.total_packets, 3);
        assert_eq!(st.counts.active_connections, 1);
        assert_eq!(st.counts.tracked_flows, 1);
        assert_eq!(e.recent_flows(7_000_000, 10).len(), 1);
    }

    fn ingest_all(e: &mut Engine, frames: Vec<Vec<u8>>) -> u64 {
        let mut flow = 0;
        for (i, f) in frames.into_iter().enumerate() {
            let id = e.ingest(&frame(f, 1_000_000 + i as u64 * 1000));
            flow = e.packet(id).and_then(|r| r.flow_id).unwrap_or(flow);
        }
        flow
    }

    fn hostname(e: &Engine, flow: u64) -> (Option<String>, Option<HostnameSource>) {
        let f = e.flow(flow).unwrap();
        (f.hostname, f.hostname_source)
    }

    #[test]
    fn frame_bytes_are_kept_only_while_enabled() {
        let mut e = engine();
        let f = synth::udp_frame(&ep(), 5000, 53, &synth::dns_query(1, "a.example", 1));
        let off = e.ingest(&frame(f.clone(), 1));
        assert!(e.packet_bytes(off).is_none(), "off by default");
        e.set_payload_capture(true);
        let on = e.ingest(&frame(f.clone(), 2));
        assert_eq!(e.packet_bytes(on), Some(&f[..]));
        e.set_payload_capture(false);
        assert!(e.packet_bytes(on).is_none(), "disabling discards kept bytes");
    }

    #[test]
    fn sni_split_across_segments_is_reassembled() {
        let mut e = engine();
        let c = ep();
        let hello = synth::tls_client_hello_padded("split.example", 1800);
        let (a, b) = hello.split_at(1400);
        let psh = TcpFlags::ACK | TcpFlags::PSH;
        let flow = ingest_all(&mut e, vec![synth::tcp_frame(&c, 40000, 443, 1, 1, TcpFlags::SYN, b""), synth::tcp_frame(&c, 40000, 443, 2, 1, psh, a)]);
        assert_eq!(hostname(&e, flow).0, None, "SNI is not in the first segment");

        // A retransmission of the first segment is ignored; the next in-order segment completes it.
        ingest_all(&mut e, vec![synth::tcp_frame(&c, 40000, 443, 2, 1, psh, a), synth::tcp_frame(&c, 40000, 443, 2 + a.len() as u32, 1, psh, b)]);
        assert_eq!(hostname(&e, flow), (Some("split.example".into()), Some(HostnameSource::InBand)));
        assert_eq!(e.sni.pending(), 0, "buffer released");
    }

    #[test]
    fn split_hello_with_a_gap_is_abandoned_without_a_name() {
        let mut e = engine();
        let c = ep();
        let hello = synth::tls_client_hello_padded("gap.example", 3000);
        let psh = TcpFlags::ACK | TcpFlags::PSH;
        let (a, rest) = hello.split_at(1400);
        let (_lost, b) = rest.split_at(1400);
        let flow = ingest_all(&mut e, vec![synth::tcp_frame(&c, 40001, 443, 1, 1, psh, a), synth::tcp_frame(&c, 40001, 443, 2801, 1, psh, b)]);
        assert_eq!(hostname(&e, flow).0, None);
        e.maintain(60_000_000);
        assert_eq!(e.sni.pending(), 0, "stale attempt expires");
    }

    #[test]
    fn dns_answers_label_flows_and_in_band_names_win() {
        let mut e = engine();
        let server = Ipv4Addr::new(203, 0, 113, 7);
        let resolver = ep();
        let to_server = Endpoints { dst_ip: IpAddr::V4(server), ..ep() };
        ingest_all(
            &mut e,
            vec![
                synth::udp_frame(&resolver, 50000, 53, &synth::dns_query(9, "video.example", 1)),
                synth::udp_frame(&resolver.reversed(), 53, 50000, &synth::dns_response_a(9, "video.example", server)),
            ],
        );
        let quic = ingest_all(&mut e, vec![synth::udp_frame(&to_server, 51000, 443, &[0xC3; 40])]);
        assert_eq!(hostname(&e, quic), (Some("video.example".into()), Some(HostnameSource::DnsAnswer)));

        let tls = ingest_all(
            &mut e,
            vec![
                synth::tcp_frame(&to_server, 41000, 443, 1, 0, TcpFlags::SYN, b""),
                synth::tcp_frame(&to_server, 41000, 443, 2, 1, TcpFlags::ACK | TcpFlags::PSH, &synth::tls_client_hello("cdn.example")),
            ],
        );
        assert_eq!(hostname(&e, tls), (Some("cdn.example".into()), Some(HostnameSource::InBand)));
        assert_eq!(e.take_batch().events.last().unwrap().host.as_deref(), Some("cdn.example"));
    }
}
