use std::net::{IpAddr, Ipv4Addr};

use super::*;
use crate::frame::LinkType;
use crate::packet::{Direction, MacAddr, ParsedPacket, TcpFlags, TrafficClass};
use crate::parser::{classify, parse_frame};
use crate::synth::{self, Endpoints};

const SEC: u64 = 1_000_000;

fn client() -> Endpoints {
    Endpoints {
        src_mac: MacAddr([2, 0, 0, 0, 0, 1]),
        dst_mac: MacAddr([2, 0, 0, 0, 0, 2]),
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
    }
}

fn p(frame: Vec<u8>) -> ParsedPacket {
    parse_frame(LinkType::Ethernet, &frame, frame.len() as u32)
}

fn feed(t: &mut FlowTable, pkt: &ParsedPacket, dir: Direction, ts: u64) -> u64 {
    t.observe(pkt, classify(pkt), dir, ts).unwrap()
}

#[test]
fn bidirectional_packets_share_one_flow() {
    let mut t = FlowTable::new(FlowTableConfig::default());
    let out = p(synth::tcp_frame(&client(), 50000, 443, 100, 0, TcpFlags::SYN, b""));
    let back = p(synth::tcp_frame(&client().reversed(), 443, 50000, 900, 101, TcpFlags::SYN | TcpFlags::ACK, b""));
    let a = feed(&mut t, &out, Direction::Outgoing, 0);
    let b = feed(&mut t, &back, Direction::Incoming, 10);
    assert_eq!(a, b);
    assert_eq!(t.len(), 1);
    let f = t.get(a).unwrap();
    assert_eq!((f.packets_fwd, f.packets_rev), (1, 1));
    assert_eq!(f.bytes_out, out.wire_len as u64);
    assert_eq!(f.bytes_in, back.wire_len as u64);
    assert_eq!(f.direction, Direction::Outgoing);
    assert_eq!(f.initiator.port, 50000);
}

#[test]
fn different_ports_are_different_flows() {
    let mut t = FlowTable::new(FlowTableConfig::default());
    let a = feed(&mut t, &p(synth::udp_frame(&client(), 1000, 53, b"")), Direction::Outgoing, 0);
    let b = feed(&mut t, &p(synth::udp_frame(&client(), 1001, 53, b"")), Direction::Outgoing, 0);
    assert_ne!(a, b);
}

#[test]
fn tcp_handshake_data_and_close() {
    let mut t = FlowTable::new(FlowTableConfig::default());
    let c = client();
    let s = c.reversed();
    let id = feed(&mut t, &p(synth::tcp_frame(&c, 50000, 80, 1, 0, TcpFlags::SYN, b"")), Direction::Outgoing, 0);
    assert_eq!(t.get(id).unwrap().tcp.as_ref().unwrap().state, TcpState::SynSent);
    feed(&mut t, &p(synth::tcp_frame(&s, 80, 50000, 500, 2, TcpFlags::SYN | TcpFlags::ACK, b"")), Direction::Incoming, 1);
    assert_eq!(t.get(id).unwrap().tcp.as_ref().unwrap().state, TcpState::SynReceived);
    feed(&mut t, &p(synth::tcp_frame(&c, 50000, 80, 2, 501, TcpFlags::ACK, b"")), Direction::Outgoing, 2);
    assert_eq!(t.get(id).unwrap().tcp.as_ref().unwrap().state, TcpState::Established);

    let get = synth::http_get("example.com", "/");
    feed(&mut t, &p(synth::tcp_frame(&c, 50000, 80, 2, 501, TcpFlags::ACK | TcpFlags::PSH, &get)), Direction::Outgoing, 3);
    assert_eq!(t.get(id).unwrap().class, TrafficClass::Http);
    assert_eq!(t.get(id).unwrap().hostname.as_deref(), Some("example.com"));

    feed(&mut t, &p(synth::tcp_frame(&c, 50000, 80, 2 + get.len() as u32, 501, TcpFlags::FIN | TcpFlags::ACK, b"")), Direction::Outgoing, 4);
    assert_eq!(t.get(id).unwrap().tcp.as_ref().unwrap().state, TcpState::Closing);
    feed(&mut t, &p(synth::tcp_frame(&s, 80, 50000, 501, 3, TcpFlags::FIN | TcpFlags::ACK, b"")), Direction::Incoming, 5);
    let f = t.get(id).unwrap();
    assert_eq!(f.tcp.as_ref().unwrap().state, TcpState::Closed);
    assert_eq!(f.packets(), 6);
    assert_eq!(f.tcp.as_ref().unwrap().retransmissions, 0);
}

#[test]
fn retransmission_is_counted() {
    let mut t = FlowTable::new(FlowTableConfig::default());
    let seg = p(synth::tcp_frame(&client(), 50000, 9000, 1000, 1, TcpFlags::ACK, &[0u8; 100]));
    let id = feed(&mut t, &seg, Direction::Outgoing, 0);
    feed(&mut t, &seg, Direction::Outgoing, 1);
    let tcp = t.get(id).unwrap().tcp.clone().unwrap();
    assert!(tcp.midstream);
    assert_eq!(tcp.retransmissions, 1);
}

#[test]
fn sequence_wraparound_is_not_retransmission() {
    let mut t = FlowTable::new(FlowTableConfig::default());
    let a = p(synth::tcp_frame(&client(), 50000, 9000, u32::MAX - 10, 1, TcpFlags::ACK, &[0u8; 8]));
    let b = p(synth::tcp_frame(&client(), 50000, 9000, u32::MAX - 2, 1, TcpFlags::ACK, &[0u8; 8]));
    let id = feed(&mut t, &a, Direction::Outgoing, 0);
    feed(&mut t, &b, Direction::Outgoing, 1);
    assert_eq!(t.get(id).unwrap().tcp.as_ref().unwrap().retransmissions, 0);
}

#[test]
fn syn_after_close_starts_new_flow() {
    let mut t = FlowTable::new(FlowTableConfig::default());
    let c = client();
    let first = feed(&mut t, &p(synth::tcp_frame(&c, 50000, 80, 1, 0, TcpFlags::SYN, b"")), Direction::Outgoing, 0);
    feed(&mut t, &p(synth::tcp_frame(&c.reversed(), 80, 50000, 1, 2, TcpFlags::RST | TcpFlags::ACK, b"")), Direction::Incoming, 1);
    let second = feed(&mut t, &p(synth::tcp_frame(&c, 50000, 80, 99, 0, TcpFlags::SYN, b"")), Direction::Outgoing, 2);
    assert_ne!(first, second);
    assert_eq!(t.len(), 1);
}

#[test]
fn midstream_join_infers_initiator_from_ports() {
    let mut t = FlowTable::new(FlowTableConfig::default());
    let server_first = p(synth::tcp_frame(&client().reversed(), 443, 52586, 1, 1, TcpFlags::ACK, &[0u8; 20]));
    let id = feed(&mut t, &server_first, Direction::Incoming, 0);
    let f = t.get(id).unwrap();
    assert_eq!(f.initiator.port, 52586);
    assert_eq!(f.direction, Direction::Outgoing);

    let dns_reply_first = p(synth::udp_frame(&client().reversed(), 53, 60000, b""));
    let id = feed(&mut t, &dns_reply_first, Direction::Incoming, 0);
    assert_eq!(t.get(id).unwrap().initiator.port, 60000);

    let broadcast = p(synth::udp_frame(&client(), 60433, 3490, b""));
    let id = feed(&mut t, &broadcast, Direction::Outgoing, 0);
    assert_eq!(t.get(id).unwrap().initiator.port, 60433, "client port to service port keeps order");
}

#[test]
fn idle_flows_expire_by_protocol() {
    let mut t = FlowTable::new(FlowTableConfig::default());
    feed(&mut t, &p(synth::udp_frame(&client(), 1, 2, b"")), Direction::Outgoing, 0);
    feed(&mut t, &p(synth::tcp_frame(&client(), 3, 4, 1, 1, TcpFlags::ACK, b"")), Direction::Outgoing, 0);
    assert_eq!(t.expire(30 * SEC), 0);
    assert_eq!(t.expire(61 * SEC), 1, "UDP idle timeout");
    assert_eq!(t.len(), 1);
    assert_eq!(t.expire(301 * SEC), 1, "TCP idle timeout");
    assert!(t.is_empty());
    assert_eq!(t.expired_total(), 2);
}

#[test]
fn capacity_is_bounded() {
    let mut t = FlowTable::new(FlowTableConfig { max_flows: 3, ..Default::default() });
    for port in 0..10u16 {
        feed(&mut t, &p(synth::udp_frame(&client(), 1000 + port, 53, b"")), Direction::Outgoing, u64::from(port));
    }
    assert_eq!(t.len(), 3);
    assert_eq!(t.evicted_total(), 7);
}

#[test]
fn snapshot_rates() {
    let mut t = FlowTable::new(FlowTableConfig::default());
    let pkt = p(synth::udp_frame(&client(), 1, 2, &[0u8; 100]));
    let id = feed(&mut t, &pkt, Direction::Outgoing, 0);
    for i in 1..=10 {
        feed(&mut t, &pkt, Direction::Outgoing, i * SEC / 10);
    }
    let s = t.get(id).unwrap().snapshot();
    assert_eq!(s.packets, 11);
    assert_eq!(s.duration_ms, 1000);
    assert!((s.packet_rate - 11.0).abs() < 1e-9);
    assert!((s.avg_packet_size - pkt.wire_len as f64).abs() < 1e-9);
    assert_eq!(s.protocol, "UDP");
    assert_eq!(s.initiator, "192.168.1.20:1");
}
