use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;
use crate::frame::LinkType;
use crate::packet::*;
use crate::synth::{self, Endpoints};

const MAC_A: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x0a]);
const MAC_B: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x0b]);

fn v4() -> Endpoints {
    Endpoints {
        src_mac: MAC_A,
        dst_mac: MAC_B,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 1, 1)),
    }
}

fn v6() -> Endpoints {
    Endpoints {
        src_mac: MAC_A,
        dst_mac: MAC_B,
        src_ip: IpAddr::V6("2001:db8::20".parse().unwrap()),
        dst_ip: IpAddr::V6("2001:db8::1".parse().unwrap()),
    }
}

fn parse(bytes: &[u8]) -> ParsedPacket {
    parse_frame(LinkType::Ethernet, bytes, bytes.len() as u32)
}

#[test]
fn ethernet_header_fields() {
    let pkt = parse(&synth::udp_frame(&v4(), 5000, 6000, b"x"));
    let eth = pkt.ethernet.as_ref().unwrap();
    assert_eq!(eth.src, MAC_A);
    assert_eq!(eth.dst, MAC_B);
    assert_eq!(eth.ether_type, ETHERTYPE_IPV4);
    assert_eq!(eth.vlan, None);
    assert!(pkt.issue.is_none());
}

#[test]
fn vlan_tag_is_unwrapped() {
    let inner = synth::udp_frame(&v4(), 5000, 6000, b"x");
    let mut tagged = inner[..12].to_vec();
    tagged.extend_from_slice(&[0x81, 0x00, 0x00, 0x2A]);
    tagged.extend_from_slice(&inner[12..]);
    let pkt = parse(&tagged);
    assert_eq!(pkt.ethernet.unwrap().vlan, Some(42));
    assert_eq!(pkt.transport, TransportProtocol::Udp);
}

#[test]
fn ipv4_tcp_fields() {
    let frame = synth::tcp_frame(&v4(), 52431, 443, 1000, 2000, TcpFlags::ACK | TcpFlags::PSH, &[0u8; 10]);
    let pkt = parse(&frame);
    let ip = pkt.ip.as_ref().unwrap();
    assert_eq!(ip.version, 4);
    assert_eq!(ip.src, v4().src_ip);
    assert_eq!(ip.dst, v4().dst_ip);
    assert_eq!(ip.ttl, 64);
    assert!(ip.dont_fragment);
    let tcp = pkt.tcp.as_ref().unwrap();
    assert_eq!((tcp.src_port, tcp.dst_port), (52431, 443));
    assert_eq!((tcp.seq, tcp.ack), (1000, 2000));
    assert_eq!(tcp.flags.names().collect::<Vec<_>>(), vec!["ACK", "PSH"]);
    assert_eq!(tcp.payload_len, 10);
    assert_eq!(pkt.app, AppProtocol::Tls, "port 443 hint");
    assert_eq!(classify(&pkt), TrafficClass::Https);
}

#[test]
fn ipv6_udp_fields() {
    let pkt = parse(&synth::udp_frame(&v6(), 40000, 9999, &[1, 2, 3]));
    let ip = pkt.ip.as_ref().unwrap();
    assert_eq!(ip.version, 6);
    assert_eq!(ip.dst, IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()));
    assert_eq!(ip.protocol, IPPROTO_UDP);
    assert_eq!(pkt.udp.as_ref().unwrap().payload_len, 3);
    assert_eq!(classify(&pkt), TrafficClass::Udp);
}

#[test]
fn ipv6_extension_headers_are_skipped() {
    let udp = synth::udp(1234, 5678, b"hi");
    let mut ext = vec![IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0];
    ext.extend_from_slice(&udp);
    let ep = v6();
    let (IpAddr::V6(s), IpAddr::V6(d)) = (ep.src_ip, ep.dst_ip) else { unreachable!() };
    let ip = synth::ipv6(s, d, 0, 64, &ext);
    let pkt = parse(&synth::ethernet(MAC_B, MAC_A, ETHERTYPE_IPV6, &ip));
    assert_eq!(pkt.ip.unwrap().protocol, IPPROTO_UDP);
    assert_eq!(pkt.udp.unwrap().dst_port, 5678);
}

#[test]
fn icmp_v4_and_v6() {
    let pkt = parse(&synth::icmp_echo_frame(&v4(), true, 1, 1));
    let icmp = pkt.icmp.as_ref().unwrap();
    assert_eq!((icmp.version, icmp.icmp_type, icmp.description), (4, 8, "Echo Request"));
    assert_eq!(classify(&pkt), TrafficClass::Icmp);

    let pkt = parse(&synth::icmp_echo_frame(&v6(), false, 1, 1));
    assert_eq!(pkt.transport, TransportProtocol::Icmpv6);
    assert_eq!(pkt.icmp.unwrap().description, "Echo Reply");
}

#[test]
fn arp_request() {
    let pkt = parse(&synth::arp_request_frame(MAC_A, Ipv4Addr::new(192, 168, 1, 20), Ipv4Addr::new(192, 168, 1, 1)));
    let arp = pkt.arp.as_ref().unwrap();
    assert_eq!(arp.operation, 1);
    assert_eq!(arp.target_ip, Ipv4Addr::new(192, 168, 1, 1));
    assert!(pkt.ethernet.as_ref().unwrap().dst.is_broadcast());
    assert_eq!(classify(&pkt), TrafficClass::Arp);
}

#[test]
fn dns_query_and_compressed_response() {
    let pkt = parse(&synth::udp_frame(&v4(), 51000, 53, &synth::dns_query(0xBEEF, "example.com", 28)));
    let dns = pkt.dns.as_ref().unwrap();
    assert_eq!(dns.transaction_id, 0xBEEF);
    assert!(!dns.is_response);
    assert_eq!(dns.query_name.as_deref(), Some("example.com"));
    assert_eq!(dns.query_type_name, Some("AAAA"));
    assert_eq!(classify(&pkt), TrafficClass::Dns);
    assert_eq!(pkt.hostname(), Some("example.com"));

    let resp = synth::dns_response_a(0xBEEF, "example.com", Ipv4Addr::new(93, 184, 216, 34));
    let pkt = parse(&synth::udp_frame(&v4().reversed(), 53, 51000, &resp));
    let dns = pkt.dns.unwrap();
    assert!(dns.is_response);
    assert_eq!(dns.answer_count, 1);
}

#[test]
fn dns_pointer_loop_is_rejected() {
    let mut msg = synth::dns_query(1, "a", 1);
    msg.truncate(12);
    msg.extend_from_slice(&[0xC0, 0x0C]);
    let pkt = parse(&synth::udp_frame(&v4(), 5353, 5353, &msg));
    assert_eq!(pkt.app, AppProtocol::Mdns);
    assert!(pkt.dns.unwrap().query_name.is_none());
    assert_eq!(pkt.issue.unwrap().layer, Layer::Application);
}

#[test]
fn tls_client_hello_sni() {
    let frame = synth::tcp_frame(&v4(), 50000, 8443, 1, 1, TcpFlags::ACK | TcpFlags::PSH, &synth::tls_client_hello("api.example.org"));
    let pkt = parse(&frame);
    let tls = pkt.tls.as_ref().unwrap();
    assert_eq!(tls.content_type_name, "Handshake");
    assert_eq!(tls.handshake_type, Some(1));
    assert_eq!(tls.sni.as_deref(), Some("api.example.org"));
    assert_eq!(pkt.app, AppProtocol::Tls);
}

#[test]
fn tls_detected_on_non_standard_port() {
    let frame = synth::tcp_frame(&v4(), 50000, 9000, 1, 1, TcpFlags::ACK, &synth::tls_application_data(100));
    let pkt = parse(&frame);
    assert_eq!(pkt.tls.unwrap().content_type_name, "ApplicationData");
    assert_eq!(pkt.app, AppProtocol::Tls);
}

#[test]
fn http_request_metadata_drops_query_string() {
    let payload = synth::http_get("example.com:8080", "/search?token=secret");
    let pkt = parse(&synth::tcp_frame(&v4(), 50001, 80, 1, 1, TcpFlags::ACK | TcpFlags::PSH, &payload));
    let http = pkt.http.as_ref().unwrap();
    assert_eq!(http.method.as_deref(), Some("GET"));
    assert_eq!(http.path.as_deref(), Some("/search"));
    assert_eq!(http.host.as_deref(), Some("example.com"));
    assert_eq!(classify(&pkt), TrafficClass::Http);
}

#[test]
fn http_response_status() {
    let pkt = parse(&synth::tcp_frame(&v4().reversed(), 80, 50001, 1, 1, TcpFlags::ACK, b"HTTP/1.1 404 Not Found\r\n\r\n"));
    assert_eq!(pkt.http.unwrap().status, Some(404));
}

#[test]
fn hostname_is_sanitized() {
    let frame = synth::tcp_frame(&v4(), 50000, 443, 1, 1, TcpFlags::ACK, &synth::tls_client_hello("evil<script>.com"));
    assert_eq!(parse(&frame).tls.unwrap().sni.as_deref(), Some("evil?script?.com"));
}

#[test]
fn loopback_null_link() {
    let ep = v4();
    let (IpAddr::V4(s), IpAddr::V4(d)) = (ep.src_ip, ep.dst_ip) else { unreachable!() };
    let mut frame = 2u32.to_le_bytes().to_vec();
    frame.extend_from_slice(&synth::ipv4(s, d, IPPROTO_UDP, 128, &synth::udp(1, 2, b"")));
    let pkt = parse_frame(LinkType::Null, &frame, frame.len() as u32);
    assert_eq!(pkt.network, NetworkProtocol::Ipv4);
    assert_eq!(pkt.udp.unwrap().dst_port, 2);
}

#[test]
fn raw_ip_link() {
    let (IpAddr::V6(s), IpAddr::V6(d)) = (v6().src_ip, v6().dst_ip) else { unreachable!() };
    let frame = synth::ipv6(s, d, IPPROTO_UDP, 1, &synth::udp(7, 8, b""));
    let pkt = parse_frame(LinkType::RawIp, &frame, frame.len() as u32);
    assert_eq!(pkt.network, NetworkProtocol::Ipv6);
}

#[test]
fn malformed_inputs_never_panic() {
    let valid = synth::tcp_frame(&v4(), 1, 2, 3, 4, TcpFlags::SYN, &synth::tls_client_hello("x.y"));
    for cut in 0..valid.len() {
        let _ = parse(&valid[..cut]);
    }
    for link in [LinkType::Ethernet, LinkType::Null, LinkType::Loop, LinkType::RawIp, LinkType::LinuxSll] {
        for len in 0..64 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let _ = parse_frame(link, &junk, len as u32);
        }
    }
}

#[test]
fn truncated_layers_report_issue() {
    assert_eq!(parse(&[0u8; 10]).issue.unwrap().layer, Layer::Link);

    let frame = synth::tcp_frame(&v4(), 1, 2, 3, 4, TcpFlags::SYN, b"");
    let pkt = parse(&frame[..14 + 20 + 8]);
    assert!(pkt.ip.is_some());
    assert!(pkt.tcp.is_none());
    assert_eq!(pkt.issue.unwrap().layer, Layer::Transport);

    let mut bad_ihl = frame.clone();
    bad_ihl[14] = 0x41;
    assert_eq!(parse(&bad_ihl).issue.unwrap().reason, "invalid IPv4 header length");
}

#[test]
fn non_first_fragment_has_no_transport() {
    let mut frame = synth::udp_frame(&v4(), 1, 53, &synth::dns_query(1, "a.b", 1));
    frame[14 + 6] = 0x00;
    frame[14 + 7] = 0x10;
    let pkt = parse(&frame);
    assert_eq!(pkt.ip.unwrap().fragment_offset, 0x10);
    assert!(pkt.udp.is_none());
}

#[test]
fn packet_serializes_for_frontend() {
    let pkt = parse(&synth::tcp_frame(&v4(), 1, 443, 0, 0, TcpFlags::SYN, b""));
    let json = serde_json::to_value(&pkt).unwrap();
    assert_eq!(json["tcp"]["flags"], serde_json::json!(["SYN"]));
    assert_eq!(json["ethernet"]["src"], "02:00:00:00:00:0a");
    assert_eq!(json["transport"], "tcp");
}
