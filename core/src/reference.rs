//! Reference capture used for the committed fixture files (`tests/fixtures/reference.*`) and the
//! integration tests that replay them. Changing this scenario requires regenerating the fixtures:
//! `cargo run -p packetcity-core --example make_fixtures`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::frame::RawFrame;
use crate::packet::{MacAddr, TcpFlags};
use crate::synth::{self, Endpoints};

pub const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);
pub const LOCAL_IP6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x20);
pub const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
pub const PEER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
pub const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
pub const DNS_IP: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
pub const PREFIX: u8 = 24;
pub const START_US: u64 = 1_700_000_000_000_000;
const STEP_US: u64 = 10_000;
const LOCAL_MAC: MacAddr = MacAddr([2, 0, 0, 0, 0, 0x20]);
const GATEWAY_MAC: MacAddr = MacAddr([2, 0, 0, 0, 0, 0x01]);
const PEER_MAC: MacAddr = MacAddr([2, 0, 0, 0, 0, 0x50]);

fn v4(src_mac: MacAddr, src: Ipv4Addr, dst_mac: MacAddr, dst: Ipv4Addr) -> Endpoints {
    Endpoints { src_mac, dst_mac, src_ip: IpAddr::V4(src), dst_ip: IpAddr::V4(dst) }
}

/// 15 Ethernet frames: ARP, DNS, a full TLS connection, ICMP, mDNS, IPv6 link-local UDP, HTTP.
pub fn reference_frames() -> Vec<RawFrame> {
    let out_gw = |dst| v4(LOCAL_MAC, LOCAL_IP, GATEWAY_MAC, dst);
    let in_gw = |src| v4(GATEWAY_MAC, src, LOCAL_MAC, LOCAL_IP);
    let tls = out_gw(REMOTE_IP);
    let tls_back = in_gw(REMOTE_IP);
    let hello = synth::tls_client_hello("example.com");
    let ack = TcpFlags::ACK;

    let frames: Vec<Vec<u8>> = vec![
        synth::arp_request_frame(LOCAL_MAC, LOCAL_IP, GATEWAY_IP),
        synth::udp_frame(&out_gw(DNS_IP), 51000, 53, &synth::dns_query(0x1111, "example.com", 1)),
        synth::udp_frame(&in_gw(DNS_IP), 53, 51000, &synth::dns_response_a(0x1111, "example.com", REMOTE_IP)),
        synth::tcp_frame(&tls, 52000, 443, 1000, 0, TcpFlags::SYN, b""),
        synth::tcp_frame(&tls_back, 443, 52000, 5000, 1001, TcpFlags::SYN | ack, b""),
        synth::tcp_frame(&tls, 52000, 443, 1001, 5001, ack, b""),
        synth::tcp_frame(&tls, 52000, 443, 1001, 5001, ack | TcpFlags::PSH, &hello),
        synth::tcp_frame(&tls_back, 443, 52000, 5001, 1001 + hello.len() as u32, ack, &synth::tls_application_data(1400)),
        synth::icmp_echo_frame(&out_gw(GATEWAY_IP), true, 7, 1),
        synth::icmp_echo_frame(&in_gw(GATEWAY_IP), false, 7, 1),
        synth::udp_frame(
            &v4(PEER_MAC, PEER_IP, MacAddr([0x01, 0x00, 0x5E, 0, 0, 0xFB]), Ipv4Addr::new(224, 0, 0, 251)),
            5353,
            5353,
            &synth::dns_query(0, "printer._ipp._tcp.local", 12),
        ),
        synth::udp_frame(
            &Endpoints { src_mac: LOCAL_MAC, dst_mac: PEER_MAC, src_ip: IpAddr::V6(LOCAL_IP6), dst_ip: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x50)) },
            5000,
            5001,
            b"hello",
        ),
        synth::tcp_frame(&out_gw(REMOTE_IP), 52100, 80, 1, 1, ack | TcpFlags::PSH, &synth::http_get("example.com", "/index.html?session=secret")),
        synth::tcp_frame(&tls, 52000, 443, 1001 + hello.len() as u32, 6406, TcpFlags::FIN | ack, b""),
        synth::tcp_frame(&tls_back, 443, 52000, 6406, 1002 + hello.len() as u32, TcpFlags::FIN | ack, b""),
    ];

    frames
        .into_iter()
        .enumerate()
        .map(|(i, data)| RawFrame { timestamp_us: START_US + i as u64 * STEP_US, wire_len: data.len() as u32, data })
        .collect()
}
