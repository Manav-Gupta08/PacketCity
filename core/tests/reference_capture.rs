//! Replays the committed reference capture files through the full engine and checks exact,
//! deterministic results. No capture driver or live network is involved.

use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::PathBuf;

use packetcity_core::capture_file::CaptureFileReader;
use packetcity_core::devices::{DeviceRole, LocalNetwork, NodeRef};
use packetcity_core::flows::TcpState;
use packetcity_core::reference::{self, reference_frames};
use packetcity_core::{Engine, EngineConfig, LinkType, RawFrame, TrafficClass};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("tests").join("fixtures").join(name)
}

fn read(name: &str) -> (LinkType, Vec<RawFrame>) {
    let mut r = CaptureFileReader::new(BufReader::new(File::open(fixture(name)).expect("fixture exists"))).unwrap();
    let mut frames = Vec::new();
    while let Some(f) = r.next_frame().unwrap() {
        frames.push(f);
    }
    (r.link_type(), frames)
}

fn engine() -> Engine {
    let local = IpAddr::V4(reference::LOCAL_IP);
    Engine::new(
        EngineConfig::new(LinkType::Ethernet, vec![local, IpAddr::V6(reference::LOCAL_IP6)], vec![])
            .with_networks(vec![LocalNetwork { addr: local, prefix: reference::PREFIX }]),
    )
}

#[test]
fn fixtures_match_the_reference_scenario() {
    let expected = reference_frames();
    for name in ["reference.pcap", "reference.pcapng"] {
        let (link, frames) = read(name);
        assert_eq!(link, LinkType::Ethernet, "{name}");
        assert_eq!(frames.len(), expected.len(), "{name}: regenerate with `cargo run -p packetcity-core --example make_fixtures`");
        for (a, b) in frames.iter().zip(&expected) {
            assert_eq!((a.timestamp_us, a.wire_len, &a.data), (b.timestamp_us, b.wire_len, &b.data), "{name}");
        }
    }
}

#[test]
fn reference_capture_replays_deterministically() {
    let (_, frames) = read("reference.pcapng");
    let mut e = engine();
    let ids: Vec<u64> = frames.iter().map(|f| e.ingest(f)).collect();
    let batch = e.take_batch();
    let stats = e.stats(reference::START_US + 1_000_000);

    assert_eq!(stats.total_packets, 15);
    assert_eq!(stats.malformed_packets, 0);
    let class = |c| stats.class_totals[&c];
    assert_eq!(class(TrafficClass::Arp), 1);
    assert_eq!(class(TrafficClass::Dns), 3);
    assert_eq!(class(TrafficClass::Https), 7);
    assert_eq!(class(TrafficClass::Icmp), 2);
    assert_eq!(class(TrafficClass::Udp), 1);
    assert_eq!(class(TrafficClass::Http), 1);

    let hello = e.packet(ids[6]).unwrap();
    assert_eq!(hello.packet.tls.as_ref().unwrap().sni.as_deref(), Some("example.com"));
    let http = e.packet(ids[12]).unwrap();
    assert_eq!(http.packet.http.as_ref().unwrap().path.as_deref(), Some("/index.html"), "query string must be dropped");

    let tls_flow = e.flow(hello.flow_id.unwrap()).unwrap();
    assert_eq!(tls_flow.packets, 7);
    assert_eq!(tls_flow.hostname.as_deref(), Some("example.com"));
    assert_eq!(tls_flow.tcp.as_ref().unwrap().state, TcpState::Closed);
    assert_eq!(tls_flow.initiator, "192.168.1.20:52000");

    let devices = e.devices();
    assert!(devices.iter().any(|d| d.role == DeviceRole::Gateway && d.ips.contains(&"192.168.1.1".to_string())));
    assert!(devices.iter().any(|d| d.role == DeviceRole::Lan && d.ips.contains(&"192.168.1.50".to_string())));

    assert_eq!(batch.packets, 15);
    let first_tls = batch.events.iter().find(|ev| ev.packet_id == ids[3]).unwrap();
    assert_eq!((first_tls.src_node, first_tls.dst_node), (NodeRef::SelfHost, NodeRef::Internet));
    let mdns = batch.events.iter().find(|ev| ev.packet_id == ids[10]).unwrap();
    assert_eq!(mdns.dst_node, NodeRef::Broadcast);
    assert!(e.take_alerts().is_empty(), "a normal capture raises no alerts");
}

#[test]
fn scan_capture_raises_port_scan_alert() {
    let (_, mut frames) = read("reference.pcap");
    let scanner = frames[3].clone();
    // Reuse a real SYN from the fixture, rewriting only its TCP destination port.
    let tcp_dst_port = 14 + 20 + 2;
    for port in 1..=30u16 {
        let mut f = scanner.clone();
        f.data[tcp_dst_port..tcp_dst_port + 2].copy_from_slice(&port.to_be_bytes());
        f.timestamp_us += u64::from(port);
        frames.push(f);
    }
    let mut e = engine();
    for f in &frames {
        e.ingest(f);
    }
    let alerts = e.take_alerts();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, packetcity_core::alerts::AlertKind::PortScan);
}
