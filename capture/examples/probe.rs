//! Headless capture probe: proves real packets flow through capture → parser → flows → stats.
//!
//! cargo run -p packetcity-capture --example probe -- [seconds] [interface-substring] [bpf] [out.pcap]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcity_capture::{capture_environment, list_interfaces, CaptureConfig, LiveCapture};
use packetcity_core::pipeline::{frame_channel, wall_clock_us};
use packetcity_core::{Engine, EngineConfig};

const PRINT_FIRST_PACKETS: usize = 25;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let seconds: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(5);
    let wanted = args.next().unwrap_or_default().to_lowercase();
    let bpf = args.next().filter(|b| !b.is_empty());
    let out_path = args.next();

    let env = capture_environment();
    println!("platform={} driver={:?} {}", env.platform, env.driver_version, env.driver_message.unwrap_or_default());

    let interfaces = list_interfaces()?;
    for (i, iface) in interfaces.iter().enumerate() {
        let ips: Vec<String> = iface.local_ips().iter().map(ToString::to_string).collect();
        println!("  [{i}] {:?} {} up={} conn={:?} ips={ips:?}", iface.kind, iface.display_name, iface.is_up, iface.connected);
    }
    let iface = interfaces
        .iter()
        .find(|i| !wanted.is_empty() && i.display_name.to_lowercase().contains(&wanted))
        .or_else(|| interfaces.first())
        .ok_or("no interfaces")?
        .clone();
    println!("\ncapturing {seconds}s on: {} ({})", iface.display_name, iface.id);

    let (tx, rx, counters) = frame_channel(8192);
    let stop = Arc::new(AtomicBool::new(false));
    let cfg = CaptureConfig { bpf_filter: bpf, ..CaptureConfig::new(&iface.id) };
    let (capture, started) = LiveCapture::start(cfg, tx, stop.clone())?;
    println!("link type: {:?}\n", started.link);

    let mut engine = Engine::new(
        EngineConfig::new(started.link, iface.local_ips(), iface.broadcast_ips()).with_networks(iface.local_networks()),
    );
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut printed = 0;
    let mut recorded = Vec::new();
    while Instant::now() < deadline {
        let Ok(frame) = rx.recv_timeout(Duration::from_millis(100)) else { continue };
        let id = engine.ingest(&frame);
        if out_path.is_some() {
            recorded.push(frame);
        }
        if printed < PRINT_FIRST_PACKETS {
            if let Some(r) = engine.packet(id) {
                let p = &r.packet;
                let ep = |ip: Option<std::net::IpAddr>, port: Option<u16>, src: bool| match (ip, port) {
                    (Some(ip), Some(port)) => format!("{ip}:{port}"),
                    (Some(ip), None) => ip.to_string(),
                    _ => p.ethernet.as_ref().map(|e| if src { e.src } else { e.dst }.to_string()).unwrap_or_default(),
                };
                println!(
                    "#{:<5} {:<9} {:<6} {:<5} {:>5}B {} -> {} {}",
                    r.id,
                    format!("{:?}", r.direction),
                    format!("{:?}", r.class),
                    format!("{:?}", p.transport),
                    p.wire_len,
                    ep(p.src_ip(), p.src_port(), true),
                    ep(p.dst_ip(), p.dst_port(), false),
                    p.hostname().unwrap_or(""),
                );
                printed += 1;
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    let outcome = capture.join();
    for f in rx.try_iter() {
        engine.ingest(&f);
        if out_path.is_some() {
            recorded.push(f);
        }
    }
    if let Some(path) = &out_path {
        let dlt = match started.link {
            packetcity_core::LinkType::Ethernet => 1,
            packetcity_core::LinkType::Null => 0,
            packetcity_core::LinkType::Loop => 108,
            packetcity_core::LinkType::RawIp => 101,
            packetcity_core::LinkType::LinuxSll => 113,
        };
        std::fs::write(path, packetcity_core::capture_file::write_pcap(dlt, &recorded))?;
        println!("saved {} frames to {path}", recorded.len());
    }

    let stats = engine.stats(wall_clock_us());
    println!("\noutcome={outcome:?}");
    println!(
        "packets={} bytes={} in={} out={} malformed={} flows={} tcp_established={} dropped={} driver_dropped={} link_down={}",
        stats.total_packets,
        stats.total_bytes,
        stats.total_bytes_in,
        stats.total_bytes_out,
        stats.malformed_packets,
        stats.counts.tracked_flows,
        stats.counts.active_connections,
        counters.frames_dropped.load(Ordering::Relaxed),
        counters.driver_dropped.load(Ordering::Relaxed),
        counters.link_down.load(Ordering::Relaxed),
    );
    println!("classes: {:?}", stats.class_totals.iter().filter(|(_, n)| **n > 0).collect::<Vec<_>>());
    for f in engine.recent_flows(wall_clock_us(), 8) {
        println!(
            "  flow #{:<4} {:<4} {:<6?} {} -> {} pkts={} bytes={} host={}",
            f.id,
            f.protocol,
            f.class,
            f.initiator,
            f.responder,
            f.packets,
            f.bytes,
            f.hostname.unwrap_or_default()
        );
    }
    for d in engine.devices() {
        println!(
            "  device {:<10} {:<9?} {:<18} mac={:<17} sent={} recv={} vendor={} name_via={:?}",
            d.node,
            d.role,
            d.label,
            d.mac.unwrap_or_default(),
            d.packets_sent,
            d.packets_received,
            d.vendor.unwrap_or("-"),
            d.hostname_source
        );
    }
    Ok(())
}
