//! Lightweight, explainable detections over the traffic the engine already sees. Every alert
//! states the evidence it is based on; thresholds are deliberately conservative to avoid noise.
//! Time is packet time, so replaying a capture produces the same alerts.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use serde::Serialize;

use crate::packet::{FlowId, MacAddr, ParsedPacket, TcpFlags, TransportProtocol};
use crate::threats::ThreatKind;

const US_PER_SEC: u64 = 1_000_000;
/// New-device alerts are suppressed at session start, when every device is "new".
pub const NEW_DEVICE_WARMUP_US: u64 = 60 * US_PER_SEC;
pub const SCAN_WINDOW_US: u64 = 10 * US_PER_SEC;
/// Distinct destination ports probed on one host within the window.
pub const PORT_SCAN_THRESHOLD: usize = 20;
/// Distinct on-link hosts probed on one port within the window.
pub const HOST_SWEEP_THRESHOLD: usize = 20;
pub const RETRANSMISSION_MIN_PACKETS: u64 = 50;
pub const RETRANSMISSION_RATIO: f64 = 0.10;
pub const MALFORMED_THRESHOLD: u64 = 20;
/// The same alert (same kind and subject) is not repeated within this period.
pub const ALERT_COOLDOWN_US: u64 = 300 * US_PER_SEC;
const MAX_TRACKED_SOURCES: usize = 4096;
pub const BRUTE_FORCE_WINDOW_US: u64 = 60 * US_PER_SEC;
/// New connections from one source to one login service within the window.
pub const BRUTE_FORCE_THRESHOLD: u32 = 15;
/// Interactive login services; mail, SMB and databases are excluded because clients and pools
/// legitimately open many connections to them.
const LOGIN_PORTS: [u16; 5] = [21, 22, 23, 3389, 5900];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Info,
    Warning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AlertKind {
    DuplicateIp,
    NewDevice,
    PortScan,
    HostSweep,
    Retransmissions,
    MalformedTraffic,
    BruteForce,
    DnsTunnel,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub id: u64,
    pub timestamp_us: u64,
    pub severity: Severity,
    pub kind: AlertKind,
    pub title: String,
    pub detail: String,
    /// Map node to focus ("dev:3", "gateway", …) when the alert concerns a device.
    pub node: Option<String>,
    pub flow_id: Option<FlowId>,
}

#[derive(Default, Debug)]
struct ScanWindow {
    start_us: u64,
    ports_by_host: HashMap<IpAddr, HashSet<u16>>,
    hosts_by_port: HashMap<u16, HashSet<IpAddr>>,
}

#[derive(Debug, Default)]
pub struct AlertEngine {
    next_id: u64,
    pending: Vec<Alert>,
    last_raised: HashMap<(AlertKind, String), u64>,
    session_start_us: Option<u64>,
    scans: HashMap<IpAddr, ScanWindow>,
    /// (source, server, port) → (window start, connection attempts).
    logins: HashMap<(IpAddr, IpAddr, u16), (u64, u32)>,
    malformed_window: (u64, u64),
}

/// Probe = connection attempt that would be sent to a closed or open port alike.
fn probe(pkt: &ParsedPacket) -> Option<(IpAddr, IpAddr, u16)> {
    let (src, dst, port) = (pkt.src_ip()?, pkt.dst_ip()?, pkt.dst_port()?);
    let is_probe = match (pkt.transport, &pkt.tcp) {
        (TransportProtocol::Tcp, Some(t)) => t.flags.has(TcpFlags::SYN) && !t.flags.has(TcpFlags::ACK),
        (TransportProtocol::Udp, _) => true,
        _ => false,
    };
    (is_probe && !dst.is_multicast()).then_some((src, dst, port))
}

struct Draft {
    severity: Severity,
    kind: AlertKind,
    /// What the alert is about; used with `kind` for cooldown de-duplication.
    subject: String,
    title: String,
    detail: String,
    node: Option<String>,
    flow_id: Option<FlowId>,
}

impl AlertEngine {
    fn raise(&mut self, ts: u64, d: Draft) {
        let key = (d.kind, d.subject);
        if self.last_raised.get(&key).is_some_and(|&t| ts.saturating_sub(t) < ALERT_COOLDOWN_US) {
            return;
        }
        self.last_raised.insert(key, ts);
        self.next_id += 1;
        self.pending.push(Alert { id: self.next_id, timestamp_us: ts, severity: d.severity, kind: d.kind, title: d.title, detail: d.detail, node: d.node, flow_id: d.flow_id });
    }

    /// Returns the sender and why when this packet shows it is scanning or brute-forcing.
    pub fn observe_packet(&mut self, pkt: &ParsedPacket, ts: u64, on_link: &dyn Fn(&IpAddr) -> bool) -> Option<(IpAddr, ThreatKind)> {
        self.session_start_us.get_or_insert(ts);

        if pkt.issue.is_some() {
            let (start, count) = &mut self.malformed_window;
            if ts.saturating_sub(*start) > SCAN_WINDOW_US {
                *start = ts;
                *count = 0;
            }
            *count += 1;
            if *count == MALFORMED_THRESHOLD {
                self.raise(ts, Draft {
                    severity: Severity::Info,
                    kind: AlertKind::MalformedTraffic,
                    subject: "malformed".into(),
                    title: "Burst of malformed packets".into(),
                    detail: format!("{MALFORMED_THRESHOLD} packets failed to parse within {} s. This can indicate truncation, unusual encapsulation or crafted traffic.", SCAN_WINDOW_US / US_PER_SEC),
                    node: None,
                    flow_id: None,
                });
            }
        }

        let (src, dst, port) = probe(pkt)?;
        let brute = pkt.tcp.is_some() && LOGIN_PORTS.contains(&port) && self.observe_login(src, dst, port, ts);
        if !self.scans.contains_key(&src) && self.scans.len() >= MAX_TRACKED_SOURCES {
            return brute.then_some((src, ThreatKind::BruteForce));
        }
        let w = self.scans.entry(src).or_default();
        if ts.saturating_sub(w.start_us) > SCAN_WINDOW_US {
            *w = ScanWindow { start_us: ts, ..Default::default() };
        }
        let ports = w.ports_by_host.entry(dst).or_default();
        ports.insert(port);
        let port_count = ports.len();
        let hosts_count = if on_link(&dst) {
            let hosts = w.hosts_by_port.entry(port).or_default();
            hosts.insert(dst);
            hosts.len()
        } else {
            0
        };

        if port_count == PORT_SCAN_THRESHOLD {
            self.raise(ts, Draft {
                severity: Severity::Warning,
                kind: AlertKind::PortScan,
                subject: format!("{src}>{dst}"),
                title: format!("Possible port scan of {dst}"),
                detail: format!("{src} probed {port_count} different ports on {dst} within {} s (TCP SYN / UDP).", SCAN_WINDOW_US / US_PER_SEC),
                node: None,
                flow_id: None,
            });
        }
        if hosts_count == HOST_SWEEP_THRESHOLD {
            self.raise(ts, Draft {
                severity: Severity::Warning,
                kind: AlertKind::HostSweep,
                subject: format!("{src}:{port}"),
                title: format!("Possible host sweep from {src}"),
                detail: format!("{src} contacted port {port} on {hosts_count} different local hosts within {} s.", SCAN_WINDOW_US / US_PER_SEC),
                node: None,
                flow_id: None,
            });
        }
        if port_count >= PORT_SCAN_THRESHOLD || hosts_count >= HOST_SWEEP_THRESHOLD {
            Some((src, ThreatKind::Scanner))
        } else {
            brute.then_some((src, ThreatKind::BruteForce))
        }
    }

    /// Counts a connection attempt to a login service; true once it looks like password guessing.
    fn observe_login(&mut self, src: IpAddr, dst: IpAddr, port: u16, ts: u64) -> bool {
        let key = (src, dst, port);
        if !self.logins.contains_key(&key) && self.logins.len() >= MAX_TRACKED_SOURCES {
            return false;
        }
        let (start, count) = self.logins.entry(key).or_insert((ts, 0));
        if ts.saturating_sub(*start) > BRUTE_FORCE_WINDOW_US {
            *start = ts;
            *count = 0;
        }
        *count += 1;
        let count = *count;
        if count == BRUTE_FORCE_THRESHOLD {
            self.raise(ts, Draft {
                severity: Severity::Warning,
                kind: AlertKind::BruteForce,
                subject: format!("{src}>{dst}:{port}"),
                title: format!("Possible brute-force login on {dst}:{port}"),
                detail: format!("{src} opened {count} connections to the {} service on {dst} within {} s, a pattern typical of password guessing.", service_name(port), BRUTE_FORCE_WINDOW_US / US_PER_SEC),
                node: None,
                flow_id: None,
            });
        }
        count >= BRUTE_FORCE_THRESHOLD
    }

    pub fn dns_tunnel(&mut self, ts: u64, name: &str, flow_id: Option<FlowId>) {
        let labels: Vec<&str> = name.trim_end_matches('.').rsplit('.').take(2).collect();
        let base = labels.into_iter().rev().collect::<Vec<_>>().join(".");
        self.raise(ts, Draft {
            severity: Severity::Warning,
            kind: AlertKind::DnsTunnel,
            subject: base.clone(),
            title: format!("Possible DNS tunnelling via {base}"),
            detail: format!("DNS names under {base} carry long, random-looking labels (e.g. {name}), which is how data is smuggled through DNS. Some security and telemetry products also do this."),
            node: None,
            flow_id,
        });
    }

    pub fn duplicate_ip(&mut self, ts: u64, ip: IpAddr, macs: (MacAddr, MacAddr), node: String) {
        self.raise(ts, Draft {
            severity: Severity::Warning,
            kind: AlertKind::DuplicateIp,
            subject: ip.to_string(),
            title: format!("{ip} is claimed by two devices"),
            detail: format!("Frames from {ip} arrive with MAC {} and with MAC {}. This is either an address conflict, a device such as a Wi-Fi extender answering for another, or ARP spoofing.", macs.0, macs.1),
            node: Some(node),
            flow_id: None,
        });
    }

    pub fn new_device(&mut self, ts: u64, label: &str, mac: Option<MacAddr>, node: String) {
        let Some(start) = self.session_start_us else { return };
        if ts.saturating_sub(start) < NEW_DEVICE_WARMUP_US {
            return;
        }
        let mac = mac.map(|m| format!(" ({m})")).unwrap_or_default();
        self.raise(ts, Draft {
            severity: Severity::Info,
            kind: AlertKind::NewDevice,
            subject: node.clone(),
            title: format!("New device {label}"),
            detail: format!("First seen on this network segment: {label}{mac}."),
            node: Some(node),
            flow_id: None,
        });
    }

    pub fn retransmissions(&mut self, ts: u64, flow_id: FlowId, description: &str, retrans: u32, packets: u64) {
        let ratio = f64::from(retrans) / packets as f64;
        if packets < RETRANSMISSION_MIN_PACKETS || ratio < RETRANSMISSION_RATIO {
            return;
        }
        self.raise(ts, Draft {
            severity: Severity::Warning,
            kind: AlertKind::Retransmissions,
            subject: flow_id.to_string(),
            title: "High TCP retransmission rate".into(),
            detail: format!("{description}: {retrans} of {packets} packets ({:.0}%) look like retransmissions, a sign of loss or congestion.", ratio * 100.0),
            node: None,
            flow_id: Some(flow_id),
        });
    }

    pub fn take(&mut self) -> Vec<Alert> {
        std::mem::take(&mut self.pending)
    }

    /// Drops scan windows that ended long ago so memory stays proportional to active sources.
    pub fn maintain(&mut self, now_us: u64) {
        self.scans.retain(|_, w| now_us.saturating_sub(w.start_us) <= 2 * SCAN_WINDOW_US);
        self.logins.retain(|_, (start, _)| now_us.saturating_sub(*start) <= 2 * BRUTE_FORCE_WINDOW_US);
    }
}

fn service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        3389 => "Remote Desktop",
        5900 => "VNC",
        _ => "login",
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::frame::LinkType;
    use crate::parser::parse_frame;
    use crate::synth::{self, Endpoints};

    const SCANNER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 66);
    const TARGET: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);

    fn ep(dst: Ipv4Addr) -> Endpoints {
        Endpoints { src_mac: MacAddr([2, 0, 0, 0, 0, 66]), dst_mac: MacAddr([2, 0, 0, 0, 0, 5]), src_ip: IpAddr::V4(SCANNER), dst_ip: IpAddr::V4(dst) }
    }

    fn syn(dst: Ipv4Addr, port: u16) -> ParsedPacket {
        let f = synth::tcp_frame(&ep(dst), 40000, port, 1, 0, TcpFlags::SYN, b"");
        parse_frame(LinkType::Ethernet, &f, f.len() as u32)
    }

    fn on_link(ip: &IpAddr) -> bool {
        matches!(ip, IpAddr::V4(v4) if v4.octets()[..3] == [10, 0, 0])
    }

    #[test]
    fn port_scan_raises_once_with_evidence() {
        let mut a = AlertEngine::default();
        for port in 1..=40 {
            a.observe_packet(&syn(TARGET, port), 1_000 + u64::from(port), &on_link);
        }
        let alerts = a.take();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::PortScan);
        assert!(alerts[0].detail.contains("20 different ports"));
    }

    #[test]
    fn slow_probing_and_normal_connections_do_not_alert() {
        let mut a = AlertEngine::default();
        for port in 1..=40u64 {
            a.observe_packet(&syn(TARGET, port as u16), port * (SCAN_WINDOW_US / 5), &on_link);
        }
        // Many outbound HTTPS connections to *different* internet hosts are normal browsing.
        for i in 0..50u8 {
            a.observe_packet(&syn(Ipv4Addr::new(142, 250, 0, i), 443), 1_000, &on_link);
        }
        assert!(a.take().is_empty());
    }

    #[test]
    fn host_sweep_on_local_network() {
        let mut a = AlertEngine::default();
        for host in 1..=25u8 {
            a.observe_packet(&syn(Ipv4Addr::new(10, 0, 0, host), 22), 1_000, &on_link);
        }
        let alerts = a.take();
        assert_eq!(alerts.iter().filter(|x| x.kind == AlertKind::HostSweep).count(), 1);
    }

    #[test]
    fn cooldown_and_warmup() {
        let mut a = AlertEngine::default();
        a.observe_packet(&syn(TARGET, 1), 0, &on_link);
        a.new_device(10 * US_PER_SEC, "10.0.0.9", None, "dev:1".into());
        assert!(a.take().is_empty(), "new devices during warm-up are expected");
        a.new_device(NEW_DEVICE_WARMUP_US + 1, "10.0.0.9", None, "dev:1".into());
        a.new_device(NEW_DEVICE_WARMUP_US + 2, "10.0.0.9", None, "dev:1".into());
        assert_eq!(a.take().len(), 1);
    }

    #[test]
    fn brute_force_on_login_port() {
        let mut a = AlertEngine::default();
        let mut verdicts = Vec::new();
        for i in 0..20u64 {
            verdicts.push(a.observe_packet(&syn(TARGET, 22), 1_000 + i * US_PER_SEC, &on_link));
        }
        assert!(verdicts[..14].iter().all(Option::is_none));
        assert_eq!(verdicts[14], Some((IpAddr::V4(SCANNER), ThreatKind::BruteForce)));
        let alerts = a.take();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::BruteForce);
        assert!(alerts[0].detail.contains("SSH"));
    }

    #[test]
    fn repeated_https_connections_are_not_brute_force() {
        let mut a = AlertEngine::default();
        for i in 0..40u64 {
            assert_eq!(a.observe_packet(&syn(TARGET, 443), 1_000 + i, &on_link), None);
        }
        assert!(a.take().is_empty());
    }

    #[test]
    fn retransmission_threshold() {
        let mut a = AlertEngine::default();
        a.retransmissions(0, 7, "flow", 4, 100);
        a.retransmissions(0, 8, "flow", 30, 40);
        assert!(a.take().is_empty());
        a.retransmissions(0, 9, "flow", 15, 100);
        assert_eq!(a.take()[0].flow_id, Some(9));
    }

    #[test]
    fn duplicate_ip_respects_cooldown() {
        let mut a = AlertEngine::default();
        for i in 0..3 {
            a.duplicate_ip(i, IpAddr::V4(TARGET), (MacAddr::default(), MacAddr::BROADCAST), "dev:0".into());
        }
        a.duplicate_ip(ALERT_COOLDOWN_US + 5, IpAddr::V4(TARGET), (MacAddr::default(), MacAddr::BROADCAST), "dev:0".into());
        assert_eq!(a.take().len(), 2);
    }
}
