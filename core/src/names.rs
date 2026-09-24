//! IP → hostname map learned from DNS answers, used to label flows that carry no name of their
//! own (QUIC, TLS without SNI, connections that started before capture).

use std::collections::HashMap;
use std::net::IpAddr;

use crate::packet::{AppProtocol, ParsedPacket};

pub const DEFAULT_CAPACITY: usize = 4096;

#[derive(Debug)]
struct Entry {
    name: String,
    learned_us: u64,
}

#[derive(Debug)]
pub struct NameTable {
    entries: HashMap<IpAddr, Entry>,
    capacity: usize,
}

impl Default for NameTable {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl NameTable {
    pub fn new(capacity: usize) -> Self {
        Self { entries: HashMap::new(), capacity: capacity.max(1) }
    }

    /// Learns from unicast DNS responses only: mDNS/LLMNR answers name LAN hosts, not destinations.
    pub fn observe(&mut self, pkt: &ParsedPacket, ts: u64) {
        let Some(dns) = pkt.dns.as_ref().filter(|d| d.is_response && pkt.app == AppProtocol::Dns) else { return };
        let Some(name) = dns.query_name.as_deref().filter(|n| *n != "." && !n.ends_with(".arpa")) else { return };
        for a in dns.answers.iter().filter(|a| !a.additional) {
            self.insert(a.address, name, ts);
        }
    }

    fn insert(&mut self, ip: IpAddr, name: &str, ts: u64) {
        match self.entries.get_mut(&ip) {
            Some(e) => {
                if e.name != name {
                    e.name = name.to_owned();
                }
                e.learned_us = ts;
            }
            None => {
                self.entries.insert(ip, Entry { name: name.to_owned(), learned_us: ts });
                if self.entries.len() > self.capacity {
                    self.evict_oldest_quarter();
                }
            }
        }
    }

    /// Amortised O(1) eviction: drops the oldest ~25 % in one pass instead of one entry per insert.
    fn evict_oldest_quarter(&mut self) {
        let mut ages: Vec<u64> = self.entries.values().map(|e| e.learned_us).collect();
        let cut = ages.len() / 4;
        let (_, &mut threshold, _) = ages.select_nth_unstable(cut);
        let mut budget = cut + 1;
        self.entries.retain(|_, e| {
            if e.learned_us <= threshold && budget > 0 {
                budget -= 1;
                false
            } else {
                true
            }
        });
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<&str> {
        self.entries.get(ip).map(|e| e.name.as_str())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::frame::LinkType;
    use crate::packet::MacAddr;
    use crate::parser::parse_frame;
    use crate::synth::{self, Endpoints};

    fn server() -> Endpoints {
        Endpoints {
            src_mac: MacAddr([2, 0, 0, 0, 0, 1]),
            dst_mac: MacAddr([2, 0, 0, 0, 0, 5]),
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        }
    }

    #[test]
    fn learns_answers_from_dns_responses() {
        let mut t = NameTable::default();
        let answer = Ipv4Addr::new(93, 184, 216, 34);
        let frame = synth::udp_frame(&server(), 53, 50000, &synth::dns_response_a(7, "example.com", answer));
        t.observe(&parse_frame(LinkType::Ethernet, &frame, frame.len() as u32), 1);
        assert_eq!(t.lookup(&IpAddr::V4(answer)), Some("example.com"));
    }

    #[test]
    fn ignores_mdns_answers() {
        let mut t = NameTable::default();
        let answer = Ipv4Addr::new(10, 0, 0, 9);
        let frame = synth::udp_frame(&server(), 5353, 5353, &synth::dns_response_a(0, "printer.local", answer));
        t.observe(&parse_frame(LinkType::Ethernet, &frame, frame.len() as u32), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn capacity_is_bounded_and_keeps_newest() {
        let mut t = NameTable::new(8);
        for i in 0..100u8 {
            t.insert(IpAddr::V4(Ipv4Addr::new(10, 1, 0, i)), "host", u64::from(i));
        }
        assert!(t.len() <= 8);
        assert_eq!(t.lookup(&IpAddr::V4(Ipv4Addr::new(10, 1, 0, 99))), Some("host"));
        assert_eq!(t.lookup(&IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0))), None);
    }
}
