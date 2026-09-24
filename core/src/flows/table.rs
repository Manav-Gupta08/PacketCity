use std::collections::HashMap;
use std::net::IpAddr;

use super::flow::{Flow, FlowSnapshot, HostnameSource, Observation};
use super::key::{FlowKey, FlowProtocol};
use super::tcp::TcpState;
use crate::packet::{Direction, FlowId, ParsedPacket, TcpFlags, TrafficClass};
use crate::statistics::EntityCounts;

const US_PER_SEC: u64 = 1_000_000;

/// Idle timeouts follow common conntrack defaults, shortened for UI relevance.
#[derive(Clone, Debug)]
pub struct FlowTableConfig {
    pub tcp_idle_us: u64,
    pub tcp_terminated_idle_us: u64,
    pub udp_idle_us: u64,
    pub other_idle_us: u64,
    /// Hard cap on tracked flows so memory stays bounded under scans/floods.
    pub max_flows: usize,
}

impl Default for FlowTableConfig {
    fn default() -> Self {
        Self {
            tcp_idle_us: 300 * US_PER_SEC,
            tcp_terminated_idle_us: 10 * US_PER_SEC,
            udp_idle_us: 60 * US_PER_SEC,
            other_idle_us: 30 * US_PER_SEC,
            max_flows: 65_536,
        }
    }
}

#[derive(Debug, Default)]
pub struct FlowTable {
    cfg: FlowTableConfig,
    index: HashMap<FlowKey, FlowId>,
    flows: HashMap<FlowId, Flow>,
    next_id: FlowId,
    expired_total: u64,
    evicted_total: u64,
}

impl FlowTable {
    pub fn new(cfg: FlowTableConfig) -> Self {
        Self { cfg, next_id: 1, ..Default::default() }
    }

    pub fn observe(&mut self, pkt: &ParsedPacket, class: TrafficClass, direction: Direction, ts: u64) -> Option<FlowId> {
        let (key, src, dst) = FlowKey::from_packet(pkt)?;
        let obs = Observation { pkt, src, dst, class, direction, ts };

        if let Some(&id) = self.index.get(&key) {
            if self.starts_new_connection(id, pkt) {
                self.remove(id);
            } else if let Some(flow) = self.flows.get_mut(&id) {
                flow.record(&obs);
                return Some(id);
            }
        }

        if self.flows.len() >= self.cfg.max_flows {
            self.expire(ts);
            if self.flows.len() >= self.cfg.max_flows {
                self.evict_oldest();
            }
        }

        let id = self.next_id;
        self.next_id += 1;
        let mut flow = Flow::new(id, key, &obs);
        flow.record(&obs);
        self.index.insert(key, id);
        self.flows.insert(id, flow);
        Some(id)
    }

    /// A fresh SYN on a terminated TCP flow is port reuse: start a new flow.
    fn starts_new_connection(&self, id: FlowId, pkt: &ParsedPacket) -> bool {
        let is_syn = pkt.tcp.as_ref().is_some_and(|t| t.flags.has(TcpFlags::SYN) && !t.flags.has(TcpFlags::ACK));
        is_syn && self.flows.get(&id).and_then(|f| f.tcp.as_ref()).is_some_and(|t| t.state.is_terminated())
    }

    fn idle_timeout(&self, flow: &Flow) -> u64 {
        match (flow.key.protocol, &flow.tcp) {
            (FlowProtocol::Tcp, Some(t)) if t.state.is_terminated() => self.cfg.tcp_terminated_idle_us,
            (FlowProtocol::Tcp, _) => self.cfg.tcp_idle_us,
            (FlowProtocol::Udp, _) => self.cfg.udp_idle_us,
            _ => self.cfg.other_idle_us,
        }
    }

    /// Removes flows idle longer than their timeout. `now_us` is packet time, so PCAP replay
    /// expires flows consistently with the original capture.
    pub fn expire(&mut self, now_us: u64) -> usize {
        let stale: Vec<FlowId> = self
            .flows
            .values()
            .filter(|f| now_us.saturating_sub(f.last_seen_us) > self.idle_timeout(f))
            .map(|f| f.id)
            .collect();
        for id in &stale {
            self.remove(*id);
        }
        self.expired_total += stale.len() as u64;
        stale.len()
    }

    fn evict_oldest(&mut self) {
        if let Some(id) = self.flows.values().min_by_key(|f| f.last_seen_us).map(|f| f.id) {
            self.remove(id);
            self.evicted_total += 1;
        }
    }

    fn remove(&mut self, id: FlowId) {
        if let Some(flow) = self.flows.remove(&id) {
            self.index.remove(&flow.key);
        }
    }

    pub fn get(&self, id: FlowId) -> Option<&Flow> {
        self.flows.get(&id)
    }

    /// Sets an in-band name found outside a single packet (reassembled TLS SNI).
    pub fn set_in_band_hostname(&mut self, id: FlowId, name: String) {
        if let Some(f) = self.flows.get_mut(&id) {
            f.set_hostname(name, HostnameSource::InBand);
        }
    }

    /// Labels an unnamed flow from `lookup` (DNS answers); in-band names always take precedence.
    pub fn label_from_dns<'a>(&mut self, id: FlowId, lookup: impl Fn(&IpAddr) -> Option<&'a str>) {
        let Some(f) = self.flows.get_mut(&id) else { return };
        if f.hostname.is_some() {
            return;
        }
        if let Some(name) = f.label_candidates().find_map(|ip| lookup(&ip)) {
            f.set_hostname(name.to_owned(), HostnameSource::DnsAnswer);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Flow> {
        self.flows.values()
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn expired_total(&self) -> u64 {
        self.expired_total
    }

    pub fn evicted_total(&self) -> u64 {
        self.evicted_total
    }

    /// Flows seen within `window_us` of `now_us`, most recently active first.
    pub fn recent(&self, now_us: u64, window_us: u64, limit: usize) -> Vec<FlowSnapshot> {
        let mut active: Vec<&Flow> = self.flows.values().filter(|f| now_us.saturating_sub(f.last_seen_us) <= window_us).collect();
        active.sort_unstable_by_key(|f| std::cmp::Reverse(f.last_seen_us));
        active.into_iter().take(limit).map(Flow::snapshot).collect()
    }

    /// "Connections" are TCP flows currently in the Established state.
    pub fn counts(&self, now_us: u64, window_us: u64) -> EntityCounts {
        let mut counts = EntityCounts { tracked_flows: self.flows.len(), ..Default::default() };
        for f in self.flows.values().filter(|f| now_us.saturating_sub(f.last_seen_us) <= window_us) {
            counts.active_flows += 1;
            if f.tcp.as_ref().is_some_and(|t| t.state == TcpState::Established) {
                counts.active_connections += 1;
            }
        }
        counts
    }
}
