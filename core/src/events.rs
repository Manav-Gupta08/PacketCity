//! Visual event layer. Packets are converted into `TrafficEvent`s which the renderer turns into
//! vehicles. Under load, events beyond a per-batch budget are merged per flow ("convoys"), so the
//! UI receives bounded work regardless of packet rate while the counts stay exact.

use std::collections::HashMap;

use serde::Serialize;

use crate::devices::NodeRef;
use crate::packet::{Cast, Direction, FlowId, PacketId, TrafficClass, TransportProtocol};
use crate::threats::ThreatKind;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficEvent {
    /// Representative (most recent) packet; use it to open the inspector.
    pub packet_id: PacketId,
    pub flow_id: Option<FlowId>,
    pub timestamp_us: u64,
    pub direction: Direction,
    pub cast: Cast,
    pub class: TrafficClass,
    pub transport: TransportProtocol,
    /// Map nodes the vehicle travels between (Global view routing).
    pub src_node: NodeRef,
    pub dst_node: NodeRef,
    pub src: String,
    pub dst: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub host: Option<String>,
    /// Wire length of the representative packet.
    pub length: u32,
    /// Packets represented by this event (1 unless aggregated).
    pub packets: u32,
    pub bytes: u64,
    /// Set when any represented packet was flagged; the renderer paints these cars red.
    pub threat: Option<ThreatKind>,
}

impl TrafficEvent {
    fn absorb(&mut self, other: TrafficEvent) {
        self.threat = self.threat.or(other.threat);
        self.packets = self.packets.saturating_add(other.packets);
        self.bytes += other.bytes;
        self.packet_id = other.packet_id;
        self.timestamp_us = other.timestamp_us;
        self.length = other.length;
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficBatch {
    pub events: Vec<TrafficEvent>,
    /// Packets represented in this batch (including those merged into aggregate events).
    pub packets: u64,
    /// Packets that were merged into aggregate events instead of getting their own.
    pub aggregated_packets: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum AggregateKey {
    Flow(FlowId),
    Unflowed(TrafficClass, Direction),
}

#[derive(Debug)]
pub struct EventBatcher {
    max_individual: usize,
    max_aggregates: usize,
    events: Vec<TrafficEvent>,
    aggregates: HashMap<AggregateKey, usize>,
    packets: u64,
    aggregated: u64,
}

impl EventBatcher {
    pub fn new(max_individual: usize, max_aggregates: usize) -> Self {
        Self {
            max_individual,
            max_aggregates,
            events: Vec::with_capacity(max_individual + max_aggregates),
            aggregates: HashMap::new(),
            packets: 0,
            aggregated: 0,
        }
    }

    pub fn push(&mut self, event: TrafficEvent) {
        self.packets += u64::from(event.packets);
        if self.events.len() < self.max_individual {
            self.events.push(event);
            return;
        }
        self.aggregated += u64::from(event.packets);
        let key = match event.flow_id {
            Some(id) => AggregateKey::Flow(id),
            None => AggregateKey::Unflowed(event.class, event.direction),
        };
        if let Some(&i) = self.aggregates.get(&key) {
            self.events[i].absorb(event);
        } else if self.aggregates.len() < self.max_aggregates {
            self.aggregates.insert(key, self.events.len());
            self.events.push(event);
        } else {
            // Budget exhausted: fold into the most recent aggregate so no packet goes uncounted.
            if let Some(last) = self.events.last_mut() {
                last.absorb(event);
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn take(&mut self) -> TrafficBatch {
        self.aggregates.clear();
        let batch = TrafficBatch {
            events: std::mem::take(&mut self.events),
            packets: self.packets,
            aggregated_packets: self.aggregated,
        };
        self.packets = 0;
        self.aggregated = 0;
        batch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: PacketId, flow: Option<FlowId>) -> TrafficEvent {
        TrafficEvent {
            packet_id: id,
            flow_id: flow,
            timestamp_us: id,
            direction: Direction::Outgoing,
            cast: Cast::Unicast,
            class: TrafficClass::Tcp,
            transport: TransportProtocol::Tcp,
            src_node: NodeRef::SelfHost,
            dst_node: NodeRef::Internet,
            src: "a".into(),
            dst: "b".into(),
            src_port: None,
            dst_port: None,
            host: None,
            length: 100,
            packets: 1,
            bytes: 100,
            threat: None,
        }
    }

    #[test]
    fn individual_events_under_budget() {
        let mut b = EventBatcher::new(10, 5);
        for i in 0..5 {
            b.push(ev(i, Some(1)));
        }
        let batch = b.take();
        assert_eq!(batch.events.len(), 5);
        assert_eq!(batch.aggregated_packets, 0);
        assert!(b.is_empty());
    }

    #[test]
    fn overflow_aggregates_per_flow_and_preserves_counts() {
        let mut b = EventBatcher::new(2, 2);
        for i in 0..100u64 {
            b.push(ev(i, Some(i % 3)));
        }
        let batch = b.take();
        assert_eq!(batch.events.len(), 4);
        assert_eq!(batch.packets, 100);
        assert_eq!(batch.aggregated_packets, 98);
        let represented: u64 = batch.events.iter().map(|e| u64::from(e.packets)).sum();
        assert_eq!(represented, 100);
        assert_eq!(batch.events.iter().map(|e| e.bytes).sum::<u64>(), 100 * 100);
    }
}
