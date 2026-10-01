use crate::packet::{PacketId, PacketRecord};

/// Fixed-capacity ring of recent packet records for the inspector. Old packets are overwritten;
/// memory use is bounded by `capacity` regardless of capture duration.
#[derive(Debug)]
pub struct PacketStore {
    slots: Vec<Option<PacketRecord>>,
}

impl PacketStore {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self { slots: (0..capacity).map(|_| None).collect() }
    }

    fn slot(&self, id: PacketId) -> usize {
        (id % self.slots.len() as u64) as usize
    }

    pub fn insert(&mut self, record: PacketRecord) {
        let i = self.slot(record.id);
        self.slots[i] = Some(record);
    }

    /// Returns `None` if the packet was never stored or has since been overwritten.
    pub fn get(&self, id: PacketId) -> Option<&PacketRecord> {
        self.slots[self.slot(id)].as_ref().filter(|r| r.id == id)
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }
}

/// Raw frame bytes for the hex view. Exists only while the user has enabled payload capture;
/// smaller than `PacketStore` because frames are large.
#[derive(Debug)]
pub struct FrameBytesStore {
    slots: Vec<Option<(PacketId, Box<[u8]>)>>,
}

pub const FRAME_BYTES_CAPACITY: usize = 5_000;
/// Enough for a full Ethernet frame; larger (offloaded) frames are cut.
pub const MAX_STORED_FRAME_BYTES: usize = 1_514;

impl FrameBytesStore {
    pub fn new(capacity: usize) -> Self {
        Self { slots: (0..capacity.max(1)).map(|_| None).collect() }
    }

    fn slot(&self, id: PacketId) -> usize {
        (id % self.slots.len() as u64) as usize
    }

    pub fn insert(&mut self, id: PacketId, data: &[u8]) {
        let i = self.slot(id);
        self.slots[i] = Some((id, data[..data.len().min(MAX_STORED_FRAME_BYTES)].into()));
    }

    pub fn get(&self, id: PacketId) -> Option<&[u8]> {
        self.slots[self.slot(id)].as_ref().filter(|(i, _)| *i == id).map(|(_, b)| &**b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Cast, Direction, ParsedPacket, TrafficClass};

    fn rec(id: PacketId) -> PacketRecord {
        PacketRecord {
            id,
            flow_id: None,
            timestamp_us: 0,
            direction: Direction::Incoming,
            cast: Cast::Unicast,
            class: TrafficClass::Other,
            threat: None,
            packet: ParsedPacket::empty(0, 0),
        }
    }

    #[test]
    fn overwrites_oldest_and_detects_eviction() {
        let mut s = PacketStore::new(4);
        for id in 1..=6 {
            s.insert(rec(id));
        }
        assert!(s.get(1).is_none());
        assert!(s.get(2).is_none());
        assert_eq!(s.get(6).unwrap().id, 6);
        assert_eq!(s.get(3).unwrap().id, 3);
        assert!(s.get(99).is_none());
    }
}
