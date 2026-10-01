//! Rolling traffic statistics in fixed one-second buckets (bounded memory, no unbounded arrays).
//! Time is packet time so live capture and PCAP replay behave identically.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::packet::{Direction, TrafficClass};

pub const HISTORY_SECS: usize = 60;
/// Rates are averaged over this many *completed* seconds to avoid a jumpy partial-second value.
pub const RATE_WINDOW_SECS: u64 = 2;
const US_PER_SEC: u64 = 1_000_000;
const CLASS_COUNT: usize = TrafficClass::ALL.len();

#[derive(Clone, Copy, Debug, Default)]
struct Bucket {
    second: u64,
    packets: u64,
    bytes: u64,
    bytes_in: u64,
    bytes_out: u64,
    by_class: [u64; CLASS_COUNT],
}

#[derive(Clone, Debug, Default)]
struct Totals {
    packets: u64,
    packets_in: u64,
    packets_out: u64,
    bytes: u64,
    bytes_in: u64,
    bytes_out: u64,
    malformed: u64,
    threats: u64,
    by_class: [u64; CLASS_COUNT],
}

#[derive(Clone, Debug)]
pub struct TrafficStats {
    buckets: [Bucket; HISTORY_SECS],
    totals: Totals,
    latest_us: u64,
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self { buckets: [Bucket::default(); HISTORY_SECS], totals: Totals::default(), latest_us: 0 }
    }
}

/// Counters maintained outside the statistics module but reported alongside it.
#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityCounts {
    pub tracked_flows: usize,
    pub active_flows: usize,
    pub active_connections: usize,
    pub active_devices: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsSnapshot {
    pub timestamp_us: u64,
    pub packets_per_sec: f64,
    pub bytes_per_sec: f64,
    pub download_bytes_per_sec: f64,
    pub upload_bytes_per_sec: f64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub malformed_packets: u64,
    /// Packets flagged by `threats::ThreatTracker`.
    pub threat_packets: u64,
    pub class_totals: BTreeMap<TrafficClass, u64>,
    pub class_rates: BTreeMap<TrafficClass, f64>,
    /// Oldest first; one entry per completed second.
    pub history_packets: Vec<u64>,
    pub history_bytes: Vec<u64>,
    pub history_bytes_in: Vec<u64>,
    pub history_bytes_out: Vec<u64>,
    #[serde(flatten)]
    pub counts: EntityCounts,
}

impl TrafficStats {
    pub fn record(&mut self, ts_us: u64, bytes: u32, direction: Direction, class: TrafficClass, malformed: bool) {
        let bytes = u64::from(bytes);
        let t = &mut self.totals;
        t.packets += 1;
        t.bytes += bytes;
        t.by_class[class.index()] += 1;
        t.malformed += u64::from(malformed);
        match direction {
            Direction::Incoming => {
                t.bytes_in += bytes;
                t.packets_in += 1;
            }
            Direction::Outgoing => {
                t.bytes_out += bytes;
                t.packets_out += 1;
            }
            _ => {}
        }
        self.latest_us = self.latest_us.max(ts_us);

        let second = ts_us / US_PER_SEC;
        let latest_second = self.latest_us / US_PER_SEC;
        // Packets older than the history window only count toward totals.
        if latest_second.saturating_sub(second) >= HISTORY_SECS as u64 {
            return;
        }
        let bucket = &mut self.buckets[(second % HISTORY_SECS as u64) as usize];
        if bucket.second != second {
            *bucket = Bucket { second, ..Bucket::default() };
        }
        bucket.packets += 1;
        bucket.bytes += bytes;
        bucket.by_class[class.index()] += 1;
        match direction {
            Direction::Incoming => bucket.bytes_in += bytes,
            Direction::Outgoing => bucket.bytes_out += bytes,
            _ => {}
        }
    }

    pub fn latest_us(&self) -> u64 {
        self.latest_us
    }

    pub fn record_threat(&mut self) {
        self.totals.threats += 1;
    }

    /// (packets in, packets out, bytes in, bytes out) since the session started.
    pub fn host_totals(&self) -> (u64, u64, u64, u64) {
        let t = &self.totals;
        (t.packets_in, t.packets_out, t.bytes_in, t.bytes_out)
    }

    fn bucket_at(&self, second: u64) -> Option<&Bucket> {
        let b = &self.buckets[(second % HISTORY_SECS as u64) as usize];
        (b.second == second && (b.packets > 0)).then_some(b)
    }

    /// `now_us` is normally wall-clock for live capture or the replay cursor for PCAP.
    pub fn snapshot(&self, now_us: u64, counts: EntityCounts) -> StatsSnapshot {
        let now_s = now_us / US_PER_SEC;
        let rate_seconds: Vec<&Bucket> =
            (1..=RATE_WINDOW_SECS).filter_map(|back| now_s.checked_sub(back)).filter_map(|s| self.bucket_at(s)).collect();
        let window = RATE_WINDOW_SECS as f64;
        let rate = |f: fn(&Bucket) -> u64| rate_seconds.iter().map(|b| f(b)).sum::<u64>() as f64 / window;

        let mut class_totals = BTreeMap::new();
        let mut class_rates = BTreeMap::new();
        for class in TrafficClass::ALL {
            let i = class.index();
            class_totals.insert(class, self.totals.by_class[i]);
            class_rates.insert(class, rate_seconds.iter().map(|b| b.by_class[i]).sum::<u64>() as f64 / window);
        }

        let history: Vec<Option<&Bucket>> =
            (1..=HISTORY_SECS as u64).rev().map(|back| now_s.checked_sub(back).and_then(|s| self.bucket_at(s))).collect();

        StatsSnapshot {
            timestamp_us: now_us,
            packets_per_sec: rate(|b| b.packets),
            bytes_per_sec: rate(|b| b.bytes),
            download_bytes_per_sec: rate(|b| b.bytes_in),
            upload_bytes_per_sec: rate(|b| b.bytes_out),
            total_packets: self.totals.packets,
            total_bytes: self.totals.bytes,
            total_bytes_in: self.totals.bytes_in,
            total_bytes_out: self.totals.bytes_out,
            malformed_packets: self.totals.malformed,
            threat_packets: self.totals.threats,
            class_totals,
            class_rates,
            history_packets: history.iter().map(|b| b.map_or(0, |b| b.packets)).collect(),
            history_bytes: history.iter().map(|b| b.map_or(0, |b| b.bytes)).collect(),
            history_bytes_in: history.iter().map(|b| b.map_or(0, |b| b.bytes_in)).collect(),
            history_bytes_out: history.iter().map(|b| b.map_or(0, |b| b.bytes_out)).collect(),
            counts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = US_PER_SEC;

    #[test]
    fn rates_use_completed_seconds() {
        let mut s = TrafficStats::default();
        for i in 0..10 {
            s.record(100 * SEC + i * 1000, 100, Direction::Incoming, TrafficClass::Tcp, false);
        }
        for _ in 0..30 {
            s.record(101 * SEC, 50, Direction::Outgoing, TrafficClass::Dns, false);
        }
        let snap = s.snapshot(102 * SEC + SEC / 2, EntityCounts::default());
        assert_eq!(snap.packets_per_sec, 20.0);
        assert_eq!(snap.download_bytes_per_sec, 500.0);
        assert_eq!(snap.upload_bytes_per_sec, 750.0);
        assert_eq!(snap.class_rates[&TrafficClass::Dns], 15.0);
        assert_eq!(snap.total_packets, 40);
        assert_eq!(snap.class_totals[&TrafficClass::Tcp], 10);
        assert_eq!(snap.history_packets.len(), HISTORY_SECS);
        assert_eq!(&snap.history_packets[HISTORY_SECS - 2..], &[10, 30]);
        assert_eq!(&snap.history_bytes_in[HISTORY_SECS - 2..], &[1000, 0]);
        assert_eq!(&snap.history_bytes_out[HISTORY_SECS - 2..], &[0, 1500]);
    }

    #[test]
    fn buckets_are_recycled_after_window() {
        let mut s = TrafficStats::default();
        s.record(5 * SEC, 10, Direction::Incoming, TrafficClass::Udp, false);
        s.record((5 + HISTORY_SECS as u64) * SEC, 10, Direction::Incoming, TrafficClass::Udp, true);
        let snap = s.snapshot((6 + HISTORY_SECS as u64) * SEC, EntityCounts::default());
        assert_eq!(snap.history_packets.iter().sum::<u64>(), 1);
        assert_eq!(snap.total_packets, 2);
        assert_eq!(snap.malformed_packets, 1);
    }

    #[test]
    fn late_packets_only_count_in_totals() {
        let mut s = TrafficStats::default();
        s.record(1000 * SEC, 10, Direction::Incoming, TrafficClass::Udp, false);
        s.record(10 * SEC, 10, Direction::Incoming, TrafficClass::Udp, false);
        let snap = s.snapshot(1001 * SEC, EntityCounts::default());
        assert_eq!(snap.total_packets, 2);
        assert_eq!(snap.history_packets.iter().sum::<u64>(), 1);
    }
}
