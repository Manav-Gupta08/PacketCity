//! Threaded processing loop shared by every capture source.
//!
//! ```text
//! capture thread ──FrameSender (bounded, drop-on-full)──► pipeline thread ──EventSink──► UI
//! ```
//! The capture side never blocks: if the pipeline falls behind, frames are dropped and counted
//! rather than stalling the driver. UI messages are emitted on fixed cadences, so message rate is
//! independent of packet rate.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossbeam_channel::{Receiver, RecvTimeoutError, SendTimeoutError, Sender, TrySendError};
use serde::Serialize;

use crate::alerts::Alert;
use crate::devices::DeviceSnapshot;
use crate::engine::Engine;
use crate::events::TrafficBatch;
use crate::flows::FlowSnapshot;
use crate::frame::RawFrame;
use crate::statistics::StatsSnapshot;

#[derive(Debug, Default)]
pub struct PipelineCounters {
    pub frames_offered: AtomicU64,
    pub frames_dropped: AtomicU64,
    /// Cumulative drops reported by the capture driver (kernel buffer full), not by us.
    pub driver_dropped: AtomicU64,
    /// Drops the network interface itself reported (not supported by every driver).
    pub interface_dropped: AtomicU64,
    /// The capture interface reports no link (cable unplugged, Wi-Fi disconnected).
    pub link_down: AtomicBool,
}

impl PipelineCounters {
    pub fn report_driver_stats(&self, dropped: u64, interface_dropped: u64) {
        self.driver_dropped.store(dropped, Ordering::Relaxed);
        self.interface_dropped.store(interface_dropped, Ordering::Relaxed);
    }
}

/// Capture-side handle. Cloneable and cheap; safe to use from the capture thread.
#[derive(Clone, Debug)]
pub struct FrameSender {
    tx: Sender<RawFrame>,
    counters: Arc<PipelineCounters>,
}

impl FrameSender {
    /// Queues a frame without blocking. Returns `false` once the pipeline has shut down.
    pub fn offer(&self, frame: RawFrame) -> bool {
        self.counters.frames_offered.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(frame) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                self.counters.frames_dropped.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Blocks until queued (file sources can wait for the pipeline). `false` if stopped or closed.
    pub fn send_blocking(&self, frame: RawFrame, stop: &AtomicBool) -> bool {
        self.counters.frames_offered.fetch_add(1, Ordering::Relaxed);
        let mut frame = frame;
        loop {
            match self.tx.send_timeout(frame, Duration::from_millis(50)) {
                Ok(()) => return true,
                Err(SendTimeoutError::Timeout(back)) if !stop.load(Ordering::Relaxed) => frame = back,
                Err(_) => return false,
            }
        }
    }

    pub fn counters(&self) -> &Arc<PipelineCounters> {
        &self.counters
    }
}

pub type FrameReceiver = Receiver<RawFrame>;

pub fn frame_channel(capacity: usize) -> (FrameSender, FrameReceiver, Arc<PipelineCounters>) {
    let (tx, rx) = crossbeam_channel::bounded(capacity);
    let counters = Arc::new(PipelineCounters::default());
    (FrameSender { tx, counters: counters.clone() }, rx, counters)
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineHealth {
    pub frames_dropped: u64,
    pub driver_dropped: u64,
    pub interface_dropped: u64,
    pub link_down: bool,
    pub queue_depth: usize,
    /// Mean delay between packet timestamp and processing, over the last stats interval.
    /// Only meaningful for live capture.
    pub mean_latency_ms: f64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum StreamMessage {
    Traffic(TrafficBatch),
    Stats { stats: Box<StatsSnapshot>, health: PipelineHealth },
    Flows { flows: Vec<FlowSnapshot> },
    Devices { devices: Vec<DeviceSnapshot> },
    /// Newly raised alerts only; the UI keeps the history.
    Alerts { alerts: Vec<Alert> },
    /// The source finished (PCAP end, capture stopped, or capture error).
    SourceEnded { reason: String, error: bool },
}

pub trait EventSink: Send {
    /// Returns `false` when the consumer is gone; the pipeline then stops.
    fn send(&self, msg: StreamMessage) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockMode {
    /// "Now" is the system clock: rates fall to zero when traffic stops (live capture, demo).
    Wall,
    /// "Now" is the newest packet timestamp (PCAP replay).
    PacketTime,
}

#[derive(Clone, Debug)]
pub struct PipelineConfig {
    pub clock: ClockMode,
    pub batch_interval: Duration,
    pub stats_interval: Duration,
    pub flows_interval: Duration,
    pub maintenance_interval: Duration,
    pub max_frames_per_lock: usize,
    pub recent_flow_limit: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            clock: ClockMode::Wall,
            // 20 Hz keeps motion smooth without flooding IPC.
            batch_interval: Duration::from_millis(50),
            stats_interval: Duration::from_millis(500),
            flows_interval: Duration::from_secs(1),
            maintenance_interval: Duration::from_secs(1),
            max_frames_per_lock: 1024,
            recent_flow_limit: 200,
        }
    }
}

pub fn wall_clock_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

struct Cadence {
    every: Duration,
    next: Instant,
}

impl Cadence {
    fn new(every: Duration, now: Instant) -> Self {
        Self { every, next: now + every }
    }

    fn due(&mut self, now: Instant) -> bool {
        if now < self.next {
            return false;
        }
        self.next = now + self.every;
        true
    }
}

/// Runs until the frame channel disconnects, `stop` is set, or the sink goes away.
/// Returns the reason the loop ended.
pub fn run(
    rx: Receiver<RawFrame>,
    engine: Arc<Mutex<Engine>>,
    sink: &dyn EventSink,
    cfg: &PipelineConfig,
    counters: &PipelineCounters,
    stop: &AtomicBool,
) -> PipelineExit {
    let start = Instant::now();
    let mut batch = Cadence::new(cfg.batch_interval, start);
    let mut stats = Cadence::new(cfg.stats_interval, start);
    let mut flows = Cadence::new(cfg.flows_interval, start);
    let mut maintenance = Cadence::new(cfg.maintenance_interval, start);
    let mut latency = (0u64, 0u64);

    let exit = loop {
        if stop.load(Ordering::Relaxed) {
            break PipelineExit::Stopped;
        }
        let wait = batch.next.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(first) => {
                let mut eng = lock(&engine);
                let wall = (cfg.clock == ClockMode::Wall).then(wall_clock_us);
                let mut ingest = |f: RawFrame| {
                    if let Some(now) = wall {
                        latency.0 += now.saturating_sub(f.timestamp_us);
                        latency.1 += 1;
                    }
                    eng.ingest(&f);
                };
                ingest(first);
                for f in rx.try_iter().take(cfg.max_frames_per_lock) {
                    ingest(f);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break PipelineExit::SourceFinished,
        }

        let now = Instant::now();
        if batch.due(now) && !emit_batch(&engine, sink) {
            break PipelineExit::SinkClosed;
        }
        if maintenance.due(now) {
            let mut eng = lock(&engine);
            let t = clock_now(&eng, cfg.clock);
            eng.maintain(t);
        }
        if stats.due(now) {
            let health = health(counters, &rx, std::mem::take(&mut latency));
            if !emit_stats(&engine, sink, cfg.clock, health) {
                break PipelineExit::SinkClosed;
            }
        }
        if flows.due(now) && !emit_flows(&engine, sink, cfg) {
            break PipelineExit::SinkClosed;
        }
    };

    if exit != PipelineExit::SinkClosed {
        emit_batch(&engine, sink);
        emit_stats(&engine, sink, cfg.clock, health(counters, &rx, latency));
        emit_flows(&engine, sink, cfg);
    }
    exit
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipelineExit {
    Stopped,
    SourceFinished,
    SinkClosed,
}

fn lock(engine: &Mutex<Engine>) -> std::sync::MutexGuard<'_, Engine> {
    // A panic while holding the lock leaves counters consistent enough to keep serving the UI.
    engine.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn clock_now(engine: &Engine, clock: ClockMode) -> u64 {
    match clock {
        ClockMode::Wall => wall_clock_us(),
        ClockMode::PacketTime => engine.latest_packet_us(),
    }
}

fn health(counters: &PipelineCounters, rx: &Receiver<RawFrame>, (latency_sum, latency_n): (u64, u64)) -> PipelineHealth {
    PipelineHealth {
        frames_dropped: counters.frames_dropped.load(Ordering::Relaxed),
        driver_dropped: counters.driver_dropped.load(Ordering::Relaxed),
        interface_dropped: counters.interface_dropped.load(Ordering::Relaxed),
        link_down: counters.link_down.load(Ordering::Relaxed),
        queue_depth: rx.len(),
        mean_latency_ms: if latency_n > 0 { latency_sum as f64 / latency_n as f64 / 1000.0 } else { 0.0 },
    }
}

fn emit_batch(engine: &Mutex<Engine>, sink: &dyn EventSink) -> bool {
    let batch = {
        let mut eng = lock(engine);
        if !eng.has_pending_events() {
            return true;
        }
        eng.take_batch()
    };
    sink.send(StreamMessage::Traffic(batch))
}

fn emit_stats(engine: &Mutex<Engine>, sink: &dyn EventSink, clock: ClockMode, health: PipelineHealth) -> bool {
    let stats = {
        let eng = lock(engine);
        eng.stats(clock_now(&eng, clock))
    };
    sink.send(StreamMessage::Stats { stats: Box::new(stats), health })
}

fn emit_flows(engine: &Mutex<Engine>, sink: &dyn EventSink, cfg: &PipelineConfig) -> bool {
    let (flows, devices, alerts) = {
        let mut eng = lock(engine);
        (eng.recent_flows(clock_now(&eng, cfg.clock), cfg.recent_flow_limit), eng.devices(), eng.take_alerts())
    };
    sink.send(StreamMessage::Flows { flows })
        && sink.send(StreamMessage::Devices { devices })
        && (alerts.is_empty() || sink.send(StreamMessage::Alerts { alerts }))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::engine::EngineConfig;
    use crate::frame::LinkType;
    use crate::packet::MacAddr;
    use crate::synth::{self, Endpoints};

    #[derive(Default)]
    struct VecSink(Mutex<Vec<StreamMessage>>);

    impl EventSink for VecSink {
        fn send(&self, msg: StreamMessage) -> bool {
            self.0.lock().unwrap().push(msg);
            true
        }
    }

    #[test]
    fn frames_flow_through_to_sink_and_drops_are_counted() {
        let (tx, rx, counters) = frame_channel(8);
        let ep = Endpoints {
            src_mac: MacAddr([2, 0, 0, 0, 0, 1]),
            dst_mac: MacAddr([2, 0, 0, 0, 0, 2]),
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        };
        let bytes = synth::udp_frame(&ep, 1, 2, b"hello");
        for i in 0..10 {
            assert!(tx.offer(RawFrame { timestamp_us: i, wire_len: bytes.len() as u32, data: bytes.clone() }));
        }
        drop(tx);

        let engine = Arc::new(Mutex::new(Engine::new(EngineConfig::new(LinkType::Ethernet, vec![ep.src_ip], vec![]))));
        let sink = VecSink::default();
        let cfg = PipelineConfig { clock: ClockMode::PacketTime, ..Default::default() };
        let exit = run(rx, engine, &sink, &cfg, &counters, &AtomicBool::new(false));
        assert_eq!(exit, PipelineExit::SourceFinished);

        let msgs = sink.0.into_inner().unwrap();
        let delivered: u64 = msgs.iter().filter_map(|m| match m { StreamMessage::Traffic(b) => Some(b.packets), _ => None }).sum();
        assert_eq!(delivered, 8);
        let dropped = msgs.iter().rev().find_map(|m| match m { StreamMessage::Stats { health, .. } => Some(health.frames_dropped), _ => None });
        assert_eq!(dropped, Some(2));

        let json = serde_json::to_value(&msgs[0]).unwrap();
        assert_eq!(json["type"], "traffic");
        assert!(json["events"].is_array());
    }
}
