//! Performance harness (Phase 9). Run in release mode:
//!   cargo run --release -p packetcity-core --example stress
//!
//! 1. Raw engine throughput: parse → classify → direction → flow → devices → stats → events.
//! 2. Full pipeline (bounded channel + pipeline thread + batching) at fixed offered rates, with a
//!    sink that only counts, reporting delivery, drops, queue depth and processing latency.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use packetcity_core::demo::{demo_engine_config, run_demo, DemoGenerator};
use packetcity_core::pipeline::{self, frame_channel, EventSink, PipelineConfig, StreamMessage};
use packetcity_core::{Engine, RawFrame};

const ENGINE_FRAMES: usize = 500_000;
const RATES: [f64; 4] = [100.0, 1_000.0, 10_000.0, 100_000.0];
const RUN: Duration = Duration::from_secs(6);
const FRAME_QUEUE: usize = 4096;

#[derive(Default)]
struct CountingSink {
    batches: AtomicU64,
    packets: AtomicU64,
    vehicle_events: AtomicU64,
    max_latency_ms: Mutex<f64>,
    last_drops: AtomicU64,
    max_queue: AtomicU64,
}

impl EventSink for CountingSink {
    fn send(&self, msg: StreamMessage) -> bool {
        match msg {
            StreamMessage::Traffic(b) => {
                self.batches.fetch_add(1, Ordering::Relaxed);
                self.packets.fetch_add(b.packets, Ordering::Relaxed);
                self.vehicle_events.fetch_add(b.events.len() as u64, Ordering::Relaxed);
            }
            StreamMessage::Stats { health, .. } => {
                let mut m = self.max_latency_ms.lock().unwrap();
                *m = m.max(health.mean_latency_ms);
                self.last_drops.store(health.frames_dropped, Ordering::Relaxed);
                self.max_queue.fetch_max(health.queue_depth as u64, Ordering::Relaxed);
            }
            _ => {}
        }
        true
    }
}

fn engine_throughput() {
    let mut gen = DemoGenerator::new(7);
    let mut frames: Vec<RawFrame> = Vec::with_capacity(ENGINE_FRAMES + 8);
    let mut ts = 1_700_000_000_000_000u64;
    while frames.len() < ENGINE_FRAMES {
        ts += 20;
        gen.step(ts, &mut frames);
    }
    let bytes: u64 = frames.iter().map(|f| u64::from(f.wire_len)).sum();
    let mut engine = Engine::new(demo_engine_config());
    let start = Instant::now();
    for (i, f) in frames.iter().enumerate() {
        engine.ingest(f);
        if i % 256 == 0 {
            engine.take_batch();
        }
    }
    let secs = start.elapsed().as_secs_f64();
    println!(
        "engine: {} frames in {:.2} s = {:.0} pkt/s ({:.1} Gbit/s of demo traffic) on one core",
        frames.len(),
        secs,
        frames.len() as f64 / secs,
        bytes as f64 * 8.0 / secs / 1e9
    );
}

fn pipeline_at(rate: f64) {
    let (tx, rx, counters) = frame_channel(FRAME_QUEUE);
    let stop = Arc::new(AtomicBool::new(false));
    let engine = Arc::new(Mutex::new(Engine::new(demo_engine_config())));
    let sink = Arc::new(CountingSink::default());

    let gen_stop = stop.clone();
    let generator = std::thread::spawn(move || run_demo(&tx, &gen_stop, rate, 42));
    let (p_engine, p_sink, p_stop, p_counters) = (engine.clone(), sink.clone(), stop.clone(), counters.clone());
    let pipeline = std::thread::spawn(move || {
        pipeline::run(rx, p_engine, p_sink.as_ref(), &PipelineConfig::default(), &p_counters, &p_stop)
    });

    std::thread::sleep(RUN);
    stop.store(true, Ordering::Relaxed);
    generator.join().unwrap();
    pipeline.join().unwrap();

    let offered = counters.frames_offered.load(Ordering::Relaxed);
    let delivered = sink.packets.load(Ordering::Relaxed);
    let secs = RUN.as_secs_f64();
    println!(
        "pipeline @ {:>7} pkt/s offered: {:>8.0} pkt/s processed, drops {:>6}, max queue {:>5}, max mean latency {:>6.2} ms, {:>4.1} batches/s, {:>5.0} vehicle events/s",
        rate,
        delivered as f64 / secs,
        sink.last_drops.load(Ordering::Relaxed),
        sink.max_queue.load(Ordering::Relaxed),
        *sink.max_latency_ms.lock().unwrap(),
        sink.batches.load(Ordering::Relaxed) as f64 / secs,
        sink.vehicle_events.load(Ordering::Relaxed) as f64 / secs,
    );
    if offered > 0 && delivered + counters.frames_dropped.load(Ordering::Relaxed) < offered / 2 {
        println!("  note: generator could not reach the offered rate on this machine");
    }
}

fn main() {
    engine_throughput();
    for rate in RATES {
        pipeline_at(rate);
    }
}
