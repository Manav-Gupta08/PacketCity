use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use packetcity_core::pipeline::{FrameSender, PipelineCounters};
use packetcity_core::{LinkType, RawFrame};

use crate::interfaces::{find_device, to_info, InterfaceInfo};
use crate::CaptureError;

/// Read timeout: bounds how long `stop()` takes to be noticed by the capture thread.
const READ_TIMEOUT_MS: i32 = 100;
/// Enough for full headers plus the first bytes of TLS/HTTP/DNS payloads; larger offloaded
/// segments are truncated (headers stay intact, `wire_len` stays exact).
pub const DEFAULT_SNAPLEN: i32 = 4096;
const KERNEL_BUFFER_BYTES: i32 = 8 * 1024 * 1024;
const US_PER_SEC: u64 = 1_000_000;
const DRIVER_STATS_INTERVAL: Duration = Duration::from_secs(1);
/// Listing adapters takes milliseconds, so it runs on its own thread at this cadence.
const INTERFACE_WATCH_INTERVAL: Duration = Duration::from_secs(2);
/// Consecutive missing listings before the interface counts as removed (avoids transient gaps).
const MISSING_LISTINGS_FOR_REMOVAL: u8 = 2;

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub interface_id: String,
    pub promiscuous: bool,
    pub snaplen: i32,
    /// BPF expression applied in the kernel/driver ("capture filter").
    pub bpf_filter: Option<String>,
}

impl CaptureConfig {
    pub fn new(interface_id: impl Into<String>) -> Self {
        Self { interface_id: interface_id.into(), promiscuous: false, snaplen: DEFAULT_SNAPLEN, bpf_filter: None }
    }
}

#[derive(Debug, Clone)]
pub struct CaptureStarted {
    pub link: LinkType,
    pub interface: InterfaceInfo,
}

#[derive(Debug, Clone)]
pub enum CaptureOutcome {
    Stopped,
    PipelineClosed,
    Failed(CaptureError),
}

/// Handle to a running capture thread. Dropping it does not stop capture; call `stop()`.
pub struct LiveCapture {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<CaptureOutcome>,
}

impl LiveCapture {
    /// Opens the interface on a dedicated thread and returns once capture is live (or failed).
    /// `stop` is shared so a session can stop capture and pipeline with one flag.
    pub fn start(cfg: CaptureConfig, frames: FrameSender, stop: Arc<AtomicBool>) -> Result<(Self, CaptureStarted), CaptureError> {
        let device = find_device(&cfg.interface_id)?;
        let interface = to_info(&device);
        let (ready_tx, ready_rx) = crossbeam_channel::bounded::<Result<LinkType, CaptureError>>(1);
        let thread_stop = stop.clone();
        let display_name = interface.display_name.clone();

        let thread = std::thread::Builder::new()
            .name("packet-capture".into())
            .spawn(move || {
                let mut cap = match open(device, &cfg) {
                    Ok((cap, link)) => {
                        let _ = ready_tx.send(Ok(link));
                        cap
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.clone()));
                        return CaptureOutcome::Failed(e);
                    }
                };
                let watch = InterfaceWatch::spawn(cfg.interface_id.clone(), frames.counters().clone());
                let outcome = read_loop(&mut cap, &frames, &thread_stop, &watch.removed, &display_name);
                watch.finish();
                outcome
            })
            .map_err(|e| CaptureError::Open(format!("could not start capture thread: {e}")))?;

        match ready_rx.recv() {
            Ok(Ok(link)) => Ok((Self { stop, thread }, CaptureStarted { link, interface })),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => Err(CaptureError::Open("capture thread exited during startup".into())),
        }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn join(self) -> CaptureOutcome {
        self.thread.join().unwrap_or_else(|_| CaptureOutcome::Failed(CaptureError::Read("capture thread panicked".into())))
    }
}

fn open(device: pcap::Device, cfg: &CaptureConfig) -> Result<(pcap::Capture<pcap::Active>, LinkType), CaptureError> {
    let mut cap = pcap::Capture::from_device(device)
        .map_err(CaptureError::from_open)?
        .promisc(cfg.promiscuous)
        .snaplen(cfg.snaplen)
        .timeout(READ_TIMEOUT_MS)
        .buffer_size(KERNEL_BUFFER_BYTES)
        .immediate_mode(true)
        .open()
        .map_err(CaptureError::from_open)?;

    if let Some(filter) = cfg.bpf_filter.as_deref().map(str::trim).filter(|f| !f.is_empty()) {
        cap.filter(filter, true).map_err(|e| CaptureError::InvalidFilter(e.to_string()))?;
    }
    let dlt = cap.get_datalink().0;
    let link = LinkType::from_dlt(dlt).ok_or(CaptureError::UnsupportedLinkType(dlt))?;
    log::info!("capture opened: link={link:?} promisc={} snaplen={}", cfg.promiscuous, cfg.snaplen);
    Ok((cap, link))
}

fn read_loop(
    cap: &mut pcap::Capture<pcap::Active>,
    frames: &FrameSender,
    stop: &AtomicBool,
    removed: &AtomicBool,
    display_name: &str,
) -> CaptureOutcome {
    let mut last_stats = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        if removed.load(Ordering::Relaxed) {
            log::warn!("capture interface disappeared: {display_name}");
            return CaptureOutcome::Failed(CaptureError::InterfaceRemoved(display_name.to_string()));
        }
        if last_stats.elapsed() >= DRIVER_STATS_INTERVAL {
            last_stats = Instant::now();
            if let Ok(s) = cap.stats() {
                frames.counters().report_driver_stats(u64::from(s.dropped), u64::from(s.if_dropped));
            }
        }
        match cap.next_packet() {
            Ok(packet) => {
                let ts = packet.header.ts;
                let timestamp_us = (ts.tv_sec as i64).max(0) as u64 * US_PER_SEC + (ts.tv_usec as i64).max(0) as u64;
                let frame = RawFrame { timestamp_us, wire_len: packet.header.len, data: packet.data.to_vec() };
                if !frames.offer(frame) {
                    return CaptureOutcome::PipelineClosed;
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => {
                log::warn!("capture read failed: {e}");
                return CaptureOutcome::Failed(CaptureError::Read(e.to_string()));
            }
        }
    }
    CaptureOutcome::Stopped
}

/// Periodically re-lists adapters to notice removal and link loss before reads start failing.
/// Holds only the counters, not a `FrameSender`, so it never keeps the frame channel open.
struct InterfaceWatch {
    removed: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl InterfaceWatch {
    fn spawn(interface_id: String, counters: Arc<PipelineCounters>) -> Self {
        let removed = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let (t_removed, t_done) = (removed.clone(), done.clone());
        let thread = std::thread::Builder::new()
            .name("interface-watch".into())
            .spawn(move || {
                let mut missing = 0u8;
                while sleep_unless(&t_done, INTERFACE_WATCH_INTERVAL) {
                    let Ok(devices) = pcap::Device::list() else { continue };
                    match devices.iter().find(|d| d.name == interface_id) {
                        Some(d) => {
                            missing = 0;
                            let down = matches!(d.flags.connection_status, pcap::ConnectionStatus::Disconnected);
                            counters.link_down.store(down, Ordering::Relaxed);
                        }
                        None => {
                            missing += 1;
                            if missing >= MISSING_LISTINGS_FOR_REMOVAL {
                                t_removed.store(true, Ordering::Relaxed);
                                return;
                            }
                        }
                    }
                }
            })
            .ok();
        Self { removed, done, thread }
    }

    fn finish(mut self) {
        self.done.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Sleeps in short steps; returns `false` as soon as `done` is set.
fn sleep_unless(done: &AtomicBool, total: Duration) -> bool {
    let step = Duration::from_millis(100);
    let end = Instant::now() + total;
    while Instant::now() < end {
        if done.load(Ordering::Relaxed) {
            return false;
        }
        std::thread::sleep(step);
    }
    !done.load(Ordering::Relaxed)
}
