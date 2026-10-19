//! PCAP replay: feeds a capture file through the normal pipeline, paced by its timestamps.
//!
//! A capture file does not say which machine recorded it, so "this host" is inferred as the
//! private unicast address present in the most packets, and its subnet from ARP-observed
//! neighbours (falling back to an explicitly *assumed* /24 for IPv4). The UI shows both.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::capture_file::{CaptureFileError, CaptureFileReader, CaptureSummary};
use crate::devices::LocalNetwork;
use crate::frame::{LinkType, RawFrame};
use crate::parser::parse_frame;
use crate::pipeline::FrameSender;

/// Idle gaps longer than this (file time) are shortened so replay doesn't sit silent for minutes.
pub const MAX_IDLE_GAP_US: u64 = 2_000_000;
pub const MIN_SPEED: f64 = 0.1;
pub const MAX_SPEED: f64 = 100.0;
const CONTROL_POLL: Duration = Duration::from_millis(20);
const NO_SEEK: u64 = u64::MAX;
const ASSUMED_V4_PREFIX: u8 = 24;
const ASSUMED_V6_PREFIX: u8 = 64;
const MIN_INFERRED_V4_PREFIX: u8 = 16;

type Reader = CaptureFileReader<BufReader<File>>;

pub fn open_capture(path: &Path) -> Result<Reader, CaptureFileError> {
    CaptureFileReader::new(BufReader::new(File::open(path)?))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PrefixSource {
    /// Derived from ARP traffic between the host and its neighbours.
    Arp,
    /// No ARP evidence; a conventional prefix was assumed.
    Assumed,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureAnalysis {
    #[serde(flatten)]
    pub summary: CaptureSummary,
    pub link: LinkType,
    pub inferred_host: Option<IpAddr>,
    pub inferred_prefix: Option<u8>,
    pub prefix_source: PrefixSource,
}

impl CaptureAnalysis {
    pub fn local_ips(&self) -> Vec<IpAddr> {
        self.inferred_host.into_iter().collect()
    }

    pub fn local_networks(&self) -> Vec<LocalNetwork> {
        match (self.inferred_host, self.inferred_prefix) {
            (Some(addr), Some(prefix)) => vec![LocalNetwork { addr, prefix }],
            _ => Vec::new(),
        }
    }
}

fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xFE00) == 0xFC00 || (v6.segments()[0] & 0xFFC0) == 0xFE80,
    }
}

fn is_unicast(ip: &IpAddr) -> bool {
    !ip.is_multicast() && !ip.is_unspecified() && !matches!(ip, IpAddr::V4(v4) if v4.is_broadcast() || v4.octets()[3] == 255)
}

fn common_prefix(a: &IpAddr, b: &IpAddr) -> Option<u8> {
    match (a, b) {
        (IpAddr::V4(x), IpAddr::V4(y)) => Some((u32::from(*x) ^ u32::from(*y)).leading_zeros() as u8),
        _ => None,
    }
}

/// Full pass over the file: packet counts/time span plus local host inference.
pub fn analyze(path: &Path) -> Result<CaptureAnalysis, CaptureFileError> {
    let mut reader = open_capture(path)?;
    let link = reader.link_type();
    let mut summary = CaptureSummary::default();
    let mut counts: HashMap<IpAddr, u64> = HashMap::new();
    let mut arp_ips: HashSet<IpAddr> = HashSet::new();

    while let Some(f) = reader.next_frame()? {
        if summary.packets == 0 {
            summary.first_us = f.timestamp_us;
        }
        summary.packets += 1;
        summary.bytes += u64::from(f.wire_len);
        summary.last_us = summary.last_us.max(f.timestamp_us);

        let pkt = parse_frame(link, &f.data, f.wire_len);
        if let Some(arp) = &pkt.arp {
            for ip in [arp.sender_ip, arp.target_ip] {
                if !ip.is_unspecified() {
                    arp_ips.insert(IpAddr::V4(ip));
                }
            }
        }
        for ip in [pkt.src_ip(), pkt.dst_ip()].into_iter().flatten().filter(is_unicast) {
            *counts.entry(ip).or_default() += 1;
        }
    }
    summary.skipped_frames = reader.skipped_frames;

    let busiest = |private: bool| counts.iter().filter(|(ip, _)| is_private(ip) == private).max_by_key(|(ip, n)| (**n, **ip)).map(|(ip, _)| *ip);
    let inferred_host = busiest(true).or_else(|| busiest(false));

    let (inferred_prefix, prefix_source) = match inferred_host {
        Some(host @ IpAddr::V4(_)) => {
            let neighbours: Vec<u8> = arp_ips.iter().filter(|ip| **ip != host).filter_map(|ip| common_prefix(&host, ip)).collect();
            // Neighbours only bound the prefix from above; use /24 unless they prove the LAN is wider.
            match neighbours.iter().min() {
                Some(&p) => (Some(p.clamp(MIN_INFERRED_V4_PREFIX, ASSUMED_V4_PREFIX)), PrefixSource::Arp),
                None => (Some(ASSUMED_V4_PREFIX), PrefixSource::Assumed),
            }
        }
        Some(IpAddr::V6(_)) => (Some(ASSUMED_V6_PREFIX), PrefixSource::Assumed),
        None => (None, PrefixSource::Assumed),
    };

    Ok(CaptureAnalysis { summary, link, inferred_host, inferred_prefix, prefix_source })
}

/// Shared between the UI commands and the replay thread.
#[derive(Debug)]
pub struct ReplayControl {
    playing: AtomicBool,
    speed_milli: AtomicU32,
    seek_to_us: AtomicU64,
    position_us: AtomicU64,
    finished: AtomicBool,
    /// Incremented on every seek so the UI knows to clear vehicles in flight.
    generation: AtomicU64,
    start_us: u64,
    end_us: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayStatus {
    pub position_us: u64,
    pub start_us: u64,
    pub end_us: u64,
    pub playing: bool,
    pub speed: f64,
    pub finished: bool,
    pub generation: u64,
}

impl ReplayControl {
    pub fn new(start_us: u64, end_us: u64) -> Self {
        Self {
            playing: AtomicBool::new(true),
            speed_milli: AtomicU32::new(1000),
            seek_to_us: AtomicU64::new(NO_SEEK),
            position_us: AtomicU64::new(start_us),
            finished: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            start_us,
            end_us,
        }
    }

    pub fn play(&self) {
        // Playing a finished replay starts it over.
        if self.finished.load(Ordering::Relaxed) {
            self.seek(self.start_us);
        }
        self.playing.store(true, Ordering::Relaxed);
    }

    pub fn pause(&self) {
        self.playing.store(false, Ordering::Relaxed);
    }

    pub fn set_speed(&self, speed: f64) {
        let s = if speed.is_finite() { speed.clamp(MIN_SPEED, MAX_SPEED) } else { 1.0 };
        self.speed_milli.store((s * 1000.0).round() as u32, Ordering::Relaxed);
    }

    pub fn speed(&self) -> f64 {
        f64::from(self.speed_milli.load(Ordering::Relaxed)) / 1000.0
    }

    pub fn seek(&self, to_us: u64) {
        self.seek_to_us.store(to_us.clamp(self.start_us, self.end_us), Ordering::Relaxed);
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn status(&self) -> ReplayStatus {
        ReplayStatus {
            position_us: self.position_us.load(Ordering::Relaxed),
            start_us: self.start_us,
            end_us: self.end_us,
            playing: self.playing.load(Ordering::Relaxed),
            speed: self.speed(),
            finished: self.finished.load(Ordering::Relaxed),
            generation: self.generation.load(Ordering::Relaxed),
        }
    }

    fn take_seek(&self) -> Option<u64> {
        match self.seek_to_us.swap(NO_SEEK, Ordering::Relaxed) {
            NO_SEEK => None,
            t => Some(t),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayEnd {
    Stopped,
    PipelineClosed,
}

/// Runs until `stop` is set or the pipeline closes. Reaching the end of the file pauses (so the
/// user can seek back) rather than ending the session. `reset_engine` is called before a seek.
pub fn run_replay(
    path: &Path,
    control: &ReplayControl,
    tx: &FrameSender,
    stop: &AtomicBool,
    reset_engine: &dyn Fn(),
) -> Result<ReplayEnd, CaptureFileError> {
    let mut reader = open_capture(path)?;
    let mut next = reader.next_frame()?;
    // (wall instant, file timestamp) pair that pacing is measured from.
    let mut anchor: Option<(Instant, u64)> = None;
    let mut anchored_speed = control.speed();

    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(ReplayEnd::Stopped);
        }
        if let Some(target) = control.take_seek() {
            reset_engine();
            reader = open_capture(path)?;
            next = reader.next_frame()?;
            while next.as_ref().is_some_and(|f| f.timestamp_us < target) {
                next = reader.next_frame()?;
            }
            control.position_us.store(target, Ordering::Relaxed);
            control.finished.store(false, Ordering::Relaxed);
            anchor = None;
            continue;
        }
        if !control.playing.load(Ordering::Relaxed) {
            anchor = None;
            std::thread::sleep(CONTROL_POLL);
            continue;
        }
        let Some(frame) = next.take() else {
            control.finished.store(true, Ordering::Relaxed);
            control.playing.store(false, Ordering::Relaxed);
            continue;
        };

        let speed = control.speed();
        let position = control.position_us.load(Ordering::Relaxed);
        if speed != anchored_speed || frame.timestamp_us.saturating_sub(position) > MAX_IDLE_GAP_US {
            anchor = None;
            anchored_speed = speed;
        }
        let (wall0, file0) = *anchor.get_or_insert((Instant::now(), frame.timestamp_us.max(position).min(frame.timestamp_us)));
        let offset_us = frame.timestamp_us.saturating_sub(file0) as f64 / speed;
        let due = wall0 + Duration::from_micros(offset_us as u64);
        let now = Instant::now();
        if due > now {
            next = Some(frame);
            std::thread::sleep((due - now).min(CONTROL_POLL));
            continue;
        }

        control.position_us.store(frame.timestamp_us, Ordering::Relaxed);
        if !tx.send_blocking(frame, stop) {
            return Ok(if stop.load(Ordering::Relaxed) { ReplayEnd::Stopped } else { ReplayEnd::PipelineClosed });
        }
        next = reader.next_frame()?;
    }
}

/// Convenience for tests and tools: all frames of a file.
pub fn read_all(path: &Path) -> Result<(LinkType, Vec<RawFrame>), CaptureFileError> {
    let mut r = open_capture(path)?;
    let mut frames = Vec::new();
    while let Some(f) = r.next_frame()? {
        frames.push(f);
    }
    Ok((r.link_type(), frames))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    use super::*;
    use crate::capture_file::write_pcap;
    use crate::pipeline::frame_channel;
    use crate::reference::{self, reference_frames};

    fn temp_capture(name: &str, frames: &[RawFrame]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("packetcity-{}-{name}.pcap", std::process::id()));
        std::fs::write(&path, write_pcap(1, frames)).unwrap();
        path
    }

    #[test]
    fn analysis_infers_host_and_subnet_from_arp() {
        let path = temp_capture("analyze", &reference_frames());
        let a = analyze(&path).unwrap();
        assert_eq!(a.summary.packets, 15);
        assert_eq!(a.inferred_host, Some(IpAddr::V4(reference::LOCAL_IP)));
        assert_eq!(a.inferred_prefix, Some(24), "neighbours within a /24 keep the conventional /24");
        assert_eq!(a.prefix_source, PrefixSource::Arp);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn replays_all_frames_in_order_and_pauses_at_end() {
        let frames = reference_frames();
        let path = temp_capture("replay", &frames);
        let control = Arc::new(ReplayControl::new(frames[0].timestamp_us, frames.last().unwrap().timestamp_us));
        control.set_speed(MAX_SPEED);
        let (tx, rx, _) = frame_channel(64);
        let stop = Arc::new(AtomicBool::new(false));
        let (c, s, p) = (control.clone(), stop.clone(), path.clone());
        let handle = std::thread::spawn(move || run_replay(&p, &c, &tx, &s, &|| {}));

        let got: Vec<RawFrame> = (0..frames.len()).map(|_| rx.recv_timeout(Duration::from_secs(5)).unwrap()).collect();
        assert!(got.windows(2).all(|w| w[0].timestamp_us <= w[1].timestamp_us));
        let deadline = Instant::now() + Duration::from_secs(2);
        while !control.status().finished && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(control.status().finished);
        assert!(!control.status().playing);

        stop.store(true, Ordering::Relaxed);
        assert_eq!(handle.join().unwrap().unwrap(), ReplayEnd::Stopped);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn seek_resets_engine_and_skips_earlier_frames() {
        let frames = reference_frames();
        let path = temp_capture("seek", &frames);
        let control = Arc::new(ReplayControl::new(frames[0].timestamp_us, frames.last().unwrap().timestamp_us));
        control.pause();
        control.set_speed(MAX_SPEED);
        let target = frames[10].timestamp_us;
        control.seek(target);
        control.play();
        let resets = Arc::new(AtomicUsize::new(0));
        let (tx, rx, _) = frame_channel(64);
        let stop = Arc::new(AtomicBool::new(false));
        let (c, s, p, r) = (control.clone(), stop.clone(), path.clone(), resets.clone());
        let handle = std::thread::spawn(move || {
            run_replay(&p, &c, &tx, &s, &|| {
                r.fetch_add(1, Ordering::Relaxed);
            })
        });

        let first = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(first.timestamp_us, target);
        assert_eq!(resets.load(Ordering::Relaxed), 1);
        assert_eq!(control.status().generation, 1);
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap().unwrap();
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn speed_is_clamped() {
        let c = ReplayControl::new(0, 10);
        c.set_speed(1e9);
        assert_eq!(c.speed(), MAX_SPEED);
        c.set_speed(f64::NAN);
        assert_eq!(c.speed(), 1.0);
    }
}
