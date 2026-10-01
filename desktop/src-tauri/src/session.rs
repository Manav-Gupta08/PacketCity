//! A session = one capture source + one engine + one pipeline thread. Starting a new session
//! stops the previous one. The pipeline thread supervises the source and reports why it ended.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use packetcity_capture::{CaptureConfig, CaptureOutcome, InterfaceInfo, LiveCapture};
use packetcity_core::capture_file::CaptureFileError;
use packetcity_core::demo::{demo_engine_config, run_demo};
use packetcity_core::pipeline::{
    self, frame_channel, wall_clock_us, ClockMode, EventSink, FrameReceiver, PipelineConfig, StreamMessage,
};
use packetcity_core::replay::{analyze, run_replay, CaptureAnalysis, ReplayControl, ReplayEnd};
use packetcity_core::{Engine, EngineConfig, LinkType};
use serde::Serialize;

use crate::error::CommandError;
use crate::scope::{demo_scope, live_scope, replay_scope, CaptureScope};
use crate::sink::ChannelSink;

/// Frames buffered between capture and processing (~6 MB at typical MTU-sized frames).
const FRAME_QUEUE_CAPACITY: usize = 4096;
pub const DEMO_DEFAULT_PACKETS_PER_SEC: f64 = 120.0;
const DEMO_MAX_PACKETS_PER_SEC: f64 = 50_000.0;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SourceKind {
    Live,
    Demo,
    Replay,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayInfo {
    pub file_name: String,
    #[serde(flatten)]
    pub analysis: CaptureAnalysis,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: u64,
    pub source: SourceKind,
    pub interface: Option<InterfaceInfo>,
    pub link: LinkType,
    pub promiscuous: bool,
    pub capture_filter: Option<String>,
    pub local_addresses: Vec<String>,
    pub started_at_us: u64,
    pub scope: CaptureScope,
    pub replay: Option<ReplayInfo>,
}

pub struct Session {
    pub info: SessionInfo,
    pub engine: Arc<Mutex<Engine>>,
    replay: Option<Arc<ReplayControl>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Session {
    fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

enum Source {
    Live(LiveCapture),
    Demo(JoinHandle<()>),
    Replay(JoinHandle<Result<ReplayEnd, CaptureFileError>>),
}

impl Source {
    /// Waits for the source to finish and describes why it ended.
    fn finish(self) -> (String, bool) {
        match self {
            Source::Live(capture) => {
                capture.stop();
                match capture.join() {
                    CaptureOutcome::Failed(e) => (e.to_string(), true),
                    CaptureOutcome::Stopped | CaptureOutcome::PipelineClosed => ("Capture stopped.".into(), false),
                }
            }
            Source::Demo(handle) => {
                let _ = handle.join();
                ("Demo stopped.".into(), false)
            }
            Source::Replay(handle) => match handle.join() {
                Ok(Err(e)) => (format!("Replay failed: {e}"), true),
                _ => ("Replay closed.".into(), false),
            },
        }
    }
}

#[derive(Default)]
pub struct AppState {
    current: Mutex<Option<Session>>,
    next_id: AtomicU64,
    /// Off at every launch; never persisted.
    payload_capture: AtomicBool,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveCaptureOptions {
    pub interface_id: String,
    #[serde(default)]
    pub promiscuous: bool,
    #[serde(default)]
    pub capture_filter: Option<String>,
}

impl AppState {
    fn slot(&self) -> std::sync::MutexGuard<'_, Option<Session>> {
        self.current.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn stop_current(&self) {
        if let Some(s) = self.slot().take() {
            s.shutdown();
        }
    }

    pub fn info(&self) -> Option<SessionInfo> {
        self.slot().as_ref().map(|s| s.info.clone())
    }

    pub fn engine(&self) -> Option<Arc<Mutex<Engine>>> {
        self.slot().as_ref().map(|s| s.engine.clone())
    }

    pub fn replay(&self) -> Option<Arc<ReplayControl>> {
        self.slot().as_ref().and_then(|s| s.replay.clone())
    }

    fn next_session_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn set_payload_capture(&self, enabled: bool) {
        self.payload_capture.store(enabled, Ordering::Relaxed);
        if let Some(engine) = self.engine() {
            engine.lock().unwrap_or_else(|p| p.into_inner()).set_payload_capture(enabled);
        }
        log::info!("payload capture {}", if enabled { "enabled" } else { "disabled" });
    }

    fn new_engine(&self, mut cfg: EngineConfig) -> Arc<Mutex<Engine>> {
        cfg.payload_capture = self.payload_capture.load(Ordering::Relaxed);
        Arc::new(Mutex::new(Engine::new(cfg)))
    }

    pub fn start_live(&self, opts: LiveCaptureOptions, sink: ChannelSink) -> Result<SessionInfo, CommandError> {
        self.stop_current();
        let (tx, rx, counters) = frame_channel(FRAME_QUEUE_CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let capture_filter = opts.capture_filter.map(|f| f.trim().to_string()).filter(|f| !f.is_empty());
        let cfg = CaptureConfig { promiscuous: opts.promiscuous, bpf_filter: capture_filter.clone(), ..CaptureConfig::new(opts.interface_id) };

        let (capture, started) = LiveCapture::start(cfg, tx, stop.clone())?;
        let iface = started.interface;
        let engine_cfg =
            EngineConfig::new(started.link, iface.local_ips(), iface.broadcast_ips()).with_networks(iface.local_networks());
        let info = SessionInfo {
            id: self.next_session_id(),
            source: SourceKind::Live,
            scope: live_scope(&iface, opts.promiscuous),
            local_addresses: iface.local_ips().iter().map(ToString::to_string).collect(),
            interface: Some(iface),
            link: started.link,
            promiscuous: opts.promiscuous,
            capture_filter,
            started_at_us: wall_clock_us(),
            replay: None,
        };
        log::info!("live session {} started on {:?}", info.id, info.interface.as_ref().map(|i| &i.display_name));
        let engine = self.new_engine(engine_cfg);
        let parts = SourceParts { rx, counters, stop, source: Source::Live(capture), replay: None, clock: ClockMode::Wall };
        self.install(info, engine, parts, sink)
    }

    pub fn start_demo(&self, packets_per_sec: Option<f64>, sink: ChannelSink) -> Result<SessionInfo, CommandError> {
        self.stop_current();
        let rate = packets_per_sec.filter(|r| r.is_finite() && *r > 0.0).unwrap_or(DEMO_DEFAULT_PACKETS_PER_SEC).min(DEMO_MAX_PACKETS_PER_SEC);
        let (tx, rx, counters) = frame_channel(FRAME_QUEUE_CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let gen_stop = stop.clone();
        let seed = wall_clock_us();
        let generator = std::thread::Builder::new()
            .name("demo-generator".into())
            .spawn(move || run_demo(&tx, &gen_stop, rate, seed))
            .map_err(|e| CommandError::internal(format!("could not start demo: {e}")))?;
        let engine_cfg = demo_engine_config();
        let info = SessionInfo {
            id: self.next_session_id(),
            source: SourceKind::Demo,
            interface: None,
            link: engine_cfg.link,
            promiscuous: false,
            capture_filter: None,
            local_addresses: engine_cfg.local_ips.iter().map(ToString::to_string).collect(),
            started_at_us: wall_clock_us(),
            scope: demo_scope(),
            replay: None,
        };
        let engine = self.new_engine(engine_cfg);
        let parts = SourceParts { rx, counters, stop, source: Source::Demo(generator), replay: None, clock: ClockMode::Wall };
        self.install(info, engine, parts, sink)
    }

    pub fn start_replay(&self, path: PathBuf, sink: ChannelSink) -> Result<SessionInfo, CommandError> {
        self.stop_current();
        let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let analysis = analyze(&path).map_err(|e| CommandError::capture_file(&e))?;
        if analysis.summary.packets == 0 {
            return Err(CommandError { code: "emptyCapture", message: "The capture file contains no packets.".into(), hint: None });
        }
        let engine_cfg =
            EngineConfig::new(analysis.link, analysis.local_ips(), Vec::new()).with_networks(analysis.local_networks());
        let engine = self.new_engine(engine_cfg.clone());
        let control = Arc::new(ReplayControl::new(analysis.summary.first_us, analysis.summary.last_us));

        let (tx, rx, counters) = frame_channel(FRAME_QUEUE_CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_stop, thread_control, thread_engine) = (stop.clone(), control.clone(), engine.clone());
        let handle = std::thread::Builder::new()
            .name("pcap-replay".into())
            .spawn(move || {
                let reset = || {
                    let mut eng = thread_engine.lock().unwrap_or_else(|p| p.into_inner());
                    let keep_bytes = eng.payload_capture();
                    *eng = Engine::new(engine_cfg.clone());
                    eng.set_payload_capture(keep_bytes);
                };
                run_replay(&path, &thread_control, &tx, &thread_stop, &reset)
            })
            .map_err(|e| CommandError::internal(format!("could not start replay: {e}")))?;

        let info = SessionInfo {
            id: self.next_session_id(),
            source: SourceKind::Replay,
            interface: None,
            link: analysis.link,
            promiscuous: false,
            capture_filter: None,
            local_addresses: analysis.local_ips().iter().map(ToString::to_string).collect(),
            started_at_us: wall_clock_us(),
            scope: replay_scope(&file_name, &analysis),
            replay: Some(ReplayInfo { file_name, analysis }),
        };
        log::info!("replay session {} started: {:?}", info.id, info.replay.as_ref().map(|r| &r.file_name));
        let parts = SourceParts { rx, counters, stop, source: Source::Replay(handle), replay: Some(control), clock: ClockMode::PacketTime };
        self.install(info, engine, parts, sink)
    }

    fn install(&self, info: SessionInfo, engine: Arc<Mutex<Engine>>, parts: SourceParts, sink: ChannelSink) -> Result<SessionInfo, CommandError> {
        let SourceParts { rx, counters, stop, source, replay, clock } = parts;
        let (thread_engine, thread_stop) = (engine.clone(), stop.clone());
        let session_id = info.id;
        let cfg = PipelineConfig { clock, ..PipelineConfig::default() };

        let thread = std::thread::Builder::new()
            .name(format!("pipeline-{session_id}"))
            .spawn(move || {
                let exit = pipeline::run(rx, thread_engine, &sink, &cfg, &counters, &thread_stop);
                thread_stop.store(true, Ordering::Relaxed);
                let (reason, error) = source.finish();
                log::info!("session {session_id} ended ({exit:?}): {reason}");
                sink.send(StreamMessage::SourceEnded { reason, error });
            })
            .map_err(|e| CommandError::internal(format!("could not start pipeline: {e}")))?;

        *self.slot() = Some(Session { info: info.clone(), engine, replay, stop, thread: Some(thread) });
        Ok(info)
    }
}

struct SourceParts {
    rx: FrameReceiver,
    counters: Arc<pipeline::PipelineCounters>,
    stop: Arc<AtomicBool>,
    source: Source,
    replay: Option<Arc<ReplayControl>>,
    clock: ClockMode,
}

/// Only regular files that look like captures are opened; the reader also validates magic.
pub fn validate_capture_path(path: &str) -> Result<PathBuf, CommandError> {
    let p = Path::new(path);
    let ok_ext = p.extension().and_then(|e| e.to_str()).is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "pcap" | "pcapng" | "cap"));
    if !p.is_absolute() || !p.is_file() || !ok_ext {
        return Err(CommandError { code: "invalidPath", message: "Choose a .pcap, .pcapng or .cap file.".into(), hint: None });
    }
    Ok(p.to_path_buf())
}

/// Export targets must be absolute `.pcap` paths in an existing directory.
pub fn validate_export_path(path: &str) -> Result<PathBuf, CommandError> {
    let p = Path::new(path);
    let ok_ext = p.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("pcap"));
    if !p.is_absolute() || !ok_ext || !p.parent().is_some_and(Path::is_dir) || p.is_dir() {
        return Err(CommandError { code: "invalidPath", message: "Choose a .pcap file in an existing folder.".into(), hint: None });
    }
    Ok(p.to_path_buf())
}
