use packetcity_capture::{CaptureEnvironment, InterfaceInfo};
use packetcity_core::capture_file::write_pcap;
use packetcity_core::flows::FlowSnapshot;
use packetcity_core::pipeline::StreamMessage;
use packetcity_core::replay::ReplayStatus;
use packetcity_core::PacketRecord;
use serde::Deserialize;
use tauri::ipc::Channel;
use tauri::State;

use crate::error::CommandError;
use crate::session::{validate_capture_path, validate_export_path, AppState, LiveCaptureOptions, SessionInfo};
use crate::sink::ChannelSink;

#[tauri::command]
pub fn capture_environment() -> CaptureEnvironment {
    packetcity_capture::capture_environment()
}

#[tauri::command(async)]
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, CommandError> {
    Ok(packetcity_capture::list_interfaces()?)
}

#[tauri::command(async)]
pub fn start_live_capture(
    state: State<'_, AppState>,
    options: LiveCaptureOptions,
    on_event: Channel<StreamMessage>,
) -> Result<SessionInfo, CommandError> {
    state.start_live(options, ChannelSink(on_event))
}

#[tauri::command(async)]
pub fn start_demo(
    state: State<'_, AppState>,
    packets_per_sec: Option<f64>,
    on_event: Channel<StreamMessage>,
) -> Result<SessionInfo, CommandError> {
    state.start_demo(packets_per_sec, ChannelSink(on_event))
}

#[tauri::command(async)]
pub fn open_capture_file(state: State<'_, AppState>, path: String, on_event: Channel<StreamMessage>) -> Result<SessionInfo, CommandError> {
    let path = validate_capture_path(&path)?;
    state.start_replay(path, ChannelSink(on_event))
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ReplayAction {
    Play,
    Pause,
    Speed { value: f64 },
    Seek { position_us: u64 },
}

#[tauri::command]
pub fn replay_control(state: State<'_, AppState>, command: ReplayAction) -> Result<ReplayStatus, CommandError> {
    let control = state.replay().ok_or_else(|| CommandError::internal("No replay is active."))?;
    match command {
        ReplayAction::Play => control.play(),
        ReplayAction::Pause => control.pause(),
        ReplayAction::Speed { value } => control.set_speed(value),
        ReplayAction::Seek { position_us } => control.seek(position_us),
    }
    Ok(control.status())
}

#[tauri::command]
pub fn replay_status(state: State<'_, AppState>) -> Option<ReplayStatus> {
    state.replay().map(|c| c.status())
}

#[tauri::command(async)]
pub fn stop_session(state: State<'_, AppState>) {
    state.stop_current();
}

#[tauri::command]
pub fn session_info(state: State<'_, AppState>) -> Option<SessionInfo> {
    state.info()
}

/// Returns `None` if no session is active or the packet has left the retention ring.
#[tauri::command]
pub fn get_packet(state: State<'_, AppState>, id: u64) -> Option<PacketRecord> {
    let engine = state.engine()?;
    let guard = engine.lock().ok()?;
    guard.packet(id).cloned()
}

#[tauri::command]
pub fn get_flow(state: State<'_, AppState>, id: u64) -> Option<FlowSnapshot> {
    let engine = state.engine()?;
    let guard = engine.lock().ok()?;
    guard.flow(id)
}

#[tauri::command]
pub fn set_payload_capture(state: State<'_, AppState>, enabled: bool) {
    state.set_payload_capture(enabled);
}

/// Raw frame bytes, only if payload capture was on when the packet arrived.
#[tauri::command]
pub fn get_packet_bytes(state: State<'_, AppState>, id: u64) -> Option<Vec<u8>> {
    let engine = state.engine()?;
    let guard = engine.lock().ok()?;
    guard.packet_bytes(id).map(<[u8]>::to_vec)
}

/// Writes the frames kept by payload capture to a classic pcap file; returns how many.
#[tauri::command(async)]
pub fn export_pcap(state: State<'_, AppState>, path: String) -> Result<usize, CommandError> {
    let path = validate_export_path(&path)?;
    let engine = state.engine().ok_or_else(|| CommandError::internal("No session is active."))?;
    let (link, frames) = {
        let guard = engine.lock().map_err(|_| CommandError::internal("Engine is unavailable."))?;
        (guard.link(), guard.kept_frames())
    };
    if frames.is_empty() {
        return Err(CommandError {
            code: "nothingToExport",
            message: "No packet bytes have been kept yet.".into(),
            hint: Some("Enable \"Keep packet bytes\" in Settings, let some traffic arrive, then export."),
        });
    }
    std::fs::write(&path, write_pcap(link.linktype(), &frames)).map_err(|e| CommandError::internal(format!("Could not write {}: {e}", path.display())))?;
    Ok(frames.len())
}
