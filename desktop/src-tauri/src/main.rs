#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod error;
mod scope;
mod session;
mod sink;

use tauri::{Manager, RunEvent};

use crate::session::AppState;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::capture_environment,
            commands::list_interfaces,
            commands::start_live_capture,
            commands::start_demo,
            commands::open_capture_file,
            commands::replay_control,
            commands::replay_status,
            commands::stop_session,
            commands::session_info,
            commands::get_packet,
            commands::get_flow,
            commands::set_payload_capture,
            commands::get_packet_bytes,
            commands::export_pcap,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build PacketCity");

    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            handle.state::<AppState>().stop_current();
        }
    });
}
