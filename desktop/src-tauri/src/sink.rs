use packetcity_core::pipeline::{EventSink, StreamMessage};
use tauri::ipc::Channel;

/// Streams pipeline messages to the webview over a Tauri channel (ordered, per-session).
pub struct ChannelSink(pub Channel<StreamMessage>);

impl EventSink for ChannelSink {
    fn send(&self, msg: StreamMessage) -> bool {
        match self.0.send(msg) {
            Ok(()) => true,
            Err(e) => {
                log::warn!("UI channel closed: {e}");
                false
            }
        }
    }
}
