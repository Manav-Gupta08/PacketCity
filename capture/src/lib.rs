//! Live capture on top of libpcap (Linux/macOS) and Npcap (Windows).
//!
//! libpcap offers one portable API, so the per-OS differences are limited to driver loading,
//! interface naming and permission guidance, all isolated in `platform`.

mod error;
mod interfaces;
mod live;
mod platform;

pub use error::CaptureError;
pub use interfaces::{list_interfaces, InterfaceAddress, InterfaceInfo, InterfaceKind};
pub use live::{CaptureConfig, CaptureOutcome, CaptureStarted, LiveCapture};
pub use platform::{capture_environment, CaptureEnvironment};
