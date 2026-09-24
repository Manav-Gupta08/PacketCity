//! Per-OS capture driver handling. Everything above this module uses the portable libpcap API.

use serde::Serialize;

use crate::CaptureError;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as imp;

#[cfg(not(windows))]
mod unix;
#[cfg(not(windows))]
use unix as imp;

pub(crate) use imp::{DRIVER_HINT, PERMISSION_HINT};

mod ffi {
    #[cfg_attr(windows, link(name = "wpcap"))]
    #[cfg_attr(not(windows), link(name = "pcap"))]
    extern "C" {
        pub fn pcap_lib_version() -> *const std::os::raw::c_char;
    }
}

/// Caller must have called `ensure_library` successfully.
fn lib_version() -> String {
    // SAFETY: pcap_lib_version returns a pointer to a static NUL-terminated string.
    unsafe { std::ffi::CStr::from_ptr(ffi::pcap_lib_version()) }.to_string_lossy().into_owned()
}

/// Makes sure the capture library can be used. Must be called before any `pcap` function.
pub(crate) fn ensure_library() -> Result<(), CaptureError> {
    imp::ensure_library().map_err(CaptureError::DriverUnavailable)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureEnvironment {
    pub platform: &'static str,
    pub driver_available: bool,
    pub driver_version: Option<String>,
    pub driver_message: Option<String>,
    pub permission_hint: &'static str,
}

pub fn capture_environment() -> CaptureEnvironment {
    match ensure_library() {
        Ok(()) => CaptureEnvironment {
            platform: imp::PLATFORM,
            driver_available: true,
            driver_version: Some(lib_version()),
            driver_message: None,
            permission_hint: PERMISSION_HINT,
        },
        Err(e) => CaptureEnvironment {
            platform: imp::PLATFORM,
            driver_available: false,
            driver_version: None,
            driver_message: Some(e.to_string()),
            permission_hint: PERMISSION_HINT,
        },
    }
}
