//! Linux and macOS link libpcap directly; there is no driver to load at runtime.

#[cfg(target_os = "macos")]
pub const PLATFORM: &str = "macos";
#[cfg(not(target_os = "macos"))]
pub const PLATFORM: &str = "linux";

pub const DRIVER_HINT: &str = "Install libpcap (e.g. `sudo apt install libpcap0.8` or it ships with macOS).";

#[cfg(target_os = "macos")]
pub const PERMISSION_HINT: &str =
    "macOS restricts /dev/bpf*. Install Wireshark's ChmodBPF helper or run PacketCity with elevated privileges.";
#[cfg(not(target_os = "macos"))]
pub const PERMISSION_HINT: &str =
    "Grant capture capabilities once: `sudo setcap cap_net_raw,cap_net_admin=eip <path-to-packetcity>`.";

pub fn ensure_library() -> Result<(), String> {
    Ok(())
}
