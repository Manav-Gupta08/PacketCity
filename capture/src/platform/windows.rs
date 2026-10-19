//! Windows: Npcap installs `wpcap.dll` into `%SystemRoot%\System32\Npcap` (or System32 itself in
//! WinPcap-compatible mode). The executable delay-loads `wpcap.dll`, so we load it here by full
//! path first; later delay-load resolution then finds the already-loaded module.

use std::sync::Mutex;

use windows_sys::Win32::System::LibraryLoader::{LoadLibraryExW, SetDllDirectoryW, LOAD_WITH_ALTERED_SEARCH_PATH};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

pub const PLATFORM: &str = "windows";
pub const DRIVER_HINT: &str =
    "Install Npcap from https://npcap.com (keep \"WinPcap API-compatible mode\" enabled), then restart PacketCity.";
pub const PERMISSION_HINT: &str = "Npcap may be configured to restrict capture to Administrators. Run PacketCity as Administrator or reinstall Npcap without the admin-only option.";

const MAX_PATH_CHARS: usize = 260;

/// Only success is cached, so installing Npcap while the app runs works after a retry.
static LOADED: Mutex<bool> = Mutex::new(false);

pub fn ensure_library() -> Result<(), String> {
    let mut loaded = LOADED.lock().unwrap_or_else(|p| p.into_inner());
    if !*loaded {
        load()?;
        *loaded = true;
    }
    Ok(())
}

fn wide(s: &str) -> impl Iterator<Item = u16> + '_ {
    s.encode_utf16()
}

fn system_directory() -> Option<Vec<u16>> {
    let mut buf = [0u16; MAX_PATH_CHARS];
    // SAFETY: buffer pointer and length describe a valid, writable u16 array.
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    (n > 0 && n < buf.len()).then(|| buf[..n].to_vec())
}

fn try_load(path: &[u16]) -> bool {
    let mut z = path.to_vec();
    z.push(0);
    // SAFETY: `z` is a NUL-terminated wide string; a null file handle is required by the API.
    let module = unsafe { LoadLibraryExW(z.as_ptr(), std::ptr::null_mut(), LOAD_WITH_ALTERED_SEARCH_PATH) };
    !module.is_null()
}

fn load() -> Result<(), String> {
    let system = system_directory().ok_or_else(|| "Could not locate the Windows system directory.".to_string())?;

    let mut npcap_dir = system.clone();
    npcap_dir.extend(wide("\\Npcap"));
    let mut dir_z = npcap_dir.clone();
    dir_z.push(0);
    // SAFETY: NUL-terminated wide string. Lets wpcap.dll resolve its sibling Packet.dll.
    unsafe { SetDllDirectoryW(dir_z.as_ptr()) };

    let mut npcap_wpcap = npcap_dir;
    npcap_wpcap.extend(wide("\\wpcap.dll"));
    let mut legacy_wpcap = system;
    legacy_wpcap.extend(wide("\\wpcap.dll"));

    if try_load(&npcap_wpcap) || try_load(&legacy_wpcap) {
        log::info!("Npcap wpcap.dll loaded");
        Ok(())
    } else {
        Err("Npcap is not installed (wpcap.dll was not found).".into())
    }
}
