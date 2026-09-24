fn main() {
    let windows_msvc = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if windows_msvc {
        // Start even when Npcap is missing; packetcity-capture loads wpcap.dll explicitly and reports errors.
        println!("cargo:rustc-link-arg-bins=/DELAYLOAD:wpcap.dll");
    }
    tauri_build::build()
}
