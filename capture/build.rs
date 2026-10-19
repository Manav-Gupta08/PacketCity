//! On Windows, libpcap is provided by Npcap. Linking needs the Npcap SDK's `wpcap.lib`
//! (fetched by `scripts/fetch-npcap-sdk.ps1` into `.deps/npcap-sdk`, or pointed to by
//! `NPCAP_SDK_DIR`). At runtime `wpcap.dll` is *delay-loaded* so the app can start and explain
//! the problem when Npcap is not installed, instead of failing with a missing-DLL dialog.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=NPCAP_SDK_DIR");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let sdk = env::var("NPCAP_SDK_DIR").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("..").join(".deps").join("npcap-sdk")
    });
    let arch_dir = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "Lib/x64",
        Ok("aarch64") => "Lib/ARM64",
        _ => "Lib",
    };
    let lib_dir = sdk.join(arch_dir);
    if !lib_dir.join("wpcap.lib").exists() {
        println!(
            "cargo:warning=Npcap SDK not found at {}. Run scripts/fetch-npcap-sdk.ps1 or set NPCAP_SDK_DIR.",
            lib_dir.display()
        );
    }
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // Needed by executables that pass /DELAYLOAD:wpcap.dll (see desktop/src-tauri/build.rs).
        println!("cargo:rustc-link-lib=delayimp");
        println!("cargo:rustc-link-arg-examples=/DELAYLOAD:wpcap.dll");
    }
}
