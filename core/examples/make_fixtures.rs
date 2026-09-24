//! Regenerates the committed reference capture files from `packetcity_core::reference`.

use std::path::PathBuf;

use packetcity_core::capture_file::{write_pcap, write_pcapng};
use packetcity_core::reference::reference_frames;

const LINKTYPE_ETHERNET: u16 = 1;

fn main() -> std::io::Result<()> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("tests").join("fixtures");
    std::fs::create_dir_all(&dir)?;
    let frames = reference_frames();
    std::fs::write(dir.join("reference.pcap"), write_pcap(u32::from(LINKTYPE_ETHERNET), &frames))?;
    std::fs::write(dir.join("reference.pcapng"), write_pcapng(LINKTYPE_ETHERNET, &frames, true))?;
    println!("wrote {} frames to {}", frames.len(), dir.display());
    Ok(())
}
