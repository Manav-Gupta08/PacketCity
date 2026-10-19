use std::io::Cursor;

use super::*;

fn frames() -> Vec<RawFrame> {
    (0..5u64)
        .map(|i| RawFrame { timestamp_us: 1_700_000_000_000_000 + i * 1_500, wire_len: 60 + i as u32, data: vec![i as u8; 20 + i as usize] })
        .collect()
}

fn read_all(bytes: Vec<u8>) -> (LinkType, Vec<RawFrame>, u64) {
    let mut r = CaptureFileReader::new(Cursor::new(bytes)).unwrap();
    let mut out = Vec::new();
    while let Some(f) = r.next_frame().unwrap() {
        out.push(f);
    }
    (r.link_type(), out, r.skipped_frames)
}

fn assert_same(a: &[RawFrame], b: &[RawFrame]) {
    assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(b) {
        assert_eq!((x.timestamp_us, x.wire_len, &x.data), (y.timestamp_us, y.wire_len, &y.data));
    }
}

#[test]
fn classic_pcap_roundtrip() {
    let (link, got, _) = read_all(write_pcap(1, &frames()));
    assert_eq!(link, LinkType::Ethernet);
    assert_same(&got, &frames());
}

#[test]
fn big_endian_nanosecond_pcap() {
    let mut b = Vec::new();
    b.extend_from_slice(&PCAP_MAGIC_NS.to_be_bytes());
    b.extend_from_slice(&[0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]);
    b.extend_from_slice(&101u32.to_be_bytes());
    b.extend_from_slice(&10u32.to_be_bytes());
    b.extend_from_slice(&123_456_789u32.to_be_bytes());
    b.extend_from_slice(&4u32.to_be_bytes());
    b.extend_from_slice(&4u32.to_be_bytes());
    b.extend_from_slice(&[0x45, 0, 0, 20]);
    let (link, got, _) = read_all(b);
    assert_eq!(link, LinkType::RawIp);
    assert_eq!(got[0].timestamp_us, 10_123_456);
}

#[test]
fn pcapng_microsecond_and_nanosecond_resolution() {
    for nanos in [false, true] {
        let (link, got, skipped) = read_all(write_pcapng(1, &frames(), nanos));
        assert_eq!(link, LinkType::Ethernet);
        assert_eq!(skipped, 0);
        assert_same(&got, &frames());
    }
}

#[test]
fn pcapng_skips_frames_from_other_link_types_and_reads_simple_packets() {
    let mut b = write_pcapng(1, &frames()[..1], false);
    let mut idb = Vec::new();
    idb.extend_from_slice(&101u16.to_le_bytes());
    idb.extend_from_slice(&[0, 0, 0xFF, 0xFF, 0, 0]);
    pcapng_block(&mut b, BLOCK_IDB, &idb);
    let mut epb = Vec::new();
    epb.extend_from_slice(&1u32.to_le_bytes());
    epb.extend_from_slice(&[0; 8]);
    epb.extend_from_slice(&4u32.to_le_bytes());
    epb.extend_from_slice(&4u32.to_le_bytes());
    epb.extend_from_slice(&[0x45, 0, 0, 20]);
    pcapng_block(&mut b, BLOCK_ENHANCED_PACKET, &epb);
    let mut spb = Vec::new();
    spb.extend_from_slice(&3u32.to_le_bytes());
    spb.extend_from_slice(&[7, 7, 7]);
    pcapng_block(&mut b, BLOCK_SIMPLE_PACKET, &spb);

    let (_, got, skipped) = read_all(b);
    assert_eq!(skipped, 1);
    assert_eq!(got.len(), 2);
    assert_eq!(got[1].data, vec![7, 7, 7]);
    assert_eq!(got[1].timestamp_us, got[0].timestamp_us, "SPB inherits the previous timestamp");
}

#[test]
fn second_section_resets_interfaces() {
    let mut b = write_pcapng(1, &frames()[..2], false);
    b.extend(write_pcapng(1, &frames()[2..], false));
    let (_, got, _) = read_all(b);
    assert_same(&got, &frames());
}

#[test]
fn rejects_non_capture_and_unsupported_files() {
    assert!(matches!(CaptureFileReader::new(Cursor::new(b"hello world, not pcap".to_vec())), Err(CaptureFileError::NotACaptureFile)));
    assert!(matches!(CaptureFileReader::new(Cursor::new(Vec::new())), Err(CaptureFileError::NotACaptureFile)));
    assert!(matches!(CaptureFileReader::new(Cursor::new(write_pcap(147, &frames()))), Err(CaptureFileError::UnsupportedLinkType(147))));
}

#[test]
fn damaged_files_error_instead_of_panicking() {
    let full = write_pcapng(1, &frames(), false);
    for cut in 1..full.len() {
        let Ok(mut r) = CaptureFileReader::new(Cursor::new(full[..cut].to_vec())) else { continue };
        while let Ok(Some(_)) = r.next_frame() {}
    }
    let mut huge = write_pcap(1, &[]);
    huge.extend_from_slice(&[0; 8]);
    huge.extend_from_slice(&u32::MAX.to_le_bytes());
    huge.extend_from_slice(&u32::MAX.to_le_bytes());
    let mut r = CaptureFileReader::new(Cursor::new(huge)).unwrap();
    assert!(matches!(r.next_frame(), Err(CaptureFileError::Corrupt(_))));
}

#[test]
fn summary_counts_packets_and_span() {
    let mut r = CaptureFileReader::new(Cursor::new(write_pcap(1, &frames()))).unwrap();
    let s = summarize(&mut r).unwrap();
    assert_eq!(s.packets, 5);
    assert_eq!(s.last_us - s.first_us, 6_000);
    assert_eq!(s.bytes, (60..65).sum::<u64>());
}
