//! Pure-Rust reader/writer for capture files, so PCAP replay needs no capture driver.
//!
//! Supports classic pcap (both byte orders, µs and ns timestamps) and pcapng (SHB, IDB with
//! `if_tsresol`, EPB, SPB, obsolete PB). pcapng files may mix interfaces; only frames whose
//! interface has the primary link type are returned, the rest are counted in `skipped_frames`.
//! Block and record sizes are bounded so a corrupt or hostile file cannot force huge allocations.

use std::fmt;
use std::io::{self, Read};

use crate::frame::{LinkType, RawFrame};

const PCAP_MAGIC_US: u32 = 0xA1B2_C3D4;
const PCAP_MAGIC_NS: u32 = 0xA1B2_3C4D;
const PCAPNG_SHB: u32 = 0x0A0D_0D0A;
const PCAPNG_BYTE_ORDER: u32 = 0x1A2B_3C4D;
const BLOCK_IDB: u32 = 1;
const BLOCK_OBSOLETE_PACKET: u32 = 2;
const BLOCK_SIMPLE_PACKET: u32 = 3;
const BLOCK_ENHANCED_PACKET: u32 = 6;
const OPT_END: u16 = 0;
const OPT_IF_TSRESOL: u16 = 9;
/// Largest record/block accepted (jumbo frames and offloaded segments fit comfortably).
const MAX_RECORD_LEN: u32 = 256 * 1024;
const MAX_BLOCK_LEN: u32 = 16 * 1024 * 1024;
const US_PER_SEC: u128 = 1_000_000;
/// LINKTYPE values carry FCS flags in the upper bits (pcap spec); the type is the low 16 bits.
const LINKTYPE_MASK: u32 = 0xFFFF;

#[derive(Debug)]
pub enum CaptureFileError {
    Io(io::Error),
    NotACaptureFile,
    UnsupportedLinkType(u32),
    Corrupt(&'static str),
}

impl fmt::Display for CaptureFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "could not read the file: {e}"),
            Self::NotACaptureFile => f.write_str("this is not a pcap or pcapng capture file"),
            Self::UnsupportedLinkType(t) => write!(f, "the capture uses an unsupported link type ({t})"),
            Self::Corrupt(why) => write!(f, "the capture file is damaged: {why}"),
        }
    }
}

impl std::error::Error for CaptureFileError {}

impl From<io::Error> for CaptureFileError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

type Result<T> = std::result::Result<T, CaptureFileError>;

#[derive(Clone, Copy, Debug)]
struct Endian(bool);

impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        if self.0 { u16::from_be_bytes(a) } else { u16::from_le_bytes(a) }
    }
    fn u32(self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if self.0 { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
    }
}

/// Reads exactly `buf.len()` bytes; `Ok(false)` on a clean EOF before the first byte.
fn read_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(CaptureFileError::Corrupt("unexpected end of file")),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

#[derive(Clone, Copy, Debug)]
struct Interface {
    raw_link: u32,
    /// Timestamp ticks per second.
    ticks_per_sec: u128,
}

enum Format {
    Pcap { endian: Endian, nanos: bool },
    PcapNg { endian: Endian, interfaces: Vec<Interface> },
}

pub struct CaptureFileReader<R: Read> {
    r: R,
    format: Format,
    link: Option<LinkType>,
    raw_link: Option<u32>,
    pending: Option<RawFrame>,
    last_ts_us: u64,
    pub skipped_frames: u64,
}

impl<R: Read> CaptureFileReader<R> {
    pub fn new(mut r: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        if !read_or_eof(&mut r, &mut magic)? {
            return Err(CaptureFileError::NotACaptureFile);
        }
        let le = u32::from_le_bytes(magic);
        let be = u32::from_be_bytes(magic);
        let mut reader = if le == PCAPNG_SHB {
            Self::blank(r, Format::PcapNg { endian: Endian(false), interfaces: Vec::new() })
        } else if [PCAP_MAGIC_US, PCAP_MAGIC_NS].contains(&le) {
            Self::blank(r, Format::Pcap { endian: Endian(false), nanos: le == PCAP_MAGIC_NS })
        } else if [PCAP_MAGIC_US, PCAP_MAGIC_NS].contains(&be) {
            Self::blank(r, Format::Pcap { endian: Endian(true), nanos: be == PCAP_MAGIC_NS })
        } else {
            return Err(CaptureFileError::NotACaptureFile);
        };

        match reader.format {
            Format::Pcap { endian, .. } => {
                let mut hdr = [0u8; 20];
                if !read_or_eof(&mut reader.r, &mut hdr)? {
                    return Err(CaptureFileError::Corrupt("truncated file header"));
                }
                let raw = endian.u32(&hdr[16..20]) & LINKTYPE_MASK;
                reader.raw_link = Some(raw);
                reader.link = LinkType::from_dlt(raw as i32);
            }
            Format::PcapNg { .. } => {
                reader.read_section_header()?;
                // Reading the first packet also consumes the interface blocks before it.
                reader.pending = reader.next_block()?;
            }
        }
        match (reader.link, reader.raw_link) {
            (Some(_), _) => Ok(reader),
            (None, Some(raw)) => Err(CaptureFileError::UnsupportedLinkType(raw)),
            (None, None) => Err(CaptureFileError::Corrupt("no interface description")),
        }
    }

    fn blank(r: R, format: Format) -> Self {
        Self { r, format, link: None, raw_link: None, pending: None, last_ts_us: 0, skipped_frames: 0 }
    }

    pub fn link_type(&self) -> LinkType {
        self.link.expect("constructor guarantees a supported link type")
    }

    pub fn next_frame(&mut self) -> Result<Option<RawFrame>> {
        if let Some(f) = self.pending.take() {
            return Ok(Some(f));
        }
        match self.format {
            Format::Pcap { endian, nanos } => self.next_pcap_record(endian, nanos),
            Format::PcapNg { .. } => self.next_block(),
        }
    }

    fn next_pcap_record(&mut self, endian: Endian, nanos: bool) -> Result<Option<RawFrame>> {
        let mut hdr = [0u8; 16];
        if !read_or_eof(&mut self.r, &mut hdr)? {
            return Ok(None);
        }
        let secs = u64::from(endian.u32(&hdr[0..4]));
        let frac = u64::from(endian.u32(&hdr[4..8]));
        let incl = endian.u32(&hdr[8..12]);
        let orig = endian.u32(&hdr[12..16]);
        if incl > MAX_RECORD_LEN {
            return Err(CaptureFileError::Corrupt("record larger than supported"));
        }
        let mut data = vec![0u8; incl as usize];
        if !read_or_eof(&mut self.r, &mut data)? && incl > 0 {
            return Err(CaptureFileError::Corrupt("truncated record"));
        }
        let timestamp_us = secs * 1_000_000 + if nanos { frac / 1000 } else { frac };
        self.last_ts_us = timestamp_us;
        Ok(Some(RawFrame { timestamp_us, wire_len: orig.max(incl), data }))
    }

    fn endian(&self) -> Endian {
        match self.format {
            Format::Pcap { endian, .. } | Format::PcapNg { endian, .. } => endian,
        }
    }

    /// Called with the SHB block type already consumed.
    fn read_section_header(&mut self) -> Result<()> {
        let mut total_raw = [0u8; 4];
        if !read_or_eof(&mut self.r, &mut total_raw)? {
            return Err(CaptureFileError::Corrupt("truncated section header"));
        }
        self.read_section_after_length(total_raw)
    }

    /// The byte-order magic that follows the length decides how the length itself is read.
    fn read_section_after_length(&mut self, total_raw: [u8; 4]) -> Result<()> {
        let mut bom = [0u8; 4];
        if !read_or_eof(&mut self.r, &mut bom)? {
            return Err(CaptureFileError::Corrupt("truncated section header"));
        }
        let endian = match u32::from_le_bytes(bom) {
            PCAPNG_BYTE_ORDER => Endian(false),
            m if m.swap_bytes() == PCAPNG_BYTE_ORDER => Endian(true),
            _ => return Err(CaptureFileError::Corrupt("bad byte-order magic")),
        };
        let total = endian.u32(&total_raw);
        if !(28..=MAX_BLOCK_LEN).contains(&total) || total % 4 != 0 {
            return Err(CaptureFileError::Corrupt("bad section header length"));
        }
        let mut rest = vec![0u8; total as usize - 12];
        if !read_or_eof(&mut self.r, &mut rest)? {
            return Err(CaptureFileError::Corrupt("truncated section header"));
        }
        // A new section starts a new interface numbering.
        self.format = Format::PcapNg { endian, interfaces: Vec::new() };
        Ok(())
    }

    fn next_block(&mut self) -> Result<Option<RawFrame>> {
        loop {
            let mut head = [0u8; 8];
            if !read_or_eof(&mut self.r, &mut head)? {
                return Ok(None);
            }
            // The SHB type is a palindrome, so it is recognisable before the byte order is known.
            if u32::from_le_bytes([head[0], head[1], head[2], head[3]]) == PCAPNG_SHB {
                self.read_section_after_length([head[4], head[5], head[6], head[7]])?;
                continue;
            }
            let endian = self.endian();
            let block_type = endian.u32(&head[0..4]);
            let total = endian.u32(&head[4..8]);
            if !(12..=MAX_BLOCK_LEN).contains(&total) || total % 4 != 0 {
                return Err(CaptureFileError::Corrupt("bad block length"));
            }
            let mut body = vec![0u8; total as usize - 8];
            if !read_or_eof(&mut self.r, &mut body)? {
                return Err(CaptureFileError::Corrupt("truncated block"));
            }
            let body = &body[..body.len() - 4];
            match block_type {
                BLOCK_IDB => self.add_interface(endian, body)?,
                BLOCK_ENHANCED_PACKET => {
                    if let Some(f) = self.packet(endian, body, 0)? {
                        return Ok(Some(f));
                    }
                }
                BLOCK_OBSOLETE_PACKET => {
                    if let Some(f) = self.packet(endian, body, 1)? {
                        return Ok(Some(f));
                    }
                }
                BLOCK_SIMPLE_PACKET => {
                    if let Some(f) = self.simple_packet(endian, body)? {
                        return Ok(Some(f));
                    }
                }
                _ => {}
            }
        }
    }

    fn add_interface(&mut self, endian: Endian, body: &[u8]) -> Result<()> {
        if body.len() < 8 {
            return Err(CaptureFileError::Corrupt("truncated interface description"));
        }
        let raw_link = u32::from(endian.u16(&body[0..2]));
        let mut ticks_per_sec = US_PER_SEC;
        let mut opt = &body[8..];
        while opt.len() >= 4 {
            let code = endian.u16(&opt[0..2]);
            let len = usize::from(endian.u16(&opt[2..4]));
            if code == OPT_END || opt.len() < 4 + len {
                break;
            }
            if code == OPT_IF_TSRESOL && len >= 1 {
                let v = opt[4];
                let exp = u32::from(v & 0x7F);
                // MSB set: negative power of 2; clear: negative power of 10.
                ticks_per_sec = if v & 0x80 != 0 { 1u128.checked_shl(exp).unwrap_or(0) } else { 10u128.checked_pow(exp).unwrap_or(0) };
                if ticks_per_sec == 0 {
                    return Err(CaptureFileError::Corrupt("invalid timestamp resolution"));
                }
            }
            opt = &opt[4 + len.div_ceil(4) * 4..];
        }
        if self.raw_link.is_none() {
            self.raw_link = Some(raw_link);
            self.link = LinkType::from_dlt(raw_link as i32);
        }
        if let Format::PcapNg { interfaces, .. } = &mut self.format {
            interfaces.push(Interface { raw_link, ticks_per_sec });
        }
        Ok(())
    }

    fn interface(&self, id: usize) -> Option<Interface> {
        match &self.format {
            Format::PcapNg { interfaces, .. } => interfaces.get(id).copied(),
            Format::Pcap { .. } => None,
        }
    }

    /// EPB (`id_width` 0 → 4-byte interface id) or obsolete PB (1 → 2-byte id + 2-byte drops).
    fn packet(&mut self, endian: Endian, body: &[u8], id_width: u8) -> Result<Option<RawFrame>> {
        if body.len() < 20 {
            return Err(CaptureFileError::Corrupt("truncated packet block"));
        }
        let id = if id_width == 0 { endian.u32(&body[0..4]) as usize } else { usize::from(endian.u16(&body[0..2])) };
        let ts = (u128::from(endian.u32(&body[4..8])) << 32) | u128::from(endian.u32(&body[8..12]));
        let caplen = endian.u32(&body[12..16]);
        let orig = endian.u32(&body[16..20]);
        if caplen > MAX_RECORD_LEN || 20 + caplen as usize > body.len() {
            return Err(CaptureFileError::Corrupt("packet data exceeds block"));
        }
        let iface = self.interface(id).ok_or(CaptureFileError::Corrupt("packet references unknown interface"))?;
        if iface.raw_link != self.raw_link.unwrap_or(u32::MAX) {
            self.skipped_frames += 1;
            return Ok(None);
        }
        let timestamp_us = (ts * US_PER_SEC / iface.ticks_per_sec) as u64;
        self.last_ts_us = timestamp_us;
        let data = body[20..20 + caplen as usize].to_vec();
        Ok(Some(RawFrame { timestamp_us, wire_len: orig.max(caplen), data }))
    }

    /// SPBs carry no timestamp; they inherit the previous packet's time.
    fn simple_packet(&mut self, endian: Endian, body: &[u8]) -> Result<Option<RawFrame>> {
        if body.len() < 4 {
            return Err(CaptureFileError::Corrupt("truncated simple packet"));
        }
        let orig = endian.u32(&body[0..4]);
        let caplen = (orig as usize).min(body.len() - 4);
        Ok(Some(RawFrame { timestamp_us: self.last_ts_us, wire_len: orig, data: body[4..4 + caplen].to_vec() }))
    }
}

/// Header-level summary used for the replay timeline.
#[derive(Clone, Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureSummary {
    pub packets: u64,
    pub bytes: u64,
    pub first_us: u64,
    pub last_us: u64,
    pub skipped_frames: u64,
}

pub fn summarize<R: Read>(reader: &mut CaptureFileReader<R>) -> Result<CaptureSummary> {
    let mut s = CaptureSummary::default();
    while let Some(f) = reader.next_frame()? {
        if s.packets == 0 {
            s.first_us = f.timestamp_us;
        }
        s.packets += 1;
        s.bytes += u64::from(f.wire_len);
        s.last_us = s.last_us.max(f.timestamp_us);
    }
    s.skipped_frames = reader.skipped_frames;
    Ok(s)
}

/// Writes a classic little-endian microsecond pcap. Used for fixtures and future export.
pub fn write_pcap(link_dlt: u32, frames: &[RawFrame]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&PCAP_MAGIC_US.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&link_dlt.to_le_bytes());
    for f in frames {
        out.extend_from_slice(&((f.timestamp_us / 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&((f.timestamp_us % 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&f.wire_len.to_le_bytes());
        out.extend_from_slice(&f.data);
    }
    out
}

fn pcapng_block(out: &mut Vec<u8>, block_type: u32, body: &[u8]) {
    let padded = body.len().div_ceil(4) * 4;
    let total = (12 + padded) as u32;
    out.extend_from_slice(&block_type.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out.resize(out.len() + padded - body.len(), 0);
    out.extend_from_slice(&total.to_le_bytes());
}

/// Writes a little-endian pcapng with one interface; `nanos` sets `if_tsresol` to 10^-9.
pub fn write_pcapng(link_dlt: u16, frames: &[RawFrame], nanos: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut shb = Vec::new();
    shb.extend_from_slice(&PCAPNG_BYTE_ORDER.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&(-1i64).to_le_bytes());
    pcapng_block(&mut out, PCAPNG_SHB, &shb);

    let mut idb = Vec::new();
    idb.extend_from_slice(&link_dlt.to_le_bytes());
    idb.extend_from_slice(&0u16.to_le_bytes());
    idb.extend_from_slice(&65535u32.to_le_bytes());
    if nanos {
        idb.extend_from_slice(&OPT_IF_TSRESOL.to_le_bytes());
        idb.extend_from_slice(&1u16.to_le_bytes());
        idb.extend_from_slice(&[9, 0, 0, 0]);
        idb.extend_from_slice(&[0, 0, 0, 0]);
    }
    pcapng_block(&mut out, BLOCK_IDB, &idb);

    for f in frames {
        let ts: u64 = if nanos { f.timestamp_us * 1000 } else { f.timestamp_us };
        let mut epb = Vec::new();
        epb.extend_from_slice(&0u32.to_le_bytes());
        epb.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
        epb.extend_from_slice(&(ts as u32).to_le_bytes());
        epb.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        epb.extend_from_slice(&f.wire_len.to_le_bytes());
        epb.extend_from_slice(&f.data);
        pcapng_block(&mut out, BLOCK_ENHANCED_PACKET, &epb);
    }
    out
}

#[cfg(test)]
mod tests;
