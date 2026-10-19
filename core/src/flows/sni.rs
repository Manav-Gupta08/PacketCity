//! Reassembles TLS ClientHello records that span several TCP segments, so the SNI is found
//! even when it sits past the first segment (large post-quantum key shares, randomised
//! extension order). Only in-order client segments of the one handshake record are buffered;
//! the buffer is freed as soon as the SNI is read or the attempt is abandoned.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::packet::{FlowId, ParsedPacket};
use crate::parser::{incomplete_client_hello_len, record_sni};

const MAX_PENDING: usize = 64;
/// TLS record header (5) + the largest record `tls::parse` accepts.
const MAX_RECORD_BYTES: usize = 5 + 16384 + 2048;
const MAX_SEGMENTS: u8 = 16;
const PENDING_TIMEOUT_US: u64 = 10_000_000;

#[derive(Debug)]
struct Pending {
    client: (Option<IpAddr>, u16),
    buf: Vec<u8>,
    need: usize,
    next_seq: u32,
    segments: u8,
    started_us: u64,
}

#[derive(Debug, Default)]
pub struct SniReassembler {
    pending: HashMap<FlowId, Pending>,
}

impl SniReassembler {
    /// Feeds one packet of `flow`. Returns the SNI when a split ClientHello completes.
    pub fn observe(&mut self, flow: FlowId, pkt: &ParsedPacket, payload: &[u8], ts: u64) -> Option<String> {
        let tcp = pkt.tcp.as_ref()?;
        if payload.is_empty() {
            return None;
        }
        // Snaplen-truncated segments leave holes that cannot be filled.
        let whole = payload.len() == tcp.payload_len as usize;
        let client = (pkt.src_ip(), tcp.src_port);

        if let Some(p) = self.pending.get_mut(&flow) {
            if p.client != client {
                return None;
            }
            p.segments += 1;
            if tcp.seq == p.next_seq && whole {
                let take = payload.len().min(p.need - p.buf.len());
                p.buf.extend_from_slice(&payload[..take]);
                p.next_seq = p.next_seq.wrapping_add(payload.len() as u32);
                if p.buf.len() == p.need {
                    let p = self.pending.remove(&flow)?;
                    return record_sni(&p.buf);
                }
            }
            if p.segments >= MAX_SEGMENTS {
                self.pending.remove(&flow);
            }
            return None;
        }

        let need = incomplete_client_hello_len(payload)?;
        if !whole || need > MAX_RECORD_BYTES {
            return None;
        }
        if self.pending.len() >= MAX_PENDING {
            self.expire(ts);
            if self.pending.len() >= MAX_PENDING {
                let oldest = self.pending.iter().min_by_key(|(_, p)| p.started_us).map(|(&id, _)| id)?;
                self.pending.remove(&oldest);
            }
        }
        let mut buf = Vec::with_capacity(need);
        buf.extend_from_slice(payload);
        self.pending.insert(
            flow,
            Pending { client, buf, need, next_seq: tcp.seq.wrapping_add(payload.len() as u32), segments: 1, started_us: ts },
        );
        None
    }

    pub fn expire(&mut self, now_us: u64) {
        self.pending.retain(|_, p| now_us.saturating_sub(p.started_us) <= PENDING_TIMEOUT_US);
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }
}
