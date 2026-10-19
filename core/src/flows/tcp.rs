//! Passive TCP observation. We only see packets on one interface and may join mid-stream,
//! so this is an observer's approximation of RFC 9293 state, not an endpoint state machine.

use serde::Serialize;

use crate::packet::{TcpFlags, TcpInfo};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TcpState {
    SynSent,
    SynReceived,
    Established,
    Closing,
    Closed,
    Reset,
}

impl TcpState {
    pub fn is_terminated(self) -> bool {
        matches!(self, Self::Closed | Self::Reset)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpTracker {
    pub state: TcpState,
    /// True when the first observed packet was not a SYN (capture started mid-connection).
    pub midstream: bool,
    pub retransmissions: u32,
    #[serde(skip)]
    fin_seen: [bool; 2],
    /// Highest sequence end seen per direction: index 0 = from initiator, 1 = reverse.
    #[serde(skip)]
    max_seq_end: [Option<u32>; 2],
}

/// Serial-number comparison (RFC 1982) so wraparound at 2^32 is handled.
fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

impl TcpTracker {
    pub fn new(first: &TcpInfo) -> Self {
        let f = first.flags;
        let state = if f.has(TcpFlags::SYN) && !f.has(TcpFlags::ACK) {
            TcpState::SynSent
        } else if f.has(TcpFlags::SYN) {
            TcpState::SynReceived
        } else {
            TcpState::Established
        };
        Self { state, midstream: !f.has(TcpFlags::SYN), retransmissions: 0, fin_seen: [false; 2], max_seq_end: [None; 2] }
    }

    /// `forward` = packet travels from the flow initiator to the responder.
    pub fn observe(&mut self, tcp: &TcpInfo, forward: bool) {
        let dir = usize::from(!forward);
        let f = tcp.flags;
        self.track_sequence(tcp, dir);

        if f.has(TcpFlags::RST) {
            self.state = TcpState::Reset;
            return;
        }
        if f.has(TcpFlags::FIN) {
            self.fin_seen[dir] = true;
            self.state = if self.fin_seen[0] && self.fin_seen[1] { TcpState::Closed } else { TcpState::Closing };
            return;
        }
        self.state = match self.state {
            TcpState::SynSent if f.has(TcpFlags::SYN) && f.has(TcpFlags::ACK) => TcpState::SynReceived,
            TcpState::SynReceived if f.has(TcpFlags::ACK) && !f.has(TcpFlags::SYN) => TcpState::Established,
            other => other,
        };
    }

    /// Heuristic: a segment whose end does not advance past data already seen in that direction
    /// is counted as a retransmission. Keep-alive probes are counted too.
    fn track_sequence(&mut self, tcp: &TcpInfo, dir: usize) {
        let f = tcp.flags;
        let seg_len = tcp.payload_len + u32::from(f.has(TcpFlags::SYN)) + u32::from(f.has(TcpFlags::FIN));
        if seg_len == 0 {
            return;
        }
        let end = tcp.seq.wrapping_add(seg_len);
        match self.max_seq_end[dir] {
            Some(max) if seq_le(end, max) => self.retransmissions += 1,
            _ => self.max_seq_end[dir] = Some(end),
        }
    }
}
