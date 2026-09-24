//! Flow aggregation. A flow is the bidirectional conversation identified by the 5-tuple
//! (both endpoints + transport). Packets remain individually inspectable via the packet store;
//! flows hold only counters and state.

mod flow;
mod key;
mod sni;
mod table;
mod tcp;

pub use flow::{Flow, FlowSnapshot, HostnameSource};
pub use key::{Endpoint, FlowKey, FlowProtocol, NetAddr};
pub use sni::SniReassembler;
pub use table::{FlowTable, FlowTableConfig};
pub use tcp::{TcpState, TcpTracker};

#[cfg(test)]
mod tests;
