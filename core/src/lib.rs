//! PacketCity core: everything between "raw bytes from a capture source" and
//! "traffic events for the visualization". This crate has no dependency on
//! libpcap/Npcap so it can be tested deterministically without capture drivers.

pub mod alerts;
pub mod capture_file;
pub mod demo;
pub mod devices;
pub mod direction;
pub mod engine;
pub mod events;
pub mod flows;
pub mod frame;
pub mod names;
pub mod oui;
pub mod packet;
pub mod parser;
pub mod pipeline;
pub mod reference;
pub mod replay;
pub mod statistics;
pub mod store;
pub mod synth;
pub mod threats;

pub use engine::{Engine, EngineConfig};
pub use frame::{LinkType, RawFrame};
pub use packet::{Direction, PacketRecord, TrafficClass};
