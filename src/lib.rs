//! Capfile - Pure Rust crate for reading/writing pcap/pcapng files
//!
//! This crate provides zero-copy parsing of pcap and pcapng files with
//! support for packet dissection and writing capture files.
//!
//! # Features
//!
//! - `std`: Enables file system access (enabled by default)
//!
//! # Example
//!
//! ```ignore
//! use capfile::PcapReader;
//!
//! // Read a pcap file
//! let mut reader = PcapReader::open("capture.pcap")?;
//! while let Some(pkt) = reader.next_packet()? {
//!     println!("{} bytes at {}", pkt.len(), pkt.timestamp_ns());
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

pub mod dissect;
pub mod error;
pub mod format;
pub mod reader;
pub mod writer;

pub use error::Error;
#[cfg(feature = "std")]
pub use reader::mmap::PcapReaderMmap;
pub use reader::{Interface, PacketRef, PcapReader, PcapngReader};
pub use writer::{PcapWriter, PcapngWriter};
