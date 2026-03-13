//! Capfile - Pure Rust crate for reading/writing pcap/pcapng files
//!
//! This crate provides zero-copy parsing of pcap and pcapng files with
//! support for packet dissection and writing capture files.
//!
//! # Features
//!
//! - **Zero-copy parsing**: Data is parsed without copying where possible,
//!   making it efficient for large capture files
//! - **Both formats**: Supports legacy PCAP and modern PCAPNG formats
//! - **Packet dissection**: Built-in support for dissecting Ethernet, IPv4,
//!   IPv6, TCP, UDP, ICMP, and DNS protocols
//! - **Write support**: Create new PCAP and PCAPNG files
//! - **no_std support**: Works without the standard library for embedded
//! - **WASM compatible**: Can be used in WebAssembly applications
//!
//! # Feature Flags
//!
//! - `std`: Enables file system access (enabled by default). Without this
//!   feature, you can only parse from in-memory byte slices.
//!
//! # Quick Start
//!
//! ## Reading a PCAP file
//!
//! ```ignore
//! use capfile::PcapReader;
//!
//! // Open a pcap file (requires std feature)
//! let mut reader = PcapReader::open("capture.pcap")?;
//!
//! // Iterate over packets
//! while let Some(pkt) = reader.next_packet()? {
//!     println!("{} bytes at {}", pkt.len(), pkt.timestamp_ns());
//! }
//! ```
//!
//! ## Reading from bytes (no_std/WASM)
//!
//! ```ignore
//! use capfile::PcapReader;
//! use std::io::Cursor;
//!
//! let data = include_bytes!("capture.pcap");
//! let mut reader = PcapReader::from_reader(Cursor::new(data))?;
//!
//! while let Some(pkt) = reader.next_packet()? {
//!     // Process packet
//! }
//! ```
//!
//! ## Reading a PCAPNG file
//!
//! ```ignore
//! use capfile::PcapngReader;
//! use capfile::format::pcapng::Block;
//!
//! let mut reader = PcapngReader::open("capture.pcapng")?;
//!
//! // Get interface information
//! for (i, iface) in reader.interfaces().iter().enumerate() {
//!     println!("Interface {}: link_type={}", i, iface.link_type);
//! }
//!
//! // Iterate over blocks
//! while let Some(block) = reader.next_block()? {
//!     match block {
//!         Block::EnhancedPacket(epb) => {
//!             println!("Packet: {} bytes", epb.captured_length);
//!         }
//!         Block::InterfaceStatistics(stats) => {
//!             println!("Stats: {} packets", stats.packets_received);
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!
//! ## Packet Dissection
//!
//! ```ignore
//! use capfile::{PcapReader, dissect::{Ethernet, Ipv4, Tcp}};
//!
//! let mut reader = PcapReader::open("capture.pcap")?;
//!
//! if let Some(pkt) = reader.next_packet()? {
//!     // Dissect Ethernet
//!     let eth = Ethernet::new(pkt.data())?;
//!     println!("{} -> {}", format_mac(eth.src()), format_mac(eth.dst()));
//!
//!     // Dissect IPv4
//!     let ip = Ipv4::new(eth.payload())?;
//!     println!("{} -> {}", ip.src_str(), ip.dst_str());
//!
//!     // Dissect TCP
//!     if let Ok(tcp) = Tcp::new(ip.payload()) {
//!         println!("{} -> {}", tcp.src_port(), tcp.dst_port());
//!     }
//! }
//! ```
//!
//! ## Writing a PCAP file
//!
//! ```ignore
//! use capfile::PcapWriter;
//!
//! let mut writer = PcapWriter::create("output.pcap", 1)?; // Ethernet
//!
//! // Write a packet
//! writer.write_packet(b"packet data", 1000000000, 100)?;
//! ```
//!
//! # Modules
//!
//! - [`error`] - Error types for operations
//! - [`format`] - File format parsing (PCAP and PCAPNG)
//! - [`reader`] - PCAP and PCAPNG readers
//! - [`writer`] - PCAP and PCAPNG writers
//! - `dissect` - Packet dissection for various protocols

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
