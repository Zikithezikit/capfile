//! PCAP and PCAPNG writers

use crate::error::Error;
use crate::format::pcap::{PcapHeader, PCAP_MAGIC, PCAP_MAGIC_NANO};

#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::io::Write;
#[cfg(feature = "std")]
use std::path::Path;

/// PCAP writer
pub struct PcapWriter<W> {
    writer: W,
    link_type: u32,
    is_nano: bool,
}

impl<W: Write> PcapWriter<W> {
    /// Create a new pcap writer
    pub fn new(mut writer: W, link_type: u32) -> Result<Self, Error> {
        // Write pcap header
        let header = PcapHeader {
            magic: if is_nano_time() {
                PCAP_MAGIC_NANO
            } else {
                PCAP_MAGIC
            },
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 65535,
            network: link_type,
        };

        let header_bytes: [u8; 24] = unsafe { core::mem::transmute(header) };

        writer.write_all(&header_bytes)?;

        let is_nano = is_nano_time();

        Ok(Self {
            writer,
            link_type,
            is_nano,
        })
    }

    /// Write a packet
    pub fn write_packet(
        &mut self,
        data: &[u8],
        timestamp_ns: u64,
        original_len: u32,
    ) -> Result<(), Error> {
        let secs = (timestamp_ns / 1_000_000_000) as u32;
        let frac = if self.is_nano {
            (timestamp_ns % 1_000_000_000) as u32
        } else {
            ((timestamp_ns % 1_000_000_000) / 1000) as u32
        };

        let header = [
            secs.to_le_bytes(),
            frac.to_le_bytes(),
            (data.len() as u32).to_le_bytes(),
            original_len.to_le_bytes(),
        ]
        .concat();

        self.writer.write_all(&header)?;
        self.writer.write_all(data)?;

        Ok(())
    }

    /// Flush the writer
    pub fn flush(&mut self) -> Result<(), Error> {
        Ok(self.writer.flush()?)
    }
}

/// Check if we should use nanosecond precision
fn is_nano_time() -> bool {
    // Default to microsecond precision for compatibility
    false
}

#[cfg(feature = "std")]
impl PcapWriter<std::fs::File> {
    /// Create a pcap file
    pub fn create<P: AsRef<Path>>(path: P, link_type: u32) -> Result<Self, Error> {
        let file = File::create(path)?;
        Self::new(file, link_type)
    }
}

/// PCAPNG writer
pub struct PcapngWriter<W> {
    writer: W,
    next_interface_id: u16,
}

impl<W: Write> PcapngWriter<W> {
    /// Create a new pcapng writer
    pub fn new(mut writer: W) -> Result<Self, Error> {
        // Write Section Header Block
        let shb: Vec<u8> = vec![
            // Block type
            0x0a, 0x0d, 0x0d, 0x0a, // Block length (28 bytes)
            0x1c, 0x00, 0x00, 0x00, // Byte order magic
            0x1a, 0x2b, 0x3c, 0x4d, // Version (1.0)
            0x01, 0x00, 0x01, 0x00, // Section length (-1, unknown)
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Block length (repeated)
            0x1c, 0x00, 0x00, 0x00,
        ];

        writer.write_all(&shb)?;

        Ok(Self {
            writer,
            next_interface_id: 0,
        })
    }

    /// Write an Interface Description Block
    pub fn write_interface(&mut self, link_type: u16, snap_len: u32) -> Result<u16, Error> {
        let interface_id = self.next_interface_id;
        self.next_interface_id += 1;

        let idb: Vec<u8> = vec![
            // Block type
            0x01,
            0x00,
            0x00,
            0x00,
            // Block length (20 bytes)
            0x14,
            0x00,
            0x00,
            0x00,
            // Link type
            link_type.to_le_bytes()[0],
            link_type.to_le_bytes()[1],
            // Reserved
            0x00,
            0x00,
            // Snap len
            snap_len.to_le_bytes()[0],
            snap_len.to_le_bytes()[1],
            snap_len.to_le_bytes()[2],
            snap_len.to_le_bytes()[3],
            // Block length (repeated)
            0x14,
            0x00,
            0x00,
            0x00,
        ];

        self.writer.write_all(&idb)?;

        Ok(interface_id)
    }

    /// Write an Enhanced Packet Block
    pub fn write_packet(
        &mut self,
        interface_id: u16,
        timestamp_ns: u64,
        data: &[u8],
        original_len: u32,
    ) -> Result<(), Error> {
        let captured_len = data.len() as u32;
        let padded_len = (captured_len + 3) & !3; // 4-byte alignment
        let padding = padded_len - captured_len;

        let timestamp_high = ((timestamp_ns >> 32) & 0xffffffff) as u32;
        let timestamp_low = (timestamp_ns & 0xffffffff) as u32;

        let block_len = 32 + padded_len; // Header (20) + trailer (4) + padded data

        let header: Vec<u8> = vec![
            // Block type (EPB)
            0x06,
            0x00,
            0x00,
            0x00,
            // Block length
            block_len.to_le_bytes()[0],
            block_len.to_le_bytes()[1],
            block_len.to_le_bytes()[2],
            block_len.to_le_bytes()[3],
            // Interface ID
            (interface_id as u32).to_le_bytes()[0],
            (interface_id as u32).to_le_bytes()[1],
            (interface_id as u32).to_le_bytes()[2],
            (interface_id as u32).to_le_bytes()[3],
            // Timestamp high
            timestamp_high.to_le_bytes()[0],
            timestamp_high.to_le_bytes()[1],
            timestamp_high.to_le_bytes()[2],
            timestamp_high.to_le_bytes()[3],
            // Timestamp low
            timestamp_low.to_le_bytes()[0],
            timestamp_low.to_le_bytes()[1],
            timestamp_low.to_le_bytes()[2],
            timestamp_low.to_le_bytes()[3],
            // Captured length
            captured_len.to_le_bytes()[0],
            captured_len.to_le_bytes()[1],
            captured_len.to_le_bytes()[2],
            captured_len.to_le_bytes()[3],
            // Original length
            original_len.to_le_bytes()[0],
            original_len.to_le_bytes()[1],
            original_len.to_le_bytes()[2],
            original_len.to_le_bytes()[3],
        ];

        self.writer.write_all(&header)?;
        self.writer.write_all(data)?;
        self.writer.write_all(&vec![0u8; padding as usize])?;

        // Block length trailer
        let trailer = block_len.to_le_bytes();
        self.writer.write_all(&trailer)?;

        Ok(())
    }

    /// Flush the writer
    pub fn flush(&mut self) -> Result<(), Error> {
        Ok(self.writer.flush()?)
    }
}

#[cfg(feature = "std")]
impl PcapngWriter<std::fs::File> {
    /// Create a pcapng file
    pub fn create<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::create(path)?;
        Self::new(file)
    }
}
