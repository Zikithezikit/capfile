//! PCAP format parsing
//!
//! PCAP is the legacy packet capture format. It has a simple structure
//! with a global header followed by packet records.

use crate::Error;

/// PCAP file magic numbers
pub const PCAP_MAGIC: u32 = 0xa1b2c3d4;
pub const PCAP_MAGIC_SWAPPED: u32 = 0xd4c3b2a1;
pub const PCAP_MAGIC_NANO: u32 = 0xa1b23c4d;
pub const PCAP_MAGIC_NANO_SWAPPED: u32 = 0x4d3cb2a1;

/// PCAPNG byte-order magic
pub const PCAPNG_BYTE_ORDER_MAGIC: u32 = 0x1a2b3c4d;

/// Common bitmasks for protocol fields
pub mod mask {
    /// IPv4 don't fragment flag
    pub const IPV4_DF: u16 = 0x4000;
    /// IPv4 more fragments flag
    pub const IPV4_MF: u16 = 0x2000;
    /// IPv4 fragment offset mask
    pub const IPV4_FRAG_OFFSET: u16 = 0x1fff;

    /// DNS QR (query/response) flag
    pub const DNS_QR: u16 = 0x8000;
    /// DNS opcode mask
    pub const DNS_OPCODE: u16 = 0x7800;
    /// DNS RCODE mask
    pub const DNS_RCODE: u16 = 0x000f;
}

/// Read a u16 from little-endian bytes safely
fn read_u16(data: &[u8], offset: usize) -> Result<u16, Error> {
    if data.len() < offset + 2 {
        return Err(Error::truncated(offset + 2, data.len()));
    }
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

/// Read a u32 from little-endian bytes safely
fn read_u32(data: &[u8], offset: usize) -> Result<u32, Error> {
    if data.len() < offset + 4 {
        return Err(Error::truncated(offset + 4, data.len()));
    }
    Ok(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Read an i32 from little-endian bytes safely
fn read_i32(data: &[u8], offset: usize) -> Result<i32, Error> {
    if data.len() < offset + 4 {
        return Err(Error::truncated(offset + 4, data.len()));
    }
    Ok(i32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Link types as defined in pcap
pub mod link_type {
    pub const LINKTYPE_ETHERNET: u16 = 1;
    pub const LINKTYPE_RAW: u16 = 101;
    pub const LINKTYPE_IPV4: u16 = 228;
    pub const LINKTYPE_IPV6: u16 = 229;
}

/// PCAP global header (24 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PcapHeader {
    /// Magic number (determines byte order and timestamp precision)
    pub magic: u32,
    /// Major version number
    pub version_major: u16,
    /// Minor version number
    pub version_minor: u16,
    /// Timestamp timezone (unused in practice)
    pub thiszone: i32,
    /// Timestamp accuracy (unused in practice)
    pub sigfigs: u32,
    /// Maximum packet length
    pub snaplen: u32,
    /// Link layer type
    pub network: u32,
}

/// Timestamp representation in pcap
#[derive(Debug, Clone, Copy)]
pub struct PcapTimestamp {
    /// Seconds since epoch
    pub secs: u32,
    /// Microseconds or nanoseconds since secs
    pub usecs: u32,
}

impl PcapTimestamp {
    /// Convert to nanoseconds since epoch
    pub fn to_ns(&self, is_nano: bool) -> u64 {
        let frac = if is_nano {
            self.usecs
        } else {
            self.usecs * 1000
        };
        (self.secs as u64) * 1_000_000_000 + frac as u64
    }
}

/// PCAP packet header (16 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PcapPacketHeader {
    /// Timestamp seconds
    pub ts_sec: u32,
    /// Timestamp microseconds
    pub ts_usec: u32,
    /// Length of packet data in file
    pub incl_len: u32,
    /// Original length of packet
    pub orig_len: u32,
}

impl PcapHeader {
    /// Parse pcap header from bytes
    pub fn parse(input: &[u8]) -> Result<(Self, &[u8]), Error> {
        if input.len() < 24 {
            return Err(Error::truncated(24, input.len()));
        }

        let magic = read_u32(input, 0)?;
        let version_major = read_u16(input, 4)?;
        let version_minor = read_u16(input, 6)?;
        let thiszone = read_i32(input, 8)?;
        let sigfigs = read_u32(input, 12)?;
        let snaplen = read_u32(input, 16)?;
        let network = read_u32(input, 20)?;

        let header = PcapHeader {
            magic,
            version_major,
            version_minor,
            thiszone,
            sigfigs,
            snaplen,
            network,
        };

        // Validate magic number
        match header.magic {
            PCAP_MAGIC | PCAP_MAGIC_SWAPPED | PCAP_MAGIC_NANO | PCAP_MAGIC_NANO_SWAPPED => {}
            _ => return Err(Error::InvalidMagic(header.magic)),
        }

        // Validate version
        if header.version_major != 2 {
            return Err(Error::InvalidVersion(header.version_major));
        }

        Ok((header, &input[24..]))
    }

    /// Check if bytes are swapped (big-endian)
    pub fn is_swapped(&self) -> bool {
        matches!(self.magic, PCAP_MAGIC_SWAPPED | PCAP_MAGIC_NANO_SWAPPED)
    }

    /// Check if timestamps are in nanoseconds
    pub fn is_nano(&self) -> bool {
        matches!(self.magic, PCAP_MAGIC_NANO | PCAP_MAGIC_NANO_SWAPPED)
    }
}
