//! PCAPNG format parsing
//!
//! PCAPNG is the modern packet capture format. It uses a block-based
//! structure with support for multiple interfaces, metadata, and comments.

use crate::format::pcap::PCAPNG_BYTE_ORDER_MAGIC;
use crate::Error;

/// PCAPNG block types
pub mod block_type {
    /// Section Header Block - defines the capture file format
    pub const SHB: u32 = 0x0a0d0d0a;
    /// Interface Description Block - defines network interfaces
    pub const IDB: u32 = 0x00000001;
    /// Packet Block - obsolete, use Enhanced Packet Block
    pub const PB: u32 = 0x00000002;
    /// Simple Packet Block - obsolete
    pub const SPB: u32 = 0x00000003;
    /// Name Resolution Block - maps addresses to names
    pub const NRB: u32 = 0x00000004;
    /// Interface Statistics Block - interface statistics
    pub const ISB: u32 = 0x00000005;
    /// Enhanced Packet Block - packet data with timestamps
    pub const EPB: u32 = 0x00000006;
    /// Custom block type
    pub const CUSTOM: u32 = 0x00040000;
}

/// Block type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    SectionHeader,
    InterfaceDescription,
    Packet,
    SimplePacket,
    NameResolution,
    InterfaceStatistics,
    EnhancedPacket,
    Unknown(u32),
}

impl From<u32> for BlockType {
    fn from(value: u32) -> Self {
        match value {
            block_type::SHB => BlockType::SectionHeader,
            block_type::IDB => BlockType::InterfaceDescription,
            block_type::PB => BlockType::Packet,
            block_type::SPB => BlockType::SimplePacket,
            block_type::NRB => BlockType::NameResolution,
            block_type::ISB => BlockType::InterfaceStatistics,
            block_type::EPB => BlockType::EnhancedPacket,
            other => BlockType::Unknown(other),
        }
    }
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

/// Read an i64 from little-endian bytes safely
fn read_i64(data: &[u8], offset: usize) -> Result<i64, Error> {
    if data.len() < offset + 8 {
        return Err(Error::truncated(offset + 8, data.len()));
    }
    let bytes: [u8; 8] = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ];
    Ok(i64::from_le_bytes(bytes))
}

/// PCAPNG Section Header Block
#[derive(Debug, Clone)]
pub struct SectionHeaderBlock {
    /// Byte-order magic (0x1a2b3c4d)
    pub byte_order_magic: u32,
    /// Major version
    pub version_major: u16,
    /// Minor version
    pub version_minor: u16,
    /// Section length (-1 for unknown)
    pub section_length: i64,
}

/// PCAPNG Interface Description Block
#[derive(Debug, Clone)]
pub struct InterfaceDescriptionBlock {
    /// Interface ID
    pub interface_id: u16,
    /// Link type (same as pcap)
    pub link_type: u16,
    /// Snapshot length
    pub snap_len: u32,
}

/// PCAPNG Enhanced Packet Block
#[derive(Debug, Clone)]
pub struct EnhancedPacketBlock {
    /// Interface ID
    pub interface_id: u32,
    /// Timestamp high bits (nanoseconds since epoch)
    pub timestamp_high: u32,
    /// Timestamp low bits
    pub timestamp_low: u32,
    /// Captured length
    pub captured_length: u32,
    /// Original length
    pub original_length: u32,
    /// Packet data (borrowed from input)
    pub data: Vec<u8>,
}

/// PCAPNG block
#[derive(Debug, Clone)]
pub enum Block {
    SectionHeader(SectionHeaderBlock),
    InterfaceDescription(InterfaceDescriptionBlock),
    EnhancedPacket(EnhancedPacketBlock),
    NameResolution,
    InterfaceStatistics,
    Unknown,
}

/// Parse a PCAPNG block
pub fn parse_block(input: &[u8], offset: usize) -> Result<(Block, usize), Error> {
    if input.len() < 12 {
        return Err(Error::truncated(12, input.len()));
    }

    // Block type (4 bytes)
    let block_type = read_u32(input, 0)?;
    // Block length (4 bytes) - includes header and trailer
    let block_len = read_u32(input, 4)? as usize;

    if block_len < 12 || block_len > input.len() {
        return Err(Error::parse(
            offset,
            format!("Invalid block length: {}", block_len),
        ));
    }

    let block_data = &input[8..block_len - 4];
    let block = match BlockType::from(block_type) {
        BlockType::SectionHeader => {
            if block_data.len() < 16 {
                return Err(Error::truncated(16, block_data.len()));
            }
            let byte_order_magic = read_u32(block_data, 0)?;
            if byte_order_magic != PCAPNG_BYTE_ORDER_MAGIC {
                return Err(Error::parse(offset, "Invalid byte-order magic".to_string()));
            }
            Block::SectionHeader(SectionHeaderBlock {
                byte_order_magic,
                version_major: read_u16(block_data, 4)?,
                version_minor: read_u16(block_data, 6)?,
                section_length: read_i64(block_data, 8)?,
            })
        }
        BlockType::InterfaceDescription => {
            if block_data.len() < 8 {
                return Err(Error::truncated(8, block_data.len()));
            }
            Block::InterfaceDescription(InterfaceDescriptionBlock {
                interface_id: 0, // Will be assigned by reader
                link_type: read_u16(block_data, 0)?,
                snap_len: read_u32(block_data, 4)?,
            })
        }
        BlockType::EnhancedPacket => {
            if block_data.len() < 20 {
                return Err(Error::truncated(20, block_data.len()));
            }
            let captured_len = read_u32(block_data, 12)? as usize;
            let data_len = captured_len + (4 - captured_len % 4) % 4; // Padding

            if block_data.len() < 20 + data_len {
                return Err(Error::truncated(20 + data_len, block_data.len()));
            }

            // Copy packet data to avoid lifetime issues
            let data = block_data[20..20 + captured_len].to_vec();

            Block::EnhancedPacket(EnhancedPacketBlock {
                interface_id: read_u32(block_data, 0)?,
                timestamp_high: read_u32(block_data, 4)?,
                timestamp_low: read_u32(block_data, 8)?,
                captured_length: captured_len as u32,
                original_length: read_u32(block_data, 16)?,
                data,
            })
        }
        BlockType::NameResolution => Block::NameResolution,
        BlockType::InterfaceStatistics => Block::InterfaceStatistics,
        BlockType::Unknown(_) | BlockType::Packet | BlockType::SimplePacket => Block::Unknown,
    };

    Ok((block, offset + block_len))
}
