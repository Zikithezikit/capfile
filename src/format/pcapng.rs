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

/// Read a u64 from little-endian bytes safely
fn read_u64(data: &[u8], offset: usize) -> Result<u64, Error> {
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
    Ok(u64::from_le_bytes(bytes))
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

/// PCAPNG Interface Statistics Block
#[derive(Debug, Clone)]
pub struct InterfaceStatisticsBlock {
    /// Interface ID
    pub interface_id: u32,
    /// Timestamp (high 32 bits)
    pub timestamp_high: u32,
    /// Timestamp (low 32 bits)
    pub timestamp_low: u32,
    /// Number of packets received
    pub packets_received: u64,
    /// Number of packets dropped
    pub packets_dropped: u64,
    /// Number of packets received but discarded
    pub packets_discarded: u64,
}

/// Name resolution record type
#[derive(Debug, Clone, PartialEq)]
pub enum NameRecord {
    /// IPv4 address mapping
    IPv4([u8; 4], String),
    /// IPv6 address mapping
    IPv6([u8; 16], String),
    /// End of records
    End,
}

/// PCAPNG Name Resolution Block
#[derive(Debug, Clone)]
pub struct NameResolutionBlock {
    /// Name resolution records
    pub records: Vec<NameRecord>,
}

/// PCAPNG block
#[derive(Debug, Clone)]
pub enum Block {
    SectionHeader(SectionHeaderBlock),
    InterfaceDescription(InterfaceDescriptionBlock),
    EnhancedPacket(EnhancedPacketBlock),
    NameResolution(NameResolutionBlock),
    InterfaceStatistics(InterfaceStatisticsBlock),
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
        BlockType::NameResolution => {
            // Name Resolution Block - parse records
            let mut records = Vec::new();
            let mut pos = 0;

            while pos + 4 <= block_data.len() {
                let record_type = read_u16(block_data, pos)?;
                pos += 2;

                if record_type == 0 {
                    // End of records
                    break;
                }

                let record_len = read_u16(block_data, pos)? as usize;
                pos += 2;

                if pos + record_len > block_data.len() {
                    break;
                }

                match record_type {
                    1 => {
                        // IPv4 address record
                        if record_len >= 4 {
                            let addr = [
                                block_data[pos],
                                block_data[pos + 1],
                                block_data[pos + 2],
                                block_data[pos + 3],
                            ];
                            let name_start = pos + 4;
                            let name_end = name_start + record_len - 4;
                            if name_end <= block_data.len() {
                                let name =
                                    String::from_utf8_lossy(&block_data[name_start..name_end])
                                        .trim_end_matches('\0')
                                        .to_string();
                                if !name.is_empty() {
                                    records.push(NameRecord::IPv4(addr, name));
                                }
                            }
                        }
                    }
                    2 => {
                        // IPv6 address record
                        if record_len >= 16 {
                            let mut addr = [0u8; 16];
                            addr.copy_from_slice(&block_data[pos..pos + 16]);
                            let name_start = pos + 16;
                            let name_end = name_start + record_len - 16;
                            if name_end <= block_data.len() {
                                let name =
                                    String::from_utf8_lossy(&block_data[name_start..name_end])
                                        .trim_end_matches('\0')
                                        .to_string();
                                if !name.is_empty() {
                                    records.push(NameRecord::IPv6(addr, name));
                                }
                            }
                        }
                    }
                    _ => {}
                }

                // Pad to 4-byte boundary
                let consumed = 4 + record_len;
                pos += (consumed + 3) & !3;
            }

            Block::NameResolution(NameResolutionBlock { records })
        }
        BlockType::InterfaceStatistics => {
            // Interface Statistics Block - minimum 24 bytes (interface ID + timestamps + start/end)
            if block_data.len() < 24 {
                return Err(Error::truncated(24, block_data.len()));
            }

            let interface_id = read_u32(block_data, 0)?;
            let ts_high = read_u32(block_data, 4)?;
            let ts_low = read_u32(block_data, 8)?;

            // Skip end timestamp (8 bytes) and read optional counters
            let mut packets_received = 0u64;
            let mut packets_dropped = 0u64;
            let mut packets_discarded = 0u64;

            if block_data.len() >= 32 {
                packets_received = read_u64(block_data, 24)?;
                packets_dropped = read_u64(block_data, 32)?;
            }
            if block_data.len() >= 40 {
                packets_discarded = read_u64(block_data, 40)?;
            }

            Block::InterfaceStatistics(InterfaceStatisticsBlock {
                interface_id,
                timestamp_high: ts_high,
                timestamp_low: ts_low,
                packets_received,
                packets_dropped,
                packets_discarded,
            })
        }
        BlockType::Unknown(_) | BlockType::Packet | BlockType::SimplePacket => Block::Unknown,
    };

    Ok((block, offset + block_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test Section Header Block parsing
    #[test]
    fn test_parse_shb() {
        // Minimal SHB: block type (4) + block length (4) + byte-order (4) + version (4) + section length (8) + block length (4)
        let data = vec![
            // Block type (SHB)
            0x0a, 0x0d, 0x0d, 0x0a, // Block length (28 bytes)
            0x1c, 0x00, 0x00, 0x00, // Byte-order magic
            0x4d, 0x3c, 0x2b, 0x1a, // Version major (2)
            0x02, 0x00, // Version minor (4)
            0x04, 0x00, // Section length (-1 = unknown)
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Block length (repeated)
            0x1c, 0x00, 0x00, 0x00,
        ];

        let (block, _) = parse_block(&data, 0).unwrap();
        match block {
            Block::SectionHeader(shb) => {
                assert_eq!(shb.byte_order_magic, PCAPNG_BYTE_ORDER_MAGIC);
                assert_eq!(shb.version_major, 2);
                assert_eq!(shb.version_minor, 4);
                assert_eq!(shb.section_length, -1);
            }
            _ => panic!("Expected SectionHeader block"),
        }
    }

    /// Test Interface Description Block parsing
    #[test]
    fn test_parse_idb() {
        // IDB format: [type:4][length:4][link_type:2][pad:2][snap_len:4][options:4][length:4]
        // Total: 4 + 4 + 2 + 2 + 4 + 4 + 4 = 24 bytes
        let data = vec![
            // Block type (IDB = 1)
            0x01, 0x00, 0x00, 0x00, // Block length (24 = 0x18)
            0x18, 0x00, 0x00, 0x00, // Link type (Ethernet = 1)
            0x01, 0x00,
            // Padding (2 bytes) - IDB requires 4-byte alignment for fields after link_type
            0x00, 0x00, // Snap len (65535 = 0xFFFF)
            0xff, 0xff, 0x00, 0x00, // Options (4 bytes, set to 0)
            0x00, 0x00, 0x00, 0x00, // Block length (repeated)
            0x18, 0x00, 0x00, 0x00,
        ];

        assert_eq!(data.len(), 24, "IDB should be exactly 24 bytes");

        let (block, _) = parse_block(&data, 0).unwrap();
        match block {
            Block::InterfaceDescription(idb) => {
                assert_eq!(idb.link_type, 1);
                assert_eq!(idb.snap_len, 65535);
            }
            _ => panic!("Expected InterfaceDescription block"),
        }
    }

    /// Test Enhanced Packet Block parsing
    #[test]
    fn test_parse_epb() {
        // EPB: block type + block length + interface id + timestamps + captured len + original len + data + padding + block length
        let packet_data = vec![0xde, 0xad, 0xbe, 0xef];
        let block_len = 32 + packet_data.len(); // 20 bytes header + data + padding + 4 block length

        let mut data = vec![
            // Block type (EPB)
            0x06, 0x00, 0x00, 0x00,
            // Block length
        ];
        data.extend_from_slice(&(block_len as u32).to_le_bytes());

        // Interface ID
        data.extend_from_slice(&0u32.to_le_bytes());
        // Timestamp high
        data.extend_from_slice(&1000u32.to_le_bytes());
        // Timestamp low
        data.extend_from_slice(&500u32.to_le_bytes());
        // Captured length
        data.extend_from_slice(&(packet_data.len() as u32).to_le_bytes());
        // Original length
        data.extend_from_slice(&(packet_data.len() as u32).to_le_bytes());
        // Packet data
        data.extend_from_slice(&packet_data);
        // Padding (to 4-byte boundary)
        #[allow(clippy::manual_is_multiple_of)]
        while data.len() % 4 != 0 {
            data.push(0);
        }
        // Block length (repeated)
        data.extend_from_slice(&(block_len as u32).to_le_bytes());

        let (block, _) = parse_block(&data, 0).unwrap();
        match block {
            Block::EnhancedPacket(epb) => {
                assert_eq!(epb.interface_id, 0);
                assert_eq!(epb.timestamp_high, 1000);
                assert_eq!(epb.timestamp_low, 500);
                assert_eq!(epb.captured_length, 4);
                assert_eq!(epb.original_length, 4);
                assert_eq!(&epb.data, &packet_data);
            }
            _ => panic!("Expected EnhancedPacket block"),
        }
    }

    /// Test truncated block
    #[test]
    fn test_parse_truncated() {
        let data = vec![0u8; 8]; // Too short

        let result = parse_block(&data, 0);
        assert!(result.is_err());
    }

    /// Test invalid block length
    #[test]
    fn test_parse_invalid_block_length() {
        let data = vec![
            0x0a, 0x0d, 0x0d, 0x0a, // SHB
            0x00, 0x00, 0x00, 0x00, // Invalid block length (0)
        ];

        let result = parse_block(&data, 0);
        assert!(result.is_err());
    }

    /// Test invalid byte-order magic
    #[test]
    fn test_parse_invalid_byte_order() {
        let data = vec![
            0x0a, 0x0d, 0x0d, 0x0a, // SHB
            0x10, 0x00, 0x00, 0x00, // Block length (16)
            0x00, 0x00, 0x00, 0x00, // Invalid byte-order magic
            0x02, 0x00, 0x04, 0x00, // Version
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Section length
            0x10, 0x00, 0x00, 0x00, // Block length (repeated)
        ];

        let result = parse_block(&data, 0);
        assert!(result.is_err());
    }
}
