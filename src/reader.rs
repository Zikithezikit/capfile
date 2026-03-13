//! PCAP and PCAPNG readers

use crate::error::Error;
use crate::format::pcap::PcapHeader;
use crate::format::pcapng as pcapng_mod;
use crate::format::pcapng::Block;

#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::io::{Read, Seek, SeekFrom};
#[cfg(feature = "std")]
use std::path::Path;

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

/// Read a u16 from little-endian bytes safely
fn read_u16(data: &[u8], offset: usize) -> Result<u16, Error> {
    if data.len() < offset + 2 {
        return Err(Error::truncated(offset + 2, data.len()));
    }
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

/// Zero-copy reference to packet data
#[derive(Debug, Clone)]
pub struct PacketRef {
    data: Vec<u8>,
    timestamp_ns: u64,
    original_len: u32,
    captured_len: u32,
}

impl PacketRef {
    /// Create a new packet reference
    pub fn new(data: &[u8], timestamp_ns: u64, original_len: u32, captured_len: u32) -> Self {
        Self {
            data: data.to_vec(),
            timestamp_ns,
            original_len,
            captured_len,
        }
    }

    /// Get packet data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get timestamp in nanoseconds since epoch
    pub fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    /// Get captured length
    pub fn captured_len(&self) -> u32 {
        self.captured_len
    }

    /// Get original length
    pub fn original_len(&self) -> u32 {
        self.original_len
    }

    /// Get packet length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if packet is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// PCAP reader
pub struct PcapReader<R> {
    reader: R,
    header: PcapHeader,
    is_nano: bool,
}

impl<R: Read + Seek> PcapReader<R> {
    /// Open a pcap file from a reader
    pub fn from_reader(reader: R) -> Result<Self, Error> {
        let mut reader = reader;
        let mut header_buf = [0u8; 24];
        reader.read_exact(&mut header_buf)?;

        let (header, _) = PcapHeader::parse(&header_buf)?;

        Ok(Self {
            reader,
            header,
            is_nano: header.is_nano(),
        })
    }

    /// Get the pcap header
    pub fn header(&self) -> PcapHeader {
        self.header
    }

    /// Get link type
    pub fn link_type(&self) -> u32 {
        self.header.network
    }

    /// Read the next packet
    pub fn next_packet(&mut self) -> Result<Option<PacketRef>, Error> {
        let mut pkthdr_buf = [0u8; 16];
        match self.reader.read_exact(&mut pkthdr_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(Error::Io(e)),
        }

        let ts_sec = read_u32(&pkthdr_buf, 0)?;
        let ts_usec = read_u32(&pkthdr_buf, 4)?;
        let incl_len = read_u32(&pkthdr_buf, 8)?;
        let orig_len = read_u32(&pkthdr_buf, 12)?;

        let timestamp_ns = if self.is_nano {
            (ts_sec as u64) * 1_000_000_000 + ts_usec as u64
        } else {
            (ts_sec as u64) * 1_000_000_000 + (ts_usec as u64) * 1000
        };

        let mut pkt_data = vec![0u8; incl_len as usize];
        self.reader.read_exact(&mut pkt_data)?;

        Ok(Some(PacketRef::new(
            &pkt_data,
            timestamp_ns,
            orig_len,
            incl_len,
        )))
    }
}

/// Iterator over packets in a pcap file
pub struct PcapIterator<R> {
    reader: PcapReader<R>,
}

impl<R: Read + Seek> Iterator for PcapIterator<R> {
    type Item = Result<PacketRef, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.reader.next_packet().transpose()
    }
}

/// PCAPNG reader
pub struct PcapngReader<R> {
    reader: R,
    interfaces: Vec<Interface>,
}

/// Interface information for pcapng
pub struct Interface {
    pub link_type: u16,
    pub snap_len: u32,
}

impl<R: Read + Seek> PcapngReader<R> {
    /// Open a pcapng file from a reader
    pub fn from_reader(mut reader: R) -> Result<Self, Error> {
        let mut interfaces = Vec::new();

        // Read first block to verify it's a SHB
        let mut initial_block = [0u8; 12];
        reader.read_exact(&mut initial_block)?;

        // Seek back to start
        reader.seek(SeekFrom::Start(0))?;

        // Read all blocks to find interfaces
        loop {
            let _current_pos = reader.stream_position()? as usize;
            let mut len_buf = [0u8; 4];
            if reader.read_exact(&mut len_buf).is_err() {
                break;
            }
            let block_len = u32::from_le_bytes(len_buf) as usize;

            if block_len < 12 || block_len > 1024 * 1024 {
                break;
            }

            let mut block_data = vec![0u8; block_len - 4];
            reader.read_exact(&mut block_data)?;

            // Parse block type
            let block_type = read_u32(&block_data, 0)?;

            if block_type == pcapng_mod::block_type::IDB {
                // Interface Description Block
                let link_type = read_u16(&block_data, 4)?;
                let snap_len = read_u32(&block_data, 8)?;
                interfaces.push(Interface {
                    link_type,
                    snap_len,
                });
            }
        }

        reader.seek(SeekFrom::Start(0))?;

        Ok(Self { reader, interfaces })
    }

    /// Get interfaces
    pub fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    /// Read the next block
    pub fn next_block(&mut self) -> Result<Option<Block>, Error> {
        let mut len_buf = [0u8; 4];
        match self.reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(Error::Io(e)),
        }

        let block_len = u32::from_le_bytes(len_buf) as usize;

        if block_len < 12 {
            return Err(Error::parse(0, "Block too small"));
        }

        let mut block_data = vec![0u8; block_len - 4];
        self.reader.read_exact(&mut block_data)?;

        let offset = 0;
        let (block, _) = pcapng_mod::parse_block(&block_data, offset)?;

        Ok(Some(block))
    }
}

#[cfg(feature = "std")]
impl PcapReader<std::io::Cursor<Vec<u8>>> {
    /// Create a reader from bytes (for embedded/WASM use)
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        Self::from_reader(std::io::Cursor::new(data.to_vec()))
    }
}

#[cfg(feature = "std")]
impl PcapngReader<std::io::Cursor<Vec<u8>>> {
    /// Create a reader from bytes (for embedded/WASM use)
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        Self::from_reader(std::io::Cursor::new(data.to_vec()))
    }
}

#[cfg(feature = "std")]
impl PcapReader<File> {
    /// Open a pcap file
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path)?;
        Self::from_reader(file)
    }
}

#[cfg(feature = "std")]
impl PcapngReader<File> {
    /// Open a pcapng file
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path)?;
        Self::from_reader(file)
    }
}
