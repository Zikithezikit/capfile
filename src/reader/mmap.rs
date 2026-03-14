//! Memory-mapped file reading for zero-copy access

#[cfg(feature = "std")]
use memmap2::Mmap;
use std::fs::File;
use std::path::Path;

use crate::error::Error;
use crate::format::pcap::PcapHeader;
use crate::reader::PacketRef;

/// A zero-copy PCAP reader using memory mapping
pub struct PcapReaderMmap {
    data: Mmap,
    header: PcapHeader,
    position: usize,
    is_nano: bool,
}

impl PcapReaderMmap {
    /// Open a pcap file with memory mapping
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path)?;
        // SAFETY: memmap2::Mmap::map is unsafe because it assumes the file
        // won't change during the lifetime of the mapping. We hold the file
        // open for the duration of the mapping's lifetime, ensuring safety.
        // The file is valid for the entire duration of this reader.
        let data = unsafe { Mmap::map(&file)? };

        let (header, _) = PcapHeader::parse(&data)?;

        Ok(Self {
            data,
            header,
            position: 24, // Skip header
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

    /// Read the next packet using zero-copy mmap
    pub fn next_packet(&mut self) -> Result<Option<PacketRef>, Error> {
        if self.position + 16 > self.data.len() {
            return Ok(None);
        }

        let ts_sec = u32::from_le_bytes([
            self.data[self.position],
            self.data[self.position + 1],
            self.data[self.position + 2],
            self.data[self.position + 3],
        ]);
        let ts_usec = u32::from_le_bytes([
            self.data[self.position + 4],
            self.data[self.position + 5],
            self.data[self.position + 6],
            self.data[self.position + 7],
        ]);
        let incl_len = u32::from_le_bytes([
            self.data[self.position + 8],
            self.data[self.position + 9],
            self.data[self.position + 10],
            self.data[self.position + 11],
        ]);
        let orig_len = u32::from_le_bytes([
            self.data[self.position + 12],
            self.data[self.position + 13],
            self.data[self.position + 14],
            self.data[self.position + 15],
        ]);

        self.position += 16;

        let timestamp_ns = if self.is_nano {
            (ts_sec as u64) * 1_000_000_000 + ts_usec as u64
        } else {
            (ts_sec as u64) * 1_000_000_000 + (ts_usec as u64) * 1000
        };

        let data_len = incl_len as usize;
        if self.position + data_len > self.data.len() {
            return Ok(None);
        }

        let packet_data = &self.data[self.position..self.position + data_len];
        self.position += data_len;

        Ok(Some(PacketRef::new(
            packet_data,
            timestamp_ns,
            orig_len,
            incl_len,
        )))
    }

    /// Get current position in file
    pub fn position(&self) -> usize {
        self.position
    }

    /// Check if there are more packets
    pub fn has_more(&self) -> bool {
        self.position < self.data.len()
    }
}

/// Iterator over packets using mmap
pub struct PcapIteratorMmap {
    reader: PcapReaderMmap,
}

impl Iterator for PcapIteratorMmap {
    type Item = Result<PacketRef, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.reader.next_packet().transpose()
    }
}

impl IntoIterator for PcapReaderMmap {
    type Item = Result<PacketRef, Error>;
    type IntoIter = PcapIteratorMmap;

    fn into_iter(self) -> Self::IntoIter {
        PcapIteratorMmap { reader: self }
    }
}
