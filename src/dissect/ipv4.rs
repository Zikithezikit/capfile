//! IPv4 packet dissection

use crate::dissect::{Dissect, DissectResult};
use crate::format::pcap::mask::IPV4_FRAG_OFFSET;
use crate::Error;

/// IPv4 packet
#[derive(Debug, Clone)]
pub struct Ipv4<'a> {
    data: &'a [u8],
}

impl<'a> Ipv4<'a> {
    /// Create a new IPv4 packet from raw data
    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < 20 {
            return Err(Error::truncated(20, data.len()));
        }
        let version = data[0] >> 4;
        if version != 4 {
            return Err(Error::parse(
                0,
                format!("Invalid IPv4 version: {}", version),
            ));
        }
        Ok(Self { data })
    }

    /// Version (should be 4)
    pub fn version(&self) -> u8 {
        self.data[0] >> 4
    }

    /// Header length in bytes
    pub fn ihl(&self) -> usize {
        ((self.data[0] & 0x0f) * 4) as usize
    }

    /// Type of Service
    pub fn tos(&self) -> u8 {
        self.data[1]
    }

    /// Total length
    pub fn total_len(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    /// Identification
    pub fn identification(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    /// Don't Fragment flag
    pub fn df(&self) -> bool {
        (self.data[6] & 0x40) != 0
    }

    /// More Fragments flag
    pub fn mf(&self) -> bool {
        (self.data[6] & 0x20) != 0
    }

    /// Fragment offset
    pub fn fragment_offset(&self) -> u16 {
        let flags = u16::from_be_bytes([self.data[6], self.data[7]]);
        flags & IPV4_FRAG_OFFSET
    }

    /// Time to Live
    pub fn ttl(&self) -> u8 {
        self.data[8]
    }

    /// Protocol (next layer)
    pub fn protocol(&self) -> u8 {
        self.data[9]
    }

    /// Header checksum
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.data[10], self.data[11]])
    }

    /// Source IP address
    pub fn src(&self) -> [u8; 4] {
        let mut ip = [0u8; 4];
        ip.copy_from_slice(&self.data[12..16]);
        ip
    }

    /// Destination IP address
    pub fn dst(&self) -> [u8; 4] {
        let mut ip = [0u8; 4];
        ip.copy_from_slice(&self.data[16..20]);
        ip
    }

    /// Source IP as string
    pub fn src_str(&self) -> String {
        let ip = self.src();
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    }

    /// Destination IP as string
    pub fn dst_str(&self) -> String {
        let ip = self.dst();
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    }

    /// Payload
    pub fn payload(&self) -> &'a [u8] {
        &self.data[self.ihl()..]
    }
}

impl<'a> Dissect<'a> for Ipv4<'a> {
    type Output = &'a [u8];

    fn dissect(&self) -> DissectResult<Self::Output> {
        Ok(self.payload())
    }

    fn data(&self) -> &'a [u8] {
        self.data
    }

    fn header_len(&self) -> usize {
        self.ihl()
    }
}

/// Protocol numbers
pub mod protocol {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
}
