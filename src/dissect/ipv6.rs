//! IPv6 packet dissection

use crate::dissect::{Dissect, DissectResult};
use crate::Error;

/// IPv6 packet
#[derive(Debug, Clone)]
pub struct Ipv6<'a> {
    data: &'a [u8],
}

impl<'a> Ipv6<'a> {
    /// Create a new IPv6 packet from raw data
    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < 40 {
            return Err(Error::truncated(40, data.len()));
        }
        let version = data[0] >> 4;
        if version != 6 {
            return Err(Error::parse(
                0,
                format!("Invalid IPv6 version: {}", version),
            ));
        }
        Ok(Self { data })
    }

    /// Version (should be 6)
    pub fn version(&self) -> u8 {
        self.data[0] >> 4
    }

    /// Traffic class
    pub fn traffic_class(&self) -> u8 {
        ((self.data[0] & 0x0f) << 4) | (self.data[1] >> 4)
    }

    /// Flow label
    pub fn flow_label(&self) -> u32 {
        u32::from_be_bytes([0, self.data[1] & 0x0f, self.data[2], self.data[3]])
    }

    /// Payload length
    pub fn payload_len(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    /// Next header (protocol)
    pub fn next_header(&self) -> u8 {
        self.data[6]
    }

    /// Hop limit
    pub fn hop_limit(&self) -> u8 {
        self.data[7]
    }

    /// Source address
    pub fn src(&self) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&self.data[8..24]);
        addr
    }

    /// Destination address
    pub fn dst(&self) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&self.data[24..40]);
        addr
    }

    /// Payload
    pub fn payload(&self) -> &'a [u8] {
        &self.data[40..]
    }
}

impl<'a> Dissect<'a> for Ipv6<'a> {
    type Output = &'a [u8];

    fn dissect(&self) -> DissectResult<Self::Output> {
        Ok(self.payload())
    }

    fn data(&self) -> &'a [u8] {
        self.data
    }

    fn header_len(&self) -> usize {
        40
    }
}
