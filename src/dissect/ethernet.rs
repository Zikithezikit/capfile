//! Ethernet frame dissection

use crate::dissect::{Dissect, DissectResult};
use crate::Error;

/// Ethernet frame
#[derive(Debug, Clone)]
pub struct Ethernet<'a> {
    data: &'a [u8],
}

impl<'a> Ethernet<'a> {
    /// Create a new Ethernet frame from raw data
    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < 14 {
            return Err(Error::truncated(14, data.len()));
        }
        Ok(Self { data })
    }

    /// Destination MAC address
    pub fn dst(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.data[0..6]);
        mac
    }

    /// Source MAC address
    pub fn src(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.data[6..12]);
        mac
    }

    /// EtherType (network layer protocol)
    pub fn ether_type(&self) -> u16 {
        u16::from_be_bytes([self.data[12], self.data[13]])
    }

    /// Payload (everything after Ethernet header)
    pub fn payload(&self) -> &'a [u8] {
        &self.data[14..]
    }
}

impl<'a> Dissect<'a> for Ethernet<'a> {
    type Output = &'a [u8];

    fn dissect(&self) -> DissectResult<Self::Output> {
        Ok(self.payload())
    }

    fn data(&self) -> &'a [u8] {
        self.data
    }

    fn header_len(&self) -> usize {
        14
    }
}
