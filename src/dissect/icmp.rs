//! ICMP packet dissection

use crate::dissect::{Dissect, DissectResult};
use crate::Error;

/// ICMP packet
#[derive(Debug, Clone)]
pub struct Icmp<'a> {
    data: &'a [u8],
}

impl<'a> Icmp<'a> {
    /// Create a new ICMP packet from raw data
    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < 8 {
            return Err(Error::truncated(8, data.len()));
        }
        Ok(Self { data })
    }

    /// ICMP type
    pub fn icmp_type(&self) -> u8 {
        self.data[0]
    }

    /// ICMP code
    pub fn code(&self) -> u8 {
        self.data[1]
    }

    /// Checksum
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    /// Rest of header (varies by type)
    pub fn rest(&self) -> &'a [u8] {
        &self.data[4..]
    }

    /// Payload
    pub fn payload(&self) -> &'a [u8] {
        if self.data.len() <= 8 {
            &[]
        } else {
            &self.data[8..]
        }
    }
}

impl<'a> Dissect<'a> for Icmp<'a> {
    type Output = &'a [u8];

    fn dissect(&self) -> DissectResult<Self::Output> {
        Ok(self.payload())
    }

    fn data(&self) -> &'a [u8] {
        self.data
    }

    fn header_len(&self) -> usize {
        8
    }
}

/// ICMP types
pub mod icmp_type {
    pub const ECHO_REPLY: u8 = 0;
    pub const DEST_UNREACHABLE: u8 = 3;
    pub const SOURCE_QUENCH: u8 = 4;
    pub const REDIRECT: u8 = 5;
    pub const ECHO_REQUEST: u8 = 8;
    pub const ROUTER_ADVERTISEMENT: u8 = 9;
    pub const ROUTER_SOLICITATION: u8 = 10;
    pub const TIME_EXCEEDED: u8 = 11;
    pub const PARAMETER_PROBLEM: u8 = 12;
    pub const TIMESTAMP_REQUEST: u8 = 13;
    pub const TIMESTAMP_REPLY: u8 = 14;
}
