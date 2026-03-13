//! DNS packet dissection

use crate::dissect::{Dissect, DissectResult};
use crate::format::pcap::mask::{DNS_OPCODE, DNS_QR, DNS_RCODE};
use crate::Error;

/// DNS packet
#[derive(Debug, Clone)]
pub struct Dns<'a> {
    data: &'a [u8],
}

impl<'a> Dns<'a> {
    /// Create a new DNS packet from raw data
    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < 12 {
            return Err(Error::truncated(12, data.len()));
        }
        Ok(Self { data })
    }

    /// Transaction ID
    pub fn id(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    /// Flags
    pub fn flags(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    /// Query/Response flag
    pub fn is_response(&self) -> bool {
        (self.flags() & DNS_QR) != 0
    }

    /// Opcode
    pub fn opcode(&self) -> u8 {
        ((self.flags() & DNS_OPCODE) >> 11) as u8
    }

    /// Response code
    pub fn rcode(&self) -> u8 {
        (self.flags() & DNS_RCODE) as u8
    }

    /// Number of questions
    pub fn qd_count(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    /// Number of answer records
    pub fn an_count(&self) -> u16 {
        u16::from_be_bytes([self.data[6], self.data[7]])
    }

    /// Number of authority records
    pub fn ns_count(&self) -> u16 {
        u16::from_be_bytes([self.data[8], self.data[9]])
    }

    /// Number of additional records
    pub fn ar_count(&self) -> u16 {
        u16::from_be_bytes([self.data[10], self.data[11]])
    }

    /// Payload (everything after header)
    pub fn payload(&self) -> &'a [u8] {
        if self.data.len() <= 12 {
            &[]
        } else {
            &self.data[12..]
        }
    }
}

impl<'a> Dissect<'a> for Dns<'a> {
    type Output = &'a [u8];

    fn dissect(&self) -> DissectResult<Self::Output> {
        Ok(self.payload())
    }

    fn data(&self) -> &'a [u8] {
        self.data
    }

    fn header_len(&self) -> usize {
        12
    }
}
