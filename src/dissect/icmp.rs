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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_new_valid() {
        // ICMP echo request (ping)
        let data = vec![
            0x08, // type = echo request
            0x00, // code = 0
            0x00, 0x00, // checksum
            0x00, 0x01, // identifier
            0x00, 0x01, // sequence number
        ];
        let icmp = Icmp::new(&data).unwrap();
        assert_eq!(icmp.icmp_type(), 8); // ECHO_REQUEST
    }

    #[test]
    fn test_icmp_new_truncated() {
        let data = vec![0u8; 4];
        let result = Icmp::new(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_icmp_types() {
        let data = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        let icmp = Icmp::new(&data).unwrap();
        assert_eq!(icmp.icmp_type(), icmp_type::ECHO_REQUEST);
        assert_eq!(icmp.code(), 0);
    }

    #[test]
    fn test_icmp_payload() {
        let mut data = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload
        let icmp = Icmp::new(&data).unwrap();
        assert_eq!(icmp.payload(), &[0xde, 0xad, 0xbe, 0xef]);
    }
}
