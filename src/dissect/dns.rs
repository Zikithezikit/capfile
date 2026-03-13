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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_new_valid() {
        // DNS query (12-byte header)
        let data = vec![
            0x12, 0x34, // transaction ID
            0x01, 0x00, // flags: standard query
            0x00, 0x01, // 1 question
            0x00, 0x00, // 0 answers
            0x00, 0x00, // 0 authority
            0x00, 0x00, // 0 additional
        ];
        let dns = Dns::new(&data).unwrap();
        assert_eq!(dns.id(), 0x1234);
        assert!(!dns.is_response());
    }

    #[test]
    fn test_dns_new_truncated() {
        let data = vec![0u8; 8];
        let result = Dns::new(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_flags() {
        let data = vec![
            0x12, 0x34, // transaction ID
            0x81, 0x80, // flags: response, no error
            0x00, 0x01, // 1 question
            0x00, 0x01, // 1 answer
            0x00, 0x00, // 0 authority
            0x00, 0x00, // 0 additional
        ];
        let dns = Dns::new(&data).unwrap();
        assert!(dns.is_response());
        assert_eq!(dns.rcode(), 0); // no error
    }

    #[test]
    fn test_dns_counts() {
        let data = vec![
            0x00, 0x00, // ID
            0x01, 0x00, // flags
            0x00, 0x02, // 2 questions
            0x00, 0x03, // 3 answers
            0x00, 0x04, // 4 authority
            0x00, 0x05, // 5 additional
        ];
        let dns = Dns::new(&data).unwrap();
        assert_eq!(dns.qd_count(), 2);
        assert_eq!(dns.an_count(), 3);
        assert_eq!(dns.ns_count(), 4);
        assert_eq!(dns.ar_count(), 5);
    }

    #[test]
    fn test_dns_payload() {
        let mut data = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload
        let dns = Dns::new(&data).unwrap();
        assert_eq!(dns.payload(), &[0xde, 0xad, 0xbe, 0xef]);
    }
}
