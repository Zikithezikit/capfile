//! UDP datagram dissection

use crate::dissect::{Dissect, DissectResult};
use crate::Error;

/// UDP datagram
#[derive(Debug, Clone)]
pub struct Udp<'a> {
    data: &'a [u8],
}

impl<'a> Udp<'a> {
    /// Create a new UDP datagram from raw data
    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < 8 {
            return Err(Error::truncated(8, data.len()));
        }
        Ok(Self { data })
    }

    /// Source port
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    /// Destination port
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    /// Length
    pub fn length(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    /// Checksum
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.data[6], self.data[7]])
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

impl<'a> Dissect<'a> for Udp<'a> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_new_valid() {
        // UDP datagram with minimum header (8 bytes)
        let data = vec![
            0x00, 0x35, // src port = 53
            0x00, 0x35, // dst port = 53
            0x00, 0x10, // length = 16
            0x00, 0x00, // checksum
        ];
        let udp = Udp::new(&data).unwrap();
        assert_eq!(udp.src_port(), 53);
        assert_eq!(udp.dst_port(), 53);
    }

    #[test]
    fn test_udp_new_truncated() {
        let data = vec![0u8; 4];
        let result = Udp::new(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_udp_payload() {
        let mut data = vec![
            0x00, 0x35, 0x01, 0xbb, // ports
            0x00, 0x10, // length
            0x00, 0x00, // checksum
        ];
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload
        let udp = Udp::new(&data).unwrap();
        assert_eq!(udp.payload(), &[0xde, 0xad, 0xbe, 0xef]);
    }
}
