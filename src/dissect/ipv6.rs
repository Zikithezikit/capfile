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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_new_valid() {
        // IPv6 packet with minimum header (40 bytes)
        let mut data = vec![0u8; 40];
        data[0] = 0x60; // version=6
        data[4] = 0x00; // payload length = 0
        data[6] = 6; // next header = TCP
        data[7] = 64; // hop limit
                      // src/dst addresses are zeros (placeholder)

        let ip = Ipv6::new(&data).unwrap();
        assert_eq!(ip.version(), 6);
        assert_eq!(ip.next_header(), 6);
    }

    #[test]
    fn test_ipv6_new_truncated() {
        let data = vec![0u8; 20];
        let result = Ipv6::new(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv6_new_invalid_version() {
        let mut data = vec![0u8; 40];
        data[0] = 0x40; // version=4, not 6
        let result = Ipv6::new(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv6_addresses() {
        let mut data = vec![0u8; 40];
        data[0] = 0x60;
        // Set src address (bytes 8-23)
        data[8] = 0x20;
        data[9] = 0x01;
        data[10] = 0x0d;
        data[11] = 0xb8;
        data[12] = 0x00;
        data[13] = 0x00;
        data[14] = 0x00;
        data[15] = 0x00;
        data[16] = 0x00;
        data[17] = 0x00;
        data[18] = 0x00;
        data[19] = 0x00;
        data[20] = 0x00;
        data[21] = 0x00;
        data[22] = 0x00;
        data[23] = 0x01;
        // Set dst address (bytes 24-39)
        data[24] = 0x20;
        data[25] = 0x01;
        data[26] = 0x0d;
        data[27] = 0xb8;
        data[28] = 0x00;
        data[29] = 0x00;
        data[30] = 0x00;
        data[31] = 0x00;
        data[32] = 0x00;
        data[33] = 0x00;
        data[34] = 0x00;
        data[35] = 0x02;
        data[36] = 0x00;
        data[37] = 0x00;
        data[38] = 0x00;
        data[39] = 0x00;

        let ip = Ipv6::new(&data).unwrap();
        assert_eq!(ip.src()[0], 0x20);
        assert_eq!(ip.dst()[0], 0x20);
    }

    #[test]
    fn test_ipv6_payload() {
        // Create IPv6 packet with header + payload
        let mut data = vec![0u8; 40]; // 40 header bytes
        data[0] = 0x60; // version = 6
                        // Append payload
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        let ip = Ipv6::new(&data).unwrap();
        assert_eq!(ip.payload(), &[0xde, 0xad, 0xbe, 0xef]);
    }
}
