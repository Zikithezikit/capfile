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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_new_valid() {
        // Ethernet frame with some payload
        let data = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
            0x08, 0x00, // IPv4 EtherType
            0xde, 0xad, 0xbe, 0xef, // payload
        ];
        let eth = Ethernet::new(&data).unwrap();
        assert_eq!(eth.ether_type(), 0x0800);
    }

    #[test]
    fn test_ethernet_new_truncated() {
        let data = vec![0u8; 10];
        let result = Ethernet::new(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_ethernet_mac_addresses() {
        let data = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
            0x08, 0x00, // IPv4 EtherType
        ];
        let eth = Ethernet::new(&data).unwrap();
        assert_eq!(eth.dst(), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(eth.src(), [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    }

    #[test]
    fn test_ethernet_payload() {
        let data = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
            0x08, 0x00, // IPv4 EtherType
            0xde, 0xad, 0xbe, 0xef, // payload
        ];
        let eth = Ethernet::new(&data).unwrap();
        assert_eq!(eth.payload(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_ethernet_dissect() {
        let data = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
            0x08, 0x00, // IPv4 EtherType
            0xde, 0xad, 0xbe, 0xef, // payload
        ];
        let eth = Ethernet::new(&data).unwrap();
        let payload: &[u8] = eth.dissect().unwrap();
        assert_eq!(payload, &[0xde, 0xad, 0xbe, 0xef]);
    }
}
