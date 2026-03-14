//! TCP segment dissection

use crate::dissect::{Dissect, DissectResult};
use crate::Error;

/// TCP segment
#[derive(Debug, Clone)]
pub struct Tcp<'a> {
    data: &'a [u8],
}

impl<'a> Tcp<'a> {
    /// Create a new TCP segment from raw data
    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < 20 {
            return Err(Error::truncated(20, data.len()));
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

    /// Sequence number
    pub fn seq(&self) -> u32 {
        u32::from_be_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }

    /// Acknowledgment number
    pub fn ack(&self) -> u32 {
        u32::from_be_bytes([self.data[8], self.data[9], self.data[10], self.data[11]])
    }

    /// Data offset (header length)
    pub fn data_offset(&self) -> usize {
        ((self.data[12] >> 4) * 4) as usize
    }

    /// Flags
    pub fn flags(&self) -> u8 {
        self.data[13]
    }

    /// FIN flag
    pub fn fin(&self) -> bool {
        (self.flags() & 0x01) != 0
    }

    /// SYN flag
    pub fn syn(&self) -> bool {
        (self.flags() & 0x02) != 0
    }

    /// RST flag
    pub fn rst(&self) -> bool {
        (self.flags() & 0x04) != 0
    }

    /// PSH flag
    pub fn psh(&self) -> bool {
        (self.flags() & 0x08) != 0
    }

    /// ACK flag
    pub fn ack_flag(&self) -> bool {
        (self.flags() & 0x10) != 0
    }

    /// URG flag
    pub fn urg(&self) -> bool {
        (self.flags() & 0x20) != 0
    }

    /// Window size
    pub fn window(&self) -> u16 {
        u16::from_be_bytes([self.data[14], self.data[15]])
    }

    /// Checksum
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.data[16], self.data[17]])
    }

    /// Urgent pointer
    pub fn urgent(&self) -> u16 {
        u16::from_be_bytes([self.data[18], self.data[19]])
    }

    /// Payload
    pub fn payload(&self) -> &'a [u8] {
        let offset = self.data_offset();
        if offset >= self.data.len() {
            &[]
        } else {
            &self.data[offset..]
        }
    }
}

impl<'a> Dissect<'a> for Tcp<'a> {
    type Output = &'a [u8];

    fn dissect(&self) -> DissectResult<Self::Output> {
        Ok(self.payload())
    }

    fn data(&self) -> &'a [u8] {
        self.data
    }

    fn header_len(&self) -> usize {
        self.data_offset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_new_valid() {
        // TCP segment with minimum header (20 bytes)
        let data = vec![
            0x00, 0x50, // src port = 80
            0x01, 0xbb, // dst port = 443
            0x00, 0x00, 0x00, 0x00, // seq = 0
            0x00, 0x00, 0x00, 0x00, // ack = 0
            0x50, 0x02, // data offset = 20, flags = SYN
            0x00, 0x00, // window = 0
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent
        ];
        let tcp = Tcp::new(&data).unwrap();
        assert_eq!(tcp.src_port(), 80);
        assert_eq!(tcp.dst_port(), 443);
        assert!(tcp.syn());
    }

    #[test]
    fn test_tcp_new_truncated() {
        let data = vec![0u8; 10];
        let result = Tcp::new(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_tcp_flags() {
        // TCP header is 20 bytes minimum
        let data = vec![
            0x00, 0x50, // src port = 80
            0x01, 0xbb, // dst port = 443
            0x00, 0x00, 0x00, 0x00, // seq = 0
            0x00, 0x00, 0x00, 0x00, // ack = 0
            0x50, 0x12, // data offset = 20, flags = SYN+ACK
            0x00, 0x00, // window = 0
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent pointer
        ];
        let tcp = Tcp::new(&data).unwrap();
        assert!(tcp.syn());
        assert!(tcp.ack_flag());
    }

    #[test]
    fn test_tcp_payload() {
        let mut data = vec![
            0x00, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload
        let tcp = Tcp::new(&data).unwrap();
        assert_eq!(tcp.payload(), &[0xde, 0xad, 0xbe, 0xef]);
    }
}
