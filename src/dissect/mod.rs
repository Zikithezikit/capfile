//! Packet dissection module
//!
//! Provides zero-copy packet dissection from Ethernet to upper layers.

pub mod dns;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;

/// Trait for dissecting packet layers
///
/// Implement this trait to add support for dissecting protocol layers.
/// The implementation should borrow from the packet data without copying.
pub trait Dissect<'a> {
    /// The output type after dissection
    type Output;

    /// Parse the next layer from the current packet data
    fn dissect(&self) -> Result<Self::Output, crate::Error>;

    /// Get the raw packet data
    fn data(&self) -> &'a [u8];

    /// Get the length of this layer's header
    fn header_len(&self) -> usize;
}

/// Result type alias for dissection
pub type DissectResult<T> = Result<T, crate::Error>;
