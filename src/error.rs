//! Unified error types for capfile

use thiserror::Error;

/// Unified error type for all capfile operations
#[derive(Debug, Error)]
pub enum Error {
    /// IO error when reading files
    #[cfg(feature = "std")]
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid magic number in file header
    #[error("Invalid magic number: {0}")]
    InvalidMagic(u32),

    /// Invalid file format version
    #[error("Invalid version: {0}")]
    InvalidVersion(u16),

    /// Unsupported file format
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    /// Parsing error with context
    #[error("Parse error at offset {offset}: {message}")]
    Parse {
        /// Byte offset where the error occurred
        offset: usize,
        /// Human-readable error message
        message: String,
    },

    /// Invalid link type
    #[error("Invalid link type: {0}")]
    InvalidLinkType(u16),

    /// Invalid packet length
    #[error("Invalid packet length: {0}")]
    InvalidPacketLength(usize),

    /// Truncated data
    #[error("Truncated data: expected {expected} bytes, got {actual}")]
    Truncated {
        /// Expected number of bytes
        expected: usize,
        /// Actual number of bytes available
        actual: usize,
    },

    /// Invalid timestamp
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),

    /// No such interface in pcapng
    #[error("No such interface: {0}")]
    NoSuchInterface(u16),

    /// Unknown block type
    #[error("Unknown block type: {0}")]
    UnknownBlockType(u32),

    /// Dissection error
    #[error("Dissection error: {0}")]
    Dissection(String),
}

impl Error {
    /// Create a parse error at a specific offset
    pub fn parse(offset: usize, message: impl Into<String>) -> Self {
        Self::Parse {
            offset,
            message: message.into(),
        }
    }

    /// Create a truncated data error
    pub fn truncated(expected: usize, actual: usize) -> Self {
        Self::Truncated { expected, actual }
    }
}
