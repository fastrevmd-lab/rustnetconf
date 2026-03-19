//! Transport layer abstraction for NETCONF.
//!
//! The `Transport` trait provides a byte-stream interface (read/write raw bytes)
//! that the framing layer sits on top of. This separation means:
//! - Framing logic is written once, shared by all transports
//! - Transports are independently testable
//! - Future transports (TLS, RESTCONF) plug in without reimplementing framing

pub mod ssh;

use async_trait::async_trait;
use crate::error::TransportError;

/// Byte-stream transport for NETCONF sessions.
///
/// Implementations provide raw read/write access to the underlying connection
/// (SSH channel, TLS socket, etc.). The framing layer handles message boundaries.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Write bytes to the transport.
    async fn write_all(&mut self, data: &[u8]) -> Result<(), TransportError>;

    /// Read available bytes from the transport into the buffer.
    /// Returns the number of bytes read, or 0 if the connection is closed.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError>;

    /// Close the transport connection.
    async fn close(&mut self) -> Result<(), TransportError>;
}

/// In-memory mock transport for testing.
///
/// Reads from a pre-loaded response buffer and captures all written data.
/// Used by unit tests to verify session/framing behavior without SSH.
#[cfg(test)]
pub mod mock {
    use super::*;

    pub struct MockTransport {
        /// Data the "device" will send back (pre-loaded).
        read_data: Vec<u8>,
        read_pos: usize,
        /// Data written by the client (captured for assertions).
        pub written: Vec<u8>,
        /// Whether the transport has been closed.
        pub closed: bool,
    }

    impl MockTransport {
        /// Create a mock transport with the given canned response data.
        pub fn new(read_data: Vec<u8>) -> Self {
            Self {
                read_data,
                read_pos: 0,
                written: Vec::new(),
                closed: false,
            }
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn write_all(&mut self, data: &[u8]) -> Result<(), TransportError> {
            if self.closed {
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "transport closed",
                )));
            }
            self.written.extend_from_slice(data);
            Ok(())
        }

        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
            if self.closed {
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "transport closed",
                )));
            }
            let remaining = &self.read_data[self.read_pos..];
            if remaining.is_empty() {
                return Ok(0);
            }
            let to_read = std::cmp::min(buf.len(), remaining.len());
            buf[..to_read].copy_from_slice(&remaining[..to_read]);
            self.read_pos += to_read;
            Ok(to_read)
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            self.closed = true;
            Ok(())
        }
    }
}
