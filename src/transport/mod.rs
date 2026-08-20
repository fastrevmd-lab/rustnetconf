//! Transport layer abstraction for NETCONF.
//!
//! The `Transport` trait provides a byte-stream interface (read/write raw bytes)
//! that the framing layer sits on top of. This separation means:
//! - Framing logic is written once, shared by all transports
//! - Transports are independently testable
//! - Future transports (TLS, RESTCONF) plug in without reimplementing framing

pub mod known_hosts;
pub mod ssh;
#[cfg(feature = "tls")]
pub mod tls;

use crate::error::TransportError;
use async_trait::async_trait;

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
    use std::sync::{Arc, Mutex};

    pub struct MockTransport {
        /// Data the "device" will send back (pre-loaded).
        read_data: Vec<u8>,
        read_pos: usize,
        /// Data written by the client (captured for assertions).
        written: Arc<Mutex<Vec<u8>>>,
        /// Whether the transport has been closed.
        pub closed: bool,
    }

    impl MockTransport {
        /// Create a mock transport with the given canned response data.
        pub fn new(read_data: Vec<u8>) -> Self {
            Self {
                read_data,
                read_pos: 0,
                written: Arc::new(Mutex::new(Vec::new())),
                closed: false,
            }
        }

        /// Get a handle to the written data that remains accessible after the
        /// transport is moved into a Session.
        pub fn written_handle(&self) -> Arc<Mutex<Vec<u8>>> {
            Arc::clone(&self.written)
        }
    }

    /// Mock transport that stalls once before reporting EOF.
    ///
    /// `MockTransport` reads synchronously and so can never be interrupted
    /// mid-await, which makes it impossible to test cancellation. This variant
    /// parks forever on the first read that would otherwise return EOF, so a
    /// caller wrapping the operation in `tokio::time::timeout` genuinely drops
    /// the future at its `.await`. Every read after that returns EOF normally,
    /// so a follow-up operation can observe how the session behaves once a
    /// cancelled call is behind it.
    pub struct StallingMockTransport {
        read_data: Vec<u8>,
        read_pos: usize,
        stalled_once: bool,
        written: Arc<Mutex<Vec<u8>>>,
        pub closed: bool,
    }

    impl StallingMockTransport {
        /// Create a stalling mock with the given canned response data.
        pub fn new(read_data: Vec<u8>) -> Self {
            Self {
                read_data,
                read_pos: 0,
                stalled_once: false,
                written: Arc::new(Mutex::new(Vec::new())),
                closed: false,
            }
        }
    }

    #[async_trait]
    impl Transport for StallingMockTransport {
        async fn write_all(&mut self, data: &[u8]) -> Result<(), TransportError> {
            self.written.lock().unwrap().extend_from_slice(data);
            Ok(())
        }

        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
            let remaining = &self.read_data[self.read_pos..];
            if remaining.is_empty() {
                // Park once so the caller's timeout can cancel us here. The flag
                // is set *before* the await, so the cancellation that drops this
                // future still leaves the stall spent.
                if !self.stalled_once {
                    self.stalled_once = true;
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                }
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

    #[async_trait]
    impl Transport for MockTransport {
        async fn write_all(&mut self, data: &[u8]) -> Result<(), TransportError> {
            if self.closed {
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "transport closed",
                )));
            }
            self.written.lock().unwrap().extend_from_slice(data);
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
