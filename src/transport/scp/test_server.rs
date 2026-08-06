//! Loopback SSH server for testing ScpClient end-to-end.

#![cfg(test)]
#![allow(dead_code)]

use russh::keys::*;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::*;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Parsed T header (timestamps for preserve mode).
#[derive(Clone, Debug)]
pub struct THeader {
    pub mtime: i64,
    pub atime: i64,
}

/// Parsed C header (mode, size, filename).
#[derive(Clone, Debug)]
pub struct CHeader {
    pub mode: u32,
    pub size: u64,
    pub filename: Vec<u8>,
}

/// Protocol data captured during an SCP transfer.
#[derive(Clone, Debug, Default)]
pub struct CapturedProtocol {
    pub t_header: Option<THeader>,
    pub c_header: Option<CHeader>,
    pub payload: Vec<u8>,
    pub terminator_received: bool,
}

/// Configurable SCP server behavior for testing.
#[derive(Clone, Debug)]
pub enum ServerBehavior {
    /// Normal sink: ack everything, read payload, exit 0.
    SinkSuccess,
    /// Normal source: send file content, exit 0.
    SourceSuccess {
        filename: String,
        content: Vec<u8>,
        mode: u32,
    },
    /// Send error ack byte at initial handshake.
    ErrorAck { code: u8, message: String },
    /// Exit with non-zero status after successful protocol.
    NonZeroExit { code: u32 },
    /// Never consume data after accepting C header (tests cancellation).
    SinkStall,
    /// Send header and payload in coalesced messages.
    SourceCoalesced {
        filename: String,
        content: Vec<u8>,
        mode: u32,
    },
    /// Send payload one byte at a time.
    SourceOneByte {
        filename: String,
        content: Vec<u8>,
        mode: u32,
    },
    /// Reject the exec request (send ChannelMsg::Failure).
    RejectExec,
    /// Send exit signal after data phase.
    ExitSignal,
    /// Source sends error status byte after payload.
    SourceFinalError {
        filename: String,
        content: Vec<u8>,
        mode: u32,
        code: u8,
        message: String,
    },
    /// Send SCP ready ack BEFORE channel success (upload regression test).
    SinkDataBeforeSuccess,
    /// Send C header BEFORE channel success (download regression test).
    SourceDataBeforeSuccess {
        filename: String,
        content: Vec<u8>,
        mode: u32,
    },
    /// Sink accepts header, then sends status-1 error after payload (e.g., disk full).
    SinkFinalError { code: u8, message: String },
    /// Sink that validates preserve mode (-p) was requested and T header was sent.
    SinkCheckPreserve,
    /// Source sends C header, waits for ack, then stalls forever (tests cancellation
    /// during download while file is open and mode-widening is in progress).
    SourceStallAfterHeader {
        filename: String,
        mode: u32,
        size: u64,
    },
    /// Delay channel open confirmation to test cancellation during channel_open_session.
    DelayChannelOpen,
    /// Sink sends warning ack (byte 1) instead of success on C header.
    SinkWarningAckOnCHeader { message: String },
}

/// Server state shared across connections.
#[derive(Clone)]
pub struct TestServerState {
    pub behavior: Arc<Mutex<ServerBehavior>>,
    pub captured: Arc<Mutex<Option<CapturedProtocol>>>,
}

impl TestServerState {
    pub fn new(behavior: ServerBehavior) -> Self {
        Self {
            behavior: Arc::new(Mutex::new(behavior)),
            captured: Arc::new(Mutex::new(None)),
        }
    }

    /// Get captured protocol data after transfer completes.
    pub async fn get_captured(&self) -> Option<CapturedProtocol> {
        self.captured.lock().await.clone()
    }
}

struct TestServer {
    state: TestServerState,
}

impl server::Server for TestServer {
    type Handler = TestHandler;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        TestHandler {
            state: self.state.clone(),
            received_data: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

struct TestHandler {
    state: TestServerState,
    /// Buffer of data received from client via data() callback.
    /// Shared across channels (each channel_open_session creates a new handler).
    received_data: Arc<Mutex<Vec<u8>>>,
}

impl server::Handler for TestHandler {
    type Error = russh::Error;

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Capture all data sent by client (T header, C header, file payload, E\n terminator).
        // The sink protocol state machine will parse from this buffer.
        eprintln!("[TEST SERVER] Received {} bytes: {:?}", data.len(), data);
        let mut buf = self.received_data.lock().await;
        buf.extend_from_slice(data);
        eprintln!("[TEST SERVER] Buffer now has {} bytes", buf.len());
        Ok(())
    }

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let behavior = self.state.behavior.lock().await.clone();
        if matches!(behavior, ServerBehavior::DelayChannelOpen) {
            // Delay the accept to test cancellation during channel_open_session
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        }
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        eprintln!(
            "[TEST SERVER] exec_request: {:?}",
            String::from_utf8_lossy(data)
        );
        let behavior = self.state.behavior.lock().await.clone();
        eprintln!("[TEST SERVER] Behavior: {:?}", behavior);

        // Check for RejectExec before parsing command
        if matches!(behavior, ServerBehavior::RejectExec) {
            session.channel_failure(channel)?;
            session.eof(channel)?;
            session.close(channel)?;
            return Ok(());
        }

        let cmd = String::from_utf8_lossy(data).to_string();

        // Check for data-before-success behaviors
        let send_success_after_data = matches!(
            behavior,
            ServerBehavior::SinkDataBeforeSuccess
                | ServerBehavior::SourceDataBeforeSuccess { .. }
                | ServerBehavior::SinkFinalError { .. }
        );

        // Send success for accepted exec requests (unless data-before-success)
        if !send_success_after_data {
            session.channel_success(channel)?;
        }

        // Clone data needed for background task
        let received_data = self.received_data.clone();
        let handle = session.handle();
        let captured = self.state.captured.clone();

        // Spawn background task to handle SCP protocol asynchronously
        // This prevents blocking the russh handler while waiting for client data
        tokio::spawn(async move {
            if cmd.contains(" -t ") {
                let _ = Self::handle_scp_sink_async(
                    channel,
                    handle.clone(),
                    behavior.clone(),
                    received_data,
                    send_success_after_data,
                    captured,
                )
                .await;
            } else if cmd.contains(" -f ") {
                let _ =
                    Self::handle_scp_source_async(channel, handle.clone(), behavior, received_data)
                        .await;
            }
        });

        Ok(())
    }
}

/// Parse a line from the buffer (delimited by \n), consuming it on success.
/// Polls with timeout to allow data() handler to populate the buffer.
async fn read_line(buf: &Arc<Mutex<Vec<u8>>>) -> Result<Vec<u8>, russh::Error> {
    let timeout_duration = std::time::Duration::from_secs(2);
    let start = std::time::Instant::now();

    loop {
        {
            let mut data = buf.lock().await;
            if let Some(pos) = data.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = data.drain(..=pos).collect();
                return Ok(line);
            }
        } // Drop lock before sleeping

        if start.elapsed() > timeout_duration {
            return Err(russh::Error::from(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timeout waiting for data",
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

/// Read exactly `len` bytes from the buffer, consuming them on success.
/// Polls with timeout to allow data() handler to populate the buffer.
async fn read_exact(buf: &Arc<Mutex<Vec<u8>>>, len: usize) -> Result<Vec<u8>, russh::Error> {
    let timeout_duration = std::time::Duration::from_secs(2);
    let start = std::time::Instant::now();

    loop {
        {
            let mut data = buf.lock().await;
            if data.len() >= len {
                let chunk: Vec<u8> = data.drain(..len).collect();
                return Ok(chunk);
            }
        } // Drop lock before sleeping

        if start.elapsed() > timeout_duration {
            return Err(russh::Error::from(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timeout waiting for data",
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

impl TestHandler {
    /// Async sink handler that runs in background task.
    /// Uses session handle to send data without blocking the russh handler.
    async fn handle_scp_sink_async(
        channel: ChannelId,
        handle: russh::server::Handle,
        behavior: ServerBehavior,
        received_data: Arc<Mutex<Vec<u8>>>,
        _send_success_after_data: bool,
        captured: Arc<Mutex<Option<CapturedProtocol>>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match behavior {
            ServerBehavior::ErrorAck { code, message } => {
                // Send error ack byte with message
                let mut msg = vec![code];
                msg.extend_from_slice(message.as_bytes());
                msg.push(b'\n');
                let _ = handle.data(channel, msg).await;
                let _ = handle.exit_status_request(channel, 1).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                Ok(())
            }

            ServerBehavior::SinkStall => {
                // Send initial \0
                let _ = handle.data(channel, vec![0u8]).await;

                // Parse T header
                let _t_line = read_line(&received_data).await?;

                // Send \0 to accept T header
                let _ = handle.data(channel, vec![0u8]).await;

                // Parse C header
                let _c_line = read_line(&received_data).await?;

                // Send \0 to accept C header
                let _ = handle.data(channel, vec![0u8]).await;

                // Now stall forever - client should cancel
                tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
                Ok(())
            }

            ServerBehavior::NonZeroExit { code } => {
                // Do normal protocol but exit non-zero
                Self::handle_normal_sink_async(channel, handle.clone(), received_data, captured)
                    .await?;
                let _ = handle.exit_status_request(channel, code).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                Ok(())
            }

            ServerBehavior::SinkSuccess => {
                Self::handle_normal_sink_async(channel, handle.clone(), received_data, captured)
                    .await?;
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                Ok(())
            }

            ServerBehavior::SinkDataBeforeSuccess => {
                // Send initial \0 BEFORE channel_success (regression test)
                // channel_success is sent after this function returns
                let _ = handle.data(channel, vec![0u8]).await;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;

                // Continue with normal protocol
                Self::handle_normal_sink_after_ready_async(channel, handle.clone(), received_data)
                    .await?;
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                Ok(())
            }

            ServerBehavior::ExitSignal => {
                // Do normal protocol then send exit signal
                Self::handle_normal_sink_async(channel, handle.clone(), received_data, captured)
                    .await?;
                let _ = handle
                    .exit_signal_request(
                        channel,
                        russh::Sig::TERM, // Signal type
                        false,            // core_dumped
                        "".to_string(),   // error message
                        "".to_string(),   // language tag
                    )
                    .await;
                let _ = handle.close(channel).await;
                Ok(())
            }

            ServerBehavior::SinkFinalError { code, message } => {
                // Send initial \0 (ready)
                let _ = handle.data(channel, vec![0u8]).await;

                // Parse T header
                let _t_line = read_line(&received_data).await?;

                // Send \0 (accept T header)
                let _ = handle.data(channel, vec![0u8]).await;

                // Parse C header
                let c_line = read_line(&received_data).await?;
                let c_str = String::from_utf8_lossy(&c_line[1..c_line.len() - 1]);
                let parts: Vec<&str> = c_str.splitn(3, ' ').collect();
                let size = parts[1].parse::<u64>().unwrap_or(0);

                // Send \0 (accept C header)
                let _ = handle.data(channel, vec![0u8]).await;

                // Consume payload and trailing \0
                let _payload = read_exact(&received_data, size as usize).await?;
                let _trailing = read_exact(&received_data, 1).await?;

                // Send error status instead of success (e.g., \x01 disk full)
                let mut error_msg = vec![code];
                error_msg.extend_from_slice(message.as_bytes());
                error_msg.push(b'\n');
                let _ = handle.data(channel, error_msg).await;

                // Exit 0 (tests that typed error is preserved despite clean exit)
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                Ok(())
            }

            ServerBehavior::SinkCheckPreserve => {
                // Verify that the client sent T header (preserve mode) before C header
                let mut cap = CapturedProtocol::default();
                let _ = handle.data(channel, vec![0u8]).await; // Initial ready

                // Parse T header: T<mtime> 0 <atime> 0\n
                let t_line = read_line(&received_data).await?;
                // Validate T header was actually sent
                if !t_line.starts_with(b"T") {
                    let msg = "preserve mode not honored: missing T header";
                    let _ = handle
                        .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                        .await;
                    let _ = handle.exit_status_request(channel, 1).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                    return Ok(());
                }

                // Parse T header
                let t_str = String::from_utf8_lossy(&t_line[1..t_line.len() - 1]);
                let t_parts: Vec<&str> = t_str.split_whitespace().collect();
                if t_parts.len() >= 4 {
                    if let (Ok(mtime), Ok(atime)) =
                        (t_parts[0].parse::<i64>(), t_parts[2].parse::<i64>())
                    {
                        cap.t_header = Some(THeader { mtime, atime });
                    }
                }

                let _ = handle.data(channel, vec![0u8]).await; // Ack T header

                // Parse C header
                let c_line = read_line(&received_data).await?;
                let c_str = String::from_utf8_lossy(&c_line[1..c_line.len() - 1]);
                let parts: Vec<&str> = c_str.splitn(3, ' ').collect();
                let size = parts[1].parse::<u64>().unwrap_or(0);

                let mode = u32::from_str_radix(parts[0], 8).unwrap_or(0);
                let filename = parts[2].as_bytes().to_vec();
                cap.c_header = Some(CHeader {
                    mode,
                    size,
                    filename,
                });

                let _ = handle.data(channel, vec![0u8]).await; // Ack C header

                // Consume payload and trailing \0
                let payload = read_exact(&received_data, size as usize).await?;
                cap.payload = payload;
                let _trailing = read_exact(&received_data, 1).await?;

                let _ = handle.data(channel, vec![0u8]).await; // Ack data received

                // Parse E\n terminator
                let e_line = read_line(&received_data).await?;
                if e_line == b"E\n" {
                    cap.terminator_received = true;
                }

                let _ = handle.data(channel, vec![0u8]).await; // Final ack

                // Store captured protocol
                *captured.lock().await = Some(cap);

                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                Ok(())
            }

            ServerBehavior::SinkWarningAckOnCHeader { message } => {
                // Send initial \0 (ready)
                let _ = handle.data(channel, vec![0u8]).await;

                // Parse T header
                let _t_line = read_line(&received_data).await?;

                // Send \0 (accept T header)
                let _ = handle.data(channel, vec![0u8]).await;

                // Parse C header
                let _c_line = read_line(&received_data).await?;

                // Send warning ack (byte 1) instead of success on C header
                let mut warning_msg = vec![1u8];
                warning_msg.extend_from_slice(message.as_bytes());
                warning_msg.push(b'\n');
                let _ = handle.data(channel, warning_msg).await;

                // Exit non-zero since transfer is rejected
                let _ = handle.exit_status_request(channel, 1).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                Ok(())
            }

            _ => Ok(()),
        }
    }

    /// Async source handler that runs in background task.
    async fn handle_scp_source_async(
        channel: ChannelId,
        handle: russh::server::Handle,
        behavior: ServerBehavior,
        _received_data: Arc<Mutex<Vec<u8>>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match behavior {
            ServerBehavior::SourceSuccess {
                filename,
                content,
                mode,
            } => {
                Self::send_file_async(
                    channel,
                    handle.clone(),
                    &filename,
                    &content,
                    mode,
                    false,
                    false,
                )
                .await?;
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                Ok(())
            }

            ServerBehavior::SourceCoalesced {
                filename,
                content,
                mode,
            } => {
                Self::send_file_async(
                    channel,
                    handle.clone(),
                    &filename,
                    &content,
                    mode,
                    true,
                    false,
                )
                .await?;
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                Ok(())
            }

            ServerBehavior::SourceOneByte {
                filename,
                content,
                mode,
            } => {
                Self::send_file_async(
                    channel,
                    handle.clone(),
                    &filename,
                    &content,
                    mode,
                    false,
                    true,
                )
                .await?;
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                Ok(())
            }

            ServerBehavior::NonZeroExit { code } => {
                // For download: Send minimal valid protocol then exit non-zero
                // Send a tiny file so the client can complete the transfer
                Self::send_file_async(
                    channel,
                    handle.clone(),
                    "test.txt",
                    b"x",
                    0o644,
                    false,
                    false,
                )
                .await?;
                let _ = handle.exit_status_request(channel, code).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                Ok(())
            }

            ServerBehavior::SourceFinalError {
                filename,
                content,
                mode,
                code,
                message,
            } => {
                // Send file normally but end with error status byte instead of \0
                Self::send_file_with_error_async(
                    channel,
                    handle.clone(),
                    &filename,
                    &content,
                    mode,
                    code,
                    &message,
                )
                .await?;
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                Ok(())
            }

            ServerBehavior::SourceDataBeforeSuccess {
                filename,
                content,
                mode,
            } => {
                // Send C header BEFORE channel_success (regression test)
                // channel_success is sent after this function returns
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                let header = format!("C{:04o} {} {}\n", mode, content.len(), filename);
                let _ = handle.data(channel, header.as_bytes().to_vec()).await;

                // Wait for client ack
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;

                // Send content
                let _ = handle.data(channel, content.to_vec()).await;

                // Send trailing \0
                let _ = handle.data(channel, vec![0u8]).await;

                // Wait for client final ack
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;

                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                Ok(())
            }

            ServerBehavior::SourceStallAfterHeader {
                filename,
                mode,
                size,
            } => {
                // Wait for client's initial \0
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;

                // Send C header with specified mode
                let header = format!("C{:04o} {} {}\n", mode, size, filename);
                let _ = handle.data(channel, header.as_bytes().to_vec()).await;

                // Wait for client ack
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;

                // Now stall forever - client should cancel
                // This lets us test that the file's mode is never widened while old contents exist
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                Ok(())
            }

            _ => Ok(()),
        }
    }

    /// Normal sink protocol using session handle.
    async fn handle_normal_sink_async(
        channel: ChannelId,
        handle: russh::server::Handle,
        received_data: Arc<Mutex<Vec<u8>>>,
        captured: Arc<Mutex<Option<CapturedProtocol>>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut cap = CapturedProtocol::default();

        // Send initial \0 (ready)
        let _ = handle.data(channel, vec![0u8]).await;

        // 1. Parse T header: T<mtime> 0 <atime> 0\n
        let t_line = read_line(&received_data).await?;
        if !t_line.starts_with(b"T") || !t_line.ends_with(b"\n") {
            let msg = format!("expected T header, got: {:?}", t_line);
            let _ = handle
                .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                .await;
            return Ok(());
        }

        // Parse T header: T<mtime> 0 <atime> 0\n
        let t_str = String::from_utf8_lossy(&t_line[1..t_line.len() - 1]);
        let t_parts: Vec<&str> = t_str.split_whitespace().collect();
        if t_parts.len() >= 4 {
            if let (Ok(mtime), Ok(atime)) = (t_parts[0].parse::<i64>(), t_parts[2].parse::<i64>()) {
                cap.t_header = Some(THeader { mtime, atime });
            }
        }

        // Send \0 (accept T header)
        let _ = handle.data(channel, vec![0u8]).await;

        // 2. Parse C header: C<mode> <size> <name>\n
        let c_line = read_line(&received_data).await?;
        if !c_line.starts_with(b"C") || !c_line.ends_with(b"\n") {
            let msg = format!("expected C header, got: {:?}", c_line);
            let _ = handle
                .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                .await;
            return Ok(());
        }

        // Parse C header: C<mode> <size> <name>\n
        let c_str = String::from_utf8_lossy(&c_line[1..c_line.len() - 1]);
        let parts: Vec<&str> = c_str.splitn(3, ' ').collect();
        if parts.len() < 3 {
            let msg = format!("malformed C header: {:?}", c_line);
            let _ = handle
                .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                .await;
            return Ok(());
        }

        let mode = u32::from_str_radix(parts[0], 8).unwrap_or(0);
        let size = match parts[1].parse::<u64>() {
            Ok(s) => s,
            Err(_) => {
                let msg = format!("invalid size in C header: {:?}", c_line);
                let _ = handle
                    .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                    .await;
                return Ok(());
            }
        };
        let filename = parts[2].as_bytes().to_vec();

        cap.c_header = Some(CHeader {
            mode,
            size,
            filename,
        });

        // Send \0 (accept C header)
        let _ = handle.data(channel, vec![0u8]).await;

        // 3. Consume exactly `size` payload bytes
        let payload = read_exact(&received_data, size as usize).await?;
        // Validate payload was received (we have it in memory, basic assertion)
        if payload.len() != size as usize {
            let msg = format!(
                "payload size mismatch: expected {}, got {}",
                size,
                payload.len()
            );
            let _ = handle
                .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                .await;
            return Ok(());
        }

        cap.payload = payload;

        // 4. Consume trailing \0
        let trailing = read_exact(&received_data, 1).await?;
        if trailing[0] != 0u8 {
            let msg = format!("expected trailing \\0, got: {:?}", trailing);
            let _ = handle
                .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                .await;
            return Ok(());
        }

        // Send \0 (data received)
        let _ = handle.data(channel, vec![0u8]).await;

        // 5. Parse E\n terminator
        let e_line = read_line(&received_data).await?;
        if e_line != b"E\n" {
            let msg = format!("expected E\\n, got: {:?}", e_line);
            let _ = handle
                .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                .await;
            return Ok(());
        }

        cap.terminator_received = true;

        // Send final \0
        let _ = handle.data(channel, vec![0u8]).await;

        // Store captured protocol
        *captured.lock().await = Some(cap);

        Ok(())
    }

    /// Normal sink protocol after initial ready byte, using session handle.
    async fn handle_normal_sink_after_ready_async(
        channel: ChannelId,
        handle: russh::server::Handle,
        received_data: Arc<Mutex<Vec<u8>>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Initial \0 already sent, continue from T header

        // 1. Parse T header
        let t_line = read_line(&received_data).await?;
        if !t_line.starts_with(b"T") || !t_line.ends_with(b"\n") {
            let msg = format!("expected T header, got: {:?}", t_line);
            let _ = handle
                .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                .await;
            return Ok(());
        }

        // Send \0 (accept T header)
        let _ = handle.data(channel, vec![0u8]).await;

        // 2. Parse C header
        let c_line = read_line(&received_data).await?;
        if !c_line.starts_with(b"C") || !c_line.ends_with(b"\n") {
            let msg = format!("expected C header, got: {:?}", c_line);
            let _ = handle
                .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                .await;
            return Ok(());
        }

        let c_str = String::from_utf8_lossy(&c_line[1..c_line.len() - 1]);
        let parts: Vec<&str> = c_str.splitn(3, ' ').collect();
        if parts.len() < 3 {
            let msg = format!("malformed C header: {:?}", c_line);
            let _ = handle
                .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                .await;
            return Ok(());
        }
        let size = match parts[1].parse::<u64>() {
            Ok(s) => s,
            Err(_) => {
                let msg = format!("invalid size in C header: {:?}", c_line);
                let _ = handle
                    .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                    .await;
                return Ok(());
            }
        };

        // Send \0 (accept C header)
        let _ = handle.data(channel, vec![0u8]).await;

        // 3. Consume payload
        let payload = read_exact(&received_data, size as usize).await?;
        if payload.len() != size as usize {
            let msg = format!(
                "payload size mismatch: expected {}, got {}",
                size,
                payload.len()
            );
            let _ = handle
                .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                .await;
            return Ok(());
        }

        // 4. Consume trailing \0
        let trailing = read_exact(&received_data, 1).await?;
        if trailing[0] != 0u8 {
            let msg = format!("expected trailing \\0, got: {:?}", trailing);
            let _ = handle
                .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                .await;
            return Ok(());
        }

        // Send \0 (data received)
        let _ = handle.data(channel, vec![0u8]).await;

        // 5. Parse E\n
        let e_line = read_line(&received_data).await?;
        if e_line != b"E\n" {
            let msg = format!("expected E\\n, got: {:?}", e_line);
            let _ = handle
                .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                .await;
            return Ok(());
        }

        // Send final \0
        let _ = handle.data(channel, vec![0u8]).await;

        Ok(())
    }

    /// Send file using session handle.
    #[allow(clippy::too_many_arguments)]
    async fn send_file_async(
        channel: ChannelId,
        handle: russh::server::Handle,
        filename: &str,
        content: &[u8],
        mode: u32,
        coalesced: bool,
        one_byte: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Wait for client's initial \0
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let header = format!("C{:04o} {} {}\n", mode, content.len(), filename);

        if coalesced {
            // Send header + content in one message
            let mut msg = header.as_bytes().to_vec();
            msg.extend_from_slice(content);
            msg.push(0u8); // trailing \0
            let _ = handle.data(channel, msg).await;
        } else if one_byte {
            // Send header normally
            let _ = handle.data(channel, header.as_bytes().to_vec()).await;

            // Wait for client ack
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;

            // Send content one byte at a time
            for &byte in content {
                let _ = handle.data(channel, vec![byte]).await;
            }

            // Send trailing \0
            let _ = handle.data(channel, vec![0u8]).await;
        } else {
            // Normal: send header
            let _ = handle.data(channel, header.as_bytes().to_vec()).await;

            // Wait for client ack
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;

            // Send content
            let _ = handle.data(channel, content.to_vec()).await;

            // Send trailing \0
            let _ = handle.data(channel, vec![0u8]).await;
        }

        // Wait for client's final ack
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        Ok(())
    }

    /// Send file with error status using session handle.
    #[allow(clippy::too_many_arguments)]
    async fn send_file_with_error_async(
        channel: ChannelId,
        handle: russh::server::Handle,
        filename: &str,
        content: &[u8],
        mode: u32,
        error_code: u8,
        error_message: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Wait for client's initial \0
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let header = format!("C{:04o} {} {}\n", mode, content.len(), filename);
        let _ = handle.data(channel, header.as_bytes().to_vec()).await;

        // Wait for client ack
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Send content
        let _ = handle.data(channel, content.to_vec()).await;

        // Send error status byte + message instead of \0
        let mut msg = vec![error_code];
        msg.extend_from_slice(error_message.as_bytes());
        msg.push(b'\n');
        let _ = handle.data(channel, msg).await;

        Ok(())
    }

    async fn handle_scp_sink(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let behavior = self.state.behavior.lock().await.clone();

        match behavior {
            ServerBehavior::ErrorAck { code, message } => {
                // Send error ack byte with message
                let mut msg = vec![code];
                msg.extend_from_slice(message.as_bytes());
                msg.push(b'\n');
                session.data(channel, msg)?;
                let _ = session.exit_status_request(channel, 1);
                session.eof(channel)?;
                session.close(channel)?;
                Ok(())
            }

            ServerBehavior::SinkStall => {
                // Send initial \0
                session.data(channel, vec![0u8])?;

                // Parse T header
                let _t_line = read_line(&self.received_data).await?;

                // Send \0 to accept T header
                session.data(channel, vec![0u8])?;

                // Parse C header
                let _c_line = read_line(&self.received_data).await?;

                // Send \0 to accept C header
                session.data(channel, vec![0u8])?;

                // Now stall forever - client should cancel
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                Ok(())
            }

            ServerBehavior::NonZeroExit { code } => {
                // Do normal protocol but exit non-zero
                self.handle_normal_sink(channel, session).await?;
                let _ = session.exit_status_request(channel, code);
                session.eof(channel)?;
                session.close(channel)?;
                Ok(())
            }

            ServerBehavior::SinkSuccess => {
                self.handle_normal_sink(channel, session).await?;
                let _ = session.exit_status_request(channel, 0);
                session.eof(channel)?;
                session.close(channel)?;
                Ok(())
            }

            ServerBehavior::SinkDataBeforeSuccess => {
                // Send initial \0 BEFORE channel_success (regression test)
                // channel_success is sent after this function returns
                session.data(channel, vec![0u8])?;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;

                // Continue with normal protocol
                self.handle_normal_sink_after_ready(channel, session)
                    .await?;
                let _ = session.exit_status_request(channel, 0);
                session.eof(channel)?;
                session.close(channel)?;
                Ok(())
            }

            ServerBehavior::ExitSignal => {
                // Do normal protocol then send exit signal
                self.handle_normal_sink(channel, session).await?;
                session.exit_signal_request(
                    channel,
                    russh::Sig::TERM, // Signal type
                    false,            // core_dumped
                    "",               // error message
                    "",               // language tag
                )?;
                session.close(channel)?;
                Ok(())
            }

            ServerBehavior::SinkFinalError { code, message } => {
                // Send initial \0 (ready)
                session.data(channel, vec![0u8])?;

                // Parse T header
                let _t_line = read_line(&self.received_data).await?;

                // Send \0 (accept T header)
                session.data(channel, vec![0u8])?;

                // Parse C header
                let c_line = read_line(&self.received_data).await?;
                let c_str = String::from_utf8_lossy(&c_line[1..c_line.len() - 1]);
                let parts: Vec<&str> = c_str.splitn(3, ' ').collect();
                let size = parts[1].parse::<u64>().unwrap_or(0);

                // Send \0 (accept C header)
                session.data(channel, vec![0u8])?;

                // Consume payload and trailing \0
                let _payload = read_exact(&self.received_data, size as usize).await?;
                let _trailing = read_exact(&self.received_data, 1).await?;

                // Send error status instead of success (e.g., \x01 disk full)
                let mut error_msg = vec![code];
                error_msg.extend_from_slice(message.as_bytes());
                error_msg.push(b'\n');
                session.data(channel, error_msg)?;

                // Exit 0 (tests that typed error is preserved despite clean exit)
                let _ = session.exit_status_request(channel, 0);
                session.eof(channel)?;
                session.close(channel)?;
                Ok(())
            }

            ServerBehavior::SinkCheckPreserve => {
                // Verify that the client sent T header (preserve mode) before C header
                session.data(channel, vec![0u8])?; // Initial ready

                // Parse T header: T<mtime> 0 <atime> 0\n
                let t_line = read_line(&self.received_data).await?;
                // Validate T header was actually sent
                if !t_line.starts_with(b"T") {
                    let msg = "preserve mode not honored: missing T header";
                    session.data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())?;
                    let _ = session.exit_status_request(channel, 1);
                    session.eof(channel)?;
                    session.close(channel)?;
                    return Ok(());
                }

                session.data(channel, vec![0u8])?; // Ack T header

                // Parse C header
                let c_line = read_line(&self.received_data).await?;
                let c_str = String::from_utf8_lossy(&c_line[1..c_line.len() - 1]);
                let parts: Vec<&str> = c_str.splitn(3, ' ').collect();
                let size = parts[1].parse::<u64>().unwrap_or(0);

                session.data(channel, vec![0u8])?; // Ack C header

                // Consume payload and trailing \0
                let _payload = read_exact(&self.received_data, size as usize).await?;
                let _trailing = read_exact(&self.received_data, 1).await?;

                session.data(channel, vec![0u8])?; // Ack data received

                // Parse E\n terminator
                let _e_line = read_line(&self.received_data).await?;

                session.data(channel, vec![0u8])?; // Final ack

                let _ = session.exit_status_request(channel, 0);
                session.eof(channel)?;
                session.close(channel)?;
                Ok(())
            }

            ServerBehavior::SinkWarningAckOnCHeader { message } => {
                // Send initial \0 (ready)
                session.data(channel, vec![0u8])?;

                // Parse T header
                let _t_line = read_line(&self.received_data).await?;

                // Send \0 (accept T header)
                session.data(channel, vec![0u8])?;

                // Parse C header
                let _c_line = read_line(&self.received_data).await?;

                // Send warning ack (byte 1) instead of success on C header
                let mut warning_msg = vec![1u8];
                warning_msg.extend_from_slice(message.as_bytes());
                warning_msg.push(b'\n');
                session.data(channel, warning_msg)?;

                // Exit non-zero since transfer is rejected
                let _ = session.exit_status_request(channel, 1);
                session.eof(channel)?;
                session.close(channel)?;
                Ok(())
            }

            _ => Ok(()),
        }
    }

    async fn handle_normal_sink(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        // Send initial \0 (ready)
        session.data(channel, vec![0u8])?;

        // 1. Parse T header: T<mtime> 0 <atime> 0\n
        let t_line = read_line(&self.received_data).await?;
        if !t_line.starts_with(b"T") || !t_line.ends_with(b"\n") {
            let msg = format!("expected T header, got: {:?}", t_line);
            session.data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())?;
            return Ok(());
        }

        // Send \0 (accept T header)
        session.data(channel, vec![0u8])?;

        // 2. Parse C header: C<mode> <size> <name>\n
        let c_line = read_line(&self.received_data).await?;
        if !c_line.starts_with(b"C") || !c_line.ends_with(b"\n") {
            let msg = format!("expected C header, got: {:?}", c_line);
            session.data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())?;
            return Ok(());
        }

        // Parse C header: C<mode> <size> <name>\n
        let c_str = String::from_utf8_lossy(&c_line[1..c_line.len() - 1]);
        let parts: Vec<&str> = c_str.splitn(3, ' ').collect();
        if parts.len() < 3 {
            let msg = format!("malformed C header: {:?}", c_line);
            session.data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())?;
            return Ok(());
        }
        let size = match parts[1].parse::<u64>() {
            Ok(s) => s,
            Err(_) => {
                let msg = format!("invalid size in C header: {:?}", c_line);
                session.data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())?;
                return Ok(());
            }
        };

        // Send \0 (accept C header)
        session.data(channel, vec![0u8])?;

        // 3. Consume exactly `size` payload bytes
        let payload = read_exact(&self.received_data, size as usize).await?;
        // Validate payload was received (we have it in memory, basic assertion)
        if payload.len() != size as usize {
            let msg = format!(
                "payload size mismatch: expected {}, got {}",
                size,
                payload.len()
            );
            session.data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())?;
            return Ok(());
        }

        // 4. Consume trailing \0
        let trailing = read_exact(&self.received_data, 1).await?;
        if trailing[0] != 0u8 {
            let msg = format!("expected trailing \\0, got: {:?}", trailing);
            session.data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())?;
            return Ok(());
        }

        // Send \0 (data received)
        session.data(channel, vec![0u8])?;

        // 5. Parse E\n terminator
        let e_line = read_line(&self.received_data).await?;
        if e_line != b"E\n" {
            let msg = format!("expected E\\n, got: {:?}", e_line);
            session.data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())?;
            return Ok(());
        }

        // Send final \0
        session.data(channel, vec![0u8])?;

        Ok(())
    }

    async fn handle_normal_sink_after_ready(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        // Initial \0 already sent, continue from T header

        // 1. Parse T header
        let t_line = read_line(&self.received_data).await?;
        if !t_line.starts_with(b"T") || !t_line.ends_with(b"\n") {
            let msg = format!("expected T header, got: {:?}", t_line);
            session.data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())?;
            return Ok(());
        }

        // Send \0 (accept T header)
        session.data(channel, vec![0u8])?;

        // 2. Parse C header
        let c_line = read_line(&self.received_data).await?;
        if !c_line.starts_with(b"C") || !c_line.ends_with(b"\n") {
            let msg = format!("expected C header, got: {:?}", c_line);
            session.data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())?;
            return Ok(());
        }

        let c_str = String::from_utf8_lossy(&c_line[1..c_line.len() - 1]);
        let parts: Vec<&str> = c_str.splitn(3, ' ').collect();
        if parts.len() < 3 {
            let msg = format!("malformed C header: {:?}", c_line);
            session.data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())?;
            return Ok(());
        }
        let size = match parts[1].parse::<u64>() {
            Ok(s) => s,
            Err(_) => {
                let msg = format!("invalid size in C header: {:?}", c_line);
                session.data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())?;
                return Ok(());
            }
        };

        // Send \0 (accept C header)
        session.data(channel, vec![0u8])?;

        // 3. Consume payload
        let payload = read_exact(&self.received_data, size as usize).await?;
        if payload.len() != size as usize {
            let msg = format!(
                "payload size mismatch: expected {}, got {}",
                size,
                payload.len()
            );
            session.data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())?;
            return Ok(());
        }

        // 4. Consume trailing \0
        let trailing = read_exact(&self.received_data, 1).await?;
        if trailing[0] != 0u8 {
            let msg = format!("expected trailing \\0, got: {:?}", trailing);
            session.data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())?;
            return Ok(());
        }

        // Send \0 (data received)
        session.data(channel, vec![0u8])?;

        // 5. Parse E\n
        let e_line = read_line(&self.received_data).await?;
        if e_line != b"E\n" {
            let msg = format!("expected E\\n, got: {:?}", e_line);
            session.data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())?;
            return Ok(());
        }

        // Send final \0
        session.data(channel, vec![0u8])?;

        Ok(())
    }

    async fn handle_scp_source(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let behavior = self.state.behavior.lock().await.clone();

        match behavior {
            ServerBehavior::SourceSuccess {
                filename,
                content,
                mode,
            } => {
                self.send_file(channel, session, &filename, &content, mode, false, false)
                    .await?;
                let _ = session.exit_status_request(channel, 0);
                session.eof(channel)?;
                session.close(channel)?;
                Ok(())
            }

            ServerBehavior::SourceCoalesced {
                filename,
                content,
                mode,
            } => {
                self.send_file(channel, session, &filename, &content, mode, true, false)
                    .await?;
                let _ = session.exit_status_request(channel, 0);
                session.eof(channel)?;
                session.close(channel)?;
                Ok(())
            }

            ServerBehavior::SourceOneByte {
                filename,
                content,
                mode,
            } => {
                self.send_file(channel, session, &filename, &content, mode, false, true)
                    .await?;
                let _ = session.exit_status_request(channel, 0);
                session.eof(channel)?;
                session.close(channel)?;
                Ok(())
            }

            ServerBehavior::NonZeroExit { code } => {
                // For download: Send minimal valid protocol then exit non-zero
                // Send a tiny file so the client can complete the transfer
                self.send_file(channel, session, "test.txt", b"x", 0o644, false, false)
                    .await?;
                let _ = session.exit_status_request(channel, code);
                session.eof(channel)?;
                session.close(channel)?;
                Ok(())
            }

            ServerBehavior::SourceFinalError {
                filename,
                content,
                mode,
                code,
                message,
            } => {
                // Send file normally but end with error status byte instead of \0
                self.send_file_with_error(
                    channel, session, &filename, &content, mode, code, &message,
                )
                .await?;
                let _ = session.exit_status_request(channel, 0);
                session.eof(channel)?;
                session.close(channel)?;
                Ok(())
            }

            ServerBehavior::SourceDataBeforeSuccess {
                filename,
                content,
                mode,
            } => {
                // Send C header BEFORE channel_success (regression test)
                // channel_success is sent after this function returns
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                let header = format!("C{:04o} {} {}\n", mode, content.len(), filename);
                session.data(channel, header.as_bytes().to_vec())?;

                // Wait for client ack
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;

                // Send content
                session.data(channel, content.to_vec())?;

                // Send trailing \0
                session.data(channel, vec![0u8])?;

                // Wait for client final ack
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;

                let _ = session.exit_status_request(channel, 0);
                session.eof(channel)?;
                session.close(channel)?;
                Ok(())
            }

            ServerBehavior::SourceStallAfterHeader {
                filename,
                mode,
                size,
            } => {
                // Wait for client's initial \0
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;

                // Send C header with specified mode
                let header = format!("C{:04o} {} {}\n", mode, size, filename);
                session.data(channel, header.as_bytes().to_vec())?;

                // Wait for client ack
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;

                // Now stall forever - client should cancel
                // This lets us test that the file's mode is never widened while old contents exist
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                Ok(())
            }

            _ => Ok(()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_file(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        filename: &str,
        content: &[u8],
        mode: u32,
        coalesced: bool,
        one_byte: bool,
    ) -> Result<(), russh::Error> {
        // Wait for client's initial \0
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let header = format!("C{:04o} {} {}\n", mode, content.len(), filename);

        if coalesced {
            // Send header + content in one message
            let mut msg = header.as_bytes().to_vec();
            msg.extend_from_slice(content);
            msg.push(0u8); // trailing \0
            session.data(channel, msg)?;
        } else if one_byte {
            // Send header normally
            session.data(channel, header.as_bytes().to_vec())?;

            // Wait for client ack
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;

            // Send content one byte at a time
            for &byte in content {
                session.data(channel, vec![byte])?;
            }

            // Send trailing \0
            session.data(channel, vec![0u8])?;
        } else {
            // Normal: send header
            session.data(channel, header.as_bytes().to_vec())?;

            // Wait for client ack
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;

            // Send content
            session.data(channel, content.to_vec())?;

            // Send trailing \0
            session.data(channel, vec![0u8])?;
        }

        // Wait for client's final ack
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_file_with_error(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
        filename: &str,
        content: &[u8],
        mode: u32,
        error_code: u8,
        error_message: &str,
    ) -> Result<(), russh::Error> {
        // Wait for client's initial \0
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let header = format!("C{:04o} {} {}\n", mode, content.len(), filename);
        session.data(channel, header.as_bytes().to_vec())?;

        // Wait for client ack
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Send content
        session.data(channel, content.to_vec())?;

        // Send error status byte + message instead of \0
        let mut msg = vec![error_code];
        msg.extend_from_slice(error_message.as_bytes());
        msg.push(b'\n');
        session.data(channel, msg)?;

        Ok(())
    }
}

/// Start the loopback SSH server on 127.0.0.1:0, return the bound address.
pub async fn start_test_server(
    state: TestServerState,
) -> Result<(tokio::task::JoinHandle<()>, std::net::SocketAddr), Box<dyn std::error::Error>> {
    // Generate ephemeral Ed25519 key at runtime (avoids embedding keys that trigger secret scans)
    let keypair = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;

    let config = russh::server::Config {
        auth_rejection_time: std::time::Duration::from_secs(0),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![keypair],
        ..Default::default()
    };

    let config = Arc::new(config);
    let mut server = TestServer {
        state: state.clone(),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };

            let config = config.clone();
            let handler = server.new_client(None);
            tokio::spawn(async move {
                let _ = server::run_stream(config, stream, handler).await;
            });
        }
    });

    // Give server time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    Ok((handle, addr))
}
