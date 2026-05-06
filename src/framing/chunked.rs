//! NETCONF 1.1 chunked framing (RFC 6242 §4.2).
//!
//! Messages are encoded as one or more chunks:
//! ```text
//! \n#<length>\n<data>
//! \n#<length>\n<data>
//! \n##\n
//! ```
//!
//! Each chunk starts with `\n#<length>\n` where `<length>` is the decimal
//! byte count of the chunk data. The end-of-chunks marker is `\n##\n`.

use crate::error::FramingError;
use crate::framing::Framer;

/// Maximum allowed chunk size (4 MB). Prevents memory exhaustion from
/// malformed chunk headers advertising absurd lengths.
const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// End-of-chunks marker.
const END_OF_CHUNKS: &[u8] = b"\n##\n";

/// NETCONF 1.1 chunked framer.
#[derive(Debug, Default)]
pub struct ChunkedFramer;

impl ChunkedFramer {
    pub fn new() -> Self {
        Self
    }
}

impl Framer for ChunkedFramer {
    fn encode(&self, message: &str) -> Vec<u8> {
        let data = message.as_bytes();
        // Empty messages: just emit the end-of-chunks marker — a zero-length
        // chunk header (\n#0\n) is rejected by the decoder per RFC 6242.
        if data.is_empty() {
            return END_OF_CHUNKS.to_vec();
        }
        // Single chunk encoding: \n#<len>\n<data>\n##\n
        let header = format!("\n#{}\n", data.len());
        let mut buf = Vec::with_capacity(header.len() + data.len() + END_OF_CHUNKS.len());
        buf.extend_from_slice(header.as_bytes());
        buf.extend_from_slice(data);
        buf.extend_from_slice(END_OF_CHUNKS);
        buf
    }

    fn decode(&self, buffer: &[u8]) -> Result<Option<(String, usize)>, FramingError> {
        let mut message = Vec::new();
        let mut pos = 0;

        loop {
            // Need at least "\n#" to start
            if pos + 2 > buffer.len() {
                return Ok(None);
            }

            // Check for \n# prefix
            if buffer[pos] != b'\n' || buffer[pos + 1] != b'#' {
                // Detect EOM-framed data arriving when chunked was negotiated.
                // This is a known firmware bug on some devices (e.g., certain Junos versions)
                // that advertise :base:1.1 but actually send EOM-framed responses.
                if looks_like_eom_data(&buffer[pos..]) {
                    return Err(FramingError::Mismatch {
                        advertised: "1.1 (chunked)".to_string(),
                        actual: "1.0 (EOM)".to_string(),
                    });
                }
                return Err(FramingError::Invalid(format!(
                    "expected chunk header at position {pos}, got {:?}",
                    &buffer[pos..std::cmp::min(pos + 4, buffer.len())]
                )));
            }

            pos += 2; // skip \n#

            // Check for end-of-chunks marker (##)
            if pos < buffer.len() && buffer[pos] == b'#' {
                // This should be \n##\n
                if pos + 2 > buffer.len() {
                    return Ok(None); // need more data
                }
                if buffer[pos + 1] == b'\n' {
                    pos += 2; // skip #\n
                    let decoded = String::from_utf8(message)
                        .map_err(|e| FramingError::Invalid(format!("invalid UTF-8: {e}")))?;
                    return Ok(Some((decoded, pos)));
                }
                return Err(FramingError::Invalid(
                    "expected \\n after ## in end-of-chunks marker".to_string(),
                ));
            }

            // Parse chunk length
            let len_start = pos;
            while pos < buffer.len() && buffer[pos] != b'\n' {
                if !buffer[pos].is_ascii_digit() {
                    return Err(FramingError::Invalid(format!(
                        "non-digit in chunk length at position {pos}: {:?}",
                        buffer[pos] as char
                    )));
                }
                pos += 1;
            }

            if pos >= buffer.len() {
                return Ok(None); // need more data for the length
            }

            let len_str = std::str::from_utf8(&buffer[len_start..pos])
                .map_err(|_| FramingError::Invalid("invalid chunk length encoding".to_string()))?;

            let chunk_len: usize = len_str
                .parse()
                .map_err(|_| FramingError::Invalid(format!("invalid chunk length: {len_str}")))?;

            if chunk_len == 0 {
                return Err(FramingError::Invalid("zero-length chunk".to_string()));
            }

            if chunk_len > MAX_CHUNK_SIZE {
                return Err(FramingError::Invalid(format!(
                    "chunk size {chunk_len} exceeds maximum {MAX_CHUNK_SIZE}"
                )));
            }

            pos += 1; // skip \n after length

            // Read chunk data
            if pos + chunk_len > buffer.len() {
                return Ok(None); // need more data
            }

            message.extend_from_slice(&buffer[pos..pos + chunk_len]);
            pos += chunk_len;
        }
    }
}

/// Heuristic: does this buffer look like EOM-framed data rather than chunked?
/// Checks for XML start (`<?xml` or `<rpc`) or the EOM delimiter `]]>]]>`.
fn looks_like_eom_data(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    // Skip leading whitespace
    let trimmed = match data.iter().position(|&b| !b.is_ascii_whitespace()) {
        Some(pos) => &data[pos..],
        None => return false,
    };
    // XML document or element start
    if trimmed.starts_with(b"<?xml") || trimmed.starts_with(b"<rpc") || trimmed.starts_with(b"<!--") {
        return true;
    }
    // EOM delimiter anywhere in the buffer
    if data.windows(6).any(|w| w == b"]]>]]>") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_single_chunk() {
        let framer = ChunkedFramer::new();
        let encoded = framer.encode("<rpc>test</rpc>");
        let expected = b"\n#15\n<rpc>test</rpc>\n##\n";
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_decode_single_chunk() {
        let framer = ChunkedFramer::new();
        let input = b"\n#15\n<rpc>test</rpc>\n##\n";
        let (msg, consumed) = framer.decode(input).unwrap().unwrap();
        assert_eq!(msg, "<rpc>test</rpc>");
        assert_eq!(consumed, input.len());
    }

    #[test]
    fn test_decode_multiple_chunks() {
        let framer = ChunkedFramer::new();
        // Two chunks: "<rpc>" (5 bytes) + "test</rpc>" (10 bytes)
        let input = b"\n#5\n<rpc>\n#10\ntest</rpc>\n##\n";
        let (msg, consumed) = framer.decode(input).unwrap().unwrap();
        assert_eq!(msg, "<rpc>test</rpc>");
        assert_eq!(consumed, input.len());
    }

    #[test]
    fn test_decode_incomplete_header() {
        let framer = ChunkedFramer::new();
        let input = b"\n#";
        assert_eq!(framer.decode(input).unwrap(), None);
    }

    #[test]
    fn test_decode_incomplete_data() {
        let framer = ChunkedFramer::new();
        let input = b"\n#15\n<rpc>partial";
        assert_eq!(framer.decode(input).unwrap(), None);
    }

    #[test]
    fn test_decode_incomplete_end_marker() {
        let framer = ChunkedFramer::new();
        let input = b"\n#5\nhello\n#";
        assert_eq!(framer.decode(input).unwrap(), None);
    }

    #[test]
    fn test_decode_malformed_length() {
        let framer = ChunkedFramer::new();
        let input = b"\n#abc\ndata\n##\n";
        assert!(framer.decode(input).is_err());
    }

    #[test]
    fn test_decode_zero_length_chunk() {
        let framer = ChunkedFramer::new();
        let input = b"\n#0\n\n##\n";
        assert!(framer.decode(input).is_err());
    }

    #[test]
    fn test_decode_oversized_chunk() {
        let framer = ChunkedFramer::new();
        let input = b"\n#999999999\ndata\n##\n";
        assert!(framer.decode(input).is_err());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let framer = ChunkedFramer::new();
        let original = "<rpc message-id=\"1\"><get-config><source><running/></source></get-config></rpc>";
        let encoded = framer.encode(original);
        let (decoded, consumed) = framer.decode(&encoded).unwrap().unwrap();
        assert_eq!(decoded, original);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_decode_invalid_start() {
        let framer = ChunkedFramer::new();
        let input = b"garbage\n#5\nhello\n##\n";
        assert!(framer.decode(input).is_err());
    }

    #[test]
    fn test_encode_empty_message() {
        let framer = ChunkedFramer::new();
        let encoded = framer.encode("");
        // Empty message must encode as just the end-of-chunks marker.
        // A \n#0\n chunk header is rejected by the decoder per RFC 6242.
        assert_eq!(encoded, b"\n##\n");
    }

    #[test]
    fn test_encode_decode_roundtrip_empty() {
        let framer = ChunkedFramer::new();
        let encoded = framer.encode("");
        let (decoded, consumed) = framer.decode(&encoded).unwrap().unwrap();
        assert_eq!(decoded, "");
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_decode_large_message() {
        let framer = ChunkedFramer::new();
        let large_body = "x".repeat(100_000);
        let encoded = framer.encode(&large_body);
        let (decoded, _) = framer.decode(&encoded).unwrap().unwrap();
        assert_eq!(decoded, large_body);
    }

    #[test]
    fn test_decode_detects_eom_xml_as_framing_mismatch() {
        let framer = ChunkedFramer::new();
        // Device advertised 1.1 but sent an EOM-framed XML response
        let input = b"<?xml version=\"1.0\"?><rpc-reply><ok/></rpc-reply>]]>]]>";
        let err = framer.decode(input).unwrap_err();
        assert!(
            matches!(err, FramingError::Mismatch { .. }),
            "expected FramingError::Mismatch, got: {err:?}"
        );
    }

    #[test]
    fn test_decode_detects_eom_rpc_reply_as_framing_mismatch() {
        let framer = ChunkedFramer::new();
        let input = b"<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"1\"><ok/></rpc-reply>]]>]]>";
        let err = framer.decode(input).unwrap_err();
        assert!(
            matches!(err, FramingError::Mismatch { .. }),
            "expected FramingError::Mismatch, got: {err:?}"
        );
    }

    #[test]
    fn test_decode_detects_eom_comment_as_framing_mismatch() {
        let framer = ChunkedFramer::new();
        // Junos-style comment prefix before hello
        let input = b"<!-- No zombies -->\n<hello><capabilities></capabilities></hello>]]>]]>";
        let err = framer.decode(input).unwrap_err();
        assert!(
            matches!(err, FramingError::Mismatch { .. }),
            "expected FramingError::Mismatch, got: {err:?}"
        );
    }

    #[test]
    fn test_decode_eom_delimiter_in_buffer_detected() {
        let framer = ChunkedFramer::new();
        // Random data containing the EOM delimiter
        let input = b"some garbage ]]>]]> more stuff";
        let err = framer.decode(input).unwrap_err();
        assert!(
            matches!(err, FramingError::Mismatch { .. }),
            "expected FramingError::Mismatch, got: {err:?}"
        );
    }

    #[test]
    fn test_decode_plain_garbage_is_invalid_not_mismatch() {
        let framer = ChunkedFramer::new();
        // Random binary garbage — not EOM data, just invalid
        let input = b"\x00\x01\x02\x03";
        let err = framer.decode(input).unwrap_err();
        assert!(
            matches!(err, FramingError::Invalid(_)),
            "expected FramingError::Invalid for non-EOM garbage, got: {err:?}"
        );
    }
}
