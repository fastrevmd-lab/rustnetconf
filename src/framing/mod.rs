//! NETCONF message framing layer.
//!
//! Handles encoding outbound XML into framed bytes and decoding inbound
//! bytes back into complete XML messages. Two framing modes:
//!
//! - **EOM** (NETCONF 1.0): Messages terminated by `]]>]]>`
//! - **Chunked** (NETCONF 1.1): Messages split into length-prefixed chunks
//!
//! The framing mode is selected by the Session after the `<hello>` exchange.

pub mod chunked;
pub mod eom;

/// Incremental frame decoding with the state the [`Framer`] trait cannot hold.
///
/// `Framer::decode` is all-or-nothing by design and its methods take `&self`,
/// so it cannot report "half of this chunk is here". That matters: this crate's
/// own chunked encoder emits **one chunk per message**, so a stateless
/// chunk-granularity decoder degenerates to buffering the whole reply — and the
/// streaming API would silently not stream against any NETCONF 1.1 peer.
#[derive(Debug)]
pub(crate) enum StreamDecoder {
    /// EOM: emit everything that cannot still be part of the delimiter.
    Eom,
    /// Chunked: `remaining` counts bytes still owed by the chunk in progress.
    Chunked { remaining: usize },
}

impl StreamDecoder {
    pub(crate) fn for_version(chunked: bool) -> Self {
        if chunked {
            StreamDecoder::Chunked { remaining: 0 }
        } else {
            StreamDecoder::Eom
        }
    }

    /// Consume what is available, emitting payload as soon as it is unambiguous.
    pub(crate) fn decode_part(
        &mut self,
        buffer: &[u8],
    ) -> Result<FramePart, crate::error::FramingError> {
        match self {
            StreamDecoder::Eom => Self::eom_part(buffer),
            StreamDecoder::Chunked { remaining } => Self::chunked_part(buffer, remaining),
        }
    }

    fn eom_part(buffer: &[u8]) -> Result<FramePart, crate::error::FramingError> {
        const DELIM: &[u8] = b"]]>]]>";
        if let Some(pos) = buffer.windows(DELIM.len()).position(|w| w == DELIM) {
            if pos > 0 {
                return Ok(FramePart::Data {
                    payload: buffer[..pos].to_vec(),
                    consumed: pos,
                });
            }
            return Ok(FramePart::End {
                consumed: DELIM.len(),
            });
        }
        // Hold back a possible partial delimiter, or framing bytes reach the
        // caller as payload.
        let safe = buffer.len().saturating_sub(DELIM.len() - 1);
        if safe == 0 {
            return Ok(FramePart::NeedMore);
        }
        Ok(FramePart::Data {
            payload: buffer[..safe].to_vec(),
            consumed: safe,
        })
    }

    fn chunked_part(
        buffer: &[u8],
        remaining: &mut usize,
    ) -> Result<FramePart, crate::error::FramingError> {
        // Mid-chunk: emit whatever has arrived. This is the whole point — a
        // single large chunk streams instead of being buffered entire.
        if *remaining > 0 {
            if buffer.is_empty() {
                return Ok(FramePart::NeedMore);
            }
            let take = buffer.len().min(*remaining);
            *remaining -= take;
            return Ok(FramePart::Data {
                payload: buffer[..take].to_vec(),
                consumed: take,
            });
        }

        if buffer.len() < 2 {
            return Ok(FramePart::NeedMore);
        }
        if buffer[0] != b'\n' || buffer[1] != b'#' {
            // Same classification the all-at-once path applies. Some firmware
            // advertises :base:1.1 and then sends EOM-framed replies; callers
            // key recovery and diagnostics off this typed variant, so the
            // streaming path must not flatten it to a generic parse failure.
            if chunked::looks_like_eom_data(buffer) {
                return Err(crate::error::FramingError::Mismatch {
                    advertised: "1.1 (chunked)".to_string(),
                    actual: "1.0 (EOM)".to_string(),
                });
            }
            return Err(crate::error::FramingError::Invalid(format!(
                "expected chunk header, got {:?}",
                &buffer[..buffer.len().min(4)]
            )));
        }
        let mut pos = 2;
        // `\n#` alone: the next byte decides between a length and the
        // end-of-chunks marker, and indexing for it before it arrives panics on
        // input a peer fully controls.
        let Some(&after_hash) = buffer.get(pos) else {
            return Ok(FramePart::NeedMore);
        };
        if after_hash == b'#' {
            if pos + 2 > buffer.len() {
                return Ok(FramePart::NeedMore);
            }
            if buffer[pos + 1] != b'\n' {
                return Err(crate::error::FramingError::Invalid(
                    "expected \\n after ## in end-of-chunks marker".to_string(),
                ));
            }
            return Ok(FramePart::End { consumed: pos + 2 });
        }
        let len_start = pos;
        while pos < buffer.len() && buffer[pos] != b'\n' {
            if !buffer[pos].is_ascii_digit() {
                return Err(crate::error::FramingError::Invalid(
                    "non-digit in chunk length".to_string(),
                ));
            }
            pos += 1;
        }
        if pos >= buffer.len() {
            return Ok(FramePart::NeedMore);
        }
        if pos == len_start {
            return Err(crate::error::FramingError::Invalid(
                "empty chunk length".to_string(),
            ));
        }
        let len: usize = std::str::from_utf8(&buffer[len_start..pos])
            .ok()
            .and_then(|t| t.parse().ok())
            .ok_or_else(|| {
                crate::error::FramingError::Invalid("invalid chunk length".to_string())
            })?;
        if len == 0 {
            return Err(crate::error::FramingError::Invalid(
                "zero-length chunk".to_string(),
            ));
        }
        // The all-at-once path bounds this; so does this one. Unbounded, a peer
        // can demand an arbitrary allocation.
        if len > chunked::MAX_CHUNK_SIZE {
            return Err(crate::error::FramingError::Invalid(format!(
                "chunk length {len} exceeds maximum {}",
                chunked::MAX_CHUNK_SIZE
            )));
        }
        pos += 1;
        *remaining = len;
        Ok(FramePart::Data {
            payload: Vec::new(),
            consumed: pos,
        })
    }
}

/// One step of incremental frame decoding.
///
/// Exists so a large reply can be consumed without holding it whole. The
/// all-at-once [`Framer::decode`] cannot do that: it returns nothing until the
/// entire message is buffered, so peak memory is the reply size regardless of
/// what the caller does with it.
#[derive(Debug, PartialEq, Eq)]
pub enum FramePart {
    /// Payload ready to emit now, plus the input bytes consumed producing it.
    ///
    /// `consumed` may exceed `payload.len()` — framing overhead (chunk headers)
    /// is consumed but not emitted.
    Data { payload: Vec<u8>, consumed: usize },
    /// The message ended. `consumed` covers the terminator.
    End { consumed: usize },
    /// Not enough input to make progress.
    NeedMore,
}

/// Trait for encoding/decoding NETCONF message frames.
///
/// Implementors handle the wire-level framing for one NETCONF version.
pub trait Framer: Send + Sync {
    /// Encode an XML message into framed bytes ready for the transport.
    fn encode(&self, message: &str) -> Vec<u8>;

    /// Attempt to decode a complete message from the input buffer.
    ///
    /// If a complete framed message is found, returns `Some((message, consumed))`
    /// where `consumed` is the number of bytes to drain from the buffer.
    /// Returns `None` if the buffer doesn't contain a complete message yet.
    fn decode(&self, buffer: &[u8]) -> Result<Option<(String, usize)>, crate::error::FramingError>;
}

#[cfg(test)]
mod incremental_tests {
    use super::chunked::ChunkedFramer;
    use super::eom::EomFramer;
    use super::{FramePart, Framer, StreamDecoder};

    /// Drive `decode_part` to completion, returning the reassembled payload.
    fn drain(mut decoder: StreamDecoder, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = input.to_vec();
        loop {
            match decoder.decode_part(&buf).expect("decode_part") {
                FramePart::Data { payload, consumed } => {
                    out.extend_from_slice(&payload);
                    buf.drain(..consumed);
                }
                FramePart::End { consumed } => {
                    buf.drain(..consumed);
                    return out;
                }
                FramePart::NeedMore => panic!("ran out of input mid-frame"),
            }
        }
    }

    #[test]
    fn eom_incremental_matches_all_at_once() {
        let msg = "<rpc-reply><data>x</data></rpc-reply>";
        let framed = EomFramer.encode(msg);
        assert_eq!(
            drain(StreamDecoder::for_version(false), &framed),
            msg.as_bytes()
        );
    }

    #[test]
    fn eom_holds_back_a_partial_delimiter() {
        // `]]>]]` could still become the delimiter. Emitting it would put
        // framing bytes into the caller's payload.
        let mut dec = StreamDecoder::for_version(false);
        match dec.decode_part(b"abc]]>]]").expect("decode_part") {
            FramePart::Data { payload, .. } => {
                assert_eq!(payload, b"abc", "must stop before the partial delimiter");
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn eom_needs_more_when_only_a_partial_delimiter_is_present() {
        let mut dec = StreamDecoder::for_version(false);
        assert_eq!(
            dec.decode_part(b"]]>]]").expect("decode_part"),
            FramePart::NeedMore
        );
    }

    #[test]
    fn chunked_incremental_matches_all_at_once() {
        let msg = "<rpc-reply><data>hello</data></rpc-reply>";
        let framed = ChunkedFramer.encode(msg);
        assert_eq!(
            drain(StreamDecoder::for_version(true), &framed),
            msg.as_bytes()
        );
    }

    #[test]
    fn chunked_emits_a_partial_chunk() {
        // The property the streaming API rests on. This crate's encoder emits
        // one chunk per message, so a decoder that waits for a whole chunk
        // never streams anything at all against a NETCONF 1.1 peer.
        let mut dec = StreamDecoder::for_version(true);
        match dec.decode_part(b"\n#100\nhalf").expect("decode_part") {
            FramePart::Data { payload, consumed } => {
                // The header alone on the first call.
                assert!(payload.is_empty());
                assert_eq!(consumed, 6);
            }
            other => panic!("expected the header, got {other:?}"),
        }
        match dec.decode_part(b"half").expect("decode_part") {
            FramePart::Data { payload, consumed } => {
                assert_eq!(payload, b"half", "must emit what has arrived");
                assert_eq!(consumed, 4);
            }
            other => panic!("expected partial data, got {other:?}"),
        }
    }

    #[test]
    fn chunked_emits_each_chunk_without_waiting_for_the_end_marker() {
        // Two chunks, no terminator yet: the first must still be emitted.
        let mut dec = StreamDecoder::for_version(true);
        let mut buf: Vec<u8> = b"\n#5\nhello\n#5\nworld".to_vec();
        let mut out = Vec::new();
        for _ in 0..2 {
            match dec.decode_part(&buf).expect("decode_part") {
                FramePart::Data { payload, consumed } => {
                    out.extend_from_slice(&payload);
                    buf.drain(..consumed);
                }
                other => panic!("expected Data, got {other:?}"),
            }
        }
        assert_eq!(out, b"hello");
    }

    #[test]
    fn chunked_needs_more_on_a_truncated_chunk() {
        let mut dec = StreamDecoder::for_version(true);
        assert_eq!(
            dec.decode_part(b"\n#").expect("decode_part"),
            FramePart::NeedMore
        );
    }

    #[test]
    fn chunked_bounds_the_announced_length() {
        // Unbounded, a device can demand an arbitrary allocation — and at
        // exactly usize::MAX the offset arithmetic overflows and panics.
        let mut dec = StreamDecoder::for_version(true);
        assert!(dec.decode_part(b"\n#99999999\nx").is_err());
        let huge = format!("\n#{}\nx", usize::MAX);
        assert!(dec.decode_part(huge.as_bytes()).is_err());
    }

    #[test]
    fn chunked_still_detects_eom_framing_from_a_lying_device() {
        let mut dec = StreamDecoder::for_version(true);
        let err = dec
            .decode_part(b"<?xml version=\"1.0\"?><rpc-reply><ok/></rpc-reply>]]>]]>")
            .expect_err("EOM data under chunked framing must fail");
        // The variant, not merely an error: callers switch on it.
        assert!(
            matches!(err, crate::error::FramingError::Mismatch { .. }),
            "expected FramingError::Mismatch, got: {err:?}"
        );
    }
}
