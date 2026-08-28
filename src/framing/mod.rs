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

    /// Decode as much as is currently possible without waiting for the whole
    /// message.
    ///
    /// Defaults to reporting that streaming is unsupported, so implementations
    /// written against an earlier version keep compiling. `Framer` is public and
    /// downstream crates implement it; making this required would break every
    /// such implementation on a patch upgrade.
    ///
    /// Implementations must never emit bytes that could still turn out to be
    /// part of a terminator once more input arrives — a partial `]]>]]>` at the
    /// end of the buffer has to be held back, or the caller receives framing
    /// bytes as payload.
    fn decode_part(&self, buffer: &[u8]) -> Result<FramePart, crate::error::FramingError> {
        let _ = buffer;
        Err(crate::error::FramingError::Invalid(
            "this Framer does not implement incremental decoding".to_string(),
        ))
    }
}

#[cfg(test)]
mod incremental_tests {
    use super::chunked::ChunkedFramer;
    use super::eom::EomFramer;
    use super::{FramePart, Framer};

    /// Drive `decode_part` to completion, returning the reassembled payload.
    fn drain(framer: &dyn Framer, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = input.to_vec();
        loop {
            match framer.decode_part(&buf).expect("decode_part") {
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
        let framer = EomFramer;
        let msg = "<rpc-reply><data>x</data></rpc-reply>";
        let framed = framer.encode(msg);
        assert_eq!(drain(&framer, &framed), msg.as_bytes());
    }

    #[test]
    fn eom_holds_back_a_partial_delimiter() {
        // `]]>]]` could still become the delimiter. Emitting it would put
        // framing bytes into the caller's payload.
        let framer = EomFramer;
        match framer.decode_part(b"abc]]>]]").expect("decode_part") {
            FramePart::Data { payload, .. } => {
                assert_eq!(payload, b"abc", "must stop before the partial delimiter");
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn eom_needs_more_when_only_a_partial_delimiter_is_present() {
        let framer = EomFramer;
        assert_eq!(
            framer.decode_part(b"]]>]]").expect("decode_part"),
            FramePart::NeedMore
        );
    }

    #[test]
    fn chunked_incremental_matches_all_at_once() {
        let framer = ChunkedFramer;
        let msg = "<rpc-reply><data>hello</data></rpc-reply>";
        let framed = framer.encode(msg);
        assert_eq!(drain(&framer, &framed), msg.as_bytes());
    }

    #[test]
    fn chunked_emits_each_chunk_without_waiting_for_the_end_marker() {
        // Two chunks, no terminator yet: the first must still be emitted.
        let framer = ChunkedFramer;
        let input = b"\n#5\nhello\n#5\nworld";
        match framer.decode_part(input).expect("decode_part") {
            FramePart::Data { payload, consumed } => {
                assert_eq!(payload, b"hello");
                assert_eq!(consumed, 9);
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn chunked_needs_more_on_a_truncated_chunk() {
        let framer = ChunkedFramer;
        assert_eq!(
            framer.decode_part(b"\n#10\nshort").expect("decode_part"),
            FramePart::NeedMore
        );
        assert_eq!(
            framer.decode_part(b"\n#").expect("decode_part"),
            FramePart::NeedMore
        );
    }

    #[test]
    fn chunked_bounds_the_announced_length() {
        // Unbounded, a device can demand an arbitrary allocation — and at
        // exactly usize::MAX the offset arithmetic overflows and panics.
        let framer = ChunkedFramer;
        assert!(framer.decode_part(b"\n#99999999\nx").is_err());
        let huge = format!("\n#{}\nx", usize::MAX);
        assert!(framer.decode_part(huge.as_bytes()).is_err());
    }

    #[test]
    fn chunked_still_detects_eom_framing_from_a_lying_device() {
        let framer = ChunkedFramer;
        assert!(framer.decode_part(b"<rpc-reply/>]]>]]>").is_err());
    }
}
