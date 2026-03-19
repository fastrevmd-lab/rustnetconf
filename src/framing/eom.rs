//! NETCONF 1.0 end-of-message framing.
//!
//! Messages are terminated by the delimiter `]]>]]>` (RFC 4741 §3.1).
//! The hello exchange always uses EOM framing regardless of version.

use crate::error::FramingError;
use crate::framing::Framer;

/// The NETCONF 1.0 end-of-message delimiter.
const EOM_DELIMITER: &[u8] = b"]]>]]>";

/// NETCONF 1.0 end-of-message framer.
///
/// Appends `]]>]]>` to outbound messages and splits inbound bytes
/// on the delimiter boundary.
#[derive(Debug, Default)]
pub struct EomFramer;

impl EomFramer {
    pub fn new() -> Self {
        Self
    }
}

impl Framer for EomFramer {
    fn encode(&self, message: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(message.len() + EOM_DELIMITER.len());
        buf.extend_from_slice(message.as_bytes());
        buf.extend_from_slice(EOM_DELIMITER);
        buf
    }

    fn decode(&self, buffer: &[u8]) -> Result<Option<(String, usize)>, FramingError> {
        // Search for the EOM delimiter in the buffer.
        let delimiter_pos = find_subsequence(buffer, EOM_DELIMITER);

        match delimiter_pos {
            Some(pos) => {
                let message_bytes = &buffer[..pos];
                let consumed = pos + EOM_DELIMITER.len();

                let message = String::from_utf8(message_bytes.to_vec())
                    .map_err(|e| FramingError::Invalid(format!("invalid UTF-8 in frame: {e}")))?;

                Ok(Some((message, consumed)))
            }
            None => Ok(None),
        }
    }
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_appends_delimiter() {
        let framer = EomFramer::new();
        let encoded = framer.encode("<rpc>test</rpc>");
        assert_eq!(encoded, b"<rpc>test</rpc>]]>]]>");
    }

    #[test]
    fn test_decode_complete_message() {
        let framer = EomFramer::new();
        let input = b"<hello>world</hello>]]>]]>";
        let result = framer.decode(input).unwrap();
        assert_eq!(
            result,
            Some(("<hello>world</hello>".to_string(), input.len()))
        );
    }

    #[test]
    fn test_decode_incomplete_message() {
        let framer = EomFramer::new();
        let input = b"<hello>partial";
        let result = framer.decode(input).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_decode_partial_delimiter() {
        let framer = EomFramer::new();
        let input = b"<rpc>data</rpc>]]>";
        let result = framer.decode(input).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_decode_empty_message() {
        let framer = EomFramer::new();
        let input = b"]]>]]>";
        let result = framer.decode(input).unwrap();
        assert_eq!(result, Some(("".to_string(), EOM_DELIMITER.len())));
    }

    #[test]
    fn test_decode_multiple_messages_returns_first() {
        let framer = EomFramer::new();
        let input = b"<first/>]]>]]><second/>]]>]]>";
        let result = framer.decode(input).unwrap();
        let (msg, consumed) = result.unwrap();
        assert_eq!(msg, "<first/>");
        // The remaining buffer after consuming the first message
        assert_eq!(&input[consumed..], b"<second/>]]>]]>");
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let framer = EomFramer::new();
        let original = "<rpc message-id=\"1\"><get-config><source><running/></source></get-config></rpc>";
        let encoded = framer.encode(original);
        let (decoded, consumed) = framer.decode(&encoded).unwrap().unwrap();
        assert_eq!(decoded, original);
        assert_eq!(consumed, encoded.len());
    }
}
