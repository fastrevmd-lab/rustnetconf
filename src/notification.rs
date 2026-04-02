//! NETCONF event notification types and parsing (RFC 5277).
//!
//! Notifications are asynchronous messages sent by the device after a
//! `create-subscription` RPC. Each notification contains an `<eventTime>`
//! and an event payload.

use crate::error::RpcError;

/// A parsed NETCONF `<notification>` message (RFC 5277 section 4).
#[derive(Debug, Clone)]
pub struct Notification {
    /// The event timestamp in RFC 3339 format (from `<eventTime>`).
    pub event_time: String,
    /// The raw XML content of the event (everything inside `<notification>`
    /// except `<eventTime>`).
    pub event_xml: String,
}

/// Classify whether a framed XML message is an `<rpc-reply>` or `<notification>`.
///
/// Only inspects the first XML element to determine the message type.
/// Returns `None` for unrecognized messages (e.g., `<hello>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    RpcReply,
    Notification,
}

/// Classify a framed XML message by its root element.
pub fn classify_message(xml: &str) -> Option<MessageKind> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref tag)) | Ok(Event::Empty(ref tag)) => {
                let local_name = tag.local_name();
                return match local_name.as_ref() {
                    b"rpc-reply" => Some(MessageKind::RpcReply),
                    b"notification" => Some(MessageKind::Notification),
                    _ => None,
                };
            }
            Ok(Event::Eof) => return None,
            Ok(_) => continue, // skip XML decl, comments, etc.
            Err(_) => return None,
        }
    }
}

/// Parse a `<notification>` XML message into a [`Notification`].
///
/// Extracts the `<eventTime>` text via quick_xml, then captures the remaining
/// event content as raw XML using string slicing to preserve the original
/// XML structure (namespaces, attributes, etc.).
pub fn parse_notification(xml: &str) -> Result<Notification, RpcError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    // Pass 1: extract eventTime using the XML parser
    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    let mut event_time: Option<String> = None;
    let mut in_event_time = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref tag)) => {
                if tag.local_name().as_ref() == b"eventTime" {
                    in_event_time = true;
                }
            }
            Ok(Event::Text(ref text)) if in_event_time => {
                let t = text.unescape().map_err(|e| {
                    RpcError::ParseError(format!("failed to parse eventTime: {e}"))
                })?;
                event_time = Some(t.trim().to_string());
            }
            Ok(Event::End(ref tag)) => {
                if tag.local_name().as_ref() == b"eventTime" {
                    in_event_time = false;
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => continue,
            Err(e) => {
                return Err(RpcError::ParseError(format!(
                    "XML parse error in notification: {e}"
                )));
            }
        }
        buf.clear();
    }

    let event_time = event_time.ok_or_else(|| {
        RpcError::ParseError("notification missing <eventTime> element".to_string())
    })?;

    // Pass 2: extract event content using byte offsets from the XML parser.
    // We re-parse and track positions to capture everything after </eventTime>
    // and before the closing </notification>, preserving raw XML.
    let event_xml = extract_event_content(xml);

    Ok(Notification {
        event_time,
        event_xml,
    })
}

/// Extract the raw XML content between `</eventTime>` and `</notification>`.
///
/// Uses the XML parser to find exact byte boundaries, then slices the raw
/// string. This handles any namespace prefix correctly.
fn extract_event_content(xml: &str) -> String {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    let mut in_notification = false;
    let mut event_time_end_offset: Option<usize> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref tag)) => {
                if tag.local_name().as_ref() == b"notification" {
                    in_notification = true;
                }
            }
            Ok(Event::End(ref tag)) => {
                let local = tag.local_name();
                if local.as_ref() == b"eventTime" && in_notification {
                    event_time_end_offset = Some(reader.buffer_position() as usize);
                } else if local.as_ref() == b"notification" && in_notification {
                    if let Some(start) = event_time_end_offset {
                        // Find the closing </...notification> tag start in the raw string
                        let pos = reader.buffer_position() as usize;
                        // Walk backwards from current position to find the '<' of the closing tag
                        let end = xml[..pos].rfind("</").unwrap_or(start);
                        if end > start {
                            return xml[start..end].trim().to_string();
                        }
                    }
                    return String::new();
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => continue,
            Err(_) => break,
        }
        buf.clear();
    }

    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_rpc_reply() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><ok/></rpc-reply>"#;
        assert_eq!(classify_message(xml), Some(MessageKind::RpcReply));
    }

    #[test]
    fn test_classify_notification() {
        let xml = r#"<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
  <eventTime>2026-04-01T12:00:00Z</eventTime>
</notification>"#;
        assert_eq!(classify_message(xml), Some(MessageKind::Notification));
    }

    #[test]
    fn test_classify_hello() {
        let xml = r#"<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities/></hello>"#;
        assert_eq!(classify_message(xml), None);
    }

    #[test]
    fn test_classify_garbage() {
        assert_eq!(classify_message("not xml at all"), None);
    }

    #[test]
    fn test_classify_prefixed_rpc_reply() {
        let xml = r#"<nc:rpc-reply xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><nc:ok/></nc:rpc-reply>"#;
        assert_eq!(classify_message(xml), Some(MessageKind::RpcReply));
    }

    #[test]
    fn test_parse_notification_basic() {
        let xml = r#"<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
  <eventTime>2026-04-01T12:00:00Z</eventTime>
  <netconf-config-change xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-notifications">
    <changed-by>
      <username>admin</username>
    </changed-by>
  </netconf-config-change>
</notification>"#;
        let notif = parse_notification(xml).unwrap();
        assert_eq!(notif.event_time, "2026-04-01T12:00:00Z");
        assert!(notif.event_xml.contains("netconf-config-change"));
        assert!(notif.event_xml.contains("admin"));
    }

    #[test]
    fn test_parse_notification_missing_event_time() {
        let xml = r#"<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
  <some-event/>
</notification>"#;
        let result = parse_notification(xml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("eventTime"));
    }

    #[test]
    fn test_parse_notification_empty_event() {
        let xml = r#"<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
  <eventTime>2026-04-01T12:00:00Z</eventTime>
</notification>"#;
        let notif = parse_notification(xml).unwrap();
        assert_eq!(notif.event_time, "2026-04-01T12:00:00Z");
        assert!(notif.event_xml.is_empty());
    }

    #[test]
    fn test_parse_notification_self_closing_event() {
        let xml = r#"<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
  <eventTime>2026-04-01T12:00:00Z</eventTime>
  <link-down xmlns="urn:example:link"/>
</notification>"#;
        let notif = parse_notification(xml).unwrap();
        assert_eq!(notif.event_time, "2026-04-01T12:00:00Z");
        assert!(notif.event_xml.contains("link-down"));
    }
}
